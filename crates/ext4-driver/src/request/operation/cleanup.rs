//! Handle finalization precedes optional journaled namespace deletion. Storage removal or
//! journal failure cannot suppress share, lock, notification, or private-cache-map release.

use super::*;
use crate::irp::reactor::CLEANUP_HANDLE_BARRIER;

/// Sole resource-release ownership phase of one CLEANUP IRP.
#[derive(Debug)]
enum CleanupState {
    /// Wait for earlier requests on this FILE_OBJECT before releasing its resources.
    Ready(OwnedIrp),
    /// The per-handle barrier owns ordering through cleanup.
    Waiting(OwnedIrp),
    /// FsRtl temporarily owns IRP completion while processing the cleanup notification.
    Delegated,
    /// Returned original IRP with its exact oplock notification outcome.
    Returned(OwnedIrp, wdk_sys::NTSTATUS),
    /// Native private cache-map release runs outside the actor.
    Uninitializing(OwnedIrp),
    /// A terminal completion or deletion mutation owns the original IRP.
    Terminal,
}

/// Cleanup owns releases independently from journal mutation admission.
#[derive(Debug)]
struct CleanupOperation {
    /// Exclusive IRP and external callback ownership.
    state: CleanupState,
    /// First native failure observed before handle release completed.
    failure: Option<DriverError>,
    /// Prevents a new stream oplock grant before optional deletion publication.
    mutation: Option<crate::state::OplockMutationLease>,
}


impl CleanupOperation {
    /// Captures the cleanup notification while its FILE_OBJECT retains the stream, even when
    /// storage has gone. FsRtl must still release its own handle-specific oplock state.
    /// # Errors
    ///
    /// Returns stream-identity or reservation failure without suppressing later handle release.
    fn prepare_oplock(
        owned: &mut OwnedIrp,
        access: &MountedVolumeAccess<'_>,
    ) -> DriverResult<Option<PreparedMutationOplock>> {
        owned.request().with_active(|active| {
            let file_object = active.current_stack()?.file_object()?;
            match crate::state::OpenedFileObject::decode(file_object)? {
                crate::state::OpenedFileObject::Node(opened) => {
                    let deletion = opened.create_deletion();
                    access
                        .acquire_oplock_mutation(file_object)
                        .map(|(mutation, stream)| {
                            Some(PreparedMutationOplock {
                                check: OplockCheck::cleanup(stream, deletion),
                                mutation,
                            })
                        })
                }
                crate::state::OpenedFileObject::Volume(_) => Ok(None),
            }
        })
    }

    /// Records a native failure while retaining responsibility for every cleanup release.
    fn record_failure(&mut self, result: DriverResult<()>) {
        if let Err(error) = result
            && self.failure.is_none()
        {
            self.failure = Some(error);
        }
    }

    /// Uninitializes only the handle's cache map; this releases resources and requests no media
    /// durability. The native call must remain outside the actor because Cc may reenter paging.
    fn uninitialize(
        mut self: Box<Self>,
        mut owned: OwnedIrp,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        match crate::request::file_info::prepare_cleanup_cache_work(owned.request(), access) {
            Ok(Some(work)) => {
                self.state = CleanupState::Uninitializing(owned);
                OperationTransition::SubmitPassiveWork {
                    work,
                    suspended: self,
                }
            }
            Ok(None) => self.release(owned, access),
            Err(error) => {
                self.record_failure(Err(error));
                self.release(owned, access)
            }
        }
    }

    /// Releases handle-owned state before acquiring any namespace mutation authority. Failure
    /// after release leaves the FILE_OBJECT cleaned; CLOSE can reclaim it without retrying an
    /// uncertain deletion. A deletion plan stays pending only if a later lower effect is unknown.
    fn release(
        mut self,
        mut owned: OwnedIrp,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let result = crate::request::file_info::cleanup(owned.request(), access);
        match result {
            Ok(crate::request::file_info::CleanupResolution::Complete(completion)) => {
                let result = self.failure.map_or(Ok(completion), Err);
                OperationTransition::Complete(owned.prepare_result(result))
            }
            Ok(crate::request::file_info::CleanupResolution::Delete(deletion)) => {
                if let Err(error) = access.authorize_durability() {
                    drop(deletion);
                    return OperationTransition::Complete(owned.prepare_result(Err(error)));
                }
                match MutationRequestOperation::try_new(
                    owned,
                    MutationRequestKind::CleanupDeletion,
                    access,
                ) {
                    Ok(mut operation) => {
                        operation.cleanup_deletion = Some(deletion);
                        operation.cleanup_deferred_error = self.failure;
                        operation.oplock_mutation = self.mutation.take();
                        operation.advance_mounted(
                            CompletionEvent::Core(OperationEvent::Admitted),
                            access,
                        )
                    }
                    Err(failure) => {
                        drop(deletion);
                        let (error, owned) = failure.into_parts();
                        OperationTransition::Complete(owned.prepare_result(Err(error)))
                    }
                }
            }
            Err(error) => OperationTransition::Complete(owned.prepare_result(Err(error))),
        }
    }
}

impl MountedVolumeOperation for CleanupOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, CleanupState::Terminal);
        match (state, event) {
            (CleanupState::Ready(owned), CompletionEvent::Core(OperationEvent::Admitted)) => {
                self.state = CleanupState::Waiting(owned);
                OperationTransition::Wait {
                    condition: WaitCondition::Barrier {
                        identity: CLEANUP_HANDLE_BARRIER,
                    },
                    suspended: self,
                }
            }
            (
                CleanupState::Waiting(mut owned),
                CompletionEvent::Core(OperationEvent::BarrierReleased(permit)),
            ) => {
                if permit.into_identity() != CLEANUP_HANDLE_BARRIER {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                match Self::prepare_oplock(&mut owned, access) {
                    Ok(Some(prepared)) => {
                        self.mutation = Some(prepared.mutation);
                        self.state = CleanupState::Delegated;
                        OperationTransition::CheckOplock {
                            check: prepared.check,
                            owned,
                            suspended: self,
                        }
                    }
                    Ok(None) => self.uninitialize(owned, access),
                    Err(error) => {
                        self.record_failure(Err(error));
                        self.uninitialize(owned, access)
                    }
                }
            }
            (
                CleanupState::Returned(owned, status),
                CompletionEvent::Core(OperationEvent::Admitted),
            ) => {
                if status < STATUS_SUCCESS {
                    self.record_failure(Err(DriverError::OplockFailure(status)));
                }
                self.uninitialize(owned, access)
            }
            (
                CleanupState::Uninitializing(owned),
                CompletionEvent::PassiveCompleted(crate::irp::PassiveWorkCompletion::Uninitialize(
                    result,
                )),
            ) => {
                self.record_failure(result);
                self.release(owned, access)
            }
            (
                CleanupState::Uninitializing(owned),
                CompletionEvent::Core(OperationEvent::CancelRequested),
            ) => {
                self.record_failure(Err(DriverError::from(Error::OperationCancelled)));
                self.release(owned, access)
            }
            _ => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }

    fn record_mounted_storage_failure(
        &mut self,
        _failure: StorageFailureClass,
        _access: &mut MountedVolumeAccess<'_>,
    ) {
        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
            .bugcheck();
    }
}

impl OplockContinuation for CleanupOperation {
    fn resume_after_oplock(
        mut self: Box<Self>,
        owned: OwnedIrp,
        status: wdk_sys::NTSTATUS,
    ) -> Box<dyn CompletionOperation> {
        if !matches!(self.state, CleanupState::Delegated) {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        }
        self.state = CleanupState::Returned(owned, status);
        self
    }
}

impl_mounted_operation_adapter!(CleanupOperation);

#[expect(
    unsafe_code,
    reason = "the FILE_OBJECT and passive/oplock envelopes retain all cleanup identities until the reactor consumes them"
)]
// SAFETY: Ownership moves only through retained reactor/native envelopes; no actor borrow or
// same-thread native resource acquisition crosses the callback boundary.
unsafe impl Send for CleanupOperation {}
