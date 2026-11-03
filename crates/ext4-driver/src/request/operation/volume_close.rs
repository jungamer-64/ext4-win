//! One completion owner drains native caches and paging mutations before clearing recovery.

use super::*;
use crate::memory::DriverVec;
use crate::state::{
    KernelDevice, KernelFileObject, PreparedVolumeClose, SessionEndRouting, StreamCacheLease,
    VolumeCloseTarget,
};

/// External request selecting the terminal close outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeCloseRequest {
    /// Forced logical dismount from a direct-volume handle.
    Dismount,
    /// System shutdown notification, independent of any user handle.
    Shutdown,
}

/// The requester identity also records whether the attempt notification was issued.
#[derive(Debug)]
enum CloseRequester {
    /// Shutdown carries no user-mode dismount notification protocol.
    Shutdown,
    /// The prepared raw transfer resumes only after filesystem and MMP writes end.
    RawWrite {
        target: RawVolumeTarget,
        resume: Box<RawVolumeOperation>,
    },
    /// Target validation succeeded, but no attempt notification has been issued.
    DismountUnannounced(KernelFileObject),
    /// Failed completion must pair the issued attempt with DISMOUNT_FAILED.
    DismountAnnounced(KernelFileObject),
}

impl CloseRequester {
    /// Projects the admitted requester without granting notification or publication authority.
    fn target(&self) -> VolumeCloseTarget {
        match self {
            Self::Shutdown => VolumeCloseTarget::Shutdown,
            Self::RawWrite { target, .. } => VolumeCloseTarget::RawWrite(target.owner()),
            Self::DismountUnannounced(file) | Self::DismountAnnounced(file) => {
                VolumeCloseTarget::Dismount(*file)
            }
        }
    }

    /// Consumes the worker's completed notification call before cache preparation can proceed.
    fn announced(&mut self) {
        *self = match self {
            Self::DismountUnannounced(file) => Self::DismountAnnounced(*file),
            _ => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        };
    }

    /// Only an issued attempt has a corresponding failure notification.
    fn failure_notification(
        &self,
    ) -> Option<(KernelFileObject, crate::kernel::volume_event::VolumeEvent)> {
        match self {
            Self::DismountAnnounced(file) => Some((
                *file,
                crate::kernel::volume_event::VolumeEvent::DismountFailed,
            )),
            Self::Shutdown | Self::RawWrite { .. } | Self::DismountUnannounced(_) => None,
        }
    }
}

/// Preparation can release exclusion; sealing transfers completion to the terminal protocol.
#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "variant contracts describe payload ownership; per-field repetition would add no semantic contract"
    )
)]
enum CloseState {
    /// All core continuation storage exists before ordinary admission is revoked.
    Ready {
        owned: OwnedIrp,
        close: Box<CleanCloseOperation>,
    },
    /// The worker retains the request while applications release their old file handles.
    Announcing {
        preparation: PreparedVolumeClose,
        close: Box<CleanCloseOperation>,
    },
    /// Explicit dismount of a raw-locked session needs notification but no media finalization.
    AnnouncingRawDismount,
    /// Previously admitted mutations may still publish streams needed by the cache snapshot.
    Draining {
        owned: OwnedIrp,
        preparation: PreparedVolumeClose,
        close: Box<CleanCloseOperation>,
    },
    /// A native worker writes back one retained stream while paging requests use the actor.
    Writeback {
        owned: OwnedIrp,
        preparation: PreparedVolumeClose,
        streams: DriverVec<StreamCacheLease>,
        close: Box<CleanCloseOperation>,
    },
    /// New paging mutations are sealed; earlier writeback must drain before marker clearance.
    Sealed {
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        close: Box<CleanCloseOperation>,
    },
    /// Only the non-cancellable core durability continuation may submit lower storage I/O.
    Closing {
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        close: Box<CleanCloseOperation>,
    },
    /// Filesystem durability is complete; its retained proof awaits final MMP release.
    ReleasingOwnership {
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
    },
    /// Failure revokes session authority and joins physical work without clearing recovery.
    Abandoning {
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        error: DriverError,
    },
    /// Filesystem writes ended; a passive worker must release journal sharing before remount.
    ReleasingJournal {
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        outcome: DriverResult<()>,
    },
    /// Completion or failure consumed the request and its publication authority.
    Terminal,
}

/// Owns completion and terminal publication across native writeback and lower durability I/O.
#[derive(Debug)]
struct VolumeCloseOperation {
    /// Validated requester retained through terminal publication and volume-event delivery.
    requester: CloseRequester,
    /// Mounted device retained by the operation and reactor completion rundown.
    device: KernelDevice,
    /// Sole completion and close-publication authority.
    state: CloseState,
}

/// Prepares core storage and validates the target before entering one-way closing.
/// # Errors
/// Returns the still-owned IRP on target, lifecycle or allocation failure.
pub(crate) fn volume_close(
    mut owned: OwnedIrp,
    kind: VolumeCloseRequest,
    access: &MountedVolumeAccess<'_>,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    let target = owned.request().with_active(|active| Ok(active.device()));
    let device = match target {
        Ok(device) => device,
        Err(error) => return Err(AdmitOperationError::new(error, owned)),
    };
    let target = match kind {
        VolumeCloseRequest::Shutdown => CloseRequester::Shutdown,
        VolumeCloseRequest::Dismount => {
            let target = match crate::request::file_system_control::direct_volume_target(
                &mut owned.request(),
            ) {
                Ok(target) => target,
                Err(error) => return Err(AdmitOperationError::new(error, owned)),
            };
            if !access.owns_volume(target.volume()) {
                return Err(AdmitOperationError::new(
                    DriverError::InvalidDeviceRequest,
                    owned,
                ));
            }
            CloseRequester::DismountUnannounced(target.owner())
        }
    };
    prepare_close(owned, target, device, access)
        .map(|operation| -> Box<dyn CompletionOperation> { operation })
}

/// All continuation storage exists before session authority can be consumed.
/// # Errors
/// Returns the owned request on allocation failure.
fn prepare_close(
    owned: OwnedIrp,
    target: CloseRequester,
    device: KernelDevice,
    access: &MountedVolumeAccess<'_>,
) -> Result<Box<VolumeCloseOperation>, AdmitOperationError> {
    let profile = access.mounted_profile();
    let close = match memory::boxed_try_with(|| Ok(CleanCloseOperation::new(profile))) {
        Ok(close) => close,
        Err(error) => return Err(AdmitOperationError::new(error, owned)),
    };
    memory::boxed_try_map(owned, |owned| VolumeCloseOperation {
        requester: target,
        device,
        state: CloseState::Ready { owned, close },
    })
    .map_err(|failure| {
        let (error, owned) = failure.into_parts();
        AdmitOperationError::new(error, owned)
    })
}

/// Transfers a fully prepared raw write into session termination before its first lower effect.
pub(super) fn before_raw_write(
    mut owned: OwnedIrp,
    resume: Box<RawVolumeOperation>,
    target: RawVolumeTarget,
    access: &mut MountedVolumeAccess<'_>,
) -> OperationTransition {
    let device = match owned.request().with_active(|active| Ok(active.device())) {
        Ok(device) => device,
        Err(error) => return OperationTransition::Complete(owned.prepare_result(Err(error))),
    };
    match prepare_close(
        owned,
        CloseRequester::RawWrite { target, resume },
        device,
        access,
    ) {
        Ok(operation) => {
            operation.advance_mounted(CompletionEvent::Core(OperationEvent::Admitted), access)
        }
        Err(error) => {
            let (error, owned) = error.into_parts();
            OperationTransition::Complete(owned.prepare_result(Err(error)))
        }
    }
}

impl VolumeCloseOperation {
    /// Completes one request, pairing failed attempts only after their announcement was issued.
    fn complete(self, owned: OwnedIrp, result: DriverResult<IrpCompletion>) -> OperationTransition {
        let failed = result.is_err();
        let mut completion = owned.prepare_result(result);
        if failed && let Some((file, event)) = self.requester.failure_notification() {
            completion = completion.with_volume_event(file, event);
        }
        OperationTransition::Complete(completion)
    }

    /// Waits for prior mutations only after dismount observers had a chance to release resources.
    fn drain(
        mut self: Box<Self>,
        owned: OwnedIrp,
        preparation: PreparedVolumeClose,
        close: Box<CleanCloseOperation>,
    ) -> OperationTransition {
        self.state = CloseState::Draining {
            owned,
            preparation,
            close,
        };
        OperationTransition::Wait {
            condition: WaitCondition::SessionDrain,
            suspended: self,
        }
    }

    /// Publishes logical termination after journal sharing has been released.
    fn publish(
        self,
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        outcome: DriverResult<()>,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let target = self.requester.target();
        let result = match outcome {
            Ok(()) => access.publish_volume_state_transition(transition),
            Err(error) => {
                access.fail_volume_state_transition(transition, error);
                Err(error)
            }
        };
        if !matches!(target, VolumeCloseTarget::Shutdown) && access.authorize_storage().is_ok() {
            let routing = if result.is_ok() {
                SessionEndRouting::DirectAccess
            } else if access.failed_close_retains_lock() {
                SessionEndRouting::Retain
            } else {
                SessionEndRouting::Remount
            };
            MountedVolumeDevice::publish_session_end(self.device, routing);
            MountedVolumeDevice::unregister_shutdown_notification(self.device);
            if matches!(target, VolumeCloseTarget::Dismount(_)) {
                MountedVolumeDevice::complete_dismount(
                    self.device,
                    result
                        .as_ref()
                        .map_or_else(|error| error.ntstatus(), |()| STATUS_SUCCESS),
                );
            }
        }
        access
            .operational_trace()
            .record_result(OperationalPath::VolumeClose, &result);
        if result.is_ok()
            && let CloseRequester::RawWrite { resume, .. } = self.requester
        {
            return resume.submit_prepared(owned);
        }
        self.complete(owned, result.map(|()| IrpCompletion::EMPTY))
    }

    /// Only a still-authorized session may reopen after cache preparation fails.
    fn fail_preparation(
        self: Box<Self>,
        owned: OwnedIrp,
        preparation: PreparedVolumeClose,
        error: DriverError,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        access
            .operational_trace()
            .record_status(OperationalPath::VolumeClose, error.ntstatus());
        record_cache_coherency_failure(error, access);
        if let Some(transition) = access.abort_or_seal_close(preparation) {
            return self.fail(owned, transition, error, access);
        }
        self.complete(owned, Err(error))
    }

    /// Revokes failed session authority before joining lower writes and journal sharing.
    fn fail(
        mut self: Box<Self>,
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        error: DriverError,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        access
            .operational_trace()
            .record_status(OperationalPath::VolumeClose, error.ntstatus());
        record_cache_coherency_failure(error, access);
        access.abandon_session();
        self.state = CloseState::Abandoning {
            owned,
            transition,
            error,
        };
        OperationTransition::WaitForClosingDrain {
            condition: WaitCondition::SessionDrain,
            suspended: self,
        }
    }

    /// A journal handle is released at most once, for either clean or unclean termination.
    fn release_journal(
        mut self: Box<Self>,
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        outcome: DriverResult<()>,
        exclusion: Option<crate::kernel::storage::ExternalJournalExclusion>,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Some(exclusion) = exclusion {
            self.state = CloseState::ReleasingJournal {
                owned,
                transition,
                outcome,
            };
            OperationTransition::SubmitPassiveWork {
                work: crate::irp::PassiveWork::CloseExternalJournal(exclusion),
                suspended: self,
            }
        } else {
            self.publish(owned, transition, outcome, access)
        }
    }

    /// Runs native cache work outside the actor so synchronous paging requests can complete.
    fn writeback(
        mut self: Box<Self>,
        owned: OwnedIrp,
        preparation: PreparedVolumeClose,
        mut streams: DriverVec<StreamCacheLease>,
        close: Box<CleanCloseOperation>,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Some(stream) = streams.pop() {
            let work = match self.requester.target() {
                VolumeCloseTarget::Dismount(_) | VolumeCloseTarget::RawWrite(_) => {
                    crate::irp::PassiveWork::CloseWriteback { stream }
                }
                VolumeCloseTarget::Shutdown => crate::irp::PassiveWork::flush(stream),
            };
            self.state = CloseState::Writeback {
                owned,
                preparation,
                streams,
                close,
            };
            OperationTransition::SubmitPassiveWork {
                work,
                suspended: self,
            }
        } else {
            let transition = match access.seal_volume_close(preparation) {
                Ok(transition) => transition,
                Err(error) => {
                    access
                        .operational_trace()
                        .record_status(OperationalPath::VolumeClose, error.ntstatus());
                    return self.complete(owned, Err(error));
                }
            };
            self.state = CloseState::Sealed {
                owned,
                transition,
                close,
            };
            OperationTransition::WaitForClosingDrain {
                condition: WaitCondition::JournalClean,
                suspended: self,
            }
        }
    }

    /// Publishes the terminal state only after the core reports the durability boundary.
    fn drive(
        mut self: Box<Self>,
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        result: CleanCloseTransition,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        match result {
            CleanCloseTransition::SubmitLower { request, suspended } => {
                self.state = CloseState::Closing {
                    owned,
                    transition,
                    close: suspended,
                };
                OperationTransition::SubmitClosingLower {
                    devices: access.storage_route(),
                    request,
                    suspended: self,
                }
            }
            CleanCloseTransition::Complete(Ok(durability)) => {
                access
                    .operational_trace()
                    .record_status(OperationalPath::VolumeCloseDurability, STATUS_SUCCESS);
                if let Err(error) = access.request_mmp_close(durability) {
                    return self.fail(owned, transition, error, access);
                }
                self.state = CloseState::ReleasingOwnership { owned, transition };
                OperationTransition::WaitForClosingDrain {
                    condition: WaitCondition::MmpRelease,
                    suspended: self,
                }
            }
            CleanCloseTransition::Complete(Err(error)) => {
                self.fail(owned, transition, DriverError::from(error), access)
            }
        }
    }
}

impl MountedVolumeOperation for VolumeCloseOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if matches!(
            (&self.state, &event),
            (
                CloseState::Ready { .. },
                CompletionEvent::Core(OperationEvent::Admitted)
            )
        ) && access.storage_access().snapshot_phase()
            != crate::kernel::stream::SnapshotPhase::Open
        {
            return OperationTransition::DeferOperation { suspended: self };
        }
        let state = core::mem::replace(&mut self.state, CloseState::Terminal);
        match (state, event) {
            (
                CloseState::Ready { owned, close },
                CompletionEvent::Core(OperationEvent::Admitted),
            ) => {
                let trace = access.operational_trace();
                trace.record(
                    OperationalPath::VolumeClose,
                    STATUS_SUCCESS,
                    OperationalOutcome::Selected,
                );
                if let CloseRequester::DismountUnannounced(file) = &self.requester
                    && access.raw_locked_by(*file)
                {
                    let file = *file;
                    self.state = CloseState::AnnouncingRawDismount;
                    return OperationTransition::SubmitPassiveWork {
                        work: crate::irp::PassiveWork::NotifyVolume {
                            owned,
                            file,
                            event: crate::kernel::volume_event::VolumeEvent::Dismount,
                        },
                        suspended: self,
                    };
                }
                let preparation = match access.prepare_volume_close(self.requester.target()) {
                    Ok(preparation) => preparation,
                    Err(error) => {
                        trace.record_status(OperationalPath::VolumeClose, error.ntstatus());
                        return self.complete(owned, Err(error));
                    }
                };
                match &self.requester {
                    CloseRequester::DismountUnannounced(file) => {
                        self.state = CloseState::Announcing { preparation, close };
                        OperationTransition::SubmitPassiveWork {
                            work: crate::irp::PassiveWork::NotifyVolume { owned, file: *file, event: crate::kernel::volume_event::VolumeEvent::Dismount },
                            suspended: self,
                        }
                    }
                    CloseRequester::Shutdown | CloseRequester::RawWrite { .. } => self.drain(owned, preparation, close),
                    CloseRequester::DismountAnnounced(_) => crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
                }
            }
            (
                CloseState::AnnouncingRawDismount,
                CompletionEvent::PassiveCompleted(
                    crate::irp::PassiveWorkCompletion::NotifyVolume { owned, result },
                ),
            ) => {
                if let Err(error) = result {
                    return self.complete(owned, Err(error));
                }
                self.requester.announced();
                let VolumeCloseTarget::Dismount(owner) = self.requester.target() else {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                access.dismount_raw_session(owner);
                MountedVolumeDevice::complete_dismount(self.device, STATUS_SUCCESS);
                self.complete(owned, Ok(IrpCompletion::EMPTY))
            }
            (
                CloseState::Abandoning {
                    owned,
                    transition,
                    error,
                },
                CompletionEvent::BarrierReleased(permit),
            ) => {
                if permit.into_identity() != crate::irp::reactor::SESSION_DRAIN_BARRIER {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                let exclusion = access.finish_abandoned_session();
                self.release_journal(owned, transition, Err(error), exclusion, access)
            }
            (
                CloseState::Announcing { preparation, close },
                CompletionEvent::PassiveCompleted(
                    crate::irp::PassiveWorkCompletion::NotifyVolume { owned, result },
                ),
            ) => match result {
                Ok(()) => {
                    self.requester.announced();
                    self.drain(owned, preparation, close)
                }
                Err(error) => self.fail_preparation(owned, preparation, error, access),
            },
            (
                CloseState::Ready { owned, .. },
                CompletionEvent::Core(OperationEvent::CancelRequested),
            ) => self.complete(owned, Err(DriverError::from(Error::OperationCancelled))),
            (
                CloseState::Draining {
                    owned,
                    preparation,
                    close,
                },
                CompletionEvent::BarrierReleased(permit),
            ) => {
                if permit.into_identity() != crate::irp::reactor::SESSION_DRAIN_BARRIER {
                    return self.fail_preparation(
                        owned,
                        preparation,
                        DriverError::InternalInvariantViolation,
                        access,
                    );
                }
                if let Err(error) = access.authorize_durability() {
                    let transition = match access.seal_volume_close(preparation) {
                        Ok(transition) => transition,
                        Err(error) => return self.complete(owned, Err(error)),
                    };
                    return self.fail(owned, transition, error, access);
                }
                let streams = match access.prepare_close_writeback(&preparation) {
                    Ok(streams) => streams,
                    Err(error) => return self.fail_preparation(owned, preparation, error, access),
                };
                self.writeback(owned, preparation, streams, close, access)
            }
            (
                CloseState::Writeback {
                    owned,
                    preparation,
                    streams,
                    close,
                },
                CompletionEvent::PassiveCompleted(completion),
            ) => {
                let result = match (self.requester.target(), completion) {
                    (VolumeCloseTarget::Dismount(_) | VolumeCloseTarget::RawWrite(_), crate::irp::PassiveWorkCompletion::CloseWriteback(result))
                    | (VolumeCloseTarget::Shutdown, crate::irp::PassiveWorkCompletion::Flush(result)) => result,
                    _ => crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
                };
                match result {
                    Ok(()) => self.writeback(owned, preparation, streams, close, access),
                    Err(error) => self.fail_preparation(owned, preparation, error, access),
                }
            }
            (
                CloseState::Sealed {
                    owned,
                    transition,
                    close,
                },
                CompletionEvent::BarrierReleased(permit),
            ) => {
                if permit.into_identity() != 1 {
                    return self.fail(
                        owned,
                        transition,
                        DriverError::InternalInvariantViolation,
                        access,
                    );
                }
                let now = match crate::kernel::time::current_ext4_timestamp() {
                    Ok(now) => now,
                    Err(error) => return self.fail(owned, transition, error, access),
                };
                access.operational_trace().record(
                    OperationalPath::VolumeCloseDurability,
                    STATUS_SUCCESS,
                    OperationalOutcome::Selected,
                );
                let close = access.start_clean_close(close, now);
                self.drive(owned, transition, close, access)
            }
            (
                CloseState::Closing {
                    owned,
                    transition,
                    close,
                },
                CompletionEvent::Core(event),
            ) => self.drive(owned, transition, close.advance(event), access),
            (
                CloseState::ReleasingOwnership { owned, transition },
                CompletionEvent::BarrierReleased(permit),
            ) => {
                if permit.into_identity() != MMP_RELEASE_BARRIER {
                    return self.fail(
                        owned,
                        transition,
                        DriverError::InternalInvariantViolation,
                        access,
                    );
                }
                let exclusion = match access.finish_mmp_close() {
                    Ok(exclusion) => exclusion,
                    Err(error) => return self.fail(owned, transition, error, access),
                };
                self.release_journal(owned, transition, Ok(()), exclusion, access)
            }

            (
                CloseState::ReleasingJournal {
                    owned,
                    transition,
                    outcome,
                },
                CompletionEvent::PassiveCompleted(
                    crate::irp::PassiveWorkCompletion::CloseExternalJournal(result),
                ),
            ) => match result {
                Ok(()) => self.publish(owned, transition, outcome, access),
                Err((error, exclusion)) => {
                    access.retain_external_journal_exclusion(exclusion);
                    access.fail_volume_state_transition(transition, error);
                    MountedVolumeDevice::unregister_shutdown_notification(self.device);
                    if matches!(self.requester.target(), VolumeCloseTarget::Dismount(_)) {
                        MountedVolumeDevice::complete_dismount(self.device, error.ntstatus());
                    }
                    self.complete(owned, Err(error))
                }
            },
            (
                CloseState::Draining {
                    owned, preparation, ..
                }
                | CloseState::Writeback {
                    owned, preparation, ..
                },
                CompletionEvent::Core(OperationEvent::CancelRequested),
            ) => {
                self.fail_preparation(owned, preparation, Error::OperationCancelled.into(), access)
            }
            (
                CloseState::Draining {
                    owned, preparation, ..
                },
                CompletionEvent::VolumeFailed(error),
            ) => self.fail_preparation(owned, preparation, error, access),
            (
                CloseState::Sealed {
                    owned, transition, ..
                }
                | CloseState::ReleasingOwnership { owned, transition },
                CompletionEvent::VolumeFailed(error),
            ) => self.fail(owned, transition, error, access),
            _ => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }

    fn record_mounted_storage_failure(
        &mut self,
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    ) {
        if failure.is_durability_unknown() {
            access.record_durability_unknown();
        }
    }
}

impl_mounted_operation_adapter!(VolumeCloseOperation);

#[expect(
    unsafe_code,
    reason = "the reactor and retained IRP pin the volume, device and close authority across worker transfers"
)]
// SAFETY: Only owned continuations move; no actor borrow or native resource guard crosses a worker boundary.
unsafe impl Send for VolumeCloseOperation {}
