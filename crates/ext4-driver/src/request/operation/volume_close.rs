//! One completion owner drains native caches and paging mutations before clearing recovery.

use super::*;
use crate::memory::DriverVec;
use crate::state::{
    CleanCloseTerminal, KernelDevice, KernelFileObject, PreparedVolumeClose, StreamCacheLease,
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
#[derive(Clone, Copy, Debug)]
enum CloseRequester {
    /// Shutdown carries no user-mode dismount notification protocol.
    Shutdown,
    /// Target validation succeeded, but no attempt notification has been issued.
    DismountUnannounced(KernelFileObject),
    /// Failed completion must pair the issued attempt with DISMOUNT_FAILED.
    DismountAnnounced(KernelFileObject),
}

impl CloseRequester {
    /// Projects the admitted requester without granting notification or publication authority.
    fn target(self) -> VolumeCloseTarget {
        match self {
            Self::Shutdown => VolumeCloseTarget::Shutdown,
            Self::DismountUnannounced(file) | Self::DismountAnnounced(file) => {
                VolumeCloseTarget::Dismount(file)
            }
        }
    }

    /// Consumes the worker's completed notification call before cache preparation can proceed.
    fn announced(self) -> Self {
        match self {
            Self::DismountUnannounced(file) => Self::DismountAnnounced(file),
            _ => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }

    /// Only an issued attempt has a corresponding failure notification.
    fn failure_notification(
        self,
    ) -> Option<(KernelFileObject, crate::kernel::volume_event::VolumeEvent)> {
        match self {
            Self::DismountAnnounced(file) => Some((
                file,
                crate::kernel::volume_event::VolumeEvent::DismountFailed,
            )),
            Self::Shutdown | Self::DismountUnannounced(_) => None,
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
    /// Filesystem writes ended; a passive worker must release journal sharing before remount.
    ReleasingJournal {
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
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
    .map(|operation| -> Box<dyn CompletionOperation> { operation })
    .map_err(|failure| {
        let (error, owned) = failure.into_parts();
        AdmitOperationError::new(error, owned)
    })
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
            condition: WaitCondition::JournalClean,
            suspended: self,
        }
    }

    /// Remount routing becomes visible only after every session exclusion has been released.
    fn publish(
        self,
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let result = access.publish_volume_state_transition(transition);
        if result.is_ok() && self.requester.target().terminal() == CleanCloseTerminal::Dismount {
            MountedVolumeDevice::publish_dismount(self.device);
            MountedVolumeDevice::unregister_shutdown_notification(self.device);
            MountedVolumeDevice::complete_dismount(self.device);
        }
        access
            .operational_trace()
            .record_result(OperationalPath::VolumeClose, &result);
        self.complete(owned, result.map(|()| IrpCompletion::EMPTY))
    }

    /// Only a still-authorized session may reopen after cache preparation fails.
    fn fail_preparation(
        self,
        owned: OwnedIrp,
        preparation: PreparedVolumeClose,
        error: DriverError,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        access
            .operational_trace()
            .record_status(OperationalPath::VolumeClose, error.ntstatus());
        record_cache_coherency_failure(error, access);
        access.fail_volume_close_preparation(preparation, error);
        self.complete(owned, Err(error))
    }

    /// Seals admission and preserves the terminal failure without authorizing a clean marker.
    fn fail(
        self,
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        error: DriverError,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        access
            .operational_trace()
            .record_status(OperationalPath::VolumeClose, error.ntstatus());
        record_cache_coherency_failure(error, access);
        access.fail_volume_state_transition(transition, error);
        self.complete(owned, Err(error))
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
            let work = match self.requester.target().terminal() {
                CleanCloseTerminal::Dismount => crate::irp::PassiveWork::CloseWriteback { stream },
                CleanCloseTerminal::Shutdown => crate::irp::PassiveWork::flush(stream),
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
                let preparation = match access.prepare_volume_close(self.requester.target()) {
                    Ok(preparation) => preparation,
                    Err(error) => {
                        trace.record_status(OperationalPath::VolumeClose, error.ntstatus());
                        return self.complete(owned, Err(error));
                    }
                };
                match self.requester {
                    CloseRequester::DismountUnannounced(file) => {
                        self.state = CloseState::Announcing { preparation, close };
                        OperationTransition::SubmitPassiveWork {
                            work: crate::irp::PassiveWork::NotifyVolume { owned, file, event: crate::kernel::volume_event::VolumeEvent::Dismount },
                            suspended: self,
                        }
                    }
                    CloseRequester::Shutdown => self.drain(owned, preparation, close),
                    CloseRequester::DismountAnnounced(_) => crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
                }
            }
            (
                CloseState::Announcing { preparation, close },
                CompletionEvent::PassiveCompleted(
                    crate::irp::PassiveWorkCompletion::NotifyVolume { owned, result },
                ),
            ) => match result {
                Ok(()) => {
                    self.requester = self.requester.announced();
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
                if permit.into_identity() != 1 {
                    return self.fail_preparation(
                        owned,
                        preparation,
                        DriverError::InternalInvariantViolation,
                        access,
                    );
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
                let result = match (self.requester.target().terminal(), completion) {
                    (CleanCloseTerminal::Dismount, crate::irp::PassiveWorkCompletion::CloseWriteback(result))
                    | (CleanCloseTerminal::Shutdown, crate::irp::PassiveWorkCompletion::Flush(result)) => result,
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
                if let Some(exclusion) = exclusion {
                    self.state = CloseState::ReleasingJournal { owned, transition };
                    OperationTransition::SubmitPassiveWork {
                        work: crate::irp::PassiveWork::CloseExternalJournal(exclusion),
                        suspended: self,
                    }
                } else {
                    self.publish(owned, transition, access)
                }
            }
            (
                CloseState::ReleasingJournal { owned, transition },
                CompletionEvent::PassiveCompleted(
                    crate::irp::PassiveWorkCompletion::CloseExternalJournal(result),
                ),
            ) => match result {
                Ok(()) => self.publish(owned, transition, access),
                Err((error, exclusion)) => {
                    access.retain_external_journal_exclusion(exclusion);
                    self.fail(owned, transition, error, access)
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
