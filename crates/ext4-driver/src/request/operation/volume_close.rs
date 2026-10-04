//! One completion owner drains native caches and paging mutations before clearing recovery.

use super::*;
use crate::memory::DriverVec;
use crate::state::{CleanCloseTerminal, KernelDevice, KernelFileObject, StreamCacheLease};

/// External request selecting the terminal close outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeCloseRequest {
    /// Forced logical dismount from a direct-volume handle.
    Dismount,
    /// System shutdown notification, independent of any user handle.
    Shutdown,
}

/// One-way close phases retain the request until either durable publication or terminal failure.
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
    /// Previously admitted mutations may still publish streams needed by the cache snapshot.
    Draining {
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        close: Box<CleanCloseOperation>,
    },
    /// A native worker writes back one retained stream while paging requests use the actor.
    Writeback {
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
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
    /// Completion or failure consumed the request and its publication authority.
    Terminal,
}

/// Owns completion and terminal publication across native writeback and lower durability I/O.
#[derive(Debug)]
struct VolumeCloseOperation {
    /// Terminal publication and native side effects selected by the original request.
    terminal: CleanCloseTerminal,
    /// Dismount lock ownership, absent for system shutdown.
    owner: Option<KernelFileObject>,
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
    let owner = match kind {
        VolumeCloseRequest::Shutdown => None,
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
            Some(target.owner())
        }
    };
    let profile = access.mounted_profile();
    let close = match memory::boxed_try_with(|| {
        Ok(CleanCloseOperation::new(
            profile.filesystem_length(),
            profile.journal_target(),
        ))
    }) {
        Ok(close) => close,
        Err(error) => return Err(AdmitOperationError::new(error, owned)),
    };
    memory::boxed_try_map(owned, |owned| VolumeCloseOperation {
        terminal: match kind {
            VolumeCloseRequest::Dismount => CleanCloseTerminal::Dismount,
            VolumeCloseRequest::Shutdown => CleanCloseTerminal::Shutdown,
        },
        owner,
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
    /// Seals admission and preserves the terminal failure without authorizing a clean marker.
    fn fail(
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        error: DriverError,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        record_cache_coherency_failure(error, access);
        access.fail_volume_state_transition(transition, error);
        OperationTransition::Complete(owned.prepare_result(Err(error)))
    }

    /// Runs native cache work outside the actor so synchronous paging requests can complete.
    fn writeback(
        mut self: Box<Self>,
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        mut streams: DriverVec<StreamCacheLease>,
        close: Box<CleanCloseOperation>,
        access: &MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Some(stream) = streams.pop() {
            self.state = CloseState::Writeback {
                owned,
                transition,
                streams,
                close,
            };
            OperationTransition::SubmitPassiveWork {
                work: crate::irp::PassiveWork::CloseWriteback { stream },
                suspended: self,
            }
        } else {
            access.seal_close_writeback();
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
            CleanCloseTransition::Complete(Ok(_durability)) => {
                let result = access.publish_volume_state_transition(transition);
                if result.is_ok() && self.terminal == CleanCloseTerminal::Dismount {
                    MountedVolumeDevice::publish_direct_writes_allowed(self.device);
                    MountedVolumeDevice::unregister_shutdown_notification(self.device);
                    MountedVolumeDevice::complete_dismount(self.device);
                }
                OperationTransition::Complete(
                    owned.prepare_result(result.map(|()| IrpCompletion::EMPTY)),
                )
            }
            CleanCloseTransition::Complete(Err(error)) => {
                Self::fail(owned, transition, DriverError::from(error), access)
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
        let state = core::mem::replace(&mut self.state, CloseState::Terminal);
        match (state, event) {
            (
                CloseState::Ready { owned, close },
                CompletionEvent::Core(OperationEvent::Admitted),
            ) => {
                let transition = match access.begin_volume_close(self.terminal, self.owner) {
                    Ok(transition) => transition,
                    Err(error) => {
                        return OperationTransition::Complete(owned.prepare_result(Err(error)));
                    }
                };
                self.state = CloseState::Draining {
                    owned,
                    transition,
                    close,
                };
                OperationTransition::WaitForClosingDrain {
                    condition: WaitCondition::JournalClean,
                    suspended: self,
                }
            }
            (
                CloseState::Ready { owned, .. },
                CompletionEvent::Core(OperationEvent::CancelRequested),
            ) => OperationTransition::Complete(
                owned.prepare_result(Err(DriverError::from(Error::OperationCancelled))),
            ),
            (
                CloseState::Draining {
                    owned,
                    transition,
                    close,
                },
                CompletionEvent::Core(OperationEvent::BarrierReleased(permit)),
            ) => {
                if permit.into_identity() != 1 {
                    return Self::fail(
                        owned,
                        transition,
                        DriverError::InternalInvariantViolation,
                        access,
                    );
                }
                let streams = match access.prepare_close_cache_writeback() {
                    Ok(streams) => streams,
                    Err(error) => return Self::fail(owned, transition, error, access),
                };
                self.writeback(owned, transition, streams, close, access)
            }
            (
                CloseState::Writeback {
                    owned,
                    transition,
                    streams,
                    close,
                },
                CompletionEvent::PassiveCompleted(
                    crate::irp::PassiveWorkCompletion::CloseWriteback(result),
                ),
            ) => match result {
                Ok(()) => self.writeback(owned, transition, streams, close, access),
                Err(error) => Self::fail(owned, transition, error, access),
            },
            (
                CloseState::Sealed {
                    owned,
                    transition,
                    close,
                },
                CompletionEvent::Core(OperationEvent::BarrierReleased(permit)),
            ) => {
                if permit.into_identity() != 1 {
                    return Self::fail(
                        owned,
                        transition,
                        DriverError::InternalInvariantViolation,
                        access,
                    );
                }
                self.drive(
                    owned,
                    transition,
                    close.advance(OperationEvent::Admitted),
                    access,
                )
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
                CloseState::Draining {
                    owned, transition, ..
                }
                | CloseState::Sealed {
                    owned, transition, ..
                },
                CompletionEvent::VolumeFailed(error),
            ) => Self::fail(owned, transition, error, access),
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
