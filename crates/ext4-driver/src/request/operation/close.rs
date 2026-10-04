//! Reusable FILE_OBJECT reclamation after the terminal per-handle barrier.
use super::*;
use crate::irp::{FinalizationOperation, FinalizationRequest};

/// The request and barrier phase are a single ownership fact.
#[derive(Debug)]
enum CloseState {
    /// The reactor owns an idle preallocated continuation.
    Dormant,
    /// Prior handle work must finish before contexts can be released.
    Ready(OwnedIrp),
    /// The exact Close barrier retains reclamation authority.
    Waiting(OwnedIrp),
}

/// Sole owner of context reclamation; it has no epoch or mutation admission dependency.
#[derive(Debug)]
struct CloseOperation {
    /// Cleared only after FILE_OBJECT reclamation consumes the terminal barrier.
    state: CloseState,
}

/// Allocates before device publication, so subsequent Close cannot fail allocation.
/// # Errors
/// Returns allocation failure while initialization still owns rollback.
pub(super) fn prepare() -> DriverResult<Box<dyn FinalizationOperation>> {
    memory::boxed_try_with(|| {
        Ok(CloseOperation {
            state: CloseState::Dormant,
        })
    })
    .map(|operation| -> Box<dyn FinalizationOperation> { operation })
}

impl FinalizationOperation for CloseOperation {
    fn activate(mut self: Box<Self>, owned: OwnedIrp) -> Box<dyn CompletionOperation> {
        if !matches!(self.state, CloseState::Dormant) {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        }
        self.state = CloseState::Ready(owned);
        self
    }
    fn kind(&self) -> FinalizationRequest {
        FinalizationRequest::Close
    }
}

impl MountedVolumeOperation for CloseOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, CloseState::Dormant);
        match (state, event) {
            (CloseState::Ready(owned), CompletionEvent::Core(OperationEvent::Admitted)) => {
                self.state = CloseState::Waiting(owned);
                OperationTransition::Wait {
                    condition: WaitCondition::Barrier {
                        identity: CLOSE_HANDLE_BARRIER,
                    },
                    suspended: self,
                }
            }
            (
                CloseState::Waiting(mut owned),
                CompletionEvent::Core(OperationEvent::BarrierReleased(permit)),
            ) => {
                if permit.into_identity() != CLOSE_HANDLE_BARRIER {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                let result = owned
                    .request()
                    .with_active(|active| crate::request::file_info::close(active, access));
                OperationTransition::CompleteFinalization {
                    completion: owned.prepare_result(result),
                    reusable: self,
                }
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
impl_mounted_operation_adapter!(CloseOperation);
