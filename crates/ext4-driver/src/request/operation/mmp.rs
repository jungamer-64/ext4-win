//! Core ownership continuations run on the mounted actor without top-level IRP or journal grants.
use super::*;

impl MountedVolumeOperation for ext4_core::MmpOperation {
    fn advance_mounted(
        self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let event = match event {
            CompletionEvent::Core(OperationEvent::Admitted) => ext4_core::MmpEvent::Start,
            CompletionEvent::Core(OperationEvent::StorageCompleted(completion)) => {
                ext4_core::MmpEvent::StorageCompleted(completion)
            }
            CompletionEvent::Core(OperationEvent::TimerElapsed) => ext4_core::MmpEvent::Elapsed,
            CompletionEvent::Core(OperationEvent::CancelRequested) => ext4_core::MmpEvent::Cancel,
            _ => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        };
        let now = match crate::kernel::time::mmp_time() {
            Ok(now) => now,
            Err(_error) => {
                access.fail_mmp(Error::InvalidTimestamp);
                return OperationTransition::Retired;
            }
        };
        match ext4_core::MmpOperation::advance(self, event, now) {
            ext4_core::MmpTransition::SubmitLower { request, suspended } => {
                OperationTransition::SubmitOwnershipLower {
                    devices: access.storage_route(),
                    request,
                    suspended,
                }
            }
            ext4_core::MmpTransition::Wait { seconds, suspended } => {
                OperationTransition::WaitForTimer { seconds, suspended }
            }
            ext4_core::MmpTransition::Complete(Ok(completion)) => {
                // Completion acceptance records and fences every rejected successor itself.
                match access.complete_mmp_action(completion) {
                    Ok(()) | Err(DriverError::Core(Error::MmpOwnershipLost)) => {}
                    Err(_error) => crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
                }
                OperationTransition::Retired
            }
            ext4_core::MmpTransition::Complete(Err(failure)) => {
                // Every effect class retires this session. No failure permits retry or a
                // compensating clean marker; a fresh mount observes ownership and recovers media.
                access.fail_mmp(failure.reason);
                OperationTransition::Retired
            }
        }
    }
    fn record_mounted_storage_failure(
        &mut self,
        _failure: StorageFailureClass,
        _access: &mut MountedVolumeAccess<'_>,
    ) {
        // The owned core completion is the failure observer. Ownership requests never enter
        // reactor storage retry, and this same actor step consumes their exact transfer outcome.
    }
}
impl_mounted_operation_adapter!(ext4_core::MmpOperation);
