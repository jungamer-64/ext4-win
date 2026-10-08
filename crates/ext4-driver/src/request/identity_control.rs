//! Administrator commands use the existing passive worker and retained completion protocol.
use crate::identity::{IdentityCatalog, PreparedIdentityAction};
use crate::irp::reactor::{
    CompletionEvent, CompletionOperation, OperationTransition, ReactorTarget,
};
use crate::irp::{IrpCompletion, OwnedIrp, PassiveWork, PassiveWorkCompletion};
use crate::kernel::status::{DriverError, DriverResult};
use crate::request::operation::AdmitOperationError;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// One ownership phase for an administrative IRP.
#[derive(Debug)]
enum ControlState {
    /// Allocation and output admission precede the first effect.
    Ready {
        /// Retained unique IRP completion authority.
        owned: OwnedIrp,
        /// Fully captured reply or persistence work.
        action: PreparedIdentityAction,
    },
    /// The passive completion envelope retains this operation until the effect finishes.
    Waiting(OwnedIrp),
    /// Terminal ownership has been consumed.
    Terminal,
}
/// Device-scoped operation; it carries no mounted-volume or inode mutation authority.
#[derive(Debug)]
struct IdentityControlOperation {
    /// Operation-owned transition phase.
    state: ControlState,
}

/// Prepares one captured command without losing its unique completion authority on failure.
/// # Errors
/// Returns the still-owned IRP on validation, resource, concurrent-update or output-admission failure.
pub(crate) fn admit(
    mut owned: OwnedIrp,
    catalog: &mut IdentityCatalog,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    let prepared = (|| {
        let mut request = owned.request();
        let capacity = request.with_active(|active| {
            active
                .current_stack()?
                .device_control()
                .map(|stack| stack.output_buffer_length().as_usize())
        })?;
        catalog.prepare(request.take_identity()?, capacity)
    })();
    let action = match prepared {
        Ok(action) => action,
        Err(error) => return Err(AdmitOperationError::new(error, owned)),
    };
    match crate::memory::boxed_try_map((owned, action), |(owned, action)| {
        IdentityControlOperation {
            state: ControlState::Ready { owned, action },
        }
    }) {
        Ok(operation) => Ok(operation),
        Err(error) => {
            let (error, (owned, _action)) = error.into_parts();
            Err(AdmitOperationError::new(error, owned))
        }
    }
}
/// Publishes only the prepared reply prefix into the I/O-manager-owned system buffer.
/// # Errors
/// Propagates a violated native output contract; the saved effect remains observable by query.
fn reply(mut owned: OwnedIrp, bytes: Vec<u8>) -> OperationTransition {
    let result: DriverResult<IrpCompletion> = owned.request().with_active(|active| {
        let extent = active
            .current_stack()?
            .device_control()?
            .output_buffer_length()
            .prefix(bytes.len())?;
        let mut output = active.buffered_output(extent)?;
        crate::memory::copy_exact(output.as_mut_slice(), &bytes)?;
        Ok(IrpCompletion::with_information(
            crate::irp::InformationLength::from_usize(bytes.len())?,
        ))
    });
    OperationTransition::Complete(owned.prepare_result(result))
}
impl CompletionOperation for IdentityControlOperation {
    fn advance(
        mut self: Box<Self>,
        event: CompletionEvent,
        target: &mut ReactorTarget,
    ) -> OperationTransition {
        target.require_control_device();
        let state = core::mem::replace(&mut self.state, ControlState::Terminal);
        match (state, event) {
            (
                ControlState::Ready {
                    owned,
                    action: PreparedIdentityAction::Reply(bytes),
                },
                CompletionEvent::Core(ext4_core::OperationEvent::Admitted),
            ) => reply(owned, bytes),
            (
                ControlState::Ready {
                    owned,
                    action: PreparedIdentityAction::Work(work),
                },
                CompletionEvent::Core(ext4_core::OperationEvent::Admitted),
            ) => {
                self.state = ControlState::Waiting(owned);
                OperationTransition::SubmitPassiveWork {
                    work: PassiveWork::Identity(work),
                    suspended: self,
                }
            }
            (
                ControlState::Ready { owned, .. },
                CompletionEvent::Core(ext4_core::OperationEvent::CancelRequested),
            ) => OperationTransition::Complete(
                owned.prepare_result(Err(DriverError::from(ext4_core::Error::OperationCancelled))),
            ),
            (
                ControlState::Waiting(owned),
                CompletionEvent::PassiveCompleted(PassiveWorkCompletion::Identity(bytes)),
            ) => reply(owned, bytes),
            (ControlState::Ready { owned, .. }, _) => OperationTransition::Complete(
                owned.prepare_result(Err(DriverError::InternalInvariantViolation)),
            ),
            (ControlState::Waiting(_), _) | (ControlState::Terminal, _) => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }
    fn record_storage_failure(
        &mut self,
        _failure: crate::kernel::storage::StorageFailureClass,
        _target: &mut ReactorTarget,
    ) {
        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
            .bugcheck();
    }
}
