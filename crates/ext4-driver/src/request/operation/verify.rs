//! Kernel verify IRPs retain their VPB association while an independent physical read runs.

use super::*;
use ext4_core::{MediaVerificationOperation, MediaVerificationOutcome, MediaVerificationTransition};

/// One raw observation and original association move together through lower completion.
#[derive(Debug)]
enum VerifyState {
    /// Original IRP retains both native identities without retaining a VPB or actor borrow.
    Reading {
        /// Unique upper completion ownership, including cancel and resource release.
        owned: OwnedIrp,
        /// Sole acknowledgment authority for the exact mounted association.
        association: crate::state::MediaVerificationAssociation,
        /// Fresh physical transcript independent from mounted caches and overlays.
        probe: Box<MediaVerificationOperation>,
    },
    /// Final completion consumed all authority.
    Terminal,
}

/// A verify request cannot widen a failed mount's admission or issue recovery writes.
#[derive(Debug)]
struct VerifyOperation {
    /// Stable lower route from the original mounted runtime.
    devices: MountedStorageRoute,
    /// Consuming read and association ownership phase.
    state: VerifyState,
}

/// Allocates a kernel-captured verify without losing the original upper IRP on failure.
/// # Errors
/// Returns foreign/withdrawn association or allocation failure with the still-owned IRP.
pub(crate) fn verify_volume(owned: OwnedIrp, target: crate::irp::VerifyVolumeTarget, access: &MountedVolumeAccess<'_>) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    let prepared = (|| {
        let association = crate::state::MountedVolumeDevice::prepare_media_verification(target)?;
        let probe = memory::boxed_try_with(|| Ok(access.mounted_profile().verify_media()))?;
        Ok::<_, DriverError>((association, probe))
    })();
    let (association, probe) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return Err(AdmitOperationError::new(error, owned)),
    };
    let devices = access.storage_route();
    match memory::boxed_try_map((owned, association, probe), |(owned, association, probe)| VerifyOperation {
        devices, state: VerifyState::Reading { owned, association, probe },
    }) {
        Ok(operation) => Ok(operation),
        Err(error) => {
            let (error, (owned, _association, _probe)) = error.into_parts();
            Err(AdmitOperationError::new(error, owned))
        }
    }
}

impl MountedVolumeOperation for VerifyOperation {
    fn advance_mounted(mut self: Box<Self>, event: CompletionEvent, access: &mut MountedVolumeAccess<'_>) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, VerifyState::Terminal);
        let VerifyState::Reading { owned, association, probe } = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        match probe.advance(event.into_core()) {
            MediaVerificationTransition::SubmitLower { request, suspended } => {
                self.state = VerifyState::Reading { owned, association, probe: suspended };
                OperationTransition::SubmitVerificationRead { devices: self.devices, request, suspended: self }
            }
            MediaVerificationTransition::Complete(result) => {
                let result = match result {
                    Ok(MediaVerificationOutcome::Same) => match association.acknowledge() {
                        Ok(()) => Ok(IrpCompletion::EMPTY),
                        Err(error) => { access.record_media_changed(); Err(error) }
                    },
                    Ok(MediaVerificationOutcome::Different | MediaVerificationOutcome::Invalid(_)) => {
                        access.record_media_changed();
                        Err(DriverError::WrongVolume)
                    }
                    // Failed or canceled reads never consume native verify acknowledgment.
                    Err(error) => Err(DriverError::from(error)),
                };
                OperationTransition::Complete(owned.prepare_result(result))
            }
        }
    }

    fn record_mounted_storage_failure(&mut self, failure: StorageFailureClass, access: &mut MountedVolumeAccess<'_>) {
        match failure {
            StorageFailureClass::ReadUnreliable => access.record_read_unreliable(),
            StorageFailureClass::Terminal => {},
            StorageFailureClass::DurabilityUnknown { .. } => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
        }
    }
}

#[expect(unsafe_code, reason = "the pending kernel verify IRP retains both native identities until its sole completion")]
// SAFETY: No VPB, actor or cache borrow crosses lower submission. Scalar native identities remain
// live through the original I/O Manager IRP, and only the owning reactor advances the operation.
unsafe impl Send for VerifyOperation {}

impl_mounted_operation_adapter!(VerifyOperation);

/// The original request stays captured while an I/O Manager verify may reenter this actor.
#[derive(Debug)]
enum VerifyAdmissionState {
    /// No filesystem operation or handle lane has been admitted.
    Ready { owned: OwnedIrp, query: crate::kernel::volume_verify::VerificationDevice },
    /// The worker owns only the real-device reference; captures remain local.
    Waiting(OwnedIrp),
    /// Completion or re-admission consumed the original request.
    Terminal,
}

/// A finite preflight gate runs before any cache, inode or mutation work.
#[derive(Debug)]
struct VerifyAdmissionOperation { state: VerifyAdmissionState }

/// Retains captures through one native verify before the shell classifies normal admission.
/// # Errors
/// Returns allocation failure with original IRP completion authority retained.
pub(crate) fn verify_before_admission(owned: OwnedIrp, query: crate::kernel::volume_verify::VerificationDevice) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    match memory::boxed_try_map((owned, query), |(owned, query)| VerifyAdmissionOperation { state: VerifyAdmissionState::Ready { owned, query } }) {
        Ok(operation) => Ok(operation),
        Err(error) => {
            let (error, (owned, _query)) = error.into_parts();
            Err(AdmitOperationError::new(error, owned))
        }
    }
}

impl MountedVolumeOperation for VerifyAdmissionOperation {
    fn advance_mounted(mut self: Box<Self>, event: CompletionEvent, _access: &mut MountedVolumeAccess<'_>) -> OperationTransition {
        match (core::mem::replace(&mut self.state, VerifyAdmissionState::Terminal), event) {
            (VerifyAdmissionState::Ready { owned, query }, CompletionEvent::Core(OperationEvent::Admitted)) => {
                self.state = VerifyAdmissionState::Waiting(owned);
                OperationTransition::SubmitPassiveWork { work: crate::irp::PassiveWork::VerifyVolume(query), suspended: self }
            }
            (VerifyAdmissionState::Ready { owned, .. }, CompletionEvent::Core(OperationEvent::CancelRequested)) => {
                OperationTransition::Complete(owned.prepare_result(Err(DriverError::from(Error::OperationCancelled))))
            }
            (VerifyAdmissionState::Waiting(owned), CompletionEvent::PassiveCompleted(crate::irp::PassiveWorkCompletion::VerifyVolume(Ok(())))) => {
                OperationTransition::ReadmitCaptured { owned }
            }
            (VerifyAdmissionState::Waiting(owned), CompletionEvent::PassiveCompleted(crate::irp::PassiveWorkCompletion::VerifyVolume(Err(error)))) => {
                OperationTransition::Complete(owned.prepare_result(Err(error)))
            }
            _ => crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
        }
    }
    fn record_mounted_storage_failure(&mut self, _failure: StorageFailureClass, _access: &mut MountedVolumeAccess<'_>) {
        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    }
}
impl_mounted_operation_adapter!(VerifyAdmissionOperation);
