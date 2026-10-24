//! Administrative free-space discard stays joined to its physical completion and volume actor.
use super::*;
use crate::irp::reactor::TRIM_ADMISSION_BARRIER;
use ext4_core::{
    TrimAdmission, TrimCursor, TrimFailure, TrimIoOutcome, TrimScanOperation, TrimScanTransition,
    TrimSelection,
};

/// Exact owner of the current read, reservation wait or physical discard completion.
#[derive(Debug)]
enum TrimState {
    /// No physical effect remains; a scheduler yield may admit a fresh bounded batch.
    Ready(TrimOwner),
    /// Metadata read owns a write-free free-space scan.
    Scanning {
        /// Retains the reply buffer and file object across metadata reads.
        owned: TrimOwner,
        /// Pins one metadata epoch; a changed epoch forces a fresh scan.
        scan: TrimScanOperation,
    },
    /// Journal or another discard still occupies admission; a stale selection will be rescanned.
    Waiting {
        /// Retains upper notification authority while no discard lease exists.
        owned: TrimOwner,
        /// A retained selection must be revalidated when admission becomes available.
        selection: Option<TrimSelection>,
    },
    /// Neither cancellation nor media revocation can drop this physical completion obligation.
    InFlight {
        /// Reply delivery must wait for the lower command's physical completion.
        owned: TrimOwner,
        /// Only the matching completion releases allocation exclusions, including after revocation.
        pending: ext4_core::PendingTrim,
    },
    /// The operation consumed its upper notification authority.
    Terminal,
}

/// One upper request owns a complete scan; each lower command remains independently bounded.
#[derive(Debug)]
struct TrimOperation {
    /// Stable lower route retained by the mounted actor's lifetime.
    devices: MountedStorageRoute,
    /// Fixed device block granularity for inward-only free-space projection.
    alignment: ext4_core::TrimAlignment,
    /// Progress observation grants no permission to skip fresh allocation validation.
    cursor: TrimCursor,
    /// Preallocated administrative progress; physical errors do not hide completed prefixes.
    report: ext4_control::TrimReport,
    /// Unique current continuation and upper request.
    state: TrimState,
}

/// Captures privilege, buffer and writable volume authority before any metadata or device effect.
/// # Errors
/// Returns the unchanged upper request on malformed input, denied authority or allocation failure.
pub(crate) fn trim(
    mut owned: OwnedIrp,
    access: &mut MountedVolumeAccess<'_>,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    let prepared = (|| -> DriverResult<_> {
        if !matches!(
            owned.actor_request(),
            crate::irp::ActorRequest::Captured(crate::irp::PreparedRequest::Trim)
        ) {
            return Err(DriverError::AccessDenied);
        }
        TrimOperation::authorize(&mut owned, access)?;
        owned.request().with_active(|active| {
            let control = active.current_stack()?.file_system_control()?;
            if !control.input_buffer_length().is_empty() {
                return Err(DriverError::InvalidParameter);
            }
            active.buffered_output(
                control
                    .output_buffer_length()
                    .prefix(ext4_control::TRIM_REPLY_BYTES)?,
            )?;
            Ok(())
        })?;
        let epoch = access.acquire_epoch()?;
        Ok((
            epoch.epoch().identity().uuid(),
            access.storage_route().trim_alignment()?,
        ))
    })();
    let (uuid, alignment) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return Err(AdmitOperationError::new(error, owned)),
    };
    memory::boxed_try_map(owned, |owned| TrimOperation {
        devices: access.storage_route(),
        alignment,
        cursor: TrimCursor::start(),
        report: ext4_control::TrimReport {
            uuid,
            outcome: ext4_control::TrimOutcome::Complete,
            status: 0,
            acknowledged_bytes: 0,
            uncertain_bytes: 0,
        },
        state: TrimState::Ready(owned),
    })
    .map(|operation| -> Box<dyn CompletionOperation> { operation })
    .map_err(|failure| {
        let (error, owned) = failure.into_parts();
        AdmitOperationError::new(error, owned)
    })
}

impl TrimOperation {
    /// Existing handles retain rights, but no snapshot restores revoked media or closed admission.
    /// # Errors
    /// Returns handle, lifecycle, write-protection or physical-ownership failure.
    fn authorize(owned: &mut OwnedIrp, access: &MountedVolumeAccess<'_>) -> DriverResult<()> {
        if access.mounted_profile().access() != ext4_core::MediaAccess::ReadWrite {
            return Err(Error::ReadOnlyFilesystem.into());
        }
        crate::request::file_system_control::authorize_path_handle(&mut owned.request(), access)?;
        owned.request().with_active(|active| {
            let opened =
                crate::state::OpenedVolume::decode(active.current_stack()?.file_object()?)?;
            opened.require_data_write()
        })?;
        access.trim_ready().map(|_ready| ())
    }

    /// Publishes the fixed progress reply, including stopped scans, through successful transport.
    /// Buffer size and identity were established before effects; losing them is kernel corruption.
    fn finish(self: Box<Self>, mut owned: OwnedIrp) -> OperationTransition {
        let bytes = self.report.encode();
        let copied: DriverResult<IrpCompletion> = owned.request().with_active(|active| {
            let control = active.current_stack()?.file_system_control()?;
            let output = active.buffered_output(
                control
                    .output_buffer_length()
                    .prefix(ext4_control::TRIM_REPLY_BYTES)?,
            )?;
            memory::copy_exact(output, &bytes)?;
            Ok(IrpCompletion::with_information(
                crate::irp::InformationLength::from_usize(ext4_control::TRIM_REPLY_BYTES)?,
            ))
        });
        let completion = match copied {
            Ok(completion) => completion,
            Err(_error) => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        };
        OperationTransition::Complete(owned.prepare_completion(completion))
    }

    /// Stops with every acknowledged prefix intact; no failure implicitly retries a physical batch.
    fn fail(mut self: Box<Self>, owned: OwnedIrp, error: DriverError) -> OperationTransition {
        self.report.outcome = if error == DriverError::Core(Error::OperationCancelled) {
            ext4_control::TrimOutcome::Cancelled
        } else {
            ext4_control::TrimOutcome::Failed
        };
        self.report.status = error.ntstatus();
        self.finish(owned)
    }

    /// Yields without holding a reservation or journal grant between bounded batches or restarts.
    fn defer(mut self: Box<Self>, owned: OwnedIrp) -> OperationTransition {
        self.state = TrimState::Ready(owned);
        OperationTransition::DeferOperation { suspended: self }
    }

    /// A concrete admission event resumes this operation; there is no polling work item.
    fn wait(
        mut self: Box<Self>,
        owned: OwnedIrp,
        selection: Option<TrimSelection>,
    ) -> OperationTransition {
        self.state = TrimState::Waiting { owned, selection };
        OperationTransition::Wait {
            condition: WaitCondition::TrimAvailable,
            suspended: self,
        }
    }

    /// Starts one write-free metadata segment only while current checkpointed admission is possible.
    fn ready(
        self: Box<Self>,
        mut owned: OwnedIrp,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Err(error) = Self::authorize(&mut owned, access) {
            return self.fail(owned, error);
        }
        if self.cursor.is_complete() {
            return self.finish(owned);
        }
        match access.trim_ready() {
            Ok(false) => return self.wait(owned, None),
            Err(error) => return self.fail(owned, error),
            Ok(true) => {}
        }
        let scan = TrimScanOperation::new(access.mounted_profile(), self.cursor, self.alignment);
        self.scan(owned, scan, OperationEvent::Admitted, access)
    }

    /// No bitmap can be carried into a different epoch; restart occurs before any physical effect.
    fn scan(
        mut self: Box<Self>,
        mut owned: OwnedIrp,
        scan: TrimScanOperation,
        event: OperationEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Err(error) = Self::authorize(&mut owned, access) {
            return self.fail(owned, error);
        }
        let step = access.with_metadata_cache(|cache, access| {
            access
                .committed_read(cache)
                .map(|context| scan.advance(event, context))
        });
        match step {
            Err(error) => self.fail(owned, error),
            Ok(TrimScanTransition::SubmitLower { request, suspended }) => {
                self.state = TrimState::Scanning {
                    owned,
                    scan: suspended,
                };
                OperationTransition::SubmitLower {
                    devices: self.devices,
                    request,
                    suspended: self,
                }
            }
            Ok(TrimScanTransition::Complete(Ok(selection))) => self.admit(owned, selection, access),
            Ok(TrimScanTransition::Complete(Err(Error::StaleReadContext))) => self.defer(owned),
            Ok(TrimScanTransition::Complete(Err(error))) => self.fail(owned, error.into()),
        }
    }

    /// Reservation happens after the scan, immediately before transferring the physical request.
    fn admit(
        mut self: Box<Self>,
        mut owned: OwnedIrp,
        selection: TrimSelection,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Err(error) = Self::authorize(&mut owned, access) {
            return self.fail(owned, error);
        }
        match access.reserve_trim(selection) {
            Ok(TrimAdmission::Prepared(batch)) => {
                let (request, pending) = batch.submit();
                self.state = TrimState::InFlight { owned, pending };
                OperationTransition::SubmitTrim {
                    devices: self.devices,
                    request,
                    suspended: self,
                }
            }
            Ok(TrimAdmission::Waiting(selection)) => self.wait(owned, Some(selection)),
            Ok(TrimAdmission::Advanced(next)) => {
                self.cursor = next;
                if next.is_complete() {
                    self.finish(owned)
                } else {
                    self.defer(owned)
                }
            }
            Err(DriverError::Core(Error::StaleReadContext)) => self.defer(owned),
            Err(error) => self.fail(owned, error),
        }
    }
}

impl MountedVolumeOperation for TrimOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, TrimState::Terminal);
        match (state, event) {
            (TrimState::Ready(owned), CompletionEvent::Core(OperationEvent::Admitted)) => {
                self.ready(owned, access)
            }
            (TrimState::Scanning { owned, scan }, CompletionEvent::Core(event)) => {
                self.scan(owned, scan, event, access)
            }
            (TrimState::Waiting { owned, selection }, CompletionEvent::BarrierReleased(permit)) => {
                if permit.into_identity() != TRIM_ADMISSION_BARRIER {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                match selection {
                    Some(selection) => self.admit(owned, selection, access),
                    None => self.ready(owned, access),
                }
            }
            (
                TrimState::Ready(owned) | TrimState::Waiting { owned, .. },
                CompletionEvent::Core(OperationEvent::CancelRequested),
            ) => self.fail(owned, Error::OperationCancelled.into()),
            (TrimState::Waiting { owned, .. }, CompletionEvent::VolumeFailed(error)) => {
                self.fail(owned, error)
            }
            (
                TrimState::InFlight { mut owned, pending },
                CompletionEvent::TrimCompleted { completion, status },
            ) => {
                let result = match access.complete_trim(pending, completion) {
                    Ok(result) => result,
                    Err(_mismatch) => crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
                };
                self.cursor = result.next;
                match result.outcome {
                    TrimIoOutcome::Acknowledged => {
                        self.report.acknowledged_bytes = self.report.acknowledged_bytes.checked_add(result.requested_bytes).unwrap_or_else(|| crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck());
                        if let Err(error) = Self::authorize(&mut owned, access) {
                            return self.fail(owned, error);
                        }
                        if result.next.is_complete() {
                            self.finish(owned)
                        } else {
                            self.defer(owned)
                        }
                    }
                    outcome @ (TrimIoOutcome::Unsubmitted(_) | TrimIoOutcome::Uncertain(_)) => {
                        let reason = match outcome {
                            TrimIoOutcome::Unsubmitted(reason) => reason,
                            TrimIoOutcome::Uncertain(reason) => { self.report.uncertain_bytes = result.requested_bytes; reason }
                            TrimIoOutcome::Acknowledged => crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
                        };
                        self.report.status = status;
                        self.report.outcome = match reason {
                            TrimFailure::Unsupported => ext4_control::TrimOutcome::Unsupported,
                            TrimFailure::Cancelled => ext4_control::TrimOutcome::Cancelled,
                            TrimFailure::Failed(_) => ext4_control::TrimOutcome::Failed,
                        };
                        self.finish(owned)
                    }
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
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    ) {
        // This observer belongs only to metadata reads. Effect-bearing DSM has its own owned outcome.
        if failure == StorageFailureClass::ReadUnreliable {
            access.record_read_unreliable();
        }
    }
}
impl_mounted_operation_adapter!(TrimOperation);
