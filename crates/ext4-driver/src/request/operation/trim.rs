//! Administrative free-space discard stays joined to its physical completion and volume actor.
use super::*;
use crate::irp::reactor::TRIM_ADMISSION_BARRIER;
use ext4_core::{
    TrimAdmission, TrimCursor, TrimFailure, TrimIoOutcome, TrimScanOperation, TrimScanTransition,
    TrimSelection,
};

/// The actor retains either a user's reply obligation or a policy-owned cycle completion.
#[derive(Debug)]
enum TrimOwner {
    /// The privileged request owns its original file object, cancellation and progress reply.
    Manual(OwnedIrp),
    /// The mounted policy owner must observe completion before admitting another cycle.
    Automatic(crate::state::AutomaticTrimRun),
}
impl TrimOwner {
    /// Revalidates only the authority appropriate to this operation's actual owner.
    /// # Errors
    /// Returns stale lifecycle, handle, write-policy or physical ownership failure.
    fn authorize(&mut self, access: &MountedVolumeAccess<'_>) -> DriverResult<()> {
        match self {
            Self::Manual(owned) => TrimOperation::authorize_manual(owned, access),
            Self::Automatic(_) => access.authorize_automatic_trim(),
        }
    }
}

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
        TrimOperation::authorize_manual(&mut owned, access)?;
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
        state: TrimState::Ready(TrimOwner::Manual(owned)),
    })
    .map(|operation| -> Box<dyn CompletionOperation> { operation })
    .map_err(|failure| {
        let (error, owned) = failure.into_parts();
        AdmitOperationError::new(error, owned)
    })
}

/// Allocates only after ordinary scheduler capacity exists; failure ends this mount's schedule.
/// No fabricated IRP, user privilege or top-level notification owner participates in this path.
/// # Errors
/// Reports pre-effect preparation failure after returning the cycle to its mounted owner.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "unit tests compile the production admission path; its sole caller is the native reactor thread"
    )
)]
pub(crate) fn automatic_trim(
    access: &mut MountedVolumeAccess<'_>,
) -> DriverResult<Option<Box<dyn CompletionOperation>>> {
    let Some(run) = access.start_automatic_trim() else {
        return Ok(None);
    };
    let prepared = (|| -> DriverResult<_> {
        access.authorize_automatic_trim()?;
        let epoch = access.acquire_epoch()?;
        Ok((
            epoch.epoch().identity().uuid(),
            access.storage_route().trim_alignment()?,
        ))
    })();
    let (uuid, alignment) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            access.complete_automatic_trim(run, ext4_control::TrimOutcome::Failed);
            return Err(error);
        }
    };
    match memory::boxed_try_map(run, |run| TrimOperation {
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
        state: TrimState::Ready(TrimOwner::Automatic(run)),
    }) {
        Ok(operation) => Ok(Some(operation)),
        Err(failure) => {
            let (error, run) = failure.into_parts();
            access.complete_automatic_trim(run, ext4_control::TrimOutcome::Failed);
            Err(error)
        }
    }
}

impl TrimOperation {
    /// Existing handles retain rights, but no snapshot restores revoked media or closed admission.
    /// # Errors
    /// Returns handle, lifecycle, write-protection or physical-ownership failure.
    fn authorize_manual(
        owned: &mut OwnedIrp,
        access: &MountedVolumeAccess<'_>,
    ) -> DriverResult<()> {
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
    fn finish(
        self: Box<Self>,
        owned: TrimOwner,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let mut owned = match owned {
            TrimOwner::Manual(owned) => owned,
            TrimOwner::Automatic(run) => {
                access.complete_automatic_trim(run, self.report.outcome);
                return OperationTransition::Retired;
            }
        };
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
    fn fail(
        mut self: Box<Self>,
        owned: TrimOwner,
        error: DriverError,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        self.report.outcome = if error == DriverError::Core(Error::OperationCancelled) {
            ext4_control::TrimOutcome::Cancelled
        } else {
            ext4_control::TrimOutcome::Failed
        };
        self.report.status = error.ntstatus();
        self.finish(owned, access)
    }

    /// Yields without holding a reservation or journal grant between bounded batches or restarts.
    fn defer(mut self: Box<Self>, owned: TrimOwner) -> OperationTransition {
        self.state = TrimState::Ready(owned);
        OperationTransition::DeferOperation { suspended: self }
    }

    /// A concrete admission event resumes this operation; there is no polling work item.
    fn wait(
        mut self: Box<Self>,
        owned: TrimOwner,
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
        mut owned: TrimOwner,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Err(error) = owned.authorize(access) {
            return self.fail(owned, error, access);
        }
        if self.cursor.is_complete() {
            return self.finish(owned, access);
        }
        match access.trim_ready() {
            Ok(false) => return self.wait(owned, None),
            Err(error) => return self.fail(owned, error, access),
            Ok(true) => {}
        }
        let scan = TrimScanOperation::new(access.mounted_profile(), self.cursor, self.alignment);
        self.scan(owned, scan, OperationEvent::Admitted, access)
    }

    /// No bitmap can be carried into a different epoch; restart occurs before any physical effect.
    fn scan(
        mut self: Box<Self>,
        mut owned: TrimOwner,
        scan: TrimScanOperation,
        event: OperationEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Err(error) = owned.authorize(access) {
            return self.fail(owned, error, access);
        }
        let step = access.with_metadata_cache(|cache, access| {
            access
                .committed_read(cache)
                .map(|context| scan.advance(event, context))
        });
        match step {
            Err(error) => self.fail(owned, error, access),
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
            Ok(TrimScanTransition::Complete(Err(error))) => self.fail(owned, error.into(), access),
        }
    }

    /// Reservation happens after the scan, immediately before transferring the physical request.
    fn admit(
        mut self: Box<Self>,
        mut owned: TrimOwner,
        selection: TrimSelection,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Err(error) = owned.authorize(access) {
            return self.fail(owned, error, access);
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
                    self.finish(owned, access)
                } else {
                    self.defer(owned)
                }
            }
            Err(DriverError::Core(Error::StaleReadContext)) => self.defer(owned),
            Err(error) => self.fail(owned, error, access),
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
            ) => self.fail(owned, Error::OperationCancelled.into(), access),
            (TrimState::Waiting { owned, .. }, CompletionEvent::VolumeFailed(error)) => {
                self.fail(owned, error, access)
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
                        if let Err(error) = owned.authorize(access) {
                            return self.fail(owned, error, access);
                        }
                        if result.next.is_complete() {
                            self.finish(owned, access)
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
                        self.finish(owned, access)
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
