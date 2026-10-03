//! Cache Manager MDL requests retain completion ownership until the worker returns.

use super::*;
use crate::irp::{
    DataIoKind, MdlTransfer, PassiveWork, PassiveWorkCompletion, ReadStartingPoint,
    WriteStartingPoint,
};
use crate::state::{DataTransferMode, OpenedRegularFile};

/// Each native effect runs exactly once, including consuming completion notifications.
#[derive(Debug)]
enum MdlState {
    /// FsRtl must break a handle oplock before pages may be exposed.
    Checking {
        /// Unique IRP authority before FsRtl delegation.
        owned: OwnedIrp,
        /// Stream retained through the break check.
        check: OplockCheck,
    },
    /// FsRtl owns the IRP and will return it through its completion callback.
    Delegated,
    /// FsRtl returned sole completion authority and its exact result.
    Returned {
        /// Unique IRP authority returned by the external completion callback.
        owned: OwnedIrp,
        /// Native break outcome that gates subsequent page acquisition.
        status: wdk_sys::NTSTATUS,
    },
    /// The request has not crossed a Cache Manager effect boundary.
    Ready(OwnedIrp),
    /// The worker owns the MDL operation; cancellation cannot discard its result or chain.
    Executing {
        /// IRP and its handle lane retained until native effect completion.
        owned: OwnedIrp,
        /// Completion notifications never publish a user data cursor.
        cursor: MdlCursor,
    },
    /// Top-level completion ownership was consumed.
    Terminal,
}

#[derive(Debug)]
/// One consuming Cache Manager operation advanced by the reactor and its passive worker.
struct MdlOperation {
    /// Exact read or write page-acquisition protocol.
    action: MdlTransfer,
    /// Unique completion authority remains local while cache work borrows the native IRP.
    state: MdlState,
}

/// Cursor publication authority exists only for a validated data-page acquisition.
#[derive(Debug)]
struct MdlCursor {
    /// Start of the acquired interval.
    start: ext4_core::FileOffset,
    /// Maximum native transfer selected from the IRP.
    requested: usize,
}

/// Admits an MDL operation without interpreting its chain as an ordinary byte mapping.
/// # Errors
///
/// Returns the still-owned IRP if allocation fails.
pub(crate) fn mdl(
    mut owned: OwnedIrp,
    action: MdlTransfer,
    access: &MountedVolumeAccess<'_>,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    let check = match owned.request().with_active(|active| {
        access
            .acquire_oplock_stream_lease(active.current_stack()?.file_object()?)
            .map(OplockCheck::ordinary)
    }) {
        Ok(check) => check,
        Err(error) => return Err(AdmitOperationError::new(error, owned)),
    };
    memory::boxed_try_map(owned, |owned| MdlOperation {
        action,
        state: MdlState::Checking { owned, check },
    })
    .map(|operation| -> Box<dyn CompletionOperation> { operation })
    .map_err(|error| {
        let (error, owned) = error.into_parts();
        AdmitOperationError::new(error, owned)
    })
}

impl MdlOperation {
    /// Establishes stream lifetime and access before submitting a native page acquisition.
    /// # Errors
    ///
    /// Rejects direct/paging transfers, invalid ranges and conflicting byte locks before Cc runs.
    fn prepare(
        &self,
        owned: &mut OwnedIrp,
        access: &MountedVolumeAccess<'_>,
    ) -> DriverResult<(PassiveWork, MdlCursor)> {
        owned.request().with_active(|active| {
            let current = active.current_stack()?;
            let file_object = current.file_object()?;
            let lease = access.acquire_file_object_cache_lease(file_object)?;
            access.ensure_mounted()?;
            if active.data_io_kind() != DataIoKind::Handle {
                return Err(DriverError::InvalidParameter);
            }
            let opened = OpenedRegularFile::decode(file_object)?;
            if matches!(opened.data_transfer_mode(), DataTransferMode::Direct(_)) {
                return Err(DriverError::InvalidParameter);
            }
            let (start, length, key) = match self.action {
                MdlTransfer::Read => {
                    let stack = current.read()?;
                    let ReadStartingPoint::Absolute(start) = stack.starting_point() else {
                        return Err(DriverError::InvalidParameter);
                    };
                    (start, stack.length().as_usize(), stack.key())
                }
                MdlTransfer::Write => {
                    let stack = current.write()?;
                    let WriteStartingPoint::Absolute(start) = stack.starting_point() else {
                        return Err(DriverError::InvalidParameter);
                    };
                    if opened.write_access() != crate::irp::RegularFileWriteAccess::Positional {
                        return Err(DriverError::AccessDenied);
                    }
                    (start, stack.length().as_usize(), stack.key())
                }
            };
            start.checked_add_len(length)?;
            // Validate the largest cursor publication before any page ownership changes.
            let _position =
                opened.prepare_current_file_position_update(DataIoKind::Handle, start, length)?;
            let permits = if self.action == MdlTransfer::Read {
                opened.file_control_block().permits_byte_range_read(
                    active.requestor_process()?,
                    opened.file_object(),
                    start,
                    length,
                    key,
                )?
            } else {
                opened.file_control_block().permits_byte_range_write(
                    active.requestor_process()?,
                    opened.file_object(),
                    start,
                    length,
                    key,
                )?
            };
            if !permits {
                return Err(DriverError::FileLockConflict);
            }
            let cursor = MdlCursor {
                start,
                requested: length,
            };
            Ok((PassiveWork::mdl(lease, active, self.action), cursor))
        })
    }
}

impl MountedVolumeOperation for MdlOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        match (
            core::mem::replace(&mut self.state, MdlState::Terminal),
            event,
        ) {
            (
                MdlState::Checking { owned, check },
                CompletionEvent::Core(OperationEvent::Admitted),
            ) => {
                self.state = MdlState::Delegated;
                OperationTransition::CheckOplock {
                    check,
                    owned,
                    suspended: self,
                }
            }
            (
                MdlState::Returned { owned, status },
                CompletionEvent::Core(OperationEvent::Admitted),
            ) => {
                if status < STATUS_SUCCESS {
                    return OperationTransition::Complete(
                        owned.prepare_result(Err(DriverError::OplockFailure(status))),
                    );
                }
                self.state = MdlState::Ready(owned);
                self.advance_mounted(CompletionEvent::Core(OperationEvent::Admitted), access)
            }
            (MdlState::Ready(mut owned), CompletionEvent::Core(OperationEvent::Admitted)) => {
                let (work, cursor) = match self.prepare(&mut owned, access) {
                    Ok(work) => work,
                    Err(error) => {
                        return OperationTransition::Complete(owned.prepare_result(Err(error)));
                    }
                };
                self.state = MdlState::Executing { owned, cursor };
                OperationTransition::SubmitPassiveWork {
                    work,
                    suspended: self,
                }
            }
            (
                MdlState::Ready(owned)
                | MdlState::Checking { owned, .. }
                | MdlState::Returned { owned, .. }
                | MdlState::Executing { owned, .. },
                CompletionEvent::Core(OperationEvent::CancelRequested),
            ) => OperationTransition::Complete(
                owned.prepare_result(Err(DriverError::from(Error::OperationCancelled))),
            ),
            (
                MdlState::Executing { mut owned, cursor },
                CompletionEvent::PassiveCompleted(PassiveWorkCompletion::Mdl(result)),
            ) => {
                let MdlCursor { start, requested } = cursor;
                let result = crate::request::file_info::finish_cached_read(
                    owned.request(),
                    start,
                    requested,
                    result,
                );
                OperationTransition::Complete(owned.prepare_result(result))
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

impl OplockContinuation for MdlOperation {
    fn resume_after_oplock(
        mut self: Box<Self>,
        owned: OwnedIrp,
        status: wdk_sys::NTSTATUS,
    ) -> Box<dyn CompletionOperation> {
        if !matches!(self.state, MdlState::Delegated) {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        }
        self.state = MdlState::Returned { owned, status };
        self
    }
}

#[expect(
    unsafe_code,
    reason = "the reactor retains unique IRP authority and the worker borrows it only while suspended"
)]
// SAFETY: The same scheduler slot retains every FILE_OBJECT and IRP until its native effect returns.
unsafe impl Send for MdlOperation {}

impl_mounted_operation_adapter!(MdlOperation);
