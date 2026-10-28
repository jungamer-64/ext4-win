//! One-shot lower device controls share completion ownership, never storage retry authority.
use super::*;
use ext4_core::{TrimCompletion, TrimFailure, TrimIoOutcome, TrimRequest};

/// Fixed Windows DSM input structure size; the range array requires eight-byte alignment.
const DSM_INPUT_BYTES: usize = 28;
/// First eight-byte-aligned position after the fixed DSM input.
const DSM_RANGES_OFFSET: usize = 32;
/// One signed starting byte offset and one unsigned byte length.
const DSM_RANGE_BYTES: usize = 16;

/// Distinct native input/output contracts retained inside one stable completion envelope.
#[derive(Debug)]
pub(crate) enum DeviceControlCommand<O> {
    /// Write-protection observation grants no write authority by itself.
    WriteAccess {
        /// Unique mount continuation.
        suspended: O,
    },
    /// Device length is an output-only control used before filesystem admission.
    Length {
        /// Unique operation resumed by the decoded length or terminal failure.
        suspended: O,
    },
    /// Discard is an input-only effect whose ranges stay reserved through physical completion.
    Trim {
        /// Unique filesystem-admitted physical request.
        request: TrimRequest,
        /// Continuation retaining the matching allocation-release authority.
        suspended: O,
    },
}

/// Native completion preserves each control's own observable outcome and unique continuation.
#[derive(Debug)]
pub(crate) enum DeviceControlCompletion<O> {
    /// Physical availability, including a protected device as a successful observation.
    WriteAccess {
        /// Sole mount continuation.
        suspended: O,
        /// Native observation failure is distinct from write protection.
        result: DriverResult<ext4_core::DeviceWriteAccess>,
    },
    /// Decoded output-only geometry observation.
    Length {
        /// Unique mount/discovery continuation.
        suspended: O,
        /// Valid positive device length or terminal boundary failure.
        result: DriverResult<DeviceLength>,
    },
    /// Ended lower execution, without retrying uncertain physical effects.
    Trim {
        /// Unique operation retaining the reservation's other half.
        suspended: O,
        /// Returned physical owner and explicit effect classification.
        completion: TrimCompletion,
        /// Native or protocol failure status for the administrative result.
        status: NTSTATUS,
    },
}

impl<O> DeviceControlCommand<O> {
    /// Borrows only operation admission after private IRP and buffer construction.
    #[cfg(not(test))]
    pub(crate) const fn suspended(&self) -> &O {
        match self {
            Self::Length { suspended }
            | Self::WriteAccess { suspended }
            | Self::Trim { suspended, .. } => suspended,
        }
    }

    /// Prepares an output-only length control with no filesystem-write authority.
    /// # Errors
    /// Returns the unchanged command on allocation, native request or rundown preparation failure.
    #[cfg(not(test))]
    pub(crate) fn query<R>(
        query: DeviceQuery,
        completion_owner: KernelDevice,
        target: KernelDevice,
        suspended: O,
        destination: R,
        rundown: CompletionRundownLease,
    ) -> Result<PreparedLowerIrp<Self, R>, LowerBuildError<Self>>
    where
        O: Send + 'static,
        R: LowerCompletionRoute<Self>,
    {
        let (command, operation, bytes) = match query {
            DeviceQuery::Length => (
                Self::Length { suspended },
                LowerOperation::QueryLength,
                size_of::<i64>(),
            ),
            DeviceQuery::WriteAccess => (
                Self::WriteAccess { suspended },
                LowerOperation::QueryWriteAccess,
                0,
            ),
        };
        let transfer = match AlignedTransferBuffer::try_zeroed(bytes, core::mem::align_of::<i64>())
        {
            Ok(transfer) => transfer,
            Err(error) => return Err(LowerBuildError::from_unsubmitted(error, command)),
        };
        PreparedLowerIrp::try_new(
            completion_owner,
            LowerIrpTransfer::new(
                target,
                operation,
                LowerTransferMethod::Buffered,
                ByteOffset::new(0),
                transfer,
            ),
            command,
            destination,
            rundown,
        )
    }

    /// Prepares one bounded filesystem discard; it cannot target the external journal.
    /// # Errors
    /// Returns both owners on geometry, encoding, allocation or private request failure before effect.
    #[cfg(not(test))]
    pub(crate) fn trim<R>(
        devices: MountedStorageRoute,
        request: TrimRequest,
        suspended: O,
        destination: R,
        rundown: CompletionRundownLease,
    ) -> Result<PreparedLowerIrp<Self, R>, LowerBuildError<Self>>
    where
        O: Send + 'static,
        R: LowerCompletionRoute<Self>,
    {
        let transfer = encode_trim(
            devices.filesystem.length,
            devices.filesystem.sector_size,
            request
                .ranges()
                .map(|range| (range.offset(), range.length_bytes())),
        );
        let command = Self::Trim { request, suspended };
        let transfer = match transfer {
            Ok(transfer) => transfer,
            Err(error) => return Err(LowerBuildError::from_unsubmitted(error, command)),
        };
        PreparedLowerIrp::try_new(
            devices.completion_owner,
            LowerIrpTransfer::new(
                devices.filesystem.device,
                LowerOperation::Trim,
                LowerTransferMethod::Buffered,
                ByteOffset::new(0),
                transfer,
            ),
            command,
            destination,
            rundown,
        )
    }

    /// Reclaims a command known not to have reached any lower device.
    pub(crate) fn unsubmitted(self, error: DriverError) -> DeviceControlCompletion<O> {
        match self {
            Self::WriteAccess { suspended } => DeviceControlCompletion::WriteAccess {
                suspended,
                result: Err(error),
            },
            Self::Length { suspended } => DeviceControlCompletion::Length {
                suspended,
                result: Err(error),
            },
            Self::Trim { request, suspended } => {
                let status = error.ntstatus();
                let failure = match error {
                    DriverError::Core(Error::OperationCancelled) => TrimFailure::Cancelled,
                    DriverError::Core(reason) => TrimFailure::Failed(reason),
                    DriverError::InsufficientResources => TrimFailure::Failed(Error::OutOfMemory),
                    _ => trim_failure(status),
                };
                DeviceControlCompletion::Trim {
                    suspended,
                    completion: request.completed(TrimIoOutcome::Unsubmitted(failure)),
                    status,
                }
            }
        }
    }
}

/// Encodes only the Windows boundary; callers retain independent free-space reservation authority.
/// # Errors
/// Rejects empty/oversized batches, sector misalignment, signed-offset overflow and device overrun.
fn encode_trim(
    device_length: DeviceLength,
    sector_size: TransferSectorSize,
    ranges: impl ExactSizeIterator<Item = (ByteOffset, u64)>,
) -> DriverResult<AlignedTransferBuffer> {
    let count = ranges.len();
    if count == 0 || count > ext4_core::TRIM_BATCH_RANGES {
        return Err(DriverError::InvalidParameter);
    }
    let range_bytes = count
        .checked_mul(DSM_RANGE_BYTES)
        .ok_or(DriverError::InvalidBufferSize)?;
    let size = DSM_RANGES_OFFSET
        .checked_add(range_bytes)
        .ok_or(DriverError::InvalidBufferSize)?;
    let mut transfer = AlignedTransferBuffer::try_zeroed(size, core::mem::align_of::<u64>())?;
    let bytes = transfer.as_mut_slice();
    for (offset, value) in [
        (
            0,
            u32::try_from(DSM_INPUT_BYTES).map_err(|_| DriverError::InvalidBufferSize)?,
        ),
        (4, 1), // DeviceDsmAction_Trim is destructive and has no parameter/output block.
        (8, 0x8000_0000), // DEVICE_DSM_FLAG_TRIM_NOT_FS_ALLOCATED, not an entire-device request.
        (
            20,
            u32::try_from(DSM_RANGES_OFFSET).map_err(|_| DriverError::InvalidBufferSize)?,
        ),
        (
            24,
            u32::try_from(range_bytes).map_err(|_| DriverError::InvalidBufferSize)?,
        ),
    ] {
        put(bytes, offset, &value.to_le_bytes())?;
    }
    let mut total = 0_u64;
    let mut previous_end = 0_u64;
    let unit = u64::from(sector_size.as_u32());
    for (index, (offset, length)) in ranges.enumerate() {
        let end = offset
            .get()
            .checked_add(length)
            .ok_or(DriverError::InvalidParameter)?;
        total = total
            .checked_add(length)
            .ok_or(DriverError::InvalidParameter)?;
        if length == 0
            || !offset.get().is_multiple_of(unit)
            || !length.is_multiple_of(unit)
            || end > device_length.bytes()
            || offset.get() < previous_end
            || total > ext4_core::TRIM_BATCH_BYTES
        {
            return Err(DriverError::InvalidParameter);
        }
        let signed = i64::try_from(offset.get()).map_err(|_| DriverError::InvalidParameter)?;
        let start = index
            .checked_mul(DSM_RANGE_BYTES)
            .and_then(|relative| relative.checked_add(DSM_RANGES_OFFSET))
            .ok_or(DriverError::InvalidBufferSize)?;
        put(bytes, start, &signed.to_le_bytes())?;
        put(
            bytes,
            start.checked_add(8).ok_or(DriverError::InvalidBufferSize)?,
            &length.to_le_bytes(),
        )?;
        previous_end = end;
    }
    Ok(transfer)
}

/// Copies one ABI scalar only after checking its complete destination range.
/// # Errors
/// Returns an invalid buffer size without partial scalar publication.
fn put(bytes: &mut [u8], offset: usize, value: &[u8]) -> DriverResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(DriverError::InvalidBufferSize)?;
    memory::copy_exact(
        bytes
            .get_mut(offset..end)
            .ok_or(DriverError::InvalidBufferSize)?,
        value,
    )
}

/// Classifies native reasons independently of whether lower execution might already have acted.
fn trim_failure(status: NTSTATUS) -> TrimFailure {
    match status {
        wdk_sys::STATUS_NOT_SUPPORTED | wdk_sys::STATUS_INVALID_DEVICE_REQUEST => {
            TrimFailure::Unsupported
        }
        wdk_sys::STATUS_CANCELLED => TrimFailure::Cancelled,
        _ => TrimFailure::Failed(Error::DeviceIo),
    }
}

impl<O> CompletedLowerIrp<DeviceControlCommand<O>> {
    /// Decodes the completed control only after lower buffer ownership and cancellation ended.
    pub(crate) fn finish_control(self) -> DeviceControlCompletion<O> {
        let Self {
            suspended: command,
            transfer,
            status,
            information,
        } = self;
        match command {
            DeviceControlCommand::WriteAccess { suspended } => {
                let result = if information != 0 {
                    Err(DriverError::InvalidParameter)
                } else if status == wdk_sys::STATUS_MEDIA_WRITE_PROTECTED {
                    Ok(ext4_core::DeviceWriteAccess::ReadOnly)
                } else if status >= wdk_sys::STATUS_SUCCESS {
                    Ok(ext4_core::DeviceWriteAccess::Writable)
                } else {
                    Err(DriverError::from(Error::DeviceIo))
                };
                DeviceControlCompletion::WriteAccess { suspended, result }
            }
            DeviceControlCommand::Length { suspended } => {
                let result = (|| {
                    if status < wdk_sys::STATUS_SUCCESS || information != size_of::<i64>() {
                        return Err(DriverError::InvalidParameter);
                    }
                    let bytes = transfer
                        .as_slice()
                        .get(..size_of::<i64>())
                        .ok_or(DriverError::InternalInvariantViolation)?;
                    let mut encoded = [0_u8; size_of::<i64>()];
                    memory::copy_exact(&mut encoded, bytes)?;
                    let length = i64::from_ne_bytes(encoded);
                    if length <= 0 {
                        return Err(DriverError::InvalidParameter);
                    }
                    Ok(DeviceLength::from_bytes(
                        u64::try_from(length).map_err(|_| DriverError::InvalidParameter)?,
                    ))
                })();
                DeviceControlCompletion::Length { suspended, result }
            }
            DeviceControlCommand::Trim { request, suspended } => {
                let status = if status >= wdk_sys::STATUS_SUCCESS && information != 0 {
                    wdk_sys::STATUS_INVALID_BUFFER_SIZE
                } else {
                    status
                };
                let outcome = if status >= wdk_sys::STATUS_SUCCESS {
                    TrimIoOutcome::Acknowledged
                } else {
                    TrimIoOutcome::Uncertain(trim_failure(status))
                };
                DeviceControlCompletion::Trim {
                    suspended,
                    completion: request.completed(outcome),
                    status,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
