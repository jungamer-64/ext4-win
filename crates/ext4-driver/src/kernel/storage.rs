//! Completion-driven lower-storage geometry, commands, retry policy, and mount-length probes.

use core::mem::size_of;

use ext4_core::{
    ByteOffset, CompletedStorageTransfer, DeviceLength, Error, StorageCompletion, StorageRequest,
    StorageTarget,
};
use wdk_sys::NTSTATUS;

use crate::irp::lower::{
    AlignedTransferBuffer, CompletedLowerIrp, LowerOperation, LowerTransferMethod,
};
#[cfg(not(test))]
use crate::irp::lower::{
    CompletionRundownLease, LowerBuildError, LowerCompletionDestination, PreparedLowerIrp,
};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory;
use crate::state::KernelDevice;

/// Retryable lower status `STATUS_DEVICE_BUSY`.
const STATUS_DEVICE_BUSY: NTSTATUS = i32::from_ne_bytes(0x8000_0011_u32.to_ne_bytes());
/// Retryable lower status `STATUS_RETRY`.
const STATUS_RETRY: NTSTATUS = i32::from_ne_bytes(0xC000_022D_u32.to_ne_bytes());
/// Retryable lower status `STATUS_DEVICE_NOT_READY`.
const STATUS_DEVICE_NOT_READY: NTSTATUS = i32::from_ne_bytes(0xC000_00A3_u32.to_ne_bytes());
/// Read-retryable but write-ambiguous status `STATUS_IO_TIMEOUT`.
const STATUS_IO_TIMEOUT: NTSTATUS = i32::from_ne_bytes(0xC000_00B5_u32.to_ne_bytes());
/// Lower medium returned a CRC failure.
const STATUS_CRC_ERROR: NTSTATUS = i32::from_ne_bytes(0xC000_003F_u32.to_ne_bytes());
/// Lower medium reported data it cannot reliably recover.
const STATUS_DEVICE_DATA_ERROR: NTSTATUS = i32::from_ne_bytes(0xC000_009C_u32.to_ne_bytes());
/// Lower device stack reported a terminal I/O device failure.
const STATUS_IO_DEVICE_ERROR: NTSTATUS = i32::from_ne_bytes(0xC000_0185_u32.to_ne_bytes());
/// Requested medium sector no longer exists.
const STATUS_NONEXISTENT_SECTOR: NTSTATUS = i32::from_ne_bytes(0xC000_0015_u32.to_ne_bytes());

/// Initial try plus two delayed retries.
const MAX_STORAGE_ATTEMPTS: u8 = 3;

/// Physical lower-device transfer constraints fixed at mount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LowerStorageDevice {
    /// Kernel lower device identity.
    device: KernelDevice,
    /// Validated device byte length.
    length: DeviceLength,
    /// Whole-sector lower transfer unit.
    sector_size: usize,
    /// Required virtual-address alignment.
    buffer_alignment: usize,
    /// Buffer representation consumed by the stack.
    transfer_method: LowerTransferMethod,
}

impl LowerStorageDevice {
    /// Captures immutable lower transfer geometry after the length query completes.
    /// # Errors
    ///
    /// Returns an error when device flags, sector size, alignment, or length are invalid.
    pub fn from_device(device: KernelDevice, length: DeviceLength) -> DriverResult<Self> {
        let object = unsafe {
            // SAFETY: The mounted lower device is live and read only for immutable geometry.
            device.as_ptr().as_ref()
        }
        .ok_or(DriverError::InvalidParameter)?;
        let sector_size = usize::from(object.SectorSize);
        let alignment_mask = usize::try_from(object.AlignmentRequirement)
            .map_err(|_| DriverError::InvalidParameter)?;
        let buffer_alignment = alignment_mask
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;
        if length.is_empty()
            || sector_size == 0
            || !sector_size.is_power_of_two()
            || !buffer_alignment.is_power_of_two()
        {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self {
            device,
            length,
            sector_size,
            buffer_alignment,
            transfer_method: LowerTransferMethod::from_device_flags(object.Flags)?,
        })
    }

    /// Covers one arbitrary core byte range with whole physical sectors.
    fn cover(self, offset: ByteOffset, byte_count: usize) -> DriverResult<CoveredTransfer> {
        let byte_count = u64::try_from(byte_count).map_err(|_| DriverError::InvalidBufferSize)?;
        let requested_end = offset
            .get()
            .checked_add(byte_count)
            .ok_or(DriverError::InvalidParameter)?;
        if requested_end > self.length.bytes() {
            return Err(DriverError::InvalidParameter);
        }
        let sector_size =
            u64::try_from(self.sector_size).map_err(|_| DriverError::InternalInvariantViolation)?;
        let sector_mask = sector_size
            .checked_sub(1)
            .ok_or(DriverError::InternalInvariantViolation)?;
        let lower_start = offset.get() & !sector_mask;
        let lower_end = requested_end
            .checked_add(sector_mask)
            .ok_or(DriverError::InvalidParameter)?
            & !sector_mask;
        if lower_end > self.length.bytes() {
            return Err(DriverError::InvalidParameter);
        }
        let transfer_len = usize::try_from(
            lower_end
                .checked_sub(lower_start)
                .ok_or(DriverError::InternalInvariantViolation)?,
        )
        .map_err(|_| DriverError::InvalidBufferSize)?;
        let requested_start = usize::try_from(
            offset
                .get()
                .checked_sub(lower_start)
                .ok_or(DriverError::InternalInvariantViolation)?,
        )
        .map_err(|_| DriverError::InvalidParameter)?;
        let requested_end = usize::try_from(
            requested_end
                .checked_sub(lower_start)
                .ok_or(DriverError::InternalInvariantViolation)?,
        )
        .map_err(|_| DriverError::InvalidParameter)?;
        Ok(CoveredTransfer {
            lower_offset: ByteOffset::new(lower_start),
            transfer_len,
            requested_start,
            requested_end,
        })
    }
}

/// Mounted filesystem and optional external-journal lower devices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountedStorageDevices {
    /// Driver-owned device whose image pins completion routine code.
    completion_owner: KernelDevice,
    /// Filesystem lower device.
    filesystem: LowerStorageDevice,
    /// External journal lower device when the superblock selects one.
    external_journal: Option<LowerStorageDevice>,
}

impl MountedStorageDevices {
    /// Builds the immutable lower device set.
    #[must_use]
    pub const fn new(
        completion_owner: KernelDevice,
        filesystem: LowerStorageDevice,
        external_journal: Option<LowerStorageDevice>,
    ) -> Self {
        Self {
            completion_owner,
            filesystem,
            external_journal,
        }
    }

    /// Selects one concrete lower device from an owned core request target.
    /// # Errors
    ///
    /// Returns an error when an external-journal request has no mounted journal device.
    fn select(self, target: StorageTarget) -> DriverResult<LowerStorageDevice> {
        match target {
            StorageTarget::Filesystem => Ok(self.filesystem),
            StorageTarget::ExternalJournal => {
                self.external_journal.ok_or(DriverError::InvalidParameter)
            }
        }
    }
}

/// Sector-aligned lower range covering one exact core request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoveredTransfer {
    /// Sector-aligned lower byte offset.
    lower_offset: ByteOffset,
    /// Whole-sector byte count.
    transfer_len: usize,
    /// Requested subrange start in the lower buffer.
    requested_start: usize,
    /// Requested subrange end in the lower buffer.
    requested_end: usize,
}

impl CoveredTransfer {
    /// Whether the core range exactly equals the whole-sector lower range.
    const fn is_complete_sector_range(self) -> bool {
        self.requested_start == 0 && self.requested_end == self.transfer_len
    }

    /// Checked requested subrange.
    fn requested_range(self) -> core::ops::Range<usize> {
        self.requested_start..self.requested_end
    }
}

/// Current lower phase of a write command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteTransferPhase {
    /// Read the surrounding sectors before altering an unaligned subrange.
    ReadBeforeWrite,
    /// Write a complete-sector request image.
    DirectWrite,
    /// Write the patched read-modify-write sector image.
    WriteAfterRead,
}

/// Operation-owned storage command retaining both transfer token and suspended operation by value.
#[derive(Debug)]
pub enum StorageCommand<O> {
    /// Exact core read backed by one sector-covered lower read.
    Read {
        /// Driver-owned device whose image pins the completion callback.
        completion_owner: KernelDevice,
        /// Original core destination buffer and logical range.
        request: StorageRequest,
        /// Suspended filesystem operation.
        suspended: O,
        /// Selected device geometry.
        device: LowerStorageDevice,
        /// Sector coverage.
        coverage: CoveredTransfer,
        /// One-based attempt number.
        attempt: u8,
    },
    /// Exact core write, optionally represented as read-modify-write.
    Write {
        /// Driver-owned device whose image pins the completion callback.
        completion_owner: KernelDevice,
        /// Original core source buffer and logical range.
        request: StorageRequest,
        /// Suspended filesystem operation.
        suspended: O,
        /// Selected device geometry.
        device: LowerStorageDevice,
        /// Sector coverage.
        coverage: CoveredTransfer,
        /// Current lower phase.
        phase: WriteTransferPhase,
        /// One-based attempt number for the current phase.
        attempt: u8,
    },
    /// Device durability barrier.
    Flush {
        /// Driver-owned device whose image pins the completion callback.
        completion_owner: KernelDevice,
        /// Original core flush request.
        request: StorageRequest,
        /// Suspended filesystem operation.
        suspended: O,
        /// Selected device geometry.
        device: LowerStorageDevice,
        /// One-based attempt number.
        attempt: u8,
    },
}

/// Initial storage-command preparation failure preserving operation and core request.
#[derive(Debug)]
pub struct StorageCommandBuildError<O> {
    /// Driver-domain preparation failure.
    error: DriverError,
    /// Suspended operation that was never submitted.
    suspended: O,
    /// Original core request that was never submitted.
    request: StorageRequest,
}

impl<O> StorageCommandBuildError<O> {
    /// Separates the error and both ownership-bearing values.
    pub fn into_parts(self) -> (DriverError, O, StorageRequest) {
        (self.error, self.suspended, self.request)
    }
}

/// Fully prepared lower transfer before private-IRP construction.
#[derive(Debug)]
pub struct PreparedStorageCommand<O> {
    /// Command moved into the stable completion envelope.
    command: StorageCommand<O>,
    /// Stable aligned transfer allocation.
    transfer: AlignedTransferBuffer,
    /// Exact lower stack operation for this phase.
    operation: LowerOperation,
}

impl<O> PreparedStorageCommand<O> {
    /// Recovers the command when teardown closes completion rundown before IRP construction.
    pub(crate) fn into_command(self) -> StorageCommand<O> {
        self.command
    }

    /// Whether submission may mutate device durability state.
    pub(crate) const fn is_effect_bearing(&self) -> bool {
        matches!(
            self.operation,
            LowerOperation::Write | LowerOperation::Flush
        )
    }

    /// Allocates and prepares one command without exposing it to a lower driver.
    pub fn try_new(
        devices: MountedStorageDevices,
        request: StorageRequest,
        suspended: O,
    ) -> Result<Self, StorageCommandBuildError<O>> {
        let device = match devices.select(request.target()) {
            Ok(device) => device,
            Err(error) => {
                return Err(StorageCommandBuildError {
                    error,
                    suspended,
                    request,
                });
            }
        };
        match &request {
            StorageRequest::Read { offset, buffer, .. } => {
                let coverage = match device.cover(*offset, buffer.len()) {
                    Ok(coverage) => coverage,
                    Err(error) => {
                        return Err(StorageCommandBuildError {
                            error,
                            suspended,
                            request,
                        });
                    }
                };
                let transfer = match AlignedTransferBuffer::try_zeroed(
                    coverage.transfer_len,
                    device.buffer_alignment,
                ) {
                    Ok(transfer) => transfer,
                    Err(error) => {
                        return Err(StorageCommandBuildError {
                            error,
                            suspended,
                            request,
                        });
                    }
                };
                Ok(Self {
                    command: StorageCommand::Read {
                        completion_owner: devices.completion_owner,
                        request,
                        suspended,
                        device,
                        coverage,
                        attempt: 1,
                    },
                    transfer,
                    operation: LowerOperation::Read,
                })
            }
            StorageRequest::Write { offset, buffer, .. } => {
                let coverage = match device.cover(*offset, buffer.len()) {
                    Ok(coverage) => coverage,
                    Err(error) => {
                        return Err(StorageCommandBuildError {
                            error,
                            suspended,
                            request,
                        });
                    }
                };
                let mut transfer = match AlignedTransferBuffer::try_zeroed(
                    coverage.transfer_len,
                    device.buffer_alignment,
                ) {
                    Ok(transfer) => transfer,
                    Err(error) => {
                        return Err(StorageCommandBuildError {
                            error,
                            suspended,
                            request,
                        });
                    }
                };
                let (phase, operation) = if coverage.is_complete_sector_range() {
                    if let Err(error) = memory::copy_exact(transfer.as_mut_slice(), buffer) {
                        return Err(StorageCommandBuildError {
                            error,
                            suspended,
                            request,
                        });
                    }
                    (WriteTransferPhase::DirectWrite, LowerOperation::Write)
                } else {
                    (WriteTransferPhase::ReadBeforeWrite, LowerOperation::Read)
                };
                Ok(Self {
                    command: StorageCommand::Write {
                        completion_owner: devices.completion_owner,
                        request,
                        suspended,
                        device,
                        coverage,
                        phase,
                        attempt: 1,
                    },
                    transfer,
                    operation,
                })
            }
            StorageRequest::Flush { .. } => {
                let transfer = match AlignedTransferBuffer::try_zeroed(0, 1) {
                    Ok(transfer) => transfer,
                    Err(error) => {
                        return Err(StorageCommandBuildError {
                            error,
                            suspended,
                            request,
                        });
                    }
                };
                Ok(Self {
                    command: StorageCommand::Flush {
                        completion_owner: devices.completion_owner,
                        request,
                        suspended,
                        device,
                        attempt: 1,
                    },
                    transfer,
                    operation: LowerOperation::Flush,
                })
            }
        }
    }

    /// Builds every private-IRP resource while preserving the command on failure.
    #[cfg(not(test))]
    pub fn build_lower(
        self,
        destination: LowerCompletionDestination<StorageCommand<O>>,
        rundown: CompletionRundownLease,
    ) -> Result<PreparedLowerIrp<StorageCommand<O>>, LowerBuildError<StorageCommand<O>>>
    where
        O: Send + 'static,
    {
        let (completion_owner, device, offset, method) = self.command.lower_contract();
        PreparedLowerIrp::try_new(
            completion_owner,
            device.device,
            self.operation,
            method,
            offset,
            self.transfer,
            self.command,
            destination,
            rundown,
        )
    }
}

impl<O> StorageCommand<O> {
    /// Concrete target, lower offset, and buffer method for this phase.
    fn lower_contract(
        &self,
    ) -> (
        KernelDevice,
        LowerStorageDevice,
        ByteOffset,
        LowerTransferMethod,
    ) {
        match self {
            Self::Read {
                completion_owner,
                device,
                coverage,
                ..
            }
            | Self::Write {
                completion_owner,
                device,
                coverage,
                ..
            } => (
                *completion_owner,
                *device,
                coverage.lower_offset,
                device.transfer_method,
            ),
            Self::Flush {
                completion_owner,
                device,
                ..
            } => (
                *completion_owner,
                *device,
                ByteOffset::new(0),
                device.transfer_method,
            ),
        }
    }

    /// Expected lower information length for this phase.
    fn expected_information(&self) -> usize {
        match self {
            Self::Read { coverage, .. } | Self::Write { coverage, .. } => coverage.transfer_len,
            Self::Flush { .. } => 0,
        }
    }

    /// Whether the current lower phase may be retried under read rules.
    fn read_retry_policy(&self) -> bool {
        matches!(
            self,
            Self::Read { .. }
                | Self::Write {
                    phase: WriteTransferPhase::ReadBeforeWrite,
                    ..
                }
        )
    }

    /// Current one-based attempt number.
    fn attempt(&self) -> u8 {
        match self {
            Self::Read { attempt, .. }
            | Self::Write { attempt, .. }
            | Self::Flush { attempt, .. } => *attempt,
        }
    }

    /// Mutably increments the attempt for a timer-granted retry.
    fn advance_attempt(&mut self) -> DriverResult<()> {
        let attempt = match self {
            Self::Read { attempt, .. }
            | Self::Write { attempt, .. }
            | Self::Flush { attempt, .. } => attempt,
        };
        *attempt = attempt
            .checked_add(1)
            .ok_or(DriverError::InternalInvariantViolation)?;
        Ok(())
    }

    /// Consumes the command into its original operation and request.
    pub(crate) fn into_parts(self) -> (O, StorageRequest) {
        match self {
            Self::Read {
                request, suspended, ..
            }
            | Self::Write {
                request, suspended, ..
            }
            | Self::Flush {
                request, suspended, ..
            } => (suspended, request),
        }
    }
}

/// Retry timer delay selected from the fixed lower-storage policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRetryDelay {
    /// First delayed retry.
    TenMilliseconds,
    /// Final delayed retry.
    HundredMilliseconds,
}

/// Reason a storage failure cannot simply complete or retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageFailureClass {
    /// Read/preparation failure with no durable ambiguity.
    Terminal,
    /// A lower read reported a medium/device failure that invalidates future committed reads.
    ReadUnreliable,
    /// A write or flush may have taken effect and journal abort/recovery is required.
    DurabilityUnknown,
}

/// Failed completed command retaining ownership for retry or abort handling.
#[derive(Debug)]
pub struct FailedStorageCommand<O> {
    /// Original command and suspended operation.
    command: StorageCommand<O>,
    /// Reusable aligned buffer; each retry still constructs a fresh private IRP.
    transfer: AlignedTransferBuffer,
    /// Raw lower status.
    status: NTSTATUS,
    /// Raw lower information length.
    information: usize,
}

impl<O> FailedStorageCommand<O> {
    /// Converts a non-retryable failure into its operation, request, and durability class.
    pub fn into_failure(self) -> (O, StorageRequest, StorageFailureClass) {
        let effect_free_write_failure = matches!(
            self.status,
            STATUS_DEVICE_BUSY | STATUS_RETRY | STATUS_DEVICE_NOT_READY
        ) && self.information == 0;
        let read_unreliable = self.command.read_retry_policy()
            && matches!(
                self.status,
                STATUS_CRC_ERROR
                    | STATUS_DEVICE_DATA_ERROR
                    | STATUS_IO_DEVICE_ERROR
                    | STATUS_NONEXISTENT_SECTOR
            );
        let class = if read_unreliable {
            StorageFailureClass::ReadUnreliable
        } else if self.command.read_retry_policy() || effect_free_write_failure {
            StorageFailureClass::Terminal
        } else {
            StorageFailureClass::DurabilityUnknown
        };
        let (suspended, request) = self.command.into_parts();
        (suspended, request, class)
    }

    /// Selects and owns the next fixed retry timer, if policy permits one.
    pub fn into_retry(mut self) -> Result<RetryingStorageCommand<O>, Self> {
        let status_retryable = if self.command.read_retry_policy() {
            matches!(
                self.status,
                STATUS_DEVICE_BUSY | STATUS_RETRY | STATUS_DEVICE_NOT_READY | STATUS_IO_TIMEOUT
            )
        } else {
            matches!(
                self.status,
                STATUS_DEVICE_BUSY | STATUS_RETRY | STATUS_DEVICE_NOT_READY
            ) && self.information == 0
        };
        if !status_retryable || self.command.attempt() >= MAX_STORAGE_ATTEMPTS {
            return Err(self);
        }
        let delay = match self.command.attempt() {
            1 => StorageRetryDelay::TenMilliseconds,
            2 => StorageRetryDelay::HundredMilliseconds,
            _ => return Err(self),
        };
        if self.command.read_retry_policy() {
            self.transfer.as_mut_slice().fill(0);
        }
        Ok(RetryingStorageCommand {
            command: self.command,
            transfer: self.transfer,
            delay,
        })
    }
}

/// Storage command waiting for its one-use retry timer permit.
#[derive(Debug)]
pub struct RetryingStorageCommand<O> {
    /// Original command.
    command: StorageCommand<O>,
    /// Reusable aligned buffer.
    transfer: AlignedTransferBuffer,
    /// Fixed timer delay.
    delay: StorageRetryDelay,
}

impl<O> RetryingStorageCommand<O> {
    /// Timer delay to arm.
    pub const fn delay(&self) -> StorageRetryDelay {
        self.delay
    }

    /// Cancels an unsubmitted retry while preserving the suspended operation.
    pub(crate) fn into_parts(self) -> (O, StorageRequest) {
        self.command.into_parts()
    }

    /// Consumes a scheduler retry permit and prepares a fresh private IRP attempt.
    pub fn permitted(mut self) -> DriverResult<PreparedStorageCommand<O>> {
        self.command.advance_attempt()?;
        let operation = match &self.command {
            StorageCommand::Read { .. } => LowerOperation::Read,
            StorageCommand::Write { phase, .. } => match phase {
                WriteTransferPhase::ReadBeforeWrite => LowerOperation::Read,
                WriteTransferPhase::DirectWrite | WriteTransferPhase::WriteAfterRead => {
                    LowerOperation::Write
                }
            },
            StorageCommand::Flush { .. } => LowerOperation::Flush,
        };
        Ok(PreparedStorageCommand {
            command: self.command,
            transfer: self.transfer,
            operation,
        })
    }
}

/// Reactor action produced by one lower-storage completion.
#[derive(Debug)]
pub enum StorageCommandStep<O> {
    /// Submit the write half of a successful read-modify-write command immediately.
    SubmitNext(PreparedStorageCommand<O>),
    /// Deliver one concrete successful core completion to the suspended operation.
    Complete {
        /// Suspended operation.
        suspended: O,
        /// Owned core completion.
        completion: StorageCompletion,
    },
    /// Apply retry, terminal error, or durability-unknown policy.
    Failed(FailedStorageCommand<O>),
}

impl<O> CompletedLowerIrp<StorageCommand<O>> {
    /// Validates one lower completion and advances its storage command without allocation.
    pub fn advance(self) -> DriverResult<StorageCommandStep<O>> {
        let Self {
            suspended: command,
            mut transfer,
            status,
            information,
        } = self;
        if status < wdk_sys::STATUS_SUCCESS || information != command.expected_information() {
            return Ok(StorageCommandStep::Failed(FailedStorageCommand {
                command,
                transfer,
                status,
                information,
            }));
        }
        match command {
            StorageCommand::Read {
                request,
                suspended,
                coverage,
                ..
            } => {
                let StorageRequest::Read {
                    target,
                    offset,
                    mut buffer,
                } = request
                else {
                    return Err(DriverError::InternalInvariantViolation);
                };
                let source = transfer
                    .as_slice()
                    .get(coverage.requested_range())
                    .ok_or(DriverError::InternalInvariantViolation)?;
                memory::copy_exact(&mut buffer, source)?;
                let core_information = buffer.len();
                let completed = CompletedStorageTransfer::Read {
                    target,
                    offset,
                    buffer,
                };
                Ok(StorageCommandStep::Complete {
                    suspended,
                    completion: StorageCompletion::success(completed, core_information),
                })
            }
            StorageCommand::Write {
                request,
                suspended,
                completion_owner,
                device,
                coverage,
                phase: WriteTransferPhase::ReadBeforeWrite,
                attempt: _,
            } => {
                let StorageRequest::Write { buffer, .. } = &request else {
                    return Err(DriverError::InternalInvariantViolation);
                };
                let destination = transfer
                    .as_mut_slice()
                    .get_mut(coverage.requested_range())
                    .ok_or(DriverError::InternalInvariantViolation)?;
                memory::copy_exact(destination, buffer)?;
                Ok(StorageCommandStep::SubmitNext(PreparedStorageCommand {
                    command: StorageCommand::Write {
                        request,
                        suspended,
                        completion_owner,
                        device,
                        coverage,
                        phase: WriteTransferPhase::WriteAfterRead,
                        attempt: 1,
                    },
                    transfer,
                    operation: LowerOperation::Write,
                }))
            }
            StorageCommand::Write {
                request,
                suspended,
                phase: WriteTransferPhase::DirectWrite | WriteTransferPhase::WriteAfterRead,
                ..
            } => {
                let core_information = request.byte_count();
                let completed = CompletedStorageTransfer::from_request(request);
                Ok(StorageCommandStep::Complete {
                    suspended,
                    completion: StorageCompletion::success(completed, core_information),
                })
            }
            StorageCommand::Flush {
                request, suspended, ..
            } => {
                let completed = CompletedStorageTransfer::from_request(request);
                Ok(StorageCommandStep::Complete {
                    suspended,
                    completion: StorageCompletion::success(completed, information),
                })
            }
        }
    }
}

/// Payload retained while a device-length IOCTL is in flight.
#[derive(Debug)]
pub struct DeviceLengthProbe<O> {
    /// Suspended mount-admission operation.
    suspended: O,
}

impl<O> DeviceLengthProbe<O> {
    /// Builds a private length-query IRP through the same stable-envelope registration boundary.
    #[cfg(not(test))]
    pub fn prepare(
        completion_owner: KernelDevice,
        target: KernelDevice,
        suspended: O,
        destination: LowerCompletionDestination<Self>,
        rundown: CompletionRundownLease,
    ) -> Result<PreparedLowerIrp<Self>, LowerBuildError<Self>>
    where
        O: Send + 'static,
    {
        let transfer =
            match AlignedTransferBuffer::try_zeroed(size_of::<i64>(), core::mem::align_of::<i64>())
            {
                Ok(transfer) => transfer,
                Err(error) => {
                    return Err(LowerBuildError::from_unsubmitted(error, Self { suspended }));
                }
            };
        PreparedLowerIrp::try_new(
            completion_owner,
            target,
            LowerOperation::QueryLength,
            LowerTransferMethod::Buffered,
            ByteOffset::new(0),
            transfer,
            Self { suspended },
            destination,
            rundown,
        )
    }

    /// Recovers the caller operation from a build or registration error.
    pub fn into_suspended(self) -> O {
        self.suspended
    }
}

impl<O> CompletedLowerIrp<DeviceLengthProbe<O>> {
    /// Validates and decodes one completed `GET_LENGTH_INFORMATION` payload.
    pub fn finish(self) -> Result<(O, DeviceLength), (O, DriverError)> {
        let Self {
            suspended: probe,
            transfer,
            status,
            information,
        } = self;
        if status < wdk_sys::STATUS_SUCCESS || information != size_of::<i64>() {
            return Err((probe.suspended, DriverError::InvalidParameter));
        }
        let Some(bytes) = transfer.as_slice().get(..size_of::<i64>()) else {
            return Err((probe.suspended, DriverError::InternalInvariantViolation));
        };
        let mut encoded = [0_u8; size_of::<i64>()];
        if let Err(error) = memory::copy_exact(&mut encoded, bytes) {
            return Err((probe.suspended, error));
        }
        let length = i64::from_ne_bytes(encoded);
        if length <= 0 {
            return Err((probe.suspended, DriverError::InvalidParameter));
        }
        let length = match u64::try_from(length) {
            Ok(length) => DeviceLength::from_bytes(length),
            Err(_) => return Err((probe.suspended, DriverError::InvalidParameter)),
        };
        Ok((probe.suspended, length))
    }
}

/// Converts one never-submitted core request into a normal core completion.
pub fn failed_unsubmitted_request(request: StorageRequest, error: Error) -> StorageCompletion {
    StorageCompletion::failure(CompletedStorageTransfer::from_request(request), error)
}

#[cfg(test)]
mod tests {
    use super::{
        LowerStorageDevice, STATUS_DEVICE_BUSY, STATUS_DEVICE_NOT_READY, STATUS_IO_TIMEOUT,
        STATUS_RETRY,
    };
    use crate::state::KernelDevice;
    use ext4_core::DeviceLength;

    /// # Panics
    ///
    /// Panics when sector coverage loses the exact requested subrange.
    #[test]
    fn sector_coverage_is_checked_and_exact() {
        let mut raw = wdk_sys::DEVICE_OBJECT {
            SectorSize: 512,
            AlignmentRequirement: wdk_sys::FILE_512_BYTE_ALIGNMENT,
            ..wdk_sys::DEVICE_OBJECT::default()
        };
        let Some(device) = KernelDevice::from_raw(core::ptr::addr_of_mut!(raw)) else {
            return;
        };
        let geometry = LowerStorageDevice::from_device(device, DeviceLength::from_bytes(4096));
        assert!(geometry.is_ok());
        let Ok(geometry) = geometry else {
            return;
        };
        let coverage = geometry.cover(ext4_core::ByteOffset::new(513), 510);
        assert!(coverage.is_ok());
        if let Ok(coverage) = coverage {
            assert_eq!(coverage.lower_offset.get(), 512);
            assert_eq!(coverage.transfer_len, 512);
            assert_eq!(coverage.requested_start, 1);
            assert_eq!(coverage.requested_end, 511);
        }
    }

    /// # Panics
    ///
    /// Panics when the exact retry status set changes silently.
    #[test]
    fn retry_status_constants_are_distinct() {
        let statuses = [
            STATUS_DEVICE_BUSY,
            STATUS_RETRY,
            STATUS_DEVICE_NOT_READY,
            STATUS_IO_TIMEOUT,
        ];
        for (index, status) in statuses.iter().enumerate() {
            assert!(statuses.iter().skip(index + 1).all(|other| other != status));
        }
    }
}
