//! Owned, completion-driven storage transfers used by filesystem operations.

use alloc::vec::Vec;

use super::block::{ByteOffset, DeviceLength};
use crate::memory::{self, FallibleVec};
use crate::{Error, Result};

/// Physical device selected by one storage transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageTarget {
    /// The ext4 filesystem device.
    Filesystem,
    /// A separately supplied JBD2 journal device.
    ExternalJournal,
}

/// One owned lower-storage request.
///
/// The transfer buffer is never borrowed from an operation. The request moves into the lower-I/O
/// envelope and returns inside [`StorageCompletion`].
#[derive(Debug)]
pub enum StorageRequest {
    /// Read exactly the owned buffer length from one device offset.
    Read {
        /// Device selected for the transfer.
        target: StorageTarget,
        /// Starting byte offset.
        offset: ByteOffset,
        /// Owned destination buffer, zero-filled before submission.
        buffer: Vec<u8>,
    },
    /// Write the complete owned byte image at one device offset.
    Write {
        /// Device selected for the transfer.
        target: StorageTarget,
        /// Starting byte offset.
        offset: ByteOffset,
        /// Owned source buffer.
        buffer: Vec<u8>,
    },
    /// Persist all preceding writes issued to the selected device.
    Flush {
        /// Device selected for the flush.
        target: StorageTarget,
    },
}

impl StorageRequest {
    /// Device selected for this transfer.
    #[must_use]
    pub const fn target(&self) -> StorageTarget {
        match self {
            Self::Read { target, .. } | Self::Write { target, .. } | Self::Flush { target } => {
                *target
            }
        }
    }

    /// Starting byte offset for a data transfer.
    #[must_use]
    pub const fn offset(&self) -> Option<ByteOffset> {
        match self {
            Self::Read { offset, .. } | Self::Write { offset, .. } => Some(*offset),
            Self::Flush { .. } => None,
        }
    }

    /// Requested byte count, or zero for a flush.
    #[must_use]
    pub fn byte_count(&self) -> usize {
        match self {
            Self::Read { buffer, .. } | Self::Write { buffer, .. } => buffer.len(),
            Self::Flush { .. } => 0,
        }
    }
}

/// Transfer returned after the lower stack has stopped using its IRP and buffer.
#[derive(Debug)]
pub enum CompletedStorageTransfer {
    /// A read buffer filled by the lower device.
    Read {
        /// Device selected for the transfer.
        target: StorageTarget,
        /// Starting byte offset.
        offset: ByteOffset,
        /// Owned completed buffer.
        buffer: Vec<u8>,
    },
    /// A write whose source buffer has been released by the lower device.
    Write {
        /// Device selected for the transfer.
        target: StorageTarget,
        /// Starting byte offset.
        offset: ByteOffset,
        /// Owned completed buffer.
        buffer: Vec<u8>,
    },
    /// A completed device flush.
    Flush {
        /// Device selected for the flush.
        target: StorageTarget,
    },
}

impl CompletedStorageTransfer {
    /// Reclaims one submitted request after the lower stack has finished with its resources.
    #[must_use]
    pub fn from_request(request: StorageRequest) -> Self {
        match request {
            StorageRequest::Read {
                target,
                offset,
                buffer,
            } => Self::Read {
                target,
                offset,
                buffer,
            },
            StorageRequest::Write {
                target,
                offset,
                buffer,
            } => Self::Write {
                target,
                offset,
                buffer,
            },
            StorageRequest::Flush { target } => Self::Flush { target },
        }
    }

    /// Device selected for this completed transfer.
    #[must_use]
    pub const fn target(&self) -> StorageTarget {
        match self {
            Self::Read { target, .. } | Self::Write { target, .. } | Self::Flush { target } => {
                *target
            }
        }
    }

    /// Number of data bytes owned by this transfer.
    #[must_use]
    pub fn byte_count(&self) -> usize {
        match self {
            Self::Read { buffer, .. } | Self::Write { buffer, .. } => buffer.len(),
            Self::Flush { .. } => 0,
        }
    }
}

/// One concrete lower-storage completion delivered to the suspended operation.
#[derive(Debug)]
pub struct StorageCompletion {
    /// Completed transfer and its returned owned buffer.
    transfer: CompletedStorageTransfer,
    /// Exact information byte count reported by the lower stack.
    information: usize,
    /// Terminal domain result after the driver has applied retry policy.
    result: Result<()>,
}

impl StorageCompletion {
    /// Builds a successful lower-storage completion.
    #[must_use]
    pub const fn success(transfer: CompletedStorageTransfer, information: usize) -> Self {
        Self {
            transfer,
            information,
            result: Ok(()),
        }
    }

    /// Builds a failed lower-storage completion after retry policy has terminated.
    #[must_use]
    pub const fn failure(transfer: CompletedStorageTransfer, error: Error) -> Self {
        Self {
            transfer,
            information: 0,
            result: Err(error),
        }
    }

    /// Returns the completed transfer's device target.
    #[must_use]
    pub const fn target(&self) -> StorageTarget {
        self.transfer.target()
    }

    /// Consumes the completion into its owned parts.
    #[must_use]
    pub fn into_parts(self) -> (CompletedStorageTransfer, usize, Result<()>) {
        (self.transfer, self.information, self.result)
    }
}

/// Allocation-free identity retained while one owned request is in the lower stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageRequestIdentity {
    /// Device selected for the request.
    target: StorageTarget,
    /// Data-transfer offset, absent for flushes.
    offset: Option<ByteOffset>,
    /// Exact transfer byte count.
    byte_count: usize,
}

impl StorageRequestIdentity {
    /// Captures the fields required to validate the matching completion.
    pub(crate) fn from_request(request: &StorageRequest) -> Self {
        Self {
            target: request.target(),
            offset: request.offset(),
            byte_count: request.byte_count(),
        }
    }

    /// Validates and consumes the matching completion after lower-buffer use has ended.
    /// # Errors
    ///
    /// Returns an error for a failed, short, wrong-device, wrong-offset, or wrong-kind
    /// completion.
    pub(crate) fn complete(self, completion: StorageCompletion) -> Result<()> {
        let (transfer, information, result) = completion.into_parts();
        result?;
        let (target, offset, byte_count) = match transfer {
            CompletedStorageTransfer::Read {
                target,
                offset,
                buffer,
            }
            | CompletedStorageTransfer::Write {
                target,
                offset,
                buffer,
            } => (target, Some(offset), buffer.len()),
            CompletedStorageTransfer::Flush { target } => (target, None, 0),
        };
        if target == self.target
            && offset == self.offset
            && byte_count == self.byte_count
            && information == self.byte_count
        {
            Ok(())
        } else {
            Err(Error::DeviceIo)
        }
    }
}

/// One exact completed read retained by a restartable operation resolve pass.
#[derive(Debug)]
struct CompletedRead {
    /// Starting device byte offset.
    offset: ByteOffset,
    /// Returned bytes.
    bytes: Vec<u8>,
}

/// Metadata retained while one read request is owned by a lower-I/O envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InFlightRead {
    /// Starting device byte offset.
    offset: ByteOffset,
    /// Exact requested byte count.
    byte_count: usize,
}

/// Per-device read transcript retained by exactly one filesystem operation.
///
/// Resolution code may restart after a completion, but completed reads are served from this
/// transcript. At most one request can be in flight, so no generation lookup or self-reference is
/// required.
#[derive(Debug)]
pub(crate) struct StorageTranscript {
    /// Device selected by this transcript.
    target: StorageTarget,
    /// Validated total device length.
    length: DeviceLength,
    /// Completed exact reads available to later resolve passes.
    completed_reads: Vec<CompletedRead>,
    /// Request built by the current pass but not yet moved into an envelope.
    pending_request: Option<StorageRequest>,
    /// Request currently owned by a lower-I/O envelope.
    in_flight: Option<InFlightRead>,
}

impl StorageTranscript {
    /// Starts an empty transcript for one concrete device.
    pub(crate) const fn new(target: StorageTarget, length: DeviceLength) -> Self {
        Self {
            target,
            length,
            completed_reads: Vec::new(),
            pending_request: None,
            in_flight: None,
        }
    }

    /// Returns the validated device length.
    pub(crate) const fn len(&self) -> DeviceLength {
        self.length
    }

    /// Returns whether the current resolve pass produced one request for submission.
    pub(crate) const fn has_pending_request(&self) -> bool {
        self.pending_request.is_some()
    }

    /// Reads an exact range from the retained transcript or requests one owned lower transfer.
    pub(crate) fn read_exact_at(&mut self, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        validate_device_range(self.length, offset, out.len())?;
        if out.is_empty() {
            return Ok(());
        }
        if let Some(read) = self
            .completed_reads
            .iter()
            .find(|read| read.offset == offset && read.bytes.len() == out.len())
        {
            return memory::copy_exact(out, &read.bytes);
        }
        if self.pending_request.is_some() || self.in_flight.is_some() {
            return Err(Error::OperationSuspended);
        }
        let buffer = memory::repeated_vec(0_u8, out.len())?;
        self.pending_request = Some(StorageRequest::Read {
            target: self.target,
            offset,
            buffer,
        });
        Err(Error::OperationSuspended)
    }

    /// Moves the pass-built request into lower-I/O ownership.
    /// # Errors
    ///
    /// Returns an invariant error when no read is pending or another transfer is already in flight.
    pub(crate) fn take_pending_request(&mut self) -> Result<StorageRequest> {
        if self.in_flight.is_some() {
            return Err(Error::DeviceIo);
        }
        let request = self.pending_request.take().ok_or(Error::DeviceIo)?;
        let StorageRequest::Read { offset, buffer, .. } = &request else {
            return Err(Error::DeviceIo);
        };
        self.in_flight = Some(InFlightRead {
            offset: *offset,
            byte_count: buffer.len(),
        });
        Ok(request)
    }

    /// Integrates the one matching lower completion into this transcript.
    /// # Errors
    ///
    /// Returns an error for a failed, short, duplicate, wrong-device, or mismatched completion.
    pub(crate) fn complete(&mut self, completion: StorageCompletion) -> Result<()> {
        let expected = self.in_flight.take().ok_or(Error::DeviceIo)?;
        let (transfer, information, result) = completion.into_parts();
        result?;
        let CompletedStorageTransfer::Read {
            target,
            offset,
            buffer,
        } = transfer
        else {
            return Err(Error::DeviceIo);
        };
        if target != self.target
            || offset != expected.offset
            || buffer.len() != expected.byte_count
            || information != expected.byte_count
        {
            return Err(Error::DeviceIo);
        }
        self.completed_reads.try_push(CompletedRead {
            offset,
            bytes: buffer,
        })
    }
}

/// Concrete device view used only during one synchronous resolve pass.
#[derive(Debug)]
pub(crate) struct OperationDevice<'transcript> {
    /// Operation-owned storage transcript.
    transcript: &'transcript mut StorageTranscript,
    /// Immutable committed overlay applied after each exact backing read.
    overlay: Option<&'transcript dyn StorageReadOverlay>,
}

/// Immutable overlay capable of patching an exact backing-device read.
pub(crate) trait StorageReadOverlay: core::fmt::Debug {
    /// Applies all durable overlay bytes intersecting one completed exact read.
    /// # Errors
    ///
    /// Returns an error when overlay range arithmetic or exact copying fails.
    fn apply(&self, target: StorageTarget, offset: ByteOffset, out: &mut [u8]) -> Result<()>;
}

impl<'transcript> OperationDevice<'transcript> {
    /// Borrows one operation transcript for a synchronous resolve pass.
    pub(crate) const fn new(transcript: &'transcript mut StorageTranscript) -> Self {
        Self {
            transcript,
            overlay: None,
        }
    }

    /// Borrows a transcript together with an immutable committed overlay.
    pub(crate) const fn with_overlay(
        transcript: &'transcript mut StorageTranscript,
        overlay: &'transcript dyn StorageReadOverlay,
    ) -> Self {
        Self {
            transcript,
            overlay: Some(overlay),
        }
    }

    /// Total addressable device length.
    pub(crate) const fn len(&self) -> DeviceLength {
        self.transcript.len()
    }

    /// Reads one exact range or suspends the surrounding resolve pass.
    pub(crate) fn read_exact_at(&mut self, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.transcript.read_exact_at(offset, out)?;
        if let Some(overlay) = self.overlay {
            overlay.apply(self.transcript.target, offset, out)?;
        }
        Ok(())
    }
}

/// Validates one byte range against a concrete device length.
fn validate_device_range(
    length: DeviceLength,
    offset: ByteOffset,
    byte_count: usize,
) -> Result<()> {
    let byte_count = u64::try_from(byte_count).map_err(|_| Error::ArithmeticOverflow)?;
    let end = offset
        .get()
        .checked_add(byte_count)
        .ok_or(Error::ArithmeticOverflow)?;
    if end <= length.bytes() {
        Ok(())
    } else {
        Err(Error::DeviceRange)
    }
}
