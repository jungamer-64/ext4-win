//! IRP completion values, create outcomes, and queue-context identities.

use super::*;

/// Completion priority boost for IRPs that should not adjust thread priority.
#[cfg(not(test))]
pub(super) const IO_NO_INCREMENT_PRIORITY: wdk_sys::CCHAR = 0;

/// Stable allocation-free marker storage for queued cleanup and close operations.
///
/// Both identities are offsets inside one object, so linker constant folding cannot merge them.
static QUEUE_CONTEXT_MARKERS: [u8; 2] = [0; 2];
/// Marker offset for a queued cleanup barrier.
pub(super) const CLEANUP_QUEUE_CONTEXT_MARKER: usize = 0;
/// Marker offset for a queued close operation.
pub(super) const CLOSE_QUEUE_CONTEXT_MARKER: usize = 1;

/// Returns one stable allocation-free queue-context marker identity.
pub(super) fn queue_context_marker(index: usize) -> *mut c_void {
    core::ptr::addr_of!(QUEUE_CONTEXT_MARKERS)
        .cast::<u8>()
        .wrapping_add(index)
        .cast_mut()
        .cast::<c_void>()
}

/// `STATUS_CANCELLED` is not emitted by the current `wdk-sys` bindings.
const STATUS_CANCELLED: NTSTATUS = i32::from_ne_bytes(0xC000_0120_u32.to_ne_bytes());

/// Byte count completed in `IO_STATUS_BLOCK::Information`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InformationLength {
    /// WDK-sized information payload.
    bytes: wdk_sys::ULONG_PTR,
}

impl InformationLength {
    /// Zero-byte completion.
    pub(crate) const ZERO: Self = Self { bytes: 0 };

    /// Builds an information length from a Rust byte count.
    /// # Errors
    ///
    /// Returns an error when `bytes` cannot be represented in `IO_STATUS_BLOCK::Information`.
    pub(crate) fn from_usize(bytes: usize) -> DriverResult<Self> {
        Ok(Self {
            bytes: wdk_sys::ULONG_PTR::try_from(bytes)
                .map_err(|_| DriverError::InvalidParameter)?,
        })
    }

    /// Returns the WDK payload for the IRP boundary.
    pub(super) const fn as_ulong_ptr(self) -> wdk_sys::ULONG_PTR {
        self.bytes
    }
}

/// Complete IRP status block payload at the NTSTATUS dispatch boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IrpCompletion {
    /// NTSTATUS returned to the I/O Manager.
    status: NTSTATUS,
    /// Completed information byte count.
    information: InformationLength,
}

impl IrpCompletion {
    /// Successful completion without output bytes.
    pub(crate) const EMPTY: Self = Self {
        status: STATUS_SUCCESS,
        information: InformationLength::ZERO,
    };

    /// Builds a successful completion from an information length.
    pub(crate) const fn with_information(information: InformationLength) -> Self {
        Self {
            status: STATUS_SUCCESS,
            information,
        }
    }

    /// Builds a successful completion from a Rust byte count.
    /// # Errors
    ///
    /// Returns an error when `bytes` cannot be represented in the IRP information field.
    pub(crate) fn from_usize(bytes: usize) -> DriverResult<Self> {
        Ok(Self::with_information(InformationLength::from_usize(
            bytes,
        )?))
    }

    /// Converts a driver error into a completed failed IRP payload.
    pub(crate) fn from_error(error: DriverError) -> Self {
        Self {
            status: error.ntstatus(),
            information: InformationLength::ZERO,
        }
    }

    /// Replaces only the status after an irreversible operation has already committed bytes.
    pub(crate) const fn committed_failure(self, error: DriverError) -> Self {
        Self {
            status: error.ntstatus(),
            information: self.information,
        }
    }

    /// Preserves one failed status raised by the native requestor-memory capture boundary.
    pub(super) const fn from_native_failure(status: NTSTATUS) -> Self {
        Self {
            status,
            information: InformationLength::ZERO,
        }
    }

    /// Builds a buffer-overflow result that preserves the operation-specific information length.
    /// # Errors
    ///
    /// Returns an error when `information` cannot be represented in the IRP information field.
    pub(crate) fn buffer_overflow(information: usize) -> DriverResult<Self> {
        Ok(Self {
            status: DriverError::BufferOverflow.ntstatus(),
            information: InformationLength::from_usize(information)?,
        })
    }

    /// Builds a canceled IRP completion payload.
    pub(super) const fn cancelled() -> Self {
        Self {
            status: STATUS_CANCELLED,
            information: InformationLength::ZERO,
        }
    }

    /// Returns the NTSTATUS for the IRP status block and dispatch return.
    pub(super) const fn status(self) -> NTSTATUS {
        self.status
    }

    /// Returns the typed information length.
    pub(super) const fn information(self) -> InformationLength {
        self.information
    }
}

/// Owned, exact-length symbolic-link buffer returned to the I/O Manager for create-name reparsing.
///
/// Dropping this value releases the allocation. Ownership leaves Rust only when a successful
/// create symlink completion installs the allocation in `IRP::Tail.Overlay.AuxiliaryBuffer`.
#[derive(Debug)]
pub(crate) struct CreateSymlinkReparseBuffer {
    /// Nonpaged bytes in driver builds and ordinary globally allocated bytes in tests.
    bytes: Box<[u8]>,
}

impl CreateSymlinkReparseBuffer {
    /// Allocates, packs, and seals one exact-length symbolic-link reparse buffer.
    /// # Errors
    ///
    /// Returns an error when `length` is zero or not representable, allocation or packing fails,
    /// the packer writes a different length, or the completed header is not an exact symlink
    /// reparse buffer.
    pub(crate) fn try_pack_exact(
        length: usize,
        pack: impl FnOnce(&mut [u8]) -> DriverResult<usize>,
    ) -> DriverResult<Self> {
        if length == 0 {
            return Err(DriverError::InvalidBufferSize);
        }
        let mut bytes = memory::boxed_zeroed_bytes(length)?;
        if pack(&mut bytes)? != length {
            return Err(DriverError::InternalInvariantViolation);
        }
        Self::validate_header(&bytes)?;
        Ok(Self { bytes })
    }

    /// Transfers the allocation as the thin pool pointer expected by the IRP auxiliary field.
    pub(super) fn into_raw(self) -> *mut wdk_sys::CHAR {
        Box::into_raw(self.bytes)
            .cast::<u8>()
            .cast::<wdk_sys::CHAR>()
    }

    /// Verifies the tag and exact `ReparseDataLength` before the buffer becomes completable.
    /// # Errors
    ///
    /// Returns an internal-invariant error when the packed header is truncated, uses another tag,
    /// exceeds the Windows reparse limit, or declares a non-exact payload length.
    fn validate_header(bytes: &[u8]) -> DriverResult<()> {
        const REPARSE_HEADER_LENGTH: usize = 8;
        const SYMLINK_PAYLOAD_HEADER_LENGTH: usize = 12;

        let maximum_length = usize::try_from(wdk_sys::MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        if bytes.len() > maximum_length {
            return Err(DriverError::InternalInvariantViolation);
        }
        let input = LittleEndianInput::new(bytes);
        let tag = input
            .read_u32(WireOffset::new(0))
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        if tag != wdk_sys::IO_REPARSE_TAG_SYMLINK {
            return Err(DriverError::InternalInvariantViolation);
        }
        let data_length = usize::from(
            input
                .read_u16(WireOffset::new(4))
                .map_err(|_| DriverError::InternalInvariantViolation)?,
        );
        if data_length < SYMLINK_PAYLOAD_HEADER_LENGTH
            || REPARSE_HEADER_LENGTH.checked_add(data_length) != Some(bytes.len())
        {
            return Err(DriverError::InternalInvariantViolation);
        }
        Ok(())
    }
}

/// Mutually exclusive terminal outcomes of a create/open request.
#[derive(Debug)]
#[must_use]
pub(crate) enum CreateCompletion {
    /// A handle was established with one exact Windows create action.
    Handle(CreateAction),
    /// A handle was established while its requested nonblocking oplock break remains underway.
    OplockBreakInProgress(CreateAction),
    /// Name resolution must continue through the Microsoft symbolic-link reparse handler.
    ReparseSymlink(CreateSymlinkReparseBuffer),
}

/// Successful Windows create action stored in `IO_STATUS_BLOCK::Information`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateAction {
    /// An existing object was opened without destructive mutation.
    Opened,
    /// A missing object was created.
    Created,
    /// `SL_OPEN_TARGET_DIRECTORY` opened the parent and the named target exists.
    TargetExists,
    /// `SL_OPEN_TARGET_DIRECTORY` opened the parent and the named target is absent.
    TargetDoesNotExist,
}

impl CreateAction {
    /// Returns the WDK `FILE_*` create action value.
    pub(super) const fn as_ulong(self) -> wdk_sys::ULONG {
        match self {
            Self::Opened => wdk_sys::FILE_OPENED,
            Self::Created => wdk_sys::FILE_CREATED,
            Self::TargetExists => wdk_sys::FILE_EXISTS,
            Self::TargetDoesNotExist => wdk_sys::FILE_DOES_NOT_EXIST,
        }
    }
}
