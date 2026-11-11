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

    /// Preserves the authoritative native status of a zero-output lower control.
    pub(crate) const fn native_status(status: NTSTATUS) -> Self {
        Self {
            status,
            information: InformationLength::ZERO,
        }
    }

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
            information: match error {
                DriverError::InvalidEaBuffer { offset } => InformationLength {
                    bytes: offset.into(),
                },
                DriverError::ShareAccessConflictDuringOplockBreak => InformationLength {
                    bytes: wdk_sys::FILE_OPBATCH_BREAK_UNDERWAY.into(),
                },
                _ => InformationLength::ZERO,
            },
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

    /// Returns the required security descriptor size with native insufficient-buffer status.
    /// # Errors
    /// Returns an information-field conversion failure before publication.
    pub(crate) fn buffer_too_small(required: usize) -> DriverResult<Self> {
        Ok(Self {
            status: DriverError::BufferTooSmall.ntstatus(),
            information: InformationLength::from_usize(required)?,
        })
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
    /// Storage whose release authority the I/O Manager can assume.
    bytes: ReparseBytes,
}

/// Pool tag identifying create reparse buffers until the I/O Manager releases them.
#[cfg(not(test))]
const REPARSE_POOL_TAG: wdk_sys::ULONG = u32::from_le_bytes(*b"E4rp");

/// Exact-length reparse storage released by `ExFreePool`, by this owner or by the I/O Manager.
///
/// The I/O Manager frees `IRP::Tail.Overlay.AuxiliaryBuffer` as a pool block. The storage is
/// therefore a direct executive-pool allocation rather than a global-allocator layout, whose
/// pointer need not identify a pool block. Host tests have no executive pool and own a box.
#[derive(Debug)]
struct ReparseBytes {
    /// First byte of the nonpaged pool block.
    #[cfg(not(test))]
    address: NonNull<u8>,
    /// Exact initialized byte count of the pool block.
    #[cfg(not(test))]
    length: usize,
    /// Host storage reconstructed by the test that observes the installed pointer.
    #[cfg(test)]
    bytes: Box<[u8]>,
}

impl ReparseBytes {
    /// Allocates zero-initialized storage of exactly `length` nonzero bytes.
    /// # Errors
    ///
    /// Returns an error when the length is not representable or the allocation fails.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the executive pool returns one exclusively owned zero-initialized block"
        )
    )]
    fn try_zeroed(length: usize) -> DriverResult<Self> {
        #[cfg(not(test))]
        {
            let size =
                wdk_sys::SIZE_T::try_from(length).map_err(|_| DriverError::InvalidBufferSize)?;
            let storage = unsafe {
                // SAFETY: The caller supplies a nonzero size; the tag and nonpaged flag request
                // zero-initialized, non-executable pool owned solely by the returned value.
                wdk_sys::ntddk::ExAllocatePool2(
                    wdk_sys::POOL_FLAG_NON_PAGED,
                    size,
                    REPARSE_POOL_TAG,
                )
            };
            let address =
                NonNull::new(storage.cast::<u8>()).ok_or(DriverError::InsufficientResources)?;
            Ok(Self { address, length })
        }
        #[cfg(test)]
        {
            Ok(Self {
                bytes: alloc::vec![0_u8; length].into_boxed_slice(),
            })
        }
    }

    /// Borrows the initialized bytes while this owner retains the allocation.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the unique owner borrows its initialized pool block"
        )
    )]
    fn as_slice(&self) -> &[u8] {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The pool zero-initialized exactly `length` bytes, and this borrow cannot
            // outlive the sole owner of the block.
            core::slice::from_raw_parts(self.address.as_ptr(), self.length)
        }
        #[cfg(test)]
        &self.bytes
    }

    /// Exclusively borrows the initialized bytes for packing.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the exclusive owner borrow excludes every other access to its pool block"
        )
    )]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The block holds `length` initialized bytes and the exclusive borrow of
            // its sole owner excludes every other access.
            core::slice::from_raw_parts_mut(self.address.as_ptr(), self.length)
        }
        #[cfg(test)]
        &mut self.bytes
    }

    /// Transfers release authority to the receiver of the thin block pointer.
    fn into_raw(self) -> *mut u8 {
        #[cfg(not(test))]
        {
            core::mem::ManuallyDrop::new(self).address.as_ptr()
        }
        #[cfg(test)]
        {
            Box::into_raw(self.bytes).cast::<u8>()
        }
    }
}

#[cfg(not(test))]
impl Drop for ReparseBytes {
    #[expect(
        unsafe_code,
        reason = "the sole owner releases its untransferred pool block exactly once"
    )]
    fn drop(&mut self) {
        unsafe {
            // SAFETY: This owner allocated the block and did not transfer it to the I/O Manager.
            wdk_sys::ntddk::ExFreePool(self.address.as_ptr().cast());
        }
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the pool block has no thread affinity and moves only with its unique owner"
)]
// SAFETY: The block is exclusively owned nonpaged memory; moving the owner moves no storage and
// release is valid on any thread.
unsafe impl Send for ReparseBytes {}

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
        let mut bytes = ReparseBytes::try_zeroed(length)?;
        if pack(bytes.as_mut_slice())? != length {
            return Err(DriverError::InternalInvariantViolation);
        }
        Self::validate_header(bytes.as_slice())?;
        Ok(Self { bytes })
    }

    /// Transfers the allocation as the thin pool pointer expected by the IRP auxiliary field.
    pub(super) fn into_raw(self) -> *mut wdk_sys::CHAR {
        self.bytes.into_raw().cast::<wdk_sys::CHAR>()
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
    /// An existing stream was overwritten while retaining its creation metadata.
    Overwritten,
    /// An existing stream and its creation metadata were superseded.
    Superseded,
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
            Self::Overwritten => wdk_sys::FILE_OVERWRITTEN,
            Self::Superseded => wdk_sys::FILE_SUPERSEDED,
            Self::TargetExists => wdk_sys::FILE_EXISTS,
            Self::TargetDoesNotExist => wdk_sys::FILE_DOES_NOT_EXIST,
        }
    }
}
