//! Typed kernel-object identities and transfer constraints at the WDK boundary.

use super::*;

/// Non-null kernel device object pointer at the WDK boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelDevice {
    /// Non-null opaque WDK device pointer.
    device: NonNull<c_void>,
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: WDM device objects are I/O Manager-owned, nonpaged objects that may be dispatched on any
// processor. This boundary exposes only stable identity and immutable device properties; teardown
// contracts require every reactor operation and lower completion to drain before deletion.
unsafe impl Send for KernelDevice {}
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Shared copies do not grant Rust mutation of the DEVICE_OBJECT.
unsafe impl Sync for KernelDevice {}

impl KernelDevice {
    /// Converts a raw WDK device pointer into the non-null boundary type.
    /// # Safety
    ///
    /// A non-null pointer must identify a live I/O Manager-owned `DEVICE_OBJECT` for every use of
    /// the returned value.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn from_raw(device: PDEVICE_OBJECT) -> Option<Self> {
        NonNull::new(device.cast()).map(|device| Self { device })
    }

    /// Returns the raw WDK device pointer for FFI calls.
    pub(crate) fn as_ptr(self) -> PDEVICE_OBJECT {
        self.device.as_ptr().cast()
    }

    /// Returns the owning driver object for creating sibling device objects.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn driver_object(self) -> Option<PDRIVER_OBJECT> {
        let device = unsafe {
            // SAFETY: `self` is a non-null DEVICE_OBJECT pointer decoded at the
            // driver boundary and is only read for its stable DriverObject field.
            self.as_ptr().as_ref()
        }?;
        NonNull::new(device.DriverObject).map(NonNull::as_ptr)
    }

    /// Returns the lower-device stack size advertised by the I/O Manager.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn stack_size(self) -> Option<i8> {
        let device = unsafe {
            // SAFETY: `self` is a non-null DEVICE_OBJECT pointer decoded at the
            // driver boundary and is only read for StackSize propagation.
            self.as_ptr().as_ref()
        }?;
        Some(device.StackSize)
    }

    /// Returns the device transfer buffer alignment advertised by the I/O Manager.
    /// # Errors
    ///
    /// Returns an error when the device object is invalid or its alignment mask is malformed.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn transfer_buffer_alignment(self) -> DriverResult<TransferBufferAlignment> {
        let device = unsafe {
            // SAFETY: `self` is a non-null DEVICE_OBJECT pointer decoded at the
            // driver boundary and is only read for AlignmentRequirement propagation.
            self.as_ptr().as_ref()
        }
        .ok_or(DriverError::InvalidParameter)?;
        TransferBufferAlignment::from_requirement_mask(device.AlignmentRequirement)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Required alignment for direct transfer buffers.
pub(crate) struct TransferBufferAlignment {
    /// WDK alignment mask, where `0` means byte-aligned and `511` means 512-byte aligned.
    mask: usize,
    /// Original WDK alignment mask.
    raw_mask: wdk_sys::ULONG,
}

impl TransferBufferAlignment {
    /// Decodes a WDK `DEVICE_OBJECT::AlignmentRequirement` mask.
    /// # Errors
    ///
    /// Returns an error when the mask cannot represent a power-of-two byte alignment.
    pub(super) fn from_requirement_mask(raw_mask: wdk_sys::ULONG) -> DriverResult<Self> {
        let mask = usize::try_from(raw_mask).map_err(|_| DriverError::InvalidParameter)?;
        let alignment = mask.checked_add(1).ok_or(DriverError::InvalidParameter)?;
        if !alignment.is_power_of_two() {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self { mask, raw_mask })
    }

    /// Returns whether `address` satisfies this transfer-buffer alignment.
    fn accepts(self, address: NonNull<u8>) -> bool {
        address.as_ptr().cast_const().addr() & self.mask == 0
    }

    /// Returns the raw WDK alignment mask.
    pub(super) const fn as_mask(self) -> wdk_sys::ULONG {
        self.raw_mask
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Byte multiple required for no-intermediate file ranges.
pub(crate) struct TransferSectorSize {
    /// Sector byte count exposed by this filesystem.
    bytes: u32,
}

impl TransferSectorSize {
    /// Sector size currently reported through `FileFs*SizeInformation`.
    pub(crate) const WINDOWS_REPORTED: Self = Self { bytes: 512 };

    /// Returns the sector size in bytes.
    pub(crate) const fn as_u32(self) -> u32 {
        self.bytes
    }

    /// Returns whether `value` is an integral sector multiple.
    /// # Errors
    ///
    /// Returns an error when the sector byte count cannot be represented as a native `usize`.
    fn divides(self, value: usize) -> DriverResult<bool> {
        let bytes = usize::try_from(self.bytes).map_err(|_| DriverError::InvalidParameter)?;
        Ok(value.is_multiple_of(bytes))
    }

    /// Returns whether `value` is an integral sector multiple.
    fn divides_u64(self, value: u64) -> bool {
        value.is_multiple_of(u64::from(self.bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Concrete constraints for a handle opened without intermediate buffering.
pub(crate) struct NoIntermediateTransfer {
    /// Sector multiple required for read/write ranges.
    pub(super) sector_size: TransferSectorSize,
    /// Buffer alignment required by the mounted storage stack.
    pub(super) buffer_alignment: TransferBufferAlignment,
}

impl NoIntermediateTransfer {
    /// Builds no-intermediate transfer constraints from the mounted device boundary.
    /// # Errors
    ///
    /// Returns an error when the mounted device cannot expose a valid transfer alignment.
    pub(crate) fn from_device(device: KernelDevice) -> DriverResult<Self> {
        Ok(Self {
            sector_size: TransferSectorSize::WINDOWS_REPORTED,
            buffer_alignment: device.transfer_buffer_alignment()?,
        })
    }

    /// Validates one read/write byte range.
    /// # Errors
    ///
    /// Returns an error when the offset or length is not sector-aligned.
    fn validate_range(self, byte_offset: u64, byte_count: usize) -> DriverResult<()> {
        if !self.sector_size.divides_u64(byte_offset) || !self.sector_size.divides(byte_count)? {
            return Err(DriverError::InvalidParameter);
        }
        Ok(())
    }

    /// Validates one persistent FILE_OBJECT byte position.
    /// # Errors
    ///
    /// Returns an error when the position is not sector-aligned.
    fn validate_position(self, byte_offset: u64) -> DriverResult<()> {
        if !self.sector_size.divides_u64(byte_offset) {
            return Err(DriverError::InvalidParameter);
        }
        Ok(())
    }

    /// Validates one transfer buffer address.
    /// # Errors
    ///
    /// Returns an error when the buffer does not satisfy the device alignment.
    fn validate_buffer(self, address: NonNull<u8>) -> DriverResult<()> {
        if !self.buffer_alignment.accepts(address) {
            return Err(DriverError::InvalidParameter);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Per-handle data transfer buffering policy.
pub(crate) enum DataTransferMode {
    /// The stream participates in Cache Manager coherency and paging writeback.
    Cached,
    /// Every non-empty transfer must satisfy no-intermediate-buffering constraints.
    Direct(NoIntermediateTransfer),
}

impl DataTransferMode {
    /// Validates one read/write byte range for this handle.
    /// # Errors
    ///
    /// Returns an error when no-intermediate buffering requires stricter alignment.
    pub(crate) fn validate_range(self, byte_offset: u64, byte_count: usize) -> DriverResult<()> {
        match self {
            Self::Cached => Ok(()),
            Self::Direct(transfer) => transfer.validate_range(byte_offset, byte_count),
        }
    }

    /// Validates one persistent FILE_OBJECT byte position for this handle.
    /// # Errors
    ///
    /// Returns an error when no-intermediate buffering requires sector alignment.
    pub(crate) fn validate_position(self, byte_offset: u64) -> DriverResult<()> {
        match self {
            Self::Cached => Ok(()),
            Self::Direct(transfer) => transfer.validate_position(byte_offset),
        }
    }

    /// Validates a non-empty transfer buffer for this handle.
    /// # Errors
    ///
    /// Returns an error when no-intermediate buffering requires stricter alignment.
    pub(crate) fn validate_buffer(self, address: NonNull<u8>) -> DriverResult<()> {
        match self {
            Self::Cached => Ok(()),
            Self::Direct(transfer) => transfer.validate_buffer(address),
        }
    }
}

/// Non-null kernel file object pointer at the WDK boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelFileObject {
    /// Non-null opaque WDK file object pointer.
    file_object: NonNull<FILE_OBJECT>,
}

/// Windows reason that permits FILE_OBJECT context release at close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileObjectCloseKind {
    /// The ordinary handle lifecycle must already have completed cleanup.
    Ordinary,
    /// A filter cancelled the successful create before any handle was created.
    CancelledOpen,
}

impl KernelFileObject {
    /// Converts a raw WDK file object pointer into the non-null boundary type.
    /// # Safety
    ///
    /// A non-null pointer must identify a live I/O Manager-owned `FILE_OBJECT` retained by the
    /// operation that uses the returned value.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn from_raw(file_object: *mut FILE_OBJECT) -> Option<Self> {
        NonNull::new(file_object).map(|file_object| Self { file_object })
    }

    /// Returns the raw WDK pointer for FFI calls that require FILE_OBJECT.
    pub(crate) const fn as_ptr(self) -> *mut FILE_OBJECT {
        self.file_object.as_ptr()
    }

    /// Returns the non-null typed pointer for lifetime-bounded native wrappers.
    pub(crate) const fn as_non_null(self) -> NonNull<FILE_OBJECT> {
        self.file_object
    }

    /// Publishes one already range-checked current-byte offset.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn write_current_byte_offset(self, position: i64) {
        unsafe {
            // SAFETY: The owning active-operation token retains this FILE_OBJECT and prevalidated
            // the signed position before constructing its publication value.
            (*self.as_ptr()).CurrentByteOffset = LARGE_INTEGER { QuadPart: position };
        }
    }
}

impl ActiveFileObject<'_> {
    /// Returns whether neither filesystem context has been attached to this FILE_OBJECT.
    pub(crate) fn has_no_file_system_contexts(self) -> bool {
        let object = self.as_ref();
        object.FsContext.is_null() && object.FsContext2.is_null()
    }

    /// Returns whether this filesystem has completed cleanup for this active FILE_OBJECT.
    pub(crate) fn cleanup_complete(self) -> bool {
        self.as_ref().Flags & wdk_sys::FO_CLEANUP_COMPLETE != 0
    }

    /// Publishes completion of every cleanup-owned release as the final cleanup mutation.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn mark_cleanup_complete(self) {
        unsafe {
            // SAFETY: Cleanup is the unique lifecycle transition that publishes this
            // filesystem-owned flag while the active IRP keeps the FILE_OBJECT live.
            (*self.as_ptr()).Flags |= wdk_sys::FO_CLEANUP_COMPLETE;
        }
    }

    /// Decodes the I/O Manager's close reason from stable FILE_OBJECT flags.
    ///
    /// A cancelled open that also claims a created handle violates the `IoCancelFileOpen`
    /// contract and cannot be recovered without risking a double lifecycle release.
    pub(crate) fn close_kind_or_bugcheck(self) -> FileObjectCloseKind {
        let flags = self.as_ref().Flags;
        let cancelled = flags & wdk_sys::FO_FILE_OPEN_CANCELLED != 0;
        let handle_created = flags & wdk_sys::FO_HANDLE_CREATED != 0;
        match (cancelled, handle_created) {
            (true, true) => KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck(),
            (true, false) => FileObjectCloseKind::CancelledOpen,
            (false, _) => FileObjectCloseKind::Ordinary,
        }
    }

    /// Writes the synchronized current position while the owning operation is serialized.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn write_current_byte_offset(self, position: i64) {
        unsafe {
            // SAFETY: The caller has validated synchronous-handle serialization and this active
            // view keeps the FILE_OBJECT live for the write.
            (*self.as_ptr()).CurrentByteOffset = LARGE_INTEGER { QuadPart: position };
        }
    }
}

/// FILE_OBJECT during create before filesystem contexts are attached.
#[derive(Debug)]
pub(crate) struct UninitializedFileObject<'owner> {
    /// Kernel FILE_OBJECT that has not yet been opened by this filesystem.
    file_object: ActiveFileObject<'owner>,
}

impl<'owner> UninitializedFileObject<'owner> {
    /// Decodes a create target whose FCB and CCB slots are both empty.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT already has filesystem-owned FCB or CCB context.
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
        let object = file_object.as_ref();
        if !object.FsContext.is_null() || !object.FsContext2.is_null() {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self { file_object })
    }

    /// Returns the underlying kernel FILE_OBJECT for FFI calls.
    pub(crate) const fn kernel_file_object(&self) -> KernelFileObject {
        self.file_object.address()
    }

    /// Returns the related opened FILE_OBJECT retained by this active create IRP, when present.
    pub(crate) fn related_file_object(&self) -> Option<ActiveFileObject<'owner>> {
        self.file_object.related_file_object()
    }

    /// Returns the immutable create-time FILE_OBJECT.
    pub(crate) fn as_ref(&self) -> &FILE_OBJECT {
        self.file_object.as_ref()
    }

    /// Returns the unpublished create-time FILE_OBJECT at its unique attachment point.
    ///
    /// # Safety
    /// The caller must own the sole successful-create attachment transition for this FILE_OBJECT.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn as_mut(&mut self) -> &mut FILE_OBJECT {
        unsafe {
            // SAFETY: This non-copy typestate is constructed only while FsContext/FsContext2 are
            // both null, and successful create consumes its sole attachment point.
            &mut *self.file_object.as_ptr()
        }
    }
}

/// Non-null VPB pointer supplied by the I/O Manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelVpb {
    /// Non-null WDK VPB pointer.
    vpb: NonNull<wdk_sys::VPB>,
}

impl KernelVpb {
    /// Converts a raw WDK VPB pointer into the non-null boundary type.
    /// # Safety
    ///
    /// A non-null pointer must identify a live I/O Manager-owned `VPB` for the mount operation.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn from_raw(vpb: *mut wdk_sys::VPB) -> Option<Self> {
        NonNull::new(vpb).map(|vpb| Self { vpb })
    }

    /// Returns the non-null VPB pointer for mount-time device initialization.
    pub(crate) const fn as_non_null(self) -> NonNull<wdk_sys::VPB> {
        self.vpb
    }
}
