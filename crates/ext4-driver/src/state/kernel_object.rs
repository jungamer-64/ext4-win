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

    /// Copies the extension address without borrowing the externally mutable device object.
    #[expect(
        unsafe_code,
        reason = "the retained device owns a stable extension pointer"
    )]
    pub(super) fn extension_address(self) -> *mut c_void {
        unsafe {
            // SAFETY: The retained device's extension allocation is fixed until deletion. This
            // scalar read does not borrow independently mutable device lifecycle or queue fields.
            (*self.as_ptr()).DeviceExtension
        }
    }

    /// Returns the owning driver object for creating sibling device objects.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn driver_object(self) -> Option<PDRIVER_OBJECT> {
        let driver = unsafe {
            // SAFETY: This retained non-null device has a stable DriverObject field. The scalar
            // read leaves the I/O Manager's independently mutable device fields unborrowed.
            (*self.as_ptr()).DriverObject
        };
        NonNull::new(driver).map(NonNull::as_ptr)
    }

    /// Returns the lower-device stack size advertised by the I/O Manager.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn stack_size(self) -> Option<i8> {
        let size = unsafe {
            // SAFETY: The retained device's stack depth is stable through lower-I/O admission;
            // no reference is formed to independent device lifecycle or queue fields.
            (*self.as_ptr()).StackSize
        };
        Some(size)
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
        let alignment = unsafe {
            // SAFETY: The retained device's alignment is stable through lower-I/O admission;
            // this scalar read does not borrow independently mutable device fields.
            (*self.as_ptr()).AlignmentRequirement
        };
        TransferBufferAlignment::from_requirement_mask(alignment)
    }

    /// Captures the logical transfer unit advertised by this live device.
    /// # Errors
    ///
    /// Rejects absent, zero or non-power-of-two sector geometry.
    #[expect(
        unsafe_code,
        reason = "the live device identity retains immutable transfer geometry"
    )]
    pub(crate) fn transfer_sector_size(self) -> DriverResult<TransferSectorSize> {
        let sector_size = unsafe {
            // SAFETY: The retained device's transfer geometry is stable through lower-I/O
            // admission; the I/O Manager's independently mutable fields remain unborrowed.
            (*self.as_ptr()).SectorSize
        };
        TransferSectorSize::from_bytes(u32::from(sector_size))
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
    /// Establishes the nonzero power-of-two transfer unit.
    /// # Errors
    ///
    /// Rejects invalid device geometry before divisibility checks may use it.
    pub(crate) fn from_bytes(bytes: u32) -> DriverResult<Self> {
        if !bytes.is_power_of_two() {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self { bytes })
    }

    /// Returns the sector size in bytes.
    pub(crate) const fn as_u32(self) -> u32 {
        self.bytes
    }

    /// Converts one allocation cluster to an integral count of logical sectors.
    /// # Errors
    ///
    /// Rejects allocation units smaller than, or not divisible by, this device's logical sector.
    pub(crate) fn sectors_per_cluster(self, cluster: ClusterSize) -> DriverResult<u32> {
        let bytes = cluster.bytes();
        if bytes < self.bytes || !bytes.is_multiple_of(self.bytes) {
            return Err(DriverError::InvalidParameter);
        }
        bytes
            .checked_div(self.bytes)
            .ok_or(DriverError::InvalidParameter)
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
    /// Returns an error when the mounted device has invalid sector geometry or buffer alignment.
    pub(crate) fn from_device(device: KernelDevice) -> DriverResult<Self> {
        Ok(Self {
            sector_size: device.transfer_sector_size()?,
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

    /// Publishes the prepared filesystem contexts through the unique successful-create boundary.
    /// # Safety
    /// The caller must own the sole attachment transition of this live FILE_OBJECT. The prepared
    /// header, CCB and section storage must remain live until the corresponding close releases them.
    #[expect(
        unsafe_code,
        reason = "successful create owns each filesystem publication field"
    )]
    pub(crate) unsafe fn publish_stream_contexts(
        self,
        header: *mut c_void,
        handle: *mut c_void,
        sections: *mut wdk_sys::SECTION_OBJECT_POINTERS,
        flags: wdk_sys::ULONG,
    ) {
        unsafe {
            // SAFETY: Sole create attachment owns these flag bits and preserves existing OS flags.
            (*self.as_ptr()).Flags |= flags;
        }
        unsafe {
            // SAFETY: The caller transfers the prepared stream header's lifetime to this open.
            (*self.as_ptr()).FsContext = header;
        }
        unsafe {
            // SAFETY: The caller transfers the prepared CCB's release ownership to this open.
            (*self.as_ptr()).FsContext2 = handle;
        }
        unsafe {
            // SAFETY: The caller retains section storage with the published stream header.
            (*self.as_ptr()).SectionObjectPointer = sections;
        }
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
    /// Copies flags without borrowing the externally mutable FILE_OBJECT.
    #[expect(
        unsafe_code,
        reason = "the active IRP retains the FILE_OBJECT for this field read"
    )]
    pub(crate) fn flags(self) -> wdk_sys::ULONG {
        unsafe {
            // SAFETY: The active owner retains this initialized field; lifecycle and position
            // mutations remain serialized by the existing handle protocol.
            (*self.as_ptr()).Flags
        }
    }

    /// Copies the filesystem-owned stream header identity.
    #[expect(
        unsafe_code,
        reason = "the active IRP retains its published filesystem context"
    )]
    pub(crate) fn stream_header(self) -> *mut c_void {
        unsafe {
            // SAFETY: Create publishes this context before ordinary admission and close clears it
            // only after active handle operations drain. No native object reference is retained.
            (*self.as_ptr()).FsContext
        }
    }

    /// Copies the filesystem-owned handle context identity.
    #[expect(
        unsafe_code,
        reason = "the active IRP retains its published handle context"
    )]
    pub(crate) fn handle_context(self) -> *mut c_void {
        unsafe {
            // SAFETY: The active handle lifecycle retains this initialized CCB pointer.
            (*self.as_ptr()).FsContext2
        }
    }

    /// Copies the section storage identity retained by this opened stream.
    #[expect(
        unsafe_code,
        reason = "the active IRP retains the initialized section pointer"
    )]
    pub(crate) fn section_objects(self) -> *mut wdk_sys::SECTION_OBJECT_POINTERS {
        unsafe {
            // SAFETY: This pointer is fixed at successful create until terminal close.
            (*self.as_ptr()).SectionObjectPointer
        }
    }

    /// Copies the Windows byte position under the existing handle serialization protocol.
    #[expect(
        unsafe_code,
        reason = "the active IRP retains the initialized position union arm"
    )]
    pub(crate) fn current_byte_offset(self) -> i64 {
        let position = unsafe {
            // SAFETY: The active owner and existing handle serialization retain only this
            // initialized position field; no reference to the containing FILE_OBJECT is created.
            &(*self.as_ptr()).CurrentByteOffset
        };
        unsafe {
            // SAFETY: Windows and this driver use the initialized QuadPart arm. Existing handle
            // serialization protects position access without borrowing other FILE_OBJECT fields.
            position.QuadPart
        }
    }

    /// Returns whether neither filesystem context has been attached to this FILE_OBJECT.
    pub(crate) fn has_no_file_system_contexts(self) -> bool {
        self.stream_header().is_null() && self.handle_context().is_null()
    }

    /// Returns whether this filesystem has completed cleanup for this active FILE_OBJECT.
    pub(crate) fn cleanup_complete(self) -> bool {
        self.flags() & wdk_sys::FO_CLEANUP_COMPLETE != 0
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
        let flags = self.flags();
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
        if !file_object.has_no_file_system_contexts() {
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

    /// Borrows the create name as bytes while the active request retains its name allocation.
    /// # Errors
    /// Returns invalid-parameter for a missing or inconsistent nonempty name descriptor.
    #[expect(
        unsafe_code,
        reason = "the I/O Manager retains the active create name allocation"
    )]
    pub(crate) fn name_bytes(&self) -> DriverResult<&[u8]> {
        let name = unsafe {
            // SAFETY: The active create owner retains its initialized, stable name descriptor.
            (*self.file_object.as_ptr()).FileName
        };
        let length = usize::from(name.Length);
        if length == 0 {
            return Ok(&[]);
        }
        if name.Length > name.MaximumLength || name.Buffer.is_null() {
            return Err(DriverError::InvalidParameter);
        }
        unsafe {
            // SAFETY: The I/O Manager's create-name contract retains these initialized bytes.
            // The checked u16 length fits one allocation and the result cannot outlive this view.
            Ok(core::slice::from_raw_parts(
                name.Buffer.cast::<u8>(),
                length,
            ))
        }
    }

    /// Borrows the create name as UTF-16 without retaining a reference to the FILE_OBJECT.
    /// # Errors
    /// Returns invalid-parameter for a missing, inconsistent, odd-length or misaligned name.
    #[expect(
        unsafe_code,
        reason = "the checked create name is aligned initialized UTF-16 storage"
    )]
    pub(crate) fn name_utf16(&self) -> DriverResult<&[u16]> {
        let bytes = self.name_bytes()?;
        if bytes.is_empty() {
            return Ok(&[]);
        }
        if !bytes.len().is_multiple_of(core::mem::size_of::<u16>())
            || !bytes.as_ptr().cast::<u16>().is_aligned()
        {
            return Err(DriverError::InvalidParameter);
        }
        unsafe {
            // SAFETY: name_bytes established the initialized allocation and owner-bound lifetime;
            // the checks above establish alignment and a whole number of UTF-16 code units.
            Ok(core::slice::from_raw_parts(
                bytes.as_ptr().cast::<u16>(),
                bytes.len() / 2,
            ))
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
