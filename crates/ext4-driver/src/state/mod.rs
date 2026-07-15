//! Driver-local lifecycle and open-object state.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::fmt;
use core::marker::{PhantomData, PhantomPinned};
#[cfg(not(test))]
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};
#[cfg(test)]
use std::sync::{Mutex, MutexGuard};

use ext4_core::{
    DeviceLength, DirectoryNodeId, Ext4Name, Ext4Timestamp, FileNodeId, FileOffset,
    FscryptKeyIdentifier, FscryptKeyPresence, FscryptKeySet, FscryptMasterKey, InternalJournal,
    JournalTransaction, JournaledVolume, MountContext, NewDirectoryMetadata, NewFileMetadata,
    NodeId, WindowsName, XattrName, XattrValue,
};
use wdk_sys::{
    DO_DEVICE_INITIALIZING, DO_DIRECT_IO, FILE_OBJECT, LARGE_INTEGER, PDEVICE_OBJECT,
    PDRIVER_OBJECT, SHARE_ACCESS, STATUS_SUCCESS, UNICODE_STRING, VPB_MOUNTED,
};
#[cfg(not(test))]
use wdk_sys::{LIST_ENTRY, PNOTIFY_SYNC, STATUS_PENDING};

use crate::irp::{
    ByteRangeLockKey, DataIoKind, DesiredAccess, DeviceExecutor, DirectoryEntryIndex,
    DispatchTarget, ExistingOperationAccess, RegularFileWriteAccess, ShareAccess,
};
use crate::kernel::cng::CngFscryptNonceGenerator;
use crate::kernel::fatal::KernelWideInconsistency;
use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::{block_device::KernelBlockDevice, ffi};
use crate::memory::{self, DriverVec};

/// Registered control device observed by the unload callback.
static mut CONTROL_DEVICE: Option<ControlDevice> = None;

/// Non-null kernel device object pointer at the WDK boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelDevice {
    /// Non-null opaque WDK device pointer.
    device: NonNull<c_void>,
}

// SAFETY: WDM device objects are I/O Manager-owned, nonpaged objects that may be dispatched on any
// processor. This boundary exposes only stable identity and immutable device properties; teardown
// contracts require every executor task and lower completion to drain before deletion.
unsafe impl Send for KernelDevice {}
// SAFETY: Shared copies do not grant Rust mutation of the DEVICE_OBJECT.
unsafe impl Sync for KernelDevice {}

impl KernelDevice {
    /// Converts a raw WDK device pointer into the non-null boundary type.
    pub(crate) fn from_raw(device: PDEVICE_OBJECT) -> Option<Self> {
        NonNull::new(device.cast()).map(|device| Self { device })
    }

    /// Returns the raw WDK device pointer for FFI calls.
    pub(crate) fn as_ptr(self) -> PDEVICE_OBJECT {
        self.device.as_ptr().cast()
    }

    /// Returns the owning driver object for creating sibling device objects.
    pub(crate) fn driver_object(self) -> Option<PDRIVER_OBJECT> {
        let device = unsafe {
            // SAFETY: `self` is a non-null DEVICE_OBJECT pointer decoded at the
            // driver boundary and is only read for its stable DriverObject field.
            self.as_ptr().as_ref()
        }?;
        NonNull::new(device.DriverObject).map(NonNull::as_ptr)
    }

    /// Returns the lower-device stack size advertised by the I/O Manager.
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
    fn from_requirement_mask(raw_mask: wdk_sys::ULONG) -> DriverResult<Self> {
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
    const fn as_mask(self) -> wdk_sys::ULONG {
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
    sector_size: TransferSectorSize,
    /// Buffer alignment required by the mounted storage stack.
    buffer_alignment: TransferBufferAlignment,
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
    /// The filesystem may use ordinary intermediate buffering behavior.
    IntermediateAllowed,
    /// Every non-empty transfer must satisfy no-intermediate-buffering constraints.
    NoIntermediate(NoIntermediateTransfer),
}

impl DataTransferMode {
    /// Validates one read/write byte range for this handle.
    /// # Errors
    ///
    /// Returns an error when no-intermediate buffering requires stricter alignment.
    pub(crate) fn validate_range(self, byte_offset: u64, byte_count: usize) -> DriverResult<()> {
        match self {
            Self::IntermediateAllowed => Ok(()),
            Self::NoIntermediate(transfer) => transfer.validate_range(byte_offset, byte_count),
        }
    }

    /// Validates one persistent FILE_OBJECT byte position for this handle.
    /// # Errors
    ///
    /// Returns an error when no-intermediate buffering requires sector alignment.
    pub(crate) fn validate_position(self, byte_offset: u64) -> DriverResult<()> {
        match self {
            Self::IntermediateAllowed => Ok(()),
            Self::NoIntermediate(transfer) => transfer.validate_position(byte_offset),
        }
    }

    /// Validates a non-empty transfer buffer for this handle.
    /// # Errors
    ///
    /// Returns an error when no-intermediate buffering requires stricter alignment.
    pub(crate) fn validate_buffer(self, address: NonNull<u8>) -> DriverResult<()> {
        match self {
            Self::IntermediateAllowed => Ok(()),
            Self::NoIntermediate(transfer) => transfer.validate_buffer(address),
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
    pub(crate) fn from_raw(file_object: *mut FILE_OBJECT) -> Option<Self> {
        NonNull::new(file_object).map(|file_object| Self { file_object })
    }

    /// Returns an immutable WDK file object reference.
    ///
    /// # Safety
    /// The returned reference must not outlive the active WDK callback that supplied this
    /// FILE_OBJECT, and the caller must not mutate the object through another alias for that
    /// lifetime.
    pub(crate) unsafe fn as_ref<'a>(self) -> &'a FILE_OBJECT {
        unsafe {
            // SAFETY: The caller ties the returned reference to the active WDK
            // callback lifetime that supplied this non-null FILE_OBJECT.
            self.file_object.as_ref()
        }
    }

    /// Returns a mutable WDK file object reference.
    ///
    /// # Safety
    /// The caller must own the current mutation point for this FILE_OBJECT and ensure no other
    /// FILE_OBJECT reference aliases the returned mutable reference.
    pub(crate) unsafe fn as_mut<'a>(mut self) -> &'a mut FILE_OBJECT {
        unsafe {
            // SAFETY: The caller owns the active mutation point for this
            // FILE_OBJECT during the current dispatch callback.
            self.file_object.as_mut()
        }
    }

    /// Returns the raw WDK pointer for FFI calls that require FILE_OBJECT.
    pub(crate) fn as_ptr(self) -> *mut FILE_OBJECT {
        self.file_object.as_ptr()
    }

    /// Returns whether this filesystem has completed cleanup for the FILE_OBJECT.
    pub(crate) fn cleanup_complete(self) -> bool {
        let flags = unsafe {
            // SAFETY: The active cleanup or close callback retains this live FILE_OBJECT while
            // reading the filesystem-owned cleanup flag.
            self.as_ref().Flags
        };
        flags & wdk_sys::FO_CLEANUP_COMPLETE != 0
    }

    /// Publishes completion of every cleanup-owned release as the final cleanup mutation.
    pub(crate) fn mark_cleanup_complete(self) {
        let file_object = unsafe {
            // SAFETY: Cleanup is the unique FILE_OBJECT lifecycle transition that publishes this
            // filesystem-owned flag, after all cleanup side effects have completed.
            self.as_mut()
        };
        file_object.Flags |= wdk_sys::FO_CLEANUP_COMPLETE;
    }

    /// Decodes the I/O Manager's close reason from stable FILE_OBJECT flags.
    ///
    /// A cancelled open that also claims a created handle violates the `IoCancelFileOpen`
    /// contract and cannot be recovered without risking a double lifecycle release.
    pub(crate) fn close_kind_or_bugcheck(self) -> FileObjectCloseKind {
        let flags = unsafe {
            // SAFETY: Close owns the live FILE_OBJECT while classifying the I/O Manager lifecycle.
            self.as_ref().Flags
        };
        let cancelled = flags & wdk_sys::FO_FILE_OPEN_CANCELLED != 0;
        let handle_created = flags & wdk_sys::FO_HANDLE_CREATED != 0;
        match (cancelled, handle_created) {
            (true, true) => KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck(),
            (true, false) => FileObjectCloseKind::CancelledOpen,
            (false, _) => FileObjectCloseKind::Ordinary,
        }
    }
}

/// FILE_OBJECT during create before filesystem contexts are attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UninitializedFileObject {
    /// Kernel FILE_OBJECT that has not yet been opened by this filesystem.
    file_object: KernelFileObject,
}

impl UninitializedFileObject {
    /// Decodes a create target whose FCB and CCB slots are both empty.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT already has filesystem-owned FCB or CCB context.
    pub(crate) fn decode(file_object: KernelFileObject) -> DriverResult<Self> {
        let object = unsafe {
            // SAFETY: The FILE_OBJECT pointer comes from the active create
            // stack and is read only for filesystem-owned context pointers.
            file_object.as_ref()
        };
        if !object.FsContext.is_null() || !object.FsContext2.is_null() {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self { file_object })
    }

    /// Returns the underlying kernel FILE_OBJECT for FFI calls.
    pub(crate) const fn kernel_file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns an immutable WDK FILE_OBJECT reference.
    ///
    /// # Safety
    /// The returned reference must stay within the active create dispatch lifetime and must not
    /// alias any concurrent mutable access to the FILE_OBJECT.
    pub(crate) unsafe fn as_ref<'a>(self) -> &'a FILE_OBJECT {
        unsafe {
            // SAFETY: The caller ties the returned reference to the active
            // create dispatch lifetime that supplied this FILE_OBJECT.
            self.file_object.as_ref()
        }
    }

    /// Returns a mutable WDK FILE_OBJECT reference.
    ///
    /// # Safety
    /// The caller must hold the unique create attach point for this uninitialized FILE_OBJECT while
    /// the returned mutable reference is alive.
    pub(crate) unsafe fn as_mut<'a>(self) -> &'a mut FILE_OBJECT {
        unsafe {
            // SAFETY: The caller owns the successful create attach point for
            // this not-yet-initialized FILE_OBJECT.
            self.file_object.as_mut()
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
    pub(crate) fn from_raw(vpb: *mut wdk_sys::VPB) -> Option<Self> {
        NonNull::new(vpb).map(|vpb| Self { vpb })
    }

    /// Returns the non-null VPB pointer for mount-time device initialization.
    pub(crate) const fn as_non_null(self) -> NonNull<wdk_sys::VPB> {
        self.vpb
    }
}

/// Driver-owned device extension kind stored after the queue common prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
struct DeviceExtensionKind {
    /// Stable discriminant written during device initialization.
    value: u8,
}

impl DeviceExtensionKind {
    /// Registered filesystem control device.
    const CONTROL: Self = Self { value: 1 };
    /// Mounted ext4 volume device.
    const MOUNTED_VOLUME: Self = Self { value: 2 };
}

/// Common prefix shared by all driver-owned device extensions.
#[repr(C)]
struct DeviceExtensionHeader {
    /// Device-owned asynchronous request execution lane.
    executor: DeviceExecutor,
    /// Concrete extension kind following the executor prefix.
    kind: DeviceExtensionKind,
}

/// Device extension stored in the file-system control device.
#[repr(C)]
pub(crate) struct ControlDeviceExtension {
    /// Common driver-owned device extension header.
    header: DeviceExtensionHeader,
}

impl ControlDeviceExtension {
    /// Initializes the extension attached to the control device.
    /// # Errors
    ///
    /// Returns an error when the device has no extension or its executor cannot be initialized.
    fn initialize(device: KernelDevice) -> DriverResult<()> {
        let device_object = unsafe {
            // SAFETY: `device` is the newly created control device object.
            device.as_ptr().as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        let extension = unsafe {
            // SAFETY: DriverEntry creates the control device with a
            // ControlDeviceExtension-sized extension.
            device_object
                .DeviceExtension
                .cast::<ControlDeviceExtension>()
                .as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        extension.header.kind = DeviceExtensionKind::CONTROL;
        unsafe {
            // SAFETY: The extension is stable device-owned storage.
            DeviceExecutor::initialize_at(
                core::ptr::addr_of_mut!(extension.header.executor),
                device,
            )
        }
    }

    /// Releases resources stored in the extension.
    /// # Safety
    ///
    /// No dispatch callback or queue worker may still access the control device.
    unsafe fn release(device: KernelDevice) {
        let Some(device_object) = (unsafe {
            // SAFETY: The caller owns teardown of the control device.
            device.as_ptr().as_mut()
        }) else {
            return;
        };
        let Some(extension) = (unsafe {
            // SAFETY: The control device was created with this extension type.
            device_object
                .DeviceExtension
                .cast::<ControlDeviceExtension>()
                .as_mut()
        }) else {
            return;
        };
        unsafe {
            // SAFETY: Teardown has exclusive access to the extension.
            DeviceExecutor::release_at(core::ptr::addr_of_mut!(extension.header.executor));
        }
    }
}

/// Registered file system control device owned by the driver.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ControlDevice {
    /// File-system control device registered with the I/O Manager.
    device: KernelDevice,
}

impl ControlDevice {
    /// Creates registered control-device state.
    /// # Errors
    ///
    /// Returns an error when the device pointer is null or its extension cannot be initialized.
    pub(crate) fn registered(device: PDEVICE_OBJECT) -> DriverResult<Self> {
        let device = KernelDevice::from_raw(device).ok_or(DriverError::InvalidParameter)?;
        ControlDeviceExtension::initialize(device)?;
        Ok(Self { device })
    }

    /// Returns the raw WDK device pointer for FFI calls.
    pub(crate) fn as_ptr(self) -> PDEVICE_OBJECT {
        self.device.as_ptr()
    }

    /// Releases resources stored in the control device extension.
    /// # Safety
    ///
    /// No dispatch callback or queue worker may still access the control device.
    pub(crate) unsafe fn release(self) {
        unsafe {
            // SAFETY: The caller owns control-device teardown.
            ControlDeviceExtension::release(self.device);
        }
    }
}

/// Publishes the registered control device for driver unload teardown.
pub(crate) fn publish_control_device(control_device: ControlDevice) {
    let control_device_slot = core::ptr::addr_of_mut!(CONTROL_DEVICE);
    unsafe {
        // SAFETY: `control_device_slot` points to the driver-owned global state.
        // Raw pointer write avoids borrowing the mutable static.
        core::ptr::write(control_device_slot, Some(control_device));
    }
}

#[expect(
    dead_code,
    reason = "mount state is introduced before FSCTL mount IRP handling"
)]
#[derive(Clone, Copy, Debug)]
/// Driver state after the control device has been registered.
pub(crate) struct RegisteredDriver {
    /// Registered control device owned by the driver.
    control_device: KernelDevice,
}

#[derive(Clone, Copy, Debug)]
/// Target device selected by mount FSCTL validation before VCB creation.
pub(crate) struct MountCandidate {
    /// Device object that will back the mounted ext4 volume.
    target_device: KernelDevice,
    /// Valid byte length reported by the storage stack.
    length: DeviceLength,
}

impl MountCandidate {
    /// Creates a mount candidate after storage length validation.
    pub(crate) const fn new(target_device: KernelDevice, length: DeviceLength) -> Self {
        Self {
            target_device,
            length,
        }
    }

    /// Returns the target storage device.
    pub(crate) const fn target_device(self) -> KernelDevice {
        self.target_device
    }

    /// Returns the validated storage length.
    pub(crate) const fn length(self) -> DeviceLength {
        self.length
    }
}

#[derive(Debug)]
/// Volume control block stored in a mounted volume device extension.
pub(crate) struct VolumeControlBlock {
    /// Volume-wide opaque FsRtl notification state. This field drops before filesystem state so
    /// pending notify IRPs cannot outlive the mounted namespace they observe.
    directory_change_notifier: DirectoryChangeNotifier,
    /// Synchronized VCB-owned FCB identities and Windows share ledger. This field drops before
    /// the mounted volume because every FCB retains that volume as its data-plane owner.
    file_control_blocks: FileControlBlockLedger,
    /// Actor-owned journaled volume state used only by the serialized operation executor.
    operations: VolumeOperationLane,
}

/// Mutable ext4 state owned exclusively by one mounted-device operation actor.
#[derive(Debug)]
pub(crate) struct VolumeOperationLane {
    /// Mounted journaled read-write ext4 volume.
    journaled: JournaledVolume<KernelBlockDevice, CngFscryptNonceGenerator>,
}

impl VolumeOperationLane {
    /// Returns the mounted journaled volume for one serialized operation.
    pub(crate) const fn journaled(
        &self,
    ) -> &JournaledVolume<KernelBlockDevice, CngFscryptNonceGenerator> {
        &self.journaled
    }

    /// Returns the mounted journaled volume for one serialized mutable operation.
    pub(crate) const fn journaled_mut(
        &mut self,
    ) -> &mut JournaledVolume<KernelBlockDevice, CngFscryptNonceGenerator> {
        &mut self.journaled
    }

    /// Persists every write issued before this point in the operation lane.
    /// # Errors
    ///
    /// Returns an error when journal or lower-device flush fails.
    pub(crate) async fn flush(&mut self) -> ext4_core::Result<()> {
        self.journaled.flush().await
    }

    /// Returns a stable serial number derived from the ext4 filesystem UUID.
    pub(crate) fn serial_number(&self) -> VolumeSerialNumber {
        let uuid = self.journaled.identity().uuid().bytes();
        let [a, b, c, d, ..] = uuid;
        VolumeSerialNumber::from_le_bytes([a, b, c, d])
    }

    /// Returns the mounted ext4 volume label.
    pub(crate) fn volume_label(&self) -> ext4_core::Ext4VolumeLabel {
        self.journaled.identity().label()
    }

    /// Adds one fscrypt master key to the mounted volume.
    /// # Errors
    ///
    /// Returns an error when the key identifier is already installed or key storage is exhausted.
    pub(crate) fn add_fscrypt_key(&mut self, key: FscryptMasterKey) -> ext4_core::Result<()> {
        self.journaled.add_fscrypt_key(key)
    }

    /// Removes one fscrypt master key from the mounted volume.
    pub(crate) fn remove_fscrypt_key(
        &mut self,
        identifier: FscryptKeyIdentifier,
    ) -> Option<FscryptMasterKey> {
        self.journaled.remove_fscrypt_key(identifier)
    }

    /// Returns the mounted volume's fscrypt key presence for one identifier.
    pub(crate) fn fscrypt_key_presence(
        &self,
        identifier: FscryptKeyIdentifier,
    ) -> FscryptKeyPresence {
        self.journaled.fscrypt_key_presence(identifier)
    }
}

/// Stable identity of one mounted VCB without granting a reference to its control-plane fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MountedVolumeRef {
    /// Heap-stable mounted VCB.
    volume: NonNull<VolumeControlBlock>,
}

// SAFETY: A mounted VCB allocation remains stable until all FILE_OBJECT references and executor
// tasks have drained. This identity grants no direct access; each projected field has its own
// synchronization or single-actor contract.
unsafe impl Send for MountedVolumeRef {}
// SAFETY: Copying the identity does not grant shared or mutable VCB references.
unsafe impl Sync for MountedVolumeRef {}

impl MountedVolumeRef {
    /// Wraps a heap-stable mounted VCB identity.
    const fn new(volume: NonNull<VolumeControlBlock>) -> Self {
        Self { volume }
    }

    /// Returns the raw typed identity for existing FCB ownership boundaries.
    const fn as_non_null(self) -> NonNull<VolumeControlBlock> {
        self.volume
    }
}

/// Exclusive capability for the mounted device's serialized ext4 operation actor.
pub(crate) struct VolumeOperationLease {
    /// Mounted VCB that owns the projected lane and control-plane ledger.
    owner: MountedVolumeRef,
    /// Disjoint actor-owned field projected without borrowing the whole VCB.
    lane: NonNull<VolumeOperationLane>,
}

// SAFETY: The mounted-device executor transfers this exclusive capability between workers but
// never polls two operation tasks concurrently. The projected journaled state is itself `Send`.
unsafe impl Send for VolumeOperationLease {}

impl VolumeOperationLease {
    /// Returns the actor-owned operation lane through this exclusive capability.
    pub(crate) fn lane(&self) -> &VolumeOperationLane {
        unsafe {
            // SAFETY: Construction requires unique actor authority for mutation; an immutable
            // borrow through that same capability cannot alias a mutable borrow from it.
            self.lane.as_ref()
        }
    }

    /// Returns the actor-owned operation lane mutably through this exclusive capability.
    pub(crate) fn lane_mut(&mut self) -> &mut VolumeOperationLane {
        unsafe {
            // SAFETY: The lease is non-cloneable and its constructor requires the unique mounted
            // executor operation right.
            self.lane.as_mut()
        }
    }

    /// Starts a missing-child transaction without borrowing VCB control-plane state mutably.
    /// # Errors
    ///
    /// Returns an error when the parent cannot be loaded or child creation cannot be staged.
    pub(crate) async fn begin_child_creation(
        &mut self,
        parent: DirectoryNodeId,
        name: &Ext4Name,
        target: ChildCreationTarget,
        now: Ext4Timestamp,
    ) -> DriverResult<PendingChildCreation<'_>> {
        let owner = self.owner;
        let file_control_blocks = unsafe {
            // SAFETY: `owner` stays live for the lease lifetime, so projecting the disjoint ledger
            // field produces a stable raw address.
            core::ptr::addr_of!((*owner.as_non_null().as_ptr()).file_control_blocks)
        };
        let file_control_blocks = unsafe {
            // SAFETY: The projected ledger is independently synchronized and disjoint from the
            // actor-owned operation lane.
            &*file_control_blocks
        };
        let mut transaction = self.lane_mut().journaled_mut().begin_transaction(now);
        let parent = transaction.directory(parent).await?;
        let node = match target {
            ChildCreationTarget::File(metadata) => {
                NodeId::File(transaction.create_file(parent, name, metadata).await?.id())
            }
            ChildCreationTarget::Directory(metadata) => NodeId::Directory(
                transaction
                    .create_directory(parent, name, metadata)
                    .await?
                    .id(),
            ),
        };
        Ok(PendingChildCreation {
            transaction,
            file_control_blocks,
            volume: owner,
            node,
        })
    }
}

/// VCB-owned FCB table and share accounting protected by one concrete executive resource.
struct FileControlBlockLedger {
    /// Mutable ledger state reachable only while `lock` is held.
    table: UnsafeCell<DriverVec<Box<FileControlBlock>>>,
    /// Stable-address executive resource for every table/share/reference transition.
    lock: FileControlBlockLedgerLock,
}

// SAFETY: Every production and test access to `table` is serialized by `lock`; no reference to
// the table or an FCB's ledger-owned mutable fields escapes the guard scope.
unsafe impl Sync for FileControlBlockLedger {}

impl fmt::Debug for FileControlBlockLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileControlBlockLedger(..)")
    }
}

impl Drop for FileControlBlockLedger {
    fn drop(&mut self) {
        if !self.table.get_mut().is_empty() {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        }
    }
}

/// Stable-address WDK executive resource dedicated to the FCB ledger.
struct FileControlBlockLedgerLock {
    /// Native resource initialized only after this allocation reaches its final pinned address.
    #[cfg(not(test))]
    native: Pin<Box<MaybeUninit<wdk_sys::ERESOURCE>>>,
    /// Host mutex with the same exclusive RAII ownership model as the native resource.
    #[cfg(test)]
    native: Mutex<()>,
}

// SAFETY: Production access uses only the executive-resource routines against pinned initialized
// storage. The host backend is a `Mutex`. Both provide exclusive guard ownership.
unsafe impl Sync for FileControlBlockLedgerLock {}

impl fmt::Debug for FileControlBlockLedgerLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileControlBlockLedgerLock(..)")
    }
}

/// Exclusive requester-thread ownership of the FCB ledger resource.
struct FileControlBlockLedgerGuard<'a> {
    /// Native resource released on the same thread when this guard drops.
    #[cfg(not(test))]
    lock: &'a FileControlBlockLedgerLock,
    /// Host guard used only where WDK executive-resource routines are unavailable.
    #[cfg(test)]
    _native: MutexGuard<'a, ()>,
    /// Executive resources cannot be released by a different thread than their acquirer.
    _not_send: PhantomData<*mut ()>,
}

impl FileControlBlockLedgerLock {
    /// Allocates and initializes an executive resource at its permanent address.
    /// # Errors
    ///
    /// Returns an error when stable resource storage cannot be allocated or initialized.
    fn try_new() -> DriverResult<Self> {
        #[cfg(not(test))]
        {
            let native =
                memory::boxed_try_with(|| Ok(MaybeUninit::<wdk_sys::ERESOURCE>::uninit()))?;
            let native = Box::into_pin(native);
            let status = unsafe {
                // SAFETY: `native` is pinned at its final nonpaged address. The storage is not
                // exposed or dropped as an initialized ERESOURCE unless initialization succeeds.
                ffi::ExInitializeResourceLite(native.as_ref().get_ref().as_ptr().cast_mut())
            };
            if status < STATUS_SUCCESS {
                return Err(DriverError::InsufficientResources);
            }
            Ok(Self { native })
        }
        #[cfg(test)]
        {
            Ok(Self {
                native: Mutex::new(()),
            })
        }
    }

    /// Acquires exclusive ledger ownership until the returned guard drops.
    fn acquire(&self) -> FileControlBlockLedgerGuard<'_> {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The resource was initialized at this pinned address. This combined routine
            // retains PASSIVE_LEVEL while disabling normal kernel APC delivery, and guard Drop
            // releases it on the acquiring thread.
            ffi::ExEnterCriticalRegionAndAcquireResourceExclusive(self.native_ptr());
        }
        #[cfg(test)]
        let native = match self.native.lock() {
            Ok(native) => native,
            Err(poisoned) => poisoned.into_inner(),
        };
        FileControlBlockLedgerGuard {
            #[cfg(not(test))]
            lock: self,
            #[cfg(test)]
            _native: native,
            _not_send: PhantomData,
        }
    }

    /// Returns the initialized native resource pointer.
    #[cfg(not(test))]
    fn native_ptr(&self) -> *mut wdk_sys::ERESOURCE {
        self.native.as_ref().get_ref().as_ptr().cast_mut()
    }
}

impl Drop for FileControlBlockLedgerGuard<'_> {
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This !Send guard is dropping on the thread that exclusively acquired the
            // matching resource and entered its critical region.
            ffi::ExReleaseResourceAndLeaveCriticalRegion(self.lock.native_ptr());
        }
    }
}

#[cfg(not(test))]
impl Drop for FileControlBlockLedgerLock {
    fn drop(&mut self) {
        let status = unsafe {
            // SAFETY: Construction publishes this wrapper only after successful initialization,
            // and ledger teardown guarantees no guard or table entry remains.
            ffi::ExDeleteResourceLite(self.native_ptr())
        };
        if status < STATUS_SUCCESS {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        }
    }
}

/// Share validation required before publishing one handle claim.
#[derive(Clone, Copy, Debug)]
enum FileControlBlockShareCheck {
    /// Existing-node operations must first respect the access shared by prior handles.
    ExistingNode(ExistingOperationAccess),
    /// A transaction-local new node has no pre-existing operation access to validate.
    NewNode,
}

impl FileControlBlockLedger {
    /// Creates an empty synchronized FCB ledger and its native resource.
    /// # Errors
    ///
    /// Returns an error when the stable executive resource cannot be allocated or initialized.
    fn try_new() -> DriverResult<Self> {
        Ok(Self {
            table: UnsafeCell::new(DriverVec::new()),
            lock: FileControlBlockLedgerLock::try_new()?,
        })
    }

    /// Opens an existing-node FCB and atomically records its share claim.
    /// # Errors
    ///
    /// Returns an error when FCB allocation/reference growth or Windows share validation fails.
    fn open_existing(
        &self,
        volume: NonNull<VolumeControlBlock>,
        node: NodeId,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        existing_operation_access: ExistingOperationAccess,
        share_access: ShareAccess,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        self.open(
            volume,
            node,
            file_object,
            desired_access,
            share_access,
            FileControlBlockShareCheck::ExistingNode(existing_operation_access),
        )
    }

    /// Opens a staged-new-node FCB and atomically records its share claim.
    /// # Errors
    ///
    /// Returns an error when FCB allocation/reference growth or Windows share validation fails.
    fn open_new(
        &self,
        volume: NonNull<VolumeControlBlock>,
        node: NodeId,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        share_access: ShareAccess,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        self.open(
            volume,
            node,
            file_object,
            desired_access,
            share_access,
            FileControlBlockShareCheck::NewNode,
        )
    }

    /// Opens or creates one ledger entry and records the FILE_OBJECT share claim atomically.
    /// # Errors
    ///
    /// Returns an error when allocation, reference growth, or share validation fails.
    fn open(
        &self,
        volume: NonNull<VolumeControlBlock>,
        node: NodeId,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        share_access: ShareAccess,
        share_check: FileControlBlockShareCheck,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        if let Some(result) =
            self.try_open_present(node, file_object, desired_access, share_access, share_check)
        {
            return result;
        }

        let candidate = memory::boxed_try_with(|| Ok(self.file_control_block(volume, node)))?;
        let mut discarded = None;
        let mut removed = None;
        let result = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource uniquely owns table mutation for this scope.
                &mut *self.table.get()
            };
            if let Some(fcb) = find_file_control_block_in_table(table, node) {
                discarded = Some(candidate);
                record_reused_file_control_block_open(
                    table,
                    fcb,
                    file_object,
                    desired_access,
                    share_access,
                    share_check,
                )
                .map(|()| fcb)
            } else {
                let fcb = NonNull::from(candidate.as_ref());
                match table.try_push_owned(candidate) {
                    Ok(()) => match record_file_control_block_share(
                        table,
                        fcb,
                        file_object,
                        desired_access,
                        share_access,
                        share_check,
                    ) {
                        Ok(()) => Ok(fcb),
                        Err(error) => {
                            removed = close_file_control_block_in_table(table, fcb);
                            Err(error)
                        }
                    },
                    Err(error) => {
                        let (error, candidate) = error.into_parts();
                        discarded = Some(candidate);
                        Err(error)
                    }
                }
            }
        };
        drop(removed);
        drop(discarded);
        result
    }

    /// Creates an uninserted FCB candidate owned by this ledger.
    fn file_control_block(
        &self,
        volume: NonNull<VolumeControlBlock>,
        node: NodeId,
    ) -> FileControlBlock {
        FileControlBlock::new(volume, NonNull::from(self), node)
    }

    /// Attempts to reuse an existing entry without allocating a candidate FCB.
    fn try_open_present(
        &self,
        node: NodeId,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        share_access: ShareAccess,
        share_check: FileControlBlockShareCheck,
    ) -> Option<DriverResult<NonNull<FileControlBlock>>> {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table lookup and open-state mutation.
            &*self.table.get()
        };
        let fcb = find_file_control_block_in_table(table, node)?;
        Some(
            record_reused_file_control_block_open(
                table,
                fcb,
                file_object,
                desired_access,
                share_access,
                share_check,
            )
            .map(|()| fcb),
        )
    }

    /// Releases a share claim while retaining the FILE_OBJECT's FCB reference until close.
    fn release_share_access(&self, fcb: NonNull<FileControlBlock>, file_object: KernelFileObject) {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes lookup and open-state mutation.
            &*self.table.get()
        };
        let mut state = ledger_file_control_block_open_state(table, fcb);
        unsafe {
            // SAFETY: The ledger resource remains exclusively held and the helper validated this
            // state pointer against the owning table.
            state.as_mut()
        }
        .remove_share_access(file_object);
    }

    /// Atomically releases a share claim and the same FILE_OBJECT's final FCB reference.
    fn release_share_access_and_reference(
        &self,
        fcb: NonNull<FileControlBlock>,
        file_object: KernelFileObject,
    ) {
        let removed = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource uniquely owns table and open-state mutation.
                &mut *self.table.get()
            };
            let mut state = ledger_file_control_block_open_state(table, fcb);
            unsafe {
                // SAFETY: The ledger resource remains exclusively held and the helper validated
                // this state pointer against the owning table.
                state.as_mut()
            }
            .remove_share_access(file_object);
            close_file_control_block_in_table(table, fcb)
        };
        drop(removed);
    }

    /// Releases one FILE_OBJECT's final FCB reference at close.
    fn close(&self, fcb: NonNull<FileControlBlock>) {
        let removed = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource uniquely owns table and open-state mutation.
                &mut *self.table.get()
            };
            close_file_control_block_in_table(table, fcb)
        };
        drop(removed);
    }
}

#[derive(Debug)]
/// Missing-child node kind selected before an ext4 namespace create transaction starts.
pub(crate) enum ChildCreationTarget {
    /// Create a regular file with prebuilt metadata.
    File(NewFileMetadata),
    /// Create a directory with prebuilt metadata.
    Directory(NewDirectoryMetadata),
}

impl VolumeControlBlock {
    /// Mounts a journaled read-write ext4 VCB.
    /// # Errors
    ///
    /// Returns an error when the lower device cannot be mounted as a journaled ext4 volume.
    pub(crate) async fn mount_journaled(
        completion_owner: KernelDevice,
        target_device: KernelDevice,
        length: DeviceLength,
    ) -> DriverResult<Self> {
        let block_device = KernelBlockDevice::new(completion_owner, target_device, length)?;
        let volume = JournaledVolume::<_, CngFscryptNonceGenerator>::mount(
            block_device,
            MountContext::new(FscryptKeySet::empty(), CngFscryptNonceGenerator),
        )
        .await?;
        Ok(Self {
            directory_change_notifier: DirectoryChangeNotifier::uninitialized(),
            file_control_blocks: FileControlBlockLedger::try_new()?,
            operations: VolumeOperationLane { journaled: volume },
        })
    }

    /// Initializes the volume-wide FsRtl notification state after this VCB reaches stable storage.
    /// # Errors
    ///
    /// Returns an error when FsRtl cannot allocate the notifier synchronization state.
    pub(crate) fn initialize_directory_change_notifier(&mut self) -> DriverResult<()> {
        self.directory_change_notifier.initialize()
    }

    /// Returns the volume-wide directory notification state.
    pub(crate) const fn directory_change_notifier(&self) -> &DirectoryChangeNotifier {
        &self.directory_change_notifier
    }

    /// Reports one committed namespace name change to pending directory watchers.
    pub(crate) fn report_directory_name_change(&self, change: DirectoryNameChange) {
        self.directory_change_notifier.report(change);
    }

    /// Opens or reuses an existing node's FCB and records its share claim atomically.
    /// # Errors
    ///
    /// Returns an error when FCB allocation/reference growth or Windows share validation fails.
    pub(crate) fn open_existing_file_control_block(
        volume: NonNull<Self>,
        node: NodeId,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        existing_operation_access: ExistingOperationAccess,
        share_access: ShareAccess,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        let volume_ptr = volume.as_ptr();
        let file_control_blocks = unsafe {
            // SAFETY: `volume_ptr` identifies the live, stable mounted VCB. `addr_of!` projects
            // the ledger address without creating a reference to the transaction-owned volume.
            core::ptr::addr_of!((*volume_ptr).file_control_blocks)
        };
        let file_control_blocks = unsafe {
            // SAFETY: The mounted VCB pointer is stable for request processing. Raw field
            // projection borrows only the independently synchronized ledger and never creates a
            // shared reference spanning the transaction-owned `volume` field.
            &*file_control_blocks
        };
        file_control_blocks.open_existing(
            volume,
            node,
            file_object,
            desired_access,
            existing_operation_access,
            share_access,
        )
    }

    /// Projects the actor-owned ext4 operation lane without borrowing VCB control-plane state.
    /// # Safety
    ///
    /// The caller must own the mounted device executor's unique active-operation right and must
    /// not construct another lease until the returned lease and every transaction borrowing it
    /// have been dropped.
    pub(crate) unsafe fn claim_operation_lane(volume: NonNull<Self>) -> VolumeOperationLease {
        let lane = unsafe {
            // SAFETY: The VCB is heap-stable, so its operation field has a stable address.
            core::ptr::addr_of_mut!((*volume.as_ptr()).operations)
        };
        let lane = unsafe {
            // SAFETY: A field address projected from a non-null live VCB cannot be null.
            NonNull::new_unchecked(lane)
        };
        VolumeOperationLease {
            owner: MountedVolumeRef::new(volume),
            lane,
        }
    }
}

/// One validated directory-notification registration owned by a FILE_OBJECT.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DirectoryNotificationRegistration {
    /// Stable CCB-owned `UNICODE_STRING` retained by FsRtl until cleanup.
    full_directory_name: NonNull<UNICODE_STRING>,
    /// Stable unique CCB address that identifies the owning FILE_OBJECT to FsRtl.
    context: NonNull<c_void>,
    /// Supported Windows completion-filter bits.
    completion_filter: wdk_sys::ULONG,
}

impl DirectoryNotificationRegistration {
    /// Builds one registration after the request boundary has rejected unsupported semantics.
    pub(crate) const fn new(
        full_directory_name: NonNull<UNICODE_STRING>,
        context: NonNull<c_void>,
        completion_filter: wdk_sys::ULONG,
    ) -> Self {
        Self {
            full_directory_name,
            context,
            completion_filter,
        }
    }
}

/// Namespace name-change action exposed through directory notifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryNameChangeAction {
    /// A child was created.
    Added,
    /// A child was removed.
    Removed,
    /// A child is being reported under its former name.
    RenamedOldName,
    /// A child is being reported under its replacement name.
    RenamedNewName,
}

impl DirectoryNameChangeAction {
    /// Returns the WDK FILE_ACTION payload for this namespace mutation.
    const fn as_ulong(self) -> wdk_sys::ULONG {
        match self {
            Self::Added => wdk_sys::FILE_ACTION_ADDED,
            Self::Removed => wdk_sys::FILE_ACTION_REMOVED,
            Self::RenamedOldName => wdk_sys::FILE_ACTION_RENAMED_OLD_NAME,
            Self::RenamedNewName => wdk_sys::FILE_ACTION_RENAMED_NEW_NAME,
        }
    }
}

/// Committed namespace mutation prepared before its ext4 transaction is published.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DirectoryNameChange {
    /// Full synthetic target name used only by the FsRtl notifier package.
    target: DirectoryNotificationTarget,
    /// FILE_NOTIFY_CHANGE_FILE_NAME or FILE_NOTIFY_CHANGE_DIR_NAME.
    completion_filter: wdk_sys::ULONG,
    /// FILE_ACTION_* payload written to matching watcher buffers.
    action: DirectoryNameChangeAction,
}

impl DirectoryNameChange {
    /// Builds a namespace change event for one parent/name/node tuple.
    /// # Errors
    ///
    /// Returns an error when the ext4 child name cannot be represented in the Windows notification
    /// namespace.
    pub(crate) fn new(
        parent: DirectoryNodeId,
        name: &Ext4Name,
        node: NodeId,
        action: DirectoryNameChangeAction,
    ) -> DriverResult<Self> {
        let completion_filter = if matches!(node, NodeId::Directory(_)) {
            wdk_sys::FILE_NOTIFY_CHANGE_DIR_NAME
        } else {
            wdk_sys::FILE_NOTIFY_CHANGE_FILE_NAME
        };
        Ok(Self {
            target: DirectoryNotificationTarget::new(parent, name)?,
            completion_filter,
            action,
        })
    }
}

/// Opaque FsRtl notification list owned by one mounted VCB.
pub(crate) struct DirectoryChangeNotifier {
    /// Native list and synchronization object, initialized only after the VCB has a stable Box
    /// allocation. FsRtl synchronizes access to the opaque list internally.
    #[cfg(not(test))]
    native: UnsafeCell<NativeDirectoryChangeNotifier>,
    /// Whether `native` has been initialized and can be passed to FsRtl.
    #[cfg(not(test))]
    initialized: bool,
}

/// Native FsRtl notification storage whose list links must point at its final address.
#[cfg(not(test))]
struct NativeDirectoryChangeNotifier {
    /// Opaque volume-wide synchronization state allocated by FsRtl.
    sync: PNOTIFY_SYNC,
    /// Head of the FsRtl-owned notification list.
    list_head: LIST_ENTRY,
}

impl DirectoryChangeNotifier {
    /// Creates uninitialized notifier storage before the VCB reaches a stable heap address.
    const fn uninitialized() -> Self {
        #[cfg(not(test))]
        {
            Self {
                native: UnsafeCell::new(NativeDirectoryChangeNotifier {
                    sync: core::ptr::null_mut(),
                    list_head: LIST_ENTRY {
                        Flink: core::ptr::null_mut(),
                        Blink: core::ptr::null_mut(),
                    },
                }),
                initialized: false,
            }
        }
        #[cfg(test)]
        {
            Self {}
        }
    }

    /// Initializes FsRtl notification state at the VCB's final address.
    /// # Errors
    ///
    /// Returns an error when FsRtl cannot allocate the volume synchronization object or this
    /// lifecycle transition is attempted twice.
    fn initialize(&mut self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            if self.initialized {
                return Err(DriverError::InternalInvariantViolation);
            }
            let native = self.native.get();
            let list_head = unsafe {
                // SAFETY: `self` is the VCB's final Box allocation, so this
                // embedded LIST_ENTRY has a stable address for its lifetime.
                core::ptr::addr_of_mut!((*native).list_head)
            };
            unsafe {
                // SAFETY: The head points to its own empty-list links before
                // FsRtl receives the list for the first time.
                (*list_head).Flink = list_head;
            }
            unsafe {
                // SAFETY: The same initialized list head owns both links.
                (*list_head).Blink = list_head;
            }
            let sync = unsafe {
                // SAFETY: `sync` is writable VCB-owned storage that has not
                // yet been initialized by FsRtl.
                core::ptr::addr_of_mut!((*native).sync)
            };
            unsafe {
                // SAFETY: FsRtl initializes the one opaque synchronization
                // pointer stored in this mounted VCB.
                ffi::FsRtlNotifyInitializeSync(sync);
            }
            if unsafe {
                // SAFETY: FsRtl initialized the out pointer above; this only
                // reads the pointer value before publication.
                (*native).sync.is_null()
            } {
                return Err(DriverError::InsufficientResources);
            }
            self.initialized = true;
            Ok(())
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Gives one queued directory-change IRP to FsRtl for pending completion.
    /// # Errors
    ///
    /// Returns an error when the mounted VCB notifier was not initialized.
    pub(crate) fn register(
        &self,
        target: DispatchTarget,
        registration: DirectoryNotificationRegistration,
    ) -> DriverResult<wdk_sys::NTSTATUS> {
        #[cfg(not(test))]
        {
            if !self.initialized {
                return Err(DriverError::InternalInvariantViolation);
            }
            let native = self.native.get();
            let sync = unsafe {
                // SAFETY: `initialized` guarantees FsRtl populated this
                // mounted VCB's synchronization pointer.
                (*native).sync
            };
            let list_head = unsafe {
                // SAFETY: The native storage stays pinned inside the mounted
                // VCB and FsRtl synchronizes access to the list links.
                core::ptr::addr_of_mut!((*native).list_head)
            };
            unsafe {
                // SAFETY: The IRP was removed from the driver queue and its
                // unique completion owner is intentionally transferring it to
                // FsRtl. The registration context is a live CCB pointer.
                ffi::FsRtlNotifyFullChangeDirectory(
                    sync,
                    list_head,
                    registration.context.as_ptr(),
                    registration.full_directory_name.as_ptr().cast(),
                    0,
                    0,
                    registration.completion_filter,
                    target.as_raw_irp(),
                    None,
                    core::ptr::null_mut(),
                );
            }
            Ok(STATUS_PENDING)
        }
        #[cfg(test)]
        {
            let DirectoryNotificationRegistration {
                full_directory_name,
                context,
                completion_filter,
            } = registration;
            core::hint::black_box((target, full_directory_name, context, completion_filter));
            Ok(STATUS_SUCCESS)
        }
    }

    /// Reports one committed namespace name change to matching watcher IRPs.
    fn report(&self, change: DirectoryNameChange) {
        #[cfg(not(test))]
        {
            if !self.initialized {
                return;
            }
            let mut full_target_name = change.target.unicode_string();
            let native = self.native.get();
            let sync = unsafe {
                // SAFETY: `initialized` guarantees FsRtl populated this
                // mounted VCB's synchronization pointer.
                (*native).sync
            };
            let list_head = unsafe {
                // SAFETY: The native storage stays pinned inside the mounted
                // VCB and FsRtl synchronizes access to the list links.
                core::ptr::addr_of_mut!((*native).list_head)
            };
            unsafe {
                // SAFETY: This runs after the namespace transaction commits
                // at PASSIVE_LEVEL. FsRtl consumes the event synchronously.
                ffi::FsRtlNotifyFullReportChange(
                    sync,
                    list_head,
                    core::ptr::from_mut(&mut full_target_name).cast(),
                    change.target.name_offset_bytes,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    change.completion_filter,
                    change.action.as_ulong(),
                    core::ptr::null_mut(),
                );
            }
        }
        #[cfg(test)]
        {
            let _change = change;
        }
    }

    /// Cancels and releases notification state owned by one cleaned-up FILE_OBJECT.
    pub(crate) fn cleanup(&self, context: NonNull<c_void>) {
        #[cfg(not(test))]
        {
            if !self.initialized {
                return;
            }
            let native = self.native.get();
            let sync = unsafe {
                // SAFETY: `initialized` guarantees FsRtl populated this
                // mounted VCB's synchronization pointer.
                (*native).sync
            };
            let list_head = unsafe {
                // SAFETY: The native storage stays pinned inside the mounted
                // VCB and FsRtl synchronizes access to the list links.
                core::ptr::addr_of_mut!((*native).list_head)
            };
            unsafe {
                // SAFETY: The CCB pointer uniquely identifies the FILE_OBJECT
                // being cleaned up and stays alive until its later close IRP.
                ffi::FsRtlNotifyCleanup(sync, list_head, context.as_ptr());
            }
        }
        #[cfg(test)]
        {
            let _context = context;
        }
    }
}

impl Drop for DirectoryChangeNotifier {
    fn drop(&mut self) {
        #[cfg(not(test))]
        {
            if !self.initialized {
                return;
            }
            let native = self.native.get();
            let sync = unsafe {
                // SAFETY: `initialized` guarantees FsRtl populated this
                // mounted VCB's synchronization pointer.
                (*native).sync
            };
            let list_head = unsafe {
                // SAFETY: This final VCB teardown still owns the stable list
                // head and no new request can be accepted during destruction.
                core::ptr::addr_of_mut!((*native).list_head)
            };
            unsafe {
                // SAFETY: FsRtl completes and frees every remaining opaque
                // notification record before its synchronization object dies.
                ffi::FsRtlNotifyCleanupAll(sync, list_head);
            }
            let sync_slot = unsafe {
                // SAFETY: The initialized sync pointer is stored in this
                // unique mutable VCB teardown path.
                core::ptr::addr_of_mut!((*native).sync)
            };
            unsafe {
                // SAFETY: The list has been cleaned up and this is the unique
                // FsRtl uninitialization for the mounted VCB.
                ffi::FsRtlNotifyUninitializeSync(sync_slot);
            }
            self.initialized = false;
        }
    }
}

impl fmt::Debug for DirectoryChangeNotifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectoryChangeNotifier(..)")
    }
}

/// Stable synthetic directory name used only for FsRtl's lexical watcher matching.
#[derive(Debug)]
struct DirectoryNotificationDirectoryName {
    /// UTF-16 `\\` followed by four private inode-identity code units.
    units: [u16; DIRECTORY_NOTIFICATION_DIRECTORY_UNITS],
    /// FsRtl retains this descriptor pointer until the CCB cleanup transition.
    string: UNICODE_STRING,
    /// Prevents moving the self-referential descriptor after `Buffer` is initialized.
    _pin: PhantomPinned,
}

impl DirectoryNotificationDirectoryName {
    /// Allocates one stable synthetic name for a directory CCB.
    /// # Errors
    ///
    /// Returns an error when the stable descriptor allocation fails.
    fn try_new(directory: DirectoryNodeId) -> DriverResult<Pin<Box<Self>>> {
        let units = Self::encode(directory);
        let byte_length = u16::try_from(core::mem::size_of_val(&units))
            .map_err(|_| DriverError::InvalidBufferSize)?;
        let mut name = memory::boxed_try_with(|| {
            Ok(Self {
                units,
                string: UNICODE_STRING {
                    Length: byte_length,
                    MaximumLength: byte_length,
                    Buffer: core::ptr::null_mut(),
                },
                _pin: PhantomPinned,
            })
        })?;
        name.string.Buffer = name.units.as_mut_ptr();
        Ok(Box::into_pin(name))
    }

    /// Encodes one directory identity without allocating storage.
    fn encode(directory: DirectoryNodeId) -> [u16; DIRECTORY_NOTIFICATION_DIRECTORY_UNITS] {
        let mut units = [0_u16; DIRECTORY_NOTIFICATION_DIRECTORY_UNITS];
        let mut slots = units.iter_mut();
        if let Some(first) = slots.next() {
            *first = DIRECTORY_NOTIFICATION_SEPARATOR;
        }
        for (slot, byte) in slots.zip(NodeId::Directory(directory).file_index().to_be_bytes()) {
            *slot = DIRECTORY_NOTIFICATION_INODE_MARKER | u16::from(byte);
        }
        units
    }

    /// Returns the stable descriptor address retained by FsRtl.
    fn descriptor(&self) -> NonNull<UNICODE_STRING> {
        NonNull::from(&self.string)
    }
}

impl PartialEq for DirectoryNotificationDirectoryName {
    fn eq(&self, other: &Self) -> bool {
        self.units == other.units
    }
}

impl Eq for DirectoryNotificationDirectoryName {}

// SAFETY: After construction this value is pinned in its own allocation, so `string.Buffer`
// continues to address `units` when ownership of the pinned box moves between executor workers.
unsafe impl Send for DirectoryNotificationDirectoryName {}

/// Full synthetic target path reported to the FsRtl notification package.
#[derive(Clone, Copy, Debug)]
struct DirectoryNotificationTarget {
    /// UTF-16 `\\<opaque parent id>\\<child name>` target path.
    units: [u16; DIRECTORY_NOTIFICATION_TARGET_UNITS],
    /// UTF-16 byte count of the populated target path.
    byte_length: u16,
    /// Byte offset of the final child component inside `units`.
    name_offset_bytes: u16,
}

impl DirectoryNotificationTarget {
    /// Builds one complete target path from a directory entry identity.
    /// # Errors
    ///
    /// Returns an error when the ext4 child name cannot be represented by Windows.
    fn new(parent: DirectoryNodeId, name: &Ext4Name) -> DriverResult<Self> {
        let directory_units = DirectoryNotificationDirectoryName::encode(parent);
        let name = WindowsName::from_ext4(name)?;
        let prefix_length = DIRECTORY_NOTIFICATION_DIRECTORY_UNITS
            .checked_add(1)
            .ok_or(DriverError::InvalidBufferSize)?;
        let length = prefix_length
            .checked_add(name.utf16().len())
            .ok_or(DriverError::InvalidBufferSize)?;
        if length > DIRECTORY_NOTIFICATION_TARGET_UNITS {
            return Err(DriverError::InvalidBufferSize);
        }
        let mut units = [0_u16; DIRECTORY_NOTIFICATION_TARGET_UNITS];
        let directory_destination = units
            .get_mut(..DIRECTORY_NOTIFICATION_DIRECTORY_UNITS)
            .ok_or(DriverError::InvalidBufferSize)?;
        let directory_source = directory_units
            .get(..DIRECTORY_NOTIFICATION_DIRECTORY_UNITS)
            .ok_or(DriverError::InvalidBufferSize)?;
        directory_destination.copy_from_slice(directory_source);
        let separator = units
            .get_mut(DIRECTORY_NOTIFICATION_DIRECTORY_UNITS)
            .ok_or(DriverError::InvalidBufferSize)?;
        *separator = DIRECTORY_NOTIFICATION_SEPARATOR;
        let child_destination = units
            .get_mut(prefix_length..length)
            .ok_or(DriverError::InvalidBufferSize)?;
        child_destination.copy_from_slice(name.utf16());
        let byte_length = u16::try_from(
            length
                .checked_mul(core::mem::size_of::<u16>())
                .ok_or(DriverError::InvalidBufferSize)?,
        )
        .map_err(|_| DriverError::InvalidBufferSize)?;
        let name_offset_bytes = u16::try_from(
            prefix_length
                .checked_mul(core::mem::size_of::<u16>())
                .ok_or(DriverError::InvalidBufferSize)?,
        )
        .map_err(|_| DriverError::InvalidBufferSize)?;
        Ok(Self {
            units,
            byte_length,
            name_offset_bytes,
        })
    }

    /// Views this complete target as the layout accepted by FsRtl's PSTRING ABI.
    fn unicode_string(&self) -> UNICODE_STRING {
        UNICODE_STRING {
            Length: self.byte_length,
            MaximumLength: self.byte_length,
            Buffer: self.units.as_ptr().cast_mut(),
        }
    }
}

/// UTF-16 backslash separator used in FsRtl synthetic paths.
const DIRECTORY_NOTIFICATION_SEPARATOR: u16 = 0x005C;
/// High-byte marker separating encoded inode bytes from Windows path separators.
const DIRECTORY_NOTIFICATION_INODE_MARKER: u16 = 0x0100;
/// `\\` plus four lossless inode-identity units.
const DIRECTORY_NOTIFICATION_DIRECTORY_UNITS: usize = 5;
/// Synthetic parent path, one separator, and the largest ext4 name in UTF-16 units.
const DIRECTORY_NOTIFICATION_TARGET_UNITS: usize = 261;

/// In-progress missing-child create transaction that has not reached durable ext4 state.
#[derive(Debug)]
pub(crate) struct PendingChildCreation<'a> {
    /// Staged ext4 namespace mutation.
    transaction:
        JournalTransaction<'a, KernelBlockDevice, CngFscryptNonceGenerator, InternalJournal>,
    /// Synchronized FCB ledger borrowed independently from the mounted ext4 volume.
    file_control_blocks: &'a FileControlBlockLedger,
    /// VCB that owns any FCB opened for the staged node.
    volume: MountedVolumeRef,
    /// Node identity allocated by the staged transaction.
    node: NodeId,
}

impl PendingChildCreation<'_> {
    /// Returns the node identity allocated by the staged create transaction.
    pub(crate) const fn node(&self) -> NodeId {
        self.node
    }

    /// Opens the staged node's FCB and records its share claim atomically.
    /// # Errors
    ///
    /// Returns an error when FCB allocation/reference growth or Windows share validation fails.
    pub(crate) fn open_file_control_block(
        &self,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        share_access: ShareAccess,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        self.file_control_blocks.open_new(
            self.volume.as_non_null(),
            self.node,
            file_object,
            desired_access,
            share_access,
        )
    }

    /// Sets or replaces one xattr on the staged child in this create transaction.
    /// # Errors
    ///
    /// Returns an error when the staged node rejects xattr mutation.
    pub(crate) async fn set_xattr(
        &mut self,
        name: XattrName,
        value: XattrValue,
    ) -> DriverResult<()> {
        let node = self.transaction.node(self.node).await?;
        self.transaction.set_xattr(node, name, value).await?;
        Ok(())
    }

    /// Removes one xattr from the staged child in this create transaction.
    /// # Errors
    ///
    /// Returns an error when the staged node rejects xattr mutation.
    pub(crate) async fn remove_xattr(&mut self, name: &XattrName) -> DriverResult<()> {
        let node = self.transaction.node(self.node).await?;
        self.transaction.remove_xattr(node, name).await?;
        Ok(())
    }

    /// Commits the staged namespace mutation to the mounted ext4 volume.
    /// # Errors
    ///
    /// Returns an error when the journal cannot durably commit the staged mutation.
    pub(crate) async fn commit(self) -> DriverResult<()> {
        self.transaction.commit().await?;
        Ok(())
    }
}

/// Records a share claim and then publishes one additional FILE_OBJECT reference.
/// # Errors
///
/// Returns an error without changing either count when reference growth or share validation fails.
fn record_reused_file_control_block_open(
    table: &DriverVec<Box<FileControlBlock>>,
    fcb: NonNull<FileControlBlock>,
    file_object: KernelFileObject,
    desired_access: DesiredAccess,
    share_access: ShareAccess,
    share_check: FileControlBlockShareCheck,
) -> DriverResult<()> {
    let mut state = ledger_file_control_block_open_state(table, fcb);
    let state = unsafe {
        // SAFETY: The caller holds the ledger resource exclusively and the helper validated this
        // state pointer against the owning table.
        state.as_mut()
    };
    let references = state.next_file_object_reference()?;
    state.record_share_access(file_object, desired_access, share_access, share_check)?;
    state.file_object_references = references;
    Ok(())
}

/// Records the first share claim on a newly inserted FCB.
/// # Errors
///
/// Returns an error when Windows rejects the requested share claim.
fn record_file_control_block_share(
    table: &DriverVec<Box<FileControlBlock>>,
    fcb: NonNull<FileControlBlock>,
    file_object: KernelFileObject,
    desired_access: DesiredAccess,
    share_access: ShareAccess,
    share_check: FileControlBlockShareCheck,
) -> DriverResult<()> {
    let mut state = ledger_file_control_block_open_state(table, fcb);
    unsafe {
        // SAFETY: The caller holds the ledger resource exclusively and the helper validated this
        // state pointer against the owning table.
        state.as_mut()
    }
    .record_share_access(file_object, desired_access, share_access, share_check)
}

/// Releases one open reference to an FCB in a VCB-owned table.
fn close_file_control_block_in_table(
    table: &mut DriverVec<Box<FileControlBlock>>,
    fcb: NonNull<FileControlBlock>,
) -> Option<Box<FileControlBlock>> {
    let Some(index) = table
        .iter()
        .position(|candidate| NonNull::from(candidate.as_ref()) == fcb)
    else {
        KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
    };
    let mut state = ledger_file_control_block_open_state(table, fcb);
    let release = unsafe {
        // SAFETY: The caller holds the ledger resource exclusively and the helper validated this
        // state pointer against the owning table.
        state.as_mut()
    }
    .release_open_reference();
    match release {
        FileControlBlockRelease::StillOpen => None,
        FileControlBlockRelease::LastReference => match table.swap_remove(index) {
            Some(removed) => Some(removed),
            None => KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck(),
        },
    }
}

/// Finds a VCB-owned FCB by node identity.
fn find_file_control_block_in_table(
    table: &DriverVec<Box<FileControlBlock>>,
    node: NodeId,
) -> Option<NonNull<FileControlBlock>> {
    table
        .iter()
        .find(|fcb| fcb.node() == node)
        .map(|fcb| NonNull::from(fcb.as_ref()))
}

/// Returns one ledger-owned FCB's open-state address after validating table ownership.
fn ledger_file_control_block_open_state(
    table: &DriverVec<Box<FileControlBlock>>,
    fcb: NonNull<FileControlBlock>,
) -> NonNull<FileControlBlockOpenState> {
    let fcb = table
        .iter()
        .find(|candidate| NonNull::from(candidate.as_ref()) == fcb)
        .map(Box::as_ref)
        .unwrap_or_else(|| {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
        });
    NonNull::new(fcb.open_state.get()).unwrap_or_else(|| {
        KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
    })
}

/// Windows volume serial number derived from the ext4 filesystem UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VolumeSerialNumber {
    /// Raw serial value expected by WDK structures.
    value: u32,
}

impl VolumeSerialNumber {
    /// Builds a serial number from little-endian UUID bytes.
    const fn from_le_bytes(bytes: [u8; 4]) -> Self {
        Self {
            value: u32::from_le_bytes(bytes),
        }
    }

    /// Returns the WDK serial number payload.
    pub(crate) const fn as_u32(self) -> u32 {
        self.value
    }
}

/// Device extension stored in mounted volume device objects.
#[repr(C)]
pub(crate) struct MountedVolumeDeviceExtension {
    /// Common driver-owned device extension header.
    header: DeviceExtensionHeader,
    /// Heap-owned VCB for this mounted volume device.
    vcb: *mut VolumeControlBlock,
}

/// Mounted volume device object produced by a successful mount FSCTL.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountedVolumeDevice {
    /// Mounted volume device object.
    device: KernelDevice,
}

impl MountedVolumeDevice {
    /// Initializes an IoCreateDevice-created mounted device and takes ownership
    /// of the VCB.
    /// # Errors
    ///
    /// Returns an error when the mounted DEVICE_OBJECT, device extension, or VPB initialization
    /// target is absent or invalid.
    pub(crate) fn initialize(
        device: PDEVICE_OBJECT,
        vcb: Box<VolumeControlBlock>,
        vpb: NonNull<wdk_sys::VPB>,
        real_device: KernelDevice,
    ) -> DriverResult<Self> {
        let device = KernelDevice::from_raw(device).ok_or(DriverError::InvalidParameter)?;
        let stack_size = real_device
            .stack_size()
            .ok_or(DriverError::InvalidParameter)?
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;
        let transfer_alignment = real_device.transfer_buffer_alignment()?;
        let mounted_flag = u16::try_from(VPB_MOUNTED).map_err(|_| DriverError::InvalidParameter)?;
        let serial_number = vcb.operations.serial_number().as_u32();
        let volume_label = VpbLabel::encode(vcb.operations.volume_label())?;
        let device_object = unsafe {
            // SAFETY: The device was just created by this driver and remains
            // valid during mount initialization.
            device.as_ptr().as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        let extension = unsafe {
            // SAFETY: The device was created with a DeviceExtension sized for
            // MountedVolumeDeviceExtension by this driver.
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
                .as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        let vpb = unsafe {
            // SAFETY: The VPB was supplied by the I/O Manager for this mount
            // request and is writable during successful mount completion.
            vpb.as_ptr().as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;

        extension.header.kind = DeviceExtensionKind::MOUNTED_VOLUME;
        unsafe {
            // SAFETY: The extension is stable device-owned storage for this
            // just-created mounted volume device.
            DeviceExecutor::initialize_at(
                core::ptr::addr_of_mut!(extension.header.executor),
                device,
            )?;
        }
        if let Err(error) = register_shutdown_notification(device) {
            unsafe {
                // SAFETY: Shutdown registration failed before this device was
                // published, so no worker or continuation can still own the executor.
                DeviceExecutor::release_at(core::ptr::addr_of_mut!(extension.header.executor));
            }
            return Err(error);
        }

        device_object.Vpb = vpb;
        device_object.Flags |= DO_DIRECT_IO;
        device_object.StackSize = stack_size;
        device_object.AlignmentRequirement = transfer_alignment.as_mask();

        vpb.SerialNumber = serial_number;
        volume_label.write_to(vpb);
        vpb.DeviceObject = device.as_ptr();
        vpb.RealDevice = real_device.as_ptr();
        vpb.Flags |= mounted_flag;

        extension.vcb = Box::into_raw(vcb);
        device_object.Flags &= !DO_DEVICE_INITIALIZING;
        Ok(Self { device })
    }

    /// Returns the mounted volume device object pointer.
    pub(crate) fn as_ptr(self) -> PDEVICE_OBJECT {
        self.device.as_ptr()
    }

    /// Returns the mounted VCB pointer stored in a mounted device extension.
    pub(crate) fn vcb(device: KernelDevice) -> Option<NonNull<VolumeControlBlock>> {
        let device_object = unsafe {
            // SAFETY: `device` is a non-null DEVICE_OBJECT decoded at the
            // dispatch boundary and is read for its extension pointer only.
            device.as_ptr().as_ref()
        }?;
        let header = unsafe {
            // SAFETY: Driver-owned device extensions share `DeviceExtensionHeader`
            // as their first field, so the kind can be checked before reading
            // any mounted-volume-only fields.
            device_object
                .DeviceExtension
                .cast::<DeviceExtensionHeader>()
                .as_ref()
        }?;
        if header.kind != DeviceExtensionKind::MOUNTED_VOLUME {
            return None;
        }
        let extension = unsafe {
            // SAFETY: The common header identified this driver-owned extension
            // as a mounted volume before the full mounted layout is read.
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
                .as_ref()
        }?;
        NonNull::new(extension.vcb)
    }

    /// Refreshes the VPB volume label after a successful label mutation.
    /// # Errors
    ///
    /// Returns an error when the mounted device or its VPB pointer is absent, or the ext4 label does
    /// not fit in the VPB label field.
    pub(crate) fn refresh_vpb_label(
        device: KernelDevice,
        volume_label: ext4_core::Ext4VolumeLabel,
    ) -> DriverResult<()> {
        let device_object = unsafe {
            // SAFETY: `device` is a mounted volume device owned by this driver
            // and is read only for its current VPB pointer.
            device.as_ptr().as_ref()
        }
        .ok_or(DriverError::InvalidParameter)?;
        let vpb = unsafe {
            // SAFETY: The VPB pointer belongs to the mounted device and stays
            // valid while the volume remains mounted.
            device_object.Vpb.as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        VpbLabel::encode(volume_label).map(|label| label.write_to(vpb))
    }
}

/// Registers a mounted filesystem device for shutdown delivery.
/// # Errors
///
/// Returns an error when the I/O Manager cannot register the mounted device for
/// `IRP_MJ_SHUTDOWN` delivery.
fn register_shutdown_notification(device: KernelDevice) -> DriverResult<()> {
    #[cfg(not(test))]
    {
        let status = unsafe {
            // SAFETY: `device` is a live mounted filesystem device whose
            // dispatch table owns IRP_MJ_SHUTDOWN before it is published.
            ffi::IoRegisterShutdownNotification(device.as_ptr())
        };
        shutdown_registration_status(status)
    }
    #[cfg(test)]
    {
        let _device = device;
        Ok(())
    }
}

/// Converts shutdown-registration status into the driver error domain.
/// # Errors
///
/// Returns an error when the I/O Manager rejected shutdown-notification registration.
fn shutdown_registration_status(status: wdk_sys::NTSTATUS) -> DriverResult<()> {
    if status < STATUS_SUCCESS {
        return Err(DriverError::InsufficientResources);
    }
    Ok(())
}

/// Count of UTF-16 code units exposed by WDK VPB::VolumeLabel.
const VPB_VOLUME_LABEL_UNITS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// VPB label payload prevalidated before mount publish mutates kernel-visible state.
struct VpbLabel {
    /// UTF-16 code units to copy into VPB::VolumeLabel.
    units: [u16; VPB_VOLUME_LABEL_UNITS],
    /// Byte length stored in VPB::VolumeLabelLength.
    byte_len: u16,
}

impl VpbLabel {
    /// Encodes an ext4 label into the VPB label layout.
    /// # Errors
    ///
    /// Returns an error when the ext4 label exceeds the VPB label capacity or the UTF-16 byte
    /// length cannot be represented by the VPB.
    fn encode(label: ext4_core::Ext4VolumeLabel) -> DriverResult<Self> {
        let bytes = label.bytes();
        if bytes.len() > VPB_VOLUME_LABEL_UNITS {
            return Err(DriverError::InvalidParameter);
        }
        let mut units = [0_u16; VPB_VOLUME_LABEL_UNITS];
        for (target, byte) in units.iter_mut().zip(bytes.iter().copied()) {
            *target = u16::from(byte);
        }
        let wchar_bytes = bytes
            .len()
            .checked_mul(core::mem::size_of::<u16>())
            .ok_or(DriverError::InvalidParameter)?;
        let byte_len = u16::try_from(wchar_bytes).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self { units, byte_len })
    }

    /// Writes a prevalidated label into a VPB.
    fn write_to(self, vpb: &mut wdk_sys::VPB) {
        vpb.VolumeLabel = self.units;
        vpb.VolumeLabelLength = self.byte_len;
    }
}

/// File control block stored in `FILE_OBJECT::FsContext`.
pub(crate) struct FileControlBlock {
    /// Mounted volume that owns this file.
    volume: NonNull<VolumeControlBlock>,
    /// Ledger that owns this FCB allocation and every open-state transition.
    owner: NonNull<FileControlBlockLedger>,
    /// Ext4 node opened by this FCB.
    node: NodeId,
    /// FsRtl-owned byte-range lock state for this opened inode identity.
    byte_range_locks: FileByteRangeLocks,
    /// Ledger-owned mutable state; accessed only under `owner`'s exclusive resource.
    open_state: UnsafeCell<FileControlBlockOpenState>,
}

// SAFETY: `volume`, `owner`, and `node` are immutable after construction. FsRtl synchronizes its
// opaque byte-range lock package, while `open_state` is accessed only under the owner ledger's
// exclusive executive resource.
unsafe impl Sync for FileControlBlock {}

impl fmt::Debug for FileControlBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileControlBlock")
            .field("volume", &self.volume)
            .field("owner", &self.owner)
            .field("node", &self.node)
            .field("byte_range_locks", &self.byte_range_locks)
            .field("open_state", &"FileControlBlockOpenState(..)")
            .finish()
    }
}

impl FileControlBlock {
    /// Creates an FCB boundary value for a mounted node with one open reference.
    fn new(
        volume: NonNull<VolumeControlBlock>,
        owner: NonNull<FileControlBlockLedger>,
        node: NodeId,
    ) -> Self {
        Self {
            volume,
            owner,
            node,
            byte_range_locks: FileByteRangeLocks::new(),
            open_state: UnsafeCell::new(FileControlBlockOpenState::new()),
        }
    }

    /// Returns the mounted VCB pointer that owns this open node.
    pub(crate) const fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.volume
    }

    /// Returns the ledger that owns this FCB without borrowing the enclosing VCB.
    const fn owner(&self) -> NonNull<FileControlBlockLedger> {
        self.owner
    }

    /// Returns the ext4 node identity opened by this FCB.
    pub(crate) const fn node(&self) -> NodeId {
        self.node
    }

    /// Transfers one validated lock-control IRP to the FsRtl lock package.
    pub(crate) fn process_byte_range_lock(&self, target: DispatchTarget) -> wdk_sys::NTSTATUS {
        self.byte_range_locks.process(target)
    }

    /// Returns whether the requestor may read one fully resolved file byte range.
    /// # Errors
    ///
    /// Returns an error when the resolved range cannot be represented by FsRtl.
    pub(crate) fn permits_byte_range_read(
        &self,
        target: DispatchTarget,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        self.byte_range_locks
            .permits_read(target, file_object, start, length, key)
    }

    /// Returns whether the requestor may write one fully resolved file byte range.
    /// # Errors
    ///
    /// Returns an error when the resolved range cannot be represented by FsRtl.
    pub(crate) fn permits_byte_range_write(
        &self,
        target: DispatchTarget,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        self.byte_range_locks
            .permits_write(target, file_object, start, length, key)
    }

    /// Releases all byte-range locks held by this FILE_OBJECT's requestor during cleanup.
    pub(crate) fn release_handle_byte_range_locks(
        &self,
        target: DispatchTarget,
        file_object: KernelFileObject,
    ) {
        self.byte_range_locks
            .release_for_cleanup(target, file_object);
    }
}

/// Mutable FCB lifecycle state owned exclusively by `FileControlBlockLedger`.
struct FileControlBlockOpenState {
    /// I/O manager share-access accounting for this inode identity.
    share_access: SHARE_ACCESS,
    /// Number of open FILE_OBJECTs currently referencing this FCB.
    file_object_references: NonZeroU32,
}

impl FileControlBlockOpenState {
    /// Creates empty share accounting for the first FILE_OBJECT reference.
    const fn new() -> Self {
        Self {
            share_access: SHARE_ACCESS {
                OpenCount: 0,
                Readers: 0,
                Writers: 0,
                Deleters: 0,
                SharedRead: 0,
                SharedWrite: 0,
                SharedDelete: 0,
            },
            file_object_references: NonZeroU32::MIN,
        }
    }

    /// Checks any operation-implied access and records the FILE_OBJECT share claim.
    /// # Errors
    ///
    /// Returns an error when existing handles do not share the effective operation access or when
    /// the requested handle claim cannot be recorded.
    fn record_share_access(
        &mut self,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        share_access: ShareAccess,
        share_check: FileControlBlockShareCheck,
    ) -> DriverResult<()> {
        if let FileControlBlockShareCheck::ExistingNode(existing_operation_access) = share_check {
            let operation_status = unsafe {
                // SAFETY: The ledger exclusively owns this SHARE_ACCESS record. Update is false,
                // so operation-implied access is checked without recording it as returned-handle
                // authority.
                ffi::IoCheckShareAccess(
                    existing_operation_access.as_raw(),
                    share_access.as_ulong(),
                    file_object.as_ptr(),
                    core::ptr::addr_of_mut!(self.share_access),
                    0,
                )
            };
            if operation_status < STATUS_SUCCESS {
                return Err(DriverError::ShareAccessConflict);
            }
        }
        let status = unsafe {
            // SAFETY: The ledger exclusively owns this SHARE_ACCESS record. This call records only
            // the access explicitly requested for the returned FILE_OBJECT.
            ffi::IoCheckShareAccess(
                desired_access.as_raw(),
                share_access.as_ulong(),
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.share_access),
                1,
            )
        };
        if status < STATUS_SUCCESS {
            return Err(DriverError::ShareAccessConflict);
        }
        Ok(())
    }

    /// Removes one FILE_OBJECT's recorded share-access claim.
    fn remove_share_access(&mut self, file_object: KernelFileObject) {
        unsafe {
            // SAFETY: Successful create recorded this FILE_OBJECT against this ledger-owned
            // SHARE_ACCESS, and the lifecycle transition selects one unique removal point.
            ffi::IoRemoveShareAccess(
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.share_access),
            );
        }
    }

    /// Computes one additional FILE_OBJECT reference without mutating state.
    /// # Errors
    ///
    /// Returns an error when the FCB open-reference counter cannot be incremented.
    fn next_file_object_reference(&self) -> DriverResult<NonZeroU32> {
        self.file_object_references
            .get()
            .checked_add(1)
            .and_then(NonZeroU32::new)
            .ok_or(DriverError::TooManyOpenReferences)
    }

    /// Releases one FILE_OBJECT reference from a non-empty FCB.
    fn release_open_reference(&mut self) -> FileControlBlockRelease {
        let Some(remaining) = self
            .file_object_references
            .get()
            .checked_sub(1)
            .and_then(NonZeroU32::new)
        else {
            return FileControlBlockRelease::LastReference;
        };
        self.file_object_references = remaining;
        FileControlBlockRelease::StillOpen
    }
}

/// Opaque FsRtl byte-range lock state owned by one FCB.
///
/// FsRtl synchronizes concurrent access to this state internally. `UnsafeCell` only permits the
/// native routines to mutate their opaque storage through the FCB's shared reference; it does not
/// expose Rust-side mutable access.
struct FileByteRangeLocks {
    /// Native lock package storage, initialized exactly once for this FCB.
    #[cfg(not(test))]
    native: UnsafeCell<wdk_sys::FILE_LOCK>,
}

/// Signed native range passed to FsRtl after file-position resolution.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "native FsRtl byte-range checks are compiled out in unit tests"
    )
)]
struct NativeFileByteRange {
    /// Non-negative starting byte.
    start: LARGE_INTEGER,
    /// Non-negative range length.
    length: LARGE_INTEGER,
}

impl NativeFileByteRange {
    /// Converts a core file range to the signed Windows lock domain.
    /// # Errors
    ///
    /// Returns an error when either endpoint exceeds the signed Windows file-offset range.
    fn new(start: FileOffset, length: usize) -> DriverResult<Self> {
        let end = start.checked_add_len(length)?;
        let _end = i64::try_from(end.bytes()).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self {
            start: LARGE_INTEGER {
                QuadPart: i64::try_from(start.bytes())
                    .map_err(|_| DriverError::InvalidParameter)?,
            },
            length: LARGE_INTEGER {
                QuadPart: i64::try_from(length).map_err(|_| DriverError::InvalidParameter)?,
            },
        })
    }
}

impl FileByteRangeLocks {
    /// Initializes FsRtl state for a newly allocated FCB.
    fn new() -> Self {
        #[cfg(not(test))]
        {
            let locks = Self {
                native: UnsafeCell::new(wdk_sys::FILE_LOCK::default()),
            };
            unsafe {
                // SAFETY: `native` points to uninitialized FILE_LOCK storage
                // owned exclusively by this newly created FCB.
                ffi::FsRtlInitializeFileLock(locks.native.get(), None, None);
            }
            locks
        }
        #[cfg(test)]
        {
            Self {}
        }
    }

    /// Lets FsRtl process and complete one byte-range lock IRP.
    fn process(&self, target: DispatchTarget) -> wdk_sys::NTSTATUS {
        #[cfg(not(test))]
        {
            unsafe {
                // SAFETY: FsRtl owns this FCB's initialized FILE_LOCK state
                // and takes over completion of the live lock-control IRP.
                ffi::FsRtlProcessFileLock(
                    self.native.get(),
                    target.as_raw_irp(),
                    core::ptr::null_mut(),
                )
            }
        }
        #[cfg(test)]
        {
            let _target = target;
            wdk_sys::STATUS_SUCCESS
        }
    }

    /// Checks one resolved read range against this FCB's byte-range locks.
    /// # Errors
    ///
    /// Returns an error when the resolved range cannot be represented by FsRtl.
    fn permits_read(
        &self,
        target: DispatchTarget,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        let range = NativeFileByteRange::new(start, length)?;
        #[cfg(not(test))]
        {
            let mut range = range;
            let requestor_process = unsafe {
                // SAFETY: `target` retains the live read IRP while the range check executes.
                ffi::IoGetRequestorProcess(target.as_raw_irp())
            };
            Ok(unsafe {
                // SAFETY: FsRtl receives initialized lock state, checked signed
                // range values, the live FILE_OBJECT, and the IRP requestor.
                ffi::FsRtlFastCheckLockForRead(
                    self.native.get(),
                    core::ptr::addr_of_mut!(range.start),
                    core::ptr::addr_of_mut!(range.length),
                    key.as_ulong(),
                    file_object.as_ptr(),
                    requestor_process.cast::<c_void>(),
                ) != 0
            })
        }
        #[cfg(test)]
        {
            let _target = target;
            let _file_object = file_object;
            let _key = key;
            let _range = range;
            Ok(true)
        }
    }

    /// Checks one resolved write range against this FCB's byte-range locks.
    /// # Errors
    ///
    /// Returns an error when the resolved range cannot be represented by FsRtl.
    fn permits_write(
        &self,
        target: DispatchTarget,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        let range = NativeFileByteRange::new(start, length)?;
        #[cfg(not(test))]
        {
            let mut range = range;
            let requestor_process = unsafe {
                // SAFETY: `target` retains the live write IRP while the range check executes.
                ffi::IoGetRequestorProcess(target.as_raw_irp())
            };
            Ok(unsafe {
                // SAFETY: FsRtl receives initialized lock state, checked signed
                // range values, the live FILE_OBJECT, and the IRP requestor.
                ffi::FsRtlFastCheckLockForWrite(
                    self.native.get(),
                    core::ptr::addr_of_mut!(range.start),
                    core::ptr::addr_of_mut!(range.length),
                    key.as_ulong(),
                    file_object.as_ptr().cast::<c_void>(),
                    requestor_process.cast::<c_void>(),
                ) != 0
            })
        }
        #[cfg(test)]
        {
            let _target = target;
            let _file_object = file_object;
            let _key = key;
            let _range = range;
            Ok(true)
        }
    }

    /// Releases all locks associated with this cleanup IRP's FILE_OBJECT and requestor.
    fn release_for_cleanup(&self, target: DispatchTarget, file_object: KernelFileObject) {
        #[cfg(not(test))]
        let requestor_process = unsafe {
            // SAFETY: `target` retains the live cleanup IRP until this
            // queued cleanup handler returns.
            ffi::IoGetRequestorProcess(target.as_raw_irp())
        };
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Cleanup runs for this live FILE_OBJECT. Passing the
            // requestor captured in its IRP matches FsRtl's lock ownership
            // identity and releases only that process's locks.
            let _status = ffi::FsRtlFastUnlockAll(
                self.native.get(),
                file_object.as_ptr(),
                requestor_process,
                core::ptr::null_mut(),
            );
        }
        #[cfg(test)]
        {
            let _target = target;
            let _file_object = file_object;
        }
    }
}

impl Drop for FileByteRangeLocks {
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This FCB initialized `native` once and cannot be
            // dropped until its final FILE_OBJECT reference is released.
            ffi::FsRtlUninitializeFileLock(self.native.get());
        }
    }
}

impl fmt::Debug for FileByteRangeLocks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileByteRangeLocks(..)")
    }
}

/// FCB lifetime state after releasing one open reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileControlBlockRelease {
    /// Other FILE_OBJECTs still reference this FCB.
    StillOpen,
    /// The released reference was the final open reference.
    LastReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Per-handle directory enumeration state.
pub(crate) struct DirectoryCursor {
    /// Next directory entry index to emit.
    next_entry: DirectoryEntryIndex,
}

impl DirectoryCursor {
    /// Creates a cursor at the first directory entry.
    pub(crate) const fn start() -> Self {
        Self {
            next_entry: DirectoryEntryIndex::from_u32(0),
        }
    }

    /// Returns the next directory entry index to emit.
    pub(crate) const fn next_entry(self) -> DirectoryEntryIndex {
        self.next_entry
    }

    /// Moves the cursor to a specific directory entry index.
    pub(crate) const fn seek(&mut self, next_entry: DirectoryEntryIndex) {
        self.next_entry = next_entry;
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Opened location identity stored with a handle.
pub(crate) enum OpenedLocation {
    /// Mounted volume root.
    Root,
    /// Child entry under a parent directory.
    DirectoryEntry {
        /// Parent directory inode.
        parent: DirectoryNodeId,
        /// Exact ext4 directory entry name.
        name: Ext4Name,
    },
    /// Opened by stable file reference without a directory-entry location.
    FileReference,
}

impl OpenedLocation {
    /// Builds a child directory-entry location by fallibly copying the ext4 child name.
    /// # Errors
    ///
    /// Returns an error when copying the child name cannot allocate.
    pub(crate) fn try_directory_entry(
        parent: DirectoryNodeId,
        name: &Ext4Name,
    ) -> DriverResult<Self> {
        Ok(Self::DirectoryEntry {
            parent,
            name: name.try_to_owned_name()?,
        })
    }

    /// Copies this opened location into a separately owned handle location.
    /// # Errors
    ///
    /// Returns an error when copying a child name cannot allocate.
    pub(crate) fn try_to_owned_location(&self) -> DriverResult<Self> {
        match self {
            Self::Root => Ok(Self::Root),
            Self::DirectoryEntry { parent, name } => Self::try_directory_entry(*parent, name),
            Self::FileReference => Ok(Self::FileReference),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Cleanup lifecycle of one successfully opened FILE_OBJECT.
enum HandleLifecycleState {
    /// The share claim and cleanup-owned resources are active.
    Active,
    /// Cleanup owns the one-way release transition.
    Cleaning,
    /// Cleanup has consumed the share claim and cleanup-owned resources.
    Cleaned,
}

impl HandleLifecycleState {
    /// Encodes the state in the atomic storage representation.
    const fn as_raw(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Cleaning => 1,
            Self::Cleaned => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Result of entering the synchronous cleanup transition.
pub(crate) enum CleanupStart {
    /// This caller owns every cleanup side effect.
    First,
    /// Cleanup was already completed before this request arrived.
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Ownership release selected before close detaches both FILE_OBJECT contexts.
pub(crate) enum CloseReleasePlan {
    /// Cleanup already removed the share claim; close releases only the FCB reference and CCB.
    CleanedHandle,
    /// A filter cancelled create before cleanup; close atomically removes share and FCB reference.
    CancelledOpen,
}

/// Selects a legal close release from the filesystem lifecycle and Windows cleanup state.
const fn select_close_release_plan(
    lifecycle: HandleLifecycleState,
    cleanup_complete: bool,
    close_kind: FileObjectCloseKind,
) -> Option<CloseReleasePlan> {
    match (lifecycle, cleanup_complete, close_kind) {
        (HandleLifecycleState::Cleaned, true, _) => Some(CloseReleasePlan::CleanedHandle),
        (HandleLifecycleState::Active, false, FileObjectCloseKind::CancelledOpen) => {
            Some(CloseReleasePlan::CancelledOpen)
        }
        _ => None,
    }
}

/// Atomic lifecycle gate shared by synchronous Cleanup/Close and outstanding request completion.
struct HandleLifecycle {
    /// Numeric `HandleLifecycleState` representation used for one-way compare-exchange transitions.
    state: AtomicU8,
}

impl HandleLifecycle {
    /// Creates an active handle lifecycle.
    const fn active() -> Self {
        Self {
            state: AtomicU8::new(HandleLifecycleState::Active.as_raw()),
        }
    }

    /// Loads the current typed lifecycle state.
    fn state(&self) -> HandleLifecycleState {
        match self.state.load(Ordering::Acquire) {
            value if value == HandleLifecycleState::Active.as_raw() => HandleLifecycleState::Active,
            value if value == HandleLifecycleState::Cleaning.as_raw() => {
                HandleLifecycleState::Cleaning
            }
            value if value == HandleLifecycleState::Cleaned.as_raw() => {
                HandleLifecycleState::Cleaned
            }
            _ => KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck(),
        }
    }

    /// Enters cleanup once while making a completed retry idempotent.
    fn begin_cleanup(&self) -> CleanupStart {
        match self.state.compare_exchange(
            HandleLifecycleState::Active.as_raw(),
            HandleLifecycleState::Cleaning.as_raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => CleanupStart::First,
            Err(value) if value == HandleLifecycleState::Cleaned.as_raw() => {
                CleanupStart::AlreadyComplete
            }
            Err(_) => KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck(),
        }
    }

    /// Publishes completion after every cleanup-owned side effect has finished.
    fn finish_cleanup(&self) {
        if self
            .state
            .compare_exchange(
                HandleLifecycleState::Cleaning.as_raw(),
                HandleLifecycleState::Cleaned.as_raw(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck();
        }
    }

    /// Selects the only legal terminal release for the observed Windows close reason.
    fn close_release_plan(
        &self,
        close_kind: FileObjectCloseKind,
        cleanup_complete: bool,
    ) -> CloseReleasePlan {
        select_close_release_plan(self.state(), cleanup_complete, close_kind).unwrap_or_else(|| {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
        })
    }
}

impl fmt::Debug for HandleLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.state().fmt(formatter)
    }
}

impl PartialEq for HandleLifecycle {
    fn eq(&self, other: &Self) -> bool {
        self.state() == other.state()
    }
}

impl Eq for HandleLifecycle {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Per-handle write completion durability requested at create/open.
pub(crate) enum WriteCommitment {
    /// Complete writes after the ext4 journal transaction is committed.
    CommitOnly,
    /// Flush the mounted volume before completing each non-empty write.
    FlushThrough,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Namespace interpretation selected for one opened handle.
pub(crate) enum OpenedNodeMode {
    /// The handle accesses the underlying ext4 node directly.
    Direct,
    /// The handle accesses a reparse point without resolving its target.
    ReparsePoint,
}

#[derive(Debug, Eq, PartialEq)]
/// FsRtl directory-name descriptor lifecycle for one opened handle.
enum DirectoryNotificationName {
    /// No directory notification IRP has required a stable name yet.
    Unregistered,
    /// FsRtl may retain this descriptor until the FILE_OBJECT cleanup transition.
    Registered(Pin<Box<DirectoryNotificationDirectoryName>>),
}

#[derive(Debug)]
/// Common per-handle state shared by every opened node kind.
struct OpenedHandleState {
    /// Namespace interpretation selected when this handle was opened.
    node_mode: OpenedNodeMode,
    /// Location used for namespace mutations on cleanup when available.
    location: UnsafeCell<OpenedLocation>,
    /// One-way cleanup lifecycle shared with the synchronous control plane.
    lifecycle: HandleLifecycle,
    /// Write completion durability requested for this handle.
    write_commitment: WriteCommitment,
    /// Data transfer buffering policy requested for this handle.
    data_transfer_mode: DataTransferMode,
    /// Stable FsRtl directory-name descriptor, retained even if the opened node changes kind.
    directory_notification_name: UnsafeCell<DirectoryNotificationName>,
}

impl OpenedHandleState {
    /// Creates shared per-handle state.
    const fn new(
        node_mode: OpenedNodeMode,
        location: OpenedLocation,
        write_commitment: WriteCommitment,
        data_transfer_mode: DataTransferMode,
    ) -> Self {
        Self {
            node_mode,
            location: UnsafeCell::new(location),
            lifecycle: HandleLifecycle::active(),
            write_commitment,
            data_transfer_mode,
            directory_notification_name: UnsafeCell::new(DirectoryNotificationName::Unregistered),
        }
    }

    /// Returns the opened location identity.
    fn location(&self) -> &OpenedLocation {
        unsafe {
            // SAFETY: The device operation lane serializes every location read and replacement.
            // Cleanup accesses only the disjoint atomic lifecycle and never this cell.
            &*self.location.get()
        }
    }

    /// Returns the namespace interpretation selected for this handle.
    const fn node_mode(&self) -> OpenedNodeMode {
        self.node_mode
    }

    /// Replaces the opened location after a successful rename.
    fn replace_location(&self, location: OpenedLocation) {
        unsafe {
            // SAFETY: The device operation lane serializes rename with every other operation that
            // reads or replaces this handle-local location.
            *self.location.get() = location;
        }
    }

    /// Returns write completion durability requested for this handle.
    const fn write_commitment(&self) -> WriteCommitment {
        self.write_commitment
    }

    /// Returns data transfer buffering policy requested at create/open.
    const fn data_transfer_mode(&self) -> DataTransferMode {
        self.data_transfer_mode
    }

    /// Begins the idempotent cleanup transition.
    fn begin_cleanup(&self) -> CleanupStart {
        self.lifecycle.begin_cleanup()
    }

    /// Publishes completion after every cleanup-owned release has finished.
    fn finish_cleanup(&self) {
        self.lifecycle.finish_cleanup();
    }

    /// Selects the legal terminal release for close.
    fn close_release_plan(
        &self,
        close_kind: FileObjectCloseKind,
        cleanup_complete: bool,
    ) -> CloseReleasePlan {
        self.lifecycle
            .close_release_plan(close_kind, cleanup_complete)
    }

    /// Allocates the stable directory-name descriptor retained by FsRtl after registration.
    /// # Errors
    ///
    /// Returns an error when allocation of the CCB-owned descriptor fails.
    fn ensure_directory_notification_name(
        &self,
        directory: DirectoryNodeId,
    ) -> DriverResult<NonNull<UNICODE_STRING>> {
        let notification_name = unsafe {
            // SAFETY: The device operation lane serializes notification registration. Cleanup
            // passes only the stable CCB address to FsRtl and does not access this cell.
            &mut *self.directory_notification_name.get()
        };
        match notification_name {
            DirectoryNotificationName::Registered(name) => Ok(name.descriptor()),
            DirectoryNotificationName::Unregistered => {
                let name = DirectoryNotificationDirectoryName::try_new(directory)?;
                let descriptor = name.descriptor();
                *notification_name = DirectoryNotificationName::Registered(name);
                Ok(descriptor)
            }
        }
    }
}

#[derive(Debug)]
/// Per-handle state stored in `FILE_OBJECT::FsContext2`.
pub(crate) struct OpenedHandle {
    /// Common handle state independent of node kind.
    state: OpenedHandleState,
    /// Kind-specific handle state.
    kind: OpenedHandleKind,
}

#[derive(Debug)]
/// Kind-specific per-handle state.
enum OpenedHandleKind {
    /// Regular file handle.
    File {
        /// Data-write authority fixed when this handle was created.
        write_access: RegularFileWriteAccess,
    },
    /// Directory handle with enumeration cursor.
    Directory {
        /// Directory enumeration cursor.
        cursor: UnsafeCell<DirectoryCursor>,
    },
    /// Symlink handle.
    Symlink,
}

impl OpenedHandle {
    /// Creates per-handle state for an opened node.
    pub(crate) fn new(
        node: NodeId,
        node_mode: OpenedNodeMode,
        location: OpenedLocation,
        write_commitment: WriteCommitment,
        data_transfer_mode: DataTransferMode,
        regular_file_write_access: RegularFileWriteAccess,
    ) -> Self {
        Self::from_parts(
            node,
            node_mode,
            location,
            write_commitment,
            data_transfer_mode,
            regular_file_write_access,
        )
    }

    /// Creates per-handle state from explicit lifecycle fields.
    fn from_parts(
        node: NodeId,
        node_mode: OpenedNodeMode,
        location: OpenedLocation,
        write_commitment: WriteCommitment,
        data_transfer_mode: DataTransferMode,
        regular_file_write_access: RegularFileWriteAccess,
    ) -> Self {
        let state =
            OpenedHandleState::new(node_mode, location, write_commitment, data_transfer_mode);
        let kind = match node {
            NodeId::File(_) => OpenedHandleKind::File {
                write_access: regular_file_write_access,
            },
            NodeId::Directory(_) => OpenedHandleKind::Directory {
                cursor: UnsafeCell::new(DirectoryCursor::start()),
            },
            NodeId::Symlink(_) => OpenedHandleKind::Symlink,
        };
        Self { state, kind }
    }

    /// Returns write completion durability requested for this handle.
    const fn write_commitment(&self) -> WriteCommitment {
        self.state.write_commitment()
    }

    /// Returns data transfer buffering policy requested for this handle.
    const fn data_transfer_mode(&self) -> DataTransferMode {
        self.state.data_transfer_mode()
    }

    /// Returns the opened location identity.
    fn location(&self) -> &OpenedLocation {
        self.state.location()
    }

    /// Returns the namespace interpretation selected for this handle.
    const fn node_mode(&self) -> OpenedNodeMode {
        self.state.node_mode()
    }

    /// Begins this handle's idempotent cleanup transition.
    fn begin_cleanup(&self) -> CleanupStart {
        self.state.begin_cleanup()
    }

    /// Publishes cleanup completion after every release has finished.
    fn finish_cleanup(&self) {
        self.state.finish_cleanup();
    }

    /// Selects the legal terminal release for close.
    fn close_release_plan(
        &self,
        close_kind: FileObjectCloseKind,
        cleanup_complete: bool,
    ) -> CloseReleasePlan {
        self.state.close_release_plan(close_kind, cleanup_complete)
    }

    /// Replaces the opened location after a successful rename.
    fn replace_location(&self, location: OpenedLocation) {
        self.state.replace_location(location);
    }

    /// Returns the stable CCB-owned descriptor needed by FsRtl directory notifications.
    /// # Errors
    ///
    /// Returns an error when the descriptor allocation fails on its first registration.
    fn ensure_directory_notification_name(
        &self,
        directory: DirectoryNodeId,
    ) -> DriverResult<NonNull<UNICODE_STRING>> {
        self.state.ensure_directory_notification_name(directory)
    }

    /// Returns the kind-specific handle state.
    const fn kind(&self) -> &OpenedHandleKind {
        &self.kind
    }

    /// Returns write authority for a regular-file handle variant.
    fn regular_file_write_access(&self) -> Option<RegularFileWriteAccess> {
        match &self.kind {
            OpenedHandleKind::File { write_access } => Some(*write_access),
            OpenedHandleKind::Directory { .. } | OpenedHandleKind::Symlink => None,
        }
    }

    /// Returns the stable interior cursor address for directory handles.
    fn directory_cursor(&self) -> Option<NonNull<DirectoryCursor>> {
        match &self.kind {
            OpenedHandleKind::Directory { cursor } => NonNull::new(cursor.get()),
            OpenedHandleKind::File { .. } | OpenedHandleKind::Symlink => None,
        }
    }
}

/// FILE_OBJECT whose FCB and CCB contexts have both been initialized by create.
#[derive(Debug)]
pub(crate) struct OpenedObject {
    /// Kernel FILE_OBJECT carrying the contexts.
    file_object: KernelFileObject,
    /// Shared file control block stored in FsContext.
    fcb: NonNull<FileControlBlock>,
    /// Per-handle context stored in FsContext2.
    handle: NonNull<OpenedHandle>,
}

impl OpenedObject {
    /// Decodes an initialized FILE_OBJECT context pair.
    ///
    /// # Errors
    /// Returns an error when either filesystem context pointer is absent or
    /// when the shared FCB node kind does not match the per-handle state kind.
    pub(crate) fn decode(file_object: KernelFileObject) -> DriverResult<Self> {
        let object = unsafe {
            // SAFETY: The FILE_OBJECT pointer comes from the active IRP stack
            // and is read only for filesystem-owned context pointers.
            file_object.as_ref()
        };
        let fcb = NonNull::new(object.FsContext.cast::<FileControlBlock>());
        let handle = NonNull::new(object.FsContext2.cast::<OpenedHandle>());
        let (fcb, handle) = match (fcb, handle) {
            (Some(fcb), Some(handle)) => (fcb, handle),
            (None, None) => return Err(DriverError::InvalidParameter),
            (Some(_), None) | (None, Some(_)) => {
                KernelWideInconsistency::file_object_context_corruption().bugcheck();
            }
        };
        let opened = Self {
            file_object,
            fcb,
            handle,
        };
        opened.validate_handle_kind()?;
        Ok(opened)
    }

    /// Returns the kernel FILE_OBJECT associated with this opened handle.
    pub(crate) const fn file_object(&self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the mounted VCB pointer owning this opened node.
    pub(crate) fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.file_control_block().volume()
    }

    /// Returns the ext4 node identity owned by the shared FCB.
    pub(crate) fn node(&self) -> NodeId {
        self.file_control_block().node()
    }

    /// Returns the opened location identity.
    pub(crate) fn location(&self) -> &OpenedLocation {
        self.handle().location()
    }

    /// Returns the namespace interpretation selected for this handle.
    pub(crate) fn node_mode(&self) -> OpenedNodeMode {
        self.handle().node_mode()
    }

    /// Replaces the opened location after a successful rename.
    pub(crate) fn replace_location(&mut self, location: OpenedLocation) {
        self.handle().replace_location(location);
    }

    /// Returns write completion durability requested for this opened handle.
    pub(crate) fn write_commitment(&self) -> WriteCommitment {
        self.handle().write_commitment()
    }

    /// Returns data transfer buffering policy requested for this opened handle.
    pub(crate) fn data_transfer_mode(&self) -> DataTransferMode {
        self.handle().data_transfer_mode()
    }

    /// Returns the synchronous FILE_OBJECT current position.
    /// # Errors
    ///
    /// Returns an error when the handle is asynchronous or its raw position is negative.
    pub(crate) fn current_file_position(&self) -> DriverResult<FileOffset> {
        if !self.has_synchronous_file_position() {
            return Err(DriverError::InvalidParameter);
        }
        let file_object = unsafe {
            // SAFETY: The opened object retains the live FILE_OBJECT and this
            // method reads only the I/O Manager position field.
            self.file_object.as_ref()
        };
        let position = unsafe {
            // SAFETY: ext4win consistently uses the QuadPart LARGE_INTEGER arm.
            file_object.CurrentByteOffset.QuadPart
        };
        Ok(FileOffset::from_bytes(
            u64::try_from(position).map_err(|_| DriverError::InvalidParameter)?,
        ))
    }

    /// Replaces the synchronous FILE_OBJECT current position.
    /// # Errors
    ///
    /// Returns an error when the handle is asynchronous or the position exceeds signed Windows
    /// range.
    pub(crate) fn set_current_file_position(&mut self, position: FileOffset) -> DriverResult<()> {
        if !self.has_synchronous_file_position() {
            return Err(DriverError::InvalidParameter);
        }
        self.write_current_file_position(position)
    }

    /// Advances the current position after a successful normal handle I/O operation.
    /// # Errors
    ///
    /// Returns an error when the resulting signed Windows position overflows.
    pub(crate) fn update_current_file_position(
        &mut self,
        kind: DataIoKind,
        start: FileOffset,
        transferred: usize,
    ) -> DriverResult<()> {
        if kind == DataIoKind::Paging || !self.has_synchronous_file_position() {
            return Ok(());
        }
        self.write_current_file_position(start.checked_add_len(transferred)?)
    }

    /// Returns whether this FILE_OBJECT owns a synchronized current-position field.
    fn has_synchronous_file_position(&self) -> bool {
        let file_object = unsafe {
            // SAFETY: The opened object retains the live FILE_OBJECT and reads only its flags.
            self.file_object.as_ref()
        };
        file_object.Flags & wdk_sys::FO_SYNCHRONOUS_IO != 0
    }

    /// Writes a preselected position after signed-range validation.
    /// # Errors
    ///
    /// Returns an error when the position exceeds signed Windows range.
    fn write_current_file_position(&mut self, position: FileOffset) -> DriverResult<()> {
        let position =
            i64::try_from(position.bytes()).map_err(|_| DriverError::InvalidParameter)?;
        let file_object = unsafe {
            // SAFETY: Queued file operations serialize ext4win mutations of
            // this live FILE_OBJECT's current-position field.
            self.file_object.as_mut()
        };
        file_object.CurrentByteOffset = LARGE_INTEGER { QuadPart: position };
        Ok(())
    }

    /// Enters this handle's synchronous cleanup transition.
    pub(crate) fn begin_cleanup(&self) -> CleanupStart {
        self.handle().begin_cleanup()
    }

    /// Removes this handle's share claim while retaining its FCB reference until close.
    pub(crate) fn release_share_access_for_cleanup(&self) {
        release_file_share_access(self.fcb, self.file_object);
    }

    /// Publishes lifecycle completion after every cleanup-owned release has finished.
    pub(crate) fn finish_cleanup(&self) {
        self.handle().finish_cleanup();
    }

    /// Selects the only legal terminal release before close detaches both contexts.
    pub(crate) fn close_release_plan(&self, close_kind: FileObjectCloseKind) -> CloseReleasePlan {
        self.handle()
            .close_release_plan(close_kind, self.file_object.cleanup_complete())
    }

    /// Returns the decoded file control block.
    pub(crate) fn file_control_block(&self) -> &FileControlBlock {
        unsafe {
            // SAFETY: `decode` only constructs this type from a non-null
            // FsContext written by successful create and used during the
            // active FILE_OBJECT lifetime.
            self.fcb.as_ref()
        }
    }

    /// Returns the unique CCB address used as the FsRtl notification owner context.
    pub(crate) const fn notification_context(&self) -> NonNull<c_void> {
        self.handle.cast()
    }

    /// Returns the stable CCB-owned directory name retained by FsRtl after registration.
    /// # Errors
    ///
    /// Returns an error when the descriptor allocation fails on its first registration.
    fn ensure_directory_notification_name(
        &self,
        directory: DirectoryNodeId,
    ) -> DriverResult<NonNull<UNICODE_STRING>> {
        self.handle().ensure_directory_notification_name(directory)
    }

    /// Returns the decoded per-handle state.
    fn handle(&self) -> &OpenedHandle {
        unsafe {
            // SAFETY: `decode` only constructs this type from a non-null
            // FsContext2 written by successful create and used during the
            // active FILE_OBJECT lifetime.
            self.handle.as_ref()
        }
    }

    /// Rejects corrupted FILE_OBJECT contexts whose FCB and handle kind disagree.
    ///
    /// # Errors
    /// Returns an error when FCB node identity and handle variant encode
    /// different node kinds.
    fn validate_handle_kind(&self) -> DriverResult<()> {
        match (self.node(), self.handle().kind()) {
            (NodeId::File(_), OpenedHandleKind::File { .. })
            | (NodeId::Directory(_), OpenedHandleKind::Directory { .. })
            | (NodeId::Symlink(_), OpenedHandleKind::Symlink) => Ok(()),
            _ => KernelWideInconsistency::file_object_context_corruption().bugcheck(),
        }
    }
}

#[derive(Debug)]
/// Opened regular file decoded from a FILE_OBJECT context pair.
pub(crate) struct OpenedRegularFile {
    /// Opened object context validated as a regular file.
    opened: OpenedObject,
    /// Typed file node identity.
    id: FileNodeId,
}

impl OpenedRegularFile {
    /// Decodes an opened FILE_OBJECT and requires a regular-file node.
    ///
    /// # Errors
    /// Returns an error when the FILE_OBJECT contexts are invalid or when the
    /// opened node is not a regular file.
    pub(crate) fn decode(file_object: KernelFileObject) -> DriverResult<Self> {
        let opened = OpenedObject::decode(file_object)?;
        let NodeId::File(id) = opened.node() else {
            return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
        };
        if opened.node_mode() == OpenedNodeMode::ReparsePoint {
            return Err(DriverError::NotSupported);
        }
        Ok(Self { opened, id })
    }

    /// Returns the typed regular-file identity.
    pub(crate) const fn id(&self) -> FileNodeId {
        self.id
    }

    /// Returns the mounted VCB pointer owning this opened file.
    pub(crate) fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.opened.volume()
    }

    /// Returns the shared FCB that owns this regular file's byte-range locks.
    pub(crate) fn file_control_block(&self) -> &FileControlBlock {
        self.opened.file_control_block()
    }

    /// Returns the typed kernel FILE_OBJECT for FsRtl ownership checks.
    pub(crate) const fn file_object(&self) -> KernelFileObject {
        self.opened.file_object()
    }

    /// Returns regular-file write authority fixed at create time.
    pub(crate) fn write_access(&self) -> RegularFileWriteAccess {
        self.opened
            .handle()
            .regular_file_write_access()
            .unwrap_or_else(|| KernelWideInconsistency::file_object_context_corruption().bugcheck())
    }

    /// Returns the synchronous per-handle file position.
    /// # Errors
    ///
    /// Returns an error when the handle is asynchronous or its position is invalid.
    pub(crate) fn current_file_position(&self) -> DriverResult<FileOffset> {
        self.opened.current_file_position()
    }

    /// Advances the current position after successful normal file I/O.
    /// # Errors
    ///
    /// Returns an error when the resulting signed Windows position overflows.
    pub(crate) fn update_current_file_position(
        &mut self,
        kind: DataIoKind,
        start: FileOffset,
        transferred: usize,
    ) -> DriverResult<()> {
        self.opened
            .update_current_file_position(kind, start, transferred)
    }

    /// Returns write completion durability requested for this regular-file handle.
    pub(crate) fn write_commitment(&self) -> WriteCommitment {
        self.opened.write_commitment()
    }

    /// Returns data transfer buffering policy requested for this regular-file handle.
    pub(crate) fn data_transfer_mode(&self) -> DataTransferMode {
        self.opened.data_transfer_mode()
    }
}

#[derive(Debug)]
/// Opened directory decoded from a FILE_OBJECT context pair.
pub(crate) struct OpenedDirectory {
    /// Opened object context validated as a directory.
    opened: OpenedObject,
    /// Typed directory node identity.
    id: DirectoryNodeId,
    /// Directory cursor stored in the directory handle variant.
    cursor: NonNull<DirectoryCursor>,
}

impl OpenedDirectory {
    /// Decodes an opened FILE_OBJECT and requires a directory node.
    ///
    /// # Errors
    /// Returns an error when the FILE_OBJECT contexts are invalid or when the
    /// opened node is not a directory.
    pub(crate) fn decode(file_object: KernelFileObject) -> DriverResult<Self> {
        let opened = OpenedObject::decode(file_object)?;
        let NodeId::Directory(id) = opened.node() else {
            return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
        };
        if opened.node_mode() == OpenedNodeMode::ReparsePoint {
            return Err(DriverError::NotSupported);
        }
        let Some(cursor) = opened.handle().directory_cursor() else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(Self { opened, id, cursor })
    }

    /// Returns the typed directory identity.
    pub(crate) const fn id(&self) -> DirectoryNodeId {
        self.id
    }

    /// Returns the stable CCB-owned name descriptor retained by FsRtl notification records.
    /// # Errors
    ///
    /// Returns an error when the descriptor allocation fails on its first registration.
    pub(crate) fn notification_directory_name(&mut self) -> DriverResult<NonNull<UNICODE_STRING>> {
        self.opened.ensure_directory_notification_name(self.id)
    }

    /// Returns the mounted VCB pointer owning this opened directory.
    pub(crate) fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.opened.volume()
    }

    /// Returns the unique CCB address used as the FsRtl notification owner context.
    pub(crate) const fn notification_context(&self) -> NonNull<c_void> {
        self.opened.notification_context()
    }

    /// Returns the mutable directory enumeration cursor.
    pub(crate) fn cursor_mut(&mut self) -> &mut DirectoryCursor {
        unsafe {
            // SAFETY: `cursor` points into the live directory handle variant
            // validated during decode. This type exposes no variant-changing
            // operation.
            self.cursor.as_mut()
        }
    }
}

/// Releases one FILE_OBJECT reference to a VCB-owned FCB.
pub(crate) fn release_file_control_block(fcb: NonNull<FileControlBlock>) {
    let owner = file_control_block_owner(fcb);
    let owner = unsafe {
        // SAFETY: The live FCB reference is owned by this ledger until `close` returns.
        owner.as_ref()
    };
    owner.close(fcb);
}

/// Releases one FILE_OBJECT's share claim while retaining its FCB reference until close.
pub(crate) fn release_file_share_access(
    fcb: NonNull<FileControlBlock>,
    file_object: KernelFileObject,
) {
    let owner = file_control_block_owner(fcb);
    let owner = unsafe {
        // SAFETY: The retained FCB reference keeps its owner ledger live for cleanup.
        owner.as_ref()
    };
    owner.release_share_access(fcb, file_object);
}

/// Rolls back a pre-attachment FCB reference and its recorded share claim.
pub(crate) fn abandon_file_control_block(
    fcb: NonNull<FileControlBlock>,
    file_object: KernelFileObject,
) {
    let owner = file_control_block_owner(fcb);
    let owner = unsafe {
        // SAFETY: The unpublished FCB remains owned by this ledger until rollback returns.
        owner.as_ref()
    };
    owner.release_share_access_and_reference(fcb, file_object);
}

/// Atomically releases a cancelled open's active share claim and final FCB reference.
pub(crate) fn release_cancelled_file_control_block(
    fcb: NonNull<FileControlBlock>,
    file_object: KernelFileObject,
) {
    let owner = file_control_block_owner(fcb);
    let owner = unsafe {
        // SAFETY: The cancelled FILE_OBJECT retains its FCB and owner until close consumes both.
        owner.as_ref()
    };
    owner.release_share_access_and_reference(fcb, file_object);
}

/// Returns the ledger pointer stored immutably in one live FCB.
fn file_control_block_owner(fcb: NonNull<FileControlBlock>) -> NonNull<FileControlBlockLedger> {
    unsafe {
        // SAFETY: All callers hold one live FILE_OBJECT or pre-attachment reference to this FCB.
        fcb.as_ref().owner()
    }
}

/// Driver unload callback registered in the driver object.
///
/// # Safety
/// The I/O Manager must call this only as the registered unload routine for this driver object,
/// after no dispatch callbacks can still use the control device being unregistered.
pub(crate) unsafe extern "C" fn driver_unload(_driver: PDRIVER_OBJECT) {
    let control_device = core::ptr::addr_of_mut!(CONTROL_DEVICE);
    let device = unsafe {
        // SAFETY: `control_device` points to the driver-owned global state.
        // Replacement takes ownership of the registered device for teardown.
        core::ptr::replace(control_device, None)
    };
    if let Some(control_device) = device {
        let device = control_device.as_ptr();
        unsafe {
            // SAFETY: The device was created and registered by DriverEntry.
            ffi::IoUnregisterFileSystem(device);
        }
        unsafe {
            // SAFETY: The control device is no longer registered and no
            // dispatch callbacks can access its queue.
            control_device.release();
        }
        unsafe {
            // SAFETY: The device is no longer registered and is owned by this driver.
            ffi::IoDeleteDevice(device);
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;
    use core::ptr::NonNull;

    use ext4_core::{DirectoryNodeId, Ext4Name, FileOffset, NodeId};

    use crate::irp::{DataIoKind, DirectoryEntryIndex, RegularFileWriteAccess};
    use crate::kernel::status::DriverError;

    use super::{
        CleanupStart, CloseReleasePlan, ControlDeviceExtension,
        DIRECTORY_NOTIFICATION_DIRECTORY_UNITS, DataTransferMode, DeviceExtensionKind,
        DirectoryNameChange, DirectoryNameChangeAction, FileControlBlock, FileControlBlockLedger,
        FileControlBlockOpenState, FileControlBlockRelease, FileObjectCloseKind, KernelDevice,
        KernelFileObject, MountedVolumeDevice, MountedVolumeDeviceExtension, NativeFileByteRange,
        NoIntermediateTransfer, OpenedDirectory, OpenedHandle, OpenedLocation, OpenedNodeMode,
        OpenedObject, OpenedRegularFile, TransferBufferAlignment, TransferSectorSize,
        UninitializedFileObject, VolumeControlBlock, WriteCommitment, select_close_release_plan,
        shutdown_registration_status,
    };

    fn file_object_with_contexts(
        fs_context: *mut core::ffi::c_void,
        fs_context2: *mut core::ffi::c_void,
    ) -> wdk_sys::FILE_OBJECT {
        wdk_sys::FILE_OBJECT {
            FsContext: fs_context,
            FsContext2: fs_context2,
            ..wdk_sys::FILE_OBJECT::default()
        }
    }

    /// Builds the typed FILE_OBJECT boundary from a local non-null test object.
    fn kernel_file_object(file: &mut wdk_sys::FILE_OBJECT) -> Option<KernelFileObject> {
        KernelFileObject::from_raw(core::ptr::addr_of_mut!(*file))
    }

    /// Builds an isolated FCB for tests that exercise only immutable data-plane fields.
    fn test_file_control_block(
        volume: NonNull<VolumeControlBlock>,
        node: NodeId,
    ) -> FileControlBlock {
        FileControlBlock::new(volume, NonNull::<FileControlBlockLedger>::dangling(), node)
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn mounted_volume_vcb_rejects_control_device_extension() {
        let mut extension = core::mem::MaybeUninit::<ControlDeviceExtension>::zeroed();
        let mut device = wdk_sys::DEVICE_OBJECT {
            DeviceExtension: extension.as_mut_ptr().cast(),
            ..wdk_sys::DEVICE_OBJECT::default()
        };
        let device = KernelDevice::from_raw(core::ptr::addr_of_mut!(device));
        assert!(device.is_some());
        if let Some(device) = device {
            assert_eq!(ControlDeviceExtension::initialize(device), Ok(()));
            assert_eq!(MountedVolumeDevice::vcb(device), None);
            unsafe {
                // SAFETY: The test initialized the control extension above and
                // no queue user exists after the local assertions.
                ControlDeviceExtension::release(device);
            }
        }
    }

    /// # Panics
    ///
    /// Panics when the mounted extension no longer exposes its live VCB pointer.
    #[test]
    fn mounted_volume_vcb_decodes_mounted_device_extension() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut extension = core::mem::MaybeUninit::<MountedVolumeDeviceExtension>::zeroed();
        let extension = unsafe {
            // SAFETY: The test initializes every field read by
            // MountedVolumeDevice::vcb before exposing this extension.
            extension.assume_init_mut()
        };
        extension.header.kind = DeviceExtensionKind::MOUNTED_VOLUME;
        extension.vcb = volume.as_ptr();
        let mut device = wdk_sys::DEVICE_OBJECT {
            DeviceExtension: core::ptr::from_mut(extension).cast(),
            ..wdk_sys::DEVICE_OBJECT::default()
        };
        let device = KernelDevice::from_raw(core::ptr::addr_of_mut!(device));
        assert_eq!(device.and_then(MountedVolumeDevice::vcb), Some(volume));
    }

    /// # Panics
    ///
    /// Panics when shutdown-registration failure stops surfacing as an allocation failure.
    #[test]
    fn shutdown_registration_status_maps_success_and_failure() {
        assert_eq!(
            shutdown_registration_status(wdk_sys::STATUS_SUCCESS),
            Ok(())
        );
        assert_eq!(
            shutdown_registration_status(wdk_sys::STATUS_INSUFFICIENT_RESOURCES),
            Err(DriverError::InsufficientResources)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn kernel_device_decodes_transfer_alignment_requirement() {
        let mut device = wdk_sys::DEVICE_OBJECT {
            AlignmentRequirement: wdk_sys::FILE_512_BYTE_ALIGNMENT,
            ..wdk_sys::DEVICE_OBJECT::default()
        };
        let device = KernelDevice::from_raw(core::ptr::addr_of_mut!(device));
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };

        let alignment = device.transfer_buffer_alignment();
        assert!(alignment.is_ok());
        if let Ok(alignment) = alignment {
            assert_eq!(alignment.as_mask(), wdk_sys::FILE_512_BYTE_ALIGNMENT);
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn no_intermediate_transfer_validates_range_and_buffer_alignment() {
        let buffer_alignment =
            TransferBufferAlignment::from_requirement_mask(wdk_sys::FILE_QUAD_ALIGNMENT);
        assert!(buffer_alignment.is_ok());
        let Ok(buffer_alignment) = buffer_alignment else {
            return;
        };
        let mode = DataTransferMode::NoIntermediate(NoIntermediateTransfer {
            sector_size: TransferSectorSize::WINDOWS_REPORTED,
            buffer_alignment,
        });

        assert_eq!(mode.validate_range(512, 1024), Ok(()));
        assert_eq!(mode.validate_position(1024), Ok(()));
        assert_eq!(
            mode.validate_range(1, 1024),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            mode.validate_position(1),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            mode.validate_range(512, 1),
            Err(DriverError::InvalidParameter)
        );

        let mut bytes = [0_u8; 32];
        let base = bytes.as_mut_ptr().addr();
        let aligned_delta = (8 - (base & 7)) & 7;
        let aligned_ptr = unsafe {
            // SAFETY: `aligned_delta` is at most 7 and the local buffer has 32 bytes.
            bytes.as_mut_ptr().add(aligned_delta)
        };
        let aligned = NonNull::new(aligned_ptr);
        assert!(aligned.is_some());
        let Some(aligned) = aligned else {
            return;
        };
        let misaligned_ptr = unsafe {
            // SAFETY: `aligned_delta + 1` is at most 8 and the local buffer has 32 bytes.
            bytes.as_mut_ptr().add(aligned_delta + 1)
        };
        let misaligned = NonNull::new(misaligned_ptr);
        assert!(misaligned.is_some());
        let Some(misaligned) = misaligned else {
            return;
        };

        assert_eq!(mode.validate_buffer(aligned), Ok(()));
        assert_eq!(
            mode.validate_buffer(misaligned),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn kernel_file_object_rejects_null_raw_pointer() {
        assert_eq!(KernelFileObject::from_raw(core::ptr::null_mut()), None);
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn unopened_object_without_contexts_is_invalid_parameter() {
        let mut file = file_object_with_contexts(core::ptr::null_mut(), core::ptr::null_mut());
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };

        assert_eq!(
            OpenedObject::decode(file_object).err(),
            Some(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn typed_opened_directory_exposes_cursor_without_option() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            OpenedLocation::Root,
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        let directory = OpenedDirectory::decode(file_object);
        assert!(directory.is_ok());
        let Ok(mut directory) = directory else {
            return;
        };

        assert_eq!(directory.id(), DirectoryNodeId::ROOT);
        assert_eq!(
            directory.cursor_mut().next_entry(),
            DirectoryEntryIndex::from_u32(0)
        );
        directory
            .cursor_mut()
            .seek(DirectoryEntryIndex::from_u32(7));
        assert_eq!(
            directory.cursor_mut().next_entry(),
            DirectoryEntryIndex::from_u32(7)
        );
    }

    /// # Panics
    ///
    /// Panics when FsRtl directory-name storage is recreated or relocated between registrations.
    #[test]
    fn opened_directory_reuses_a_stable_notification_name_descriptor() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            OpenedLocation::Root,
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        let directory = OpenedDirectory::decode(file_object);
        assert!(directory.is_ok());
        let Ok(mut directory) = directory else {
            return;
        };

        let first = directory.notification_directory_name();
        assert!(first.is_ok());
        let Ok(first) = first else {
            return;
        };
        let second = directory.notification_directory_name();
        assert_eq!(second, Ok(first));
        let descriptor = unsafe {
            // SAFETY: The descriptor is owned by the live CCB and the test
            // has not executed its cleanup or close transition.
            first.as_ref()
        };
        assert_eq!(descriptor.Length, descriptor.MaximumLength);
        assert!(!descriptor.Buffer.is_null());
    }

    /// # Panics
    ///
    /// Panics when a namespace change does not preserve its synthetic parent/name boundary.
    #[test]
    fn directory_name_change_encodes_the_child_boundary_and_action() {
        let name = Ext4Name::new(b"child");
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let change = DirectoryNameChange::new(
            DirectoryNodeId::ROOT,
            &name,
            NodeId::Directory(DirectoryNodeId::ROOT),
            DirectoryNameChangeAction::Added,
        );
        assert!(change.is_ok());
        let Ok(change) = change else {
            return;
        };

        assert_eq!(
            change.completion_filter,
            wdk_sys::FILE_NOTIFY_CHANGE_DIR_NAME
        );
        assert_eq!(change.action.as_ulong(), wdk_sys::FILE_ACTION_ADDED);
        let prefix_units = DIRECTORY_NOTIFICATION_DIRECTORY_UNITS.checked_add(1);
        assert!(prefix_units.is_some());
        let Some(prefix_units) = prefix_units else {
            return;
        };
        let prefix_bytes = prefix_units.checked_mul(core::mem::size_of::<u16>());
        assert!(prefix_bytes.is_some());
        let Some(prefix_bytes) = prefix_bytes else {
            return;
        };
        assert_eq!(usize::from(change.target.name_offset_bytes), prefix_bytes);
        let target_name = change.target.unicode_string();
        assert_eq!(target_name.Buffer, change.target.units.as_ptr().cast_mut());
        assert_eq!(target_name.Length, change.target.byte_length);
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn typed_opened_decoders_reject_wrong_node_kind() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            OpenedLocation::Root,
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };

        assert_eq!(
            OpenedRegularFile::decode(file_object).err(),
            Some(DriverError::Core(ext4_core::Error::WrongInodeKind))
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn reparse_point_directory_handle_rejects_directory_operations() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::ReparsePoint,
            OpenedLocation::Root,
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };

        assert_eq!(
            OpenedDirectory::decode(file_object).err(),
            Some(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when cleanup retries repeat cleanup-owned side effects.
    #[test]
    fn handle_lifecycle_makes_completed_cleanup_idempotent() {
        let handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            OpenedLocation::Root,
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        assert_eq!(handle.begin_cleanup(), CleanupStart::First);
        handle.finish_cleanup();
        assert_eq!(handle.begin_cleanup(), CleanupStart::AlreadyComplete);
        assert_eq!(
            handle.close_release_plan(FileObjectCloseKind::Ordinary, true),
            CloseReleasePlan::CleanedHandle
        );
        assert_eq!(
            handle.close_release_plan(FileObjectCloseKind::CancelledOpen, true),
            CloseReleasePlan::CleanedHandle
        );
    }

    /// # Panics
    ///
    /// Panics when a filter-cancelled open cannot select its one atomic release path.
    #[test]
    fn active_cancelled_open_selects_combined_share_and_reference_release() {
        let handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            OpenedLocation::Root,
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        assert_eq!(
            handle.close_release_plan(FileObjectCloseKind::CancelledOpen, false),
            CloseReleasePlan::CancelledOpen
        );
    }

    /// # Panics
    ///
    /// Panics when ordinary close before cleanup is accidentally accepted.
    #[test]
    fn ordinary_close_before_cleanup_has_no_release_plan() {
        assert_eq!(
            select_close_release_plan(
                super::HandleLifecycleState::Active,
                false,
                FileObjectCloseKind::Ordinary,
            ),
            None
        );
        assert_eq!(
            select_close_release_plan(
                super::HandleLifecycleState::Cleaned,
                false,
                FileObjectCloseKind::Ordinary,
            ),
            None
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn opened_object_preserves_write_commitment() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            OpenedLocation::Root,
            WriteCommitment::FlushThrough,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        let opened = OpenedObject::decode(file_object);
        assert!(opened.is_ok());
        if let Ok(opened) = opened {
            assert_eq!(opened.write_commitment(), WriteCommitment::FlushThrough);
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn opened_object_preserves_data_transfer_mode() {
        let buffer_alignment =
            TransferBufferAlignment::from_requirement_mask(wdk_sys::FILE_QUAD_ALIGNMENT);
        assert!(buffer_alignment.is_ok());
        let Ok(buffer_alignment) = buffer_alignment else {
            return;
        };
        let transfer = NoIntermediateTransfer {
            sector_size: TransferSectorSize::WINDOWS_REPORTED,
            buffer_alignment,
        };
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            OpenedLocation::Root,
            WriteCommitment::CommitOnly,
            DataTransferMode::NoIntermediate(transfer),
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        let opened = OpenedObject::decode(file_object);
        assert!(opened.is_ok());
        if let Ok(opened) = opened {
            assert_eq!(
                opened.data_transfer_mode(),
                DataTransferMode::NoIntermediate(transfer)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when synchronous FILE_OBJECT position transitions are inconsistent.
    #[test]
    fn synchronous_opened_object_reads_sets_and_advances_position() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            OpenedLocation::Root,
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        file.Flags = wdk_sys::FO_SYNCHRONOUS_IO;
        file.CurrentByteOffset = wdk_sys::LARGE_INTEGER { QuadPart: 11 };
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        let opened = OpenedObject::decode(file_object);
        assert!(opened.is_ok());
        let Ok(mut opened) = opened else {
            return;
        };

        assert_eq!(
            opened.current_file_position(),
            Ok(FileOffset::from_bytes(11))
        );
        assert_eq!(
            opened.set_current_file_position(FileOffset::from_bytes(32)),
            Ok(())
        );
        assert_eq!(
            opened
                .update_current_file_position(DataIoKind::Handle, FileOffset::from_bytes(100), 0,),
            Ok(())
        );
        assert_eq!(
            opened.current_file_position(),
            Ok(FileOffset::from_bytes(100))
        );
        assert_eq!(
            opened.update_current_file_position(
                DataIoKind::Handle,
                FileOffset::from_bytes(100),
                23,
            ),
            Ok(())
        );
        assert_eq!(
            opened.current_file_position(),
            Ok(FileOffset::from_bytes(123))
        );
    }

    /// # Panics
    ///
    /// Panics when the regular-file CCB variant loses its create-time write authority.
    #[test]
    fn regular_file_handle_retains_write_authority() {
        for write_access in [
            RegularFileWriteAccess::Denied,
            RegularFileWriteAccess::AppendOnly,
            RegularFileWriteAccess::Positional,
        ] {
            let handle = OpenedHandle {
                state: super::OpenedHandleState::new(
                    OpenedNodeMode::Direct,
                    OpenedLocation::Root,
                    WriteCommitment::CommitOnly,
                    DataTransferMode::IntermediateAllowed,
                ),
                kind: super::OpenedHandleKind::File { write_access },
            };
            assert_eq!(handle.regular_file_write_access(), Some(write_access));
        }
    }

    /// # Panics
    ///
    /// Panics when asynchronous or paging I/O changes the current-position field.
    #[test]
    fn asynchronous_and_paging_io_do_not_advance_position() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            OpenedLocation::Root,
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        file.CurrentByteOffset = wdk_sys::LARGE_INTEGER { QuadPart: 7 };
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        let opened = OpenedObject::decode(file_object);
        assert!(opened.is_ok());
        let Ok(mut opened) = opened else {
            return;
        };

        assert_eq!(
            opened.current_file_position(),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            opened.set_current_file_position(FileOffset::from_bytes(9)),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            opened.update_current_file_position(
                DataIoKind::Handle,
                FileOffset::from_bytes(100),
                23,
            ),
            Ok(())
        );
        file.Flags = wdk_sys::FO_SYNCHRONOUS_IO;
        assert_eq!(
            opened.update_current_file_position(
                DataIoKind::Paging,
                FileOffset::from_bytes(100),
                23,
            ),
            Ok(())
        );
        let position = unsafe {
            // SAFETY: Tests consistently use the QuadPart LARGE_INTEGER arm.
            file.CurrentByteOffset.QuadPart
        };
        assert_eq!(position, 7);
    }

    /// # Panics
    ///
    /// Panics when invalid current positions or lock ranges enter the signed Windows domain.
    #[test]
    fn file_position_and_native_lock_range_reject_signed_overflow() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            OpenedLocation::Root,
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        file.Flags = wdk_sys::FO_SYNCHRONOUS_IO;
        file.CurrentByteOffset = wdk_sys::LARGE_INTEGER { QuadPart: -1 };
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        let opened = OpenedObject::decode(file_object);
        assert!(opened.is_ok());
        let Ok(mut opened) = opened else {
            return;
        };

        assert_eq!(
            opened.current_file_position(),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            opened.set_current_file_position(FileOffset::from_bytes(u64::MAX)),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            NativeFileByteRange::new(FileOffset::from_bytes(i64::MAX.unsigned_abs()), 1).err(),
            Some(DriverError::InvalidParameter)
        );
        assert!(NativeFileByteRange::new(FileOffset::from_bytes(4096), 512).is_ok());
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn uninitialized_file_object_rejects_existing_contexts() {
        let mut file = file_object_with_contexts(core::ptr::null_mut(), core::ptr::null_mut());
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };

        assert!(UninitializedFileObject::decode(file_object).is_ok());

        let mut file = file_object_with_contexts(
            NonNull::<FileControlBlock>::dangling().as_ptr().cast(),
            core::ptr::null_mut(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        assert_eq!(
            UninitializedFileObject::decode(file_object),
            Err(DriverError::InvalidParameter)
        );

        let mut file = file_object_with_contexts(
            core::ptr::null_mut(),
            NonNull::<super::OpenedHandle>::dangling().as_ptr().cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        assert_eq!(
            UninitializedFileObject::decode(file_object),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_control_block_reference_count_cannot_represent_zero() {
        let mut state = FileControlBlockOpenState::new();

        assert_eq!(state.file_object_references.get(), 1);
        let next = state.next_file_object_reference();
        assert_eq!(
            next,
            NonZeroU32::new(2).ok_or(DriverError::TooManyOpenReferences)
        );
        let Ok(next) = next else {
            return;
        };
        state.file_object_references = next;
        assert_eq!(state.file_object_references.get(), 2);
        assert_eq!(
            state.release_open_reference(),
            FileControlBlockRelease::StillOpen
        );
        assert_eq!(state.file_object_references.get(), 1);
        assert_eq!(
            state.release_open_reference(),
            FileControlBlockRelease::LastReference
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_control_block_reference_count_overflow_is_typed() {
        let mut state = FileControlBlockOpenState::new();
        state.file_object_references = NonZeroU32::MAX;

        assert_eq!(
            state.next_file_object_reference(),
            Err(DriverError::TooManyOpenReferences)
        );
        assert_eq!(state.file_object_references, NonZeroU32::MAX);
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_control_block_starts_with_empty_share_access() {
        let state = FileControlBlockOpenState::new();

        assert_eq!(state.share_access.OpenCount, 0);
        assert_eq!(state.share_access.Readers, 0);
        assert_eq!(state.share_access.Writers, 0);
        assert_eq!(state.share_access.Deleters, 0);
        assert_eq!(state.share_access.SharedRead, 0);
        assert_eq!(state.share_access.SharedWrite, 0);
        assert_eq!(state.share_access.SharedDelete, 0);
    }
}
