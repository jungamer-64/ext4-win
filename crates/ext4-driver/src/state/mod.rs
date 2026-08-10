//! Driver-local lifecycle and open-object state.

mod volume_runtime;

pub(crate) use volume_runtime::{
    EpochLease, EpochPublicationSlot, EpochPublicationSlots, PendingCheckpoint, VolumeRuntime,
};

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
    CompletedMount, DeviceLength, DirectoryNodeId, Ext4Name, FileNodeId, FileOffset,
    MutationResolvePass, NewDirectoryMetadata, NewFileMetadata, NodeId, WindowsName, XattrName,
    XattrValue,
};
use wdk_sys::{
    DO_DEVICE_INITIALIZING, DO_DIRECT_IO, FILE_OBJECT, LARGE_INTEGER, PDEVICE_OBJECT,
    PDRIVER_OBJECT, SHARE_ACCESS, STATUS_SUCCESS, UNICODE_STRING, VPB_MOUNTED,
};
#[cfg(not(test))]
use wdk_sys::{LIST_ENTRY, PNOTIFY_SYNC, STATUS_PENDING};

use crate::irp::{
    ActiveFileObject, ByteRangeLockKey, CompletionReactor, CreateDeletion, DataIoKind,
    DeleteAccess, DesiredAccess, DirectoryEntryIndex, DispatchTarget, ExistingOperationAccess,
    FileAttributesWriteAccess, RegularFileWriteAccess, RequestorProcess, ShareAccess,
};
use crate::kernel::cng::CngFscryptNonceGenerator;
use crate::kernel::fatal::KernelWideInconsistency;
use crate::kernel::ffi;
use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::storage::MountedStorageDevices;
use crate::memory::{self, DriverVec};

/// Non-null kernel device object pointer at the WDK boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelDevice {
    /// Non-null opaque WDK device pointer.
    device: NonNull<c_void>,
}

// SAFETY: WDM device objects are I/O Manager-owned, nonpaged objects that may be dispatched on any
// processor. This boundary exposes only stable identity and immutable device properties; teardown
// contracts require every reactor operation and lower completion to drain before deletion.
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

    /// Returns the raw WDK pointer for FFI calls that require FILE_OBJECT.
    pub(crate) const fn as_ptr(self) -> *mut FILE_OBJECT {
        self.file_object.as_ptr()
    }

    /// Publishes one already range-checked current-byte offset.
    fn write_current_byte_offset(self, position: i64) {
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
    fn write_current_byte_offset(self, position: i64) {
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

/// Driver-owned device kind decoded before selecting a concrete extension teardown path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DriverDeviceKind {
    /// Registered filesystem control device.
    Control,
    /// Mounted ext4 volume device.
    MountedVolume,
}

impl DriverDeviceKind {
    /// Decodes the common extension discriminant.
    /// # Errors
    ///
    /// Returns an invariant error when driver-owned extension storage has an unknown kind.
    fn decode(kind: DeviceExtensionKind) -> DriverResult<Self> {
        if kind == DeviceExtensionKind::CONTROL {
            Ok(Self::Control)
        } else if kind == DeviceExtensionKind::MOUNTED_VOLUME {
            Ok(Self::MountedVolume)
        } else {
            Err(DriverError::InternalInvariantViolation)
        }
    }
}

/// Common prefix shared by all driver-owned device extensions.
#[repr(C)]
struct DeviceExtensionHeader {
    /// Device-owned completion-driven operation reactor.
    reactor: CompletionReactor,
    /// Concrete extension kind following the reactor prefix.
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
    /// Returns an error when the device has no extension or its reactor cannot be initialized.
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
            CompletionReactor::initialize_at(
                core::ptr::addr_of_mut!(extension.header.reactor),
                device,
            )
        }
    }

    /// Releases resources stored in the extension.
    /// # Safety
    ///
    /// No dispatch callback or device actor may still access the control device.
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
            CompletionReactor::release_at(core::ptr::addr_of_mut!(extension.header.reactor));
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
    /// Actor-owned volume lifecycle and direct-open share accounting.
    volume_control: VolumeControlPlane,
    /// Mounted profile, committed epochs, and mutation coordination.
    runtime: VolumeRuntime,
}

/// Actor-owned mounted-volume lifecycle and direct-open ledger.
#[derive(Debug)]
struct VolumeControlPlane {
    /// Current mount/lock state.
    state: MountedVolumeState,
    /// Share claims for direct user volume opens.
    handles: VolumeHandleLedger,
    /// Direct-volume FILE_OBJECT allocations retained until Close.
    volume_file_objects: u32,
}

impl VolumeControlPlane {
    /// Creates the control plane for a newly mounted volume.
    const fn mounted() -> Self {
        Self {
            state: MountedVolumeState::Mounted,
            handles: VolumeHandleLedger::new(),
            volume_file_objects: 0,
        }
    }
}

/// Mounted-volume state serialized by the device actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MountedVolumeState {
    /// Namespace and direct-volume opens are admitted.
    Mounted,
    /// Only the FILE_OBJECT that locked the volume may issue ordinary operations.
    Locked {
        /// Direct-volume FILE_OBJECT that owns the lock.
        owner: KernelFileObject,
    },
    /// Filesystem operations are rejected after a forced logical dismount.
    Dismounted {
        /// Prior lock owner allowed to release the lock after dismount.
        lock_owner: Option<KernelFileObject>,
    },
    /// Last FILE_OBJECT closed and the preallocated retirement work item owns teardown.
    Retiring,
}

impl MountedVolumeState {
    /// Selects the locked state reached by one direct-volume FILE_OBJECT.
    /// # Errors
    ///
    /// Returns access denied when already locked or volume dismounted after terminal dismount.
    fn lock(self, owner: KernelFileObject) -> DriverResult<Self> {
        match self {
            Self::Mounted => Ok(Self::Locked { owner }),
            Self::Locked { .. } => Err(DriverError::AccessDenied),
            Self::Dismounted { .. } | Self::Retiring => Err(DriverError::VolumeDismounted),
        }
    }

    /// Selects the state reached when one FILE_OBJECT releases its volume lock.
    /// # Errors
    ///
    /// Returns not locked when `owner` does not own the current lock.
    fn unlock(self, owner: KernelFileObject) -> DriverResult<Self> {
        match self {
            Self::Locked {
                owner: current_owner,
            } if current_owner == owner => Ok(Self::Mounted),
            Self::Dismounted {
                lock_owner: Some(current_owner),
            } if current_owner == owner => Ok(Self::Dismounted { lock_owner: None }),
            Self::Mounted | Self::Locked { .. } | Self::Dismounted { .. } | Self::Retiring => {
                Err(DriverError::NotLocked)
            }
        }
    }

    /// Selects the terminal state reached by a forced dismount request.
    /// # Errors
    ///
    /// Returns access denied for another lock owner or volume dismounted after terminal dismount.
    fn dismount(self, owner: KernelFileObject) -> DriverResult<Self> {
        match self {
            Self::Mounted => Ok(Self::Dismounted { lock_owner: None }),
            Self::Locked {
                owner: current_owner,
            } if current_owner == owner => Ok(Self::Dismounted {
                lock_owner: Some(owner),
            }),
            Self::Locked { .. } => Err(DriverError::AccessDenied),
            Self::Dismounted { .. } | Self::Retiring => Err(DriverError::VolumeDismounted),
        }
    }

    /// Applies implicit lock release when the owning FILE_OBJECT is cleaned up.
    fn cleanup(self, owner: KernelFileObject) -> (Self, VolumeHandleCleanup) {
        match self {
            Self::Locked {
                owner: current_owner,
            } if current_owner == owner => (Self::Mounted, VolumeHandleCleanup::Unlocked),
            Self::Dismounted {
                lock_owner: Some(current_owner),
            } if current_owner == owner => (
                Self::Dismounted { lock_owner: None },
                VolumeHandleCleanup::Unlocked,
            ),
            Self::Mounted | Self::Locked { .. } | Self::Dismounted { .. } => {
                (self, VolumeHandleCleanup::Released)
            }
            Self::Retiring => KernelWideInconsistency::mounted_volume_state_corruption().bugcheck(),
        }
    }

    /// Selects the one physical-retirement transition after all FILE_OBJECTs close.
    fn retire_if_unreferenced(
        self,
        namespace_empty: bool,
        volume_file_objects: u32,
    ) -> (Self, VolumeRetirement) {
        match self {
            Self::Dismounted { lock_owner: None }
                if namespace_empty && volume_file_objects == 0 =>
            {
                (Self::Retiring, VolumeRetirement::Start)
            }
            Self::Retiring => KernelWideInconsistency::mounted_volume_state_corruption().bugcheck(),
            Self::Mounted | Self::Locked { .. } | Self::Dismounted { .. } => {
                (self, VolumeRetirement::Retained)
            }
        }
    }

    /// Reports whether this volume remains logically mounted.
    /// # Errors
    ///
    /// Returns volume dismounted after the terminal transition.
    fn ensure_mounted(self) -> DriverResult<()> {
        match self {
            Self::Mounted | Self::Locked { .. } => Ok(()),
            Self::Dismounted { .. } | Self::Retiring => Err(DriverError::VolumeDismounted),
        }
    }

    /// Applies create/open admission policy.
    /// # Errors
    ///
    /// Returns access denied while locked or volume dismounted after terminal dismount.
    fn authorize_create(self) -> DriverResult<()> {
        match self {
            Self::Mounted => Ok(()),
            Self::Locked { .. } => Err(DriverError::AccessDenied),
            Self::Dismounted { .. } | Self::Retiring => Err(DriverError::VolumeDismounted),
        }
    }

    /// Applies ordinary handle-operation policy.
    /// # Errors
    ///
    /// Returns access denied for a competing lock owner or volume dismounted after dismount.
    fn authorize_handle(self, file_object: KernelFileObject) -> DriverResult<()> {
        match self {
            Self::Mounted => Ok(()),
            Self::Locked { owner } if owner == file_object => Ok(()),
            Self::Locked { .. } => Err(DriverError::AccessDenied),
            Self::Dismounted { .. } | Self::Retiring => Err(DriverError::VolumeDismounted),
        }
    }
}

/// Direct-volume FILE_OBJECT share claims owned by the mounted-device actor.
struct VolumeHandleLedger {
    /// I/O Manager share-access accounting for the mounted volume identity.
    share_access: SHARE_ACCESS,
}

impl VolumeHandleLedger {
    /// Creates empty direct-volume share accounting.
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
        }
    }

    /// Records one direct-volume FILE_OBJECT share claim.
    /// # Errors
    ///
    /// Returns an error when an existing direct-volume handle conflicts with the requested access.
    fn open(
        &mut self,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        share_access: ShareAccess,
    ) -> DriverResult<()> {
        let status = unsafe {
            // SAFETY: The mounted-device actor exclusively owns this SHARE_ACCESS record and this
            // successful check records the returned FILE_OBJECT's exact claim.
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

    /// Removes one direct-volume FILE_OBJECT share claim at cleanup or canceled-open close.
    fn cleanup(&mut self, file_object: KernelFileObject) {
        unsafe {
            // SAFETY: A successful volume open recorded this FILE_OBJECT exactly once, and the
            // handle lifecycle selects one terminal share-removal transition.
            ffi::IoRemoveShareAccess(
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.share_access),
            );
        }
    }

    /// Returns the number of direct-volume handles whose share claims remain active.
    const fn active_handle_count(&self) -> u32 {
        self.share_access.OpenCount
    }
}

impl fmt::Debug for VolumeHandleLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VolumeHandleLedger(..)")
    }
}

/// Stable identity of one mounted VCB without granting a reference to its control-plane fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MountedVolumeRef {
    /// Heap-stable mounted VCB.
    volume: NonNull<VolumeControlBlock>,
}

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

/// Reactor-thread access to one stable mounted VCB.
///
/// Multiple suspended operations may retain this identity, but only the reactor thread may call
/// its projection methods and no projection may cross an operation transition.
pub(crate) struct VolumeAccess {
    /// Mounted VCB that owns the projected runtime and control-plane ledger.
    owner: MountedVolumeRef,
    /// Mounted runtime projected without borrowing the whole VCB.
    runtime: NonNull<VolumeRuntime>,
    /// Volume lifecycle projected under the same unique actor authority.
    control: NonNull<VolumeControlPlane>,
    /// FCB ledger used only to count active namespace handles during volume lock.
    file_control_blocks: NonNull<FileControlBlockLedger>,
}

/// VPB-visible effect produced when a direct-volume handle is cleaned up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeHandleCleanup {
    /// Only the direct-volume share claim was released.
    Released,
    /// The cleaned-up FILE_OBJECT also owned the volume lock.
    Unlocked,
}

/// Physical-retirement decision produced by one actor-owned Close transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeRetirement {
    /// At least one FILE_OBJECT remains or the volume has not logically dismounted.
    Retained,
    /// The last FILE_OBJECT closed after dismount and teardown must be queued exactly once.
    Start,
}

/// Direct-volume Close effects published after typed context release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VolumeCloseOutcome {
    /// Whether a cancelled open also released the visible VPB lock.
    cleanup: VolumeHandleCleanup,
    /// Whether this Close owns the one physical-retirement transition.
    retirement: VolumeRetirement,
}

/// Lifecycle transition retained while a durability barrier drains earlier work.
#[derive(Debug)]
pub(crate) struct PreparedVolumeStateTransition {
    /// State that must still be visible when the barrier releases.
    expected: MountedVolumeState,
    /// State published after durability succeeds.
    next: MountedVolumeState,
}

impl VolumeCloseOutcome {
    /// Returns the VPB-visible cleanup effect.
    pub(crate) const fn cleanup(self) -> VolumeHandleCleanup {
        self.cleanup
    }

    /// Returns the physical-retirement decision.
    pub(crate) const fn retirement(self) -> VolumeRetirement {
        self.retirement
    }
}

impl VolumeAccess {
    /// Records one direct-volume FILE_OBJECT share claim.
    /// # Errors
    ///
    /// Returns an error when an existing volume handle denies the requested sharing.
    pub(crate) fn open_volume_handle(
        &mut self,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        share_access: ShareAccess,
    ) -> DriverResult<()> {
        let control = unsafe {
            // SAFETY: This non-cloneable actor lease uniquely owns volume-handle transitions.
            self.control.as_mut()
        };
        control.state.authorize_create()?;
        let next_count = control
            .volume_file_objects
            .checked_add(1)
            .ok_or(DriverError::InsufficientResources)?;
        control
            .handles
            .open(file_object, desired_access, share_access)?;
        control.volume_file_objects = next_count;
        Ok(())
    }

    /// Removes one direct-volume FILE_OBJECT share claim.
    pub(crate) fn cleanup_volume_handle(
        &mut self,
        file_object: KernelFileObject,
    ) -> VolumeHandleCleanup {
        let control = unsafe {
            // SAFETY: This non-cloneable actor lease uniquely owns volume-handle transitions.
            self.control.as_mut()
        };
        control.handles.cleanup(file_object);
        let (state, effect) = control.state.cleanup(file_object);
        control.state = state;
        effect
    }

    /// Releases one direct-volume FILE_OBJECT and selects terminal physical retirement.
    pub(crate) fn close_volume_file_object(
        &mut self,
        file_object: KernelFileObject,
        release_plan: CloseReleasePlan,
    ) -> VolumeCloseOutcome {
        let cleanup = {
            let control = unsafe {
                // SAFETY: This non-cloneable actor lease uniquely owns volume-handle transitions.
                self.control.as_mut()
            };
            let cleanup = match release_plan {
                CloseReleasePlan::CleanedHandle => VolumeHandleCleanup::Released,
                CloseReleasePlan::CancelledOpen => {
                    control.handles.cleanup(file_object);
                    let (state, cleanup) = control.state.cleanup(file_object);
                    control.state = state;
                    cleanup
                }
            };
            control.volume_file_objects = control
                .volume_file_objects
                .checked_sub(1)
                .unwrap_or_else(|| {
                    KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
                });
            cleanup
        };
        VolumeCloseOutcome {
            cleanup,
            retirement: self.begin_retirement(),
        }
    }

    /// Rechecks physical retirement after one namespace FILE_OBJECT has closed.
    pub(crate) fn close_node_file_object(&mut self) -> VolumeRetirement {
        self.begin_retirement()
    }

    /// Atomically moves the actor-owned volume into its one physical-retirement transition.
    fn begin_retirement(&mut self) -> VolumeRetirement {
        let namespace_empty = unsafe {
            // SAFETY: The VCB retains the synchronized ledger throughout this actor lease.
            self.file_control_blocks.as_ref()
        }
        .is_empty();
        let control = unsafe {
            // SAFETY: This non-cloneable actor lease uniquely owns lifecycle transitions.
            self.control.as_mut()
        };
        let (state, retirement) = control
            .state
            .retire_if_unreferenced(namespace_empty, control.volume_file_objects);
        control.state = state;
        retirement
    }

    /// Validates a volume lock and prepares its post-durability publication.
    /// # Errors
    ///
    /// Returns access denied while any other handle is active, volume dismounted after terminal
    /// dismount.
    pub(crate) fn prepare_lock_volume(
        &self,
        owner: KernelFileObject,
    ) -> DriverResult<PreparedVolumeStateTransition> {
        let control = unsafe {
            // SAFETY: The stable VCB retains its control plane throughout reactor processing.
            self.control.as_ref()
        };
        let next_state = control.state.lock(owner)?;
        let namespace_handles = unsafe {
            // SAFETY: The heap-stable VCB retains this ledger throughout the actor lease.
            self.file_control_blocks.as_ref()
        }
        .active_handle_count();
        if namespace_handles != 0 || control.handles.active_handle_count() != 1 {
            return Err(DriverError::AccessDenied);
        }
        Ok(PreparedVolumeStateTransition {
            expected: control.state,
            next: next_state,
        })
    }

    /// Releases a volume lock owned by the supplied direct-volume FILE_OBJECT.
    /// # Errors
    ///
    /// Returns not-locked when this FILE_OBJECT is not the current lock owner.
    pub(crate) fn unlock_volume(&mut self, owner: KernelFileObject) -> DriverResult<()> {
        let control = unsafe {
            // SAFETY: This non-cloneable actor lease uniquely owns volume lifecycle transitions.
            self.control.as_mut()
        };
        control.state = control.state.unlock(owner)?;
        Ok(())
    }

    /// Prepares terminal logical dismount publication behind a clean-journal barrier.
    /// # Errors
    ///
    /// Returns access denied when another FILE_OBJECT owns the volume lock, volume dismounted for
    /// a repeated request.
    pub(crate) fn prepare_dismount_volume(
        &self,
        owner: KernelFileObject,
    ) -> DriverResult<PreparedVolumeStateTransition> {
        let current = unsafe {
            // SAFETY: This non-cloneable actor lease uniquely observes volume lifecycle state.
            self.control.as_ref()
        }
        .state;
        Ok(PreparedVolumeStateTransition {
            expected: current,
            next: current.dismount(owner)?,
        })
    }

    /// Publishes one previously validated lifecycle transition after its barrier succeeds.
    pub(crate) fn publish_volume_state_transition(
        &mut self,
        transition: PreparedVolumeStateTransition,
    ) {
        let control = unsafe {
            // SAFETY: Only the reactor thread publishes volume lifecycle transitions.
            self.control.as_mut()
        };
        if control.state != transition.expected {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
        }
        control.state = transition.next;
    }

    /// Reports whether the volume remains logically mounted.
    /// # Errors
    ///
    /// Returns volume dismounted after a successful forced dismount.
    pub(crate) fn ensure_mounted(&self) -> DriverResult<()> {
        unsafe {
            // SAFETY: The actor lease keeps the heap-stable volume control plane live.
            self.control.as_ref()
        }
        .state
        .ensure_mounted()
    }

    /// Authorizes creation of a new FILE_OBJECT against the current volume state.
    /// # Errors
    ///
    /// Returns access denied while locked or volume dismounted after terminal dismount.
    pub(crate) fn authorize_create(&self) -> DriverResult<()> {
        unsafe {
            // SAFETY: The actor lease keeps the heap-stable volume control plane live.
            self.control.as_ref()
        }
        .state
        .authorize_create()
    }

    /// Authorizes one ordinary handle operation against the current volume state.
    /// # Errors
    ///
    /// Returns access denied when another handle owns the lock, or volume dismounted after
    /// terminal logical dismount.
    pub(crate) fn authorize_handle(&self, file_object: KernelFileObject) -> DriverResult<()> {
        unsafe {
            // SAFETY: The actor lease keeps the heap-stable volume control plane live.
            self.control.as_ref()
        }
        .state
        .authorize_handle(file_object)
    }

    /// Rejects namespace traversal through an inode that is delete-pending.
    /// # Errors
    ///
    /// Returns delete-pending while an open FCB owns a deferred deletion for `node`.
    pub(crate) fn ensure_node_openable(&self, node: NodeId) -> DriverResult<()> {
        let ledger = unsafe {
            // SAFETY: The mounted VCB and its independently synchronized ledger remain live for
            // this actor lease.
            self.file_control_blocks.as_ref()
        };
        if ledger.node_delete_pending(node) {
            Err(DriverError::DeletePending)
        } else {
            Ok(())
        }
    }

    /// Requires an existing replacement target to have no active handles.
    /// # Errors
    ///
    /// Returns delete-pending for a terminal target or sharing-violation while any active handle
    /// could still reference an inode that replacement would unlink.
    pub(crate) fn ensure_node_replaceable(&self, node: NodeId) -> DriverResult<()> {
        let ledger = unsafe {
            // SAFETY: The mounted VCB and its independently synchronized ledger remain live for
            // this actor lease.
            self.file_control_blocks.as_ref()
        };
        ledger.ensure_node_replaceable(node)
    }

    /// Publishes successful removal of the exact FCB-owned delete target.
    pub(crate) fn complete_file_delete(
        &mut self,
        fcb: NonNull<FileControlBlock>,
        target: NonNull<FileDeleteTarget>,
    ) {
        unsafe {
            // SAFETY: The mounted VCB and its synchronized ledger remain live, and this actor lease
            // serializes deletion completion with every namespace operation.
            self.file_control_blocks.as_ref()
        }
        .complete_delete(fcb, target);
    }

    /// Publishes a validated delete-pending target into one live FCB.
    pub(crate) fn set_file_delete_pending(
        &mut self,
        fcb: NonNull<FileControlBlock>,
        pending: PendingFileDeletion,
    ) {
        unsafe {
            // SAFETY: The mounted VCB and its synchronized ledger remain live, and this actor lease
            // serializes the disposition mutation with every namespace operation.
            self.file_control_blocks.as_ref()
        }
        .set_delete_pending(fcb, pending);
    }

    /// Reports one committed namespace mutation through the mounted VCB notifier.
    pub(crate) fn report_directory_change(&self, change: DirectoryChange) {
        let volume = unsafe {
            // SAFETY: The actor lease retains the heap-stable mounted VCB for this request.
            self.owner.as_non_null().as_ref()
        };
        volume.report_directory_change(change);
    }

    /// Borrows the mounted runtime for one non-suspending reactor transition.
    pub(crate) fn runtime(&self) -> &VolumeRuntime {
        unsafe {
            // SAFETY: The VCB remains stable and this reference cannot outlive the access borrow.
            self.runtime.as_ref()
        }
    }

    /// Borrows the mounted runtime mutably for one non-suspending reactor transition.
    pub(crate) fn runtime_mut(&mut self) -> &mut VolumeRuntime {
        unsafe {
            // SAFETY: Only the sole reactor thread constructs active projection scopes, and the
            // returned reference is tied to this unique access borrow.
            self.runtime.as_mut()
        }
    }

    /// Stages a missing child in the current ephemeral mutation resolve pass.
    /// # Errors
    ///
    /// Returns an error when the parent cannot be loaded or child creation cannot be staged.
    pub(crate) fn begin_child_creation(
        &self,
        transaction: &mut MutationResolvePass<'_, '_, '_, CngFscryptNonceGenerator>,
        parent: DirectoryNodeId,
        name: &Ext4Name,
        target: ChildCreationTarget,
    ) -> DriverResult<PendingChildCreation> {
        let owner = self.owner;
        let file_control_blocks = unsafe {
            // SAFETY: `owner` stays live for the lease lifetime, so projecting the disjoint ledger
            // field produces a stable raw address.
            core::ptr::addr_of!((*owner.as_non_null().as_ptr()).file_control_blocks)
        };
        let file_control_blocks = unsafe {
            // SAFETY: The projected ledger is independently synchronized and VCB-owned.
            &*file_control_blocks
        };
        let parent = transaction.directory(parent)?;
        let node = match target {
            ChildCreationTarget::File(metadata) => {
                NodeId::File(transaction.create_file(parent, name, metadata)?.id())
            }
            ChildCreationTarget::Directory(metadata) => {
                NodeId::Directory(transaction.create_directory(parent, name, metadata)?.id())
            }
        };
        Ok(PendingChildCreation {
            file_control_blocks: NonNull::from(file_control_blocks),
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

    /// Releases a share claim and selects final-active-handle deletion while retaining the FCB.
    fn release_share_access(
        &self,
        fcb: NonNull<FileControlBlock>,
        file_object: KernelFileObject,
    ) -> FileCleanupDisposition {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes lookup and open-state mutation.
            &*self.table.get()
        };
        let mut state = ledger_file_control_block_open_state(table, fcb);
        let state = unsafe {
            // SAFETY: The ledger resource remains exclusively held and the helper validated this
            // state pointer against the owning table.
            state.as_mut()
        };
        state.remove_share_access(file_object);
        state.cleanup_disposition()
    }

    /// Publishes a stable delete-pending target for one live FCB.
    fn set_delete_pending(&self, fcb: NonNull<FileControlBlock>, pending: PendingFileDeletion) {
        let previous = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource serializes lookup and open-state mutation.
                &*self.table.get()
            };
            let mut state = ledger_file_control_block_open_state(table, fcb);
            unsafe {
                // SAFETY: The FCB was validated against the table while the resource is held.
                state.as_mut()
            }
            .set_delete_pending(pending)
        };
        drop(previous);
    }

    /// Cancels delete-pending for one live FCB.
    fn clear_delete_pending(&self, fcb: NonNull<FileControlBlock>) {
        let previous = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource serializes lookup and open-state mutation.
                &*self.table.get()
            };
            let mut state = ledger_file_control_block_open_state(table, fcb);
            unsafe {
                // SAFETY: The FCB was validated against the table while the resource is held.
                state.as_mut()
            }
            .clear_delete_pending()
        };
        drop(previous);
    }

    /// Returns whether one live FCB is delete-pending.
    fn delete_pending(&self, fcb: NonNull<FileControlBlock>) -> bool {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table and open-state observation.
            &*self.table.get()
        };
        let state = ledger_file_control_block_open_state(table, fcb);
        unsafe {
            // SAFETY: The FCB was validated against the table while the resource is held.
            state.as_ref()
        }
        .delete_pending()
    }

    /// Publishes committed removal of the exact pending target.
    fn complete_delete(&self, fcb: NonNull<FileControlBlock>, target: NonNull<FileDeleteTarget>) {
        let completed = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource serializes lookup and open-state mutation.
                &*self.table.get()
            };
            let mut state = ledger_file_control_block_open_state(table, fcb);
            unsafe {
                // SAFETY: The FCB was validated against the table while the resource is held.
                state.as_mut()
            }
            .complete_delete(target)
        };
        drop(completed);
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

    /// Counts namespace handles whose cleanup share claims remain active.
    fn active_handle_count(&self) -> u32 {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table and open-state observation.
            &*self.table.get()
        };
        table.iter().fold(0_u32, |total, fcb| {
            let open_count = unsafe {
                // SAFETY: The ledger resource is held and this FCB remains table-owned.
                (*fcb.open_state.get()).share_access.OpenCount
            };
            total.checked_add(open_count).unwrap_or_else(|| {
                KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
            })
        })
    }

    /// Returns whether every namespace FILE_OBJECT has released its FCB reference.
    fn is_empty(&self) -> bool {
        let _guard = self.lock.acquire();
        unsafe {
            // SAFETY: The executive resource serializes table observation.
            (*self.table.get()).is_empty()
        }
    }

    /// Returns whether a currently open inode identity rejects new namespace traversal.
    fn node_delete_pending(&self, node: NodeId) -> bool {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table and open-state observation.
            &*self.table.get()
        };
        let Some(fcb) = find_file_control_block_in_table(table, node) else {
            return false;
        };
        let fcb = unsafe {
            // SAFETY: The table owns this FCB and the resource remains held for the observation.
            fcb.as_ref()
        };
        let state = unsafe {
            // SAFETY: The ledger resource serializes this FCB open-state observation.
            &*fcb.open_state.get()
        };
        state.delete_pending()
    }

    /// Requires a currently open inode to permit ordinary namespace replacement.
    /// # Errors
    ///
    /// Returns delete-pending or sharing-violation when the open state rejects replacement.
    fn ensure_node_replaceable(&self, node: NodeId) -> DriverResult<()> {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table and open-state observation.
            &*self.table.get()
        };
        let Some(fcb) = find_file_control_block_in_table(table, node) else {
            return Ok(());
        };
        let fcb = unsafe {
            // SAFETY: The table owns this FCB and the resource remains held for the observation.
            fcb.as_ref()
        };
        let state = unsafe {
            // SAFETY: The ledger resource serializes this FCB open-state observation.
            &*fcb.open_state.get()
        };
        state.ensure_namespace_replaceable()
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
    /// Builds a mounted VCB from a completed mount operation and validated lower devices.
    /// # Errors
    ///
    /// Returns an error when driver-local mounted state cannot be allocated.
    pub(crate) fn from_completed_mount(
        mount: CompletedMount,
        storage: MountedStorageDevices,
    ) -> DriverResult<Self> {
        Ok(Self {
            directory_change_notifier: DirectoryChangeNotifier::uninitialized(),
            file_control_blocks: FileControlBlockLedger::try_new()?,
            volume_control: VolumeControlPlane::mounted(),
            runtime: VolumeRuntime::new(mount, storage),
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
    pub(crate) fn report_directory_change(&self, change: DirectoryChange) {
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

    /// Projects stable mounted fields for one reactor-thread transition.
    /// # Safety
    ///
    /// The caller must run on the owning reactor thread and must not retain a projected reference
    /// across a transition, lower submission, timer arm, or completion callback.
    pub(crate) unsafe fn operation_access(volume: NonNull<Self>) -> VolumeAccess {
        let runtime = unsafe {
            // SAFETY: The VCB is heap-stable, so its runtime field has a stable address.
            core::ptr::addr_of_mut!((*volume.as_ptr()).runtime)
        };
        let runtime = unsafe {
            // SAFETY: A field address projected from a non-null live VCB cannot be null.
            NonNull::new_unchecked(runtime)
        };
        let control = unsafe {
            // SAFETY: The VCB is heap-stable, so its volume control plane has a stable address.
            core::ptr::addr_of_mut!((*volume.as_ptr()).volume_control)
        };
        let control = unsafe {
            // SAFETY: A field address projected from a non-null live VCB cannot be null.
            NonNull::new_unchecked(control)
        };
        let file_control_blocks = unsafe {
            // SAFETY: The VCB is heap-stable, so its FCB ledger has a stable address.
            core::ptr::addr_of_mut!((*volume.as_ptr()).file_control_blocks)
        };
        let file_control_blocks = unsafe {
            // SAFETY: A field address projected from a non-null live VCB cannot be null.
            NonNull::new_unchecked(file_control_blocks)
        };
        VolumeAccess {
            owner: MountedVolumeRef::new(volume),
            runtime,
            control,
            file_control_blocks,
        }
    }

    /// Returns whether logical dismount already consumed shutdown registration.
    fn is_logically_dismounted(&self) -> bool {
        matches!(
            self.volume_control.state,
            MountedVolumeState::Dismounted { .. } | MountedVolumeState::Retiring
        )
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
pub(crate) enum DirectoryChangeAction {
    /// A child was created.
    Added,
    /// A child was removed.
    Removed,
    /// An existing name now resolves to different file metadata.
    Modified,
    /// A child is being reported under its former name.
    RenamedOldName,
    /// A child is being reported under its replacement name.
    RenamedNewName,
}

impl DirectoryChangeAction {
    /// Returns the WDK FILE_ACTION payload for this namespace mutation.
    const fn as_ulong(self) -> wdk_sys::ULONG {
        match self {
            Self::Added => wdk_sys::FILE_ACTION_ADDED,
            Self::Removed => wdk_sys::FILE_ACTION_REMOVED,
            Self::Modified => wdk_sys::FILE_ACTION_MODIFIED,
            Self::RenamedOldName => wdk_sys::FILE_ACTION_RENAMED_OLD_NAME,
            Self::RenamedNewName => wdk_sys::FILE_ACTION_RENAMED_NEW_NAME,
        }
    }
}

/// Committed namespace mutation prepared before its ext4 transaction is published.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DirectoryChange {
    /// Full synthetic target name used only by the FsRtl notifier package.
    target: DirectoryNotificationTarget,
    /// FILE_NOTIFY_CHANGE_FILE_NAME or FILE_NOTIFY_CHANGE_DIR_NAME.
    completion_filter: wdk_sys::ULONG,
    /// FILE_ACTION_* payload written to matching watcher buffers.
    action: DirectoryChangeAction,
}

impl DirectoryChange {
    /// Builds a namespace change event for one parent/name/node tuple.
    /// # Errors
    ///
    /// Returns an error when the ext4 child name cannot be represented in the Windows notification
    /// namespace.
    pub(crate) fn new(
        parent: DirectoryNodeId,
        name: &Ext4Name,
        node: NodeId,
        action: DirectoryChangeAction,
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

    /// Builds the metadata-change event required when one exact file link is replaced in place.
    /// # Errors
    ///
    /// Returns an error when the ext4 child name cannot be represented in the Windows notification
    /// namespace.
    pub(crate) fn hard_link_replaced(
        parent: DirectoryNodeId,
        name: &Ext4Name,
    ) -> DriverResult<Self> {
        const FILTER: wdk_sys::ULONG = wdk_sys::FILE_NOTIFY_CHANGE_ATTRIBUTES
            | wdk_sys::FILE_NOTIFY_CHANGE_SIZE
            | wdk_sys::FILE_NOTIFY_CHANGE_LAST_WRITE
            | wdk_sys::FILE_NOTIFY_CHANGE_LAST_ACCESS
            | wdk_sys::FILE_NOTIFY_CHANGE_CREATION
            | wdk_sys::FILE_NOTIFY_CHANGE_SECURITY
            | wdk_sys::FILE_NOTIFY_CHANGE_EA;
        Ok(Self {
            target: DirectoryNotificationTarget::new(parent, name)?,
            completion_filter: FILTER,
            action: DirectoryChangeAction::Modified,
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

    /// Verifies that this mounted-volume notifier can accept one IRP transfer.
    /// # Errors
    ///
    /// Returns an error when the mounted VCB notifier was not initialized.
    pub(crate) fn ensure_registration_ready(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        if !self.initialized {
            return Err(DriverError::InternalInvariantViolation);
        }
        Ok(())
    }

    /// Gives one queued directory-change IRP to FsRtl for pending completion.
    pub(crate) fn register(
        &self,
        target: DispatchTarget,
        registration: DirectoryNotificationRegistration,
    ) -> wdk_sys::NTSTATUS {
        #[cfg(not(test))]
        {
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
                    target.into_raw_irp(),
                    None,
                    core::ptr::null_mut(),
                );
            }
            STATUS_PENDING
        }
        #[cfg(test)]
        {
            let DirectoryNotificationRegistration {
                full_directory_name,
                context,
                completion_filter,
            } = registration;
            core::hint::black_box((target, full_directory_name, context, completion_filter));
            STATUS_SUCCESS
        }
    }

    /// Reports one committed namespace name change to matching watcher IRPs.
    fn report(&self, change: DirectoryChange) {
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

/// Driver publication values prepared for a child staged in an ephemeral mutation pass.
#[derive(Debug)]
pub(crate) struct PendingChildCreation {
    /// Stable synchronized FCB ledger owned by the mounted VCB.
    file_control_blocks: NonNull<FileControlBlockLedger>,
    /// VCB that owns any FCB opened for the staged node.
    volume: MountedVolumeRef,
    /// Node identity allocated by the staged transaction.
    node: NodeId,
}

impl PendingChildCreation {
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
        unsafe {
            // SAFETY: The mounted VCB outlives all admitted operations and FILE_OBJECT contexts.
            self.file_control_blocks.as_ref()
        }
        .open_new(
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
    pub(crate) fn set_xattr(
        &mut self,
        transaction: &mut MutationResolvePass<'_, '_, '_, CngFscryptNonceGenerator>,
        name: XattrName,
        value: XattrValue,
    ) -> DriverResult<()> {
        let node = transaction.node(self.node)?;
        transaction.set_xattr(node, name, value)?;
        Ok(())
    }

    /// Removes one xattr from the staged child in this create transaction.
    /// # Errors
    ///
    /// Returns an error when the staged node rejects xattr mutation.
    pub(crate) fn remove_xattr(
        &mut self,
        transaction: &mut MutationResolvePass<'_, '_, '_, CngFscryptNonceGenerator>,
        name: &XattrName,
    ) -> DriverResult<()> {
        let node = transaction.node(self.node)?;
        transaction.remove_xattr(node, name)?;
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
    /// Mount-preallocated work item that performs actor-safe physical retirement.
    retirement_work_item: wdk_sys::PIO_WORKITEM,
}

/// Owner that consumes mounted-device extension resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MountedDeviceTeardown {
    /// DriverUnload owns an unqueued retirement work item.
    DriverUnload,
    /// The queued retirement callback owns and later frees its executing work item.
    #[cfg(not(test))]
    RetirementWorkItem,
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
        extension.vcb = core::ptr::null_mut();
        extension.retirement_work_item = core::ptr::null_mut();
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
            CompletionReactor::initialize_at(
                core::ptr::addr_of_mut!(extension.header.reactor),
                device,
            )?;
        }
        if let Err(error) = register_shutdown_notification(device) {
            unsafe {
                // SAFETY: Shutdown registration failed before this device was
                // published, so no actor continuation can still own the executor.
                CompletionReactor::release_at(core::ptr::addr_of_mut!(extension.header.reactor));
            }
            return Err(error);
        }
        #[cfg(not(test))]
        let retirement_work_item = unsafe {
            // SAFETY: The new mounted device remains live and unpublished during allocation.
            ffi::IoAllocateWorkItem(device.as_ptr())
        };
        #[cfg(test)]
        let retirement_work_item = NonNull::<wdk_sys::_IO_WORKITEM>::dangling().as_ptr();
        if retirement_work_item.is_null() {
            Self::unregister_shutdown_notification(device);
            unsafe {
                // SAFETY: Work-item allocation failed before publication; no request can race
                // executor teardown.
                CompletionReactor::release_at(core::ptr::addr_of_mut!(extension.header.reactor));
            }
            return Err(DriverError::InsufficientResources);
        }
        extension.retirement_work_item = retirement_work_item;

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

    /// Releases actor, VPB, and VCB resources before the I/O Manager deletes this device.
    /// # Safety
    ///
    /// New dispatch must be excluded. Every FILE_OBJECT must have completed Close, or teardown
    /// terminates at the VCB ownership boundary instead of freeing referenced state.
    unsafe fn release(device: KernelDevice, teardown: MountedDeviceTeardown) {
        let device_object = unsafe {
            // SAFETY: The caller owns terminal teardown of this mounted device.
            device.as_ptr().as_mut()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        let extension = unsafe {
            // SAFETY: The common extension kind was decoded as mounted before this call.
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
                .as_mut()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        let retirement_work_item =
            NonNull::new(extension.retirement_work_item).unwrap_or_else(|| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
        unsafe {
            // SAFETY: Terminal teardown closes admission, drains IRPs, and joins the actor before
            // any VCB or VPB storage is released.
            CompletionReactor::release_at(core::ptr::addr_of_mut!(extension.header.reactor));
        }
        let vcb = NonNull::new(extension.vcb).unwrap_or_else(|| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        });
        if !unsafe {
            // SAFETY: The executor is joined, granting teardown exclusive VCB access.
            vcb.as_ref()
        }
        .is_logically_dismounted()
        {
            Self::unregister_shutdown_notification(device);
        }
        Self::detach_vpb(device);
        extension.vcb = core::ptr::null_mut();
        extension.retirement_work_item = core::ptr::null_mut();
        unsafe {
            // SAFETY: Mount transferred this Box to the extension and terminal teardown takes it
            // exactly once after every actor access ended.
            drop(Box::from_raw(vcb.as_ptr()));
        }
        if teardown == MountedDeviceTeardown::DriverUnload {
            #[cfg(not(test))]
            unsafe {
                // SAFETY: DriverUnload owns the mount-preallocated item and it was never queued.
                ffi::IoFreeWorkItem(retirement_work_item.as_ptr());
            }
            #[cfg(test)]
            let _retirement_work_item = retirement_work_item;
        }
    }

    /// Queues the preallocated work item that retires this device after its actor returns.
    pub(crate) fn schedule_retirement(device: KernelDevice) {
        let work_item = Self::retirement_work_item(device);
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Mount allocated this item for the device and Retiring makes this the unique
            // queue operation. I/O work-item ownership pins the device until callback completion.
            ffi::IoQueueWorkItem(
                work_item.as_ptr(),
                Some(mounted_volume_retirement),
                wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue,
                work_item.as_ptr().cast::<c_void>(),
            );
        }
        #[cfg(test)]
        let _work_item = work_item;
    }

    /// Returns the mount-preallocated retirement work item from a live mounted extension.
    fn retirement_work_item(device: KernelDevice) -> NonNull<wdk_sys::_IO_WORKITEM> {
        let device_object = unsafe {
            // SAFETY: The caller retains the mounted device and its extension.
            device.as_ptr().as_ref()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        let extension = unsafe {
            // SAFETY: Retirement is emitted only by a mounted-volume actor.
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
                .as_ref()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        NonNull::new(extension.retirement_work_item).unwrap_or_else(|| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        })
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

    /// Publishes whether the mounted VPB rejects creates for a volume lock.
    /// # Errors
    ///
    /// Stops the system if the live mounted device has lost its VPB association.
    pub(crate) fn publish_volume_lock(device: KernelDevice, locked: bool) {
        let locked_flag = u16::try_from(wdk_sys::VPB_LOCKED).unwrap_or_else(|_| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        });
        Self::update_vpb_flags(device, |flags| {
            if locked {
                *flags |= locked_flag;
            } else {
                *flags &= !locked_flag;
            }
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    }

    /// Publishes that direct lower-volume writes are permitted after logical dismount.
    /// # Errors
    ///
    /// Stops the system if the live mounted device has lost its VPB association.
    pub(crate) fn publish_direct_writes_allowed(device: KernelDevice) {
        let direct_writes =
            u16::try_from(wdk_sys::VPB_DIRECT_WRITES_ALLOWED).unwrap_or_else(|_| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
        Self::update_vpb_flags(device, |flags| *flags |= direct_writes).unwrap_or_else(|_| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        });
    }

    /// Stops shutdown IRP delivery after this volume has logically dismounted.
    pub(crate) fn unregister_shutdown_notification(device: KernelDevice) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Successful mount registered this live mounted device exactly once, and the
            // actor's one-way dismount transition calls this exactly once.
            ffi::IoUnregisterShutdownNotification(device.as_ptr());
        }
        #[cfg(test)]
        let _device = device;
    }

    /// Notifies FsRtl that this lower storage volume completed a dismount request.
    /// # Errors
    ///
    /// Stops the system if the mounted device has lost its VPB/real-device association.
    pub(crate) fn complete_dismount(device: KernelDevice) {
        let real_device = Self::with_vpb(device, |vpb| {
            KernelDevice::from_raw(vpb.RealDevice).ok_or(DriverError::InvalidParameter)
        })
        .and_then(core::convert::identity)
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The VPB identified this live lower storage device and logical dismount
            // completed successfully before this notification.
            ffi::FsRtlDismountComplete(real_device.as_ptr(), STATUS_SUCCESS);
        }
        #[cfg(test)]
        let _real_device = real_device;
    }

    /// Mutates VPB flags while holding the global VPB spin lock in production.
    /// # Errors
    ///
    /// Returns an error when the mounted device or its VPB is absent.
    fn update_vpb_flags(device: KernelDevice, update: impl FnOnce(&mut u16)) -> DriverResult<()> {
        Self::with_vpb(device, |vpb| update(&mut vpb.Flags))
    }

    /// Removes this mounted device from its VPB while holding the global VPB lock.
    fn detach_vpb(device: KernelDevice) {
        let mounted = u16::try_from(wdk_sys::VPB_MOUNTED).unwrap_or_else(|_| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        });
        let locked = u16::try_from(wdk_sys::VPB_LOCKED).unwrap_or_else(|_| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        });
        let direct_writes =
            u16::try_from(wdk_sys::VPB_DIRECT_WRITES_ALLOWED).unwrap_or_else(|_| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
        Self::with_vpb(device, |vpb| {
            if vpb.DeviceObject != device.as_ptr() {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
            }
            vpb.Flags &= !(mounted | locked | direct_writes);
            vpb.DeviceObject = core::ptr::null_mut();
            let device_object = unsafe {
                // SAFETY: The VPB lock is held and terminal teardown still owns the device.
                device.as_ptr().as_mut()
            }
            .unwrap_or_else(|| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
            device_object.Vpb = core::ptr::null_mut();
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    }

    /// Runs one nonblocking VPB access under the global VPB spin lock in production.
    /// # Errors
    ///
    /// Returns an error when the mounted device or its VPB is absent.
    fn with_vpb<R>(
        device: KernelDevice,
        operation: impl FnOnce(&mut wdk_sys::VPB) -> R,
    ) -> DriverResult<R> {
        #[cfg(not(test))]
        let mut irql = 0;
        #[cfg(not(test))]
        unsafe {
            // SAFETY: `irql` is writable stack storage paired with the release below.
            ffi::IoAcquireVpbSpinLock(core::ptr::addr_of_mut!(irql));
        }
        let result = (|| {
            let device = unsafe {
                // SAFETY: The actor-owned mounted device remains live throughout this operation.
                device.as_ptr().as_mut()
            }
            .ok_or(DriverError::InvalidParameter)?;
            let vpb = unsafe {
                // SAFETY: The VPB spin lock protects this mounted association in production.
                device.Vpb.as_mut()
            }
            .ok_or(DriverError::InvalidParameter)?;
            Ok(operation(vpb))
        })();
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This balances the immediately preceding successful VPB-lock acquisition.
            ffi::IoReleaseVpbSpinLock(irql);
        }
        result
    }
}

/// PASSIVE_LEVEL work-item callback that joins the retiring actor and deletes its device.
/// # Safety
///
/// `device` and `context` must be the unique pair queued by
/// `MountedVolumeDevice::schedule_retirement`.
#[cfg(not(test))]
unsafe extern "C" fn mounted_volume_retirement(device: PDEVICE_OBJECT, context: wdk_sys::PVOID) {
    let Some(device) = KernelDevice::from_raw(device) else {
        KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
    };
    let work_item = NonNull::new(context.cast::<wdk_sys::_IO_WORKITEM>())
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    if MountedVolumeDevice::retirement_work_item(device) != work_item {
        KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
    }
    unsafe {
        // SAFETY: Work-item ownership excludes driver unload and pins the device while release
        // closes admission, drains the actor, and destroys extension-owned resources.
        MountedVolumeDevice::release(device, MountedDeviceTeardown::RetirementWorkItem);
    }
    unsafe {
        // SAFETY: All extension resources are gone and the work item still pins this device.
        ffi::IoDeleteDevice(device.as_ptr());
    }
    unsafe {
        // SAFETY: The system dequeued this item before invoking the callback. This final operation
        // releases its device reference and may complete pending device deletion.
        ffi::IoFreeWorkItem(work_item.as_ptr());
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
        requestor: RequestorProcess,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        self.byte_range_locks
            .permits_read(requestor, file_object, start, length, key)
    }

    /// Returns whether the requestor may write one fully resolved file byte range.
    /// # Errors
    ///
    /// Returns an error when the resolved range cannot be represented by FsRtl.
    pub(crate) fn permits_byte_range_write(
        &self,
        requestor: RequestorProcess,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        self.byte_range_locks
            .permits_write(requestor, file_object, start, length, key)
    }

    /// Releases all byte-range locks held by this FILE_OBJECT's requestor during cleanup.
    pub(crate) fn release_handle_byte_range_locks(
        &self,
        requestor: RequestorProcess,
        file_object: KernelFileObject,
    ) {
        self.byte_range_locks
            .release_for_cleanup(requestor, file_object);
    }
}

/// Mutable FCB lifecycle state owned exclusively by `FileControlBlockLedger`.
struct FileControlBlockOpenState {
    /// I/O manager share-access accounting for this inode identity.
    share_access: SHARE_ACCESS,
    /// Number of open FILE_OBJECTs currently referencing this FCB.
    file_object_references: NonZeroU32,
    /// One namespace deletion truth shared by every handle for this inode.
    deletion: FileDeletionState,
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
            deletion: FileDeletionState::Live,
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
        self.deletion.ensure_openable()?;
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

    /// Selects deferred deletion after one share claim has been removed.
    fn cleanup_disposition(&self) -> FileCleanupDisposition {
        self.deletion
            .cleanup_target(self.share_access.OpenCount)
            .map_or(
                FileCleanupDisposition::Retained,
                FileCleanupDisposition::Delete,
            )
    }

    /// Requires ordinary replacement to respect deletion state and open-inode lifetime.
    /// # Errors
    ///
    /// Returns delete-pending or sharing-violation when the current open state rejects replacement.
    fn ensure_namespace_replaceable(&self) -> DriverResult<()> {
        self.deletion.ensure_openable()?;
        if self.share_access.OpenCount == 0 {
            Ok(())
        } else {
            Err(DriverError::ShareAccessConflict)
        }
    }

    /// Publishes a shared delete-pending target and returns displaced storage.
    ///
    /// A create-time delete-on-close target is mandatory and therefore cannot be replaced by a
    /// later, cancellable disposition request from another already-open handle.
    fn set_delete_pending(&mut self, pending: PendingFileDeletion) -> Option<PendingFileDeletion> {
        if matches!(
            &self.deletion,
            FileDeletionState::Pending(existing)
                if existing.cause() == FileDeletionCause::DeleteOnClose
        ) {
            return Some(pending);
        }
        match core::mem::replace(&mut self.deletion, FileDeletionState::Pending(pending)) {
            FileDeletionState::Live => None,
            FileDeletionState::Pending(previous) => Some(previous),
            FileDeletionState::Deleted => {
                KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
            }
        }
    }

    /// Cancels a disposition-originated delete-pending before final active cleanup.
    ///
    /// Create-time delete-on-close is mandatory and is intentionally unaffected.
    fn clear_delete_pending(&mut self) -> Option<PendingFileDeletion> {
        if matches!(
            &self.deletion,
            FileDeletionState::Pending(existing)
                if existing.cause() == FileDeletionCause::DeleteOnClose
        ) {
            return None;
        }
        match core::mem::replace(&mut self.deletion, FileDeletionState::Live) {
            FileDeletionState::Live => None,
            FileDeletionState::Pending(previous) => Some(previous),
            FileDeletionState::Deleted => {
                KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
            }
        }
    }

    /// Returns whether the inode has crossed into delete-pending.
    const fn delete_pending(&self) -> bool {
        self.deletion.is_pending()
    }

    /// Publishes successful removal of the exact target selected by cleanup.
    fn complete_delete(&mut self, target: NonNull<FileDeleteTarget>) -> PendingFileDeletion {
        match core::mem::replace(&mut self.deletion, FileDeletionState::Deleted) {
            FileDeletionState::Pending(pending) if pending.target() == target => pending,
            FileDeletionState::Live
            | FileDeletionState::Pending(_)
            | FileDeletionState::Deleted => {
                KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
            }
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
                    target.into_raw_irp(),
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
        requestor: RequestorProcess,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        let range = NativeFileByteRange::new(start, length)?;
        #[cfg(not(test))]
        {
            let mut range = range;
            Ok(unsafe {
                // SAFETY: FsRtl receives initialized lock state, checked signed
                // range values, the live FILE_OBJECT, and the IRP requestor.
                ffi::FsRtlFastCheckLockForRead(
                    self.native.get(),
                    core::ptr::addr_of_mut!(range.start),
                    core::ptr::addr_of_mut!(range.length),
                    key.as_ulong(),
                    file_object.as_ptr(),
                    requestor.as_ptr(),
                ) != 0
            })
        }
        #[cfg(test)]
        {
            let _requestor = requestor;
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
        requestor: RequestorProcess,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        let range = NativeFileByteRange::new(start, length)?;
        #[cfg(not(test))]
        {
            let mut range = range;
            Ok(unsafe {
                // SAFETY: FsRtl receives initialized lock state, checked signed
                // range values, the live FILE_OBJECT, and the IRP requestor.
                ffi::FsRtlFastCheckLockForWrite(
                    self.native.get(),
                    core::ptr::addr_of_mut!(range.start),
                    core::ptr::addr_of_mut!(range.length),
                    key.as_ulong(),
                    file_object.as_ptr().cast::<c_void>(),
                    requestor.as_ptr(),
                ) != 0
            })
        }
        #[cfg(test)]
        {
            let _requestor = requestor;
            let _file_object = file_object;
            let _key = key;
            let _range = range;
            Ok(true)
        }
    }

    /// Releases all locks associated with this cleanup IRP's FILE_OBJECT and requestor.
    fn release_for_cleanup(&self, requestor: RequestorProcess, file_object: KernelFileObject) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Cleanup runs for this live FILE_OBJECT. Passing the
            // requestor captured in its IRP matches FsRtl's lock ownership
            // identity and releases only that process's locks.
            let _status = ffi::FsRtlFastUnlockAll(
                self.native.get(),
                file_object.as_ptr(),
                requestor.as_ptr().cast(),
                core::ptr::null_mut(),
            );
        }
        #[cfg(test)]
        {
            let _requestor = requestor;
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

/// Stable namespace identity selected for a deferred Windows deletion.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FileDeleteTarget {
    /// Directory containing the link selected by the deleting handle.
    parent: DirectoryNodeId,
    /// Exact ext4 link name that must still resolve to the opened inode.
    name: Ext4Name,
}

impl FileDeleteTarget {
    /// Returns the parent directory containing the selected link.
    pub(crate) const fn parent(&self) -> DirectoryNodeId {
        self.parent
    }

    /// Returns the exact ext4 link name selected for deletion.
    pub(crate) const fn name(&self) -> &Ext4Name {
        &self.name
    }
}

/// Heap-stable delete target owned by one FCB until deletion completes or is cancelled.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PendingFileDeletion {
    /// Stable target storage referenced by an actor-local cleanup plan across suspension.
    target: Box<FileDeleteTarget>,
    /// Whether the pending state may be cancelled by a later disposition request.
    cause: FileDeletionCause,
}

impl PendingFileDeletion {
    /// Copies a normal disposition target into stable FCB-owned storage.
    /// # Errors
    ///
    /// Returns cannot-delete for root and file-reference handles, or an allocation error when the
    /// exact directory-entry name cannot be retained.
    pub(crate) fn try_from_disposition(location: &OpenedLocation) -> DriverResult<Self> {
        Self::try_from_location(location, FileDeletionCause::Disposition)
    }

    /// Copies a mandatory delete-on-close target into stable FCB-owned storage.
    /// # Errors
    ///
    /// Returns cannot-delete for root and file-reference handles, or an allocation error when the
    /// exact directory-entry name cannot be retained.
    pub(crate) fn try_from_delete_on_close(location: &OpenedLocation) -> DriverResult<Self> {
        Self::try_from_location(location, FileDeletionCause::DeleteOnClose)
    }

    /// Copies an exact location and deletion cause into stable storage.
    /// # Errors
    ///
    /// Returns cannot-delete when the location has no deletable directory entry, or an allocation
    /// error when the exact entry name cannot be retained.
    fn try_from_location(
        location: &OpenedLocation,
        cause: FileDeletionCause,
    ) -> DriverResult<Self> {
        let OpenedLocation::DirectoryEntry { parent, name } = location else {
            return Err(DriverError::CannotDelete);
        };
        let name = name.try_to_owned_name()?;
        Ok(Self {
            target: memory::boxed_try_with(|| {
                Ok(FileDeleteTarget {
                    parent: *parent,
                    name,
                })
            })?,
            cause,
        })
    }

    /// Returns the stable target pointer retained by this pending state.
    fn target(&self) -> NonNull<FileDeleteTarget> {
        NonNull::from(self.target.as_ref())
    }

    /// Borrows the exact target before this pending state is published into the FCB.
    pub(crate) fn target_ref(&self) -> &FileDeleteTarget {
        self.target.as_ref()
    }

    /// Returns the cancellation semantics fixed when this pending target was created.
    const fn cause(&self) -> FileDeletionCause {
        self.cause
    }
}

/// Origin of one shared FCB delete-pending state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileDeletionCause {
    /// Set-information may later cancel this pending state.
    Disposition,
    /// Create-time delete-on-close cannot be cancelled by normal disposition.
    DeleteOnClose,
}

/// Namespace deletion state shared by every FILE_OBJECT for one inode identity.
#[derive(Debug, Eq, PartialEq)]
enum FileDeletionState {
    /// The inode may be opened and no link has been selected for deletion.
    Live,
    /// New opens are rejected and the selected link is removed after the final active cleanup.
    Pending(PendingFileDeletion),
    /// The selected link has been removed; only terminal FILE_OBJECT close references remain.
    Deleted,
}

impl FileDeletionState {
    /// Rejects a new open after delete-pending has been published.
    /// # Errors
    ///
    /// Returns delete-pending after the one-way namespace transition begins.
    const fn ensure_openable(&self) -> DriverResult<()> {
        match self {
            Self::Live => Ok(()),
            Self::Pending(_) | Self::Deleted => Err(DriverError::DeletePending),
        }
    }

    /// Returns whether Windows queries must expose `DeletePending`.
    const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_) | Self::Deleted)
    }

    /// Returns the stable target when the final active handle may perform deletion.
    fn cleanup_target(&self, active_handles: u32) -> Option<NonNull<FileDeleteTarget>> {
        match self {
            Self::Pending(pending) if active_handles == 0 => Some(pending.target()),
            Self::Live | Self::Pending(_) | Self::Deleted => None,
        }
    }
}

/// Cleanup effect selected atomically with removal of one FILE_OBJECT share claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileCleanupDisposition {
    /// Other active handles remain or no deletion is pending.
    Retained,
    /// This was the final active handle and must remove the selected namespace link.
    Delete(NonNull<FileDeleteTarget>),
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

/// Per-handle state stored in `FsContext2` for a direct user volume open.
#[derive(Debug)]
pub(crate) struct OpenedVolumeHandle {
    /// One-way cleanup lifecycle shared with the volume FILE_OBJECT.
    lifecycle: HandleLifecycle,
}

impl OpenedVolumeHandle {
    /// Creates one active direct-volume handle.
    pub(crate) const fn new() -> Self {
        Self {
            lifecycle: HandleLifecycle::active(),
        }
    }

    /// Begins this volume handle's idempotent cleanup transition.
    fn begin_cleanup(&self) -> CleanupStart {
        self.lifecycle.begin_cleanup()
    }

    /// Publishes completion after its share claim has been removed.
    fn finish_cleanup(&self) {
        self.lifecycle.finish_cleanup();
    }

    /// Selects the legal terminal close release.
    fn close_release_plan(
        &self,
        close_kind: FileObjectCloseKind,
        cleanup_complete: bool,
    ) -> CloseReleasePlan {
        self.lifecycle
            .close_release_plan(close_kind, cleanup_complete)
    }
}

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

/// Per-handle namespace deletion authority and create-time lifecycle.
///
/// Delete-on-close is a distinct variant because that lifecycle necessarily includes `DELETE`
/// authority; an unauthorized delete-on-close handle is unrepresentable after create decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleDeletion {
    /// No create-time deletion was requested; later disposition uses the retained authorities.
    Retain {
        /// Authority to change ordinary deletion disposition.
        delete_access: DeleteAccess,
        /// Authority to override a read-only attribute during extended disposition.
        file_attributes_write_access: FileAttributesWriteAccess,
    },
    /// The exact opened link must be removed after final active cleanup.
    DeleteOnClose {
        /// Authority to override a read-only attribute during extended disposition.
        file_attributes_write_access: FileAttributesWriteAccess,
    },
}

impl HandleDeletion {
    /// Binds decoded create deletion to the handle's retained delete authority.
    /// # Errors
    ///
    /// Returns access denied when delete-on-close is paired with missing `DELETE` authority.
    pub(crate) fn from_create(
        deletion: CreateDeletion,
        delete_access: DeleteAccess,
        file_attributes_write_access: FileAttributesWriteAccess,
    ) -> DriverResult<Self> {
        match deletion {
            CreateDeletion::Retain => Ok(Self::Retain {
                delete_access,
                file_attributes_write_access,
            }),
            CreateDeletion::DeleteOnClose => {
                delete_access.require()?;
                Ok(Self::DeleteOnClose {
                    file_attributes_write_access,
                })
            }
        }
    }

    /// Requires delete authority retained by this handle lifecycle.
    /// # Errors
    ///
    /// Returns access denied when a retained handle was not opened with `DELETE`.
    fn require_delete_access(self) -> DriverResult<()> {
        match self {
            Self::Retain { delete_access, .. } => delete_access.require(),
            Self::DeleteOnClose { .. } => Ok(()),
        }
    }

    /// Projects the create-time namespace deletion request.
    pub(crate) const fn create_deletion(self) -> CreateDeletion {
        match self {
            Self::Retain { .. } => CreateDeletion::Retain,
            Self::DeleteOnClose { .. } => CreateDeletion::DeleteOnClose,
        }
    }

    /// Returns retained `FILE_WRITE_ATTRIBUTES` authority.
    const fn file_attributes_write_access(self) -> FileAttributesWriteAccess {
        match self {
            Self::Retain {
                file_attributes_write_access,
                ..
            }
            | Self::DeleteOnClose {
                file_attributes_write_access,
            } => file_attributes_write_access,
        }
    }
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
    /// Delete authority and namespace lifecycle fixed when this handle was opened.
    deletion: HandleDeletion,
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
        deletion: HandleDeletion,
        write_commitment: WriteCommitment,
        data_transfer_mode: DataTransferMode,
    ) -> Self {
        Self {
            node_mode,
            location: UnsafeCell::new(location),
            lifecycle: HandleLifecycle::active(),
            deletion,
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

    /// Requires delete authority retained by this handle.
    /// # Errors
    ///
    /// Returns access denied when this retained handle was not opened with `DELETE`.
    fn require_delete_access(&self) -> DriverResult<()> {
        self.deletion.require_delete_access()
    }

    /// Returns the namespace deletion lifecycle selected at create/open.
    const fn create_deletion(&self) -> CreateDeletion {
        self.deletion.create_deletion()
    }

    /// Returns retained `FILE_WRITE_ATTRIBUTES` authority.
    const fn file_attributes_write_access(&self) -> FileAttributesWriteAccess {
        self.deletion.file_attributes_write_access()
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
        deletion: HandleDeletion,
        write_commitment: WriteCommitment,
        data_transfer_mode: DataTransferMode,
        regular_file_write_access: RegularFileWriteAccess,
    ) -> Self {
        Self::from_parts(
            node,
            node_mode,
            location,
            deletion,
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
        deletion: HandleDeletion,
        write_commitment: WriteCommitment,
        data_transfer_mode: DataTransferMode,
        regular_file_write_access: RegularFileWriteAccess,
    ) -> Self {
        let state = OpenedHandleState::new(
            node_mode,
            location,
            deletion,
            write_commitment,
            data_transfer_mode,
        );
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

    /// Requires delete authority retained by this handle.
    /// # Errors
    ///
    /// Returns access denied when this retained handle was not opened with `DELETE`.
    fn require_delete_access(&self) -> DriverResult<()> {
        self.state.require_delete_access()
    }

    /// Returns the namespace deletion lifecycle selected at create/open.
    const fn create_deletion(&self) -> CreateDeletion {
        self.state.create_deletion()
    }

    /// Returns retained `FILE_WRITE_ATTRIBUTES` authority.
    const fn file_attributes_write_access(&self) -> FileAttributesWriteAccess {
        self.state.file_attributes_write_access()
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
pub(crate) struct OpenedObject<'owner> {
    /// Kernel FILE_OBJECT carrying the contexts.
    file_object: ActiveFileObject<'owner>,
    /// Shared file control block stored in FsContext.
    fcb: NonNull<FileControlBlock>,
    /// Per-handle context stored in FsContext2.
    handle: NonNull<OpenedHandle>,
}

/// Prevalidated, allocation-free update to one stable per-handle namespace location.
#[derive(Debug)]
pub(crate) struct PreparedOpenedLocationPublication {
    /// Stable CCB allocated at create and retained until CLOSE.
    handle: NonNull<OpenedHandle>,
    /// Fully owned location prepared before the first lower write.
    location: OpenedLocation,
}

impl PreparedOpenedLocationPublication {
    /// Moves the prepared location into the live CCB without allocation or validation.
    pub(crate) fn publish(self) {
        let handle = unsafe {
            // SAFETY: The originating top-level IRP retains the FILE_OBJECT/CCB through commit,
            // and CLOSE is ordered behind that operation by the per-handle lane.
            self.handle.as_ref()
        };
        handle.replace_location(self.location);
    }
}

// SAFETY: This token moves only through the reactor and completion envelopes. Its CCB is stable
// from successful CREATE publication until the ordered CLOSE transition.
unsafe impl Send for PreparedOpenedLocationPublication {}

/// Prevalidated FILE_OBJECT position update published after successful data I/O.
#[derive(Debug)]
pub(crate) enum PreparedFilePositionPublication {
    /// Paging or asynchronous I/O does not update the user-visible cursor.
    Unchanged,
    /// Exact signed position ready for one infallible field write.
    Set {
        /// Stable FILE_OBJECT retained by the active operation lane.
        file_object: KernelFileObject,
        /// Checked Windows current-byte-offset value.
        position: i64,
    },
}

impl PreparedFilePositionPublication {
    /// Applies the prevalidated position without allocation or ordinary failure.
    pub(crate) fn publish(self) {
        if let Self::Set {
            file_object,
            position,
        } = self
        {
            file_object.write_current_byte_offset(position);
        }
    }
}

// SAFETY: The FILE_OBJECT is kept live through the per-handle active-operation lane and the token
// is moved only through reactor-owned operation state.
unsafe impl Send for PreparedFilePositionPublication {}

impl<'owner> OpenedObject<'owner> {
    /// Decodes an initialized FILE_OBJECT context pair.
    ///
    /// # Errors
    /// Returns an error when either filesystem context pointer is absent or
    /// when the shared FCB node kind does not match the per-handle state kind.
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
        let object = file_object.as_ref();
        if object.Flags & wdk_sys::FO_VOLUME_OPEN != 0 {
            return Err(DriverError::ObjectTypeMismatch);
        }
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
        self.file_object.address()
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

    /// Requires delete authority retained by this handle.
    /// # Errors
    ///
    /// Returns access denied when the create/open did not request `DELETE`.
    pub(crate) fn require_delete_access(&self) -> DriverResult<()> {
        self.handle().require_delete_access()
    }

    /// Returns the namespace deletion lifecycle selected when this handle was created.
    pub(crate) fn create_deletion(&self) -> CreateDeletion {
        self.handle().create_deletion()
    }

    /// Returns `FILE_WRITE_ATTRIBUTES` authority retained when this handle was created.
    pub(crate) fn file_attributes_write_access(&self) -> FileAttributesWriteAccess {
        self.handle().file_attributes_write_access()
    }

    /// Copies this handle's exact deletable location into stable FCB-owned storage.
    /// # Errors
    ///
    /// Returns cannot-delete for root or file-reference handles, or an allocation failure.
    pub(crate) fn prepare_pending_deletion(&self) -> DriverResult<PendingFileDeletion> {
        PendingFileDeletion::try_from_disposition(self.location())
    }

    /// Cancels delete-pending for the shared FCB.
    pub(crate) fn clear_delete_pending(&self) {
        let owner = file_control_block_owner(self.fcb);
        unsafe {
            // SAFETY: This opened FILE_OBJECT keeps the FCB and its ledger owner live.
            owner.as_ref()
        }
        .clear_delete_pending(self.fcb);
    }

    /// Returns whether the shared FCB is delete-pending.
    pub(crate) fn delete_pending(&self) -> bool {
        let owner = file_control_block_owner(self.fcb);
        unsafe {
            // SAFETY: This opened FILE_OBJECT keeps the FCB and its ledger owner live.
            owner.as_ref()
        }
        .delete_pending(self.fcb)
    }

    /// Returns the stable FCB address retained by this FILE_OBJECT.
    pub(crate) const fn file_control_block_address(&self) -> NonNull<FileControlBlock> {
        self.fcb
    }

    /// Replaces the opened location after a successful rename.
    pub(crate) fn replace_location(&mut self, location: OpenedLocation) {
        self.handle().replace_location(location);
    }

    /// Prepares a post-commit handle-location update without retaining an active IRP borrow.
    pub(crate) fn prepare_location_publication(
        &self,
        location: OpenedLocation,
    ) -> PreparedOpenedLocationPublication {
        PreparedOpenedLocationPublication {
            handle: self.handle,
            location,
        }
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
        let file_object = self.file_object.as_ref();
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

    /// Precomputes a post-I/O cursor update while failures are still harmless.
    pub(crate) fn prepare_current_file_position_update(
        &self,
        kind: DataIoKind,
        start: FileOffset,
        transferred: usize,
    ) -> DriverResult<PreparedFilePositionPublication> {
        if kind == DataIoKind::Paging || !self.has_synchronous_file_position() {
            return Ok(PreparedFilePositionPublication::Unchanged);
        }
        let position = start.checked_add_len(transferred)?;
        Ok(PreparedFilePositionPublication::Set {
            file_object: self.file_object(),
            position: i64::try_from(position.bytes()).map_err(|_| DriverError::InvalidParameter)?,
        })
    }

    /// Returns whether this FILE_OBJECT owns a synchronized current-position field.
    fn has_synchronous_file_position(&self) -> bool {
        let file_object = self.file_object.as_ref();
        file_object.Flags & wdk_sys::FO_SYNCHRONOUS_IO != 0
    }

    /// Writes a preselected position after signed-range validation.
    /// # Errors
    ///
    /// Returns an error when the position exceeds signed Windows range.
    fn write_current_file_position(&mut self, position: FileOffset) -> DriverResult<()> {
        let position =
            i64::try_from(position.bytes()).map_err(|_| DriverError::InvalidParameter)?;
        self.file_object.write_current_byte_offset(position);
        Ok(())
    }

    /// Enters this handle's synchronous cleanup transition.
    pub(crate) fn begin_cleanup(&self) -> CleanupStart {
        self.handle().begin_cleanup()
    }

    /// Removes this handle's share claim and selects final-active-handle deletion.
    pub(crate) fn release_share_access_for_cleanup(&self) -> FileCleanupDisposition {
        release_file_share_access(self.fcb, self.file_object.address())
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

    /// Detaches the exact FCB and CCB pair validated by this opened-object capability.
    ///
    /// A close IRP is the sole transition permitted to consume this pair. Any pointer change
    /// between decode and detachment is global lifecycle corruption.
    pub(crate) fn detach_contexts(self) -> (NonNull<FileControlBlock>, NonNull<OpenedHandle>) {
        let object = unsafe {
            // SAFETY: This consumed active opened-object capability represents the unique close
            // transition for the live FILE_OBJECT.
            &mut *self.file_object.as_ptr()
        };
        let fcb = NonNull::new(
            core::mem::replace(&mut object.FsContext, core::ptr::null_mut())
                .cast::<FileControlBlock>(),
        );
        let handle = NonNull::new(
            core::mem::replace(&mut object.FsContext2, core::ptr::null_mut())
                .cast::<OpenedHandle>(),
        );
        match (fcb, handle) {
            (Some(fcb), Some(handle)) if fcb == self.fcb && handle == self.handle => (fcb, handle),
            _ => KernelWideInconsistency::file_object_context_corruption().bugcheck(),
        }
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

/// Successfully opened FILE_OBJECT kind selected without reinterpreting context pointers.
#[derive(Debug)]
pub(crate) enum OpenedFileObject<'owner> {
    /// Namespace node backed by an FCB and `OpenedHandle`.
    Node(OpenedObject<'owner>),
    /// Direct mounted-volume handle backed by a VCB and `OpenedVolumeHandle`.
    Volume(OpenedVolume<'owner>),
}

impl<'owner> OpenedFileObject<'owner> {
    /// Decodes the filesystem-owned context pair according to the FSD-owned volume-open flag.
    /// # Errors
    ///
    /// Returns an error when the selected context pair is absent or inconsistent.
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
        if file_object.as_ref().Flags & wdk_sys::FO_VOLUME_OPEN != 0 {
            OpenedVolume::decode(file_object).map(Self::Volume)
        } else {
            OpenedObject::decode(file_object).map(Self::Node)
        }
    }
}

/// Direct user volume open decoded from its typed FILE_OBJECT context pair.
#[derive(Debug)]
pub(crate) struct OpenedVolume<'owner> {
    /// Live direct-volume FILE_OBJECT.
    file_object: ActiveFileObject<'owner>,
    /// Mounted VCB stored in `FsContext`.
    volume: NonNull<VolumeControlBlock>,
    /// Per-handle lifecycle stored in `FsContext2`.
    handle: NonNull<OpenedVolumeHandle>,
}

impl<'owner> OpenedVolume<'owner> {
    /// Decodes a direct-volume FILE_OBJECT.
    /// # Errors
    ///
    /// Returns an error when the volume flag or either typed context pointer is absent.
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
        let object = file_object.as_ref();
        if object.Flags & wdk_sys::FO_VOLUME_OPEN == 0 {
            return Err(DriverError::ObjectTypeMismatch);
        }
        let volume = NonNull::new(object.FsContext.cast::<VolumeControlBlock>());
        let handle = NonNull::new(object.FsContext2.cast::<OpenedVolumeHandle>());
        match (volume, handle) {
            (Some(volume), Some(handle)) => Ok(Self {
                file_object,
                volume,
                handle,
            }),
            (None, None) => Err(DriverError::InvalidParameter),
            (Some(_), None) | (None, Some(_)) => {
                KernelWideInconsistency::file_object_context_corruption().bugcheck()
            }
        }
    }

    /// Returns the mounted VCB identified by this volume handle.
    pub(crate) const fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.volume
    }

    /// Returns the kernel FILE_OBJECT identity whose share claim is recorded.
    pub(crate) const fn file_object(&self) -> KernelFileObject {
        self.file_object.address()
    }

    /// Begins this handle's idempotent cleanup transition.
    pub(crate) fn begin_cleanup(&self) -> CleanupStart {
        unsafe {
            // SAFETY: Decode validated the live `OpenedVolumeHandle` context pointer.
            self.handle.as_ref()
        }
        .begin_cleanup()
    }

    /// Publishes completion after its share claim has been removed.
    pub(crate) fn finish_cleanup(&self) {
        unsafe {
            // SAFETY: Decode validated the live `OpenedVolumeHandle` context pointer.
            self.handle.as_ref()
        }
        .finish_cleanup();
    }

    /// Selects the only legal terminal close release.
    pub(crate) fn close_release_plan(&self, close_kind: FileObjectCloseKind) -> CloseReleasePlan {
        unsafe {
            // SAFETY: Decode validated the live `OpenedVolumeHandle` context pointer.
            self.handle.as_ref()
        }
        .close_release_plan(close_kind, self.file_object.cleanup_complete())
    }

    /// Detaches the exact VCB and volume-handle pair at terminal close.
    pub(crate) fn detach_contexts(
        self,
    ) -> (NonNull<VolumeControlBlock>, NonNull<OpenedVolumeHandle>) {
        let object = unsafe {
            // SAFETY: This consumed capability represents the unique close transition.
            &mut *self.file_object.as_ptr()
        };
        let volume = NonNull::new(
            core::mem::replace(&mut object.FsContext, core::ptr::null_mut())
                .cast::<VolumeControlBlock>(),
        );
        let handle = NonNull::new(
            core::mem::replace(&mut object.FsContext2, core::ptr::null_mut())
                .cast::<OpenedVolumeHandle>(),
        );
        match (volume, handle) {
            (Some(volume), Some(handle)) if volume == self.volume && handle == self.handle => {
                (volume, handle)
            }
            _ => KernelWideInconsistency::file_object_context_corruption().bugcheck(),
        }
    }
}

#[derive(Debug)]
/// Opened regular file decoded from a FILE_OBJECT context pair.
pub(crate) struct OpenedRegularFile<'owner> {
    /// Opened object context validated as a regular file.
    opened: OpenedObject<'owner>,
    /// Typed file node identity.
    id: FileNodeId,
}

impl<'owner> OpenedRegularFile<'owner> {
    /// Decodes an opened FILE_OBJECT and requires a regular-file node.
    ///
    /// # Errors
    /// Returns an error when the FILE_OBJECT contexts are invalid or when the
    /// opened node is not a regular file.
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
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

    /// Precomputes an infallible post-I/O position publication.
    pub(crate) fn prepare_current_file_position_update(
        &self,
        kind: DataIoKind,
        start: FileOffset,
        transferred: usize,
    ) -> DriverResult<PreparedFilePositionPublication> {
        self.opened
            .prepare_current_file_position_update(kind, start, transferred)
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
pub(crate) struct OpenedDirectory<'owner> {
    /// Opened object context validated as a directory.
    opened: OpenedObject<'owner>,
    /// Typed directory node identity.
    id: DirectoryNodeId,
    /// Directory cursor stored in the directory handle variant.
    cursor: NonNull<DirectoryCursor>,
}

impl<'owner> OpenedDirectory<'owner> {
    /// Decodes an opened FILE_OBJECT and requires a directory node.
    ///
    /// # Errors
    /// Returns an error when the FILE_OBJECT contexts are invalid or when the
    /// opened node is not a directory.
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
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
) -> FileCleanupDisposition {
    let owner = file_control_block_owner(fcb);
    let owner = unsafe {
        // SAFETY: The retained FCB reference keeps its owner ledger live for cleanup.
        owner.as_ref()
    };
    owner.release_share_access(fcb, file_object)
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
pub(crate) unsafe extern "C" fn driver_unload(driver: PDRIVER_OBJECT) {
    let Some(driver) = (unsafe {
        // SAFETY: The I/O Manager invokes DriverUnload with this driver's live object.
        driver.as_mut()
    }) else {
        return;
    };
    let control = find_control_device(driver.DeviceObject)
        .and_then(|device| device.ok_or(DriverError::InternalInvariantViolation))
        .unwrap_or_else(|_| {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck()
        });
    unsafe {
        // SAFETY: Unregistration closes the I/O Manager's filesystem entry before actor teardown.
        ffi::IoUnregisterFileSystem(control.as_ptr());
    }
    unsafe {
        // SAFETY: Unregistration excludes new control requests. Joining this actor also completes
        // any in-flight mount, stabilizing the complete driver device chain.
        ControlDeviceExtension::release(control);
    }
    unsafe {
        // SAFETY: Control extension resources were released exactly once above.
        ffi::IoDeleteDevice(control.as_ptr());
    }

    while let Some(device) = KernelDevice::from_raw(driver.DeviceObject) {
        if driver_device_kind(device) != Ok(DriverDeviceKind::MountedVolume) {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
        unsafe {
            // SAFETY: The control actor is gone, so the mounted-device set can no longer grow.
            MountedVolumeDevice::release(device, MountedDeviceTeardown::DriverUnload);
        }
        unsafe {
            // SAFETY: Mounted extension resources were released exactly once above.
            ffi::IoDeleteDevice(device.as_ptr());
        }
    }
}

/// Finds the unique control device before unload joins its mount-capable actor.
/// # Errors
///
/// Returns an invariant error for an unknown extension or more than one control device.
fn find_control_device(first: PDEVICE_OBJECT) -> DriverResult<Option<KernelDevice>> {
    let mut found = None;
    let mut next = first;
    while let Some(device) = KernelDevice::from_raw(next) {
        if driver_device_kind(device)? == DriverDeviceKind::Control
            && found.replace(device).is_some()
        {
            return Err(DriverError::InternalInvariantViolation);
        }
        next = unsafe {
            // SAFETY: This read-only traversal occurs before any chain member is deleted.
            device.as_ptr().as_ref()
        }
        .map_or(core::ptr::null_mut(), |object| object.NextDevice);
    }
    Ok(found)
}

/// Decodes the common extension kind for one device in this driver's I/O Manager-owned chain.
/// # Errors
///
/// Returns an invariant error when the device or its typed extension header is absent or unknown.
fn driver_device_kind(device: KernelDevice) -> DriverResult<DriverDeviceKind> {
    let device = unsafe {
        // SAFETY: The unload chain retains this device until its resources are selected.
        device.as_ptr().as_ref()
    }
    .ok_or(DriverError::InternalInvariantViolation)?;
    let header = unsafe {
        // SAFETY: Every device created by this driver begins with DeviceExtensionHeader.
        device
            .DeviceExtension
            .cast::<DeviceExtensionHeader>()
            .as_ref()
    }
    .ok_or(DriverError::InternalInvariantViolation)?;
    DriverDeviceKind::decode(header.kind)
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;
    use core::ptr::NonNull;

    use ext4_core::{DirectoryNodeId, Ext4Name, FileOffset, NodeId};

    use crate::irp::{
        ActiveFileObject, CreateDeletion, DataIoKind, DeleteAccess, DirectoryEntryIndex,
        FileAttributesWriteAccess, ReceivedIrp, RegularFileWriteAccess,
    };
    use crate::kernel::status::DriverError;

    use super::{
        CleanupStart, CloseReleasePlan, ControlDeviceExtension,
        DIRECTORY_NOTIFICATION_DIRECTORY_UNITS, DataTransferMode, DeviceExtensionKind,
        DirectoryChange, DirectoryChangeAction, DriverDeviceKind, FileControlBlock,
        FileControlBlockLedger, FileControlBlockOpenState, FileControlBlockRelease,
        FileObjectCloseKind, HandleDeletion, KernelDevice, KernelFileObject, MountedVolumeDevice,
        MountedVolumeDeviceExtension, MountedVolumeState, NativeFileByteRange,
        NoIntermediateTransfer, OpenedDirectory, OpenedFileObject, OpenedHandle, OpenedLocation,
        OpenedNodeMode, OpenedObject, OpenedRegularFile, OpenedVolumeHandle,
        TransferBufferAlignment, TransferSectorSize, UninitializedFileObject, VolumeControlBlock,
        VolumeHandleCleanup, VolumeRetirement, WriteCommitment, select_close_release_plan,
        shutdown_registration_status,
    };

    /// Returns the common no-delete fixture policy for opened-handle tests.
    const fn retained_handle_deletion() -> HandleDeletion {
        HandleDeletion::Retain {
            delete_access: DeleteAccess::Denied,
            file_attributes_write_access: FileAttributesWriteAccess::Denied,
        }
    }

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

    /// # Panics
    ///
    /// Panics when the FSD-owned volume flag does not select the VCB/volume-handle context layout.
    #[test]
    fn volume_open_flag_selects_typed_volume_contexts() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut handle = OpenedVolumeHandle::new();
        let mut file = file_object_with_contexts(
            volume.as_ptr().cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        file.Flags |= wdk_sys::FO_VOLUME_OPEN;

        let result = with_active_file_object(&mut file, |file_object| {
            assert!(matches!(
                OpenedObject::decode(file_object),
                Err(DriverError::ObjectTypeMismatch)
            ));
            let opened = OpenedFileObject::decode(file_object)?;
            let OpenedFileObject::Volume(opened) = opened else {
                return Err(DriverError::InternalInvariantViolation);
            };
            assert_eq!(opened.volume(), volume);
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when the mounted/locked policy permits a competing handle or create.
    #[test]
    fn mounted_volume_lock_policy_is_owned_by_one_file_object() {
        let mut owner_file = wdk_sys::FILE_OBJECT::default();
        let mut competing_file = wdk_sys::FILE_OBJECT::default();
        let Some(owner) = KernelFileObject::from_raw(core::ptr::addr_of_mut!(owner_file)) else {
            return;
        };
        let Some(competing) = KernelFileObject::from_raw(core::ptr::addr_of_mut!(competing_file))
        else {
            return;
        };

        let mounted = MountedVolumeState::Mounted;
        assert_eq!(mounted.authorize_create(), Ok(()));
        assert_eq!(mounted.authorize_handle(competing), Ok(()));
        let locked = mounted.lock(owner);
        assert_eq!(locked, Ok(MountedVolumeState::Locked { owner }));
        let Ok(locked) = locked else {
            return;
        };
        assert_eq!(locked.authorize_create(), Err(DriverError::AccessDenied));
        assert_eq!(locked.authorize_handle(owner), Ok(()));
        assert_eq!(
            locked.authorize_handle(competing),
            Err(DriverError::AccessDenied)
        );
        assert_eq!(locked.unlock(competing), Err(DriverError::NotLocked));
        assert_eq!(locked.unlock(owner), Ok(MountedVolumeState::Mounted));
    }

    /// # Panics
    ///
    /// Panics when logical dismount can be reversed or loses its retained lock owner.
    #[test]
    fn mounted_volume_dismount_is_terminal_and_cleanup_can_release_lock() {
        let mut owner_file = wdk_sys::FILE_OBJECT::default();
        let mut competing_file = wdk_sys::FILE_OBJECT::default();
        let Some(owner) = KernelFileObject::from_raw(core::ptr::addr_of_mut!(owner_file)) else {
            return;
        };
        let Some(competing) = KernelFileObject::from_raw(core::ptr::addr_of_mut!(competing_file))
        else {
            return;
        };

        let dismounted = MountedVolumeState::Locked { owner }.dismount(owner);
        assert_eq!(
            dismounted,
            Ok(MountedVolumeState::Dismounted {
                lock_owner: Some(owner)
            })
        );
        let Ok(dismounted) = dismounted else {
            return;
        };
        assert_eq!(
            dismounted.ensure_mounted(),
            Err(DriverError::VolumeDismounted)
        );
        assert_eq!(
            dismounted.authorize_handle(owner),
            Err(DriverError::VolumeDismounted)
        );
        assert_eq!(
            dismounted.dismount(owner),
            Err(DriverError::VolumeDismounted)
        );
        assert_eq!(dismounted.unlock(competing), Err(DriverError::NotLocked));
        assert_eq!(
            dismounted.cleanup(competing),
            (dismounted, VolumeHandleCleanup::Released)
        );
        assert_eq!(
            dismounted.cleanup(owner),
            (
                MountedVolumeState::Dismounted { lock_owner: None },
                VolumeHandleCleanup::Unlocked
            )
        );
    }

    /// # Panics
    ///
    /// Panics when physical retirement starts before every FILE_OBJECT is gone.
    #[test]
    fn dismounted_volume_retires_only_after_all_file_objects_close() {
        let dismounted = MountedVolumeState::Dismounted { lock_owner: None };
        assert_eq!(
            dismounted.retire_if_unreferenced(false, 0),
            (dismounted, VolumeRetirement::Retained)
        );
        assert_eq!(
            dismounted.retire_if_unreferenced(true, 1),
            (dismounted, VolumeRetirement::Retained)
        );
        assert_eq!(
            dismounted.retire_if_unreferenced(true, 0),
            (MountedVolumeState::Retiring, VolumeRetirement::Start)
        );
        assert_eq!(
            MountedVolumeState::Mounted.retire_if_unreferenced(true, 0),
            (MountedVolumeState::Mounted, VolumeRetirement::Retained)
        );
    }

    /// Runs one decoder against a FILE_OBJECT whose lifetime is owned by an active test IRP.
    /// # Errors
    ///
    /// Returns an error when the test IRP boundary or `operation` rejects the FILE_OBJECT.
    fn with_active_file_object<R>(
        file: &mut wdk_sys::FILE_OBJECT,
        operation: impl for<'view> FnOnce(ActiveFileObject<'view>) -> Result<R, DriverError>,
    ) -> Result<R, DriverError> {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: core::ptr::from_mut(file),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let mut irp = wdk_sys::IRP::default();
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::from_mut(&mut stack);
        let mut received = ReceivedIrp::decode(
            core::ptr::from_mut(&mut device),
            core::ptr::from_mut(&mut irp),
        )?;
        received.with_active(|active| operation(active.current_stack()?.file_object()?))
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
    /// Panics when a device extension discriminant decodes to the wrong teardown owner.
    #[test]
    fn driver_device_kinds_select_exact_teardown_owners() {
        assert_eq!(
            DriverDeviceKind::decode(DeviceExtensionKind::CONTROL),
            Ok(DriverDeviceKind::Control)
        );
        assert_eq!(
            DriverDeviceKind::decode(DeviceExtensionKind::MOUNTED_VOLUME),
            Ok(DriverDeviceKind::MountedVolume)
        );
        assert_eq!(
            DriverDeviceKind::decode(DeviceExtensionKind { value: u8::MAX }),
            Err(DriverError::InternalInvariantViolation)
        );
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

        assert_eq!(
            with_active_file_object(&mut file, |file_object| {
                OpenedObject::decode(file_object).map(|_| ())
            })
            .err(),
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
            retained_handle_deletion(),
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let result = with_active_file_object(&mut file, |file_object| {
            let mut directory = OpenedDirectory::decode(file_object)?;
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
            Ok(())
        });
        assert_eq!(result, Ok(()));
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
            retained_handle_deletion(),
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let result = with_active_file_object(&mut file, |file_object| {
            let mut directory = OpenedDirectory::decode(file_object)?;
            let first = directory.notification_directory_name()?;
            let second = directory.notification_directory_name();
            assert_eq!(second, Ok(first));
            let descriptor = unsafe {
                // SAFETY: The descriptor is owned by the live CCB and the test
                // has not executed its cleanup or close transition.
                first.as_ref()
            };
            assert_eq!(descriptor.Length, descriptor.MaximumLength);
            assert!(!descriptor.Buffer.is_null());
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when a namespace change does not preserve its synthetic parent/name boundary.
    #[test]
    fn directory_change_encodes_the_child_boundary_and_action() {
        let name = Ext4Name::new(b"child");
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let change = DirectoryChange::new(
            DirectoryNodeId::ROOT,
            &name,
            NodeId::Directory(DirectoryNodeId::ROOT),
            DirectoryChangeAction::Added,
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
    /// Panics when in-place hard-link replacement loses its metadata notification contract.
    #[test]
    fn hard_link_replacement_reports_modified_metadata_filters() {
        let name = Ext4Name::new(b"child");
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let change = DirectoryChange::hard_link_replaced(DirectoryNodeId::ROOT, &name);
        assert!(change.is_ok());
        let Ok(change) = change else {
            return;
        };
        assert_eq!(change.action.as_ulong(), wdk_sys::FILE_ACTION_MODIFIED);
        assert_ne!(
            change.completion_filter & wdk_sys::FILE_NOTIFY_CHANGE_ATTRIBUTES,
            0
        );
        assert_ne!(
            change.completion_filter & wdk_sys::FILE_NOTIFY_CHANGE_SECURITY,
            0
        );
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
            retained_handle_deletion(),
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        assert_eq!(
            with_active_file_object(&mut file, |file_object| {
                OpenedRegularFile::decode(file_object).map(|_| ())
            })
            .err(),
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
            retained_handle_deletion(),
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        assert_eq!(
            with_active_file_object(&mut file, |file_object| {
                OpenedDirectory::decode(file_object).map(|_| ())
            })
            .err(),
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
            retained_handle_deletion(),
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
            retained_handle_deletion(),
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
            retained_handle_deletion(),
            WriteCommitment::FlushThrough,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let result = with_active_file_object(&mut file, |file_object| {
            let opened = OpenedObject::decode(file_object)?;
            assert_eq!(opened.write_commitment(), WriteCommitment::FlushThrough);
            Ok(())
        });
        assert_eq!(result, Ok(()));
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
            retained_handle_deletion(),
            WriteCommitment::CommitOnly,
            DataTransferMode::NoIntermediate(transfer),
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let result = with_active_file_object(&mut file, |file_object| {
            let opened = OpenedObject::decode(file_object)?;
            assert_eq!(
                opened.data_transfer_mode(),
                DataTransferMode::NoIntermediate(transfer)
            );
            Ok(())
        });
        assert_eq!(result, Ok(()));
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
            retained_handle_deletion(),
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
        let result = with_active_file_object(&mut file, |file_object| {
            let mut opened = OpenedObject::decode(file_object)?;
            assert_eq!(
                opened.current_file_position(),
                Ok(FileOffset::from_bytes(11))
            );
            assert_eq!(
                opened.set_current_file_position(FileOffset::from_bytes(32)),
                Ok(())
            );
            assert_eq!(
                opened.update_current_file_position(
                    DataIoKind::Handle,
                    FileOffset::from_bytes(100),
                    0,
                ),
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
            Ok(())
        });
        assert_eq!(result, Ok(()));
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
                    retained_handle_deletion(),
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
            retained_handle_deletion(),
            WriteCommitment::CommitOnly,
            DataTransferMode::IntermediateAllowed,
            RegularFileWriteAccess::Denied,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        file.CurrentByteOffset = wdk_sys::LARGE_INTEGER { QuadPart: 7 };
        let asynchronous = with_active_file_object(&mut file, |file_object| {
            let mut opened = OpenedObject::decode(file_object)?;
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
            Ok(())
        });
        assert_eq!(asynchronous, Ok(()));
        file.Flags = wdk_sys::FO_SYNCHRONOUS_IO;
        let paging = with_active_file_object(&mut file, |file_object| {
            let mut opened = OpenedObject::decode(file_object)?;
            assert_eq!(
                opened.update_current_file_position(
                    DataIoKind::Paging,
                    FileOffset::from_bytes(100),
                    23,
                ),
                Ok(())
            );
            Ok(())
        });
        assert_eq!(paging, Ok(()));
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
            retained_handle_deletion(),
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
        let result = with_active_file_object(&mut file, |file_object| {
            let mut opened = OpenedObject::decode(file_object)?;
            assert_eq!(
                opened.current_file_position(),
                Err(DriverError::InvalidParameter)
            );
            assert_eq!(
                opened.set_current_file_position(FileOffset::from_bytes(u64::MAX)),
                Err(DriverError::InvalidParameter)
            );
            Ok(())
        });
        assert_eq!(result, Ok(()));
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
        assert!(
            with_active_file_object(&mut file, |file_object| {
                UninitializedFileObject::decode(file_object).map(|_| ())
            })
            .is_ok()
        );

        let mut file = file_object_with_contexts(
            NonNull::<FileControlBlock>::dangling().as_ptr().cast(),
            core::ptr::null_mut(),
        );
        assert_eq!(
            with_active_file_object(&mut file, |file_object| {
                UninitializedFileObject::decode(file_object).map(|_| ())
            }),
            Err(DriverError::InvalidParameter)
        );

        let mut file = file_object_with_contexts(
            core::ptr::null_mut(),
            NonNull::<super::OpenedHandle>::dangling().as_ptr().cast(),
        );
        assert_eq!(
            with_active_file_object(&mut file, |file_object| {
                UninitializedFileObject::decode(file_object).map(|_| ())
            }),
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

    /// # Panics
    ///
    /// Panics when ordinary namespace replacement can unlink an actively referenced inode.
    #[test]
    fn namespace_replacement_requires_no_active_handles() {
        let mut state = FileControlBlockOpenState::new();
        assert_eq!(state.ensure_namespace_replaceable(), Ok(()));

        state.share_access.OpenCount = 2;
        state.share_access.SharedDelete = 2;
        assert_eq!(
            state.ensure_namespace_replaceable(),
            Err(DriverError::ShareAccessConflict)
        );

        state.share_access.OpenCount = 0;
        assert_eq!(state.ensure_namespace_replaceable(), Ok(()));
    }

    /// # Panics
    ///
    /// Panics when the shared FCB deletion state permits reopen or deletes before final cleanup.
    #[test]
    fn file_deletion_state_is_shared_and_waits_for_final_active_cleanup() {
        let name = Ext4Name::new(b"pending");
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let location = OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &name);
        assert!(location.is_ok());
        let Ok(location) = location else {
            return;
        };
        let pending = super::PendingFileDeletion::try_from_disposition(&location);
        assert!(pending.is_ok());
        let Ok(pending) = pending else {
            return;
        };
        let target = pending.target();
        let mut state = FileControlBlockOpenState::new();

        assert_eq!(state.deletion.ensure_openable(), Ok(()));
        assert!(!state.delete_pending());
        assert!(state.set_delete_pending(pending).is_none());
        assert_eq!(
            state.deletion.ensure_openable(),
            Err(DriverError::DeletePending)
        );
        state.share_access.OpenCount = 1;
        assert_eq!(
            state.cleanup_disposition(),
            super::FileCleanupDisposition::Retained
        );
        state.share_access.OpenCount = 0;
        assert_eq!(
            state.cleanup_disposition(),
            super::FileCleanupDisposition::Delete(target)
        );

        let completed = state.complete_delete(target);
        assert_eq!(completed.target(), target);
        assert!(state.delete_pending());
        assert_eq!(
            state.deletion.ensure_openable(),
            Err(DriverError::DeletePending)
        );
    }

    /// # Panics
    ///
    /// Panics when the CCB deletion domain can represent unauthorized delete-on-close.
    #[test]
    fn handle_deletion_requires_delete_authority_for_delete_on_close() {
        assert_eq!(
            HandleDeletion::from_create(
                CreateDeletion::DeleteOnClose,
                DeleteAccess::Denied,
                FileAttributesWriteAccess::Denied,
            ),
            Err(DriverError::AccessDenied)
        );
        assert_eq!(
            HandleDeletion::from_create(
                CreateDeletion::DeleteOnClose,
                DeleteAccess::Granted,
                FileAttributesWriteAccess::Granted,
            ),
            Ok(HandleDeletion::DeleteOnClose {
                file_attributes_write_access: FileAttributesWriteAccess::Granted,
            })
        );
        assert_eq!(
            HandleDeletion::from_create(
                CreateDeletion::Retain,
                DeleteAccess::Denied,
                FileAttributesWriteAccess::Granted,
            ),
            Ok(HandleDeletion::Retain {
                delete_access: DeleteAccess::Denied,
                file_attributes_write_access: FileAttributesWriteAccess::Granted,
            })
        );
    }

    /// # Panics
    ///
    /// Panics when cancellation or non-directory-entry deletion targets become ambiguous.
    #[test]
    fn pending_file_deletion_cancels_only_before_commit_and_requires_a_link() {
        assert_eq!(
            super::PendingFileDeletion::try_from_disposition(&OpenedLocation::Root),
            Err(DriverError::CannotDelete)
        );
        assert_eq!(
            super::PendingFileDeletion::try_from_disposition(&OpenedLocation::FileReference),
            Err(DriverError::CannotDelete)
        );

        let name = Ext4Name::new(b"cancel");
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let location = OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &name);
        assert!(location.is_ok());
        let Ok(location) = location else {
            return;
        };
        let pending = super::PendingFileDeletion::try_from_disposition(&location);
        assert!(pending.is_ok());
        let Ok(pending) = pending else {
            return;
        };
        let mut state = FileControlBlockOpenState::new();
        assert!(state.set_delete_pending(pending).is_none());
        assert!(state.clear_delete_pending().is_some());
        assert_eq!(state.deletion.ensure_openable(), Ok(()));
        assert!(!state.delete_pending());
    }

    /// # Panics
    ///
    /// Panics when a mandatory create-time delete target can be cancelled or replaced by a normal
    /// disposition request.
    #[test]
    fn delete_on_close_pending_cannot_be_cancelled_or_replaced() {
        let mandatory_name = Ext4Name::new(b"mandatory");
        assert!(mandatory_name.is_ok());
        let Ok(mandatory_name) = mandatory_name else {
            return;
        };
        let mandatory_location =
            OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &mandatory_name);
        assert!(mandatory_location.is_ok());
        let Ok(mandatory_location) = mandatory_location else {
            return;
        };
        let mandatory = super::PendingFileDeletion::try_from_delete_on_close(&mandatory_location);
        assert!(mandatory.is_ok());
        let Ok(mandatory) = mandatory else {
            return;
        };
        let mandatory_target = mandatory.target();

        let replacement_name = Ext4Name::new(b"replacement");
        assert!(replacement_name.is_ok());
        let Ok(replacement_name) = replacement_name else {
            return;
        };
        let replacement_location =
            OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &replacement_name);
        assert!(replacement_location.is_ok());
        let Ok(replacement_location) = replacement_location else {
            return;
        };
        let replacement = super::PendingFileDeletion::try_from_disposition(&replacement_location);
        assert!(replacement.is_ok());
        let Ok(replacement) = replacement else {
            return;
        };
        let replacement_target = replacement.target();

        let mut state = FileControlBlockOpenState::new();
        assert!(state.set_delete_pending(mandatory).is_none());
        assert!(state.clear_delete_pending().is_none());
        assert_eq!(
            state.cleanup_disposition(),
            super::FileCleanupDisposition::Delete(mandatory_target)
        );
        let displaced = state.set_delete_pending(replacement);
        assert!(displaced.is_some());
        let Some(displaced) = displaced else {
            return;
        };
        assert_eq!(displaced.target(), replacement_target);
        assert_eq!(
            state.cleanup_disposition(),
            super::FileCleanupDisposition::Delete(mandatory_target)
        );
    }
}
