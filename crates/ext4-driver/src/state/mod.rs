//! Driver-local lifecycle and open-object state.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::num::NonZeroU32;
use core::ptr::NonNull;

use ext4_core::{
    DeviceLength, DirectoryNodeId, Ext4Name, FscryptKeyIdentifier, FscryptKeyPresence,
    FscryptKeySet, FscryptMasterKey, JournaledVolume, MountContext, NodeId, Result as Ext4Result,
};
use wdk_sys::{
    DO_DEVICE_INITIALIZING, DO_DIRECT_IO, FILE_OBJECT, PDEVICE_OBJECT, PDRIVER_OBJECT,
    SHARE_ACCESS, STATUS_SUCCESS, VPB_MOUNTED,
};

use crate::irp::{DesiredAccess, DirectoryEntryIndex, ShareAccess};
use crate::kernel::cng::CngFscryptNonceGenerator;
use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::{block_device::KernelBlockDevice, ffi};

/// Registered control device observed by the unload callback.
static mut CONTROL_DEVICE: Option<ControlDevice> = None;

/// Non-null kernel device object pointer at the WDK boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelDevice {
    /// Non-null opaque WDK device pointer.
    device: NonNull<c_void>,
}

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
}

/// Non-null kernel file object pointer at the WDK boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelFileObject {
    /// Non-null opaque WDK file object pointer.
    file_object: NonNull<FILE_OBJECT>,
}

impl KernelFileObject {
    /// Converts a raw WDK file object pointer into the non-null boundary type.
    pub(crate) fn from_raw(file_object: *mut FILE_OBJECT) -> Option<Self> {
        NonNull::new(file_object).map(|file_object| Self { file_object })
    }

    /// Returns an immutable WDK file object reference.
    pub(crate) unsafe fn as_ref<'a>(self) -> &'a FILE_OBJECT {
        unsafe {
            // SAFETY: The caller ties the returned reference to the active WDK
            // callback lifetime that supplied this non-null FILE_OBJECT.
            self.file_object.as_ref()
        }
    }

    /// Returns a mutable WDK file object reference.
    pub(crate) unsafe fn as_mut<'a>(mut self) -> &'a mut FILE_OBJECT {
        unsafe {
            // SAFETY: The caller owns the active mutation point for this
            // FILE_OBJECT during the current dispatch callback.
            self.file_object.as_mut()
        }
    }

    /// Returns the raw WDK pointer for FFI calls that require FILE_OBJECT.
    fn as_ptr(self) -> *mut FILE_OBJECT {
        self.file_object.as_ptr()
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
    pub(crate) unsafe fn as_ref<'a>(self) -> &'a FILE_OBJECT {
        unsafe {
            // SAFETY: The caller ties the returned reference to the active
            // create dispatch lifetime that supplied this FILE_OBJECT.
            self.file_object.as_ref()
        }
    }

    /// Returns a mutable WDK FILE_OBJECT reference.
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

/// Non-null security descriptor pointer supplied by the I/O Manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelSecurityDescriptor {
    /// Non-null opaque security descriptor pointer.
    descriptor: NonNull<c_void>,
}

impl KernelSecurityDescriptor {
    /// Converts a raw WDK security descriptor pointer into the non-null boundary type.
    pub(crate) fn from_raw(descriptor: *mut c_void) -> Option<Self> {
        NonNull::new(descriptor).map(|descriptor| Self { descriptor })
    }

    /// Returns an immutable descriptor reference as an opaque pointer.
    pub(crate) const fn as_non_null(self) -> NonNull<c_void> {
        self.descriptor
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
    pub(crate) fn registered(device: PDEVICE_OBJECT) -> Option<Self> {
        KernelDevice::from_raw(device).map(|device| Self { device })
    }

    /// Returns the raw WDK device pointer for FFI calls.
    pub(crate) fn as_ptr(self) -> PDEVICE_OBJECT {
        self.device.as_ptr()
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
    /// Mounted journaled read-write ext4 volume.
    volume: JournaledVolume<KernelBlockDevice, CngFscryptNonceGenerator>,
    /// VCB-owned FCBs keyed by ext4 node identity.
    file_control_blocks: Vec<NonNull<FileControlBlock>>,
}

impl VolumeControlBlock {
    /// Mounts a journaled read-write ext4 VCB.
    pub(crate) fn mount_journaled(
        target_device: KernelDevice,
        length: DeviceLength,
    ) -> Ext4Result<Self> {
        let block_device = KernelBlockDevice::new(target_device, length);
        let volume = JournaledVolume::<_, CngFscryptNonceGenerator>::mount(
            block_device,
            MountContext::new(FscryptKeySet::empty(), CngFscryptNonceGenerator),
        )?;
        Ok(Self {
            volume,
            file_control_blocks: Vec::new(),
        })
    }

    /// Returns a stable serial number derived from the ext4 filesystem UUID.
    pub(crate) fn serial_number(&self) -> VolumeSerialNumber {
        let uuid = self.volume.identity().uuid().bytes();
        let [a, b, c, d, ..] = uuid;
        VolumeSerialNumber::from_le_bytes([a, b, c, d])
    }

    /// Returns the mounted ext4 volume.
    pub(crate) const fn volume(
        &self,
    ) -> &JournaledVolume<KernelBlockDevice, CngFscryptNonceGenerator> {
        &self.volume
    }

    /// Returns the mounted ext4 volume for journaled mutation.
    pub(crate) const fn volume_mut(
        &mut self,
    ) -> &mut JournaledVolume<KernelBlockDevice, CngFscryptNonceGenerator> {
        &mut self.volume
    }

    /// Returns the mounted ext4 volume label.
    pub(crate) fn volume_label(&self) -> ext4_core::Ext4VolumeLabel {
        self.volume.identity().label()
    }

    /// Adds one fscrypt master key to the mounted volume.
    pub(crate) fn add_fscrypt_key(&mut self, key: FscryptMasterKey) -> Ext4Result<()> {
        self.volume.add_fscrypt_key(key)
    }

    /// Removes one fscrypt master key from the mounted volume.
    pub(crate) fn remove_fscrypt_key(
        &mut self,
        identifier: FscryptKeyIdentifier,
    ) -> Option<FscryptMasterKey> {
        self.volume.remove_fscrypt_key(identifier)
    }

    /// Returns the mounted volume's fscrypt key presence for one identifier.
    pub(crate) fn fscrypt_key_presence(
        &self,
        identifier: FscryptKeyIdentifier,
    ) -> FscryptKeyPresence {
        self.volume.fscrypt_key_presence(identifier)
    }

    /// Opens or reuses the VCB-owned FCB for a node.
    pub(crate) fn open_file_control_block(
        mut volume: NonNull<Self>,
        node: NodeId,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        let vcb = unsafe {
            // SAFETY: The caller passes a live mounted VCB pointer from the
            // mounted device extension while processing create/open.
            volume.as_mut()
        };
        if let Some(mut fcb) = vcb.find_file_control_block(node) {
            let fcb_ref = unsafe {
                // SAFETY: FCB pointers in the table are Box allocations owned
                // by this VCB and remain valid until their open count reaches
                // zero in `close_file_control_block`.
                fcb.as_mut()
            };
            fcb_ref.add_open_reference()?;
            return Ok(fcb);
        }

        let fcb = Box::new(FileControlBlock::new(volume, node));
        let fcb = NonNull::from(Box::leak(fcb));
        vcb.file_control_blocks.push(fcb);
        Ok(fcb)
    }

    /// Releases one open reference to a VCB-owned FCB.
    fn close_file_control_block(&mut self, fcb: NonNull<FileControlBlock>) {
        let Some(index) = self
            .file_control_blocks
            .iter()
            .position(|candidate| *candidate == fcb)
        else {
            return;
        };
        let mut fcb = fcb;
        let fcb_ref = unsafe {
            // SAFETY: The FCB was found in this VCB's ownership table.
            fcb.as_mut()
        };
        match fcb_ref.release_open_reference() {
            FileControlBlockRelease::StillOpen => {}
            FileControlBlockRelease::LastReference => {
                let removed = self.file_control_blocks.swap_remove(index);
                unsafe {
                    // SAFETY: The pointer was removed from the ownership table
                    // exactly once and no open FILE_OBJECT should reference it
                    // after the last close.
                    drop(Box::from_raw(removed.as_ptr()));
                }
            }
        }
    }

    /// Finds a VCB-owned FCB by node identity.
    fn find_file_control_block(&mut self, node: NodeId) -> Option<NonNull<FileControlBlock>> {
        self.file_control_blocks.iter().copied().find(|fcb| {
            let fcb = unsafe {
                // SAFETY: FCB pointers in this table are owned by the VCB.
                fcb.as_ref()
            };
            fcb.node() == node
        })
    }
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

impl Drop for VolumeControlBlock {
    fn drop(&mut self) {
        for fcb in self.file_control_blocks.drain(..) {
            unsafe {
                // SAFETY: Remaining FCB pointers are still owned by this VCB
                // during volume teardown.
                drop(Box::from_raw(fcb.as_ptr()));
            }
        }
    }
}

/// Device extension stored in mounted volume device objects.
#[repr(C)]
pub(crate) struct MountedVolumeDeviceExtension {
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
    pub(crate) fn initialize(
        device: PDEVICE_OBJECT,
        vcb: Box<VolumeControlBlock>,
        vpb: NonNull<wdk_sys::VPB>,
        real_device: KernelDevice,
    ) -> DriverResult<Self> {
        let device = KernelDevice::from_raw(device).ok_or(DriverError::InvalidParameter)?;
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
        Self::initialize_device_object(device, vpb, real_device)?;
        extension.vcb = Box::into_raw(vcb);
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
        let extension = unsafe {
            // SAFETY: Mounted volume devices created by this driver store a
            // MountedVolumeDeviceExtension in DeviceExtension. Null or foreign
            // extensions are rejected by the following pointer checks.
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
                .as_ref()
        }?;
        NonNull::new(extension.vcb)
    }

    /// Initializes DEVICE_OBJECT and VPB fields after a successful core mount.
    fn initialize_device_object(
        device: KernelDevice,
        mut vpb: NonNull<wdk_sys::VPB>,
        real_device: KernelDevice,
    ) -> DriverResult<()> {
        let device_object = unsafe {
            // SAFETY: The mounted device object was created by this driver and
            // remains valid during mount initialization.
            device.as_ptr().as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        device_object.Vpb = vpb.as_ptr();
        device_object.Flags |= DO_DIRECT_IO;
        device_object.Flags &= !DO_DEVICE_INITIALIZING;
        device_object.StackSize = real_device
            .stack_size()
            .ok_or(DriverError::InvalidParameter)?
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;

        let vpb = unsafe {
            // SAFETY: The VPB was supplied by the I/O Manager for this mount
            // request and is writable during successful mount completion.
            vpb.as_mut()
        };
        vpb.DeviceObject = device.as_ptr();
        vpb.RealDevice = real_device.as_ptr();
        vpb.Flags |= u16::try_from(VPB_MOUNTED).map_err(|_| DriverError::InvalidParameter)?;
        Ok(())
    }

    /// Copies VCB-derived identity fields into the VPB.
    pub(crate) fn initialize_vpb_identity(
        vpb: NonNull<wdk_sys::VPB>,
        vcb: &VolumeControlBlock,
    ) -> DriverResult<()> {
        let vpb = unsafe {
            // SAFETY: The VPB belongs to the active mount request and remains
            // writable until the mount IRP is completed.
            vpb.as_ptr().as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        vpb.SerialNumber = vcb.serial_number().as_u32();
        write_vpb_label(vpb, vcb.volume_label())
    }

    /// Refreshes the VPB volume label after a successful label mutation.
    pub(crate) fn refresh_vpb_label(
        device: KernelDevice,
        vcb: &VolumeControlBlock,
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
        write_vpb_label(vpb, vcb.volume_label())
    }
}

/// Writes an ext4 label into the UTF-16 VPB label field using one code unit per
/// ext4 label byte.
fn write_vpb_label(vpb: &mut wdk_sys::VPB, label: ext4_core::Ext4VolumeLabel) -> DriverResult<()> {
    vpb.VolumeLabel.fill(0);
    let bytes = label.bytes();
    if bytes.len() > vpb.VolumeLabel.len() {
        return Err(DriverError::InvalidParameter);
    }
    for (index, byte) in bytes.iter().enumerate() {
        *vpb.VolumeLabel
            .get_mut(index)
            .ok_or(DriverError::InvalidParameter)? = u16::from(*byte);
    }
    let wchar_bytes = bytes
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)?;
    vpb.VolumeLabelLength =
        u16::try_from(wchar_bytes).map_err(|_| DriverError::InvalidParameter)?;
    Ok(())
}

#[derive(Debug)]
/// File control block stored in `FILE_OBJECT::FsContext`.
pub(crate) struct FileControlBlock {
    /// Mounted volume that owns this file.
    volume: NonNull<VolumeControlBlock>,
    /// Ext4 node opened by this FCB.
    node: NodeId,
    /// I/O manager share-access accounting for this inode identity.
    share_access: SHARE_ACCESS,
    /// Number of open FILE_OBJECTs currently referencing this FCB.
    open_count: NonZeroU32,
}

impl FileControlBlock {
    /// Creates an FCB boundary value for a mounted node with one open reference.
    pub(crate) const fn new(volume: NonNull<VolumeControlBlock>, node: NodeId) -> Self {
        Self {
            volume,
            node,
            share_access: SHARE_ACCESS {
                OpenCount: 0,
                Readers: 0,
                Writers: 0,
                Deleters: 0,
                SharedRead: 0,
                SharedWrite: 0,
                SharedDelete: 0,
            },
            open_count: NonZeroU32::MIN,
        }
    }

    /// Returns the mounted VCB pointer that owns this open node.
    pub(crate) const fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.volume
    }

    /// Returns the ext4 node identity opened by this FCB.
    pub(crate) const fn node(&self) -> NodeId {
        self.node
    }

    /// Replaces the ext4 node identity after an in-place namespace conversion.
    pub(crate) fn replace_node(&mut self, node: NodeId) {
        self.node = node;
    }

    /// Checks and records one FILE_OBJECT's share-access claim.
    pub(crate) fn check_share_access(
        &mut self,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        share_access: ShareAccess,
    ) -> DriverResult<()> {
        let status = unsafe {
            // SAFETY: The FCB owns this SHARE_ACCESS record for the opened
            // inode identity, and FILE_OBJECT is the active create target.
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
    pub(crate) fn remove_share_access(&mut self, file_object: KernelFileObject) {
        unsafe {
            // SAFETY: Successful create recorded this FILE_OBJECT against this
            // FCB-owned SHARE_ACCESS, and close is the unique removal point.
            ffi::IoRemoveShareAccess(
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.share_access),
            );
        }
    }

    /// Adds one FILE_OBJECT reference to an already-open FCB.
    fn add_open_reference(&mut self) -> DriverResult<()> {
        let count = self
            .open_count
            .get()
            .checked_add(1)
            .and_then(NonZeroU32::new)
            .ok_or(DriverError::TooManyOpenReferences)?;
        self.open_count = count;
        Ok(())
    }

    /// Releases one FILE_OBJECT reference from a non-empty FCB.
    fn release_open_reference(&mut self) -> FileControlBlockRelease {
        let Some(remaining) = self
            .open_count
            .get()
            .checked_sub(1)
            .and_then(NonZeroU32::new)
        else {
            return FileControlBlockRelease::LastReference;
        };
        self.open_count = remaining;
        FileControlBlockRelease::StillOpen
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

#[derive(Clone, Debug, Eq, PartialEq)]
/// Opened path identity stored with a handle.
pub(crate) enum OpenedPath {
    /// Mounted volume root.
    Root,
    /// Child entry under a parent directory.
    Child {
        /// Parent directory inode.
        parent: DirectoryNodeId,
        /// Exact ext4 directory entry name.
        name: Ext4Name,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Action requested when the last handle cleanup occurs.
pub(crate) enum CloseDisposition {
    /// Keep the opened object.
    Keep,
    /// Delete the opened object during cleanup.
    Delete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Per-handle state stored in `FILE_OBJECT::FsContext2`.
pub(crate) enum OpenedHandle {
    /// Regular file handle.
    File {
        /// Path used for namespace mutations on cleanup.
        path: OpenedPath,
        /// Requested close disposition.
        close_disposition: CloseDisposition,
    },
    /// Directory handle with enumeration cursor.
    Directory {
        /// Directory enumeration cursor.
        cursor: DirectoryCursor,
        /// Path used for namespace mutations on cleanup.
        path: OpenedPath,
        /// Requested close disposition.
        close_disposition: CloseDisposition,
    },
    /// Symlink handle.
    Symlink {
        /// Path used for namespace mutations on cleanup.
        path: OpenedPath,
        /// Requested close disposition.
        close_disposition: CloseDisposition,
    },
}

impl OpenedHandle {
    /// Creates per-handle state for an opened node.
    pub(crate) fn new(node: NodeId, path: OpenedPath) -> Self {
        Self::from_parts(node, path, CloseDisposition::Keep)
    }

    /// Creates per-handle state from explicit lifecycle fields.
    fn from_parts(node: NodeId, path: OpenedPath, close_disposition: CloseDisposition) -> Self {
        match node {
            NodeId::File(_) => Self::File {
                path,
                close_disposition,
            },
            NodeId::Directory(_) => Self::Directory {
                cursor: DirectoryCursor::start(),
                path,
                close_disposition,
            },
            NodeId::Symlink(_) => Self::Symlink {
                path,
                close_disposition,
            },
        }
    }

    /// Returns the mutable directory cursor when this handle opened a directory.
    pub(crate) fn directory_cursor_mut(&mut self) -> Option<&mut DirectoryCursor> {
        match self {
            Self::Directory { cursor, .. } => Some(cursor),
            Self::File { .. } | Self::Symlink { .. } => None,
        }
    }

    /// Marks the handle for delete-on-close cleanup.
    pub(crate) fn mark_delete_on_close(&mut self) {
        *self.close_disposition_mut() = CloseDisposition::Delete;
    }

    /// Clears a delete-on-close request for this handle.
    pub(crate) fn keep_on_close(&mut self) {
        *self.close_disposition_mut() = CloseDisposition::Keep;
    }

    /// Returns the requested close disposition.
    pub(crate) const fn close_disposition(&self) -> CloseDisposition {
        match self {
            Self::File {
                close_disposition, ..
            }
            | Self::Directory {
                close_disposition, ..
            }
            | Self::Symlink {
                close_disposition, ..
            } => *close_disposition,
        }
    }

    /// Returns the opened path identity.
    pub(crate) const fn path(&self) -> &OpenedPath {
        match self {
            Self::File { path, .. } | Self::Directory { path, .. } | Self::Symlink { path, .. } => {
                path
            }
        }
    }

    /// Replaces the opened path after a successful rename.
    pub(crate) fn replace_path(&mut self, path: OpenedPath) {
        *self.path_mut() = path;
    }

    /// Replaces handle-local node state after an in-place namespace conversion.
    pub(crate) fn replace_node(&mut self, node: NodeId) {
        let path = self.path().clone();
        let close_disposition = self.close_disposition();
        *self = Self::from_parts(node, path, close_disposition);
    }

    /// Returns the mutable close disposition field for this handle variant.
    fn close_disposition_mut(&mut self) -> &mut CloseDisposition {
        match self {
            Self::File {
                close_disposition, ..
            }
            | Self::Directory {
                close_disposition, ..
            }
            | Self::Symlink {
                close_disposition, ..
            } => close_disposition,
        }
    }

    /// Returns the mutable opened path field for this handle variant.
    fn path_mut(&mut self) -> &mut OpenedPath {
        match self {
            Self::File { path, .. } | Self::Directory { path, .. } | Self::Symlink { path, .. } => {
                path
            }
        }
    }
}

/// FILE_OBJECT whose FCB and CCB contexts have both been initialized by create.
#[derive(Debug)]
pub(crate) struct OpenedFileObject {
    /// Kernel FILE_OBJECT carrying the contexts.
    file_object: KernelFileObject,
    /// Shared file control block stored in FsContext.
    fcb: NonNull<FileControlBlock>,
    /// Per-handle context stored in FsContext2.
    handle: NonNull<OpenedHandle>,
}

impl OpenedFileObject {
    /// Decodes an initialized FILE_OBJECT context pair.
    pub(crate) fn decode(file_object: KernelFileObject) -> DriverResult<Self> {
        let object = unsafe {
            // SAFETY: The FILE_OBJECT pointer comes from the active IRP stack
            // and is read only for filesystem-owned context pointers.
            file_object.as_ref()
        };
        let fcb = NonNull::new(object.FsContext.cast::<FileControlBlock>())
            .ok_or(DriverError::InvalidParameter)?;
        let handle = NonNull::new(object.FsContext2.cast::<OpenedHandle>())
            .ok_or(DriverError::InvalidParameter)?;
        Ok(Self {
            file_object,
            fcb,
            handle,
        })
    }

    /// Returns the kernel FILE_OBJECT associated with this opened handle.
    pub(crate) const fn file_object(&self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the mounted VCB pointer owning this opened node.
    pub(crate) fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.file_control_block().volume()
    }

    /// Returns the ext4 node identity opened by this FILE_OBJECT.
    pub(crate) fn node(&self) -> NodeId {
        self.file_control_block().node()
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

    /// Returns mutable decoded file control block state for the active dispatch.
    pub(crate) fn file_control_block_mut(&mut self) -> &mut FileControlBlock {
        unsafe {
            // SAFETY: Mutating FCB-local identity is limited to the active
            // synchronous dispatch path that owns `&mut self`.
            self.fcb.as_mut()
        }
    }

    /// Returns the decoded per-handle state.
    pub(crate) fn handle(&self) -> &OpenedHandle {
        unsafe {
            // SAFETY: `decode` only constructs this type from a non-null
            // FsContext2 written by successful create and used during the
            // active FILE_OBJECT lifetime.
            self.handle.as_ref()
        }
    }

    /// Returns mutable per-handle state for the active dispatch.
    pub(crate) fn handle_mut(&mut self) -> &mut OpenedHandle {
        unsafe {
            // SAFETY: Mutating handle-local state is serialized by the active
            // synchronous dispatch path that owns `&mut self`.
            self.handle.as_mut()
        }
    }
}

/// Releases one FILE_OBJECT reference to a VCB-owned FCB.
pub(crate) fn release_file_control_block(fcb: NonNull<FileControlBlock>) {
    let mut volume = unsafe {
        // SAFETY: FCBs are owned by the VCB recorded in the FCB itself.
        fcb.as_ref().volume()
    };
    let vcb = unsafe {
        // SAFETY: The VCB outlives all FCBs it owns.
        volume.as_mut()
    };
    vcb.close_file_control_block(fcb);
}

/// Driver unload callback registered in the driver object.
pub(crate) unsafe extern "C" fn driver_unload(_driver: PDRIVER_OBJECT) {
    let control_device = core::ptr::addr_of_mut!(CONTROL_DEVICE);
    let device = unsafe {
        // SAFETY: `control_device` points to the driver-owned global state.
        // Replacement takes ownership of the registered device for teardown.
        core::ptr::replace(control_device, None)
    };
    if let Some(device) = device {
        let device = device.as_ptr();
        unsafe {
            // SAFETY: The device was created and registered by DriverEntry.
            ffi::IoUnregisterFileSystem(device);
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

    use ext4_core::{DirectoryNodeId, NodeId};

    use crate::kernel::status::DriverError;

    use super::{
        FileControlBlock, FileControlBlockRelease, KernelFileObject, OpenedFileObject,
        UninitializedFileObject, VolumeControlBlock,
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

    #[test]
    fn kernel_file_object_rejects_null_raw_pointer() {
        assert_eq!(KernelFileObject::from_raw(core::ptr::null_mut()), None);
    }

    #[test]
    fn opened_file_object_requires_both_contexts() {
        let mut file = file_object_with_contexts(core::ptr::null_mut(), core::ptr::null_mut());
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };

        assert_eq!(
            OpenedFileObject::decode(file_object).err(),
            Some(DriverError::InvalidParameter)
        );

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
            OpenedFileObject::decode(file_object).err(),
            Some(DriverError::InvalidParameter)
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
            OpenedFileObject::decode(file_object).err(),
            Some(DriverError::InvalidParameter)
        );
    }

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

    #[test]
    fn file_control_block_open_count_cannot_represent_zero() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = FileControlBlock::new(volume, NodeId::Directory(DirectoryNodeId::ROOT));

        assert_eq!(fcb.open_count.get(), 1);
        assert_eq!(fcb.add_open_reference(), Ok(()));
        assert_eq!(fcb.open_count.get(), 2);
        assert_eq!(
            fcb.release_open_reference(),
            FileControlBlockRelease::StillOpen
        );
        assert_eq!(fcb.open_count.get(), 1);
        assert_eq!(
            fcb.release_open_reference(),
            FileControlBlockRelease::LastReference
        );
    }

    #[test]
    fn file_control_block_open_count_overflow_is_typed() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = FileControlBlock::new(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        fcb.open_count = NonZeroU32::MAX;

        assert_eq!(
            fcb.add_open_reference(),
            Err(DriverError::TooManyOpenReferences)
        );
        assert_eq!(fcb.open_count, NonZeroU32::MAX);
    }

    #[test]
    fn file_control_block_starts_with_empty_share_access() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let fcb = FileControlBlock::new(volume, NodeId::Directory(DirectoryNodeId::ROOT));

        assert_eq!(fcb.share_access.OpenCount, 0);
        assert_eq!(fcb.share_access.Readers, 0);
        assert_eq!(fcb.share_access.Writers, 0);
        assert_eq!(fcb.share_access.Deleters, 0);
        assert_eq!(fcb.share_access.SharedRead, 0);
        assert_eq!(fcb.share_access.SharedWrite, 0);
        assert_eq!(fcb.share_access.SharedDelete, 0);
    }
}
