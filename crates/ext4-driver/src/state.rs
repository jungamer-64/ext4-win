//! Driver-local lifecycle and open-object state.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{DeviceLength, Ext4Name, InodeId, InternalJournal, ReadWrite, Result, Volume};
use wdk_sys::{DO_DEVICE_INITIALIZING, DO_DIRECT_IO, PDEVICE_OBJECT, PDRIVER_OBJECT, VPB_MOUNTED};

use crate::{block_device::KernelBlockDevice, ffi};

/// Non-null kernel device object pointer at the WDK boundary.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KernelDevice {
    /// Non-null opaque WDK device pointer.
    device: NonNull<c_void>,
}

impl KernelDevice {
    /// Converts a raw WDK device pointer into the non-null boundary type.
    pub(crate) fn from_raw(device: PDEVICE_OBJECT) -> Option<Self> {
        NonNull::new(device.cast()).map(|device| Self { device })
    }

    /// Creates a kernel device from a non-null WDK device pointer.
    pub(crate) fn from_non_null(device: NonNull<wdk_sys::DEVICE_OBJECT>) -> Self {
        Self {
            device: device.cast(),
        }
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

#[expect(
    dead_code,
    reason = "VCB state is defined before mount FSCTL allocates device extensions"
)]
#[derive(Debug)]
/// Volume control block stored in a mounted volume device extension.
pub(crate) struct VolumeControlBlock {
    /// Mounted journaled read-write ext4 volume.
    volume: Volume<KernelBlockDevice, ReadWrite<InternalJournal>>,
    /// Root directory inode of the mounted volume.
    root_inode: InodeId,
}

impl VolumeControlBlock {
    /// Mounts a journaled read-write ext4 VCB.
    pub(crate) fn mount_read_write(
        target_device: KernelDevice,
        length: DeviceLength,
    ) -> Result<Self> {
        let block_device = KernelBlockDevice::new(target_device, length);
        let volume = Volume::<_, ReadWrite<InternalJournal>>::mount_read_write(block_device)?;
        Ok(Self {
            volume,
            root_inode: InodeId::ROOT,
        })
    }

    /// Returns a stable serial number derived from the ext4 filesystem UUID.
    pub(crate) fn serial_number(&self) -> Option<u32> {
        let uuid = self.volume.superblock().uuid().bytes();
        let bytes: [u8; 4] = uuid.get(0..4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    /// Returns the mounted ext4 volume.
    pub(crate) const fn volume(&self) -> &Volume<KernelBlockDevice, ReadWrite<InternalJournal>> {
        &self.volume
    }

    /// Returns the mounted ext4 volume for journaled mutation.
    pub(crate) const fn volume_mut(
        &mut self,
    ) -> &mut Volume<KernelBlockDevice, ReadWrite<InternalJournal>> {
        &mut self.volume
    }

    /// Returns the mounted ext4 volume label.
    pub(crate) fn volume_label(&self) -> ext4_core::Ext4VolumeLabel {
        self.volume.volume_label()
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
    ) -> Option<Self> {
        let device = KernelDevice::from_raw(device)?;
        let device_object = unsafe {
            // SAFETY: The device was just created by this driver and remains
            // valid during mount initialization.
            device.as_ptr().as_mut()
        }?;
        let extension = unsafe {
            // SAFETY: The device was created with a DeviceExtension sized for
            // MountedVolumeDeviceExtension by this driver.
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
                .as_mut()
        }?;
        Self::initialize_device_object(device, vpb, real_device)?;
        extension.vcb = Box::into_raw(vcb);
        Some(Self { device })
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
    ) -> Option<()> {
        let device_object = unsafe {
            // SAFETY: The mounted device object was created by this driver and
            // remains valid during mount initialization.
            device.as_ptr().as_mut()
        }?;
        device_object.Vpb = vpb.as_ptr();
        device_object.Flags |= DO_DIRECT_IO;
        device_object.Flags &= !DO_DEVICE_INITIALIZING;
        device_object.StackSize = real_device.stack_size()?.checked_add(1)?;

        let vpb = unsafe {
            // SAFETY: The VPB was supplied by the I/O Manager for this mount
            // request and is writable during successful mount completion.
            vpb.as_mut()
        };
        vpb.DeviceObject = device.as_ptr();
        vpb.RealDevice = real_device.as_ptr();
        vpb.Flags |= u16::try_from(VPB_MOUNTED).ok()?;
        Some(())
    }

    /// Copies VCB-derived identity fields into the VPB.
    pub(crate) fn initialize_vpb_identity(
        vpb: NonNull<wdk_sys::VPB>,
        vcb: &VolumeControlBlock,
    ) -> Option<()> {
        let vpb = unsafe {
            // SAFETY: The VPB belongs to the active mount request and remains
            // writable until the mount IRP is completed.
            vpb.as_ptr().as_mut()
        }?;
        vpb.SerialNumber = vcb.serial_number()?;
        write_vpb_label(vpb, vcb.volume_label())
    }
}

/// Writes an ext4 label into the UTF-16 VPB label field using one code unit per
/// ext4 label byte.
fn write_vpb_label(vpb: &mut wdk_sys::VPB, label: ext4_core::Ext4VolumeLabel) -> Option<()> {
    vpb.VolumeLabel.fill(0);
    let bytes = label.bytes();
    if bytes.len() > vpb.VolumeLabel.len() {
        return None;
    }
    for (index, byte) in bytes.iter().enumerate() {
        *vpb.VolumeLabel.get_mut(index)? = u16::from(*byte);
    }
    let wchar_bytes = bytes.len().checked_mul(core::mem::size_of::<u16>())?;
    vpb.VolumeLabelLength = u16::try_from(wchar_bytes).ok()?;
    Some(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Ext4 node represented by an FCB.
pub(crate) enum FileSystemNode {
    /// Regular file inode.
    File(InodeId),
    /// Directory inode.
    Directory(InodeId),
    /// Symbolic link inode.
    Symlink(InodeId),
}

impl FileSystemNode {
    /// Returns the inode represented by this node.
    pub(crate) const fn inode(self) -> InodeId {
        match self {
            Self::File(inode) | Self::Directory(inode) | Self::Symlink(inode) => inode,
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// File control block stored in `FILE_OBJECT::FsContext`.
pub(crate) struct FileControlBlock {
    /// Mounted volume that owns this file.
    volume: NonNull<VolumeControlBlock>,
    /// Ext4 node opened by this FCB.
    node: FileSystemNode,
}

impl FileControlBlock {
    /// Creates an FCB boundary value for a mounted node.
    pub(crate) const fn new(volume: NonNull<VolumeControlBlock>, node: FileSystemNode) -> Self {
        Self { volume, node }
    }

    /// Returns the mounted VCB pointer that owns this open node.
    pub(crate) const fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.volume
    }

    /// Returns the ext4 node identity opened by this FCB.
    pub(crate) const fn node(&self) -> FileSystemNode {
        self.node
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Per-handle directory enumeration state.
pub(crate) struct DirectoryCursor {
    /// Next directory entry index to emit.
    next_entry: u32,
}

impl DirectoryCursor {
    /// Creates a cursor at the first directory entry.
    pub(crate) const fn start() -> Self {
        Self { next_entry: 0 }
    }

    /// Returns the next directory entry index to emit.
    pub(crate) const fn next_entry(self) -> u32 {
        self.next_entry
    }

    /// Moves the cursor to a specific directory entry index.
    pub(crate) const fn seek(&mut self, next_entry: u32) {
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
        parent: InodeId,
        /// Exact ext4 directory entry name.
        name: Ext4Name,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Handle-local node state.
pub(crate) enum OpenedHandleState {
    /// Regular file handle.
    File,
    /// Directory handle with enumeration cursor.
    Directory(DirectoryCursor),
    /// Symlink handle.
    Symlink,
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
pub(crate) struct ContextControlBlock {
    /// Handle-local node state.
    handle: OpenedHandleState,
    /// Path used for namespace mutations on cleanup.
    path: OpenedPath,
    /// Requested close disposition.
    close_disposition: CloseDisposition,
}

impl ContextControlBlock {
    /// Creates per-handle state for an opened node.
    pub(crate) fn new(node: FileSystemNode, path: OpenedPath) -> Self {
        let handle = match node {
            FileSystemNode::File(_) => OpenedHandleState::File,
            FileSystemNode::Directory(_) => OpenedHandleState::Directory(DirectoryCursor::start()),
            FileSystemNode::Symlink(_) => OpenedHandleState::Symlink,
        };
        Self {
            handle,
            path,
            close_disposition: CloseDisposition::Keep,
        }
    }

    /// Returns the mutable directory cursor when this handle opened a directory.
    pub(crate) fn directory_cursor_mut(&mut self) -> Option<&mut DirectoryCursor> {
        match &mut self.handle {
            OpenedHandleState::Directory(cursor) => Some(cursor),
            OpenedHandleState::File | OpenedHandleState::Symlink => None,
        }
    }

    /// Marks the handle for delete-on-close cleanup.
    pub(crate) const fn mark_delete_on_close(&mut self) {
        self.close_disposition = CloseDisposition::Delete;
    }

    /// Clears a delete-on-close request for this handle.
    pub(crate) const fn keep_on_close(&mut self) {
        self.close_disposition = CloseDisposition::Keep;
    }

    /// Returns the requested close disposition.
    pub(crate) const fn close_disposition(&self) -> CloseDisposition {
        self.close_disposition
    }

    /// Returns the opened path identity.
    pub(crate) const fn path(&self) -> &OpenedPath {
        &self.path
    }

    /// Replaces the opened path after a successful rename.
    pub(crate) fn replace_path(&mut self, path: OpenedPath) {
        self.path = path;
    }
}

/// Driver unload callback registered in the driver object.
pub(crate) unsafe extern "C" fn driver_unload(_driver: PDRIVER_OBJECT) {
    let control_device = core::ptr::addr_of_mut!(crate::CONTROL_DEVICE);
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
