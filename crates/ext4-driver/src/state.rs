//! Driver-local lifecycle and open-object state.

use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{DeviceLength, InodeId, InternalJournal, ReadWrite, Result, Volume};
use wdk_sys::{PDEVICE_OBJECT, PDRIVER_OBJECT};

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

#[expect(
    dead_code,
    reason = "VCB accessors are defined before IRP dispatch stores VCB pointers"
)]
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

    /// Returns the mounted ext4 volume.
    pub(crate) const fn volume(&self) -> &Volume<KernelBlockDevice, ReadWrite<InternalJournal>> {
        &self.volume
    }

    /// Returns the mounted ext4 volume for mutation.
    pub(crate) const fn volume_mut(
        &mut self,
    ) -> &mut Volume<KernelBlockDevice, ReadWrite<InternalJournal>> {
        &mut self.volume
    }

    /// Returns the mounted root inode.
    pub(crate) const fn root_inode(&self) -> InodeId {
        self.root_inode
    }
}

#[expect(
    dead_code,
    reason = "FCB node variants are defined before CREATE constructs FCB state"
)]
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

#[expect(
    dead_code,
    reason = "FCB node accessors are defined before CREATE constructs FCB state"
)]
impl FileSystemNode {
    /// Returns the inode represented by this node.
    pub(crate) const fn inode(self) -> InodeId {
        match self {
            Self::File(inode) | Self::Directory(inode) | Self::Symlink(inode) => inode,
        }
    }
}

#[expect(
    dead_code,
    reason = "FCB state is defined before CREATE allocates file objects"
)]
#[derive(Clone, Copy, Debug)]
/// File control block stored in `FILE_OBJECT::FsContext`.
pub(crate) struct FileControlBlock {
    /// Mounted volume that owns this file.
    volume: NonNull<c_void>,
    /// Ext4 node opened by this FCB.
    node: FileSystemNode,
}

#[expect(
    dead_code,
    reason = "FCB constructors are defined before CREATE stores FsContext"
)]
impl FileControlBlock {
    /// Creates an FCB boundary value for a mounted node.
    pub(crate) const fn new(volume: NonNull<c_void>, node: FileSystemNode) -> Self {
        Self { volume, node }
    }

    /// Returns the opaque VCB pointer.
    pub(crate) const fn volume(self) -> NonNull<c_void> {
        self.volume
    }

    /// Returns the ext4 node.
    pub(crate) const fn node(self) -> FileSystemNode {
        self.node
    }
}

#[expect(
    dead_code,
    reason = "directory CCB cursor is defined before DIRECTORY_CONTROL stores FsContext2"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Per-handle directory enumeration state.
pub(crate) struct DirectoryCursor {
    /// Next directory entry index to emit.
    next_entry: u32,
}

#[expect(
    dead_code,
    reason = "directory cursor accessors are defined before DIRECTORY_CONTROL uses CCB state"
)]
impl DirectoryCursor {
    /// Creates a cursor at the first directory entry.
    pub(crate) const fn start() -> Self {
        Self { next_entry: 0 }
    }

    /// Returns the next directory entry index.
    pub(crate) const fn next_entry(self) -> u32 {
        self.next_entry
    }
}

#[expect(
    dead_code,
    reason = "CCB variants are defined before CREATE stores FsContext2"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Per-handle state stored in `FILE_OBJECT::FsContext2`.
pub(crate) enum ContextControlBlock {
    /// Regular file handle.
    File,
    /// Directory handle with enumeration cursor.
    Directory(DirectoryCursor),
    /// Symlink handle.
    Symlink,
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
