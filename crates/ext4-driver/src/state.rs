//! Driver-local lifecycle and open-object state.

use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{DeviceLength, InodeId};
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

#[expect(
    dead_code,
    reason = "mount state is introduced before FSCTL mount IRP handling"
)]
#[derive(Clone, Copy, Debug)]
/// Target device selected by mount FSCTL validation before VCB creation.
pub(crate) struct MountCandidate {
    /// Device object that will back the mounted ext4 volume.
    target_device: KernelDevice,
    /// Valid byte length reported by the storage stack.
    length: DeviceLength,
}

#[expect(
    dead_code,
    reason = "mount capability is defined before mount FSCTL constructs VCB state"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Mounted volume capability selected by the core mount mode.
pub(crate) enum MountMode {
    /// Journaled read-write volume.
    ReadWrite,
}

#[expect(
    dead_code,
    reason = "VCB state is defined before mount FSCTL allocates device extensions"
)]
#[derive(Clone, Copy, Debug)]
/// Volume control block stored in a mounted volume device extension.
pub(crate) struct VolumeControlBlock {
    /// Storage target connected to ext4-core block I/O.
    block_device: KernelBlockDevice,
    /// Root directory inode of the mounted volume.
    root_inode: InodeId,
    /// Mounted volume capability.
    mode: MountMode,
}

#[expect(
    dead_code,
    reason = "VCB accessors are defined before IRP dispatch stores VCB pointers"
)]
impl VolumeControlBlock {
    /// Creates a journaled read-write VCB.
    pub(crate) const fn read_write(target_device: KernelDevice, length: DeviceLength) -> Self {
        Self {
            block_device: KernelBlockDevice::new(target_device, length),
            root_inode: InodeId::ROOT,
            mode: MountMode::ReadWrite,
        }
    }

    /// Returns the mounted block-device boundary.
    pub(crate) const fn block_device(self) -> KernelBlockDevice {
        self.block_device
    }

    /// Returns the mounted root inode.
    pub(crate) const fn root_inode(self) -> InodeId {
        self.root_inode
    }

    /// Returns the mounted capability.
    pub(crate) const fn mode(self) -> MountMode {
        self.mode
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
