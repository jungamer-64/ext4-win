//! Driver-local lifecycle and open-object state.

use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::InodeId;
use wdk_sys::{PDEVICE_OBJECT, PDRIVER_OBJECT};

use crate::ffi;

/// Non-null kernel device object pointer at the WDK boundary.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KernelDevice {
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
}

/// Registered file system control device owned by the driver.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ControlDevice {
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
pub(crate) struct RegisteredDriver {
    control_device: KernelDevice,
}

#[expect(
    dead_code,
    reason = "mount state is introduced before FSCTL mount IRP handling"
)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountCandidate {
    target_device: KernelDevice,
}

#[expect(
    dead_code,
    reason = "volume state is introduced before VCB allocation is wired"
)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountedVolume {
    root_inode: InodeId,
    target_device: KernelDevice,
}

#[expect(
    dead_code,
    reason = "open node state is introduced before CREATE allocates CCBs"
)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum OpenNode {
    File(InodeId),
    Directory(InodeId),
    Symlink(InodeId),
}

/// Driver unload callback registered in the driver object.
pub(crate) unsafe extern "system" fn driver_unload(_driver: PDRIVER_OBJECT) {
    let device = unsafe {
        // SAFETY: Driver unload is serialized by the I/O Manager for this
        // driver object. Use raw pointer replacement to avoid borrowing the
        // mutable static.
        core::ptr::replace(core::ptr::addr_of_mut!(crate::CONTROL_DEVICE), None)
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
