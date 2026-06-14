//! Driver-local lifecycle and open-object state.

use ext4_core::InodeId;
use wdk_sys::{PDEVICE_OBJECT, PDRIVER_OBJECT};

use crate::ffi;

/// Registered file system control device owned by the driver.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ControlDevice {
    device: PDEVICE_OBJECT,
}

impl ControlDevice {
    /// Creates an empty unregistered control-device state.
    pub(crate) const fn none() -> Self {
        Self {
            device: core::ptr::null_mut(),
        }
    }

    /// Creates registered control-device state.
    pub(crate) const fn registered(device: PDEVICE_OBJECT) -> Self {
        Self { device }
    }

    fn take(&mut self) -> PDEVICE_OBJECT {
        let device = self.device;
        self.device = core::ptr::null_mut();
        device
    }
}

#[expect(
    dead_code,
    reason = "mount state is introduced before FSCTL mount IRP handling"
)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct RegisteredDriver {
    control_device: PDEVICE_OBJECT,
}

#[expect(
    dead_code,
    reason = "mount state is introduced before FSCTL mount IRP handling"
)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountCandidate {
    target_device: PDEVICE_OBJECT,
}

#[expect(
    dead_code,
    reason = "volume state is introduced before VCB allocation is wired"
)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountedVolume {
    root_inode: InodeId,
    target_device: PDEVICE_OBJECT,
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
        // driver object. The mutable static is only touched during load/unload.
        crate::CONTROL_DEVICE.take()
    };
    if !device.is_null() {
        unsafe {
            // SAFETY: The device was created and registered by DriverEntry.
            ffi::IoUnregisterFileSystem(device);
            ffi::IoDeleteDevice(device);
        }
    }
}
