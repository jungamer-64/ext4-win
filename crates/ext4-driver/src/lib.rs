//! Native Windows kernel entry point for the ext4 file system driver.

#![no_std]

extern crate alloc;

mod block_device;
mod create;
mod dispatch;
mod ea;
mod ffi;
mod file_info;
mod file_system_control;
mod fsctl;
mod irp;
mod metadata;
mod reparse;
mod security;
mod state;
mod status;
mod time;
mod volume_info;

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;
use wdk_sys::{
    NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};

#[cfg(not(test))]
#[global_allocator]
/// Kernel allocator used by WDK-backed driver builds.
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

/// Registered control device observed by the unload callback.
static mut CONTROL_DEVICE: Option<state::ControlDevice> = None;

/// Driver entry point called by the Windows kernel loader.
///
/// # Safety
/// The kernel must pass a valid `DRIVER_OBJECT` for the lifetime of this call.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let Some(driver_object) = (unsafe {
        // SAFETY: The kernel contract for DriverEntry provides a valid pointer
        // when loading the driver. Null is still handled defensively.
        driver.as_mut()
    }) else {
        return wdk_sys::STATUS_INVALID_PARAMETER;
    };

    if dispatch::install(driver_object).is_err() {
        return STATUS_INVALID_PARAMETER;
    }

    let mut device = core::ptr::null_mut();
    let status = unsafe {
        // SAFETY: The driver object is valid for DriverEntry, the device name
        // is intentionally unnamed, and `device` points to writable storage.
        ffi::IoCreateDevice(
            driver,
            0,
            core::ptr::null_mut(),
            ffi::FILE_DEVICE_DISK_FILE_SYSTEM,
            0,
            0,
            &mut device,
        )
    };
    if status != STATUS_SUCCESS {
        return status;
    }

    let Some(control_device) = state::ControlDevice::registered(device) else {
        return STATUS_INVALID_PARAMETER;
    };

    unsafe {
        // SAFETY: `control_device` was initialized by a successful IoCreateDevice call.
        ffi::IoRegisterFileSystem(control_device.as_ptr());
    }
    let control_device_slot = core::ptr::addr_of_mut!(CONTROL_DEVICE);
    unsafe {
        // SAFETY: `control_device_slot` points to the driver-owned global state.
        // Raw pointer write avoids borrowing the mutable static.
        core::ptr::write(control_device_slot, Some(control_device));
    };

    STATUS_SUCCESS
}
