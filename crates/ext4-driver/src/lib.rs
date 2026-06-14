//! Native Windows kernel entry point for the read-only ext4 file system driver.

#![no_std]

mod dispatch;
mod ffi;
mod state;

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;
use wdk_sys::{NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, STATUS_SUCCESS};

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

static mut CONTROL_DEVICE: state::ControlDevice = state::ControlDevice::none();

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

    dispatch::install(driver_object);

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

    unsafe {
        // SAFETY: `device` was initialized by a successful IoCreateDevice call.
        ffi::IoRegisterFileSystem(device);
        CONTROL_DEVICE = state::ControlDevice::registered(device);
    }

    STATUS_SUCCESS
}
