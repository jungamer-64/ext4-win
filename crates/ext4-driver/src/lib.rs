//! Native Windows kernel entry point for the ext4 file system driver.

#![feature(allocator_api)]
#![feature(try_reserve_kind)]
#![feature(vec_push_within_capacity)]
#![no_std]

extern crate alloc;

mod irp;
mod kernel;
mod memory;
mod request;
mod state;
mod wire;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;
use wdk_sys::{NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, STATUS_SUCCESS};

#[cfg(not(test))]
#[global_allocator]
/// Kernel allocator used by WDK-backed driver builds.
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

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
        return kernel::status::DriverError::InvalidParameter.ntstatus();
    };

    if request::dispatch::install(driver_object).is_err() {
        return kernel::status::DriverError::InvalidParameter.ntstatus();
    }

    let mut device = core::ptr::null_mut();
    let extension_size =
        match wdk_sys::ULONG::try_from(core::mem::size_of::<state::ControlDeviceExtension>()) {
            Ok(size) => size,
            Err(_) => return kernel::status::DriverError::InvalidParameter.ntstatus(),
        };
    let status = unsafe {
        // SAFETY: The driver object is valid for DriverEntry, the device name
        // is intentionally unnamed, and `device` points to writable storage.
        kernel::ffi::IoCreateDevice(
            driver,
            extension_size,
            core::ptr::null_mut(),
            kernel::ffi::FILE_DEVICE_DISK_FILE_SYSTEM,
            0,
            0,
            &mut device,
        )
    };
    if status != STATUS_SUCCESS {
        return kernel::status::DriverError::InsufficientResources.ntstatus();
    }

    let control_device = match state::ControlDevice::registered(device) {
        Ok(control_device) => control_device,
        Err(error) => {
            unsafe {
                // SAFETY: `device` was returned by IoCreateDevice and has not
                // been registered with the I/O Manager.
                kernel::ffi::IoDeleteDevice(device);
            }
            return error.ntstatus();
        }
    };

    unsafe {
        // SAFETY: `control_device` was initialized by a successful IoCreateDevice call.
        kernel::ffi::IoRegisterFileSystem(control_device.as_ptr());
    }
    state::publish_control_device(control_device);

    STATUS_SUCCESS
}
