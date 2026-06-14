//! IRP major-function dispatch table for the read-only FSD boundary.

use wdk_sys::{
    DRIVER_OBJECT, NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_ACCESS_DENIED,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_IMPLEMENTED,
    STATUS_SUCCESS,
};

const IRP_MJ_CREATE: usize = 0x00;
const IRP_MJ_CLOSE: usize = 0x02;
const IRP_MJ_READ: usize = 0x03;
const IRP_MJ_WRITE: usize = 0x04;
const IRP_MJ_QUERY_INFORMATION: usize = 0x05;
const IRP_MJ_SET_INFORMATION: usize = 0x06;
const IRP_MJ_QUERY_VOLUME_INFORMATION: usize = 0x0A;
const IRP_MJ_SET_VOLUME_INFORMATION: usize = 0x0B;
const IRP_MJ_DIRECTORY_CONTROL: usize = 0x0C;
const IRP_MJ_FILE_SYSTEM_CONTROL: usize = 0x0D;
const IRP_MJ_DEVICE_CONTROL: usize = 0x0E;
const IRP_MJ_SHUTDOWN: usize = 0x10;
const IRP_MJ_CLEANUP: usize = 0x12;
const IRP_MJ_QUERY_SECURITY: usize = 0x14;
const IRP_MJ_SET_SECURITY: usize = 0x15;

/// Installs the v1 read-only dispatch table.
pub(crate) fn install(driver: &mut DRIVER_OBJECT) {
    driver.DriverUnload = Some(super::state::driver_unload);
    driver.MajorFunction[IRP_MJ_CREATE] = Some(create);
    driver.MajorFunction[IRP_MJ_CLOSE] = Some(success);
    driver.MajorFunction[IRP_MJ_CLEANUP] = Some(success);
    driver.MajorFunction[IRP_MJ_READ] = Some(read);
    driver.MajorFunction[IRP_MJ_QUERY_INFORMATION] = Some(query_information);
    driver.MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = Some(query_volume_information);
    driver.MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = Some(directory_control);
    driver.MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = Some(file_system_control);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL] = Some(device_control);
    driver.MajorFunction[IRP_MJ_SHUTDOWN] = Some(success);
    driver.MajorFunction[IRP_MJ_QUERY_SECURITY] = Some(query_security);

    driver.MajorFunction[IRP_MJ_WRITE] = Some(read_only);
    driver.MajorFunction[IRP_MJ_SET_INFORMATION] = Some(read_only);
    driver.MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION] = Some(read_only);
    driver.MajorFunction[IRP_MJ_SET_SECURITY] = Some(read_only);
}

unsafe extern "system" fn create(_device: PDEVICE_OBJECT, _irp: PIRP) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

unsafe extern "system" fn read(_device: PDEVICE_OBJECT, _irp: PIRP) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

unsafe extern "system" fn query_information(_device: PDEVICE_OBJECT, _irp: PIRP) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

unsafe extern "system" fn query_volume_information(
    _device: PDEVICE_OBJECT,
    _irp: PIRP,
) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

unsafe extern "system" fn directory_control(_device: PDEVICE_OBJECT, _irp: PIRP) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

unsafe extern "system" fn file_system_control(_device: PDEVICE_OBJECT, _irp: PIRP) -> NTSTATUS {
    STATUS_INVALID_DEVICE_REQUEST
}

unsafe extern "system" fn device_control(_device: PDEVICE_OBJECT, _irp: PIRP) -> NTSTATUS {
    STATUS_INVALID_DEVICE_REQUEST
}

unsafe extern "system" fn query_security(_device: PDEVICE_OBJECT, _irp: PIRP) -> NTSTATUS {
    STATUS_ACCESS_DENIED
}

unsafe extern "system" fn read_only(_device: PDEVICE_OBJECT, _irp: PIRP) -> NTSTATUS {
    STATUS_MEDIA_WRITE_PROTECTED
}

unsafe extern "system" fn success(_device: PDEVICE_OBJECT, _irp: PIRP) -> NTSTATUS {
    STATUS_SUCCESS
}
