//! Small I/O Manager FFI surface not yet modeled by `windows-drivers-rs`.

use wdk_sys::{
    BOOLEAN, DEVICE_TYPE, NTSTATUS, PDEVICE_OBJECT, PDRIVER_OBJECT, PUNICODE_STRING, ULONG,
};

/// Device type for disk file system control devices.
pub(crate) const FILE_DEVICE_DISK_FILE_SYSTEM: DEVICE_TYPE = 0x0000_0008;

unsafe extern "system" {
    /// Creates the file system control device object.
    pub(crate) fn IoCreateDevice(
        driver_object: PDRIVER_OBJECT,
        device_extension_size: ULONG,
        device_name: PUNICODE_STRING,
        device_type: DEVICE_TYPE,
        device_characteristics: ULONG,
        exclusive: BOOLEAN,
        device_object: *mut PDEVICE_OBJECT,
    ) -> NTSTATUS;

    /// Registers a file system control device with the I/O Manager.
    pub(crate) fn IoRegisterFileSystem(device_object: PDEVICE_OBJECT);

    /// Unregisters a file system control device from the I/O Manager.
    pub(crate) fn IoUnregisterFileSystem(device_object: PDEVICE_OBJECT);

    /// Deletes a device object created by this driver.
    pub(crate) fn IoDeleteDevice(device_object: PDEVICE_OBJECT);
}
