//! I/O Manager symbols used by the driver boundary.

pub(crate) use wdk_sys::FILE_DEVICE_DISK_FILE_SYSTEM;
pub(crate) use wdk_sys::ntddk::{
    IoBuildDeviceIoControlRequest, IoBuildSynchronousFsdRequest, IoCreateDevice, IoDeleteDevice,
    IoRegisterFileSystem, IoUnregisterFileSystem, IofCallDriver, KeInitializeEvent,
    KeQuerySystemTimePrecise, KeWaitForSingleObject, MmMapLockedPagesSpecifyCache,
    RtlSecondsSince1970ToTime, RtlTimeToSecondsSince1970,
};
