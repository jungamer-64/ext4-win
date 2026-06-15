//! I/O Manager symbols used by the driver boundary.

pub(crate) use wdk_sys::FILE_DEVICE_DISK_FILE_SYSTEM;
pub(crate) use wdk_sys::ntddk::{
    IoBuildSynchronousFsdRequest, IoCreateDevice, IoDeleteDevice, IoRegisterFileSystem,
    IoUnregisterFileSystem, IofCallDriver, KeInitializeEvent, KeWaitForSingleObject,
};
