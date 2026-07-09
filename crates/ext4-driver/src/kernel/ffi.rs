//! I/O Manager symbols used by the driver boundary.

pub(crate) use wdk_sys::FILE_DEVICE_DISK_FILE_SYSTEM;
#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::IofCompleteRequest;
pub(crate) use wdk_sys::ntddk::{
    IoBuildDeviceIoControlRequest, IoBuildSynchronousFsdRequest, IoCheckShareAccess,
    IoCreateDevice, IoDeleteDevice, IoRegisterFileSystem, IoRemoveShareAccess,
    IoUnregisterFileSystem, IofCallDriver, KeInitializeEvent, KeQuerySystemTimePrecise,
    KeWaitForSingleObject, MmMapLockedPagesSpecifyCache, RtlSecondsSince1970ToTime,
    RtlTimeToSecondsSince1970,
};

#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::{
    FsRtlCheckLockForReadAccess, FsRtlCheckLockForWriteAccess, FsRtlFastUnlockAll,
    FsRtlInitializeFileLock, FsRtlProcessFileLock, FsRtlUninitializeFileLock, IoAllocateWorkItem,
    IoCsqInitialize, IoCsqInsertIrp, IoCsqRemoveNextIrp, IoFreeWorkItem, IoGetRequestorProcess,
    IoQueueWorkItem, IoRegisterShutdownNotification, KeAcquireSpinLockRaiseToDpc,
    KeInitializeSpinLock, KeReleaseSpinLock,
};
