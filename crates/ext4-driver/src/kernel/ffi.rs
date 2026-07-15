//! I/O Manager symbols used by the driver boundary.

pub(crate) use wdk_sys::FILE_DEVICE_DISK_FILE_SYSTEM;
#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::IofCompleteRequest;
pub(crate) use wdk_sys::ntddk::{
    IoCheckShareAccess, IoCreateDevice, IoDeleteDevice, IoRegisterFileSystem, IoRemoveShareAccess,
    IoUnregisterFileSystem, KeQuerySystemTimePrecise, MmMapLockedPagesSpecifyCache,
    RtlSecondsSince1970ToTime, RtlTimeToSecondsSince1970,
};

#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::{
    ExDeleteResourceLite, ExEnterCriticalRegionAndAcquireResourceExclusive,
    ExInitializeResourceLite, ExReleaseResourceAndLeaveCriticalRegion, FsRtlFastCheckLockForRead,
    FsRtlFastCheckLockForWrite, FsRtlFastUnlockAll, FsRtlInitializeFileLock, FsRtlNotifyCleanup,
    FsRtlNotifyCleanupAll, FsRtlNotifyFullChangeDirectory, FsRtlNotifyFullReportChange,
    FsRtlNotifyInitializeSync, FsRtlNotifyUninitializeSync, FsRtlProcessFileLock,
    FsRtlUninitializeFileLock, IoAllocateIrp, IoAllocateMdl, IoAllocateWorkItem, IoCsqInitialize,
    IoCsqInsertIrp, IoCsqRemoveNextIrp, IoFreeIrp, IoFreeMdl, IoFreeWorkItem,
    IoGetRequestorProcess, IoQueueWorkItem, IoRegisterShutdownNotification,
    IoSetCompletionRoutineEx, IofCallDriver, KeAcquireSpinLockRaiseToDpc, KeInitializeSpinLock,
    KeReleaseSpinLock, MmBuildMdlForNonPagedPool, MmUnlockPages,
};
