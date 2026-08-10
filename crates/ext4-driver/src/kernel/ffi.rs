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
    ExAcquireRundownProtection, ExDeleteResourceLite,
    ExEnterCriticalRegionAndAcquireResourceExclusive, ExInitializeResourceLite,
    ExInitializeRundownProtection, ExReleaseResourceAndLeaveCriticalRegion,
    ExReleaseRundownProtection, ExWaitForRundownProtectionRelease, FsRtlDismountComplete,
    FsRtlFastCheckLockForRead, FsRtlFastCheckLockForWrite, FsRtlFastUnlockAll,
    FsRtlInitializeFileLock, FsRtlNotifyCleanup, FsRtlNotifyCleanupAll,
    FsRtlNotifyFullChangeDirectory, FsRtlNotifyFullReportChange, FsRtlNotifyInitializeSync,
    FsRtlNotifyUninitializeSync, FsRtlProcessFileLock, FsRtlUninitializeFileLock,
    IoAcquireVpbSpinLock, IoAllocateIrp, IoAllocateMdl, IoAllocateWorkItem, IoCancelIrp,
    IoCsqInitialize, IoCsqInsertIrp, IoCsqRemoveNextIrp, IoFreeIrp, IoFreeMdl, IoFreeWorkItem,
    IoGetRequestorProcess, IoQueueWorkItem, IoRegisterShutdownNotification, IoReleaseVpbSpinLock,
    IoSetCompletionRoutineEx, IoUnregisterShutdownNotification, IofCallDriver,
    KeAcquireSpinLockRaiseToDpc, KeInitializeEvent, KeInitializeSpinLock, KeReleaseSpinLock,
    KeSetEvent, KeWaitForSingleObject, MmBuildMdlForNonPagedPool, MmUnlockPages,
    PsCreateSystemThread, PsTerminateSystemThread, ZwClose, ZwWaitForSingleObject,
};

#[cfg(not(test))]
unsafe extern "system" {
    /// Captures an exact-length query-security output as an opaque native target.
    pub(crate) fn ext4win_capture_query_security_output(
        output_out: *mut wdk_sys::PVOID,
        required_length_out: *mut wdk_sys::ULONG,
        requestor_buffer: wdk_sys::PVOID,
        requestor_buffer_length: wdk_sys::ULONG,
        required_length: wdk_sys::ULONG,
        requestor_mode: wdk_sys::KPROCESSOR_MODE,
    ) -> wdk_sys::NTSTATUS;

    /// Copies owned bytes into a captured query target, then consumes and unlocks the target.
    pub(crate) fn ext4win_copy_query_security_output(
        output: wdk_sys::PVOID,
        owned_source: *const core::ffi::c_void,
        source_length: wdk_sys::ULONG,
    ) -> wdk_sys::NTSTATUS;

    /// Releases a captured query target.
    pub(crate) fn ext4win_release_query_security_output(output: wdk_sys::PVOID);

    /// Bounded-copies and validates one caller descriptor into owned, aligned native memory.
    pub(crate) fn ext4win_capture_set_security_descriptor(
        source: wdk_sys::PSECURITY_DESCRIPTOR,
        requestor_mode: wdk_sys::KPROCESSOR_MODE,
        required_information: wdk_sys::SECURITY_INFORMATION,
        maximum_length: wdk_sys::ULONG,
        snapshot_out: *mut wdk_sys::PVOID,
        length_out: *mut wdk_sys::ULONG,
    ) -> wdk_sys::NTSTATUS;

    /// Releases one native set-security snapshot.
    pub(crate) fn ext4win_release_set_security_descriptor(snapshot: wdk_sys::PVOID);

    /// Copies one bounded FILE_GET_EA_INFORMATION name list into nonpaged native memory.
    pub(crate) fn ext4win_capture_ea_name_list(
        source: *const core::ffi::c_void,
        length: wdk_sys::ULONG,
        requestor_mode: wdk_sys::KPROCESSOR_MODE,
        snapshot_out: *mut wdk_sys::PVOID,
        length_out: *mut wdk_sys::ULONG,
    ) -> wdk_sys::NTSTATUS;

    /// Copies one validated I/O-manager-owned query pattern into nonpaged native memory.
    pub(crate) fn ext4win_capture_io_manager_directory_pattern(
        source: *const wdk_sys::UNICODE_STRING,
        snapshot_out: *mut wdk_sys::PVOID,
        length_out: *mut wdk_sys::ULONG,
    ) -> wdk_sys::NTSTATUS;

    /// Releases one purpose-specific requestor-input capture.
    pub(crate) fn ext4win_release_captured_requestor_input(snapshot: wdk_sys::PVOID);
}

unsafe extern "system" {
    /// Copies one checked write-input window into driver-owned storage.
    pub(crate) fn ext4win_copy_write_input_window(
        source: *const core::ffi::c_void,
        source_length: wdk_sys::ULONG,
        source_offset: wdk_sys::ULONG,
        destination: wdk_sys::PVOID,
        destination_length: wdk_sys::ULONG,
    ) -> wdk_sys::NTSTATUS;
}
