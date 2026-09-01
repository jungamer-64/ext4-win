//! I/O Manager symbols used by the driver boundary.

pub(crate) use wdk_sys::FILE_DEVICE_DISK_FILE_SYSTEM;
#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::IofCompleteRequest;
pub(crate) use wdk_sys::ntddk::{
    IoCheckShareAccess, IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
    IoRegisterFileSystem, IoRemoveShareAccess, IoUnregisterFileSystem, KeQuerySystemTimePrecise,
    MmMapLockedPagesSpecifyCache, RtlSecondsSince1970ToTime, RtlTimeToSecondsSince1970,
};

#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::{
    IoGetFileObjectGenericMapping, SeAccessCheck, SeAppendPrivileges, SeFreePrivileges,
    SeLockSubjectContext, SeSetAccessStateGenericMapping, SeUnlockSubjectContext,
};

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
#[cfg(not(test))]
#[link(name = "wdmsec", kind = "static")]
unsafe extern "system" {
    /// Creates the named control device with the exact SDDL and setup-class identity supplied by
    /// the generated lifecycle contract.
    pub(crate) fn WdmlibIoCreateDeviceSecure(
        driver: wdk_sys::PDRIVER_OBJECT,
        extension_size: wdk_sys::ULONG,
        device_name: wdk_sys::PUNICODE_STRING,
        device_type: wdk_sys::ULONG,
        device_characteristics: wdk_sys::ULONG,
        exclusive: wdk_sys::BOOLEAN,
        default_sddl: wdk_sys::PCUNICODE_STRING,
        device_class_guid: wdk_sys::LPCGUID,
        device: *mut wdk_sys::PDEVICE_OBJECT,
    ) -> wdk_sys::NTSTATUS;
}

#[cfg(test)]
#[expect(
    unsafe_code,
    non_snake_case,
    clippy::too_many_arguments,
    reason = "the host test build preserves the exact external symbol shape without linking a kernel-only library"
)]
/// Host-test stand-in for a kernel-library boundary that production links and checks separately.
/// # Safety
///
/// The arguments retain the production FFI shape but are never dereferenced by this stand-in.
pub(crate) unsafe fn WdmlibIoCreateDeviceSecure(
    _driver: wdk_sys::PDRIVER_OBJECT,
    _extension_size: wdk_sys::ULONG,
    _device_name: wdk_sys::PUNICODE_STRING,
    _device_type: wdk_sys::ULONG,
    _device_characteristics: wdk_sys::ULONG,
    _exclusive: wdk_sys::BOOLEAN,
    _default_sddl: wdk_sys::PCUNICODE_STRING,
    _device_class_guid: wdk_sys::LPCGUID,
    _device: *mut wdk_sys::PDEVICE_OBJECT,
) -> wdk_sys::NTSTATUS {
    wdk_sys::STATUS_NOT_SUPPORTED
}

#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::{
    ExAcquireRundownProtection, ExDeleteResourceLite,
    ExEnterCriticalRegionAndAcquireResourceExclusive, ExInitializeResourceLite,
    ExInitializeRundownProtection, ExReleaseResourceAndLeaveCriticalRegion,
    ExReleaseRundownProtection, ExWaitForRundownProtectionRelease, FsRtlDismountComplete,
    FsRtlFastCheckLockForRead, FsRtlFastCheckLockForWrite, FsRtlInitializeFileLock,
    FsRtlNotifyCleanup, FsRtlNotifyCleanupAll, FsRtlNotifyFullChangeDirectory,
    FsRtlNotifyFullReportChange, FsRtlNotifyInitializeSync, FsRtlNotifyUninitializeSync,
    FsRtlUninitializeFileLock, IoAcquireVpbSpinLock, IoAllocateIrp, IoAllocateMdl,
    IoAllocateWorkItem, IoCancelIrp, IoCsqInitialize, IoCsqInsertIrp, IoCsqRemoveNextIrp,
    IoFreeIrp, IoFreeMdl, IoFreeWorkItem, IoGetRequestorProcess, IoQueueWorkItem,
    IoRegisterShutdownNotification, IoReleaseVpbSpinLock, IoSetCompletionRoutineEx,
    IoUnregisterShutdownNotification, IofCallDriver, KeAcquireSpinLockRaiseToDpc, KeCancelTimer,
    KeFlushQueuedDpcs, KeInitializeDpc, KeInitializeEvent, KeInitializeSpinLock, KeInitializeTimer,
    KeReleaseSpinLock, KeSetEvent, KeSetTimer, KeWaitForSingleObject, MmBuildMdlForNonPagedPool,
    MmUnlockPages, ObfDereferenceObject, PsCreateSystemThread, PsTerminateSystemThread, ZwClose,
    ZwWaitForSingleObject,
};

#[cfg(not(test))]
pub(crate) use wdk_sys::IoFileObjectType;
#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::{
    ExFreePool, IoGetDeviceAttachmentBaseRef, IoGetDeviceInterfaces, IoGetDeviceObjectPointer,
    IoGetRelatedDeviceObject, ObReferenceObjectByHandle, ZwCreateFile,
};

#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::{IoAcquireCancelSpinLock, IoReleaseCancelSpinLock};

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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
