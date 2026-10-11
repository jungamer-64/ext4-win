//! I/O Manager symbols used by the driver boundary.

pub(crate) use wdk_sys::FILE_DEVICE_DISK_FILE_SYSTEM;
#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::IoCompleteRequest;
#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::{
    IoCheckShareAccess, IoRemoveShareAccess, KeQuerySystemTimePrecise,
};
pub(crate) use wdk_sys::ntddk::{
    IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
    IoRegisterFileSystem, IoUnregisterFileSystem, RtlSecondsSince1970ToTime,
    RtlTimeToSecondsSince1970,
};

/// # Safety
/// Retains the native sharing boundary; host fixtures cannot establish kernel share claims.
/// # Panics
/// Fails if a host fixture attempts native share admission.
#[cfg(test)]
#[expect(
    unsafe_code,
    non_snake_case,
    clippy::panic,
    clippy::disallowed_macros,
    reason = "host tests must not report native sharing behavior without the I/O Manager"
)]
pub(crate) unsafe fn IoCheckShareAccess(
    _access: wdk_sys::ACCESS_MASK,
    _sharing: wdk_sys::ULONG,
    _file: wdk_sys::PFILE_OBJECT,
    _shares: wdk_sys::PSHARE_ACCESS,
    _update: wdk_sys::BOOLEAN,
) -> wdk_sys::NTSTATUS {
    panic!("native share admission requires the I/O Manager")
}

/// # Safety
/// Retains the native sharing boundary; host fixtures cannot own kernel share claims.
/// # Panics
/// Fails if a host fixture attempts native share removal.
#[cfg(test)]
#[expect(
    unsafe_code,
    non_snake_case,
    clippy::panic,
    clippy::disallowed_macros,
    reason = "host tests cannot consume a native claim that they never acquired"
)]
pub(crate) unsafe fn IoRemoveShareAccess(
    _file: wdk_sys::PFILE_OBJECT,
    _shares: wdk_sys::PSHARE_ACCESS,
) {
    panic!("native share removal requires the I/O Manager")
}

/// # Safety
/// Retains the kernel clock ABI without synthesizing a native time observation.
/// # Panics
/// Fails if a host fixture reaches the kernel-only clock boundary.
#[cfg(test)]
#[expect(
    unsafe_code,
    non_snake_case,
    clippy::panic,
    clippy::disallowed_macros,
    reason = "host tests must supply timestamps before crossing the kernel clock boundary"
)]
pub(crate) unsafe fn KeQuerySystemTimePrecise(_time: wdk_sys::PLARGE_INTEGER) {
    panic!("kernel clock observation requires a loaded driver")
}

#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::MmMapLockedPagesSpecifyCache;

/// Host fixtures can describe already mapped buffers but cannot map physical kernel pages.
/// # Safety
/// Retains the production argument contract; reaching this kernel-only branch fails the host test.
/// # Panics
/// Always fails if a host test reaches the physical-page mapping boundary.
#[cfg(test)]
#[expect(
    unsafe_code,
    non_snake_case,
    clippy::panic,
    clippy::disallowed_macros,
    reason = "fail closed if a host fixture attempts a kernel-only physical-page mapping"
)]
pub(crate) unsafe fn MmMapLockedPagesSpecifyCache(
    _mdl: wdk_sys::PMDL,
    _mode: wdk_sys::KPROCESSOR_MODE,
    _cache_type: wdk_sys::MEMORY_CACHING_TYPE,
    _address: wdk_sys::PVOID,
    _bugcheck_on_failure: wdk_sys::ULONG,
    _priority: wdk_sys::ULONG,
) -> wdk_sys::PVOID {
    panic!("host MDL fixtures must supply an already mapped buffer")
}

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
    FsRtlFastCheckLockForRead, FsRtlFastCheckLockForWrite, FsRtlGetSectorSizeInformation,
    FsRtlInitializeFileLock, FsRtlNotifyCleanup, FsRtlNotifyCleanupAll,
    FsRtlNotifyFullChangeDirectory, FsRtlNotifyFullReportChange, FsRtlNotifyInitializeSync,
    FsRtlNotifyUninitializeSync, FsRtlUninitializeFileLock, IoAcquireVpbSpinLock, IoAllocateIrp,
    IoAllocateMdl, IoAllocateWorkItem, IoCancelIrp, IoCsqInitialize, IoCsqInsertIrp,
    IoCsqRemoveNextIrp, IoFreeIrp, IoFreeMdl, IoFreeWorkItem, IoGetNextIrpStackLocation,
    IoGetRequestorProcess, IoGetTopLevelIrp, IoQueueWorkItem, IoRegisterShutdownNotification,
    IoReleaseVpbSpinLock, IoSetCompletionRoutineEx, IoSetTopLevelIrp,
    IoUnregisterShutdownNotification, IofCallDriver, KeAcquireSpinLockRaiseToDpc, KeCancelTimer,
    KeFlushQueuedDpcs, KeInitializeDpc, KeInitializeEvent, KeInitializeSpinLock, KeInitializeTimer,
    KeInsertQueueDpc, KeReleaseSpinLock, KeSetEvent, KeSetTimer, KeWaitForSingleObject,
    MmBuildMdlForNonPagedPool, MmUnlockPages, ObfDereferenceObject, ObfReferenceObject,
    PsCreateSystemThread, PsTerminateSystemThread, ZwClose, ZwWaitForSingleObject,
};

#[cfg(not(test))]
pub(crate) use wdk_sys::IoFileObjectType;
#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::{
    ExFreePool, IoGetDeviceAttachmentBaseRef, IoGetDeviceInterfaces, IoGetDeviceObjectPointer,
    IoGetRelatedDeviceObject, ObReferenceObjectByHandle, ZwCreateFile,
};

#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::{
    IoAcquireCancelSpinLock, IoReleaseCancelSpinLock, IoSetCancelRoutine,
};

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe extern "system" {
    /// Copies effective user/primary-group SIDs while retaining and locking the captured subject.
    pub(crate) fn ext4win_creator_sids(
        subject: *mut wdk_sys::SECURITY_SUBJECT_CONTEXT,
        user: *mut u8,
        user_length: *mut u32,
        group: *mut u8,
        group_length: *mut u32,
    ) -> wdk_sys::NTSTATUS;

    /// Copies the fixed signed VCN from the current FSCTL's Type3 buffer under SEH.
    pub(crate) fn ext4win_capture_starting_vcn(
        irp: wdk_sys::PIRP,
        value: *mut i64,
    ) -> wdk_sys::NTSTATUS;

    /// Locks a bounded writable requestor prefix as an opaque owning native target.
    pub(crate) fn ext4win_capture_requestor_output(
        output_out: *mut wdk_sys::PVOID,
        requestor_buffer: wdk_sys::PVOID,
        capacity: wdk_sys::ULONG,
        requestor_mode: wdk_sys::KPROCESSOR_MODE,
    ) -> wdk_sys::NTSTATUS;

    /// Copies owned bytes into a captured query target, then consumes and unlocks the target.
    pub(crate) fn ext4win_copy_requestor_output(
        output: wdk_sys::PVOID,
        owned_source: *const core::ffi::c_void,
        source_length: wdk_sys::ULONG,
    ) -> wdk_sys::NTSTATUS;

    /// Releases an unconsumed locked requestor output.
    pub(crate) fn ext4win_release_requestor_output(output: wdk_sys::PVOID);

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
    /// Opens the service-owned persistent identity root at PASSIVE_LEVEL.
    pub(crate) fn ext4win_identity_open_root(
        service: wdk_sys::PCUNICODE_STRING,
        output: *mut wdk_sys::HANDLE,
    ) -> wdk_sys::NTSTATUS;
    /// Enumerates one canonical UUID subkey into 36 UTF-16 units.
    pub(crate) fn ext4win_identity_enumerate(
        root: wdk_sys::HANDLE,
        index: u32,
        uuid: *mut u16,
    ) -> wdk_sys::NTSTATUS;
    /// Reads one complete bounded binary table into pool-aligned owned storage.
    pub(crate) fn ext4win_identity_read(
        root: wdk_sys::HANDLE,
        uuid: *const u16,
        buffer: wdk_sys::PVOID,
        capacity: u32,
        length: *mut u32,
    ) -> wdk_sys::NTSTATUS;
    /// Saves and flushes a whole table, retaining the accepted-effect phase on failure.
    pub(crate) fn ext4win_identity_save(
        root: wdk_sys::HANDLE,
        uuid: *const u16,
        record: *const u8,
        length: u32,
        phase: *mut u32,
    ) -> wdk_sys::NTSTATUS;
    /// Establishes durability of a record observed during reconciliation.
    pub(crate) fn ext4win_identity_flush(
        root: wdk_sys::HANDLE,
        uuid: *const u16,
    ) -> wdk_sys::NTSTATUS;
    /// Releases the kernel-only root after all worker and catalog ownership drains.
    pub(crate) fn ext4win_identity_close(root: wdk_sys::HANDLE);

}
