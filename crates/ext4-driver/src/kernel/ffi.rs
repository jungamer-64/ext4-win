//! I/O Manager symbols used by the driver boundary.

pub(crate) use wdk_sys::ntddk::RtlCopyVolatileMemory;

#[expect(
    unsafe_code,
    reason = "the native boundary owns concurrent access to the OS FILE_OBJECT flag word"
)]
unsafe extern "system" {
    /// Accounts issued physical bytes before private IRP ownership moves to the lower stack.
    /// # Safety
    /// The live private IRP must contain its initialized next stack location.
    #[cfg(not(test))]
    pub(crate) fn ext4win_account_lower_io(irp: wdk_sys::PIRP);
    /// Observes only flag bits; retaining the file does not grant access to its other fields.
    /// # Safety
    /// `file` must remain a live FILE_OBJECT throughout this native atomic load.
    pub(crate) fn ext4win_file_flags(file: wdk_sys::PFILE_OBJECT) -> wdk_sys::ULONG;
    /// Adds bits without losing concurrent cache or lifecycle updates.
    /// # Safety
    /// `file` must remain live and the caller must own the transition represented by `flags`.
    pub(crate) fn ext4win_file_set_flags(file: wdk_sys::PFILE_OBJECT, flags: wdk_sys::ULONG);
}

// Host tests execute the user-mode implementation of the WDK shared-memory copy contract.
#[cfg(test)]
#[link(name = "volatileaccessu", kind = "static")]
#[expect(
    unsafe_code,
    reason = "host execution of the WDK copy binding requires its user-mode static library"
)]
unsafe extern "C" {}

#[cfg(not(test))]
pub(crate) use wdk::file_system::complete_request;
pub(crate) use wdk_sys::FILE_DEVICE_DISK_FILE_SYSTEM;
#[cfg(not(test))]
pub(crate) use wdk_sys::ntddk::{
    IoCheckShareAccess, IoCreateDevice, IoDeleteDevice, IoRemoveShareAccess,
    KeQueryInterruptTimePrecise, KeQuerySystemTimePrecise,
};
pub(crate) use wdk_sys::ntddk::{
    IoCreateSymbolicLink, IoDeleteSymbolicLink, IoRegisterFileSystem, IoUnregisterFileSystem,
};

/// # Safety
/// Retains the I/O Manager ABI; host fixtures cannot create kernel device objects.
/// # Panics
/// Fails if a host fixture attempts native device creation.
#[cfg(test)]
#[expect(
    unsafe_code,
    non_snake_case,
    clippy::panic,
    clippy::disallowed_macros,
    reason = "host admission tests must not simulate kernel device allocation"
)]
pub(crate) unsafe fn IoCreateDevice(
    _driver: wdk_sys::PDRIVER_OBJECT,
    _extension_size: wdk_sys::ULONG,
    _name: wdk_sys::PUNICODE_STRING,
    _device_type: wdk_sys::ULONG,
    _characteristics: wdk_sys::ULONG,
    _exclusive: wdk_sys::BOOLEAN,
    _device: *mut wdk_sys::PDEVICE_OBJECT,
) -> wdk_sys::NTSTATUS {
    panic!("native device creation requires the I/O Manager")
}

/// # Safety
/// Retains the I/O Manager ABI; host fixtures never own deletable kernel device objects.
/// # Panics
/// Fails if a host fixture attempts native device deletion.
#[cfg(test)]
#[expect(
    unsafe_code,
    non_snake_case,
    clippy::panic,
    clippy::disallowed_macros,
    reason = "host admission tests cannot delete a kernel device they never acquired"
)]
pub(crate) unsafe fn IoDeleteDevice(_device: wdk_sys::PDEVICE_OBJECT) {
    panic!("native device deletion requires the I/O Manager")
}

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

/// # Safety
/// Retains the kernel clock ABI; host fixtures must supply clock observations explicitly.
/// # Panics
/// Fails if a host fixture reaches this kernel-only boundary.
#[cfg(test)]
#[expect(
    unsafe_code,
    non_snake_case,
    clippy::panic,
    clippy::disallowed_macros,
    reason = "host fixtures cannot synthesize kernel monotonic clock observations"
)]
pub(crate) unsafe fn KeQueryInterruptTimePrecise(_counter: *mut u64) -> u64 {
    panic!("kernel monotonic clock observation requires a loaded driver")
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
    /// # Safety
    /// Must run on the original requestor dispatch thread before queue insertion.
    pub(crate) fn ext4win_volume_management_privilege(mode: wdk_sys::KPROCESSOR_MODE) -> u8;
    /// Checks symbolic-link creation against the dispatch thread's effective token.
    pub(crate) fn ext4win_symbolic_link_privilege(mode: wdk_sys::KPROCESSOR_MODE) -> u8;
    /// Captures the effective requestor and retains a device-bound cleanup work item.
    pub(crate) fn ext4win_subject_capture(
        device: wdk_sys::PDEVICE_OBJECT,
        mode: wdk_sys::KPROCESSOR_MODE,
        output: *mut wdk_sys::PVOID,
    ) -> wdk_sys::NTSTATUS;
    /// Consumes the subject; raised-IRQL cancellation defers token retirement to its retained worker.
    pub(crate) fn ext4win_subject_release(subject: wdk_sys::PVOID);
    /// Captures notification traversal authority on the original dispatch thread.
    pub(crate) fn ext4win_notification_subject_capture(
        device: wdk_sys::PDEVICE_OBJECT,
        mode: wdk_sys::KPROCESSOR_MODE,
        output: *mut wdk_sys::PVOID,
    ) -> wdk_sys::NTSTATUS;
    /// Consumes a captured subject and transfers its token/pool ownership to FsRtl.
    pub(crate) fn ext4win_subject_transfer_notification(
        subject: wdk_sys::PVOID,
    ) -> *mut wdk_sys::SECURITY_SUBJECT_CONTEXT;
    /// Checks target attribute rights against the retained effective subject at PASSIVE_LEVEL.
    pub(crate) fn ext4win_subject_write_attributes(
        subject: wdk_sys::PVOID,
        descriptor: wdk_sys::PSECURITY_DESCRIPTOR,
    ) -> wdk_sys::NTSTATUS;
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
    FsRtlInitializeFileLock, FsRtlNotifyUninitializeSync, FsRtlUninitializeFileLock,
    IoAcquireVpbSpinLock, IoAllocateIrp, IoAllocateMdl, IoAllocateWorkItem, IoCancelIrp,
    IoCsqInitialize, IoCsqInsertIrp, IoCsqRemoveNextIrp, IoFreeIrp, IoFreeMdl, IoFreeWorkItem,
    IoGetNextIrpStackLocation, IoGetRequestorProcess, IoQueueWorkItem,
    IoRegisterShutdownNotification, IoReleaseVpbSpinLock, IoSetCompletionRoutineEx,
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
    IoAcquireCancelSpinLock, IoReleaseCancelSpinLock, IoSetCancelRoutine, SePrivilegeCheck,
};

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe extern "system" {
    /// Initializes unowned FsRtl synchronization storage at PASSIVE_LEVEL.
    /// Returns only success or insufficient resources; allocation exceptions are caught in C.
    pub(crate) fn ext4win_notify_initialize_sync(
        sync: *mut wdk_sys::PNOTIFY_SYNC,
    ) -> wdk_sys::NTSTATUS;

    /// Transfers a live watch IRP to FsRtl with recursive completion marked until return.
    /// The pinned sync/list and CCB context must outlive the registered watch.
    pub(crate) fn ext4win_notify_register(
        sync: wdk_sys::PNOTIFY_SYNC,
        list: *mut wdk_sys::LIST_ENTRY,
        context: wdk_sys::PVOID,
        directory: wdk_sys::PSTRING,
        filter: u32,
        subtree: u8,
        irp: wdk_sys::PIRP,
        subject: *mut wdk_sys::SECURITY_SUBJECT_CONTEXT,
    );

    /// Checks one aligned descriptor against the callback's already-locked captured subject.
    pub(crate) fn ext4win_notification_check_traverse(
        subject: *mut wdk_sys::SECURITY_SUBJECT_CONTEXT,
        descriptor: wdk_sys::PSECURITY_DESCRIPTOR,
    ) -> u8;

    /// Copies effective user/primary-group SIDs while retaining and locking the captured subject.
    pub(crate) fn ext4win_creator_sids(
        subject: *mut wdk_sys::SECURITY_SUBJECT_CONTEXT,
        user: *mut u8,
        user_length: *mut u32,
        group: *mut u8,
        group_length: *mut u32,
    ) -> wdk_sys::NTSTATUS;

    /// Snapshots the fixed signed VCN or LCN from a supported allocation FSCTL under SEH.
    pub(crate) fn ext4win_capture_allocation_start(
        irp: wdk_sys::PIRP,
        value: *mut i64,
    ) -> wdk_sys::NTSTATUS;

    /// Snapshots buffered cluster-control ABI fields without acquiring object authority.
    pub(crate) fn ext4win_capture_cluster_control(
        irp: wdk_sys::PIRP,
        handle: *mut wdk_sys::HANDLE,
        vcn: *mut u64,
        lcn: *mut u64,
        count: *mut u32,
        source_info: *mut u32,
        flags: *mut u32,
    ) -> wdk_sys::NTSTATUS;

    /// Resolves an admitted embedded handle before leaving its original requestor context.
    pub(crate) fn ext4win_reference_cluster_file(
        handle: wdk_sys::HANDLE,
        mode: wdk_sys::KPROCESSOR_MODE,
        file: *mut wdk_sys::PFILE_OBJECT,
        granted: *mut u32,
    ) -> wdk_sys::NTSTATUS;

    /// Borrows one coherent native size tuple under the retained header mutex.
    pub(crate) fn ext4win_stream_get_sizes(
        header: *mut core::ffi::c_void,
        allocation: *mut i64,
        eof: *mut i64,
        valid: *mut i64,
        charge: *mut i64,
    ) -> wdk_sys::NTSTATUS;

    /// Projects an activated paging map into the native advanced-header flags.
    pub(crate) fn ext4win_stream_mark_paging_file(header: *mut core::ffi::c_void);

    /// Copies an I/O Manager-captured descriptor into owned, aligned memory and validates it.
    pub(crate) fn ext4win_capture_io_manager_security_descriptor(
        source: wdk_sys::PSECURITY_DESCRIPTOR,
        required_information: wdk_sys::SECURITY_INFORMATION,
        maximum_length: wdk_sys::ULONG,
        snapshot_out: *mut wdk_sys::PVOID,
        length_out: *mut wdk_sys::ULONG,
    ) -> wdk_sys::NTSTATUS;

    /// Releases one native set-security snapshot.
    pub(crate) fn ext4win_release_set_security_descriptor(snapshot: wdk_sys::PVOID);

    /// Copies an I/O Manager-captured FILE_GET_EA_INFORMATION list into owned nonpaged memory.
    pub(crate) fn ext4win_capture_io_manager_ea_name_list(
        source: *const core::ffi::c_void,
        length: wdk_sys::ULONG,
        snapshot_out: *mut wdk_sys::PVOID,
        length_out: *mut wdk_sys::ULONG,
    ) -> wdk_sys::NTSTATUS;

    /// Copies one validated I/O-manager-owned query pattern into nonpaged native memory.
    pub(crate) fn ext4win_capture_io_manager_directory_pattern(
        source: *const wdk_sys::UNICODE_STRING,
        snapshot_out: *mut wdk_sys::PVOID,
        length_out: *mut wdk_sys::ULONG,
    ) -> wdk_sys::NTSTATUS;

    /// Releases one owned EA-list or directory-pattern snapshot.
    pub(crate) fn ext4win_release_captured_auxiliary_input(snapshot: wdk_sys::PVOID);
    /// Opens the service-owned persistent configuration root at PASSIVE_LEVEL.
    pub(crate) fn ext4win_configuration_open_root(
        service: wdk_sys::PCUNICODE_STRING,
        domain: u32,
        output: *mut wdk_sys::HANDLE,
    ) -> wdk_sys::NTSTATUS;
    /// Enumerates one canonical UUID subkey into 36 UTF-16 units.
    pub(crate) fn ext4win_configuration_enumerate(
        root: wdk_sys::HANDLE,
        index: u32,
        uuid: *mut u16,
    ) -> wdk_sys::NTSTATUS;
    /// Reads one complete bounded binary table into pool-aligned owned storage.
    pub(crate) fn ext4win_configuration_read(
        root: wdk_sys::HANDLE,
        uuid: *const u16,
        buffer: wdk_sys::PVOID,
        capacity: u32,
        length: *mut u32,
    ) -> wdk_sys::NTSTATUS;
    /// Saves and flushes a whole table, retaining the accepted-effect phase on failure.
    pub(crate) fn ext4win_configuration_save(
        root: wdk_sys::HANDLE,
        uuid: *const u16,
        record: *const u8,
        length: u32,
        phase: *mut u32,
    ) -> wdk_sys::NTSTATUS;
    /// Establishes durability of a record observed during reconciliation.
    pub(crate) fn ext4win_configuration_flush(
        root: wdk_sys::HANDLE,
        uuid: *const u16,
    ) -> wdk_sys::NTSTATUS;
    /// Releases the kernel-only root after all worker and catalog ownership drains.
    pub(crate) fn ext4win_configuration_close(root: wdk_sys::HANDLE);

}
