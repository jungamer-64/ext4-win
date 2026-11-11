#pragma once

/* Requestor memory is validated at most by a probe; its mapping can change before access.
 * Access violations and misalignment are therefore ordinary request failures here, unlike
 * the FsRtl expected-status filter used for Cc/MM/FsRtl calls. Instruction faults and other
 * unexpected statuses remain driver defects and continue the exception search. */
static __inline LONG
ext4win_requestor_access_filter(_In_ NTSTATUS code)
{
    return ((code == STATUS_ACCESS_VIOLATION) || (code == STATUS_DATATYPE_MISALIGNMENT) ||
            FsRtlIsNtstatusExpected(code))
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH;
}

/* Address-space faults keep their exact status; any other contained raise is a buffer error. */
static __inline NTSTATUS
ext4win_requestor_access_status(_In_ NTSTATUS code)
{
    return ((code == STATUS_ACCESS_VIOLATION) || (code == STATUS_DATATYPE_MISALIGNMENT) ||
            (code == STATUS_IN_PAGE_ERROR))
        ? code
        : STATUS_INVALID_USER_BUFFER;
}

/* Copies a fixed requestor prefix into driver storage in the original requestor context.
 * A user-mode source is probed here; a kernel-mode source belongs to its trusted caller. */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static __inline NTSTATUS
ext4win_requestor_read(
    _In_ KPROCESSOR_MODE mode,
    _In_reads_bytes_(length) const VOID *source,
    _Out_writes_bytes_(length) PVOID destination,
    _In_ ULONG length,
    _In_ ULONG alignment)
{
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        if (mode == UserMode) { ProbeForRead((PVOID)source, length, alignment); }
        RtlCopyVolatileMemory(destination, source, length);
    }
    __except (ext4win_requestor_access_filter((NTSTATUS)GetExceptionCode())) {
        status = ext4win_requestor_access_status((NTSTATUS)GetExceptionCode());
    }
    return status;
}

/* Publishes a prepared driver record to an I/O Manager-probed requestor buffer. Callers hold
 * no driver resource or critical region here: a contained fault returns without cleanup. */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static __inline NTSTATUS
ext4win_requestor_write(
    _Out_writes_bytes_(length) PVOID destination,
    _In_reads_bytes_(length) const VOID *source,
    _In_ ULONG length)
{
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        RtlCopyVolatileMemory(destination, source, length);
    }
    __except (ext4win_requestor_access_filter((NTSTATUS)GetExceptionCode())) {
        status = ext4win_requestor_access_status((NTSTATUS)GetExceptionCode());
    }
    return status;
}
