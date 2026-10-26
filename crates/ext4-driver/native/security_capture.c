#include <ntifs.h>

#define EXT4WIN_SECURITY_POOL_TAG ((ULONG)0x53773445UL)

#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS                                      \
    (FsRtlIsNtstatusExpected((NTSTATUS)GetExceptionCode())                     \
         ? EXCEPTION_EXECUTE_HANDLER                                           \
         : EXCEPTION_CONTINUE_SEARCH)

/* Requestor output mappings and Type3 input are probed in their original context.
 * I/O Manager input snapshots have a separate native ownership contract. */
#include "io_manager_input.h"
#include "input_validation.h"

typedef struct _EXT4WIN_REQUESTOR_OUTPUT {
    PMDL Mdl;
    PVOID SystemAddress;
    ULONG Capacity;
} EXT4WIN_REQUESTOR_OUTPUT, *PEXT4WIN_REQUESTOR_OUTPUT;

static BOOLEAN
ext4win_is_requestor_mode_valid(_In_ KPROCESSOR_MODE requestor_mode)
{
    return (requestor_mode == KernelMode) || (requestor_mode == UserMode);
}

static NTSTATUS
ext4win_normalize_buffer_exception(_In_ LONG exception_code)
{
    const NTSTATUS status = (NTSTATUS)exception_code;

    if ((status == STATUS_ACCESS_VIOLATION) ||
        (status == STATUS_DATATYPE_MISALIGNMENT) ||
        (status == STATUS_IN_PAGE_ERROR)) {
        return status;
    }

    return STATUS_INVALID_USER_BUFFER;
}

static VOID
ext4win_release_requestor_output_internal(
    _Frees_ptr_opt_ PEXT4WIN_REQUESTOR_OUTPUT output)
{
    if (output == NULL) {
        return;
    }

    /* Only the successful capture handle can reach this private destructor. */
#pragma warning(suppress: 6001)
    if (output->Mdl != NULL) {
        MmUnlockPages(output->Mdl);
        IoFreeMdl(output->Mdl);
    }
    RtlSecureZeroMemory(output, sizeof(*output));
    ExFreePoolWithTag(output, EXT4WIN_SECURITY_POOL_TAG);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_capture_requestor_output(
    _Outptr_ PVOID *output_out,
    _In_opt_ PVOID requestor_buffer,
    _In_ ULONG capacity,
    _In_ KPROCESSOR_MODE requestor_mode)
{
    PEXT4WIN_REQUESTOR_OUTPUT output;
    PVOID system_address;
    NTSTATUS status;

    if (output_out != NULL) {
        *output_out = NULL;
    }

    if ((output_out == NULL) ||
        !ext4win_is_requestor_mode_valid(requestor_mode) ||
        (capacity == 0)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (requestor_buffer == NULL) {
        return STATUS_INVALID_USER_BUFFER;
    }

    /* Successful return transfers this allocation through output_out to the Rust owner. */
#pragma warning(suppress: 6014)
    output = (PEXT4WIN_REQUESTOR_OUTPUT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*output),
        EXT4WIN_SECURITY_POOL_TAG);
    if (output == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(output, sizeof(*output));

    /* IoAllocateMdl consumes the untrusted virtual address, not its uninitialized contents. */
#pragma warning(suppress: 6001)
    output->Mdl = IoAllocateMdl(
        requestor_buffer,
        capacity,
        FALSE,
        FALSE,
        NULL);
    if (output->Mdl == NULL) {
        ext4win_release_requestor_output_internal(output);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = STATUS_SUCCESS;
    __try {
        MmProbeAndLockPages(output->Mdl, requestor_mode, IoWriteAccess);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = ext4win_normalize_buffer_exception(GetExceptionCode());
    }
    if (!NT_SUCCESS(status)) {
        IoFreeMdl(output->Mdl);
        output->Mdl = NULL;
        ext4win_release_requestor_output_internal(output);
        return status;
    }

    system_address = MmGetSystemAddressForMdlSafe(
        output->Mdl,
        (MM_PAGE_PRIORITY)(NormalPagePriority | MdlMappingNoExecute));
    if (system_address == NULL) {
        ext4win_release_requestor_output_internal(output);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    output->SystemAddress = system_address;
    output->Capacity = capacity;
    *output_out = output;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_copy_requestor_output(
    _In_ PVOID output_handle,
    _In_reads_bytes_(source_length) const VOID *owned_source,
    _In_ ULONG source_length)
{
    PEXT4WIN_REQUESTOR_OUTPUT output;
    NTSTATUS status;

    if (output_handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    output = (PEXT4WIN_REQUESTOR_OUTPUT)output_handle;
    if ((owned_source == NULL) || (source_length > output->Capacity) ||
        (output->Mdl == NULL) || (output->SystemAddress == NULL)) {
        status = STATUS_INVALID_PARAMETER;
    } else {
        RtlCopyVolatileMemory(output->SystemAddress, owned_source, source_length);
        status = STATUS_SUCCESS;
    }

    ext4win_release_requestor_output_internal(output);
    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NTAPI
ext4win_release_requestor_output(_Frees_ptr_opt_ PVOID output)
{
    /* Rust returns only the initialized opaque handle produced by the capture call. */
#pragma warning(suppress: 6001)
    ext4win_release_requestor_output_internal(
        (PEXT4WIN_REQUESTOR_OUTPUT)output);
}

/* Fixed Type3 input is snapshotted in requestor context before actor admission. */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS NTAPI
ext4win_capture_allocation_start(_In_ PIRP irp, _Out_ PLONGLONG value)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_SUCCESS;
    PVOID source;
    if ((value == NULL) || (stack->MajorFunction != IRP_MJ_FILE_SYSTEM_CONTROL) ||
        ((stack->Parameters.FileSystemControl.FsControlCode != FSCTL_GET_RETRIEVAL_POINTERS) &&
         (stack->Parameters.FileSystemControl.FsControlCode != FSCTL_GET_VOLUME_BITMAP)) ||
        (stack->Parameters.FileSystemControl.InputBufferLength < sizeof(*value)) ||
        !ext4win_is_requestor_mode_valid(irp->RequestorMode)) { return STATUS_INVALID_PARAMETER; }
    source = stack->Parameters.FileSystemControl.Type3InputBuffer;
    if (source == NULL) { return STATUS_INVALID_USER_BUFFER; }
    __try {
        if (irp->RequestorMode == UserMode) { ProbeForRead(source, sizeof(*value), TYPE_ALIGNMENT(LONGLONG)); }
        RtlCopyVolatileMemory(value, source, sizeof(*value));
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = ext4win_normalize_buffer_exception(GetExceptionCode());
    }
    if (NT_SUCCESS(status) && (*value < 0)) { return STATUS_INVALID_PARAMETER; }
    return status;
}
