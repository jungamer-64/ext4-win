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

#include "cluster_control_capture.h"
#include "requestor_access.h"

static BOOLEAN
ext4win_is_requestor_mode_valid(_In_ KPROCESSOR_MODE requestor_mode)
{
    return (requestor_mode == KernelMode) || (requestor_mode == UserMode);
}

/* Fixed Type3 input is snapshotted in requestor context before actor admission. */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS NTAPI
ext4win_capture_allocation_start(_In_ PIRP irp, _Out_ PLONGLONG value)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status;
    PVOID source;
    if ((value == NULL) || (stack->MajorFunction != IRP_MJ_FILE_SYSTEM_CONTROL) ||
        ((stack->Parameters.FileSystemControl.FsControlCode != FSCTL_GET_RETRIEVAL_POINTERS) &&
         (stack->Parameters.FileSystemControl.FsControlCode != FSCTL_GET_VOLUME_BITMAP)) ||
        (stack->Parameters.FileSystemControl.InputBufferLength < sizeof(*value)) ||
        !ext4win_is_requestor_mode_valid(irp->RequestorMode)) { return STATUS_INVALID_PARAMETER; }
    source = stack->Parameters.FileSystemControl.Type3InputBuffer;
    if (source == NULL) { return STATUS_INVALID_USER_BUFFER; }
    status = ext4win_requestor_read(irp->RequestorMode, source, value, sizeof(*value),
        TYPE_ALIGNMENT(LONGLONG));
    if (NT_SUCCESS(status) && (*value < 0)) { return STATUS_INVALID_PARAMETER; }
    return status;
}
