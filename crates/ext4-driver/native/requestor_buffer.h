#pragma once

#include "requestor_access.h"
#include "requestor_context.h"

/* The caller must lock the returned output in this dispatch context before deferring. */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS NTAPI ext4win_requestor_output_address(_In_ PIRP irp, _Out_ PVOID *address)
{
    NTSTATUS status;
    *address = NULL;
    if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_INVALID_DEVICE_STATE; }
    status = ext4win_require_requestor_process(irp);
    if (!NT_SUCCESS(status)) { return status; }
    if (irp->UserBuffer == NULL) { return STATUS_INVALID_USER_BUFFER; }
    *address = irp->UserBuffer;
    return STATUS_SUCCESS;
}

/* Fixed Type3 input is snapshotted in requestor context before actor admission. */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS NTAPI ext4win_capture_allocation_start(_In_ PIRP irp, _Out_ PLONGLONG value)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status;
    PVOID source;
    if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_INVALID_DEVICE_STATE; }
    if ((value == NULL) || (stack->MajorFunction != IRP_MJ_FILE_SYSTEM_CONTROL) ||
        ((stack->Parameters.FileSystemControl.FsControlCode != FSCTL_GET_RETRIEVAL_POINTERS) &&
         (stack->Parameters.FileSystemControl.FsControlCode != FSCTL_GET_VOLUME_BITMAP)) ||
        (stack->Parameters.FileSystemControl.InputBufferLength < sizeof(*value))) {
        return STATUS_INVALID_PARAMETER;
    }
    status = ext4win_require_requestor_process(irp);
    if (!NT_SUCCESS(status)) { return status; }
    source = stack->Parameters.FileSystemControl.Type3InputBuffer;
    if (source == NULL) { return STATUS_INVALID_USER_BUFFER; }
    status = ext4win_requestor_read(irp->RequestorMode, source, value, sizeof(*value),
        TYPE_ALIGNMENT(LONGLONG));
    if (NT_SUCCESS(status) && (*value < 0)) { return STATUS_INVALID_PARAMETER; }
    return status;
}
