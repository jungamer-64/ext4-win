#pragma once

/* User addresses and handle values are relative to the issuing process. An IRP
 * can resume on another thread, and IoGetRequestorProcess can follow an attachment.
 * Require the issuing thread's owning process as well as the I/O Manager's view.
 * Kernel callers supply addresses and handles valid in the dispatch context. */
_IRQL_requires_max_(APC_LEVEL)
static __inline NTSTATUS ext4win_require_requestor_process(PIRP irp)
{
    PETHREAD thread;
    PEPROCESS process;
    if (irp->RequestorMode == KernelMode) { return STATUS_SUCCESS; }
    if (irp->RequestorMode != UserMode) { return STATUS_INVALID_PARAMETER; }
    thread = irp->Tail.Overlay.Thread;
    if (thread == NULL) { return STATUS_INVALID_DEVICE_STATE; }
    process = PsGetThreadProcess(thread);
    if (process == NULL || PsGetCurrentProcess() != process ||
        IoGetRequestorProcess(irp) != process) { return STATUS_INVALID_DEVICE_STATE; }
    return STATUS_SUCCESS;
}
