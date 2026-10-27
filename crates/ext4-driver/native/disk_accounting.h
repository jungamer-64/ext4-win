#pragma once

/* Called before handing the private request to storage; records issued physical bytes,
 * including retries, independently of the logical request's eventual completion. */
VOID NTAPI ext4win_account_lower_io(PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(irp);
    if (stack->MajorFunction == IRP_MJ_READ) {
        FsRtlUpdateDiskCounters(stack->Parameters.Read.Length, 0);
    } else if (stack->MajorFunction == IRP_MJ_WRITE) {
        FsRtlUpdateDiskCounters(0, stack->Parameters.Write.Length);
    }
}

/* Capture runs on the issuing thread. Cc owns nested paging charges; mapped faults and
 * modified-page writes retain a separate process reference across actor transfer. */
PVOID NTAPI ext4win_capture_disk_process(PIRP irp)
{
    PIRP top = IoGetTopLevelIrp();
    PETHREAD issuing = PsGetCurrentThread();
    PETHREAD request = irp->Tail.Overlay.Thread;
    BOOLEAN nested = top != NULL && top != irp && top != (PIRP)FSRTL_MOD_WRITE_TOP_LEVEL_IRP;
    PEPROCESS process;
    process = IoGetRequestorProcess(irp);
    if ((irp->Flags & IRP_PAGING_IO) != 0) {
        /* Inline page faults retain their user origin even inside a nested cache read.
         * Background nested paging is accounted by Cc; modified-page writes are independent. */
        if (IoGetCurrentIrpStackLocation(irp)->MajorFunction == IRP_MJ_READ &&
            request != NULL && !IoIsSystemThread(request)) {
            process = PsGetThreadProcess(request);
        } else if (IoGetCurrentIrpStackLocation(irp)->MajorFunction == IRP_MJ_READ &&
                   !IoIsSystemThread(issuing)) {
            process = PsGetThreadProcess(issuing);
        } else if (nested) { return NULL; }
    }
    if (process == NULL) { process = PsGetThreadProcess(issuing); }
    ObReferenceObject(process);
    return process;
}

/* Lifecycle queue markers have no allocated capture. Observe only their retained IRP
 * requestor; substituting the current actor thread would attribute I/O to the worker. */
PVOID NTAPI ext4win_capture_lifecycle_disk_process(PIRP irp)
{
    PEPROCESS process = IoGetRequestorProcess(irp);
    if (process != NULL) { ObReferenceObject(process); }
    return process;
}

VOID NTAPI ext4win_account_process_io(PVOID origin, ULONG64 read, ULONG64 written, ULONG flush)
{
    if (!PsIsDiskCountersEnabled()) { return; }
    PsUpdateDiskCounters((PEPROCESS)origin, read, written, read != 0, written != 0, flush);
}

/* Paging-file forwarding executes entirely in the original dispatch ownership scope. */
VOID NTAPI ext4win_account_paging_io(PIRP irp, ULONG64 read, ULONG64 written, ULONG flush)
{
    PEPROCESS process;
    if (!PsIsDiskCountersEnabled()) { return; }
    process = IoGetRequestorProcess(irp);
    if (process == NULL) { process = PsGetThreadProcess(PsGetCurrentThread()); }
    ext4win_account_process_io(process, read, written, flush);
}
