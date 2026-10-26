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

/* Completion still owns the original request, and hence its requestor thread/process.
 * Cache hits are charged by Cc. No actor or notification worker process is substituted
 * when the original request has no associated requestor process. */
VOID NTAPI ext4win_account_request_io(PIRP irp, ULONG64 read, ULONG64 written, ULONG flush)
{
    PEPROCESS process;
    if (!PsIsDiskCountersEnabled()) { return; }
    process = IoGetRequestorProcess(irp);
    if (process == NULL) { return; }
    PsUpdateDiskCounters(process, read, written, read != 0, written != 0, flush);
}
