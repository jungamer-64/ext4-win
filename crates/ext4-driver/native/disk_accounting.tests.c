#include <stddef.h>
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
#define assert(value) do { if (!(value)) { ExitProcess(__LINE__); } } while (0)
#define VOID void
#define NTAPI __stdcall
#define IRP_MJ_READ 3
#define IRP_MJ_WRITE 4
typedef unsigned long ULONG;
typedef unsigned long long ULONG64;
typedef void *PEPROCESS;
typedef struct {
    unsigned char MajorFunction;
    union { struct { ULONG Length; } Read, Write; } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
typedef struct { IO_STACK_LOCATION stack; PEPROCESS process; } IRP, *PIRP;
static int enabled, process_calls, physical_calls;
static ULONG64 physical_read, physical_written, charged_read, charged_written;
static ULONG read_count, write_count, flush_count;
static PIO_STACK_LOCATION IoGetNextIrpStackLocation(PIRP irp) { return &irp->stack; }
static PEPROCESS IoGetRequestorProcess(PIRP irp) { return irp->process; }
static int PsIsDiskCountersEnabled(void) { return enabled; }
static void FsRtlUpdateDiskCounters(ULONG64 read, ULONG64 written)
{
    ++physical_calls; physical_read += read; physical_written += written;
}
static void PsUpdateDiskCounters(PEPROCESS process, ULONG64 read, ULONG64 written,
    ULONG reads, ULONG writes, ULONG flushes)
{
    assert(process == &enabled);
    ++process_calls; charged_read += read; charged_written += written;
    read_count += reads; write_count += writes; flush_count += flushes;
}
#include "disk_accounting.h"
int main(void)
{
    IRP irp = {0};
    irp.process = &enabled;
    irp.stack.MajorFunction = IRP_MJ_READ;
    irp.stack.Parameters.Read.Length = 4096;
    ext4win_account_lower_io(&irp);
    irp.stack.MajorFunction = IRP_MJ_WRITE;
    irp.stack.Parameters.Write.Length = 8192;
    ext4win_account_lower_io(&irp);
    irp.stack.MajorFunction = 9;
    ext4win_account_lower_io(&irp);
    assert(physical_calls == 2 && physical_read == 4096 && physical_written == 8192);
    ext4win_account_request_io(&irp, 17, 0, 0);
    assert(process_calls == 0);
    enabled = 1;
    ext4win_account_request_io(&irp, 17, 0, 0);
    ext4win_account_request_io(&irp, 0, 23, 0);
    ext4win_account_request_io(&irp, 0, 0, 1);
    irp.process = NULL;
    ext4win_account_request_io(&irp, 10, 10, 1);
    assert(process_calls == 3 && charged_read == 17 && charged_written == 23);
    assert(read_count == 1 && write_count == 1 && flush_count == 1);
    ExitProcess(0);
}
