#include <stddef.h>
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
#define assert(value) do { if (!(value)) { ExitProcess(__LINE__); } } while (0)
#define VOID void
#define NTAPI __stdcall
#define IRP_MJ_READ 3
#define IRP_MJ_WRITE 4
#define IRP_PAGING_IO 2
#define FSRTL_MOD_WRITE_TOP_LEVEL_IRP 3
typedef unsigned long ULONG;
typedef unsigned char BOOLEAN;
typedef unsigned long long ULONG64;
typedef void *PEPROCESS;
typedef void *PETHREAD;
typedef void *PVOID;
typedef struct {
    unsigned char MajorFunction;
    union { struct { ULONG Length; } Read, Write; } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
typedef struct {
    IO_STACK_LOCATION stack;
    PEPROCESS process;
    ULONG Flags;
    struct { struct { PETHREAD Thread; } Overlay; } Tail;
} IRP, *PIRP;
static int enabled, process_calls, physical_calls;
static int references, thread_process, other_process;
static int current_is_system = 1;
static PIRP top;
static PEPROCESS last_process;
static ULONG64 physical_read, physical_written, charged_read, charged_written;
static ULONG read_count, write_count, flush_count;
static PIO_STACK_LOCATION IoGetNextIrpStackLocation(PIRP irp) { return &irp->stack; }
static PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP irp) { return &irp->stack; }
static PEPROCESS IoGetRequestorProcess(PIRP irp) { return irp->process; }
static PIRP IoGetTopLevelIrp(void) { return top; }
static PVOID PsGetCurrentThread(void) { return &thread_process; }
static PEPROCESS PsGetThreadProcess(PVOID thread) { return thread; }
static int IoIsSystemThread(PETHREAD thread) {
    return thread == &enabled || (thread == &thread_process && current_is_system);
}
static void ObReferenceObject(PEPROCESS process) { assert(process != NULL); ++references; }
static void ObDereferenceObject(PEPROCESS process) { assert(process != NULL && references > 0); --references; }
static int PsIsDiskCountersEnabled(void) { return enabled; }
static void FsRtlUpdateDiskCounters(ULONG64 read, ULONG64 written)
{
    ++physical_calls; physical_read += read; physical_written += written;
}
static void PsUpdateDiskCounters(PEPROCESS process, ULONG64 read, ULONG64 written,
    ULONG reads, ULONG writes, ULONG flushes)
{
    assert(process == &enabled || process == &thread_process || process == &other_process);
    last_process = process;
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
    ext4win_account_process_io(&enabled, 17, 0, 0);
    assert(process_calls == 0);
    enabled = 1;
    ext4win_account_process_io(&enabled, 17, 0, 0);
    ext4win_account_process_io(&enabled, 0, 23, 0);
    ext4win_account_process_io(&enabled, 0, 0, 1);
    irp.process = NULL;
    assert(process_calls == 3 && charged_read == 17 && charged_written == 23);
    assert(read_count == 1 && write_count == 1 && flush_count == 1);
    /* Nested Cc paging owns its charge; a mapped-page writer remains independent. */
    irp.Flags = IRP_PAGING_IO;
    top = (PIRP)1;
    assert(ext4win_capture_disk_process(&irp) == NULL && references == 0);
    top = (PIRP)FSRTL_MOD_WRITE_TOP_LEVEL_IRP;
    {
        PVOID captured = ext4win_capture_disk_process(&irp);
        assert(captured == &thread_process && references == 1);
        irp.process = &other_process;
        ext4win_account_process_io(captured, 4096, 0, 0);
        assert(last_process == &thread_process);
        ObDereferenceObject(captured);
    }
    top = &irp;
    {
        PVOID captured = ext4win_capture_disk_process(&irp);
        assert(captured == &other_process && references == 1);
        ObDereferenceObject(captured);
    }
    top = (PIRP)1;
    irp.stack.MajorFunction = IRP_MJ_READ;
    irp.Tail.Overlay.Thread = &other_process;
    {
        PVOID captured = ext4win_capture_disk_process(&irp);
        assert(captured == &other_process && references == 1);
        ObDereferenceObject(captured);
    }
    irp.Tail.Overlay.Thread = &enabled;
    irp.process = &enabled;
    current_is_system = 0;
    {
        PVOID captured = ext4win_capture_disk_process(&irp);
        assert(captured == &thread_process && references == 1);
        ObDereferenceObject(captured);
    }
    current_is_system = 1;
    /* Lifecycle capture cannot accidentally attribute work to its current actor. */
    irp.process = NULL;
    assert(ext4win_capture_lifecycle_disk_process(&irp) == NULL && references == 0);
    irp.process = &enabled;
    {
        PVOID captured = ext4win_capture_lifecycle_disk_process(&irp);
        assert(captured == &enabled && references == 1);
        ObDereferenceObject(captured);
    }
    ext4win_account_paging_io(&irp, 0, 4096, 0);
    assert(last_process == &enabled && references == 0);
    ExitProcess(0);
}
