/* Execute the production FsRtl boundary with independent shared/exclusive
 * argument expectations, including native failure and atomic CREATE. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _IRQL_requires_max_(level)
#define _Must_inspect_result_
#define _In_
#define _Inout_
#define NTAPI
#define TRUE 1
#define NULL ((void *)0)
#define STATUS_INVALID_PARAMETER (-1)
#define IRP_MJ_CREATE 0
#define IRP_MJ_FILE_SYSTEM_CONTROL 9
#define EXT4WIN_TRACE_EVENT_OPLOCK_CONTROL 1
#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS 1
#define GetExceptionCode() ((NTSTATUS)__exception_code())

typedef int NTSTATUS;
typedef unsigned ULONG;
typedef unsigned char BOOLEAN;
typedef void *PVOID;
typedef struct { unsigned held; } ERESOURCE, *PERESOURCE;
typedef struct { unsigned locks, requests; } FILE_LOCK, *PFILE_LOCK;
typedef struct { unsigned MajorFunction; } IO_STACK_LOCATION, *PIO_STACK_LOCATION;
typedef struct { IO_STACK_LOCATION stack; unsigned shared; } IRP, *PIRP;
typedef struct {
    unsigned Kind;
    PFILE_LOCK ByteRangeLocks;
    ERESOURCE MainResource;
    struct { unsigned Oplock; } Header;
} EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;

static EXT4WIN_STREAM_CONTEXT stream;
static FILE_LOCK locks;
static unsigned expected_count, calls, projections;
static NTSTATUS expected_status;
__declspec(dllimport) void __stdcall RaiseException(ULONG, ULONG, ULONG, const unsigned long long *);

static PEXT4WIN_STREAM_CONTEXT ext4win_stream_from_header(PVOID header) { return header; }
static void ext4win_trace_selected(PEXT4WIN_STREAM_CONTEXT target, unsigned event) {
    assert(target == &stream && event == EXT4WIN_TRACE_EVENT_OPLOCK_CONTROL);
}
static void ext4win_trace_status(PEXT4WIN_STREAM_CONTEXT target, unsigned event, NTSTATUS status) {
    assert(target == &stream && event == EXT4WIN_TRACE_EVENT_OPLOCK_CONTROL);
    assert(status == expected_status && !stream.MainResource.held && !locks.requests);
}
static void wdk_sys_acquire_resource_exclusive(PERESOURCE resource, unsigned wait) {
    assert(resource == &stream.MainResource && !resource->held && wait);
    resource->held = 1;
}
static void wdk_sys_release_resource(PERESOURCE resource) {
    assert(resource == &stream.MainResource && resource->held);
    resource->held = 0;
}
static PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP irp) { return &irp->stack; }
static BOOLEAN FsRtlOplockIsSharedRequest(PIRP irp) {
    assert(stream.MainResource.held && irp->stack.MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL);
    return (BOOLEAN)irp->shared;
}
static BOOLEAN FsRtlAreThereCurrentFileLocks(PFILE_LOCK file_lock) {
    assert(file_lock == &locks && stream.MainResource.held && !locks.requests);
    return (BOOLEAN)file_lock->locks;
}
static void FsRtlIncrementLockRequestsInProgress(PFILE_LOCK file_lock) { file_lock->requests++; }
static void FsRtlDecrementLockRequestsInProgress(PFILE_LOCK file_lock) { file_lock->requests--; }
static void ext4win_stream_refresh_fast_io_projection(PEXT4WIN_STREAM_CONTEXT target) {
    assert(target == &stream && stream.MainResource.held && !locks.requests);
    projections++;
}
static NTSTATUS wdk_sys_oplock_fsctrl(unsigned *oplock, PIRP irp, ULONG count, ULONG flags) {
    assert(oplock == &stream.Header.Oplock && irp != NULL && flags == 0);
    assert(stream.MainResource.held && locks.requests == 1 && count == expected_count);
    calls++;
    if (expected_status < 0) { RaiseException((ULONG)expected_status, 0, 0, NULL); }
    return expected_status;
}

#include "oplock_control.h"

int main(void) {
    IRP irp = {{IRP_MJ_FILE_SYSTEM_CONTROL}, 0};
    unsigned scenario;
    stream.Kind = 1;
    stream.ByteRangeLocks = &locks;
    for (scenario = 0; scenario < 5; scenario++) {
        irp.stack.MajorFunction = scenario == 4 ? IRP_MJ_CREATE : IRP_MJ_FILE_SYSTEM_CONTROL;
        irp.shared = scenario < 3;
        locks.locks = scenario == 1;
        expected_count = scenario < 3 ? locks.locks : 7;
        expected_status = scenario == 2 ? (NTSTATUS)0xC000009AUL : 0x103;
        assert(ext4win_stream_oplock_fsctrl(&stream, &irp, 7, 0) == expected_status);
        assert(calls == scenario + 1 && projections == scenario + 1);
        assert(!stream.MainResource.held && !locks.requests);
    }
    assert(ext4win_stream_oplock_fsctrl(NULL, &irp, 7, 0) == STATUS_INVALID_PARAMETER);
    assert(calls == 5);
    return 0;
}
