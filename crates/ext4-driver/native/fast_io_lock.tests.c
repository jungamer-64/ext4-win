/* Execute the production Fast I/O lock callback with native admission and
 * file-lock oracles. Oplock exclusion must be observed under MainResource;
 * fallback retains the caller's completion storage without acquiring a lock. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _Success_(condition)
#define _In_
#define _Out_
#define NTAPI
#define UNREFERENCED_PARAMETER(value) ((void)(value))
#define FALSE 0
#define TRUE 1
#define NULL ((void *)0)

typedef int BOOLEAN;
typedef unsigned long ULONG;
typedef struct { unsigned held; } ERESOURCE, *PERESOURCE;
typedef struct { BOOLEAN possible; } OPLOCK, *POPLOCK;
typedef struct { unsigned requests; } FILE_LOCK, *PFILE_LOCK;
typedef struct { long long QuadPart; } LARGE_INTEGER, *PLARGE_INTEGER;
typedef struct { int Status; unsigned Information; } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef struct { unsigned identity; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { unsigned identity; } EPROCESS, *PEPROCESS;
typedef struct { unsigned identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct {
    struct { OPLOCK Oplock; } Header;
    ERESOURCE MainResource;
    PFILE_LOCK ByteRangeLocks;
} EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;

static EXT4WIN_STREAM_CONTEXT stream;
static FILE_LOCK locks;
static FILE_OBJECT file;
static EPROCESS process;
static DEVICE_OBJECT device;
static LARGE_INTEGER offset, length;
static IO_STATUS_BLOCK status;
static BOOLEAN oplock_changes_on_acquire, native_handled;
static unsigned acquisitions, releases, oplock_checks, lock_calls, projections;

static BOOLEAN ext4win_stream_fast_io_stream(
    PFILE_OBJECT observed, PEXT4WIN_STREAM_CONTEXT *out)
{
    assert(observed == &file);
    *out = &stream;
    return TRUE;
}

static void wdk_sys_acquire_resource_exclusive(PERESOURCE resource, BOOLEAN wait)
{
    assert(resource == &stream.MainResource && !resource->held && wait);
    if (oplock_changes_on_acquire) { stream.Header.Oplock.possible = FALSE; }
    resource->held = 1;
    acquisitions++;
}

static void wdk_sys_release_resource(PERESOURCE resource)
{
    assert(resource == &stream.MainResource && resource->held == 1);
    resource->held = 0;
    releases++;
}

BOOLEAN FsRtlOplockIsFastIoPossible(POPLOCK oplock)
{
    assert(oplock == &stream.Header.Oplock && stream.MainResource.held == 1);
    oplock_checks++;
    return oplock->possible;
}

static void FsRtlIncrementLockRequestsInProgress(PFILE_LOCK observed)
{
    assert(observed == &locks && !locks.requests && stream.MainResource.held == 1);
    locks.requests++;
}

static void FsRtlDecrementLockRequestsInProgress(PFILE_LOCK observed)
{
    assert(observed == &locks && locks.requests == 1 && stream.MainResource.held == 1);
    locks.requests--;
}

static BOOLEAN FsRtlFastLock(PFILE_LOCK observed, PFILE_OBJECT observed_file,
    PLARGE_INTEGER position, PLARGE_INTEGER count, PEPROCESS requestor, ULONG key,
    BOOLEAN fail_immediately, BOOLEAN exclusive, PIO_STATUS_BLOCK result,
    void *context, BOOLEAN synchronized)
{
    assert(observed == &locks && locks.requests == 1 && stream.MainResource.held == 1);
    assert(observed_file == &file && position == &offset && count == &length);
    assert(position->QuadPart == 64 && count->QuadPart == 32);
    assert(requestor == &process && key == 0x1234 && fail_immediately && exclusive);
    assert(result == &status && context == NULL && synchronized);
    lock_calls++;
    if (native_handled) { result->Status = 0; result->Information = 0; }
    return native_handled;
}

static void ext4win_stream_refresh_fast_io_projection(PEXT4WIN_STREAM_CONTEXT observed)
{
    assert(observed == &stream && !locks.requests && stream.MainResource.held == 1);
    projections++;
}

#include "fast_io_lock.h"

static void reset(void)
{
    stream.MainResource.held = 0;
    stream.Header.Oplock.possible = TRUE;
    stream.ByteRangeLocks = &locks;
    locks.requests = 0;
    oplock_changes_on_acquire = FALSE;
    native_handled = TRUE;
    offset.QuadPart = 64;
    length.QuadPart = 32;
    status.Status = -7;
    status.Information = 123;
    acquisitions = releases = oplock_checks = lock_calls = projections = 0;
}

static BOOLEAN lock(void)
{
    return ext4win_fast_io_lock(&file, &offset, &length, &process, 0x1234,
        TRUE, TRUE, &status, &device);
}

int main(void)
{
    unsigned scenario;
    for (scenario = 0; scenario < 2; scenario++) {
        reset();
        if (scenario == 0) { stream.Header.Oplock.possible = FALSE; }
        else { oplock_changes_on_acquire = TRUE; }
        assert(!lock());
        assert(acquisitions == 1 && releases == 1 && !stream.MainResource.held);
        assert(oplock_checks == 1 && !lock_calls && !locks.requests && !projections);
        assert(status.Status == -7 && status.Information == 123);
    }
    reset();
    assert(lock());
    assert(status.Status == 0 && !status.Information);
    assert(oplock_checks == 1 && lock_calls == 1 && projections == 1);
    assert(acquisitions == 1 && releases == 1 && !stream.MainResource.held && !locks.requests);
    reset();
    native_handled = FALSE;
    assert(!lock());
    assert(status.Status == -7 && status.Information == 123);
    assert(oplock_checks == 1 && lock_calls == 1 && projections == 1);
    assert(acquisitions == 1 && releases == 1 && !stream.MainResource.held && !locks.requests);
    return 0;
}
