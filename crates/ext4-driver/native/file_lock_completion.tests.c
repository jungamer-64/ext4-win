/* Execute the production consuming boundary against an FsRtl oracle. Terminal
 * callbacks retain their notification context and defer upper completion until
 * the actor/resource scope can progress; both rejection and conflict waiting
 * must preserve exactly one completion owner. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _IRQL_requires_max_(level)
#define _Must_inspect_result_
#define _In_
#define _Inout_
#define NTAPI
#define TRUE 1
#define NULL ((void *)0)
#define STATUS_SUCCESS 0
#define STATUS_PENDING 0x103
#define STATUS_INVALID_PARAMETER (-1)
#define STATUS_LOCK_NOT_GRANTED (-2)

typedef void VOID, *PVOID;
typedef int NTSTATUS;
typedef struct { unsigned held; } ERESOURCE, *PERESOURCE;
typedef struct { unsigned identity; } FILE_LOCK, *PFILE_LOCK;
typedef struct {
    struct { NTSTATUS Status; unsigned Information; } IoStatus;
} IRP, *PIRP;
typedef struct {
    unsigned Kind;
    PFILE_LOCK ByteRangeLocks;
    ERESOURCE MainResource;
} EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;
typedef struct {
    PIRP irp;
    unsigned returned;
    NTSTATUS terminal_status;
} COMPLETION_CONTEXT;

static EXT4WIN_STREAM_CONTEXT stream;
static FILE_LOCK locks;
static IRP request;
static COMPLETION_CONTEXT context;
static NTSTATUS lock_status;
static unsigned grants, upper_completions, acquisitions, releases, projections;
static PVOID pending_context;
static PIRP pending_irp;

static PEXT4WIN_STREAM_CONTEXT ext4win_stream_from_header(PVOID header)
{
    return header;
}

static void ext4win_acquire_resource_exclusive(PERESOURCE resource, int wait)
{
    assert(resource == &stream.MainResource && resource->held == 0 && wait);
    resource->held = 1;
    acquisitions++;
}

static void ext4win_release_resource(PERESOURCE resource)
{
    assert(resource == &stream.MainResource && resource->held == 1);
    resource->held = 0;
    releases++;
}

static void ext4win_stream_refresh_fast_io_projection(PEXT4WIN_STREAM_CONTEXT observed)
{
    assert(observed == &stream && stream.MainResource.held == 1);
    projections++;
}

NTSTATUS NTAPI ext4win_complete_file_lock(PVOID supplied, PIRP irp)
{
    COMPLETION_CONTEXT *completion = supplied;
    assert(completion == &context && completion->irp == irp);
    assert(completion->returned == 0);
    completion->returned = 1;
    completion->terminal_status = irp->IoStatus.Status;
    /* The Rust callback accepts ownership without calling an upper driver. */
    assert(upper_completions == 0);
    return STATUS_SUCCESS;
}

static NTSTATUS FsRtlProcessFileLock(PFILE_LOCK file_lock, PIRP irp, PVOID supplied)
{
    assert(file_lock == &locks && stream.MainResource.held == 1);
    assert(irp == &request && supplied == &context);
    grants++;
    if (lock_status == STATUS_PENDING) {
        pending_irp = irp;
        pending_context = supplied;
    } else {
        irp->IoStatus.Status = lock_status;
        assert(ext4win_complete_file_lock(supplied, irp) == STATUS_SUCCESS);
    }
    return lock_status;
}

#include "file_lock_completion.h"

static void reset(void)
{
    stream.Kind = 1;
    stream.ByteRangeLocks = &locks;
    stream.MainResource.held = 0;
    context.irp = &request;
    context.returned = 0;
    upper_completions = acquisitions = releases = projections = grants = 0;
    pending_irp = NULL;
    pending_context = NULL;
}

static void notify_upper(void)
{
    assert(context.returned == 1 && stream.MainResource.held == 0);
    upper_completions++;
}

int main(void)
{
    unsigned scenario;
    for (scenario = 0; scenario < 3; scenario++) {
        reset();
        lock_status = scenario == 0 ? STATUS_SUCCESS :
            (scenario == 1 ? STATUS_LOCK_NOT_GRANTED : STATUS_PENDING);
        assert(ext4win_stream_process_file_lock(&stream, &request, &context) == lock_status);
        assert(grants == 1 && acquisitions == 1 && releases == 1 && projections == 1);
        assert(upper_completions == 0);
        if (lock_status == STATUS_PENDING) {
            assert(context.returned == 0 && pending_irp == &request && pending_context == &context);
            pending_irp->IoStatus.Status = STATUS_LOCK_NOT_GRANTED;
            assert(ext4win_complete_file_lock(pending_context, pending_irp) == STATUS_SUCCESS);
            assert(context.terminal_status == STATUS_LOCK_NOT_GRANTED);
        } else {
            assert(context.terminal_status == lock_status);
        }
        notify_upper();
        assert(upper_completions == 1);
    }
    for (scenario = 0; scenario < 3; scenario++) {
        PVOID header;
        reset();
        header = &stream;
        if (scenario == 0) { header = NULL; }
        if (scenario == 1) { stream.Kind = 2; }
        if (scenario == 2) { stream.ByteRangeLocks = NULL; }
        request.IoStatus.Information = 123;
        assert(ext4win_stream_process_file_lock(header, &request, &context) == STATUS_INVALID_PARAMETER);
        assert(context.returned == 1 && context.terminal_status == STATUS_INVALID_PARAMETER);
        assert(request.IoStatus.Information == 0 && acquisitions == 0 && grants == 0);
        notify_upper();
    }
    return 0;
}
