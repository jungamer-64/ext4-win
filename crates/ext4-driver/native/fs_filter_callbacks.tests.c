/* Invoke the registered production callbacks with the completion-context storage
 * omitted by FsRtl, or supplied by a caller. Resource ownership remains paired. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _In_
#define _Out_opt_
#define _IRQL_requires_(level)
#define NTAPI
#define NULL ((void *)0)
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY 0x126
#define STATUS_FILE_LOCK_CONFLICT (-1)
#define STATUS_INVALID_PARAMETER (-2)
#define STATUS_CANT_WAIT (-3)
#define EXT4WIN_TRACE_EVENT_MAPPED_WRITE 1
#define SyncTypeOther 0
#define SyncTypeCreateSection 1

typedef int NTSTATUS;
typedef int BOOLEAN;
typedef void VOID;
typedef void *PVOID;
typedef struct { unsigned held; } ERESOURCE, *PERESOURCE;
typedef struct { PVOID FsContext; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { unsigned unused; } DRIVER_OBJECT, *PDRIVER_OBJECT;
typedef struct {
    PFILE_OBJECT FileObject;
    union {
        struct { unsigned SyncType; } AcquireForSectionSynchronization;
        struct { PERESOURCE *ResourceToRelease; } AcquireForModifiedPageWriter;
        struct { PERESOURCE ResourceToRelease; } ReleaseForModifiedPageWriter;
    } Parameters;
} FS_FILTER_CALLBACK_DATA, *PFS_FILTER_CALLBACK_DATA;
typedef NTSTATUS (*PFS_FILTER_CALLBACK)(PFS_FILTER_CALLBACK_DATA, PVOID *);
typedef void (*PFS_FILTER_COMPLETION_CALLBACK)(PFS_FILTER_CALLBACK_DATA, NTSTATUS, PVOID);
typedef struct {
    unsigned SizeOfFsFilterCallbacks, Reserved;
    PFS_FILTER_CALLBACK PreAcquireForSectionSynchronization;
    PFS_FILTER_COMPLETION_CALLBACK PostAcquireForSectionSynchronization;
    PFS_FILTER_CALLBACK PreReleaseForSectionSynchronization;
    PFS_FILTER_COMPLETION_CALLBACK PostReleaseForSectionSynchronization;
    PFS_FILTER_CALLBACK PreAcquireForCcFlush;
    PFS_FILTER_COMPLETION_CALLBACK PostAcquireForCcFlush;
    PFS_FILTER_CALLBACK PreReleaseForCcFlush;
    PFS_FILTER_COMPLETION_CALLBACK PostReleaseForCcFlush;
    PFS_FILTER_CALLBACK PreAcquireForModifiedPageWriter;
    PFS_FILTER_COMPLETION_CALLBACK PostAcquireForModifiedPageWriter;
    PFS_FILTER_CALLBACK PreReleaseForModifiedPageWriter;
    PFS_FILTER_COMPLETION_CALLBACK PostReleaseForModifiedPageWriter;
    PFS_FILTER_CALLBACK PreQueryOpen;
    PFS_FILTER_COMPLETION_CALLBACK PostQueryOpen;
} FS_FILTER_CALLBACKS;
typedef struct {
    ERESOURCE MainResource, PagingIoResource;
} EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;

static EXT4WIN_STREAM_CONTEXT stream;
static FILE_OBJECT file;
static DRIVER_OBJECT driver;
static FS_FILTER_CALLBACKS registered;
static BOOLEAN ordinary_io_available = TRUE;
static BOOLEAN paging_available = TRUE;
static NTSTATUS registration_status;

static void RtlZeroMemory(PVOID memory, unsigned long long size)
{
    unsigned char *bytes = memory;
    while (size != 0) { *bytes++ = 0; size--; }
}
static NTSTATUS FsRtlRegisterFileSystemFilterCallbacks(
    PDRIVER_OBJECT object, const FS_FILTER_CALLBACKS *callbacks)
{
    const unsigned char *input = (const unsigned char *)callbacks;
    unsigned char *output = (unsigned char *)&registered;
    unsigned index;
    assert(object == &driver && callbacks->SizeOfFsFilterCallbacks == sizeof(*callbacks));
    for (index = 0; index < sizeof(registered); index++) { output[index] = input[index]; }
    return registration_status;
}
static PEXT4WIN_STREAM_CONTEXT ext4win_stream_from_header(PVOID header)
{
    return header == &stream ? &stream : NULL;
}
static BOOLEAN ext4win_stream_section_callback_stream(
    PFILE_OBJECT object, PEXT4WIN_STREAM_CONTEXT *output)
{
    if (object != &file) { return FALSE; }
    *output = &stream;
    return TRUE;
}
static BOOLEAN ext4win_stream_fast_io_stream(
    PFILE_OBJECT object, PEXT4WIN_STREAM_CONTEXT *output)
{
    return ext4win_stream_section_callback_stream(object, output);
}
static BOOLEAN ext4win_stream_acquire_main_after_section_mutation(
    PEXT4WIN_STREAM_CONTEXT object, BOOLEAN exclusive)
{
    assert(object == &stream && exclusive && stream.MainResource.held == 0);
    stream.MainResource.held++;
    return FALSE;
}
static void ext4win_stream_acquire_main_after_sealed_section_mutation(
    PEXT4WIN_STREAM_CONTEXT object)
{
    (void)ext4win_stream_acquire_main_after_section_mutation(object, TRUE);
}
static BOOLEAN ext4win_stream_acquire_paging_after_section_mutation(
    PEXT4WIN_STREAM_CONTEXT object, BOOLEAN exclusive, BOOLEAN wait)
{
    assert(object == &stream && !exclusive && wait && stream.PagingIoResource.held == 0);
    if (!paging_available) { return FALSE; }
    stream.PagingIoResource.held++;
    return TRUE;
}
static BOOLEAN ext4win_stream_ordinary_io_available(PEXT4WIN_STREAM_CONTEXT object)
{
    assert(object == &stream && stream.MainResource.held == 1);
    return ordinary_io_available;
}
static void ext4win_release_resource(PERESOURCE resource)
{
    assert((resource == &stream.MainResource || resource == &stream.PagingIoResource)
        && resource->held == 1);
    resource->held--;
}
static void ext4win_trace_selected(PEXT4WIN_STREAM_CONTEXT object, unsigned event)
{
    assert(object == &stream && event == EXT4WIN_TRACE_EVENT_MAPPED_WRITE);
}
static void ext4win_trace_status(PEXT4WIN_STREAM_CONTEXT object, unsigned event, NTSTATUS status)
{
    assert(object == &stream && event == EXT4WIN_TRACE_EVENT_MAPPED_WRITE);
    assert(status == STATUS_SUCCESS || status == STATUS_CANT_WAIT);
}

#include "fs_filter_callbacks.h"

static void invoke(PFS_FILTER_CALLBACK callback, PFS_FILTER_CALLBACK_DATA data,
    BOOLEAN supply_context, NTSTATUS expected)
{
    PVOID context = data;
    assert(callback != NULL);
    assert(callback(data, supply_context ? &context : NULL) == expected);
    if (supply_context) { assert(context == NULL); }
}

static void exercise_callbacks(BOOLEAN supply_context)
{
    FS_FILTER_CALLBACK_DATA data;
    PERESOURCE paging_resource = NULL;
    data.FileObject = &file;
    data.Parameters.AcquireForSectionSynchronization.SyncType = SyncTypeCreateSection;
    invoke(registered.PreAcquireForSectionSynchronization, &data, supply_context,
        STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY);
    assert(stream.MainResource.held == 1);
    invoke(registered.PreReleaseForSectionSynchronization, &data, supply_context,
        STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY);
    assert(stream.MainResource.held == 0);

    ordinary_io_available = FALSE;
    invoke(registered.PreAcquireForSectionSynchronization, &data, supply_context,
        STATUS_FILE_LOCK_CONFLICT);
    assert(stream.MainResource.held == 0);
    data.Parameters.AcquireForSectionSynchronization.SyncType = SyncTypeOther;
    invoke(registered.PreAcquireForSectionSynchronization, &data, supply_context,
        STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY);
    invoke(registered.PreReleaseForSectionSynchronization, &data, supply_context,
        STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY);
    ordinary_io_available = TRUE;

    data.Parameters.AcquireForModifiedPageWriter.ResourceToRelease = &paging_resource;
    invoke(registered.PreAcquireForModifiedPageWriter, &data, supply_context,
        STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY);
    assert(paging_resource == &stream.PagingIoResource && paging_resource->held == 1);
    data.Parameters.ReleaseForModifiedPageWriter.ResourceToRelease = paging_resource;
    invoke(registered.PreReleaseForModifiedPageWriter, &data, supply_context,
        STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY);
    assert(stream.PagingIoResource.held == 0);

    paging_available = FALSE;
    data.Parameters.AcquireForModifiedPageWriter.ResourceToRelease = &paging_resource;
    invoke(registered.PreAcquireForModifiedPageWriter, &data, supply_context, STATUS_CANT_WAIT);
    assert(stream.PagingIoResource.held == 0);
    paging_available = TRUE;

    invoke(registered.PreAcquireForCcFlush, &data, supply_context,
        STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY);
    assert(stream.MainResource.held == 1);
    invoke(registered.PreReleaseForCcFlush, &data, supply_context,
        STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY);
    assert(stream.MainResource.held == 0);

    data.FileObject = NULL;
    invoke(registered.PreAcquireForSectionSynchronization, &data, supply_context, STATUS_SUCCESS);
    invoke(registered.PreReleaseForSectionSynchronization, &data, supply_context, STATUS_SUCCESS);
    invoke(registered.PreAcquireForModifiedPageWriter, &data, supply_context, STATUS_INVALID_PARAMETER);
    invoke(registered.PreReleaseForModifiedPageWriter, &data, supply_context, STATUS_INVALID_PARAMETER);
    invoke(registered.PreAcquireForCcFlush, &data, supply_context, STATUS_INVALID_PARAMETER);
    invoke(registered.PreReleaseForCcFlush, &data, supply_context, STATUS_INVALID_PARAMETER);
    assert(stream.MainResource.held == 0 && stream.PagingIoResource.held == 0);
}

int main(void)
{
    file.FsContext = &stream;
    assert(ext4win_register_section_callbacks(&driver) == STATUS_SUCCESS);
    assert(registered.PostAcquireForSectionSynchronization == NULL);
    assert(registered.PostReleaseForSectionSynchronization == NULL);
    assert(registered.PostAcquireForModifiedPageWriter == NULL);
    assert(registered.PostReleaseForModifiedPageWriter == NULL);
    assert(registered.PostAcquireForCcFlush == NULL && registered.PostReleaseForCcFlush == NULL);
    exercise_callbacks(FALSE);
    exercise_callbacks(TRUE);
    registration_status = STATUS_INVALID_PARAMETER;
    assert(ext4win_register_section_callbacks(&driver) == registration_status);
    return 0;
}
