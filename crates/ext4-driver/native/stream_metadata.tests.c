/* Execute durable publication against a cache-map lifetime and paging-progress oracle.
 * A read-ahead owner can release MainResource only after the reactor services paging I/O.
 * Kernel Cc/MM behavior and actual IRP scheduling remain the live-test contract. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _IRQL_requires_max_(level)
#define _Must_inspect_result_
#define _In_
#define _Out_
#define NTAPI
#define NULL ((void *)0)
#define FALSE 0
#define TRUE 1
#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS 1
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER (-1)
#define STATUS_INTERNAL_ERROR (-2)
#define STATUS_UNSUCCESSFUL (-3)

typedef int NTSTATUS;
typedef int BOOLEAN;
typedef unsigned ULONG;
typedef unsigned long long ULONGLONG;
typedef unsigned long long ULONG_PTR;
typedef long long LONGLONG;
typedef void *PVOID;
typedef struct { LONGLONG QuadPart; } LARGE_INTEGER;
typedef struct { unsigned held; } FAST_MUTEX;
typedef struct { unsigned readers; unsigned writer; } ERESOURCE;
typedef struct { unsigned references; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { PFILE_OBJECT SharedCacheMap; } SECTION_OBJECT_POINTERS;
typedef struct {
    LARGE_INTEGER AllocationSize, FileSize, ValidDataLength;
} CC_FILE_SIZES;
typedef struct { ULONGLONG Epoch; ULONG NumberOfLinks; } EXT4WIN_STREAM_METADATA;
typedef EXT4WIN_STREAM_METADATA EXT4WIN_PUBLISHED_STREAM_METADATA;
typedef struct {
    CC_FILE_SIZES Header;
    FAST_MUTEX HeaderMutex;
    ERESOURCE MainResource;
    SECTION_OBJECT_POINTERS SectionObjects;
    LONGLONG AllocationCharge;
    EXT4WIN_PUBLISHED_STREAM_METADATA PublishedMetadata;
    BOOLEAN MetadataValid;
    ULONG Kind;
} EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;

#define GetExceptionCode() ((NTSTATUS)__exception_code())
__declspec(dllimport) void __stdcall RaiseException(ULONG, ULONG, ULONG, const ULONG_PTR *);

static EXT4WIN_STREAM_CONTEXT stream;
static FILE_OBJECT cache_file;
static unsigned cache_calls, reference_calls;
static NTSTATUS cache_result;
static BOOLEAN reference_missing, reference_raises, cache_raises;
static CC_FILE_SIZES cache_sizes;

static PEXT4WIN_STREAM_CONTEXT ext4win_stream_from_header(PVOID header)
{
    assert(header == NULL || header == &stream.Header);
    return header == NULL ? NULL : &stream;
}
static BOOLEAN ext4win_prepare_stream_metadata(const EXT4WIN_STREAM_METADATA *input,
    EXT4WIN_PUBLISHED_STREAM_METADATA *output)
{
    if (input == NULL || input->NumberOfLinks == 0) { return FALSE; }
    *output = *input;
    return TRUE;
}
static void ExAcquireFastMutex(FAST_MUTEX *mutex)
{
    assert(mutex == &stream.HeaderMutex && mutex->held == 0);
    mutex->held = 1;
}
static void ExReleaseFastMutex(FAST_MUTEX *mutex)
{
    assert(mutex == &stream.HeaderMutex && mutex->held == 1);
    mutex->held = 0;
}
static BOOLEAN ext4win_acquire_resource_exclusive(ERESOURCE *resource, BOOLEAN wait)
{
    /* Waiting with a read-ahead owner would stop the reactor that must unblock it. */
    assert(resource == &stream.MainResource && wait == TRUE);
    assert(stream.HeaderMutex.held == 0 && resource->readers == 0 && resource->writer == 0);
    resource->writer = 1;
    return TRUE;
}
static void ext4win_release_resource(ERESOURCE *resource)
{
    assert(resource == &stream.MainResource && resource->writer == 1);
    assert(stream.HeaderMutex.held == 0);
    resource->writer = 0;
}
static PFILE_OBJECT CcGetFileObjectFromSectionPtrsRef(SECTION_OBJECT_POINTERS *sections)
{
    assert(sections == &stream.SectionObjects && sections->SharedCacheMap == &cache_file);
    assert(stream.MainResource.writer == 1 && stream.HeaderMutex.held == 0);
    reference_calls++;
    if (reference_raises) { RaiseException((ULONG)STATUS_UNSUCCESSFUL, 0, 0, NULL); }
    if (reference_missing) { return NULL; }
    cache_file.references++;
    return &cache_file;
}
static NTSTATUS CcSetFileSizesEx(PFILE_OBJECT file, const CC_FILE_SIZES *sizes)
{
    assert(file == &cache_file && file->references == 1);
    assert(stream.MainResource.writer == 1 && stream.HeaderMutex.held == 0);
    /* Cc observes an already committed, coherent header tuple. */
    assert(stream.MetadataValid && stream.PublishedMetadata.Epoch != 0);
    assert(sizes->AllocationSize.QuadPart == stream.Header.AllocationSize.QuadPart);
    assert(sizes->FileSize.QuadPart == stream.Header.FileSize.QuadPart);
    assert(sizes->ValidDataLength.QuadPart == stream.Header.ValidDataLength.QuadPart);
    cache_calls++;
    if (cache_raises) { RaiseException((ULONG)STATUS_UNSUCCESSFUL, 0, 0, NULL); }
    if (cache_result == STATUS_SUCCESS) { cache_sizes = *sizes; }
    return cache_result;
}
static void ObDereferenceObject(PFILE_OBJECT file)
{
    assert(file == &cache_file && file->references == 1);
    assert(stream.MainResource.writer == 1 && stream.HeaderMutex.held == 0);
    file->references--;
}

#include "stream_metadata.h"

static void publish(ULONGLONG epoch, LONGLONG allocation, LONGLONG eof,
    LONGLONG charge, NTSTATUS expected_cache_status)
{
    const EXT4WIN_STREAM_METADATA metadata = { epoch, 2 };
    NTSTATUS cache_status = 99;
    assert(ext4win_stream_publish_metadata(&stream.Header, allocation, eof, eof,
        charge, &metadata, &cache_status) == STATUS_SUCCESS);
    assert(cache_status == expected_cache_status);
    assert(stream.MetadataValid && stream.PublishedMetadata.Epoch == epoch);
    assert(stream.PublishedMetadata.NumberOfLinks == 2 && stream.AllocationCharge == charge);
    assert(stream.Header.AllocationSize.QuadPart == allocation);
    assert(stream.Header.FileSize.QuadPart == eof && stream.Header.ValidDataLength.QuadPart == eof);
    assert(stream.HeaderMutex.held == 0 && stream.MainResource.writer == 0);
    assert(cache_file.references == 0);
}

int main(void)
{
    EXT4WIN_STREAM_METADATA metadata;
    NTSTATUS cache_status;
    stream.Kind = 1;
    stream.Header.AllocationSize.QuadPart = 8192;
    stream.Header.FileSize.QuadPart = 8192;
    stream.Header.ValidDataLength.QuadPart = 8192;
    stream.SectionObjects.SharedCacheMap = &cache_file;

    /* Rename/link/timestamps and physical charge can commit while read-ahead awaits paging.
     * Even an unavailable Cc projection has no work to perform when its dimensions agree. */
    stream.MainResource.readers = 1;
    cache_result = STATUS_UNSUCCESSFUL;
    publish(1, 8192, 8192, 4096, STATUS_SUCCESS);
    publish(2, 8192, 8192, 12288, STATUS_SUCCESS);
    assert(reference_calls == 0 && cache_calls == 0 && stream.MainResource.readers == 1);

    /* Malformed input and stale epochs have no native commit or cache effect. */
    metadata.Epoch = 2;
    metadata.NumberOfLinks = 1;
    cache_status = 99;
    assert(ext4win_stream_publish_metadata(&stream.Header, 16384, 16384, 16384,
        8192, &metadata, &cache_status) == STATUS_INVALID_PARAMETER);
    metadata.Epoch = 3;
    assert(ext4win_stream_publish_metadata(&stream.Header, 4096, 8192, 8192,
        4096, &metadata, &cache_status) == STATUS_INVALID_PARAMETER);
    assert(ext4win_stream_publish_metadata(&stream.Header, 8192, 8192, 4096,
        4096, &metadata, &cache_status) == STATUS_INVALID_PARAMETER);
    assert(stream.PublishedMetadata.Epoch == 2 && stream.Header.FileSize.QuadPart == 8192);
    assert(reference_calls == 0 && cache_calls == 0 && stream.HeaderMutex.held == 0);

    /* Completing paging lets passive section preparation drain the read-ahead owner. */
    stream.MainResource.readers = 0;
    cache_result = STATUS_SUCCESS;
    publish(3, 16384, 12288, 8192, STATUS_SUCCESS);
    assert(cache_calls == 1 && cache_sizes.AllocationSize.QuadPart == 16384);
    assert(cache_sizes.FileSize.QuadPart == 12288 && cache_sizes.ValidDataLength.QuadPart == 12288);
    publish(4, 16384, 4096, 4096, STATUS_SUCCESS);
    assert(cache_calls == 2 && cache_sizes.FileSize.QuadPart == 4096);

    /* Returned and raised Cc failures preserve the native commit and release every reference. */
    cache_result = STATUS_UNSUCCESSFUL;
    publish(5, 16384, 8192, 8192, STATUS_UNSUCCESSFUL);
    cache_raises = TRUE;
    publish(6, 16384, 12288, 8192, STATUS_UNSUCCESSFUL);
    cache_raises = FALSE;
    reference_missing = TRUE;
    publish(7, 16384, 4096, 4096, STATUS_INTERNAL_ERROR);
    reference_missing = FALSE;
    reference_raises = TRUE;
    publish(8, 16384, 8192, 8192, STATUS_UNSUCCESSFUL);
    reference_raises = FALSE;
    assert(cache_calls == 4 && reference_calls == 6);

    stream.SectionObjects.SharedCacheMap = NULL;
    publish(9, 32768, 24576, 8192, STATUS_SUCCESS);
    assert(cache_calls == 4 && reference_calls == 6);
    return 0;
}
