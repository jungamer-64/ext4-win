/* Exercise close-time cache flush, mapping and residency contracts. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _Must_inspect_result_
#define NTAPI
#define FALSE 0
#define TRUE 1
#define NULL ((void *)0)
#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS 1
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER (-1)
#define STATUS_END_OF_FILE (-2)
#define STATUS_UNSUCCESSFUL (-3)
#define NT_SUCCESS(status) ((status) >= 0)

typedef int NTSTATUS;
typedef unsigned char BOOLEAN;
typedef unsigned ULONG;
typedef unsigned long long ULONG_PTR;
typedef long long LONGLONG;
typedef struct { LONGLONG QuadPart; } LARGE_INTEGER;
typedef struct { unsigned identity; } MDL, *PMDL;
typedef struct { unsigned identity; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { PMDL MdlAddress; } IRP, *PIRP;
typedef struct { NTSTATUS Status; ULONG_PTR Information; } IO_STATUS_BLOCK;

#define STATUS_CACHE_PAGE_LOCKED 1
#define STATUS_USER_MAPPED_FILE (-4)
typedef struct {
    unsigned dirty; unsigned mapped;
    void *DataSectionObject, *SharedCacheMap, *ImageSectionObject;
} SECTION_OBJECT_POINTERS, *PSECTION_OBJECT_POINTERS;
typedef struct { unsigned exclusive, acquisitions, releases; } ERESOURCE, *PERESOURCE;
static BOOLEAN wdk_sys_acquire_resource_shared(PERESOURCE resource, BOOLEAN wait)
{
    /* An exclusive Cc owner is suspended awaiting this reactor's paging completion. */
    assert(wait == FALSE);
    resource->acquisitions++;
    return !resource->exclusive;
}
static void wdk_sys_release_resource(PERESOURCE resource)
{
    assert(!resource->exclusive);
    resource->releases++;
}
static NTSTATUS flush_status;
static unsigned flush_calls;
static void CcCoherencyFlushAndPurgeCache(PSECTION_OBJECT_POINTERS sections, LARGE_INTEGER *offset,
    ULONG length, IO_STATUS_BLOCK *status, ULONG flags)
{
    assert(offset == NULL && length == 0 && flags == 0);
    flush_calls++;
    status->Status = flush_status;
    if (flush_status == STATUS_SUCCESS) { sections->dirty = 0; }
}
static int MmCanFileBeTruncated(PSECTION_OBJECT_POINTERS sections, LARGE_INTEGER *size)
{
    assert(size->QuadPart == 0);
    return !sections->mapped;
}
#include "cache_close.h"

int main(void)
{
    FILE_OBJECT file;
    {
        SECTION_OBJECT_POINTERS sections = { .dirty = 1, .mapped = 0 };
        flush_status = STATUS_SUCCESS;
        assert(ext4win_cache_close_writeback(&sections) == STATUS_SUCCESS);
        assert(flush_calls == 1 && sections.dirty == 0);
        sections.dirty = 1;
        sections.mapped = 1;
        assert(ext4win_cache_close_writeback(&sections) == STATUS_USER_MAPPED_FILE);
        assert(sections.dirty == 0);
        sections.mapped = 0;
        flush_status = STATUS_CACHE_PAGE_LOCKED;
        assert(ext4win_cache_close_writeback(&sections) == STATUS_USER_MAPPED_FILE);
        flush_status = STATUS_UNSUCCESSFUL;
        assert(ext4win_cache_close_writeback(&sections) == STATUS_UNSUCCESSFUL);
    }
    {
        SECTION_OBJECT_POINTERS sections = {0};
        ERESOURCE resource = { .exclusive = 1 };
        assert(ext4win_cache_may_have_residency(&sections, &resource));
        assert(resource.acquisitions == 1 && resource.releases == 0);
        /* Paging completion can now release the Cc owner, permitting a fresh observation. */
        resource.exclusive = 0;
        sections.SharedCacheMap = &file;
        assert(ext4win_cache_may_have_residency(&sections, &resource));
        sections.SharedCacheMap = NULL;
        assert(!ext4win_cache_may_have_residency(&sections, &resource));
        assert(resource.acquisitions == 3 && resource.releases == 2);
    }
    return 0;
}
