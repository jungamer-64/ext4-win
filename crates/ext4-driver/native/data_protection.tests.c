/* Execute production protection admission and pre-hash coherence against independent
 * mapping, dirty-page and invalidation observations. Real Cc/MM requires the live gate. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _Must_inspect_result_
#define NULL ((void *)0)
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_CACHE_PAGE_LOCKED 1
#define STATUS_USER_MAPPED_FILE (-1)
#define STATUS_IO_DEVICE_ERROR (-2)
#define PAGE_READONLY 2
#define PAGE_READWRITE 4
#define PAGE_WRITECOPY 8
#define PAGE_EXECUTE_READWRITE 64
#define PAGE_EXECUTE_WRITECOPY 128
#define MmFlushForWrite 1
typedef int NTSTATUS;
typedef int BOOLEAN;
typedef unsigned char UCHAR;
typedef unsigned ULONG;
typedef struct { long long QuadPart; } LARGE_INTEGER;
typedef struct { NTSTATUS Status; unsigned long long Information; } IO_STATUS_BLOCK;
typedef struct { unsigned disk, cache; BOOLEAN dirty, cached; } SECTION_OBJECT_POINTERS, *PSECTION_OBJECT_POINTERS;
static SECTION_OBJECT_POINTERS sections;
static BOOLEAN mapped, image_mapped, main_held, paging_admitted;
static unsigned sequence, flushes;
static NTSTATUS cache_result;
static BOOLEAN MmCanFileBeTruncated(PSECTION_OBJECT_POINTERS objects, LARGE_INTEGER *size)
{
    assert(objects == &sections && size->QuadPart == 0 && main_held && paging_admitted);
    assert(sequence++ == 0);
    return !mapped;
}
static BOOLEAN MmFlushImageSection(PSECTION_OBJECT_POINTERS objects, unsigned kind)
{
    assert(objects == &sections && kind == MmFlushForWrite && main_held && paging_admitted);
    assert(sequence++ == 1);
    return !image_mapped;
}
static void CcCoherencyFlushAndPurgeCache(PSECTION_OBJECT_POINTERS objects, void *offset,
    unsigned length, IO_STATUS_BLOCK *status, unsigned flags)
{
    assert(objects == &sections && offset == NULL && length == 0 && flags == 0);
    assert(main_held && paging_admitted && sequence++ == 2);
    assert(status->Status == STATUS_SUCCESS && status->Information == 0);
    flushes++;
    status->Status = cache_result;
    if (cache_result == STATUS_SUCCESS) {
        sections.disk = sections.cache;
        sections.dirty = FALSE;
        sections.cached = FALSE;
    }
}
#include "data_protection.h"
int main(void)
{
    main_held = paging_admitted = TRUE;
    sections.disk = 3;
    sections.cache = 9;
    sections.dirty = sections.cached = TRUE;
    assert(ext4win_prepare_frozen_data(&sections) == STATUS_SUCCESS);
    assert(sequence == 3 && flushes == 1);
    assert(sections.disk == 9 && !sections.dirty && !sections.cached);
    sequence = 0;
    mapped = TRUE;
    assert(ext4win_prepare_frozen_data(&sections) == STATUS_USER_MAPPED_FILE && flushes == 1);
    sequence = 0;
    mapped = FALSE;
    image_mapped = TRUE;
    assert(ext4win_prepare_frozen_data(&sections) == STATUS_USER_MAPPED_FILE && flushes == 1);
    sequence = 0;
    image_mapped = FALSE;
    cache_result = STATUS_CACHE_PAGE_LOCKED;
    assert(ext4win_prepare_frozen_data(&sections) == STATUS_USER_MAPPED_FILE && flushes == 2);
    sequence = 0;
    cache_result = STATUS_IO_DEVICE_ERROR;
    assert(ext4win_prepare_frozen_data(&sections) == STATUS_IO_DEVICE_ERROR && flushes == 3);
    assert(ext4win_section_data_admitted(0, TRUE, PAGE_READWRITE));
    assert(!ext4win_section_data_admitted(0, FALSE, PAGE_READWRITE));
    assert(!ext4win_section_data_admitted(0, FALSE, PAGE_EXECUTE_READWRITE));
    assert(ext4win_section_data_admitted(0, FALSE, PAGE_READONLY));
    assert(ext4win_section_data_admitted(0, FALSE, PAGE_WRITECOPY));
    assert(ext4win_section_data_admitted(0, FALSE, PAGE_EXECUTE_WRITECOPY));
    assert(!ext4win_section_data_admitted(1, TRUE, PAGE_READWRITE));
    assert(ext4win_section_data_admitted(1, FALSE, PAGE_READONLY));
    assert(!ext4win_section_data_admitted(2, TRUE, PAGE_READONLY));
    return 0;
}
