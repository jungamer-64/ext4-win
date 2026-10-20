/* Exercise production deletion admission with independent MM mapping and Cc residency
 * observations. Successful invalidation deliberately retains both cache pointers. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _Must_inspect_result_
#define NULL ((void *)0)
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_CACHE_PAGE_LOCKED 1
#define STATUS_CANNOT_DELETE (-1)
#define STATUS_IO_DEVICE_ERROR (-2)
#define MmFlushForDelete 0
typedef int NTSTATUS;
typedef int BOOLEAN;
typedef struct { long long QuadPart; } LARGE_INTEGER;
typedef struct { NTSTATUS Status; unsigned long long Information; } IO_STATUS_BLOCK;
typedef struct {
    void *DataSectionObject, *SharedCacheMap, *ImageSectionObject;
} SECTION_OBJECT_POINTERS, *PSECTION_OBJECT_POINTERS;
static SECTION_OBJECT_POINTERS sections;
static BOOLEAN image_allowed = TRUE, truncation_allowed = TRUE;
static NTSTATUS purge_status;
static unsigned image_checks, truncation_checks, purges;

static BOOLEAN MmFlushImageSection(PSECTION_OBJECT_POINTERS objects, unsigned operation)
{
    assert(objects == &sections && operation == MmFlushForDelete);
    image_checks++;
    return image_allowed;
}
static BOOLEAN MmCanFileBeTruncated(PSECTION_OBJECT_POINTERS objects, LARGE_INTEGER *size)
{
    assert(objects == &sections && size->QuadPart == 0);
    truncation_checks++;
    return truncation_allowed;
}
static void CcCoherencyFlushAndPurgeCache(PSECTION_OBJECT_POINTERS objects, void *offset,
    unsigned length, IO_STATUS_BLOCK *status, unsigned flags)
{
    assert(objects == &sections && offset == NULL && length == 0 && flags == 0);
    assert(status->Status == STATUS_SUCCESS && status->Information == 0);
    purges++;
    status->Status = purge_status;
}
#include "section_deletion.h"

int main(void)
{
    assert(ext4win_prepare_section_deletion(&sections) == STATUS_SUCCESS);
    assert(image_checks == 1 && truncation_checks == 1 && purges == 0);

    sections.DataSectionObject = &sections;
    sections.SharedCacheMap = &sections;
    assert(ext4win_prepare_section_deletion(&sections) == STATUS_SUCCESS);
    assert(sections.DataSectionObject != NULL && sections.SharedCacheMap != NULL && purges == 1);

    image_allowed = FALSE;
    assert(ext4win_prepare_section_deletion(&sections) == STATUS_CANNOT_DELETE);
    assert(truncation_checks == 2 && purges == 1);
    image_allowed = TRUE;
    truncation_allowed = FALSE;
    assert(ext4win_prepare_section_deletion(&sections) == STATUS_CANNOT_DELETE && purges == 1);
    truncation_allowed = TRUE;
    purge_status = STATUS_CACHE_PAGE_LOCKED;
    assert(ext4win_prepare_section_deletion(&sections) == STATUS_CANNOT_DELETE && purges == 2);
    purge_status = STATUS_IO_DEVICE_ERROR;
    assert(ext4win_prepare_section_deletion(&sections) == STATUS_IO_DEVICE_ERROR && purges == 3);
    return 0;
}
