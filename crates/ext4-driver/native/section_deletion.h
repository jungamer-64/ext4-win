#pragma once

/* MainResource and Preparing exclude new mappings while paging can drain. MM decides
 * whether user mappings or write probes prevent deletion; a retained cache section is
 * only residency. Cc may keep its section pointers after successful invalidation. */
_Must_inspect_result_
static NTSTATUS
ext4win_prepare_section_deletion(PSECTION_OBJECT_POINTERS sections)
{
    LARGE_INTEGER zero;
    IO_STATUS_BLOCK status;
    zero.QuadPart = 0;
    if (!MmFlushImageSection(sections, MmFlushForDelete) ||
        !MmCanFileBeTruncated(sections, &zero)) {
        return STATUS_CANNOT_DELETE;
    }
    if ((sections->DataSectionObject == NULL) && (sections->SharedCacheMap == NULL)) {
        return STATUS_SUCCESS;
    }
    status.Status = STATUS_SUCCESS;
    status.Information = 0;
    CcCoherencyFlushAndPurgeCache(sections, NULL, 0, &status, 0);
    return status.Status == STATUS_CACHE_PAGE_LOCKED ? STATUS_CANNOT_DELETE : status.Status;
}
