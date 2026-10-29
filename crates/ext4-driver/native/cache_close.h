#pragma once

/* Reactor completion and lease release must never wait for a Cc/MM resource owner.
 * Contention cannot prove absence: retain the stream and let delayed close recheck it. */
_Must_inspect_result_
static BOOLEAN
ext4win_cache_may_have_residency(PSECTION_OBJECT_POINTERS sections, PERESOURCE resource)
{
    BOOLEAN resident;
    if (!wdk_sys_acquire_resource_shared(resource, FALSE)) { return TRUE; }
    resident = (sections->DataSectionObject != NULL) ||
        (sections->SharedCacheMap != NULL) || (sections->ImageSectionObject != NULL);
    wdk_sys_release_resource(resource);
    return resident;
}

/* Called under exclusive stream ownership after ordinary cache/section admission closes.
 * Flush gathers dirty mapped pages; locked pages or remaining mappings prevent clean-close.
 * The caller catches native exceptions and retains paging admission throughout this call. */
_Must_inspect_result_
static NTSTATUS
ext4win_cache_close_writeback(PSECTION_OBJECT_POINTERS sections)
{
    IO_STATUS_BLOCK status;
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    status.Status = STATUS_SUCCESS;
    status.Information = 0;
    CcCoherencyFlushAndPurgeCache(sections, NULL, 0, &status, 0);
    if ((status.Status == STATUS_CACHE_PAGE_LOCKED) ||
        (NT_SUCCESS(status.Status) && !MmCanFileBeTruncated(sections, &zero))) {
        return STATUS_USER_MAPPED_FILE;
    }
    return status.Status;
}
