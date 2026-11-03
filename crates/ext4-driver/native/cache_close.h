#pragma once

/* A durability flush retains mapped sections and private cache maps. Shutdown must not
 * require mappings to disappear before dirty file data can reach lower storage. */
_Must_inspect_result_
static NTSTATUS
ext4win_cache_flush(PSECTION_OBJECT_POINTERS sections)
{
    IO_STATUS_BLOCK status;
    status.Status = STATUS_SUCCESS;
    status.Information = 0;
    CcFlushCache(sections, NULL, 0, &status);
    return status.Status;
}

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

/* Ordinary cache/section admission is closed while paging remains available for flush.
 * Existing views retain their own lifetimes; failure to purge residency cannot veto
 * logical dismount. Sealing paging after this call prevents later media writes. */
_Must_inspect_result_
static NTSTATUS
ext4win_cache_close_writeback(PSECTION_OBJECT_POINTERS sections)
{
    NTSTATUS status = ext4win_cache_flush(sections);
    if (NT_SUCCESS(status)) {
        /* A retained view may prevent purging; its reference still owns that residency. */
        (VOID)CcPurgeCacheSection(sections, NULL, 0, FALSE);
    }
    return status;
}
