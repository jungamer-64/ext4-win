#pragma once

/* MainResource and section preparation exclude new transfers/mappings. Paging stays
 * admitted until this synchronous Cc flush finishes, then Rust drains and seals it.
 * Hashing or physical relocation may observe data only after writeback and invalidation succeed. */
_Must_inspect_result_
static NTSTATUS
ext4win_prepare_frozen_data(PSECTION_OBJECT_POINTERS sections)
{
    LARGE_INTEGER zero;
    IO_STATUS_BLOCK status;
    zero.QuadPart = 0;
    if (!MmCanFileBeTruncated(sections, &zero) || !MmFlushImageSection(sections, MmFlushForWrite)) {
        return STATUS_USER_MAPPED_FILE;
    }
    status.Status = STATUS_SUCCESS;
    status.Information = 0;
    CcCoherencyFlushAndPurgeCache(sections, NULL, 0, &status, 0);
    return status.Status == STATUS_CACHE_PAGE_LOCKED ? STATUS_USER_MAPPED_FILE : status.Status;
}

