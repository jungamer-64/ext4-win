#ifndef EXT4WIN_PUBLISHED_STREAM_METADATA_H
#define EXT4WIN_PUBLISHED_STREAM_METADATA_H

/* Thread that brings Cc to a changed header size, selected by Rust from the size gate. */
/* The reactor briefly owns MainResource itself. A sealed section permit guarantees that no
 * other owner of that resource is waiting for the reactor. */
#define EXT4WIN_SIZE_PROJECTION_REACTOR 0UL
/* A synchronous requester owns MainResource exclusively until its IRP completes and awaits
 * the reactor; Cc observes the sizes on that owner before its ownership ends. */
#define EXT4WIN_SIZE_PROJECTION_REQUESTER 1UL

/* Cc's file object references are released with deferred deletion. Cc lazy close can drop
 * every other reference meanwhile, and deleting the object on this thread would send a
 * synchronous IRP_MJ_CLOSE that the reactor must process, possibly from the reactor itself. */

/* Cc must observe the header sizes before any later Cc entry. Only an exclusive owner of
 * MainResource may call this; a failure leaves the projection pending for the next owner. */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NTSTATUS
ext4win_stream_project_cache_sizes(_In_ PEXT4WIN_STREAM_CONTEXT stream)
{
    CC_FILE_SIZES sizes;
    PFILE_OBJECT file_object;
    NTSTATUS status;

    if (InterlockedCompareExchange(&stream->CacheProjectionPending, FALSE, FALSE) == FALSE) {
        return STATUS_SUCCESS;
    }
    if (stream->SectionObjects.SharedCacheMap == NULL) {
        (VOID)InterlockedExchange(&stream->CacheProjectionPending, FALSE);
        return STATUS_SUCCESS;
    }
    ExAcquireFastMutex(&stream->HeaderMutex);
    sizes.AllocationSize = stream->Header.AllocationSize;
    sizes.FileSize = stream->Header.FileSize;
    sizes.ValidDataLength = stream->Header.ValidDataLength;
    ExReleaseFastMutex(&stream->HeaderMutex);
    file_object = NULL;
    __try {
        file_object = CcGetFileObjectFromSectionPtrsRef(&stream->SectionObjects);
        status = (file_object == NULL) ? STATUS_INTERNAL_ERROR : CcSetFileSizesEx(file_object, &sizes);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    if (file_object != NULL) {
        ObDereferenceObjectDeferDelete(file_object);
    }
    if (NT_SUCCESS(status)) {
        (VOID)InterlockedExchange(&stream->CacheProjectionPending, FALSE);
    }
    return status;
}

/* Durable publications are serialized by the volume reactor. Header-only changes must
 * not wait on MainResource: read-ahead can retain it while awaiting that reactor's
 * paging I/O. Size changes are covered by the exclusion their gate established before
 * commit. A requester exclusion leaves the Cc projection to the owning thread. */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_publish_metadata(
    _In_ PVOID stream_header,
    _In_ LONGLONG allocation_size,
    _In_ LONGLONG file_size,
    _In_ LONGLONG valid_data_length,
    _In_ LONGLONG allocation_charge,
    _In_ const EXT4WIN_PUBLISHED_STREAM_METADATA *metadata,
    _In_ ULONG size_projection,
    _Out_ NTSTATUS *cache_status_out)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    CC_FILE_SIZES sizes;
    PFILE_OBJECT file_object;
    BOOLEAN size_change;
    BOOLEAN reactor_projection;
    NTSTATUS cache_status;

    if (cache_status_out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *cache_status_out = STATUS_SUCCESS;
    if ((stream == NULL) || (stream->Kind != 1) ||
        (metadata == NULL) ||
        ((size_projection != EXT4WIN_SIZE_PROJECTION_REACTOR) &&
            (size_projection != EXT4WIN_SIZE_PROJECTION_REQUESTER)) ||
        (allocation_size < 0) || (file_size < 0) ||
        (allocation_charge < 0) ||
        (valid_data_length != file_size) ||
        (file_size > allocation_size)) {
        return STATUS_INVALID_PARAMETER;
    }

    cache_status = STATUS_SUCCESS;
    file_object = NULL;
    ExAcquireFastMutex(&stream->HeaderMutex);
    if ((stream->MetadataValid != FALSE) &&
        (metadata->Epoch <= stream->PublishedMetadata.Epoch)) {
        ExReleaseFastMutex(&stream->HeaderMutex);
        return STATUS_INVALID_PARAMETER;
    }
    size_change = (stream->Header.AllocationSize.QuadPart != allocation_size) ||
        (stream->Header.FileSize.QuadPart != file_size) ||
        (stream->Header.ValidDataLength.QuadPart != valid_data_length);
    reactor_projection = size_change && (size_projection == EXT4WIN_SIZE_PROJECTION_REACTOR);
    if (reactor_projection) {
        ExReleaseFastMutex(&stream->HeaderMutex);
        wdk_sys_acquire_resource_exclusive(&stream->MainResource, TRUE);
        ExAcquireFastMutex(&stream->HeaderMutex);
    }
    if (size_change) {
        stream->Header.AllocationSize.QuadPart = allocation_size;
        stream->Header.FileSize.QuadPart = file_size;
        stream->Header.ValidDataLength.QuadPart = valid_data_length;
        if (!reactor_projection && (stream->SectionObjects.SharedCacheMap != NULL)) {
            (VOID)InterlockedExchange(&stream->CacheProjectionPending, TRUE);
        }
    }
    stream->AllocationCharge = allocation_charge;
    stream->PublishedMetadata = *metadata;
    stream->MetadataValid = TRUE;
    sizes.AllocationSize = stream->Header.AllocationSize;
    sizes.FileSize = stream->Header.FileSize;
    sizes.ValidDataLength = stream->Header.ValidDataLength;
    ExReleaseFastMutex(&stream->HeaderMutex);

    if (reactor_projection && (stream->SectionObjects.SharedCacheMap != NULL)) {
        __try {
            file_object = CcGetFileObjectFromSectionPtrsRef(&stream->SectionObjects);
            if (file_object == NULL) {
                cache_status = STATUS_INTERNAL_ERROR;
            }
            else {
                cache_status = CcSetFileSizesEx(file_object, &sizes);
            }
        }
        __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
            cache_status = GetExceptionCode();
        }
        if (NT_SUCCESS(cache_status)) {
            (VOID)InterlockedExchange(&stream->CacheProjectionPending, FALSE);
        }
    }
    if (file_object != NULL) {
        ObDereferenceObjectDeferDelete(file_object);
    }
    *cache_status_out = cache_status;
    if (reactor_projection) {
        wdk_sys_release_resource(&stream->MainResource);
    }
    return STATUS_SUCCESS;
}

#endif
