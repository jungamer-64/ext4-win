#ifndef EXT4WIN_STREAM_METADATA_H
#define EXT4WIN_STREAM_METADATA_H

/* Durable publications are serialized by the volume reactor. Header-only changes must
 * not wait on MainResource: read-ahead can retain it while awaiting that reactor's
 * paging I/O. Size changes use the section gate drained by a passive worker before
 * commit; MainResource then protects the cache-map lifetime through Cc publication. */
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
    _In_ const EXT4WIN_STREAM_METADATA *metadata,
    _Out_ NTSTATUS *cache_status_out)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    EXT4WIN_PUBLISHED_STREAM_METADATA prepared_metadata;
    CC_FILE_SIZES sizes;
    PFILE_OBJECT file_object;
    BOOLEAN size_change;
    NTSTATUS cache_status;

    if (cache_status_out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *cache_status_out = STATUS_SUCCESS;
    if ((stream == NULL) || (stream->Kind != 1) ||
        !ext4win_prepare_stream_metadata(metadata, &prepared_metadata) ||
        (allocation_size < 0) || (file_size < 0) ||
        (allocation_charge < 0) || (allocation_charge > allocation_size) ||
        (valid_data_length != file_size) ||
        (file_size > allocation_size)) {
        return STATUS_INVALID_PARAMETER;
    }

    cache_status = STATUS_SUCCESS;
    file_object = NULL;
    ExAcquireFastMutex(&stream->HeaderMutex);
    if ((stream->MetadataValid != FALSE) &&
        (prepared_metadata.Epoch <= stream->PublishedMetadata.Epoch)) {
        ExReleaseFastMutex(&stream->HeaderMutex);
        return STATUS_INVALID_PARAMETER;
    }
    size_change = (stream->Header.AllocationSize.QuadPart != allocation_size) ||
        (stream->Header.FileSize.QuadPart != file_size) ||
        (stream->Header.ValidDataLength.QuadPart != valid_data_length);
    if (size_change) {
        ExReleaseFastMutex(&stream->HeaderMutex);
        ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
        ExAcquireFastMutex(&stream->HeaderMutex);
        stream->Header.AllocationSize.QuadPart = allocation_size;
        stream->Header.FileSize.QuadPart = file_size;
        stream->Header.ValidDataLength.QuadPart = valid_data_length;
    }
    stream->AllocationCharge = allocation_charge;
    stream->PublishedMetadata = prepared_metadata;
    stream->MetadataValid = TRUE;
    sizes.AllocationSize = stream->Header.AllocationSize;
    sizes.FileSize = stream->Header.FileSize;
    sizes.ValidDataLength = stream->Header.ValidDataLength;
    ExReleaseFastMutex(&stream->HeaderMutex);

    if (size_change && (stream->SectionObjects.SharedCacheMap != NULL)) {
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
    }
    if (file_object != NULL) {
        ObDereferenceObject(file_object);
    }
    *cache_status_out = cache_status;
    if (size_change) {
        ext4win_release_resource(&stream->MainResource);
    }
    return STATUS_SUCCESS;
}

#endif
