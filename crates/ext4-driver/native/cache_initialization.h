#pragma once

/* The marker authenticates only a gate that returned before Cc entry. A Cc exception with
 * STATUS_VERIFY_REQUIRED remains a Cache Manager result and never grants replay authority. */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_cache_initialize(
    _In_ PVOID stream_header,
    _Inout_ PFILE_OBJECT file_object,
    _Out_ PUCHAR verify_before_entry)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    CC_FILE_SIZES sizes;
    NTSTATUS status;

    if (verify_before_entry == NULL) { return STATUS_INVALID_PARAMETER; }
    *verify_before_entry = 0;
    if (!ext4win_stream_matches_file_object(stream, file_object)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (stream->PagingFile.Active != EXT4WIN_PAGING_VACANT) { return STATUS_INVALID_DEVICE_REQUEST; }
    if (!ext4win_stream_ordinary_io_available(stream)) {
        if (ext4win_storage_verify_required(stream->VolumeStream->RustState)) {
            *verify_before_entry = 1;
            return STATUS_VERIFY_REQUIRED;
        }
        return ext4win_stream_storage_available(stream) ? STATUS_VOLUME_DISMOUNTED : STATUS_DEVICE_REMOVED;
    }

    status = STATUS_SUCCESS;
    (VOID)ext4win_section_acquire_main(stream->SectionState, &stream->MainResource, TRUE, TRUE, NULL);
    if (!ext4win_stream_ordinary_io_available(stream)) {
        if (ext4win_storage_verify_required(stream->VolumeStream->RustState)) {
            *verify_before_entry = 1;
            status = STATUS_VERIFY_REQUIRED;
        } else {
            status = ext4win_stream_storage_available(stream) ? STATUS_VOLUME_DISMOUNTED : STATUS_DEVICE_REMOVED;
        }
        ext4win_release_resource(&stream->MainResource);
        return status;
    }
    __try {
        if (file_object->PrivateCacheMap == NULL) {
            ext4win_capture_cache_sizes(stream, &sizes);
            __try {
                CcInitializeCacheMap(
                    file_object,
                    &sizes,
                    FALSE,
                    &ext4win_cache_callbacks,
                    &stream->Header);
                if (PsIsDiskCountersEnabled()) {
                    CcSetAdditionalCacheAttributesEx(file_object, CC_ENABLE_DISK_IO_ACCOUNTING);
                }
                ext4win_file_set_flags(file_object, FO_CACHE_SUPPORTED);
            }
            __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
                status = GetExceptionCode();
            }
        }
    }
    __finally {
        ext4win_release_resource(&stream->MainResource);
    }
    return status;
}
