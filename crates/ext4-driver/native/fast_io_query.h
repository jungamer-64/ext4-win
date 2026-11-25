#ifndef EXT4WIN_FAST_IO_QUERY_H
#define EXT4WIN_FAST_IO_QUERY_H

_Success_(return != FALSE)
static BOOLEAN
ext4win_capture_fast_io_query_snapshot(
    _In_ PEXT4WIN_STREAM_CONTEXT stream,
    _In_ BOOLEAN wait,
    _Out_ PEXT4WIN_FAST_IO_QUERY_SNAPSHOT snapshot)
{
    BOOLEAN valid;

    if (wait) {
        ExAcquireFastMutex(&stream->HeaderMutex);
    } else if (!ExTryToAcquireFastMutex(&stream->HeaderMutex)) {
        return FALSE;
    }
    valid = (stream->MetadataValid != FALSE) &&
        (InterlockedCompareExchange(&stream->NamespaceQueryFallback, FALSE, FALSE) == FALSE);
    if (valid) {
        snapshot->Metadata = stream->PublishedMetadata;
        snapshot->AllocationSize.QuadPart = stream->AllocationCharge;
        snapshot->EndOfFile = stream->Header.FileSize;
    }
    ExReleaseFastMutex(&stream->HeaderMutex);
    return valid;
}

/* Admission and the committed metadata snapshot are observed under shared MainResource.
 * Fast I/O passes the requestor's raw buffer, so publication starts only after release:
 * a contained requestor fault cannot retain the resource or its critical region. */
_Success_(return != FALSE)
static BOOLEAN
ext4win_fast_io_query_observe(
    _In_ PFILE_OBJECT file_object,
    _In_ BOOLEAN wait,
    _Out_ PEXT4WIN_FAST_IO_QUERY_SNAPSHOT snapshot)
{
    PEXT4WIN_STREAM_CONTEXT stream, volume;
    BOOLEAN captured;

    if (!ext4win_stream_fast_io_stream(file_object, &stream)) { return FALSE; }
    volume = stream->VolumeStream;
    if (volume == NULL || !wdk_sys_acquire_resource_shared(&stream->MainResource, wait)) {
        return FALSE;
    }
    captured = !ext4win_storage_verify_required(volume->RustState) &&
        ext4win_fast_io_query_admit(ext4win_file_flags(file_object), file_object->ReadAccess,
            stream->Header.IsFastIoPossible == FastIoIsPossible,
            ext4win_storage_media_state(volume->RustState),
            (UCHAR)ext4win_section_phase(stream->SectionState),
            ext4win_storage_io_policy(volume->RustState)) &&
        ext4win_capture_fast_io_query_snapshot(stream, wait, snapshot);
    wdk_sys_release_resource(&stream->MainResource);
    return captured;
}

/* A requestor fault is this query's terminal result; the I/O Manager must not retry it. */
static VOID
ext4win_fast_io_query_publish(
    _Out_writes_bytes_(length) PVOID buffer,
    _In_reads_bytes_(length) const VOID *record,
    _In_ ULONG length,
    _Out_ PIO_STATUS_BLOCK status)
{
    status->Status = ext4win_requestor_write(buffer, record, length);
    status->Information = NT_SUCCESS(status->Status) ? length : 0;
}

/* Rust encodes a local record from the released snapshot; C owns only the requestor copy. */
static BOOLEAN NTAPI ext4win_fast_io_query_basic_info(PFILE_OBJECT file, BOOLEAN wait,
    PFILE_BASIC_INFORMATION buffer, PIO_STATUS_BLOCK status, PDEVICE_OBJECT device)
{
    EXT4WIN_FAST_IO_QUERY_SNAPSHOT snapshot;
    FILE_BASIC_INFORMATION prepared;
    UNREFERENCED_PARAMETER(device);
    if ((buffer == NULL) || (status == NULL)) { return FALSE; }
    status->Status = STATUS_NOT_SUPPORTED;
    status->Information = 0;
    if (!ext4win_fast_io_query_observe(file, wait, &snapshot)) { return FALSE; }
    RtlZeroMemory(&prepared, sizeof(prepared));
    ext4win_fast_io_basic_record(&snapshot, &prepared);
    ext4win_fast_io_query_publish(buffer, &prepared, (ULONG)sizeof(prepared), status);
    return TRUE;
}

static BOOLEAN NTAPI ext4win_fast_io_query_standard_info(PFILE_OBJECT file, BOOLEAN wait,
    PFILE_STANDARD_INFORMATION buffer, PIO_STATUS_BLOCK status, PDEVICE_OBJECT device)
{
    EXT4WIN_FAST_IO_QUERY_SNAPSHOT snapshot;
    FILE_STANDARD_INFORMATION prepared;
    UNREFERENCED_PARAMETER(device);
    if ((buffer == NULL) || (status == NULL)) { return FALSE; }
    status->Status = STATUS_NOT_SUPPORTED;
    status->Information = 0;
    if (!ext4win_fast_io_query_observe(file, wait, &snapshot)) { return FALSE; }
    RtlZeroMemory(&prepared, sizeof(prepared));
    ext4win_fast_io_standard_record(&snapshot, &prepared);
    ext4win_fast_io_query_publish(buffer, &prepared, (ULONG)sizeof(prepared), status);
    return TRUE;
}

static BOOLEAN NTAPI ext4win_fast_io_query_network_open_info(PFILE_OBJECT file, BOOLEAN wait,
    PFILE_NETWORK_OPEN_INFORMATION buffer, PIO_STATUS_BLOCK status, PDEVICE_OBJECT device)
{
    EXT4WIN_FAST_IO_QUERY_SNAPSHOT snapshot;
    FILE_NETWORK_OPEN_INFORMATION prepared;
    UNREFERENCED_PARAMETER(device);
    if ((buffer == NULL) || (status == NULL)) { return FALSE; }
    status->Status = STATUS_NOT_SUPPORTED;
    status->Information = 0;
    if (!ext4win_fast_io_query_observe(file, wait, &snapshot)) { return FALSE; }
    RtlZeroMemory(&prepared, sizeof(prepared));
    ext4win_fast_io_network_record(&snapshot, &prepared);
    ext4win_fast_io_query_publish(buffer, &prepared, (ULONG)sizeof(prepared), status);
    return TRUE;
}

#endif
