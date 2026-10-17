#ifndef EXT4WIN_FAST_IO_TRANSFER_H
#define EXT4WIN_FAST_IO_TRANSFER_H

/* The transfer decision must observe EOF, byte-range locks and oplocks after
 * MainResource acquisition. Success retains the resource and its APC scope
 * through the Cc call; rejection releases both before returning to IRP fallback. */
_Success_(return != FALSE)
_Must_inspect_result_
static BOOLEAN
ext4win_stream_acquire_fast_io_main(
    _In_ PFILE_OBJECT file,
    _In_ PEXT4WIN_STREAM_CONTEXT stream,
    _In_ PLARGE_INTEGER offset,
    _In_ ULONG length,
    _In_ BOOLEAN wait,
    _In_ ULONG key,
    _In_ BOOLEAN read,
    _Out_ PIO_STATUS_BLOCK status,
    _In_ PDEVICE_OBJECT device)
{
    PEXT4WIN_STREAM_CONTEXT observed;

    if (!wait) { return FALSE; }
    /* A throttled write falls back before acquiring MainResource. The queued
     * passive IRP owns deferred admission and its callback lifetime. */
    if (!read && !CcCanIWrite(file, length, FALSE, FALSE)) { return FALSE; }
    ext4win_acquire_resource_shared(&stream->MainResource, TRUE);
    if (!ext4win_stream_fast_io_candidate(file, &observed) || (observed != stream) ||
        !ext4win_fast_io_check_if_possible(file, offset, length, wait, key, read, status, device) ||
        (!read && !CcCanIWrite(file, length, FALSE, TRUE))) {
        ext4win_release_resource(&stream->MainResource);
        return FALSE;
    }
    return TRUE;
}

/* Successful copies publish a synchronous cursor while MainResource still retains the
 * admitted signed range. Asynchronous handles keep their explicitly selected position. */
_Success_(return != FALSE && NT_SUCCESS(io_status->Status))
static BOOLEAN
NTAPI
ext4win_fast_io_read(
    _In_ PFILE_OBJECT file_object,
    _In_ PLARGE_INTEGER file_offset,
    _In_ ULONG length,
    _In_ BOOLEAN wait,
    _In_ ULONG lock_key,
    _Out_writes_bytes_(length) PVOID buffer,
    _Out_ PIO_STATUS_BLOCK io_status,
    _In_ PDEVICE_OBJECT device_object)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    BOOLEAN handled;

    if ((buffer == NULL) || (io_status == NULL) || (file_offset == NULL) ||
        !wait ||
        !ext4win_stream_fast_io_candidate(file_object, &stream)) {
        return FALSE;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_FAST_IO_READ);
    handled = FALSE;
    if (!ext4win_stream_acquire_fast_io_main(file_object, stream, file_offset, length,
            wait, lock_key, TRUE, io_status, device_object)) {
        ext4win_trace_fallback(stream, EXT4WIN_TRACE_EVENT_FAST_IO_READ);
        return FALSE;
    }
    __try {
        handled = CcCopyRead(file_object, file_offset, length, wait, buffer, io_status);
        if (handled && NT_SUCCESS(io_status->Status) &&
            ((file_object->Flags & FO_SYNCHRONOUS_IO) != 0)) {
            file_object->CurrentByteOffset.QuadPart = file_offset->QuadPart + io_status->Information;
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        io_status->Status = GetExceptionCode();
        io_status->Information = 0;
        handled = TRUE;
    }
    ext4win_release_resource(&stream->MainResource);
    if (handled) {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_FAST_IO_READ, io_status->Status);
    }
    else {
        ext4win_trace_fallback(stream, EXT4WIN_TRACE_EVENT_FAST_IO_READ);
    }
    return handled;
}

_Success_(return != FALSE)
static BOOLEAN
NTAPI
ext4win_fast_io_write(
    _In_ PFILE_OBJECT file_object,
    _In_ PLARGE_INTEGER file_offset,
    _In_ ULONG length,
    _In_ BOOLEAN wait,
    _In_ ULONG lock_key,
    _In_reads_bytes_(length) PVOID buffer,
    _Out_ PIO_STATUS_BLOCK io_status,
    _In_ PDEVICE_OBJECT device_object)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    BOOLEAN handled;

    if ((buffer == NULL) || (io_status == NULL) || (file_offset == NULL) ||
        !wait ||
        ((file_object->Flags & FO_WRITE_THROUGH) != 0) ||
        !ext4win_stream_fast_io_candidate(file_object, &stream) ||
        !ext4win_handle_allows_cached_write(file_object->FsContext2)) {
        return FALSE;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_FAST_IO_WRITE);
    handled = FALSE;
    if (!ext4win_stream_acquire_fast_io_main(file_object, stream, file_offset, length,
            wait, lock_key, FALSE, io_status, device_object)) {
        ext4win_trace_fallback(stream, EXT4WIN_TRACE_EVENT_FAST_IO_WRITE);
        return FALSE;
    }
    __try {
        handled = CcCopyWrite(file_object, file_offset, length, wait, buffer);
        if (handled) {
            io_status->Status = STATUS_SUCCESS;
            io_status->Information = length;
            if ((file_object->Flags & FO_SYNCHRONOUS_IO) != 0) {
                file_object->CurrentByteOffset.QuadPart = file_offset->QuadPart + length;
            }
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        io_status->Status = GetExceptionCode();
        io_status->Information = 0;
        handled = TRUE;
    }
    ext4win_release_resource(&stream->MainResource);
    if (handled) {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_FAST_IO_WRITE, io_status->Status);
    }
    else {
        ext4win_trace_fallback(stream, EXT4WIN_TRACE_EVENT_FAST_IO_WRITE);
    }
    return handled;
}

#endif
