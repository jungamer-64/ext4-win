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
    ext4win_acquire_resource_shared(&stream->MainResource, TRUE);
    if (!ext4win_stream_fast_io_candidate(file, &observed) || (observed != stream) ||
        !ext4win_fast_io_check_if_possible(file, offset, length, wait, key, read, status, device)) {
        ext4win_release_resource(&stream->MainResource);
        return FALSE;
    }
    return TRUE;
}

#endif
