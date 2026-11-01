#ifndef EXT4WIN_FAST_IO_LOCK_H
#define EXT4WIN_FAST_IO_LOCK_H

_Success_(return != FALSE)
static BOOLEAN
NTAPI
ext4win_fast_io_lock(
    _In_ PFILE_OBJECT file_object,
    _In_ PLARGE_INTEGER file_offset,
    _In_ PLARGE_INTEGER length,
    _In_ PEPROCESS process,
    _In_ ULONG key,
    _In_ BOOLEAN fail_immediately,
    _In_ BOOLEAN exclusive_lock,
    _Out_ PIO_STATUS_BLOCK io_status,
    _In_ PDEVICE_OBJECT device_object)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    BOOLEAN handled;

    UNREFERENCED_PARAMETER(device_object);
    if ((io_status == NULL) || (file_offset == NULL) || (length == NULL) ||
        (process == NULL) || !ext4win_stream_fast_io_stream(file_object, &stream)) {
        return FALSE;
    }
    wdk_sys_acquire_resource_exclusive(&stream->MainResource, TRUE);
    /* A lock requiring an oplock break belongs to the IRP path, which owns
     * the break notification and any required acknowledgment wait. */
    if (!FsRtlOplockIsFastIoPossible(&stream->Header.Oplock)) {
        wdk_sys_release_resource(&stream->MainResource);
        return FALSE;
    }
    FsRtlIncrementLockRequestsInProgress(stream->ByteRangeLocks);
    /* FsRtlFastLock is the current public macro, but WDK 10.0.28000.0 expands it to the
     * analyzer-obsolete FsRtlPrivateLock implementation symbol. */
#pragma warning(suppress: 28159)
    handled = FsRtlFastLock(
        stream->ByteRangeLocks,
        file_object,
        file_offset,
        length,
        process,
        key,
        fail_immediately,
        exclusive_lock,
        io_status,
        NULL,
        TRUE);
    FsRtlDecrementLockRequestsInProgress(stream->ByteRangeLocks);
    ext4win_stream_refresh_fast_io_projection(stream);
    wdk_sys_release_resource(&stream->MainResource);
    return handled;
}

#endif
