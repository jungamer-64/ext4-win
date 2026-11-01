#ifndef EXT4WIN_OPLOCK_CONTROL_H
#define EXT4WIN_OPLOCK_CONTROL_H

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_oplock_fsctrl(
    _In_ PVOID stream_header,
    _Inout_ PIRP irp,
    _In_ ULONG open_count,
    _In_ ULONG flags)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS status;
    ULONG count = open_count;

    if ((stream == NULL) || (stream->Kind != 1) ||
        (stream->ByteRangeLocks == NULL) || (irp == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_OPLOCK_CONTROL);
    wdk_sys_acquire_resource_exclusive(&stream->MainResource, TRUE);
    /* Shared oplocks consume a byte-lock observation, not a handle count.
     * MainResource excludes lock grants throughout observation and delegation.
     * CREATE retains its distinct atomic-create handle-count contract. */
    if (IoGetCurrentIrpStackLocation(irp)->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL &&
        FsRtlOplockIsSharedRequest(irp)) {
        count = FsRtlAreThereCurrentFileLocks(stream->ByteRangeLocks) ? 1UL : 0UL;
    }
    FsRtlIncrementLockRequestsInProgress(stream->ByteRangeLocks);
    __try {
        status = wdk_sys_oplock_fsctrl(
            &stream->Header.Oplock,
            irp,
            count,
            flags);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    FsRtlDecrementLockRequestsInProgress(stream->ByteRangeLocks);
    ext4win_stream_refresh_fast_io_projection(stream);
    wdk_sys_release_resource(&stream->MainResource);
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_OPLOCK_CONTROL, status);
    return status;
}

#endif
