#ifndef EXT4WIN_FILE_LOCK_COMPLETION_H
#define EXT4WIN_FILE_LOCK_COMPLETION_H

extern NTSTATUS NTAPI ext4win_complete_file_lock(_In_ PVOID context, _Inout_ PIRP irp);

/* The retained context owns a preallocated terminal notification worker. FsRtl
 * calls that completion boundary on both immediate and delayed completion;
 * upper drivers are invoked outside this resource acquisition and actor stack. */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_process_file_lock(
    _In_ PVOID stream_header,
    _Inout_ PIRP irp,
    _In_ PVOID completion)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS status;

    /* Both identities are mandatory preconditions of the consuming Rust boundary. */
    if ((irp == NULL) || (completion == NULL)) { return STATUS_INVALID_PARAMETER; }
    if ((stream == NULL) || (stream->Kind != 1) || (stream->ByteRangeLocks == NULL)) {
        irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        irp->IoStatus.Information = 0;
        (VOID)ext4win_complete_file_lock(completion, irp);
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    status = FsRtlProcessFileLock(stream->ByteRangeLocks, irp, completion);
    ext4win_stream_refresh_fast_io_projection(stream);
    ext4win_release_resource(&stream->MainResource);
    return status;
}

#endif
