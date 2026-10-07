#ifndef EXT4WIN_FS_FILTER_CALLBACKS_H
#define EXT4WIN_FS_FILTER_CALLBACKS_H

/* FsRtl can omit completion-context storage when no post callback is registered.
 * These callbacks retain no post-operation state; supplied storage receives NULL. */
/* Section creation is a fallible authority boundary. SyncTypeOther is a resource-only
 * acquisition used by Cc/MM and must remain available while terminal writeback drains. */
static NTSTATUS NTAPI
ext4win_pre_acquire_section(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_opt_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    if (context != NULL) {
        *context = NULL;
    }
    if (!ext4win_stream_section_callback_stream(data->FileObject, &stream)) {
        return STATUS_SUCCESS;
    }
    (VOID)ext4win_stream_acquire_main_after_section_mutation(stream, TRUE);
    if ((data->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection)
        && !ext4win_stream_ordinary_io_available(stream)) {
        ext4win_release_resource(&stream->MainResource);
        return STATUS_FILE_LOCK_CONFLICT;
    }
    return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
}

static NTSTATUS NTAPI
ext4win_pre_release_section(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_opt_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    if (context != NULL) {
        *context = NULL;
    }
    if (!ext4win_stream_section_callback_stream(data->FileObject, &stream)) {
        return STATUS_SUCCESS;
    }
    ext4win_release_resource(&stream->MainResource);
    return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
}

static NTSTATUS
NTAPI
ext4win_pre_acquire_mod_write(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_opt_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    PFILE_OBJECT file_object = data->FileObject;
    PERESOURCE *resource_to_release = data->Parameters.AcquireForModifiedPageWriter.ResourceToRelease;
    if (context != NULL) {
        *context = NULL;
    }
    if ((resource_to_release == NULL) ||
        !ext4win_stream_fast_io_stream(file_object, &stream)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_MAPPED_WRITE);
    if (!ext4win_stream_acquire_paging_after_section_mutation(stream, FALSE, TRUE)) {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_MAPPED_WRITE, STATUS_CANT_WAIT);
        return STATUS_CANT_WAIT;
    }
    *resource_to_release = &stream->PagingIoResource;
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_MAPPED_WRITE, STATUS_SUCCESS);
    return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
}

static NTSTATUS
NTAPI
ext4win_pre_release_mod_write(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_opt_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    PFILE_OBJECT file_object = data->FileObject;
    PERESOURCE resource_to_release = data->Parameters.ReleaseForModifiedPageWriter.ResourceToRelease;
    if (context != NULL) {
        *context = NULL;
    }
    if ((resource_to_release == NULL) || (file_object == NULL) ||
        ((stream = ext4win_stream_from_header(file_object->FsContext)) == NULL) ||
        (resource_to_release != &stream->PagingIoResource)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_release_resource(resource_to_release);
    return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
}

static NTSTATUS
NTAPI
ext4win_pre_acquire_cc_flush(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_opt_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    PFILE_OBJECT file_object = data->FileObject;
    if (context != NULL) {
        *context = NULL;
    }
    if (!ext4win_stream_fast_io_stream(file_object, &stream)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_stream_acquire_main_after_sealed_section_mutation(stream);
    return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
}

static NTSTATUS
NTAPI
ext4win_pre_release_cc_flush(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_opt_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    PFILE_OBJECT file_object = data->FileObject;
    if (context != NULL) {
        *context = NULL;
    }
    if ((file_object == NULL) ||
        ((stream = ext4win_stream_from_header(file_object->FsContext)) == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_release_resource(&stream->MainResource);
    return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NTAPI
ext4win_register_section_callbacks(_In_ PDRIVER_OBJECT driver)
{
    FS_FILTER_CALLBACKS callbacks;
    RtlZeroMemory(&callbacks, sizeof(callbacks));
    callbacks.SizeOfFsFilterCallbacks = sizeof(callbacks);
    callbacks.PreAcquireForSectionSynchronization = ext4win_pre_acquire_section;
    callbacks.PreReleaseForSectionSynchronization = ext4win_pre_release_section;
    callbacks.PreAcquireForModifiedPageWriter = ext4win_pre_acquire_mod_write;
    callbacks.PreReleaseForModifiedPageWriter = ext4win_pre_release_mod_write;
    callbacks.PreAcquireForCcFlush = ext4win_pre_acquire_cc_flush;
    callbacks.PreReleaseForCcFlush = ext4win_pre_release_cc_flush;
    return FsRtlRegisterFileSystemFilterCallbacks(driver, &callbacks);
}

#endif
