#include <ntifs.h>
#include "executive_resource.h"
#include "section_mutation.h"
#include "operational_trace.h"

#define EXT4WIN_STREAM_POOL_TAG ((ULONG)0x53743445UL)
#define EXT4WIN_STREAM_SIGNATURE ((ULONG)0x53463445UL)
#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS                                      \
    (FsRtlIsNtstatusExpected((NTSTATUS)GetExceptionCode())                     \
         ? EXCEPTION_EXECUTE_HANDLER                                           \
         : EXCEPTION_CONTINUE_SEARCH)
#include "cache_mdl.h"
#include "cache_close.h"

extern VOID NTAPI ext4win_oplock_wait_complete(_In_ PVOID context, _Inout_ PIRP irp);
extern VOID NTAPI ext4win_oplock_prepost(_In_ PVOID context, _Inout_ PIRP irp);
extern UCHAR NTAPI ext4win_storage_media_state(_In_ const VOID *state);
extern UCHAR NTAPI ext4win_storage_close_phase(_In_ const VOID *state);
extern NTSTATUS NTAPI ext4win_prepare_mdl_completion(_In_ const VOID *queue, _In_ PFILE_OBJECT file_object);

/* This consuming call preserves buffered/direct/neither IOCTL semantics and lower cancellation. */
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_forward_original_irp(_In_ PDEVICE_OBJECT device, _Inout_ PIRP irp)
{
    IoSkipCurrentIrpStackLocation(irp);
    return IoCallDriver(device, irp);
}

typedef struct _EXT4WIN_STREAM_METADATA {
    ULONGLONG Epoch;
    ULONG CreationTimeSeconds;
    ULONG LastAccessTimeSeconds;
    ULONG LastWriteTimeSeconds;
    ULONG ChangeTimeSeconds;
    ULONG FileAttributes;
    ULONG NumberOfLinks;
    ULONG Directory;
} EXT4WIN_STREAM_METADATA, *PEXT4WIN_STREAM_METADATA;

typedef struct _EXT4WIN_PUBLISHED_STREAM_METADATA {
    ULONGLONG Epoch;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
    ULONG NumberOfLinks;
    ULONG Directory;
} EXT4WIN_PUBLISHED_STREAM_METADATA, *PEXT4WIN_PUBLISHED_STREAM_METADATA;

typedef struct _EXT4WIN_FAST_IO_QUERY_SNAPSHOT {
    EXT4WIN_PUBLISHED_STREAM_METADATA Metadata;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    BOOLEAN DeletePending;
} EXT4WIN_FAST_IO_QUERY_SNAPSHOT, *PEXT4WIN_FAST_IO_QUERY_SNAPSHOT;

typedef struct _EXT4WIN_FAST_IO_TRANSFER_OBSERVATION {
    LONGLONG Eof;
    ULONG Flags;
    UCHAR Cached, Media, Close, Mutation, ReadAccess, WriteAccess;
} EXT4WIN_FAST_IO_TRANSFER_OBSERVATION;

extern BOOLEAN NTAPI ext4win_fast_io_admit(ULONG flags, UCHAR cached, UCHAR media, UCHAR close, UCHAR mutation);
extern BOOLEAN NTAPI ext4win_fast_io_query_admit(ULONG flags, UCHAR read_access, UCHAR possible, UCHAR media, UCHAR mutation);
extern BOOLEAN NTAPI ext4win_fast_io_check_if_possible(PFILE_OBJECT file, PLARGE_INTEGER offset,
    ULONG length, BOOLEAN wait, ULONG key, BOOLEAN read, PIO_STATUS_BLOCK status, PDEVICE_OBJECT device);
extern VOID NTAPI ext4win_fast_io_basic_record(const EXT4WIN_FAST_IO_QUERY_SNAPSHOT *snapshot, PFILE_BASIC_INFORMATION output);
extern VOID NTAPI ext4win_fast_io_standard_record(const EXT4WIN_FAST_IO_QUERY_SNAPSHOT *snapshot, PFILE_STANDARD_INFORMATION output);
extern VOID NTAPI ext4win_fast_io_network_record(const EXT4WIN_FAST_IO_QUERY_SNAPSHOT *snapshot, PFILE_NETWORK_OPEN_INFORMATION output);
C_ASSERT(sizeof(EXT4WIN_FAST_IO_TRANSFER_OBSERVATION) == 24);
C_ASSERT(FIELD_OFFSET(EXT4WIN_FAST_IO_TRANSFER_OBSERVATION, Cached) == 12);
C_ASSERT(sizeof(EXT4WIN_FAST_IO_QUERY_SNAPSHOT) == 80);
C_ASSERT(FIELD_OFFSET(EXT4WIN_FAST_IO_QUERY_SNAPSHOT, DeletePending) == 72);

typedef struct _EXT4WIN_STREAM_CONTEXT {
    FSRTL_ADVANCED_FCB_HEADER Header;
    FAST_MUTEX HeaderMutex;
    ERESOURCE MainResource;
    ERESOURCE PagingIoResource;
    SECTION_OBJECT_POINTERS SectionObjects;
    /* Rust owns the domain-specific admission or completion allocation. */
    PVOID RustState;
    /* Physical storage charge is not the header's logical section bound. */
    LONGLONG AllocationCharge;
    EXT4WIN_PUBLISHED_STREAM_METADATA PublishedMetadata;
    PVOID FileContextSupport;
    PVOID Owner;
    /* Published once with the VCB owner, before any volume FILE_OBJECT is exposed. */
    PDEVICE_OBJECT VolumeControlDevice;
    /* The VCB outlives all ledger-owned node streams, including mapped sections. */
    struct _EXT4WIN_STREAM_CONTEXT *VolumeStream;
    ERESOURCE Submissions;
    PFILE_LOCK ByteRangeLocks;
    PVOID AePushLock;
    REGHANDLE TraceRegistrationHandle;
    EXT4WIN_SECTION_MUTATION SectionMutation;
    volatile LONG MetadataValid;
    volatile LONG DeletePending;
    ULONG Signature;
    ULONG Kind;
    BOOLEAN MainResourceInitialized;
    BOOLEAN PagingResourceInitialized;
    BOOLEAN HeaderInitialized;
    BOOLEAN OplockInitialized;
} EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;

C_ASSERT(FIELD_OFFSET(EXT4WIN_STREAM_CONTEXT, Header) == 0);
C_ASSERT(sizeof(EXT4WIN_STREAM_CONTEXT) <= MAXSHORT);
C_ASSERT(sizeof(EXT4WIN_STREAM_METADATA) == 40);
C_ASSERT(FIELD_OFFSET(EXT4WIN_STREAM_METADATA, Epoch) == 0);
C_ASSERT(FIELD_OFFSET(EXT4WIN_STREAM_METADATA, CreationTimeSeconds) == 8);
C_ASSERT(FIELD_OFFSET(EXT4WIN_STREAM_METADATA, FileAttributes) == 24);
C_ASSERT(FIELD_OFFSET(EXT4WIN_STREAM_METADATA, NumberOfLinks) == 28);
C_ASSERT(FIELD_OFFSET(EXT4WIN_STREAM_METADATA, Directory) == 32);

_Success_(return != FALSE)
static BOOLEAN
ext4win_prepare_stream_metadata(
    _In_ const EXT4WIN_STREAM_METADATA *input,
    _Out_ PEXT4WIN_PUBLISHED_STREAM_METADATA output)
{
    if ((input == NULL) || (output == NULL) ||
        (input->FileAttributes == 0) || (input->NumberOfLinks == 0) ||
        (input->Directory > 1)) {
        return FALSE;
    }

    RtlZeroMemory(output, sizeof(*output));
    output->Epoch = input->Epoch;
    RtlSecondsSince1970ToTime(input->CreationTimeSeconds, &output->CreationTime);
    RtlSecondsSince1970ToTime(input->LastAccessTimeSeconds, &output->LastAccessTime);
    RtlSecondsSince1970ToTime(input->LastWriteTimeSeconds, &output->LastWriteTime);
    RtlSecondsSince1970ToTime(input->ChangeTimeSeconds, &output->ChangeTime);
    output->FileAttributes = input->FileAttributes;
    output->NumberOfLinks = input->NumberOfLinks;
    output->Directory = input->Directory;
    return TRUE;
}

static VOID
ext4win_trace_selected(
    _In_ PEXT4WIN_STREAM_CONTEXT stream,
    _In_ USHORT event_id)
{
    ext4win_trace_write(
        stream->TraceRegistrationHandle,
        event_id,
        STATUS_SUCCESS,
        EXT4WIN_TRACE_OUTCOME_SELECTED);
}

static VOID
ext4win_trace_status(
    _In_ PEXT4WIN_STREAM_CONTEXT stream,
    _In_ USHORT event_id,
    _In_ NTSTATUS status)
{
    ext4win_trace_write(
        stream->TraceRegistrationHandle,
        event_id,
        status,
        status == STATUS_PENDING
            ? EXT4WIN_TRACE_OUTCOME_PENDING
            : (NT_SUCCESS(status)
                ? EXT4WIN_TRACE_OUTCOME_COMPLETED
                : EXT4WIN_TRACE_OUTCOME_FAILED));
}

static VOID
ext4win_trace_fallback(
    _In_ PEXT4WIN_STREAM_CONTEXT stream,
    _In_ USHORT event_id)
{
    ext4win_trace_write(
        stream->TraceRegistrationHandle,
        event_id,
        STATUS_NOT_SUPPORTED,
        EXT4WIN_TRACE_OUTCOME_FALLBACK);
}

static PEXT4WIN_STREAM_CONTEXT
ext4win_stream_from_header(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    if (stream_header == NULL) {
        return NULL;
    }

    stream = CONTAINING_RECORD(stream_header, EXT4WIN_STREAM_CONTEXT, Header);
    if ((stream->Signature != EXT4WIN_STREAM_SIGNATURE) ||
        (stream_header != (PVOID)&stream->Header)) {
        return NULL;
    }
    return stream;
}

/* Node cache and Fast I/O admission consult the volume's sole removal authority. */
static BOOLEAN
ext4win_stream_storage_available(_In_ PEXT4WIN_STREAM_CONTEXT stream)
{
    PEXT4WIN_STREAM_CONTEXT volume = (stream->Kind == 2) ? stream : stream->VolumeStream;
    return (volume != NULL) && (ext4win_storage_media_state(volume->RustState) == 0);
}

/* Cache/Fast I/O authority is independent from lower storage presence. */
static BOOLEAN
ext4win_stream_ordinary_io_available(_In_ PEXT4WIN_STREAM_CONTEXT stream)
{
    PEXT4WIN_STREAM_CONTEXT volume = (stream->Kind == 2) ? stream : stream->VolumeStream;
    return ext4win_stream_storage_available(stream)
        && (ext4win_storage_close_phase(volume->RustState) == 0);
}

static BOOLEAN
ext4win_stream_acquire_paging_after_section_mutation(
    _In_ PEXT4WIN_STREAM_CONTEXT stream,
    _In_ BOOLEAN exclusive,
    _In_ BOOLEAN wait)
{
    for (;;) {
        while (ext4win_section_mutation_state(&stream->SectionMutation) == EXT4WIN_SECTION_MUTATION_SEALED) {
            if (!wait) {
                return FALSE;
            }
            (VOID)KeWaitForSingleObject(
                &stream->SectionMutation.Released,
                Executive,
                KernelMode,
                FALSE,
                NULL);
        }
        if (exclusive) {
            if (wait) {
                (VOID)ext4win_acquire_resource_exclusive(&stream->PagingIoResource, TRUE);
            }
            else if (!ext4win_acquire_resource_exclusive(&stream->PagingIoResource, FALSE)) {
                return FALSE;
            }
        }
        else {
            if (wait) {
                (VOID)ext4win_acquire_resource_shared(&stream->PagingIoResource, TRUE);
            }
            else if (!ext4win_acquire_resource_shared(&stream->PagingIoResource, FALSE)) {
                return FALSE;
            }
        }
        if (ext4win_section_mutation_state(&stream->SectionMutation) != EXT4WIN_SECTION_MUTATION_SEALED) {
            return TRUE;
        }
        ext4win_release_resource(&stream->PagingIoResource);
        if (!wait) {
            return FALSE;
        }
    }
}

static VOID
ext4win_stream_acquire_main_after_sealed_section_mutation(
    _In_ PEXT4WIN_STREAM_CONTEXT stream)
{
    for (;;) {
        while (ext4win_section_mutation_state(&stream->SectionMutation) == EXT4WIN_SECTION_MUTATION_SEALED) {
            (VOID)KeWaitForSingleObject(
                &stream->SectionMutation.Released,
                Executive,
                KernelMode,
                FALSE,
                NULL);
        }
        ext4win_acquire_resource_shared(&stream->MainResource, TRUE);
        if (ext4win_section_mutation_state(&stream->SectionMutation) != EXT4WIN_SECTION_MUTATION_SEALED) {
            return;
        }
        ext4win_release_resource(&stream->MainResource);
    }
}

static BOOLEAN
NTAPI
ext4win_acquire_for_lazy_write(
    _In_ PVOID context,
    _In_ BOOLEAN wait)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(context);

    if (stream == NULL) {
        return FALSE;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_MAPPED_WRITE);
    if (!ext4win_stream_acquire_paging_after_section_mutation(stream, TRUE, wait)) {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_MAPPED_WRITE, STATUS_CANT_WAIT);
        return FALSE;
    }
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_MAPPED_WRITE, STATUS_SUCCESS);
    return TRUE;
}

static VOID
NTAPI
ext4win_release_from_lazy_write(_In_ PVOID context)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(context);

    if (stream != NULL) {
        ext4win_release_resource(&stream->PagingIoResource);
    }
}

static BOOLEAN
NTAPI
ext4win_acquire_for_read_ahead(
    _In_ PVOID context,
    _In_ BOOLEAN wait)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(context);

    if (stream == NULL) {
        return FALSE;
    }
    for (;;) {
        while (ext4win_section_mutation_state(&stream->SectionMutation) != EXT4WIN_SECTION_MUTATION_IDLE) {
            if (!wait) {
                return FALSE;
            }
            (VOID)KeWaitForSingleObject(
                &stream->SectionMutation.Released,
                Executive,
                KernelMode,
                FALSE,
                NULL);
        }
        if (!ext4win_acquire_resource_shared(&stream->MainResource, wait)) {
            return FALSE;
        }
        if (ext4win_section_mutation_state(&stream->SectionMutation) == EXT4WIN_SECTION_MUTATION_IDLE) {
            return TRUE;
        }
        ext4win_release_resource(&stream->MainResource);
        if (!wait) {
            return FALSE;
        }
    }
}

static VOID
NTAPI
ext4win_release_from_read_ahead(_In_ PVOID context)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(context);

    if (stream != NULL) {
        ext4win_release_resource(&stream->MainResource);
    }
}

static CACHE_MANAGER_CALLBACKS ext4win_cache_callbacks = {
    ext4win_acquire_for_lazy_write,
    ext4win_release_from_lazy_write,
    ext4win_acquire_for_read_ahead,
    ext4win_release_from_read_ahead
};

static BOOLEAN
ext4win_stream_matches_file_object(
    _In_ PEXT4WIN_STREAM_CONTEXT stream,
    _In_ PFILE_OBJECT file_object)
{
    return (stream != NULL) && (file_object != NULL) &&
        (file_object->FsContext == (PVOID)&stream->Header) &&
        (file_object->SectionObjectPointer == &stream->SectionObjects);
}

_Success_(return != FALSE)
static BOOLEAN
ext4win_stream_fast_io_stream(
    _In_ PFILE_OBJECT file_object,
    _Outptr_ PEXT4WIN_STREAM_CONTEXT *stream_out)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    if ((file_object == NULL) || (stream_out == NULL) ||
        (file_object->FsContext == NULL)) {
        return FALSE;
    }
    stream = ext4win_stream_from_header(file_object->FsContext);
    if (!ext4win_stream_matches_file_object(stream, file_object) ||
        (stream->Kind != 1) || (stream->ByteRangeLocks == NULL)) {
        return FALSE;
    }
    *stream_out = stream;
    return TRUE;
}

_Success_(return != FALSE)
static BOOLEAN
ext4win_stream_fast_io_candidate(
    _In_ PFILE_OBJECT file_object,
    _Outptr_ PEXT4WIN_STREAM_CONTEXT *stream_out)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    PEXT4WIN_STREAM_CONTEXT volume;
    if (!ext4win_stream_fast_io_stream(file_object, &stream)) { return FALSE; }
    volume = stream->VolumeStream;
    if (volume == NULL) { return FALSE; }
    *stream_out = stream;
    return ext4win_fast_io_admit(file_object->Flags, file_object->PrivateCacheMap != NULL,
        ext4win_storage_media_state(volume->RustState), ext4win_storage_close_phase(volume->RustState),
        (UCHAR)ext4win_section_mutation_state(&stream->SectionMutation));
}

_Success_(return != FALSE)
static BOOLEAN
ext4win_stream_section_callback_stream(
    _In_ PFILE_OBJECT file_object,
    _Outptr_ PEXT4WIN_STREAM_CONTEXT *stream_out)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    if ((file_object == NULL) || (stream_out == NULL) ||
        (file_object->FsContext == NULL)) {
        return FALSE;
    }
    stream = ext4win_stream_from_header(file_object->FsContext);
    if (!ext4win_stream_matches_file_object(stream, file_object) ||
        !stream->MainResourceInitialized) {
        return FALSE;
    }
    *stream_out = stream;
    return TRUE;
}

static BOOLEAN
ext4win_stream_acquire_main_after_section_mutation(
    _In_ PEXT4WIN_STREAM_CONTEXT stream,
    _In_ BOOLEAN exclusive)
{
    BOOLEAN waited;

    waited = FALSE;
    for (;;) {
        while (ext4win_section_mutation_state(&stream->SectionMutation) != EXT4WIN_SECTION_MUTATION_IDLE) {
            waited = TRUE;
            (VOID)KeWaitForSingleObject(
                &stream->SectionMutation.Released,
                Executive,
                KernelMode,
                FALSE,
                NULL);
        }
        if (exclusive) {
            ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
        }
        else {
            ext4win_acquire_resource_shared(&stream->MainResource, TRUE);
        }
        if (ext4win_section_mutation_state(&stream->SectionMutation) == EXT4WIN_SECTION_MUTATION_IDLE) {
            return waited;
        }
        waited = TRUE;
        ext4win_release_resource(&stream->MainResource);
    }
}

static NTSTATUS
ext4win_stream_seal_section_mutation(_In_ PEXT4WIN_STREAM_CONTEXT stream)
{
    NTSTATUS status;

    status = STATUS_SUCCESS;
    ext4win_acquire_resource_exclusive(&stream->PagingIoResource, TRUE);
    if (!ext4win_section_mutation_seal(&stream->SectionMutation)) {
        status = STATUS_INTERNAL_ERROR;
    }
    ext4win_release_resource(&stream->PagingIoResource);
    return status;
}

static NTSTATUS
ext4win_stream_end_section_mutation(_In_ PEXT4WIN_STREAM_CONTEXT stream)
{
    if (ext4win_section_mutation_state(&stream->SectionMutation) != EXT4WIN_SECTION_MUTATION_SEALED) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    ext4win_section_mutation_release(&stream->SectionMutation);
    return STATUS_SUCCESS;
}

static BOOLEAN
ext4win_stream_acquire_fast_io_main(_In_ PFILE_OBJECT file, _In_ PEXT4WIN_STREAM_CONTEXT stream)
{
    PEXT4WIN_STREAM_CONTEXT observed;
    ext4win_acquire_resource_shared(&stream->MainResource, TRUE);
    if (!ext4win_stream_fast_io_candidate(file, &observed) || (observed != stream)) {
        ext4win_release_resource(&stream->MainResource);
        return FALSE;
    }
    return TRUE;
}

static VOID
ext4win_stream_refresh_fast_io_projection(_In_ PEXT4WIN_STREAM_CONTEXT stream)
{
    if ((stream == NULL) || (stream->ByteRangeLocks == NULL) ||
        !FsRtlOplockIsFastIoPossible(&stream->Header.Oplock)) {
        if (stream != NULL) {
            stream->Header.IsFastIoPossible = FastIoIsNotPossible;
        }
    } else if (FsRtlAreThereCurrentFileLocks(stream->ByteRangeLocks)) {
        stream->Header.IsFastIoPossible = FastIoIsQuestionable;
    } else {
        stream->Header.IsFastIoPossible = FastIoIsPossible;
    }
}

static VOID
ext4win_capture_cache_sizes(
    _In_ PEXT4WIN_STREAM_CONTEXT stream,
    _Out_ PCC_FILE_SIZES sizes)
{
    ExAcquireFastMutex(&stream->HeaderMutex);
    sizes->AllocationSize = stream->Header.AllocationSize;
    sizes->FileSize = stream->Header.FileSize;
    sizes->ValidDataLength = stream->Header.ValidDataLength;
    ExReleaseFastMutex(&stream->HeaderMutex);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_create(
    _In_ ULONG kind,
    _In_ LONGLONG allocation_size,
    _In_ LONGLONG file_size,
    _In_ LONGLONG valid_data_length,
    _In_ LONGLONG allocation_charge,
    _In_opt_ const EXT4WIN_STREAM_METADATA *metadata,
    _In_ REGHANDLE trace_registration_handle,
    _In_ PVOID rust_state,
    _Outptr_ PVOID *stream_header_out)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    EXT4WIN_PUBLISHED_STREAM_METADATA prepared_metadata;
    BOOLEAN metadata_valid;
    NTSTATUS status;

    if (stream_header_out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *stream_header_out = NULL;
    RtlZeroMemory(&prepared_metadata, sizeof(prepared_metadata));
    metadata_valid = FALSE;
    if ((rust_state == NULL) || ((kind != 1) && (kind != 2))) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((metadata != NULL) &&
        !ext4win_prepare_stream_metadata(metadata, &prepared_metadata)) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((kind == 2) && (metadata != NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    metadata_valid = metadata != NULL;
    if ((trace_registration_handle == (REGHANDLE)0) ||
        (allocation_size < 0) || (file_size < 0) ||
        (allocation_charge < 0) || (allocation_charge > allocation_size) ||
        (valid_data_length != file_size) ||
        (file_size > allocation_size)) {
        return STATUS_INVALID_PARAMETER;
    }

    stream = (PEXT4WIN_STREAM_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*stream),
        EXT4WIN_STREAM_POOL_TAG);
    if (stream == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(stream, sizeof(*stream));
    stream->TraceRegistrationHandle = trace_registration_handle;
    stream->RustState = rust_state;

    status = ExInitializeResourceLite(&stream->MainResource);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(stream, EXT4WIN_STREAM_POOL_TAG);
        return status;
    }
    stream->MainResourceInitialized = TRUE;

    status = ExInitializeResourceLite(&stream->PagingIoResource);
    if (!NT_SUCCESS(status)) {
        (VOID)ExDeleteResourceLite(&stream->MainResource);
        ExFreePoolWithTag(stream, EXT4WIN_STREAM_POOL_TAG);
        return status;
    }
    stream->PagingResourceInitialized = TRUE;

    ext4win_section_mutation_initialize(&stream->SectionMutation);

    stream->AePushLock = FsRtlAllocateAePushLock(NonPagedPoolNx, EXT4WIN_STREAM_POOL_TAG);
    if (stream->AePushLock == NULL) {
        (VOID)ExDeleteResourceLite(&stream->PagingIoResource);
        (VOID)ExDeleteResourceLite(&stream->MainResource);
        ExFreePoolWithTag(stream, EXT4WIN_STREAM_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (kind == 2) {
        status = ExInitializeResourceLite(&stream->Submissions);
        if (!NT_SUCCESS(status)) {
            FsRtlFreeAePushLock(stream->AePushLock);
            (VOID)ExDeleteResourceLite(&stream->PagingIoResource);
            (VOID)ExDeleteResourceLite(&stream->MainResource);
            ExFreePoolWithTag(stream, EXT4WIN_STREAM_POOL_TAG);
            return status;
        }
    }

    ExInitializeFastMutex(&stream->HeaderMutex);
    stream->Header.Resource = &stream->MainResource;
    stream->Header.PagingIoResource = &stream->PagingIoResource;
    stream->Header.AllocationSize.QuadPart = allocation_size;
    stream->Header.FileSize.QuadPart = file_size;
    stream->Header.ValidDataLength.QuadPart = valid_data_length;
    stream->AllocationCharge = allocation_charge;
    if (metadata_valid) {
        stream->PublishedMetadata = prepared_metadata;
        stream->MetadataValid = TRUE;
    }
    stream->Header.IsFastIoPossible = FastIoIsQuestionable;
    FsRtlSetupAdvancedHeaderEx2(
        &stream->Header,
        &stream->HeaderMutex,
        &stream->FileContextSupport,
        stream->AePushLock);
    stream->HeaderInitialized = TRUE;
    FsRtlInitializeOplock(&stream->Header.Oplock);
    stream->OplockInitialized = TRUE;
    stream->Signature = EXT4WIN_STREAM_SIGNATURE;
    stream->Kind = kind;
    *stream_header_out = &stream->Header;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_bind_node_owner(
    _In_ PVOID stream_header,
    _In_ PVOID owner,
    _Inout_ PFILE_LOCK byte_range_locks,
    _In_ PVOID volume_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    PEXT4WIN_STREAM_CONTEXT volume = ext4win_stream_from_header(volume_header);

    if ((stream == NULL) || (stream->Kind != 1) || (owner == NULL) ||
        (byte_range_locks == NULL) || (stream->Owner != NULL) ||
        (stream->ByteRangeLocks != NULL) || (volume == NULL) || (volume->Kind != 2)) {
        return STATUS_INVALID_PARAMETER;
    }
    stream->Owner = owner;
    stream->ByteRangeLocks = byte_range_locks;
    stream->VolumeStream = volume;
    ext4win_stream_refresh_fast_io_projection(stream);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_bind_volume_owner(
    _In_ PVOID stream_header,
    _In_ PVOID owner,
    _In_ PDEVICE_OBJECT control_device)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);

    if ((stream == NULL) || (stream->Kind != 2) || (owner == NULL) || (control_device == NULL) ||
        (stream->Owner != NULL) || (stream->ByteRangeLocks != NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    stream->VolumeControlDevice = control_device;
    stream->Owner = owner;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PDEVICE_OBJECT
NTAPI
ext4win_stream_volume_control_device(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    return ((stream != NULL) && (stream->Kind == 2) && (stream->Owner != NULL))
        ? stream->VolumeControlDevice : NULL;
}

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

    if ((stream == NULL) || (stream->Kind != 1) ||
        (stream->ByteRangeLocks == NULL) || (irp == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_OPLOCK_CONTROL);
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    FsRtlIncrementLockRequestsInProgress(stream->ByteRangeLocks);
    __try {
        status = FsRtlOplockFsctrlEx(
            &stream->Header.Oplock,
            irp,
            open_count,
            flags);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    FsRtlDecrementLockRequestsInProgress(stream->ByteRangeLocks);
    ext4win_stream_refresh_fast_io_projection(stream);
    ext4win_release_resource(&stream->MainResource);
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_OPLOCK_CONTROL, status);
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_check_oplock(
    _In_ PVOID stream_header,
    _Inout_ PIRP irp,
    _In_ ULONG flags,
    _In_ PVOID continuation)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS status;

    if ((stream == NULL) || (stream->Kind != 1) ||
        (stream->ByteRangeLocks == NULL) || (irp == NULL) ||
        (continuation == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_OPLOCK_CHECK);
    ext4win_acquire_resource_shared(&stream->MainResource, TRUE);
    __try {
        status = FsRtlCheckOplockEx(
            &stream->Header.Oplock,
            irp,
            flags,
            continuation,
            ext4win_oplock_wait_complete,
            ext4win_oplock_prepost);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    ext4win_release_resource(&stream->MainResource);
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    ext4win_stream_refresh_fast_io_projection(stream);
    ext4win_release_resource(&stream->MainResource);
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_OPLOCK_CHECK, status);
    return status;
}

/* Cleanup never waits for an oplock acknowledgment and never transfers IRP ownership.
 * It must release FsRtl state even when storage admission has been revoked. */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_cleanup_oplock(_In_ PVOID stream_header, _Inout_ PIRP irp, _In_ ULONG flags)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS status;
    if ((stream == NULL) || (stream->Kind != 1) || (irp == NULL) ||
        (IoGetCurrentIrpStackLocation(irp)->MajorFunction != IRP_MJ_CLEANUP) ||
        ((flags != 0) && (flags != OPLOCK_FLAG_CLOSING_DELETE_ON_CLOSE))) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_OPLOCK_CHECK);
    ext4win_acquire_resource_shared(&stream->MainResource, TRUE);
    __try {
        status = FsRtlCheckOplockEx(&stream->Header.Oplock, irp, flags, NULL, NULL, NULL);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) { status = GetExceptionCode(); }
    ext4win_release_resource(&stream->MainResource);
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    ext4win_stream_refresh_fast_io_projection(stream);
    ext4win_release_resource(&stream->MainResource);
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_OPLOCK_CHECK, status);
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_backout_atomic_oplock(
    _In_ PVOID stream_header,
    _Inout_ PIRP irp)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS status;

    if ((stream == NULL) || (stream->Kind != 1) ||
        (stream->ByteRangeLocks == NULL) || (irp == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_OPLOCK_CHECK);
    ext4win_acquire_resource_shared(&stream->MainResource, TRUE);
    __try {
        status = FsRtlCheckOplockEx(
            &stream->Header.Oplock,
            irp,
            OPLOCK_FLAG_BACK_OUT_ATOMIC_OPLOCK,
            NULL,
            NULL,
            NULL);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    ext4win_release_resource(&stream->MainResource);
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    ext4win_stream_refresh_fast_io_projection(stream);
    ext4win_release_resource(&stream->MainResource);
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_OPLOCK_CHECK, status);
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_process_file_lock(
    _In_ PVOID stream_header,
    _Inout_ PIRP irp)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS status;

    if ((stream == NULL) || (stream->Kind != 1) ||
        (stream->ByteRangeLocks == NULL) || (irp == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    status = FsRtlProcessFileLock(stream->ByteRangeLocks, irp, NULL);
    ext4win_stream_refresh_fast_io_projection(stream);
    ext4win_release_resource(&stream->MainResource);
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_unlock_all(
    _In_ PVOID stream_header,
    _In_ PFILE_OBJECT file_object,
    _In_ PEPROCESS process)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS status;

    if ((stream == NULL) || (stream->Kind != 1) ||
        (stream->ByteRangeLocks == NULL) ||
        !ext4win_stream_matches_file_object(stream, file_object) ||
        (process == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    status = FsRtlFastUnlockAll(
        stream->ByteRangeLocks,
        file_object,
        process,
        NULL);
    ext4win_stream_refresh_fast_io_projection(stream);
    ext4win_release_resource(&stream->MainResource);
    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_decode_owner(
    _In_ PVOID stream_header,
    _In_ ULONG expected_kind,
    _Outptr_ PVOID *owner_out)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);

    if (owner_out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *owner_out = NULL;
    if ((stream == NULL) || (stream->Kind != expected_kind) ||
        (stream->Owner == NULL) ||
        ((stream->Header.Flags & FSRTL_FLAG_ADVANCED_HEADER) == 0)) {
        return STATUS_INVALID_PARAMETER;
    }
    *owner_out = stream->Owner;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_section_objects(
    _In_ PVOID stream_header,
    _Outptr_ PSECTION_OBJECT_POINTERS *section_objects_out)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);

    if (section_objects_out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *section_objects_out = NULL;
    if (stream == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *section_objects_out = &stream->SectionObjects;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_get_sizes(
    _In_ PVOID stream_header,
    _Out_ LONGLONG *allocation_size_out,
    _Out_ LONGLONG *file_size_out,
    _Out_ LONGLONG *valid_data_length_out,
    _Out_ LONGLONG *allocation_charge_out)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);

    if ((stream == NULL) || (allocation_size_out == NULL) ||
        (file_size_out == NULL) || (valid_data_length_out == NULL) ||
        (allocation_charge_out == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    ExAcquireFastMutex(&stream->HeaderMutex);
    *allocation_size_out = stream->Header.AllocationSize.QuadPart;
    *file_size_out = stream->Header.FileSize.QuadPart;
    *valid_data_length_out = stream->Header.ValidDataLength.QuadPart;
    *allocation_charge_out = stream->AllocationCharge;
    ExReleaseFastMutex(&stream->HeaderMutex);
    return STATUS_SUCCESS;
}

#include "stream_metadata.h"

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_set_delete_pending(
    _In_ PVOID stream_header,
    _In_ BOOLEAN pending)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);

    if ((stream == NULL) || (stream->Kind != 1) ||
        ((pending != FALSE) && (pending != TRUE))) {
        return STATUS_INVALID_PARAMETER;
    }
    InterlockedExchange(&stream->DeletePending, pending != FALSE);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_cache_initialize(
    _In_ PVOID stream_header,
    _Inout_ PFILE_OBJECT file_object)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    CC_FILE_SIZES sizes;
    NTSTATUS status;

    if (!ext4win_stream_matches_file_object(stream, file_object)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!ext4win_stream_ordinary_io_available(stream)) { return ext4win_stream_storage_available(stream) ? STATUS_VOLUME_DISMOUNTED : STATUS_DEVICE_REMOVED; }

    status = STATUS_SUCCESS;
    (VOID)ext4win_stream_acquire_main_after_section_mutation(stream, TRUE);
    if (!ext4win_stream_ordinary_io_available(stream)) {
        ext4win_release_resource(&stream->MainResource);
        return ext4win_stream_storage_available(stream) ? STATUS_VOLUME_DISMOUNTED : STATUS_DEVICE_REMOVED;
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
                file_object->Flags |= FO_CACHE_SUPPORTED;
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

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_cache_read(
    _In_ PVOID stream_header,
    _Inout_ PFILE_OBJECT file_object,
    _In_ LONGLONG offset,
    _In_ ULONG length,
    _Out_writes_bytes_(length) PVOID buffer,
    _Out_ ULONG_PTR *information_out)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    IO_STATUS_BLOCK io_status;
    LARGE_INTEGER file_offset;
    LONGLONG current_file_size;
    NTSTATUS status;

    if (!ext4win_stream_matches_file_object(stream, file_object) ||
        (offset < 0) || ((length != 0) && (buffer == NULL)) ||
        (information_out == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    *information_out = 0;
    status = ext4win_stream_cache_initialize(stream_header, file_object);
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_CACHED_READ);
    if (!NT_SUCCESS(status) || (length == 0)) {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_CACHED_READ, status);
        return status;
    }

    file_offset.QuadPart = offset;
    io_status.Status = STATUS_SUCCESS;
    io_status.Information = 0;
    (VOID)ext4win_stream_acquire_main_after_section_mutation(stream, FALSE);
    if (!ext4win_stream_ordinary_io_available(stream)) {
        ext4win_release_resource(&stream->MainResource);
        return ext4win_stream_storage_available(stream) ? STATUS_VOLUME_DISMOUNTED : STATUS_DEVICE_REMOVED;
    }
    ExAcquireFastMutex(&stream->HeaderMutex);
    current_file_size = stream->Header.FileSize.QuadPart;
    ExReleaseFastMutex(&stream->HeaderMutex);
    __try {
        if ((offset > current_file_size) ||
            ((LONGLONG)length > (current_file_size - offset))) {
            /* A size gate published after this read was planned; resolve against the new epoch. */
            status = STATUS_RETRY;
        }
        else {
            if (!CcCopyRead(file_object, &file_offset, length, TRUE, buffer, &io_status)) {
                status = STATUS_CANT_WAIT;
            }
            else {
                status = io_status.Status;
                *information_out = io_status.Information;
            }
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    ext4win_release_resource(&stream->MainResource);
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_CACHED_READ, status);
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_cache_write(
    _In_ PVOID stream_header,
    _Inout_ PFILE_OBJECT file_object,
    _In_ LONGLONG offset,
    _In_ ULONG length,
    _In_reads_bytes_(length) PVOID buffer)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    LARGE_INTEGER file_offset;
    LONGLONG current_file_size;
    NTSTATUS status;

    if (!ext4win_stream_matches_file_object(stream, file_object) ||
        (offset < 0) || ((length != 0) && (buffer == NULL))) {
        return STATUS_INVALID_PARAMETER;
    }
    status = ext4win_stream_cache_initialize(stream_header, file_object);
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_CACHED_WRITE);
    if (!NT_SUCCESS(status) || (length == 0)) {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_CACHED_WRITE, status);
        return status;
    }

    file_offset.QuadPart = offset;
    (VOID)ext4win_stream_acquire_main_after_section_mutation(stream, FALSE);
    if (!ext4win_stream_ordinary_io_available(stream)) {
        ext4win_release_resource(&stream->MainResource);
        return ext4win_stream_storage_available(stream) ? STATUS_VOLUME_DISMOUNTED : STATUS_DEVICE_REMOVED;
    }
    ExAcquireFastMutex(&stream->HeaderMutex);
    current_file_size = stream->Header.FileSize.QuadPart;
    ExReleaseFastMutex(&stream->HeaderMutex);
    __try {
        if ((offset > current_file_size) ||
            ((LONGLONG)length > (current_file_size - offset))) {
            /* A size gate published after this write was planned; resolve against the new epoch. */
            status = STATUS_RETRY;
        }
        else {
            status = CcCopyWrite(file_object, &file_offset, length, TRUE, buffer)
                ? STATUS_SUCCESS
                : STATUS_CANT_WAIT;
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    ext4win_release_resource(&stream->MainResource);
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_CACHED_WRITE, status);
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_cache_mdl(
    _In_ PVOID stream_header,
    _Inout_ PFILE_OBJECT file_object,
    _Inout_ PIRP irp,
    _In_ ULONG action,
    _Out_ ULONG_PTR *information_out)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    PIO_STACK_LOCATION stack;
    LARGE_INTEGER offset;
    ULONG length;
    LONGLONG eof;
    NTSTATUS status;

    if (!ext4win_stream_matches_file_object(stream, file_object) ||
        (irp == NULL) || (information_out == NULL) || ((action != 0) && (action != 2))) {
        return STATUS_INVALID_PARAMETER;
    }
    *information_out = 0;
    stack = IoGetCurrentIrpStackLocation(irp);
    offset = stack->Parameters.Read.ByteOffset;
    length = stack->Parameters.Read.Length;
    if ((offset.QuadPart < 0) || (irp->MdlAddress != NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    status = ext4win_stream_cache_initialize(stream_header, file_object);
    if (!NT_SUCCESS(status) || (length == 0)) {
        return status;
    }
    status = ext4win_prepare_mdl_completion(stream->RustState, file_object);
    if (!NT_SUCCESS(status)) { return status; }
    (VOID)ext4win_stream_acquire_main_after_section_mutation(stream, FALSE);
    if (!ext4win_stream_ordinary_io_available(stream)) {
        ext4win_release_resource(&stream->MainResource);
        return ext4win_stream_storage_available(stream) ? STATUS_VOLUME_DISMOUNTED : STATUS_DEVICE_REMOVED;
    }
    ExAcquireFastMutex(&stream->HeaderMutex);
    eof = stream->Header.FileSize.QuadPart;
    ExReleaseFastMutex(&stream->HeaderMutex);
    status = ext4win_cache_mdl_transfer(file_object, irp, action, offset, length, eof, information_out);
    ext4win_release_resource(&stream->MainResource);
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_cache_flush(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;

    if (stream == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!ext4win_stream_storage_available(stream)) { return STATUS_DEVICE_REMOVED; }
    if (stream->SectionObjects.SharedCacheMap == NULL) {
        return STATUS_SUCCESS;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_CACHE_FLUSH);

    io_status.Status = STATUS_SUCCESS;
    io_status.Information = 0;
    status = STATUS_SUCCESS;
    (VOID)ext4win_stream_acquire_main_after_section_mutation(stream, FALSE);
    if (!ext4win_stream_storage_available(stream)) {
        ext4win_release_resource(&stream->MainResource);
        return STATUS_DEVICE_REMOVED;
    }
    __try {
        CcFlushCache(&stream->SectionObjects, NULL, 0, &io_status);
        status = io_status.Status;
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    ext4win_release_resource(&stream->MainResource);
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_CACHE_FLUSH, status);
    return status;
}

/* Native close flush preserves active FILE_OBJECT cache maps. A remaining mapped view or
 * pinned page prevents clean-close publication; cleanup may still release that residency. */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS NTAPI
ext4win_stream_cache_close_writeback(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS status = STATUS_SUCCESS;
    if (stream == NULL) { return STATUS_INVALID_PARAMETER; }
    if (!ext4win_stream_storage_available(stream)) { return STATUS_DEVICE_REMOVED; }
    (VOID)ext4win_stream_acquire_main_after_section_mutation(stream, TRUE);
    __try {
        if (!ext4win_stream_storage_available(stream)) { status = STATUS_DEVICE_REMOVED; }
        else {
            status = ext4win_cache_close_writeback(&stream->SectionObjects);
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) { status = GetExceptionCode(); }
    ext4win_release_resource(&stream->MainResource);
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_cache_coherency_flush_and_purge(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    BOOLEAN waited;

    if (stream == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    io_status.Status = STATUS_SUCCESS;
    io_status.Information = 0;
    status = STATUS_SUCCESS;
    waited = ext4win_stream_acquire_main_after_section_mutation(stream, TRUE);
    if (!ext4win_stream_storage_available(stream)) {
        ext4win_release_resource(&stream->MainResource);
        return STATUS_DEVICE_REMOVED;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_CACHE_COHERENCY);
    __try {
        if ((stream->SectionObjects.DataSectionObject != NULL) ||
            (stream->SectionObjects.SharedCacheMap != NULL)) {
            CcCoherencyFlushAndPurgeCache(
                &stream->SectionObjects,
                NULL,
                0,
                &io_status,
                0);
            status = io_status.Status;
            /* This informational Cc status means invalidation failed, not coherent success. */
            if (status == STATUS_CACHE_PAGE_LOCKED) {
                status = STATUS_USER_MAPPED_FILE;
            }
        }
        if (NT_SUCCESS(status) && waited) {
            status = STATUS_RETRY;
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    ext4win_release_resource(&stream->MainResource);
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_CACHE_COHERENCY, status);
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_begin_size_change(
    _In_ PVOID stream_header,
    _In_ LONGLONG new_file_size)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    IO_STATUS_BLOCK io_status;
    LARGE_INTEGER file_size;
    LONGLONG current_file_size;
    NTSTATUS status;

    if ((stream == NULL) || (new_file_size < 0)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!ext4win_stream_storage_available(stream)) { return STATUS_DEVICE_REMOVED; }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_MAPPED_SECTION);
    ext4win_section_mutation_begin(&stream->SectionMutation);

    file_size.QuadPart = new_file_size;
    io_status.Status = STATUS_SUCCESS;
    io_status.Information = 0;
    status = STATUS_SUCCESS;
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    ExAcquireFastMutex(&stream->HeaderMutex);
    current_file_size = stream->Header.FileSize.QuadPart;
    ExReleaseFastMutex(&stream->HeaderMutex);
    __try {
        if (!ext4win_stream_storage_available(stream)) {
            status = STATUS_DEVICE_REMOVED;
        }
        else if ((new_file_size < current_file_size) &&
            !MmCanFileBeTruncated(&stream->SectionObjects, &file_size)) {
            status = STATUS_USER_MAPPED_FILE;
        }
        else if ((stream->SectionObjects.DataSectionObject != NULL) ||
                 (stream->SectionObjects.SharedCacheMap != NULL)) {
            CcCoherencyFlushAndPurgeCache(
                &stream->SectionObjects,
                NULL,
                0,
                &io_status,
                0);
            status = io_status.Status;
            if (status == STATUS_CACHE_PAGE_LOCKED) {
                status = STATUS_USER_MAPPED_FILE;
            }
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    ext4win_release_resource(&stream->MainResource);

    if (NT_SUCCESS(status)) {
        status = ext4win_stream_seal_section_mutation(stream);
    }

    if (!NT_SUCCESS(status)) {
        ext4win_section_mutation_release(&stream->SectionMutation);
    }
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_MAPPED_SECTION, status);
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_begin_delete(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;

    if (stream == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!ext4win_stream_storage_available(stream)) { return STATUS_DEVICE_REMOVED; }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_MAPPED_SECTION);
    ext4win_section_mutation_begin(&stream->SectionMutation);

    io_status.Status = STATUS_SUCCESS;
    io_status.Information = 0;
    status = STATUS_SUCCESS;
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    __try {
        if (!ext4win_stream_storage_available(stream)) {
            status = STATUS_DEVICE_REMOVED;
        }
        else if (!MmFlushImageSection(&stream->SectionObjects, MmFlushForDelete)) {
            status = STATUS_CANNOT_DELETE;
        }
        else if ((stream->SectionObjects.DataSectionObject != NULL) ||
                 (stream->SectionObjects.SharedCacheMap != NULL)) {
            CcCoherencyFlushAndPurgeCache(
                &stream->SectionObjects,
                NULL,
                0,
                &io_status,
                0);
            status = io_status.Status;
            if (status == STATUS_CACHE_PAGE_LOCKED) {
                status = STATUS_CANNOT_DELETE;
            }
        }
        if (NT_SUCCESS(status) &&
            ((stream->SectionObjects.DataSectionObject != NULL) ||
             (stream->SectionObjects.ImageSectionObject != NULL))) {
            status = STATUS_CANNOT_DELETE;
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    ext4win_release_resource(&stream->MainResource);

    if (NT_SUCCESS(status)) {
        status = ext4win_stream_seal_section_mutation(stream);
    }
    if (!NT_SUCCESS(status)) {
        ext4win_section_mutation_release(&stream->SectionMutation);
    }
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_MAPPED_SECTION, status);
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_begin_write_open(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS status;

    if (stream == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!ext4win_stream_storage_available(stream)) { return STATUS_DEVICE_REMOVED; }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_MAPPED_SECTION);
    ext4win_section_mutation_begin(&stream->SectionMutation);

    status = STATUS_SUCCESS;
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    __try {
        if (!ext4win_stream_storage_available(stream)) {
            status = STATUS_DEVICE_REMOVED;
        }
        else if (!MmFlushImageSection(&stream->SectionObjects, MmFlushForWrite)) {
            status = STATUS_SHARING_VIOLATION;
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    ext4win_release_resource(&stream->MainResource);

    if (NT_SUCCESS(status)) {
        status = ext4win_stream_seal_section_mutation(stream);
    }
    if (!NT_SUCCESS(status)) {
        ext4win_section_mutation_release(&stream->SectionMutation);
    }
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_MAPPED_SECTION, status);
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_end_size_change(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);

    if (stream == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    return ext4win_stream_end_section_mutation(stream);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_end_delete(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);

    if (stream == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    return ext4win_stream_end_section_mutation(stream);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_end_write_open(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);

    if (stream == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    return ext4win_stream_end_section_mutation(stream);
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_cache_drain_for_volume_lock(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;

    if (stream == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if ((stream->SectionObjects.DataSectionObject == NULL) &&
        (stream->SectionObjects.SharedCacheMap == NULL) &&
        (stream->SectionObjects.ImageSectionObject == NULL)) {
        return STATUS_SUCCESS;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_CACHE_COHERENCY);

    io_status.Status = STATUS_SUCCESS;
    io_status.Information = 0;
    status = STATUS_SUCCESS;
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    __try {
        if (!MmFlushImageSection(&stream->SectionObjects, MmFlushForWrite)) {
            status = STATUS_USER_MAPPED_FILE;
        }
        else if ((stream->SectionObjects.DataSectionObject != NULL) ||
                 (stream->SectionObjects.SharedCacheMap != NULL)) {
            CcCoherencyFlushAndPurgeCache(
                &stream->SectionObjects,
                NULL,
                0,
                &io_status,
                0);
            status = io_status.Status;
            if (status == STATUS_CACHE_PAGE_LOCKED) {
                status = STATUS_USER_MAPPED_FILE;
            }
        }
        if (NT_SUCCESS(status) &&
            ((stream->SectionObjects.DataSectionObject != NULL) ||
             (stream->SectionObjects.SharedCacheMap != NULL) ||
             (stream->SectionObjects.ImageSectionObject != NULL))) {
            status = STATUS_USER_MAPPED_FILE;
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    ext4win_release_resource(&stream->MainResource);
    ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_CACHE_COHERENCY, status);
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_cache_uninitialize(
    _In_ PVOID stream_header,
    _Inout_ PFILE_OBJECT file_object)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS status;

    if (!ext4win_stream_matches_file_object(stream, file_object)) {
        return STATUS_INVALID_PARAMETER;
    }
    status = STATUS_SUCCESS;
    __try {
        (VOID)CcUninitializeCacheMap(file_object, NULL, NULL);
        file_object->Flags &= ~FO_CACHE_SUPPORTED;
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_has_native_residency(
    _In_ PVOID stream_header,
    _Out_ PBOOLEAN resident_out)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);

    if ((stream == NULL) || (resident_out == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_acquire_resource_shared(&stream->MainResource, TRUE);
    *resident_out = (stream->SectionObjects.DataSectionObject != NULL) ||
        (stream->SectionObjects.SharedCacheMap != NULL) ||
        (stream->SectionObjects.ImageSectionObject != NULL);
    ext4win_release_resource(&stream->MainResource);
    return STATUS_SUCCESS;
}

_Success_(return != FALSE)
static BOOLEAN
ext4win_acquire_fast_io_query_stream(
    _In_ PFILE_OBJECT file_object,
    _In_ BOOLEAN wait,
    _Outptr_ PEXT4WIN_STREAM_CONTEXT *stream_out)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    if (!ext4win_stream_fast_io_stream(file_object, &stream) || (stream->VolumeStream == NULL)) { return FALSE; }
    if (!ext4win_fast_io_query_admit(file_object->Flags, file_object->ReadAccess,
        stream->Header.IsFastIoPossible == FastIoIsPossible,
        ext4win_storage_media_state(stream->VolumeStream->RustState),
        (UCHAR)ext4win_section_mutation_state(&stream->SectionMutation))) { return FALSE; }
    if (wait) {
        (VOID)ext4win_acquire_resource_shared(&stream->MainResource, TRUE);
    }
    else if (!ext4win_acquire_resource_shared(&stream->MainResource, FALSE)) {
        return FALSE;
    }
    if (!ext4win_fast_io_query_admit(file_object->Flags, file_object->ReadAccess,
        stream->Header.IsFastIoPossible == FastIoIsPossible,
        ext4win_storage_media_state(stream->VolumeStream->RustState),
        (UCHAR)ext4win_section_mutation_state(&stream->SectionMutation))) {
        ext4win_release_resource(&stream->MainResource);
        return FALSE;
    }
    *stream_out = stream;
    return TRUE;
}

_Success_(return != FALSE)
static BOOLEAN
ext4win_capture_fast_io_query_snapshot(
    _In_ PEXT4WIN_STREAM_CONTEXT stream,
    _Out_ PEXT4WIN_FAST_IO_QUERY_SNAPSHOT snapshot)
{
    BOOLEAN valid;

    ExAcquireFastMutex(&stream->HeaderMutex);
    valid = stream->MetadataValid != FALSE;
    if (valid) {
        snapshot->Metadata = stream->PublishedMetadata;
        snapshot->AllocationSize.QuadPart = stream->AllocationCharge;
        snapshot->EndOfFile = stream->Header.FileSize;
        snapshot->DeletePending = (BOOLEAN)(InterlockedCompareExchange(
            &stream->DeletePending,
            FALSE,
            FALSE) != FALSE);
    }
    ExReleaseFastMutex(&stream->HeaderMutex);
    return valid;
}

/* Rust prepares a local record; the requestor copy is entirely contained by SEH. */
static BOOLEAN NTAPI ext4win_fast_io_query_basic_info(PFILE_OBJECT file, BOOLEAN wait,
    PFILE_BASIC_INFORMATION buffer, PIO_STATUS_BLOCK status, PDEVICE_OBJECT device)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    EXT4WIN_FAST_IO_QUERY_SNAPSHOT snapshot;
    FILE_BASIC_INFORMATION prepared;
    UNREFERENCED_PARAMETER(device);
    if ((buffer == NULL) || (status == NULL)) { return FALSE; }
    status->Status = STATUS_NOT_SUPPORTED;
    status->Information = 0;
    if (!ext4win_acquire_fast_io_query_stream(file, wait, &stream)) { return FALSE; }
    if (!ext4win_capture_fast_io_query_snapshot(stream, &snapshot)) {
        ext4win_release_resource(&stream->MainResource);
        return FALSE;
    }
    RtlZeroMemory(&prepared, sizeof(prepared));
    ext4win_fast_io_basic_record(&snapshot, &prepared);
    __try {
        *buffer = prepared;
        status->Status = STATUS_SUCCESS;
        status->Information = sizeof(prepared);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status->Status = GetExceptionCode();
        status->Information = 0;
    }
    ext4win_release_resource(&stream->MainResource);
    return TRUE;
}

/* Rust prepares a local record; the requestor copy is entirely contained by SEH. */
static BOOLEAN NTAPI ext4win_fast_io_query_standard_info(PFILE_OBJECT file, BOOLEAN wait,
    PFILE_STANDARD_INFORMATION buffer, PIO_STATUS_BLOCK status, PDEVICE_OBJECT device)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    EXT4WIN_FAST_IO_QUERY_SNAPSHOT snapshot;
    FILE_STANDARD_INFORMATION prepared;
    UNREFERENCED_PARAMETER(device);
    if ((buffer == NULL) || (status == NULL)) { return FALSE; }
    status->Status = STATUS_NOT_SUPPORTED;
    status->Information = 0;
    if (!ext4win_acquire_fast_io_query_stream(file, wait, &stream)) { return FALSE; }
    if (!ext4win_capture_fast_io_query_snapshot(stream, &snapshot)) {
        ext4win_release_resource(&stream->MainResource);
        return FALSE;
    }
    RtlZeroMemory(&prepared, sizeof(prepared));
    ext4win_fast_io_standard_record(&snapshot, &prepared);
    __try {
        *buffer = prepared;
        status->Status = STATUS_SUCCESS;
        status->Information = sizeof(prepared);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status->Status = GetExceptionCode();
        status->Information = 0;
    }
    ext4win_release_resource(&stream->MainResource);
    return TRUE;
}

/* Rust prepares a local record; the requestor copy is entirely contained by SEH. */
static BOOLEAN NTAPI ext4win_fast_io_query_network_open_info(PFILE_OBJECT file, BOOLEAN wait,
    PFILE_NETWORK_OPEN_INFORMATION buffer, PIO_STATUS_BLOCK status, PDEVICE_OBJECT device)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    EXT4WIN_FAST_IO_QUERY_SNAPSHOT snapshot;
    FILE_NETWORK_OPEN_INFORMATION prepared;
    UNREFERENCED_PARAMETER(device);
    if ((buffer == NULL) || (status == NULL)) { return FALSE; }
    status->Status = STATUS_NOT_SUPPORTED;
    status->Information = 0;
    if (!ext4win_acquire_fast_io_query_stream(file, wait, &stream)) { return FALSE; }
    if (!ext4win_capture_fast_io_query_snapshot(stream, &snapshot)) {
        ext4win_release_resource(&stream->MainResource);
        return FALSE;
    }
    RtlZeroMemory(&prepared, sizeof(prepared));
    ext4win_fast_io_network_record(&snapshot, &prepared);
    __try {
        *buffer = prepared;
        status->Status = STATUS_SUCCESS;
        status->Information = sizeof(prepared);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status->Status = GetExceptionCode();
        status->Information = 0;
    }
    ext4win_release_resource(&stream->MainResource);
    return TRUE;
}

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

    if ((buffer == NULL) || !ext4win_fast_io_check_if_possible(
            file_object,
            file_offset,
            length,
            wait,
            lock_key,
            TRUE,
            io_status,
            device_object) ||
        !ext4win_stream_fast_io_candidate(file_object, &stream)) {
        return FALSE;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_FAST_IO_READ);
    handled = FALSE;
    if (!ext4win_stream_acquire_fast_io_main(file_object, stream)) {
        ext4win_trace_fallback(stream, EXT4WIN_TRACE_EVENT_FAST_IO_READ);
        return FALSE;
    }
    __try {
        handled = CcCopyRead(file_object, file_offset, length, wait, buffer, io_status);
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

    if ((buffer == NULL) || ((file_object->Flags & FO_WRITE_THROUGH) != 0) ||
        !ext4win_fast_io_check_if_possible(
            file_object,
            file_offset,
            length,
            wait,
            lock_key,
            FALSE,
            io_status,
            device_object) ||
        !ext4win_stream_fast_io_candidate(file_object, &stream)) {
        return FALSE;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_FAST_IO_WRITE);
    handled = FALSE;
    if (!ext4win_stream_acquire_fast_io_main(file_object, stream)) {
        ext4win_trace_fallback(stream, EXT4WIN_TRACE_EVENT_FAST_IO_WRITE);
        return FALSE;
    }
    __try {
        handled = CcCopyWrite(file_object, file_offset, length, wait, buffer);
        if (handled) {
            io_status->Status = STATUS_SUCCESS;
            io_status->Information = length;
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
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
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
    ext4win_release_resource(&stream->MainResource);
    return handled;
}

_Success_(return != FALSE)
static BOOLEAN
NTAPI
ext4win_fast_io_unlock_single(
    _In_ PFILE_OBJECT file_object,
    _In_ PLARGE_INTEGER file_offset,
    _In_ PLARGE_INTEGER length,
    _In_ PEPROCESS process,
    _In_ ULONG key,
    _Out_ PIO_STATUS_BLOCK io_status,
    _In_ PDEVICE_OBJECT device_object)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    UNREFERENCED_PARAMETER(device_object);
    if ((io_status == NULL) || (file_offset == NULL) || (length == NULL) ||
        (process == NULL) || !ext4win_stream_fast_io_stream(file_object, &stream)) {
        return FALSE;
    }
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    io_status->Status = FsRtlFastUnlockSingle(
        stream->ByteRangeLocks,
        file_object,
        file_offset,
        length,
        process,
        key,
        NULL,
        TRUE);
    io_status->Information = 0;
    ext4win_stream_refresh_fast_io_projection(stream);
    ext4win_release_resource(&stream->MainResource);
    return TRUE;
}

_Success_(return != FALSE)
static BOOLEAN
NTAPI
ext4win_fast_io_unlock_all(
    _In_ PFILE_OBJECT file_object,
    _In_ PEPROCESS process,
    _Out_ PIO_STATUS_BLOCK io_status,
    _In_ PDEVICE_OBJECT device_object)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    UNREFERENCED_PARAMETER(device_object);
    if ((io_status == NULL) || (process == NULL) ||
        !ext4win_stream_fast_io_stream(file_object, &stream)) {
        return FALSE;
    }
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    io_status->Status = FsRtlFastUnlockAll(
        stream->ByteRangeLocks,
        file_object,
        process,
        NULL);
    io_status->Information = 0;
    ext4win_stream_refresh_fast_io_projection(stream);
    ext4win_release_resource(&stream->MainResource);
    return TRUE;
}

_Success_(return != FALSE)
static BOOLEAN
NTAPI
ext4win_fast_io_unlock_all_by_key(
    _In_ PFILE_OBJECT file_object,
    _In_ PVOID process,
    _In_ ULONG key,
    _Out_ PIO_STATUS_BLOCK io_status,
    _In_ PDEVICE_OBJECT device_object)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    UNREFERENCED_PARAMETER(device_object);
    if ((io_status == NULL) || (process == NULL) ||
        !ext4win_stream_fast_io_stream(file_object, &stream)) {
        return FALSE;
    }
    ext4win_acquire_resource_exclusive(&stream->MainResource, TRUE);
    io_status->Status = FsRtlFastUnlockAllByKey(
        stream->ByteRangeLocks,
        file_object,
        (PEPROCESS)process,
        key,
        NULL);
    io_status->Information = 0;
    ext4win_stream_refresh_fast_io_projection(stream);
    ext4win_release_resource(&stream->MainResource);
    return TRUE;
}

/* Section creation is a fallible authority boundary. SyncTypeOther is a resource-only
 * acquisition used by Cc/MM and must remain available while terminal writeback drains. */
static NTSTATUS NTAPI
ext4win_pre_acquire_section(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    *context = NULL;
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
ext4win_pre_release_section(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    *context = NULL;
    if (!ext4win_stream_section_callback_stream(data->FileObject, &stream)) {
        return STATUS_SUCCESS;
    }
    ext4win_release_resource(&stream->MainResource);
    return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
}

_Success_(return != FALSE)
static BOOLEAN
NTAPI
ext4win_mdl_read(
    _In_ PFILE_OBJECT file_object,
    _In_ PLARGE_INTEGER file_offset,
    _In_ ULONG length,
    _In_ ULONG lock_key,
    _Out_ PMDL *mdl_chain,
    _Out_ PIO_STATUS_BLOCK io_status,
    _In_ PDEVICE_OBJECT device_object)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    BOOLEAN handled;

    if ((mdl_chain == NULL) || !ext4win_fast_io_check_if_possible(
            file_object,
            file_offset,
            length,
            TRUE,
            lock_key,
            TRUE,
            io_status,
            device_object) ||
        !ext4win_stream_fast_io_candidate(file_object, &stream)) {
        return FALSE;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_READ);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return FALSE; }
    if (!NT_SUCCESS(ext4win_prepare_mdl_completion(stream->RustState, file_object))) { return FALSE; }
    *mdl_chain = NULL;
    handled = FALSE;
    if (!ext4win_stream_acquire_fast_io_main(file_object, stream)) {
        ext4win_trace_fallback(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_READ);
        return FALSE;
    }
    __try {
        CcMdlRead(file_object, file_offset, length, mdl_chain, io_status);
        handled = TRUE;
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        io_status->Status = GetExceptionCode();
        io_status->Information = 0;
    }
    if (!NT_SUCCESS(io_status->Status) && (*mdl_chain != NULL)) {
        CcMdlReadComplete(file_object, *mdl_chain);
        *mdl_chain = NULL;
        io_status->Information = 0;
    }
    ext4win_release_resource(&stream->MainResource);
    if (handled) {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_READ, io_status->Status);
    }
    else {
        ext4win_trace_fallback(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_READ);
    }
    return handled;
}

static BOOLEAN
NTAPI
ext4win_mdl_read_complete(
    _In_ PFILE_OBJECT file_object,
    _In_ PMDL mdl_chain,
    _In_ PDEVICE_OBJECT device_object)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    BOOLEAN handled;

    UNREFERENCED_PARAMETER(device_object);
    if ((KeGetCurrentIrql() != PASSIVE_LEVEL) || (mdl_chain == NULL) || !ext4win_stream_fast_io_stream(file_object, &stream)) {
        return FALSE;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_READ);
    handled = TRUE;
    __try {
        CcMdlReadComplete(file_object, mdl_chain);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        handled = FALSE;
    }
    if (handled) {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_READ, STATUS_SUCCESS);
    }
    else {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_READ, STATUS_UNSUCCESSFUL);
    }
    return handled;
}

_Success_(return != FALSE)
static BOOLEAN
NTAPI
ext4win_prepare_mdl_write(
    _In_ PFILE_OBJECT file_object,
    _In_ PLARGE_INTEGER file_offset,
    _In_ ULONG length,
    _In_ ULONG lock_key,
    _Out_ PMDL *mdl_chain,
    _Out_ PIO_STATUS_BLOCK io_status,
    _In_ PDEVICE_OBJECT device_object)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    BOOLEAN handled;

    if ((mdl_chain == NULL) || ((file_object->Flags & FO_WRITE_THROUGH) != 0) ||
        !ext4win_fast_io_check_if_possible(
            file_object,
            file_offset,
            length,
            TRUE,
            lock_key,
            FALSE,
            io_status,
            device_object) ||
        !ext4win_stream_fast_io_candidate(file_object, &stream)) {
        return FALSE;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_WRITE);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return FALSE; }
    if (!NT_SUCCESS(ext4win_prepare_mdl_completion(stream->RustState, file_object))) { return FALSE; }
    *mdl_chain = NULL;
    handled = FALSE;
    if (!ext4win_stream_acquire_fast_io_main(file_object, stream)) {
        ext4win_trace_fallback(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_WRITE);
        return FALSE;
    }
    __try {
        CcPrepareMdlWrite(file_object, file_offset, length, mdl_chain, io_status);
        handled = TRUE;
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        io_status->Status = GetExceptionCode();
        io_status->Information = 0;
    }
    if (!NT_SUCCESS(io_status->Status) && (*mdl_chain != NULL)) {
        CcMdlWriteAbort(file_object, *mdl_chain);
        *mdl_chain = NULL;
        io_status->Information = 0;
    }
    ext4win_release_resource(&stream->MainResource);
    if (handled) {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_WRITE, io_status->Status);
    }
    else {
        ext4win_trace_fallback(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_WRITE);
    }
    return handled;
}

static BOOLEAN
NTAPI
ext4win_mdl_write_complete(
    _In_ PFILE_OBJECT file_object,
    _In_ PLARGE_INTEGER file_offset,
    _In_ PMDL mdl_chain,
    _In_ PDEVICE_OBJECT device_object)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    BOOLEAN handled;

    UNREFERENCED_PARAMETER(device_object);
    if ((KeGetCurrentIrql() != PASSIVE_LEVEL) || (file_offset == NULL) || (mdl_chain == NULL) ||
        !ext4win_stream_fast_io_stream(file_object, &stream)) {
        return FALSE;
    }
    ext4win_trace_selected(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_WRITE);
    handled = TRUE;
    __try {
        CcMdlWriteComplete(file_object, file_offset, mdl_chain);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        handled = FALSE;
    }
    if (handled) {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_WRITE, STATUS_SUCCESS);
    }
    else {
        ext4win_trace_status(stream, EXT4WIN_TRACE_EVENT_FAST_IO_MDL_WRITE, STATUS_UNSUCCESSFUL);
    }
    return handled;
}

static NTSTATUS
NTAPI
ext4win_pre_acquire_mod_write(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    PFILE_OBJECT file_object = data->FileObject;
    PERESOURCE *resource_to_release = data->Parameters.AcquireForModifiedPageWriter.ResourceToRelease;
    *context = NULL;
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
ext4win_pre_release_mod_write(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    PFILE_OBJECT file_object = data->FileObject;
    PERESOURCE resource_to_release = data->Parameters.ReleaseForModifiedPageWriter.ResourceToRelease;
    *context = NULL;
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
ext4win_pre_acquire_cc_flush(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    PFILE_OBJECT file_object = data->FileObject;
    *context = NULL;
    if (!ext4win_stream_fast_io_stream(file_object, &stream)) {
        return STATUS_INVALID_PARAMETER;
    }
    ext4win_stream_acquire_main_after_sealed_section_mutation(stream);
    return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
}

static NTSTATUS
NTAPI
ext4win_pre_release_cc_flush(_In_ PFS_FILTER_CALLBACK_DATA data, _Out_ PVOID *context)
{
    PEXT4WIN_STREAM_CONTEXT stream;

    PFILE_OBJECT file_object = data->FileObject;
    *context = NULL;
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

static FAST_IO_DISPATCH ext4win_fast_io_dispatch_table = {
    sizeof(FAST_IO_DISPATCH),
    ext4win_fast_io_check_if_possible,
    ext4win_fast_io_read,
    ext4win_fast_io_write,
    ext4win_fast_io_query_basic_info,
    ext4win_fast_io_query_standard_info,
    ext4win_fast_io_lock,
    ext4win_fast_io_unlock_single,
    ext4win_fast_io_unlock_all,
    ext4win_fast_io_unlock_all_by_key,
    NULL,
    NULL,
    NULL,
    NULL,
    ext4win_fast_io_query_network_open_info,
    NULL,
    ext4win_mdl_read,
    ext4win_mdl_read_complete,
    ext4win_prepare_mdl_write,
    ext4win_mdl_write_complete,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

_IRQL_requires_max_(DISPATCH_LEVEL)
PFAST_IO_DISPATCH
NTAPI
ext4win_fast_io_dispatch(VOID)
{
    return &ext4win_fast_io_dispatch_table;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_destroy(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS paging_status;
    NTSTATUS main_status;
    NTSTATUS storage_status;
    if (stream == NULL) { return STATUS_INVALID_PARAMETER; }
    if ((stream->SectionObjects.DataSectionObject != NULL) ||
        (stream->SectionObjects.SharedCacheMap != NULL) ||
        (stream->SectionObjects.ImageSectionObject != NULL) ||
        (ext4win_section_mutation_state(&stream->SectionMutation) != EXT4WIN_SECTION_MUTATION_IDLE)) {
        return STATUS_DEVICE_BUSY;
    }

    stream->Signature = 0;
    stream->Owner = NULL;
    if (stream->OplockInitialized) {
        FsRtlUninitializeOplock(&stream->Header.Oplock);
        stream->OplockInitialized = FALSE;
    }
    if (stream->HeaderInitialized) {
        FsRtlTeardownPerStreamContexts(&stream->Header);
        stream->HeaderInitialized = FALSE;
    }
    if (stream->AePushLock != NULL) {
        FsRtlFreeAePushLock(stream->AePushLock);
        stream->AePushLock = NULL;
    }

    storage_status = STATUS_SUCCESS;
    if (stream->Kind == 2) {
        storage_status = ExDeleteResourceLite(&stream->Submissions);
    }
    paging_status = STATUS_SUCCESS;
    if (stream->PagingResourceInitialized) {
        paging_status = ExDeleteResourceLite(&stream->PagingIoResource);
        stream->PagingResourceInitialized = FALSE;
    }
    main_status = STATUS_SUCCESS;
    if (stream->MainResourceInitialized) {
        main_status = ExDeleteResourceLite(&stream->MainResource);
        stream->MainResourceInitialized = FALSE;
    }
    ExFreePoolWithTag(stream, EXT4WIN_STREAM_POOL_TAG);
    if (!NT_SUCCESS(paging_status)) {
        return paging_status;
    }
    return NT_SUCCESS(storage_status) ? main_status : storage_status;
}

/* Resource-only boundaries: Rust owns admission and checks it while the shared scope is held. */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN NTAPI ext4win_stream_acquire_submissions(_In_ PVOID header, _In_ BOOLEAN exclusive)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(header);
    if ((stream == NULL) || (stream->Kind != 2)) { return FALSE; }
    return exclusive ? ext4win_acquire_resource_exclusive(&stream->Submissions, TRUE)
        : ext4win_acquire_resource_shared(&stream->Submissions, FALSE);
}

_IRQL_requires_max_(APC_LEVEL)
VOID NTAPI ext4win_stream_release_submissions(_In_ PVOID header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(header);
    ext4win_release_resource(&stream->Submissions);
}

PVOID NTAPI ext4win_stream_mdl_queue(_In_ PFILE_OBJECT file)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    if (!ext4win_stream_fast_io_stream(file, &stream)) { return NULL; }
    return stream->RustState;
}

NTSTATUS NTAPI ext4win_complete_cache_mdl(_Inout_ PIRP irp, _In_ ULONG action)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG_PTR information;
    return ext4win_cache_mdl_transfer(stack->FileObject, irp, action,
        stack->Parameters.Read.ByteOffset, 0, 0, &information);
}

/* Fixed observation only; Rust decides whether this callback may select Fast I/O. */
BOOLEAN NTAPI ext4win_fast_io_observe(PFILE_OBJECT file, EXT4WIN_FAST_IO_TRANSFER_OBSERVATION *output)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    PEXT4WIN_STREAM_CONTEXT volume;
    if (!ext4win_stream_fast_io_stream(file, &stream) || (output == NULL)) { return FALSE; }
    volume = stream->VolumeStream;
    if (volume == NULL) { return FALSE; }
    RtlZeroMemory(output, sizeof(*output));
    ExAcquireFastMutex(&stream->HeaderMutex);
    output->Eof = stream->Header.FileSize.QuadPart;
    ExReleaseFastMutex(&stream->HeaderMutex);
    output->Flags = file->Flags;
    output->Cached = file->PrivateCacheMap != NULL;
    output->Media = ext4win_storage_media_state(volume->RustState);
    output->Close = ext4win_storage_close_phase(volume->RustState);
    output->Mutation = (UCHAR)ext4win_section_mutation_state(&stream->SectionMutation);
    output->ReadAccess = file->ReadAccess;
    output->WriteAccess = file->WriteAccess;
    return TRUE;
}

BOOLEAN NTAPI ext4win_fast_io_check_locks(PFILE_OBJECT file, LONGLONG offset, LONGLONG length, ULONG key, BOOLEAN read)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    LARGE_INTEGER file_offset, native_length;
    if (!ext4win_stream_fast_io_stream(file, &stream)) { return FALSE; }
    file_offset.QuadPart = offset;
    native_length.QuadPart = length;
    if (!FsRtlOplockIsFastIoPossible(&stream->Header.Oplock)) { return FALSE; }
    return read ? FsRtlFastCheckLockForRead(stream->ByteRangeLocks, &file_offset,
        &native_length, key, file, PsGetCurrentProcess())
        : FsRtlFastCheckLockForWrite(stream->ByteRangeLocks, &file_offset,
        &native_length, key, file, PsGetCurrentProcess());
}
