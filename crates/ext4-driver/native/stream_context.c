#include <ntifs.h>

#define EXT4WIN_STREAM_POOL_TAG ((ULONG)0x53743445UL)
#define EXT4WIN_STREAM_SIGNATURE ((ULONG)0x53463445UL)

typedef struct _EXT4WIN_STREAM_CONTEXT {
    FSRTL_ADVANCED_FCB_HEADER Header;
    FAST_MUTEX HeaderMutex;
    ERESOURCE MainResource;
    ERESOURCE PagingIoResource;
    SECTION_OBJECT_POINTERS SectionObjects;
    PVOID FileContextSupport;
    PVOID Owner;
    PVOID AePushLock;
    ULONG Signature;
    ULONG Kind;
    BOOLEAN MainResourceInitialized;
    BOOLEAN PagingResourceInitialized;
    BOOLEAN HeaderInitialized;
    BOOLEAN OplockInitialized;
} EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;

C_ASSERT(FIELD_OFFSET(EXT4WIN_STREAM_CONTEXT, Header) == 0);
C_ASSERT(sizeof(EXT4WIN_STREAM_CONTEXT) <= MAXSHORT);

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

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_stream_create(
    _In_ ULONG kind,
    _In_ LONGLONG allocation_size,
    _In_ LONGLONG file_size,
    _In_ LONGLONG valid_data_length,
    _Outptr_ PVOID *stream_header_out)
{
    PEXT4WIN_STREAM_CONTEXT stream;
    NTSTATUS status;

    if (stream_header_out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *stream_header_out = NULL;
    if ((kind == 0) || (allocation_size < 0) || (file_size < 0) ||
        (valid_data_length < 0) || (valid_data_length > file_size) ||
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

    stream->AePushLock = FsRtlAllocateAePushLock(NonPagedPoolNx, EXT4WIN_STREAM_POOL_TAG);
    if (stream->AePushLock == NULL) {
        (VOID)ExDeleteResourceLite(&stream->PagingIoResource);
        (VOID)ExDeleteResourceLite(&stream->MainResource);
        ExFreePoolWithTag(stream, EXT4WIN_STREAM_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeFastMutex(&stream->HeaderMutex);
    stream->Header.Resource = &stream->MainResource;
    stream->Header.PagingIoResource = &stream->PagingIoResource;
    stream->Header.AllocationSize.QuadPart = allocation_size;
    stream->Header.FileSize.QuadPart = file_size;
    stream->Header.ValidDataLength.QuadPart = valid_data_length;
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
ext4win_stream_bind_owner(
    _In_ PVOID stream_header,
    _In_ ULONG expected_kind,
    _In_ PVOID owner)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);

    if ((stream == NULL) || (owner == NULL) ||
        (stream->Kind != expected_kind) || (stream->Owner != NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    stream->Owner = owner;
    return STATUS_SUCCESS;
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
ext4win_stream_destroy(_In_ PVOID stream_header)
{
    PEXT4WIN_STREAM_CONTEXT stream = ext4win_stream_from_header(stream_header);
    NTSTATUS paging_status;
    NTSTATUS main_status;

    if (stream == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((stream->SectionObjects.DataSectionObject != NULL) ||
        (stream->SectionObjects.SharedCacheMap != NULL) ||
        (stream->SectionObjects.ImageSectionObject != NULL)) {
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
    return main_status;
}
