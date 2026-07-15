#include <ntifs.h>

#define EXT4WIN_SECURITY_POOL_TAG ((ULONG)0x53773445UL)

/*
 * This translation unit is the only boundary that touches neither-I/O security
 * buffers supplied by an untrusted requestor. Rust receives only an opaque
 * output target or an owned, validated byte snapshot; requestor mappings never
 * enter Rust's aliasing model.
 */

typedef struct _EXT4WIN_SID_PREFIX {
    UCHAR Revision;
    UCHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
} EXT4WIN_SID_PREFIX;

typedef struct _EXT4WIN_QUERY_SECURITY_OUTPUT {
    PMDL Mdl;
    PVOID SystemAddress;
    ULONG Length;
} EXT4WIN_QUERY_SECURITY_OUTPUT, *PEXT4WIN_QUERY_SECURITY_OUTPUT;

C_ASSERT(sizeof(SECURITY_DESCRIPTOR_RELATIVE) == 20);
C_ASSERT(sizeof(EXT4WIN_SID_PREFIX) == 8);
C_ASSERT(sizeof(ACL) == 8);

static BOOLEAN
ext4win_is_requestor_mode_valid(_In_ KPROCESSOR_MODE requestor_mode)
{
    return (requestor_mode == KernelMode) || (requestor_mode == UserMode);
}

static NTSTATUS
ext4win_normalize_user_buffer_exception(_In_ LONG exception_code)
{
    const NTSTATUS status = (NTSTATUS)exception_code;

    if ((status == STATUS_ACCESS_VIOLATION) ||
        (status == STATUS_DATATYPE_MISALIGNMENT) ||
        (status == STATUS_IN_PAGE_ERROR)) {
        return status;
    }

    return STATUS_INVALID_USER_BUFFER;
}

static NTSTATUS
ext4win_relative_range(
    _In_ PSECURITY_DESCRIPTOR security_descriptor,
    _In_ ULONG offset,
    _In_ ULONG length,
    _In_ ULONG maximum_length,
    _Outptr_result_bytebuffer_(length) PVOID *address_out,
    _Out_ PULONG end_out)
{
    const ULONG_PTR base = (ULONG_PTR)security_descriptor;
    ULONG_PTR address;

    if ((address_out == NULL) || (end_out == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }

    *address_out = NULL;
    *end_out = 0;

    if ((length > maximum_length) || (offset > (maximum_length - length))) {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    address = base + (ULONG_PTR)offset;
    if ((address < base) ||
        (address > (MAXULONG_PTR - (ULONG_PTR)length))) {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    *address_out = (PVOID)address;
    *end_out = offset + length;
    return STATUS_SUCCESS;
}

static VOID
ext4win_extend_measured_length(_Inout_ PULONG measured_length, _In_ ULONG end)
{
    if (end > *measured_length) {
        *measured_length = end;
    }
}

static NTSTATUS
ext4win_measure_relative_sid(
    _In_ PSECURITY_DESCRIPTOR security_descriptor,
    _In_ ULONG offset,
    _In_ KPROCESSOR_MODE requestor_mode,
    _In_ ULONG maximum_length,
    _Inout_ PULONG measured_length)
{
    const ULONG prefix_length = (ULONG)sizeof(EXT4WIN_SID_PREFIX);
    EXT4WIN_SID_PREFIX prefix;
    PVOID prefix_address;
    PVOID sid_address;
    ULONG prefix_end;
    ULONG sid_end;
    ULONG sid_length;
    NTSTATUS status;

    status = ext4win_relative_range(
        security_descriptor,
        offset,
        prefix_length,
        maximum_length,
        &prefix_address,
        &prefix_end);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (requestor_mode == UserMode) {
        ProbeForRead(prefix_address, prefix_length, TYPE_ALIGNMENT(UCHAR));
    }
    RtlCopyMemory(&prefix, prefix_address, prefix_length);
    ext4win_extend_measured_length(measured_length, prefix_end);

    sid_length = prefix_length +
        ((ULONG)prefix.SubAuthorityCount * (ULONG)sizeof(ULONG));
    status = ext4win_relative_range(
        security_descriptor,
        offset,
        sid_length,
        maximum_length,
        &sid_address,
        &sid_end);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ext4win_extend_measured_length(measured_length, sid_end);
    return STATUS_SUCCESS;
}

static NTSTATUS
ext4win_measure_relative_acl(
    _In_ PSECURITY_DESCRIPTOR security_descriptor,
    _In_ ULONG offset,
    _In_ KPROCESSOR_MODE requestor_mode,
    _In_ ULONG maximum_length,
    _Inout_ PULONG measured_length)
{
    const ULONG header_length = (ULONG)sizeof(ACL);
    ACL header;
    PVOID header_address;
    PVOID acl_address;
    ULONG header_end;
    ULONG acl_end;
    ULONG acl_length;
    NTSTATUS status;

    status = ext4win_relative_range(
        security_descriptor,
        offset,
        header_length,
        maximum_length,
        &header_address,
        &header_end);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (requestor_mode == UserMode) {
        ProbeForRead(header_address, header_length, TYPE_ALIGNMENT(UCHAR));
    }
    RtlCopyMemory(&header, header_address, header_length);
    ext4win_extend_measured_length(measured_length, header_end);

    acl_length = (ULONG)header.AclSize;
    if (acl_length < header_length) {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    status = ext4win_relative_range(
        security_descriptor,
        offset,
        acl_length,
        maximum_length,
        &acl_address,
        &acl_end);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ext4win_extend_measured_length(measured_length, acl_end);
    return STATUS_SUCCESS;
}

static NTSTATUS
ext4win_measure_relative_security_descriptor(
    _In_ PSECURITY_DESCRIPTOR source,
    _In_ KPROCESSOR_MODE requestor_mode,
    _In_ ULONG maximum_length,
    _Out_ PULONG measured_length_out)
{
    const ULONG header_length = (ULONG)sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    SECURITY_DESCRIPTOR_RELATIVE header;
    ULONG measured_length;
    NTSTATUS status;

    if ((source == NULL) || (measured_length_out == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }

    *measured_length_out = 0;
    if (maximum_length < header_length) {
        return STATUS_BUFFER_OVERFLOW;
    }

    if (requestor_mode == UserMode) {
        ProbeForRead(source, header_length, TYPE_ALIGNMENT(UCHAR));
    }
    RtlCopyMemory(&header, source, header_length);

    if ((header.Control & SE_SELF_RELATIVE) == 0) {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    measured_length = header_length;

    if (header.Owner != 0) {
        status = ext4win_measure_relative_sid(
            source,
            header.Owner,
            requestor_mode,
            maximum_length,
            &measured_length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    if (header.Group != 0) {
        status = ext4win_measure_relative_sid(
            source,
            header.Group,
            requestor_mode,
            maximum_length,
            &measured_length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    if (header.Sacl != 0) {
        status = ext4win_measure_relative_acl(
            source,
            header.Sacl,
            requestor_mode,
            maximum_length,
            &measured_length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    if (header.Dacl != 0) {
        status = ext4win_measure_relative_acl(
            source,
            header.Dacl,
            requestor_mode,
            maximum_length,
            &measured_length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    *measured_length_out = measured_length;
    return STATUS_SUCCESS;
}

static VOID
ext4win_release_query_security_output_internal(
    _Frees_ptr_opt_ PEXT4WIN_QUERY_SECURITY_OUTPUT output)
{
    if (output == NULL) {
        return;
    }

    if (output->Mdl != NULL) {
        MmUnlockPages(output->Mdl);
        IoFreeMdl(output->Mdl);
    }
    RtlSecureZeroMemory(output, sizeof(*output));
    ExFreePoolWithTag(output, EXT4WIN_SECURITY_POOL_TAG);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_capture_query_security_output(
    _Outptr_ PVOID *output_out,
    _Out_ PULONG required_length_out,
    _In_reads_bytes_opt_(requestor_buffer_length) PVOID requestor_buffer,
    _In_ ULONG requestor_buffer_length,
    _In_ ULONG required_length,
    _In_ KPROCESSOR_MODE requestor_mode)
{
    PEXT4WIN_QUERY_SECURITY_OUTPUT output;
    PVOID system_address;
    NTSTATUS status;

    if (output_out != NULL) {
        *output_out = NULL;
    }
    if (required_length_out != NULL) {
        *required_length_out = required_length;
    }

    if ((output_out == NULL) || (required_length_out == NULL) ||
        !ext4win_is_requestor_mode_valid(requestor_mode) ||
        (required_length == 0)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (requestor_buffer_length < required_length) {
        return STATUS_BUFFER_OVERFLOW;
    }
    if (requestor_buffer == NULL) {
        return STATUS_INVALID_USER_BUFFER;
    }

    output = (PEXT4WIN_QUERY_SECURITY_OUTPUT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*output),
        EXT4WIN_SECURITY_POOL_TAG);
    if (output == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(output, sizeof(*output));

    output->Mdl = IoAllocateMdl(
        requestor_buffer,
        required_length,
        FALSE,
        FALSE,
        NULL);
    if (output->Mdl == NULL) {
        ext4win_release_query_security_output_internal(output);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = STATUS_SUCCESS;
    __try {
        MmProbeAndLockPages(output->Mdl, requestor_mode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = ext4win_normalize_user_buffer_exception(GetExceptionCode());
    }
    if (!NT_SUCCESS(status)) {
        IoFreeMdl(output->Mdl);
        output->Mdl = NULL;
        ext4win_release_query_security_output_internal(output);
        return status;
    }

    system_address = MmGetSystemAddressForMdlSafe(
        output->Mdl,
        (MM_PAGE_PRIORITY)(NormalPagePriority | MdlMappingNoExecute));
    if (system_address == NULL) {
        ext4win_release_query_security_output_internal(output);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    output->SystemAddress = system_address;
    output->Length = required_length;
    *output_out = output;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_copy_query_security_output(
    _In_ PVOID output_handle,
    _In_reads_bytes_(source_length) const VOID *owned_source,
    _In_ ULONG source_length)
{
    PEXT4WIN_QUERY_SECURITY_OUTPUT output;
    NTSTATUS status;

    if (output_handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    output = (PEXT4WIN_QUERY_SECURITY_OUTPUT)output_handle;
    if ((owned_source == NULL) || (source_length != output->Length) ||
        (output->Mdl == NULL) || (output->SystemAddress == NULL)) {
        status = STATUS_INVALID_PARAMETER;
    } else {
        RtlCopyMemory(output->SystemAddress, owned_source, source_length);
        status = STATUS_SUCCESS;
    }

    ext4win_release_query_security_output_internal(output);
    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NTAPI
ext4win_release_query_security_output(_Frees_ptr_opt_ PVOID output)
{
    ext4win_release_query_security_output_internal(
        (PEXT4WIN_QUERY_SECURITY_OUTPUT)output);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_capture_set_security_descriptor(
    _In_reads_bytes_(maximum_length) PSECURITY_DESCRIPTOR source,
    _In_ KPROCESSOR_MODE requestor_mode,
    _In_ SECURITY_INFORMATION required_information,
    _In_ ULONG maximum_length,
    _Outptr_result_bytebuffer_(*length_out) PVOID *snapshot_out,
    _Out_ PULONG length_out)
{
    const ULONG header_length = (ULONG)sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    const SECURITY_INFORMATION supported_information =
        OWNER_SECURITY_INFORMATION |
        GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION;
    PVOID snapshot;
    ULONG candidate_length;
    ULONG snapshot_length;
    NTSTATUS status;

    if (snapshot_out != NULL) {
        *snapshot_out = NULL;
    }
    if (length_out != NULL) {
        *length_out = 0;
    }

    if ((snapshot_out == NULL) || (length_out == NULL) ||
        !ext4win_is_requestor_mode_valid(requestor_mode) ||
        ((required_information & ~supported_information) != 0) ||
        (maximum_length < header_length)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (source == NULL) {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    candidate_length = 0;
    status = STATUS_SUCCESS;
    __try {
        status = ext4win_measure_relative_security_descriptor(
            source,
            requestor_mode,
            maximum_length,
            &candidate_length);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = ext4win_normalize_user_buffer_exception(GetExceptionCode());
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    snapshot = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        candidate_length,
        EXT4WIN_SECURITY_POOL_TAG);
    if (snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = STATUS_SUCCESS;
    __try {
        if (requestor_mode == UserMode) {
            ProbeForRead(source, candidate_length, TYPE_ALIGNMENT(UCHAR));
        }
        RtlCopyMemory(snapshot, source, candidate_length);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = ext4win_normalize_user_buffer_exception(GetExceptionCode());
    }
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(snapshot, candidate_length);
        ExFreePoolWithTag(snapshot, EXT4WIN_SECURITY_POOL_TAG);
        return status;
    }

    if (!RtlValidRelativeSecurityDescriptor(
            (PSECURITY_DESCRIPTOR)snapshot,
            candidate_length,
            required_information)) {
        RtlSecureZeroMemory(snapshot, candidate_length);
        ExFreePoolWithTag(snapshot, EXT4WIN_SECURITY_POOL_TAG);
        return STATUS_INVALID_SECURITY_DESCR;
    }

    snapshot_length = RtlLengthSecurityDescriptor(
        (PSECURITY_DESCRIPTOR)snapshot);
    if (snapshot_length != candidate_length) {
        RtlSecureZeroMemory(snapshot, candidate_length);
        ExFreePoolWithTag(snapshot, EXT4WIN_SECURITY_POOL_TAG);
        return STATUS_INVALID_SECURITY_DESCR;
    }

    *snapshot_out = snapshot;
    *length_out = snapshot_length;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NTAPI
ext4win_release_set_security_descriptor(_Frees_ptr_opt_ PVOID snapshot)
{
    if (snapshot != NULL) {
        ExFreePoolWithTag(snapshot, EXT4WIN_SECURITY_POOL_TAG);
    }
}
