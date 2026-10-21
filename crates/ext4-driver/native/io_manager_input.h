#pragma once

/* I/O Manager input allocations remain stable through the active IRP. Snapshot them
 * before queue publication without treating RequestorMode as their address-space origin.
 * Only selected descriptor components are measured and validated within the copy bound. */

#define EXT4WIN_DESCRIPTOR_POOL_TAG ((ULONG)0x53773445UL)

/* Input copies remain bounded independently of the initiating requestor mode. */
#define EXT4WIN_MAX_EA_NAME_LIST_SIZE (64UL * 1024UL)
#define EXT4WIN_MAX_DIRECTORY_PATTERN_SIZE (64UL * 1024UL - sizeof(WCHAR))
typedef struct _EXT4WIN_SID_PREFIX {
    UCHAR Revision;
    UCHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
} EXT4WIN_SID_PREFIX;

C_ASSERT(sizeof(SECURITY_DESCRIPTOR_RELATIVE) == 20);
C_ASSERT(sizeof(EXT4WIN_SID_PREFIX) == 8);
C_ASSERT(sizeof(ACL) == 8);

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
    _In_ ULONG maximum_length,
    _Inout_ PULONG measured_length)
{
    const ULONG prefix_length = (ULONG)sizeof(EXT4WIN_SID_PREFIX);
    EXT4WIN_SID_PREFIX prefix = {0};
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

    status = STATUS_SUCCESS;
    __try {
        RtlCopyVolatileMemory(&prefix, prefix_address, prefix_length);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = (NTSTATUS)GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
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
    _In_ ULONG maximum_length,
    _Inout_ PULONG measured_length)
{
    const ULONG header_length = (ULONG)sizeof(ACL);
    ACL header = {0};
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

    status = STATUS_SUCCESS;
    __try {
        RtlCopyVolatileMemory(&header, header_address, header_length);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = (NTSTATUS)GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
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
    _In_ SECURITY_INFORMATION required_information,
    _In_ ULONG maximum_length,
    _Out_ PULONG measured_length_out)
{
    const ULONG header_length = (ULONG)sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    SECURITY_DESCRIPTOR_RELATIVE header = {0};
    ULONG measured_length;
    NTSTATUS status;

    if ((source == NULL) || (measured_length_out == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }

    *measured_length_out = 0;
    if (maximum_length < header_length) {
        return STATUS_BUFFER_OVERFLOW;
    }

    status = STATUS_SUCCESS;
    __try {
        RtlCopyVolatileMemory(&header, source, header_length);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = (NTSTATUS)GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if ((header.Control & SE_SELF_RELATIVE) == 0) {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    measured_length = header_length;

    if (((required_information & OWNER_SECURITY_INFORMATION) != 0) &&
        (header.Owner != 0)) {
        status = ext4win_measure_relative_sid(
            source,
            header.Owner,
            maximum_length,
            &measured_length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    if (((required_information & GROUP_SECURITY_INFORMATION) != 0) &&
        (header.Group != 0)) {
        status = ext4win_measure_relative_sid(
            source,
            header.Group,
            maximum_length,
            &measured_length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    if (((required_information & DACL_SECURITY_INFORMATION) != 0) &&
        ((header.Control & SE_DACL_PRESENT) != 0) &&
        (header.Dacl != 0)) {
        status = ext4win_measure_relative_acl(
            source,
            header.Dacl,
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
ext4win_retain_selected_security_information(
    _Inout_ SECURITY_DESCRIPTOR_RELATIVE *descriptor,
    _In_ SECURITY_INFORMATION required_information)
{
    if ((required_information & OWNER_SECURITY_INFORMATION) == 0) {
        descriptor->Owner = 0;
        descriptor->Control &= ~SE_OWNER_DEFAULTED;
    }
    if ((required_information & GROUP_SECURITY_INFORMATION) == 0) {
        descriptor->Group = 0;
        descriptor->Control &= ~SE_GROUP_DEFAULTED;
    }

    descriptor->Sacl = 0;
    descriptor->Control &= ~(
        SE_SACL_PRESENT |
        SE_SACL_DEFAULTED |
        SE_SACL_AUTO_INHERIT_REQ |
        SE_SACL_AUTO_INHERITED |
        SE_SACL_PROTECTED);

    if ((required_information & DACL_SECURITY_INFORMATION) == 0) {
        descriptor->Dacl = 0;
        descriptor->Control &= ~(
            SE_DACL_PRESENT |
            SE_DACL_DEFAULTED |
            SE_DACL_AUTO_INHERIT_REQ |
            SE_DACL_AUTO_INHERITED |
            SE_DACL_PROTECTED);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_capture_io_manager_security_descriptor(
    _In_ PSECURITY_DESCRIPTOR source,
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
    NTSTATUS status;

    if (snapshot_out != NULL) {
        *snapshot_out = NULL;
    }
    if (length_out != NULL) {
        *length_out = 0;
    }

    if ((snapshot_out == NULL) || (length_out == NULL) ||
        (required_information == 0) ||
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
            required_information,
            maximum_length,
            &candidate_length);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = (NTSTATUS)GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if ((candidate_length < header_length) ||
        (candidate_length > maximum_length)) {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    snapshot = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        candidate_length,
        EXT4WIN_DESCRIPTOR_POOL_TAG);
    if (snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = STATUS_SUCCESS;
    __try {
        RtlCopyVolatileMemory(snapshot, source, candidate_length);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = (NTSTATUS)GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(snapshot, candidate_length);
        ExFreePoolWithTag(snapshot, EXT4WIN_DESCRIPTOR_POOL_TAG);
        return status;
    }

    ext4win_retain_selected_security_information(
        (SECURITY_DESCRIPTOR_RELATIVE *)snapshot,
        required_information);

    if (!RtlValidRelativeSecurityDescriptor(
            (PSECURITY_DESCRIPTOR)snapshot,
            candidate_length,
            required_information)) {
        RtlSecureZeroMemory(snapshot, candidate_length);
        ExFreePoolWithTag(snapshot, EXT4WIN_DESCRIPTOR_POOL_TAG);
        return STATUS_INVALID_SECURITY_DESCR;
    }

    /* Relative offsets retain gaps after unselected components are cleared. The validated
     * endpoint bound must include those gaps; summing component sizes can truncate live data. */
    *snapshot_out = snapshot;
    *length_out = candidate_length;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NTAPI
ext4win_release_set_security_descriptor(_Frees_ptr_opt_ PVOID snapshot)
{
    if (snapshot != NULL) {
        ExFreePoolWithTag(snapshot, EXT4WIN_DESCRIPTOR_POOL_TAG);
    }
}

#define EXT4WIN_AUXILIARY_INPUT_POOL_TAG ((ULONG)0x43573445UL)

/*
 * EA lists and directory patterns have already been captured by the I/O Manager.
 * Each public capture fixes its own limit before this private owned copy.
 */
static NTSTATUS
ext4win_capture_bounded_input(
    _In_reads_bytes_(length) const VOID *source,
    _In_ ULONG length,
    _In_ ULONG maximum_length,
    _Outptr_result_bytebuffer_maybenull_(*length_out) PVOID *snapshot_out,
    _Out_ PULONG length_out)
{
    PVOID snapshot;
    NTSTATUS status;

    if ((snapshot_out == NULL) || (length_out == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    *snapshot_out = NULL;
    *length_out = 0;
    if (length > maximum_length) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (length == 0) {
        return STATUS_SUCCESS;
    }
    if (source == NULL) {
        return STATUS_INVALID_USER_BUFFER;
    }

    snapshot = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        length,
        EXT4WIN_AUXILIARY_INPUT_POOL_TAG);
    if (snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = STATUS_SUCCESS;
    __try {
        RtlCopyVolatileMemory(snapshot, source, length);
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = (NTSTATUS)GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(snapshot, EXT4WIN_AUXILIARY_INPUT_POOL_TAG);
        return status;
    }

    *snapshot_out = snapshot;
    *length_out = length;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_capture_io_manager_ea_name_list(
    _In_reads_bytes_(length) const VOID *source,
    _In_ ULONG length,
    _Outptr_result_bytebuffer_maybenull_(*length_out) PVOID *snapshot_out,
    _Out_ PULONG length_out)
{
    return ext4win_capture_bounded_input(
        source,
        length,
        EXT4WIN_MAX_EA_NAME_LIST_SIZE,
        snapshot_out,
        length_out);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_capture_io_manager_directory_pattern(
    _In_ PCUNICODE_STRING source,
    _Outptr_result_bytebuffer_maybenull_(*length_out) PVOID *snapshot_out,
    _Out_ PULONG length_out)
{
    UNICODE_STRING header = {0};
    NTSTATUS status;

    if (snapshot_out != NULL) {
        *snapshot_out = NULL;
    }
    if (length_out != NULL) {
        *length_out = 0;
    }
    if ((snapshot_out == NULL) || (length_out == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (source == NULL) {
        return STATUS_INVALID_USER_BUFFER;
    }

    status = STATUS_SUCCESS;
    __try {
        /* NtQueryDirectoryFile has already captured this descriptor for the IRP. */
        RtlCopyVolatileMemory(&header, source, sizeof(header));
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = (NTSTATUS)GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if ((header.Length > header.MaximumLength) ||
        ((header.Length & (sizeof(WCHAR) - 1)) != 0) ||
        ((header.MaximumLength & (sizeof(WCHAR) - 1)) != 0) ||
        (header.Length > EXT4WIN_MAX_DIRECTORY_PATTERN_SIZE) ||
        ((header.Length != 0) && (header.Buffer == NULL))) {
        return STATUS_INVALID_PARAMETER;
    }

    /* The I/O manager owns both the descriptor and its captured payload. */
    return ext4win_capture_bounded_input(
        header.Buffer,
        header.Length,
        EXT4WIN_MAX_DIRECTORY_PATTERN_SIZE,
        snapshot_out,
        length_out);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NTAPI
ext4win_release_captured_auxiliary_input(_Frees_ptr_opt_ PVOID snapshot)
{
    if (snapshot != NULL) {
        ExFreePoolWithTag(snapshot, EXT4WIN_AUXILIARY_INPUT_POOL_TAG);
    }
}
