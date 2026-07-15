#include <ntifs.h>

/*
 * This translation unit is the only boundary that touches neither-I/O security
 * buffers supplied by an untrusted requestor. Rust receives only a locked
 * system mapping or an owned byte snapshot.
 */

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

static BOOLEAN
ext4win_is_self_relative_security_descriptor(
    _In_ PSECURITY_DESCRIPTOR security_descriptor)
{
    const PISECURITY_DESCRIPTOR_RELATIVE relative_descriptor =
        (PISECURITY_DESCRIPTOR_RELATIVE)security_descriptor;

    return (relative_descriptor->Control & SE_SELF_RELATIVE) != 0;
}

_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_lock_query_security_output(
    _In_reads_bytes_opt_(length) PVOID user_buffer,
    _In_ ULONG length,
    _In_ KPROCESSOR_MODE requestor_mode,
    _Outptr_result_maybenull_ PMDL *locked_mdl_out,
    _Outptr_result_bytebuffer_maybenull_(length) PVOID *system_address_out)
{
    PMDL mdl;
    PVOID system_address;
    NTSTATUS status;

    if (locked_mdl_out != NULL) {
        *locked_mdl_out = NULL;
    }
    if (system_address_out != NULL) {
        *system_address_out = NULL;
    }

    if ((locked_mdl_out == NULL) || (system_address_out == NULL) ||
        !ext4win_is_requestor_mode_valid(requestor_mode)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (length == 0) {
        return STATUS_SUCCESS;
    }
    if (user_buffer == NULL) {
        return STATUS_INVALID_USER_BUFFER;
    }

    mdl = IoAllocateMdl(user_buffer, length, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = STATUS_SUCCESS;
    __try {
        MmProbeAndLockPages(mdl, requestor_mode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = ext4win_normalize_user_buffer_exception(GetExceptionCode());
    }

    if (!NT_SUCCESS(status)) {
        IoFreeMdl(mdl);
        return status;
    }

    system_address = MmGetSystemAddressForMdlSafe(
        mdl,
        (MM_PAGE_PRIORITY)(NormalPagePriority | MdlMappingNoExecute));
    if (system_address == NULL) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *locked_mdl_out = mdl;
    *system_address_out = system_address;
    return STATUS_SUCCESS;
}

VOID
NTAPI
ext4win_unlock_query_security_output(_Frees_ptr_opt_ PMDL locked_mdl)
{
    if (locked_mdl != NULL) {
        MmUnlockPages(locked_mdl);
        IoFreeMdl(locked_mdl);
    }
}

_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_measure_set_security_descriptor(
    _In_ PSECURITY_DESCRIPTOR source,
    _In_ KPROCESSOR_MODE requestor_mode,
    _In_ ULONG maximum_length,
    _Out_ PULONG length_out)
{
    ULONG measured_length;
    NTSTATUS status;

    if (length_out != NULL) {
        *length_out = 0;
    }

    if ((length_out == NULL) ||
        !ext4win_is_requestor_mode_valid(requestor_mode) ||
        (maximum_length < sizeof(SECURITY_DESCRIPTOR_RELATIVE))) {
        return STATUS_INVALID_PARAMETER;
    }
    if (source == NULL) {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    measured_length = 0;
    status = STATUS_SUCCESS;
    __try {
        if (requestor_mode == UserMode) {
            ProbeForRead(
                source,
                sizeof(SECURITY_DESCRIPTOR_RELATIVE),
                TYPE_ALIGNMENT(UCHAR));
        }

        if (!ext4win_is_self_relative_security_descriptor(source)) {
            status = STATUS_INVALID_SECURITY_DESCR;
        } else {
            measured_length = RtlLengthSecurityDescriptor(source);
            if (measured_length < sizeof(SECURITY_DESCRIPTOR_RELATIVE)) {
                status = STATUS_INVALID_SECURITY_DESCR;
            } else if (measured_length > maximum_length) {
                status = STATUS_BUFFER_OVERFLOW;
            } else {
                if (requestor_mode == UserMode) {
                    ProbeForRead(source, measured_length, TYPE_ALIGNMENT(UCHAR));
                }

                if (!RtlValidRelativeSecurityDescriptor(
                        source,
                        measured_length,
                        0)) {
                    status = STATUS_INVALID_SECURITY_DESCR;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = ext4win_normalize_user_buffer_exception(GetExceptionCode());
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }

    *length_out = measured_length;
    return STATUS_SUCCESS;
}

_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_copy_set_security_descriptor(
    _In_ PSECURITY_DESCRIPTOR source,
    _In_ KPROCESSOR_MODE requestor_mode,
    _In_ ULONG maximum_length,
    _In_ ULONG expected_length,
    _Out_writes_bytes_(destination_capacity) PVOID destination,
    _In_ ULONG destination_capacity,
    _Out_ PULONG bytes_copied_out)
{
    ULONG measured_length;
    NTSTATUS status;

    if (bytes_copied_out != NULL) {
        *bytes_copied_out = 0;
    }

    if ((bytes_copied_out == NULL) ||
        !ext4win_is_requestor_mode_valid(requestor_mode) ||
        (maximum_length < sizeof(SECURITY_DESCRIPTOR_RELATIVE)) ||
        (expected_length < sizeof(SECURITY_DESCRIPTOR_RELATIVE)) ||
        (expected_length > maximum_length)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (destination_capacity < expected_length) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (source == NULL) {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    if (destination == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    measured_length = 0;
    status = STATUS_SUCCESS;
    __try {
        if (requestor_mode == UserMode) {
            ProbeForRead(
                source,
                sizeof(SECURITY_DESCRIPTOR_RELATIVE),
                TYPE_ALIGNMENT(UCHAR));
        }

        if (!ext4win_is_self_relative_security_descriptor(source)) {
            status = STATUS_INVALID_SECURITY_DESCR;
        } else {
            measured_length = RtlLengthSecurityDescriptor(source);
            if (measured_length > maximum_length) {
                status = STATUS_BUFFER_OVERFLOW;
            } else if (measured_length != expected_length) {
                status = STATUS_INVALID_SECURITY_DESCR;
            } else {
                if (requestor_mode == UserMode) {
                    ProbeForRead(source, measured_length, TYPE_ALIGNMENT(UCHAR));
                }

                /* Revalidate after probing and immediately before the bounded copy. */
                measured_length = RtlLengthSecurityDescriptor(source);
                if ((measured_length > maximum_length) ||
                    (measured_length > destination_capacity)) {
                    status = STATUS_BUFFER_OVERFLOW;
                } else if (measured_length != expected_length) {
                    status = STATUS_INVALID_SECURITY_DESCR;
                } else {
                    RtlCopyMemory(destination, source, expected_length);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = ext4win_normalize_user_buffer_exception(GetExceptionCode());
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }

    *bytes_copied_out = expected_length;
    return STATUS_SUCCESS;
}
