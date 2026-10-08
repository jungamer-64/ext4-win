#include <ntifs.h>

/* Each handle is kernel-only. Callers own the root through worker rundown. */
static NTSTATUS
identity_key(HANDLE parent, PUNICODE_STRING name, ACCESS_MASK access,
             BOOLEAN create, PHANDLE output)
{
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parent, NULL);
    if (create) {
        return ZwCreateKey(output, access, &attributes, 0, NULL,
                           REG_OPTION_NON_VOLATILE, NULL);
    }
    return ZwOpenKey(output, access, &attributes);
}

NTSTATUS ext4win_identity_open_root(PCUNICODE_STRING service, PHANDLE output)
{
    HANDLE service_key = NULL, parameters = NULL;
    UNICODE_STRING name;
    NTSTATUS status;
    PAGED_CODE();
    *output = NULL;
    if (service == NULL || service->Buffer == NULL ||
        service->Length == 0 || (service->Length & 1) != 0 ||
        service->Length > service->MaximumLength) {
        return STATUS_INVALID_PARAMETER;
    }
    name = *service;
    status = identity_key(NULL, &name, KEY_CREATE_SUB_KEY, FALSE, &service_key);
    if (!NT_SUCCESS(status)) { return status; }
    RtlInitUnicodeString(&name, L"Parameters");
    status = identity_key(service_key, &name, KEY_CREATE_SUB_KEY, TRUE, &parameters);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&name, L"IdentityMappings");
        status = identity_key(parameters, &name,
            KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS, TRUE, output);
        ZwClose(parameters);
    }
    ZwClose(service_key);
    return status;
}

NTSTATUS ext4win_identity_enumerate(HANDLE root, ULONG index, PWCHAR uuid)
{
    union {
        ULONGLONG alignment;
        UCHAR bytes[FIELD_OFFSET(KEY_BASIC_INFORMATION, Name) + 72];
    } storage;
    PKEY_BASIC_INFORMATION information = (PKEY_BASIC_INFORMATION)storage.bytes;
    ULONG length;
    NTSTATUS status;
    PAGED_CODE();
    status = ZwEnumerateKey(root, index, KeyBasicInformation, &storage,
                            sizeof(storage), &length);
    if (!NT_SUCCESS(status)) { return status; }
    if (information->NameLength != 72) { return STATUS_DATA_ERROR; }
    RtlCopyMemory(uuid, information->Name, 72);
    return STATUS_SUCCESS;
}

/* Output storage is pool-aligned and includes the native information header. */
NTSTATUS ext4win_identity_read(HANDLE root, const WCHAR *uuid,
    PVOID buffer, ULONG capacity, PULONG length)
{
    const ULONG header_length = (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);
    HANDLE key = NULL;
    UNICODE_STRING name = {72, 72, (PWCHAR)uuid};
    UNICODE_STRING value;
    PKEY_VALUE_PARTIAL_INFORMATION information = buffer;
    ULONG required;
    NTSTATUS status;
    PAGED_CODE();
    *length = 0;
    if (capacity < header_length) { return STATUS_INVALID_BUFFER_SIZE; }
    status = identity_key(root, &name, KEY_QUERY_VALUE, FALSE, &key);
    if (!NT_SUCCESS(status)) { return status; }
    RtlInitUnicodeString(&value, L"Table");
    status = ZwQueryValueKey(key, &value, KeyValuePartialInformation,
                             buffer, capacity, &required);
    if (NT_SUCCESS(status)) {
        if (information->Type != REG_BINARY ||
            information->DataLength > capacity - header_length) {
            status = STATUS_DATA_ERROR;
        } else {
            *length = information->DataLength;
            RtlMoveMemory(buffer, information->Data, *length);
        }
    }
    ZwClose(key);
    return status;
}

#include "identity_persistence.h"

/* Successful reconciliation establishes durability for the observed whole record. */
NTSTATUS ext4win_identity_flush(HANDLE root, const WCHAR *uuid)
{
    HANDLE key = NULL;
    UNICODE_STRING name = {72, 72, (PWCHAR)uuid};
    NTSTATUS status;
    PAGED_CODE();
    status = identity_key(root, &name, KEY_QUERY_VALUE, FALSE, &key);
    if (NT_SUCCESS(status)) {
        status = ZwFlushKey(key);
        ZwClose(key);
    }
    return status;
}

void ext4win_identity_close(HANDLE root)
{
    PAGED_CODE();
    ZwClose(root);
}
