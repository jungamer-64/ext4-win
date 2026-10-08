#ifndef EXT4WIN_IDENTITY_PERSISTENCE_H
#define EXT4WIN_IDENTITY_PERSISTENCE_H

/* phase: 0 = no effect accepted, 3 = persistence uncertain, 1 = durable. */
NTSTATUS ext4win_identity_save(HANDLE root, const WCHAR *uuid,
    const UCHAR *record, ULONG length, PULONG phase)
{
    HANDLE key = NULL;
    UNICODE_STRING name = {72, 72, (PWCHAR)uuid};
    UNICODE_STRING value;
    NTSTATUS status;
    PAGED_CODE();
    *phase = 0;
    status = identity_key(root, &name, KEY_SET_VALUE | KEY_QUERY_VALUE, TRUE, &key);
    if (!NT_SUCCESS(status)) { return status; }
    RtlInitUnicodeString(&value, L"Table");
    *phase = 3;
    status = ZwSetValueKey(key, &value, 0, REG_BINARY, (PVOID)record, length);
    if (NT_SUCCESS(status)) { status = ZwFlushKey(key); }
    if (NT_SUCCESS(status)) { *phase = 1; }
    ZwClose(key);
    return status;
}

#endif
