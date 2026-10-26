#pragma once

/* This cache is advisory. FsRtl owns expiry and allocation policy; durable names and times
 * remain in the journaled ext4 transaction. No plaintext encrypted-directory name enters it. */
_IRQL_requires_(PASSIVE_LEVEL)
PVOID ext4win_tunnel_create(VOID)
{
    PTUNNEL cache = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TUNNEL), 'nT4E');
    if (cache != NULL) { FsRtlInitializeTunnelCache(cache); }
    return cache;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID ext4win_tunnel_destroy(_In_ PVOID opaque)
{
    FsRtlDeleteTunnelCache((PTUNNEL)opaque);
    ExFreePoolWithTag(opaque, 'nT4E');
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID ext4win_tunnel_delete_directory(_In_ PVOID opaque, _In_ ULONGLONG directory)
{
    FsRtlDeleteKeyFromTunnelCache((PTUNNEL)opaque, directory);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID ext4win_tunnel_add(
    _In_ PVOID opaque, _In_ ULONGLONG directory,
    _In_reads_bytes_(name_length) const WCHAR *name, _In_ USHORT name_length,
    _In_reads_bytes_(short_length) const WCHAR *short_name, _In_ USHORT short_length,
    _In_ LONGLONG creation_time)
{
    UNICODE_STRING long_string = { name_length, name_length, (PWCH)name };
    UNICODE_STRING short_string = { short_length, short_length, (PWCH)short_name };
    __try {
        FsRtlAddToTunnelCache((PTUNNEL)opaque, directory, &short_string, &long_string,
            FALSE, sizeof(creation_time), &creation_time);
    }
    __except (FsRtlIsNtstatusExpected(GetExceptionCode())
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        /* Cache loss cannot reverse a committed namespace operation. */
        return;
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ext4win_tunnel_find(
    _In_ PVOID opaque, _In_ ULONGLONG directory,
    _In_reads_bytes_(name_length) const WCHAR *name, _In_ USHORT name_length,
    _Out_writes_(12) WCHAR *short_name, _Out_ USHORT *short_length,
    _Out_ LONGLONG *creation_time, _Out_ BOOLEAN *found)
{
    WCHAR long_buffer[256];
    UNICODE_STRING lookup = { name_length, name_length, (PWCH)name };
    UNICODE_STRING short_string = { 0, 12 * sizeof(WCHAR), short_name };
    UNICODE_STRING long_string = { 0, sizeof(long_buffer), long_buffer };
    ULONG data_length = sizeof(*creation_time);
    NTSTATUS status = STATUS_SUCCESS;
    *found = FALSE;
    *short_length = 0;
    *creation_time = 0;
    RtlZeroMemory(short_name, 12 * sizeof(WCHAR));
    RtlZeroMemory(long_buffer, sizeof(long_buffer));
    __try {
        *found = FsRtlFindInTunnelCache((PTUNNEL)opaque, directory, &lookup,
            &short_string, &long_string, &data_length, creation_time);
        if (*found && (short_string.Length > 12 * sizeof(WCHAR)
            || data_length != sizeof(*creation_time))) {
            status = STATUS_FILE_CORRUPT_ERROR;
            *found = FALSE;
        } else { *short_length = short_string.Length; }
    }
    __except (FsRtlIsNtstatusExpected(GetExceptionCode())
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        status = GetExceptionCode();
    }
    if (long_string.Buffer != NULL && long_string.Buffer != long_buffer) { ExFreePool(long_string.Buffer); }
    return status;
}
