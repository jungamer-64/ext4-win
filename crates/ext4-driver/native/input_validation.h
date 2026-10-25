/* Callers retain immutable kernel-owned snapshots at PASSIVE_LEVEL. Native validators
 * own Windows layout admission; subsequent interpretation must use these same bytes. */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS NTAPI
ext4win_validate_full_ea(
    _In_reads_bytes_(length) const UCHAR *bytes,
    _In_ ULONG length,
    _Out_ ULONG *error_offset)
{
    *error_offset = 0;
    return IoCheckEaBufferValidity((PFILE_FULL_EA_INFORMATION)bytes, length, error_offset);
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS NTAPI
ext4win_validate_reparse(
    _In_reads_bytes_(length) const UCHAR *bytes,
    _In_ ULONG length)
{
    return FsRtlValidateReparsePointBuffer(length, (PREPARSE_DATA_BUFFER)bytes);
}
