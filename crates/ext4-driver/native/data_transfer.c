#include <ntifs.h>

/*
 * Rust never forms a reference over a requestor's direct-I/O mapping.  This
 * native boundary snapshots one checked window into driver-owned nonpaged
 * storage while the pending IRP still owns the system buffer or MDL mapping.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_copy_write_input_window(
    _In_reads_bytes_(source_length) const VOID *source,
    _In_ ULONG source_length,
    _In_ ULONG source_offset,
    _Out_writes_bytes_(destination_length) VOID *destination,
    _In_ ULONG destination_length)
{
    if ((source == NULL) || (destination == NULL) ||
        (destination_length == 0) ||
        (source_offset > source_length) ||
        (destination_length > (source_length - source_offset))) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(
        destination,
        (const UCHAR *)source + source_offset,
        destination_length);
    return STATUS_SUCCESS;
}
