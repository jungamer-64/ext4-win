#pragma once

/* FILE_OBJECT lifetime belongs to the retaining IRP or native callback. Its flag
 * word is shared by actor admission, cache workers and Fast I/O. Every driver
 * access uses this boundary: aligned native loads and interlocked bit updates.
 * Flags do not publish Rust contexts; create completion and handle lifecycle
 * transitions own that ordering. */
ULONG NTAPI ext4win_file_flags(_In_ PFILE_OBJECT file);
VOID NTAPI ext4win_file_set_flags(_Inout_ PFILE_OBJECT file, _In_ ULONG flags);
VOID NTAPI ext4win_file_clear_flags(_Inout_ PFILE_OBJECT file, _In_ ULONG flags);
