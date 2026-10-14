#pragma once

/* A synchronization object becomes Rust-owned only after initialization succeeds.
 * FsRtl's documented allocation exception must not unwind through Rust frames. */
NTSTATUS NTAPI ext4win_notify_initialize_sync(PNOTIFY_SYNC *sync)
{
    *sync = NULL;
    __try { FsRtlNotifyInitializeSync(sync); }
    __except (GetExceptionCode() == STATUS_INSUFFICIENT_RESOURCES
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    return STATUS_SUCCESS;
}
