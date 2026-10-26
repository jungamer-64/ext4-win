#pragma once

/* Advisory mount notification runs on the reserved completion worker. Allocation or delivery
 * failure cannot turn an already published mount into a failed mount or authorize a retry.
 * The Rust notification retains the device; the temporary native file has no filesystem contexts. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ext4win_notify_volume_mount(_In_ PDEVICE_OBJECT device)
{
    PFILE_OBJECT file = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        file = IoCreateStreamFileObjectLite(NULL, device);
        if (file == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; }
        else { status = FsRtlNotifyVolumeEvent(file, FSRTL_VOLUME_MOUNT); }
    }
    __except (FsRtlIsNtstatusExpected(GetExceptionCode())
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        status = GetExceptionCode();
    }
    if (file != NULL) { ObDereferenceObject(file); }
    return status;
}
