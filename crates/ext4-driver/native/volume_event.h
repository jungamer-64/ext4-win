#pragma once

/* The pending mount retains the original VPB while the stream acquires its own reference.
 * No volume event or stream close can run until completion ownership has been discharged. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ext4win_prepare_volume_mount_event(
    _In_ PDEVICE_OBJECT device,
    _Outptr_result_nullonfailure_ PFILE_OBJECT *prepared)
{
    PFILE_OBJECT file = NULL;
    KIRQL irql;
    *prepared = NULL;
    __try {
        file = IoCreateStreamFileObjectLite(NULL, device);
    }
    __except (FsRtlIsNtstatusExpected(GetExceptionCode())
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return GetExceptionCode();
    }
    if (file == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Associate the stream's acquired VPB reference before transferring the file. */
    IoAcquireVpbSpinLock(&irql);
    file->Vpb = device->Vpb;
    IoReleaseVpbSpinLock(irql);
    *prepared = file;
    return STATUS_SUCCESS;
}

/* The caller holds the stream reference through delivery and releases it at PASSIVE_LEVEL. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ext4win_deliver_volume_mount_event(_In_ PFILE_OBJECT file)
{
    NTSTATUS status;
    __try {
        status = FsRtlNotifyVolumeEvent(file, FSRTL_VOLUME_MOUNT);
    }
    __except (FsRtlIsNtstatusExpected(GetExceptionCode())
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        status = GetExceptionCode();
    }
    return status;
}
