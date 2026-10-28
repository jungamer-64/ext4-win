#pragma once

/* These FsRtl calls can synchronously complete an IRP while the actor or a
 * stream resource is held. A non-NULL TopLevelIrp prevents Filter Manager name
 * queries from recursively entering the filesystem on that completion stack.
 * Preserve incoming Cc/MM/IRP markers as opaque values. Restoration belongs to
 * C finally blocks so it also runs on SEH exceptions. */
static PIRP ext4win_enter_fsrtl_completion(VOID)
{
    PIRP previous = IoGetTopLevelIrp();
    if (previous == NULL) {
        IoSetTopLevelIrp((PIRP)FSRTL_FSP_TOP_LEVEL_IRP);
    }
    return previous;
}

VOID NTAPI ext4win_notify_register(PNOTIFY_SYNC sync, PLIST_ENTRY list, PVOID context,
    PSTRING directory, ULONG filter, BOOLEAN subtree, PIRP irp)
{
    PIRP previous = ext4win_enter_fsrtl_completion();
    __try {
        FsRtlNotifyFullChangeDirectory(sync, list, context, directory,
            subtree, FALSE, filter, irp, NULL, NULL);
    }
    __finally { IoSetTopLevelIrp(previous); }
}

VOID NTAPI ext4win_notify_report(PNOTIFY_SYNC sync, PLIST_ENTRY list, PSTRING target,
    USHORT name_offset, ULONG filter, ULONG action)
{
    PIRP previous = ext4win_enter_fsrtl_completion();
    __try {
        FsRtlNotifyFullReportChange(sync, list, target, name_offset,
            NULL, NULL, filter, action, NULL);
    }
    __finally { IoSetTopLevelIrp(previous); }
}

VOID NTAPI ext4win_notify_cleanup(PNOTIFY_SYNC sync, PLIST_ENTRY list, PVOID context)
{
    PIRP previous = ext4win_enter_fsrtl_completion();
    __try { FsRtlNotifyCleanup(sync, list, context); }
    __finally { IoSetTopLevelIrp(previous); }
}

VOID NTAPI ext4win_notify_cleanup_all(PNOTIFY_SYNC sync, PLIST_ENTRY list)
{
    PIRP previous = ext4win_enter_fsrtl_completion();
    __try { FsRtlNotifyCleanupAll(sync, list); }
    __finally { IoSetTopLevelIrp(previous); }
}

static NTSTATUS ext4win_oplock_fsctrl(POPLOCK oplock, PIRP irp, ULONG count, ULONG flags)
{
    NTSTATUS status;
    PIRP previous = ext4win_enter_fsrtl_completion();
    __try { status = FsRtlOplockFsctrlEx(oplock, irp, count, flags); }
    __finally { IoSetTopLevelIrp(previous); }
    return status;
}

static NTSTATUS ext4win_check_oplock(POPLOCK oplock, PIRP irp, ULONG flags,
    PVOID context, POPLOCK_WAIT_COMPLETE_ROUTINE completion, POPLOCK_FS_PREPOST_IRP prepost)
{
    NTSTATUS status;
    PIRP previous = ext4win_enter_fsrtl_completion();
    __try { status = FsRtlCheckOplockEx(oplock, irp, flags, context, completion, prepost); }
    __finally { IoSetTopLevelIrp(previous); }
    return status;
}

static VOID ext4win_uninitialize_oplock(POPLOCK oplock)
{
    PIRP previous = ext4win_enter_fsrtl_completion();
    __try { FsRtlUninitializeOplock(oplock); }
    __finally { IoSetTopLevelIrp(previous); }
}
