#pragma once

extern BOOLEAN NTAPI ext4win_notification_traverse(const VOID *target, PSECURITY_SUBJECT_CONTEXT subject);

/* Each reported name is anchored to one exact watched inode. Rust lends only the
 * intervening directory descriptors for that anchor, prepared before commit. */
static BOOLEAN ext4win_notify_traverse(PVOID context, PVOID target, PSECURITY_SUBJECT_CONTEXT subject)
{
    BOOLEAN allowed;
    UNREFERENCED_PARAMETER(context);
    if (target == NULL || subject == NULL) { return FALSE; }
    SeLockSubjectContext(subject);
    allowed = ext4win_notification_traverse(target, subject);
    SeUnlockSubjectContext(subject);
    return allowed;
}

BOOLEAN NTAPI ext4win_notification_check_traverse(PSECURITY_SUBJECT_CONTEXT subject,
    PSECURITY_DESCRIPTOR descriptor)
{
    PPRIVILEGE_SET privileges = NULL;
    ACCESS_MASK granted = 0;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    BOOLEAN allowed = SeAccessCheck(descriptor, subject, TRUE, FILE_TRAVERSE,
        0, &privileges, IoGetFileObjectGenericMapping(), UserMode, &granted, &status);
    if (privileges != NULL) { SeFreePrivileges(privileges); }
    return allowed;
}


VOID NTAPI ext4win_notify_register(PNOTIFY_SYNC sync, PLIST_ENTRY list, PVOID context,
    PSTRING directory, ULONG filter, BOOLEAN subtree, PIRP irp, PSECURITY_SUBJECT_CONTEXT subject)
{
    wdk_sys_notify_change_directory(sync, list, context, directory, subtree, FALSE, filter, irp,
        subject == NULL ? NULL : ext4win_notify_traverse, subject);
}
