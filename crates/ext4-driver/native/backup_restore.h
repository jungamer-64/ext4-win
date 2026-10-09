#ifndef EXT4WIN_BACKUP_RESTORE_H
#define EXT4WIN_BACKUP_RESTORE_H

/* The caller holds the captured subject lock. Only an enabled native privilege
 * establishes these rights. The returned records must be appended to ACCESS_STATE
 * after the complete access decision succeeds, before publishing handle authority. */
static ACCESS_MASK
ext4win_create_privilege(
    PSECURITY_SUBJECT_CONTEXT subject,
    KPROCESSOR_MODE mode,
    ULONG privilege,
    ACCESS_MASK requested,
    PINITIAL_PRIVILEGE_SET used)
{
    PRIVILEGE_SET required;
    if (requested == 0) { return 0; }
    RtlZeroMemory(&required, sizeof(required));
    required.PrivilegeCount = 1;
    required.Control = PRIVILEGE_SET_ALL_NECESSARY;
    required.Privilege[0].Luid = RtlConvertLongToLuid(privilege);
    if (!SePrivilegeCheck(&required, subject, mode)) { return 0; }
    used->Privilege[used->PrivilegeCount++] = required.Privilege[0];
    return requested;
}

static ACCESS_MASK
ext4win_privileged_create_access(
    PSECURITY_SUBJECT_CONTEXT subject,
    KPROCESSOR_MODE mode,
    ULONG disposition,
    ACCESS_MASK desired,
    PINITIAL_PRIVILEGE_SET used)
{
    const ACCESS_MASK backup = READ_CONTROL | ACCESS_SYSTEM_SECURITY | FILE_GENERIC_READ | FILE_TRAVERSE;
    const ACCESS_MASK restore = WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY | FILE_GENERIC_WRITE | DELETE;
    const BOOLEAN maximum = (desired & MAXIMUM_ALLOWED) != 0;
    ACCESS_MASK granted = 0;
    RtlZeroMemory(used, sizeof(*used));
    used->Control = PRIVILEGE_SET_ALL_NECESSARY;
    if ((disposition == FILE_OPEN) || (disposition == FILE_OPEN_IF) || (disposition == FILE_OVERWRITE_IF)) {
        granted |= ext4win_create_privilege(subject, mode, SE_BACKUP_PRIVILEGE,
            maximum ? backup : desired & backup, used);
    }
    granted |= ext4win_create_privilege(subject, mode, SE_RESTORE_PRIVILEGE,
        maximum ? restore : desired & restore, used);
    return granted;
}

#endif
