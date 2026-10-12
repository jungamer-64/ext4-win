#include <ntifs.h>

typedef struct _EXT4WIN_REQUESTOR_SUBJECT {
    SECURITY_SUBJECT_CONTEXT Subject;
    KPROCESSOR_MODE Mode;
    PIO_WORKITEM ReleaseWork;
} EXT4WIN_REQUESTOR_SUBJECT, *PEXT4WIN_REQUESTOR_SUBJECT;

/* The work item references the device until PASSIVE_LEVEL token retirement completes.
 * Queue cancellation may transfer this unique cleanup owner at DISPATCH_LEVEL. */
static VOID ext4win_subject_destroy(PEXT4WIN_REQUESTOR_SUBJECT subject)
{
    SeReleaseSubjectContext(&subject->Subject);
    IoFreeWorkItem(subject->ReleaseWork);
    ExFreePool(subject);
}

static VOID ext4win_subject_release_worker(PDEVICE_OBJECT device, PVOID context)
{
    UNREFERENCED_PARAMETER(device);
    ext4win_subject_destroy((PEXT4WIN_REQUESTOR_SUBJECT)context);
}

NTSTATUS ext4win_subject_capture(PDEVICE_OBJECT device, KPROCESSOR_MODE mode, PVOID *output)
{
    PEXT4WIN_REQUESTOR_SUBJECT subject;
    *output = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_INVALID_DEVICE_STATE; }
    subject = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*subject), 'sR4E');
    if (subject == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    subject->ReleaseWork = IoAllocateWorkItem(device);
    if (subject->ReleaseWork == NULL) { ExFreePool(subject); return STATUS_INSUFFICIENT_RESOURCES; }
    subject->Mode = mode;
    SeCaptureSubjectContext(&subject->Subject);
    *output = subject;
    return STATUS_SUCCESS;
}

VOID ext4win_subject_release(PVOID context)
{
    PEXT4WIN_REQUESTOR_SUBJECT subject = context;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        ext4win_subject_destroy(subject);
    } else {
        IoQueueWorkItem(subject->ReleaseWork, ext4win_subject_release_worker, DelayedWorkQueue, subject);
    }
}

NTSTATUS ext4win_subject_write_attributes(PVOID context, PSECURITY_DESCRIPTOR descriptor)
{
    PEXT4WIN_REQUESTOR_SUBJECT subject = context;
    PPRIVILEGE_SET privileges = NULL;
    ACCESS_MASK granted = 0;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    BOOLEAN allowed;
    PAGED_CODE();
    SeLockSubjectContext(&subject->Subject);
    allowed = SeAccessCheck(descriptor, &subject->Subject, TRUE, FILE_WRITE_ATTRIBUTES,
        0, &privileges, IoGetFileObjectGenericMapping(), subject->Mode, &granted, &status);
    SeUnlockSubjectContext(&subject->Subject);
    if (privileges != NULL) { SeFreePrivileges(privileges); }
    return allowed ? STATUS_SUCCESS : status;
}

/* Evaluated on the requestor dispatch thread, before any reactor queue handoff. */
BOOLEAN NTAPI
ext4win_key_management_privilege(KPROCESSOR_MODE requestor_mode)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return FALSE; }
    PAGED_CODE();
    return SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_MANAGE_VOLUME_PRIVILEGE), requestor_mode);
}

/* Checked while the caller's effective token still belongs to the dispatch thread. */
BOOLEAN NTAPI
ext4win_symbolic_link_privilege(KPROCESSOR_MODE requestor_mode)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return FALSE; }
    PAGED_CODE();
    return SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE), requestor_mode);
}

/* Token information is owned here; only complete copied SIDs cross into Rust. */
NTSTATUS
ext4win_creator_sids(
    _Inout_ PSECURITY_SUBJECT_CONTEXT subject,
    _Out_writes_bytes_(68) PUCHAR user_sid,
    _Out_ PULONG user_length,
    _Out_writes_bytes_(68) PUCHAR group_sid,
    _Out_ PULONG group_length)
{
    PACCESS_TOKEN token;
    PTOKEN_USER user = NULL;
    PTOKEN_PRIMARY_GROUP group = NULL;
    NTSTATUS status;
    ULONG user_size;
    ULONG group_size;

    PAGED_CODE();
    *user_length = 0;
    *group_length = 0;
    SeLockSubjectContext(subject);
    token = SeQuerySubjectContextToken(subject);
    status = SeQueryInformationToken(token, TokenUser, (PVOID *)&user);
    if (NT_SUCCESS(status)) {
        status = SeQueryInformationToken(token, TokenPrimaryGroup, (PVOID *)&group);
    }
    if (NT_SUCCESS(status)) {
        if (!RtlValidSid(user->User.Sid) || !RtlValidSid(group->PrimaryGroup)) {
            status = STATUS_INVALID_SID;
        } else {
            user_size = RtlLengthSid(user->User.Sid);
            group_size = RtlLengthSid(group->PrimaryGroup);
            if ((user_size > 68) || (group_size > 68)) {
                status = STATUS_INVALID_SID;
            } else {
                RtlCopyMemory(user_sid, user->User.Sid, user_size);
                RtlCopyMemory(group_sid, group->PrimaryGroup, group_size);
                *user_length = user_size;
                *group_length = group_size;
            }
        }
    }
    if (group != NULL) { ExFreePool(group); }
    if (user != NULL) { ExFreePool(user); }
    SeUnlockSubjectContext(subject);
    return status;
}
