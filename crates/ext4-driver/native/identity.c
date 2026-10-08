#include <ntifs.h>

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
