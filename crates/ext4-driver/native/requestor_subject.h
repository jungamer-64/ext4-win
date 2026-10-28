#ifndef EXT4WIN_REQUESTOR_SUBJECT_H
#define EXT4WIN_REQUESTOR_SUBJECT_H

typedef struct _EXT4WIN_REQUESTOR_SUBJECT {
    SECURITY_SUBJECT_CONTEXT Subject;
    KPROCESSOR_MODE Mode;
    PIO_WORKITEM ReleaseWork;
} EXT4WIN_REQUESTOR_SUBJECT, *PEXT4WIN_REQUESTOR_SUBJECT;

/* FsRtl releases and pool-frees this prefix after notification ownership transfers. */
C_ASSERT(FIELD_OFFSET(EXT4WIN_REQUESTOR_SUBJECT, Subject) == 0);

/* The work item references the device until PASSIVE_LEVEL token retirement completes.
 * Queue cancellation may transfer this unique cleanup owner at DISPATCH_LEVEL. */
static VOID ext4win_subject_destroy(PEXT4WIN_REQUESTOR_SUBJECT subject)
{
    SeReleaseSubjectContext(&subject->Subject);
    IoFreeWorkItem(subject->ReleaseWork);
    ExFreePool(subject);
}

static IO_WORKITEM_ROUTINE ext4win_subject_release_worker;

_Use_decl_annotations_
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

/* NULL on success means the original requestor acquired traversal bypass authority. */
NTSTATUS ext4win_notification_subject_capture(PDEVICE_OBJECT device, KPROCESSOR_MODE mode, PVOID *output)
{
    *output = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_INVALID_DEVICE_STATE; }
    if (mode != KernelMode && mode != UserMode) { return STATUS_INVALID_PARAMETER; }
    if (SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_CHANGE_NOTIFY_PRIVILEGE), mode)) {
        return STATUS_SUCCESS;
    }
    return ext4win_subject_capture(device, mode, output);
}

/* Preparation/cancellation retain the work item. FsRtl takes only the pool allocation
 * and token references; no Rust or work-item destruction obligation follows transfer. */
PSECURITY_SUBJECT_CONTEXT ext4win_subject_transfer_notification(PVOID context)
{
    PEXT4WIN_REQUESTOR_SUBJECT subject = context;
    PAGED_CODE();
    IoFreeWorkItem(subject->ReleaseWork);
    subject->ReleaseWork = NULL;
    return &subject->Subject;
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

#endif
