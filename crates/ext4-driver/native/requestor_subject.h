#ifndef EXT4WIN_REQUESTOR_SUBJECT_H
#define EXT4WIN_REQUESTOR_SUBJECT_H

typedef struct _EXT4WIN_REQUESTOR_SUBJECT {
    SECURITY_SUBJECT_CONTEXT Subject;
    KPROCESSOR_MODE Mode;
    PIO_WORKITEM ReleaseWork;
} EXT4WIN_REQUESTOR_SUBJECT, *PEXT4WIN_REQUESTOR_SUBJECT;

/* FsRtl releases and pool-frees this prefix after notification ownership transfers. */
C_ASSERT(FIELD_OFFSET(EXT4WIN_REQUESTOR_SUBJECT, Subject) == 0);

/* A filter may resume this IRP on a different thread. Use the IRP's retained
 * issuing thread and its stable owning process for user authorization. */
static NTSTATUS ext4win_capture_irp_subject(PIRP irp, PSECURITY_SUBJECT_CONTEXT subject)
{
    PETHREAD thread = irp->Tail.Overlay.Thread;
    PEPROCESS process;
    if (irp->RequestorMode == KernelMode) {
        SeCaptureSubjectContext(subject);
        return STATUS_SUCCESS;
    }
    if (irp->RequestorMode != UserMode) { return STATUS_INVALID_PARAMETER; }
    if (thread == NULL) { return STATUS_INVALID_DEVICE_STATE; }
    process = PsGetThreadProcess(thread);
    if (process == NULL || IoGetRequestorProcess(irp) != process) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    SeCaptureSubjectContextEx(thread, process, subject);
    return STATUS_SUCCESS;
}

static BOOLEAN ext4win_subject_has_privilege(PSECURITY_SUBJECT_CONTEXT subject, ULONG privilege)
{
    PRIVILEGE_SET required = {0};
    required.PrivilegeCount = 1;
    required.Control = PRIVILEGE_SET_ALL_NECESSARY;
    required.Privilege[0].Luid = RtlConvertUlongToLuid(privilege);
    return SePrivilegeCheck(&required, subject, UserMode);
}

BOOLEAN NTAPI ext4win_requestor_has_privilege(PIRP irp, ULONG privilege)
{
    SECURITY_SUBJECT_CONTEXT subject;
    BOOLEAN allowed;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return 0; }
    if (irp->RequestorMode == KernelMode) { return TRUE; }
    if (!NT_SUCCESS(ext4win_capture_irp_subject(irp, &subject))) { return 0; }
    allowed = ext4win_subject_has_privilege(&subject, privilege);
    SeReleaseSubjectContext(&subject);
    return allowed;
}

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

/* Consumes the captured token references, transferring them to the pool context on success. */
static NTSTATUS ext4win_subject_retain(PDEVICE_OBJECT device, KPROCESSOR_MODE mode,
    PSECURITY_SUBJECT_CONTEXT captured, PVOID *output)
{
    PEXT4WIN_REQUESTOR_SUBJECT subject;
    subject = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*subject), 'sR4E');
    if (subject == NULL) {
        SeReleaseSubjectContext(captured);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    subject->ReleaseWork = IoAllocateWorkItem(device);
    if (subject->ReleaseWork == NULL) {
        ExFreePool(subject);
        SeReleaseSubjectContext(captured);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    subject->Mode = mode;
    subject->Subject = *captured;
    *output = subject;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ext4win_subject_capture(PDEVICE_OBJECT device, PIRP irp, PVOID *output)
{
    SECURITY_SUBJECT_CONTEXT captured;
    NTSTATUS status;
    *output = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_INVALID_DEVICE_STATE; }
    status = ext4win_capture_irp_subject(irp, &captured);
    if (!NT_SUCCESS(status)) { return status; }
    return ext4win_subject_retain(device, irp->RequestorMode, &captured, output);
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
NTSTATUS NTAPI ext4win_notification_subject_capture(PDEVICE_OBJECT device, PIRP irp, PVOID *output)
{
    SECURITY_SUBJECT_CONTEXT captured;
    NTSTATUS status;
    *output = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_INVALID_DEVICE_STATE; }
    if (irp->RequestorMode == KernelMode) { return STATUS_SUCCESS; }
    status = ext4win_capture_irp_subject(irp, &captured);
    if (!NT_SUCCESS(status)) { return status; }
    if (ext4win_subject_has_privilege(&captured, SE_CHANGE_NOTIFY_PRIVILEGE)) {
        SeReleaseSubjectContext(&captured);
        return STATUS_SUCCESS;
    }
    return ext4win_subject_retain(device, UserMode, &captured, output);
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

static NTSTATUS ext4win_subject_check_access(PVOID context, PSECURITY_DESCRIPTOR descriptor,
    ACCESS_MASK desired)
{
    PEXT4WIN_REQUESTOR_SUBJECT subject = context;
    PPRIVILEGE_SET privileges = NULL;
    ACCESS_MASK granted = 0;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    BOOLEAN allowed;
    PAGED_CODE();
    SeLockSubjectContext(&subject->Subject);
    allowed = SeAccessCheck(descriptor, &subject->Subject, TRUE, desired,
        0, &privileges, IoGetFileObjectGenericMapping(), subject->Mode, &granted, &status);
    SeUnlockSubjectContext(&subject->Subject);
    if (privileges != NULL) { SeFreePrivileges(privileges); }
    return allowed ? STATUS_SUCCESS : status;
}

NTSTATUS ext4win_subject_write_attributes(PVOID context, PSECURITY_DESCRIPTOR descriptor)
{
    return ext4win_subject_check_access(context, descriptor, FILE_WRITE_ATTRIBUTES);
}

/* Only an ordinary access refusal permits the alternate parent deletion check. */
NTSTATUS ext4win_subject_replace(PVOID context, PSECURITY_DESCRIPTOR target,
    PSECURITY_DESCRIPTOR parent)
{
    NTSTATUS status = ext4win_subject_check_access(context, target, DELETE);
    if (status == STATUS_ACCESS_DENIED || status == STATUS_PRIVILEGE_NOT_HELD) {
        return ext4win_subject_check_access(context, parent, FILE_DELETE_CHILD);
    }
    return status;
}

#endif
