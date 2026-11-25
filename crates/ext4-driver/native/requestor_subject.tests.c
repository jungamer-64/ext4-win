/* Production subject ownership with an independent effective-token and IRQL oracle. */
#include <stddef.h>
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2
#define POOL_FLAG_NON_PAGED 1
#define STATUS_SUCCESS 0
#define STATUS_INVALID_DEVICE_STATE (-1)
#define STATUS_INSUFFICIENT_RESOURCES (-2)
#define STATUS_ACCESS_DENIED (-3)
#define STATUS_INVALID_PARAMETER (-4)
#define STATUS_PRIVILEGE_NOT_HELD (-5)
#define STATUS_IO_DEVICE_ERROR (-6)
#define KernelMode 0
#define UserMode 1
#define SE_CHANGE_NOTIFY_PRIVILEGE 23
#define SE_MANAGE_VOLUME_PRIVILEGE 28
#define PRIVILEGE_SET_ALL_NECESSARY 1
#define NT_SUCCESS(status) ((status) >= 0)
#define FIELD_OFFSET(type, field) offsetof(type, field)
#define C_ASSERT(condition) _Static_assert(condition, #condition)
#define FILE_WRITE_ATTRIBUTES 0x100
#define DELETE 0x10000
#define FILE_DELETE_CHILD 0x40
#define TRUE 1
#define DelayedWorkQueue 0
#define PAGED_CODE() assert(irql == PASSIVE_LEVEL)
#define VOID void
#define NTAPI
#define _Use_decl_annotations_
#define UNREFERENCED_PARAMETER(value) ((void)(value))
typedef int NTSTATUS, KPROCESSOR_MODE, BOOLEAN;
typedef unsigned ULONG;
typedef unsigned ACCESS_MASK;
typedef void *PVOID;
typedef struct { unsigned token; } SECURITY_SUBJECT_CONTEXT;
typedef SECURITY_SUBJECT_CONTEXT *PSECURITY_SUBJECT_CONTEXT;
typedef struct { unsigned identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct { unsigned identity; } EPROCESS, *PEPROCESS;
typedef struct { unsigned token; PEPROCESS process; } ETHREAD, *PETHREAD;
typedef struct {
    struct { struct { PETHREAD Thread; } Overlay; } Tail;
    KPROCESSOR_MODE RequestorMode;
    PEPROCESS process;
} IRP, *PIRP;
typedef struct { ACCESS_MASK allowed; NTSTATUS failure; } SECURITY_DESCRIPTOR, *PSECURITY_DESCRIPTOR;
typedef struct {
    unsigned PrivilegeCount, Control;
    struct { unsigned Luid; } Privilege[1];
} PRIVILEGE_SET, *PPRIVILEGE_SET;
typedef VOID IO_WORKITEM_ROUTINE(PDEVICE_OBJECT, PVOID);
typedef IO_WORKITEM_ROUTINE *PIO_WORKITEM_ROUTINE;
typedef struct { PIO_WORKITEM_ROUTINE routine; PVOID context; } IO_WORKITEM, *PIO_WORKITEM;
static DEVICE_OBJECT device;
static int irql, pools, works, subjects, locks, fail_pool, fail_work;
static const unsigned caller_token = 99;
static int traversal_privilege, management_privilege;
static PIO_WORKITEM queued;
static PRIVILEGE_SET privilege;
static SECURITY_DESCRIPTOR writable = {FILE_WRITE_ATTRIBUTES, STATUS_ACCESS_DENIED};
static SECURITY_DESCRIPTOR denied = {0, STATUS_ACCESS_DENIED};
static SECURITY_DESCRIPTOR deletable = {DELETE, STATUS_ACCESS_DENIED};
static SECURITY_DESCRIPTOR parent = {FILE_DELETE_CHILD, STATUS_ACCESS_DENIED};
static SECURITY_DESCRIPTOR broken = {0, STATUS_IO_DEVICE_ERROR};
static unsigned checks;
static int mapping;
static _Alignas(16) unsigned char pool[256];
static IO_WORKITEM release_work;
static int KeGetCurrentIrql(void) { return irql; }
static unsigned RtlConvertUlongToLuid(unsigned privilege_id) { return privilege_id; }
static PEPROCESS IoGetRequestorProcess(PIRP irp) { return irp->process; }
static PEPROCESS PsGetThreadProcess(PETHREAD thread) { return thread->process; }
static BOOLEAN SePrivilegeCheck(PRIVILEGE_SET *required, PSECURITY_SUBJECT_CONTEXT subject, KPROCESSOR_MODE mode)
{
    assert(irql == PASSIVE_LEVEL && mode == UserMode);
    assert(required->PrivilegeCount == 1 && required->Control == PRIVILEGE_SET_ALL_NECESSARY);
    if (subject->token == caller_token) { return TRUE; }
    assert(subject->token == 77);
    switch (required->Privilege[0].Luid) {
    case SE_CHANGE_NOTIFY_PRIVILEGE: return traversal_privilege;
    case SE_MANAGE_VOLUME_PRIVILEGE: return management_privilege;
    default: assert(0); return 0;
    }
}
static PVOID ExAllocatePool2(int flags, size_t bytes, unsigned tag)
{
    assert(flags == POOL_FLAG_NON_PAGED && tag != 0);
    if (fail_pool) { return NULL; }
    assert(pools == 0 && bytes <= sizeof(pool));
    pools++;
    return pool;
}
static void ExFreePool(PVOID memory) { assert(pools == 1 && memory == pool); pools--; }
static PIO_WORKITEM IoAllocateWorkItem(PDEVICE_OBJECT observed)
{
    assert(observed == &device);
    if (fail_work) { return NULL; }
    assert(works == 0);
    works++;
    return &release_work;
}
static void IoFreeWorkItem(PIO_WORKITEM work) { assert(works == 1 && work == &release_work); works--; }
static void IoQueueWorkItem(PIO_WORKITEM work, PIO_WORKITEM_ROUTINE routine, int queue, PVOID context)
{
    assert(irql == DISPATCH_LEVEL && queue == DelayedWorkQueue && queued == NULL);
    work->routine = routine; work->context = context; queued = work;
}
static void SeCaptureSubjectContext(SECURITY_SUBJECT_CONTEXT *subject)
{ (void)subject; assert(0); }
static void SeCaptureSubjectContextEx(PETHREAD thread, PEPROCESS process, SECURITY_SUBJECT_CONTEXT *subject)
{
    assert(irql == PASSIVE_LEVEL && thread->process == process);
    subjects++;
    subject->token = thread->token;
}
static void SeReleaseSubjectContext(SECURITY_SUBJECT_CONTEXT *subject)
{ assert(irql == PASSIVE_LEVEL && subject->token == 77 && subjects == 1); subjects--; }
static void SeLockSubjectContext(SECURITY_SUBJECT_CONTEXT *subject)
{ assert(subject->token == 77 && locks == 0); locks++; }
static void SeUnlockSubjectContext(SECURITY_SUBJECT_CONTEXT *subject)
{ assert(subject->token == 77 && locks == 1); locks--; }
static PVOID IoGetFileObjectGenericMapping(void) { return &mapping; }
static BOOLEAN SeAccessCheck(PSECURITY_DESCRIPTOR descriptor, SECURITY_SUBJECT_CONTEXT *subject,
    BOOLEAN locked, ACCESS_MASK desired, ACCESS_MASK previous, PPRIVILEGE_SET *used,
    PVOID generic, KPROCESSOR_MODE mode, ACCESS_MASK *granted, NTSTATUS *status)
{
    assert(irql == PASSIVE_LEVEL && locks == 1 && locked && subject->token == 77);
    assert((desired == FILE_WRITE_ATTRIBUTES || desired == DELETE || desired == FILE_DELETE_CHILD)
        && previous == 0 && generic == &mapping && mode == 1);
    checks++;
    *used = &privilege; *granted = descriptor->allowed & desired;
    *status = *granted == desired ? STATUS_SUCCESS : descriptor->failure;
    return *granted == desired;
}
static void SeFreePrivileges(PPRIVILEGE_SET used) { assert(used == &privilege); }
#include "requestor_subject.h"

int main(void)
{
    PVOID subject = NULL;
    EPROCESS process = {1}, unrelated = {2};
    ETHREAD thread = {77, &process};
    IRP request = {{{&thread}}, UserMode, &process};
    fail_pool = 1;
    assert(ext4win_subject_capture(&device, &request, &subject) == STATUS_INSUFFICIENT_RESOURCES);
    assert(subject == NULL && pools == 0 && works == 0);
    fail_pool = 0; fail_work = 1;
    assert(ext4win_subject_capture(&device, &request, &subject) == STATUS_INSUFFICIENT_RESOURCES);
    assert(subject == NULL && pools == 0 && works == 0);
    fail_work = 0;
    assert(ext4win_subject_capture(&device, &request, &subject) == STATUS_SUCCESS);
    assert(ext4win_subject_write_attributes(subject, &writable) == STATUS_SUCCESS);
    assert(ext4win_subject_write_attributes(subject, &denied) == STATUS_ACCESS_DENIED);
    checks = 0;
    assert(ext4win_subject_replace(subject, &deletable, &broken) == STATUS_SUCCESS);
    assert(checks == 1); /* Target permission is sufficient; do not probe an irrelevant parent. */
    checks = 0;
    assert(ext4win_subject_replace(subject, &denied, &parent) == STATUS_SUCCESS);
    assert(checks == 2);
    assert(ext4win_subject_replace(subject, &denied, &denied) == STATUS_ACCESS_DENIED);
    checks = 0;
    assert(ext4win_subject_replace(subject, &broken, &parent) == STATUS_IO_DEVICE_ERROR);
    assert(checks == 1); /* Execution failure is not a denial and cannot authorize fallback. */
    denied.failure = STATUS_PRIVILEGE_NOT_HELD;
    assert(ext4win_subject_replace(subject, &denied, &parent) == STATUS_SUCCESS);
    denied.failure = STATUS_ACCESS_DENIED;
    ext4win_subject_release(subject);
    assert(subjects == 0 && works == 0 && pools == 0 && locks == 0);
    assert(ext4win_subject_capture(&device, &request, &subject) == STATUS_SUCCESS);
    irql = DISPATCH_LEVEL;
    ext4win_subject_release(subject);
    assert(subjects == 1 && works == 1 && pools == 1 && queued != NULL);
    irql = PASSIVE_LEVEL;
    {
        PIO_WORKITEM owner = queued;
        queued = NULL;
        owner->routine(&device, owner->context);
    }
    assert(subjects == 0 && works == 0 && pools == 0);

    request.RequestorMode = 2;
    assert(ext4win_notification_subject_capture(&device, &request, &subject) == STATUS_INVALID_PARAMETER);
    assert(subject == NULL && subjects == 0 && pools == 0);
    request.RequestorMode = KernelMode;
    assert(ext4win_notification_subject_capture(&device, &request, &subject) == STATUS_SUCCESS);
    assert(subject == NULL && subjects == 0 && works == 0);
    request.RequestorMode = UserMode;
    request.Tail.Overlay.Thread = NULL;
    assert(ext4win_notification_subject_capture(&device, &request, &subject) == STATUS_INVALID_DEVICE_STATE);
    assert(!ext4win_requestor_has_privilege(&request, SE_MANAGE_VOLUME_PRIVILEGE));
    request.Tail.Overlay.Thread = &thread;
    request.process = &unrelated;
    assert(ext4win_notification_subject_capture(&device, &request, &subject) == STATUS_INVALID_DEVICE_STATE);
    assert(subject == NULL && subjects == 0);
    request.process = &process;
    assert(!ext4win_requestor_has_privilege(&request, SE_MANAGE_VOLUME_PRIVILEGE));
    management_privilege = 1;
    assert(ext4win_requestor_has_privilege(&request, SE_MANAGE_VOLUME_PRIVILEGE));
    traversal_privilege = 1;
    assert(ext4win_notification_subject_capture(&device, &request, &subject) == STATUS_SUCCESS);
    assert(subject == NULL && subjects == 0 && works == 0);
    traversal_privilege = 0;
    fail_pool = 1;
    assert(ext4win_notification_subject_capture(&device, &request, &subject) == STATUS_INSUFFICIENT_RESOURCES);
    assert(subject == NULL && subjects == 0 && works == 0);
    fail_pool = 0;
    assert(ext4win_notification_subject_capture(&device, &request, &subject) == STATUS_SUCCESS);
    {
        PSECURITY_SUBJECT_CONTEXT transferred = ext4win_subject_transfer_notification(subject);
        assert(transferred == (PSECURITY_SUBJECT_CONTEXT)pool && transferred->token == 77);
        assert(works == 0 && subjects == 1 && pools == 1);
        /* FsRtl alone now consumes the context and the matching pool allocation. */
        SeReleaseSubjectContext(transferred);
        ExFreePool(transferred);
    }
    assert(subjects == 0 && works == 0 && pools == 0);
    assert(ext4win_notification_subject_capture(&device, &request, &subject) == STATUS_SUCCESS);
    irql = DISPATCH_LEVEL;
    ext4win_subject_release(subject);
    assert(subjects == 1 && works == 1 && pools == 1 && queued != NULL);
    irql = PASSIVE_LEVEL;
    {
        PIO_WORKITEM owner = queued;
        queued = NULL;
        owner->routine(&device, owner->context);
    }
    assert(subjects == 0 && works == 0 && pools == 0);
    return 0;
}
