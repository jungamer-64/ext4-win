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
#define FILE_WRITE_ATTRIBUTES 0x100
#define TRUE 1
#define DelayedWorkQueue 0
#define PAGED_CODE() assert(irql == PASSIVE_LEVEL)
#define VOID void
#define _Use_decl_annotations_
#define UNREFERENCED_PARAMETER(value) ((void)(value))
typedef int NTSTATUS, KPROCESSOR_MODE, BOOLEAN;
typedef unsigned ACCESS_MASK;
typedef void *PVOID;
typedef struct { unsigned token; } SECURITY_SUBJECT_CONTEXT;
typedef struct { unsigned identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct { int allowed; } SECURITY_DESCRIPTOR, *PSECURITY_DESCRIPTOR;
typedef struct { int used; } PRIVILEGE_SET, *PPRIVILEGE_SET;
typedef VOID IO_WORKITEM_ROUTINE(PDEVICE_OBJECT, PVOID);
typedef IO_WORKITEM_ROUTINE *PIO_WORKITEM_ROUTINE;
typedef struct { PIO_WORKITEM_ROUTINE routine; PVOID context; } IO_WORKITEM, *PIO_WORKITEM;
static DEVICE_OBJECT device;
static int irql, pools, works, subjects, locks, fail_pool, fail_work;
static unsigned caller_token;
static PIO_WORKITEM queued;
static PRIVILEGE_SET privilege;
static SECURITY_DESCRIPTOR writable = {1}, denied = {0};
static int mapping;
static _Alignas(16) unsigned char pool[256];
static IO_WORKITEM release_work;
static int KeGetCurrentIrql(void) { return irql; }
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
{ assert(irql == PASSIVE_LEVEL); subjects++; subject->token = caller_token; }
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
    assert(desired == FILE_WRITE_ATTRIBUTES && previous == 0 && generic == &mapping && mode == 1);
    *used = &privilege; *granted = descriptor->allowed ? desired : 0;
    *status = descriptor->allowed ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    return descriptor->allowed;
}
static void SeFreePrivileges(PPRIVILEGE_SET used) { assert(used == &privilege); }
#include "requestor_subject.h"

int main(void)
{
    PVOID subject = NULL;
    caller_token = 77;
    fail_pool = 1;
    assert(ext4win_subject_capture(&device, 1, &subject) == STATUS_INSUFFICIENT_RESOURCES);
    assert(subject == NULL && pools == 0 && works == 0);
    fail_pool = 0; fail_work = 1;
    assert(ext4win_subject_capture(&device, 1, &subject) == STATUS_INSUFFICIENT_RESOURCES);
    assert(subject == NULL && pools == 0 && works == 0);
    fail_work = 0;
    assert(ext4win_subject_capture(&device, 1, &subject) == STATUS_SUCCESS);
    caller_token = 99; /* The worker's ambient identity must never grant caller rights. */
    assert(ext4win_subject_write_attributes(subject, &writable) == STATUS_SUCCESS);
    assert(ext4win_subject_write_attributes(subject, &denied) == STATUS_ACCESS_DENIED);
    ext4win_subject_release(subject);
    assert(subjects == 0 && works == 0 && pools == 0 && locks == 0);
    caller_token = 77;
    assert(ext4win_subject_capture(&device, 1, &subject) == STATUS_SUCCESS);
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
