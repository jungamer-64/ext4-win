/* Exercise the production completion boundaries, including real SEH unwinding. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define NTAPI
#define NULL ((void *)0)
#define FALSE 0
#define TRUE 1
#define UserMode 1
#define FILE_TRAVERSE 0x20
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022UL)
#define UNREFERENCED_PARAMETER(value) ((void)(value))
#define FSRTL_FSP_TOP_LEVEL_IRP 1
#define FSRTL_CACHE_TOP_LEVEL_IRP 2
#define STATUS_PENDING ((NTSTATUS)0x103)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AUL)
#define UNEXPECTED_EXCEPTION ((NTSTATUS)0xE0000001UL)
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define GetExceptionCode() ((NTSTATUS)__exception_code())

typedef int NTSTATUS;
typedef void VOID;
typedef void *PVOID;
typedef unsigned char BOOLEAN;
typedef unsigned short USHORT;
typedef unsigned ULONG;
typedef unsigned long long ULONG_PTR;
typedef struct { unsigned identity; } IRP, *PIRP;
typedef struct { unsigned identity; } NOTIFY_SYNC, *PNOTIFY_SYNC;
typedef struct { unsigned identity; } LIST_ENTRY, *PLIST_ENTRY;
typedef struct { USHORT Length, MaximumLength; char *Buffer; } STRING, *PSTRING;
typedef PVOID OPLOCK, *POPLOCK;
typedef VOID (*POPLOCK_WAIT_COMPLETE_ROUTINE)(PVOID, PIRP);
typedef VOID (*POPLOCK_FS_PREPOST_IRP)(PVOID, PIRP);
typedef struct { unsigned token; } SECURITY_SUBJECT_CONTEXT, *PSECURITY_SUBJECT_CONTEXT;
typedef struct { unsigned allowed; } SECURITY_DESCRIPTOR, *PSECURITY_DESCRIPTOR;
typedef struct { unsigned used; } PRIVILEGE_SET, *PPRIVILEGE_SET;
typedef unsigned ACCESS_MASK;
typedef BOOLEAN (*PCHECK_FOR_TRAVERSE_ACCESS)(PVOID, PVOID, PSECURITY_SUBJECT_CONTEXT);

__declspec(dllimport) void __stdcall RaiseException(ULONG, ULONG, ULONG, const ULONG_PTR *);

static IRP incoming_irp, watched_irp;
static NOTIFY_SYNC sync;
static LIST_ENTRY list;
static STRING name;
static OPLOCK oplock;
static unsigned context;
static PIRP top_level, expected_marker;
static NTSTATUS native_exception, native_status = STATUS_PENDING;
static unsigned completions, nest_completion;
static SECURITY_SUBJECT_CONTEXT original_subject = {77};
static SECURITY_DESCRIPTOR traversal = {1};
static PRIVILEGE_SET privilege;
static unsigned subject_locks, traverse_calls, privilege_frees;
static int mapping;

static VOID SeLockSubjectContext(PSECURITY_SUBJECT_CONTEXT subject)
{ assert(subject == &original_subject && subject->token == 77 && subject_locks == 0); subject_locks++; }
static VOID SeUnlockSubjectContext(PSECURITY_SUBJECT_CONTEXT subject)
{ assert(subject == &original_subject && subject_locks == 1); subject_locks--; }
static PVOID IoGetFileObjectGenericMapping(VOID) { return &mapping; }
static BOOLEAN SeAccessCheck(PSECURITY_DESCRIPTOR descriptor, PSECURITY_SUBJECT_CONTEXT subject,
    BOOLEAN locked, ACCESS_MASK desired, ACCESS_MASK previous, PPRIVILEGE_SET *used,
    PVOID generic, int mode, ACCESS_MASK *granted, NTSTATUS *status)
{
    assert(subject == &original_subject && subject->token == 77 && subject_locks == 1 && locked);
    assert(desired == FILE_TRAVERSE && previous == 0 && generic == &mapping && mode == UserMode);
    *used = &privilege; *granted = descriptor->allowed ? desired : 0;
    *status = descriptor->allowed ? 0 : STATUS_ACCESS_DENIED;
    traverse_calls++;
    return (BOOLEAN)descriptor->allowed;
}
static VOID SeFreePrivileges(PPRIVILEGE_SET used) { assert(used == &privilege); privilege_frees++; }
BOOLEAN ext4win_notification_traverse(const VOID *target, PSECURITY_SUBJECT_CONTEXT subject);

static PIRP IoGetTopLevelIrp(VOID) { return top_level; }
static VOID IoSetTopLevelIrp(PIRP marker) { top_level = marker; }
static VOID observe_completion(VOID);

static VOID wait_complete(PVOID owner, PIRP irp)
{
    assert(owner == &context && irp == &watched_irp);
    observe_completion();
}
static VOID prepost(PVOID owner, PIRP irp)
{
    assert(owner == &context && irp == &watched_irp);
    observe_completion();
}

static VOID FsRtlNotifyFullChangeDirectory(PNOTIFY_SYNC lock, PLIST_ENTRY head, PVOID owner,
    PSTRING directory, BOOLEAN subtree, BOOLEAN ignore_buffer, ULONG filter, PIRP irp,
    PCHECK_FOR_TRAVERSE_ACCESS traverse, PSECURITY_SUBJECT_CONTEXT subject)
{
    assert(lock == &sync && head == &list && owner == &context && directory == &name);
    assert(subtree && !ignore_buffer && filter == 0x13 && irp == &watched_irp);
    if (subject == NULL) { assert(traverse == NULL); }
    else {
        assert(traverse != NULL && subject == &original_subject);
        assert(traverse(owner, &traversal, subject) == traversal.allowed);
        assert(!traverse(owner, NULL, subject));
        assert(!traverse(owner, &traversal, NULL));
        assert(subject_locks == 0);
    }
    observe_completion();
}
static VOID FsRtlNotifyFullReportChange(PNOTIFY_SYNC lock, PLIST_ENTRY head, PSTRING target,
    USHORT offset, PSTRING stream, PSTRING parent, ULONG filter, ULONG action, PVOID target_context)
{
    assert(lock == &sync && head == &list && target == &name && offset == 6);
    assert(stream == NULL && parent == NULL && filter == 0x13 && action == 2);
    assert(target_context == &traversal);
    observe_completion();
}
static VOID FsRtlNotifyCleanup(PNOTIFY_SYNC lock, PLIST_ENTRY head, PVOID owner)
{
    assert(lock == &sync && head == &list && owner == &context);
    observe_completion();
}
static VOID FsRtlNotifyCleanupAll(PNOTIFY_SYNC lock, PLIST_ENTRY head)
{
    assert(lock == &sync && head == &list);
    observe_completion();
}
static NTSTATUS FsRtlOplockFsctrlEx(POPLOCK state, PIRP irp, ULONG count, ULONG flags)
{
    assert(state == &oplock && irp == &watched_irp && count == 3 && flags == 0x10);
    observe_completion();
    return native_status;
}
static NTSTATUS FsRtlCheckOplockEx(POPLOCK state, PIRP irp, ULONG flags, PVOID owner,
    POPLOCK_WAIT_COMPLETE_ROUTINE completion, POPLOCK_FS_PREPOST_IRP before_post)
{
    assert(state == &oplock && irp == &watched_irp && flags == 0x20);
    if (owner != NULL) {
        assert(owner == &context && completion == wait_complete && before_post == prepost);
        before_post(owner, irp);
        completion(owner, irp);
    } else {
        assert(completion == NULL && before_post == NULL);
    }
    observe_completion();
    return native_status;
}
static VOID FsRtlUninitializeOplock(POPLOCK state)
{
    assert(state == &oplock);
    observe_completion();
}

#include "fsrtl_completion.h"

BOOLEAN ext4win_notification_traverse(const VOID *target, PSECURITY_SUBJECT_CONTEXT subject)
{
    assert(target == &traversal);
    return ext4win_notification_check_traverse(subject, (PSECURITY_DESCRIPTOR)target);
}

static VOID observe_completion(VOID)
{
    /* Filter Manager must see recursion before an upper completion can query a name. */
    assert(top_level != NULL && top_level == expected_marker);
    completions++;
    if (nest_completion) {
        nest_completion = 0;
        ext4win_notify_cleanup_all(&sync, &list);
        assert(top_level == expected_marker);
    }
    if (native_exception != 0) {
        RaiseException((ULONG)native_exception, 0, 0, NULL);
    }
}

static VOID invoke(unsigned operation)
{
    switch (operation) {
    case 0: ext4win_notify_register(&sync, &list, &context, &name, 0x13, 1, &watched_irp, &original_subject); break;
    case 1: ext4win_notify_report(&sync, &list, &name, 6, 0x13, 2, &traversal); break;
    case 2: ext4win_notify_cleanup(&sync, &list, &context); break;
    case 3: ext4win_notify_cleanup_all(&sync, &list); break;
    case 4:
        assert(ext4win_oplock_fsctrl(&oplock, &watched_irp, 3, 0x10) == native_status);
        break;
    case 5:
        assert(ext4win_check_oplock(&oplock, &watched_irp, 0x20, &context,
            wait_complete, prepost) == native_status);
        break;
    case 6:
        assert(ext4win_check_oplock(&oplock, &watched_irp, 0x20,
            NULL, NULL, NULL) == native_status);
        break;
    case 7: ext4win_uninitialize_oplock(&oplock); break;
    default: assert(0);
    }
}

static VOID check(unsigned operation, PIRP incoming, NTSTATUS exception)
{
    unsigned before = completions;
    top_level = incoming;
    expected_marker = incoming != NULL ? incoming : (PIRP)FSRTL_FSP_TOP_LEVEL_IRP;
    native_exception = exception;
    __try {
        invoke(operation);
        assert(exception == 0);
    }
    __except (GetExceptionCode() == exception
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        assert(exception != 0);
    }
    assert(completions > before && top_level == incoming);
}

int main(void)
{
    unsigned operation;
    for (operation = 0; operation != 8; operation++) {
        check(operation, NULL, 0);
        check(operation, (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP, 0);
        check(operation, &incoming_irp, 0);
        check(operation, NULL, STATUS_INSUFFICIENT_RESOURCES);
        check(operation, &incoming_irp, UNEXPECTED_EXCEPTION);
    }
    nest_completion = 1;
    check(1, NULL, 0);
    nest_completion = 1;
    check(1, NULL, UNEXPECTED_EXCEPTION);

    /* An ordinary native failure is returned verbatim rather than raised or masked. */
    native_status = STATUS_INSUFFICIENT_RESOURCES;
    check(4, NULL, 0);
    check(5, &incoming_irp, 0);
    check(6, NULL, 0);
    traversal.allowed = 0;
    check(0, NULL, 0);
    assert(traverse_calls != 0 && traverse_calls == privilege_frees && subject_locks == 0);
    ext4win_notify_register(&sync, &list, &context, &name, 0x13, 1, &watched_irp, NULL);
    return 0;
}
