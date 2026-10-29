/* Exercise requestor subject locking and ext4 traversal callback selection. */
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

static IRP watched_irp;
static NOTIFY_SYNC sync;
static LIST_ENTRY list;
static STRING name;
static unsigned context;
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

static VOID wdk_sys_notify_change_directory(PNOTIFY_SYNC supplied_sync, PLIST_ENTRY supplied_list,
    PVOID supplied_context, PSTRING directory, BOOLEAN subtree, BOOLEAN ignore, ULONG filter,
    PIRP irp, PCHECK_FOR_TRAVERSE_ACCESS callback, PSECURITY_SUBJECT_CONTEXT subject)
{
    assert(supplied_sync == &sync && supplied_list == &list && supplied_context == &context);
    assert(directory == &name && subtree && !ignore && filter == 0x13 && irp == &watched_irp);
    if (subject == NULL) { assert(callback == NULL); }
    else { assert(callback != NULL); assert(callback(supplied_context, &traversal, subject) == traversal.allowed); }
}
#include "notification_access.h"
BOOLEAN ext4win_notification_traverse(const VOID *target, PSECURITY_SUBJECT_CONTEXT subject)
{
    assert(target == &traversal);
    return ext4win_notification_check_traverse(subject, (PSECURITY_DESCRIPTOR)target);
}
int main(void)
{
    ext4win_notify_register(&sync, &list, &context, &name, 0x13, 1, &watched_irp, &original_subject);
    traversal.allowed = 0;
    ext4win_notify_register(&sync, &list, &context, &name, 0x13, 1, &watched_irp, &original_subject);
    ext4win_notify_register(&sync, &list, &context, &name, 0x13, 1, &watched_irp, NULL);
    assert(traverse_calls == 2 && privilege_frees == 2 && subject_locks == 0);
    assert(!ext4win_notify_traverse(&context, NULL, &original_subject));
    assert(!ext4win_notify_traverse(&context, &traversal, NULL));
    return 0;
}
