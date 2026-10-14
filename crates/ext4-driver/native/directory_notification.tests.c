/* Exercise the production exception boundary with real user-mode SEH. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define NTAPI
#define NULL ((void *)0)
#define STATUS_SUCCESS 0
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AUL)
#define UNEXPECTED_EXCEPTION ((NTSTATUS)0xE0000001UL)
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define GetExceptionCode() ((NTSTATUS)__exception_code())

typedef int NTSTATUS;
typedef unsigned ULONG;
typedef unsigned long long ULONG_PTR;
typedef struct { unsigned identity; } NOTIFY_SYNC, *PNOTIFY_SYNC;

__declspec(dllimport) void __stdcall RaiseException(ULONG, ULONG, ULONG, const ULONG_PTR *);

static NOTIFY_SYNC allocation = { 7 };
static NTSTATUS allocation_exception;
static unsigned allocation_calls;

static void FsRtlNotifyInitializeSync(PNOTIFY_SYNC *sync)
{
    assert(*sync == NULL);
    allocation_calls++;
    if (allocation_exception != STATUS_SUCCESS) {
        RaiseException((ULONG)allocation_exception, 0, 0, NULL);
    }
    *sync = &allocation;
}

#include "directory_notification.h"

int main(void)
{
    PNOTIFY_SYNC sync = NULL;
    assert(ext4win_notify_initialize_sync(&sync) == STATUS_SUCCESS);
    assert(sync == &allocation && allocation_calls == 1);

    allocation_exception = STATUS_INSUFFICIENT_RESOURCES;
    sync = NULL;
    assert(ext4win_notify_initialize_sync(&sync) == STATUS_INSUFFICIENT_RESOURCES);
    assert(sync == NULL && allocation_calls == 2);

    /* An allocation failure leaves the unpublished state reusable. */
    allocation_exception = STATUS_SUCCESS;
    assert(ext4win_notify_initialize_sync(&sync) == STATUS_SUCCESS);
    assert(sync == &allocation && allocation_calls == 3);

    allocation_exception = UNEXPECTED_EXCEPTION;
    sync = NULL;
    __try {
        ext4win_notify_initialize_sync(&sync);
        assert(0);
    }
    __except (GetExceptionCode() == UNEXPECTED_EXCEPTION
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        assert(sync == NULL && allocation_calls == 4);
    }
    return 0;
}
