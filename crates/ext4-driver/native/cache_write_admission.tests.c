/* Execute the production Cc admission protocol with immediate and deferred
 * callback delivery. Cache Manager pressure itself remains a live-kernel contract. */
#include <stdint.h>
#include <stddef.h>
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _IRQL_requires_(level)
#define PASSIVE_LEVEL 0
#define FALSE 0
#define TRUE 1
#define UNREFERENCED_PARAMETER(value) ((void)(value))
#define IO_NO_INCREMENT 0
#define NotificationEvent 0
#define Executive 0
#define KernelMode 0
typedef void VOID;
typedef void *PVOID;
typedef uint32_t ULONG;
typedef uint8_t BOOLEAN;
typedef struct { BOOLEAN Initialized; BOOLEAN Signaled; } KEVENT, *PKEVENT;
typedef struct { ULONG Identity; } FILE_OBJECT, *PFILE_OBJECT;
typedef VOID (*PCC_POST_DEFERRED_WRITE)(PVOID, PVOID);

static FILE_OBJECT file = { 7 };
static ULONG calls, deferred, waits, callbacks, accepted_call;
static BOOLEAN immediate;
static BOOLEAN expected_wait = TRUE;
static PCC_POST_DEFERRED_WRITE pending;
static PVOID pending_context;
static PVOID pending_file;

static BOOLEAN CcCanIWrite(PFILE_OBJECT object, ULONG length, BOOLEAN wait, BOOLEAN retrying) {
    assert(object == &file && length == 4096 && wait == expected_wait);
    assert(retrying == (calls != 0));
    return ++calls == accepted_call;
}
static VOID KeInitializeEvent(PKEVENT event, int kind, BOOLEAN state) {
    assert(kind == NotificationEvent && state == FALSE && pending == NULL);
    event->Initialized = TRUE; event->Signaled = state;
}
static int KeSetEvent(PKEVENT event, int priority, BOOLEAN wait) {
    assert(event->Initialized && !event->Signaled && priority == 0 && !wait);
    event->Signaled = TRUE; callbacks++;
    return 0;
}
static VOID deliver(void) {
    PCC_POST_DEFERRED_WRITE callback = pending;
    PVOID context = pending_context;
    PVOID object = pending_file;
    assert(context != NULL && object == &file);
    pending = NULL; pending_context = NULL; pending_file = NULL;
    callback(context, object);
}
static VOID CcDeferWrite(PFILE_OBJECT object, PCC_POST_DEFERRED_WRITE callback, PVOID context, PVOID second_context, ULONG length, BOOLEAN retrying) {
    assert(object == &file && length == 4096 && context != NULL && second_context == object && pending == NULL);
    assert(retrying == (deferred != 0));
    deferred++; pending = callback; pending_context = context; pending_file = second_context;
    if (immediate) { deliver(); }
}
static int KeWaitForSingleObject(PKEVENT event, int reason, int mode, BOOLEAN alertable, PVOID timeout) {
    assert(reason == Executive && mode == KernelMode && !alertable && timeout == NULL);
    waits++;
    if (pending != NULL) { assert(pending_context == event); deliver(); }
    assert(event->Signaled && callbacks == waits);
    return 0;
}
#include "cache_write_admission.h"

int main(void) {
    EXT4WIN_CACHE_WRITE_ADMISSION admission = EXT4WIN_CACHE_WRITE_FIRST;
    accepted_call = 1;
    ext4win_cache_wait_for_write(&file, 4096, &admission);
    assert(calls == 1 && deferred == 0 && waits == 0 && callbacks == 0);
    expected_wait = FALSE;
    assert(!ext4win_cache_try_write(&file, 4096, FALSE, &admission));
    expected_wait = TRUE; accepted_call = 4;
    ext4win_cache_wait_for_write(&file, 4096, &admission);
    assert(calls == 4 && deferred == 1 && waits == 1 && callbacks == 1);
    for (immediate = FALSE; immediate <= TRUE; immediate++) {
        calls = deferred = waits = callbacks = 0; accepted_call = 3;
        admission = EXT4WIN_CACHE_WRITE_FIRST;
        ext4win_cache_wait_for_write(&file, 4096, &admission);
        assert(calls == 3 && deferred == 2 && waits == 2 && callbacks == 2 && pending == NULL);
    }
    return 0;
}
