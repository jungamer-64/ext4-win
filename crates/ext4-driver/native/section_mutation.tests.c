/* The dispatcher oracle schedules higher-priority waiters at event signaling
 * or IRQL restoration, and checks the admission predicate they can observe. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _IRQL_requires_max_(level)
#define _Must_inspect_result_
#define _Inout_
#define _In_
#define TRUE 1
#define FALSE 0
#define NULL ((void *)0)
#define DISPATCH_LEVEL 2
#define APC_LEVEL 1
#define NotificationEvent 0
#define Executive 0
#define KernelMode 0
#define IO_NO_INCREMENT 0

typedef int BOOLEAN;
typedef void VOID;
typedef long LONG;
typedef unsigned char KIRQL;
typedef struct { BOOLEAN held; } KSPIN_LOCK;
typedef struct { BOOLEAN signaled; } KEVENT;

static KIRQL current_irql;
static VOID (*ready_waiters)(VOID);
static VOID (*ready_contender)(VOID);
static VOID (*waiting_owner)(VOID);
static volatile LONG *observed_state;
static unsigned waits;
static unsigned awakened;

static VOID schedule_waiters(VOID)
{
    if (ready_contender != NULL && current_irql < DISPATCH_LEVEL) {
        VOID (*run)(VOID) = ready_contender;
        ready_contender = NULL;
        run();
    }
    if (ready_waiters != NULL && current_irql < DISPATCH_LEVEL) {
        VOID (*run)(VOID) = ready_waiters;
        ready_waiters = NULL;
        run();
    }
}

static VOID KeInitializeSpinLock(KSPIN_LOCK *lock) { lock->held = FALSE; }
static VOID KeAcquireSpinLock(KSPIN_LOCK *lock, KIRQL *old_irql)
{
    assert(!lock->held);
    *old_irql = current_irql;
    current_irql = DISPATCH_LEVEL;
    lock->held = TRUE;
}
static VOID KeReleaseSpinLock(KSPIN_LOCK *lock, KIRQL old_irql)
{
    assert(lock->held && current_irql == DISPATCH_LEVEL);
    lock->held = FALSE;
    current_irql = old_irql;
    schedule_waiters();
}
static VOID KeInitializeEvent(KEVENT *event, unsigned type, BOOLEAN signaled)
{
    assert(type == NotificationEvent);
    event->signaled = signaled;
}
static VOID KeClearEvent(KEVENT *event) { event->signaled = FALSE; }
static LONG KeSetEvent(KEVENT *event, unsigned increment, BOOLEAN wait)
{
    LONG previous = event->signaled;
    assert(increment == IO_NO_INCREMENT && !wait);
    event->signaled = TRUE;
    /* A notification wakes every waiter; the predicate must already permit
     * progress even if another processor observes the signal immediately. */
    assert(observed_state != NULL && *observed_state == 0);
    schedule_waiters();
    return previous;
}
static LONG KeWaitForSingleObject(
    KEVENT *event, unsigned reason, unsigned mode, BOOLEAN alertable, VOID *timeout)
{
    assert(current_irql <= APC_LEVEL);
    assert(reason == Executive && mode == KernelMode && !alertable && timeout == NULL);
    /* Busy admission must actually block, rather than repeatedly return from
     * a still-signaled notification while starving the releasing owner. */
    assert(!event->signaled && waiting_owner != NULL);
    waits++;
    waiting_owner();
    assert(event->signaled);
    return 0;
}
static LONG InterlockedCompareExchange(volatile LONG *state, LONG replacement, LONG expected)
{
    LONG previous = *state;
    if (previous == expected) { *state = replacement; }
    return previous;
}
static LONG InterlockedExchange(volatile LONG *state, LONG replacement)
{
    LONG previous = *state;
    *state = replacement;
    schedule_waiters();
    return previous;
}

#include "section_mutation.h"

static EXT4WIN_SECTION_MUTATION mutation;

static VOID release_waiting_owner(VOID)
{
    assert(!mutation.Lock.held);
    ext4win_section_mutation_release(&mutation);
}

/* The first awakened requester starts a new mutation. Other awakened waiters
 * must see its reset event, never a delayed signal from the previous owner. */
static VOID wake_waiters_and_readmit(VOID)
{
    unsigned waiter;
    for (waiter = 0; waiter < 3; waiter++) {
        if (waiter == 0) {
            assert(ext4win_section_mutation_state(&mutation) == EXT4WIN_SECTION_MUTATION_IDLE);
            assert(mutation.Released.signaled);
            assert(ext4win_section_mutation_try_begin(&mutation));
        } else {
            assert(!ext4win_section_mutation_try_begin(&mutation));
            assert(!mutation.Released.signaled);
        }
        awakened++;
    }
}

/* Admission can compete as soon as idle becomes visible on another processor.
 * Its reset must not be overwritten by the preceding owner's later signal. */
static VOID readmit_contender(VOID)
{
    assert(ext4win_section_mutation_state(&mutation) == EXT4WIN_SECTION_MUTATION_IDLE);
    assert(ext4win_section_mutation_try_begin(&mutation));
    assert(!mutation.Released.signaled);
}

static VOID wake_waiters_behind_contender(VOID)
{
    unsigned waiter;
    for (waiter = 0; waiter < 3; waiter++) {
        assert(!ext4win_section_mutation_try_begin(&mutation));
        assert(!mutation.Released.signaled);
        awakened++;
    }
}

int main(VOID)
{
    unsigned iteration;
    ext4win_section_mutation_initialize(&mutation);
    observed_state = &mutation.State;
    assert(mutation.Released.signaled);
    assert(!ext4win_section_mutation_seal(&mutation));
    for (iteration = 0; iteration < 3; iteration++) {
        assert(ext4win_section_mutation_try_begin(&mutation));
        assert(ext4win_section_mutation_state(&mutation) == EXT4WIN_SECTION_MUTATION_PREPARING);
        assert(!mutation.Released.signaled);
        assert(!ext4win_section_mutation_try_begin(&mutation));
        if (iteration != 0) {
            assert(ext4win_section_mutation_seal(&mutation));
            assert(ext4win_section_mutation_state(&mutation) == EXT4WIN_SECTION_MUTATION_SEALED);
            assert(!mutation.Released.signaled);
            assert(!ext4win_section_mutation_seal(&mutation));
        }
        ready_waiters = wake_waiters_and_readmit;
        ext4win_section_mutation_release(&mutation);
        assert(ready_waiters == NULL && current_irql == 0 && !mutation.Lock.held);
        assert(ext4win_section_mutation_state(&mutation) == EXT4WIN_SECTION_MUTATION_PREPARING);
        assert(!mutation.Released.signaled);
        waiting_owner = release_waiting_owner;
        ext4win_section_mutation_begin(&mutation);
        assert(ext4win_section_mutation_state(&mutation) == EXT4WIN_SECTION_MUTATION_PREPARING);
        assert(!mutation.Released.signaled);
        ext4win_section_mutation_release(&mutation);
    }
    assert(waits == 3 && awakened == 9);
    assert(ext4win_section_mutation_try_begin(&mutation));
    ready_contender = readmit_contender;
    ready_waiters = wake_waiters_behind_contender;
    ext4win_section_mutation_release(&mutation);
    assert(ready_contender == NULL && ready_waiters == NULL && awakened == 12);
    assert(ext4win_section_mutation_state(&mutation) == EXT4WIN_SECTION_MUTATION_PREPARING);
    assert(!mutation.Released.signaled);
    ext4win_section_mutation_release(&mutation);
    assert(ext4win_section_mutation_state(&mutation) == EXT4WIN_SECTION_MUTATION_IDLE);
    assert(mutation.Released.signaled);
    return 0;
}
