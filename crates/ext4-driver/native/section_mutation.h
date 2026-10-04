#ifndef EXT4WIN_SECTION_MUTATION_H
#define EXT4WIN_SECTION_MUTATION_H

#define EXT4WIN_SECTION_MUTATION_IDLE ((LONG)0)
#define EXT4WIN_SECTION_MUTATION_PREPARING ((LONG)1)
#define EXT4WIN_SECTION_MUTATION_SEALED ((LONG)2)

/* State is the admission predicate; Released is its notification projection.
 * Admission/reset and release/signal share Lock so an earlier release cannot
 * signal a newly admitted mutation. Idle is published before waking waiters:
 * a higher-priority waiter must never spin on a signaled, still-busy predicate.
 * PREPARING permits paging needed by Cc/MM; SEALED excludes new paging. */
typedef struct _EXT4WIN_SECTION_MUTATION {
    KSPIN_LOCK Lock;
    volatile LONG State;
    KEVENT Released;
} EXT4WIN_SECTION_MUTATION, *PEXT4WIN_SECTION_MUTATION;

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ext4win_section_mutation_initialize(_Inout_ PEXT4WIN_SECTION_MUTATION mutation)
{
    KeInitializeSpinLock(&mutation->Lock);
    mutation->State = EXT4WIN_SECTION_MUTATION_IDLE;
    KeInitializeEvent(&mutation->Released, NotificationEvent, TRUE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static LONG
ext4win_section_mutation_state(_In_ PEXT4WIN_SECTION_MUTATION mutation)
{
    return InterlockedCompareExchange(
        &mutation->State,
        EXT4WIN_SECTION_MUTATION_IDLE,
        EXT4WIN_SECTION_MUTATION_IDLE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static BOOLEAN
ext4win_section_mutation_try_begin(_Inout_ PEXT4WIN_SECTION_MUTATION mutation)
{
    KIRQL old_irql;
    BOOLEAN admitted = FALSE;
    KeAcquireSpinLock(&mutation->Lock, &old_irql);
    if (ext4win_section_mutation_state(mutation) == EXT4WIN_SECTION_MUTATION_IDLE) {
        KeClearEvent(&mutation->Released);
        (VOID)InterlockedExchange(&mutation->State, EXT4WIN_SECTION_MUTATION_PREPARING);
        admitted = TRUE;
    }
    KeReleaseSpinLock(&mutation->Lock, old_irql);
    return admitted;
}

_IRQL_requires_max_(APC_LEVEL)
static VOID
ext4win_section_mutation_begin(_Inout_ PEXT4WIN_SECTION_MUTATION mutation)
{
    while (!ext4win_section_mutation_try_begin(mutation)) {
        (VOID)KeWaitForSingleObject(&mutation->Released, Executive, KernelMode, FALSE, NULL);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static BOOLEAN
ext4win_section_mutation_seal(_Inout_ PEXT4WIN_SECTION_MUTATION mutation)
{
    KIRQL old_irql;
    BOOLEAN sealed;
    KeAcquireSpinLock(&mutation->Lock, &old_irql);
    sealed = InterlockedCompareExchange(
        &mutation->State,
        EXT4WIN_SECTION_MUTATION_SEALED,
        EXT4WIN_SECTION_MUTATION_PREPARING) == EXT4WIN_SECTION_MUTATION_PREPARING;
    KeReleaseSpinLock(&mutation->Lock, old_irql);
    return sealed;
}

/* Only the admitted mutation owner releases, after either preparation failure
 * or committed publication. Every observer rechecks its admission predicate. */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ext4win_section_mutation_release(_Inout_ PEXT4WIN_SECTION_MUTATION mutation)
{
    KIRQL old_irql;
    KeAcquireSpinLock(&mutation->Lock, &old_irql);
    (VOID)InterlockedExchange(&mutation->State, EXT4WIN_SECTION_MUTATION_IDLE);
    KeSetEvent(&mutation->Released, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&mutation->Lock, old_irql);
}

#endif
