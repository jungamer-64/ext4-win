/* Execute the production acquisition boundary against an APC-aware WDK oracle.
 * The oracle models only the documented acquisition precondition and scope
 * nesting; live Driver Verifier remains the authority for kernel behavior. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)

#define _IRQL_requires_max_(level)
#define _IRQL_requires_(level)
#define _When_(condition, annotation)
#define _Requires_lock_held_(lock)
#define _Releases_lock_(lock)
#define _Inout_
#define _In_
#define FALSE 0
#define TRUE 1

typedef int BOOLEAN;
typedef void VOID;
typedef long LONG;
typedef struct {
    unsigned held;
} ERESOURCE, *PERESOURCE;

static unsigned apc_depth;
static BOOLEAN acquisition_succeeds;
static BOOLEAN expected_wait;
static unsigned acquisitions;
static unsigned releases;

static VOID KeEnterCriticalRegion(void) { apc_depth++; }
static VOID KeLeaveCriticalRegion(void)
{
    assert(apc_depth != 0);
    apc_depth--;
}

static BOOLEAN acquire(PERESOURCE resource, BOOLEAN wait)
{
    assert(apc_depth != 0);
    assert(wait == expected_wait);
    acquisitions++;
    if (acquisition_succeeds) { resource->held++; }
    return acquisition_succeeds;
}

static BOOLEAN ExAcquireResourceSharedLite(PERESOURCE resource, BOOLEAN wait)
{
    return acquire(resource, wait);
}
static BOOLEAN ExAcquireResourceExclusiveLite(PERESOURCE resource, BOOLEAN wait)
{
    return acquire(resource, wait);
}
static VOID ExReleaseResourceLite(PERESOURCE resource)
{
    assert(apc_depth != 0);
    assert(resource->held != 0);
    resource->held--;
    releases++;
}

#include "executive_resource.h"

static LONG InterlockedCompareExchange(volatile LONG *target, LONG replacement, LONG expected)
{
    LONG previous = *target;
    if (previous == expected) { *target = replacement; }
    return previous;
}
static LONG InterlockedExchange(volatile LONG *target, LONG replacement)
{
    LONG previous = *target;
    *target = replacement;
    return previous;
}

#include "storage_admission.h"

int main(void)
{
    unsigned incoming;
    BOOLEAN exclusive, wait;
    for (incoming = 0; incoming < 3; incoming++) {
        for (exclusive = FALSE; exclusive <= TRUE; exclusive++) {
            for (wait = FALSE; wait <= TRUE; wait++) {
                ERESOURCE resource;
                resource.held = 0;
                apc_depth = incoming;
                acquisition_succeeds = TRUE;
                expected_wait = wait;
                assert((exclusive
                    ? ext4win_acquire_resource_exclusive(&resource, wait)
                    : ext4win_acquire_resource_shared(&resource, wait)) == TRUE);
                assert(apc_depth == incoming + 1 && resource.held == 1);
                ext4win_release_resource(&resource);
                assert(apc_depth == incoming && resource.held == 0);

                if (!wait) {
                    acquisition_succeeds = FALSE;
                    assert((exclusive
                        ? ext4win_acquire_resource_exclusive(&resource, wait)
                        : ext4win_acquire_resource_shared(&resource, wait)) == FALSE);
                    assert(apc_depth == incoming && resource.held == 0);
                }
            }
        }
    }
    {
        ERESOURCE main_resource, paging_resource;
        main_resource.held = 0;
        paging_resource.held = 0;
        apc_depth = 1;
        acquisition_succeeds = TRUE;
        expected_wait = TRUE;
        assert(ext4win_acquire_resource_shared(&main_resource, TRUE));
        assert(ext4win_acquire_resource_exclusive(&paging_resource, TRUE));
        assert(apc_depth == 3);
        ext4win_release_resource(&paging_resource);
        assert(apc_depth == 2 && main_resource.held == 1);
        ext4win_release_resource(&main_resource);
        assert(apc_depth == 1 && main_resource.held == 0);
    }
    assert(acquisitions == 20 && releases == 14);
    {
        EXT4WIN_STORAGE_ADMISSION storage;
        storage.Submissions.held = 0;
        storage.RemovalState = 0;
        apc_depth = 2;
        expected_wait = FALSE;
        acquisition_succeeds = FALSE;
        assert(!ext4win_storage_begin_submission(&storage));
        assert(apc_depth == 2 && storage.Submissions.held == 0);
        assert(ext4win_storage_removal_state(&storage) == 0);
        acquisition_succeeds = TRUE;
        assert(ext4win_storage_begin_submission(&storage));
        assert(apc_depth == 3 && storage.Submissions.held == 1);
        ext4win_storage_end_submission(&storage);
        assert(apc_depth == 2 && storage.Submissions.held == 0);
        expected_wait = TRUE;
        ext4win_storage_remove(&storage, FALSE);
        assert(ext4win_storage_removal_state(&storage) == 1);
        assert(apc_depth == 2 && storage.Submissions.held == 0);
        expected_wait = FALSE;
        assert(!ext4win_storage_begin_submission(&storage));
        assert(apc_depth == 2 && storage.Submissions.held == 0);
        expected_wait = TRUE;
        ext4win_storage_remove(&storage, TRUE);
        ext4win_storage_remove(&storage, FALSE);
        assert(ext4win_storage_removal_state(&storage) == 2);
        expected_wait = FALSE;
        assert(!ext4win_storage_begin_submission(&storage));
        assert(apc_depth == 2 && storage.Submissions.held == 0);
        storage.RemovalState = 0;
        expected_wait = TRUE;
        ext4win_storage_remove(&storage, TRUE);
        assert(ext4win_storage_removal_state(&storage) == 2);
        expected_wait = FALSE;
        assert(!ext4win_storage_begin_submission(&storage));
        assert(apc_depth == 2 && storage.Submissions.held == 0);
    }
    return 0;
}
