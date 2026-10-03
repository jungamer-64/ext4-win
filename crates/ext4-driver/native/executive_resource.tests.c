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

typedef LONG NTSTATUS;
typedef struct { unsigned identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct { struct { NTSTATUS Status; } IoStatus; } IRP, *PIRP;
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)-1)
static PEXT4WIN_STORAGE_ADMISSION forward_storage;
static PDEVICE_OBJECT forward_lower;
static BOOLEAN forward_succeeds;
static NTSTATUS lower_status;

static BOOLEAN IoForwardIrpSynchronously(PDEVICE_OBJECT lower, PIRP irp)
{
    assert(lower == forward_lower);
    assert(irp->IoStatus.Status == STATUS_SUCCESS);
    assert(forward_storage->QueryRemoveState == 2);
    assert(!ext4win_storage_create_admitted(forward_storage));
    irp->IoStatus.Status = lower_status;
    return forward_succeeds;
}

#include "pnp_remove.h"

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
        storage.QueryRemoveState = 0;
        assert(ext4win_storage_create_admitted(&storage));
        ext4win_storage_cancel_query_remove(&storage);
        assert(ext4win_storage_prepare_query_remove(&storage));
        assert(!ext4win_storage_create_admitted(&storage));
        assert(!ext4win_storage_prepare_query_remove(&storage));
        ext4win_storage_cancel_query_remove(&storage);
        assert(storage.QueryRemoveState == 1);
        ext4win_storage_abort_query_remove(&storage);
        assert(ext4win_storage_create_admitted(&storage));
        assert(ext4win_storage_prepare_query_remove(&storage));
        assert(ext4win_storage_publish_query_remove(&storage));
        ext4win_storage_abort_query_remove(&storage);
        assert(storage.QueryRemoveState == 2);
        assert(!ext4win_storage_create_admitted(&storage));
        apc_depth = 2;
        expected_wait = FALSE;
        acquisition_succeeds = TRUE;
        assert(ext4win_storage_begin_submission(&storage));
        ext4win_storage_end_submission(&storage);
        assert(apc_depth == 2 && storage.Submissions.held == 0);
        ext4win_storage_cancel_query_remove(&storage);
        assert(ext4win_storage_create_admitted(&storage));
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
        ext4win_storage_cancel_query_remove(&storage);
        assert(!ext4win_storage_create_admitted(&storage));
        assert(!ext4win_storage_prepare_query_remove(&storage));
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
        storage.RemovalState = 0;
        assert(ext4win_storage_prepare_query_remove(&storage));
        assert(ext4win_storage_publish_query_remove(&storage));
        expected_wait = TRUE;
        ext4win_storage_remove(&storage, FALSE);
        ext4win_storage_cancel_query_remove(&storage);
        assert(!ext4win_storage_create_admitted(&storage));
        assert(ext4win_storage_removal_state(&storage) == 1);
    }
    {
        EXT4WIN_STORAGE_ADMISSION storage;
        DEVICE_OBJECT lower;
        IRP irp;
        storage.Submissions.held = 0;
        storage.RemovalState = 0;
        storage.QueryRemoveState = 2;
        lower.identity = 1;
        forward_storage = &storage;
        forward_lower = &lower;
        forward_succeeds = FALSE;
        lower_status = STATUS_SUCCESS;
        assert(ext4win_pnp_cancel_remove(&storage, &lower, &irp) == STATUS_INVALID_DEVICE_REQUEST);
        assert(storage.QueryRemoveState == 2);
        forward_succeeds = TRUE;
        lower_status = (NTSTATUS)-2;
        assert(ext4win_pnp_cancel_remove(&storage, &lower, &irp) == lower_status);
        assert(storage.QueryRemoveState == 2);
        lower_status = STATUS_SUCCESS;
        assert(ext4win_pnp_cancel_remove(&storage, &lower, &irp) == STATUS_SUCCESS);
        assert(ext4win_storage_create_admitted(&storage));
        storage.QueryRemoveState = 2;
        storage.RemovalState = 1;
        assert(ext4win_pnp_cancel_remove(&storage, &lower, &irp) == STATUS_SUCCESS);
        assert(!ext4win_storage_create_admitted(&storage));
        assert(storage.RemovalState == 1);
    }
    return 0;
}
