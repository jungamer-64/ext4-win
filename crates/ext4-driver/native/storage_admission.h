#ifndef EXT4WIN_STORAGE_ADMISSION_H
#define EXT4WIN_STORAGE_ADMISSION_H

/* Owned by the volume; node streams borrow this authority while the VCB retains them.
 * Removal waits only for IoCallDriver submission scopes, never for lower completion.
 * The dedicated resource avoids treating unrelated section contention as device removal. */
typedef struct _EXT4WIN_STORAGE_ADMISSION {
    ERESOURCE Submissions;
    volatile LONG RemovalState;
} EXT4WIN_STORAGE_ADMISSION, *PEXT4WIN_STORAGE_ADMISSION;

static LONG
ext4win_storage_removal_state(_Inout_ PEXT4WIN_STORAGE_ADMISSION storage)
{
    return InterlockedCompareExchange(&storage->RemovalState, 0, 0);
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
ext4win_storage_remove(_Inout_ PEXT4WIN_STORAGE_ADMISSION storage, _In_ BOOLEAN final_remove)
{
    ext4win_acquire_resource_exclusive(&storage->Submissions, TRUE);
    if (final_remove) { InterlockedExchange(&storage->RemovalState, 2); }
    else { (VOID)InterlockedCompareExchange(&storage->RemovalState, 1, 0); }
    ext4win_release_resource(&storage->Submissions);
}

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
ext4win_storage_begin_submission(_Inout_ PEXT4WIN_STORAGE_ADMISSION storage)
{
    if (!ext4win_acquire_resource_shared(&storage->Submissions, FALSE)) { return FALSE; }
    if (ext4win_storage_removal_state(storage) != 0) {
        ext4win_release_resource(&storage->Submissions);
        return FALSE;
    }
    return TRUE;
}

_IRQL_requires_max_(APC_LEVEL)
static VOID
ext4win_storage_end_submission(_Inout_ PEXT4WIN_STORAGE_ADMISSION storage)
{
    ext4win_release_resource(&storage->Submissions);
}

#endif
