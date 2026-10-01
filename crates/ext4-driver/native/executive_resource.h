#ifndef EXT4WIN_EXECUTIVE_RESOURCE_H
#define EXT4WIN_EXECUTIVE_RESOURCE_H

/* Resource ownership includes one normal-kernel-APC suppression scope. Failed
 * nonblocking acquisition restores the incoming APC state; successful callers
 * retain the scope until release, including acquire/release callback pairs. */
_IRQL_requires_max_(APC_LEVEL)
_When_(return != FALSE, _Acquires_lock_(_Global_critical_region_))
static BOOLEAN
ext4win_acquire_resource_shared(
    _Inout_ _When_(return != FALSE, _Acquires_shared_lock_(*_Curr_)) PERESOURCE resource,
    _In_ BOOLEAN wait)
{
    KeEnterCriticalRegion();
    if (ExAcquireResourceSharedLite(resource, wait)) {
        return TRUE;
    }
    KeLeaveCriticalRegion();
    return FALSE;
}

_IRQL_requires_max_(APC_LEVEL)
_When_(return != FALSE, _Acquires_lock_(_Global_critical_region_))
static BOOLEAN
ext4win_acquire_resource_exclusive(
    _Inout_ _When_(return != FALSE, _Acquires_exclusive_lock_(*_Curr_)) PERESOURCE resource,
    _In_ BOOLEAN wait)
{
    KeEnterCriticalRegion();
    if (ExAcquireResourceExclusiveLite(resource, wait)) {
        return TRUE;
    }
    KeLeaveCriticalRegion();
    return FALSE;
}

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_held_(_Global_critical_region_)
_Releases_lock_(_Global_critical_region_)
static VOID
ext4win_release_resource(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) PERESOURCE resource)
{
    ExReleaseResourceLite(resource);
    KeLeaveCriticalRegion();
}

#endif
