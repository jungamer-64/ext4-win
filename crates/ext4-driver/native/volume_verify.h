#pragma once

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN ext4win_volume_requires_verify(_In_ PDEVICE_OBJECT device)
{
    return (InterlockedCompareExchange((volatile LONG *)&device->Flags, 0, 0)
        & (LONG)DO_VERIFY_VOLUME) != 0;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ext4win_verify_volume(_In_ PDEVICE_OBJECT device)
{
    return IoVerifyVolume(device, FALSE);
}

/* Caller retains the mounted association and revalidates it under the global VPB lock. */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ext4win_clear_verify_required(_In_ PDEVICE_OBJECT device)
{
    InterlockedAnd((volatile LONG *)&device->Flags, ~(LONG)DO_VERIFY_VOLUME);
}
