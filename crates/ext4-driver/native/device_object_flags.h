#pragma once

C_ASSERT(sizeof(((DEVICE_OBJECT *)0)->Flags) == sizeof(ULONG));
C_ASSERT((FIELD_OFFSET(DEVICE_OBJECT, Flags) % TYPE_ALIGNMENT(ULONG)) == 0);

/* The retaining operation owns device lifetime. Transfer bits are fixed after
 * initialization, but the same word includes mutable native lifecycle bits.
 * This snapshot grants no lifecycle or memory-publication authority. */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG NTAPI ext4win_device_flags(_In_ PDEVICE_OBJECT device)
{
    return ReadULongNoFence(&device->Flags);
}
