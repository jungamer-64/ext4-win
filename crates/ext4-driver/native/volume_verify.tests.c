#include <stddef.h>
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
#define assert(value) do { if (!(value)) { ExitProcess(__LINE__); } } while (0)
#define _IRQL_requires_max_(level)
#define _IRQL_requires_(level)
#define _In_
#define FALSE 0
#define DO_VERIFY_VOLUME 2
#define VOID void
typedef long LONG;
typedef long NTSTATUS;
typedef unsigned char BOOLEAN;
typedef struct { unsigned long Flags; } DEVICE_OBJECT, *PDEVICE_OBJECT;
static PDEVICE_OBJECT observed_device;
static unsigned verify_calls, atomic_reads, atomic_changes;
static NTSTATUS verify_status;
static LONG InterlockedCompareExchange(volatile LONG *target, LONG value, LONG expected)
{
    LONG original = *target;
    ++atomic_reads;
    assert(value == 0 && expected == 0);
    if (original == expected) { *target = value; }
    return original;
}
static LONG InterlockedAnd(volatile LONG *target, LONG mask)
{
    LONG original = *target;
    ++atomic_changes;
    *target = original & mask;
    return original;
}
static NTSTATUS IoVerifyVolume(PDEVICE_OBJECT device, BOOLEAN allow_raw)
{
    assert(device == observed_device && allow_raw == FALSE);
    ++verify_calls;
    return verify_status;
}
#include "volume_verify.h"
int main(void)
{
    DEVICE_OBJECT device = { 0x4012 };
    observed_device = &device;
    assert(ext4win_volume_requires_verify(&device));
    assert(device.Flags == 0x4012 && atomic_reads == 1 && atomic_changes == 0);
    verify_status = (NTSTATUS)0xc0000012L;
    assert(ext4win_verify_volume(&device) == verify_status);
    assert(device.Flags == 0x4012 && atomic_changes == 0);
    verify_status = 0;
    assert(ext4win_verify_volume(&device) == 0 && verify_calls == 2);
    assert(device.Flags == 0x4012 && atomic_changes == 0);
    ext4win_clear_verify_required(&device);
    assert(device.Flags == 0x4010 && atomic_changes == 1);
    assert(!ext4win_volume_requires_verify(&device));
    assert(device.Flags == 0x4010 && atomic_reads == 2);
    return 0;
}
