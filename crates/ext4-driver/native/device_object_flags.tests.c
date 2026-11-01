#include <stddef.h>
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
#define assert(value) do { if (!(value)) { ExitProcess(__LINE__); } } while (0)
#define _IRQL_requires_max_(level)
#define _In_
#define NTAPI __stdcall
#define C_ASSERT(value) _Static_assert(value, #value)
#define FIELD_OFFSET(type, field) offsetof(type, field)
#define TYPE_ALIGNMENT(type) _Alignof(type)
typedef unsigned long ULONG;
typedef struct { ULONG Flags; } DEVICE_OBJECT, *PDEVICE_OBJECT;
static const ULONG *observed_flags;
static unsigned reads;
static ULONG ReadULongNoFence(const ULONG *flags)
{
    assert(flags == observed_flags);
    ++reads;
    return *flags;
}
#include "device_object_flags.h"
int main(void)
{
    DEVICE_OBJECT device = { 0x4010 };
    observed_flags = &device.Flags;
    assert(ext4win_device_flags(&device) == 0x4010 && reads == 1);
    assert(device.Flags == 0x4010);
    device.Flags |= 2;
    assert(ext4win_device_flags(&device) == 0x4012 && reads == 2);
    assert(device.Flags == 0x4012);
    return 0;
}
