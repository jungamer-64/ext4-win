#include <stddef.h>

__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) void __stdcall RaiseException(unsigned long, unsigned long, unsigned long, const unsigned long long *);
#define assert(value) do { if (!(value)) { ExitProcess(__LINE__); } } while (0)
#define _IRQL_requires_(level)
#define _In_
#define PASSIVE_LEVEL 0
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define STATUS_SUCCESS 0L
#define STATUS_INSUFFICIENT_RESOURCES ((long)0xc000009a)
#define FSRTL_VOLUME_MOUNT 1

typedef long NTSTATUS;
typedef struct { unsigned references; } VPB, *PVPB;
typedef struct { PVPB Vpb; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct { PVPB Vpb; } FILE_OBJECT, *PFILE_OBJECT;
unsigned long __cdecl _exception_code(void);
#define GetExceptionCode() ((NTSTATUS)_exception_code())
static VPB vpb = { 1 };
static DEVICE_OBJECT device = { &vpb };
static FILE_OBJECT file;
static unsigned allocations, notifications, releases, deny, raise_notification;
static NTSTATUS result;
static int FsRtlIsNtstatusExpected(NTSTATUS status)
{
    return status == result || status == STATUS_INSUFFICIENT_RESOURCES;
}
static PFILE_OBJECT IoCreateStreamFileObjectLite(PFILE_OBJECT source, PDEVICE_OBJECT target)
{
    assert(source == NULL && target == &device && vpb.references == 1);
    ++allocations;
    if (deny == 1) { return NULL; }
    if (deny == 2) { RaiseException((unsigned long)STATUS_INSUFFICIENT_RESOURCES, 0, 0, NULL); }
    /* Creation acquires the device's VPB reference; the filesystem supplies the file association. */
    ++target->Vpb->references;
    file.Vpb = NULL;
    return &file;
}
static NTSTATUS FsRtlNotifyVolumeEvent(PFILE_OBJECT target, unsigned event)
{
    assert(target == &file && target->Vpb == &vpb && event == FSRTL_VOLUME_MOUNT);
    assert(vpb.references == 2);
    ++notifications;
    if (raise_notification) { RaiseException((unsigned long)result, 0, 0, NULL); }
    return result;
}
static void ObDereferenceObject(PFILE_OBJECT target)
{
    assert(target == &file);
    if (target->Vpb != NULL) {
        assert(target->Vpb == &vpb && vpb.references == 2);
        --target->Vpb->references;
        target->Vpb = NULL;
    }
    ++releases;
}
#include "volume_event.h"

int main(void)
{
    assert(ext4win_notify_volume_mount(&device) == STATUS_SUCCESS);
    assert(allocations == 1 && notifications == 1 && releases == 1 && vpb.references == 1);
    result = (NTSTATUS)0xc000000d;
    assert(ext4win_notify_volume_mount(&device) == result);
    assert(allocations == 2 && notifications == 2 && releases == 2 && vpb.references == 1);
    raise_notification = 1;
    assert(ext4win_notify_volume_mount(&device) == result);
    assert(allocations == 3 && notifications == 3 && releases == 3 && vpb.references == 1);
    deny = 1;
    assert(ext4win_notify_volume_mount(&device) == STATUS_INSUFFICIENT_RESOURCES);
    assert(allocations == 4 && notifications == 3 && releases == 3 && vpb.references == 1);
    deny = 2;
    assert(ext4win_notify_volume_mount(&device) == STATUS_INSUFFICIENT_RESOURCES);
    assert(allocations == 5 && notifications == 3 && releases == 3 && vpb.references == 1);
    ExitProcess(0);
}
