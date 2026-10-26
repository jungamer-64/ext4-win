#include <stddef.h>

__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
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
typedef void *PDEVICE_OBJECT;
typedef void *PFILE_OBJECT;
unsigned long __cdecl _exception_code(void);
#define GetExceptionCode() ((NTSTATUS)_exception_code())
static int device, file, allocations, notifications, releases, deny;
static NTSTATUS result;
static int FsRtlIsNtstatusExpected(NTSTATUS status) { return status == result; }
static PFILE_OBJECT IoCreateStreamFileObjectLite(PFILE_OBJECT source, PDEVICE_OBJECT target)
{
    assert(source == NULL && target == &device);
    ++allocations;
    return deny ? NULL : &file;
}
static NTSTATUS FsRtlNotifyVolumeEvent(PFILE_OBJECT target, unsigned event)
{
    assert(target == &file && event == FSRTL_VOLUME_MOUNT);
    ++notifications;
    return result;
}
static void ObDereferenceObject(PFILE_OBJECT target) { assert(target == &file); ++releases; }
#include "volume_event.h"

int main(void)
{
    assert(ext4win_notify_volume_mount(&device) == STATUS_SUCCESS);
    assert(allocations == 1 && notifications == 1 && releases == 1);
    result = (NTSTATUS)0xc000000d;
    assert(ext4win_notify_volume_mount(&device) == result);
    assert(allocations == 2 && notifications == 2 && releases == 2);
    deny = 1;
    assert(ext4win_notify_volume_mount(&device) == STATUS_INSUFFICIENT_RESOURCES);
    assert(allocations == 3 && notifications == 2 && releases == 2);
    ExitProcess(0);
}
