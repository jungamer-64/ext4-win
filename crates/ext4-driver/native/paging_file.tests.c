#include <stddef.h>
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) void __stdcall RaiseException(unsigned long, unsigned long, unsigned long, const unsigned long long *);
#define assert(condition) do { if (!(condition)) { ExitProcess(__LINE__); } } while (0)
#define TRUE 1
#define FALSE 0
#define UNALIGNED
#define NTAPI __stdcall
#define IO_NO_INCREMENT 0
#define KernelMode 0
#define UserMode 1
#define IRP_PAGING_IO 2
#define IRP_MJ_READ 3
#define IRP_MJ_WRITE 4
#define IRP_MJ_FILE_SYSTEM_CONTROL 9
#define IRP_MN_USER_FS_REQUEST 0
#define FSCTL_QUERY_RETRIEVAL_POINTERS 0x9003b
#define STATUS_SUCCESS 0L
#define STATUS_PENDING 0x103L
#define STATUS_INVALID_PARAMETER ((long)0xc000000d)
#define STATUS_INSUFFICIENT_RESOURCES ((long)0xc000009a)
#define STATUS_DEVICE_NOT_CONNECTED ((long)0xc000009d)
#define STATUS_ACCESS_VIOLATION ((long)0xc0000005)
#define STATUS_SHARING_VIOLATION ((long)0xc0000043)
#define STATUS_FILE_CLOSED ((long)0xc0000128)
#define STATUS_CONTINUE_COMPLETION STATUS_SUCCESS
#define MAXULONG 0xffffffffUL
#define NotificationEvent 0
#define Executive 0
#define UNREFERENCED_PARAMETER(value) ((void)(value))
#define POOL_FLAG_NON_PAGED 1
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS EXCEPTION_EXECUTE_HANDLER
unsigned long __cdecl _exception_code(void);
#define GetExceptionCode() ((long)_exception_code())
typedef long NTSTATUS, LONG;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef unsigned long ULONG;
typedef unsigned char BOOLEAN;
typedef void *PVOID;
typedef void VOID;
typedef void *PFILE_OBJECT;
typedef unsigned char KIRQL;
typedef unsigned long long KSPIN_LOCK;
typedef struct { unsigned Signaled; } KEVENT;
typedef struct _IRP IRP, *PIRP;
typedef struct { int Identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef NTSTATUS (NTAPI *COMPLETION)(PDEVICE_OBJECT, PIRP, PVOID);
typedef NTSTATUS (NTAPI IO_COMPLETION_ROUTINE)(PDEVICE_OBJECT, PIRP, PVOID);
typedef struct { LONGLONG QuadPart; } LARGE_INTEGER;
typedef struct { ULONG ByteCount; } MDL;
typedef struct {
    unsigned char MajorFunction, MinorFunction, Control;
    void *FileObject;
    union {
        struct { ULONG Length; LARGE_INTEGER ByteOffset; } Read;
        struct { ULONG InputBufferLength, OutputBufferLength, FsControlCode; void *Type3InputBuffer; } FileSystemControl;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
struct _IRP {
    struct { NTSTATUS Status; size_t Information; } IoStatus;
    unsigned RequestorMode, Flags, Cancel;
    MDL *MdlAddress;
    void *UserBuffer;
    IO_STACK_LOCATION Stack[2];
    COMPLETION Completion;
    PVOID Context;
};
static DEVICE_OBJECT lower;
static unsigned calls, completions, allocations, frees, deny_allocation;
static unsigned physical_charges, request_charges;
static ULONGLONG charged_reads, charged_writes;
static unsigned raise_copy;
static unsigned locks, references, dereferences, hold_completions;
static PIRP pending[2];
static unsigned pending_count;
static void (*wait_action)(void);
static NTSTATUS lower_result = STATUS_PENDING;
static unsigned long long pool[4];
static IO_STACK_LOCATION *IoGetCurrentIrpStackLocation(PIRP irp) { return &irp->Stack[0]; }
static IO_STACK_LOCATION *IoGetNextIrpStackLocation(PIRP irp) { return &irp->Stack[1]; }
static void IoMarkIrpPending(PIRP irp) { irp->Stack[0].Control |= 1; }
static void IoCopyCurrentIrpStackLocationToNext(PIRP irp) { irp->Stack[1] = irp->Stack[0]; irp->Stack[1].Control = 0; }
static ULONG MmGetMdlByteCount(MDL *mdl) { return mdl->ByteCount; }
static VOID KeInitializeSpinLock(KSPIN_LOCK *lock) { *lock = 0; }
static VOID KeAcquireSpinLock(KSPIN_LOCK *lock, KIRQL *irql) { (void)lock; assert(locks == 0); ++locks; *irql = 0; }
static VOID KeReleaseSpinLock(KSPIN_LOCK *lock, KIRQL irql) { (void)lock; (void)irql; assert(locks == 1); --locks; }
static VOID KeInitializeEvent(KEVENT *event, unsigned type, unsigned state) { assert(type == NotificationEvent); event->Signaled = state; }
static VOID KeClearEvent(KEVENT *event) { event->Signaled = 0; }
static LONG KeSetEvent(KEVENT *event, unsigned increment, unsigned wait) { assert(increment == 0 && !wait); event->Signaled = 1; return 0; }
static NTSTATUS KeWaitForSingleObject(KEVENT *event, unsigned reason, unsigned mode, unsigned alertable, void *timeout) {
    assert(locks == 0 && reason == Executive && mode == KernelMode && !alertable && timeout == NULL);
    if (!event->Signaled && wait_action != NULL) { wait_action(); }
    assert(event->Signaled);
    return STATUS_SUCCESS;
}
static VOID ObReferenceObject(PVOID file) { assert(file != NULL); ++references; }
static VOID ObDereferenceObject(PVOID file) { assert(file != NULL && locks == 0); ++dereferences; }
static __declspec(noreturn) VOID NTAPI ext4win_paging_ownership_corruption(VOID) { ExitProcess(1); }
static VOID IoSetCompletionRoutine(PIRP irp, COMPLETION completion, PVOID context, BOOLEAN success, BOOLEAN error, BOOLEAN cancel) {
    assert(success && error && cancel);
    irp->Completion = completion; irp->Context = context;
}
static void IoCompleteRequest(PIRP irp, int increment) { (void)irp; assert(increment == 0); ++completions; }
static NTSTATUS IoCallDriver(PDEVICE_OBJECT device, PIRP irp) {
    assert(device == &lower && irp->MdlAddress != NULL);
    assert(irp->Stack[1].FileObject == NULL);
    assert(irp->Stack[1].Parameters.Read.ByteOffset.QuadPart == 1048576 + irp->Stack[0].Parameters.Read.ByteOffset.QuadPart);
    assert(irp->Stack[1].Parameters.Read.Length == irp->Stack[0].Parameters.Read.Length);
    ++calls;
    if (hold_completions) { assert(pending_count < 2); pending[pending_count++] = irp; }
    else { assert(irp->Completion(device, irp, irp->Context) == STATUS_CONTINUE_COMPLETION); }
    return lower_result;
}
static __declspec(noinline) void RtlCopyMemory(void *out, const void *input, size_t length) {
    size_t i;
    if (raise_copy) { RaiseException((ULONG)STATUS_ACCESS_VIOLATION, 0, 0, NULL); }
    for (i = 0; i < length; ++i) { ((unsigned char *)out)[i] = ((const unsigned char *)input)[i]; }
}
static void *ExAllocatePool2(unsigned flags, size_t length, ULONG tag) {
    assert(flags == POOL_FLAG_NON_PAGED && length == sizeof(pool) && tag == 0x50703445UL);
    ++allocations;
    return deny_allocation ? NULL : pool;
}
static void ExFreePool(void *value) { assert(value == pool); ++frees; }
static VOID NTAPI ext4win_account_lower_io(PIRP irp) {
    assert(irp->Stack[1].FileObject == NULL);
    ++physical_charges;
}
static VOID NTAPI ext4win_account_paging_io(PIRP irp, ULONGLONG read, ULONGLONG written, ULONG flush) {
    assert(flush == 0);
    assert(read == (irp->Stack[0].MajorFunction == IRP_MJ_READ ? 4096 : 0));
    assert(written == (irp->Stack[0].MajorFunction == IRP_MJ_WRITE ? 4096 : 0));
    charged_reads += read;
    charged_writes += written;
    ++request_charges;
}
#include "paging_file.h"

static PEXT4WIN_PAGING_FILE retiring_map;
static void finish_retirement_work(void) {
    if (retiring_map->Active == EXT4WIN_PAGING_EXTENDING) {
        ext4win_paging_abort(retiring_map, TRUE);
    } else {
        assert(retiring_map->Active == EXT4WIN_PAGING_RETIRING);
        while (pending_count != 0) {
            PIRP irp = pending[--pending_count];
            assert(irp->Completion(&lower, irp, irp->Context) == STATUS_CONTINUE_COMPLETION);
        }
    }
}

int main(void) {
    EXT4WIN_PAGING_FILE map = { 0 };
    MDL mdl = { 4096 };
    unsigned operation, scenario;
    NTSTATUS result;
    ext4win_paging_initialize(&map);
    map.Active = EXT4WIN_PAGING_ACTIVE; map.Owner = &map;
    map.Lower = &lower; map.PhysicalStart = 1048576; map.Length = 65536; map.SectorSize = 512;
    for (scenario = 0; scenario < 3; ++scenario) {
    lower_result = scenario == 0 ? STATUS_SUCCESS : scenario == 1 ? STATUS_PENDING : STATUS_DEVICE_NOT_CONNECTED;
    for (operation = IRP_MJ_READ; operation <= IRP_MJ_WRITE; ++operation) {
        IRP irp = { 0 };
        unsigned completed_before = completions;
        irp.RequestorMode = KernelMode;
        irp.Flags = IRP_PAGING_IO;
        irp.Cancel = 1;
        irp.MdlAddress = &mdl;
        irp.Stack[0].MajorFunction = (unsigned char)operation;
        irp.Stack[0].FileObject = &map;
        irp.Stack[0].Parameters.Read.Length = 4096;
        irp.Stack[0].Parameters.Read.ByteOffset.QuadPart = 61440;
        assert(ext4win_paging_dispatch(&map, &irp, TRUE, &result));
        assert(result == STATUS_PENDING && irp.Cancel == 1);
        assert(irp.Stack[0].Control == 1 && irp.Stack[1].Control == 0);
        assert(irp.Stack[0].Parameters.Read.ByteOffset.QuadPart == 61440);
        assert(allocations == 0 && completions == completed_before);
        irp.Stack[0].Parameters.Read.ByteOffset.QuadPart = 65536;
        assert(ext4win_paging_dispatch(&map, &irp, TRUE, &result));
        assert(result == STATUS_INVALID_PARAMETER);
        irp.Stack[0].Parameters.Read.ByteOffset.QuadPart = 0;
        assert(ext4win_paging_dispatch(&map, &irp, FALSE, &result));
        assert(result == STATUS_DEVICE_NOT_CONNECTED);
        irp.Flags = 0;
        assert(ext4win_paging_dispatch(&map, &irp, TRUE, &result));
        assert(result == STATUS_INVALID_PARAMETER);
        assert(!ext4win_paging_dispatch(NULL, &irp, TRUE, &result));
    }
    }
    assert(calls == 6 && allocations == 0);
    assert(physical_charges == 6 && request_charges == 6);
    assert(charged_reads == 12288 && charged_writes == 12288);
    {
        IRP irp = { 0 };
        LONGLONG requested = 32768;
        EXT4WIN_PAGING_MAPPING_PAIR *returned = NULL;
        irp.RequestorMode = KernelMode;
        irp.UserBuffer = &returned;
        irp.Stack[0].MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
        irp.Stack[0].Parameters.FileSystemControl.FsControlCode = FSCTL_QUERY_RETRIEVAL_POINTERS;
        irp.Stack[0].Parameters.FileSystemControl.InputBufferLength = sizeof(LARGE_INTEGER);
        irp.Stack[0].Parameters.FileSystemControl.OutputBufferLength = sizeof(void *);
        irp.Stack[0].Parameters.FileSystemControl.Type3InputBuffer = &requested;
        assert(ext4win_paging_dispatch(&map, &irp, TRUE, &result));
        assert(result == STATUS_SUCCESS && returned != NULL);
        assert(returned[0].Length == requested && returned[0].PhysicalStart == 1048576);
        assert(returned[1].Length == 0 && returned[1].PhysicalStart == 0);
        assert(irp.IoStatus.Information == 0 && frees == 0);
        ExFreePool(returned);
        requested = 65537;
        assert(ext4win_paging_dispatch(&map, &irp, TRUE, &result));
        assert(result == STATUS_INVALID_PARAMETER && allocations == 1);
        requested = 0;
        assert(ext4win_paging_dispatch(&map, &irp, TRUE, &result));
        assert(result == STATUS_INVALID_PARAMETER && allocations == 1);
        requested = 65536;
        deny_allocation = 1;
        assert(ext4win_paging_dispatch(&map, &irp, TRUE, &result));
        assert(result == STATUS_INSUFFICIENT_RESOURCES && allocations == 2 && frees == 1);
        irp.RequestorMode = UserMode;
        assert(ext4win_paging_dispatch(&map, &irp, TRUE, &result));
        assert(result == STATUS_INVALID_PARAMETER && allocations == 2);
        irp.RequestorMode = KernelMode;
        deny_allocation = 0;
        raise_copy = 1;
        assert(ext4win_paging_dispatch(&map, &irp, TRUE, &result));
        assert(result == STATUS_ACCESS_VIOLATION && allocations == 2 && frees == 1);
    }
    {
        EXT4WIN_PAGING_FILE setup = { 0 };
        LONGLONG physical, length;
        IRP first = { 0 }, second = { 0 };
        ext4win_paging_initialize(&setup);
        assert(ext4win_paging_reserve(&setup, &setup, FALSE, &physical, &length) == STATUS_SUCCESS);
        assert(setup.Active == EXT4WIN_PAGING_PREPARING && physical == 0 && length == 0);
        assert(ext4win_paging_reserve(&setup, &setup, FALSE, &physical, &length) == STATUS_SHARING_VIOLATION);
        ext4win_paging_abort(&setup, FALSE);
        assert(setup.Active == EXT4WIN_PAGING_VACANT && setup.Owner == NULL);
        assert(ext4win_paging_reserve(&setup, &setup, FALSE, &physical, &length) == STATUS_SUCCESS);
        assert(ext4win_paging_activate(&setup, FALSE, &lower, 1048576, 65536, 512) == STATUS_SUCCESS);
        assert(ext4win_paging_reserve(&setup, &setup, TRUE, &physical, &length) == STATUS_SUCCESS);
        assert(physical == 1048576 && length == 65536);
        assert(ext4win_paging_activate(&setup, TRUE, &lower, 2097152, 131072, 512) == STATUS_INVALID_PARAMETER);
        assert(ext4win_paging_activate(&setup, TRUE, &lower, 1048576, 131072, 512) == STATUS_SUCCESS);
        assert(setup.Length == 131072);
        assert(ext4win_paging_mutation_allowed(&setup, FALSE, 0, 131072));
        assert(ext4win_paging_mutation_allowed(&setup, FALSE, 126976, 131072));
        assert(ext4win_paging_mutation_allowed(&setup, FALSE, 131072, 131072));
        assert(!ext4win_paging_mutation_allowed(&setup, FALSE, 0, 0));
        assert(!ext4win_paging_mutation_allowed(&setup, FALSE, -1, 131072));
        assert(!ext4win_paging_mutation_allowed(&setup, FALSE, 135168, 135168));
        assert(!ext4win_paging_mutation_allowed(&setup, TRUE, 0, 0));
        assert(setup.Length == 131072);
        hold_completions = 1;
        first.RequestorMode = KernelMode; first.Flags = IRP_PAGING_IO; first.MdlAddress = &mdl;
        first.Stack[0].MajorFunction = IRP_MJ_WRITE; first.Stack[0].FileObject = &setup;
        first.Stack[0].Parameters.Read.Length = 4096;
        second = first; second.Stack[0].MajorFunction = IRP_MJ_READ;
        assert(ext4win_paging_dispatch(&setup, &first, TRUE, &result));
        assert(ext4win_paging_dispatch(&setup, &second, TRUE, &result));
        assert(setup.InFlight == 2 && !setup.Idle.Signaled && references == dereferences + 2);
        assert(ext4win_paging_reserve(&setup, &setup, TRUE, &physical, &length) == STATUS_SUCCESS);
        ext4win_paging_retire(&setup, &lower);
        assert(setup.Active == EXT4WIN_PAGING_EXTENDING);
        retiring_map = &setup; wait_action = finish_retirement_work;
        ext4win_paging_retire(&setup, &setup);
        assert(setup.Active == EXT4WIN_PAGING_RETIRED && setup.InFlight == 0);
        assert(setup.Idle.Signaled && references == dereferences && pending_count == 0);
        assert(ext4win_paging_dispatch(&setup, &first, TRUE, &result));
        assert(result == STATUS_FILE_CLOSED && references == dereferences);
        assert(allocations == 2 && locks == 0);
    }
    return 0;
}
