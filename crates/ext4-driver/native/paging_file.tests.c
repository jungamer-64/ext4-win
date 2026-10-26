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
typedef struct { int Identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
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
typedef struct {
    struct { NTSTATUS Status; size_t Information; } IoStatus;
    unsigned RequestorMode, Flags, Cancel;
    MDL *MdlAddress;
    void *UserBuffer;
    IO_STACK_LOCATION Stack[2];
} IRP, *PIRP;
static DEVICE_OBJECT lower;
static unsigned calls, completions, allocations, frees, deny_allocation;
static unsigned physical_charges, request_charges;
static ULONGLONG charged_reads, charged_writes;
static unsigned raise_copy;
static NTSTATUS lower_result = STATUS_PENDING;
static unsigned long long pool[4];
static IO_STACK_LOCATION *IoGetCurrentIrpStackLocation(PIRP irp) { return &irp->Stack[0]; }
static IO_STACK_LOCATION *IoGetNextIrpStackLocation(PIRP irp) { return &irp->Stack[1]; }
static void IoMarkIrpPending(PIRP irp) { irp->Stack[0].Control |= 1; }
static void IoCopyCurrentIrpStackLocationToNext(PIRP irp) { irp->Stack[1] = irp->Stack[0]; irp->Stack[1].Control = 0; }
static ULONG MmGetMdlByteCount(MDL *mdl) { return mdl->ByteCount; }
static void IoCompleteRequest(PIRP irp, int increment) { (void)irp; assert(increment == 0); ++completions; }
static NTSTATUS IoCallDriver(PDEVICE_OBJECT device, PIRP irp) {
    assert(device == &lower && irp->MdlAddress != NULL);
    assert(irp->Stack[1].FileObject == NULL);
    assert(irp->Stack[1].Parameters.Read.ByteOffset.QuadPart == 1048576 + irp->Stack[0].Parameters.Read.ByteOffset.QuadPart);
    assert(irp->Stack[1].Parameters.Read.Length == irp->Stack[0].Parameters.Read.Length);
    ++calls;
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
static VOID NTAPI ext4win_account_request_io(PIRP irp, ULONGLONG read, ULONGLONG written, ULONG flush) {
    assert(flush == 0);
    assert(read == (irp->Stack[0].MajorFunction == IRP_MJ_READ ? 4096 : 0));
    assert(written == (irp->Stack[0].MajorFunction == IRP_MJ_WRITE ? 4096 : 0));
    charged_reads += read;
    charged_writes += written;
    ++request_charges;
}
#include "paging_file.h"

int main(void) {
    EXT4WIN_PAGING_FILE map = { 1, &lower, 1048576, 65536, 512 };
    MDL mdl = { 4096 };
    unsigned operation, scenario;
    NTSTATUS result;
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
    return 0;
}
