/* Native original-IRP transport and kernel pointer-return ABI. Rust owns map policy. */
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
#define STATUS_ACCESS_VIOLATION ((long)0xc0000005)
#define STATUS_CONTINUE_COMPLETION STATUS_SUCCESS
#define UNREFERENCED_PARAMETER(value) ((void)(value))
#define POOL_FLAG_NON_PAGED 1
#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS 1
unsigned long __cdecl _exception_code(void);
#define GetExceptionCode() ((long)_exception_code())
typedef long NTSTATUS;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef unsigned long ULONG;
typedef unsigned char UCHAR, BOOLEAN;
typedef void *PVOID, *PFILE_OBJECT;
typedef void VOID;
typedef struct _IRP IRP, *PIRP;
typedef struct { int Identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef NTSTATUS (NTAPI *COMPLETION)(PDEVICE_OBJECT, PIRP, PVOID);
typedef NTSTATUS (NTAPI IO_COMPLETION_ROUTINE)(PDEVICE_OBJECT, PIRP, PVOID);
typedef struct { LONGLONG QuadPart; } LARGE_INTEGER;
typedef struct { ULONG ByteCount; } MDL;
typedef struct {
    UCHAR MajorFunction, MinorFunction, Control;
    PFILE_OBJECT FileObject;
    union {
        struct { ULONG Length; LARGE_INTEGER ByteOffset; } Read;
        struct { ULONG InputBufferLength, OutputBufferLength, FsControlCode; void *Type3InputBuffer; } FileSystemControl;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
struct _IRP {
    struct { NTSTATUS Status; size_t Information; } IoStatus;
    unsigned RequestorMode, Flags;
    MDL *MdlAddress;
    void *UserBuffer;
    IO_STACK_LOCATION Stack[2];
    COMPLETION Completion;
    PVOID Context;
};
static DEVICE_OBJECT lower;
static unsigned state_identity, file_identity;
static unsigned calls, completions, allocations, frees, deny_allocation, raise_copy;
static unsigned references, dereferences, obligations, hold_completion, physical_charges, request_charges;
static BOOLEAN observed_valid, observed_available;
static UCHAR selected_action = 2;
static NTSTATUS selected_status = STATUS_INVALID_PARAMETER;
static BOOLEAN query_admitted = TRUE;
static unsigned long long pool[4];
static IO_STACK_LOCATION *IoGetCurrentIrpStackLocation(PIRP irp) { return &irp->Stack[0]; }
static IO_STACK_LOCATION *IoGetNextIrpStackLocation(PIRP irp) { return &irp->Stack[1]; }
static void IoMarkIrpPending(PIRP irp) { irp->Stack[0].Control |= 1; }
static void IoCopyCurrentIrpStackLocationToNext(PIRP irp) { irp->Stack[1] = irp->Stack[0]; irp->Stack[1].Control = 0; }
static ULONG MmGetMdlByteCount(MDL *mdl) { return mdl->ByteCount; }
static VOID ObReferenceObject(PVOID file) { assert(file == &file_identity); ++references; }
static VOID ObDereferenceObject(PVOID file) { assert(file == &file_identity); ++dereferences; }
static __declspec(noreturn) VOID NTAPI ext4win_paging_ownership_corruption(VOID) { ExitProcess(1); }
static VOID IoSetCompletionRoutine(PIRP irp, COMPLETION completion, PVOID context, BOOLEAN success, BOOLEAN error, BOOLEAN cancel) {
    assert(success && error && cancel); irp->Completion = completion; irp->Context = context;
}
static void IoCompleteRequest(PIRP irp, int increment) { assert(irp != NULL && increment == 0); ++completions; }
static NTSTATUS IoCallDriver(PDEVICE_OBJECT device, PIRP irp) {
    assert(device == &lower && irp->MdlAddress != NULL && irp->Stack[0].Control == 1);
    assert(irp->Stack[0].FileObject == &file_identity && irp->Stack[1].FileObject == NULL);
    assert(irp->Stack[0].Parameters.Read.ByteOffset.QuadPart == 4096);
    assert(irp->Stack[1].Parameters.Read.ByteOffset.QuadPart == 1052672);
    assert(irp->Stack[1].Parameters.Read.Length == 4096);
    ++calls;
    if (!hold_completion) { assert(irp->Completion(device, irp, irp->Context) == STATUS_CONTINUE_COMPLETION); }
    return STATUS_SUCCESS;
}
static __declspec(noinline) void RtlCopyMemory(void *out, const void *input, size_t length) {
    size_t i;
    if (raise_copy) { RaiseException((ULONG)STATUS_ACCESS_VIOLATION, 0, 0, NULL); }
    for (i = 0; i < length; ++i) { ((unsigned char *)out)[i] = ((const unsigned char *)input)[i]; }
}
static void *ExAllocatePool2(unsigned flags, size_t length, ULONG tag) {
    assert(flags == POOL_FLAG_NON_PAGED && length == sizeof(pool) && tag == 0x50703445UL);
    ++allocations; return deny_allocation ? NULL : pool;
}
static void ExFreePool(void *value) { assert(value == pool); ++frees; }
static VOID NTAPI ext4win_account_lower_io(PIRP irp) { assert(irp->Stack[1].FileObject == NULL); ++physical_charges; }
static VOID NTAPI ext4win_account_paging_io(PIRP irp, ULONGLONG read, ULONGLONG written, ULONG flush) {
    assert(flush == 0);
    assert(read == (irp->Stack[0].MajorFunction == IRP_MJ_READ ? 4096 : 0));
    assert(written == (irp->Stack[0].MajorFunction == IRP_MJ_WRITE ? 4096 : 0));
    ++request_charges;
}
UCHAR NTAPI ext4win_paging_begin(const VOID *state, LONGLONG offset, ULONG length, BOOLEAN valid,
    BOOLEAN available, NTSTATUS *status, PDEVICE_OBJECT *target, LONGLONG *physical) {
    assert(state == &state_identity && offset == 4096 && length == 4096);
    observed_valid = valid; observed_available = available;
    *status = selected_status;
    if (selected_action == 2) { *target = &lower; *physical = 1052672; ++obligations; }
    return selected_action;
}
VOID NTAPI ext4win_paging_complete_transfer(const VOID *state) {
    assert(state == &state_identity && obligations != 0); --obligations;
}
BOOLEAN NTAPI ext4win_paging_query_prefix(const VOID *state, LONGLONG requested, LONGLONG *physical) {
    assert(state == &state_identity && requested == 65536); *physical = 1048576; return query_admitted;
}
#include "paging_file.h"

int main(void) {
    IRP irp = {0};
    MDL mdl = {4096};
    NTSTATUS result;
    unsigned mode;
    for (mode = 0; mode < 2; ++mode) {
        irp.RequestorMode = KernelMode; irp.Flags = IRP_PAGING_IO; irp.MdlAddress = &mdl;
        irp.Stack[0].MajorFunction = mode ? IRP_MJ_WRITE : IRP_MJ_READ;
        irp.Stack[0].FileObject = &file_identity;
        irp.Stack[0].Parameters.Read.ByteOffset.QuadPart = 4096;
        irp.Stack[0].Parameters.Read.Length = 4096;
        irp.Stack[0].Control = 0;
        assert(ext4win_paging_dispatch(&state_identity, &irp, TRUE, &result));
        assert(result == STATUS_PENDING && obligations == 0 && references == dereferences);
        assert(observed_valid && observed_available && allocations == 0);
    }
    assert(calls == 2 && physical_charges == 2 && request_charges == 2);
    hold_completion = 1; irp.Stack[0].Control = 0;
    assert(ext4win_paging_dispatch(&state_identity, &irp, TRUE, &result));
    assert(result == STATUS_PENDING && obligations == 1 && references == dereferences + 1);
    assert(irp.Completion(&lower, &irp, irp.Context) == STATUS_CONTINUE_COMPLETION);
    assert(obligations == 0 && references == dereferences);
    selected_action = 0;
    assert(!ext4win_paging_dispatch(&state_identity, &irp, TRUE, &result));
    assert(references == dereferences && calls == 3);
    selected_action = 1; irp.MdlAddress = NULL;
    assert(ext4win_paging_dispatch(&state_identity, &irp, FALSE, &result));
    assert(result == STATUS_INVALID_PARAMETER && !observed_valid && !observed_available);
    assert(references == dereferences && calls == 3);
    {
        LARGE_INTEGER requested = {65536};
        EXT4WIN_PAGING_MAPPING_PAIR *returned = NULL;
        irp.Stack[0].MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
        irp.Stack[0].Parameters.FileSystemControl.FsControlCode = FSCTL_QUERY_RETRIEVAL_POINTERS;
        irp.Stack[0].Parameters.FileSystemControl.InputBufferLength = sizeof(requested);
        irp.Stack[0].Parameters.FileSystemControl.OutputBufferLength = sizeof(returned);
        irp.Stack[0].Parameters.FileSystemControl.Type3InputBuffer = &requested;
        irp.UserBuffer = &returned;
        assert(ext4win_paging_dispatch(&state_identity, &irp, TRUE, &result));
        assert(result == STATUS_SUCCESS && returned == (PVOID)pool && irp.IoStatus.Information == 0);
        assert(returned[0].Length == 65536 && returned[0].PhysicalStart == 1048576);
        assert(returned[1].Length == 0 && returned[1].PhysicalStart == 0);
        ExFreePool(returned);
        query_admitted = FALSE;
        assert(ext4win_paging_dispatch(&state_identity, &irp, TRUE, &result));
        assert(result == STATUS_INVALID_PARAMETER && allocations == 1);
        query_admitted = TRUE; deny_allocation = TRUE;
        assert(ext4win_paging_dispatch(&state_identity, &irp, TRUE, &result));
        assert(result == STATUS_INSUFFICIENT_RESOURCES);
        deny_allocation = FALSE; raise_copy = TRUE;
        assert(ext4win_paging_dispatch(&state_identity, &irp, TRUE, &result));
        assert(result == STATUS_ACCESS_VIOLATION && allocations == 2);
        raise_copy = FALSE; irp.UserBuffer = (PVOID)1;
        assert(ext4win_paging_dispatch(&state_identity, &irp, TRUE, &result));
        assert(result == STATUS_ACCESS_VIOLATION && allocations == 3 && frees == 2);
        irp.UserBuffer = &returned; irp.RequestorMode = UserMode;
        assert(ext4win_paging_dispatch(&state_identity, &irp, TRUE, &result));
        assert(result == STATUS_INVALID_PARAMETER && allocations == 3);
    }
    return 0;
}
