/* ABI vectors and Object Manager capture, using the production requestor-context decoder. */
#include <stddef.h>
#include <stdint.h>

__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) void * __cdecl memcpy(void *, const void *, size_t);
#define assert(value) do { if (!(value)) { ExitProcess(__LINE__); } } while (0)
#define _IRQL_requires_max_(value)
#define NTAPI
#define NT_SUCCESS(value) ((value) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xc0000010)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022)
#define FSCTL_MOVE_FILE 0x90074U
#define FSCTL_MARK_HANDLE 0x900fcU
#define IRP_MJ_FILE_SYSTEM_CONTROL 13U
#define IRP_MN_USER_FS_REQUEST 0U
#define MARK_HANDLE_PROTECT_CLUSTERS 1U
#define RtlCopyMemory(target, source, width) copy_bytes((target), (source), (width))
#define UlongToHandle(value) ((HANDLE)(uintptr_t)(value))
typedef int NTSTATUS;
typedef unsigned ULONG, *PULONG, ACCESS_MASK, *PACCESS_MASK;
typedef unsigned long long ULONGLONG, *PULONGLONG;
typedef void *PVOID, *HANDLE;
typedef struct { long long QuadPart; } LARGE_INTEGER;
typedef struct { unsigned identity; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { ACCESS_MASK GrantedAccess; ULONG HandleAttributes; } OBJECT_HANDLE_INFORMATION;
typedef struct { HANDLE FileHandle; LARGE_INTEGER StartingVcn, StartingLcn; ULONG ClusterCount; } MOVE_FILE_DATA;
typedef struct { uint32_t FileHandle; LARGE_INTEGER StartingVcn, StartingLcn; ULONG ClusterCount; } MOVE_FILE_DATA32;
typedef struct { ULONG UsnSourceInfo; HANDLE VolumeHandle; ULONG HandleInfo; } MARK_HANDLE_INFO;
typedef struct { ULONG UsnSourceInfo; uint32_t VolumeHandle; ULONG HandleInfo; } MARK_HANDLE_INFO32;
typedef struct {
    unsigned char MajorFunction, MinorFunction;
    struct { struct { ULONG OutputBufferLength, InputBufferLength, FsControlCode; } FileSystemControl; } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
typedef struct { IO_STACK_LOCATION stack; struct { PVOID SystemBuffer; } AssociatedIrp; unsigned char RequestorMode; } IRP, *PIRP;
static unsigned wow64, references;
static NTSTATUS reference_status;
static FILE_OBJECT object;
static void *object_type;
static void **IoFileObjectType = &object_type;
static PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP irp) { return &irp->stack; }
static unsigned IoIs32bitProcess(PIRP irp) { (void)irp; return wow64; }
static void copy_bytes(void *target, const void *source, size_t width)
{
    size_t i;
    for (i = 0; i < width; i++) { ((unsigned char *)target)[i] = ((const unsigned char *)source)[i]; }
}
static NTSTATUS ObReferenceObjectByHandle(HANDLE handle, ACCESS_MASK desired, void *type,
    unsigned char mode, PVOID *result, OBJECT_HANDLE_INFORMATION *information)
{
    assert(handle == (HANDLE)(uintptr_t)0x44);
    assert(desired == 0 && type == object_type && mode == 1);
    references++;
    if (reference_status < 0) { return reference_status; }
    *result = &object;
    information->GrantedAccess = 0x123;
    return STATUS_SUCCESS;
}
#include "cluster_control_capture.h"

static void put32(unsigned char *bytes, unsigned offset, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4; i++) { bytes[offset+i] = (unsigned char)(value >> (i*8)); }
}
int main(void)
{
    IRP irp = {0};
    unsigned char input[32] = {0};
    PFILE_OBJECT file;
    ULONGLONG vcn, lcn;
    ULONG count, source, flags;
    ACCESS_MASK granted;
    unsigned mode;
    _Static_assert(sizeof(MOVE_FILE_DATA) == 32 && offsetof(MOVE_FILE_DATA, StartingVcn) == 8, "native MOVE ABI");
    _Static_assert(sizeof(MOVE_FILE_DATA32) == 32 && offsetof(MOVE_FILE_DATA32, StartingVcn) == 8, "WOW64 MOVE ABI");
    _Static_assert(sizeof(MARK_HANDLE_INFO) == 24 && sizeof(MARK_HANDLE_INFO32) == 12, "MARK ABIs");
    irp.stack.MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
    irp.RequestorMode = 1;
    irp.AssociatedIrp.SystemBuffer = input;
    for (mode = 0; mode < 2; mode++) {
        wow64 = mode;
        irp.stack.Parameters.FileSystemControl.FsControlCode = FSCTL_MOVE_FILE;
        irp.stack.Parameters.FileSystemControl.InputBufferLength = 32;
        put32(input, 0, 0x44); put32(input, 8, 7); put32(input, 16, 109); put32(input, 24, 3);
        assert(ext4win_capture_cluster_control(&irp, &file, &vcn, &lcn, &count, &source, &flags, &granted) == STATUS_SUCCESS);
        assert(file == &object && vcn == 7 && lcn == 109 && count == 3 && granted == 0x123);
        irp.stack.Parameters.FileSystemControl.InputBufferLength = 31;
        assert(ext4win_capture_cluster_control(&irp, &file, &vcn, &lcn, &count, &source, &flags, &granted) == STATUS_BUFFER_TOO_SMALL);
        irp.stack.Parameters.FileSystemControl.InputBufferLength = 32;
        put32(input, 12, 0x80000000U);
        assert(ext4win_capture_cluster_control(&irp, &file, &vcn, &lcn, &count, &source, &flags, &granted) == STATUS_INVALID_PARAMETER);
        put32(input, 12, 0); put32(input, 24, 0);
        assert(ext4win_capture_cluster_control(&irp, &file, &vcn, &lcn, &count, &source, &flags, &granted) == STATUS_INVALID_PARAMETER);
    }
    for (mode = 0; mode < 2; mode++) {
        unsigned i, before;
        wow64 = mode;
        for (i = 0; i < sizeof(input); i++) { input[i] = 0; }
        irp.stack.Parameters.FileSystemControl.FsControlCode = FSCTL_MARK_HANDLE;
        irp.stack.Parameters.FileSystemControl.InputBufferLength = mode ? 12 : 24;
        put32(input, mode ? 4 : 8, 0x44); put32(input, mode ? 8 : 16, 1);
        assert(ext4win_capture_cluster_control(&irp, &file, &vcn, &lcn, &count, &source, &flags, &granted) == STATUS_SUCCESS);
        assert(file == &object && source == 0 && flags == 1);
        put32(input, mode ? 4 : 8, 0);
        before = references;
        assert(ext4win_capture_cluster_control(&irp, &file, &vcn, &lcn, &count, &source, &flags, &granted) == STATUS_SUCCESS);
        assert(file == NULL && references == before);
        put32(input, 0, 1);
        assert(ext4win_capture_cluster_control(&irp, &file, &vcn, &lcn, &count, &source, &flags, &granted) == STATUS_NOT_SUPPORTED);
        assert(references == before);
    }
    reference_status = STATUS_ACCESS_DENIED;
    put32(input, 0, 0); put32(input, 4, 0x44);
    assert(ext4win_capture_cluster_control(&irp, &file, &vcn, &lcn, &count, &source, &flags, &granted) == STATUS_ACCESS_DENIED);
    assert(file == NULL);
    ExitProcess(0);
}
