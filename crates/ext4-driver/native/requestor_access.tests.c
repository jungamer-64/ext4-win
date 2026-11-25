/* Exercise the production requestor-memory boundary with real hardware faults and probe
 * raises. Access violations and misalignment must be contained; instruction faults must
 * continue to an outer handler instead of becoming request failures. */
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) void __stdcall RaiseException(unsigned long, unsigned long, unsigned long, const unsigned long long *);
#define assert(value) do { if (!(value)) { ExitProcess(__LINE__); } } while (0)
#define _In_
#define _Out_
#define _Out_writes_bytes_(length)
#define _In_reads_bytes_(length)
#define _IRQL_requires_max_(level)
#define _Must_inspect_result_
#define NULL ((void *)0)
#define VOID void
#define NTAPI
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2
#define NT_SUCCESS(value) ((value) >= 0)
#define TYPE_ALIGNMENT(type) _Alignof(type)
#define IRP_MJ_FILE_SYSTEM_CONTROL 13
#define FSCTL_GET_RETRIEVAL_POINTERS 0x90073
#define FSCTL_GET_VOLUME_BITMAP 0x9006f
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define KernelMode 0
#define UserMode 1
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_DATATYPE_MISALIGNMENT ((NTSTATUS)0x80000002L)
#define STATUS_ACCESS_VIOLATION ((NTSTATUS)0xC0000005L)
#define STATUS_IN_PAGE_ERROR ((NTSTATUS)0xC0000006L)
#define STATUS_ILLEGAL_INSTRUCTION ((NTSTATUS)0xC000001DL)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_INSTRUCTION_MISALIGNMENT ((NTSTATUS)0xC00000AAL)
#define STATUS_INVALID_USER_BUFFER ((NTSTATUS)0xC00000E8L)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184L)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)

typedef long NTSTATUS;
typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned char BOOLEAN;
typedef char KPROCESSOR_MODE;
typedef void *PVOID;
typedef long long LONGLONG, *PLONGLONG;
typedef struct { unsigned identity; } EPROCESS, *PEPROCESS;
typedef struct { PEPROCESS owner; } ETHREAD, *PETHREAD;
typedef struct {
    unsigned MajorFunction;
    struct {
        struct { ULONG FsControlCode, InputBufferLength; PVOID Type3InputBuffer; } FileSystemControl;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
typedef struct {
    IO_STACK_LOCATION stack;
    struct { struct { PETHREAD Thread; } Overlay; } Tail;
    PEPROCESS requestor_process;
    KPROCESSOR_MODE RequestorMode;
    PVOID UserBuffer;
} IRP, *PIRP;
static EPROCESS issuer, unrelated;
static ETHREAD issuing_thread = { &issuer };
static PEPROCESS current_process = &issuer;
static unsigned irql;
static unsigned KeGetCurrentIrql(void) { return irql; }
static PEPROCESS PsGetThreadProcess(PETHREAD thread) { return thread->owner; }
static PEPROCESS PsGetCurrentProcess(void) { return current_process; }
static PEPROCESS IoGetRequestorProcess(PIRP irp) { return irp->requestor_process; }
static PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP irp) { return &irp->stack; }
unsigned long __cdecl _exception_code(void);
#define GetExceptionCode() ((NTSTATUS)_exception_code())

/* The four statuses FsRtl documents as unexpected driver faults. */
static BOOLEAN FsRtlIsNtstatusExpected(NTSTATUS status)
{
    return (status != STATUS_DATATYPE_MISALIGNMENT) && (status != STATUS_ACCESS_VIOLATION) &&
        (status != STATUS_ILLEGAL_INSTRUCTION) && (status != STATUS_INSTRUCTION_MISALIGNMENT);
}

static unsigned probes;
static NTSTATUS probe_raise;
static const void *probed_address;
static ULONG probed_length, probed_alignment;

static void ProbeForRead(PVOID address, ULONG length, ULONG alignment)
{
    ++probes;
    probed_address = address;
    probed_length = length;
    probed_alignment = alignment;
    if (probe_raise != STATUS_SUCCESS) {
        RaiseException((unsigned long)probe_raise, 0, 0, NULL);
    }
}

/* Byte copies touch the supplied addresses directly, as the WDK volatile copy does. */
static void RtlCopyVolatileMemory(volatile void *destination, volatile const void *source,
    unsigned long long length)
{
    volatile unsigned char *output = destination;
    volatile const unsigned char *input = source;
    while (length-- != 0) { *output++ = *input++; }
}

#include "requestor_buffer.h"

/* Unmapped in every Windows user address space: the first 64 KiB are never allocated. */
#define UNMAPPED_ADDRESS ((void *)(unsigned long long)0x10)

static NTSTATUS read_probe_raise(NTSTATUS raised)
{
    long long source = 7, value = 0;
    NTSTATUS status;
    probe_raise = raised;
    status = ext4win_requestor_read(UserMode, &source, &value, sizeof(value), 8);
    probe_raise = STATUS_SUCCESS;
    assert(value == 0);
    return status;
}

static BOOLEAN instruction_fault_propagates(void)
{
    BOOLEAN propagated = 0;
    __try {
        (void)read_probe_raise(STATUS_ILLEGAL_INSTRUCTION);
    }
    __except (GetExceptionCode() == STATUS_ILLEGAL_INSTRUCTION
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        propagated = 1;
    }
    probe_raise = STATUS_SUCCESS;
    return propagated;
}

static void irp_buffers_require_the_issuing_process(void)
{
    LONGLONG input = 17, value = 0;
    unsigned char buffer[16];
    PVOID output = NULL;
    IRP irp = {
        .stack = { IRP_MJ_FILE_SYSTEM_CONTROL, { { FSCTL_GET_VOLUME_BITMAP, sizeof(input), &input } } },
        .Tail = { { &issuing_thread } },
        .requestor_process = &issuer,
        .RequestorMode = UserMode,
        .UserBuffer = buffer,
    };
    unsigned before = probes;

    current_process = &unrelated;
    assert(ext4win_capture_allocation_start(&irp, &value) == STATUS_INVALID_DEVICE_STATE);
    assert(ext4win_requestor_output_address(&irp, &output) == STATUS_INVALID_DEVICE_STATE);
    assert(probes == before && value == 0 && output == NULL);

    /* The issuing thread may now be attached to the worker's process. */
    irp.requestor_process = &unrelated;
    assert(ext4win_capture_allocation_start(&irp, &value) == STATUS_INVALID_DEVICE_STATE);
    assert(ext4win_requestor_output_address(&irp, &output) == STATUS_INVALID_DEVICE_STATE);
    assert(probes == before && value == 0 && output == NULL);

    current_process = &issuer;
    irp.requestor_process = &issuer;
    assert(ext4win_capture_allocation_start(&irp, &value) == STATUS_SUCCESS);
    assert(value == input && probes == before + 1);
    assert(ext4win_requestor_output_address(&irp, &output) == STATUS_SUCCESS && output == buffer);
    irql = DISPATCH_LEVEL;
    assert(ext4win_capture_allocation_start(&irp, &value) == STATUS_INVALID_DEVICE_STATE);
    assert(ext4win_requestor_output_address(&irp, &output) == STATUS_INVALID_DEVICE_STATE);
    assert(probes == before + 1 && output == NULL);
    irql = 0;

    irp.UserBuffer = NULL;
    assert(ext4win_requestor_output_address(&irp, &output) == STATUS_INVALID_USER_BUFFER);
    assert(output == NULL);
}

int main(void)
{
    long long source = 0x1122334455667788LL, value = 0;
    unsigned char record[4] = { 1, 2, 3, 4 }, published[4] = { 0 };

    assert(ext4win_requestor_read(UserMode, &source, &value, sizeof(value), 8) == STATUS_SUCCESS);
    assert(value == source && probes == 1 && probed_address == &source);
    assert(probed_length == sizeof(value) && probed_alignment == 8);

    value = 0;
    assert(ext4win_requestor_read(KernelMode, &source, &value, sizeof(value), 8) == STATUS_SUCCESS);
    assert(value == source && probes == 1);

    /* Probe failures are user-controlled request failures, never unhandled kernel exceptions. */
    assert(read_probe_raise(STATUS_DATATYPE_MISALIGNMENT) == STATUS_DATATYPE_MISALIGNMENT);
    assert(read_probe_raise(STATUS_ACCESS_VIOLATION) == STATUS_ACCESS_VIOLATION);
    assert(read_probe_raise(STATUS_IN_PAGE_ERROR) == STATUS_IN_PAGE_ERROR);
    assert(read_probe_raise(STATUS_INSUFFICIENT_RESOURCES) == STATUS_INVALID_USER_BUFFER);

    /* A probed user range can still be unmapped when the copy touches it. */
    value = 0;
    assert(ext4win_requestor_read(UserMode, UNMAPPED_ADDRESS, &value, sizeof(value), 8)
        == STATUS_ACCESS_VIOLATION);
    assert(value == 0);

    assert(ext4win_requestor_write(published, record, sizeof(record)) == STATUS_SUCCESS);
    assert(published[0] == 1 && published[3] == 4);
    assert(ext4win_requestor_write(UNMAPPED_ADDRESS, record, sizeof(record))
        == STATUS_ACCESS_VIOLATION);

    assert(instruction_fault_propagates());
    irp_buffers_require_the_issuing_process();
    ExitProcess(0);
}
