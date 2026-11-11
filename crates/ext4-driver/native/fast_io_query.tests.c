/* Exercise the production Fast I/O query boundary. Admission and snapshot capture own
 * MainResource; record encoding and the raw requestor copy must run after its release,
 * so a faulting requestor buffer completes the query without retaining the resource. */
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
#define assert(value) do { if (!(value)) { ExitProcess(__LINE__); } } while (0)
#define _In_
#define _Out_
#define _Success_(condition)
#define _Out_writes_bytes_(length)
#define _In_reads_bytes_(length)
#define _IRQL_requires_max_(level)
#define _Must_inspect_result_
#define NTAPI
#define NULL ((void *)0)
#define VOID void
#define FALSE 0
#define UserMode 1
#define TRUE 1
#define UNREFERENCED_PARAMETER(value) ((void)(value))
#define NT_SUCCESS(status) ((status) >= 0)
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_DATATYPE_MISALIGNMENT ((NTSTATUS)0x80000002L)
#define STATUS_ACCESS_VIOLATION ((NTSTATUS)0xC0000005L)
#define STATUS_IN_PAGE_ERROR ((NTSTATUS)0xC0000006L)
#define STATUS_ILLEGAL_INSTRUCTION ((NTSTATUS)0xC000001DL)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#define STATUS_INSTRUCTION_MISALIGNMENT ((NTSTATUS)0xC00000AAL)
#define STATUS_INVALID_USER_BUFFER ((NTSTATUS)0xC00000E8L)

typedef long NTSTATUS;
typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned long long ULONG_PTR;
typedef unsigned char BOOLEAN;
typedef char KPROCESSOR_MODE;
typedef void *PVOID;
typedef struct { NTSTATUS Status; ULONG_PTR Information; } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef struct { unsigned identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct { unsigned identity; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { unsigned held; } ERESOURCE, *PERESOURCE;
typedef struct { ERESOURCE MainResource; } EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;
typedef struct { unsigned long long marker; } EXT4WIN_FAST_IO_QUERY_SNAPSHOT,
    *PEXT4WIN_FAST_IO_QUERY_SNAPSHOT;
typedef struct { unsigned long long times[4]; ULONG attributes; } FILE_BASIC_INFORMATION,
    *PFILE_BASIC_INFORMATION;
typedef struct { unsigned long long sizes[2]; ULONG links; } FILE_STANDARD_INFORMATION,
    *PFILE_STANDARD_INFORMATION;
typedef struct { unsigned long long values[6]; ULONG attributes; } FILE_NETWORK_OPEN_INFORMATION,
    *PFILE_NETWORK_OPEN_INFORMATION;
unsigned long __cdecl _exception_code(void);
#define GetExceptionCode() ((NTSTATUS)_exception_code())
#define RtlZeroMemory(destination, length) __builtin_memset((destination), 0, (length))

static BOOLEAN FsRtlIsNtstatusExpected(NTSTATUS status)
{
    return (status != STATUS_DATATYPE_MISALIGNMENT) && (status != STATUS_ACCESS_VIOLATION) &&
        (status != STATUS_ILLEGAL_INSTRUCTION) && (status != STATUS_INSTRUCTION_MISALIGNMENT);
}
static void ProbeForRead(PVOID address, ULONG length, ULONG alignment)
{
    (void)address; (void)length; (void)alignment;
    assert(0);
}
static void RtlCopyVolatileMemory(volatile void *destination, volatile const void *source,
    unsigned long long length)
{
    volatile unsigned char *output = destination;
    volatile const unsigned char *input = source;
    while (length-- != 0) { *output++ = *input++; }
}
#include "requestor_access.h"

static EXT4WIN_STREAM_CONTEXT stream;
static FILE_OBJECT file;
static DEVICE_OBJECT device;
static BOOLEAN admitted = TRUE, snapshot_valid = TRUE;
static unsigned acquisitions, releases, encodings;

static BOOLEAN ext4win_acquire_fast_io_query_stream(
    PFILE_OBJECT observed, BOOLEAN wait, PEXT4WIN_STREAM_CONTEXT *stream_out)
{
    assert(observed == &file && wait && stream.MainResource.held == 0);
    if (!admitted) { return FALSE; }
    stream.MainResource.held = 1;
    ++acquisitions;
    *stream_out = &stream;
    return TRUE;
}
static BOOLEAN ext4win_capture_fast_io_query_snapshot(
    PEXT4WIN_STREAM_CONTEXT observed, PEXT4WIN_FAST_IO_QUERY_SNAPSHOT snapshot)
{
    assert(observed == &stream && stream.MainResource.held == 1);
    snapshot->marker = 0x5a;
    return snapshot_valid;
}
static void wdk_sys_release_resource(PERESOURCE resource)
{
    assert(resource == &stream.MainResource && resource->held == 1);
    resource->held = 0;
    ++releases;
}
static void ext4win_fast_io_basic_record(const EXT4WIN_FAST_IO_QUERY_SNAPSHOT *snapshot,
    PFILE_BASIC_INFORMATION output)
{
    assert(snapshot->marker == 0x5a && stream.MainResource.held == 0);
    ++encodings;
    output->attributes = 0x20;
}
static void ext4win_fast_io_standard_record(const EXT4WIN_FAST_IO_QUERY_SNAPSHOT *snapshot,
    PFILE_STANDARD_INFORMATION output)
{
    assert(snapshot->marker == 0x5a && stream.MainResource.held == 0);
    ++encodings;
    output->links = 2;
}
static void ext4win_fast_io_network_record(const EXT4WIN_FAST_IO_QUERY_SNAPSHOT *snapshot,
    PFILE_NETWORK_OPEN_INFORMATION output)
{
    assert(snapshot->marker == 0x5a && stream.MainResource.held == 0);
    ++encodings;
    output->attributes = 0x80;
}

#include "fast_io_query.h"

/* Unmapped in every Windows user address space: the first 64 KiB are never allocated. */
#define UNMAPPED_ADDRESS ((void *)(unsigned long long)0x10)

static void assert_balanced(unsigned expected_acquisitions)
{
    assert(acquisitions == expected_acquisitions && releases == expected_acquisitions);
    assert(stream.MainResource.held == 0);
}

int main(void)
{
    IO_STATUS_BLOCK status;
    FILE_BASIC_INFORMATION basic = { { 0 }, 0 };
    FILE_STANDARD_INFORMATION standard = { { 0 }, 0 };
    FILE_NETWORK_OPEN_INFORMATION network = { { 0 }, 0 };

    assert(ext4win_fast_io_query_basic_info(&file, TRUE, &basic, &status, &device));
    assert(status.Status == STATUS_SUCCESS && status.Information == sizeof(basic));
    assert(basic.attributes == 0x20);
    assert_balanced(1);

    /* A raw requestor buffer can fault after the I/O Manager probe. */
    assert(ext4win_fast_io_query_basic_info(&file, TRUE, UNMAPPED_ADDRESS, &status, &device));
    assert(status.Status == STATUS_ACCESS_VIOLATION && status.Information == 0);
    assert_balanced(2);

    assert(ext4win_fast_io_query_standard_info(&file, TRUE, &standard, &status, &device));
    assert(status.Status == STATUS_SUCCESS && status.Information == sizeof(standard));
    assert(standard.links == 2);
    assert(ext4win_fast_io_query_standard_info(&file, TRUE, UNMAPPED_ADDRESS, &status, &device));
    assert(status.Status == STATUS_ACCESS_VIOLATION && status.Information == 0);
    assert_balanced(4);

    assert(ext4win_fast_io_query_network_open_info(&file, TRUE, &network, &status, &device));
    assert(status.Status == STATUS_SUCCESS && status.Information == sizeof(network));
    assert(network.attributes == 0x80);
    assert(ext4win_fast_io_query_network_open_info(&file, TRUE, UNMAPPED_ADDRESS, &status, &device));
    assert(status.Status == STATUS_ACCESS_VIOLATION && status.Information == 0);
    assert_balanced(6);
    assert(encodings == 6);

    /* Rejected snapshots release the resource and fall back without encoding. */
    snapshot_valid = FALSE;
    assert(!ext4win_fast_io_query_basic_info(&file, TRUE, &basic, &status, &device));
    assert(status.Status == STATUS_NOT_SUPPORTED && status.Information == 0);
    assert_balanced(7);
    assert(encodings == 6);

    admitted = FALSE;
    assert(!ext4win_fast_io_query_basic_info(&file, TRUE, &basic, &status, &device));
    assert_balanced(7);
    ExitProcess(0);
}
