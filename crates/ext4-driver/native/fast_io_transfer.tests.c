/* Exercise the production transfer boundary with state changes at resource
 * acquisition. Rust range/admission tests own policy correctness; this oracle
 * checks the synchronization scope, exact request forwarding and rejection. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _In_
#define _Out_
#define _Success_(condition)
#define _Must_inspect_result_
#define _Out_writes_bytes_(length)
#define _In_reads_bytes_(length)
#define NTAPI
#define FO_SYNCHRONOUS_IO 2
#define FO_WRITE_THROUGH 16
#define NT_SUCCESS(status) ((status) >= 0)
#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL (-3)
#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS 1
#define EXT4WIN_TRACE_EVENT_FAST_IO_READ 1
#define EXT4WIN_TRACE_EVENT_FAST_IO_WRITE 2
#define GetExceptionCode() ((int)__exception_code())
#define FALSE 0
#define TRUE 1
#define NULL ((void *)0)

typedef int BOOLEAN;
typedef unsigned long ULONG;
typedef unsigned long long ULONG_PTR;
typedef void *PVOID;
typedef struct { long long QuadPart; } LARGE_INTEGER, *PLARGE_INTEGER;
typedef struct { unsigned held; } ERESOURCE, *PERESOURCE;
typedef struct { int Status; ULONG_PTR Information; } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef struct { unsigned identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct {
    ERESOURCE MainResource;
    long long eof;
    BOOLEAN eligible, unlocked, oplock_possible;
} EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;
typedef struct {
    PEXT4WIN_STREAM_CONTEXT stream;
    ULONG Flags;
    PVOID FsContext2;
    LARGE_INTEGER CurrentByteOffset;
} FILE_OBJECT, *PFILE_OBJECT;

enum acquisition_change {
    UNCHANGED,
    SHRINK_EOF,
    CONFLICTING_LOCK,
    OPLOCK_GRANTED,
    ADMISSION_CLOSED,
    WRITE_THROTTLED,
    STREAM_REPLACED
};

static EXT4WIN_STREAM_CONTEXT stream, replacement;
static FILE_OBJECT file;
static DEVICE_OBJECT device;
static LARGE_INTEGER offset;
static IO_STATUS_BLOCK status;
static enum acquisition_change change;
static unsigned acquisitions, releases, checks;
static BOOLEAN expected_read;
static BOOLEAN write_admitted;
static unsigned write_checks;
static BOOLEAN copy_handled, copy_raises;
static int copy_status;
static ULONG_PTR copy_length;
static unsigned copies;
static unsigned char buffer[32];

__declspec(dllimport) void __stdcall RaiseException(ULONG, ULONG, ULONG, const ULONG_PTR *);

static void ext4win_trace_selected(PEXT4WIN_STREAM_CONTEXT observed, unsigned event)
{ assert(observed == &stream && event == (expected_read ? 1U : 2U)); }
static void ext4win_trace_status(PEXT4WIN_STREAM_CONTEXT observed, unsigned event, int result)
{ (void)result; ext4win_trace_selected(observed, event); }
static void ext4win_trace_fallback(PEXT4WIN_STREAM_CONTEXT observed, unsigned event)
{ ext4win_trace_selected(observed, event); }
static BOOLEAN ext4win_handle_allows_cached_write(PVOID context)
{ assert(context == &file); return TRUE; }

static BOOLEAN CcCopyRead(PFILE_OBJECT observed, PLARGE_INTEGER position, ULONG length,
    BOOLEAN wait, PVOID output, PIO_STATUS_BLOCK result)
{
    assert(observed == &file && position == &offset && length == 32 && wait);
    assert(stream.MainResource.held == 1 && output == buffer);
    copies++;
    if (copy_raises) { RaiseException((ULONG)STATUS_UNSUCCESSFUL, 0, 0, NULL); }
    result->Status = copy_status;
    result->Information = copy_length;
    return copy_handled;
}
static BOOLEAN CcCopyWrite(PFILE_OBJECT observed, PLARGE_INTEGER position, ULONG length,
    BOOLEAN wait, PVOID input)
{
    IO_STATUS_BLOCK result;
    return CcCopyRead(observed, position, length, wait, input, &result);
}

static BOOLEAN CcCanIWrite(PFILE_OBJECT observed_file, ULONG length, BOOLEAN wait, BOOLEAN retrying)
{
    assert(observed_file == &file && length == 32 && !wait);
    assert(retrying == (write_checks != 0));
    assert(stream.MainResource.held == (retrying ? 1U : 0U));
    write_checks++;
    return write_admitted;
}

static BOOLEAN ext4win_acquire_resource_shared(PERESOURCE resource, BOOLEAN wait)
{
    assert(resource == &stream.MainResource && wait);
    assert(resource->held == 0);
    acquisitions++;
    /* Model an exclusive mutator winning immediately before shared acquisition. */
    switch (change) {
        case SHRINK_EOF: stream.eof = 80; break;
        case CONFLICTING_LOCK: stream.unlocked = FALSE; break;
        case OPLOCK_GRANTED: stream.oplock_possible = FALSE; break;
        case ADMISSION_CLOSED: stream.eligible = FALSE; break;
        case WRITE_THROTTLED: write_admitted = FALSE; break;
        case STREAM_REPLACED: file.stream = &replacement; break;
        case UNCHANGED: break;
    }
    resource->held = 1;
    return TRUE;
}

static void ext4win_release_resource(PERESOURCE resource)
{
    assert(resource == &stream.MainResource && resource->held == 1);
    resource->held = 0;
    releases++;
}

static BOOLEAN ext4win_stream_fast_io_candidate(
    PFILE_OBJECT observed_file, PEXT4WIN_STREAM_CONTEXT *observed)
{
    assert(observed_file == &file);
    *observed = observed_file->stream;
    return (*observed)->eligible;
}

static BOOLEAN ext4win_fast_io_check_if_possible(
    PFILE_OBJECT observed_file, PLARGE_INTEGER observed_offset, ULONG length,
    BOOLEAN wait, ULONG key, BOOLEAN read, PIO_STATUS_BLOCK observed_status,
    PDEVICE_OBJECT observed_device)
{
    assert(stream.MainResource.held == 1);
    assert(observed_file == &file && observed_file->stream == &stream);
    assert(observed_offset == &offset && length == 32 && wait);
    assert(key == 0x1234 && read == expected_read);
    assert(observed_status == &status && observed_device == &device);
    checks++;
    /* Policy is an independent fixture evaluated from the state visible now. */
    return stream.eof >= 96 && stream.unlocked && stream.oplock_possible;
}

#include "fast_io_transfer.h"

static void reset(void)
{
    stream.MainResource.held = 0;
    stream.eof = 96;
    stream.eligible = TRUE;
    stream.unlocked = TRUE;
    stream.oplock_possible = TRUE;
    replacement.eligible = TRUE;
    file.stream = &stream;
    file.Flags = FO_SYNCHRONOUS_IO;
    file.FsContext2 = &file;
    file.CurrentByteOffset.QuadPart = 11;
    offset.QuadPart = 64;
    acquisitions = releases = checks = 0;
    write_admitted = TRUE;
    write_checks = 0;
    copy_handled = TRUE;
    copy_raises = FALSE;
    copy_status = STATUS_SUCCESS;
    copy_length = 32;
    copies = 0;
}

static void verify_copy_completion(void)
{
    unsigned asynchronous, scenario;
    for (expected_read = FALSE; expected_read <= TRUE; expected_read++) {
        for (asynchronous = 0; asynchronous <= 1; asynchronous++) {
            for (scenario = 0; scenario < 5; scenario++) {
                BOOLEAN handled;
                reset();
                change = UNCHANGED;
                if (asynchronous) { file.Flags = 0; }
                switch (scenario) {
                    case 1: change = CONFLICTING_LOCK; break;
                    case 2: copy_handled = FALSE; break;
                    case 3: copy_raises = TRUE; break;
                    case 4: copy_length = 7; break;
                    default: break;
                }
                handled = expected_read
                    ? ext4win_fast_io_read(&file, &offset, 32, TRUE, 0x1234, buffer, &status, &device)
                    : ext4win_fast_io_write(&file, &offset, 32, TRUE, 0x1234, buffer, &status, &device);
                assert(handled == (scenario != 1 && scenario != 2));
                assert(stream.MainResource.held == 0 && releases == 1);
                assert(copies == (scenario == 1 ? 0U : 1U));
                if (scenario == 0 || scenario == 4) {
                    ULONG_PTR transferred = expected_read ? copy_length : 32;
                    assert(status.Status == STATUS_SUCCESS && status.Information == transferred);
                    assert(file.CurrentByteOffset.QuadPart ==
                        (asynchronous ? 11 : 64 + (long long)transferred));
                } else {
                    assert(file.CurrentByteOffset.QuadPart == 11);
                    if (scenario == 3) {
                        assert(status.Status == STATUS_UNSUCCESSFUL && status.Information == 0);
                    }
                }
            }
        }
    }
}

int main(void)
{
    enum acquisition_change scenario;
    for (expected_read = FALSE; expected_read <= TRUE; expected_read++) {
        for (scenario = UNCHANGED; scenario <= STREAM_REPLACED; scenario++) {
            PEXT4WIN_STREAM_CONTEXT candidate;
            BOOLEAN admitted;
            reset();
            change = scenario;
            assert(ext4win_stream_fast_io_candidate(&file, &candidate));
            assert(candidate == &stream);
            admitted = ext4win_stream_acquire_fast_io_main(&file, candidate, &offset,
                32, TRUE, 0x1234, expected_read, &status, &device);
            assert(acquisitions == 1);
            if (scenario == UNCHANGED || (scenario == WRITE_THROTTLED && expected_read)) {
                assert(admitted && stream.MainResource.held == 1 && releases == 0);
                /* Cc sees the same retained scope as the admission decision. */
                assert(checks == 1);
                ext4win_release_resource(&stream.MainResource);
            } else {
                assert(!admitted && stream.MainResource.held == 0 && releases == 1);
                assert(checks == ((scenario == ADMISSION_CLOSED || scenario == STREAM_REPLACED)
                    ? 0U : 1U));
            }
        }
        reset();
        change = UNCHANGED;
        assert(!ext4win_stream_acquire_fast_io_main(&file, &stream, &offset,
            32, FALSE, 0x1234, expected_read, &status, &device));
        assert(acquisitions == 0 && releases == 0 && checks == 0);
    }
    reset();
    expected_read = FALSE;
    write_admitted = FALSE;
    assert(!ext4win_stream_acquire_fast_io_main(&file, &stream, &offset,
        32, TRUE, 0x1234, FALSE, &status, &device));
    assert(write_checks == 1 && acquisitions == 0 && releases == 0 && checks == 0);
    verify_copy_completion();
    return 0;
}
