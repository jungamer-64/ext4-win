/* Exercise the production transfer boundary with state changes at resource
 * acquisition. Rust range/admission tests own policy correctness; this oracle
 * checks the synchronization scope, exact request forwarding and rejection. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _In_
#define _Out_
#define _Success_(condition)
#define _Must_inspect_result_
#define FALSE 0
#define TRUE 1
#define NULL ((void *)0)

typedef int BOOLEAN;
typedef unsigned long ULONG;
typedef struct { long long QuadPart; } LARGE_INTEGER, *PLARGE_INTEGER;
typedef struct { unsigned held; } ERESOURCE, *PERESOURCE;
typedef struct { int Status; } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef struct { unsigned identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct {
    ERESOURCE MainResource;
    long long eof;
    BOOLEAN eligible, unlocked, oplock_possible;
} EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;
typedef struct {
    PEXT4WIN_STREAM_CONTEXT stream;
} FILE_OBJECT, *PFILE_OBJECT;

enum acquisition_change {
    UNCHANGED,
    SHRINK_EOF,
    CONFLICTING_LOCK,
    OPLOCK_GRANTED,
    ADMISSION_CLOSED,
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
    offset.QuadPart = 64;
    acquisitions = releases = checks = 0;
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
            if (scenario == UNCHANGED) {
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
    return 0;
}
