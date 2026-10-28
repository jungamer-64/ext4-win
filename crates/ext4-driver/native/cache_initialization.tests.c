#include <stddef.h>
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) void __stdcall RaiseException(unsigned long, unsigned long, unsigned long, const unsigned long long *);
unsigned long __cdecl _exception_code(void);
#define assert(value) do { if (!(value)) { ExitProcess(__LINE__); } } while (0)
#define _IRQL_requires_max_(level)
#define _Must_inspect_result_
#define _In_
#define _Inout_
#define _Out_
#define NTAPI __stdcall
#define TRUE 1
#define FALSE 0
#define VOID void
#define STATUS_SUCCESS 0L
#define STATUS_INVALID_PARAMETER ((long)0xc000000dL)
#define STATUS_INVALID_DEVICE_REQUEST ((long)0xc0000010L)
#define STATUS_VERIFY_REQUIRED ((long)0x80000016L)
#define STATUS_VOLUME_DISMOUNTED ((long)0xc000026eL)
#define STATUS_DEVICE_REMOVED ((long)0xc00002b6L)
#define STATUS_IO_DEVICE_ERROR ((long)0xc0000185L)
#define FO_CACHE_SUPPORTED 0x00000040UL
#define CC_ENABLE_DISK_IO_ACCOUNTING 0x00000010UL
#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS 1
#define GetExceptionCode() ((long)_exception_code())
typedef long NTSTATUS;
typedef unsigned long ULONG;
typedef unsigned char UCHAR, *PUCHAR, BOOLEAN;
typedef void *PVOID;
typedef struct { unsigned Held; } ERESOURCE, *PERESOURCE;
typedef struct { long long AllocationSize, FileSize, ValidDataLength; } CC_FILE_SIZES;
typedef struct { ULONG Flags; PVOID PrivateCacheMap, FsContext; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct _EXT4WIN_STREAM_CONTEXT {
    struct { long long Size; } Header;
    PVOID PagingState;
    struct _EXT4WIN_STREAM_CONTEXT *VolumeStream;
    PVOID RustState, SectionState;
    ERESOURCE MainResource;
} EXT4WIN_STREAM_CONTEXT, *PEXT4WIN_STREAM_CONTEXT;
static EXT4WIN_STREAM_CONTEXT stream, volume;
static BOOLEAN ext4win_paging_is_special(const VOID *state) { return state != NULL; }
static FILE_OBJECT file;
static unsigned cache_identity, callbacks_identity, section_identity, runtime_identity;
#define ext4win_cache_callbacks callbacks_identity
static unsigned verify_required, storage_present, closing, set_verify_on_lock, set_verify_in_cc;
static unsigned gate_calls, acquisitions, releases, entries, captures, flag_updates, accounting;
static unsigned accounting_enabled;
static NTSTATUS cc_exception;
static PEXT4WIN_STREAM_CONTEXT ext4win_stream_from_header(PVOID header)
{
    return header == &stream.Header ? &stream : NULL;
}
static BOOLEAN ext4win_stream_matches_file_object(PEXT4WIN_STREAM_CONTEXT selected, PFILE_OBJECT selected_file)
{
    return selected == &stream && selected_file == &file && file.FsContext == &stream.Header;
}
static BOOLEAN ext4win_stream_ordinary_io_available(PEXT4WIN_STREAM_CONTEXT selected)
{
    assert(selected == &stream);
    ++gate_calls;
    return storage_present && !closing && !verify_required;
}
static UCHAR ext4win_storage_verify_required(PVOID state)
{
    assert(state == &runtime_identity);
    return (UCHAR)verify_required;
}
static BOOLEAN ext4win_stream_storage_available(PEXT4WIN_STREAM_CONTEXT selected)
{
    assert(selected == &stream);
    return (BOOLEAN)storage_present;
}
static BOOLEAN ext4win_section_acquire_main(PVOID state, PERESOURCE resource,
    BOOLEAN exclusive, BOOLEAN wait, BOOLEAN *waited)
{
    assert(state == &section_identity && resource == &stream.MainResource && exclusive && wait && waited == NULL);
    assert(!resource->Held);
    resource->Held = 1;
    ++acquisitions;
    if (set_verify_on_lock) { verify_required = 1; }
    return TRUE;
}
static VOID ext4win_release_resource(PERESOURCE resource)
{
    assert(resource == &stream.MainResource && resource->Held);
    resource->Held = 0;
    ++releases;
}
static VOID ext4win_capture_cache_sizes(PEXT4WIN_STREAM_CONTEXT selected, CC_FILE_SIZES *sizes)
{
    assert(selected == &stream && stream.MainResource.Held);
    ++captures;
    sizes->AllocationSize = 8192;
    sizes->FileSize = 4097;
    sizes->ValidDataLength = 4097;
}
static VOID CcInitializeCacheMap(PFILE_OBJECT selected, CC_FILE_SIZES *sizes,
    BOOLEAN pin_access, PVOID callbacks, PVOID context)
{
    assert(selected == &file && stream.MainResource.Held && file.PrivateCacheMap == NULL);
    assert(sizes->AllocationSize == 8192 && sizes->FileSize == 4097 && sizes->ValidDataLength == 4097);
    assert(!pin_access && callbacks == &callbacks_identity && context == &stream.Header);
    ++entries;
    file.PrivateCacheMap = &cache_identity;
    if (set_verify_in_cc) { verify_required = 1; }
    if (cc_exception != STATUS_SUCCESS) { RaiseException((ULONG)cc_exception, 0, 0, NULL); }
}
static BOOLEAN PsIsDiskCountersEnabled(VOID) { return (BOOLEAN)accounting_enabled; }
static VOID CcSetAdditionalCacheAttributesEx(PFILE_OBJECT selected, ULONG flags)
{
    assert(selected == &file && stream.MainResource.Held && file.PrivateCacheMap == &cache_identity && flags == 0x10);
    ++accounting;
}
static VOID ext4win_file_set_flags(PFILE_OBJECT selected, ULONG flags)
{
    assert(selected == &file && stream.MainResource.Held && flags == 0x40);
    ++flag_updates;
    selected->Flags |= flags;
}
#include "cache_initialization.h"

static VOID reset(VOID)
{
    assert(!stream.MainResource.Held);
    stream.VolumeStream = &volume;
    stream.SectionState = &section_identity;
    stream.PagingState = NULL;
    volume.RustState = &runtime_identity;
    file.FsContext = &stream.Header;
    file.PrivateCacheMap = NULL;
    file.Flags = 0xa000;
    verify_required = closing = set_verify_on_lock = set_verify_in_cc = 0;
    gate_calls = acquisitions = releases = entries = captures = flag_updates = accounting = 0;
    storage_present = accounting_enabled = 1;
    cc_exception = STATUS_SUCCESS;
}
int main(void)
{
    UCHAR before;
    NTSTATUS status;
    /* Entry refusal preserves the uninitialized cache identity and never takes Main. */
    reset(); before = 99; verify_required = 1;
    status = ext4win_stream_cache_initialize(&stream.Header, &file, &before);
    assert(status == STATUS_VERIFY_REQUIRED && before == 1);
    assert(gate_calls == 1 && acquisitions == 0 && releases == 0 && entries == 0);
    assert(file.PrivateCacheMap == NULL && file.Flags == 0xa000 && flag_updates == 0);

    /* The independent lock oracle raises DO_VERIFY after initial admission. */
    reset(); before = 99; set_verify_on_lock = 1;
    status = ext4win_stream_cache_initialize(&stream.Header, &file, &before);
    assert(status == STATUS_VERIFY_REQUIRED && before == 1);
    assert(gate_calls == 2 && acquisitions == 1 && releases == 1 && entries == 0 && captures == 0);
    assert(!stream.MainResource.Held && file.PrivateCacheMap == NULL && file.Flags == 0xa000);

    /* An existing map is still subject to the late gate, without losing its identity. */
    reset(); before = 99; file.PrivateCacheMap = &cache_identity; set_verify_on_lock = 1;
    assert(ext4win_stream_cache_initialize(&stream.Header, &file, &before) == STATUS_VERIFY_REQUIRED && before == 1);
    assert(entries == 0 && acquisitions == 1 && releases == 1 && file.PrivateCacheMap == &cache_identity);

    /* Cc may establish a map and then raise VERIFY: this has no pre-entry marker. */
    reset(); before = 99; cc_exception = STATUS_VERIFY_REQUIRED; set_verify_in_cc = 1;
    assert(ext4win_stream_cache_initialize(&stream.Header, &file, &before) == STATUS_VERIFY_REQUIRED && before == 0);
    assert(entries == 1 && captures == 1 && acquisitions == 1 && releases == 1);
    assert(file.PrivateCacheMap == &cache_identity && file.Flags == 0xa000 && flag_updates == 0 && accounting == 0);

    reset(); before = 99; cc_exception = STATUS_IO_DEVICE_ERROR;
    assert(ext4win_stream_cache_initialize(&stream.Header, &file, &before) == STATUS_IO_DEVICE_ERROR && before == 0);
    assert(entries == 1 && acquisitions == 1 && releases == 1 && flag_updates == 0);

    /* A post-entry flag cannot retrospectively authenticate an earlier refusal. */
    reset(); before = 99; set_verify_in_cc = 1;
    assert(ext4win_stream_cache_initialize(&stream.Header, &file, &before) == STATUS_SUCCESS && before == 0);
    assert(entries == 1 && accounting == 1 && flag_updates == 1 && file.Flags == 0xa040);
    assert(acquisitions == 1 && releases == 1 && verify_required);

    reset(); before = 99; file.PrivateCacheMap = &cache_identity;
    assert(ext4win_stream_cache_initialize(&stream.Header, &file, &before) == STATUS_SUCCESS && before == 0);
    assert(entries == 0 && flag_updates == 0 && acquisitions == 1 && releases == 1);

    reset(); before = 99; storage_present = 0;
    assert(ext4win_stream_cache_initialize(&stream.Header, &file, &before) == STATUS_DEVICE_REMOVED && before == 0);
    assert(entries == 0 && acquisitions == 0);
    reset(); before = 99; closing = 1;
    assert(ext4win_stream_cache_initialize(&stream.Header, &file, &before) == STATUS_VOLUME_DISMOUNTED && before == 0);
    assert(entries == 0 && acquisitions == 0);
    reset(); before = 99; stream.PagingState = &stream; verify_required = 1;
    assert(ext4win_stream_cache_initialize(&stream.Header, &file, &before) == STATUS_INVALID_DEVICE_REQUEST && before == 0);
    assert(entries == 0 && acquisitions == 0 && gate_calls == 0);
    reset(); before = 99;
    assert(ext4win_stream_cache_initialize(NULL, &file, &before) == STATUS_INVALID_PARAMETER && before == 0);
    assert(ext4win_stream_cache_initialize(&stream.Header, &file, NULL) == STATUS_INVALID_PARAMETER);
    assert(entries == 0 && acquisitions == 0);
    return 0;
}
