#include <stddef.h>

__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
#define assert(value) do { if (!(value)) { ExitProcess(__LINE__); } } while (0)
#define _IRQL_requires_(level)
#define _In_
#define _Out_
#define _In_reads_bytes_(length)
#define _Out_writes_(length)
#define PASSIVE_LEVEL 0
#define POOL_FLAG_NON_PAGED 0x40
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define STATUS_SUCCESS 0L
#define STATUS_FILE_CORRUPT_ERROR ((long)0xc0000102)
#define FALSE 0
typedef void VOID;
typedef void *PVOID;
typedef long NTSTATUS;
typedef unsigned short WCHAR, USHORT, *PWCH;
typedef unsigned long ULONG;
typedef unsigned char BOOLEAN;
typedef unsigned __int64 ULONGLONG;
typedef __int64 LONGLONG;
typedef struct { USHORT Length, MaximumLength; PWCH Buffer; } UNICODE_STRING;
typedef struct { int initialized; } TUNNEL, *PTUNNEL;
unsigned long __cdecl _exception_code(void);
#define GetExceptionCode() ((NTSTATUS)_exception_code())
static TUNNEL storage;
static int allocations, initialized, destroyed, releases, denied, hit, malformed;
static int adds, finds;
static int retired;
static ULONGLONG expected_directory = 0x1234567800000002ui64;
static LONGLONG saved_creation;
static WCHAR expected_name[] = { 'l', 'o', 'n', 'g' };
static WCHAR expected_short[] = { 'L', 'O', 'N', 'G', '~', '1' };

static void RtlZeroMemory(void *target, size_t length)
{
    unsigned char *bytes = target;
    while (length != 0) { *bytes++ = 0; --length; }
}
static int FsRtlIsNtstatusExpected(NTSTATUS status) { return status < 0; }
static PVOID ExAllocatePool2(ULONGLONG flags, size_t length, ULONG tag)
{
    assert(flags == POOL_FLAG_NON_PAGED && length == sizeof(TUNNEL) && tag != 0);
    ++allocations;
    return denied ? NULL : &storage;
}
static void ExFreePoolWithTag(PVOID value, ULONG tag)
{
    assert(value == &storage && tag != 0 && destroyed == 1);
    ++releases;
}
static void ExFreePool(PVOID value) { assert(value == NULL); }
static void FsRtlInitializeTunnelCache(PTUNNEL cache)
{
    assert(cache == &storage); cache->initialized = 1; ++initialized;
}
static void FsRtlDeleteTunnelCache(PTUNNEL cache)
{
    assert(cache == &storage && cache->initialized == 1); ++destroyed;
}
static void FsRtlDeleteKeyFromTunnelCache(PTUNNEL cache, ULONGLONG directory)
{
    assert(cache == &storage && directory == expected_directory); ++retired;
}
static void FsRtlAddToTunnelCache(PTUNNEL cache, ULONGLONG directory,
    UNICODE_STRING *short_name, UNICODE_STRING *name, BOOLEAN by_short,
    ULONG length, PVOID data)
{
    assert(cache == &storage && directory == expected_directory && by_short == FALSE);
    assert(name->Length == sizeof(expected_name) && name->Buffer == expected_name);
    assert(short_name->Length == sizeof(expected_short) && short_name->Buffer == expected_short);
    assert(length == sizeof(LONGLONG));
    saved_creation = *(LONGLONG *)data; ++adds;
}
static BOOLEAN FsRtlFindInTunnelCache(PTUNNEL cache, ULONGLONG directory,
    UNICODE_STRING *name, UNICODE_STRING *short_name, UNICODE_STRING *long_name,
    ULONG *length, PVOID data)
{
    size_t i;
    assert(cache == &storage && directory == expected_directory);
    assert(name->Length == sizeof(expected_name) && name->Buffer == expected_name);
    assert(short_name->MaximumLength == 24 && long_name->MaximumLength == 512);
    assert(*length == sizeof(LONGLONG)); ++finds;
    if (!hit) { return FALSE; }
    for (i = 0; i < sizeof(expected_short) / sizeof(WCHAR); ++i) {
        short_name->Buffer[i] = expected_short[i];
    }
    short_name->Length = sizeof(expected_short);
    *(LONGLONG *)data = saved_creation;
    if (malformed) { *length = 7; }
    return 1;
}
#include "tunnel_cache.h"

int main(void)
{
    PVOID cache;
    WCHAR short_name[12];
    USHORT length;
    LONGLONG creation;
    BOOLEAN found;
    denied = 1;
    assert(ext4win_tunnel_create() == NULL && initialized == 0);
    denied = 0;
    cache = ext4win_tunnel_create();
    assert(cache == &storage && allocations == 2 && initialized == 1);
    ext4win_tunnel_add(cache, expected_directory, expected_name, sizeof(expected_name),
        expected_short, sizeof(expected_short), 123456789);
    assert(adds == 1 && saved_creation == 123456789);
    assert(ext4win_tunnel_find(cache, expected_directory, expected_name, sizeof(expected_name),
        short_name, &length, &creation, &found) == STATUS_SUCCESS);
    assert(found == FALSE && length == 0 && creation == 0 && finds == 1);
    hit = 1;
    assert(ext4win_tunnel_find(cache, expected_directory, expected_name, sizeof(expected_name),
        short_name, &length, &creation, &found) == STATUS_SUCCESS);
    assert(found && length == sizeof(expected_short) && creation == saved_creation && finds == 2);
    malformed = 1;
    assert(ext4win_tunnel_find(cache, expected_directory, expected_name, sizeof(expected_name),
        short_name, &length, &creation, &found) == STATUS_FILE_CORRUPT_ERROR && found == FALSE);
    ext4win_tunnel_delete_directory(cache, expected_directory);
    assert(retired == 1);
    ext4win_tunnel_destroy(cache);
    assert(destroyed == 1 && releases == 1);
    ExitProcess(0);
}
