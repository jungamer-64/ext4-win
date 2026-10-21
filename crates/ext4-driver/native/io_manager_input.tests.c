/* Execute production capture with bounded pool/copy ownership and real Windows descriptor
 * validation and SEH. I/O Manager dispatch provenance remains a live-driver contract. */
#include <stddef.h>

__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
#define assert(condition) do { if (!(condition)) { ExitProcess(__LINE__); } } while (0)
#define _IRQL_requires_max_(level)
#define _Must_inspect_result_
#define _In_
#define _Inout_
#define _Out_
#define _In_reads_bytes_(length)
#define _Outptr_result_bytebuffer_(length)
#define _Outptr_result_bytebuffer_maybenull_(length)
#define _Frees_ptr_opt_
#define NTAPI
#define C_ASSERT(condition) _Static_assert(condition, #condition)
#define NT_SUCCESS(status) ((status) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_ACCESS_VIOLATION ((NTSTATUS)0xC0000005)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009A)
#define STATUS_INVALID_SECURITY_DESCR ((NTSTATUS)0xC0000079)
#define STATUS_INVALID_USER_BUFFER ((NTSTATUS)0xC00000E8)
#define STATUS_INVALID_BUFFER_SIZE ((NTSTATUS)0xC0000206)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005)
#define OWNER_SECURITY_INFORMATION 1U
#define GROUP_SECURITY_INFORMATION 2U
#define DACL_SECURITY_INFORMATION 4U
#define SE_OWNER_DEFAULTED 0x0001
#define SE_GROUP_DEFAULTED 0x0002
#define SE_DACL_PRESENT 0x0004
#define SE_DACL_DEFAULTED 0x0008
#define SE_SACL_PRESENT 0x0010
#define SE_SACL_DEFAULTED 0x0020
#define SE_DACL_AUTO_INHERIT_REQ 0x0100
#define SE_SACL_AUTO_INHERIT_REQ 0x0200
#define SE_DACL_AUTO_INHERITED 0x0400
#define SE_SACL_AUTO_INHERITED 0x0800
#define SE_DACL_PROTECTED 0x1000
#define SE_SACL_PROTECTED 0x2000
#define SE_SELF_RELATIVE 0x8000
#define POOL_FLAG_NON_PAGED 0x40ULL
#define MAXULONG_PTR (~(ULONG_PTR)0)
#define GetExceptionCode() ((NTSTATUS)__exception_code())
#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS \
    ((GetExceptionCode() == STATUS_ACCESS_VIOLATION) ? 1 : 0)

typedef unsigned char UCHAR, BOOLEAN;
typedef unsigned short USHORT, WCHAR;
typedef unsigned ULONG, *PULONG, SECURITY_INFORMATION;
typedef unsigned long long ULONG_PTR;
typedef size_t SIZE_T;
typedef int NTSTATUS;
typedef void VOID, *PVOID, *PSECURITY_DESCRIPTOR;
typedef struct { UCHAR Value[6]; } SID_IDENTIFIER_AUTHORITY;
typedef struct {
    UCHAR Revision, Sbz1;
    USHORT Control;
    ULONG Owner, Group, Sacl, Dacl;
} SECURITY_DESCRIPTOR_RELATIVE;
typedef struct {
    UCHAR AclRevision, Sbz1;
    USHORT AclSize, AceCount, Sbz2;
} ACL;
typedef struct {
    USHORT Length, MaximumLength;
    WCHAR *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

__declspec(dllimport) void __stdcall RaiseException(ULONG, ULONG, ULONG, const ULONG_PTR *);
__declspec(dllimport) BOOLEAN NTAPI RtlValidRelativeSecurityDescriptor(
    PSECURITY_DESCRIPTOR, ULONG, SECURITY_INFORMATION);

static union { ULONG_PTR alignment; UCHAR bytes[65536]; } pool;
static SIZE_T allocation_size;
static ULONG allocation_tag, allocations, frees, copies, fail_copy;
static int live_allocation, fail_allocation;
static NTSTATUS copy_exception = STATUS_ACCESS_VIOLATION;
static const UCHAR *read_base[2];
static SIZE_T read_length[2];

static VOID *RtlSecureZeroMemory(VOID *address, SIZE_T length)
{
    volatile UCHAR *bytes = address;
    for (SIZE_T i = 0; i < length; ++i) { bytes[i] = 0; }
    return address;
}

static PVOID ExAllocatePool2(ULONG_PTR flags, SIZE_T length, ULONG tag)
{
    assert(flags == POOL_FLAG_NON_PAGED && !live_allocation);
    assert(length > 0 && length <= sizeof(pool.bytes) && tag != 0);
    if (fail_allocation) { return NULL; }
    RtlSecureZeroMemory(pool.bytes, sizeof(pool.bytes));
    allocation_size = length;
    allocation_tag = tag;
    allocations++;
    live_allocation = 1;
    return pool.bytes;
}

static VOID ExFreePoolWithTag(PVOID address, ULONG tag)
{
    assert(address == pool.bytes && live_allocation && tag == allocation_tag);
    frees++;
    live_allocation = 0;
}

static VOID RtlCopyVolatileMemory(VOID *destination, const VOID *source, SIZE_T length)
{
    const ULONG_PTR address = (ULONG_PTR)source;
    int bounded = 0;
    for (unsigned i = 0; i < 2; ++i) {
        const ULONG_PTR base = (ULONG_PTR)read_base[i];
        if (source != NULL && address >= base && length <= read_length[i] &&
            address - base <= read_length[i] - length) { bounded = 1; }
    }
    assert(bounded);
    copies++;
    volatile UCHAR *out = destination;
    const volatile UCHAR *in = source;
    for (SIZE_T i = 0; i < length; ++i) {
        if (copies == fail_copy && i == length / 2) {
            RaiseException((ULONG)copy_exception, 0, 0, NULL);
        }
        out[i] = in[i];
    }
}

#include "io_manager_input.h"

static VOID begin(const VOID *first, SIZE_T first_length, const VOID *second, SIZE_T second_length)
{
    assert(!live_allocation && allocations == frees);
    read_base[0] = first;
    read_length[0] = first_length;
    read_base[1] = second;
    read_length[1] = second_length;
    copies = fail_copy = 0;
    fail_allocation = 0;
    copy_exception = STATUS_ACCESS_VIOLATION;
}

/* Self-relative Windows layout, two SIDs and an ACCESS_ALLOWED_ACE, encoded independently
 * of the production length measurement. Selecting later components retains offset gaps. */
static const UCHAR descriptor[] = {
    1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 44, 0, 0, 0,
    1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
    1, 1, 0, 0, 0, 0, 0, 5, 20, 0, 0, 0,
    2, 0, 28, 0, 1, 0, 0, 0,
    0, 0, 20, 0, 1, 0, 0, 0,
    1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0
};

static VOID test_descriptors(VOID)
{
    const SECURITY_INFORMATION selections[] = { 1, 2, 4, 7 };
    UCHAR source[sizeof(descriptor)];
    PVOID snapshot;
    ULONG length;

    for (unsigned i = 0; i < sizeof(selections) / sizeof(selections[0]); ++i) {
        for (SIZE_T j = 0; j < sizeof(source); ++j) { source[j] = descriptor[j]; }
        begin(source, sizeof(source), NULL, 0);
        assert(ext4win_capture_io_manager_security_descriptor(source, selections[i],
            sizeof(source), &snapshot, &length) == STATUS_SUCCESS);
        assert(live_allocation && snapshot != source && length <= allocation_size);
        assert(RtlValidRelativeSecurityDescriptor(snapshot, length, selections[i]));
        const SECURITY_DESCRIPTOR_RELATIVE *header = snapshot;
        assert(((header->Owner != 0) == ((selections[i] & 1) != 0)));
        assert(((header->Group != 0) == ((selections[i] & 2) != 0)));
        assert(((header->Dacl != 0) == ((selections[i] & 4) != 0)));
        RtlSecureZeroMemory(source, sizeof(source));
        assert(RtlValidRelativeSecurityDescriptor(snapshot, length, selections[i]));
        ext4win_release_set_security_descriptor(snapshot);
    }

    for (SIZE_T j = 0; j < sizeof(source); ++j) { source[j] = descriptor[j]; }
    begin(source, sizeof(source), NULL, 0);
    fail_allocation = 1;
    assert(ext4win_capture_io_manager_security_descriptor(source, 7, sizeof(source),
        &snapshot, &length) == STATUS_INSUFFICIENT_RESOURCES);
    assert(snapshot == NULL && length == 0 && !live_allocation);

    /* Each bounded read can raise before ownership transfer, including the allocated copy. */
    for (ULONG fault = 1; fault <= 5; ++fault) {
        begin(source, sizeof(source), NULL, 0);
        fail_copy = fault;
        assert(ext4win_capture_io_manager_security_descriptor(source, 7, sizeof(source),
            &snapshot, &length) == STATUS_ACCESS_VIOLATION);
        assert(snapshot == NULL && length == 0 && !live_allocation);
        if (fault == 5) {
            for (SIZE_T j = 0; j < allocation_size; ++j) { assert(pool.bytes[j] == 0); }
        }
    }

    begin(source, sizeof(source), NULL, 0);
    source[20] = 2; /* SID revision rejected by the independent Windows validator. */
    assert(ext4win_capture_io_manager_security_descriptor(source, 7, sizeof(source),
        &snapshot, &length) == STATUS_INVALID_SECURITY_DESCR);
    assert(!live_allocation && snapshot == NULL && length == 0);
    for (SIZE_T j = 0; j < allocation_size; ++j) { assert(pool.bytes[j] == 0); }
    source[20] = descriptor[20];
    source[4] = 255; /* Selected SID lies outside the admitted copy bound. */
    begin(source, sizeof(source), NULL, 0);
    assert(ext4win_capture_io_manager_security_descriptor(source, 1, sizeof(source),
        &snapshot, &length) == STATUS_INVALID_SECURITY_DESCR);
    assert(copies == 1 && !live_allocation && snapshot == NULL && length == 0);

    begin(source, sizeof(source), NULL, 0);
    assert(ext4win_capture_io_manager_security_descriptor(source, 7, 19,
        &snapshot, &length) == STATUS_INVALID_PARAMETER);
    assert(copies == 0 && !live_allocation && snapshot == NULL && length == 0);
    assert(ext4win_capture_io_manager_security_descriptor(source, 8, sizeof(source),
        &snapshot, &length) == STATUS_INVALID_PARAMETER);
}

static VOID test_ea_names(VOID)
{
    UCHAR names[] = { 0, 0, 0, 0, 3, 'F', 'O', 'O', 0 };
    static UCHAR maximum_names[65536];
    PVOID snapshot;
    ULONG length;
    begin(names, sizeof(names), NULL, 0);
    assert(ext4win_capture_io_manager_ea_name_list(names, sizeof(names),
        &snapshot, &length) == STATUS_SUCCESS);
    assert(length == sizeof(names) && snapshot != names);
    for (SIZE_T i = 0; i < length; ++i) { assert(((UCHAR *)snapshot)[i] == names[i]); }
    names[5] = 'X';
    assert(((UCHAR *)snapshot)[5] == 'F');
    ext4win_release_captured_auxiliary_input(snapshot);

    begin(maximum_names, sizeof(maximum_names), NULL, 0);
    assert(ext4win_capture_io_manager_ea_name_list(maximum_names, sizeof(maximum_names),
        &snapshot, &length) == STATUS_SUCCESS);
    assert(length == sizeof(maximum_names));
    ext4win_release_captured_auxiliary_input(snapshot);
    begin(maximum_names, sizeof(maximum_names), NULL, 0);
    assert(ext4win_capture_io_manager_ea_name_list(maximum_names, 65537,
        &snapshot, &length) == STATUS_INVALID_BUFFER_SIZE);
    assert(copies == 0 && !live_allocation && snapshot == NULL && length == 0);
    assert(ext4win_capture_io_manager_ea_name_list(NULL, 0,
        &snapshot, &length) == STATUS_SUCCESS && snapshot == NULL && length == 0);
    assert(ext4win_capture_io_manager_ea_name_list(NULL, 1,
        &snapshot, &length) == STATUS_INVALID_USER_BUFFER);

    begin(names, sizeof(names), NULL, 0);
    fail_allocation = 1;
    assert(ext4win_capture_io_manager_ea_name_list(names, sizeof(names),
        &snapshot, &length) == STATUS_INSUFFICIENT_RESOURCES);
    assert(!live_allocation && snapshot == NULL && length == 0);
    begin(names, sizeof(names), NULL, 0);
    fail_copy = 1;
    assert(ext4win_capture_io_manager_ea_name_list(names, sizeof(names),
        &snapshot, &length) == STATUS_ACCESS_VIOLATION);
    assert(!live_allocation && snapshot == NULL && length == 0);

    /* Exceptions outside the expected status set retain their outer failure authority. */
    begin(names, sizeof(names), NULL, 0);
    fail_copy = 1;
    copy_exception = (NTSTATUS)0xE0000001;
    int caught = 0;
    __try {
        ext4win_capture_io_manager_ea_name_list(names, sizeof(names), &snapshot, &length);
    } __except (GetExceptionCode() == copy_exception ? 1 : 0) { caught = 1; }
    assert(caught && live_allocation);
    /* The kernel's unexpected-exception policy is terminal, outside recoverable capture. */
    ext4win_release_captured_auxiliary_input(pool.bytes);
}

static VOID test_directory_patterns(VOID)
{
    WCHAR pattern[] = { '*', '.', 'r', 's' };
    UNICODE_STRING source = { sizeof(pattern), sizeof(pattern), pattern };
    PVOID snapshot;
    ULONG length;
    begin(&source, sizeof(source), pattern, sizeof(pattern));
    assert(ext4win_capture_io_manager_directory_pattern(&source, &snapshot, &length)
        == STATUS_SUCCESS);
    assert(length == sizeof(pattern) && ((WCHAR *)snapshot)[0] == '*');
    pattern[0] = 'X';
    assert(((WCHAR *)snapshot)[0] == '*');
    ext4win_release_captured_auxiliary_input(snapshot);

    for (ULONG fault = 1; fault <= 2; ++fault) {
        begin(&source, sizeof(source), pattern, sizeof(pattern));
        fail_copy = fault;
        assert(ext4win_capture_io_manager_directory_pattern(&source, &snapshot, &length)
            == STATUS_ACCESS_VIOLATION);
        assert(snapshot == NULL && length == 0 && !live_allocation);
    }
    begin(&source, sizeof(source), pattern, sizeof(pattern));
    source.Length--;
    assert(ext4win_capture_io_manager_directory_pattern(&source, &snapshot, &length)
        == STATUS_INVALID_PARAMETER);
    source.Length = 0;
    source.MaximumLength = 0;
    source.Buffer = NULL;
    assert(ext4win_capture_io_manager_directory_pattern(&source, &snapshot, &length)
        == STATUS_SUCCESS && snapshot == NULL && length == 0);
}

int main(VOID)
{
    test_descriptors();
    test_ea_names();
    test_directory_patterns();
    assert(allocations == frees && !live_allocation);
    return 0;
}
