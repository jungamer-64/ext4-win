/* Fault oracle executes the production persistence sequence against independent DDI outcomes. */
#include <stdint.h>
#include <stddef.h>
typedef int32_t NTSTATUS;
typedef uint32_t ULONG;
typedef ULONG *PULONG;
typedef uint8_t UCHAR;
typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR;
typedef void *HANDLE;
typedef HANDLE *PHANDLE;
typedef void *PVOID;
typedef uint8_t BOOLEAN;
typedef ULONG ACCESS_MASK;
typedef struct {
    uint16_t Length;
    uint16_t MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#define TRUE 1
#define KEY_SET_VALUE 2
#define KEY_QUERY_VALUE 1
#define REG_BINARY 3
#define NT_SUCCESS(value) ((value) >= 0)
#define PAGED_CODE() ((void)0)
/* Standalone oracle links without a CRT; this supplies the compiler's aggregate initializer. */
void *memset(void *destination, int value, size_t length)
{
    volatile UCHAR *bytes = destination;
    while (length != 0) { *bytes++ = (UCHAR)value; length--; }
    return destination;
}
static NTSTATUS open_status, set_status, flush_status;
static ULONG opened, set, flushed, closed, invalid;
static int root_storage, key_storage;
static NTSTATUS identity_key(HANDLE root, PUNICODE_STRING name,
    ACCESS_MASK access, BOOLEAN create, PHANDLE key)
{
    opened++;
    if (root != &root_storage || name->Length != 72 ||
        name->MaximumLength != 72 || access != (KEY_SET_VALUE | KEY_QUERY_VALUE) || create != TRUE) {
        invalid++;
    }
    if (NT_SUCCESS(open_status)) { *key = &key_storage; }
    return open_status;
}
static void RtlInitUnicodeString(PUNICODE_STRING value, const WCHAR *text)
{
    value->Length = 10;
    value->MaximumLength = 12;
    value->Buffer = (PWCHAR)text;
}
static NTSTATUS ZwSetValueKey(HANDLE key, PUNICODE_STRING name,
    ULONG title, ULONG kind, PVOID data, ULONG length)
{
    set++;
    if (key != &key_storage || name->Length != 10 || title != 0 ||
        kind != REG_BINARY || data == NULL || length != 4 || closed != 0) {
        invalid++;
    }
    return set_status;
}
static NTSTATUS ZwFlushKey(HANDLE key)
{
    flushed++;
    if (key != &key_storage || set != 1 || closed != 0) { invalid++; }
    return flush_status;
}
static NTSTATUS ZwClose(HANDLE key)
{
    closed++;
    if (key != &key_storage || closed != 1) { invalid++; }
    return 0;
}
#include "identity_persistence.h"

int main(void)
{
    static const UCHAR record[4] = {1, 2, 3, 4};
    WCHAR uuid[36];
    ULONG phase;
    NTSTATUS status;
    ULONG index;
    for (index = 0; index < 36; index++) { uuid[index] = L'0'; }
    open_status = -17;
    status = ext4win_identity_save(&root_storage, uuid, record, 4, &phase);
    if (status != -17 || phase != 0 || opened != 1 || set || flushed || closed || invalid) { return 1; }
    open_status = 0;
    opened = 0;
    set_status = -18;
    status = ext4win_identity_save(&root_storage, uuid, record, 4, &phase);
    if (status != -18 || phase != 3 || opened != 1 || set != 1 || flushed || closed != 1 || invalid) { return 2; }
    opened = set = closed = 0;
    set_status = 0;
    flush_status = -19;
    status = ext4win_identity_save(&root_storage, uuid, record, 4, &phase);
    if (status != -19 || phase != 3 || opened != 1 || set != 1 || flushed != 1 || closed != 1 || invalid) { return 3; }
    opened = set = flushed = closed = 0;
    flush_status = 0;
    status = ext4win_identity_save(&root_storage, uuid, record, 4, &phase);
    if (status != 0 || phase != 1 || opened != 1 || set != 1 || flushed != 1 || closed != 1 || invalid) { return 4; }
    return 0;
}
