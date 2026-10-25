/* Production delegation and outcome propagation; the validators themselves require a
 * loaded driver. These doubles never implement or claim Windows format validation. */
#include <stddef.h>
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
#define assert(condition) do { if (!(condition)) { ExitProcess(__LINE__); } } while (0)
#define _IRQL_requires_(level)
#define _Must_inspect_result_
#define _In_reads_bytes_(length)
#define _In_
#define _Out_
#define NTAPI __stdcall
typedef unsigned char UCHAR;
typedef unsigned long ULONG;
typedef long NTSTATUS;
typedef void *PFILE_FULL_EA_INFORMATION;
typedef void *PREPARSE_DATA_BUFFER;
static const UCHAR *expected;
static ULONG expected_length;
static NTSTATUS result;
static ULONG calls;
static NTSTATUS IoCheckEaBufferValidity(PFILE_FULL_EA_INFORMATION bytes, ULONG length, ULONG *offset)
{
    assert(bytes == expected && length == expected_length);
    assert(*offset == 0);
    ++calls;
    *offset = 28;
    return result;
}
static NTSTATUS FsRtlValidateReparsePointBuffer(ULONG length, PREPARSE_DATA_BUFFER bytes)
{
    assert(bytes == expected && length == expected_length);
    ++calls;
    return result;
}
#include "input_validation.h"
int main(void)
{
    UCHAR bytes[64] = {0};
    ULONG offset = 100;
    expected = bytes;
    expected_length = sizeof(bytes);
    result = (NTSTATUS)0x80000014L; /* STATUS_EA_LIST_INCONSISTENT */
    assert(ext4win_validate_full_ea(bytes, sizeof(bytes), &offset) == result);
    assert(offset == 28 && calls == 1);
    result = 0;
    assert(ext4win_validate_full_ea(bytes, sizeof(bytes), &offset) == 0);
    assert(calls == 2);
    result = (NTSTATUS)0xc0000278L;
    assert(ext4win_validate_reparse(bytes, sizeof(bytes)) == result);
    result = (NTSTATUS)0xc0000276L;
    assert(ext4win_validate_reparse(bytes, sizeof(bytes)) == result);
    result = 0;
    assert(ext4win_validate_reparse(bytes, sizeof(bytes)) == 0 && calls == 5);
    ExitProcess(0);
}
