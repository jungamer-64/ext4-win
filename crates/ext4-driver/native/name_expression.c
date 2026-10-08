#include <ntifs.h>

/* FsRtl owns Windows expression semantics; expected allocation exceptions
 * become request failures before any directory cursor is published. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NTAPI ext4win_name_expression(
    _In_reads_bytes_(expression_length) const WCHAR *expression,
    _In_ USHORT expression_length,
    _In_reads_bytes_(name_length) const WCHAR *name,
    _In_ USHORT name_length,
    _Out_ BOOLEAN *matched)
{
    UNICODE_STRING expression_string;
    UNICODE_STRING name_string;
    expression_string.Buffer = (PWCH)expression;
    expression_string.Length = expression_length;
    expression_string.MaximumLength = expression_string.Length;
    name_string.Buffer = (PWCH)name;
    name_string.Length = name_length;
    name_string.MaximumLength = name_string.Length;
    *matched = FALSE;
    __try {
        *matched = FsRtlIsNameInExpression(&expression_string, &name_string, FALSE, NULL);
        return STATUS_SUCCESS;
    }
    __except (FsRtlIsNtstatusExpected(GetExceptionCode())
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return GetExceptionCode();
    }
}
