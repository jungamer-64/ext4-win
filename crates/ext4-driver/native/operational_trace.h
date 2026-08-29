#pragma once

#include <ntifs.h>
#include "operational-trace-v1.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_trace_register(_Out_ PREGHANDLE registration_handle_out);

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_trace_unregister(_In_ REGHANDLE registration_handle);

_IRQL_requires_max_(HIGH_LEVEL)
VOID
NTAPI
ext4win_trace_write(
    _In_ REGHANDLE registration_handle,
    _In_ USHORT event_id,
    _In_ NTSTATUS status,
    _In_ ULONG outcome);
