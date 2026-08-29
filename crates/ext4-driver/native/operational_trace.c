#include "operational_trace.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_trace_register(_Out_ PREGHANDLE registration_handle_out)
{
    if (registration_handle_out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *registration_handle_out = (REGHANDLE)0;
    return EtwRegister(
        &EXT4WIN_OPERATIONAL_TRACE_PROVIDER,
        NULL,
        NULL,
        registration_handle_out);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NTAPI
ext4win_trace_unregister(_In_ REGHANDLE registration_handle)
{
    if (registration_handle == (REGHANDLE)0) {
        return STATUS_INVALID_PARAMETER;
    }
    return EtwUnregister(registration_handle);
}

_IRQL_requires_max_(HIGH_LEVEL)
VOID
NTAPI
ext4win_trace_write(
    _In_ REGHANDLE registration_handle,
    _In_ USHORT event_id,
    _In_ NTSTATUS status,
    _In_ ULONG outcome)
{
    EVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR data[2];

    if ((registration_handle == (REGHANDLE)0) || (event_id == 0)) {
        return;
    }

    RtlZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.Id = event_id;
    descriptor.Level = EXT4WIN_OPERATIONAL_TRACE_LEVEL;
    descriptor.Keyword = EXT4WIN_OPERATIONAL_TRACE_KEYWORD;
    if (!EtwEventEnabled(registration_handle, &descriptor)) {
        return;
    }

    EventDataDescCreate(&data[0], &status, sizeof(status));
    EventDataDescCreate(&data[1], &outcome, sizeof(outcome));
    (VOID)EtwWrite(registration_handle, &descriptor, NULL, RTL_NUMBER_OF(data), data);
}
