#pragma once

/* Immediate dispatch has not marked the IRP pending and retains no completion
 * callback. The lower driver may reuse that dispatch stack location. */
_Must_inspect_result_
NTSTATUS NTAPI
ext4win_forward_original_irp(_In_ PDEVICE_OBJECT device, _Inout_ PIRP irp)
{
    IoSkipCurrentIrpStackLocation(irp);
    return IoCallDriver(device, irp);
}

/* Queued dispatch already published SL_PENDING_RETURNED. Keep its stack
 * location independent of lower-driver changes until completion unwinds. */
_Must_inspect_result_
NTSTATUS NTAPI
ext4win_forward_pending_irp(_In_ PDEVICE_OBJECT device, _Inout_ PIRP irp)
{
    IoCopyCurrentIrpStackLocationToNext(irp);
    return IoCallDriver(device, irp);
}
