#ifndef EXT4WIN_PNP_REMOVE_H
#define EXT4WIN_PNP_REMOVE_H

/* CANCEL_REMOVE travels to lower drivers first. The system PnP thread retains
 * original IRP ownership while waiting; no actor resource or allocation is held.
 * A lower failure leaves the reversible gate closed, and terminal media revocation
 * remains independent even after a successful cancellation. */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
ext4win_pnp_cancel_remove(
    _Inout_ PEXT4WIN_STORAGE_ADMISSION storage,
    _In_ PDEVICE_OBJECT lower,
    _Inout_ PIRP irp)
{
    irp->IoStatus.Status = STATUS_SUCCESS;
    if (!IoForwardIrpSynchronously(lower, irp)) { return STATUS_INVALID_DEVICE_REQUEST; }
    if (irp->IoStatus.Status >= STATUS_SUCCESS) {
        ext4win_storage_cancel_query_remove(storage);
    }
    return irp->IoStatus.Status;
}

#endif
