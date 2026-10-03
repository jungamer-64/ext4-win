#pragma once

/* PASSIVE_LEVEL: the caller retains the FILE_OBJECT and IRP and holds the stream resource
 * for acquisitions. Writes are restricted to the committed EOF. A failed write-through
 * completion retains its chain in Cc; abort releases it before terminal IRP completion.
 * Abort does not roll back dirty cache bytes or a partial lower flush; failure preserves
 * the native status without promising that the file contents are unchanged. */
_Must_inspect_result_
static NTSTATUS
ext4win_cache_mdl_transfer(
    PFILE_OBJECT file_object,
    PIRP irp,
    ULONG action,
    LARGE_INTEGER offset,
    ULONG length,
    LONGLONG eof,
    ULONG_PTR *information_out)
{
    PMDL chain;
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;

    *information_out = 0;
    if ((action == 1) || (action == 3)) {
        chain = irp->MdlAddress;
        if (chain == NULL) {
            return STATUS_INVALID_PARAMETER;
        }
        if (action == 1) {
            CcMdlReadComplete(file_object, chain);
            status = STATUS_SUCCESS;
        }
        else {
            __try {
                CcMdlWriteComplete(file_object, &offset, chain);
                status = STATUS_SUCCESS;
            }
            __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
                status = GetExceptionCode();
                CcMdlWriteAbort(file_object, chain);
            }
        }
        irp->MdlAddress = NULL;
        return status;
    }
    if ((action != 0) && (action != 2)) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((offset.QuadPart < 0) || (irp->MdlAddress != NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (length == 0) {
        return STATUS_SUCCESS;
    }
    if (offset.QuadPart >= eof) {
        return (action == 0) ? STATUS_END_OF_FILE : STATUS_INVALID_PARAMETER;
    }
    if ((action == 2) && ((LONGLONG)length > eof - offset.QuadPart)) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((action == 0) && ((LONGLONG)length > eof - offset.QuadPart)) {
        length = (ULONG)(eof - offset.QuadPart);
    }
    io_status.Status = STATUS_SUCCESS;
    io_status.Information = 0;
    __try {
        if (action == 0) {
            CcMdlRead(file_object, &offset, length, &irp->MdlAddress, &io_status);
        }
        else {
            CcPrepareMdlWrite(file_object, &offset, length, &irp->MdlAddress, &io_status);
        }
        status = io_status.Status;
        if (NT_SUCCESS(status)) {
            *information_out = io_status.Information;
        }
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status) && (irp->MdlAddress != NULL)) {
        chain = irp->MdlAddress;
        if (action == 0) {
            CcMdlReadComplete(file_object, chain);
        }
        else {
            CcMdlWriteAbort(file_object, chain);
        }
        irp->MdlAddress = NULL;
    }
    return status;
}
