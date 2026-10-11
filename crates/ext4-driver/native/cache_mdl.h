#pragma once

/* Rust selects and bounds the transfer under stream resource ownership. C owns partial
 * chain cleanup through SEH. A failed write completion aborts chain ownership, without
 * promising rollback of dirty bytes or lower writeback already accepted by Cc. */
static NTSTATUS ext4win_cc_acquire_mdl(PFILE_OBJECT file, LONGLONG position, ULONG length,
    PMDL *chain, ULONG_PTR *information, BOOLEAN write)
{
    LARGE_INTEGER offset;
    IO_STATUS_BLOCK io_status = {0};
    NTSTATUS status;
    offset.QuadPart = position;
    *information = 0;
    __try {
        if (write) { CcPrepareMdlWrite(file, &offset, length, chain, &io_status); }
        else { CcMdlRead(file, &offset, length, chain, &io_status); }
        status = io_status.Status;
    }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) { status = GetExceptionCode(); }
    if (!NT_SUCCESS(status) && (*chain != NULL)) {
        if (write) { CcMdlWriteAbort(file, *chain); }
        else { CcMdlReadComplete(file, *chain); }
        *chain = NULL;
    }
    if (NT_SUCCESS(status)) { *information = io_status.Information; }
    return status;
}
NTSTATUS NTAPI ext4win_cc_read_mdl(PFILE_OBJECT file, LONGLONG offset, ULONG length,
    PMDL *chain, ULONG_PTR *information)
{
    return ext4win_cc_acquire_mdl(file, offset, length, chain, information, FALSE);
}
NTSTATUS NTAPI ext4win_cc_prepare_mdl_write(PFILE_OBJECT file, LONGLONG offset, ULONG length,
    PMDL *chain, ULONG_PTR *information)
{
    return ext4win_cc_acquire_mdl(file, offset, length, chain, information, TRUE);
}
NTSTATUS NTAPI ext4win_cc_complete_mdl_write(PFILE_OBJECT file, LONGLONG position, PMDL chain)
{
    LARGE_INTEGER offset;
    offset.QuadPart = position;
    __try { CcMdlWriteComplete(file, &offset, chain); }
    __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        NTSTATUS status = GetExceptionCode();
        CcMdlWriteAbort(file, chain);
        return status;
    }
    return STATUS_SUCCESS;
}
