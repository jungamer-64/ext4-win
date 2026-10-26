#pragma once

VOID NTAPI ext4win_account_lower_io(PIRP irp);
VOID NTAPI ext4win_account_request_io(PIRP irp, ULONGLONG read, ULONGLONG written, ULONG flush);

/* The containing nonpaged FCB owns this immutable map until its final FILE_OBJECT
 * and all I/O references are released. Publication precedes FILE_OBJECT attachment.
 * The direct path uses the original IRP/MDL: no allocation, worker, journal, or
 * filesystem resource is needed after paging-file admission. */
typedef struct _EXT4WIN_PAGING_FILE {
    volatile LONG Active;
    PDEVICE_OBJECT Lower;
    LONGLONG PhysicalStart;
    LONGLONG Length;
    ULONG SectorSize;
} EXT4WIN_PAGING_FILE, *PEXT4WIN_PAGING_FILE;

typedef struct _EXT4WIN_PAGING_MAPPING_PAIR {
    LONGLONG Length;
    LONGLONG PhysicalStart;
} EXT4WIN_PAGING_MAPPING_PAIR;

static NTSTATUS
ext4win_paging_complete(PIRP irp, NTSTATUS status)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* QUERY is the kernel paging-file pointer-return ABI. The requested prefix is
 * measured in bytes, and the caller owns the returned nonpaged allocation. */
static NTSTATUS
ext4win_paging_query(PEXT4WIN_PAGING_FILE map, PIRP irp, PIO_STACK_LOCATION stack)
{
    EXT4WIN_PAGING_MAPPING_PAIR *pairs = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    LONGLONG requested;
    if (irp->RequestorMode != KernelMode || map == NULL || map->Active != 1 ||
        stack->Parameters.FileSystemControl.InputBufferLength != sizeof(LARGE_INTEGER) ||
        stack->Parameters.FileSystemControl.OutputBufferLength != sizeof(PVOID) ||
        stack->Parameters.FileSystemControl.Type3InputBuffer == NULL || irp->UserBuffer == NULL) {
        return ext4win_paging_complete(irp, status);
    }
    __try {
        RtlCopyMemory(&requested, stack->Parameters.FileSystemControl.Type3InputBuffer, sizeof(requested));
        if (requested > 0 && requested <= map->Length) {
            pairs = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                2 * sizeof(EXT4WIN_PAGING_MAPPING_PAIR), (ULONG)0x50703445UL);
            if (pairs == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; }
            else {
                pairs[0].Length = requested;
                pairs[0].PhysicalStart = map->PhysicalStart;
                pairs[1].Length = 0;
                pairs[1].PhysicalStart = 0;
                *(EXT4WIN_PAGING_MAPPING_PAIR * UNALIGNED *)irp->UserBuffer = pairs;
                pairs = NULL;
                status = STATUS_SUCCESS;
            }
        }
    } __except (EXT4WIN_CATCH_EXPECTED_EXCEPTIONS) {
        status = (NTSTATUS)GetExceptionCode();
    }
    if (pairs != NULL) { ExFreePool(pairs); }
    return ext4win_paging_complete(irp, status);
}

static BOOLEAN
ext4win_paging_dispatch(PEXT4WIN_PAGING_FILE map, PIRP irp,
    BOOLEAN storage_available, NTSTATUS *status_out)
{
    PIO_STACK_LOCATION current = IoGetCurrentIrpStackLocation(irp);
    PIO_STACK_LOCATION next;
    LONGLONG offset;
    ULONG length;
    if (current->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL &&
        current->MinorFunction == IRP_MN_USER_FS_REQUEST &&
        current->Parameters.FileSystemControl.FsControlCode == FSCTL_QUERY_RETRIEVAL_POINTERS) {
        *status_out = ext4win_paging_query(map, irp, current);
        return TRUE;
    }
    if (map == NULL || map->Active != 1 ||
        (current->MajorFunction != IRP_MJ_READ && current->MajorFunction != IRP_MJ_WRITE)) {
        return FALSE;
    }
    if (!storage_available) {
        *status_out = ext4win_paging_complete(irp, STATUS_DEVICE_NOT_CONNECTED);
        return TRUE;
    }
    offset = current->Parameters.Read.ByteOffset.QuadPart;
    length = current->Parameters.Read.Length;
    if (irp->RequestorMode != KernelMode || (irp->Flags & IRP_PAGING_IO) == 0 ||
        offset < 0 || offset > map->Length || (ULONGLONG)length > (ULONGLONG)(map->Length - offset) ||
        map->SectorSize == 0 || ((ULONGLONG)offset % map->SectorSize) != 0 ||
        (length % map->SectorSize) != 0 ||
        (length != 0 && (irp->MdlAddress == NULL || MmGetMdlByteCount(irp->MdlAddress) < length))) {
        *status_out = ext4win_paging_complete(irp, STATUS_INVALID_PARAMETER);
        return TRUE;
    }
    if (length == 0) {
        *status_out = ext4win_paging_complete(irp, STATUS_SUCCESS);
        return TRUE;
    }
    /* The upper stack remains independent because its offset is file-relative.
     * Mark it pending before delegation; lower completion may free the original
     * request inline, and no completion callback or post-call IRP access is needed. */
    IoMarkIrpPending(irp);
    IoCopyCurrentIrpStackLocationToNext(irp);
    next = IoGetNextIrpStackLocation(irp);
    next->FileObject = NULL;
    next->Parameters.Read.ByteOffset.QuadPart = map->PhysicalStart + offset;
    ext4win_account_request_io(irp,
        current->MajorFunction == IRP_MJ_READ ? length : 0,
        current->MajorFunction == IRP_MJ_WRITE ? length : 0, 0);
    ext4win_account_lower_io(irp);
    *status_out = STATUS_PENDING;
    (VOID)IoCallDriver(map->Lower, irp);
    return TRUE;
}
