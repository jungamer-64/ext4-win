#pragma once

VOID NTAPI ext4win_account_lower_io(PIRP irp);
VOID NTAPI ext4win_account_paging_io(PIRP irp, ULONGLONG read, ULONGLONG written, ULONG flush);
__declspec(noreturn) VOID NTAPI ext4win_paging_ownership_corruption(VOID);
extern UCHAR NTAPI ext4win_paging_begin(const VOID *state, LONGLONG offset, ULONG length,
    BOOLEAN request_valid, BOOLEAN available, NTSTATUS *status, PDEVICE_OBJECT *lower, LONGLONG *physical);
extern VOID NTAPI ext4win_paging_complete_transfer(const VOID *state);
extern BOOLEAN NTAPI ext4win_paging_query_prefix(const VOID *state, LONGLONG requested, LONGLONG *physical);
extern BOOLEAN NTAPI ext4win_paging_is_special(const VOID *state);
extern VOID NTAPI ext4win_paging_retire_owner(const VOID *state, PFILE_OBJECT owner);

/* Rust owns the map and completion obligation. The original upper FILE_OBJECT reference
 * keeps that state alive until this allocation-free native completion returns. */
static IO_COMPLETION_ROUTINE ext4win_paging_completed;
static NTSTATUS NTAPI
ext4win_paging_completed(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    PFILE_OBJECT file = IoGetCurrentIrpStackLocation(irp)->FileObject;
    UNREFERENCED_PARAMETER(device);
    if (context == NULL || file == NULL) { ext4win_paging_ownership_corruption(); }
    ext4win_paging_complete_transfer(context);
    ObDereferenceObject(file);
    return STATUS_CONTINUE_COMPLETION;
}

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

/* QUERY is the kernel pointer-return ABI. Rust selects the acknowledged prefix;
 * C contains external-pointer access and allocation ownership through SEH. */
static NTSTATUS
ext4win_paging_query(const VOID *state, PIRP irp, PIO_STACK_LOCATION stack)
{
    EXT4WIN_PAGING_MAPPING_PAIR *pairs = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    LONGLONG requested, physical;
    if (irp->RequestorMode != KernelMode || state == NULL ||
        stack->Parameters.FileSystemControl.InputBufferLength != sizeof(LARGE_INTEGER) ||
        stack->Parameters.FileSystemControl.OutputBufferLength != sizeof(PVOID) ||
        stack->Parameters.FileSystemControl.Type3InputBuffer == NULL || irp->UserBuffer == NULL) {
        return ext4win_paging_complete(irp, status);
    }
    __try {
        RtlCopyMemory(&requested, stack->Parameters.FileSystemControl.Type3InputBuffer, sizeof(requested));
        if (ext4win_paging_query_prefix(state, requested, &physical)) {
            pairs = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                2 * sizeof(EXT4WIN_PAGING_MAPPING_PAIR), (ULONG)0x50703445UL);
            if (pairs == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; }
            else {
                pairs[0].Length = requested;
                pairs[0].PhysicalStart = physical;
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
ext4win_paging_dispatch(PVOID state, PIRP irp, BOOLEAN available, NTSTATUS *status_out)
{
    PIO_STACK_LOCATION current = IoGetCurrentIrpStackLocation(irp);
    PIO_STACK_LOCATION next;
    PDEVICE_OBJECT lower = NULL;
    LONGLONG physical = 0;
    UCHAR action;
    ULONG length;
    BOOLEAN valid;
    if (current->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL &&
        current->MinorFunction == IRP_MN_USER_FS_REQUEST &&
        current->Parameters.FileSystemControl.FsControlCode == FSCTL_QUERY_RETRIEVAL_POINTERS) {
        *status_out = ext4win_paging_query(state, irp, current);
        return TRUE;
    }
    if (state == NULL ||
        (current->MajorFunction != IRP_MJ_READ && current->MajorFunction != IRP_MJ_WRITE)) { return FALSE; }
    length = current->Parameters.Read.Length;
    valid = irp->RequestorMode == KernelMode && (irp->Flags & IRP_PAGING_IO) != 0 &&
        (length == 0 || (irp->MdlAddress != NULL && MmGetMdlByteCount(irp->MdlAddress) >= length));
    action = ext4win_paging_begin(state, current->Parameters.Read.ByteOffset.QuadPart,
        length, valid, available, status_out, &lower, &physical);
    if (action != 2) {
        if (action == 0) { return FALSE; }
        *status_out = ext4win_paging_complete(irp, *status_out);
        return TRUE;
    }
    /* Dispatch still owns the original FILE_OBJECT. Acquire its independent completion
     * reference only after Rust admits forwarding; ordinary fallback performs no retain. */
    ObReferenceObject(current->FileObject);
    /* Lower completion can free the original IRP inline. Publish pending before delegation
     * and make no access to the original request after IoCallDriver. */
    IoMarkIrpPending(irp);
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, ext4win_paging_completed, state, TRUE, TRUE, TRUE);
    next = IoGetNextIrpStackLocation(irp);
    next->FileObject = NULL;
    next->Parameters.Read.ByteOffset.QuadPart = physical;
    ext4win_account_paging_io(irp,
        current->MajorFunction == IRP_MJ_READ ? length : 0,
        current->MajorFunction == IRP_MJ_WRITE ? length : 0, 0);
    ext4win_account_lower_io(irp);
    *status_out = STATUS_PENDING;
    (VOID)IoCallDriver(lower, irp);
    return TRUE;
}
