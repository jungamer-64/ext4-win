#pragma once

VOID NTAPI ext4win_account_lower_io(PIRP irp);
VOID NTAPI ext4win_account_paging_io(PIRP irp, ULONGLONG read, ULONGLONG written, ULONG flush);
__declspec(noreturn) VOID NTAPI ext4win_paging_ownership_corruption(VOID);

/* The containing nonpaged FCB owns the map, state lock, and drain notifications.
 * Active/Extending admit original-IRP data transfers over the acknowledged prefix.
 * Preparing owns an unpublished setup; Extending keeps the old physical prefix
 * usable while a unique setup initializes its tail. Retirement closes admission,
 * waits for every forwarded completion, and only then permits allocation release. */
#define EXT4WIN_PAGING_VACANT 0
#define EXT4WIN_PAGING_PREPARING (-1)
#define EXT4WIN_PAGING_ACTIVE 1
#define EXT4WIN_PAGING_EXTENDING 2
#define EXT4WIN_PAGING_RETIRING 3
#define EXT4WIN_PAGING_RETIRED 4
typedef struct _EXT4WIN_PAGING_FILE {
    volatile LONG Active;
    KSPIN_LOCK Lock;
    KEVENT Idle;
    KEVENT SetupDone;
    ULONG InFlight;
    PFILE_OBJECT Owner;
    PDEVICE_OBJECT Lower;
    LONGLONG PhysicalStart;
    LONGLONG Length;
    ULONG SectorSize;
} EXT4WIN_PAGING_FILE, *PEXT4WIN_PAGING_FILE;

static VOID
ext4win_paging_initialize(PEXT4WIN_PAGING_FILE map)
{
    KeInitializeSpinLock(&map->Lock);
    KeInitializeEvent(&map->Idle, NotificationEvent, TRUE);
    KeInitializeEvent(&map->SetupDone, NotificationEvent, TRUE);
}

/* Reserve/rollback/activate are paired by one retained Rust setup lease. */
static NTSTATUS
ext4win_paging_reserve(PEXT4WIN_PAGING_FILE map, PFILE_OBJECT owner, BOOLEAN extension,
    LONGLONG *physical, LONGLONG *length)
{
    KIRQL irql;
    NTSTATUS status = STATUS_SHARING_VIOLATION;
    KeAcquireSpinLock(&map->Lock, &irql);
    if ((!extension && map->Active == EXT4WIN_PAGING_VACANT) ||
        (extension && map->Active == EXT4WIN_PAGING_ACTIVE)) {
        *physical = extension ? map->PhysicalStart : 0;
        *length = extension ? map->Length : 0;
        if (!extension) { map->Owner = owner; }
        map->Active = extension ? EXT4WIN_PAGING_EXTENDING : EXT4WIN_PAGING_PREPARING;
        KeClearEvent(&map->SetupDone);
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&map->Lock, irql);
    return status;
}

static VOID
ext4win_paging_abort(PEXT4WIN_PAGING_FILE map, BOOLEAN extension)
{
    KIRQL irql;
    KeAcquireSpinLock(&map->Lock, &irql);
    if (map->Active == (extension ? EXT4WIN_PAGING_EXTENDING : EXT4WIN_PAGING_PREPARING)) {
        map->Active = extension ? EXT4WIN_PAGING_ACTIVE : EXT4WIN_PAGING_VACANT;
        if (!extension) { map->Owner = NULL; }
        KeSetEvent(&map->SetupDone, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&map->Lock, irql);
}

static NTSTATUS
ext4win_paging_activate(PEXT4WIN_PAGING_FILE map, BOOLEAN extension,
    PDEVICE_OBJECT lower, LONGLONG physical, LONGLONG length, ULONG sector_size)
{
    KIRQL irql;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    KeAcquireSpinLock(&map->Lock, &irql);
    if (map->Active == (extension ? EXT4WIN_PAGING_EXTENDING : EXT4WIN_PAGING_PREPARING) &&
        (!extension || (map->PhysicalStart == physical && map->Length <= length))) {
        map->Lower = lower;
        map->PhysicalStart = physical;
        map->Length = length;
        map->SectorSize = sector_size;
        map->Active = EXT4WIN_PAGING_ACTIVE;
        KeSetEvent(&map->SetupDone, IO_NO_INCREMENT, FALSE);
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&map->Lock, irql);
    return status;
}

/* Only the activating FILE_OBJECT owns map retirement. Reopened control handles
 * release their own CCB without revoking the Memory Manager's paging authority. */
static VOID
ext4win_paging_retire(PEXT4WIN_PAGING_FILE map, PFILE_OBJECT owner)
{
    KIRQL irql;
    for (;;) {
        KeAcquireSpinLock(&map->Lock, &irql);
        if (map->Owner != owner || map->Active == EXT4WIN_PAGING_VACANT ||
            map->Active == EXT4WIN_PAGING_RETIRED) {
            KeReleaseSpinLock(&map->Lock, irql);
            return;
        }
        if (map->Active == EXT4WIN_PAGING_EXTENDING) {
            KeReleaseSpinLock(&map->Lock, irql);
            (VOID)KeWaitForSingleObject(&map->SetupDone, Executive, KernelMode, FALSE, NULL);
            continue;
        }
        map->Active = EXT4WIN_PAGING_RETIRING;
        KeReleaseSpinLock(&map->Lock, irql);
        (VOID)KeWaitForSingleObject(&map->Idle, Executive, KernelMode, FALSE, NULL);
        KeAcquireSpinLock(&map->Lock, &irql);
        if (map->InFlight == 0) {
            map->Active = EXT4WIN_PAGING_RETIRED;
            KeReleaseSpinLock(&map->Lock, irql);
            return;
        }
        KeReleaseSpinLock(&map->Lock, irql);
    }
}

static IO_COMPLETION_ROUTINE ext4win_paging_completed;

static NTSTATUS NTAPI
ext4win_paging_completed(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    PEXT4WIN_PAGING_FILE map = (PEXT4WIN_PAGING_FILE)context;
    PFILE_OBJECT file = IoGetCurrentIrpStackLocation(irp)->FileObject;
    KIRQL irql;
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(irp);
    /* This callback is registered only with a retained non-null map and an
     * explicitly referenced upper FILE_OBJECT. Losing either consumes an
     * unidentifiable in-flight allocation owner and cannot continue safely. */
    if (map == NULL || file == NULL) { ext4win_paging_ownership_corruption(); }
    KeAcquireSpinLock(&map->Lock, &irql);
    if (map->InFlight == 0) { ext4win_paging_ownership_corruption(); }
    --map->InFlight;
    if (map->InFlight == 0) { KeSetEvent(&map->Idle, IO_NO_INCREMENT, FALSE); }
    KeReleaseSpinLock(&map->Lock, irql);
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

/* QUERY is the kernel paging-file pointer-return ABI. The requested prefix is
 * measured in bytes, and the caller owns the returned nonpaged allocation. */
static NTSTATUS
ext4win_paging_query(PEXT4WIN_PAGING_FILE map, PIRP irp, PIO_STACK_LOCATION stack)
{
    EXT4WIN_PAGING_MAPPING_PAIR *pairs = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    LONGLONG requested, physical, length;
    KIRQL irql;
    if (irp->RequestorMode != KernelMode || map == NULL ||
        stack->Parameters.FileSystemControl.InputBufferLength != sizeof(LARGE_INTEGER) ||
        stack->Parameters.FileSystemControl.OutputBufferLength != sizeof(PVOID) ||
        stack->Parameters.FileSystemControl.Type3InputBuffer == NULL || irp->UserBuffer == NULL) {
        return ext4win_paging_complete(irp, status);
    }
    KeAcquireSpinLock(&map->Lock, &irql);
    if (map->Active != EXT4WIN_PAGING_ACTIVE && map->Active != EXT4WIN_PAGING_EXTENDING) {
        KeReleaseSpinLock(&map->Lock, irql);
        return ext4win_paging_complete(irp, status);
    }
    physical = map->PhysicalStart;
    length = map->Length;
    KeReleaseSpinLock(&map->Lock, irql);
    __try {
        RtlCopyMemory(&requested, stack->Parameters.FileSystemControl.Type3InputBuffer, sizeof(requested));
        if (requested > 0 && requested <= length) {
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
ext4win_paging_dispatch(PEXT4WIN_PAGING_FILE map, PIRP irp,
    BOOLEAN storage_available, NTSTATUS *status_out)
{
    PIO_STACK_LOCATION current = IoGetCurrentIrpStackLocation(irp);
    PIO_STACK_LOCATION next;
    LONGLONG offset;
    ULONG length;
    LONGLONG physical;
    PDEVICE_OBJECT lower;
    KIRQL irql;
    if (current->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL &&
        current->MinorFunction == IRP_MN_USER_FS_REQUEST &&
        current->Parameters.FileSystemControl.FsControlCode == FSCTL_QUERY_RETRIEVAL_POINTERS) {
        *status_out = ext4win_paging_query(map, irp, current);
        return TRUE;
    }
    if (map == NULL ||
        (current->MajorFunction != IRP_MJ_READ && current->MajorFunction != IRP_MJ_WRITE)) {
        return FALSE;
    }
    KeAcquireSpinLock(&map->Lock, &irql);
    if (map->Active == EXT4WIN_PAGING_VACANT) {
        KeReleaseSpinLock(&map->Lock, irql);
        return FALSE;
    }
    if (map->Active != EXT4WIN_PAGING_ACTIVE && map->Active != EXT4WIN_PAGING_EXTENDING) {
        KeReleaseSpinLock(&map->Lock, irql);
        *status_out = ext4win_paging_complete(irp, STATUS_FILE_CLOSED);
        return TRUE;
    }
    if (!storage_available) {
        KeReleaseSpinLock(&map->Lock, irql);
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
        KeReleaseSpinLock(&map->Lock, irql);
        *status_out = ext4win_paging_complete(irp, STATUS_INVALID_PARAMETER);
        return TRUE;
    }
    if (length == 0) {
        KeReleaseSpinLock(&map->Lock, irql);
        *status_out = ext4win_paging_complete(irp, STATUS_SUCCESS);
        return TRUE;
    }
    if (map->InFlight == MAXULONG) {
        KeReleaseSpinLock(&map->Lock, irql);
        *status_out = ext4win_paging_complete(irp, STATUS_INSUFFICIENT_RESOURCES);
        return TRUE;
    }
    physical = map->PhysicalStart + offset;
    lower = map->Lower;
    ObReferenceObject(current->FileObject);
    if (map->InFlight++ == 0) { KeClearEvent(&map->Idle); }
    KeReleaseSpinLock(&map->Lock, irql);
    /* The upper stack remains independent because its offset is file-relative.
     * Mark it pending before delegation; lower completion may free the original
     * request inline. The allocation-free completion releases its in-flight lease;
     * this dispatch makes no post-call access to the original IRP. */
    IoMarkIrpPending(irp);
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, ext4win_paging_completed, map, TRUE, TRUE, TRUE);
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
