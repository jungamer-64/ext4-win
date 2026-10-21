#pragma once

#define EXT4WIN_DISCOVERY_POOL_TAG ((ULONG)0x44743445UL)
#define EXT4WIN_DISCOVERY_MAX_TRANSFER (128UL * 1024UL)
#define EXT4WIN_DISCOVERY_PENDING 0L
#define EXT4WIN_DISCOVERY_CANCEL_REQUESTED 1L
#define EXT4WIN_DISCOVERY_COMPLETED 2L

typedef struct _EXT4WIN_DISCOVERY_REQUEST EXT4WIN_DISCOVERY_REQUEST;

/* One bounded exchange slot. The discovery owner joins its worker and observes
 * quiescence before destroying this allocation.
 * A late lower request keeps the slot occupied; no replacement can forget it. */
typedef struct _EXT4WIN_DISCOVERY_CHANNEL {
    KSPIN_LOCK Lock;
    KEVENT Stopping;
    volatile LONG Closed;
    PDEVICE_OBJECT CompletionOwner;
    EXT4WIN_DISCOVERY_REQUEST *Pending;
} EXT4WIN_DISCOVERY_CHANNEL;

/* The caller, channel slot, completion callback and active cancel observer each
 * own a reference. Private IRP/MDL/buffer/device ownership ends only at zero,
 * even when cancellation completes synchronously inside IoCancelIrp. */
struct _EXT4WIN_DISCOVERY_REQUEST {
    volatile LONG References;
    volatile LONG State;
    volatile LONG Submitted;
    KEVENT Completed;
    IO_STATUS_BLOCK Result;
    PIRP Irp;
    PDEVICE_OBJECT Target;
    PVOID Allocation;
    PVOID Buffer;
};

static VOID ext4win_discovery_release_request(EXT4WIN_DISCOVERY_REQUEST *request)
{
    PMDL mdl, next;
    if (InterlockedDecrement(&request->References) != 0) { return; }
    if (request->Irp != NULL) {
        mdl = request->Irp->MdlAddress;
        request->Irp->MdlAddress = NULL;
        while (mdl != NULL) {
            next = mdl->Next;
            if ((mdl->MdlFlags & MDL_PAGES_LOCKED) != 0) { MmUnlockPages(mdl); }
            IoFreeMdl(mdl);
            mdl = next;
        }
        IoFreeIrp(request->Irp);
    }
    if (request->Allocation != NULL) {
        ExFreePoolWithTag(request->Allocation, EXT4WIN_DISCOVERY_POOL_TAG);
    }
    ObDereferenceObject(request->Target);
    ExFreePoolWithTag(request, EXT4WIN_DISCOVERY_POOL_TAG);
}

static VOID ext4win_discovery_cancel_request(EXT4WIN_DISCOVERY_REQUEST *request)
{
    /* Submission cannot be cancelled before IoCallDriver has returned. The worker
     * observes Closed again immediately after publishing Submitted. Its reference
     * and the cancel observer's reference both prevent completion from freeing IRP. */
    if (InterlockedCompareExchange(&request->Submitted, 0, 0) == 0) { return; }
    if (InterlockedCompareExchange(&request->State,
            EXT4WIN_DISCOVERY_CANCEL_REQUESTED, EXT4WIN_DISCOVERY_PENDING)
        == EXT4WIN_DISCOVERY_PENDING) {
        (VOID)IoCancelIrp(request->Irp);
    }
}

static NTSTATUS NTAPI ext4win_discovery_complete(
    PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    EXT4WIN_DISCOVERY_REQUEST *request = context;
    (VOID)device;
    request->Result = irp->IoStatus;
    InterlockedExchange(&request->State, EXT4WIN_DISCOVERY_COMPLETED);
    KeSetEvent(&request->Completed, IO_NO_INCREMENT, FALSE);
    /* No request/channel access follows release. IoSetCompletionRoutineEx keeps
     * the driver image resident until this native callback itself has returned. */
    ext4win_discovery_release_request(request);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/* Reap only the sole channel reference: callback/caller/cancel access must all
 * have ended before the channel can report quiescence or reuse its slot. */
BOOLEAN NTAPI ext4win_discovery_channel_idle(EXT4WIN_DISCOVERY_CHANNEL *channel)
{
    KIRQL irql;
    EXT4WIN_DISCOVERY_REQUEST *retired = NULL;
    BOOLEAN idle;
    KeAcquireSpinLock(&channel->Lock, &irql);
    if ((channel->Pending != NULL)
        && (InterlockedCompareExchange(&channel->Pending->State, 0, 0)
            == EXT4WIN_DISCOVERY_COMPLETED)
        && (InterlockedCompareExchange(&channel->Pending->References, 0, 0) == 1)) {
        retired = channel->Pending;
        channel->Pending = NULL;
    }
    idle = channel->Pending == NULL;
    KeReleaseSpinLock(&channel->Lock, irql);
    if (retired != NULL) { ext4win_discovery_release_request(retired); }
    return idle;
}

PVOID NTAPI ext4win_discovery_channel_create(PDEVICE_OBJECT owner)
{
    EXT4WIN_DISCOVERY_CHANNEL *channel = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*channel), EXT4WIN_DISCOVERY_POOL_TAG);
    if (channel == NULL) { return NULL; }
    KeInitializeSpinLock(&channel->Lock);
    KeInitializeEvent(&channel->Stopping, NotificationEvent, FALSE);
    channel->CompletionOwner = owner;
    return channel;
}

VOID NTAPI ext4win_discovery_channel_close(EXT4WIN_DISCOVERY_CHANNEL *channel)
{
    EXT4WIN_DISCOVERY_REQUEST *request;
    KIRQL irql;
    KeAcquireSpinLock(&channel->Lock, &irql);
    InterlockedExchange(&channel->Closed, TRUE);
    request = channel->Pending;
    if (request != NULL) { InterlockedIncrement(&request->References); }
    KeReleaseSpinLock(&channel->Lock, irql);
    KeSetEvent(&channel->Stopping, IO_NO_INCREMENT, FALSE);
    if (request != NULL) {
        ext4win_discovery_cancel_request(request);
        ext4win_discovery_release_request(request);
    }
}

/* Called only after the worker has joined. A failed destroy preserves ownership. */
BOOLEAN NTAPI ext4win_discovery_channel_destroy(EXT4WIN_DISCOVERY_CHANNEL *channel)
{
    if ((InterlockedCompareExchange(&channel->Closed, 0, 0) == 0)
        || !ext4win_discovery_channel_idle(channel)) { return FALSE; }
    ExFreePoolWithTag(channel, EXT4WIN_DISCOVERY_POOL_TAG);
    return TRUE;
}

static NTSTATUS ext4win_discovery_prepare(
    PDEVICE_OBJECT device, UCHAR major, ULONG code,
    const VOID *input, ULONG input_length, ULONG output_length, ULONG alignment_mask,
    EXT4WIN_DISCOVERY_REQUEST **prepared)
{
    EXT4WIN_DISCOVERY_REQUEST *request;
    PIO_STACK_LOCATION stack;
    ULONG length = input_length > output_length ? input_length : output_length;
    ULONG mask = device->AlignmentRequirement;
    *prepared = NULL;
    if ((length > EXT4WIN_DISCOVERY_MAX_TRANSFER) || (mask > 65535)
        || (((mask + 1) & mask) != 0) || (device->StackSize <= 0)
        || (alignment_mask > 65535) || (((alignment_mask + 1) & alignment_mask) != 0)
        || ((major == IRP_MJ_DEVICE_CONTROL) && ((code & 3) != METHOD_BUFFERED))
        || ((major == IRP_MJ_READ)
            && ((device->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO))
                == (DO_BUFFERED_IO | DO_DIRECT_IO)))) {
        return STATUS_INVALID_PARAMETER;
    }
    if (alignment_mask > mask) { mask = alignment_mask; }
    request = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*request), EXT4WIN_DISCOVERY_POOL_TAG);
    if (request == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    request->References = 1;
    request->Target = device;
    ObReferenceObject(device);
    KeInitializeEvent(&request->Completed, NotificationEvent, FALSE);
    request->Allocation = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        (SIZE_T)length + mask + 1, EXT4WIN_DISCOVERY_POOL_TAG);
    if (request->Allocation == NULL) {
        ext4win_discovery_release_request(request);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    request->Buffer = (PVOID)(((ULONG_PTR)request->Allocation + mask) & ~(ULONG_PTR)mask);
    if (input_length != 0) { RtlCopyMemory(request->Buffer, input, input_length); }
    request->Irp = IoAllocateIrp(device->StackSize, FALSE);
    if (request->Irp == NULL) {
        ext4win_discovery_release_request(request);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    request->Irp->RequestorMode = KernelMode;
    stack = IoGetNextIrpStackLocation(request->Irp);
    RtlZeroMemory(stack, sizeof(*stack));
    stack->MajorFunction = major;
    if (major == IRP_MJ_DEVICE_CONTROL) {
        stack->Parameters.DeviceIoControl.IoControlCode = code;
        stack->Parameters.DeviceIoControl.InputBufferLength = input_length;
        stack->Parameters.DeviceIoControl.OutputBufferLength = output_length;
        request->Irp->AssociatedIrp.SystemBuffer = request->Buffer;
    } else {
        request->Irp->Flags = IRP_READ_OPERATION;
        stack->Parameters.Read.Length = output_length;
        if ((device->Flags & DO_DIRECT_IO) != 0) {
            PMDL mdl = IoAllocateMdl(request->Buffer, output_length, FALSE, FALSE, request->Irp);
            if (mdl == NULL) {
                ext4win_discovery_release_request(request);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            MmBuildMdlForNonPagedPool(mdl);
        } else if ((device->Flags & DO_BUFFERED_IO) != 0) {
            request->Irp->AssociatedIrp.SystemBuffer = request->Buffer;
        } else {
            request->Irp->UserBuffer = request->Buffer;
        }
    }
    *prepared = request;
    return STATUS_SUCCESS;
}

/* A deadline or stop ends only the caller's borrow. Every late completion uses
 * request-owned buffers and a referenced target; cancellation is not completion.
 * One occupied slot bounds retained allocation independently of device behavior. */
static NTSTATUS ext4win_discovery_exchange(
    EXT4WIN_DISCOVERY_CHANNEL *channel, PDEVICE_OBJECT device, UCHAR major, ULONG code,
    const VOID *input, ULONG input_length, PVOID output, ULONG output_length,
    ULONG alignment_mask, PULONG_PTR transferred)
{
    EXT4WIN_DISCOVERY_REQUEST *request;
    KIRQL irql;
    PVOID events[2];
    LARGE_INTEGER deadline;
    NTSTATUS status;
    ULONG_PTR copied;
    *transferred = 0;
    if (!ext4win_discovery_channel_idle(channel)) { return STATUS_DEVICE_BUSY; }
    if (InterlockedCompareExchange(&channel->Closed, 0, 0) != 0) { return STATUS_CANCELLED; }
    status = ext4win_discovery_prepare(device, major, code,
        input, input_length, output_length, alignment_mask, &request);
    if (!NT_SUCCESS(status)) { return status; }
    KeAcquireSpinLock(&channel->Lock, &irql);
    if ((channel->Closed != 0) || (channel->Pending != NULL)) {
        KeReleaseSpinLock(&channel->Lock, irql);
        ext4win_discovery_release_request(request);
        return STATUS_CANCELLED;
    }
    InterlockedIncrement(&request->References); /* Channel slot. */
    channel->Pending = request;
    KeReleaseSpinLock(&channel->Lock, irql);
    InterlockedIncrement(&request->References); /* Completion, including inline return. */
    status = IoSetCompletionRoutineEx(channel->CompletionOwner, request->Irp,
        ext4win_discovery_complete, request, TRUE, TRUE, TRUE);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&request->State, EXT4WIN_DISCOVERY_COMPLETED);
        ext4win_discovery_release_request(request); /* No callback was registered. */
        ext4win_discovery_release_request(request); /* Caller. */
        return status;
    }
    (VOID)IoCallDriver(device, request->Irp);
    InterlockedExchange(&request->Submitted, TRUE);
    if (InterlockedCompareExchange(&channel->Closed, 0, 0) != 0) {
        ext4win_discovery_cancel_request(request);
    }
    events[0] = &request->Completed;
    events[1] = &channel->Stopping;
    deadline.QuadPart = -5LL * 1000 * 1000 * 10;
    status = KeWaitForMultipleObjects(2, events, WaitAny, Executive, KernelMode,
        FALSE, &deadline, NULL);
    if (status == STATUS_WAIT_0) {
        copied = request->Result.Information;
        if (copied > output_length) { copied = output_length; }
        if (copied != 0) { RtlCopyMemory(output, request->Buffer, copied); }
        *transferred = request->Result.Information;
        status = request->Result.Status;
    } else {
        ext4win_discovery_cancel_request(request);
        if (status == STATUS_TIMEOUT) { status = STATUS_IO_TIMEOUT; }
        else if (status == STATUS_WAIT_0 + 1) { status = STATUS_CANCELLED; }
        else if (NT_SUCCESS(status)) { status = STATUS_INVALID_DEVICE_STATE; }
    }
    ext4win_discovery_release_request(request);
    return status;
}

NTSTATUS NTAPI ext4win_discovery_ioctl(
    EXT4WIN_DISCOVERY_CHANNEL *channel, PDEVICE_OBJECT device, ULONG code,
    const VOID *input, ULONG input_length, PVOID output, ULONG output_length,
    PULONG_PTR transferred)
{
    return ext4win_discovery_exchange(channel, device, IRP_MJ_DEVICE_CONTROL, code,
        input, input_length, output, output_length, 0, transferred);
}

NTSTATUS NTAPI ext4win_read_volume_prefix(
    EXT4WIN_DISCOVERY_CHANNEL *channel, PDEVICE_OBJECT device, PVOID buffer, ULONG length,
    ULONG sector_size)
{
    ULONG_PTR transferred;
    NTSTATUS status;
    if ((sector_size < 512) || (sector_size > 65536)
        || ((sector_size & (sector_size - 1)) != 0)
        || (length == 0) || ((length % sector_size) != 0)) {
        return STATUS_INVALID_PARAMETER;
    }
    status = ext4win_discovery_exchange(channel, device, IRP_MJ_READ, 0,
        NULL, 0, buffer, length, sector_size - 1, &transferred);
    if (NT_SUCCESS(status) && (transferred != length)) { return STATUS_DEVICE_DATA_ERROR; }
    return status;
}
