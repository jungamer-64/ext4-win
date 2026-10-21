/* Execute production private-IRP ownership against adversarial native schedules.
 * No kernel import or physical device is used by this oracle. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define NTAPI
#define _At_(target, annotation)
#define _Frees_ptr_
#define _Frees_ptr_opt_
#define _In_
#define _In_reads_bytes_opt_(length)
#define _Outptr_result_nullonfailure_
#define _Success_(condition)
#define NULL ((void *)0)
#define TRUE 1
#define FALSE 0
#define POOL_FLAG_NON_PAGED 1
#define NotificationEvent 0
#define IO_NO_INCREMENT 0
#define KernelMode 0
#define Executive 0
#define WaitAny 0
#define IRP_MJ_READ 3
#define IRP_MJ_DEVICE_CONTROL 14
#define IRP_READ_OPERATION 1
#define DO_BUFFERED_IO 4
#define DO_DIRECT_IO 16
#define METHOD_BUFFERED 0
#define MDL_PAGES_LOCKED 1
#define STATUS_SUCCESS 0
#define STATUS_WAIT_0 0
#define STATUS_PENDING 0x103
#define STATUS_TIMEOUT 0x102
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011)
#define STATUS_CANCELLED ((NTSTATUS)0xc0000120)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184)
#define STATUS_DEVICE_DATA_ERROR ((NTSTATUS)0xc000009c)
#define STATUS_MORE_PROCESSING_REQUIRED ((NTSTATUS)0xc0000016)
#define NT_SUCCESS(status) ((status) >= 0)

typedef void VOID, *PVOID;
typedef unsigned char BOOLEAN, UCHAR, KIRQL;
typedef signed char CCHAR;
typedef long NTSTATUS, LONG;
typedef unsigned long ULONG;
typedef unsigned long long ULONG_PTR, SIZE_T, *PULONG_PTR;
typedef struct { long long QuadPart; } LARGE_INTEGER;
typedef struct { unsigned held; } KSPIN_LOCK;
typedef struct { LONG signaled; } KEVENT, *PKEVENT;
typedef struct { NTSTATUS Status; ULONG_PTR Information; } IO_STATUS_BLOCK;
typedef struct _MDL { struct _MDL *Next; unsigned MdlFlags; PVOID Buffer; } MDL, *PMDL;
typedef struct { ULONG AlignmentRequirement, Flags; CCHAR StackSize; unsigned references; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct {
    UCHAR MajorFunction;
    union {
        struct { ULONG IoControlCode, InputBufferLength, OutputBufferLength; } DeviceIoControl;
        struct { ULONG Length; } Read;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
typedef struct _IRP IRP, *PIRP;
typedef NTSTATUS (*COMPLETION)(PDEVICE_OBJECT, PIRP, PVOID);
struct _IRP {
    PMDL MdlAddress;
    UCHAR RequestorMode;
    ULONG Flags;
    struct { PVOID SystemBuffer; } AssociatedIrp;
    PVOID UserBuffer;
    IO_STATUS_BLOCK IoStatus;
    IO_STACK_LOCATION Stack;
    COMPLETION Completion;
    PVOID Context;
};

static PVOID ExAllocatePool2(unsigned flags, SIZE_T size, ULONG tag);
static VOID ExFreePoolWithTag(PVOID allocation, ULONG tag);
static VOID RtlZeroMemory(PVOID bytes, SIZE_T size);
static VOID RtlCopyMemory(PVOID target, const VOID *source, SIZE_T size);
static VOID KeInitializeSpinLock(KSPIN_LOCK *lock) { lock->held = 0; }
static VOID KeAcquireSpinLock(KSPIN_LOCK *lock, KIRQL *irql) { assert(lock->held == 0); lock->held = 1; *irql = 0; }
static VOID KeReleaseSpinLock(KSPIN_LOCK *lock, KIRQL irql) { assert(lock->held == 1 && irql == 0); lock->held = 0; }
static VOID KeInitializeEvent(PKEVENT event, unsigned type, BOOLEAN signaled) { assert(type == NotificationEvent); event->signaled = signaled; }
static LONG KeSetEvent(PKEVENT event, unsigned priority, BOOLEAN wait);
static LONG InterlockedIncrement(volatile LONG *value) { return ++*value; }
static LONG InterlockedDecrement(volatile LONG *value) { return --*value; }
static LONG InterlockedExchange(volatile LONG *value, LONG next) { LONG previous = *value; *value = next; return previous; }
static LONG InterlockedCompareExchange(volatile LONG *value, LONG next, LONG expected) {
    LONG previous = *value;
    if (previous == expected) { *value = next; }
    return previous;
}
static VOID ObReferenceObject(PDEVICE_OBJECT device) { device->references++; }
static VOID ObDereferenceObject(PDEVICE_OBJECT device) { assert(device->references != 0); device->references--; }
static PIRP IoAllocateIrp(CCHAR stack, BOOLEAN charge);
static VOID IoFreeIrp(PIRP irp) { ExFreePoolWithTag(irp, 0); }
static PMDL IoAllocateMdl(PVOID buffer, ULONG size, BOOLEAN secondary, BOOLEAN charge, PIRP irp);
static VOID IoFreeMdl(PMDL mdl) { ExFreePoolWithTag(mdl, 0); }
static VOID MmUnlockPages(PMDL mdl) { mdl->MdlFlags &= ~MDL_PAGES_LOCKED; }
static VOID MmBuildMdlForNonPagedPool(PMDL mdl) { assert(mdl->MdlFlags == 0); }
static PIO_STACK_LOCATION IoGetNextIrpStackLocation(PIRP irp) { return &irp->Stack; }
static NTSTATUS IoSetCompletionRoutineEx(PDEVICE_OBJECT owner, PIRP irp, COMPLETION completion,
    PVOID context, BOOLEAN success, BOOLEAN error, BOOLEAN cancel);
static NTSTATUS IoCallDriver(PDEVICE_OBJECT device, PIRP irp);
static BOOLEAN IoCancelIrp(PIRP irp);
static NTSTATUS KeWaitForMultipleObjects(ULONG count, PVOID *objects, unsigned wait_type,
    unsigned reason, unsigned mode, BOOLEAN alertable, LARGE_INTEGER *timeout, PVOID blocks);

#include "discovery_io.h"

/* Fixed oracle-owned allocations expose double-free, pool retention and cleanup on OOM. */
_Alignas(16) static unsigned char allocations[16][200000];
static BOOLEAN occupied[16];
static LONG fail_allocation = -1;
static unsigned live_allocations, submissions, cancellations;
static BOOLEAN fail_registration, complete_on_cancel, probe_destroy, destroy_refused;
static DEVICE_OBJECT owner, target;
static EXT4WIN_DISCOVERY_CHANNEL *channel;
static PIRP pending_irp;
enum SCHEDULE { Inline, AtWait, Deadline, StopAtWait, StopAtSubmit, CompleteAfterDeadline, ShortRead };
static enum SCHEDULE schedule;

static VOID RtlZeroMemory(PVOID bytes, SIZE_T size) {
    unsigned char *out = bytes;
    while (size != 0) { *out++ = 0; size--; }
}
static VOID RtlCopyMemory(PVOID target_bytes, const VOID *source, SIZE_T size) {
    unsigned char *out = target_bytes;
    const unsigned char *in = source;
    while (size != 0) { *out++ = *in++; size--; }
}
static PVOID ExAllocatePool2(unsigned flags, SIZE_T size, ULONG tag) {
    unsigned index;
    (VOID)tag;
    assert(flags == POOL_FLAG_NON_PAGED && size <= sizeof(allocations[0]));
    if (fail_allocation == 0) { return NULL; }
    if (fail_allocation > 0) { fail_allocation--; }
    for (index = 0; index < 16; index++) {
        if (!occupied[index]) {
            occupied[index] = TRUE;
            live_allocations++;
            RtlZeroMemory(allocations[index], size);
            return allocations[index];
        }
    }
    assert(FALSE);
    return NULL;
}
static VOID ExFreePoolWithTag(PVOID allocation, ULONG tag) {
    unsigned index;
    (VOID)tag;
    for (index = 0; index < 16; index++) {
        if (allocation == allocations[index]) {
            assert(occupied[index]);
            occupied[index] = FALSE;
            live_allocations--;
            return;
        }
    }
    assert(FALSE);
}
static PIRP IoAllocateIrp(CCHAR stack, BOOLEAN charge) {
    assert(stack > 0 && !charge);
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IRP), 0);
}
static PMDL IoAllocateMdl(PVOID buffer, ULONG size, BOOLEAN secondary, BOOLEAN charge, PIRP irp) {
    PMDL mdl;
    assert(size != 0 && !secondary && !charge && irp->MdlAddress == NULL);
    mdl = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MDL), 0);
    if (mdl != NULL) { mdl->Buffer = buffer; irp->MdlAddress = mdl; }
    return mdl;
}
static NTSTATUS IoSetCompletionRoutineEx(PDEVICE_OBJECT device, PIRP irp, COMPLETION completion,
    PVOID context, BOOLEAN success, BOOLEAN error, BOOLEAN cancel) {
    assert(device == &owner && success && error && cancel);
    if (fail_registration) { return STATUS_INSUFFICIENT_RESOURCES; }
    irp->Completion = completion;
    irp->Context = context;
    return STATUS_SUCCESS;
}
static VOID complete(PIRP irp, NTSTATUS status, ULONG_PTR length) {
    EXT4WIN_DISCOVERY_REQUEST *request = irp->Context;
    unsigned char *bytes = request->Buffer;
    ULONG_PTR index;
    for (index = 0; index < length; index++) { bytes[index] = 0x7b; }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = length;
    assert(irp->Completion(&target, irp, request) == STATUS_MORE_PROCESSING_REQUIRED);
}
static ULONG transfer_length(PIRP irp) {
    return irp->Stack.MajorFunction == IRP_MJ_READ
        ? irp->Stack.Parameters.Read.Length
        : irp->Stack.Parameters.DeviceIoControl.OutputBufferLength;
}
static NTSTATUS IoCallDriver(PDEVICE_OBJECT device, PIRP irp) {
    assert(device == &target && target.references == 1);
    assert(channel->Lock.held == 0);
    pending_irp = irp;
    submissions++;
    if (irp->Stack.MajorFunction == IRP_MJ_READ) {
        EXT4WIN_DISCOVERY_REQUEST *request = irp->Context;
        assert(((ULONG_PTR)request->Buffer & 511) == 0);
    }
    if (schedule == Inline) { complete(irp, STATUS_SUCCESS, transfer_length(irp)); return STATUS_SUCCESS; }
    if (schedule == ShortRead) { complete(irp, STATUS_SUCCESS, 4); return STATUS_SUCCESS; }
    if (schedule == StopAtSubmit) {
        ext4win_discovery_channel_close(channel);
        assert(cancellations == 0); /* No cancellation before submit returns. */
    }
    return STATUS_PENDING;
}
static BOOLEAN IoCancelIrp(PIRP irp) {
    assert(channel->Lock.held == 0 && irp == pending_irp);
    cancellations++;
    if (complete_on_cancel) {
        unsigned before = live_allocations;
        probe_destroy = TRUE;
        complete(irp, STATUS_CANCELLED, 0);
        probe_destroy = FALSE;
        assert(live_allocations == before); /* Cancel still owns the IRP. */
        assert(((EXT4WIN_DISCOVERY_REQUEST *)irp->Context)->State == EXT4WIN_DISCOVERY_COMPLETED);
    }
    return TRUE;
}
static LONG KeSetEvent(PKEVENT event, unsigned priority, BOOLEAN wait) {
    LONG previous = event->signaled;
    assert(priority == IO_NO_INCREMENT && !wait);
    event->signaled = TRUE;
    if (probe_destroy && channel->Closed) {
        assert(!ext4win_discovery_channel_destroy(channel));
        destroy_refused = TRUE;
    }
    return previous;
}
static NTSTATUS KeWaitForMultipleObjects(ULONG count, PVOID *objects, unsigned wait_type,
    unsigned reason, unsigned mode, BOOLEAN alertable, LARGE_INTEGER *timeout, PVOID blocks) {
    PKEVENT done = objects[0], stopping = objects[1];
    assert(count == 2 && wait_type == WaitAny && reason == Executive && mode == KernelMode);
    assert(!alertable && timeout != NULL && timeout->QuadPart < 0 && blocks == NULL);
    if (schedule == AtWait) { complete(pending_irp, STATUS_SUCCESS, transfer_length(pending_irp)); }
    if (schedule == StopAtWait) { ext4win_discovery_channel_close(channel); }
    if (schedule == CompleteAfterDeadline) {
        complete(pending_irp, STATUS_SUCCESS, transfer_length(pending_irp));
        return STATUS_TIMEOUT;
    }
    if (done->signaled) { return STATUS_WAIT_0; }
    if (stopping->signaled) { return STATUS_WAIT_0 + 1; }
    return STATUS_TIMEOUT;
}

static VOID begin(enum SCHEDULE selected) {
    assert(live_allocations == 0 && target.references == 0);
    submissions = cancellations = 0;
    fail_allocation = -1;
    fail_registration = complete_on_cancel = probe_destroy = destroy_refused = FALSE;
    target.StackSize = 1;
    target.AlignmentRequirement = 511;
    target.Flags = DO_DIRECT_IO;
    schedule = selected;
    channel = ext4win_discovery_channel_create(&owner);
    assert(channel != NULL);
}
static VOID finish(VOID) {
    ext4win_discovery_channel_close(channel);
    assert(ext4win_discovery_channel_idle(channel));
    assert(ext4win_discovery_channel_destroy(channel));
    assert(live_allocations == 0 && target.references == 0);
}
static VOID completed_exchanges(VOID) {
    unsigned mode;
    for (mode = 0; mode < 3; mode++) {
        unsigned char output[512] = {0};
        begin(mode == 0 ? Inline : AtWait);
        target.Flags = mode == 0 ? DO_BUFFERED_IO : (mode == 1 ? DO_DIRECT_IO : 0);
        target.AlignmentRequirement = 0; /* Sector alignment must survive weaker device alignment. */
        assert(ext4win_read_volume_prefix(channel, &target, output, sizeof(output), 512) == STATUS_SUCCESS);
        assert(output[0] == 0x7b && output[3] == 0x7b);
        assert(ext4win_discovery_channel_idle(channel));
        assert(submissions == 1 && cancellations == 0 && live_allocations == 1);
        finish();
    }
}
static VOID late_completion_owns_every_lower_resource(VOID) {
    unsigned char input[4] = {1, 2, 3, 4}, output[4] = {0};
    ULONG_PTR transferred = 99;
    EXT4WIN_DISCOVERY_REQUEST *request;
    begin(Deadline);
    assert(ext4win_discovery_ioctl(channel, &target, 0, input, 4, output, 4, &transferred) == STATUS_IO_TIMEOUT);
    request = channel->Pending;
    assert(request != NULL && request->Buffer != output && request->Buffer != input);
    assert(((unsigned char *)request->Buffer)[0] == 1);
    assert(transferred == 0 && output[0] == 0 && target.references == 1);
    input[0] = 17; output[0] = 19;
    assert(!ext4win_discovery_channel_idle(channel));
    assert(ext4win_discovery_ioctl(channel, &target, 0, input, 4, output, 4, &transferred) == STATUS_DEVICE_BUSY);
    ext4win_discovery_channel_close(channel);
    assert(!ext4win_discovery_channel_destroy(channel));
    assert(submissions == 1 && cancellations == 1);
    complete(pending_irp, STATUS_SUCCESS, 4);
    assert(output[0] == 19 && input[0] == 17); /* No late writes to caller storage. */
    finish();
}
static VOID cancellation_and_completion_orders(VOID) {
    enum SCHEDULE orders[] = {Deadline, StopAtWait, StopAtSubmit, CompleteAfterDeadline};
    unsigned index;
    for (index = 0; index < sizeof(orders) / sizeof(orders[0]); index++) {
        unsigned char output[512] = {0};
        NTSTATUS status;
        begin(orders[index]);
        complete_on_cancel = TRUE;
        status = ext4win_read_volume_prefix(channel, &target, output, sizeof(output), 512);
        assert(status == (index == 1 || index == 2 ? STATUS_CANCELLED : STATUS_IO_TIMEOUT));
        assert(cancellations == (index == 3 ? 0U : 1U));
        assert(ext4win_discovery_channel_idle(channel));
        if (index == 1 || index == 2) { assert(destroy_refused); }
        finish();
    }
}
static VOID late_direct_read_retains_mdl_and_rejects_short_success(VOID) {
    unsigned char output[512] = {0};
    begin(Deadline);
    assert(ext4win_read_volume_prefix(channel, &target, output, sizeof(output), 512) == STATUS_IO_TIMEOUT);
    assert(channel->Pending != NULL && channel->Pending->Irp->MdlAddress != NULL);
    assert(channel->Pending->Irp->MdlAddress->Buffer == channel->Pending->Buffer);
    ext4win_discovery_channel_close(channel);
    assert(!ext4win_discovery_channel_destroy(channel));
    complete(pending_irp, STATUS_SUCCESS, sizeof(output));
    assert(output[0] == 0 && output[511] == 0);
    finish();

    begin(ShortRead);
    assert(ext4win_read_volume_prefix(channel, &target, output, sizeof(output), 512) == STATUS_DEVICE_DATA_ERROR);
    assert(output[0] == 0x7b && output[511] == 0);
    finish();
}
static VOID preparation_failures_release_unsubmitted_ownership(VOID) {
    LONG failure;
    for (failure = 0; failure < 5; failure++) {
        unsigned char output[512] = {0};
        begin(Inline);
        if (failure == 4) { fail_registration = TRUE; }
        else { fail_allocation = failure; }
        assert(ext4win_read_volume_prefix(channel, &target, output, sizeof(output), 512) == STATUS_INSUFFICIENT_RESOURCES);
        assert(submissions == 0 && cancellations == 0 && output[0] == 0);
        assert(ext4win_discovery_channel_idle(channel));
        fail_allocation = -1;
        finish();
    }
}
static VOID optional_input_requires_storage_for_nonzero_length(VOID) {
    unsigned char output[4] = {1, 2, 3, 4};
    ULONG_PTR transferred = 99;
    begin(Inline);
    assert(ext4win_discovery_ioctl(channel, &target, 0, NULL, 1, output,
        sizeof(output), &transferred) == STATUS_INVALID_PARAMETER);
    assert(transferred == 0);
    assert(output[0] == 1 && output[1] == 2 && output[2] == 3 && output[3] == 4);
    assert(submissions == 0 && cancellations == 0 && live_allocations == 1);
    assert(channel->Pending == NULL && target.references == 0);
    assert(ext4win_discovery_ioctl(channel, &target, 0, NULL, 0, output,
        sizeof(output), &transferred) == STATUS_SUCCESS);
    assert(transferred == sizeof(output));
    assert(output[0] == 0x7b && output[3] == 0x7b);
    assert(submissions == 1 && cancellations == 0);
    finish();
}
static VOID closed_and_invalid_requests_have_no_effect(VOID) {
    unsigned char output[512] = {0};
    ULONG_PTR transferred;
    begin(Inline);
    assert(ext4win_discovery_ioctl(channel, &target, 1, NULL, 0, output, 4, &transferred) == STATUS_INVALID_PARAMETER);
    assert(ext4win_discovery_ioctl(channel, &target, 0, NULL, 0, output,
        EXT4WIN_DISCOVERY_MAX_TRANSFER + 1, &transferred) == STATUS_INVALID_PARAMETER);
    assert(ext4win_read_volume_prefix(channel, &target, output, 4, 512) == STATUS_INVALID_PARAMETER);
    ext4win_discovery_channel_close(channel);
    assert(ext4win_read_volume_prefix(channel, &target, output, sizeof(output), 512) == STATUS_CANCELLED);
    assert(submissions == 0 && cancellations == 0 && live_allocations == 1);
    finish();
}
int main(VOID) {
    completed_exchanges();
    late_completion_owns_every_lower_resource();
    cancellation_and_completion_orders();
    late_direct_read_retains_mdl_and_rejects_short_success();
    preparation_failures_release_unsubmitted_ownership();
    optional_input_requires_storage_for_nonzero_length();
    closed_and_invalid_requests_have_no_effect();
    return 0;
}
