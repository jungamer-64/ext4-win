#include <ntifs.h>
#include <ntdddisk.h>
#include <mountdev.h>
#include <ntiologc.h>

/* All calls run on the discovery system thread. Rust retains the referenced
 * volume until the complete synchronous exchange returns. No partition-table
 * writes, interface registration on foreign PDOs, or synthetic identities occur.
 */
static NTSTATUS
volume_ioctl(
    PDEVICE_OBJECT device, ULONG code,
    PVOID input, ULONG input_length, PVOID output, ULONG output_length,
    PULONG_PTR transferred)
{
    KEVENT event;
    IO_STATUS_BLOCK completion = {0};
    PIRP irp;
    NTSTATUS status;
    *transferred = 0;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp = IoBuildDeviceIoControlRequest(
        code, device, input, input_length, output, output_length,
        FALSE, &event, &completion);
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = IoCallDriver(device, irp);
    if (status == STATUS_PENDING) {
        /* Nonalertable KernelMode wait: buffers and completion storage cannot
         * be released while the I/O manager still owns this request. */
        (VOID)KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = completion.Status;
    }
    *transferred = completion.Information;
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NTAPI
ext4win_query_volume_partition(
    _In_ PDEVICE_OBJECT device,
    _Out_ GUID *partition_type,
    _Out_ ULONGLONG *attributes)
{
    PARTITION_INFORMATION_EX partition = {0};
    ULONG_PTR transferred;
    NTSTATUS status = volume_ioctl(
        device, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0,
        &partition, sizeof(partition), &transferred);
    if (!NT_SUCCESS(status)) { return status; }
    if (transferred < sizeof(partition)) { return STATUS_INFO_LENGTH_MISMATCH; }
    if (partition.PartitionStyle != PARTITION_STYLE_GPT) {
        return STATUS_NOT_SUPPORTED;
    }
    *partition_type = partition.Gpt.PartitionType;
    *attributes = partition.Gpt.Attributes;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NTAPI
ext4win_query_volume_sector_size(
    _In_ PDEVICE_OBJECT device, _Out_ ULONG *sector_size)
{
    DISK_GEOMETRY geometry = {0};
    ULONG_PTR transferred;
    NTSTATUS status = volume_ioctl(
        device, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
        &geometry, sizeof(geometry), &transferred);
    if (!NT_SUCCESS(status)) { return status; }
    if (transferred < sizeof(geometry)) { return STATUS_INFO_LENGTH_MISMATCH; }
    *sector_size = geometry.BytesPerSector;
    return STATUS_SUCCESS;
}

/* The caller supplies a nonpaged, device-aligned, sector-multiple allocation.
 * Completion consumes the IRP, not the caller's allocation. The prefix remains
 * borrowed exclusively until this routine has observed final completion. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NTAPI
ext4win_read_volume_prefix(
    _In_ PDEVICE_OBJECT device,
    _Out_writes_bytes_(length) PVOID buffer, _In_ ULONG length)
{
    KEVENT event;
    IO_STATUS_BLOCK completion = {0};
    LARGE_INTEGER offset;
    PIRP irp;
    NTSTATUS status;
    offset.QuadPart = 0;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp = IoBuildSynchronousFsdRequest(
        IRP_MJ_READ, device, buffer, length, &offset, &event, &completion);
    if (irp == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    status = IoCallDriver(device, irp);
    if (status == STATUS_PENDING) {
        (VOID)KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = completion.Status;
    }
    if (NT_SUCCESS(status) && completion.Information != length) {
        return STATUS_DEVICE_DATA_ERROR;
    }
    return status;
}

/* A fully constructed name query distinguishes absence from transport failure.
 * BUFFER_OVERFLOW means matching points exist; the points themselves are not
 * needed here. A successful empty result still means the volume is registered.
 */
static NTSTATUS
query_registration(PDEVICE_OBJECT manager, PMOUNTMGR_MOUNT_POINT query, ULONG size)
{
    MOUNTMGR_MOUNT_POINTS points = {0};
    ULONG_PTR transferred;
    NTSTATUS status = volume_ioctl(
        manager, IOCTL_MOUNTMGR_QUERY_POINTS, query, size,
        &points, sizeof(points), &transferred);
    if (status == STATUS_BUFFER_OVERFLOW) { return STATUS_SUCCESS; }
    return status;
}

/* Mount Manager owns persistent names and their target-device lifetime. This
 * operation publishes the existing lower stack, not a driver-owned endpoint.
 * Queries reconcile repeated discovery and an ambiguous arrival completion;
 * callers must never delete shared mount points as rollback for an error.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NTAPI
ext4win_announce_volume(_In_ PDEVICE_OBJECT device)
{
    MOUNTDEV_NAME header = {0};
    PMOUNTDEV_NAME name = NULL;
    PMOUNTMGR_MOUNT_POINT query = NULL;
    PMOUNTMGR_TARGET_NAME target = NULL;
    PFILE_OBJECT manager_file = NULL;
    PDEVICE_OBJECT manager = NULL;
    UNICODE_STRING manager_name = RTL_CONSTANT_STRING(MOUNTMGR_DEVICE_NAME);
    ULONG_PTR transferred;
    ULONG name_size;
    ULONG query_size;
    ULONG target_size;
    NTSTATUS status;
    NTSTATUS arrival_status;

    status = volume_ioctl(device, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME,
        NULL, 0, &header, sizeof(header), &transferred);
    if (status != STATUS_BUFFER_OVERFLOW && !NT_SUCCESS(status)) { return status; }
    if (transferred < sizeof(USHORT) || header.NameLength == 0 ||
        (header.NameLength % sizeof(WCHAR)) != 0) {
        return STATUS_OBJECT_NAME_INVALID;
    }
    name_size = FIELD_OFFSET(MOUNTDEV_NAME, Name) + (ULONG)header.NameLength;
    name = ExAllocatePool2(POOL_FLAG_NON_PAGED, name_size, 'dV4E');
    if (name == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    status = volume_ioctl(device, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME,
        NULL, 0, name, name_size, &transferred);
    if (!NT_SUCCESS(status)) { goto finish; }
    if (name->NameLength != header.NameLength || transferred < name_size) {
        status = STATUS_OBJECT_NAME_INVALID;
        goto finish;
    }

    query_size = sizeof(MOUNTMGR_MOUNT_POINT) + (ULONG)name->NameLength;
    target_size = FIELD_OFFSET(MOUNTMGR_TARGET_NAME, DeviceName) + (ULONG)name->NameLength;
    query = ExAllocatePool2(POOL_FLAG_NON_PAGED, query_size, 'dV4E');
    target = ExAllocatePool2(POOL_FLAG_NON_PAGED, target_size, 'dV4E');
    if (query == NULL || target == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto finish;
    }
    query->DeviceNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
    query->DeviceNameLength = name->NameLength;
    RtlCopyMemory((PUCHAR)query + query->DeviceNameOffset, name->Name, name->NameLength);
    target->DeviceNameLength = name->NameLength;
    RtlCopyMemory(target->DeviceName, name->Name, name->NameLength);

    status = IoGetDeviceObjectPointer(
        &manager_name, FILE_READ_ATTRIBUTES, &manager_file, &manager);
    if (!NT_SUCCESS(status)) { goto finish; }
    status = query_registration(manager, query, query_size);
    if (status != STATUS_INVALID_PARAMETER) { goto finish; }

    /* All allocation and message construction precedes acceptance. Never infer
     * absence from an arbitrary query failure. The valid exact-name query above
     * has the documented INVALID_PARAMETER result for an unregistered target. */
    arrival_status = volume_ioctl(manager, IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION,
        target, target_size, NULL, 0, &transferred);
    status = query_registration(manager, query, query_size);
    if (!NT_SUCCESS(status)) {
        status = NT_SUCCESS(arrival_status) ? STATUS_DEVICE_NOT_READY : arrival_status;
    }
finish:
    if (manager_file != NULL) { ObDereferenceObject(manager_file); }
    if (target != NULL) { ExFreePoolWithTag(target, 'dV4E'); }
    if (query != NULL) { ExFreePoolWithTag(query, 'dV4E'); }
    ExFreePoolWithTag(name, 'dV4E');
    return status;
}

/* Failure observer at the Windows boundary, not a new domain/debug API. */
_IRQL_requires_(PASSIVE_LEVEL)
VOID NTAPI
ext4win_report_volume_discovery_failure(
    _In_ PDEVICE_OBJECT owner, _In_ NTSTATUS status)
{
    PIO_ERROR_LOG_PACKET packet = IoAllocateErrorLogEntry(owner, sizeof(IO_ERROR_LOG_PACKET));
    if (packet == NULL) { return; } /* The OS error-log service is best effort under OOM. */
    RtlZeroMemory(packet, sizeof(*packet));
    packet->ErrorCode = IO_ERR_DRIVER_ERROR;
    packet->FinalStatus = status;
    IoWriteErrorLogEntry(packet);
}
