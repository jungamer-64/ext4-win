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
