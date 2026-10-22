#include <ntifs.h>
#include <ntdddisk.h>
#include <ntiologc.h>

#include "discovery_io.h"

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NTAPI
ext4win_query_volume_partition(
    _In_ EXT4WIN_DISCOVERY_CHANNEL *channel,
    _In_ PDEVICE_OBJECT device,
    _Out_ GUID *partition_type,
    _Out_ ULONGLONG *attributes)
{
    PARTITION_INFORMATION_EX partition = {0};
    ULONG_PTR transferred;
    NTSTATUS status = ext4win_discovery_ioctl(
        channel, device, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0,
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
    _In_ EXT4WIN_DISCOVERY_CHANNEL *channel,
    _In_ PDEVICE_OBJECT device, _Out_ ULONG *sector_size)
{
    DISK_GEOMETRY geometry = {0};
    ULONG_PTR transferred;
    NTSTATUS status = ext4win_discovery_ioctl(
        channel, device, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
        &geometry, sizeof(geometry), &transferred);
    if (!NT_SUCCESS(status)) { return status; }
    if (transferred < sizeof(geometry)) { return STATUS_INFO_LENGTH_MISMATCH; }
    *sector_size = geometry.BytesPerSector;
    return STATUS_SUCCESS;
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
