#pragma once

/* The existing storage PDO owns interface identity and PnP removal. Mount Manager
 * observes this interface's arrival AND removal, retaining persistent mount names
 * while withdrawing their active links. No reference string or synthetic device
 * name may introduce another volume identity. PnP disables the interface when it
 * removes the PDO; filesystem shutdown does not withdraw a live storage volume.
 *
 * Registration/enablement are idempotent, including STATUS_OBJECT_NAME_EXISTS.
 * Enable success is not synchronous Mount Manager acceptance. All temporary
 * ownership ends here, independently of asynchronous interface notifications. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NTAPI
ext4win_publish_volume_interface(
    _In_ PDEVICE_OBJECT device, _In_ const GUID *interface_class)
{
    PDEVICE_OBJECT pdo = IoGetDeviceAttachmentBaseRef(device);
    UNICODE_STRING name = {0};
    NTSTATUS status;
    if (pdo == NULL) { return STATUS_NO_SUCH_DEVICE; }
    status = IoRegisterDeviceInterface(pdo, interface_class, NULL, &name);
    if (NT_SUCCESS(status)) {
        status = IoSetDeviceInterfaceState(&name, TRUE);
        RtlFreeUnicodeString(&name);
    }
    ObDereferenceObject(pdo);
    return status;
}
