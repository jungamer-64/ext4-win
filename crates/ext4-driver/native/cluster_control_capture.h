#ifndef EXT4WIN_CLUSTER_CONTROL_CAPTURE_H
#define EXT4WIN_CLUSTER_CONTROL_CAPTURE_H

/* Embedded handles must be interpreted in the requesting process before queue publication.
 * A successful result transfers one FILE_OBJECT reference, including the optional volume
 * reference in MARK_HANDLE. Scalar outputs are independent of the buffered input lifetime. */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS NTAPI ext4win_capture_cluster_control(
    PIRP irp, PFILE_OBJECT *file, PULONGLONG vcn, PULONGLONG lcn,
    PULONG count, PULONG source_info, PULONG flags, PACCESS_MASK granted)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG code = stack->Parameters.FileSystemControl.FsControlCode;
    ULONG length = stack->Parameters.FileSystemControl.InputBufferLength;
    HANDLE handle = NULL;
    LARGE_INTEGER starting_vcn = {0}, starting_lcn = {0};
    OBJECT_HANDLE_INFORMATION information = {0};
    NTSTATUS status;
    *file = NULL; *vcn = 0; *lcn = 0; *count = 0;
    *source_info = 0; *flags = 0; *granted = 0;
    if (stack->MajorFunction != IRP_MJ_FILE_SYSTEM_CONTROL ||
        stack->MinorFunction != IRP_MN_USER_FS_REQUEST ||
        stack->Parameters.FileSystemControl.OutputBufferLength != 0 ||
        irp->AssociatedIrp.SystemBuffer == NULL) { return STATUS_INVALID_PARAMETER; }
    if (code == FSCTL_MOVE_FILE) {
#if defined(_WIN64)
        if (IoIs32bitProcess(irp)) {
            MOVE_FILE_DATA32 input;
            if (length < sizeof(input)) { return STATUS_BUFFER_TOO_SMALL; }
            RtlCopyMemory(&input, irp->AssociatedIrp.SystemBuffer, sizeof(input));
            handle = UlongToHandle(input.FileHandle);
            starting_vcn = input.StartingVcn; starting_lcn = input.StartingLcn;
            *count = input.ClusterCount;
        } else
#endif
        {
            MOVE_FILE_DATA input;
            if (length < sizeof(input)) { return STATUS_BUFFER_TOO_SMALL; }
            RtlCopyMemory(&input, irp->AssociatedIrp.SystemBuffer, sizeof(input));
            handle = input.FileHandle;
            starting_vcn = input.StartingVcn; starting_lcn = input.StartingLcn;
            *count = input.ClusterCount;
        }
        if (starting_vcn.QuadPart < 0 || starting_lcn.QuadPart < 0 || *count == 0 ||
            handle == NULL) { return STATUS_INVALID_PARAMETER; }
        *vcn = (ULONGLONG)starting_vcn.QuadPart;
        *lcn = (ULONGLONG)starting_lcn.QuadPart;
    } else if (code == FSCTL_MARK_HANDLE) {
#if defined(_WIN64)
        if (IoIs32bitProcess(irp)) {
            MARK_HANDLE_INFO32 input;
            if (length < sizeof(input)) { return STATUS_BUFFER_TOO_SMALL; }
            RtlCopyMemory(&input, irp->AssociatedIrp.SystemBuffer, sizeof(input));
            handle = UlongToHandle(input.VolumeHandle);
            *source_info = input.UsnSourceInfo; *flags = input.HandleInfo;
        } else
#endif
        {
            MARK_HANDLE_INFO input;
            if (length < sizeof(input)) { return STATUS_BUFFER_TOO_SMALL; }
            RtlCopyMemory(&input, irp->AssociatedIrp.SystemBuffer, sizeof(input));
            handle = input.VolumeHandle;
            *source_info = input.UsnSourceInfo; *flags = input.HandleInfo;
        }
        if (handle == NULL) { return STATUS_SUCCESS; }
    } else { return STATUS_INVALID_DEVICE_REQUEST; }
    status = ObReferenceObjectByHandle(handle, 0, *IoFileObjectType,
        irp->RequestorMode, (PVOID *)file, &information);
    if (NT_SUCCESS(status)) { *granted = information.GrantedAccess; }
    return status;
}

#endif
