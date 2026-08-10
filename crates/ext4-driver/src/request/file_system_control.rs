//! File-system-control admission and mounted lifecycle boundaries.

use crate::irp::{
    FileSystemControlMinorFunction, FsControlCode, IrpBufferLength, IrpCompletion, PendingIrpLease,
};
use crate::kernel::status::{DriverError, DriverResult};
use crate::state::{KernelDevice, KernelVpb, OpenedFileObject, VolumeControlBlock};

/// Owned classification copied from an FSCTL stack before operation allocation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FsControlAdmission {
    /// I/O Manager mount request with stable kernel identities pinned by the top-level IRP.
    Mount(MountAdmission),
    /// User request selected by its typed control code.
    User(FsControlCode),
    /// Minor function not owned by ext4win.
    Unsupported,
}

/// Pointer-free mount scalars plus stable kernel object identities.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountAdmission {
    /// Filesystem control device receiving the mount.
    file_system_device: KernelDevice,
    /// VPB supplied by the I/O Manager.
    vpb: KernelVpb,
    /// Lower storage target.
    target_device: KernelDevice,
    /// Caller output capacity.
    output_buffer_length: IrpBufferLength,
}

impl MountAdmission {
    /// Filesystem control device that owns completion code.
    pub(crate) const fn file_system_device(self) -> KernelDevice {
        self.file_system_device
    }

    /// I/O Manager VPB retained by the mount IRP.
    pub(crate) const fn vpb(self) -> KernelVpb {
        self.vpb
    }

    /// Lower filesystem device selected for mount.
    pub(crate) const fn target_device(self) -> KernelDevice {
        self.target_device
    }

    /// Mount output capacity supplied by the I/O Manager.
    pub(crate) const fn output_buffer_length(self) -> IrpBufferLength {
        self.output_buffer_length
    }
}

/// Classifies one captured filesystem-control request without retaining an IRP-internal pointer.
/// # Errors
///
/// Returns an error when the current stack cannot be decoded as its captured minor function.
pub(crate) fn classify(
    mut request: PendingIrpLease<'_>,
    minor: FileSystemControlMinorFunction,
) -> DriverResult<FsControlAdmission> {
    request.with_active(|active| match minor {
        FileSystemControlMinorFunction::MountVolume => {
            let stack = active.current_stack()?.mount_volume()?;
            Ok(FsControlAdmission::Mount(MountAdmission {
                file_system_device: active.device(),
                vpb: stack.vpb(),
                target_device: stack.target_device(),
                output_buffer_length: stack.output_buffer_length(),
            }))
        }
        FileSystemControlMinorFunction::UserFsRequest => {
            let stack = active.current_stack()?.file_system_control()?;
            Ok(FsControlAdmission::User(stack.fs_control_code()))
        }
        FileSystemControlMinorFunction::Unsupported => Ok(FsControlAdmission::Unsupported),
    })
}

/// Authorizes one path-scoped FSCTL against the live opened handle.
/// # Errors
///
/// Returns an error for malformed FILE_OBJECT state, a volume lock owned elsewhere, or dismount.
pub(crate) fn authorize_path_handle(request: &mut PendingIrpLease<'_>) -> DriverResult<()> {
    let (volume, file_object) = request.with_active(|active| {
        let opened = OpenedFileObject::decode(active.current_stack()?.file_object()?)?;
        Ok::<_, DriverError>(match opened {
            OpenedFileObject::Node(opened) => (opened.volume(), opened.file_object()),
            OpenedFileObject::Volume(opened) => (opened.volume(), opened.file_object()),
        })
    })?;
    let operations = unsafe {
        // SAFETY: Authorization is a non-suspending reactor-thread projection and no reference is
        // retained by the operation.
        VolumeControlBlock::operation_access(volume)
    };
    operations.authorize_handle(file_object)
}

/// Executes device control requests addressed to this FSD.
/// # Errors
///
/// Always returns `InvalidDeviceRequest`; device controls are not owned by this FSD path.
pub(crate) fn device_control() -> DriverResult<IrpCompletion> {
    Err(DriverError::InvalidDeviceRequest)
}
