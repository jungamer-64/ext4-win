//! File-system control, mount, reparse, and device-control dispatch boundary.

use alloc::boxed::Box;

use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_SUCCESS};

use crate::{
    block_device::query_device_length,
    ffi, fsctl,
    irp::{
        DispatchTarget, DriverCompletion, FileSystemControlMinorFunction, FileSystemControlStack,
        FsControlCode, IrpBufferLength, MountVolumeStack,
    },
    reparse,
    state::{
        KernelDevice, KernelVpb, MountCandidate, MountedVolumeDevice, MountedVolumeDeviceExtension,
        VolumeControlBlock,
    },
    status::{DriverError, DriverResult},
};

/// Handles file-system control requests, including mount and reparse controls.
pub(crate) fn dispatch(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(FileSystemControlRequest::decode) {
        Ok(FileSystemControlRequest::MountVolume(request)) => match mount_volume(request) {
            Ok(()) => STATUS_SUCCESS,
            Err(error) => error.ntstatus(),
        },
        Ok(FileSystemControlRequest::UserFsControl(request)) => match user_fs_control(request) {
            Ok(completion) => {
                request.target().complete(completion);
                STATUS_SUCCESS
            }
            Err(error) => error.ntstatus(),
        },
        Ok(FileSystemControlRequest::Unsupported) => DriverError::NotSupported.ntstatus(),
        Err(error) => error.ntstatus(),
    }
}

/// Handles device control requests addressed to this FSD.
pub(crate) fn device_control(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            let _device = target.device();
            crate::status::DriverError::InvalidDeviceRequest.ntstatus()
        }
        Err(error) => error.ntstatus(),
    }
}

/// File-system-control request understood at the dispatch boundary.
#[derive(Clone, Copy, Debug)]
enum FileSystemControlRequest {
    /// Mount request issued by the I/O Manager.
    MountVolume(MountVolumeRequest),
    /// User FSCTL request addressed to an opened file object.
    UserFsControl(UserFsControlRequest),
    /// Other FSCTL minor functions not owned by this FSD path yet.
    Unsupported,
}

impl FileSystemControlRequest {
    /// Decodes the current FSCTL stack location.
    fn decode(target: DispatchTarget) -> Result<Self, crate::status::DriverError> {
        let stack = target.current_stack()?;
        match stack.file_system_control_minor() {
            FileSystemControlMinorFunction::MountVolume => Ok(Self::MountVolume(
                MountVolumeRequest::from_stack(target.device(), stack.mount_volume()?),
            )),
            FileSystemControlMinorFunction::UserFsRequest => Ok(Self::UserFsControl(
                UserFsControlRequest::from_stack(target, stack.file_system_control()?),
            )),
            FileSystemControlMinorFunction::Unsupported => Ok(Self::Unsupported),
        }
    }
}

/// User FSCTL request after raw IRP stack decoding.
#[derive(Clone, Copy, Debug)]
struct UserFsControlRequest {
    /// Dispatch target that owns output buffer completion.
    target: DispatchTarget,
    /// Decoded file-system-control stack parameters.
    stack: FileSystemControlStack,
}

impl UserFsControlRequest {
    /// Converts decoded stack parameters into the user-FSCTL domain boundary.
    const fn from_stack(target: DispatchTarget, stack: FileSystemControlStack) -> Self {
        Self { target, stack }
    }

    /// Returns the dispatch target.
    const fn target(self) -> DispatchTarget {
        self.target
    }

    /// Returns the decoded FSCTL stack.
    const fn stack(self) -> FileSystemControlStack {
        self.stack
    }

    /// Returns the requested FSCTL code.
    const fn fs_control_code(self) -> FsControlCode {
        self.stack.fs_control_code()
    }
}

/// Mount request after raw IRP stack decoding.
#[derive(Clone, Copy, Debug)]
struct MountVolumeRequest {
    /// File-system control device receiving the mount IRP.
    file_system_device: KernelDevice,
    /// VPB supplied by the I/O Manager for this mount.
    vpb: KernelVpb,
    /// Lower storage device selected by the I/O Manager.
    target_device: KernelDevice,
    /// Output buffer length supplied with the mount request.
    output_buffer_length: IrpBufferLength,
}

impl MountVolumeRequest {
    /// Converts decoded stack parameters into the mount domain boundary.
    fn from_stack(file_system_device: KernelDevice, stack: MountVolumeStack) -> Self {
        Self {
            file_system_device,
            vpb: stack.vpb(),
            target_device: stack.target_device(),
            output_buffer_length: stack.output_buffer_length(),
        }
    }

    /// Returns the file-system control device receiving this mount request.
    const fn file_system_device(self) -> KernelDevice {
        self.file_system_device
    }

    /// Returns the VPB supplied by the I/O Manager.
    const fn vpb(self) -> KernelVpb {
        self.vpb
    }

    /// Returns the lower storage device selected for mounting.
    const fn target_device(self) -> KernelDevice {
        self.target_device
    }

    /// Returns the mount output buffer length.
    const fn output_buffer_length(self) -> IrpBufferLength {
        self.output_buffer_length
    }
}

/// Handles a decoded mount request.
fn mount_volume(request: MountVolumeRequest) -> DriverResult<()> {
    let length = query_device_length(request.target_device())?;
    let candidate = MountCandidate::new(request.target_device(), length);
    let vcb =
        match VolumeControlBlock::mount_read_write(candidate.target_device(), candidate.length()) {
            Ok(vcb) => vcb,
            Err(ext4_core::Error::InvalidMagic | ext4_core::Error::InvalidSuperblock) => {
                return Err(DriverError::UnrecognizedVolume);
            }
            Err(error) => return Err(DriverError::from(error)),
        };
    let _output_buffer_length = request.output_buffer_length();
    let Some(driver_object) = request.file_system_device().driver_object() else {
        return Err(DriverError::InvalidParameter);
    };

    let mut device = core::ptr::null_mut();
    let extension_size =
        match wdk_sys::ULONG::try_from(core::mem::size_of::<MountedVolumeDeviceExtension>()) {
            Ok(size) => size,
            Err(_) => return Err(DriverError::InvalidParameter),
        };
    let status = unsafe {
        // SAFETY: `driver_object` belongs to the control device receiving the
        // mount IRP. `device` points to writable storage for the created object.
        ffi::IoCreateDevice(
            driver_object,
            extension_size,
            core::ptr::null_mut(),
            ffi::FILE_DEVICE_DISK_FILE_SYSTEM,
            0,
            0,
            core::ptr::addr_of_mut!(device),
        )
    };
    if status < STATUS_SUCCESS {
        return Err(DriverError::InsufficientResources);
    }

    if MountedVolumeDevice::initialize_vpb_identity(request.vpb().as_non_null(), &vcb).is_none() {
        unsafe {
            // SAFETY: `device` was returned by a successful IoCreateDevice call
            // and has not been published as a mounted volume.
            ffi::IoDeleteDevice(device);
        }
        return Err(DriverError::InvalidParameter);
    }

    let Some(mounted_device) = MountedVolumeDevice::initialize(
        device,
        Box::new(vcb),
        request.vpb().as_non_null(),
        candidate.target_device(),
    ) else {
        unsafe {
            // SAFETY: `device` was returned by a successful IoCreateDevice call
            // and no initialized extension owns heap state on this path.
            ffi::IoDeleteDevice(device);
        }
        return Err(DriverError::InvalidParameter);
    };
    let _mounted_device = mounted_device.as_ptr();
    Ok(())
}

/// Handles path-scoped user FSCTL requests.
fn user_fs_control(request: UserFsControlRequest) -> DriverResult<DriverCompletion> {
    match request.fs_control_code() {
        FsControlCode::GetReparsePoint => {
            reparse::get_reparse_point(request.target(), request.stack())
        }
        FsControlCode::SetReparsePoint => {
            reparse::set_reparse_point(request.target(), request.stack())
        }
        FsControlCode::DeleteReparsePoint => Err(DriverError::NotSupported),
        FsControlCode::AddEncryptionKey => {
            fsctl::add_encryption_key(request.target(), request.stack())
        }
        FsControlCode::RemoveEncryptionKey => {
            fsctl::remove_encryption_key(request.target(), request.stack())
        }
        FsControlCode::GetEncryptionKeyStatus => {
            fsctl::get_encryption_key_status(request.target(), request.stack())
        }
        FsControlCode::EnableVerity => fsctl::enable_verity(request.target(), request.stack()),
    }
}
