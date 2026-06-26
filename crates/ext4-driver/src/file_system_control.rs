//! File-system control, mount, reparse, and device-control dispatch boundary.

use alloc::boxed::Box;

use wdk_sys::{
    NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
    STATUS_UNRECOGNIZED_VOLUME,
};

use crate::{
    block_device::query_device_length,
    ffi, fsctl,
    irp::{DispatchTarget, FileSystemControlStack, IrpBufferLength, MountVolumeStack},
    reparse,
    state::{
        KernelDevice, MountCandidate, MountedVolumeDevice, MountedVolumeDeviceExtension,
        VolumeControlBlock,
    },
    status::DriverError,
};

/// IRP_MN_MOUNT_VOLUME as a stack-location minor function byte.
const MOUNT_VOLUME_MINOR: wdk_sys::UCHAR = 1;

/// Handles file-system control requests, including mount and reparse controls.
pub(crate) fn dispatch(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(FileSystemControlRequest::decode) {
        Ok(FileSystemControlRequest::MountVolume(request)) => mount_volume(request),
        Ok(FileSystemControlRequest::UserFsControl(request)) => user_fs_control(request),
        Ok(FileSystemControlRequest::Unsupported) => STATUS_NOT_SUPPORTED,
        Err(error) => error.ntstatus(),
    }
}

/// Handles device control requests addressed to this FSD.
pub(crate) fn device_control(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            let _device = target.device();
            let _irp = target.irp();
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
        if stack.minor_function() == MOUNT_VOLUME_MINOR {
            return Ok(Self::MountVolume(MountVolumeRequest::from_stack(
                target.device(),
                stack.mount_volume()?,
            )));
        }
        if u32::from(stack.minor_function()) == wdk_sys::IRP_MN_USER_FS_REQUEST {
            return Ok(Self::UserFsControl(UserFsControlRequest::from_stack(
                target,
                stack.file_system_control()?,
            )));
        }
        Ok(Self::Unsupported)
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
    const fn fs_control_code(self) -> wdk_sys::ULONG {
        self.stack.fs_control_code()
    }
}

/// Mount request after raw IRP stack decoding.
#[derive(Clone, Copy, Debug)]
struct MountVolumeRequest {
    /// File-system control device receiving the mount IRP.
    file_system_device: KernelDevice,
    /// VPB supplied by the I/O Manager for this mount.
    vpb: core::ptr::NonNull<wdk_sys::VPB>,
    /// Lower storage device selected by the I/O Manager.
    target_device: KernelDevice,
    /// Output buffer length supplied with the mount request.
    output_buffer_length: IrpBufferLength,
}

impl MountVolumeRequest {
    /// Converts decoded stack parameters into the mount domain boundary.
    fn from_stack(
        file_system_device: core::ptr::NonNull<wdk_sys::DEVICE_OBJECT>,
        stack: MountVolumeStack,
    ) -> Self {
        Self {
            file_system_device: KernelDevice::from_non_null(file_system_device),
            vpb: stack.vpb(),
            target_device: KernelDevice::from_non_null(stack.target_device()),
            output_buffer_length: stack.output_buffer_length(),
        }
    }

    /// Returns the file-system control device receiving this mount request.
    const fn file_system_device(self) -> KernelDevice {
        self.file_system_device
    }

    /// Returns the VPB supplied by the I/O Manager.
    const fn vpb(self) -> core::ptr::NonNull<wdk_sys::VPB> {
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
fn mount_volume(request: MountVolumeRequest) -> NTSTATUS {
    let length = match query_device_length(request.target_device()) {
        Ok(length) => length,
        Err(error) => return DriverError::from(error).ntstatus(),
    };
    let candidate = MountCandidate::new(request.target_device(), length);
    let vcb =
        match VolumeControlBlock::mount_read_write(candidate.target_device(), candidate.length()) {
            Ok(vcb) => vcb,
            Err(ext4_core::Error::InvalidMagic | ext4_core::Error::InvalidSuperblock) => {
                return STATUS_UNRECOGNIZED_VOLUME;
            }
            Err(error) => return DriverError::from(error).ntstatus(),
        };
    let _output_buffer_length = request.output_buffer_length();
    let Some(driver_object) = request.file_system_device().driver_object() else {
        return STATUS_INVALID_PARAMETER;
    };

    let mut device = core::ptr::null_mut();
    let extension_size =
        match wdk_sys::ULONG::try_from(core::mem::size_of::<MountedVolumeDeviceExtension>()) {
            Ok(size) => size,
            Err(_) => return STATUS_INVALID_PARAMETER,
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
        return status;
    }

    if MountedVolumeDevice::initialize_vpb_identity(request.vpb(), &vcb).is_none() {
        unsafe {
            // SAFETY: `device` was returned by a successful IoCreateDevice call
            // and has not been published as a mounted volume.
            ffi::IoDeleteDevice(device);
        }
        return STATUS_INVALID_PARAMETER;
    }

    let Some(mounted_device) = MountedVolumeDevice::initialize(
        device,
        Box::new(vcb),
        request.vpb(),
        candidate.target_device(),
    ) else {
        unsafe {
            // SAFETY: `device` was returned by a successful IoCreateDevice call
            // and no initialized extension owns heap state on this path.
            ffi::IoDeleteDevice(device);
        }
        return STATUS_INVALID_PARAMETER;
    };
    let _mounted_device = mounted_device.as_ptr();
    STATUS_SUCCESS
}

/// Handles path-scoped user FSCTL requests.
fn user_fs_control(request: UserFsControlRequest) -> NTSTATUS {
    match request.fs_control_code() {
        reparse::FSCTL_GET_REPARSE_POINT => {
            reparse::get_reparse_point(request.target(), request.stack())
        }
        reparse::FSCTL_SET_REPARSE_POINT => {
            reparse::set_reparse_point(request.target(), request.stack())
        }
        reparse::FSCTL_DELETE_REPARSE_POINT => STATUS_NOT_SUPPORTED,
        fsctl::FSCTL_EXT4WIN_ADD_ENCRYPTION_KEY => {
            fsctl::add_encryption_key(request.target(), request.stack())
        }
        fsctl::FSCTL_EXT4WIN_REMOVE_ENCRYPTION_KEY => {
            fsctl::remove_encryption_key(request.target(), request.stack())
        }
        fsctl::FSCTL_EXT4WIN_GET_ENCRYPTION_KEY_STATUS => {
            fsctl::get_encryption_key_status(request.target(), request.stack())
        }
        fsctl::FSCTL_EXT4WIN_ENABLE_VERITY => {
            fsctl::enable_verity(request.target(), request.stack())
        }
        _ => STATUS_NOT_SUPPORTED,
    }
}
