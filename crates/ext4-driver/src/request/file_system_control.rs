//! File-system control, mount, reparse, and device-control dispatch boundary.

use wdk_sys::STATUS_SUCCESS;

use crate::{
    irp::{
        DispatchTarget, FileSystemControlMinorFunction, FileSystemControlStack, FsControlCode,
        IrpBufferLength, IrpCompletion, MountVolumeStack, PendingIrpLease,
    },
    kernel::{
        block_device::query_device_length,
        ffi,
        status::{DriverError, DriverResult},
    },
    memory,
    request::{fsctl, reparse},
    state::{
        KernelDevice, KernelVpb, MountCandidate, MountedVolumeDevice, MountedVolumeDeviceExtension,
        VolumeControlBlock,
    },
};

/// Executes file-system control requests, including mount and reparse controls.
/// # Errors
///
/// Returns an error when FSCTL stack decoding, mount, reparse, encryption-key, or verity handling
/// rejects the request.
pub(crate) async fn execute(request: PendingIrpLease<'_>) -> DriverResult<IrpCompletion> {
    match FileSystemControlRequest::decode(request)? {
        FileSystemControlRequest::MountVolume(request) => {
            mount_volume(request).await.map(|()| IrpCompletion::EMPTY)
        }
        FileSystemControlRequest::UserFsControl(request) => user_fs_control(request).await,
        FileSystemControlRequest::Unsupported => Err(DriverError::NotSupported),
    }
}

/// Executes device control requests addressed to this FSD.
/// # Errors
///
/// Always returns `InvalidDeviceRequest`; device controls are not owned by this FSD path.
pub(crate) fn device_control(_target: DispatchTarget) -> DriverResult<IrpCompletion> {
    Err(DriverError::InvalidDeviceRequest)
}

/// File-system-control request understood at the dispatch boundary.
#[derive(Debug)]
enum FileSystemControlRequest<'a> {
    /// Mount request issued by the I/O Manager.
    MountVolume(MountVolumeRequest<'a>),
    /// User FSCTL request addressed to an opened file object.
    UserFsControl(UserFsControlRequest<'a>),
    /// Other FSCTL minor functions not owned by this FSD path yet.
    Unsupported,
}

impl<'a> FileSystemControlRequest<'a> {
    /// Decodes the current FSCTL stack location.
    /// # Errors
    ///
    /// Returns an error when the current IRP stack is absent or its mount/user-FSCTL parameters are
    /// malformed.
    fn decode(request: PendingIrpLease<'a>) -> Result<Self, crate::kernel::status::DriverError> {
        let target = request.target();
        let stack = target.current_stack()?;
        match stack.file_system_control_minor() {
            FileSystemControlMinorFunction::MountVolume => Ok(Self::MountVolume(
                MountVolumeRequest::from_stack(request, stack.mount_volume()?),
            )),
            FileSystemControlMinorFunction::UserFsRequest => Ok(Self::UserFsControl(
                UserFsControlRequest::from_stack(request, stack.file_system_control()?),
            )),
            FileSystemControlMinorFunction::Unsupported => Ok(Self::Unsupported),
        }
    }
}

/// User FSCTL request after raw IRP stack decoding.
#[derive(Debug)]
struct UserFsControlRequest<'a> {
    /// Exclusive pending IRP lease retaining every FSCTL buffer and FILE_OBJECT.
    request: PendingIrpLease<'a>,
    /// Decoded file-system-control stack parameters.
    stack: FileSystemControlStack,
}

// SAFETY: The pending lease pins all decoded stack pointers while the mounted-device executor
// serially moves this request between PASSIVE_LEVEL workers.
unsafe impl Send for UserFsControlRequest<'_> {}

impl<'a> UserFsControlRequest<'a> {
    /// Converts decoded stack parameters into the user-FSCTL domain boundary.
    const fn from_stack(request: PendingIrpLease<'a>, stack: FileSystemControlStack) -> Self {
        Self { request, stack }
    }

    /// Returns the dispatch target.
    const fn target(&self) -> DispatchTarget {
        self.request.target()
    }

    /// Returns the decoded FSCTL stack.
    const fn stack(&self) -> FileSystemControlStack {
        self.stack
    }

    /// Returns the requested FSCTL code.
    const fn fs_control_code(&self) -> FsControlCode {
        self.stack.fs_control_code()
    }
}

/// Mount request after raw IRP stack decoding.
#[derive(Debug)]
struct MountVolumeRequest<'a> {
    /// Exclusive pending mount IRP that pins the VPB until terminal completion.
    _request: PendingIrpLease<'a>,
    /// File-system control device receiving the mount IRP.
    file_system_device: KernelDevice,
    /// VPB supplied by the I/O Manager for this mount.
    vpb: KernelVpb,
    /// Lower storage device selected by the I/O Manager.
    target_device: KernelDevice,
    /// Output buffer length supplied with the mount request.
    output_buffer_length: IrpBufferLength,
}

// SAFETY: The pending-IRP lease keeps the VPB and target device alive while the serialized mount
// future moves between PASSIVE_LEVEL workers. No second executor task polls this request.
unsafe impl Send for MountVolumeRequest<'_> {}

impl<'a> MountVolumeRequest<'a> {
    /// Converts decoded stack parameters into the mount domain boundary.
    fn from_stack(request: PendingIrpLease<'a>, stack: MountVolumeStack) -> Self {
        Self {
            file_system_device: request.target().device(),
            _request: request,
            vpb: stack.vpb(),
            target_device: stack.target_device(),
            output_buffer_length: stack.output_buffer_length(),
        }
    }

    /// Returns the file-system control device receiving this mount request.
    const fn file_system_device(&self) -> KernelDevice {
        self.file_system_device
    }

    /// Returns the VPB supplied by the I/O Manager.
    const fn vpb(&self) -> KernelVpb {
        self.vpb
    }

    /// Returns the lower storage device selected for mounting.
    const fn target_device(&self) -> KernelDevice {
        self.target_device
    }

    /// Returns the mount output buffer length.
    const fn output_buffer_length(&self) -> IrpBufferLength {
        self.output_buffer_length
    }
}

/// Handles a decoded mount request.
/// # Errors
///
/// Returns an error when the target device cannot be queried or mounted, the filesystem device has
/// no driver object, or mounted-device/VPB initialization fails.
async fn mount_volume(request: MountVolumeRequest<'_>) -> DriverResult<()> {
    let completion_owner = request.file_system_device();
    let length = query_device_length(completion_owner, request.target_device()).await?;
    let candidate = MountCandidate::new(request.target_device(), length);
    let vcb = match VolumeControlBlock::mount_journaled(
        completion_owner,
        candidate.target_device(),
        candidate.length(),
    )
    .await
    {
        Ok(vcb) => vcb,
        Err(DriverError::Core(
            ext4_core::Error::InvalidMagic | ext4_core::Error::InvalidSuperblock,
        )) => {
            return Err(DriverError::UnrecognizedVolume);
        }
        Err(error) => return Err(error),
    };
    let _output_buffer_length = request.output_buffer_length();
    let Some(driver_object) = request.file_system_device().driver_object() else {
        return Err(DriverError::InvalidParameter);
    };
    let mut vcb = memory::boxed_try_with(move || Ok(vcb))?;
    vcb.initialize_directory_change_notifier()?;

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

    let mounted_device = match MountedVolumeDevice::initialize(
        device,
        vcb,
        request.vpb().as_non_null(),
        candidate.target_device(),
    ) {
        Ok(mounted_device) => mounted_device,
        Err(error) => {
            unsafe {
                // SAFETY: `device` was returned by a successful IoCreateDevice call
                // and no initialized extension owns heap state on this path.
                ffi::IoDeleteDevice(device);
            }
            return Err(error);
        }
    };
    let _mounted_device = mounted_device.as_ptr();
    Ok(())
}

/// Handles path-scoped user FSCTL requests.
/// # Errors
///
/// Returns an error when the requested reparse, encryption-key, or verity operation rejects its
/// buffers, file object, or mounted-volume state.
async fn user_fs_control(request: UserFsControlRequest<'_>) -> DriverResult<IrpCompletion> {
    match request.fs_control_code() {
        FsControlCode::GetReparsePoint => reparse::get_reparse_point(request.target()).await,
        FsControlCode::SetReparsePoint => reparse::set_reparse_point(request.target()).await,
        FsControlCode::DeleteReparsePoint => reparse::delete_reparse_point(request.target()).await,
        FsControlCode::AddEncryptionKey => {
            fsctl::add_encryption_key(request.target(), request.stack())
        }
        FsControlCode::RemoveEncryptionKey => {
            fsctl::remove_encryption_key(request.target(), request.stack())
        }
        FsControlCode::GetEncryptionKeyStatus => {
            fsctl::get_encryption_key_status(request.target(), request.stack())
        }
        FsControlCode::EnableVerity => fsctl::enable_verity(request.target()).await,
    }
}
