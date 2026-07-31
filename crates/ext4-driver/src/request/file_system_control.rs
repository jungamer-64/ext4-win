//! File-system control, mount, reparse, and device-control dispatch boundary.

use core::ptr::NonNull;

use wdk_sys::STATUS_SUCCESS;

use crate::{
    irp::{
        FileSystemControlMinorFunction, FileSystemControlStack, FsControlCode, IrpBufferLength,
        IrpCompletion, MountVolumeStack, PendingIrpLease,
    },
    kernel::{
        block_device::query_device_length,
        ffi,
        status::{DriverError, DriverResult},
    },
    memory,
    request::{fsctl, reparse},
    state::{
        KernelDevice, KernelFileObject, KernelVpb, MountCandidate, MountedVolumeDevice,
        MountedVolumeDeviceExtension, OpenedFileObject, OpenedVolume, VolumeControlBlock,
    },
};

/// Executes file-system control requests, including mount and reparse controls.
/// # Errors
///
/// Returns an error when FSCTL stack decoding, mount, reparse, encryption-key, or verity handling
/// rejects the request.
pub(crate) async fn execute(
    request: PendingIrpLease<'_>,
    minor: FileSystemControlMinorFunction,
) -> DriverResult<IrpCompletion> {
    match FileSystemControlRequest::decode(request, minor)? {
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
pub(crate) fn device_control() -> DriverResult<IrpCompletion> {
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
    fn decode(
        mut request: PendingIrpLease<'a>,
        minor: FileSystemControlMinorFunction,
    ) -> Result<Self, crate::kernel::status::DriverError> {
        match minor {
            FileSystemControlMinorFunction::MountVolume => {
                let (device, stack) = request.with_active(|active| {
                    Ok::<_, DriverError>((active.device(), active.current_stack()?.mount_volume()?))
                })?;
                Ok(Self::MountVolume(MountVolumeRequest::from_stack(
                    request, device, stack,
                )))
            }
            FileSystemControlMinorFunction::UserFsRequest => {
                let stack =
                    request.with_active(|active| active.current_stack()?.file_system_control())?;
                Ok(Self::UserFsControl(UserFsControlRequest::from_stack(
                    request, stack,
                )))
            }
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

impl<'a> UserFsControlRequest<'a> {
    /// Converts decoded stack parameters into the user-FSCTL domain boundary.
    const fn from_stack(request: PendingIrpLease<'a>, stack: FileSystemControlStack) -> Self {
        Self { request, stack }
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

impl<'a> MountVolumeRequest<'a> {
    /// Converts decoded stack parameters into the mount domain boundary.
    fn from_stack(
        request: PendingIrpLease<'a>,
        file_system_device: KernelDevice,
        stack: MountVolumeStack,
    ) -> Self {
        Self {
            file_system_device,
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
async fn user_fs_control(mut request: UserFsControlRequest<'_>) -> DriverResult<IrpCompletion> {
    let control_code = request.fs_control_code();
    if !matches!(
        control_code,
        FsControlCode::LockVolume
            | FsControlCode::UnlockVolume
            | FsControlCode::DismountVolume
            | FsControlCode::IsVolumeMounted
    ) {
        authorize_fs_control_handle(&mut request.request)?;
    }
    match control_code {
        FsControlCode::LockVolume => lock_volume(request).await,
        FsControlCode::UnlockVolume => unlock_volume(request),
        FsControlCode::DismountVolume => dismount_volume(request).await,
        FsControlCode::IsVolumeMounted => is_volume_mounted(request),
        FsControlCode::GetReparsePoint => reparse::get_reparse_point(request.request).await,
        FsControlCode::SetReparsePoint => reparse::set_reparse_point(request.request).await,
        FsControlCode::DeleteReparsePoint => reparse::delete_reparse_point(request.request).await,
        FsControlCode::AddEncryptionKey => {
            fsctl::add_encryption_key(&mut request.request, request.stack)
        }
        FsControlCode::RemoveEncryptionKey => {
            fsctl::remove_encryption_key(&mut request.request, request.stack)
        }
        FsControlCode::GetEncryptionKeyStatus => {
            fsctl::get_encryption_key_status(&mut request.request, request.stack)
        }
        FsControlCode::EnableVerity => fsctl::enable_verity(request.request).await,
    }
}

/// Direct-volume identity decoded from one standard volume-control request.
#[derive(Clone, Copy, Debug)]
struct DirectVolumeTarget {
    /// Mounted filesystem device receiving the request.
    device: KernelDevice,
    /// VCB stored in the direct-volume FILE_OBJECT.
    volume: NonNull<VolumeControlBlock>,
    /// Direct-volume FILE_OBJECT that owns the handle state.
    owner: KernelFileObject,
}

/// Flushes and locks a volume when the caller is its only active handle.
/// # Errors
///
/// Returns an error for invalid buffers or handles, competing opens, dismount, or flush failure.
async fn lock_volume(mut request: UserFsControlRequest<'_>) -> DriverResult<IrpCompletion> {
    let target = direct_volume_target(&mut request)?;
    let _request_owner = request.request;
    let mut operations = unsafe {
        // SAFETY: User FSCTLs execute on the mounted-device actor, which grants this request the
        // unique operation lease until terminal completion.
        VolumeControlBlock::claim_operation_lane(target.volume)
    };
    operations.lock_volume(target.owner).await?;
    MountedVolumeDevice::publish_volume_lock(target.device, true);
    Ok(IrpCompletion::EMPTY)
}

/// Releases the volume lock owned by the calling direct-volume handle.
/// # Errors
///
/// Returns an error for invalid buffers or handles, or when the caller does not own the lock.
fn unlock_volume(mut request: UserFsControlRequest<'_>) -> DriverResult<IrpCompletion> {
    let target = direct_volume_target(&mut request)?;
    let _request_owner = request.request;
    let mut operations = unsafe {
        // SAFETY: User FSCTLs execute on the mounted-device actor, which uniquely owns lifecycle
        // transitions for this VCB.
        VolumeControlBlock::claim_operation_lane(target.volume)
    };
    operations.unlock_volume(target.owner)?;
    MountedVolumeDevice::publish_volume_lock(target.device, false);
    Ok(IrpCompletion::EMPTY)
}

/// Flushes and enters the terminal logical-dismount state.
/// # Errors
///
/// Returns an error for invalid buffers or handles, a competing lock owner, repeated dismount, or
/// flush failure.
async fn dismount_volume(mut request: UserFsControlRequest<'_>) -> DriverResult<IrpCompletion> {
    let target = direct_volume_target(&mut request)?;
    let _request_owner = request.request;
    let mut operations = unsafe {
        // SAFETY: User FSCTLs execute on the mounted-device actor, which uniquely owns lifecycle
        // transitions for this VCB.
        VolumeControlBlock::claim_operation_lane(target.volume)
    };
    operations.dismount_volume(target.owner).await?;
    MountedVolumeDevice::publish_direct_writes_allowed(target.device);
    MountedVolumeDevice::unregister_shutdown_notification(target.device);
    MountedVolumeDevice::complete_dismount(target.device);
    Ok(IrpCompletion::EMPTY)
}

/// Reports whether the direct-volume handle still names a logically mounted volume.
/// # Errors
///
/// Returns an error for invalid buffers or handles, or after logical dismount.
fn is_volume_mounted(mut request: UserFsControlRequest<'_>) -> DriverResult<IrpCompletion> {
    let target = direct_volume_target(&mut request)?;
    let _request_owner = request.request;
    let operations = unsafe {
        // SAFETY: User FSCTLs execute on the mounted-device actor, which uniquely observes this
        // VCB's lifecycle state.
        VolumeControlBlock::claim_operation_lane(target.volume)
    };
    operations.ensure_mounted()?;
    Ok(IrpCompletion::EMPTY)
}

/// Decodes and validates the direct-volume FILE_OBJECT for a standard volume FSCTL.
/// # Errors
///
/// Returns an error when buffers are nonempty or the FILE_OBJECT is not a valid direct-volume
/// handle.
fn direct_volume_target(
    request: &mut UserFsControlRequest<'_>,
) -> DriverResult<DirectVolumeTarget> {
    require_empty_volume_control_buffers(request.stack)?;
    request.request.with_active(|active| {
        let device = active.device();
        let opened = OpenedVolume::decode(active.current_stack()?.file_object()?)?;
        let volume = opened.volume();
        if MountedVolumeDevice::vcb(device) != Some(volume) {
            crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                .bugcheck();
        }
        Ok(DirectVolumeTarget {
            device,
            volume,
            owner: opened.file_object(),
        })
    })
}

/// Rejects payload buffers on standard volume FSCTLs whose wire contract has no payload.
/// # Errors
///
/// Returns invalid parameter when either input or output length is nonzero.
fn require_empty_volume_control_buffers(stack: FileSystemControlStack) -> DriverResult<()> {
    if stack.input_buffer_length().is_empty() && stack.output_buffer_length().is_empty() {
        Ok(())
    } else {
        Err(DriverError::InvalidParameter)
    }
}

/// Applies the actor-owned mount/lock policy before a path-scoped user FSCTL.
/// # Errors
///
/// Returns an error when the FILE_OBJECT is invalid, locked by another handle, or dismounted.
fn authorize_fs_control_handle(request: &mut PendingIrpLease<'_>) -> DriverResult<()> {
    request.with_active(|active| {
        let device = active.device();
        let opened = OpenedFileObject::decode(active.current_stack()?.file_object()?)?;
        let (volume, file_object) = match opened {
            OpenedFileObject::Node(opened) => (opened.volume(), opened.file_object()),
            OpenedFileObject::Volume(opened) => (opened.volume(), opened.file_object()),
        };
        if MountedVolumeDevice::vcb(device) != Some(volume) {
            crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                .bugcheck();
        }
        let operations = unsafe {
            // SAFETY: User FSCTLs execute on the mounted-device actor and this synchronous policy
            // check does not retain the lease beyond the active IRP borrow.
            VolumeControlBlock::claim_operation_lane(volume)
        };
        operations.authorize_handle(file_object)
    })
}
