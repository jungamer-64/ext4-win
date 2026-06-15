//! File-system control, mount, reparse, and device-control dispatch boundary.

use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_NOT_SUPPORTED, STATUS_UNRECOGNIZED_VOLUME};

use crate::{
    irp::{DispatchTarget, MountVolumeStack},
    state::KernelDevice,
};

/// IRP_MN_MOUNT_VOLUME as a stack-location minor function byte.
const MOUNT_VOLUME_MINOR: wdk_sys::UCHAR = 1;

/// Handles create/open requests.
pub(crate) fn create(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles file-system control requests, including mount and reparse controls.
pub(crate) fn dispatch(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(FileSystemControlRequest::decode) {
        Ok(FileSystemControlRequest::MountVolume(request)) => mount_volume(request),
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

/// Rejects a decoded FSCTL until a dedicated control path owns it.
fn decoded_not_supported(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            let _device = target.device();
            let _irp = target.irp();
            STATUS_NOT_SUPPORTED
        }
        Err(error) => error.ntstatus(),
    }
}

/// File-system-control request understood at the dispatch boundary.
#[derive(Clone, Copy, Debug)]
enum FileSystemControlRequest {
    /// Mount request issued by the I/O Manager.
    MountVolume(MountVolumeRequest),
    /// Other FSCTL minor functions not owned by this FSD path yet.
    Unsupported,
}

impl FileSystemControlRequest {
    /// Decodes the current FSCTL stack location.
    fn decode(target: DispatchTarget) -> Result<Self, crate::status::DriverError> {
        let stack = target.current_stack()?;
        if stack.minor_function() != MOUNT_VOLUME_MINOR {
            return Ok(Self::Unsupported);
        }
        Ok(Self::MountVolume(MountVolumeRequest::from_stack(
            stack.mount_volume()?,
        )))
    }
}

/// Mount request after raw IRP stack decoding.
#[derive(Clone, Copy, Debug)]
struct MountVolumeRequest {
    /// VPB supplied by the I/O Manager for this mount.
    vpb: core::ptr::NonNull<wdk_sys::VPB>,
    /// Lower storage device selected by the I/O Manager.
    target_device: KernelDevice,
    /// Output buffer length supplied with the mount request.
    output_buffer_length: wdk_sys::ULONG,
}

impl MountVolumeRequest {
    /// Converts decoded stack parameters into the mount domain boundary.
    fn from_stack(stack: MountVolumeStack) -> Self {
        Self {
            vpb: stack.vpb(),
            target_device: KernelDevice::from_non_null(stack.target_device()),
            output_buffer_length: stack.output_buffer_length(),
        }
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
    const fn output_buffer_length(self) -> wdk_sys::ULONG {
        self.output_buffer_length
    }
}

/// Handles a decoded mount request.
fn mount_volume(request: MountVolumeRequest) -> NTSTATUS {
    let _mount_boundary = (
        request.vpb(),
        request.target_device(),
        request.output_buffer_length(),
    );
    STATUS_UNRECOGNIZED_VOLUME
}
