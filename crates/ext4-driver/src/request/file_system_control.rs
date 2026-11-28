//! File-system-control admission and mounted lifecycle boundaries.

use crate::irp::PendingIrpLease;
use crate::kernel::status::{DriverError, DriverResult};
use core::ptr::NonNull;

use crate::state::{
    KernelDevice, KernelFileObject, MountedVolumeAccess, OpenedFileObject, OpenedVolume,
    VolumeControlBlock,
};

/// Stable direct-volume identities selected from a lifecycle FSCTL.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DirectVolumeTarget {
    /// Mounted device receiving the request.
    device: KernelDevice,
    /// Mounted VCB named by the direct-volume FILE_OBJECT.
    volume: NonNull<VolumeControlBlock>,
    /// Direct-volume FILE_OBJECT owning the lifecycle authority.
    owner: KernelFileObject,
}

impl DirectVolumeTarget {
    /// Mounted device receiving the lifecycle request.
    pub(crate) const fn device(self) -> KernelDevice {
        self.device
    }

    /// Mounted VCB selected by the direct-volume handle.
    pub(crate) const fn volume(self) -> NonNull<VolumeControlBlock> {
        self.volume
    }

    /// FILE_OBJECT identity owning lock/dismount authority.
    pub(crate) const fn owner(self) -> KernelFileObject {
        self.owner
    }
}

/// Authorizes one path-scoped FSCTL against the live opened handle.
/// # Errors
///
/// Returns an error for malformed FILE_OBJECT state, a volume lock owned elsewhere, or dismount.
pub(crate) fn authorize_path_handle(
    request: &mut PendingIrpLease<'_>,
    operations: &MountedVolumeAccess<'_>,
) -> DriverResult<()> {
    let (volume, file_object) = request.with_active(|active| {
        let opened = OpenedFileObject::decode(active.current_stack()?.file_object()?)?;
        Ok::<_, DriverError>(match opened {
            OpenedFileObject::Node(opened) => (opened.volume(), opened.file_object()),
            OpenedFileObject::Volume(opened) => (opened.volume(), opened.file_object()),
        })
    })?;
    if !operations.owns_volume(volume) {
        crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption().bugcheck();
    }
    operations.authorize_handle(file_object)
}

/// Decodes one payload-free volume lifecycle request into stable typed identities.
/// # Errors
///
/// Returns an error for nonempty buffers, a non-volume FILE_OBJECT, or a VCB/device mismatch.
pub(crate) fn direct_volume_target(
    request: &mut PendingIrpLease<'_>,
) -> DriverResult<DirectVolumeTarget> {
    request.with_active(|active| {
        let stack = active.current_stack()?.file_system_control()?;
        if !stack.input_buffer_length().is_empty() || !stack.output_buffer_length().is_empty() {
            return Err(DriverError::InvalidParameter);
        }
        let device = active.device();
        let opened = OpenedVolume::decode(active.current_stack()?.file_object()?)?;
        let volume = opened.volume();
        Ok(DirectVolumeTarget {
            device,
            volume,
            owner: opened.file_object(),
        })
    })
}

/// Applies `FSCTL_ALLOW_EXTENDED_DASD_IO` to one payload-free direct-volume handle.
/// # Errors
///
/// Returns an error for payload-bearing requests, a foreign VCB, invalid handle state, or a
/// lifecycle state that no longer admits this handle.
pub(crate) fn allow_extended_dasd_io(
    request: &mut PendingIrpLease<'_>,
    operations: &MountedVolumeAccess<'_>,
) -> DriverResult<()> {
    request.with_active(|active| {
        let stack = active.current_stack()?.file_system_control()?;
        if !stack.input_buffer_length().is_empty() || !stack.output_buffer_length().is_empty() {
            return Err(DriverError::InvalidParameter);
        }
        let mut opened = OpenedVolume::decode(active.current_stack()?.file_object()?)?;
        if !operations.owns_volume(opened.volume()) {
            return Err(DriverError::InvalidDeviceRequest);
        }
        operations.authorize_raw_extent_change(opened.file_object())?;
        opened.allow_partition_extent();
        Ok(())
    })
}
