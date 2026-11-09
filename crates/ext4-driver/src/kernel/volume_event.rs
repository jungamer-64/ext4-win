//! Advisory volume events delivered outside actor borrows with independent mount completion.

use crate::kernel::operational_trace::{OperationalOutcome, OperationalPath, OperationalTrace};
use crate::state::{KernelDevice, KernelFileObject};
#[cfg(not(test))]
use core::ptr::NonNull;
#[cfg(not(test))]
use wdk_sys::NTSTATUS;
use wdk_sys::STATUS_SUCCESS;

/// Lifecycle observations confer no volume-transition authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeEvent {
    /// Allows registered users to release handles before exclusive-lock admission.
    Lock,
    /// An announced exclusive lock did not complete.
    LockFailed,
    /// The exclusive handle released its volume lock.
    Unlock,
    /// Allows registered users to release handles before dismount cache preparation.
    Dismount,
    /// An announced dismount attempt did not complete.
    DismountFailed,
}

/// Notification ordering follows the source of FILE_OBJECT ownership.
#[derive(Debug)]
pub(crate) enum VolumeNotification {
    /// The IRP retains a user volume file through delivery.
    File {
        /// Exact direct-volume file retained by the original IRP.
        file: KernelFileObject,
        /// Event corresponding to the observed transition.
        event: VolumeEvent,
    },
    /// Mount has no user FILE_OBJECT; retain the published device for native stream creation.
    Mount(MountedEventDevice),
}

/// One object reference, acquired while mount still owns its published device.
#[derive(Debug)]
pub(crate) struct MountedEventDevice {
    /// Mount device retained through completion and advisory event delivery.
    device: KernelDevice,
    /// Reports completion and the independently fallible advisory event.
    trace: OperationalTrace,
}

impl Drop for MountedEventDevice {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the notification consumes its sole native device reference"
        )
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Construction acquired exactly one reference retained until worker delivery.
            crate::kernel::ffi::ObfDereferenceObject(self.device.as_ptr().cast());
        }
    }
}

impl VolumeNotification {
    /// Captures an event and its IRP-retained native identity.
    pub(crate) const fn new(file: KernelFileObject, event: VolumeEvent) -> Self {
        Self::File { file, event }
    }

    /// Retains the successful mount independently of actor admission and request completion.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "mount publication retains this live DEVICE_OBJECT through native reference acquisition"
        )
    )]
    pub(crate) fn mounted(device: KernelDevice, trace: OperationalTrace) -> Self {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Successful publication retains the mounted device during this increment.
            crate::kernel::ffi::ObfReferenceObject(device.as_ptr().cast());
        }
        Self::Mount(MountedEventDevice { device, trace })
    }

    /// File events borrow the IRP's file. Mount events instead carry a stream reference across
    /// completion, so a notification callback can open the volume without waiting on this IRP.
    pub(crate) fn complete(self, finish: impl FnOnce()) {
        match self {
            Self::File { file, event } => {
                event.deliver(file);
                finish();
            }
            Self::Mount(device) => {
                device.trace.record(
                    OperationalPath::MountNotification,
                    STATUS_SUCCESS,
                    OperationalOutcome::Selected,
                );
                #[cfg(not(test))]
                let prepared = device.prepare();
                device.trace.record(
                    OperationalPath::MountCompletion,
                    STATUS_SUCCESS,
                    OperationalOutcome::Selected,
                );
                finish();
                device
                    .trace
                    .record_status(OperationalPath::MountCompletion, STATUS_SUCCESS);
                #[cfg(not(test))]
                let status = prepared.map_or_else(core::convert::identity, MountEventFile::deliver);
                #[cfg(test)]
                let status = {
                    let _device = device.device;
                    STATUS_SUCCESS
                };
                device
                    .trace
                    .record_status(OperationalPath::MountNotification, status);
            }
        }
    }
}

impl VolumeEvent {
    /// The enclosing IRP retains this file for the advisory native call.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the worker retains the original FILE_OBJECT through this advisory native call"
        )
    )]
    pub(crate) fn deliver(self, file: KernelFileObject) {
        let code = match self {
            VolumeEvent::Lock => wdk_sys::FSRTL_VOLUME_LOCK,
            VolumeEvent::LockFailed => wdk_sys::FSRTL_VOLUME_LOCK_FAILED,
            VolumeEvent::Unlock => wdk_sys::FSRTL_VOLUME_UNLOCK,
            VolumeEvent::Dismount => wdk_sys::FSRTL_VOLUME_DISMOUNT,
            VolumeEvent::DismountFailed => wdk_sys::FSRTL_VOLUME_DISMOUNT_FAILED,
        };
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The IRP owns this FILE_OBJECT; no actor/resource borrow survives handoff.
            // Notification is advisory, and no recovery owner can retry an observed transition.
            let _notification_status = wdk_sys::ntddk::FsRtlNotifyVolumeEvent(file.as_ptr(), code);
        }
        #[cfg(test)]
        let _native_arguments = (file, code);
    }
}

#[cfg(not(test))]
impl MountedEventDevice {
    /// Takes the stream's independent VPB reference while the mount IRP still owns its association.
    /// # Errors
    /// Returns native stream creation failure. Mount completion remains independently valid.
    #[expect(
        unsafe_code,
        reason = "the live mount pins the device and the native result transfers one stream reference"
    )]
    fn prepare(&self) -> Result<MountEventFile, NTSTATUS> {
        let mut file = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: This owner and the pending mount IRP retain the published device and VPB.
            ext4win_prepare_volume_mount_event(self.device.as_ptr(), &raw mut file)
        };
        if status < STATUS_SUCCESS {
            return Err(status);
        }
        NonNull::new(file)
            .map(MountEventFile)
            .ok_or(wdk_sys::STATUS_INTERNAL_ERROR)
    }
}

/// A native stream reference that also retains the original VPB after mount-IRP completion.
#[cfg(not(test))]
struct MountEventFile(NonNull<wdk_sys::FILE_OBJECT>);

#[cfg(not(test))]
impl MountEventFile {
    /// Consumes advisory delivery authority before releasing the stream on this worker.
    #[expect(
        unsafe_code,
        reason = "the owned stream reference pins the exact native file during notification"
    )]
    fn deliver(self) -> NTSTATUS {
        unsafe {
            // SAFETY: The stream and its VPB remain live through this PASSIVE_LEVEL call.
            ext4win_deliver_volume_mount_event(self.0.as_ptr())
        }
    }
}

#[cfg(not(test))]
impl Drop for MountEventFile {
    #[expect(
        unsafe_code,
        reason = "the stream owner releases exactly one native reference at PASSIVE_LEVEL"
    )]
    fn drop(&mut self) {
        unsafe {
            // SAFETY: This owner exclusively holds the reference returned by native preparation.
            crate::kernel::ffi::ObfDereferenceObject(self.0.as_ptr().cast());
        }
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the native mount-event boundary contains stream allocation and notification exceptions"
)]
unsafe extern "C" {
    /// Creates one contextless stream and transfers its reference on success.
    fn ext4win_prepare_volume_mount_event(
        device: wdk_sys::PDEVICE_OBJECT,
        prepared: *mut wdk_sys::PFILE_OBJECT,
    ) -> NTSTATUS;
    /// Delivers the event while the caller retains its contextless stream reference.
    fn ext4win_deliver_volume_mount_event(file: wdk_sys::PFILE_OBJECT) -> NTSTATUS;
}
