//! Advisory volume events delivered outside actor borrows while an IRP retains its file.

use crate::state::{KernelDevice, KernelFileObject};

/// Lifecycle observations confer no volume-transition authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeEvent {
    /// Allows registered users to release handles before exclusive-lock admission.
    Lock,
    /// An announced exclusive lock did not complete.
    LockFailed,
    /// The exclusive handle released its volume lock.
    Unlock,
    /// A durable logical dismount completed.
    Dismount,
}

/// The enclosing IRP/worker retains this FILE_OBJECT until delivery returns.
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
pub(crate) struct MountedEventDevice(KernelDevice);

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
            crate::kernel::ffi::ObfDereferenceObject(self.0.as_ptr().cast());
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
    pub(crate) fn mounted(device: KernelDevice) -> Self {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Successful publication retains the mounted device during this increment.
            crate::kernel::ffi::ObfReferenceObject(device.as_ptr().cast());
        }
        Self::Mount(MountedEventDevice(device))
    }

    /// Delivers once at PASSIVE_LEVEL. Advisory failure cannot roll back the volume effect
    /// and grants no retry authority; the IRP keeps its independently prepared outcome.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the worker retains the original FILE_OBJECT through this advisory native call"
        )
    )]
    pub(crate) fn deliver(self) {
        let (file, event) = match self {
            Self::File { file, event } => (file, event),
            Self::Mount(device) => {
                #[cfg(not(test))]
                unsafe {
                    // SAFETY: The reference pins the device through SEH-protected temporary
                    // stream creation, event delivery and native object release.
                    let _notification_status = ext4win_notify_volume_mount(device.0.as_ptr());
                }
                #[cfg(test)]
                let _device = device.0;
                return;
            }
        };
        let code = match event {
            VolumeEvent::Lock => wdk_sys::FSRTL_VOLUME_LOCK,
            VolumeEvent::LockFailed => wdk_sys::FSRTL_VOLUME_LOCK_FAILED,
            VolumeEvent::Unlock => wdk_sys::FSRTL_VOLUME_UNLOCK,
            VolumeEvent::Dismount => wdk_sys::FSRTL_VOLUME_DISMOUNT,
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
#[expect(
    unsafe_code,
    reason = "the native mount-event boundary contains stream allocation and notification exceptions"
)]
unsafe extern "C" {
    /// Creates and releases one contextless stream FILE_OBJECT on the retained mounted device.
    fn ext4win_notify_volume_mount(device: wdk_sys::PDEVICE_OBJECT) -> wdk_sys::NTSTATUS;
}
