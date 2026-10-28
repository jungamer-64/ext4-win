//! Effective requestor tokens retained through queued authorization or FsRtl watch ownership.

use crate::kernel::status::{DriverError, DriverResult};
use crate::security_descriptor::SecurityDescriptorRef;
use crate::state::KernelDevice;

/// Traversal authority captured on the requesting thread before notification queueing.
#[derive(Debug)]
pub(crate) struct NotificationSubject {
    /// Only original-context native capture may establish either authority.
    #[cfg(not(test))]
    authority: NotificationTraversalAuthority,
}

/// Captured bypass and retained-token checks are mutually exclusive.
#[derive(Debug)]
#[cfg(not(test))]
enum NotificationTraversalAuthority {
    /// The original subject has traversal bypass authority.
    Bypass,
    /// Tokens remain owned through cancellation or consuming FsRtl registration.
    Traverse(RequestorSubject),
}

impl NotificationSubject {
    /// Captures traversal bypass or the effective subject before leaving requestor context.
    /// # Errors
    /// Returns native IRQL/allocation failure; host fixtures cannot fabricate token authority.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "native capture interprets the original effective token before queue publication"
        )
    )]
    pub(crate) fn capture(
        device: KernelDevice,
        mode: wdk_sys::KPROCESSOR_MODE,
    ) -> DriverResult<Self> {
        #[cfg(not(test))]
        {
            let mut native = core::ptr::null_mut();
            let status = unsafe {
                // SAFETY: Original dispatch retains the device and this output during capture.
                super::ffi::ext4win_notification_subject_capture(device.as_ptr(), mode, &mut native)
            };
            if status < 0 {
                return Err(DriverError::SecurityCheckFailed(status));
            }
            Ok(Self {
                authority: match core::ptr::NonNull::new(native) {
                    Some(native) => {
                        NotificationTraversalAuthority::Traverse(RequestorSubject { native })
                    }
                    None => NotificationTraversalAuthority::Bypass,
                },
            })
        }
        #[cfg(test)]
        {
            core::hint::black_box((device, mode));
            Err(DriverError::NotSupported)
        }
    }

    /// Transfers the captured tokens and matching pool allocation to FsRtl at PASSIVE_LEVEL.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "consuming notification authority withdraws Rust cleanup before FsRtl can complete synchronously"
    )]
    pub(crate) fn into_fsrtl(self) -> *mut wdk_sys::SECURITY_SUBJECT_CONTEXT {
        match self.authority {
            NotificationTraversalAuthority::Bypass => core::ptr::null_mut(),
            NotificationTraversalAuthority::Traverse(subject) => {
                let subject = core::mem::ManuallyDrop::new(subject);
                unsafe {
                    // SAFETY: This consumes the sole native owner; C removes its worker and
                    // returns the allocation prefix that FsRtl releases and pool-frees once.
                    super::ffi::ext4win_subject_transfer_notification(subject.native.as_ptr())
                }
            }
        }
    }
}

/// The original requestor's token references, retained until authorization or cancellation.
/// Native release owns a device-referenced work item when cancellation runs above PASSIVE_LEVEL.
#[derive(Debug)]
pub(crate) struct RequestorSubject {
    /// Unique native context; it exposes only target attribute checks and consuming release.
    #[cfg(not(test))]
    native: core::ptr::NonNull<core::ffi::c_void>,
}

impl RequestorSubject {
    /// Captures the dispatch thread's effective subject before queue handoff.
    /// # Errors
    /// Returns native allocation/IRQL failure; host tests cannot capture kernel token authority.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "native capture retains tokens and a device-referenced release work item"
        )
    )]
    pub(crate) fn capture(
        _device: KernelDevice,
        _mode: wdk_sys::KPROCESSOR_MODE,
    ) -> DriverResult<Self> {
        #[cfg(not(test))]
        {
            let mut native = core::ptr::null_mut();
            let status = unsafe {
                // SAFETY: Dispatch retains this device and writable output through original-context capture.
                super::ffi::ext4win_subject_capture(_device.as_ptr(), _mode, &mut native)
            };
            if status < 0 {
                return Err(DriverError::SecurityCheckFailed(status));
            }
            Ok(Self {
                native: core::ptr::NonNull::new(native)
                    .ok_or(DriverError::InternalInvariantViolation)?,
            })
        }
        #[cfg(test)]
        Err(DriverError::NotSupported)
    }

    /// Requires attribute-write access to the exact replacement descriptor using the captured subject.
    /// # Errors
    /// Returns the Security Reference Monitor's denial; no namespace mutation has been staged.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the request retains the subject and immutable descriptor through the check"
        )
    )]
    pub(crate) fn require_write_attributes(
        &self,
        _descriptor: SecurityDescriptorRef<'_>,
    ) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let prepared = _descriptor.prepare(wdk_sys::FILE_WRITE_ATTRIBUTES)?;
            let status = unsafe {
                // SAFETY: This owner retains its native subject; the descriptor owner retains all encoded bytes.
                super::ffi::ext4win_subject_write_attributes(
                    self.native.as_ptr(),
                    prepared.as_ptr(),
                )
            };
            if status < 0 {
                Err(DriverError::SecurityCheckFailed(status))
            } else {
                Ok(())
            }
        }
        #[cfg(test)]
        Err(DriverError::NotSupported)
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the unique native owner transfers cleanup exactly once; its work item pins the device through release"
)]
impl Drop for RequestorSubject {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: This sole owner consumes its token context. Native code owns PASSIVE_LEVEL retirement.
            super::ffi::ext4win_subject_release(self.native.as_ptr());
        }
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "captured token references are locked by native checks and uniquely owned by the queued request"
)]
// SAFETY: Moves do not change token identity; every check runs at PASSIVE_LEVEL and release is IRQL-safe.
unsafe impl Send for RequestorSubject {}
