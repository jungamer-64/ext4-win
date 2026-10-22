//! Bounded discovery exchanges with completion-owned native buffers and device references.

use core::{ffi::c_void, ptr::NonNull};
use wdk_sys::NTSTATUS;

use crate::kernel::fatal::KernelWideInconsistency;
use crate::state::KernelDevice;

/// One finite native request slot, retained by discovery until worker and lower callbacks retire.
#[derive(Debug)]
pub(in crate::kernel) struct DiscoveryIo {
    /// Native allocation owns its stop event, pending request, and independent lower buffers.
    channel: NonNull<c_void>,
}

impl DiscoveryIo {
    /// Allocates before the discovery worker or PnP subscription is published.
    /// # Errors
    /// Returns pool exhaustion without publishing any callback or native I/O.
    #[expect(
        unsafe_code,
        reason = "the control device encloses this channel and every registered completion"
    )]
    pub(super) fn try_new(owner: KernelDevice) -> Result<Self, NTSTATUS> {
        let channel = unsafe {
            // SAFETY: Control-device initialization retains this live completion-owner device.
            ext4win_discovery_channel_create(owner.as_ptr())
        };
        Ok(Self {
            channel: NonNull::new(channel).ok_or(wdk_sys::STATUS_INSUFFICIENT_RESOURCES)?,
        })
    }

    /// Raw identity used only by the adjacent native volume-query wire boundary.
    pub(super) fn as_ptr(&self) -> *mut c_void {
        self.channel.as_ptr()
    }

    /// Closes submission admission and requests cancellation without waiting for completion.
    #[expect(
        unsafe_code,
        reason = "the channel serializes closure with submission and retains the cancelled private IRP"
    )]
    pub(super) fn close(&self) {
        unsafe {
            // SAFETY: The discovery owner retains this initialized channel throughout closure.
            ext4win_discovery_channel_close(self.channel.as_ptr());
        }
    }

    /// Reclaims completed exchanges only after caller, callback and cancel access all end.
    #[expect(
        unsafe_code,
        reason = "native slot ownership serializes observation and reclamation"
    )]
    pub(super) fn idle(&self) -> bool {
        unsafe {
            // SAFETY: The native channel is retained by this sole discovery owner.
            ext4win_discovery_channel_idle(self.channel.as_ptr()) != 0
        }
    }
}

impl Drop for DiscoveryIo {
    #[expect(
        unsafe_code,
        reason = "joined discovery or dormant initialization rollback owns final channel destruction"
    )]
    fn drop(&mut self) {
        self.close();
        let released = unsafe {
            // SAFETY: The worker has joined or was never activated. Native destruction refuses
            // to consume its allocation while any lower completion or cancel observer remains.
            ext4win_discovery_channel_destroy(self.channel.as_ptr())
        };
        if released == 0 {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
    }
}

#[expect(
    unsafe_code,
    reason = "opaque native ownership contains private IRP, buffer and callback lifetimes"
)]
unsafe extern "system" {
    /// Creates one request channel under the driver's live completion-owner device.
    fn ext4win_discovery_channel_create(owner: wdk_sys::PDEVICE_OBJECT) -> *mut c_void;
    /// Closes admission and requests cancellation without joining lower I/O.
    fn ext4win_discovery_channel_close(channel: *mut c_void);
    /// Reports absence only after every observer of the pending request has retired.
    fn ext4win_discovery_channel_idle(channel: *mut c_void) -> u8;
    /// Consumes the channel only after explicit closure and observed quiescence.
    fn ext4win_discovery_channel_destroy(channel: *mut c_void) -> u8;
}
