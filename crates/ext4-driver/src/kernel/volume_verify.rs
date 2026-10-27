//! Final native verify acknowledgment changes only the retained real device's verify flag.

use crate::kernel::status::{DriverError, DriverResult};
use crate::state::KernelDevice;

/// One native device reference held by a verification worker or the volume admission owner.
#[derive(Debug)]
pub(crate) struct VerificationDevice {
    /// Reference survives actor suspension and native verify reentry.
    device: KernelDevice,
}

impl VerificationDevice {
    /// Acquires retention while the caller's VPB lock establishes native object liveness.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "VPB retention establishes liveness before Object Manager reference acquisition"
        )
    )]
    pub(crate) fn reference(device: KernelDevice) -> Self {
        #[cfg(not(test))]
        // SAFETY: The caller retains the real device under the VPB lock until this reference exists.
        unsafe {
            crate::kernel::ffi::ObfReferenceObject(device.as_ptr().cast());
        }
        Self { device }
    }

    /// Borrows native identity for admission publication without transferring its reference.
    pub(super) fn as_raw(&self) -> wdk_sys::PDEVICE_OBJECT {
        self.device.as_ptr()
    }

    /// Transfers its native reference into the volume's published admission slot.
    pub(super) fn into_raw(self) -> wdk_sys::PDEVICE_OBJECT {
        let pointer = self.device.as_ptr();
        core::mem::forget(self);
        pointer
    }

    /// Reclaims exactly the native reference previously transferred into admission storage.
    /// # Safety
    /// The pointer must own one still-live reference transferred by `into_raw`, consumed once.
    #[expect(
        unsafe_code,
        reason = "only admission teardown reconstructs its unique previously transferred native reference"
    )]
    pub(super) unsafe fn from_owned_raw(pointer: wdk_sys::PDEVICE_OBJECT) -> Option<Self> {
        // SAFETY: The caller owns and retains this native device reference through reconstruction.
        unsafe { KernelDevice::from_raw(pointer) }.map(|device| Self { device })
    }

    /// Invokes the I/O Manager outside actor/VPB/stream-resource ownership.
    /// # Errors
    /// Returns the exact failed verify status; success grants no recovery or media-write authority.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the owned native device reference survives the blocking I/O Manager verify and reentrant kernel IRP"
        )
    )]
    pub(crate) fn execute(self) -> DriverResult<()> {
        #[cfg(not(test))]
        // SAFETY: The worker runs at PASSIVE_LEVEL with no actor/native resource borrow and retains the device.
        let status = unsafe { ext4win_verify_volume(self.device.as_ptr()) };
        #[cfg(test)]
        let status = wdk_sys::STATUS_SUCCESS;
        if status == wdk_sys::STATUS_WRONG_VOLUME {
            Err(DriverError::WrongVolume)
        } else if status < 0 {
            Err(DriverError::CacheManagerFailure(status))
        } else {
            Ok(())
        }
    }
}

impl Drop for VerificationDevice {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "unique native reference is released after its worker or admission lifetime ends"
        )
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        // SAFETY: This owner consumes exactly its independently acquired Object Manager reference.
        unsafe {
            crate::kernel::ffi::ObfDereferenceObject(self.device.as_ptr().cast());
        }
    }
}

/// Polls the physical verify flag without admitting or acknowledging any I/O.
#[expect(
    unsafe_code,
    reason = "the retained native identity permits an atomic flag observation"
)]
pub(crate) fn required(device: KernelDevice) -> bool {
    // SAFETY: The caller retains this real device while native code atomically reads its flags.
    unsafe { ext4win_volume_requires_verify(device.as_ptr()) != 0 }
}

/// Caller serializes and revalidates its complete mounted association before acknowledgment.
#[expect(
    unsafe_code,
    reason = "native interlocked flag update accepts the retained real-device identity by value"
)]
pub(crate) fn acknowledge(device: KernelDevice) {
    // SAFETY: The caller retains the I/O Manager device and holds its mounted VPB lock;
    // native code atomically clears only DO_VERIFY_VOLUME without borrowing other device fields.
    unsafe {
        ext4win_clear_verify_required(device.as_ptr());
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native code owns the interlocked DEVICE_OBJECT flag representation"
)]
unsafe extern "C" {
    fn ext4win_clear_verify_required(device: wdk_sys::PDEVICE_OBJECT);
    fn ext4win_volume_requires_verify(device: wdk_sys::PDEVICE_OBJECT) -> u8;
    fn ext4win_verify_volume(device: wdk_sys::PDEVICE_OBJECT) -> wdk_sys::NTSTATUS;
}

#[cfg(test)]
/// Applies acknowledgment to a retained host device fixture.
/// # Safety
/// The caller must retain aligned, initialized device storage without non-atomic flag access.
#[expect(
    unsafe_code,
    reason = "host fixtures retain their device allocation through this atomic scalar update"
)]
unsafe fn ext4win_clear_verify_required(device: wdk_sys::PDEVICE_OBJECT) {
    // SAFETY: Test callers retain the same exclusive device fixture through acknowledgment.
    let flags = unsafe { core::ptr::addr_of_mut!((*device).Flags) };
    // SAFETY: Flags is naturally aligned nonpaged ULONG storage; this is its sole test writer.
    let flags = unsafe { core::sync::atomic::AtomicU32::from_ptr(flags) };
    flags.fetch_and(
        !wdk_sys::DO_VERIFY_VOLUME,
        core::sync::atomic::Ordering::AcqRel,
    );
}

#[cfg(test)]
/// Observes a retained host device fixture through the native atomic contract.
/// # Safety
/// The caller must retain aligned, initialized device storage without non-atomic flag access.
#[expect(
    unsafe_code,
    reason = "host fixtures retain their device allocation through this atomic scalar read"
)]
unsafe fn ext4win_volume_requires_verify(device: wdk_sys::PDEVICE_OBJECT) -> u8 {
    // SAFETY: The caller retains this initialized native device through the host observation.
    let flags = unsafe { core::ptr::addr_of_mut!((*device).Flags) };
    // SAFETY: Natural ULONG storage is retained and mutable flag access is atomic during host observations.
    let flags = unsafe { core::sync::atomic::AtomicU32::from_ptr(flags) };
    u8::from(flags.load(core::sync::atomic::Ordering::Acquire) & wdk_sys::DO_VERIFY_VOLUME != 0)
}
