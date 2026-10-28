//! Volume admission shared by dispatch, the reactor and native cache callbacks.
//!
//! Media revocation, reversible query removal and filesystem close are independent facts.
//! Only submission scopes hold the native resource; revocation never waits for lower completion.

use super::io_reliability::IoReliabilityObservation;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering};

/// Monotonic lower-device availability, independent of filesystem close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum MediaState {
    /// Lower submissions remain available.
    Present = 0,
    /// Surprise removal has revoked storage.
    SurpriseRemoved = 1,
    /// Final removal also permits device retirement.
    Removed = 2,
}

impl MediaState {
    /// Private atomic representation of this independent state domain.
    #[expect(
        clippy::as_conversions,
        reason = "repr(u8) defines the private atomic representation"
    )]
    const fn raw(self) -> u8 {
        self as u8
    }
}

/// Filesystem admission while a terminal close drains writeback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum ClosePhase {
    /// Ordinary requests and creates are admitted.
    Open = 0,
    /// Only paging writeback is admitted.
    Writeback = 1,
    /// Filesystem I/O is sealed; owner-driven lower flush remains available.
    Sealed = 2,
}

impl ClosePhase {
    /// Private atomic representation of this independent state domain.
    #[expect(
        clippy::as_conversions,
        reason = "repr(u8) defines the private atomic representation"
    )]
    const fn raw(self) -> u8 {
        self as u8
    }
}

/// Reversible create exclusion owned by the query-remove protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum QueryPhase {
    /// Creates are admitted.
    Open = 0,
    /// A unique preparation owns rollback.
    Preparing = 1,
    /// Lower PnP cancellation or terminal removal owns resolution.
    Pending = 2,
}

impl QueryPhase {
    /// Private atomic representation of this independent state domain.
    #[expect(
        clippy::as_conversions,
        reason = "repr(u8) defines the private atomic representation"
    )]
    const fn raw(self) -> u8 {
        self as u8
    }
}

/// Sole admission authority. Atomics permit observations from native cache callbacks.
#[derive(Debug)]
pub(super) struct StorageAdmission {
    /// Owns one real-device reference published before mounted callbacks become visible.
    verification_device: AtomicPtr<wdk_sys::DEVICE_OBJECT>,
    /// Reactor-owned reliability projection retained independently from media and close.
    pub(super) reliability: IoReliabilityObservation,
    /// Monotonic media revocation.
    media: AtomicU8,
    /// One-way filesystem close admission.
    close: AtomicU8,
    /// Independent reversible create exclusion.
    query: AtomicU8,
    /// Independent namespace exclusion retained while a drained-volume key is removed.
    key_removal: AtomicBool,
}

impl StorageAdmission {
    /// Unpublished volume with storage and filesystem admission open.
    pub(super) const fn new(reliability: IoReliabilityObservation) -> Self {
        Self {
            verification_device: AtomicPtr::new(core::ptr::null_mut()),
            reliability,
            media: AtomicU8::new(0),
            close: AtomicU8::new(0),
            query: AtomicU8::new(0),
            key_removal: AtomicBool::new(false),
        }
    }

    /// Publishes the real device exactly once before mounted admission is exposed.
    /// # Errors
    /// Rejects duplicate initialization while retaining the supplied reference for destruction.
    pub(super) fn bind_verification_device(
        &self,
        device: super::volume_verify::VerificationDevice,
    ) -> crate::kernel::status::DriverResult<()> {
        self.verification_device
            .compare_exchange(
                core::ptr::null_mut(),
                device.as_raw(),
                Ordering::Release,
                Ordering::Relaxed,
            )
            .map_err(|_| crate::kernel::status::DriverError::InternalInvariantViolation)?;
        let _transferred = device.into_raw();
        Ok(())
    }

    /// Observes the physical flag independently from cached runtime reliability.
    #[expect(
        unsafe_code,
        reason = "the admission owner retains the published real-device reference through every callback"
    )]
    pub(super) fn verification_required(&self) -> bool {
        let pointer = self.verification_device.load(Ordering::Acquire);
        // SAFETY: A nonnull slot owns its independently retained device reference until Drop.
        let device = unsafe { crate::state::KernelDevice::from_raw(pointer) };
        device.is_some_and(super::volume_verify::required)
    }

    /// Observes the monotonic media state after publication.
    pub(super) fn media(&self) -> MediaState {
        match self.media.load(Ordering::Acquire) {
            0 => MediaState::Present,
            1 => MediaState::SurpriseRemoved,
            _ => MediaState::Removed,
        }
    }

    /// Observes filesystem admission independently of media state.
    pub(super) fn close(&self) -> ClosePhase {
        match self.close.load(Ordering::Acquire) {
            0 => ClosePhase::Open,
            1 => ClosePhase::Writeback,
            _ => ClosePhase::Sealed,
        }
    }

    /// Ordinary native transfers require verified media and open filesystem admission.
    pub(super) fn ordinary_io_admitted(&self, write: bool) -> bool {
        self.media() == MediaState::Present
            && self.close() == ClosePhase::Open
            && !self.verification_required()
            && self.reliability.policy().permits(write)
    }

    /// Paging may drain during terminal writeback, independently from ordinary verification.
    pub(super) fn paging_io_admitted(&self, write: bool) -> bool {
        self.media() == MediaState::Present
            && self.close() != ClosePhase::Sealed
            && self.reliability.policy().permits(write)
    }

    /// Private copy-on-write sections do not acquire backing-file write authority.
    pub(super) fn section_admitted(&self, writable_data: bool, protection: u32) -> bool {
        let write = protection & (wdk_sys::PAGE_READWRITE | wdk_sys::PAGE_EXECUTE_READWRITE) != 0;
        self.ordinary_io_admitted(write) && (!write || writable_data)
    }

    /// Creates require every independent gate to admit them.
    pub(super) fn creates_admitted(&self) -> bool {
        self.media() == MediaState::Present
            && self.close() == ClosePhase::Open
            && self.query.load(Ordering::Acquire) == QueryPhase::Open.raw()
            && !self.key_removal_active()
            && !self.verification_required()
    }

    /// Claims the unique exclusion after the actor validates completed volume-lock ownership.
    pub(super) fn begin_key_removal(&self) -> bool {
        self.key_removal
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Observes only exclusion; it grants neither lock ownership nor key mutation authority.
    pub(super) fn key_removal_active(&self) -> bool {
        self.key_removal.load(Ordering::Acquire)
    }

    /// Released by the unique operation lease after publication or abandonment.
    pub(super) fn end_key_removal(&self) {
        self.key_removal.store(false, Ordering::Release);
    }

    /// Claims close writeback exactly once without restoring revoked media.
    pub(super) fn begin_close(&self) -> bool {
        self.media() == MediaState::Present
            && self
                .close
                .compare_exchange(
                    ClosePhase::Open.raw(),
                    ClosePhase::Writeback.raw(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    /// Irreversibly stops paging admission after writeback has drained.
    pub(super) fn seal_close(&self) {
        self.close
            .store(ClosePhase::Sealed.raw(), Ordering::Release);
    }

    /// Claims the sole reversible preparation.
    pub(super) fn prepare_query(&self) -> bool {
        self.media() == MediaState::Present
            && self
                .query
                .compare_exchange(
                    QueryPhase::Open.raw(),
                    QueryPhase::Preparing.raw(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    /// Rollback can reopen only an unpublished preparation.
    pub(super) fn abort_query(&self) {
        let _observed = self.query.compare_exchange(
            QueryPhase::Preparing.raw(),
            QueryPhase::Open.raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Transfers create exclusion from preparation to the PnP protocol.
    pub(super) fn publish_query(&self) -> bool {
        self.media() == MediaState::Present
            && self
                .query
                .compare_exchange(
                    QueryPhase::Preparing.raw(),
                    QueryPhase::Pending.raw(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    /// Successful lower cancellation can clear only published reversible exclusion.
    pub(super) fn cancel_query(&self) {
        let _observed = self.query.compare_exchange(
            QueryPhase::Pending.raw(),
            QueryPhase::Open.raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Called under exclusive submission exclusion; no observation can restore media.
    pub(super) fn remove(&self, state: MediaState) {
        self.media.fetch_max(state.raw(), Ordering::AcqRel);
    }
}

impl Drop for StorageAdmission {
    #[expect(
        unsafe_code,
        reason = "native stream destruction precedes consuming the admission owner's transferred real-device reference"
    )]
    fn drop(&mut self) {
        let pointer = self
            .verification_device
            .swap(core::ptr::null_mut(), Ordering::AcqRel);
        // SAFETY: A nonnull pointer is the unique reference transferred into this slot once;
        // the native stream has drained all callbacks before its admission allocation drops.
        let owned = unsafe { super::volume_verify::VerificationDevice::from_owned_raw(pointer) };
        drop(owned);
    }
}

/// Native callbacks borrow only media observation, never mutation authority.
/// # Safety
/// `state` must be the volume's live admission allocation retained by its VCB.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native node lifetime is enclosed by the volume admission owner"
)]
#[expect(
    clippy::as_conversions,
    reason = "repr(u8) fixes the callback observation representation"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_storage_media_state(state: *const StorageAdmission) -> u8 {
    let state = unsafe {
        // SAFETY: The native volume header borrows this retained allocation.
        &*state
    };
    state.media() as u8
}

/// Observes media presence without exposing its representation to native policy code.
/// # Safety
/// The enclosing volume retains `state` throughout this callback.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native callbacks borrow the retained volume admission allocation"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_storage_present(state: *const StorageAdmission) -> u8 {
    // SAFETY: The native volume retains this allocation through the call.
    u8::from(unsafe { &*state }.media() == MediaState::Present)
}

/// Selects ordinary cache admission from the sole Rust policy owner.
/// # Safety
/// The enclosing volume retains `state` throughout this callback.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native callbacks borrow the retained volume admission allocation"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_storage_ordinary_io(state: *const StorageAdmission) -> u8 {
    // SAFETY: The native volume retains this allocation through the call.
    u8::from(unsafe { &*state }.ordinary_io_admitted(false))
}

/// Selects backing-file section authority after native resource acquisition.
/// # Safety
/// The enclosing volume retains `state`; `writable_data` is its committed inode observation.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native callbacks lend immutable policy and inode observations"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_storage_section_io(
    state: *const StorageAdmission,
    writable_data: u8,
    protection: u32,
) -> u8 {
    // SAFETY: The native volume retains this allocation through the call.
    u8::from(unsafe { &*state }.section_admitted(writable_data != 0, protection))
}

/// Selects direct paging admission without exposing phase encodings to C.
/// # Safety
/// The enclosing volume retains `state` throughout this callback.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native dispatch borrows the retained volume admission allocation"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_storage_paging_io(
    state: *const StorageAdmission,
    write: u8,
) -> u8 {
    // SAFETY: The native volume retains this allocation through the call.
    u8::from(unsafe { &*state }.paging_io_admitted(write != 0))
}

/// Returns a cached-I/O observation with physical verification folded into Rust policy.
/// # Safety
/// The enclosing volume retains `state` throughout this callback.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native dispatch borrows the retained volume admission allocation"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_storage_cached_policy(state: *const StorageAdmission) -> u8 {
    // SAFETY: The native volume retains this allocation through the call.
    let state = unsafe { &*state };
    if state.verification_required() {
        super::io_reliability::NativeIoPolicy::Unavailable.raw()
    } else {
        state.reliability.policy().raw()
    }
}

/// Native callbacks borrow only filesystem admission observation.
/// # Safety
/// `state` must be the volume's live admission allocation retained by its VCB.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native cache observers cannot acquire transition authority"
)]
#[expect(
    clippy::as_conversions,
    reason = "repr(u8) fixes the callback observation representation"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_storage_close_phase(state: *const StorageAdmission) -> u8 {
    let state = unsafe {
        // SAFETY: Native callbacks retain the node and its enclosing volume.
        &*state
    };
    state.close() as u8
}

/// Observes reliability without acquiring actor or filesystem resources.
/// # Safety
/// `state` is retained by the enclosing volume through every native callback.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native callbacks borrow the retained volume observation"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_storage_io_policy(state: *const StorageAdmission) -> u8 {
    let state = unsafe {
        // SAFETY: The native volume header retains this allocation and its observation lease.
        &*state
    };
    state.reliability.policy().raw()
}

/// Reports the current physical flag without changing reliability, admission or acknowledgment.
/// # Safety
/// The native volume header must retain this initialized admission allocation through the call.
#[expect(
    unsafe_code,
    reason = "native callbacks borrow the retained volume admission owner"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_storage_verify_required(state: *const StorageAdmission) -> u8 {
    // SAFETY: The native volume header retains this allocation through its callback.
    let state = unsafe { &*state };
    u8::from(state.verification_required())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns allocation or retained-observation budget failure.
    /// # Panics
    /// Fails if native admission bypasses inode protection, terminal close or reliability.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture setup precedes native admission assertions"
    )]
    fn native_io_classes_share_volume_policy_and_keep_writeback_independent()
    -> crate::kernel::status::DriverResult<()> {
        use crate::kernel::io_reliability::{IoReliabilityOwner, NativeIoPolicy};
        let mut owner = IoReliabilityOwner::try_new()?;
        let state = StorageAdmission::new(owner.observe()?);
        assert!(state.section_admitted(true, wdk_sys::PAGE_READWRITE));
        assert!(!state.section_admitted(false, wdk_sys::PAGE_READWRITE));
        assert!(!state.section_admitted(false, wdk_sys::PAGE_EXECUTE_READWRITE));
        assert!(state.section_admitted(false, wdk_sys::PAGE_READONLY));
        assert!(state.section_admitted(false, wdk_sys::PAGE_WRITECOPY));
        assert!(state.section_admitted(false, wdk_sys::PAGE_EXECUTE_WRITECOPY));
        owner.publish(NativeIoPolicy::ReadOnly, None);
        assert!(state.ordinary_io_admitted(false));
        assert!(!state.ordinary_io_admitted(true));
        assert!(!state.section_admitted(true, wdk_sys::PAGE_READWRITE));
        assert!(state.section_admitted(false, wdk_sys::PAGE_WRITECOPY));
        assert!(state.paging_io_admitted(false));
        assert!(!state.paging_io_admitted(true));
        owner.publish(NativeIoPolicy::Unavailable, None);
        assert!(!state.section_admitted(true, wdk_sys::PAGE_READONLY));
        assert!(!state.paging_io_admitted(false));
        owner.publish(NativeIoPolicy::ReadWrite, None);
        assert!(state.begin_close());
        assert!(!state.ordinary_io_admitted(false));
        assert!(state.paging_io_admitted(true));
        state.seal_close();
        assert!(!state.paging_io_admitted(false));
        state.remove(MediaState::SurpriseRemoved);
        assert!(!state.ordinary_io_admitted(false));
        assert!(!state.paging_io_admitted(true));
        Ok(())
    }

    /// # Errors
    /// Returns fixture retention or native-observation allocation failure.
    /// # Panics
    /// Fails if physical verification bypasses create gating or restores failed runtime health.
    #[test]
    #[expect(
        unsafe_code,
        reason = "the scoped device allocation outlives admission and all atomic native observations"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture ownership surrounds independent media and reliability assertions"
    )]
    fn physical_verify_gate_is_independent_from_runtime_reliability()
    -> crate::kernel::status::DriverResult<()> {
        use crate::kernel::io_reliability::{IoReliabilityOwner, NativeIoPolicy};
        let mut device = wdk_sys::DEVICE_OBJECT {
            Flags: wdk_sys::DO_VERIFY_VOLUME | 0x4000,
            ..Default::default()
        };
        // SAFETY: The device fixture outlives the admission reference and every native call below.
        let device = unsafe { crate::state::KernelDevice::from_raw(&raw mut device) }
            .ok_or(crate::kernel::status::DriverError::InvalidParameter)?;
        let mut reliability = IoReliabilityOwner::try_new()?;
        let state = StorageAdmission::new(reliability.observe()?);
        state.bind_verification_device(
            super::super::volume_verify::VerificationDevice::reference(device),
        )?;
        assert!(state.verification_required());
        assert!(!state.creates_admitted());
        assert!(!state.ordinary_io_admitted(false));
        assert!(!state.section_admitted(true, wdk_sys::PAGE_READWRITE));
        assert!(state.reliability.policy().permits(true));
        super::super::volume_verify::acknowledge(device);
        assert!(!state.verification_required());
        assert!(state.creates_admitted());
        assert!(state.ordinary_io_admitted(true));
        reliability.publish(NativeIoPolicy::Unavailable, None);
        super::super::volume_verify::acknowledge(device);
        assert!(!state.reliability.policy().permits(false));
        Ok(())
    }

    /// # Panics
    /// Fails if native observations retain stale permission after actor publication.
    /// # Errors
    /// Returns allocation or reference-budget failure during setup.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check native revocation while setup propagates allocation failure"
    )]
    fn reliability_revokes_native_writes_and_reads_independently()
    -> crate::kernel::status::DriverResult<()> {
        use crate::kernel::io_reliability::{IoReliabilityOwner, NativeIoPolicy};
        let mut owner = IoReliabilityOwner::try_new()?;
        let state = StorageAdmission::new(owner.observe()?);
        assert!(state.reliability.policy().permits(true));
        owner.publish(NativeIoPolicy::ReadOnly, None);
        assert!(state.reliability.policy().permits(false));
        assert!(!state.reliability.policy().permits(true));
        owner.publish(NativeIoPolicy::Unavailable, None);
        assert!(!state.reliability.policy().permits(false));
        assert!(!state.reliability.policy().permits(true));
        Ok(())
    }

    /// # Panics
    /// Fails if reversible cancellation restores media or terminal filesystem admission.
    /// # Errors
    /// Returns allocation or reference-budget failure during setup.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check cancellation while setup propagates allocation failure"
    )]
    fn cancellation_does_not_restore_terminal_authority() -> crate::kernel::status::DriverResult<()>
    {
        let owner = crate::kernel::io_reliability::IoReliabilityOwner::try_new()?;
        let state = StorageAdmission::new(owner.observe()?);
        assert!(state.prepare_query());
        assert!(!state.creates_admitted());
        assert!(state.publish_query());
        state.abort_query();
        assert!(!state.creates_admitted());
        state.cancel_query();
        assert!(state.creates_admitted());
        assert!(state.begin_close());
        assert!(!state.begin_close());
        state.seal_close();
        state.cancel_query();
        assert!(!state.creates_admitted());
        assert_eq!(state.close(), ClosePhase::Sealed);
        state.remove(MediaState::Removed);
        state.remove(MediaState::SurpriseRemoved);
        state.cancel_query();
        assert_eq!(state.media(), MediaState::Removed);
        assert!(!state.prepare_query());
        Ok(())
    }
}
