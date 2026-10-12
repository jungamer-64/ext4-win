//! Volume admission shared by dispatch, the reactor and native cache callbacks.
//!
//! Media revocation, reversible query removal and filesystem close are independent facts.
//! Only submission scopes hold the native resource; revocation never waits for lower completion.

use super::io_reliability::IoReliabilityObservation;
use core::sync::atomic::{AtomicU8, Ordering};

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
    /// Reactor-owned reliability projection retained independently from media and close.
    pub(super) reliability: IoReliabilityObservation,
    /// Monotonic media revocation.
    media: AtomicU8,
    /// One-way filesystem close admission.
    close: AtomicU8,
    /// Independent reversible create exclusion.
    query: AtomicU8,
}

impl StorageAdmission {
    /// Unpublished volume with storage and filesystem admission open.
    pub(super) const fn new(reliability: IoReliabilityObservation) -> Self {
        Self {
            reliability,
            media: AtomicU8::new(0),
            close: AtomicU8::new(0),
            query: AtomicU8::new(0),
        }
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

    /// Creates require every independent gate to admit them.
    pub(super) fn creates_admitted(&self) -> bool {
        self.media() == MediaState::Present
            && self.close() == ClosePhase::Open
            && self.query.load(Ordering::Acquire) == QueryPhase::Open.raw()
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

#[cfg(test)]
mod tests {
    use super::*;

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
        owner.publish(NativeIoPolicy::ReadOnly);
        assert!(state.reliability.policy().permits(false));
        assert!(!state.reliability.policy().permits(true));
        owner.publish(NativeIoPolicy::Unavailable);
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
