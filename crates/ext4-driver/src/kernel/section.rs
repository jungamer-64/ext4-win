//! Stream mutation ownership and callback admission. C only borrows the native resources.
//!
//! Preparation permits paging needed by Cc/MM. Sealing follows paging-resource drainage and
//! excludes further paging until the unique permit is released. Kernel section exclusion only
//! acquires its resource and remains available for Cc reentry; it grants no paging or creation
//! authority. State publication and wakeup
//! share one transition lock, so an earlier release cannot signal a successor preparation.

use super::status::{DriverError, DriverResult};
use crate::memory::{DriverShared, DriverSharedLease};
use core::sync::atomic::{AtomicU8, Ordering};
#[cfg(not(test))]
use core::{cell::UnsafeCell, marker::PhantomData, ptr::NonNull};

/// Independent native callback admission during one stream mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SectionPhase {
    /// New ordinary acquisitions and mutation preparations are admitted.
    Idle,
    /// Cc/MM paging reentry may drain while ordinary acquisition is excluded.
    Preparing,
    /// Neither ordinary acquisition nor new paging may cross the mutation boundary.
    Sealed,
}

/// Sole state authority retained by the stream and its unique mutation permit.
pub(super) struct SectionSynchronization {
    /// Acquire/release observation consumed by native cache callbacks.
    phase: AtomicU8,
    /// Serializes state publication with resetting and signaling the notification.
    #[cfg(not(test))]
    lock: UnsafeCell<wdk_sys::KSPIN_LOCK>,
    /// Address-stable kernel notification retained through every waiter.
    #[cfg(not(test))]
    released: UnsafeCell<wdk_sys::KEVENT>,
    /// Host counterpart of the transition lock.
    #[cfg(test)]
    lock: std::sync::Mutex<()>,
    /// Host waiters recheck the authoritative phase under the transition lock.
    #[cfg(test)]
    released: std::sync::Condvar,
}

impl core::fmt::Debug for SectionSynchronization {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SectionSynchronization")
            .field("phase", &self.phase())
            .finish()
    }
}

impl SectionSynchronization {
    /// Allocates before stream publication and initializes the notification at its final address.
    /// # Errors
    /// Returns nonpaged allocation failure before any native callback can observe the state.
    pub(super) fn try_new() -> DriverResult<DriverShared<Self>> {
        let owner = DriverShared::try_new(Self {
            phase: AtomicU8::new(0),
            #[cfg(not(test))]
            lock: UnsafeCell::new(0),
            #[cfg(not(test))]
            released: UnsafeCell::new(wdk_sys::KEVENT::default()),
            #[cfg(test)]
            lock: std::sync::Mutex::new(()),
            #[cfg(test)]
            released: std::sync::Condvar::new(),
        })?;
        #[cfg(not(test))]
        {
            #[expect(
                unsafe_code,
                reason = "the unpublished shared allocation has its final address before event initialization"
            )]
            unsafe {
                // SAFETY: No observer exists yet and the owner retains the event's stable storage.
                super::ffi::KeInitializeEvent(
                    owner.get().released.get(),
                    wdk_sys::_EVENT_TYPE::NotificationEvent,
                    1,
                );
            }
        }
        Ok(owner)
    }

    /// Observes admission without acquiring mutation authority.
    fn phase(&self) -> SectionPhase {
        match self.phase.load(Ordering::Acquire) {
            0 => SectionPhase::Idle,
            1 => SectionPhase::Preparing,
            _ => SectionPhase::Sealed,
        }
    }

    /// Keeps a transition and its notification publication under the same lock.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "only atomics and the retained notification are touched under the native spin lock"
        )
    )]
    fn transition<T>(&self, operation: impl FnOnce() -> T) -> T {
        #[cfg(not(test))]
        let irql = unsafe {
            // SAFETY: The shared owner retains this nonpaged, zero-initialized spin lock.
            super::ffi::KeAcquireSpinLockRaiseToDpc(self.lock.get())
        };
        #[cfg(test)]
        let _guard = self.lock.lock().unwrap_or_else(|_| {
            super::fatal::KernelWideInconsistency::file_control_block_ownership_corruption()
                .bugcheck()
        });
        let result = operation();
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This same thread holds the lock and restores its incoming IRQL.
            super::ffi::KeReleaseSpinLock(self.lock.get(), irql);
        }
        result
    }

    /// Begins only after the previous owner published Idle and signaled its notification.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "notification reset precedes preparing publication under the transition lock"
        )
    )]
    fn try_begin(&self) -> bool {
        self.transition(|| {
            if self.phase() != SectionPhase::Idle {
                return false;
            }
            #[cfg(not(test))]
            unsafe {
                // SAFETY: Transition ownership serializes reset with every release/signal.
                wdk_sys::ntddk::KeClearEvent(self.released.get());
            }
            self.phase.store(1, Ordering::Release);
            true
        })
    }

    /// Claims a unique preparation while retaining its state independently of owner movement.
    /// # Errors
    /// Returns finite shared-reference exhaustion before admission changes.
    pub(super) fn begin(owner: &DriverShared<Self>) -> DriverResult<SectionPreparation> {
        let state = owner.try_acquire()?;
        while !state.get().try_begin() {
            state.get().wait(SectionAdmission::Ordinary);
        }
        Ok(SectionPreparation {
            ownership: MutationOwnership { state },
        })
    }

    /// Releases the unique owner before waking waiters or admitting a successor.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "Idle publication precedes notification under the same transition lock"
        )
    )]
    fn release(&self) {
        self.transition(|| {
            self.phase.store(0, Ordering::Release);
            #[cfg(not(test))]
            unsafe {
                // SAFETY: This lock serializes signaling with successor admission/reset.
                super::ffi::KeSetEvent(self.released.get(), 0, 0);
            }
            #[cfg(test)]
            self.released.notify_all();
        });
    }

    /// Waits for admission; a native callback may hold no filesystem resource during this wait.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the nonalertable wait retains shared event storage through completion"
        )
    )]
    fn wait(&self, admission: SectionAdmission) {
        #[cfg(not(test))]
        while !admission.accepts(self.phase()) {
            unsafe {
                // SAFETY: The caller retains the shared state; this indefinite KernelMode wait
                // finishes before its borrowed event storage or callback owner can retire.
                let _wait_status = super::ffi::KeWaitForSingleObject(
                    self.released.get().cast(),
                    wdk_sys::_KWAIT_REASON::Executive,
                    0,
                    0,
                    core::ptr::null_mut(),
                );
            }
        }
        #[cfg(test)]
        {
            let mut guard = self.lock.lock().unwrap_or_else(|_| {
                super::fatal::KernelWideInconsistency::file_control_block_ownership_corruption()
                    .bugcheck()
            });
            while !admission.accepts(self.phase()) {
                guard = self.released.wait(guard).unwrap_or_else(|_| {
                    super::fatal::KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
                });
            }
        }
    }

    /// Native destruction may retire only a stream without active mutation authority.
    pub(super) fn idle(&self) -> bool {
        self.phase() == SectionPhase::Idle
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "shared native state is address-stable and all interior access is atomic or spin-lock synchronized"
)]
// SAFETY: Owners move without moving native storage; teardown follows all waiter/permit leases.
unsafe impl Send for SectionSynchronization {}
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the transition lock protects notification mutation and phase observations are atomic"
)]
// SAFETY: No mutable Rust reference to event/lock storage is exposed; native wait/signal supports sharing.
unsafe impl Sync for SectionSynchronization {}

/// Callback classes differ while preparation permits Cc/MM paging to drain.
#[derive(Clone, Copy)]
enum SectionAdmission {
    /// Requires the mutation owner to have released its complete publication scope.
    Ordinary,
    /// May reenter preparation until paging exclusion is sealed.
    Paging,
    /// Kernel exclusion acquires only the resource; it neither creates sections nor admits I/O.
    ResourceOnly,
}
impl SectionAdmission {
    /// Windows kernel section exclusion must remain callable during Cc preparation/publication.
    fn for_section_sync(sync_type: wdk_sys::FS_FILTER_SECTION_SYNC_TYPE) -> Self {
        if sync_type == wdk_sys::_FS_FILTER_SECTION_SYNC_TYPE::SyncTypeOther {
            Self::ResourceOnly
        } else {
            Self::Ordinary
        }
    }

    /// Tests the shared phase without owning any transition.
    fn accepts(self, phase: SectionPhase) -> bool {
        match self {
            Self::Ordinary => phase == SectionPhase::Idle,
            Self::Paging => phase != SectionPhase::Sealed,
            Self::ResourceOnly => true,
        }
    }
}

/// One unique release authority retained through preparation and committed publication.
#[derive(Debug)]
struct MutationOwnership {
    /// Retains notification storage independently until this sole release authority is consumed.
    state: DriverSharedLease<SectionSynchronization>,
}
impl Drop for MutationOwnership {
    fn drop(&mut self) {
        self.state.get().release();
    }
}

/// Paging remains admissible while native Cc/MM preparation runs.
#[derive(Debug)]
pub(super) struct SectionPreparation {
    /// Unique release authority moves across sealing without being duplicated.
    ownership: MutationOwnership,
}
impl SectionPreparation {
    /// Seals admission only while the caller has drained paging-resource owners.
    /// # Errors
    /// Returns an invariant violation if this unique preparation lost its phase.
    pub(super) fn seal(self) -> DriverResult<SealedSectionMutation> {
        let sealed = self.ownership.state.get().transition(|| {
            self.ownership
                .state
                .get()
                .phase
                .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        });
        if !sealed {
            return Err(DriverError::InternalInvariantViolation);
        }
        Ok(SealedSectionMutation {
            ownership: self.ownership,
        })
    }
}

/// Operation whose Windows section contract must be accepted before publication.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SectionMutationOperation {
    /// Exact validated final cache dimensions select truncation and purge requirements.
    Resize(super::stream::StreamSizes),
    /// Image and data sections must admit namespace removal.
    Delete,
    /// Executable image residency must admit a writable handle.
    WriteOpen,
    /// Dirty data must reach disk and all data mappings must drain before Merkle construction.
    EnableVerity,
}

/// Paging and ordinary acquisition remain excluded until this unique permit is dropped.
pub(crate) struct SealedSectionMutation {
    /// Unique release authority moves across sealing without being duplicated.
    ownership: MutationOwnership,
}
impl core::fmt::Debug for SealedSectionMutation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SealedSectionMutation")
            .field(&self.ownership)
            .finish()
    }
}

/// Native ERESOURCE borrow tied to the retaining stream or callback entry.
#[cfg(not(test))]
pub(super) struct SectionResource<'a> {
    /// Stable resource borrowed from the retaining native stream.
    resource: NonNull<wdk_sys::ERESOURCE>,
    /// Bounds same-thread native resource use by the enclosing stream borrow.
    lifetime: PhantomData<&'a super::stream::StreamContext>,
}
#[cfg(not(test))]
impl<'a> SectionResource<'a> {
    /// Establishes a native borrow before entering any synchronization protocol.
    /// # Safety
    /// `resource` must remain live through the stream borrow or the native acquire/release callback pair.
    /// # Errors
    /// Returns an invariant violation for a missing native resource.
    #[expect(
        unsafe_code,
        reason = "the owning stream or native callback retains this resource"
    )]
    pub(super) unsafe fn from_raw(resource: *mut wdk_sys::ERESOURCE) -> DriverResult<Self> {
        Ok(Self {
            resource: NonNull::new(resource).ok_or(DriverError::InternalInvariantViolation)?,
            lifetime: PhantomData,
        })
    }

    /// Acquires one same-thread APC suppression scope with the ERESOURCE.
    #[expect(
        unsafe_code,
        reason = "the native borrow retains resource storage through acquisition"
    )]
    fn acquire(&self, exclusive: bool, wait: bool) -> bool {
        unsafe {
            // SAFETY: The callback/stream owner keeps resource live on this <= APC_LEVEL thread.
            wdk_sys::ntddk::KeEnterCriticalRegion();
        }
        let acquired = if exclusive {
            unsafe {
                // SAFETY: This call owns an APC suppression scope and borrows a retained ERESOURCE.
                wdk_sys::ntddk::ExAcquireResourceExclusiveLite(
                    self.resource.as_ptr(),
                    u8::from(wait),
                )
            }
        } else {
            unsafe {
                // SAFETY: This call owns an APC suppression scope and borrows a retained ERESOURCE.
                wdk_sys::ntddk::ExAcquireResourceSharedLite(self.resource.as_ptr(), u8::from(wait))
            }
        };
        if acquired == 0 {
            unsafe {
                // SAFETY: Failed acquisition retained no resource; restore the incoming APC state.
                wdk_sys::ntddk::KeLeaveCriticalRegion();
            }
        }
        acquired != 0
    }

    /// Releases this thread's acquisition and its matching APC scope.
    #[expect(
        unsafe_code,
        reason = "the caller owns this same-thread resource/APC acquisition"
    )]
    fn release(&self) {
        unsafe {
            // SAFETY: Only successful acquisition paths can call this paired release.
            super::ffi::ExReleaseResourceAndLeaveCriticalRegion(self.resource.as_ptr());
        }
    }

    /// Retains ordinary acquisition after rechecking the phase under the acquired resource.
    pub(super) fn ordinary_shared(
        self,
        state: &SectionSynchronization,
    ) -> SectionResourceGuard<'a> {
        let resource = SectionResource {
            resource: self.resource,
            lifetime: PhantomData,
        };
        if !acquire_callback(state, resource, false, true, SectionAdmission::Ordinary).0 {
            super::fatal::KernelWideInconsistency::file_control_block_ownership_corruption()
                .bugcheck();
        }
        SectionResourceGuard {
            resource: self,
            same_thread: PhantomData,
        }
    }

    /// Retains an exclusive resource through a synchronous native preparation call.
    pub(super) fn exclusive(self) -> SectionResourceGuard<'a> {
        if !self.acquire(true, true) {
            super::fatal::KernelWideInconsistency::file_control_block_ownership_corruption()
                .bugcheck();
        }
        SectionResourceGuard {
            resource: self,
            same_thread: PhantomData,
        }
    }
}

/// Same-thread native resource ownership cannot move with a passive continuation.
#[cfg(not(test))]
pub(super) struct SectionResourceGuard<'a> {
    /// Successful native acquisition released exactly once by this guard.
    resource: SectionResource<'a>,
    /// Prevents moving an ERESOURCE/APC acquisition to another execution thread.
    same_thread: PhantomData<*mut ()>,
}
#[cfg(not(test))]
impl Drop for SectionResourceGuard<'_> {
    fn drop(&mut self) {
        self.resource.release();
    }
}

/// Acquires under the predicate and revalidates after resource acquisition before exposing success.
#[cfg(not(test))]
fn acquire_callback(
    state: &SectionSynchronization,
    resource: SectionResource<'_>,
    exclusive: bool,
    wait: bool,
    admission: SectionAdmission,
) -> (bool, bool) {
    let mut waited = false;
    loop {
        if !admission.accepts(state.phase()) {
            if !wait {
                return (false, waited);
            }
            waited = true;
            state.wait(admission);
        }
        if !resource.acquire(exclusive, wait) {
            return (false, waited);
        }
        if admission.accepts(state.phase()) {
            return (true, waited);
        }
        resource.release();
        if !wait {
            return (false, waited);
        }
        waited = true;
    }
}

/// Native callbacks only observe the Rust-owned phase.
/// # Safety
/// `state` is retained by the live stream until all native callbacks retire.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the native stream borrows only retained synchronized state"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_section_phase(state: *const SectionSynchronization) -> u8 {
    let state = unsafe {
        // SAFETY: The native stream retains this initialized state.
        &*state
    };
    match state.phase() {
        SectionPhase::Idle => 0,
        SectionPhase::Preparing => 1,
        SectionPhase::Sealed => 2,
    }
}

/// Acquires section synchronization without blocking kernel-only exclusion on mutation admission.
/// # Safety
/// The native callback retains state and resource through its paired same-thread release,
/// supplies the Windows synchronization type, and runs at <= APC_LEVEL.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native callback ownership encloses the resource/APC acquisition"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_section_acquire_sync(
    state: *const SectionSynchronization,
    resource: *mut wdk_sys::ERESOURCE,
    sync_type: wdk_sys::FS_FILTER_SECTION_SYNC_TYPE,
) -> u8 {
    let state = unsafe {
        // SAFETY: The native callback retains initialized state until paired release.
        &*state
    };
    let resource = unsafe {
        // SAFETY: The native callback retains resource through its paired same-thread release.
        SectionResource::from_raw(resource)
    }
    .unwrap_or_else(|_| {
        super::fatal::KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
    });
    u8::from(
        acquire_callback(
            state,
            resource,
            true,
            true,
            SectionAdmission::for_section_sync(sync_type),
        )
        .0,
    )
}

/// Acquires ordinary stream admission; the native release callback owns the successful resource/APC scope.
/// # Safety
/// The callback retains `state` and `resource`, runs at <= APC_LEVEL, and pairs successful release
/// on the same thread. Supplied `waited` storage is exclusive for this call.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the OS callback owns the native acquire/release lifetime and output storage"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_section_acquire_main(
    state: *const SectionSynchronization,
    resource: *mut wdk_sys::ERESOURCE,
    exclusive: u8,
    wait: u8,
    waited: *mut u8,
) -> u8 {
    let state = unsafe {
        // SAFETY: Native callback retention covers initialized state.
        &*state
    };
    let resource = unsafe {
        // SAFETY: Native callback retention covers its resource/release pair.
        SectionResource::from_raw(resource)
    }
    .unwrap_or_else(|_| {
        super::fatal::KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
    });
    let (acquired, did_wait) = acquire_callback(
        state,
        resource,
        exclusive != 0,
        wait != 0,
        SectionAdmission::Ordinary,
    );
    if !waited.is_null() {
        unsafe {
            // SAFETY: Non-null output is exclusive native local storage.
            waited.write(u8::from(did_wait));
        }
    }
    u8::from(acquired)
}

/// Acquires paging or flush admission, permitting preparation-driven Cc/MM reentry.
/// # Safety
/// Native callback retention and same-thread release obey the main-resource callback contract.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native callback ownership encloses the resource/APC acquisition"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_section_acquire_paging(
    state: *const SectionSynchronization,
    resource: *mut wdk_sys::ERESOURCE,
    exclusive: u8,
    wait: u8,
) -> u8 {
    let state = unsafe {
        // SAFETY: The native callback retains the initialized shared state.
        &*state
    };
    let resource = unsafe {
        // SAFETY: The native callback retains resource through paired release.
        SectionResource::from_raw(resource)
    }
    .unwrap_or_else(|_| {
        super::fatal::KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
    });
    u8::from(
        acquire_callback(
            state,
            resource,
            exclusive != 0,
            wait != 0,
            SectionAdmission::Paging,
        )
        .0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns allocation, channel or waiter failure.
    /// # Panics
    /// Fails if a retained paging waiter resumes before sealed authority is released.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "setup/worker failures return Result while admission is checked by assertions"
    )]
    fn releasing_a_sealed_permit_resumes_retained_waiters() -> DriverResult<()> {
        let owner = SectionSynchronization::try_new()?;
        let sealed = SectionSynchronization::begin(&owner)?.seal()?;
        let waiter = owner.try_acquire()?;
        let (started, received) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                started.send(())?;
                waiter.get().wait(SectionAdmission::Paging);
                Ok::<_, std::sync::mpsc::SendError<()>>(waiter.get().phase())
            });
            received
                .recv()
                .map_err(|_| DriverError::InternalInvariantViolation)?;
            assert!(!owner.get().idle());
            drop(sealed);
            let phase = worker
                .join()
                .map_err(|_| DriverError::InternalInvariantViolation)?
                .map_err(|_| DriverError::InternalInvariantViolation)?;
            assert_eq!(phase, SectionPhase::Idle);
            Ok::<_, DriverError>(())
        })
    }

    /// # Errors
    /// Returns allocation or finite lease failure before acquiring mutation authority.
    /// # Panics
    /// Fails if paging cannot drain preparation or a sealed permit permits new paging.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "setup failures return Result while assertions verify admission transitions"
    )]
    fn mutation_permit_controls_callback_admission_and_release() -> DriverResult<()> {
        let owner = SectionSynchronization::try_new()?;
        let preparation = SectionSynchronization::begin(&owner)?;
        assert!(SectionAdmission::Paging.accepts(owner.get().phase()));
        assert!(!SectionAdmission::Ordinary.accepts(owner.get().phase()));
        let sealed = preparation.seal()?;
        assert!(!SectionAdmission::Paging.accepts(owner.get().phase()));
        drop(sealed);
        assert!(owner.get().idle());
        let failed_preparation = SectionSynchronization::begin(&owner)?;
        drop(failed_preparation);
        assert!(owner.get().idle());
        Ok(())
    }

    /// # Panics
    /// Fails if Cc's resource-only section exclusion waits on its own mutation admission.
    #[test]
    fn kernel_section_exclusion_remains_available_during_cc_reentry() {
        let exclusion = SectionAdmission::for_section_sync(
            wdk_sys::_FS_FILTER_SECTION_SYNC_TYPE::SyncTypeOther,
        );
        assert!(exclusion.accepts(SectionPhase::Preparing));
        assert!(exclusion.accepts(SectionPhase::Sealed));
        let creation = SectionAdmission::for_section_sync(
            wdk_sys::_FS_FILTER_SECTION_SYNC_TYPE::SyncTypeCreateSection,
        );
        assert!(!creation.accepts(SectionPhase::Preparing));
        assert!(!creation.accepts(SectionPhase::Sealed));
    }
}
