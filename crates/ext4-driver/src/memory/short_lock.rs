//! Short native critical sections for shared ownership and fixed publication facts.
use core::cell::UnsafeCell;

/// Interior state protected by a native spin lock. Callbacks must not block or allocate.
#[derive(Debug)]
pub(crate) struct ShortLock<T> {
    /// Unlocked native representation.
    #[cfg(not(test))]
    lock: UnsafeCell<wdk_sys::KSPIN_LOCK>,
    /// User-mode equivalent without a kernel import.
    #[cfg(test)]
    lock: core::sync::atomic::AtomicBool,
    /// All access occurs inside the callback critical section.
    state: UnsafeCell<T>,
}
impl<T> ShortLock<T> {
    /// Constructs unlocked address-independent storage before shared publication.
    pub(crate) const fn new(state: T) -> Self {
        Self {
            #[cfg(not(test))]
            lock: UnsafeCell::new(0),
            #[cfg(test)]
            lock: core::sync::atomic::AtomicBool::new(false),
            state: UnsafeCell::new(state),
        }
    }
    /// Lends exclusive state for one bounded, nonblocking, allocation-free callback.
    #[expect(
        unsafe_code,
        reason = "the native lock serializes every state borrow and no borrow escapes the callback"
    )]
    pub(crate) fn with<R>(&self, operation: impl FnOnce(&mut T) -> R) -> R {
        #[cfg(not(test))]
        let irql = unsafe {
            // SAFETY: Zero initializes an unlocked KSPIN_LOCK and storage remains live.
            crate::kernel::ffi::KeAcquireSpinLockRaiseToDpc(self.lock.get())
        };
        #[cfg(test)]
        while self
            .lock
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::Acquire,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            core::hint::spin_loop();
        }
        let result = operation(unsafe {
            // SAFETY: The same exclusive lock protects every access; the callback cannot retain this borrow.
            &mut *self.state.get()
        });
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Balances the acquisition above on the same thread.
            crate::kernel::ffi::KeReleaseSpinLock(self.lock.get(), irql);
        }
        #[cfg(test)]
        self.lock
            .store(false, core::sync::atomic::Ordering::Release);
        result
    }
}
#[expect(
    unsafe_code,
    reason = "moving the lock transfers exclusive ownership of Send state"
)]
// SAFETY: No reference can survive moving this object; shared publication is separately retained.
unsafe impl<T: Send> Send for ShortLock<T> {}
#[expect(
    unsafe_code,
    reason = "the short native lock serializes all access to Send state"
)]
// SAFETY: T is never accessed concurrently and mutable references cannot escape the critical section.
unsafe impl<T: Send> Sync for ShortLock<T> {}
