//! Stable shared allocations with fallible reference acquisition and preallocated publication.
//!
//! The allocator owns physical storage policy. This boundary owns reference lifetime only;
//! acquiring a reference grants shared access, without independent mutation or shutdown authority.

#![no_std]
#![deny(unsafe_code)]
#![feature(allocator_ext)]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::boxed::Box;
use core::{
    fmt,
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit, size_of},
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering, fence},
};

/// Failure before allocation or additional reference ownership is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The allocator could not provide storage for the shared value.
    AllocationFailed,
    /// The reference counter cannot represent another live reference.
    ReferenceLimit,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AllocationFailed => "shared allocation failed",
            Self::ReferenceLimit => "shared reference limit reached",
        })
    }
}

impl core::error::Error for Error {}

/// Storage retained until its final initialized reference or unique reservation is released.
struct SharedStorage<T> {
    /// Exact number of owning handles; no weak references or raw acquisition routes exist.
    references: AtomicUsize,
    /// Initialization authority belongs exclusively to the unique reservation.
    value: MaybeUninit<T>,
}

/// One owning reference to stable, initialized storage.
///
/// Every additional handle is acquired fallibly. Forgetting a handle retains the allocation;
/// it cannot make another handle's borrow dangle. Destruction occurs on the final holder's thread.
pub struct Shared<T> {
    /// Allocation retained by this handle, initialized before publication.
    storage: NonNull<SharedStorage<T>>,
    /// Preserves ownership and drop checking independently of the raw storage identity.
    ownership: PhantomData<SharedStorage<T>>,
}

impl<T> Shared<T> {
    /// Allocates one owning reference using the caller's global allocator.
    /// # Errors
    /// Returns [`Error::AllocationFailed`] before publishing any reference.
    pub fn try_new(value: T) -> Result<Self, Error> {
        Ok(SharedSlot::try_new()?.initialize(value))
    }

    /// Retains this value without allocating or copying it.
    /// # Errors
    /// Returns [`Error::ReferenceLimit`] without changing ownership when the counter is full.
    pub fn try_acquire(&self) -> Result<Self, Error> {
        self.storage()
            .references
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_add(1)
            })
            .map_err(|_| Error::ReferenceLimit)?;
        // The existing handle keeps storage live through the atomic increment. Publication to
        // another thread uses that caller's synchronization, independent of reference accounting.
        Ok(Self {
            storage: self.storage,
            ownership: PhantomData,
        })
    }

    /// Borrows the value for no longer than this owning reference.
    #[expect(
        unsafe_code,
        reason = "only initialized reservations construct owning handles"
    )]
    pub fn get(&self) -> &T {
        unsafe {
            // SAFETY: Construction consumes the sole initialization authority before any handle
            // can be acquired, and this handle retains storage throughout the returned borrow.
            self.storage().value.assume_init_ref()
        }
    }

    /// Retained allocation size, including reference accounting and alignment padding.
    #[must_use]
    pub const fn allocation_size() -> usize {
        size_of::<SharedStorage<T>>()
    }

    /// Borrows the header while this handle prevents its destruction.
    #[expect(
        unsafe_code,
        reason = "every owning handle retains one live storage reference"
    )]
    fn storage(&self) -> &SharedStorage<T> {
        unsafe {
            // SAFETY: The non-null allocation is initialized and cannot be released while this
            // handle, including the returned borrow, remains live.
            self.storage.as_ref()
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Shared<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

impl<T> Drop for Shared<T> {
    #[expect(
        unsafe_code,
        reason = "the final atomic release consumes the unique storage allocation"
    )]
    fn drop(&mut self) {
        if self.storage().references.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        // Pair with every preceding holder's release before destroying the shared value.
        fence(Ordering::Acquire);
        let mut allocation = unsafe {
            // SAFETY: Exactly one decrement observes one. No raw acquisition or weak reference
            // can resurrect storage, and allocation used this exact Box layout.
            Box::from_raw(self.storage.as_ptr())
        };
        unsafe {
            // SAFETY: Initialization precedes all owning handles, and this final-reference path
            // exclusively owns the initialized value and destroys it exactly once.
            allocation.value.assume_init_drop();
        }
    }
}

/// Unique storage reservation whose initialization publishes its first owning reference.
///
/// Dropping an unused reservation frees only storage. No reference or borrow to a value can
/// exist until initialization consumes this reservation.
pub struct SharedSlot<T> {
    /// Unique allocation whose value has not been initialized.
    storage: NonNull<SharedStorage<T>>,
    /// Preserves eventual value ownership and drop checking.
    ownership: PhantomData<SharedStorage<T>>,
}

impl<T> SharedSlot<T> {
    /// Reserves storage without constructing a value.
    /// # Errors
    /// Returns [`Error::AllocationFailed`] without publishing any reference.
    pub fn try_new() -> Result<Self, Error> {
        let allocation = Box::try_new(SharedStorage {
            references: AtomicUsize::new(1),
            value: MaybeUninit::uninit(),
        })
        .map_err(|_| Error::AllocationFailed)?;
        Ok(Self {
            storage: NonNull::from(Box::leak(allocation)),
            ownership: PhantomData,
        })
    }

    /// Consumes unique initialization authority without allocating.
    #[expect(
        unsafe_code,
        reason = "the consumed reservation is the sole owner of uninitialized storage"
    )]
    pub fn initialize(self, value: T) -> Shared<T> {
        let mut slot = ManuallyDrop::new(self);
        unsafe {
            // SAFETY: No handle can be acquired from a reservation. This unique write initializes
            // the value before its allocation reference transfers into the returned handle.
            slot.storage.as_mut().value.write(value);
        }
        Shared {
            storage: slot.storage,
            ownership: PhantomData,
        }
    }
}

impl<T> fmt::Debug for SharedSlot<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SharedSlot").finish_non_exhaustive()
    }
}

impl<T> Drop for SharedSlot<T> {
    #[expect(
        unsafe_code,
        reason = "an unconsumed reservation uniquely owns its uninitialized allocation"
    )]
    fn drop(&mut self) {
        unsafe {
            // SAFETY: The reservation has no initialized value or sibling references and was
            // allocated with this exact Box layout. MaybeUninit does not destroy T.
            drop(Box::from_raw(self.storage.as_ptr()));
        }
    }
}

#[expect(
    unsafe_code,
    reason = "atomic ownership permits transfer only for transferable shared values"
)]
// SAFETY: Every reference transition is atomic; access is shared and final destruction may run
// on any holder's thread, requiring both Send and Sync for T.
unsafe impl<T: Send + Sync> Send for Shared<T> {}

#[expect(
    unsafe_code,
    reason = "shared access retains storage and exposes only shared value borrows"
)]
// SAFETY: T is safe to share, and atomic reference ownership keeps its allocation live. T must
// also be Send because the final holder may destroy it on another thread.
unsafe impl<T: Send + Sync> Sync for Shared<T> {}

#[expect(
    unsafe_code,
    reason = "unique uninitialized storage transfers without exposing any value"
)]
// SAFETY: A reservation has no siblings or initialized value. Its eventual value ownership may
// move across threads only when T itself can be transferred.
unsafe impl<T: Send> Send for SharedSlot<T> {}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "tests propagate fallible setup while assertion failures belong to the test harness"
)]
mod tests {
    use super::{Error, Shared, SharedSlot};
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Counts destruction independently of shared ownership accounting.
    struct DropProbe<'a>(&'a AtomicUsize);

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// # Errors
    /// Returns an allocation or reference acquisition failure.
    /// # Panics
    /// Panics if concurrent final holders fail to retain and destroy the value exactly once.
    #[test]
    fn final_release_destroys_the_value_once() -> Result<(), Error> {
        let drops = AtomicUsize::new(0);
        let owner = Shared::try_new(DropProbe(&drops))?;
        let first = owner.try_acquire()?;
        drop(owner);
        let second = first.try_acquire()?;
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let barrier = &barrier;
            let first = scope.spawn(move || {
                barrier.wait();
                drop(first);
            });
            let second = scope.spawn(move || {
                barrier.wait();
                drop(second);
            });
            assert!(first.join().is_ok());
            assert!(second.join().is_ok());
        });
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        Ok(())
    }

    /// # Errors
    /// Returns allocation or reference acquisition failure.
    /// # Panics
    /// Panics if a consumed reservation does not preserve the initialized value.
    #[test]
    fn reservation_initializes_shared_storage() -> Result<(), Error> {
        drop(SharedSlot::<u32>::try_new()?);
        let owner = SharedSlot::try_new()?.initialize(0x5A_u32);
        let retained = owner.try_acquire()?;
        drop(owner);
        assert_eq!(*retained.get(), 0x5A);
        Ok(())
    }

    /// # Errors
    /// Returns allocation failure.
    /// # Panics
    /// Panics if reference exhaustion changes the count or loses the existing value.
    #[test]
    fn reference_exhaustion_preserves_ownership() -> Result<(), Error> {
        let owner = Shared::try_new(0xA5_u32)?;
        let references = &owner.storage().references;
        references.store(usize::MAX, Ordering::Relaxed);
        let failure = owner.try_acquire().err();
        let count = references.load(Ordering::Relaxed);
        // Restore the single real owner before any assertion can unwind.
        references.store(1, Ordering::Relaxed);
        assert_eq!(failure, Some(Error::ReferenceLimit));
        assert_eq!(count, usize::MAX);
        assert_eq!(*owner.get(), 0xA5);
        Ok(())
    }
}
