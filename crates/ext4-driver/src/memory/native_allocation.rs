//! Unique allocation ownership while native code retains pointers to shared state.

use alloc::boxed::Box;
use core::{fmt, marker::PhantomData, mem::ManuallyDrop, ptr::NonNull};

/// Owns one allocation whose retained pointers remain valid when this owner moves.
///
/// Construction establishes the raw allocation pointer before any context can be published.
/// Shared borrows cannot move or replace the value; native mutation must use its interior
/// mutability and synchronization contract. The publishing boundary must withdraw all native
/// access before dropping this owner, or consume it with [`Self::into_raw`] to transfer destruction
/// responsibility. Forgetting the owner retains the allocation.
pub(crate) struct NativeAllocation<T> {
    /// Original allocation pointer, also used for the sole terminal deallocation.
    allocation: NonNull<T>,
    /// Retains ownership and drop-check responsibility for every lifetime inside `T`.
    ownership: PhantomData<T>,
}

impl<T> NativeAllocation<T> {
    /// Takes the box's destruction responsibility before any native pointer is retained.
    #[expect(
        unsafe_code,
        reason = "Box::into_raw transfers one live non-null allocation without retaining Box aliasing authority"
    )]
    pub(crate) fn from_box(value: Box<T>) -> Self {
        let pointer = Box::into_raw(value);
        let allocation = unsafe {
            // SAFETY: Box::into_raw returns a non-null, aligned pointer even for zero-sized T.
            NonNull::new_unchecked(pointer)
        };
        Self {
            allocation,
            ownership: PhantomData,
        }
    }

    /// Borrows the value while this owner retains its allocation.
    #[expect(
        unsafe_code,
        reason = "the owner retains initialized storage and exposes no exclusive reborrow while native pointers exist"
    )]
    pub(crate) fn get(&self) -> &T {
        unsafe {
            // SAFETY: Construction initialized T, this owner retains it for the borrow, and shared
            // native access must obey T's interior-mutability contract.
            self.allocation.as_ref()
        }
    }

    /// Returns the allocation's original pointer for the audited native publication boundary.
    ///
    /// Observing the address does not extend storage lifetime or confer mutation authority.
    pub(crate) const fn address(&self) -> NonNull<T> {
        self.allocation
    }

    /// Transfers sole destruction responsibility without reborrowing the value.
    ///
    /// The receiver must retain the allocation through native access and finally restore one
    /// matching `Box<T>` only after all native and Rust borrows have ended.
    #[must_use = "the native owner must retain this allocation and release it exactly once"]
    pub(crate) fn into_raw(self) -> NonNull<T> {
        ManuallyDrop::new(self).allocation
    }
}

impl<T: fmt::Debug> fmt::Debug for NativeAllocation<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

impl<T> Drop for NativeAllocation<T> {
    #[expect(
        unsafe_code,
        reason = "the unique owner restores its matching Box only after native publication has ended"
    )]
    fn drop(&mut self) {
        unsafe {
            // SAFETY: This is the sole destruction owner of the exact Box::into_raw allocation.
            // Safe borrows ended before Drop; the native publisher must have withdrawn its access.
            drop(Box::from_raw(self.allocation.as_ptr()));
        }
    }
}

#[expect(
    unsafe_code,
    reason = "moving the owner transfers destruction responsibility without moving or exclusively reborrowing T"
)]
// SAFETY: The unique destruction owner may change threads when T may be moved and destroyed there.
// Retained native-pointer access has its own publication and synchronization obligations.
unsafe impl<T: Send> Send for NativeAllocation<T> {}

#[expect(
    unsafe_code,
    reason = "shared owner access exposes only shared borrows of T"
)]
// SAFETY: All safe shared access yields only &T, and Sync requires T to support concurrent sharing.
// Destruction still requires consuming the unique owner after all borrowed access ends.
unsafe impl<T: Sync> Sync for NativeAllocation<T> {}

#[cfg(test)]
mod tests {
    use super::NativeAllocation;
    use crate::{kernel::status::DriverResult, memory::boxed_try_with};
    use alloc::boxed::Box;
    use core::{
        ptr::NonNull,
        sync::atomic::{AtomicUsize, Ordering},
    };

    /// Native-visible interior state with an independently observed destruction count.
    struct CallbackState<'a> {
        /// Shared callback mutation.
        value: AtomicUsize,
        /// Test-frame observer retained through allocation destruction.
        drops: &'a AtomicUsize,
    }

    impl Drop for CallbackState<'_> {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Retains one callback context independently of the owner's location.
    struct PublishedContext<T> {
        /// Native callback address established before moving the owner.
        address: NonNull<T>,
        /// Sole allocation destruction responsibility.
        owner: NativeAllocation<T>,
    }

    /// Transfers allocation ownership across a call while preserving the published context.
    fn publish<T>(owner: NativeAllocation<T>) -> PublishedContext<T> {
        let address = owner.address();
        PublishedContext { address, owner }
    }

    /// # Errors
    /// Returns allocation failure before any context is published.
    /// # Panics
    /// Fails if retained callbacks lose their storage or ownership transfer duplicates destruction.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "the test returns fallible allocation errors while assertion failures are reported by the test harness"
    )]
    #[expect(
        unsafe_code,
        reason = "the test retains each native context through owner moves and withdraws every borrow before destruction"
    )]
    fn retained_context_survives_owner_moves_and_transfer() -> DriverResult<()> {
        let drops = AtomicUsize::new(0);
        let owner = NativeAllocation::from_box(boxed_try_with(|| {
            Ok(CallbackState {
                value: AtomicUsize::new(0),
                drops: &drops,
            })
        })?);
        let before_move = owner.address();
        let published = publish(owner);
        let shared = published.owner.get();
        unsafe {
            // SAFETY: The moved owner retains this context; mutation is confined to the atomic.
            published.address.as_ref().value.store(7, Ordering::Release);
        }
        assert_eq!(shared.value.load(Ordering::Acquire), 7);
        assert_eq!(before_move, published.address);

        let allocation = published.owner.into_raw();
        unsafe {
            // SAFETY: Ownership transfer retained storage; no exclusive borrow was introduced.
            before_move.as_ref().value.store(9, Ordering::Release);
        }
        assert_eq!(
            unsafe {
                // SAFETY: The transferred allocation remains owned and the atomic is initialized.
                allocation.as_ref().value.load(Ordering::Acquire)
            },
            9
        );
        assert_eq!(drops.load(Ordering::Acquire), 0);
        unsafe {
            // SAFETY: All callback access ended; this restores the sole matching Box owner.
            drop(Box::from_raw(allocation.as_ptr()));
        }
        assert_eq!(drops.load(Ordering::Acquire), 1);
        Ok(())
    }

    /// # Errors
    /// Returns allocation failure before any native publication.
    /// # Panics
    /// Fails if untransferred ownership fails to destroy its value exactly once.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "the test returns fallible allocation errors while assertion failures are reported by the test harness"
    )]
    fn unpublished_owner_rolls_back_once() -> DriverResult<()> {
        let drops = AtomicUsize::new(0);
        let owner = NativeAllocation::from_box(boxed_try_with(|| {
            Ok(CallbackState {
                value: AtomicUsize::new(0),
                drops: &drops,
            })
        })?);
        drop(publish(owner));
        assert_eq!(drops.load(Ordering::Acquire), 1);
        Ok(())
    }
}
