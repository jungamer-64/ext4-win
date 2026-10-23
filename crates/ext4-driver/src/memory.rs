//! Fallible allocation helpers for the Windows driver boundary.

use alloc::{
    alloc::{AllocError, Allocator, Global},
    boxed::Box,
    collections::{TryReserveError, TryReserveErrorKind},
    vec::Vec,
};
use core::{
    alloc::Layout,
    fmt,
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering, fence},
};

use crate::kernel::fatal::KernelWideInconsistency;
use crate::kernel::status::{DriverError, DriverResult};
use zeroize::Zeroize;

mod native_allocation;
mod short_lock;
pub(crate) use native_allocation::NativeAllocation;
pub(crate) use short_lock::ShortLock;

/// Converts allocator failure into the driver error domain.
#[inline]
fn alloc_failed(_: AllocError) -> DriverError {
    DriverError::InsufficientResources
}

/// Converts vector reservation failure into the driver error domain.
///
/// `CapacityOverflow` means the requested logical capacity is invalid for the collection, not that
/// kernel memory is exhausted.
#[inline]
fn reserve_failed(error: TryReserveError) -> DriverError {
    match error.kind() {
        TryReserveErrorKind::CapacityOverflow => DriverError::InvalidBufferSize,
        TryReserveErrorKind::AllocError { .. } => DriverError::InsufficientResources,
    }
}

/// Copies exactly equal slices without invoking a bounds-panicking copy intrinsic.
/// # Errors
///
/// Returns an invariant error when source and destination lengths differ.
pub(crate) fn copy_exact<T: Copy>(destination: &mut [T], source: &[T]) -> DriverResult<()> {
    if destination.len() != source.len() {
        return Err(DriverError::InternalInvariantViolation);
    }
    for (target, source) in destination.iter_mut().zip(source.iter().copied()) {
        *target = source;
    }
    Ok(())
}

/// Rollback owner for a value constructed in caller-provided address-stable storage.
///
/// Until [`Self::publish`] consumes this guard, dropping it destroys the initialized value in
/// place. This keeps fallible native initialization from leaking Rust-owned fields after the value
/// has moved out of ordinary stack ownership.
#[must_use]
pub(crate) struct InPlaceInitialization<T> {
    /// Initialized destination uniquely owned until publication.
    destination: NonNull<T>,
    /// Destruction responsibility retains the exact `T`, including every reference lifetime.
    invariant: PhantomData<core::cell::Cell<T>>,
    /// True while guard drop must roll the value back.
    rollback: bool,
}

impl<T> InPlaceInitialization<T> {
    /// Takes rollback ownership after field-by-field initialization at the final address.
    /// # Safety
    ///
    /// Every field at `destination` must be initialized as a valid `T`. The storage must remain
    /// writable, address-stable and uniquely owned until publication or guard drop. The caller
    /// transfers sole destruction responsibility; this guard does not allocate or move `T`.
    #[expect(
        unsafe_code,
        reason = "the constructor accepts the caller's proof of complete final-address initialization"
    )]
    pub(crate) unsafe fn assume_init(destination: NonNull<T>) -> Self {
        Self {
            destination,
            invariant: PhantomData,
            rollback: true,
        }
    }

    /// Transfers drop responsibility to the owner of the final-address storage.
    pub(crate) fn publish(mut self) {
        self.rollback = false;
    }
}

impl<T> Drop for InPlaceInitialization<T> {
    #[expect(
        unsafe_code,
        reason = "an armed initialization guard uniquely owns and rolls back its in-place value"
    )]
    fn drop(&mut self) {
        if self.rollback {
            unsafe {
                // SAFETY: The armed guard uniquely owns this initialized value until drop.
                self.destination.as_ptr().drop_in_place();
            }
        }
    }
}

/// Error returned by owned push operations.
///
/// This preserves ownership of the value on failure. The helper itself does not drop the value on
/// allocation failure. The caller must either recover it or intentionally drop the returned
/// [`PushError`].
#[must_use]
pub(crate) enum PushError<T> {
    /// The capacity reservation failed. The value was not inserted.
    Reserve {
        /// Driver-domain reservation error.
        error: DriverError,
        /// Original value that was not inserted.
        value: T,
    },

    /// `push_within_capacity` failed after successful reservation.
    ///
    /// This is only reachable if this module's local capacity invariant is broken or the standard
    /// library contract changes.
    CapacityInvariant {
        /// Original value that was not inserted.
        value: T,
    },
}

impl<T> PushError<T> {
    /// Splits the push error into the driver error and original value.
    pub(crate) fn into_parts(self) -> (DriverError, T) {
        match self {
            Self::Reserve { error, value } => (error, value),
            Self::CapacityInvariant { value } => (DriverError::InternalInvariantViolation, value),
        }
    }
}

/// Failed box allocation that preserves the source value before construction begins.
#[must_use]
pub(crate) struct BoxMapError<S> {
    /// Driver-domain allocation error.
    error: DriverError,
    /// Source value that was never moved into the destination object.
    source: S,
}

impl<S> BoxMapError<S> {
    /// Splits the allocation failure into its error and still-owned source value.
    pub(crate) fn into_parts(self) -> (DriverError, S) {
        (self.error, self.source)
    }
}

/// Kernel-bound vector wrapper.
///
/// This intentionally does not implement `Deref<Target = [T]>` and does not expose `into_inner`.
/// Production paths should not fall back to raw `Vec::push`, `Vec::resize`, `Vec::extend`, or the
/// vector macro after crossing this boundary.
#[repr(transparent)]
pub(crate) struct KernelVec<T, A: Allocator = Global> {
    /// Owned vector guarded by this module's fallible growth API.
    inner: Vec<T, A>,
}

/// Driver vector using the crate-global allocator.
///
/// In driver builds, `Global` is backed by `wdk_alloc::WdkAllocator`, which allocates from
/// `POOL_FLAG_NON_PAGED`.
pub(crate) type DriverVec<T> = KernelVec<T, Global>;

/// Fixed-length captured secret storage erased before its allocation is released.
///
/// Only immutable borrows escape: the buffer cannot grow, shrink, or transfer its backing
/// allocation, so no discarded allocation or truncated prefix can retain a secret copy.
pub(crate) struct SensitiveBytes<A: Allocator = Global> {
    /// Initialized bytes owned until erasure and allocator release.
    bytes: KernelVec<u8, A>,
}

impl SensitiveBytes<Global> {
    /// Captures secret bytes with the driver's nonpaged global allocator.
    /// # Errors
    /// Returns invalid capacity or allocation failure without copying input bytes.
    pub(crate) fn try_copied_from_slice(source: &[u8]) -> DriverResult<Self> {
        Self::try_copied_from_slice_in(source, Global)
    }
}

impl<A: Allocator> SensitiveBytes<A> {
    /// Captures bytes under the supplied allocator's lifetime and release contract.
    /// # Errors
    /// Returns reservation or filling failure; any copied prefix is erased before release.
    pub(crate) fn try_copied_from_slice_in(source: &[u8], allocator: A) -> DriverResult<Self> {
        let mut output = Self {
            bytes: KernelVec::try_with_capacity_in(source.len(), allocator)?,
        };
        output.bytes.try_extend_from_copy_slice(source)?;
        Ok(output)
    }

    /// Borrows the captured bytes without changing allocation or erasure ownership.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl<A: Allocator> Drop for SensitiveBytes<A> {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}

impl<A: Allocator> fmt::Debug for SensitiveBytes<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveBytes")
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// One stable nonpaged allocation shared by explicit owner and lease types.
///
/// The standard `Arc` overflow path lowers to `llvm.trap`, which is not an admissible failure sink
/// in the production kernel image. This representation keeps allocation failure and reference
/// exhaustion recoverable while preserving ownership if a lease is deliberately forgotten.
struct DriverSharedInner<T> {
    /// Number of live owners and leases.
    references: AtomicUsize,
    /// Initialized exactly once before a [`DriverShared`] becomes observable.
    value: MaybeUninit<T>,
}

/// Stable shared owner for driver state that must outlive independently retained leases.
///
/// This type intentionally does not implement `Clone`. Every additional authority is acquired
/// fallibly as a [`DriverSharedLease`], so the finite reference budget remains explicit.
pub(crate) struct DriverShared<T> {
    /// Owned shared allocation.
    inner: NonNull<DriverSharedInner<T>>,
    /// Records ownership and drop-check responsibility for `T`.
    ownership: PhantomData<DriverSharedInner<T>>,
}

impl<T> DriverShared<T> {
    /// Allocates and initializes one stable shared owner.
    /// # Errors
    ///
    /// Returns insufficient resources when the nonpaged allocation cannot be created.
    pub(crate) fn try_new(value: T) -> DriverResult<Self> {
        Ok(DriverSharedSlot::try_new()?.initialize(value))
    }

    /// Acquires one independently owned lease.
    /// # Errors
    ///
    /// Returns insufficient resources when the finite reference count is exhausted.
    pub(crate) fn try_acquire(&self) -> DriverResult<DriverSharedLease<T>> {
        acquire_shared(self.inner)
    }

    /// Borrows the initialized shared value.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn get(&self) -> &T {
        let inner = unsafe {
            // SAFETY: This owner holds one reference, so the allocation remains live for the
            // returned borrow.
            self.inner.as_ref()
        };
        unsafe {
            // SAFETY: `DriverShared` can only be constructed by initializing its unique slot.
            inner.value.assume_init_ref()
        }
    }
}

impl<T> fmt::Debug for DriverShared<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

impl<T> Drop for DriverShared<T> {
    fn drop(&mut self) {
        release_shared(self.inner);
    }
}

/// One independently retained reference to a [`DriverShared`] value.
pub(crate) struct DriverSharedLease<T> {
    /// Shared allocation retained by this lease.
    inner: NonNull<DriverSharedInner<T>>,
    /// Records ownership and drop-check responsibility for `T`.
    ownership: PhantomData<DriverSharedInner<T>>,
}

impl<T> DriverSharedLease<T> {
    /// Retains another lease without changing the finite reference budget contract.
    /// # Errors
    /// Returns insufficient resources when the reference count is exhausted.
    pub(crate) fn try_acquire(&self) -> DriverResult<Self> {
        acquire_shared(self.inner)
    }
    /// Borrows the initialized value retained by this lease.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn get(&self) -> &T {
        let inner = unsafe {
            // SAFETY: This lease owns one reference, so the allocation remains live for the
            // returned borrow.
            self.inner.as_ref()
        };
        unsafe {
            // SAFETY: Every lease originates from an initialized `DriverShared` owner.
            inner.value.assume_init_ref()
        }
    }
}

/// Increments a live owner's finite reference count before publishing another lease.
/// # Errors
/// Returns insufficient resources before changing ownership when the counter is exhausted.
#[expect(
    unsafe_code,
    reason = "the private caller retains an owner or lease through this increment"
)]
fn acquire_shared<T>(inner: NonNull<DriverSharedInner<T>>) -> DriverResult<DriverSharedLease<T>> {
    let references = unsafe {
        // SAFETY: Both callers retain this allocation through their existing reference.
        &inner.as_ref().references
    };
    match references.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        if current == 0 {
            None
        } else {
            current.checked_add(1)
        }
    }) {
        Ok(_) => Ok(DriverSharedLease {
            inner,
            ownership: PhantomData,
        }),
        Err(0) => KernelWideInconsistency::shared_ownership_corruption().bugcheck(),
        Err(_) => Err(DriverError::InsufficientResources),
    }
}

impl<T> fmt::Debug for DriverSharedLease<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

impl<T> Drop for DriverSharedLease<T> {
    fn drop(&mut self) {
        release_shared(self.inner);
    }
}

/// Unique uninitialized allocation reserved for an infallible later publication.
pub(crate) struct DriverSharedSlot<T> {
    /// Unique allocation; no lease can exist before initialization consumes this type.
    inner: NonNull<DriverSharedInner<T>>,
    /// Records ownership and drop-check responsibility for `T`.
    ownership: PhantomData<DriverSharedInner<T>>,
}

impl<T> DriverSharedSlot<T> {
    /// Reserves one stable allocation without constructing `T`.
    /// # Errors
    ///
    /// Returns insufficient resources when the nonpaged allocation cannot be created.
    pub(crate) fn try_new() -> DriverResult<Self> {
        let allocation = boxed_try_with(|| {
            Ok(DriverSharedInner {
                references: AtomicUsize::new(1),
                value: MaybeUninit::uninit(),
            })
        })?;
        Ok(Self {
            inner: NonNull::from(Box::leak(allocation)),
            ownership: PhantomData,
        })
    }

    /// Initializes the unique reservation and converts it into shared ownership.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn initialize(self, value: T) -> DriverShared<T> {
        let mut slot = ManuallyDrop::new(self);
        unsafe {
            // SAFETY: `DriverSharedSlot` is unique and exposes no acquisition operation. This is
            // the sole initialization, and `ManuallyDrop` transfers its allocation reference to
            // the returned initialized owner.
            slot.inner.as_mut().value.write(value);
        }
        DriverShared {
            inner: slot.inner,
            ownership: PhantomData,
        }
    }
}

impl<T> Drop for DriverSharedSlot<T> {
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn drop(&mut self) {
        unsafe {
            // SAFETY: An unconsumed slot is uniquely owned, contains no initialized `T`, and was
            // allocated as this exact box type.
            drop(Box::from_raw(self.inner.as_ptr()));
        }
    }
}

/// Releases one initialized shared reference and destroys the allocation after the final release.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn release_shared<T>(inner: NonNull<DriverSharedInner<T>>) {
    let references = unsafe {
        // SAFETY: The caller owns one reference, so the allocation is live for this decrement.
        &inner.as_ref().references
    };
    let previous = match references.try_update(Ordering::Release, Ordering::Relaxed, |current| {
        current.checked_sub(1)
    }) {
        Ok(previous) => previous,
        Err(_) => KernelWideInconsistency::shared_ownership_corruption().bugcheck(),
    };
    if previous != 1 {
        return;
    }

    fence(Ordering::Acquire);
    let mut allocation = unsafe {
        // SAFETY: The transition from one reference to zero gives this path exclusive ownership,
        // and this allocation originated from the matching box type.
        Box::from_raw(inner.as_ptr())
    };
    unsafe {
        // SAFETY: Every initialized owner originated from `DriverSharedSlot::initialize`, so `T`
        // is live and this final-reference path must drop it exactly once.
        allocation.value.assume_init_drop();
    }
    drop(allocation);
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Ownership of `T` can move across threads only when `T` is both transferable and safe to
// share. All reference-count transitions are atomic and the value is immutable after publication.
unsafe impl<T: Send + Sync> Send for DriverShared<T> {}
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Shared access exposes only `&T`, requiring `T: Sync`; final destruction may occur on any
// holder's thread, requiring `T: Send`.
unsafe impl<T: Send + Sync> Sync for DriverShared<T> {}
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: A lease has the same transfer and shared-access contract as its owner.
unsafe impl<T: Send + Sync> Send for DriverSharedLease<T> {}
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: A lease has the same transfer and shared-access contract as its owner.
unsafe impl<T: Send + Sync> Sync for DriverSharedLease<T> {}
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The uninitialized slot is uniquely owned and may move when its eventual `T` may move.
unsafe impl<T: Send> Send for DriverSharedSlot<T> {}

impl<T, A> fmt::Debug for KernelVec<T, A>
where
    T: fmt::Debug,
    A: Allocator,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(formatter)
    }
}

impl<T, A> PartialEq for KernelVec<T, A>
where
    T: PartialEq,
    A: Allocator,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T, A> Eq for KernelVec<T, A>
where
    T: Eq,
    A: Allocator,
{
}

impl<T> KernelVec<T, Global> {
    /// Creates an empty vector using the global allocator.
    pub(crate) const fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Creates an empty vector with fallibly reserved exact capacity.
    /// # Errors
    ///
    /// Returns an error when the requested capacity overflows `Vec` limits or allocation fails.
    pub(crate) fn try_with_capacity(capacity: usize) -> DriverResult<Self> {
        Self::try_with_capacity_in(capacity, Global)
    }

    /// Copies a slice into a newly allocated vector.
    /// # Errors
    ///
    /// Returns an error when reserving or filling the destination vector fails.
    pub(crate) fn try_copied_from_slice(source: &[T]) -> DriverResult<Self>
    where
        T: Copy,
    {
        Self::try_copied_from_slice_in(source, Global)
    }

    /// Builds a vector filled with `len` bitwise copies of `value`.
    /// # Errors
    ///
    /// Returns an error when reserving or filling the destination vector fails.
    pub(crate) fn try_repeated_copy(value: T, len: usize) -> DriverResult<Self>
    where
        T: Copy,
    {
        Self::try_repeated_copy_in(value, len, Global)
    }
}

/// Builds one fully initialized standard vector for an external ownership boundary.
///
/// Most driver code uses [`KernelVec`] so later growth cannot allocate accidentally. Core storage
/// requests own `alloc::vec::Vec`, so this boundary performs the only fallible construction before
/// transferring the completed allocation.
/// # Errors
///
/// Returns an error when the requested length overflows vector limits or allocation fails.
pub(crate) fn try_repeated_vec<T: Copy>(value: T, len: usize) -> DriverResult<Vec<T>> {
    let mut output = Vec::new();
    output.try_reserve_exact(len).map_err(reserve_failed)?;
    while output.len() < len {
        output
            .push_within_capacity(value)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
    }
    Ok(output)
}

impl<T, A: Allocator> IntoIterator for KernelVec<T, A> {
    type Item = T;
    type IntoIter = alloc::vec::IntoIter<T, A>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<T> Default for KernelVec<T, Global> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, A> KernelVec<T, A>
where
    A: Allocator,
{
    /// Creates an empty vector with fallibly reserved exact capacity.
    /// # Errors
    ///
    /// Returns an error when the requested capacity overflows `Vec` limits or allocation fails.
    pub(crate) fn try_with_capacity_in(capacity: usize, allocator: A) -> DriverResult<Self> {
        let mut inner = Vec::new_in(allocator);
        inner.try_reserve_exact(capacity).map_err(reserve_failed)?;
        Ok(Self { inner })
    }

    /// Returns the current logical length.
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns whether the vector is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the contents as a slice.
    pub(crate) fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    /// Iterates over the vector contents without exposing growth operations.
    pub(crate) fn iter(&self) -> core::slice::Iter<'_, T> {
        self.inner.iter()
    }

    /// Returns the contents as a mutable slice.
    ///
    /// This does not expose allocation-changing vector operations.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        self.inner.as_mut_slice()
    }

    /// Fallibly reserves exact additional capacity.
    /// # Errors
    ///
    /// Returns an error when the requested additional capacity overflows `Vec` limits or allocation
    /// fails.
    pub(crate) fn try_reserve_exact(&mut self, additional: usize) -> DriverResult<()> {
        self.inner
            .try_reserve_exact(additional)
            .map_err(reserve_failed)
    }

    /// Pushes an owned value while preserving ownership on failure.
    ///
    /// Use this for non-`Copy` values. The caller must decide what to do with the original value if
    /// allocation fails.
    /// # Errors
    ///
    /// Returns [`PushError`] with the original value when reservation fails or the reserved-capacity
    /// invariant is violated.
    pub(crate) fn try_push_owned(&mut self, value: T) -> Result<(), PushError<T>> {
        if let Err(error) = self.inner.try_reserve_exact(1) {
            return Err(PushError::Reserve {
                error: reserve_failed(error),
                value,
            });
        }

        match self.inner.push_within_capacity(value) {
            Ok(_) => Ok(()),
            Err(value) => Err(PushError::CapacityInvariant { value }),
        }
    }

    /// Inserts an owned value after capacity has already been reserved.
    ///
    /// This function never attempts allocation. The original value is returned if the caller's
    /// reserved-capacity invariant is violated.
    /// # Errors
    ///
    /// Returns [`PushError::CapacityInvariant`] with the original value when no spare capacity
    /// remains.
    pub(crate) fn push_reserved_owned(&mut self, value: T) -> Result<(), PushError<T>> {
        match self.inner.push_within_capacity(value) {
            Ok(_) => Ok(()),
            Err(value) => Err(PushError::CapacityInvariant { value }),
        }
    }

    /// Pushes one `Copy` value and returns only the driver error.
    ///
    /// This is intentionally restricted to `Copy`. On error, discarding the value cannot run a
    /// destructor.
    /// # Errors
    ///
    /// Returns an error when reservation fails or the reserved-capacity invariant is violated.
    pub(crate) fn try_push(&mut self, value: T) -> DriverResult<()>
    where
        T: Copy,
    {
        self.try_push_owned(value).map_err(|error| {
            let (driver_error, _) = error.into_parts();
            driver_error
        })
    }

    /// Extends from a copyable slice after fallibly reserving the exact additional length.
    ///
    /// This does not call `Clone`. Elements are copied by value from the slice.
    /// # Errors
    ///
    /// Returns an error when reservation fails or the reserved-capacity invariant is violated.
    pub(crate) fn try_extend_from_copy_slice(&mut self, source: &[T]) -> DriverResult<()>
    where
        T: Copy,
    {
        self.try_reserve_exact(source.len())?;

        for &item in source {
            self.push_reserved_copy(item)?;
        }

        Ok(())
    }

    /// Resizes a `Copy` vector.
    ///
    /// Growing is fallible. Shrinking cannot allocate and cannot run destructors because `Copy`
    /// types cannot implement `Drop`.
    /// # Errors
    ///
    /// Returns an error when growth reservation fails or the reserved-capacity invariant is
    /// violated.
    pub(crate) fn try_resize_copy(&mut self, new_len: usize, value: T) -> DriverResult<()>
    where
        T: Copy,
    {
        let old_len = self.inner.len();

        if new_len <= old_len {
            self.inner.truncate(new_len);
            return Ok(());
        }

        let additional = new_len.saturating_sub(old_len);
        self.try_reserve_exact(additional)?;

        while self.inner.len() < new_len {
            self.push_reserved_copy(value)?;
        }

        Ok(())
    }

    /// Removes the last element without panicking.
    pub(crate) fn pop(&mut self) -> Option<T> {
        self.inner.pop()
    }

    /// Removes one element by swapping in the last element.
    ///
    /// Returns `None` instead of panicking when `index` is outside the current length.
    pub(crate) fn swap_remove(&mut self, index: usize) -> Option<T> {
        let last_index = self.inner.len().checked_sub(1)?;
        if index > last_index {
            return None;
        }
        let last = self.inner.pop()?;
        if index == last_index {
            return Some(last);
        }
        let slot = self.inner.get_mut(index)?;
        Some(core::mem::replace(slot, last))
    }

    /// Copies a slice into a newly allocated vector using the provided allocator.
    /// # Errors
    ///
    /// Returns an error when reserving or filling the destination vector fails.
    pub(crate) fn try_copied_from_slice_in(source: &[T], allocator: A) -> DriverResult<Self>
    where
        T: Copy,
    {
        let mut output = Self::try_with_capacity_in(source.len(), allocator)?;
        output.try_extend_from_copy_slice(source)?;
        Ok(output)
    }

    /// Builds a vector filled with `len` bitwise copies of `value`.
    /// # Errors
    ///
    /// Returns an error when reserving or filling the destination vector fails.
    pub(crate) fn try_repeated_copy_in(value: T, len: usize, allocator: A) -> DriverResult<Self>
    where
        T: Copy,
    {
        let mut output = Self::try_with_capacity_in(len, allocator)?;
        output.try_resize_copy(len, value)?;
        Ok(output)
    }

    /// Inserts after capacity has already been reserved.
    ///
    /// This function never attempts allocation. `push_within_capacity` appends only when spare
    /// capacity exists and otherwise returns the original value instead of reallocating.
    /// # Errors
    ///
    /// Returns an error if the reserved-capacity invariant is violated.
    fn push_reserved_copy(&mut self, value: T) -> DriverResult<()>
    where
        T: Copy,
    {
        match self.inner.push_within_capacity(value) {
            Ok(_) => Ok(()),
            Err(_) => Err(DriverError::InternalInvariantViolation),
        }
    }
}

/// Allocates one boxed value after the heap slot has already been reserved.
///
/// `build` is still arbitrary code. This function converts allocation failure and explicit builder
/// failure into [`DriverError`]; it does not make `build` panic-free.
/// # Errors
///
/// Returns an error when box allocation fails or `build` returns an error.
pub(crate) fn boxed_try_with_in<T, A, F>(allocator: A, build: F) -> DriverResult<Box<T, A>>
where
    A: Allocator,
    F: FnOnce() -> DriverResult<T>,
{
    let slot = Box::<T, A>::try_new_uninit_in(allocator).map_err(alloc_failed)?;
    let value = build()?;
    Ok(Box::write(slot, value))
}

/// Global-allocator version of [`boxed_try_with_in`].
/// # Errors
///
/// Returns an error when box allocation fails or `build` returns an error.
pub(crate) fn boxed_try_with<T, F>(build: F) -> DriverResult<Box<T>>
where
    F: FnOnce() -> DriverResult<T>,
{
    boxed_try_with_in(Global, build)
}

/// Allocates a destination slot before moving an ownership-bearing source into it.
///
/// This is used when dropping `source` on allocation failure would violate a terminal ownership
/// obligation, such as completing a pending IRP. The mapping closure cannot run until allocation
/// has succeeded.
/// # Errors
///
/// Returns the allocation error together with the untouched source value when the destination slot
/// cannot be allocated.
pub(crate) fn boxed_try_map<S, T>(
    source: S,
    map: impl FnOnce(S) -> T,
) -> Result<Box<T>, BoxMapError<S>> {
    let slot = match Box::<T, Global>::try_new_uninit_in(Global) {
        Ok(slot) => slot,
        Err(error) => {
            return Err(BoxMapError {
                error: alloc_failed(error),
                source,
            });
        }
    };
    Ok(Box::write(slot, map(source)))
}

/// Allocates an exact-length, zero-initialized byte slice with the global allocator.
/// # Errors
///
/// Returns [`DriverError::InvalidBufferSize`] when `length` cannot form a byte-slice layout, or
/// [`DriverError::InsufficientResources`] when the allocation fails.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
pub(crate) fn boxed_zeroed_bytes(length: usize) -> DriverResult<Box<[u8]>> {
    if Layout::array::<u8>(length).is_err() {
        return Err(DriverError::InvalidBufferSize);
    }

    let bytes =
        Box::<[u8], Global>::try_new_zeroed_slice_in(length, Global).map_err(alloc_failed)?;
    let bytes = unsafe {
        // SAFETY: The allocator initialized every byte to zero, and every possible
        // `u8` bit pattern represents a valid initialized value.
        bytes.assume_init()
    };
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use alloc::alloc::{AllocError, Allocator, Global};
    use core::alloc::Layout;
    use core::cell::Cell;
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{DriverShared, DriverSharedSlot, InPlaceInitialization, SensitiveBytes};
    use crate::kernel::status::{DriverError, DriverResult};

    /// Observes captured bytes while their allocation is still live at release.
    struct ErasureAllocator<'a> {
        /// Whether the allocator should deny acquisition.
        fail: bool,
        /// Number of allocations released by the owning buffer.
        releases: &'a Cell<usize>,
        /// Whether every initialized byte was cleared before release.
        erased: &'a Cell<bool>,
    }

    #[expect(
        unsafe_code,
        reason = "the observer delegates allocation to Global and inspects live initialized bytes before matching deallocation"
    )]
    // SAFETY: Allocations and matching layouts retain Global's ownership contract. The
    // observer reads initialized storage before forwarding each unique release to Global.
    unsafe impl Allocator for ErasureAllocator<'_> {
        fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
            if self.fail {
                return Err(AllocError);
            }
            Global.allocate_zeroed(layout)
        }

        unsafe fn deallocate(&self, pointer: NonNull<u8>, layout: Layout) {
            let bytes = unsafe {
                // SAFETY: This allocator initialized the entire allocation, and capture
                // writes initialized bytes into it. The original Global allocation remains
                // live for its full layout until the matching release below.
                core::slice::from_raw_parts(pointer.as_ptr(), layout.size())
            };
            self.erased.set(bytes.iter().all(|byte| *byte == 0));
            self.releases.set(self.releases.get().saturating_add(1));
            unsafe {
                // SAFETY: The caller transfers this live Global allocation and its original
                // layout for one release; observation above did not change ownership.
                Global.deallocate(pointer, layout);
            }
        }
    }

    /// Consumes captured bytes through a fallible operation before ownership is released.
    /// # Errors
    /// Returns allocator denial or the supplied consumer failure.
    /// # Panics
    /// Fails if capture changes the input bytes.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "the test consumer asserts copy fidelity while returning an injected failure to exercise early erasure"
    )]
    fn consume_sensitive(
        source: &[u8],
        allocator: ErasureAllocator<'_>,
        outcome: DriverResult<()>,
    ) -> DriverResult<()> {
        let input = SensitiveBytes::try_copied_from_slice_in(source, allocator)?;
        assert_eq!(input.as_slice(), source);
        outcome?;
        Ok(())
    }

    /// # Panics
    /// Fails if success or an early error releases an allocation containing secret bytes.
    #[test]
    fn sensitive_capture_erases_before_release_on_success_and_error() {
        for outcome in [Ok(()), Err(DriverError::InvalidParameter)] {
            let releases = Cell::new(0);
            let erased = Cell::new(false);
            let result = consume_sensitive(
                &[0xA5; 32],
                ErasureAllocator {
                    fail: false,
                    releases: &releases,
                    erased: &erased,
                },
                outcome,
            );
            assert_eq!(result, outcome);
            assert_eq!(releases.get(), 1);
            assert!(erased.get());
        }
    }

    /// # Panics
    /// Fails if allocation denial changes failure classification or releases unowned storage.
    #[test]
    fn sensitive_capture_preserves_allocation_failure() {
        let releases = Cell::new(0);
        let erased = Cell::new(false);
        let result = consume_sensitive(
            &[0xA5; 32],
            ErasureAllocator {
                fail: true,
                releases: &releases,
                erased: &erased,
            },
            Ok(()),
        );
        assert_eq!(result, Err(DriverError::InsufficientResources));
        assert_eq!(releases.get(), 0);
    }

    /// Records exactly when the final shared reference destroys its value.
    struct DropProbe<'a> {
        /// Destructor observation owned by the test frame.
        drops: &'a AtomicUsize,
    }

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// # Panics
    ///
    /// Panics if fallible in-place initialization leaks on rollback or remains guard-owned after
    /// explicit publication.
    #[test]
    #[expect(
        unsafe_code,
        reason = "the test supplies live aligned MaybeUninit storage and drops published values once"
    )]
    fn in_place_initialization_rolls_back_until_publication() {
        let drops = AtomicUsize::new(0);
        let mut rollback_storage = core::mem::MaybeUninit::<DropProbe<'_>>::uninit();
        {
            let destination =
                core::ptr::NonNull::from(rollback_storage.write(DropProbe { drops: &drops }));
            let _guard = unsafe {
                // SAFETY: The initialized slot remains exclusively owned until guard drop.
                InPlaceInitialization::assume_init(destination)
            };
        }
        assert_eq!(drops.load(Ordering::Acquire), 1);

        let mut published_storage = core::mem::MaybeUninit::<DropProbe<'_>>::uninit();
        let destination =
            core::ptr::NonNull::from(published_storage.write(DropProbe { drops: &drops }));
        let guard = unsafe {
            // SAFETY: The initialized second slot is uniquely retained through publication.
            InPlaceInitialization::assume_init(destination)
        };
        let published = published_storage.as_mut_ptr();
        guard.publish();
        assert_eq!(drops.load(Ordering::Acquire), 1);
        unsafe {
            // SAFETY: Publication transferred the one initialized value to this test owner.
            published.drop_in_place();
        }
        assert_eq!(drops.load(Ordering::Acquire), 2);
    }

    /// # Panics
    ///
    /// Panics if dropping the primary owner invalidates retained leases or destroys the value more
    /// than once.
    #[test]
    fn shared_leases_retain_the_value_until_the_final_release() {
        let drops = AtomicUsize::new(0);
        let Ok(owner) = DriverShared::try_new(DropProbe { drops: &drops }) else {
            return;
        };
        let Ok(first) = owner.try_acquire() else {
            return;
        };
        drop(owner);
        let Ok(second) = first.try_acquire() else {
            return;
        };
        assert_eq!(drops.load(Ordering::Acquire), 0);
        drop(first);
        assert_eq!(drops.load(Ordering::Acquire), 0);
        drop(second);
        assert_eq!(drops.load(Ordering::Acquire), 1);
    }

    /// # Panics
    ///
    /// Panics if preallocated publication does not initialize exactly one retained value.
    #[test]
    fn shared_slot_publishes_without_an_additional_allocation() {
        let Ok(slot) = DriverSharedSlot::try_new() else {
            return;
        };
        let owner = slot.initialize(0x5A_u32);
        let Ok(lease) = owner.try_acquire() else {
            return;
        };
        drop(owner);
        assert_eq!(*lease.get(), 0x5A);
    }

    /// # Panics
    ///
    /// Panics if reference-budget exhaustion traps or mutates the owner count.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn shared_reference_exhaustion_is_recoverable() {
        let Ok(owner) = DriverShared::try_new(0xA5_u32) else {
            return;
        };
        let Ok(lease) = owner.try_acquire() else {
            return;
        };
        let references = unsafe {
            // SAFETY: This test retains the owner and lease and restores both live references
            // before either is dropped.
            &owner.inner.as_ref().references
        };
        references.store(usize::MAX, Ordering::Release);
        assert!(matches!(
            owner.try_acquire(),
            Err(DriverError::InsufficientResources)
        ));
        assert!(matches!(
            lease.try_acquire(),
            Err(DriverError::InsufficientResources)
        ));
        assert_eq!(references.load(Ordering::Acquire), usize::MAX);
        references.store(2, Ordering::Release);
    }
}
