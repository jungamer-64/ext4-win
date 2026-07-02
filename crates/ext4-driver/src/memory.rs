//! Fallible allocation helpers for the Windows driver boundary.

use alloc::{
    alloc::{AllocError, Allocator, Global},
    boxed::Box,
    collections::{TryReserveError, TryReserveErrorKind},
    vec::Vec,
};

use crate::kernel::status::{DriverError, DriverResult};

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

/// Error returned by owned push operations.
///
/// This keeps ownership of the value on failure. A generic `T` may have a destructor, and dropping
/// it inside an allocation helper would make allocation failure execute arbitrary destructor code.
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

/// Kernel-bound vector wrapper.
///
/// This intentionally does not implement `Deref<Target = [T]>` and does not expose `into_inner`.
/// Production paths should not fall back to raw `Vec::push`, `Vec::resize`, `Vec::extend`, or
/// `vec![]` after crossing this boundary.
#[repr(transparent)]
pub(crate) struct KernelVec<T, A: Allocator = Global> {
    /// Owned vector guarded by this module's fallible growth API.
    inner: Vec<T, A>,
}

/// Default driver vector using the crate-global allocator.
pub(crate) type DriverVec<T> = KernelVec<T, Global>;

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

impl<T> Default for KernelVec<T, Global> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, A> KernelVec<T, A>
where
    A: Allocator,
{
    /// Creates an empty vector using the provided allocator.
    pub(crate) fn new_in(allocator: A) -> Self {
        Self {
            inner: Vec::new_in(allocator),
        }
    }

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

    /// Returns the current allocated capacity reported by `Vec`.
    pub(crate) fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns the contents as a slice.
    pub(crate) fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    /// Returns the contents as a mutable slice.
    ///
    /// This does not expose allocation-changing vector operations.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        self.inner.as_mut_slice()
    }

    /// Returns an element by index without panicking.
    pub(crate) fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    /// Returns a mutable element by index without panicking.
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.inner.get_mut(index)
    }

    /// Returns the raw pointer for FFI/kernel boundary calls.
    pub(crate) fn as_ptr(&self) -> *const T {
        self.inner.as_ptr()
    }

    /// Returns the mutable raw pointer for FFI/kernel boundary calls.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut T {
        self.inner.as_mut_ptr()
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
            Ok(()) => Ok(()),
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

        let additional = new_len - old_len;
        self.try_reserve_exact(additional)?;

        while self.inner.len() < new_len {
            self.push_reserved_copy(value)?;
        }

        Ok(())
    }

    /// Truncates a `Copy` vector without allocation or destructor execution.
    pub(crate) fn truncate_copy(&mut self, new_len: usize)
    where
        T: Copy,
    {
        self.inner.truncate(new_len);
    }

    /// Clears a `Copy` vector without allocation or destructor execution.
    pub(crate) fn clear_copy(&mut self)
    where
        T: Copy,
    {
        self.inner.clear();
    }

    /// Removes the last element without panicking.
    pub(crate) fn pop(&mut self) -> Option<T> {
        self.inner.pop()
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
            Ok(()) => Ok(()),
            Err(_) => Err(DriverError::InternalInvariantViolation),
        }
    }
}

/// Allocates one boxed value after allocation has already succeeded.
///
/// Prefer this over `boxed_copy` for large values, because the value is constructed only after the
/// heap slot exists.
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

/// Allocates one boxed value after allocation has already succeeded.
/// # Errors
///
/// Returns an error when box allocation fails.
pub(crate) fn boxed_with_in<T, A, F>(allocator: A, build: F) -> DriverResult<Box<T, A>>
where
    A: Allocator,
    F: FnOnce() -> T,
{
    boxed_try_with_in(allocator, || Ok(build()))
}

/// Boxes a `Copy` value using the provided allocator.
///
/// This convenience function is restricted to `Copy` so allocation failure cannot cause a
/// destructor to run for the input value.
/// # Errors
///
/// Returns an error when box allocation fails.
pub(crate) fn boxed_copy_in<T, A>(value: T, allocator: A) -> DriverResult<Box<T, A>>
where
    T: Copy,
    A: Allocator,
{
    boxed_with_in(allocator, || value)
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

/// Global-allocator version of [`boxed_with_in`].
/// # Errors
///
/// Returns an error when box allocation fails.
pub(crate) fn boxed_with<T, F>(build: F) -> DriverResult<Box<T>>
where
    F: FnOnce() -> T,
{
    boxed_with_in(Global, build)
}

/// Global-allocator version of [`boxed_copy_in`].
/// # Errors
///
/// Returns an error when box allocation fails.
pub(crate) fn boxed_copy<T>(value: T) -> DriverResult<Box<T>>
where
    T: Copy,
{
    boxed_copy_in(value, Global)
}
