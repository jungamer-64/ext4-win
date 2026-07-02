//! Fallible allocation helpers for the Windows driver boundary.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::kernel::status::{DriverError, DriverResult};

/// Converts allocation reservation failure into the driver error domain.
fn allocation_failed(_: alloc::collections::TryReserveError) -> DriverError {
    DriverError::InsufficientResources
}

/// Allocates one boxed value without routing allocation failure through the panic path.
/// # Errors
///
/// Returns [`DriverError::InsufficientResources`] when allocating the box fails.
pub(crate) fn boxed<T>(value: T) -> DriverResult<Box<T>> {
    Box::try_new(value).map_err(|_| DriverError::InsufficientResources)
}

/// Builds a vector filled with `len` copies after reserving its allocation.
/// # Errors
///
/// Returns [`DriverError::InsufficientResources`] when reserving the vector storage fails.
pub(crate) fn repeated_vec<T: Clone>(value: T, len: usize) -> DriverResult<Vec<T>> {
    let mut output = Vec::new();
    output.try_reserve_exact(len).map_err(allocation_failed)?;
    output.resize(len, value);
    Ok(output)
}

/// Copies one slice into a newly allocated vector.
/// # Errors
///
/// Returns [`DriverError::InsufficientResources`] when reserving the destination storage fails.
pub(crate) fn copied_slice<T: Copy>(source: &[T]) -> DriverResult<Vec<T>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(source.len())
        .map_err(allocation_failed)?;
    output.extend_from_slice(source);
    Ok(output)
}

/// Fallible growth operations for vectors in production code paths.
pub(crate) trait FallibleVec<T> {
    /// Pushes one value after reserving capacity for it.
    /// # Errors
    ///
    /// Returns [`DriverError::InsufficientResources`] when reserving room for the new element fails.
    fn try_push(&mut self, value: T) -> DriverResult<()>;

    /// Extends from a copyable slice after reserving the exact additional length.
    /// # Errors
    ///
    /// Returns [`DriverError::InsufficientResources`] when reserving room for the copied elements fails.
    fn try_extend_from_slice(&mut self, source: &[T]) -> DriverResult<()>
    where
        T: Copy;

    /// Resizes after reserving the additional capacity needed by the new length.
    /// # Errors
    ///
    /// Returns [`DriverError::InsufficientResources`] when reserving room for the resized vector fails.
    fn try_resize(&mut self, new_len: usize, value: T) -> DriverResult<()>
    where
        T: Clone;
}

impl<T> FallibleVec<T> for Vec<T> {
    fn try_push(&mut self, value: T) -> DriverResult<()> {
        self.try_reserve(1).map_err(allocation_failed)?;
        self.push(value);
        Ok(())
    }

    fn try_extend_from_slice(&mut self, source: &[T]) -> DriverResult<()>
    where
        T: Copy,
    {
        self.try_reserve(source.len()).map_err(allocation_failed)?;
        self.extend_from_slice(source);
        Ok(())
    }

    fn try_resize(&mut self, new_len: usize, value: T) -> DriverResult<()>
    where
        T: Clone,
    {
        let additional = new_len.saturating_sub(self.len());
        self.try_reserve(additional).map_err(allocation_failed)?;
        self.resize(new_len, value);
        Ok(())
    }
}
