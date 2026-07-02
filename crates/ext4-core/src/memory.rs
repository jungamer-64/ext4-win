//! Fallible allocation helpers for the ext4 domain.

use alloc::vec::Vec;

use crate::{Error, Result};

/// Converts allocation reservation failure into the ext4 error domain.
fn allocation_failed(_: alloc::collections::TryReserveError) -> Error {
    Error::OutOfMemory
}

/// Builds a vector filled with `len` copies after reserving its allocation.
/// # Errors
///
/// Returns [`Error::OutOfMemory`] when reserving the vector storage fails.
pub(crate) fn repeated_vec<T: Clone>(value: T, len: usize) -> Result<Vec<T>> {
    let mut output = Vec::new();
    output.try_reserve_exact(len).map_err(allocation_failed)?;
    output.resize(len, value);
    Ok(output)
}

/// Copies one slice into a newly allocated vector.
/// # Errors
///
/// Returns [`Error::OutOfMemory`] when reserving the destination storage fails.
pub(crate) fn copied_slice<T: Copy>(source: &[T]) -> Result<Vec<T>> {
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
    /// Returns [`Error::OutOfMemory`] when reserving room for the new element fails.
    fn try_push(&mut self, value: T) -> Result<()>;

    /// Extends from a copyable slice after reserving the exact additional length.
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when reserving room for the copied elements fails.
    fn try_extend_from_slice(&mut self, source: &[T]) -> Result<()>
    where
        T: Copy;
}

impl<T> FallibleVec<T> for Vec<T> {
    fn try_push(&mut self, value: T) -> Result<()> {
        self.try_reserve(1).map_err(allocation_failed)?;
        self.push(value);
        Ok(())
    }

    fn try_extend_from_slice(&mut self, source: &[T]) -> Result<()>
    where
        T: Copy,
    {
        self.try_reserve(source.len()).map_err(allocation_failed)?;
        self.extend_from_slice(source);
        Ok(())
    }
}
