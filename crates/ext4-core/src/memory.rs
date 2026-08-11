//! Fallible allocation helpers for the ext4 domain.

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::{Error, Result};

/// Converts allocation reservation failure into the ext4 error domain.
fn allocation_failed(_: alloc::collections::TryReserveError) -> Error {
    Error::OutOfMemory
}

/// Builds a vector filled with `len` copies after reserving its allocation.
/// # Errors
///
/// Returns [`Error::OutOfMemory`] when reserving the vector storage fails, or
/// [`Error::ArithmeticOverflow`] when its length cannot be represented.
pub(crate) fn repeated_vec<T: Copy>(value: T, len: usize) -> Result<Vec<T>> {
    let mut output = Vec::new();
    output.try_reserve_exact(len).map_err(allocation_failed)?;
    for _index in 0..len {
        output.try_push(value)?;
    }
    Ok(output)
}

/// Copies one slice into a newly allocated vector.
/// # Errors
///
/// Returns [`Error::OutOfMemory`] when reserving the destination storage fails,
/// or [`Error::ArithmeticOverflow`] when its length cannot be represented.
pub(crate) fn copied_slice<T: Copy>(source: &[T]) -> Result<Vec<T>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(source.len())
        .map_err(allocation_failed)?;
    for value in source.iter().copied() {
        output.try_push(value)?;
    }
    Ok(output)
}

/// Copies between equal-length slices without calling the panicking slice copy intrinsic.
/// # Errors
///
/// Returns [`Error::InvalidWriteRange`] when the lengths differ.
pub(crate) fn copy_exact<T: Copy>(destination: &mut [T], source: &[T]) -> Result<()> {
    if destination.len() != source.len() {
        return Err(Error::InvalidWriteRange);
    }
    for (destination, source) in destination.iter_mut().zip(source.iter().copied()) {
        *destination = source;
    }
    Ok(())
}

/// Sorts a slice in place with a non-allocating binary heap and checked access.
///
/// The ordering is intentionally unstable. Callers must provide a complete
/// deterministic comparison key when equal-key order matters to serialization.
///
/// # Errors
///
/// Returns [`Error::ArithmeticOverflow`] when heap index arithmetic overflows,
/// or [`Error::InvalidWriteRange`] if the checked slice partition is invalid.
pub(crate) fn heap_sort_by<T>(
    values: &mut [T],
    mut compare: impl FnMut(&T, &T) -> Ordering,
) -> Result<()> {
    let mut root = values
        .len()
        .checked_div(2)
        .ok_or(Error::ArithmeticOverflow)?;
    while root > 0 {
        root = root.checked_sub(1).ok_or(Error::ArithmeticOverflow)?;
        sift_heap(values, root, values.len(), &mut compare)?;
    }

    let mut end = values.len();
    while end > 1 {
        end = end.checked_sub(1).ok_or(Error::ArithmeticOverflow)?;
        swap_checked(values, 0, end)?;
        sift_heap(values, 0, end, &mut compare)?;
    }
    Ok(())
}

/// Restores the max-heap invariant below one root.
///
/// # Errors
///
/// Returns [`Error::ArithmeticOverflow`] when child-index arithmetic overflows,
/// or [`Error::InvalidWriteRange`] if a heap position is outside `values`.
fn sift_heap<T>(
    values: &mut [T],
    mut root: usize,
    end: usize,
    compare: &mut impl FnMut(&T, &T) -> Ordering,
) -> Result<()> {
    loop {
        let left = root
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::ArithmeticOverflow)?;
        if left >= end {
            return Ok(());
        }
        let right = left.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        let child = if right < end {
            let left_value = values.get(left).ok_or(Error::InvalidWriteRange)?;
            let right_value = values.get(right).ok_or(Error::InvalidWriteRange)?;
            if compare(left_value, right_value) == Ordering::Less {
                right
            } else {
                left
            }
        } else {
            left
        };
        let root_value = values.get(root).ok_or(Error::InvalidWriteRange)?;
        let child_value = values.get(child).ok_or(Error::InvalidWriteRange)?;
        if compare(root_value, child_value) != Ordering::Less {
            return Ok(());
        }
        swap_checked(values, root, child)?;
        root = child;
    }
}

/// Swaps two checked slice positions without the panicking slice swap primitive.
///
/// # Errors
///
/// Returns [`Error::InvalidWriteRange`] when either position is outside
/// `values`.
fn swap_checked<T>(values: &mut [T], first: usize, second: usize) -> Result<()> {
    if first == second {
        return Ok(());
    }
    let (lower_index, upper_index) = if first < second {
        (first, second)
    } else {
        (second, first)
    };
    let (lower, upper) = values
        .split_at_mut_checked(upper_index)
        .ok_or(Error::InvalidWriteRange)?;
    let lower_value = lower.get_mut(lower_index).ok_or(Error::InvalidWriteRange)?;
    let upper_value = upper.first_mut().ok_or(Error::InvalidWriteRange)?;
    core::mem::swap(lower_value, upper_value);
    Ok(())
}

/// Fallible growth operations for vectors in production code paths.
pub(crate) trait FallibleVec<T> {
    /// Pushes one value after reserving capacity for it.
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when reserving room for the new element
    /// fails, or [`Error::ArithmeticOverflow`] at the maximum vector length.
    fn try_push(&mut self, value: T) -> Result<()>;

    /// Inserts one value after reserving capacity for it.
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when reserving room for the new element
    /// fails, [`Error::ArithmeticOverflow`] at the maximum vector length, or
    /// [`Error::InvalidWriteRange`] when `index` is past the end.
    fn try_insert(&mut self, index: usize, value: T) -> Result<()>;

    /// Removes and returns one value after validating its position.
    /// # Errors
    ///
    /// Returns [`Error::InvalidWriteRange`] when `index` is outside the vector.
    fn try_remove_at(&mut self, index: usize) -> Result<T>;

    /// Extends from a copyable slice after reserving the exact additional length.
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when reserving room for the copied elements
    /// fails, or [`Error::ArithmeticOverflow`] at the maximum vector length.
    fn try_extend_from_slice(&mut self, source: &[T]) -> Result<()>
    where
        T: Copy;
}

impl<T> FallibleVec<T> for Vec<T> {
    fn try_push(&mut self, value: T) -> Result<()> {
        let _updated_len = self.len().checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        self.try_reserve(1).map_err(allocation_failed)?;
        self.push_within_capacity(value)
            .map(|_inserted| ())
            .map_err(|_value| Error::OutOfMemory)
    }

    fn try_insert(&mut self, index: usize, value: T) -> Result<()> {
        let current_len = self.len();
        if index > current_len {
            return Err(Error::InvalidWriteRange);
        }
        let _updated_len = current_len
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        self.try_reserve(1).map_err(allocation_failed)?;
        self.push_within_capacity(value)
            .map_err(|_value| Error::OutOfMemory)?;

        let inserted_tail = self.get_mut(index..).ok_or(Error::InvalidWriteRange)?;
        inserted_tail.reverse();
        inserted_tail
            .get_mut(1..)
            .ok_or(Error::InvalidWriteRange)?
            .reverse();
        Ok(())
    }

    fn try_remove_at(&mut self, index: usize) -> Result<T> {
        let current_len = self.len();
        if index >= current_len {
            return Err(Error::InvalidWriteRange);
        }
        let tail_len = current_len
            .checked_sub(index)
            .ok_or(Error::InvalidWriteRange)?;
        let preserved_len = tail_len.checked_sub(1).ok_or(Error::InvalidWriteRange)?;
        let removal_tail = self.get_mut(index..).ok_or(Error::InvalidWriteRange)?;
        removal_tail.reverse();
        removal_tail
            .get_mut(..preserved_len)
            .ok_or(Error::InvalidWriteRange)?
            .reverse();
        self.pop().ok_or(Error::InvalidWriteRange)
    }

    fn try_extend_from_slice(&mut self, source: &[T]) -> Result<()>
    where
        T: Copy,
    {
        let _updated_len = self
            .len()
            .checked_add(source.len())
            .ok_or(Error::ArithmeticOverflow)?;
        self.try_reserve(source.len()).map_err(allocation_failed)?;
        for value in source.iter().copied() {
            self.try_push(value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{FallibleVec, heap_sort_by};

    /// # Panics
    ///
    /// Panics when checked insertion does not preserve stable element order.
    #[test]
    fn checked_insert_preserves_order_at_every_boundary() {
        let mut values = vec![2_u8, 4];
        assert_eq!(values.try_insert(0, 1), Ok(()));
        assert_eq!(values.try_insert(2, 3), Ok(()));
        assert_eq!(values.try_insert(4, 5), Ok(()));
        assert_eq!(values, [1, 2, 3, 4, 5]);
        assert!(values.try_insert(6, 9).is_err());
    }

    /// # Panics
    ///
    /// Panics when checked removal returns the wrong value or changes order.
    #[test]
    fn checked_remove_preserves_remaining_order() {
        let mut values = vec![1_u8, 2, 3, 4, 5];
        assert_eq!(values.try_remove_at(2), Ok(3));
        assert_eq!(values, [1, 2, 4, 5]);
        assert_eq!(values.try_remove_at(0), Ok(1));
        assert_eq!(values.try_remove_at(1), Ok(4));
        assert_eq!(values, [2, 5]);
        assert!(values.try_remove_at(2).is_err());
    }

    /// # Panics
    ///
    /// Panics when heap ordering differs from the complete comparison key.
    #[test]
    fn checked_heap_sort_orders_empty_singleton_and_duplicate_values() {
        let mut empty: [i32; 0] = [];
        assert_eq!(heap_sort_by(&mut empty, i32::cmp), Ok(()));

        let mut singleton = [7_i32];
        assert_eq!(heap_sort_by(&mut singleton, i32::cmp), Ok(()));
        assert_eq!(singleton, [7]);

        let mut values = [5_i32, -1, 4, 4, 0, 9, -3, 2];
        assert_eq!(heap_sort_by(&mut values, i32::cmp), Ok(()));
        assert_eq!(values, [-3, -1, 0, 2, 4, 4, 5, 9]);
    }
}
