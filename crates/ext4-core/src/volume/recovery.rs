//! Private write-free replay images, retained unchanged for the entire read-only mount.

use alloc::vec::Vec;
use core::mem::size_of;

use super::RecoveryMemoryLimit;
use crate::disk::storage::StorageReadOverlay;
use crate::memory::{self, FallibleVec};
use crate::{ByteOffset, Error, Result, StorageTarget};

/// One accepted virtual write. Order determines precedence for overlapping ranges.
#[derive(Debug)]
struct RecoveryImage {
    /// The filesystem and external journal have independent address spaces.
    target: StorageTarget,
    /// First byte changed by this image.
    offset: ByteOffset,
    /// Complete replacement bytes, including their reserved capacity charge.
    bytes: Vec<u8>,
}

/// Bounded replay storage. Only the unpublished mount can change it.
#[derive(Debug)]
pub(super) struct RecoveryOverlay {
    /// Payload plus index capacity admitted for this mount.
    limit: RecoveryMemoryLimit,
    /// Accepted writes in chronological order.
    images: Vec<RecoveryImage>,
    /// Sum of retained payload capacities; index capacity is charged separately.
    payload_bytes: usize,
}

impl RecoveryOverlay {
    /// Creates an empty, allocation-free recovery sink.
    pub(super) const fn new(limit: RecoveryMemoryLimit) -> Self {
        Self {
            limit,
            images: Vec::new(),
            payload_bytes: 0,
        }
    }

    /// Seals replay storage before it becomes a shared, immutable read source.
    /// # Errors
    /// Returns budget exhaustion or physical allocation failure before mount publication.
    pub(super) fn seal(self) -> Result<ext4_shared::Shared<Self>> {
        self.require_budget(self.payload_bytes, self.images.capacity())?;
        ext4_shared::Shared::try_new(self).map_err(memory::shared_failure)
    }

    /// Admits the complete successor before replacing any accepted replay image.
    /// # Errors
    /// Returns logical budget exhaustion separately from physical allocation failure.
    pub(super) fn write(
        &mut self,
        target: StorageTarget,
        offset: ByteOffset,
        bytes: &[u8],
    ) -> Result<()> {
        offset
            .get()
            .checked_add(u64::try_from(bytes.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        let replaced = self.images.iter().position(|image| {
            image.target == target && image.offset == offset && image.bytes.len() == bytes.len()
        });
        let previous = replaced
            .and_then(|index| self.images.get(index))
            .map_or(0, |image| image.bytes.capacity());
        let count = self
            .images
            .len()
            .checked_add(usize::from(replaced.is_none()))
            .ok_or(Error::ArithmeticOverflow)?;
        let payload = self
            .payload_bytes
            .checked_sub(previous)
            .and_then(|value| value.checked_add(bytes.len()))
            .ok_or(Error::ArithmeticOverflow)?;
        self.require_budget(payload, count.max(self.images.capacity()))?;
        let replacement = memory::copied_slice(bytes)?;
        let payload = self
            .payload_bytes
            .checked_sub(previous)
            .and_then(|value| value.checked_add(replacement.capacity()))
            .ok_or(Error::ArithmeticOverflow)?;
        if replaced.is_none() {
            self.images
                .try_reserve_exact(1)
                .map_err(|_| Error::OutOfMemory)?;
        }
        self.require_budget(payload, self.images.capacity())?;
        if let Some(index) = replaced {
            // Remove before appending: a replacement is the newest write even when other
            // accepted writes partially overlap its byte range.
            drop(self.images.try_remove_at(index)?);
        }
        self.images.try_push(RecoveryImage {
            target,
            offset,
            bytes: replacement,
        })?;
        self.payload_bytes = payload;
        Ok(())
    }

    /// Checks logical admission before allocation and after the allocator selects capacities.
    /// # Errors
    /// Returns arithmetic overflow or logical recovery-budget exhaustion.
    fn require_budget(&self, payload: usize, index_capacity: usize) -> Result<()> {
        let shared_bytes = ext4_shared::Shared::<Self>::allocation_size();
        let charged = index_capacity
            .checked_mul(size_of::<RecoveryImage>())
            .and_then(|index| index.checked_add(payload))
            .and_then(|bytes| bytes.checked_add(shared_bytes))
            .ok_or(Error::ArithmeticOverflow)?;
        if charged > self.limit.bytes() {
            Err(Error::RecoveryMemoryLimitExceeded)
        } else {
            Ok(())
        }
    }
}

impl StorageReadOverlay for RecoveryOverlay {
    fn read(&self, target: StorageTarget, offset: ByteOffset, out: &mut [u8]) -> Result<bool> {
        let end = offset
            .get()
            .checked_add(u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut covered = false;
        for image in &self.images {
            let image_end = image
                .offset
                .get()
                .checked_add(
                    u64::try_from(image.bytes.len()).map_err(|_| Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            covered |=
                image.target == target && image.offset.get() <= offset.get() && image_end >= end;
        }
        if covered {
            self.apply(target, offset, out)?;
        }
        Ok(covered)
    }

    fn apply(&self, target: StorageTarget, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        let end = offset
            .get()
            .checked_add(u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        for image in self.images.iter().filter(|image| image.target == target) {
            let image_end = image
                .offset
                .get()
                .checked_add(
                    u64::try_from(image.bytes.len()).map_err(|_| Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            let start = offset.get().max(image.offset.get());
            let stop = end.min(image_end);
            if start >= stop {
                continue;
            }
            let target_start = usize::try_from(
                start
                    .checked_sub(offset.get())
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let source_start = usize::try_from(
                start
                    .checked_sub(image.offset.get())
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let length = usize::try_from(stop.checked_sub(start).ok_or(Error::ArithmeticOverflow)?)
                .map_err(|_| Error::ArithmeticOverflow)?;
            let target_end = target_start
                .checked_add(length)
                .ok_or(Error::ArithmeticOverflow)?;
            let source_end = source_start
                .checked_add(length)
                .ok_or(Error::ArithmeticOverflow)?;
            memory::copy_exact(
                out.get_mut(target_start..target_end)
                    .ok_or(Error::DeviceRange)?,
                image
                    .bytes
                    .get(source_start..source_end)
                    .ok_or(Error::DeviceRange)?,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns bounded storage admission or range failures.
    /// # Panics
    /// Fails if overwrite order or independent device coordinates are lost.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions compare virtual reads against independently specified byte sequences"
    )]
    fn overlapping_writes_keep_order_and_device_identity() -> Result<()> {
        let mut images = RecoveryOverlay::new(RecoveryMemoryLimit::DEFAULT);
        images.write(StorageTarget::Filesystem, ByteOffset::new(4), b"abcdef")?;
        images.write(StorageTarget::Filesystem, ByteOffset::new(6), b"XYZ")?;
        images.write(
            StorageTarget::ExternalJournal,
            ByteOffset::new(4),
            b"journal",
        )?;
        let mut out = [0; 6];
        assert!(images.read(StorageTarget::Filesystem, ByteOffset::new(4), &mut out)?);
        assert_eq!(&out, b"abXYZf");
        images.write(StorageTarget::Filesystem, ByteOffset::new(4), b"ABCDEF")?;
        assert!(images.read(StorageTarget::Filesystem, ByteOffset::new(4), &mut out)?);
        assert_eq!(&out, b"ABCDEF");
        let mut other = [0; 7];
        assert!(images.read(
            StorageTarget::ExternalJournal,
            ByteOffset::new(4),
            &mut other
        )?);
        assert_eq!(&other, b"journal");
        Ok(())
    }
}
