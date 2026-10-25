//! Immutable byte reads over complete filesystem-block postimages.
use super::{BlockSize, ByteOffset, Error, JournalBlock, Result, memory};
use crate::disk::storage::{StorageReadOverlay, StorageTarget};

/// A borrowed projection grants reads only; ownership and publication remain with the image set.
#[derive(Debug)]
pub(crate) struct JournalOverlay<'a> {
    /// Physical byte coordinate conversion shared by every image in this set.
    block_size: BlockSize,
    /// Sole immutable postimages; the caller owns their unique block-address invariant.
    blocks: &'a [JournalBlock],
}
impl<'a> JournalOverlay<'a> {
    /// Borrows existing postimages without allocating or minting write authority.
    pub(crate) const fn new(block_size: BlockSize, blocks: &'a [JournalBlock]) -> Self {
        Self { block_size, blocks }
    }
}
impl StorageReadOverlay for JournalOverlay<'_> {
    fn read(&self, target: StorageTarget, offset: ByteOffset, out: &mut [u8]) -> Result<bool> {
        if target != StorageTarget::Filesystem {
            return Ok(false);
        }
        let end = offset
            .get()
            .checked_add(u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        for image in self.blocks {
            let start = self.block_size.offset_of(image.block())?.get();
            let image_end = start
                .checked_add(
                    u64::try_from(image.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            if offset.get() >= start && end <= image_end {
                let from = usize::try_from(
                    offset
                        .get()
                        .checked_sub(start)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .map_err(|_| Error::ArithmeticOverflow)?;
                let to = from
                    .checked_add(out.len())
                    .ok_or(Error::ArithmeticOverflow)?;
                memory::copy_exact(out, image.bytes().get(from..to).ok_or(Error::DeviceRange)?)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn apply(&self, target: StorageTarget, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        if target != StorageTarget::Filesystem || out.is_empty() {
            return Ok(());
        }
        let start = offset.get();
        let end = start
            .checked_add(u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        for image in self.blocks {
            let image_start = self.block_size.offset_of(image.block())?.get();
            let image_end = image_start
                .checked_add(
                    u64::try_from(image.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            let first = start.max(image_start);
            let last = end.min(image_end);
            if first >= last {
                continue;
            }
            let relative = |base| {
                usize::try_from(first.checked_sub(base).ok_or(Error::ArithmeticOverflow)?)
                    .map_err(|_| Error::ArithmeticOverflow)
            };
            let length = usize::try_from(last.checked_sub(first).ok_or(Error::ArithmeticOverflow)?)
                .map_err(|_| Error::ArithmeticOverflow)?;
            let from = relative(image_start)?;
            let to = relative(start)?;
            let source_end = from.checked_add(length).ok_or(Error::ArithmeticOverflow)?;
            let target_end = to.checked_add(length).ok_or(Error::ArithmeticOverflow)?;
            memory::copy_exact(
                out.get_mut(to..target_end).ok_or(Error::DeviceRange)?,
                image
                    .bytes()
                    .get(from..source_end)
                    .ok_or(Error::DeviceRange)?,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::block::BlockAddress;
    use alloc::vec;

    /// # Panics
    /// Fails if exact and partial reads disagree, gaps are overwritten, or target domains mix.
    #[test]
    fn postimages_cover_only_their_physical_filesystem_bytes() {
        let result = (|| -> Result<()> {
            let blocks = [
                JournalBlock::new(BlockAddress::new(1), vec![0x11; 1024]),
                JournalBlock::new(BlockAddress::new(3), vec![0x33; 1024]),
            ];
            let view = JournalOverlay::new(BlockSize::from_superblock_log(0)?, &blocks);
            let mut exact = [0x55; 4];
            assert!(view.read(StorageTarget::Filesystem, ByteOffset::new(1024), &mut exact)?);
            assert_eq!(exact, [0x11; 4]);
            let mut crossing = [0x55; 1028];
            assert!(!view.read(
                StorageTarget::Filesystem,
                ByteOffset::new(2046),
                &mut crossing
            )?);
            view.apply(
                StorageTarget::Filesystem,
                ByteOffset::new(2046),
                &mut crossing,
            )?;
            assert_eq!(crossing.get(..2), Some([0x11; 2].as_slice()));
            assert!(
                crossing
                    .get(2..1026)
                    .ok_or(Error::DeviceRange)?
                    .iter()
                    .all(|byte| *byte == 0x55)
            );
            assert_eq!(crossing.get(1026..), Some([0x33; 2].as_slice()));
            exact.fill(0x55);
            assert!(!view.read(
                StorageTarget::ExternalJournal,
                ByteOffset::new(1024),
                &mut exact
            )?);
            view.apply(
                StorageTarget::ExternalJournal,
                ByteOffset::new(1024),
                &mut exact,
            )?;
            assert_eq!(exact, [0x55; 4]);
            assert_eq!(
                view.read(
                    StorageTarget::Filesystem,
                    ByteOffset::new(u64::MAX),
                    &mut exact
                ),
                Err(Error::ArithmeticOverflow)
            );
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }
}
