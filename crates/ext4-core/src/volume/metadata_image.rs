//! Unique full-block postimages assembled before journal publication.

use super::scope::*;

/// Coalesces byte-range edits under one block-coordinate conversion and one authoritative image.
#[derive(Debug)]
pub(super) struct MetadataImages {
    /// Byte width shared by every admitted postimage.
    block_size: BlockSize,
    /// No block address occurs twice; later patches replace bytes in the same owned image.
    blocks: Vec<JournalBlock>,
}
impl MetadataImages {
    /// Starts an effect-free image set.
    pub(super) const fn new(block_size: BlockSize) -> Self {
        Self {
            block_size,
            blocks: Vec::new(),
        }
    }

    /// Reads a containing block at most once and applies one admitted, non-crossing edit.
    /// # Errors
    /// Returns suspended I/O, allocation, coordinate, or range failure without device writes.
    pub(super) fn patch(
        &mut self,
        volume: &mut EpochReadView<'_, '_>,
        offset: ByteOffset,
        bytes: &[u8],
    ) -> Result<()> {
        let size = volume.superblock.block_size();
        if size != self.block_size {
            return Err(Error::InvalidWriteRange);
        }
        let width = u64::from(size.bytes());
        let block = BlockAddress::new(
            offset
                .get()
                .checked_div(width)
                .ok_or(Error::InvalidSuperblock)?,
        );
        let within = usize::try_from(
            offset
                .get()
                .checked_rem(width)
                .ok_or(Error::InvalidSuperblock)?,
        )
        .map_err(|_| Error::ArithmeticOverflow)?;
        let end = within
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        let block_bytes = usize::try_from(size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        if end > block_bytes {
            return Err(Error::InvalidWriteRange);
        }
        let index = if let Some(index) = self.blocks.iter().position(|image| image.block() == block)
        {
            index
        } else {
            let mut original = memory::repeated_vec(0, block_bytes)?;
            volume
                .device
                .read_metadata_exact_at(size.offset_of(block)?, &mut original)?;
            self.blocks.try_push(JournalBlock::new(block, original))?;
            self.blocks
                .len()
                .checked_sub(1)
                .ok_or(Error::ArithmeticOverflow)?
        };
        memory::copy_exact(
            self.blocks
                .get_mut(index)
                .ok_or(Error::InvalidWriteRange)?
                .bytes_mut()
                .get_mut(within..end)
                .ok_or(Error::InvalidWriteRange)?,
            bytes,
        )
    }

    /// Transfers the sole postimages to a journal planner after resolution has completed.
    pub(super) fn into_blocks(self) -> Vec<JournalBlock> {
        self.blocks
    }
}

impl crate::disk::storage::StorageReadOverlay for MetadataImages {
    fn read(
        &self,
        target: crate::StorageTarget,
        offset: ByteOffset,
        out: &mut [u8],
    ) -> Result<bool> {
        crate::disk_format::journal::JournalOverlay::new(self.block_size, &self.blocks)
            .read(target, offset, out)
    }
    fn apply(
        &self,
        target: crate::StorageTarget,
        offset: ByteOffset,
        out: &mut [u8],
    ) -> Result<()> {
        crate::disk_format::journal::JournalOverlay::new(self.block_size, &self.blocks)
            .apply(target, offset, out)
    }
}
