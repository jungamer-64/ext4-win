//! Staged transaction images.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Full block image staged for metadata rewrite.
pub(super) struct BlockImage {
    /// Metadata block address.
    pub(super) block: BlockAddress,
    /// Complete block bytes to journal and write.
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Descriptor transition required when a derived bitmap is first persisted.
pub(super) enum BitmapInitializationTransition {
    /// Preserve the descriptor's current initialization state.
    Preserve,
    /// Clear the corresponding uninitialized flag at commit.
    Initialize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Accumulated block group accounting changes.
pub(super) struct GroupDelta {
    /// Block group receiving the accounting changes.
    pub(super) group: BlockGroupId,
    /// Free-cluster count delta for the descriptor.
    pub(super) free_clusters_delta: FreeClusterDelta,
    /// Free-inode count delta for the descriptor.
    pub(super) free_inodes_delta: i64,
    /// Used-directory count delta for the descriptor.
    pub(super) used_dirs_delta: i64,
    /// Block bitmap initialization transition.
    pub(super) block_bitmap_initialization: BitmapInitializationTransition,
    /// Inode bitmap initialization transition.
    pub(super) inode_bitmap_initialization: BitmapInitializationTransition,
}

impl GroupDelta {
    /// Starts an empty accounting delta for one block group.
    pub(super) fn new(group: BlockGroupId) -> Self {
        Self {
            group,
            free_clusters_delta: FreeClusterDelta::ZERO,
            free_inodes_delta: 0,
            used_dirs_delta: 0,
            block_bitmap_initialization: BitmapInitializationTransition::Preserve,
            inode_bitmap_initialization: BitmapInitializationTransition::Preserve,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Plaintext image used as the base for an encrypted partial-block update.
pub(super) enum EncryptedBlockBase {
    /// Decrypt the existing physical block before merging the write.
    ExistingPlaintext,
    /// Start from a zero-filled plaintext block.
    ZeroedPlaintext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Byte range write staged for ordered data or metadata persistence.
pub(super) struct RangeWrite {
    /// Absolute device byte offset.
    pub(super) offset: ByteOffset,
    /// Bytes to write at the offset.
    pub(super) bytes: Vec<u8>,
}

/// Persistence authority retained by each staged file-data update.
#[derive(Debug)]
pub(super) enum StagedFileWrite {
    /// Data that must reach its home location before the metadata commit.
    Ordered(RangeWrite),
    /// A complete data block that must travel through the journal commit and checkpoint.
    Journaled(JournalBlock),
}

impl StagedFileWrite {
    /// Locates ordered ranges and journaled block images in the same device byte domain.
    /// # Errors
    /// Returns an error when a journaled block's byte offset overflows.
    fn byte_range(&self, block_size: BlockSize) -> Result<(ByteOffset, &[u8])> {
        match self {
            Self::Ordered(write) => Ok((write.offset, &write.bytes)),
            Self::Journaled(write) => Ok((block_size.offset_of(write.block())?, write.bytes())),
        }
    }
}

impl MetadataMutation<'_, '_> {
    /// Reads the current transaction's physical block, applying staged data in operation order.
    /// A staged image covering the whole block replaces the device read, including new allocation.
    /// # Errors
    /// Returns allocation, device read, arithmetic or invalid staged-range failures.
    pub(super) fn file_block_bytes(&mut self, physical: BlockAddress) -> Result<Vec<u8>> {
        let block_size = self.volume.superblock.block_size();
        let width = usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let offset = block_size.offset_of(physical)?;
        let start = offset.get();
        let end = start
            .checked_add(u64::from(block_size.bytes()))
            .ok_or(Error::ArithmeticOverflow)?;
        let mut bytes = memory::repeated_vec(0_u8, width)?;
        let mut after_base = None;
        for (index, write) in self.file_writes.iter().enumerate().rev() {
            let (write_offset, payload) = write.byte_range(block_size)?;
            let write_start = write_offset.get();
            let write_end = write_start
                .checked_add(u64::try_from(payload.len()).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            if write_start <= start && write_end >= end {
                let from = usize::try_from(
                    start
                        .checked_sub(write_start)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .map_err(|_| Error::ArithmeticOverflow)?;
                let to = from.checked_add(width).ok_or(Error::ArithmeticOverflow)?;
                memory::copy_exact(
                    &mut bytes,
                    payload.get(from..to).ok_or(Error::InvalidWriteRange)?,
                )?;
                after_base = Some(index.checked_add(1).ok_or(Error::ArithmeticOverflow)?);
                break;
            }
        }
        if after_base.is_none() {
            self.volume.device.read_exact_at(offset, &mut bytes)?;
        }
        for write in self.file_writes.iter().skip(after_base.unwrap_or(0)) {
            let (write_offset, payload) = write.byte_range(block_size)?;
            let write_start = write_offset.get();
            let write_end = write_start
                .checked_add(u64::try_from(payload.len()).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let overlap_start = start.max(write_start);
            let overlap_end = end.min(write_end);
            if overlap_start >= overlap_end {
                continue;
            }
            let target_start = usize::try_from(
                overlap_start
                    .checked_sub(start)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let target_end = usize::try_from(
                overlap_end
                    .checked_sub(start)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let source_start = usize::try_from(
                overlap_start
                    .checked_sub(write_start)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let source_end = usize::try_from(
                overlap_end
                    .checked_sub(write_start)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            memory::copy_exact(
                bytes
                    .get_mut(target_start..target_end)
                    .ok_or(Error::InvalidWriteRange)?,
                payload
                    .get(source_start..source_end)
                    .ok_or(Error::InvalidWriteRange)?,
            )?;
        }
        Ok(bytes)
    }

    /// Stages data at the inode-selected persistence boundary before any lower write.
    /// Journaled partial writes retain a full committed or already staged block image.
    /// # Errors
    /// Returns allocation, read, arithmetic or single-block-range errors during preparation.
    pub(super) fn stage_file_write(
        &mut self,
        persistence: FileDataPersistence,
        write: RangeWrite,
    ) -> Result<()> {
        if persistence == FileDataPersistence::Ordered {
            return self.file_writes.try_push(StagedFileWrite::Ordered(write));
        }
        let block_size = self.volume.superblock.block_size();
        let width = u64::from(block_size.bytes());
        let block = BlockAddress::new(
            write
                .offset
                .get()
                .checked_div(width)
                .ok_or(Error::InvalidSuperblock)?,
        );
        let start = usize::try_from(
            write
                .offset
                .get()
                .checked_rem(width)
                .ok_or(Error::InvalidSuperblock)?,
        )
        .map_err(|_| Error::ArithmeticOverflow)?;
        let end = start
            .checked_add(write.bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        let block_bytes = usize::try_from(width).map_err(|_| Error::ArithmeticOverflow)?;
        if end > block_bytes {
            return Err(Error::InvalidWriteRange);
        }
        if let Some(StagedFileWrite::Journaled(staged)) = self.file_writes.iter_mut().find(
            |item| matches!(item, StagedFileWrite::Journaled(staged) if staged.block() == block),
        ) {
            return memory::copy_exact(
                staged
                    .bytes_mut()
                    .get_mut(start..end)
                    .ok_or(Error::InvalidWriteRange)?,
                &write.bytes,
            );
        }
        let bytes = if start == 0 && write.bytes.len() == block_bytes {
            write.bytes
        } else {
            let mut bytes = self.file_block_bytes(block)?;
            memory::copy_exact(
                bytes.get_mut(start..end).ok_or(Error::InvalidWriteRange)?,
                &write.bytes,
            )?;
            bytes
        };
        self.file_writes
            .try_push(StagedFileWrite::Journaled(JournalBlock::new(block, bytes)))
    }
}
