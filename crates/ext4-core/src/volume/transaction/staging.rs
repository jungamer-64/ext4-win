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

impl MetadataMutation<'_, '_> {
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
            let mut bytes = memory::repeated_vec(0_u8, block_bytes)?;
            self.volume
                .device
                .read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
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
