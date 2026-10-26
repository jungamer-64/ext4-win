//! Persistent inode retirement policy and its physical completion boundary.

use super::*;

/// Persistence boundary required before reporting a mutation's successful completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationCompletionDurability {
    /// The durable journal record and committed metadata overlay suffice.
    JournalCommit,
    /// Committed physical payload images must reach home storage and its durability barrier.
    HomeCheckpoint,
}

impl ResolvedMutation {
    /// Returns the completion boundary derived from this exact resolved attempt's staged effects.
    #[must_use]
    pub const fn completion_durability(&self) -> MutationCompletionDurability {
        self.completion_durability
    }
}

impl MutationResolvePass<'_, '_, '_> {
    /// Enables persistent physical zeroing when file allocation loses its last owner.
    /// Inline payload is converted to extent storage in the same commit. Zeroing uses journaled
    /// images, so it cannot destroy the old file before its retirement is durably committed.
    /// # Errors
    /// Returns inode-policy, allocation, inline-conversion, storage or serialization failures.
    pub fn set_zero_on_deallocation(&mut self, file: TransactionFile) -> Result<()> {
        self.edit(|pass| {
            let index = pass.mutation.ensure_inode_update(file.inode())?;
            let mut raw = pass.mutation.staged_live_inode(index)?;
            let _metadata = raw.parse()?.metadata_mutation()?;
            pass.mutation.require_extent_storage(&mut raw)?;
            raw.mark_zero_on_deallocation()?;
            pass.mutation.register_zero_on_deallocation(&raw.parse()?)?;
            pass.mutation.replace_live_inode(index, raw)
        })
    }
}

impl MetadataMutation<'_, '_> {
    /// Projects policy only over current inode-owned storage; the bitmap remains its sole owner.
    /// # Errors
    /// Returns invalid extents, storage reads, coordinate or allocation failures.
    pub(super) fn register_zero_on_deallocation(&mut self, inode: &Inode) -> Result<()> {
        if !inode.flags().zero_on_deallocation() {
            return Ok(());
        }
        if let InodeStorage::Extents(_) = inode.storage() {
            let tree = self.mutable_extent_tree(inode)?;
            for extent in tree.extents().iter().copied() {
                self.zero_retirement_ranges.try_push(InodeAllocationClusterRange::from_extent(
                    self.volume.superblock, extent,
                )?)?;
            }
            for block in tree.metadata_blocks().iter().copied() {
                self.protect_zero_retirement(block)?;
            }
        }
        if let Some(block) = self.raw_inode_for_policy(inode.id())?.xattr_block()? {
            self.protect_zero_retirement(block)?;
        }
        Ok(())
    }

    /// Records one policy-owned metadata block before its reference is retired.
    /// # Errors
    /// Returns invalid cluster coordinates or allocation failure.
    pub(super) fn protect_zero_retirement(&mut self, block: BlockAddress) -> Result<()> {
        self.zero_retirement_ranges.try_push(InodeAllocationClusterRange::from_block(
            self.volume.superblock, block,
        )?)
    }

    /// Journals zero images after the last old owner is retired, never as precommit home writes.
    /// The commit lane excludes every successor allocation until this checkpoint completes.
    /// # Errors
    /// Returns invalid cluster geometry, image allocation or journal-staging failures.
    pub(super) fn zero_retired_cluster(&mut self, cluster: ClusterAddress) -> Result<()> {
        if !self.zero_retirement_ranges.iter().any(|range| {
            range.start <= cluster && cluster.get() < range.end_exclusive
        }) {
            return Ok(());
        }
        let superblock = self.volume.superblock;
        let first = superblock.first_block_of_cluster(cluster)?;
        let width = usize::try_from(superblock.block_size().bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        for within in 0..superblock.blocks_in_cluster(cluster)? {
            let block = BlockAddress::new(first.get().checked_add(u64::from(within)).ok_or(Error::ArithmeticOverflow)?);
            self.release_block_images(block);
            self.stage_file_write(FileDataPersistence::Journaled, RangeWrite {
                offset: superblock.block_size().offset_of(block)?,
                bytes: memory::repeated_vec(0_u8, width)?,
            })?;
        }
        self.completion_durability = MutationCompletionDurability::HomeCheckpoint;
        Ok(())
    }
}
