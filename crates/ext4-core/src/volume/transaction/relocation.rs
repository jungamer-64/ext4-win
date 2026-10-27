//! Physical relocation without changing logical contents or their authentication coordinates.

use super::*;
use crate::ClusterCount;

impl MutationResolvePass<'_, '_, '_> {
    /// Relocates allocated file clusters to an exact free physical destination.
    ///
    /// `start` is cluster aligned. Sparse virtual clusters retain their holes and leave the
    /// corresponding destination unused. Ciphertext and verity payloads retain their inode and
    /// logical coordinates. Destination allocation and source retirement share one journal commit;
    /// an occupied or concurrently reserved destination rejects the entire staging pass.
    /// # Errors
    /// Returns invalid ranges, unsupported inode storage, occupied destinations, storage,
    /// allocation, serialization or reference-accounting failures.
    pub fn move_file_clusters(
        &mut self,
        file: TransactionFile,
        start: FileOffset,
        destination: ClusterAddress,
        count: ClusterCount,
    ) -> Result<()> {
        self.edit(|pass| {
            let superblock = pass.mutation.volume.superblock;
            let cluster_bytes = u64::from(superblock.cluster_size().bytes());
            let blocks_per_cluster = u64::from(superblock.blocks_per_cluster().as_u32());
            if !start.bytes().is_multiple_of(cluster_bytes) {
                return Err(Error::InvalidWriteRange);
            }
            let logical_start = start
                .bytes()
                .checked_div(u64::from(superblock.block_size().bytes()))
                .ok_or(Error::InvalidClusterGeometry)?;
            let logical_end = count
                .as_u64()
                .checked_mul(blocks_per_cluster)
                .and_then(|blocks| logical_start.checked_add(blocks))
                .ok_or(Error::ArithmeticOverflow)?;
            let _last = LogicalBlock::try_from(
                logical_end.checked_sub(1).ok_or(Error::InvalidWriteRange)?,
            )?;
            let destination_end = destination
                .get()
                .checked_add(count.as_u64())
                .ok_or(Error::ArithmeticOverflow)?;
            if destination_end > superblock.cluster_count().as_u64() {
                return Err(Error::DeviceRange);
            }
            let inode_index = pass.mutation.ensure_inode_update(file.inode())?;
            let mut raw_inode = pass.mutation.staged_live_inode(inode_index)?;
            let inode = raw_inode.parse()?;
            let _metadata = inode.metadata_mutation()?;
            let mut tree = pass.mutation.mutable_extent_tree(&inode)?;
            let extents = memory::copied_slice(tree.extents())?;
            let allocated_end = extents.last().map_or(0, |extent| extent.end_logical());
            let allocation_boundary = round_up_div(allocated_end, blocks_per_cluster)?
                .checked_mul(blocks_per_cluster)
                .ok_or(Error::ArithmeticOverflow)?;
            if logical_start >= allocated_end || logical_end > allocation_boundary {
                return Err(Error::InvalidWriteRange);
            }
            let mut replacement = Vec::new();
            for extent in extents.iter().copied() {
                let extent_start = extent.logical_start().as_u64();
                let extent_end = extent.end_logical();
                if extent_end <= logical_start || extent_start >= logical_end {
                    replacement.try_push(extent)?;
                    continue;
                }
                if extent_start < logical_start {
                    replacement.try_push(fragment(
                        extent,
                        extent_start,
                        logical_start,
                        extent.physical_start(),
                    )?)?;
                }
                if extent_end > logical_end {
                    let physical = physical_at(extent, logical_end)?;
                    replacement.try_push(fragment(extent, logical_end, extent_end, physical)?)?;
                }
            }
            let mut claimed = None;
            for extent in extents.iter().copied() {
                let from = logical_start.max(extent.logical_start().as_u64());
                let to = logical_end.min(extent.end_logical());
                for logical in from..to {
                    let relative = logical
                        .checked_sub(logical_start)
                        .ok_or(Error::ArithmeticOverflow)?
                        .checked_div(blocks_per_cluster)
                        .ok_or(Error::InvalidClusterGeometry)?;
                    let within = logical
                        .checked_rem(blocks_per_cluster)
                        .ok_or(Error::InvalidClusterGeometry)?;
                    let target = ClusterAddress::new(
                        destination
                            .get()
                            .checked_add(relative)
                            .ok_or(Error::ArithmeticOverflow)?,
                    );
                    let first = if claimed == Some(target) {
                        pass.mutation.record_cluster_reference_delta(target, 1)?;
                        superblock.first_block_of_cluster(target)?
                    } else {
                        claimed = Some(target);
                        pass.mutation.allocate_cluster_at(target)?
                    };
                    let physical = BlockAddress::new(
                        first
                            .get()
                            .checked_add(within)
                            .ok_or(Error::ArithmeticOverflow)?,
                    );
                    let previous = physical_at(extent, logical)?;
                    if extent.initialization() == ExtentInitialization::Initialized {
                        let bytes = pass.mutation.file_block_bytes(previous)?;
                        pass.mutation.stage_file_write(
                            inode.data_persistence(),
                            RangeWrite {
                                offset: superblock.block_size().offset_of(physical)?,
                                bytes,
                            },
                        )?;
                    }
                    pass.mutation.release_cluster_reference(previous)?;
                    replacement.try_push(fragment(
                        extent,
                        logical,
                        logical.checked_add(1).ok_or(Error::ArithmeticOverflow)?,
                        physical,
                    )?)?;
                }
            }
            tree.replace_extents(replacement)?;
            pass.mutation.stage_extent_tree(&mut raw_inode, tree)?;
            // Physical allocation queries can be followed by raw LCN reads. Journaled payload
            // images must therefore reach their new home addresses before MOVE acknowledges.
            pass.mutation.completion_durability = MutationCompletionDurability::HomeCheckpoint;
            pass.mutation.replace_live_inode(inode_index, raw_inode)
        })
    }
}

/// Converts a logical coordinate through one already authenticated allocated extent.
/// # Errors
/// Returns out-of-extent coordinates or physical-address overflow.
fn physical_at(extent: Extent, logical: u64) -> Result<BlockAddress> {
    if logical < extent.logical_start().as_u64() || logical >= extent.end_logical() {
        return Err(Error::InvalidExtentTree);
    }
    Ok(BlockAddress::new(
        extent
            .physical_start()
            .get()
            .checked_add(
                logical
                    .checked_sub(extent.logical_start().as_u64())
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?,
    ))
}

/// Preserves the zero-read state while constructing an allocated subrange.
/// # Errors
/// Returns logical/physical-coordinate overflow or an invalid extent length.
fn fragment(extent: Extent, start: u64, end: u64, physical: BlockAddress) -> Result<Extent> {
    let logical = LogicalBlock::try_from(start)?;
    let length = ExtentLength::new(
        u16::try_from(end.checked_sub(start).ok_or(Error::ArithmeticOverflow)?)
            .map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    Ok(match extent.initialization() {
        ExtentInitialization::Initialized => Extent::initialized(logical, length, physical),
        ExtentInitialization::Uninitialized => Extent::uninitialized(logical, length, physical),
    })
}
