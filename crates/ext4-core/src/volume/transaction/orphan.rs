//! Bounded orphan metadata mutation using the ordinary allocation and JBD2 serializers.

use super::*;
use crate::disk_format::extent::ExtentTail;
use crate::volume::orphan::{
    OrphanProgress, OrphanRecoveryTarget, OrphanSource, extent_context, read_allocated_inode,
};

/// Conservative payload credits: one data bitmap group, up to five pruned metadata groups,
/// descriptors, inode table, primary superblock, and terminal orphan/xattr/inode-bitmap updates.
pub(in crate::volume) const ORPHAN_METADATA_BUDGET: usize = 32;
/// Maximum data-block references released in one batch, additionally split at group boundaries.
const RELEASE_BLOCK_BUDGET: u64 = 1024;

/// State revealed only after the admitted batch persistence protocol completes.
#[derive(Debug)]
pub(in crate::volume) struct OrphanBatchCompletion {
    /// Journal cursor for a journaled batch; direct home updates have no journal cursor.
    pub(in crate::volume) journal: Option<Journal<CleanJournal>>,
    /// Allocation counts corresponding to checkpointed home metadata.
    pub(in crate::volume) clusters: ClusterReferenceIndex,
    /// Primary metadata including a possibly advanced fallback head.
    pub(in crate::volume) superblock: Superblock,
}

/// Prepares all failure-prone work before a bounded batch issues its first media effect.
/// # Errors
/// Returns validation, allocation, capacity, or suspended-I/O errors without writing anything.
pub(in crate::volume) fn prepare_orphan_batch(
    volume: EpochReadView<'_, '_>,
    target: &OrphanRecoveryTarget,
    journal: Option<&Journal<CleanJournal>>,
) -> Result<(
    StorageRequestSequence<OrphanBatchCompletion>,
    OrphanProgress,
)> {
    let mut mutation = MetadataMutation::begin(
        volume,
        AllocationExclusionSource::Discard(super::super::trim::AllocationExclusions::unreserved()),
    );
    let superblock = mutation.volume.superblock;
    let block_size = superblock.block_size();
    let raw = read_allocated_inode(&mut mutation.volume, target.tracking.inode)?;
    if let OrphanSource::Chain { next } = target.tracking.source
        && (le_u32(raw.bytes(), disk_offset(INODE_DTIME_OFFSET))?
            != next.map_or(0, InodeId::as_u32)
            || superblock.last_orphan() != Some(target.tracking.inode))
    {
        return Err(Error::InvalidOrphanTracking);
    }
    let mut inode = RecoverableOrphanInode::parse(raw)?;
    // Secure retirement contributes complete journaled data images in addition to metadata.
    // One data-reference retirement bounds each batch before journal-credit admission below.
    let release_budget = if inode.raw().flags()?.zero_on_deallocation() {
        1
    } else {
        RELEASE_BLOCK_BUDGET
    };
    let data = inode.data()?;
    let cutoff = match &inode {
        RecoverableOrphanInode::Unlinked(_) => 0,
        RecoverableOrphanInode::Truncating(_) => {
            round_up_div(data.size().bytes(), u64::from(block_size.bytes()))?
        }
    };
    let mut released = Vec::new();
    if let InodeStorage::Extents(root) = data.storage() {
        let tail = ExtentTail::load(
            root,
            block_size,
            &mut mutation.volume.device,
            extent_context(superblock, &data),
        )?;
        if let Some(extent) = tail.last()?
            && extent.end_logical() > cutoff
        {
            let available = extent
                .end_logical()
                .checked_sub(core::cmp::max(cutoff, extent.logical_start().as_u64()))
                .ok_or(Error::InvalidExtentTree)?;
            let last = extent
                .physical_start()
                .get()
                .checked_add(extent.len().as_u64())
                .and_then(|end| end.checked_sub(1))
                .ok_or(Error::ArithmeticOverflow)?;
            let group = ClusterBitmapPosition::from_cluster(
                &superblock,
                superblock.cluster_of_block(BlockAddress::new(last))?,
            )?
            .group();
            for offset in 0..core::cmp::min(available, release_budget) {
                let block =
                    BlockAddress::new(last.checked_sub(offset).ok_or(Error::ArithmeticOverflow)?);
                if ClusterBitmapPosition::from_cluster(
                    &superblock,
                    superblock.cluster_of_block(block)?,
                )?
                .group()
                    != group
                {
                    break;
                }
                released.try_push(block)?;
            }
            let keep = extent
                .len()
                .as_u64()
                .checked_sub(u64::try_from(released.len()).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let (serialized, metadata) =
                tail.trim(u16::try_from(keep).map_err(|_| Error::ArithmeticOverflow)?)?;
            for block in metadata {
                released.try_push(block)?;
            }
            for block in &released {
                if inode.raw().flags()?.zero_on_deallocation() {
                    mutation.protect_zero_retirement(*block)?;
                }
                mutation.release_cluster_reference(*block)?;
            }
            inode
                .raw_mut()
                .set_extent_root_bytes(serialized.inode_root())?;
            for image in serialized.external_blocks() {
                mutation.extent_updates.try_push(BlockImage {
                    block: image.block(),
                    bytes: memory::copied_slice(image.bytes())?,
                })?;
            }
        }
    }
    let progress = if released.is_empty() {
        if let RecoverableOrphanInode::Unlinked(_) = inode {
            mutation.reclaim_inode(inode.raw())?;
        }
        mutation.inode_updates.try_push(inode.finish()?)?;
        OrphanProgress::Complete
    } else {
        let allocation = target.allocation.releasing(superblock, &released)?;
        let encoded = superblock
            .inode_data_encoding()
            .encode_allocation_size(allocation.size(superblock)?)?;
        inode.raw_mut().set_encoded_allocation_size(encoded)?;
        mutation
            .inode_updates
            .try_push(StagedInodeRecord::Recovering(inode))?;
        OrphanProgress::Remaining(allocation)
    };
    let (clusters, mut next_superblock) = mutation.committed_cluster_state()?;
    let mut metadata = mutation.recovery_images()?.into_blocks();
    if matches!(progress, OrphanProgress::Complete) {
        match target.tracking.source {
            OrphanSource::File {
                block,
                slot,
                context,
            } => {
                let image = metadata_image(&mut mutation.volume, &mut metadata, block)?;
                context.remove(image.bytes_mut(), block, slot, target.tracking.inode)?;
            }
            OrphanSource::Chain { next } => {
                let image = metadata_image(
                    &mut mutation.volume,
                    &mut metadata,
                    Superblock::primary_block(block_size),
                )?;
                let offset: usize = if block_size.bytes() == 1024 { 0 } else { 1024 };
                let end = offset.checked_add(1024).ok_or(Error::ArithmeticOverflow)?;
                let raw = image
                    .bytes_mut()
                    .get_mut(offset..end)
                    .ok_or(Error::InvalidSuperblock)?;
                if le_u32(raw, disk_offset(0xe8))? != target.tracking.inode.as_u32() {
                    return Err(Error::InvalidOrphanTracking);
                }
                put_le_u32(raw, disk_offset(0xe8), next.map_or(0, InodeId::as_u32))?;
                Superblock::refresh_checksum(raw)?;
                next_superblock = Superblock::parse_mutable(raw)?;
            }
        }
    }
    if metadata.len() > ORPHAN_METADATA_BUDGET {
        return Err(Error::TransactionTooLarge);
    }
    let sequence = if let Some(journal) = journal {
        let prepared = journal.prepare_commit(
            block_size,
            crate::disk_format::journal::JournalCommitImage::full(metadata),
        )?;
        StorageRequestSequence::checkpoint(prepared, &[], |journal| OrphanBatchCompletion {
            journal: Some(journal),
            clusters,
            superblock: next_superblock,
        })?
    } else {
        StorageRequestSequence::home_updates(
            metadata,
            block_size,
            OrphanBatchCompletion {
                journal: None,
                clusters,
                superblock: next_superblock,
            },
        )?
    };
    Ok((sequence, progress))
}

/// Coalesces a tracker edit with any already staged inode/group/superblock image.
/// # Errors
/// Returns a read, allocation, or invalid metadata index error.
fn metadata_image<'a>(
    volume: &mut EpochReadView<'_, '_>,
    metadata: &'a mut Vec<JournalBlock>,
    block: BlockAddress,
) -> Result<&'a mut JournalBlock> {
    let index = match metadata.iter().position(|image| image.block() == block) {
        Some(index) => index,
        None => {
            let block_size = volume.superblock.block_size();
            let mut bytes = memory::repeated_vec(
                0,
                usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            volume
                .device
                .read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
            metadata.try_push(JournalBlock::new(block, bytes))?;
            metadata
                .len()
                .checked_sub(1)
                .ok_or(Error::ArithmeticOverflow)?
        }
    };
    metadata.get_mut(index).ok_or(Error::InvalidOrphanTracking)
}
