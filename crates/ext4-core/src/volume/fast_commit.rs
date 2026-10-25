//! Delta postconditions resolve completely before a full-journal conversion touches home blocks.

use super::metadata_image::MetadataImages;
use super::scope::*;
use super::transaction::StorageRequestSequence;
use crate::disk_format::journal::{DeltaRecoverySeed, fast_commit::ParsedDelta};

/// Resolves metadata-only postconditions; unsupported ownership changes never produce writes.
/// # Errors
/// Returns suspended I/O, allocation, target-layout or unsupported semantic replay failure.
pub(super) fn resolve(
    volume: &mut EpochReadView<'_, '_>,
    seed: &DeltaRecoverySeed,
) -> Result<Vec<JournalBlock>> {
    seed.require_filesystem(&volume.superblock)?;
    let mut images = MetadataImages::new(volume.superblock.block_size());
    let records = seed.program().records();
    for (index, record) in records.iter().enumerate() {
        let ParsedDelta::Inode { inode, encoded } = record else {
            return Err(Error::UnsupportedJournal);
        };
        // Only the final metadata image is a postcondition; earlier versions have no independent effect.
        if records
            .get(index.checked_add(1).ok_or(Error::ArithmeticOverflow)?..)
            .ok_or(Error::JournalCorrupt)?
            .iter()
            .any(|later| matches!(later, ParsedDelta::Inode { inode: other, .. } if other == inode))
        {
            continue;
        }
        let live = volume
            .read_live_inode_record(*inode)?
            .apply_metadata_delta(encoded)?;
        let mut staged = StagedInodeRecord::Live(live);
        staged.refresh_checksum(&volume.superblock)?;
        images.patch(volume, staged.offset(), staged.bytes())?;
    }
    Ok(images.into_blocks())
}

/// The complete conversion and checkpoint sequence is allocated before the first write.
/// Its full commit invalidates this delta TID only after a durable replacement exists.
/// # Errors
/// Returns journal capacity, allocation or serialization failure without sending any request.
pub(super) fn prepare(
    seed: DeltaRecoverySeed,
    size: BlockSize,
    blocks: Vec<JournalBlock>,
) -> Result<StorageRequestSequence<Journal<CleanJournal>>> {
    let prepared = seed.prepare_commit(size, blocks)?;
    StorageRequestSequence::checkpoint(prepared, |journal| journal)
}
