//! Primary block images used to persist write-session markers.

use alloc::vec::Vec;

use super::transaction::StorageRequestSequence;
use crate::disk::block::BlockSize;
use crate::disk::storage::{OperationDevice, StorageTarget};
use crate::disk_format::journal::{CleanJournal, Journal, JournalBlock};
use crate::disk_format::superblock::Superblock;
use crate::memory::{self, FallibleVec};
use crate::{Error, Result};

/// Prepares a complete primary block while retaining bytes outside the superblock payload.
/// All log/checkpoint requests are allocated before the first effect; journal replay is the
/// sole repair authority for a torn home image, including its clocks and checksum.
/// Keep checkpoint construction out of the executor's frame so journal serialization scratch
/// is present only while this phase runs.
/// # Errors
/// Returns source-read suspension, invalid coordinates, serialization or allocation failure.
#[inline(never)]
pub(super) fn prepare_session_checkpoint(
    device: &mut OperationDevice<'_>,
    raw: &[u8; 1024],
    block_size: BlockSize,
    journal: &Journal<CleanJournal>,
    flush_before: &[StorageTarget],
) -> Result<StorageRequestSequence<Journal<CleanJournal>>> {
    let blocks = prepare_primary_images(device, raw, block_size)?;
    let prepared = journal.prepare_commit(
        block_size,
        crate::disk_format::journal::JournalCommitImage::full(blocks),
    )?;
    StorageRequestSequence::checkpoint(prepared, flush_before, |journal| journal)
}

/// Retains bytes outside the primary payload in its complete home-block image.
/// # Errors
/// Returns source suspension, range or allocation failure before submission.
pub(super) fn prepare_primary_images(
    device: &mut OperationDevice<'_>,
    raw: &[u8; 1024],
    block_size: BlockSize,
) -> Result<Vec<JournalBlock>> {
    let block = Superblock::primary_block(block_size);
    let mut bytes = memory::repeated_vec(
        0,
        usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    device.read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
    let offset = usize::try_from(
        1024_u64
            .checked_sub(block_size.offset_of(block)?.get())
            .ok_or(Error::InvalidSuperblock)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)?;
    memory::copy_exact(
        bytes
            .get_mut(offset..offset.checked_add(1024).ok_or(Error::ArithmeticOverflow)?)
            .ok_or(Error::InvalidSuperblock)?,
        raw,
    )?;
    let mut blocks = Vec::new();
    blocks.try_push(JournalBlock::new(block, bytes))?;
    Ok(blocks)
}
