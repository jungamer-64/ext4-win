//! JBD2 journal loading, replay, checkpointing, and commit construction.
//!
//! The journal code is modeled as typestates: loaded journals must be replayed
//! into a clean state before write transactions can commit, dirty transactions
//! must become durable before checkpoint, and checkpointed transactions can then
//! advance the superblock tail. This keeps crash-ordering rules out of ad hoc
//! booleans in the volume layer.

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use crate::disk::block::{BlockAddress, BlockReader, BlockSize, BlockWriter, ByteOffset};
use crate::disk::checksum::crc32c;
use crate::disk::endian::{DiskOffset, be_u16, be_u32, be_u64, put_be_u16, put_be_u32};
use crate::disk_format::extent::{ExtentTree, ExtentTreeContext};
use crate::disk_format::inode::Inode;
use crate::disk_format::superblock::RecoveryState;
use crate::error::{Error, Result};
use crate::volume::MetadataBlock;

// Common JBD2 block header fields. JBD2 stores its control structures big-endian.
/// Magic value that prefixes every JBD2 control block.
const JBD2_MAGIC: u32 = 0xC03B_3998;
/// JBD2 block type for transaction descriptors.
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
/// JBD2 block type for transaction commits.
const JBD2_COMMIT_BLOCK: u32 = 2;
/// JBD2 block type for v1 journal superblocks.
const JBD2_SUPERBLOCK_V1: u32 = 3;
/// JBD2 block type for v2 journal superblocks.
const JBD2_SUPERBLOCK_V2: u32 = 4;
/// JBD2 block type for revoke records.
const JBD2_REVOKE_BLOCK: u32 = 5;

/// Builds a JBD2 control-structure field offset.
const fn disk_offset(offset: usize) -> DiskOffset {
    DiskOffset::new(offset)
}

// Incompatible feature bits are validated before replay because unsupported
// features can change transaction interpretation.
/// Incompatible feature bit for revoke records.
const JBD2_FEATURE_INCOMPAT_REVOKE: u32 = 0x0001;
/// Incompatible feature bit for 64-bit journal block tags.
const JBD2_FEATURE_INCOMPAT_64BIT: u32 = 0x0002;
/// Incompatible feature bit for asynchronous commit checksums.
const JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT: u32 = 0x0004;
/// Incompatible feature bit for v2 journal checksums.
const JBD2_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x0008;
/// Incompatible feature bit for v3 journal checksums.
const JBD2_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x0010;
/// Incompatible feature bit for fast commit areas.
const JBD2_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0020;
/// JBD2 incompatible feature mask supported by replay and commit.
const JBD2_SUPPORTED_INCOMPAT: u32 = JBD2_FEATURE_INCOMPAT_REVOKE
    | JBD2_FEATURE_INCOMPAT_64BIT
    | JBD2_FEATURE_INCOMPAT_CSUM_V2
    | JBD2_FEATURE_INCOMPAT_CSUM_V3;

// Descriptor tag flags define how following payload blocks are decoded.
/// Descriptor tag flag for escaped data blocks that begin with the JBD2 magic.
const JBD2_TAG_FLAG_ESCAPE: u32 = 0x0001;
/// Descriptor tag flag omitting the repeated filesystem UUID.
const JBD2_TAG_FLAG_SAME_UUID: u32 = 0x0002;
/// Descriptor tag flag marking the following payload block as deleted.
const JBD2_TAG_FLAG_DELETED: u32 = 0x0004;
/// Descriptor tag flag marking the final tag in a descriptor block.
const JBD2_TAG_FLAG_LAST_TAG: u32 = 0x0008;

// JBD2 checksum and layout constants used by both replay and new commits.
/// JBD2 checksum type value for CRC32C.
const JBD2_CHECKSUM_CRC32C: u8 = 4;
/// Bytes occupied by the common JBD2 control block header.
const JOURNAL_HEADER_BYTES: usize = 12;
/// Bytes occupied by the JBD2 superblock payload.
const JOURNAL_SUPERBLOCK_BYTES: usize = 1024;
/// Byte offset of an external journal superblock on its journal device.
const JOURNAL_EXTERNAL_SUPERBLOCK_OFFSET: u64 = 2048;
/// External journal blocks reserved before usable log space.
const JOURNAL_OVERHEAD_BLOCKS: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
/// JBD2 journal with typestate-tracked replay and commit phases.
pub(crate) struct Journal<State = CleanJournal> {
    /// Physical location of the journal blocks.
    location: JournalLocation,
    /// Parsed journal superblock kept as the mutable journal metadata source.
    superblock: JournalSuperblock,
    /// Validated circular log range inside the journal device.
    ring: JournalRing,
    /// Filesystem block count used to reject journal entries outside the volume.
    filesystem_blocks: u64,
    /// Typestate marker for loaded, clean, dirty, or checkpointed journal state.
    state: PhantomData<State>,
}

/// Journal loaded from disk but not yet replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LoadedJournal;

/// Journal whose committed transactions have been checkpointed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CleanJournal;

/// Journal after descriptor/data/commit blocks have been durably written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirtyJournal;

/// Journal after transaction home blocks have been checkpointed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CheckpointedJournal;

/// Wrapping JBD2 transaction sequence number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalSequence(u32);

impl JournalSequence {
    /// Creates a sequence number from an on-disk or freshly allocated value.
    const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw sequence number for block encoding.
    const fn get(self) -> u32 {
        self.0
    }

    /// Returns the next sequence with JBD2 wrapping semantics.
    const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Compares two wrapping sequence numbers using half-range ordering.
    const fn is_after(self, other: Self) -> bool {
        let distance = self.0.wrapping_sub(other.0);
        distance != 0 && distance < 0x8000_0000
    }
}

impl<State> Journal<State> {
    /// Rebuilds the same journal data with a different typestate marker.
    fn clone_without_state<Next>(&self) -> Journal<Next> {
        Journal {
            location: self.location.clone(),
            superblock: self.superblock.clone(),
            ring: self.ring,
            filesystem_blocks: self.filesystem_blocks,
            state: PhantomData,
        }
    }

    /// Loads an internal journal stored in the filesystem journal inode.
    pub(crate) fn from_inode(
        inode: &Inode,
        block_size: BlockSize,
        filesystem_blocks: u64,
        reader: &impl BlockReader,
    ) -> Result<Journal<LoadedJournal>> {
        if inode.size().bytes() == 0 || block_size.bytes() == 0 {
            return Err(Error::UnsupportedJournal);
        }
        let capacity_blocks = inode
            .size()
            .bytes()
            .checked_div(u64::from(block_size.bytes()))
            .ok_or(Error::ArithmeticOverflow)?;
        let capacity_blocks =
            u32::try_from(capacity_blocks).map_err(|_| Error::UnsupportedJournal)?;
        if capacity_blocks <= JOURNAL_OVERHEAD_BLOCKS {
            return Err(Error::UnsupportedJournal);
        }

        let tree = ExtentTree::load_inode_tree(
            inode.extent_root()?,
            block_size,
            reader,
            ExtentTreeContext::none(),
        )?;
        let location =
            JournalLocation::Internal(InternalJournalLayout::new(tree.extents(), capacity_blocks)?);
        let mut raw =
            vec![0_u8; usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?];
        read_journal_block(reader, &location, block_size, 0, &mut raw)?;
        let superblock = JournalSuperblock::parse(&raw)?;
        let ring = superblock.validate_for_mount(block_size, capacity_blocks)?;
        location.validate_ring(&ring)?;

        Ok(Journal {
            location,
            superblock,
            ring,
            filesystem_blocks,
            state: PhantomData,
        })
    }

    /// Loads an external journal device and validates its filesystem UUID.
    pub(crate) fn from_external_device(
        journal: &impl BlockReader,
        block_size: BlockSize,
        expected_uuid: [u8; 16],
        filesystem_blocks: u64,
    ) -> Result<Journal<LoadedJournal>> {
        let mut raw =
            vec![0_u8; usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?];
        journal.read_exact_at(
            ByteOffset::new(JOURNAL_EXTERNAL_SUPERBLOCK_OFFSET),
            &mut raw,
        )?;
        let superblock = JournalSuperblock::parse(&raw)?;
        if *superblock.uuid() != expected_uuid {
            return Err(Error::UnsupportedJournal);
        }
        let location = JournalLocation::External(ExternalJournalLayout::new(journal, block_size)?);
        let ring = superblock.validate_for_mount(block_size, location.capacity_blocks())?;
        location.validate_ring(&ring)?;
        Ok(Journal {
            location,
            superblock,
            ring,
            filesystem_blocks,
            state: PhantomData,
        })
    }

    /// Verifies that one metadata transaction can fit in the usable log window.
    pub(crate) fn ensure_transaction_capacity(&self, metadata_blocks: usize) -> Result<()> {
        if metadata_blocks > self.descriptor_tag_capacity()? {
            return Err(Error::TransactionTooLarge);
        }
        let required = u32::try_from(metadata_blocks)
            .map_err(|_| Error::TransactionTooLarge)?
            .checked_add(JOURNAL_OVERHEAD_BLOCKS)
            .ok_or(Error::TransactionTooLarge)?;
        if required > self.usable_log_blocks()? {
            Err(Error::TransactionTooLarge)
        } else {
            Ok(())
        }
    }

    /// Replays and checkpoints an internal journal through the filesystem device.
    pub(crate) fn replay_and_checkpoint_internal(
        mut self,
        filesystem: &mut impl BlockWriter,
        block_size: BlockSize,
        recovery_state: RecoveryState,
    ) -> Result<Journal<CleanJournal>> {
        let mut io = InternalJournalIo { device: filesystem };
        self.replay_and_checkpoint(&mut io, block_size, recovery_state)
    }

    /// Replays and checkpoints an external journal through separate I/O targets.
    pub(crate) fn replay_and_checkpoint_external(
        mut self,
        filesystem: &mut impl BlockWriter,
        journal: &mut impl BlockWriter,
        block_size: BlockSize,
        recovery_state: RecoveryState,
    ) -> Result<Journal<CleanJournal>> {
        let mut io = ExternalJournalIo {
            filesystem,
            journal,
        };
        self.replay_and_checkpoint(&mut io, block_size, recovery_state)
    }

    /// Commits metadata blocks through an internal journal.
    pub(crate) fn commit_internal(
        &mut self,
        filesystem: &mut impl BlockWriter,
        block_size: BlockSize,
        metadata_blocks: &[MetadataBlock],
    ) -> Result<()> {
        let mut io = InternalJournalIo { device: filesystem };
        self.commit_metadata_transaction(&mut io, block_size, metadata_blocks)
    }

    /// Commits metadata blocks through an external journal.
    pub(crate) fn commit_external(
        &mut self,
        filesystem: &mut impl BlockWriter,
        journal: &mut impl BlockWriter,
        block_size: BlockSize,
        metadata_blocks: &[MetadataBlock],
    ) -> Result<()> {
        let mut io = ExternalJournalIo {
            filesystem,
            journal,
        };
        self.commit_metadata_transaction(&mut io, block_size, metadata_blocks)
    }

    /// Replays committed transactions and advances the journal to a clean state.
    fn replay_and_checkpoint(
        &mut self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        recovery_state: RecoveryState,
    ) -> Result<Journal<CleanJournal>> {
        if recovery_state == RecoveryState::NeedsRecovery && self.superblock.start() == 0 {
            return Err(Error::JournalCorrupt);
        }
        let scan = self.committed_transactions(io, block_size)?;
        if scan.tail == JournalScanTail::CleanSuperblock {
            return Ok(self.clone_without_state());
        }
        if scan.transactions.is_empty() {
            self.mark_clean(io, block_size, self.superblock.sequence())?;
            return Ok(self.clone_without_state());
        }

        let mut revokes = Vec::new();
        for transaction in &scan.transactions {
            for (order, event) in transaction.events.iter().enumerate() {
                if let JournalTransactionEvent::Revoke(block) = event {
                    revokes.push(RevokedBlock {
                        sequence: transaction.sequence,
                        order,
                        block: *block,
                    });
                }
            }
        }

        let mut next_sequence = self.superblock.sequence();
        for transaction in &scan.transactions {
            next_sequence = transaction.sequence.next();
            for (order, event) in transaction.events.iter().enumerate() {
                if let JournalTransactionEvent::Entry(entry) = event {
                    if is_revoked_after(&revokes, entry.home, transaction.sequence, order) {
                        continue;
                    }
                    io.write_home_block(block_size, entry.home, &entry.bytes)?;
                }
            }
        }
        io.flush_all()?;
        self.mark_clean(io, block_size, next_sequence)?;
        Ok(self.clone_without_state())
    }

    /// Writes, checkpoints, and cleans one metadata transaction.
    fn commit_metadata_transaction(
        &mut self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        metadata_blocks: &[MetadataBlock],
    ) -> Result<()> {
        if self.superblock.start() != 0 {
            return Err(Error::JournalCorrupt);
        }
        let prepared = self.prepare_metadata_transaction(block_size, metadata_blocks)?;
        let durable = self.write_prepared_transaction(io, block_size, prepared)?;
        let checkpointed =
            self.checkpoint_durable_transaction(io, block_size, metadata_blocks, durable)?;
        self.clean_checkpointed_transaction(io, block_size, checkpointed)
    }

    /// Persists descriptor, data, and commit blocks in crash-safe order.
    fn write_prepared_transaction(
        &mut self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        prepared: PreparedJournalTransaction,
    ) -> Result<JournalDurableTransaction> {
        let mut cursor = prepared.descriptor;
        let dirty_superblock =
            self.superblock
                .encode_dirty(block_size, prepared.descriptor, prepared.sequence)?;
        io.write_journal_block(self, block_size, 0, &dirty_superblock)?;
        self.superblock
            .apply_dirty(prepared.descriptor, prepared.sequence, dirty_superblock);

        io.write_journal_block(self, block_size, cursor, &prepared.descriptor_block)?;
        cursor = self.next_logical(cursor)?;

        for data in &prepared.data_blocks {
            io.write_journal_block(self, block_size, cursor, data)?;
            cursor = self.next_logical(cursor)?;
        }
        io.flush_all()?;

        io.write_journal_block(self, block_size, cursor, &prepared.commit_block)?;
        io.flush_all()?;

        Ok(JournalDurableTransaction {
            next_sequence: prepared.next_sequence,
            state: PhantomData,
        })
    }

    /// Copies durable journal payloads back to their home filesystem blocks.
    fn checkpoint_durable_transaction(
        &mut self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        metadata_blocks: &[MetadataBlock],
        durable: JournalDurableTransaction,
    ) -> Result<CheckpointedJournalTransaction> {
        for metadata in metadata_blocks {
            io.write_home_block(block_size, metadata.block(), metadata.bytes())?;
        }
        io.flush_all()?;
        Ok(CheckpointedJournalTransaction {
            next_sequence: durable.next_sequence,
            state: PhantomData,
        })
    }

    /// Marks a checkpointed transaction clean in the journal superblock.
    fn clean_checkpointed_transaction(
        &mut self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        checkpointed: CheckpointedJournalTransaction,
    ) -> Result<()> {
        self.mark_clean(io, block_size, checkpointed.next_sequence)?;
        Ok(())
    }

    /// Builds descriptor, escaped data blocks, and commit block for a transaction.
    fn prepare_metadata_transaction(
        &self,
        block_size: BlockSize,
        metadata_blocks: &[MetadataBlock],
    ) -> Result<PreparedJournalTransaction> {
        self.ensure_transaction_capacity(metadata_blocks.len())?;
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let mut data_blocks = Vec::with_capacity(metadata_blocks.len());
        for metadata in metadata_blocks {
            if metadata.bytes().len() != block_bytes {
                return Err(Error::InvalidWriteRange);
            }
            let mut data = metadata.bytes().to_vec();
            if starts_with_jbd2_magic(&data) {
                put_be_u32(&mut data, disk_offset(0), 0)?;
            }
            data_blocks.push(data);
        }

        let sequence = self.superblock.sequence();
        let descriptor = self.superblock.first();
        Ok(PreparedJournalTransaction {
            sequence,
            next_sequence: sequence.next(),
            descriptor,
            descriptor_block: self.encode_descriptor_block(
                sequence,
                metadata_blocks,
                &data_blocks,
                block_size,
            )?,
            data_blocks,
            commit_block: self.encode_commit_block(sequence, block_size)?,
        })
    }

    /// Scans the journal ring for complete committed transactions.
    fn committed_transactions(
        &self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
    ) -> Result<JournalReplayScan> {
        if self.superblock.start() == 0 {
            return Ok(JournalReplayScan {
                transactions: Vec::new(),
                tail: JournalScanTail::CleanSuperblock,
            });
        }

        let mut transactions = Vec::new();
        let mut cursor = self.superblock.start();
        let mut sequence = self.superblock.sequence();
        let mut consumed = 0_u32;
        while consumed < self.usable_log_blocks()? {
            match self.parse_transaction(io, block_size, cursor, sequence)? {
                JournalTransactionScan::Committed {
                    transaction,
                    next_cursor,
                    consumed: transaction_blocks,
                } => {
                    transactions.push(transaction);
                    cursor = next_cursor;
                    sequence = sequence.next();
                    consumed = consumed
                        .checked_add(transaction_blocks)
                        .ok_or(Error::ArithmeticOverflow)?;
                }
                JournalTransactionScan::IncompleteTail => {
                    return Ok(JournalReplayScan {
                        transactions,
                        tail: JournalScanTail::IncompleteTail,
                    });
                }
                JournalTransactionScan::EndOfLog => {
                    if transactions.is_empty() {
                        return Err(Error::JournalCorrupt);
                    }
                    return Ok(JournalReplayScan {
                        transactions,
                        tail: JournalScanTail::EndOfLog,
                    });
                }
            }
        }
        Ok(JournalReplayScan {
            transactions,
            tail: JournalScanTail::EndOfLog,
        })
    }

    /// Parses one transaction starting at the supplied logical journal block.
    fn parse_transaction(
        &self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        start: u32,
        sequence: JournalSequence,
    ) -> Result<JournalTransactionScan> {
        let mut transaction = JournalTransaction {
            sequence,
            events: Vec::new(),
        };
        let mut cursor = start;
        let mut consumed = 0_u32;
        let mut descriptor_seen = false;

        while consumed < self.usable_log_blocks()? {
            let block = self.read_journal_block(io, block_size, cursor)?;
            let Ok(header) = Jbd2Header::parse(&block) else {
                return Ok(transaction_tail(consumed));
            };
            if header.sequence() != sequence.get() {
                if consumed == 0 {
                    return Ok(JournalTransactionScan::EndOfLog);
                }
                return Err(Error::JournalCorrupt);
            }

            match header.block_type() {
                JBD2_DESCRIPTOR_BLOCK => {
                    if descriptor_seen {
                        return Err(Error::UnsupportedJournal);
                    }
                    descriptor_seen = true;
                    let descriptor = self.parse_descriptor_block(&block)?;
                    cursor = self.next_logical(cursor)?;
                    consumed = consumed.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                    for tag in descriptor.tags {
                        let mut data = self.read_journal_block(io, block_size, cursor)?;
                        if tag.flags & JBD2_TAG_FLAG_DELETED == 0 {
                            self.verify_tag_checksum(sequence, &tag, &data)?;
                            if tag.flags & JBD2_TAG_FLAG_ESCAPE != 0 {
                                if be_u32(&data, disk_offset(0))? != 0 {
                                    return Err(Error::JournalCorrupt);
                                }
                                put_be_u32(&mut data, disk_offset(0), JBD2_MAGIC)?;
                            }
                            self.validate_replay_target(tag.block)?;
                            if transaction.events.iter().any(|event| {
                                matches!(event, JournalTransactionEvent::Entry(entry) if entry.home == tag.block)
                            }) {
                                return Err(Error::JournalCorrupt);
                            }
                            transaction
                                .events
                                .push(JournalTransactionEvent::Entry(JournalEntry {
                                    home: tag.block,
                                    bytes: data,
                                }));
                        }
                        cursor = self.next_logical(cursor)?;
                        consumed = consumed.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                    }
                }
                JBD2_REVOKE_BLOCK => {
                    let revoke = self.parse_revoke_block(&block)?;
                    for block in revoke.blocks {
                        transaction
                            .events
                            .push(JournalTransactionEvent::Revoke(block));
                    }
                    cursor = self.next_logical(cursor)?;
                    consumed = consumed.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                }
                JBD2_COMMIT_BLOCK => {
                    if transaction.events.is_empty() {
                        return Err(Error::JournalCorrupt);
                    }
                    self.parse_commit_block(&block, sequence)?;
                    return Ok(JournalTransactionScan::Committed {
                        transaction,
                        next_cursor: self.next_logical(cursor)?,
                        consumed: consumed.checked_add(1).ok_or(Error::ArithmeticOverflow)?,
                    });
                }
                _ => {
                    if consumed == 0 {
                        return Ok(JournalTransactionScan::EndOfLog);
                    }
                    return Err(Error::UnsupportedJournal);
                }
            }
        }

        Ok(JournalTransactionScan::IncompleteTail)
    }

    /// Reads one logical journal block into an owned buffer.
    fn read_journal_block(
        &self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        logical: u32,
    ) -> Result<Vec<u8>> {
        let mut block =
            vec![0_u8; usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?];
        io.read_journal_block(self, block_size, logical, &mut block)?;
        Ok(block)
    }

    /// Rejects replay targets outside the filesystem or inside the internal journal.
    fn validate_replay_target(&self, block: BlockAddress) -> Result<()> {
        if block.get() >= self.filesystem_blocks {
            return Err(Error::JournalCorrupt);
        }
        if self.location.contains_home_block(block)? {
            return Err(Error::JournalCorrupt);
        }
        Ok(())
    }

    /// Parses descriptor tags from a JBD2 descriptor block.
    fn parse_descriptor_block(&self, block: &[u8]) -> Result<JournalDescriptor> {
        self.verify_block_tail_checksum(block)?;
        let mut offset = JOURNAL_HEADER_BYTES;
        let limit = if self.superblock.has_metadata_checksums() {
            block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?
        } else {
            block.len()
        };
        let mut tags = Vec::new();
        let mut saw_last = false;
        while offset < limit {
            let Some((tag, next_offset)) = self.parse_tag(block, offset, limit)? else {
                return Err(Error::JournalCorrupt);
            };
            let last = tag.flags & JBD2_TAG_FLAG_LAST_TAG != 0;
            tags.push(tag);
            offset = next_offset;
            if last {
                saw_last = true;
                break;
            }
        }
        if tags.is_empty() || !saw_last {
            return Err(Error::JournalCorrupt);
        }
        Ok(JournalDescriptor { tags })
    }

    /// Parses one descriptor tag and returns the next tag offset.
    fn parse_tag(
        &self,
        block: &[u8],
        offset: usize,
        limit: usize,
    ) -> Result<Option<(JournalTag, usize)>> {
        if self.superblock.has_csum_v3() {
            let base_size = 16_usize;
            if offset
                .checked_add(base_size)
                .ok_or(Error::ArithmeticOverflow)?
                > limit
            {
                return Ok(None);
            }
            let block_low = u64::from(be_u32(block, disk_offset(offset))?);
            let flags = be_u32(block, disk_offset(offset).checked_add_bytes(4)?)?;
            let block_high = u64::from(be_u32(block, disk_offset(offset).checked_add_bytes(8)?)?);
            let checksum = be_u32(block, disk_offset(offset).checked_add_bytes(12)?)?;
            if block_low == 0 && block_high == 0 && flags == 0 && checksum == 0 {
                return Ok(None);
            }
            validate_tag_flags(flags)?;
            let uuid_size = if flags & JBD2_TAG_FLAG_SAME_UUID == 0 {
                16
            } else {
                0
            };
            let next = offset
                .checked_add(base_size)
                .and_then(|value| value.checked_add(uuid_size))
                .ok_or(Error::ArithmeticOverflow)?;
            if next > limit {
                return Err(Error::JournalCorrupt);
            }
            if uuid_size == 16 {
                let uuid = block
                    .get(
                        offset
                            .checked_add(base_size)
                            .ok_or(Error::ArithmeticOverflow)?..next,
                    )
                    .ok_or(Error::TruncatedStructure)?;
                if uuid != self.superblock.uuid() {
                    return Err(Error::JournalCorrupt);
                }
            }
            return Ok(Some((
                JournalTag {
                    block: BlockAddress::new((block_high << 32) | block_low),
                    flags,
                    checksum,
                },
                next,
            )));
        }

        let base_size = 8_usize;
        if offset
            .checked_add(base_size)
            .ok_or(Error::ArithmeticOverflow)?
            > limit
        {
            return Ok(None);
        }
        let block_low = u64::from(be_u32(block, disk_offset(offset))?);
        let checksum = u32::from(be_u16(block, disk_offset(offset).checked_add_bytes(4)?)?);
        let flags = u32::from(be_u16(block, disk_offset(offset).checked_add_bytes(6)?)?);
        if block_low == 0 && flags == 0 && checksum == 0 {
            return Ok(None);
        }
        validate_tag_flags(flags)?;
        let high_size = if self.superblock.has_64bit() { 4 } else { 0 };
        let block_high = if high_size == 4 {
            u64::from(be_u32(block, disk_offset(offset).checked_add_bytes(8)?)?)
        } else {
            0
        };
        let uuid_size = if flags & JBD2_TAG_FLAG_SAME_UUID == 0 {
            16
        } else {
            0
        };
        let next = offset
            .checked_add(base_size)
            .and_then(|value| value.checked_add(high_size))
            .and_then(|value| value.checked_add(uuid_size))
            .ok_or(Error::ArithmeticOverflow)?;
        if next > limit {
            return Err(Error::JournalCorrupt);
        }
        if uuid_size == 16 {
            let uuid_start = offset
                .checked_add(base_size)
                .and_then(|value| value.checked_add(high_size))
                .ok_or(Error::ArithmeticOverflow)?;
            let uuid = block
                .get(uuid_start..next)
                .ok_or(Error::TruncatedStructure)?;
            if uuid != self.superblock.uuid() {
                return Err(Error::JournalCorrupt);
            }
        }
        Ok(Some((
            JournalTag {
                block: BlockAddress::new((block_high << 32) | block_low),
                flags,
                checksum,
            },
            next,
        )))
    }

    /// Parses a revoke block into the home blocks it cancels.
    fn parse_revoke_block(&self, block: &[u8]) -> Result<JournalRevoke> {
        self.verify_block_tail_checksum(block)?;
        let used = usize::try_from(be_u32(block, disk_offset(JOURNAL_HEADER_BYTES))?)
            .map_err(|_| Error::JournalCorrupt)?;
        if used < 16 || used > block.len() {
            return Err(Error::JournalCorrupt);
        }
        let tail = if self.superblock.has_metadata_checksums() {
            4
        } else {
            0
        };
        let limit = used.checked_sub(tail).ok_or(Error::JournalCorrupt)?;
        let entry_size = if self.superblock.has_64bit() { 8 } else { 4 };
        let mut offset = 16_usize;
        let mut blocks = Vec::new();
        while offset
            .checked_add(entry_size)
            .ok_or(Error::ArithmeticOverflow)?
            <= limit
        {
            let block = if entry_size == 8 {
                be_u64(block, disk_offset(offset))?
            } else {
                u64::from(be_u32(block, disk_offset(offset))?)
            };
            blocks.push(BlockAddress::new(block));
            offset = offset
                .checked_add(entry_size)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        if offset != limit {
            return Err(Error::JournalCorrupt);
        }
        Ok(JournalRevoke { blocks })
    }

    /// Validates a commit block for the expected transaction sequence.
    fn parse_commit_block(
        &self,
        block: &[u8],
        expected_sequence: JournalSequence,
    ) -> Result<JournalCommit> {
        let header = Jbd2Header::parse(block)?;
        if header.block_type() != JBD2_COMMIT_BLOCK {
            return Err(Error::JournalCorrupt);
        }
        if header.sequence() != expected_sequence.get() {
            return Err(Error::JournalCorrupt);
        }
        if self.superblock.has_metadata_checksums() {
            if *block.get(0x0C).ok_or(Error::TruncatedStructure)? != JBD2_CHECKSUM_CRC32C
                || *block.get(0x0D).ok_or(Error::TruncatedStructure)? != 4
                || *block.get(0x0E).ok_or(Error::TruncatedStructure)? != 0
                || *block.get(0x0F).ok_or(Error::TruncatedStructure)? != 0
            {
                return Err(Error::JournalCorrupt);
            }
            self.verify_commit_checksum(block)?;
        }
        Ok(JournalCommit {
            sequence: JournalSequence::new(header.sequence()),
        })
    }

    /// Encodes descriptor tags for the metadata blocks in a new transaction.
    fn encode_descriptor_block(
        &self,
        sequence: JournalSequence,
        metadata_blocks: &[MetadataBlock],
        data_blocks: &[Vec<u8>],
        block_size: BlockSize,
    ) -> Result<Vec<u8>> {
        let mut block =
            vec![0_u8; usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?];
        Jbd2Header::descriptor(sequence.get()).encode(&mut block)?;
        let mut offset = JOURNAL_HEADER_BYTES;
        for (index, metadata) in metadata_blocks.iter().enumerate() {
            let last =
                index.checked_add(1).ok_or(Error::ArithmeticOverflow)? == metadata_blocks.len();
            let data = data_blocks.get(index).ok_or(Error::InvalidWriteRange)?;
            let flags = JBD2_TAG_FLAG_SAME_UUID
                | if last { JBD2_TAG_FLAG_LAST_TAG } else { 0 }
                | if starts_with_jbd2_magic(metadata.bytes()) {
                    JBD2_TAG_FLAG_ESCAPE
                } else {
                    0
                };
            offset = self.encode_tag(&mut block, offset, sequence, metadata, data, flags)?;
        }
        self.write_block_tail_checksum(&mut block)?;
        Ok(block)
    }

    /// Encodes one descriptor tag using the active JBD2 tag format.
    fn encode_tag(
        &self,
        block: &mut [u8],
        offset: usize,
        sequence: JournalSequence,
        metadata: &MetadataBlock,
        data: &[u8],
        flags: u32,
    ) -> Result<usize> {
        let checksum = self.tag_checksum(sequence, data)?;
        if self.superblock.has_csum_v3() {
            let next = offset.checked_add(16).ok_or(Error::ArithmeticOverflow)?;
            if next > self.descriptor_payload_limit(block.len())? {
                return Err(Error::TransactionTooLarge);
            }
            put_be_u32(
                block,
                disk_offset(offset),
                u32::try_from(metadata.block().get() & u64::from(u32::MAX))
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            put_be_u32(block, disk_offset(offset).checked_add_bytes(4)?, flags)?;
            put_be_u32(
                block,
                disk_offset(offset).checked_add_bytes(8)?,
                u32::try_from(metadata.block().get() >> 32)
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            put_be_u32(block, disk_offset(offset).checked_add_bytes(12)?, checksum)?;
            return Ok(next);
        }

        let high_size = if self.superblock.has_64bit() { 4 } else { 0 };
        let next = offset
            .checked_add(8)
            .and_then(|value| value.checked_add(high_size))
            .ok_or(Error::ArithmeticOverflow)?;
        if next > self.descriptor_payload_limit(block.len())? {
            return Err(Error::TransactionTooLarge);
        }
        put_be_u32(
            block,
            disk_offset(offset),
            u32::try_from(metadata.block().get() & u64::from(u32::MAX))
                .map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_be_u16(
            block,
            disk_offset(offset).checked_add_bytes(4)?,
            u16::try_from(checksum & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_be_u16(
            block,
            disk_offset(offset).checked_add_bytes(6)?,
            u16::try_from(flags).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if high_size == 4 {
            put_be_u32(
                block,
                disk_offset(offset).checked_add_bytes(8)?,
                u32::try_from(metadata.block().get() >> 32)
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(next)
    }

    /// Encodes the commit block that makes a transaction durable.
    fn encode_commit_block(
        &self,
        sequence: JournalSequence,
        block_size: BlockSize,
    ) -> Result<Vec<u8>> {
        let mut block =
            vec![0_u8; usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?];
        Jbd2Header::commit(sequence.get()).encode(&mut block)?;
        if self.superblock.has_metadata_checksums() {
            *block.get_mut(0x0C).ok_or(Error::TruncatedStructure)? = JBD2_CHECKSUM_CRC32C;
            *block.get_mut(0x0D).ok_or(Error::TruncatedStructure)? = 4;
            let checksum = self.block_checksum_with_zeroed(&block, 0x10)?;
            put_be_u32(&mut block, disk_offset(0x10), checksum)?;
        }
        Ok(block)
    }

    /// Writes a clean journal superblock with the next transaction sequence.
    fn mark_clean(
        &mut self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        next_sequence: JournalSequence,
    ) -> Result<()> {
        let block = self.superblock.encode_clean(block_size, next_sequence)?;
        io.write_journal_block(self, block_size, 0, &block)?;
        io.flush_all()?;
        self.superblock.apply_clean(next_sequence, block);
        Ok(())
    }

    /// Returns the number of usable blocks in the journal ring.
    fn usable_log_blocks(&self) -> Result<u32> {
        self.ring.usable_blocks()
    }

    /// Returns how many tags fit in one descriptor block.
    fn descriptor_tag_capacity(&self) -> Result<usize> {
        let block_bytes =
            usize::try_from(self.superblock.block_size()).map_err(|_| Error::ArithmeticOverflow)?;
        let tail_bytes = if self.superblock.has_metadata_checksums() {
            4
        } else {
            0
        };
        let usable = block_bytes
            .checked_sub(JOURNAL_HEADER_BYTES)
            .and_then(|value| value.checked_sub(tail_bytes))
            .ok_or(Error::TransactionTooLarge)?;
        usable
            .checked_div(self.descriptor_tag_size())
            .ok_or(Error::TransactionTooLarge)
    }

    /// Returns the serialized tag width for the active JBD2 feature set.
    fn descriptor_tag_size(&self) -> usize {
        if self.superblock.has_csum_v3() {
            16
        } else if self.superblock.has_64bit() {
            12
        } else {
            8
        }
    }

    /// Returns the descriptor payload limit before an optional checksum tail.
    fn descriptor_payload_limit(&self, block_len: usize) -> Result<usize> {
        if self.superblock.has_metadata_checksums() {
            block_len.checked_sub(4).ok_or(Error::InvalidSuperblock)
        } else {
            Ok(block_len)
        }
    }

    /// Advances a logical journal block with ring wraparound.
    fn next_logical(&self, logical: u32) -> Result<u32> {
        self.ring.next(logical)
    }

    /// Verifies a descriptor tag checksum against its data block.
    fn verify_tag_checksum(
        &self,
        sequence: JournalSequence,
        tag: &JournalTag,
        data: &[u8],
    ) -> Result<()> {
        if !self.superblock.has_metadata_checksums() {
            return Ok(());
        }
        let actual = self.tag_checksum(sequence, data)?;
        let expected = if self.superblock.has_csum_v3() {
            tag.checksum
        } else {
            tag.checksum & u32::from(u16::MAX)
        };
        let actual = if self.superblock.has_csum_v3() {
            actual
        } else {
            actual & u32::from(u16::MAX)
        };
        if actual == expected {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Computes the JBD2 checksum for one journal data block.
    fn tag_checksum(&self, sequence: JournalSequence, data: &[u8]) -> Result<u32> {
        let mut sequence_bytes = [0_u8; 4];
        put_be_u32(&mut sequence_bytes, disk_offset(0), sequence.get())?;
        let seed = crc32c(0, self.superblock.uuid());
        let seed = crc32c(seed, &sequence_bytes);
        Ok(crc32c(seed, data))
    }

    /// Verifies the optional checksum stored at the end of a control block.
    fn verify_block_tail_checksum(&self, block: &[u8]) -> Result<()> {
        if !self.superblock.has_metadata_checksums() {
            return Ok(());
        }
        let offset = block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?;
        let expected = be_u32(block, disk_offset(offset))?;
        let actual = self.block_checksum_with_zeroed(block, offset)?;
        if actual == expected {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Writes the optional checksum stored at the end of a control block.
    fn write_block_tail_checksum(&self, block: &mut [u8]) -> Result<()> {
        if !self.superblock.has_metadata_checksums() {
            return Ok(());
        }
        let offset = block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?;
        let checksum = self.block_checksum_with_zeroed(block, offset)?;
        put_be_u32(block, disk_offset(offset), checksum)
    }

    /// Verifies the checksum field embedded in a commit block.
    fn verify_commit_checksum(&self, block: &[u8]) -> Result<()> {
        let expected = be_u32(block, disk_offset(0x10))?;
        let actual = self.block_checksum_with_zeroed(block, 0x10)?;
        if expected == actual {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Computes a control-block checksum with its checksum field zeroed.
    fn block_checksum_with_zeroed(&self, block: &[u8], checksum_offset: usize) -> Result<u32> {
        let end = checksum_offset
            .checked_add(4)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut checked = block.to_vec();
        checked
            .get_mut(checksum_offset..end)
            .ok_or(Error::TruncatedStructure)?
            .fill(0);
        Ok(crc32c(crc32c(0, self.superblock.uuid()), &checked))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Validated circular range of usable logical journal blocks.
struct JournalRing {
    /// First usable logical block in the journal ring.
    first: u32,
    /// Exclusive upper bound of logical journal blocks.
    maxlen: u32,
}

impl JournalRing {
    /// Validates ring geometry from a parsed journal superblock.
    fn new(superblock: &JournalSuperblock, capacity_blocks: u32) -> Result<Self> {
        let first = superblock.first();
        let maxlen = superblock.maxlen();
        if maxlen == 0
            || maxlen > capacity_blocks
            || first != 1
            || first >= maxlen
            || (superblock.start() != 0
                && (superblock.start() < first || superblock.start() >= maxlen))
        {
            return Err(Error::UnsupportedJournal);
        }
        Ok(Self { first, maxlen })
    }

    /// Returns usable block count after the reserved superblock region.
    fn usable_blocks(self) -> Result<u32> {
        self.maxlen
            .checked_sub(self.first)
            .ok_or(Error::UnsupportedJournal)
    }

    /// Returns the next logical block, wrapping at the ring end.
    fn next(self, logical: u32) -> Result<u32> {
        if logical < self.first || logical >= self.maxlen {
            return Err(Error::JournalCorrupt);
        }
        let next = logical.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        if next >= self.maxlen {
            Ok(self.first)
        } else {
            Ok(next)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Physical placement of a journal's logical block stream.
enum JournalLocation {
    /// Journal stored in an inode on the filesystem device.
    Internal(InternalJournalLayout),
    /// Journal stored on a separate block device.
    External(ExternalJournalLayout),
}

impl JournalLocation {
    /// Maps a logical journal block to a byte offset on its backing device.
    fn offset_of(&self, logical: u32, block_size: BlockSize) -> Result<ByteOffset> {
        match self {
            Self::Internal(layout) => block_size.offset_of(layout.map_logical(logical)?),
            Self::External(layout) => layout.offset_of(logical, block_size),
        }
    }

    /// Verifies that the journal ring is backed by the selected location.
    fn validate_ring(&self, ring: &JournalRing) -> Result<()> {
        match self {
            Self::Internal(layout) => layout.validate_ring(ring),
            Self::External(layout) => layout.validate_ring(ring),
        }
    }

    /// Returns whether a filesystem home block overlaps the internal journal.
    fn contains_home_block(&self, block: BlockAddress) -> Result<bool> {
        match self {
            Self::Internal(layout) => layout.contains_physical(block),
            Self::External(_) => Ok(false),
        }
    }

    /// Returns the physical journal capacity in blocks.
    const fn capacity_blocks(&self) -> u32 {
        match self {
            Self::Internal(layout) => layout.capacity_blocks(),
            Self::External(layout) => layout.capacity_blocks(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Extent-backed layout for a journal inode stored inside the filesystem.
struct InternalJournalLayout {
    /// Journal inode extents mapped into logical journal order.
    extents: Vec<JournalExtent>,
    /// Total blocks addressable by the journal inode.
    capacity_blocks: u32,
}

impl InternalJournalLayout {
    /// Converts inode extents into a contiguous logical journal layout.
    fn new(extents: &[crate::disk_format::extent::Extent], capacity_blocks: u32) -> Result<Self> {
        let mut mapped = Vec::with_capacity(extents.len());
        for extent in extents {
            let len = extent.len().as_u32();
            let logical_start = extent.logical_start().as_u32();
            let logical_end = logical_start
                .checked_add(len)
                .ok_or(Error::ArithmeticOverflow)?;
            if logical_end > capacity_blocks {
                return Err(Error::UnsupportedJournal);
            }
            mapped.push(JournalExtent::new(
                logical_start,
                logical_end,
                extent.physical_start(),
                len,
            )?);
        }
        mapped.sort_by_key(|extent| extent.logical_start);
        Ok(Self {
            extents: mapped,
            capacity_blocks,
        })
    }

    /// Verifies that extents cover the journal ring from logical block zero.
    fn validate_ring(&self, ring: &JournalRing) -> Result<()> {
        let mut expected = 0_u32;
        for extent in &self.extents {
            if extent.logical_start != expected {
                return Err(Error::UnsupportedJournal);
            }
            expected = extent.logical_end;
            if expected >= ring.maxlen {
                return Ok(());
            }
        }
        Err(Error::UnsupportedJournal)
    }

    /// Maps a logical journal block through the journal inode extents.
    fn map_logical(&self, logical: u32) -> Result<BlockAddress> {
        for extent in &self.extents {
            if let Some(block) = extent.map_logical(logical)? {
                return Ok(block);
            }
        }
        Err(Error::UnsupportedJournal)
    }

    /// Returns whether a physical filesystem block belongs to the journal inode.
    fn contains_physical(&self, block: BlockAddress) -> Result<bool> {
        for extent in &self.extents {
            if extent.contains_physical(block) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns the journal inode capacity in blocks.
    const fn capacity_blocks(&self) -> u32 {
        self.capacity_blocks
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// One contiguous extent in the journal inode's logical address space.
struct JournalExtent {
    /// Inclusive logical start block in the journal inode.
    logical_start: u32,
    /// Exclusive logical end block in the journal inode.
    logical_end: u32,
    /// First physical filesystem block for this journal extent.
    physical_start: BlockAddress,
    /// Exclusive physical filesystem block after this journal extent.
    physical_end: u64,
}

impl JournalExtent {
    /// Builds a checked journal extent from logical and physical bounds.
    fn new(
        logical_start: u32,
        logical_end: u32,
        physical_start: BlockAddress,
        len: u32,
    ) -> Result<Self> {
        let physical_end = physical_start
            .get()
            .checked_add(u64::from(len))
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Self {
            logical_start,
            logical_end,
            physical_start,
            physical_end,
        })
    }

    /// Maps a logical journal block when it falls inside this extent.
    fn map_logical(self, logical: u32) -> Result<Option<BlockAddress>> {
        if logical < self.logical_start || logical >= self.logical_end {
            return Ok(None);
        }
        let offset = logical
            .checked_sub(self.logical_start)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Some(BlockAddress::new(
            self.physical_start
                .get()
                .checked_add(u64::from(offset))
                .ok_or(Error::ArithmeticOverflow)?,
        )))
    }

    /// Returns whether a physical block lies inside this extent.
    fn contains_physical(self, block: BlockAddress) -> bool {
        block.get() >= self.physical_start.get() && block.get() < self.physical_end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Contiguous layout for a journal stored on a separate journal device.
struct ExternalJournalLayout {
    /// Byte offset where the external journal superblock starts.
    base: ByteOffset,
    /// Total blocks available on the external journal device.
    capacity_blocks: u32,
}

impl ExternalJournalLayout {
    /// Derives external journal capacity from the journal device length.
    fn new(journal: &impl BlockReader, block_size: BlockSize) -> Result<Self> {
        let base = ByteOffset::new(JOURNAL_EXTERNAL_SUPERBLOCK_OFFSET);
        let remaining = journal
            .len()
            .bytes()
            .checked_sub(base.get())
            .ok_or(Error::UnsupportedJournal)?;
        let capacity_blocks = remaining
            .checked_div(u64::from(block_size.bytes()))
            .ok_or(Error::ArithmeticOverflow)?;
        let capacity_blocks =
            u32::try_from(capacity_blocks).map_err(|_| Error::UnsupportedJournal)?;
        if capacity_blocks <= JOURNAL_OVERHEAD_BLOCKS {
            return Err(Error::UnsupportedJournal);
        }
        Ok(Self {
            base,
            capacity_blocks,
        })
    }

    /// Verifies that the journal ring fits on the external device.
    fn validate_ring(self, ring: &JournalRing) -> Result<()> {
        if ring.maxlen <= self.capacity_blocks {
            Ok(())
        } else {
            Err(Error::UnsupportedJournal)
        }
    }

    /// Maps a logical journal block to an external journal byte offset.
    fn offset_of(self, logical: u32, block_size: BlockSize) -> Result<ByteOffset> {
        if logical >= self.capacity_blocks {
            return Err(Error::UnsupportedJournal);
        }
        Ok(ByteOffset::new(
            self.base
                .get()
                .checked_add(
                    u64::from(logical)
                        .checked_mul(u64::from(block_size.bytes()))
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?,
        ))
    }

    /// Returns the external journal capacity in blocks.
    const fn capacity_blocks(self) -> u32 {
        self.capacity_blocks
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Parsed JBD2 superblock with raw bytes retained for state updates.
pub(crate) struct JournalSuperblock {
    /// Raw superblock image used as the base for clean/dirty rewrites.
    raw: Vec<u8>,
    /// Journal block size recorded by `s_blocksize`.
    block_size: u32,
    /// Total logical blocks recorded by `s_maxlen`.
    maxlen: u32,
    /// First usable logical block recorded by `s_first`.
    first: u32,
    /// Next transaction sequence recorded by `s_sequence`.
    sequence: JournalSequence,
    /// First pending transaction block recorded by `s_start`.
    start: u32,
    /// JBD2 compatible feature bits.
    compat: u32,
    /// JBD2 incompatible feature bits.
    incompat: u32,
    /// JBD2 read-only compatible feature bits.
    ro_compat: u32,
    /// Filesystem UUID copied into journal checksum inputs.
    uuid: [u8; 16],
    /// JBD2 checksum type byte from the superblock.
    checksum_type: u8,
}

impl JournalSuperblock {
    /// Parses and verifies a JBD2 superblock image.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < JOURNAL_SUPERBLOCK_BYTES {
            return Err(Error::TruncatedStructure);
        }
        let header = Jbd2Header::parse(bytes)?;
        if !matches!(header.block_type(), JBD2_SUPERBLOCK_V1 | JBD2_SUPERBLOCK_V2) {
            return Err(Error::UnsupportedJournal);
        }
        let mut uuid = [0_u8; 16];
        uuid.copy_from_slice(bytes.get(0x30..0x40).ok_or(Error::TruncatedStructure)?);
        if be_u32(bytes, disk_offset(0xFC))? != 0 {
            verify_journal_superblock_checksum(bytes)?;
        }
        Ok(Self {
            raw: bytes.to_vec(),
            block_size: be_u32(bytes, disk_offset(0x0C))?,
            maxlen: be_u32(bytes, disk_offset(0x10))?,
            first: be_u32(bytes, disk_offset(0x14))?,
            sequence: JournalSequence::new(be_u32(bytes, disk_offset(0x18))?),
            start: be_u32(bytes, disk_offset(0x1C))?,
            compat: be_u32(bytes, disk_offset(0x24))?,
            incompat: be_u32(bytes, disk_offset(0x28))?,
            ro_compat: be_u32(bytes, disk_offset(0x2C))?,
            uuid,
            checksum_type: *bytes.get(0x50).ok_or(Error::TruncatedStructure)?,
        })
    }

    /// Validates JBD2 features and ring geometry for mounting.
    fn validate_for_mount(
        &self,
        block_size: BlockSize,
        capacity_blocks: u32,
    ) -> Result<JournalRing> {
        if self.block_size != block_size.bytes() {
            return Err(Error::UnsupportedJournal);
        }
        if self.compat != 0 {
            return Err(Error::UnsupportedJournal);
        }
        if self.incompat & (JBD2_FEATURE_INCOMPAT_FAST_COMMIT | JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)
            != 0
        {
            return Err(Error::UnsupportedJournal);
        }
        if self.incompat & !JBD2_SUPPORTED_INCOMPAT != 0 {
            return Err(Error::UnsupportedJournal);
        }
        if self.ro_compat != 0 {
            return Err(Error::UnsupportedJournal);
        }
        if self.has_metadata_checksums() && self.checksum_type != JBD2_CHECKSUM_CRC32C {
            return Err(Error::UnsupportedJournal);
        }
        JournalRing::new(self, capacity_blocks)
    }

    /// Encodes a superblock image with updated sequence and start fields.
    fn encode_with_state(
        &self,
        block_size: BlockSize,
        sequence: JournalSequence,
        start: u32,
    ) -> Result<Vec<u8>> {
        let block_len =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        if self.raw.len() != block_len {
            return Err(Error::JournalCorrupt);
        }
        let mut block = self.raw.clone();
        put_be_u32(&mut block, disk_offset(0x18), sequence.get())?;
        put_be_u32(&mut block, disk_offset(0x1C), start)?;
        if self.has_superblock_checksum()? {
            refresh_journal_superblock_checksum(&mut block)?;
        }
        Ok(block)
    }

    /// Encodes a clean journal superblock with no pending transaction tail.
    fn encode_clean(&self, block_size: BlockSize, sequence: JournalSequence) -> Result<Vec<u8>> {
        self.encode_with_state(block_size, sequence, 0)
    }

    /// Encodes a dirty journal superblock pointing at a transaction descriptor.
    fn encode_dirty(
        &self,
        block_size: BlockSize,
        start: u32,
        sequence: JournalSequence,
    ) -> Result<Vec<u8>> {
        self.encode_with_state(block_size, sequence, start)
    }

    /// Applies the clean superblock state after it has been written.
    fn apply_clean(&mut self, sequence: JournalSequence, raw: Vec<u8>) {
        self.sequence = sequence;
        self.start = 0;
        self.raw = raw;
    }

    /// Applies the dirty superblock state after it has been written.
    fn apply_dirty(&mut self, start: u32, sequence: JournalSequence, raw: Vec<u8>) {
        self.start = start;
        self.sequence = sequence;
        self.raw = raw;
    }

    /// Returns the journal block size recorded by the superblock.
    pub(crate) const fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Returns the total logical block count recorded by the superblock.
    pub(crate) const fn maxlen(&self) -> u32 {
        self.maxlen
    }

    /// Returns the first usable logical journal block.
    pub(crate) const fn first(&self) -> u32 {
        self.first
    }

    /// Returns the next journal transaction sequence.
    pub(crate) const fn sequence(&self) -> JournalSequence {
        self.sequence
    }

    /// Returns the first pending transaction block, or zero when clean.
    pub(crate) const fn start(&self) -> u32 {
        self.start
    }

    /// Returns the UUID used by JBD2 checksum calculations.
    pub(crate) const fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }

    /// Returns whether journal tags carry high block-number fields.
    pub(crate) const fn has_64bit(&self) -> bool {
        self.incompat & JBD2_FEATURE_INCOMPAT_64BIT != 0
    }

    /// Returns whether v3 journal checksums are enabled.
    fn has_csum_v3(&self) -> bool {
        self.incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3 != 0
    }

    /// Returns whether descriptor, commit, and tail checksums are enabled.
    fn has_metadata_checksums(&self) -> bool {
        self.incompat & (JBD2_FEATURE_INCOMPAT_CSUM_V2 | JBD2_FEATURE_INCOMPAT_CSUM_V3) != 0
    }

    /// Returns whether the journal superblock checksum field is populated.
    fn has_superblock_checksum(&self) -> Result<bool> {
        Ok(be_u32(&self.raw, disk_offset(0xFC))? != 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Common JBD2 control block header.
pub(crate) struct Jbd2Header {
    /// JBD2 control block type.
    block_type: u32,
    /// Transaction sequence associated with the control block.
    sequence: u32,
}

impl Jbd2Header {
    /// Parses the common JBD2 control block header.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < JOURNAL_HEADER_BYTES {
            return Err(Error::TruncatedStructure);
        }
        if be_u32(bytes, disk_offset(0))? != JBD2_MAGIC {
            return Err(Error::JournalCorrupt);
        }
        Ok(Self {
            block_type: be_u32(bytes, disk_offset(4))?,
            sequence: be_u32(bytes, disk_offset(8))?,
        })
    }

    /// Builds a descriptor block header for a transaction sequence.
    pub(crate) fn descriptor(sequence: u32) -> Self {
        Self {
            block_type: JBD2_DESCRIPTOR_BLOCK,
            sequence,
        }
    }

    /// Builds a commit block header for a transaction sequence.
    pub(crate) fn commit(sequence: u32) -> Self {
        Self {
            block_type: JBD2_COMMIT_BLOCK,
            sequence,
        }
    }

    /// Writes the common JBD2 header fields into a block image.
    pub(crate) fn encode(self, bytes: &mut [u8]) -> Result<()> {
        if bytes.len() < JOURNAL_HEADER_BYTES {
            return Err(Error::TruncatedStructure);
        }
        put_be_u32(bytes, disk_offset(0), JBD2_MAGIC)?;
        put_be_u32(bytes, disk_offset(4), self.block_type)?;
        put_be_u32(bytes, disk_offset(8), self.sequence)
    }

    /// Returns the JBD2 control block type.
    pub(crate) const fn block_type(self) -> u32 {
        self.block_type
    }

    /// Returns the transaction sequence stored in the header.
    pub(crate) const fn sequence(self) -> u32 {
        self.sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Committed journal transaction reconstructed during replay scanning.
struct JournalTransaction {
    /// Transaction sequence shared by all records in this transaction.
    sequence: JournalSequence,
    /// Replayable entries and revokes in journal order.
    events: Vec<JournalTransactionEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Result of scanning the journal for committed transactions.
struct JournalReplayScan {
    /// Complete transactions found before the scan tail.
    transactions: Vec<JournalTransaction>,
    /// Reason the journal scan stopped.
    tail: JournalScanTail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Serialized transaction ready to be written to the journal.
struct PreparedJournalTransaction {
    /// Sequence number encoded into descriptor and commit blocks.
    sequence: JournalSequence,
    /// Sequence number to store once the transaction is clean.
    next_sequence: JournalSequence,
    /// Logical journal block where the descriptor will be written.
    descriptor: u32,
    /// Serialized descriptor block.
    descriptor_block: Vec<u8>,
    /// Escaped metadata payload blocks.
    data_blocks: Vec<Vec<u8>>,
    /// Serialized commit block.
    commit_block: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Transaction whose commit block has reached durable storage.
struct JournalDurableTransaction {
    /// Sequence number to publish after checkpoint.
    next_sequence: JournalSequence,
    /// Typestate marker for the dirty journal phase.
    state: PhantomData<DirtyJournal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Transaction whose home blocks have been checkpointed.
struct CheckpointedJournalTransaction {
    /// Sequence number to publish when marking the journal clean.
    next_sequence: JournalSequence,
    /// Typestate marker for the checkpointed journal phase.
    state: PhantomData<CheckpointedJournal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Reason a replay scan stopped after the last complete transaction.
enum JournalScanTail {
    /// Superblock already reported a clean journal.
    CleanSuperblock,
    /// Scan reached a non-transaction block after complete transactions.
    EndOfLog,
    /// Scan reached a partial transaction tail.
    IncompleteTail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Result of scanning for one transaction at a journal cursor.
enum JournalTransactionScan {
    /// A complete transaction ending in a valid commit block.
    Committed {
        /// Parsed transaction contents.
        transaction: JournalTransaction,
        /// Logical block after the commit block.
        next_cursor: u32,
        /// Number of logical blocks consumed by this transaction.
        consumed: u32,
    },
    /// A descriptor or revoke sequence ended before a commit block.
    IncompleteTail,
    /// No transaction starts at the requested cursor.
    EndOfLog,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Journaled metadata payload and its filesystem home block.
struct JournalEntry {
    /// Filesystem block overwritten during checkpoint or replay.
    home: BlockAddress,
    /// Metadata bytes carried by the journal transaction.
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Ordered event inside a journal transaction.
enum JournalTransactionEvent {
    /// Metadata block payload to replay unless revoked later.
    Entry(JournalEntry),
    /// Home block whose older payload must not be replayed.
    Revoke(BlockAddress),
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Parsed descriptor block containing journal payload tags.
struct JournalDescriptor {
    /// Tags that map following data blocks to filesystem blocks.
    tags: Vec<JournalTag>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Descriptor tag for one following data block.
struct JournalTag {
    /// Filesystem home block for the following payload.
    block: BlockAddress,
    /// JBD2 tag flags controlling UUID, escape, delete, and tail semantics.
    flags: u32,
    /// Stored data-block checksum.
    checksum: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Revoke block listing home blocks cancelled by a transaction.
struct JournalRevoke {
    /// Home blocks whose older journal entries are revoked.
    blocks: Vec<BlockAddress>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Validated commit block for a transaction.
struct JournalCommit {
    /// Sequence number committed by this block.
    sequence: JournalSequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Revoke event annotated with transaction order for replay filtering.
struct RevokedBlock {
    /// Sequence of the transaction that recorded the revoke.
    sequence: JournalSequence,
    /// Event order inside the transaction.
    order: usize,
    /// Home block cancelled by the revoke.
    block: BlockAddress,
}

/// I/O boundary shared by internal and external journal backends.
trait JournalIo {
    /// Reads one logical journal block from the journal device.
    fn read_journal_block<S>(
        &mut self,
        journal: &Journal<S>,
        block_size: BlockSize,
        logical: u32,
        out: &mut [u8],
    ) -> Result<()>;

    /// Writes one logical journal block to the journal device.
    fn write_journal_block<S>(
        &mut self,
        journal: &Journal<S>,
        block_size: BlockSize,
        logical: u32,
        bytes: &[u8],
    ) -> Result<()>;

    /// Writes one filesystem home block.
    fn write_home_block(
        &mut self,
        block_size: BlockSize,
        block: BlockAddress,
        bytes: &[u8],
    ) -> Result<()>;

    /// Flushes all devices touched by this journal operation.
    fn flush_all(&mut self) -> Result<()>;
}

/// Journal I/O for an internal journal stored on the filesystem device.
struct InternalJournalIo<'a, D> {
    /// Shared filesystem and journal block device.
    device: &'a mut D,
}

impl<D: BlockWriter> JournalIo for InternalJournalIo<'_, D> {
    fn read_journal_block<S>(
        &mut self,
        journal: &Journal<S>,
        block_size: BlockSize,
        logical: u32,
        out: &mut [u8],
    ) -> Result<()> {
        self.device
            .read_exact_at(journal.offset_of(logical, block_size)?, out)
    }

    fn write_journal_block<S>(
        &mut self,
        journal: &Journal<S>,
        block_size: BlockSize,
        logical: u32,
        bytes: &[u8],
    ) -> Result<()> {
        self.device
            .write_exact_at(journal.offset_of(logical, block_size)?, bytes)
    }

    fn write_home_block(
        &mut self,
        block_size: BlockSize,
        block: BlockAddress,
        bytes: &[u8],
    ) -> Result<()> {
        self.device
            .write_exact_at(block_size.offset_of(block)?, bytes)
    }

    fn flush_all(&mut self) -> Result<()> {
        self.device.flush()
    }
}

/// Journal I/O for an external journal paired with a filesystem device.
struct ExternalJournalIo<'a, F, J> {
    /// Filesystem device that receives checkpointed home blocks.
    filesystem: &'a mut F,
    /// External journal device that stores JBD2 control and data blocks.
    journal: &'a mut J,
}

impl<F: BlockWriter, J: BlockWriter> JournalIo for ExternalJournalIo<'_, F, J> {
    fn read_journal_block<S>(
        &mut self,
        journal: &Journal<S>,
        block_size: BlockSize,
        logical: u32,
        out: &mut [u8],
    ) -> Result<()> {
        self.journal
            .read_exact_at(journal.offset_of(logical, block_size)?, out)
    }

    fn write_journal_block<S>(
        &mut self,
        journal: &Journal<S>,
        block_size: BlockSize,
        logical: u32,
        bytes: &[u8],
    ) -> Result<()> {
        self.journal
            .write_exact_at(journal.offset_of(logical, block_size)?, bytes)
    }

    fn write_home_block(
        &mut self,
        block_size: BlockSize,
        block: BlockAddress,
        bytes: &[u8],
    ) -> Result<()> {
        self.filesystem
            .write_exact_at(block_size.offset_of(block)?, bytes)
    }

    fn flush_all(&mut self) -> Result<()> {
        self.journal.flush()?;
        self.filesystem.flush()
    }
}

impl<State> Journal<State> {
    /// Maps a logical journal block to a byte offset for this journal.
    fn offset_of(&self, logical: u32, block_size: BlockSize) -> Result<ByteOffset> {
        self.location.offset_of(logical, block_size)
    }
}

/// Reads a logical journal block from an arbitrary journal location.
fn read_journal_block(
    reader: &impl BlockReader,
    location: &JournalLocation,
    block_size: BlockSize,
    logical: u32,
    out: &mut [u8],
) -> Result<()> {
    let offset = location.offset_of(logical, block_size)?;
    reader.read_exact_at(offset, out)
}

/// Returns whether a metadata payload must be escaped before journaling.
fn starts_with_jbd2_magic(bytes: &[u8]) -> bool {
    bytes
        .get(0..4)
        .is_some_and(|prefix| prefix == JBD2_MAGIC.to_be_bytes())
}

/// Rejects descriptor tag flags this journal implementation cannot interpret.
fn validate_tag_flags(flags: u32) -> Result<()> {
    const SUPPORTED_TAG_FLAGS: u32 = JBD2_TAG_FLAG_ESCAPE
        | JBD2_TAG_FLAG_SAME_UUID
        | JBD2_TAG_FLAG_DELETED
        | JBD2_TAG_FLAG_LAST_TAG;
    if flags & !SUPPORTED_TAG_FLAGS == 0 {
        Ok(())
    } else {
        Err(Error::UnsupportedJournal)
    }
}

/// Classifies a transaction tail based on how much of it was consumed.
fn transaction_tail(consumed: u32) -> JournalTransactionScan {
    if consumed == 0 {
        JournalTransactionScan::EndOfLog
    } else {
        JournalTransactionScan::IncompleteTail
    }
}

/// Verifies the checksum stored in a journal superblock.
fn verify_journal_superblock_checksum(block: &[u8]) -> Result<()> {
    let expected = be_u32(block, disk_offset(0xFC))?;
    let actual = journal_superblock_checksum(block)?;
    if expected == actual {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch)
    }
}

/// Recomputes and writes the journal superblock checksum.
fn refresh_journal_superblock_checksum(block: &mut [u8]) -> Result<()> {
    put_be_u32(block, disk_offset(0xFC), 0)?;
    let checksum = journal_superblock_checksum(block)?;
    put_be_u32(block, disk_offset(0xFC), checksum)
}

/// Computes a journal superblock checksum with its checksum field zeroed.
fn journal_superblock_checksum(block: &[u8]) -> Result<u32> {
    let mut checked = block
        .get(..JOURNAL_SUPERBLOCK_BYTES)
        .ok_or(Error::TruncatedStructure)?
        .to_vec();
    checked
        .get_mut(0xFC..0x100)
        .ok_or(Error::TruncatedStructure)?
        .fill(0);
    Ok(crc32c(0, &checked))
}

/// Returns whether a later revoke cancels replay of a home block.
fn is_revoked_after(
    revokes: &[RevokedBlock],
    block: BlockAddress,
    sequence: JournalSequence,
    order: usize,
) -> bool {
    revokes.iter().any(|revoked| {
        revoked.block == block
            && (revoked.sequence.is_after(sequence)
                || (revoked.sequence == sequence && revoked.order > order))
    })
}
