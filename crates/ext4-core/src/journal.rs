//! JBD2 journal loading, replay, checkpointing, and commit construction.
//!
//! The journal code is modeled as typestates: loaded journals must be replayed
//! into a clean state before write transactions can commit, dirty transactions
//! must become durable before checkpoint, and checkpointed transactions can then
//! advance the superblock tail. This keeps crash-ordering rules out of ad hoc
//! booleans in the volume layer.

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use crate::block::{BlockAddress, BlockReader, BlockSize, BlockWriter, ByteOffset};
use crate::checksum::crc32c;
use crate::endian::{be_u16, be_u32, be_u64, put_be_u16, put_be_u32};
use crate::error::{Error, Result};
use crate::extent::{ExtentTree, ExtentTreeContext};
use crate::inode::Inode;
use crate::superblock::RecoveryState;
use crate::volume::MetadataBlock;

// Common JBD2 block header fields. JBD2 stores its control structures big-endian.
/// Internal constant JBD2_MAGIC used by on-disk layout and policy checks.
const JBD2_MAGIC: u32 = 0xC03B_3998;
/// Internal constant JBD2_DESCRIPTOR_BLOCK used by on-disk layout and policy checks.
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
/// Internal constant JBD2_COMMIT_BLOCK used by on-disk layout and policy checks.
const JBD2_COMMIT_BLOCK: u32 = 2;
/// Internal constant JBD2_SUPERBLOCK_V1 used by on-disk layout and policy checks.
const JBD2_SUPERBLOCK_V1: u32 = 3;
/// Internal constant JBD2_SUPERBLOCK_V2 used by on-disk layout and policy checks.
const JBD2_SUPERBLOCK_V2: u32 = 4;
/// Internal constant JBD2_REVOKE_BLOCK used by on-disk layout and policy checks.
const JBD2_REVOKE_BLOCK: u32 = 5;

// Incompatible feature bits are validated before replay because unsupported
// features can change transaction interpretation.
/// Internal constant JBD2_FEATURE_INCOMPAT_REVOKE used by on-disk layout and policy checks.
const JBD2_FEATURE_INCOMPAT_REVOKE: u32 = 0x0001;
/// Internal constant JBD2_FEATURE_INCOMPAT_64BIT used by on-disk layout and policy checks.
const JBD2_FEATURE_INCOMPAT_64BIT: u32 = 0x0002;
/// Internal constant JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT used by on-disk layout and policy checks.
const JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT: u32 = 0x0004;
/// Internal constant JBD2_FEATURE_INCOMPAT_CSUM_V2 used by on-disk layout and policy checks.
const JBD2_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x0008;
/// Internal constant JBD2_FEATURE_INCOMPAT_CSUM_V3 used by on-disk layout and policy checks.
const JBD2_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x0010;
/// Internal constant JBD2_FEATURE_INCOMPAT_FAST_COMMIT used by on-disk layout and policy checks.
const JBD2_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0020;
/// Internal constant JBD2_SUPPORTED_INCOMPAT used by on-disk layout and policy checks.
const JBD2_SUPPORTED_INCOMPAT: u32 = JBD2_FEATURE_INCOMPAT_REVOKE
    | JBD2_FEATURE_INCOMPAT_64BIT
    | JBD2_FEATURE_INCOMPAT_CSUM_V2
    | JBD2_FEATURE_INCOMPAT_CSUM_V3;

// Descriptor tag flags define how following payload blocks are decoded.
/// Internal constant JBD2_TAG_FLAG_ESCAPE used by on-disk layout and policy checks.
const JBD2_TAG_FLAG_ESCAPE: u32 = 0x0001;
/// Internal constant JBD2_TAG_FLAG_SAME_UUID used by on-disk layout and policy checks.
const JBD2_TAG_FLAG_SAME_UUID: u32 = 0x0002;
/// Internal constant JBD2_TAG_FLAG_DELETED used by on-disk layout and policy checks.
const JBD2_TAG_FLAG_DELETED: u32 = 0x0004;
/// Internal constant JBD2_TAG_FLAG_LAST_TAG used by on-disk layout and policy checks.
const JBD2_TAG_FLAG_LAST_TAG: u32 = 0x0008;

// JBD2 checksum and layout constants used by both replay and new commits.
/// Internal constant JBD2_CHECKSUM_CRC32C used by on-disk layout and policy checks.
const JBD2_CHECKSUM_CRC32C: u8 = 4;
/// Internal constant JOURNAL_HEADER_BYTES used by on-disk layout and policy checks.
const JOURNAL_HEADER_BYTES: usize = 12;
/// Internal constant JOURNAL_SUPERBLOCK_BYTES used by on-disk layout and policy checks.
const JOURNAL_SUPERBLOCK_BYTES: usize = 1024;
/// Internal constant JOURNAL_EXTERNAL_SUPERBLOCK_OFFSET used by on-disk layout and policy checks.
const JOURNAL_EXTERNAL_SUPERBLOCK_OFFSET: u64 = 2048;
/// Internal constant JOURNAL_OVERHEAD_BLOCKS used by on-disk layout and policy checks.
const JOURNAL_OVERHEAD_BLOCKS: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal Journal state used to keep module invariants explicit.
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

    /// Internal replay_and_checkpoint operation used by this module's domain boundary.
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

    /// Internal commit_metadata_transaction operation used by this module's domain boundary.
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

    /// Internal write_prepared_transaction operation used by this module's domain boundary.
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

    /// Internal checkpoint_durable_transaction operation used by this module's domain boundary.
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

    /// Internal clean_checkpointed_transaction operation used by this module's domain boundary.
    fn clean_checkpointed_transaction(
        &mut self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        checkpointed: CheckpointedJournalTransaction,
    ) -> Result<()> {
        self.mark_clean(io, block_size, checkpointed.next_sequence)?;
        Ok(())
    }

    /// Internal prepare_metadata_transaction operation used by this module's domain boundary.
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
                put_be_u32(&mut data, 0, 0)?;
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

    /// Internal committed_transactions operation used by this module's domain boundary.
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

    /// Internal parse_transaction operation used by this module's domain boundary.
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
                                if be_u32(&data, 0)? != 0 {
                                    return Err(Error::JournalCorrupt);
                                }
                                put_be_u32(&mut data, 0, JBD2_MAGIC)?;
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

    /// Internal read_journal_block operation used by this module's domain boundary.
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

    /// Internal validate_replay_target operation used by this module's domain boundary.
    fn validate_replay_target(&self, block: BlockAddress) -> Result<()> {
        if block.get() >= self.filesystem_blocks {
            return Err(Error::JournalCorrupt);
        }
        if self.location.contains_home_block(block)? {
            return Err(Error::JournalCorrupt);
        }
        Ok(())
    }

    /// Internal parse_descriptor_block operation used by this module's domain boundary.
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

    /// Internal parse_tag operation used by this module's domain boundary.
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
            let block_low = u64::from(be_u32(block, offset)?);
            let flags = be_u32(
                block,
                offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
            )?;
            let block_high = u64::from(be_u32(
                block,
                offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?,
            )?);
            let checksum = be_u32(
                block,
                offset.checked_add(12).ok_or(Error::ArithmeticOverflow)?,
            )?;
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
        let block_low = u64::from(be_u32(block, offset)?);
        let checksum = u32::from(be_u16(
            block,
            offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
        )?);
        let flags = u32::from(be_u16(
            block,
            offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?,
        )?);
        if block_low == 0 && flags == 0 && checksum == 0 {
            return Ok(None);
        }
        validate_tag_flags(flags)?;
        let high_size = if self.superblock.has_64bit() { 4 } else { 0 };
        let block_high = if high_size == 4 {
            u64::from(be_u32(
                block,
                offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?,
            )?)
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

    /// Internal parse_revoke_block operation used by this module's domain boundary.
    fn parse_revoke_block(&self, block: &[u8]) -> Result<JournalRevoke> {
        self.verify_block_tail_checksum(block)?;
        let used = usize::try_from(be_u32(block, JOURNAL_HEADER_BYTES)?)
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
                be_u64(block, offset)?
            } else {
                u64::from(be_u32(block, offset)?)
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

    /// Internal parse_commit_block operation used by this module's domain boundary.
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

    /// Internal encode_descriptor_block operation used by this module's domain boundary.
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

    /// Internal encode_tag operation used by this module's domain boundary.
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
                offset,
                u32::try_from(metadata.block().get() & u64::from(u32::MAX))
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            put_be_u32(
                block,
                offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
                flags,
            )?;
            put_be_u32(
                block,
                offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?,
                u32::try_from(metadata.block().get() >> 32)
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            put_be_u32(
                block,
                offset.checked_add(12).ok_or(Error::ArithmeticOverflow)?,
                checksum,
            )?;
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
            offset,
            u32::try_from(metadata.block().get() & u64::from(u32::MAX))
                .map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_be_u16(
            block,
            offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
            u16::try_from(checksum & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_be_u16(
            block,
            offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?,
            u16::try_from(flags).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if high_size == 4 {
            put_be_u32(
                block,
                offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?,
                u32::try_from(metadata.block().get() >> 32)
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(next)
    }

    /// Internal encode_commit_block operation used by this module's domain boundary.
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
            put_be_u32(&mut block, 0x10, checksum)?;
        }
        Ok(block)
    }

    /// Internal mark_clean operation used by this module's domain boundary.
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

    /// Internal usable_log_blocks operation used by this module's domain boundary.
    fn usable_log_blocks(&self) -> Result<u32> {
        self.ring.usable_blocks()
    }

    /// Internal descriptor_tag_capacity operation used by this module's domain boundary.
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

    /// Internal descriptor_tag_size operation used by this module's domain boundary.
    fn descriptor_tag_size(&self) -> usize {
        if self.superblock.has_csum_v3() {
            16
        } else if self.superblock.has_64bit() {
            12
        } else {
            8
        }
    }

    /// Internal descriptor_payload_limit operation used by this module's domain boundary.
    fn descriptor_payload_limit(&self, block_len: usize) -> Result<usize> {
        if self.superblock.has_metadata_checksums() {
            block_len.checked_sub(4).ok_or(Error::InvalidSuperblock)
        } else {
            Ok(block_len)
        }
    }

    /// Internal next_logical operation used by this module's domain boundary.
    fn next_logical(&self, logical: u32) -> Result<u32> {
        self.ring.next(logical)
    }

    /// Internal verify_tag_checksum operation used by this module's domain boundary.
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

    /// Internal tag_checksum operation used by this module's domain boundary.
    fn tag_checksum(&self, sequence: JournalSequence, data: &[u8]) -> Result<u32> {
        let mut sequence_bytes = [0_u8; 4];
        put_be_u32(&mut sequence_bytes, 0, sequence.get())?;
        let seed = crc32c(0, self.superblock.uuid());
        let seed = crc32c(seed, &sequence_bytes);
        Ok(crc32c(seed, data))
    }

    /// Internal verify_block_tail_checksum operation used by this module's domain boundary.
    fn verify_block_tail_checksum(&self, block: &[u8]) -> Result<()> {
        if !self.superblock.has_metadata_checksums() {
            return Ok(());
        }
        let offset = block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?;
        let expected = be_u32(block, offset)?;
        let actual = self.block_checksum_with_zeroed(block, offset)?;
        if actual == expected {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Internal write_block_tail_checksum operation used by this module's domain boundary.
    fn write_block_tail_checksum(&self, block: &mut [u8]) -> Result<()> {
        if !self.superblock.has_metadata_checksums() {
            return Ok(());
        }
        let offset = block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?;
        let checksum = self.block_checksum_with_zeroed(block, offset)?;
        put_be_u32(block, offset, checksum)
    }

    /// Internal verify_commit_checksum operation used by this module's domain boundary.
    fn verify_commit_checksum(&self, block: &[u8]) -> Result<()> {
        let expected = be_u32(block, 0x10)?;
        let actual = self.block_checksum_with_zeroed(block, 0x10)?;
        if expected == actual {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Internal block_checksum_with_zeroed operation used by this module's domain boundary.
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
/// Internal JournalRing state used to keep module invariants explicit.
struct JournalRing {
    /// Internal first state carried by this domain type.
    first: u32,
    /// Internal maxlen state carried by this domain type.
    maxlen: u32,
}

impl JournalRing {
    /// Internal new operation used by this module's domain boundary.
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

    /// Internal usable_blocks operation used by this module's domain boundary.
    fn usable_blocks(self) -> Result<u32> {
        self.maxlen
            .checked_sub(self.first)
            .ok_or(Error::UnsupportedJournal)
    }

    /// Internal next operation used by this module's domain boundary.
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
/// Internal JournalLocation states used to make module control flow explicit.
enum JournalLocation {
    /// Internal Internal variant for this domain state.
    Internal(InternalJournalLayout),
    /// Internal External variant for this domain state.
    External(ExternalJournalLayout),
}

impl JournalLocation {
    /// Internal offset_of operation used by this module's domain boundary.
    fn offset_of(&self, logical: u32, block_size: BlockSize) -> Result<ByteOffset> {
        match self {
            Self::Internal(layout) => block_size.offset_of(layout.map_logical(logical)?),
            Self::External(layout) => layout.offset_of(logical, block_size),
        }
    }

    /// Internal validate_ring operation used by this module's domain boundary.
    fn validate_ring(&self, ring: &JournalRing) -> Result<()> {
        match self {
            Self::Internal(layout) => layout.validate_ring(ring),
            Self::External(layout) => layout.validate_ring(ring),
        }
    }

    /// Internal contains_home_block operation used by this module's domain boundary.
    fn contains_home_block(&self, block: BlockAddress) -> Result<bool> {
        match self {
            Self::Internal(layout) => layout.contains_physical(block),
            Self::External(_) => Ok(false),
        }
    }

    /// Internal fn operation used by this module's domain boundary.
    const fn capacity_blocks(&self) -> u32 {
        match self {
            Self::Internal(layout) => layout.capacity_blocks(),
            Self::External(layout) => layout.capacity_blocks(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal InternalJournalLayout state used to keep module invariants explicit.
struct InternalJournalLayout {
    /// Internal extents state carried by this domain type.
    extents: Vec<JournalExtent>,
    /// Internal capacity_blocks state carried by this domain type.
    capacity_blocks: u32,
}

impl InternalJournalLayout {
    /// Internal new operation used by this module's domain boundary.
    fn new(extents: &[crate::extent::Extent], capacity_blocks: u32) -> Result<Self> {
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

    /// Internal validate_ring operation used by this module's domain boundary.
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

    /// Internal map_logical operation used by this module's domain boundary.
    fn map_logical(&self, logical: u32) -> Result<BlockAddress> {
        for extent in &self.extents {
            if let Some(block) = extent.map_logical(logical)? {
                return Ok(block);
            }
        }
        Err(Error::UnsupportedJournal)
    }

    /// Internal contains_physical operation used by this module's domain boundary.
    fn contains_physical(&self, block: BlockAddress) -> Result<bool> {
        for extent in &self.extents {
            if extent.contains_physical(block) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Internal fn operation used by this module's domain boundary.
    const fn capacity_blocks(&self) -> u32 {
        self.capacity_blocks
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal JournalExtent state used to keep module invariants explicit.
struct JournalExtent {
    /// Internal logical_start state carried by this domain type.
    logical_start: u32,
    /// Internal logical_end state carried by this domain type.
    logical_end: u32,
    /// Internal physical_start state carried by this domain type.
    physical_start: BlockAddress,
    /// Internal physical_end state carried by this domain type.
    physical_end: u64,
}

impl JournalExtent {
    /// Internal new operation used by this module's domain boundary.
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

    /// Internal map_logical operation used by this module's domain boundary.
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

    /// Internal contains_physical operation used by this module's domain boundary.
    fn contains_physical(self, block: BlockAddress) -> bool {
        block.get() >= self.physical_start.get() && block.get() < self.physical_end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal ExternalJournalLayout state used to keep module invariants explicit.
struct ExternalJournalLayout {
    /// Internal base state carried by this domain type.
    base: ByteOffset,
    /// Internal capacity_blocks state carried by this domain type.
    capacity_blocks: u32,
}

impl ExternalJournalLayout {
    /// Internal new operation used by this module's domain boundary.
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

    /// Internal validate_ring operation used by this module's domain boundary.
    fn validate_ring(self, ring: &JournalRing) -> Result<()> {
        if ring.maxlen <= self.capacity_blocks {
            Ok(())
        } else {
            Err(Error::UnsupportedJournal)
        }
    }

    /// Internal offset_of operation used by this module's domain boundary.
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

    /// Internal fn operation used by this module's domain boundary.
    const fn capacity_blocks(self) -> u32 {
        self.capacity_blocks
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal JournalSuperblock state used to keep module invariants explicit.
pub(crate) struct JournalSuperblock {
    /// Internal raw state carried by this domain type.
    raw: Vec<u8>,
    /// Internal block_size state carried by this domain type.
    block_size: u32,
    /// Internal maxlen state carried by this domain type.
    maxlen: u32,
    /// Internal first state carried by this domain type.
    first: u32,
    /// Internal sequence state carried by this domain type.
    sequence: JournalSequence,
    /// Internal start state carried by this domain type.
    start: u32,
    /// Internal compat state carried by this domain type.
    compat: u32,
    /// Internal incompat state carried by this domain type.
    incompat: u32,
    /// Internal ro_compat state carried by this domain type.
    ro_compat: u32,
    /// Internal uuid state carried by this domain type.
    uuid: [u8; 16],
    /// Internal checksum_type state carried by this domain type.
    checksum_type: u8,
}

impl JournalSuperblock {
    /// Internal parse operation used by this module's domain boundary.
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
        if be_u32(bytes, 0xFC)? != 0 {
            verify_journal_superblock_checksum(bytes)?;
        }
        Ok(Self {
            raw: bytes.to_vec(),
            block_size: be_u32(bytes, 0x0C)?,
            maxlen: be_u32(bytes, 0x10)?,
            first: be_u32(bytes, 0x14)?,
            sequence: JournalSequence::new(be_u32(bytes, 0x18)?),
            start: be_u32(bytes, 0x1C)?,
            compat: be_u32(bytes, 0x24)?,
            incompat: be_u32(bytes, 0x28)?,
            ro_compat: be_u32(bytes, 0x2C)?,
            uuid,
            checksum_type: *bytes.get(0x50).ok_or(Error::TruncatedStructure)?,
        })
    }

    /// Internal validate_for_mount operation used by this module's domain boundary.
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

    /// Internal encode_with_state operation used by this module's domain boundary.
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
        put_be_u32(&mut block, 0x18, sequence.get())?;
        put_be_u32(&mut block, 0x1C, start)?;
        if self.has_superblock_checksum()? {
            refresh_journal_superblock_checksum(&mut block)?;
        }
        Ok(block)
    }

    /// Internal encode_clean operation used by this module's domain boundary.
    fn encode_clean(&self, block_size: BlockSize, sequence: JournalSequence) -> Result<Vec<u8>> {
        self.encode_with_state(block_size, sequence, 0)
    }

    /// Internal encode_dirty operation used by this module's domain boundary.
    fn encode_dirty(
        &self,
        block_size: BlockSize,
        start: u32,
        sequence: JournalSequence,
    ) -> Result<Vec<u8>> {
        self.encode_with_state(block_size, sequence, start)
    }

    /// Internal apply_clean operation used by this module's domain boundary.
    fn apply_clean(&mut self, sequence: JournalSequence, raw: Vec<u8>) {
        self.sequence = sequence;
        self.start = 0;
        self.raw = raw;
    }

    /// Internal apply_dirty operation used by this module's domain boundary.
    fn apply_dirty(&mut self, start: u32, sequence: JournalSequence, raw: Vec<u8>) {
        self.start = start;
        self.sequence = sequence;
        self.raw = raw;
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn maxlen(&self) -> u32 {
        self.maxlen
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn first(&self) -> u32 {
        self.first
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn sequence(&self) -> JournalSequence {
        self.sequence
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn start(&self) -> u32 {
        self.start
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn has_64bit(&self) -> bool {
        self.incompat & JBD2_FEATURE_INCOMPAT_64BIT != 0
    }

    /// Internal has_csum_v3 operation used by this module's domain boundary.
    fn has_csum_v3(&self) -> bool {
        self.incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3 != 0
    }

    /// Internal has_metadata_checksums operation used by this module's domain boundary.
    fn has_metadata_checksums(&self) -> bool {
        self.incompat & (JBD2_FEATURE_INCOMPAT_CSUM_V2 | JBD2_FEATURE_INCOMPAT_CSUM_V3) != 0
    }

    /// Internal has_superblock_checksum operation used by this module's domain boundary.
    fn has_superblock_checksum(&self) -> Result<bool> {
        Ok(be_u32(&self.raw, 0xFC)? != 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal Jbd2Header state used to keep module invariants explicit.
pub(crate) struct Jbd2Header {
    /// Internal block_type state carried by this domain type.
    block_type: u32,
    /// Internal sequence state carried by this domain type.
    sequence: u32,
}

impl Jbd2Header {
    /// Internal parse operation used by this module's domain boundary.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < JOURNAL_HEADER_BYTES {
            return Err(Error::TruncatedStructure);
        }
        if be_u32(bytes, 0)? != JBD2_MAGIC {
            return Err(Error::JournalCorrupt);
        }
        Ok(Self {
            block_type: be_u32(bytes, 4)?,
            sequence: be_u32(bytes, 8)?,
        })
    }

    /// Internal descriptor operation used by this module's domain boundary.
    pub(crate) fn descriptor(sequence: u32) -> Self {
        Self {
            block_type: JBD2_DESCRIPTOR_BLOCK,
            sequence,
        }
    }

    /// Internal commit operation used by this module's domain boundary.
    pub(crate) fn commit(sequence: u32) -> Self {
        Self {
            block_type: JBD2_COMMIT_BLOCK,
            sequence,
        }
    }

    /// Internal encode operation used by this module's domain boundary.
    pub(crate) fn encode(self, bytes: &mut [u8]) -> Result<()> {
        if bytes.len() < JOURNAL_HEADER_BYTES {
            return Err(Error::TruncatedStructure);
        }
        put_be_u32(bytes, 0, JBD2_MAGIC)?;
        put_be_u32(bytes, 4, self.block_type)?;
        put_be_u32(bytes, 8, self.sequence)
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn block_type(self) -> u32 {
        self.block_type
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn sequence(self) -> u32 {
        self.sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal JournalTransaction state used to keep module invariants explicit.
struct JournalTransaction {
    /// Internal sequence state carried by this domain type.
    sequence: JournalSequence,
    /// Internal events state carried by this domain type.
    events: Vec<JournalTransactionEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal JournalReplayScan state used to keep module invariants explicit.
struct JournalReplayScan {
    /// Internal transactions state carried by this domain type.
    transactions: Vec<JournalTransaction>,
    /// Internal tail state carried by this domain type.
    tail: JournalScanTail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal PreparedJournalTransaction state used to keep module invariants explicit.
struct PreparedJournalTransaction {
    /// Internal sequence state carried by this domain type.
    sequence: JournalSequence,
    /// Internal next_sequence state carried by this domain type.
    next_sequence: JournalSequence,
    /// Internal descriptor state carried by this domain type.
    descriptor: u32,
    /// Internal descriptor_block state carried by this domain type.
    descriptor_block: Vec<u8>,
    /// Internal data_blocks state carried by this domain type.
    data_blocks: Vec<Vec<u8>>,
    /// Internal commit_block state carried by this domain type.
    commit_block: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal JournalDurableTransaction state used to keep module invariants explicit.
struct JournalDurableTransaction {
    /// Internal next_sequence state carried by this domain type.
    next_sequence: JournalSequence,
    /// Internal state state carried by this domain type.
    state: PhantomData<DirtyJournal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal CheckpointedJournalTransaction state used to keep module invariants explicit.
struct CheckpointedJournalTransaction {
    /// Internal next_sequence state carried by this domain type.
    next_sequence: JournalSequence,
    /// Internal state state carried by this domain type.
    state: PhantomData<CheckpointedJournal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal JournalScanTail states used to make module control flow explicit.
enum JournalScanTail {
    /// Internal CleanSuperblock variant for this domain state.
    CleanSuperblock,
    /// Internal EndOfLog variant for this domain state.
    EndOfLog,
    /// Internal IncompleteTail variant for this domain state.
    IncompleteTail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal JournalTransactionScan states used to make module control flow explicit.
enum JournalTransactionScan {
    /// Internal Committed variant for this domain state.
    Committed {
        /// Internal transaction state carried by this domain type.
        transaction: JournalTransaction,
        /// Internal next_cursor state carried by this domain type.
        next_cursor: u32,
        /// Internal consumed state carried by this domain type.
        consumed: u32,
    },
    /// Internal IncompleteTail variant for this domain state.
    IncompleteTail,
    /// Internal EndOfLog variant for this domain state.
    EndOfLog,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal JournalEntry state used to keep module invariants explicit.
struct JournalEntry {
    /// Internal home state carried by this domain type.
    home: BlockAddress,
    /// Internal bytes state carried by this domain type.
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal JournalTransactionEvent states used to make module control flow explicit.
enum JournalTransactionEvent {
    /// Internal Entry variant for this domain state.
    Entry(JournalEntry),
    /// Internal Revoke variant for this domain state.
    Revoke(BlockAddress),
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal JournalDescriptor state used to keep module invariants explicit.
struct JournalDescriptor {
    /// Internal tags state carried by this domain type.
    tags: Vec<JournalTag>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal JournalTag state used to keep module invariants explicit.
struct JournalTag {
    /// Internal block state carried by this domain type.
    block: BlockAddress,
    /// Internal flags state carried by this domain type.
    flags: u32,
    /// Internal checksum state carried by this domain type.
    checksum: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Internal JournalRevoke state used to keep module invariants explicit.
struct JournalRevoke {
    /// Internal blocks state carried by this domain type.
    blocks: Vec<BlockAddress>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal JournalCommit state used to keep module invariants explicit.
struct JournalCommit {
    /// Internal sequence state carried by this domain type.
    sequence: JournalSequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal RevokedBlock state used to keep module invariants explicit.
struct RevokedBlock {
    /// Internal sequence state carried by this domain type.
    sequence: JournalSequence,
    /// Internal order state carried by this domain type.
    order: usize,
    /// Internal block state carried by this domain type.
    block: BlockAddress,
}

/// Internal JournalIo boundary used by this module.
trait JournalIo {
    /// Internal read_journal_block operation used by this module's domain boundary.
    fn read_journal_block<S>(
        &mut self,
        journal: &Journal<S>,
        block_size: BlockSize,
        logical: u32,
        out: &mut [u8],
    ) -> Result<()>;

    /// Internal write_journal_block operation used by this module's domain boundary.
    fn write_journal_block<S>(
        &mut self,
        journal: &Journal<S>,
        block_size: BlockSize,
        logical: u32,
        bytes: &[u8],
    ) -> Result<()>;

    /// Internal write_home_block operation used by this module's domain boundary.
    fn write_home_block(
        &mut self,
        block_size: BlockSize,
        block: BlockAddress,
        bytes: &[u8],
    ) -> Result<()>;

    /// Internal flush_all operation used by this module's domain boundary.
    fn flush_all(&mut self) -> Result<()>;
}

/// Internal InternalJournalIo state used to keep module invariants explicit.
struct InternalJournalIo<'a, D> {
    /// Internal device state carried by this domain type.
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

/// Internal ExternalJournalIo state used to keep module invariants explicit.
struct ExternalJournalIo<'a, F, J> {
    /// Internal filesystem state carried by this domain type.
    filesystem: &'a mut F,
    /// Internal journal state carried by this domain type.
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
    /// Internal offset_of operation used by this module's domain boundary.
    fn offset_of(&self, logical: u32, block_size: BlockSize) -> Result<ByteOffset> {
        self.location.offset_of(logical, block_size)
    }
}

/// Internal read_journal_block operation used by this module's domain boundary.
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

/// Internal starts_with_jbd2_magic operation used by this module's domain boundary.
fn starts_with_jbd2_magic(bytes: &[u8]) -> bool {
    bytes
        .get(0..4)
        .is_some_and(|prefix| prefix == JBD2_MAGIC.to_be_bytes())
}

/// Internal validate_tag_flags operation used by this module's domain boundary.
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

/// Internal transaction_tail operation used by this module's domain boundary.
fn transaction_tail(consumed: u32) -> JournalTransactionScan {
    if consumed == 0 {
        JournalTransactionScan::EndOfLog
    } else {
        JournalTransactionScan::IncompleteTail
    }
}

/// Internal verify_journal_superblock_checksum operation used by this module's domain boundary.
fn verify_journal_superblock_checksum(block: &[u8]) -> Result<()> {
    let expected = be_u32(block, 0xFC)?;
    let actual = journal_superblock_checksum(block)?;
    if expected == actual {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch)
    }
}

/// Internal refresh_journal_superblock_checksum operation used by this module's domain boundary.
fn refresh_journal_superblock_checksum(block: &mut [u8]) -> Result<()> {
    put_be_u32(block, 0xFC, 0)?;
    let checksum = journal_superblock_checksum(block)?;
    put_be_u32(block, 0xFC, checksum)
}

/// Internal journal_superblock_checksum operation used by this module's domain boundary.
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

/// Internal is_revoked_after operation used by this module's domain boundary.
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
