//! JBD2 journal loading, replay, checkpointing, and commit construction.
//!
//! The journal code is modeled as typestates: loaded journals must be replayed
//! into a clean state before write transactions can commit, dirty transactions
//! must become durable before checkpoint, and checkpointed transactions can then
//! advance the superblock tail. This keeps crash-ordering rules out of ad hoc
//! booleans in the volume layer.

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::disk::block::{BlockAddress, BlockSize, ByteOffset};
use crate::disk::checksum::ext4_crc32c;
use crate::disk::endian::{DiskOffset, be_u16, be_u32, be_u64, put_be_u16, put_be_u32};
use crate::disk::storage::{OperationDevice, StorageRequest, StorageTarget};
use crate::disk_format::extent::{ExtentTree, ExtentTreeContext};
use crate::disk_format::inode::Inode;
use crate::error::{Error, Result};
use crate::memory::{self, FallibleVec};

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
/// Compatible feature bit for the legacy transaction checksum format.
const JBD2_FEATURE_COMPAT_CHECKSUM: u32 = 0x0001;

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
/// One descriptor block and one commit block are the minimum transaction overhead.
const JOURNAL_MIN_TRANSACTION_BLOCKS: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Full filesystem metadata block supplied to the journal commit path.
pub(crate) struct MetadataBlock {
    /// Filesystem block address.
    block: BlockAddress,
    /// Complete metadata block bytes.
    bytes: Vec<u8>,
}

impl MetadataBlock {
    /// Creates a complete metadata block image for a journal transaction.
    pub(crate) fn new(block: BlockAddress, bytes: Vec<u8>) -> Self {
        Self { block, bytes }
    }

    /// Returns the filesystem block address.
    pub(crate) const fn block(&self) -> BlockAddress {
        self.block
    }

    /// Returns the full metadata block bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the mutable full metadata block bytes before commit encoding.
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// One fully allocated storage write in a journal or checkpoint phase.
#[derive(Debug)]
pub(crate) struct PlannedStorageWrite {
    /// Device that receives this write.
    target: StorageTarget,
    /// Starting device byte offset.
    offset: ByteOffset,
    /// Complete owned write image.
    bytes: Vec<u8>,
}

impl PlannedStorageWrite {
    /// Builds one fully owned write plan.
    pub(crate) const fn new(target: StorageTarget, offset: ByteOffset, bytes: Vec<u8>) -> Self {
        Self {
            target,
            offset,
            bytes,
        }
    }

    /// Converts this plan into the concrete storage request submitted by the reactor.
    pub(crate) fn into_request(self) -> StorageRequest {
        StorageRequest::Write {
            target: self.target,
            offset: self.offset,
            buffer: self.bytes,
        }
    }
}

/// Home-block and clean-superblock work detached from the commit visibility gate.
#[derive(Debug)]
pub(crate) struct PreparedJournalCheckpoint {
    /// Preallocated filesystem home-block writes.
    home_writes: Vec<PlannedStorageWrite>,
    /// Preallocated journal superblock write that marks the checkpoint clean.
    clean_write: PlannedStorageWrite,
    /// Clean coordinator journal state published after the clean write is durable.
    clean_journal: Journal<CleanJournal>,
}

impl PreparedJournalCheckpoint {
    /// Consumes the checkpoint into its preallocated parts.
    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<PlannedStorageWrite>,
        PlannedStorageWrite,
        Journal<CleanJournal>,
    ) {
        (self.home_writes, self.clean_write, self.clean_journal)
    }
}

/// Journal transaction serialized completely before its first lower write.
#[derive(Debug)]
pub(crate) struct PreparedJournalCommit {
    /// Dirty-superblock, descriptor, and journal data writes before the first durability flush.
    precommit_writes: Vec<PlannedStorageWrite>,
    /// Commit-record write issued after precommit writes are durable.
    commit_write: PlannedStorageWrite,
    /// Journal device whose flush establishes commit durability.
    journal_target: StorageTarget,
    /// Coordinator journal state after commit durability and before checkpoint completion.
    durable_journal: Journal<DirtyJournal>,
    /// Immutable metadata overlay published at commit durability.
    overlay: Vec<MetadataBlock>,
    /// Independent checkpoint work prepared before the first lower write.
    checkpoint: PreparedJournalCheckpoint,
}

/// Transaction checksum profile selected by validated JBD2 features.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalChecksumProfile {
    /// Descriptor, payload, and commit checksums are absent.
    None,
    /// Descriptor tails and truncated 16-bit payload checksums are present.
    V2,
    /// Descriptor tails and full 32-bit payload checksums are present.
    V3,
}

/// Validated JBD2 interpretation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalProfile {
    /// Payload and control-block checksum representation.
    checksum: JournalChecksumProfile,
    /// Whether tags and revoke records carry 64-bit filesystem block addresses.
    block_numbers_64bit: bool,
}

impl JournalProfile {
    /// Validates feature bits that change JBD2 record interpretation.
    fn from_superblock(superblock: &JournalSuperblock) -> Result<Self> {
        if superblock.compat & JBD2_FEATURE_COMPAT_CHECKSUM != 0
            || superblock.compat & !JBD2_FEATURE_COMPAT_CHECKSUM != 0
            || superblock.ro_compat != 0
            || superblock.incompat
                & (JBD2_FEATURE_INCOMPAT_FAST_COMMIT | JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)
                != 0
            || superblock.incompat & !JBD2_SUPPORTED_INCOMPAT != 0
            || superblock.errno != 0
        {
            return Err(Error::UnsupportedJournal);
        }
        let v2 = superblock.incompat & JBD2_FEATURE_INCOMPAT_CSUM_V2 != 0;
        let v3 = superblock.incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3 != 0;
        let checksum = match (v2, v3) {
            (false, false) => JournalChecksumProfile::None,
            (true, false) => JournalChecksumProfile::V2,
            (false, true) => JournalChecksumProfile::V3,
            (true, true) => return Err(Error::UnsupportedJournal),
        };
        if checksum != JournalChecksumProfile::None
            && superblock.checksum_type != JBD2_CHECKSUM_CRC32C
        {
            return Err(Error::UnsupportedJournal);
        }
        Ok(Self {
            checksum,
            block_numbers_64bit: superblock.incompat & JBD2_FEATURE_INCOMPAT_64BIT != 0,
        })
    }

    const fn has_metadata_checksums(self) -> bool {
        !matches!(self.checksum, JournalChecksumProfile::None)
    }

    const fn has_csum_v3(self) -> bool {
        matches!(self.checksum, JournalChecksumProfile::V3)
    }

    const fn has_64bit(self) -> bool {
        self.block_numbers_64bit
    }
}

/// Validated physical and circular JBD2 address domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalGeometry {
    /// Block size shared by the filesystem and journal device.
    block_size: BlockSize,
    /// Circular range containing transaction records.
    ring: JournalRing,
}

impl JournalGeometry {
    fn from_superblock(
        superblock: &JournalSuperblock,
        block_size: BlockSize,
        capacity_blocks: u32,
    ) -> Result<Self> {
        if superblock.block_size != block_size.bytes() {
            return Err(Error::UnsupportedJournal);
        }
        Ok(Self {
            block_size,
            ring: JournalRing::new(superblock, capacity_blocks)?,
        })
    }
}

/// Next sequence and clean-log head used by all Journal typestates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalCursor {
    /// Sequence expected for the next committed transaction.
    sequence: JournalSequence,
    /// Logical ring block where the next transaction begins.
    head: u32,
}

impl JournalCursor {
    fn from_superblock(superblock: &JournalSuperblock, ring: JournalRing) -> Result<Self> {
        let head = if superblock.version == JournalSuperblockVersion::V1 {
            ring.first
        } else {
            superblock.head
        };
        if head < ring.first || head >= ring.maxlen {
            return Err(Error::JournalCorrupt);
        }
        Ok(Self {
            sequence: superblock.sequence,
            head,
        })
    }
}

impl PreparedJournalCommit {
    /// Consumes the commit into its preallocated phase values.
    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<PlannedStorageWrite>,
        PlannedStorageWrite,
        StorageTarget,
        Journal<DirtyJournal>,
        Vec<MetadataBlock>,
        PreparedJournalCheckpoint,
    ) {
        (
            self.precommit_writes,
            self.commit_write,
            self.journal_target,
            self.durable_journal,
            self.overlay,
            self.checkpoint,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// JBD2 journal with typestate-tracked replay and commit phases.
pub(crate) struct Journal<State = CleanJournal> {
    /// Physical location of the journal blocks.
    location: JournalLocation,
    /// Parsed journal superblock kept as the mutable journal metadata source.
    superblock: JournalSuperblock,
    /// Feature-dependent wire interpretation.
    profile: JournalProfile,
    /// Validated block and circular-log geometry.
    geometry: JournalGeometry,
    /// Next sequence and clean head.
    cursor: JournalCursor,
    /// Filesystem block count used to reject journal entries outside the volume.
    filesystem_blocks: u64,
    /// Typestate marker for loaded, clean, or commit-durable journal state.
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
    /// # Errors
    ///
    /// Returns an error when copying the typestate-independent journal data cannot allocate.
    fn copy_without_state<Next>(&self) -> Result<Journal<Next>> {
        Ok(Journal {
            location: self.location.try_clone()?,
            superblock: self.superblock.try_clone()?,
            profile: self.profile,
            geometry: self.geometry,
            cursor: self.cursor,
            filesystem_blocks: self.filesystem_blocks,
            state: PhantomData,
        })
    }

    /// Loads an internal journal stored in the filesystem journal inode.
    /// # Errors
    ///
    /// Returns an error when the inode is not a supported extent-backed journal, the journal
    /// superblock cannot be read or parsed, or the ring layout is inconsistent with the inode size.
    pub(crate) fn from_inode(
        inode: &Inode,
        block_size: BlockSize,
        filesystem_blocks: u64,
        reader: &mut OperationDevice<'_>,
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
        if capacity_blocks <= JOURNAL_MIN_TRANSACTION_BLOCKS {
            return Err(Error::UnsupportedJournal);
        }

        let tree = ExtentTree::load_inode_tree(
            inode.extent_root()?,
            block_size,
            reader,
            ExtentTreeContext::none(),
        )?;
        let location = JournalLocation::Internal(InternalJournalLayout::new(
            tree.extents(),
            capacity_blocks,
            filesystem_blocks,
        )?);
        let mut raw = memory::repeated_vec(
            0_u8,
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        read_journal_block(reader, &location, block_size, 0, &mut raw)?;
        let superblock = JournalSuperblock::parse(&raw)?;
        let profile = JournalProfile::from_superblock(&superblock)?;
        let geometry = JournalGeometry::from_superblock(&superblock, block_size, capacity_blocks)?;
        location.validate_ring(&geometry.ring)?;
        let cursor = JournalCursor::from_superblock(&superblock, geometry.ring)?;

        Ok(Journal {
            location,
            superblock,
            profile,
            geometry,
            cursor,
            filesystem_blocks,
            state: PhantomData,
        })
    }

    /// Serializes every commit, publish-overlay, and checkpoint allocation before the first write.
    /// # Errors
    ///
    /// Returns an error when the journal is not clean, the transaction does not fit, serialization
    /// fails, or any required owned image cannot be allocated.
    pub(crate) fn prepare_commit(
        &self,
        block_size: BlockSize,
        metadata_blocks: Vec<MetadataBlock>,
    ) -> Result<PreparedJournalCommit> {
        if self.superblock.start() != 0 {
            return Err(Error::JournalCorrupt);
        }
        let prepared = self.prepare_metadata_transaction(block_size, &metadata_blocks)?;
        let journal_target = self.location.storage_target();
        let dirty_superblock =
            self.superblock
                .encode_dirty(block_size, prepared.descriptor, prepared.sequence)?;
        let dirty_state_bytes = memory::copied_slice(&dirty_superblock)?;
        let mut durable_journal = self.copy_without_state::<DirtyJournal>()?;
        durable_journal.superblock.apply_dirty(
            prepared.descriptor,
            prepared.sequence,
            dirty_state_bytes,
        );
        durable_journal.cursor = prepared.next_cursor;

        let additional_precommit = prepared
            .log_blocks
            .len()
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut precommit_writes = Vec::new();
        precommit_writes
            .try_reserve_exact(additional_precommit)
            .map_err(|_| Error::OutOfMemory)?;
        precommit_writes.try_push(PlannedStorageWrite::new(
            journal_target,
            self.offset_of(0, block_size)?,
            dirty_superblock,
        ))?;
        let mut cursor = prepared.descriptor;
        for block in prepared.log_blocks {
            precommit_writes.try_push(PlannedStorageWrite::new(
                journal_target,
                self.offset_of(cursor, block_size)?,
                block,
            ))?;
            cursor = self.next_logical(cursor)?;
        }
        if cursor != prepared.commit {
            return Err(Error::JournalCorrupt);
        }
        let commit_write = PlannedStorageWrite::new(
            journal_target,
            self.offset_of(cursor, block_size)?,
            prepared.commit_block,
        );

        let clean_bytes = self
            .superblock
            .encode_clean(block_size, prepared.next_cursor)?;
        let clean_state_bytes = memory::copied_slice(&clean_bytes)?;
        let mut clean_journal = self.copy_without_state::<CleanJournal>()?;
        clean_journal.cursor = prepared.next_cursor;
        clean_journal
            .superblock
            .apply_clean(prepared.next_cursor, clean_state_bytes);
        let clean_write =
            PlannedStorageWrite::new(journal_target, self.offset_of(0, block_size)?, clean_bytes);

        let mut home_writes = Vec::new();
        home_writes
            .try_reserve_exact(metadata_blocks.len())
            .map_err(|_| Error::OutOfMemory)?;
        for metadata in &metadata_blocks {
            home_writes.try_push(PlannedStorageWrite::new(
                StorageTarget::Filesystem,
                block_size.offset_of(metadata.block())?,
                memory::copied_slice(metadata.bytes())?,
            ))?;
        }

        Ok(PreparedJournalCommit {
            precommit_writes,
            commit_write,
            journal_target,
            durable_journal,
            overlay: metadata_blocks,
            checkpoint: PreparedJournalCheckpoint {
                home_writes,
                clean_write,
                clean_journal,
            },
        })
    }

    /// Builds descriptor, escaped data blocks, and commit block for a transaction.
    /// # Errors
    ///
    /// Returns an error when the transaction is too large, a metadata block has the wrong size, data
    /// escaping fails, or descriptor/commit serialization fails.
    fn prepare_metadata_transaction(
        &self,
        block_size: BlockSize,
        metadata_blocks: &[MetadataBlock],
    ) -> Result<PreparedJournalTransaction> {
        let credits = self.journal_credits(metadata_blocks.len(), block_size)?;
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let mut data_blocks = Vec::new();
        data_blocks
            .try_reserve_exact(metadata_blocks.len())
            .map_err(|_| Error::OutOfMemory)?;
        for metadata in metadata_blocks {
            if metadata.bytes().len() != block_bytes {
                return Err(Error::InvalidWriteRange);
            }
            let mut data = memory::copied_slice(metadata.bytes())?;
            if starts_with_jbd2_magic(&data) {
                put_be_u32(&mut data, disk_offset(0), 0)?;
            }
            data_blocks.try_push(data)?;
        }

        let sequence = self.cursor.sequence;
        let descriptor = self.cursor.head;
        let log_capacity = credits
            .descriptors
            .checked_add(credits.payloads)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut log_blocks = Vec::new();
        log_blocks
            .try_reserve_exact(log_capacity)
            .map_err(|_| Error::OutOfMemory)?;
        let mut first = 0_usize;
        while first < metadata_blocks.len() {
            let end = self.descriptor_group_end(first, metadata_blocks.len(), block_size)?;
            log_blocks.try_push(
                self.encode_descriptor_block(
                    sequence,
                    metadata_blocks
                        .get(first..end)
                        .ok_or(Error::InvalidWriteRange)?,
                    data_blocks
                        .get(first..end)
                        .ok_or(Error::InvalidWriteRange)?,
                    block_size,
                )?,
            )?;
            for data in data_blocks
                .get(first..end)
                .ok_or(Error::InvalidWriteRange)?
            {
                log_blocks.try_push(memory::copied_slice(data)?)?;
            }
            first = end;
        }
        if log_blocks.len()
            != credits
                .descriptors
                .checked_add(credits.payloads)
                .ok_or(Error::ArithmeticOverflow)?
            || credits.total
                != u32::try_from(
                    log_blocks
                        .len()
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .map_err(|_| Error::ArithmeticOverflow)?
        {
            return Err(Error::JournalCorrupt);
        }
        let mut commit = descriptor;
        for _ in 0..log_blocks.len() {
            commit = self.next_logical(commit)?;
        }
        let next_head = self.next_logical(commit)?;
        let next_cursor = JournalCursor {
            sequence: sequence.next(),
            head: next_head,
        };
        Ok(PreparedJournalTransaction {
            sequence,
            descriptor,
            log_blocks,
            commit,
            next_cursor,
            commit_block: self.encode_commit_block(sequence, block_size)?,
        })
    }

    /// Computes exact descriptor and ring credits from the active wire profile.
    /// # Errors
    ///
    /// Returns an error when no metadata payload is present, a descriptor cannot hold its required
    /// explicit UUID tag, arithmetic overflows, or the complete transaction does not fit the ring.
    fn journal_credits(&self, payloads: usize, block_size: BlockSize) -> Result<JournalCredits> {
        if payloads == 0 || block_size != self.geometry.block_size {
            return Err(Error::InvalidWriteRange);
        }
        let descriptor_capacity = self.descriptor_tag_capacity()?;
        let descriptors = payloads
            .checked_add(
                descriptor_capacity
                    .checked_sub(1)
                    .ok_or(Error::TransactionTooLarge)?,
            )
            .ok_or(Error::ArithmeticOverflow)?
            .checked_div(descriptor_capacity)
            .ok_or(Error::TransactionTooLarge)?;
        let total_usize = descriptors
            .checked_add(payloads)
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::ArithmeticOverflow)?;
        let total = u32::try_from(total_usize).map_err(|_| Error::TransactionTooLarge)?;
        if total > self.usable_log_blocks()? {
            return Err(Error::TransactionTooLarge);
        }
        Ok(JournalCredits {
            descriptors,
            payloads,
            total,
        })
    }

    /// Returns the exclusive tag index for one descriptor block.
    /// # Errors
    ///
    /// Returns an error when `first` is outside the transaction or descriptor arithmetic overflows.
    fn descriptor_group_end(
        &self,
        first: usize,
        payloads: usize,
        block_size: BlockSize,
    ) -> Result<usize> {
        if first >= payloads || block_size != self.geometry.block_size {
            return Err(Error::InvalidWriteRange);
        }
        Ok(first
            .checked_add(self.descriptor_tag_capacity()?)
            .ok_or(Error::ArithmeticOverflow)?
            .min(payloads))
    }

    /// Scans the journal ring for complete committed transactions.
    /// # Errors
    ///
    /// Returns an error when usable ring bounds cannot be computed or a transaction block cannot be
    /// read and parsed.
    fn committed_transactions(
        &self,
        journal: &mut OperationDevice<'_>,
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
        let mut sequence = self.cursor.sequence;
        let mut consumed = 0_u32;
        while consumed < self.usable_log_blocks()? {
            match self.parse_transaction(journal, block_size, cursor, sequence)? {
                JournalTransactionScan::Committed {
                    transaction,
                    next_cursor,
                    consumed: transaction_blocks,
                } => {
                    transactions.try_push(transaction)?;
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
    /// # Errors
    ///
    /// Returns an error when a transaction has inconsistent sequence numbers, duplicate descriptor
    /// blocks, corrupt escaped data, duplicate home blocks, invalid revokes, or a bad commit block.
    fn parse_transaction(
        &self,
        journal: &mut OperationDevice<'_>,
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
            let block = self.read_journal_block(journal, block_size, cursor)?;
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
                        let mut data = self.read_journal_block(journal, block_size, cursor)?;
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
                            transaction.events.try_push(JournalTransactionEvent::Entry(
                                JournalEntry {
                                    home: tag.block,
                                    bytes: data,
                                },
                            ))?;
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
                            .try_push(JournalTransactionEvent::Revoke(block))?;
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
    /// # Errors
    ///
    /// Returns an error when the journal block size cannot be allocated or the logical block cannot
    /// be read from the journal location.
    fn read_journal_block(
        &self,
        journal: &mut OperationDevice<'_>,
        block_size: BlockSize,
        logical: u32,
    ) -> Result<Vec<u8>> {
        let mut block = memory::repeated_vec(
            0_u8,
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        journal.read_exact_at(self.offset_of(logical, block_size)?, &mut block)?;
        Ok(block)
    }

    /// Rejects replay targets outside the filesystem or inside the internal journal.
    /// # Errors
    ///
    /// Returns an error when the replay target is beyond the filesystem or overlaps the internal
    /// journal's home blocks.
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
    /// # Errors
    ///
    /// Returns an error when the descriptor tail checksum is invalid, no last tag is present, or any
    /// tag is malformed.
    fn parse_descriptor_block(&self, block: &[u8]) -> Result<JournalDescriptor> {
        self.verify_block_tail_checksum(block)?;
        let mut offset = JOURNAL_HEADER_BYTES;
        let limit = if self.profile.has_metadata_checksums() {
            block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?
        } else {
            block.len()
        };
        let mut tags = Vec::new();
        let mut saw_last = false;
        while offset < limit {
            let Some((tag, next_offset)) = self.parse_tag(block, offset, limit, tags.is_empty())?
            else {
                return Err(Error::JournalCorrupt);
            };
            let last = tag.flags & JBD2_TAG_FLAG_LAST_TAG != 0;
            tags.try_push(tag)?;
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
    /// # Errors
    ///
    /// Returns an error when tag fields exceed the descriptor payload, tag flags are unsupported, or
    /// an embedded UUID does not match the journal superblock.
    fn parse_tag(
        &self,
        block: &[u8],
        offset: usize,
        limit: usize,
        first_tag: bool,
    ) -> Result<Option<(JournalTag, usize)>> {
        if self.profile.has_csum_v3() {
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
            if first_tag && flags & JBD2_TAG_FLAG_SAME_UUID != 0 {
                return Err(Error::JournalCorrupt);
            }
            if !self.profile.has_64bit() && block_high != 0 {
                return Err(Error::JournalCorrupt);
            }
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
        if first_tag && flags & JBD2_TAG_FLAG_SAME_UUID != 0 {
            return Err(Error::JournalCorrupt);
        }
        let high_size = if self.profile.has_64bit() { 4 } else { 0 };
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
    /// # Errors
    ///
    /// Returns an error when the revoke block checksum is invalid, its used length is inconsistent,
    /// or its block-address entries are not exactly aligned.
    fn parse_revoke_block(&self, block: &[u8]) -> Result<JournalRevoke> {
        self.verify_block_tail_checksum(block)?;
        let used = usize::try_from(be_u32(block, disk_offset(JOURNAL_HEADER_BYTES))?)
            .map_err(|_| Error::JournalCorrupt)?;
        if used < 16 || used > block.len() {
            return Err(Error::JournalCorrupt);
        }
        let tail = if self.profile.has_metadata_checksums() {
            4
        } else {
            0
        };
        let limit = used.checked_sub(tail).ok_or(Error::JournalCorrupt)?;
        let entry_size = if self.profile.has_64bit() { 8 } else { 4 };
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
            blocks.try_push(BlockAddress::new(block))?;
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
    /// # Errors
    ///
    /// Returns an error when the block is not a commit block for `expected_sequence`, checksum
    /// metadata fields are invalid, or the commit checksum fails.
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
        if self.profile.has_metadata_checksums() {
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
    /// # Errors
    ///
    /// Returns an error when the block size cannot be allocated, a data block is missing, a tag does
    /// not fit, or the descriptor tail checksum cannot be written.
    fn encode_descriptor_block(
        &self,
        sequence: JournalSequence,
        metadata_blocks: &[MetadataBlock],
        data_blocks: &[Vec<u8>],
        block_size: BlockSize,
    ) -> Result<Vec<u8>> {
        let mut block = memory::repeated_vec(
            0_u8,
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        Jbd2Header::descriptor(sequence.get()).encode(&mut block)?;
        let mut offset = JOURNAL_HEADER_BYTES;
        for (index, metadata) in metadata_blocks.iter().enumerate() {
            let last =
                index.checked_add(1).ok_or(Error::ArithmeticOverflow)? == metadata_blocks.len();
            let data = data_blocks.get(index).ok_or(Error::InvalidWriteRange)?;
            let flags = if index == 0 {
                0
            } else {
                JBD2_TAG_FLAG_SAME_UUID
            } | if last { JBD2_TAG_FLAG_LAST_TAG } else { 0 }
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
    /// # Errors
    ///
    /// Returns an error when the tag would exceed the descriptor payload or its block address,
    /// checksum, or flags cannot be represented in the active tag format.
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
        if !self.profile.has_64bit() && metadata.block().get() > u64::from(u32::MAX) {
            return Err(Error::TransactionTooLarge);
        }
        let uuid_size = if flags & JBD2_TAG_FLAG_SAME_UUID == 0 {
            16
        } else {
            0
        };
        if self.profile.has_csum_v3() {
            let next = offset
                .checked_add(16)
                .and_then(|value| value.checked_add(uuid_size))
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
            put_be_u32(block, disk_offset(offset).checked_add_bytes(4)?, flags)?;
            put_be_u32(
                block,
                disk_offset(offset).checked_add_bytes(8)?,
                u32::try_from(metadata.block().get() >> 32)
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            put_be_u32(block, disk_offset(offset).checked_add_bytes(12)?, checksum)?;
            if uuid_size == 16 {
                memory::copy_exact(
                    block
                        .get_mut(offset.checked_add(16).ok_or(Error::ArithmeticOverflow)?..next)
                        .ok_or(Error::TruncatedStructure)?,
                    self.superblock.uuid(),
                )?;
            }
            return Ok(next);
        }

        let high_size = if self.profile.has_64bit() { 4 } else { 0 };
        let next = offset
            .checked_add(8)
            .and_then(|value| value.checked_add(high_size))
            .and_then(|value| value.checked_add(uuid_size))
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
        if uuid_size == 16 {
            let uuid_start = offset
                .checked_add(8)
                .and_then(|value| value.checked_add(high_size))
                .ok_or(Error::ArithmeticOverflow)?;
            memory::copy_exact(
                block
                    .get_mut(uuid_start..next)
                    .ok_or(Error::TruncatedStructure)?,
                self.superblock.uuid(),
            )?;
        }
        Ok(next)
    }

    /// Encodes the commit block that makes a transaction durable.
    /// # Errors
    ///
    /// Returns an error when the block size cannot be allocated, the header cannot be written, or
    /// commit checksum fields are outside the block.
    fn encode_commit_block(
        &self,
        sequence: JournalSequence,
        block_size: BlockSize,
    ) -> Result<Vec<u8>> {
        let mut block = memory::repeated_vec(
            0_u8,
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        Jbd2Header::commit(sequence.get()).encode(&mut block)?;
        if self.profile.has_metadata_checksums() {
            *block.get_mut(0x0C).ok_or(Error::TruncatedStructure)? = JBD2_CHECKSUM_CRC32C;
            *block.get_mut(0x0D).ok_or(Error::TruncatedStructure)? = 4;
            let checksum = self.block_checksum_with_zeroed(&block, 0x10)?;
            put_be_u32(&mut block, disk_offset(0x10), checksum)?;
        }
        Ok(block)
    }

    /// Returns the number of usable blocks in the journal ring.
    /// # Errors
    ///
    /// Returns an error when ring geometry leaves no usable journal blocks.
    fn usable_log_blocks(&self) -> Result<u32> {
        self.geometry.ring.usable_blocks()
    }

    /// Returns how many tags fit in one descriptor block.
    /// # Errors
    ///
    /// Returns an error when the journal block cannot hold the descriptor header, optional tail, and
    /// at least one tag.
    fn descriptor_tag_capacity(&self) -> Result<usize> {
        let block_bytes = usize::try_from(self.geometry.block_size.bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let tail_bytes = if self.profile.has_metadata_checksums() {
            4
        } else {
            0
        };
        let usable = block_bytes
            .checked_sub(JOURNAL_HEADER_BYTES)
            .and_then(|value| value.checked_sub(tail_bytes))
            .ok_or(Error::TransactionTooLarge)?;
        let tag_size = self.descriptor_tag_size();
        let first_tag_size = tag_size.checked_add(16).ok_or(Error::ArithmeticOverflow)?;
        let remaining = usable
            .checked_sub(first_tag_size)
            .ok_or(Error::TransactionTooLarge)?;
        Ok(remaining
            .checked_div(tag_size)
            .ok_or(Error::TransactionTooLarge)?
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?)
    }

    /// Returns the serialized tag width for the active JBD2 feature set.
    fn descriptor_tag_size(&self) -> usize {
        if self.profile.has_csum_v3() {
            16
        } else if self.profile.has_64bit() {
            12
        } else {
            8
        }
    }

    /// Returns the descriptor payload limit before an optional checksum tail.
    /// # Errors
    ///
    /// Returns an error when metadata checksums are enabled but the block is smaller than its tail.
    fn descriptor_payload_limit(&self, block_len: usize) -> Result<usize> {
        if self.profile.has_metadata_checksums() {
            block_len.checked_sub(4).ok_or(Error::InvalidSuperblock)
        } else {
            Ok(block_len)
        }
    }

    /// Advances a logical journal block with ring wraparound.
    /// # Errors
    ///
    /// Returns an error when the logical block is outside the validated journal ring.
    fn next_logical(&self, logical: u32) -> Result<u32> {
        self.geometry.ring.next(logical)
    }

    /// Verifies a descriptor tag checksum against its data block.
    /// # Errors
    ///
    /// Returns an error when the computed data checksum does not match the tag checksum.
    fn verify_tag_checksum(
        &self,
        sequence: JournalSequence,
        tag: &JournalTag,
        data: &[u8],
    ) -> Result<()> {
        if !self.profile.has_metadata_checksums() {
            return Ok(());
        }
        let actual = self.tag_checksum(sequence, data)?;
        let expected = if self.profile.has_csum_v3() {
            tag.checksum
        } else {
            tag.checksum & u32::from(u16::MAX)
        };
        let actual = if self.profile.has_csum_v3() {
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
    /// # Errors
    ///
    /// Returns an error when the sequence number cannot be written into the checksum seed buffer.
    fn tag_checksum(&self, sequence: JournalSequence, data: &[u8]) -> Result<u32> {
        let mut sequence_bytes = [0_u8; 4];
        put_be_u32(&mut sequence_bytes, disk_offset(0), sequence.get())?;
        let seed = ext4_crc32c(u32::MAX, self.superblock.uuid());
        let seed = ext4_crc32c(seed, &sequence_bytes);
        Ok(ext4_crc32c(seed, data))
    }

    /// Verifies the optional checksum stored at the end of a control block.
    /// # Errors
    ///
    /// Returns an error when the control block is too short for a tail checksum or the computed
    /// checksum differs from the stored value.
    fn verify_block_tail_checksum(&self, block: &[u8]) -> Result<()> {
        if !self.profile.has_metadata_checksums() {
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
    /// # Errors
    ///
    /// Returns an error when the control block is too short for a tail checksum or the checksum
    /// field cannot be written.
    fn write_block_tail_checksum(&self, block: &mut [u8]) -> Result<()> {
        if !self.profile.has_metadata_checksums() {
            return Ok(());
        }
        let offset = block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?;
        let checksum = self.block_checksum_with_zeroed(block, offset)?;
        put_be_u32(block, disk_offset(offset), checksum)
    }

    /// Verifies the checksum field embedded in a commit block.
    /// # Errors
    ///
    /// Returns an error when the commit checksum field is truncated or does not match the block
    /// checksum with that field zeroed.
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
    /// # Errors
    ///
    /// Returns an error when the checksum field range overflows or is outside the control block.
    fn block_checksum_with_zeroed(&self, block: &[u8], checksum_offset: usize) -> Result<u32> {
        let end = checksum_offset
            .checked_add(4)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut checked = memory::copied_slice(block)?;
        checked
            .get_mut(checksum_offset..end)
            .ok_or(Error::TruncatedStructure)?
            .fill(0);
        Ok(ext4_crc32c(
            ext4_crc32c(u32::MAX, self.superblock.uuid()),
            &checked,
        ))
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
    /// # Errors
    ///
    /// Returns an error when `first`, `maxlen`, or `start` falls outside the supported ring shape or
    /// physical journal capacity.
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
    /// # Errors
    ///
    /// Returns an error when `maxlen` does not leave any blocks after `first`.
    fn usable_blocks(self) -> Result<u32> {
        self.maxlen
            .checked_sub(self.first)
            .ok_or(Error::UnsupportedJournal)
    }

    /// Returns the next logical block, wrapping at the ring end.
    /// # Errors
    ///
    /// Returns an error when `logical` is outside the ring or advancing it overflows.
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
    External,
}

impl JournalLocation {
    /// Selects the concrete device that stores this journal.
    const fn storage_target(&self) -> StorageTarget {
        match self {
            Self::Internal(_) => StorageTarget::Filesystem,
            Self::External => StorageTarget::ExternalJournal,
        }
    }

    /// Copies this journal location without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the internal journal layout cannot allocate.
    fn try_clone(&self) -> Result<Self> {
        match self {
            Self::Internal(layout) => Ok(Self::Internal(layout.try_clone()?)),
            Self::External => Ok(Self::External),
        }
    }

    /// Maps a logical journal block to a byte offset on its backing device.
    /// # Errors
    ///
    /// Returns an error when the logical block is not backed by the internal layout or exceeds the
    /// external journal capacity.
    fn offset_of(&self, logical: u32, block_size: BlockSize) -> Result<ByteOffset> {
        match self {
            Self::Internal(layout) => block_size.offset_of(layout.map_logical(logical)?),
            Self::External => block_size.offset_of(BlockAddress::new(u64::from(logical))),
        }
    }

    /// Verifies that the journal ring is backed by the selected location.
    /// # Errors
    ///
    /// Returns an error when the selected physical location does not cover the validated ring.
    fn validate_ring(&self, ring: &JournalRing) -> Result<()> {
        match self {
            Self::Internal(layout) => layout.validate_ring(ring),
            Self::External => {
                let _ = ring;
                Err(Error::UnsupportedJournal)
            }
        }
    }

    /// Returns whether a filesystem home block overlaps the internal journal.
    /// # Errors
    ///
    /// Returns an error when the internal journal extent mapping cannot be evaluated.
    fn contains_home_block(&self, block: BlockAddress) -> Result<bool> {
        match self {
            Self::Internal(layout) => layout.contains_physical(block),
            Self::External => Ok(false),
        }
    }

    /// Returns the physical journal capacity in blocks.
    const fn capacity_blocks(&self) -> u32 {
        match self {
            Self::Internal(layout) => layout.capacity_blocks(),
            Self::External => 0,
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
    /// Copies this internal journal layout without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the extent list cannot allocate.
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            extents: memory::copied_slice(&self.extents)?,
            capacity_blocks: self.capacity_blocks,
        })
    }

    /// Converts inode extents into a contiguous logical journal layout.
    /// # Errors
    ///
    /// Returns an error when an inode extent exceeds journal capacity or its logical/physical bounds
    /// overflow.
    fn new(
        extents: &[crate::disk_format::extent::Extent],
        capacity_blocks: u32,
        filesystem_blocks: u64,
    ) -> Result<Self> {
        let mut mapped = Vec::new();
        mapped
            .try_reserve_exact(extents.len())
            .map_err(|_| Error::OutOfMemory)?;
        for extent in extents {
            let len = extent.len().as_u32();
            let logical_start = extent.logical_start().as_u32();
            let logical_end = logical_start
                .checked_add(len)
                .ok_or(Error::ArithmeticOverflow)?;
            if logical_end > capacity_blocks {
                return Err(Error::UnsupportedJournal);
            }
            let mapped_extent =
                JournalExtent::new(logical_start, logical_end, extent.physical_start(), len)?;
            if mapped_extent.physical_end > filesystem_blocks {
                return Err(Error::UnsupportedJournal);
            }
            mapped.try_push(mapped_extent)?;
        }
        memory::heap_sort_by(&mut mapped, |left, right| {
            left.logical_start.cmp(&right.logical_start)
        })?;
        let mut logical_cursor = 0_u32;
        for (index, extent) in mapped.iter().enumerate() {
            if extent.logical_start != logical_cursor {
                return Err(Error::UnsupportedJournal);
            }
            logical_cursor = extent.logical_end;
            for prior in mapped.get(..index).ok_or(Error::InvalidWriteRange)? {
                if extent.physical_start.get() < prior.physical_end
                    && prior.physical_start.get() < extent.physical_end
                {
                    return Err(Error::UnsupportedJournal);
                }
            }
        }
        if logical_cursor != capacity_blocks {
            return Err(Error::UnsupportedJournal);
        }
        Ok(Self {
            extents: mapped,
            capacity_blocks,
        })
    }

    /// Verifies that extents cover the journal ring from logical block zero.
    /// # Errors
    ///
    /// Returns an error when journal inode extents are not contiguous from block zero through the
    /// ring end.
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
    /// # Errors
    ///
    /// Returns an error when no journal inode extent covers `logical` or the physical mapping
    /// overflows.
    fn map_logical(&self, logical: u32) -> Result<BlockAddress> {
        for extent in &self.extents {
            if let Some(block) = extent.map_logical(logical)? {
                return Ok(block);
            }
        }
        Err(Error::UnsupportedJournal)
    }

    /// Returns whether a physical filesystem block belongs to the journal inode.
    /// # Errors
    ///
    /// Returns an error when an extent's physical range cannot be evaluated.
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
    /// # Errors
    ///
    /// Returns an error when `physical_start + len` overflows.
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
    /// # Errors
    ///
    /// Returns an error when subtracting the extent start or adding the physical offset overflows.
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
enum JournalSuperblockVersion {
    V1,
    V2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Parsed JBD2 superblock with raw bytes retained for state updates.
pub(crate) struct JournalSuperblock {
    /// Raw superblock image used as the base for clean/dirty rewrites.
    raw: Vec<u8>,
    /// On-disk JBD2 superblock generation.
    version: JournalSuperblockVersion,
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
    /// Aborted-journal error code recorded by JBD2.
    errno: u32,
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
    /// Clean-log head recorded by v2 superblocks.
    head: u32,
    /// Number of filesystems attached to an external journal.
    nr_users: u32,
    /// First external-journal user UUID.
    first_user: [u8; 16],
}

impl JournalSuperblock {
    /// Copies this parsed superblock without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the raw superblock image cannot allocate.
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            raw: memory::copied_slice(&self.raw)?,
            version: self.version,
            block_size: self.block_size,
            maxlen: self.maxlen,
            first: self.first,
            sequence: self.sequence,
            start: self.start,
            errno: self.errno,
            compat: self.compat,
            incompat: self.incompat,
            ro_compat: self.ro_compat,
            uuid: self.uuid,
            checksum_type: self.checksum_type,
            head: self.head,
            nr_users: self.nr_users,
            first_user: self.first_user,
        })
    }

    /// Parses and verifies a JBD2 superblock image.
    /// # Errors
    ///
    /// Returns an error when the image is truncated, lacks a JBD2 superblock header, has an invalid
    /// superblock checksum, or required fields are missing.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < JOURNAL_SUPERBLOCK_BYTES {
            return Err(Error::TruncatedStructure);
        }
        let header = Jbd2Header::parse(bytes)?;
        let version = match header.block_type() {
            JBD2_SUPERBLOCK_V1 => JournalSuperblockVersion::V1,
            JBD2_SUPERBLOCK_V2 => JournalSuperblockVersion::V2,
            _ => return Err(Error::UnsupportedJournal),
        };
        let mut uuid = [0_u8; 16];
        memory::copy_exact(
            &mut uuid,
            bytes.get(0x30..0x40).ok_or(Error::TruncatedStructure)?,
        )?;
        let mut first_user = [0_u8; 16];
        memory::copy_exact(
            &mut first_user,
            bytes.get(0x100..0x110).ok_or(Error::TruncatedStructure)?,
        )?;
        if be_u32(bytes, disk_offset(0xFC))? != 0 {
            verify_journal_superblock_checksum(bytes)?;
        }
        Ok(Self {
            raw: memory::copied_slice(bytes)?,
            version,
            block_size: be_u32(bytes, disk_offset(0x0C))?,
            maxlen: be_u32(bytes, disk_offset(0x10))?,
            first: be_u32(bytes, disk_offset(0x14))?,
            sequence: JournalSequence::new(be_u32(bytes, disk_offset(0x18))?),
            start: be_u32(bytes, disk_offset(0x1C))?,
            errno: be_u32(bytes, disk_offset(0x20))?,
            compat: be_u32(bytes, disk_offset(0x24))?,
            incompat: be_u32(bytes, disk_offset(0x28))?,
            ro_compat: be_u32(bytes, disk_offset(0x2C))?,
            uuid,
            checksum_type: *bytes.get(0x50).ok_or(Error::TruncatedStructure)?,
            head: be_u32(bytes, disk_offset(0x58))?,
            nr_users: be_u32(bytes, disk_offset(0x40))?,
            first_user,
        })
    }

    /// Validates JBD2 features and ring geometry for mounting.
    /// # Errors
    ///
    /// Returns an error when block size, feature bits, checksum type, or ring geometry are outside
    /// the supported JBD2 profile.
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
    /// # Errors
    ///
    /// Returns an error when the retained raw superblock length does not match `block_size` or the
    /// sequence/start/checksum fields cannot be rewritten.
    fn encode_with_state(
        &self,
        block_size: BlockSize,
        sequence: JournalSequence,
        start: u32,
        head: u32,
    ) -> Result<Vec<u8>> {
        let block_len =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        if self.raw.len() != block_len {
            return Err(Error::JournalCorrupt);
        }
        let mut block = memory::copied_slice(&self.raw)?;
        put_be_u32(&mut block, disk_offset(0x18), sequence.get())?;
        put_be_u32(&mut block, disk_offset(0x1C), start)?;
        if self.version == JournalSuperblockVersion::V2 {
            put_be_u32(&mut block, disk_offset(0x58), head)?;
        }
        if self.has_superblock_checksum()? {
            refresh_journal_superblock_checksum(&mut block)?;
        }
        Ok(block)
    }

    /// Encodes a clean journal superblock with no pending transaction tail.
    /// # Errors
    ///
    /// Returns an error when the clean sequence/start state cannot be encoded into a valid
    /// superblock image.
    fn encode_clean(&self, block_size: BlockSize, cursor: JournalCursor) -> Result<Vec<u8>> {
        self.encode_with_state(block_size, cursor.sequence, 0, cursor.head)
    }

    /// Encodes a dirty journal superblock pointing at a transaction descriptor.
    /// # Errors
    ///
    /// Returns an error when the dirty sequence/start state cannot be encoded into a valid
    /// superblock image.
    fn encode_dirty(
        &self,
        block_size: BlockSize,
        start: u32,
        sequence: JournalSequence,
    ) -> Result<Vec<u8>> {
        self.encode_with_state(block_size, sequence, start, start)
    }

    /// Applies the clean superblock state after it has been written.
    fn apply_clean(&mut self, cursor: JournalCursor, raw: Vec<u8>) {
        self.sequence = cursor.sequence;
        self.start = 0;
        self.head = cursor.head;
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
    /// # Errors
    ///
    /// Returns an error when the checksum field is outside the retained raw superblock image.
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
    /// # Errors
    ///
    /// Returns an error when the header is truncated or the JBD2 magic does not match.
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
    /// # Errors
    ///
    /// Returns an error when the destination block is too small for a JBD2 header.
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
    /// Logical journal block where the descriptor will be written.
    descriptor: u32,
    /// Descriptor and escaped payload blocks in exact on-disk order.
    log_blocks: Vec<Vec<u8>>,
    /// Logical journal block where the commit record is written.
    commit: u32,
    /// Cursor stored after checkpoint or recovery completes.
    next_cursor: JournalCursor,
    /// Serialized commit block.
    commit_block: Vec<u8>,
}

/// Exact log-space accounting for one full-commit transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalCredits {
    /// Number of descriptor blocks required by the tag stream.
    descriptors: usize,
    /// Number of metadata payload blocks.
    payloads: usize,
    /// Descriptor, payload, and final commit blocks combined.
    total: u32,
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

impl<State> Journal<State> {
    /// Maps a logical journal block to a byte offset for this journal.
    /// # Errors
    ///
    /// Returns an error when the journal location cannot map `logical` to a device offset.
    fn offset_of(&self, logical: u32, block_size: BlockSize) -> Result<ByteOffset> {
        self.location.offset_of(logical, block_size)
    }
}

/// Reads a logical journal block from an arbitrary journal location.
/// # Errors
///
/// Returns an error when the location cannot map `logical` or the backing reader fails.
fn read_journal_block(
    reader: &mut OperationDevice<'_>,
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
/// # Errors
///
/// Returns an error when any tag flag outside the supported escape, same-UUID, deleted, and last-tag
/// set is present.
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
/// # Errors
///
/// Returns an error when the checksum field is truncated or the computed checksum differs from the
/// stored value.
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
/// # Errors
///
/// Returns an error when the journal superblock checksum field cannot be zeroed or rewritten.
fn refresh_journal_superblock_checksum(block: &mut [u8]) -> Result<()> {
    put_be_u32(block, disk_offset(0xFC), 0)?;
    let checksum = journal_superblock_checksum(block)?;
    put_be_u32(block, disk_offset(0xFC), checksum)
}

/// Computes a journal superblock checksum with its checksum field zeroed.
/// # Errors
///
/// Returns an error when the superblock body or checksum field is truncated.
fn journal_superblock_checksum(block: &[u8]) -> Result<u32> {
    let mut checked = memory::copied_slice(
        block
            .get(..JOURNAL_SUPERBLOCK_BYTES)
            .ok_or(Error::TruncatedStructure)?,
    )?;
    checked
        .get_mut(0xFC..0x100)
        .ok_or(Error::TruncatedStructure)?
        .fill(0);
    Ok(ext4_crc32c(u32::MAX, &checked))
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

#[cfg(test)]
mod tests {
    use super::{JOURNAL_SUPERBLOCK_BYTES, journal_superblock_checksum};

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn journal_superblock_checksum_starts_from_the_kernel_crc_state() {
        assert_eq!(
            journal_superblock_checksum(&[0_u8; JOURNAL_SUPERBLOCK_BYTES]),
            Ok(0x1151_2183)
        );
    }
}
