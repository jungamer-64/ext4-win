use alloc::{vec, vec::Vec};

use crate::block::{BlockAddress, BlockReader, BlockSize, BlockWriter, ByteOffset};
use crate::checksum::crc32c;
use crate::endian::{be_u16, be_u32, be_u64, put_be_u16, put_be_u32};
use crate::error::{Error, Result};
use crate::extent::ExtentTree;
use crate::inode::Inode;
use crate::volume::MetadataBlock;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
const JBD2_COMMIT_BLOCK: u32 = 2;
const JBD2_SUPERBLOCK_V1: u32 = 3;
const JBD2_SUPERBLOCK_V2: u32 = 4;
const JBD2_REVOKE_BLOCK: u32 = 5;

const JBD2_FEATURE_INCOMPAT_REVOKE: u32 = 0x0001;
const JBD2_FEATURE_INCOMPAT_64BIT: u32 = 0x0002;
const JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT: u32 = 0x0004;
const JBD2_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x0008;
const JBD2_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x0010;
const JBD2_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0020;
const JBD2_SUPPORTED_INCOMPAT: u32 = JBD2_FEATURE_INCOMPAT_REVOKE
    | JBD2_FEATURE_INCOMPAT_64BIT
    | JBD2_FEATURE_INCOMPAT_CSUM_V2
    | JBD2_FEATURE_INCOMPAT_CSUM_V3;

const JBD2_TAG_FLAG_ESCAPE: u32 = 0x0001;
const JBD2_TAG_FLAG_SAME_UUID: u32 = 0x0002;
const JBD2_TAG_FLAG_DELETED: u32 = 0x0004;
const JBD2_TAG_FLAG_LAST_TAG: u32 = 0x0008;

const JBD2_CHECKSUM_CRC32C: u8 = 4;
const JOURNAL_HEADER_BYTES: usize = 12;
const JOURNAL_SUPERBLOCK_BYTES: usize = 1024;
const JOURNAL_EXTERNAL_SUPERBLOCK_OFFSET: u64 = 2048;
const JOURNAL_OVERHEAD_BLOCKS: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Journal {
    location: JournalLocation,
    superblock: JournalSuperblock,
    filesystem_blocks: u64,
    state: JournalState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalState {
    Loaded,
    Clean,
    Dirty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalSequence(u32);

impl JournalSequence {
    const fn new(value: u32) -> Self {
        Self(value)
    }

    const fn get(self) -> u32 {
        self.0
    }

    const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    const fn is_after(self, other: Self) -> bool {
        let distance = self.0.wrapping_sub(other.0);
        distance != 0 && distance < 0x8000_0000
    }
}

impl Journal {
    pub(crate) fn from_inode(
        inode: &Inode,
        block_size: BlockSize,
        filesystem_blocks: u64,
        reader: &impl BlockReader,
    ) -> Result<Self> {
        if inode.size() == 0 || block_size.bytes() == 0 {
            return Err(Error::UnsupportedJournal);
        }
        let capacity_blocks = inode
            .size()
            .checked_div(u64::from(block_size.bytes()))
            .ok_or(Error::ArithmeticOverflow)?;
        let capacity_blocks =
            u32::try_from(capacity_blocks).map_err(|_| Error::UnsupportedJournal)?;
        if capacity_blocks <= JOURNAL_OVERHEAD_BLOCKS {
            return Err(Error::UnsupportedJournal);
        }

        let tree = ExtentTree::load_inode_tree(inode.block(), block_size, reader)?;
        let mut blocks = Vec::with_capacity(
            usize::try_from(capacity_blocks).map_err(|_| Error::ArithmeticOverflow)?,
        );
        for logical in 0..capacity_blocks {
            blocks.push(
                tree.map_logical(u64::from(logical))
                    .ok_or(Error::UnsupportedJournal)?,
            );
        }

        let location = JournalLocation::Internal { blocks };
        let mut raw =
            vec![0_u8; usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?];
        read_journal_block(reader, &location, block_size, 0, &mut raw)?;
        let superblock = JournalSuperblock::parse(&raw)?;
        superblock.validate_for_mount(block_size, capacity_blocks)?;

        Ok(Self {
            location,
            superblock,
            filesystem_blocks,
            state: JournalState::Loaded,
        })
    }

    pub(crate) fn from_external_device(
        journal: &impl BlockReader,
        block_size: BlockSize,
        expected_uuid: [u8; 16],
        filesystem_blocks: u64,
    ) -> Result<Self> {
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
        superblock.validate_for_mount(block_size, superblock.maxlen())?;
        Ok(Self {
            location: JournalLocation::External {
                base: ByteOffset::new(JOURNAL_EXTERNAL_SUPERBLOCK_OFFSET),
            },
            superblock,
            filesystem_blocks,
            state: JournalState::Loaded,
        })
    }

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

    pub(crate) fn replay_and_checkpoint_internal(
        &mut self,
        filesystem: &mut impl BlockWriter,
        block_size: BlockSize,
        recovery_required: bool,
    ) -> Result<()> {
        let mut io = InternalJournalIo { device: filesystem };
        self.replay_and_checkpoint(&mut io, block_size, recovery_required)
    }

    pub(crate) fn replay_and_checkpoint_external(
        &mut self,
        filesystem: &mut impl BlockWriter,
        journal: &mut impl BlockWriter,
        block_size: BlockSize,
        recovery_required: bool,
    ) -> Result<()> {
        let mut io = ExternalJournalIo {
            filesystem,
            journal,
        };
        self.replay_and_checkpoint(&mut io, block_size, recovery_required)
    }

    pub(crate) fn commit_internal(
        &mut self,
        filesystem: &mut impl BlockWriter,
        block_size: BlockSize,
        metadata_blocks: &[MetadataBlock],
    ) -> Result<()> {
        let mut io = InternalJournalIo { device: filesystem };
        self.commit_metadata_transaction(&mut io, block_size, metadata_blocks)
    }

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

    fn replay_and_checkpoint(
        &mut self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        recovery_required: bool,
    ) -> Result<()> {
        if self.state == JournalState::Dirty {
            return Err(Error::JournalCorrupt);
        }
        if recovery_required && self.superblock.start() == 0 {
            return Err(Error::JournalCorrupt);
        }
        let scan = self.committed_transactions(io, block_size)?;
        if scan.tail == JournalScanTail::CleanSuperblock {
            self.state = JournalState::Clean;
            return Ok(());
        }
        if scan.transactions.is_empty() {
            self.mark_clean(io, block_size, self.superblock.sequence())?;
            self.state = JournalState::Clean;
            return Ok(());
        }

        let mut revokes = Vec::new();
        for transaction in &scan.transactions {
            for block in &transaction.revokes {
                revokes.push(RevokedBlock {
                    sequence: transaction.sequence,
                    block: *block,
                });
            }
        }

        let mut next_sequence = self.superblock.sequence();
        for transaction in &scan.transactions {
            next_sequence = transaction.sequence.next();
            for entry in &transaction.entries {
                if is_revoked_after(&revokes, entry.home, transaction.sequence) {
                    continue;
                }
                io.write_home_block(block_size, entry.home, &entry.bytes)?;
            }
        }
        io.flush_all()?;
        self.mark_clean(io, block_size, next_sequence)?;
        self.state = JournalState::Clean;
        Ok(())
    }

    fn commit_metadata_transaction(
        &mut self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        metadata_blocks: &[MetadataBlock],
    ) -> Result<()> {
        if self.state != JournalState::Clean || self.superblock.start() != 0 {
            return Err(Error::JournalCorrupt);
        }
        let prepared = self.prepare_metadata_transaction(block_size, metadata_blocks)?;
        let mut cursor = prepared.descriptor;
        let dirty_superblock =
            self.superblock
                .encode_dirty(block_size, prepared.descriptor, prepared.sequence)?;
        io.write_journal_block(self, block_size, 0, &dirty_superblock)?;
        self.superblock
            .apply_dirty(prepared.descriptor, prepared.sequence, dirty_superblock);
        self.state = JournalState::Dirty;

        io.write_journal_block(self, block_size, cursor, &prepared.descriptor_block)?;
        cursor = self.next_logical(cursor)?;

        for data in &prepared.data_blocks {
            io.write_journal_block(self, block_size, cursor, data)?;
            cursor = self.next_logical(cursor)?;
        }
        io.flush_all()?;

        io.write_journal_block(self, block_size, cursor, &prepared.commit_block)?;
        io.flush_all()?;

        for metadata in metadata_blocks {
            io.write_home_block(block_size, metadata.block(), metadata.bytes())?;
        }
        io.flush_all()?;

        self.mark_clean(io, block_size, prepared.next_sequence)?;
        self.state = JournalState::Clean;
        Ok(())
    }

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

    fn parse_transaction(
        &self,
        io: &mut impl JournalIo,
        block_size: BlockSize,
        start: u32,
        sequence: JournalSequence,
    ) -> Result<JournalTransactionScan> {
        let mut transaction = JournalTransaction {
            sequence,
            entries: Vec::new(),
            revokes: Vec::new(),
        };
        let mut cursor = start;
        let mut consumed = 0_u32;

        while consumed < self.usable_log_blocks()? {
            let block = self.read_journal_block(io, block_size, cursor)?;
            let Ok(header) = Jbd2Header::parse(&block) else {
                return Ok(transaction_tail(consumed));
            };
            if header.sequence() != sequence.get() {
                return Ok(transaction_tail(consumed));
            }

            match header.block_type() {
                JBD2_DESCRIPTOR_BLOCK => {
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
                            transaction.revokes.retain(|block| *block != tag.block);
                            transaction.entries.push(JournalEntry {
                                home: tag.block,
                                bytes: data,
                            });
                        }
                        cursor = self.next_logical(cursor)?;
                        consumed = consumed.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                    }
                }
                JBD2_REVOKE_BLOCK => {
                    let revoke = self.parse_revoke_block(&block)?;
                    for block in revoke.blocks {
                        if !transaction.entries.iter().any(|entry| entry.home == block) {
                            transaction.revokes.push(block);
                        }
                    }
                    cursor = self.next_logical(cursor)?;
                    consumed = consumed.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                }
                JBD2_COMMIT_BLOCK => {
                    self.parse_commit_block(&block)?;
                    return Ok(JournalTransactionScan::Committed {
                        transaction,
                        next_cursor: self.next_logical(cursor)?,
                        consumed: consumed.checked_add(1).ok_or(Error::ArithmeticOverflow)?,
                    });
                }
                _ => return Ok(transaction_tail(consumed)),
            }
        }

        Ok(JournalTransactionScan::IncompleteTail)
    }

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

    fn validate_replay_target(&self, block: BlockAddress) -> Result<()> {
        if block.get() >= self.filesystem_blocks {
            return Err(Error::JournalCorrupt);
        }
        if let JournalLocation::Internal { blocks } = &self.location
            && blocks.contains(&block)
        {
            return Err(Error::JournalCorrupt);
        }
        Ok(())
    }

    fn parse_descriptor_block(&self, block: &[u8]) -> Result<JournalDescriptor> {
        self.verify_block_tail_checksum(block)?;
        let mut offset = JOURNAL_HEADER_BYTES;
        let limit = if self.superblock.has_metadata_checksums() {
            block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?
        } else {
            block.len()
        };
        let mut tags = Vec::new();
        while offset < limit {
            let Some((tag, next_offset)) = self.parse_tag(block, offset, limit)? else {
                break;
            };
            let last = tag.flags & JBD2_TAG_FLAG_LAST_TAG != 0;
            tags.push(tag);
            offset = next_offset;
            if last {
                break;
            }
        }
        Ok(JournalDescriptor { tags })
    }

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
        Ok(Some((
            JournalTag {
                block: BlockAddress::new((block_high << 32) | block_low),
                flags,
                checksum,
            },
            next,
        )))
    }

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

    fn parse_commit_block(&self, block: &[u8]) -> Result<JournalCommit> {
        let header = Jbd2Header::parse(block)?;
        if header.block_type() != JBD2_COMMIT_BLOCK {
            return Err(Error::JournalCorrupt);
        }
        if self.superblock.has_metadata_checksums() {
            if *block.get(0x0C).ok_or(Error::TruncatedStructure)? != JBD2_CHECKSUM_CRC32C
                || *block.get(0x0D).ok_or(Error::TruncatedStructure)? != 4
            {
                return Err(Error::JournalCorrupt);
            }
            self.verify_commit_checksum(block)?;
        }
        Ok(JournalCommit {
            sequence: JournalSequence::new(header.sequence()),
        })
    }

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

    fn usable_log_blocks(&self) -> Result<u32> {
        self.superblock
            .maxlen()
            .checked_sub(self.superblock.first())
            .ok_or(Error::UnsupportedJournal)
    }

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

    fn descriptor_tag_size(&self) -> usize {
        if self.superblock.has_csum_v3() {
            16
        } else if self.superblock.has_64bit() {
            12
        } else {
            8
        }
    }

    fn descriptor_payload_limit(&self, block_len: usize) -> Result<usize> {
        if self.superblock.has_metadata_checksums() {
            block_len.checked_sub(4).ok_or(Error::InvalidSuperblock)
        } else {
            Ok(block_len)
        }
    }

    fn next_logical(&self, logical: u32) -> Result<u32> {
        let next = logical.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        if next >= self.superblock.maxlen() {
            Ok(self.superblock.first())
        } else {
            Ok(next)
        }
    }

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

    fn tag_checksum(&self, sequence: JournalSequence, data: &[u8]) -> Result<u32> {
        let mut sequence_bytes = [0_u8; 4];
        put_be_u32(&mut sequence_bytes, 0, sequence.get())?;
        let seed = crc32c(0, self.superblock.uuid());
        let seed = crc32c(seed, &sequence_bytes);
        Ok(crc32c(seed, data))
    }

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

    fn write_block_tail_checksum(&self, block: &mut [u8]) -> Result<()> {
        if !self.superblock.has_metadata_checksums() {
            return Ok(());
        }
        let offset = block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?;
        let checksum = self.block_checksum_with_zeroed(block, offset)?;
        put_be_u32(block, offset, checksum)
    }

    fn verify_commit_checksum(&self, block: &[u8]) -> Result<()> {
        let expected = be_u32(block, 0x10)?;
        let actual = self.block_checksum_with_zeroed(block, 0x10)?;
        if expected == actual {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

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

#[derive(Clone, Debug, Eq, PartialEq)]
enum JournalLocation {
    Internal { blocks: Vec<BlockAddress> },
    External { base: ByteOffset },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalSuperblock {
    raw: Vec<u8>,
    block_size: u32,
    maxlen: u32,
    first: u32,
    sequence: JournalSequence,
    start: u32,
    compat: u32,
    incompat: u32,
    ro_compat: u32,
    uuid: [u8; 16],
    checksum_type: u8,
}

impl JournalSuperblock {
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

    fn validate_for_mount(&self, block_size: BlockSize, capacity_blocks: u32) -> Result<()> {
        if self.block_size != block_size.bytes()
            || self.maxlen == 0
            || self.maxlen > capacity_blocks
            || self.first == 0
            || self.first >= self.maxlen
            || (self.start != 0 && (self.start < self.first || self.start >= self.maxlen))
        {
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
        Ok(())
    }

    fn encode_with_state(
        &self,
        block_size: BlockSize,
        sequence: JournalSequence,
        start: u32,
    ) -> Result<Vec<u8>> {
        let block_len = usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
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

    fn encode_clean(&self, block_size: BlockSize, sequence: JournalSequence) -> Result<Vec<u8>> {
        self.encode_with_state(block_size, sequence, 0)
    }

    fn encode_dirty(
        &self,
        block_size: BlockSize,
        start: u32,
        sequence: JournalSequence,
    ) -> Result<Vec<u8>> {
        self.encode_with_state(block_size, sequence, start)
    }

    fn apply_clean(&mut self, sequence: JournalSequence, raw: Vec<u8>) {
        self.sequence = sequence;
        self.start = 0;
        self.raw = raw;
    }

    fn apply_dirty(&mut self, start: u32, sequence: JournalSequence, raw: Vec<u8>) {
        self.start = start;
        self.sequence = sequence;
        self.raw = raw;
    }

    pub(crate) const fn block_size(&self) -> u32 {
        self.block_size
    }

    pub(crate) const fn maxlen(&self) -> u32 {
        self.maxlen
    }

    pub(crate) const fn first(&self) -> u32 {
        self.first
    }

    pub(crate) const fn sequence(&self) -> JournalSequence {
        self.sequence
    }

    pub(crate) const fn start(&self) -> u32 {
        self.start
    }

    pub(crate) const fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }

    pub(crate) const fn has_64bit(&self) -> bool {
        self.incompat & JBD2_FEATURE_INCOMPAT_64BIT != 0
    }

    fn has_csum_v3(&self) -> bool {
        self.incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3 != 0
    }

    fn has_metadata_checksums(&self) -> bool {
        self.incompat & (JBD2_FEATURE_INCOMPAT_CSUM_V2 | JBD2_FEATURE_INCOMPAT_CSUM_V3) != 0
    }

    fn has_superblock_checksum(&self) -> Result<bool> {
        Ok(be_u32(&self.raw, 0xFC)? != 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Jbd2Header {
    block_type: u32,
    sequence: u32,
}

impl Jbd2Header {
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

    pub(crate) fn descriptor(sequence: u32) -> Self {
        Self {
            block_type: JBD2_DESCRIPTOR_BLOCK,
            sequence,
        }
    }

    pub(crate) fn commit(sequence: u32) -> Self {
        Self {
            block_type: JBD2_COMMIT_BLOCK,
            sequence,
        }
    }

    pub(crate) fn encode(self, bytes: &mut [u8]) -> Result<()> {
        if bytes.len() < JOURNAL_HEADER_BYTES {
            return Err(Error::TruncatedStructure);
        }
        put_be_u32(bytes, 0, JBD2_MAGIC)?;
        put_be_u32(bytes, 4, self.block_type)?;
        put_be_u32(bytes, 8, self.sequence)
    }

    pub(crate) const fn block_type(self) -> u32 {
        self.block_type
    }

    pub(crate) const fn sequence(self) -> u32 {
        self.sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalTransaction {
    sequence: JournalSequence,
    entries: Vec<JournalEntry>,
    revokes: Vec<BlockAddress>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalReplayScan {
    transactions: Vec<JournalTransaction>,
    tail: JournalScanTail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedJournalTransaction {
    sequence: JournalSequence,
    next_sequence: JournalSequence,
    descriptor: u32,
    descriptor_block: Vec<u8>,
    data_blocks: Vec<Vec<u8>>,
    commit_block: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalScanTail {
    CleanSuperblock,
    EndOfLog,
    IncompleteTail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JournalTransactionScan {
    Committed {
        transaction: JournalTransaction,
        next_cursor: u32,
        consumed: u32,
    },
    IncompleteTail,
    EndOfLog,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalEntry {
    home: BlockAddress,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalDescriptor {
    tags: Vec<JournalTag>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalTag {
    block: BlockAddress,
    flags: u32,
    checksum: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalRevoke {
    blocks: Vec<BlockAddress>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalCommit {
    sequence: JournalSequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RevokedBlock {
    sequence: JournalSequence,
    block: BlockAddress,
}

trait JournalIo {
    fn read_journal_block(
        &mut self,
        journal: &Journal,
        block_size: BlockSize,
        logical: u32,
        out: &mut [u8],
    ) -> Result<()>;

    fn write_journal_block(
        &mut self,
        journal: &Journal,
        block_size: BlockSize,
        logical: u32,
        bytes: &[u8],
    ) -> Result<()>;

    fn write_home_block(
        &mut self,
        block_size: BlockSize,
        block: BlockAddress,
        bytes: &[u8],
    ) -> Result<()>;

    fn flush_all(&mut self) -> Result<()>;
}

struct InternalJournalIo<'a, D> {
    device: &'a mut D,
}

impl<D: BlockWriter> JournalIo for InternalJournalIo<'_, D> {
    fn read_journal_block(
        &mut self,
        journal: &Journal,
        block_size: BlockSize,
        logical: u32,
        out: &mut [u8],
    ) -> Result<()> {
        self.device
            .read_exact_at(journal.offset_of(logical, block_size)?, out)
    }

    fn write_journal_block(
        &mut self,
        journal: &Journal,
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

struct ExternalJournalIo<'a, F, J> {
    filesystem: &'a mut F,
    journal: &'a mut J,
}

impl<F: BlockWriter, J: BlockWriter> JournalIo for ExternalJournalIo<'_, F, J> {
    fn read_journal_block(
        &mut self,
        journal: &Journal,
        block_size: BlockSize,
        logical: u32,
        out: &mut [u8],
    ) -> Result<()> {
        self.journal
            .read_exact_at(journal.offset_of(logical, block_size)?, out)
    }

    fn write_journal_block(
        &mut self,
        journal: &Journal,
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

impl Journal {
    fn offset_of(&self, logical: u32, block_size: BlockSize) -> Result<ByteOffset> {
        match &self.location {
            JournalLocation::Internal { blocks } => {
                let index = usize::try_from(logical).map_err(|_| Error::ArithmeticOverflow)?;
                let block = *blocks.get(index).ok_or(Error::UnsupportedJournal)?;
                block_size.offset_of(block)
            }
            JournalLocation::External { base } => Ok(ByteOffset::new(
                base.get()
                    .checked_add(
                        u64::from(logical)
                            .checked_mul(u64::from(block_size.bytes()))
                            .ok_or(Error::ArithmeticOverflow)?,
                    )
                    .ok_or(Error::ArithmeticOverflow)?,
            )),
        }
    }
}

fn read_journal_block(
    reader: &impl BlockReader,
    location: &JournalLocation,
    block_size: BlockSize,
    logical: u32,
    out: &mut [u8],
) -> Result<()> {
    let offset = match location {
        JournalLocation::Internal { blocks } => {
            let index = usize::try_from(logical).map_err(|_| Error::ArithmeticOverflow)?;
            block_size.offset_of(*blocks.get(index).ok_or(Error::UnsupportedJournal)?)?
        }
        JournalLocation::External { base } => ByteOffset::new(
            base.get()
                .checked_add(
                    u64::from(logical)
                        .checked_mul(u64::from(block_size.bytes()))
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?,
        ),
    };
    reader.read_exact_at(offset, out)
}

fn starts_with_jbd2_magic(bytes: &[u8]) -> bool {
    bytes
        .get(0..4)
        .is_some_and(|prefix| prefix == JBD2_MAGIC.to_be_bytes())
}

fn transaction_tail(consumed: u32) -> JournalTransactionScan {
    if consumed == 0 {
        JournalTransactionScan::EndOfLog
    } else {
        JournalTransactionScan::IncompleteTail
    }
}

fn verify_journal_superblock_checksum(block: &[u8]) -> Result<()> {
    let expected = be_u32(block, 0xFC)?;
    let actual = journal_superblock_checksum(block)?;
    if expected == actual {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch)
    }
}

fn refresh_journal_superblock_checksum(block: &mut [u8]) -> Result<()> {
    put_be_u32(block, 0xFC, 0)?;
    let checksum = journal_superblock_checksum(block)?;
    put_be_u32(block, 0xFC, checksum)
}

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

fn is_revoked_after(
    revokes: &[RevokedBlock],
    block: BlockAddress,
    sequence: JournalSequence,
) -> bool {
    revokes
        .iter()
        .any(|revoked| revoked.block == block && revoked.sequence.is_after(sequence))
}
