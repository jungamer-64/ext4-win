use alloc::vec;

use crate::block::{BlockReader, BlockSize, BlockWriter};
use crate::endian::{be_u32, put_be_u32};
use crate::error::{Error, Result};
use crate::extent::ExtentTree;
use crate::inode::Inode;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
const JBD2_COMMIT_BLOCK: u32 = 2;
const JOURNAL_OVERHEAD_BLOCKS: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Journal {
    capacity_blocks: u32,
    descriptor_block: crate::block::BlockAddress,
    commit_block: crate::block::BlockAddress,
}

impl Journal {
    pub(crate) fn from_inode(
        inode: &Inode,
        block_size: BlockSize,
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
        let descriptor_block = tree.map_logical(1).ok_or(Error::UnsupportedJournal)?;
        let commit_block = tree.map_logical(2).ok_or(Error::UnsupportedJournal)?;
        Ok(Self {
            capacity_blocks,
            descriptor_block,
            commit_block,
        })
    }

    pub(crate) fn ensure_transaction_capacity(self, metadata_blocks: usize) -> Result<()> {
        let required = u32::try_from(metadata_blocks)
            .map_err(|_| Error::TransactionTooLarge)?
            .checked_add(JOURNAL_OVERHEAD_BLOCKS)
            .ok_or(Error::TransactionTooLarge)?;
        if required > self.capacity_blocks {
            Err(Error::TransactionTooLarge)
        } else {
            Ok(())
        }
    }

    pub(crate) fn write_descriptor_marker(
        self,
        writer: &mut impl BlockWriter,
        block_size: BlockSize,
        sequence: u32,
    ) -> Result<()> {
        let mut block =
            vec![0_u8; usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?];
        Jbd2Header::descriptor(sequence).encode(&mut block)?;
        let parsed = Jbd2Header::parse(&block)?;
        if parsed.block_type() != JBD2_DESCRIPTOR_BLOCK || parsed.sequence() != sequence {
            return Err(Error::JournalCorrupt);
        }
        writer.write_exact_at(block_size.offset_of(self.descriptor_block)?, &block)
    }

    pub(crate) fn write_commit_marker(
        self,
        writer: &mut impl BlockWriter,
        block_size: BlockSize,
        sequence: u32,
    ) -> Result<()> {
        let mut block =
            vec![0_u8; usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?];
        Jbd2Header::commit(sequence).encode(&mut block)?;
        let parsed = Jbd2Header::parse(&block)?;
        if parsed.block_type() != JBD2_COMMIT_BLOCK || parsed.sequence() != sequence {
            return Err(Error::JournalCorrupt);
        }
        writer.write_exact_at(block_size.offset_of(self.commit_block)?, &block)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Jbd2Header {
    block_type: u32,
    sequence: u32,
}

impl Jbd2Header {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
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
        if bytes.len() < 12 {
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
