use crate::block::{BlockReader, BlockSize, BlockWriter};
use crate::endian::be_u32;
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

    pub(crate) fn replay_and_checkpoint(
        self,
        _filesystem: &mut impl BlockWriter,
        _journal: &mut impl BlockWriter,
        _block_size: BlockSize,
    ) -> Result<()> {
        replay_journal(self)
    }

    pub(crate) fn commit_metadata_transaction(
        self,
        _filesystem: &mut impl BlockWriter,
        _journal: &mut impl BlockWriter,
        _block_size: BlockSize,
        _metadata_blocks: &[crate::volume::MetadataBlock],
    ) -> Result<()> {
        commit_journal_transaction(self)
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

    pub(crate) const fn block_type(self) -> u32 {
        self.block_type
    }

    pub(crate) const fn sequence(self) -> u32 {
        self.sequence
    }
}

fn replay_journal(_journal: Journal) -> Result<()> {
    Err(Error::UnsupportedJournal)
}

fn commit_journal_transaction(_journal: Journal) -> Result<()> {
    Err(Error::UnsupportedJournal)
}
