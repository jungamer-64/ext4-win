use alloc::vec::Vec;

use crate::block::{BlockAddress, BlockReader, BlockSize, ByteOffset};
use crate::endian::{le_u16, le_u32, put_le_u16};
use crate::error::{Error, Result};
use crate::superblock::Superblock;

const BG_BLOCK_BITMAP_LO_OFFSET: usize = 0;
const BG_INODE_TABLE_LO_OFFSET: usize = 8;
const BG_FREE_BLOCKS_LO_OFFSET: usize = 12;
const BG_BLOCK_BITMAP_HI_OFFSET: usize = 32;
const BG_INODE_TABLE_HI_OFFSET: usize = 40;
const BG_FREE_BLOCKS_HI_OFFSET: usize = 44;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlockGroupDescriptor {
    offset: ByteOffset,
    bytes: Vec<u8>,
    block_bitmap: BlockAddress,
    inode_table: BlockAddress,
    free_blocks_count: u32,
}

impl BlockGroupDescriptor {
    pub(crate) fn read_from(
        reader: &impl BlockReader,
        superblock: &Superblock,
        group: u32,
    ) -> Result<Self> {
        if group >= superblock.block_group_count()? {
            return Err(Error::InvalidSuperblock);
        }
        let offset =
            descriptor_offset(superblock.block_size(), superblock.descriptor_size(), group)?;
        let mut bytes = alloc::vec![0_u8; usize::from(superblock.descriptor_size())];
        reader.read_exact_at(offset, &mut bytes)?;
        let block_bitmap = descriptor_block_address(
            &bytes,
            BG_BLOCK_BITMAP_LO_OFFSET,
            BG_BLOCK_BITMAP_HI_OFFSET,
            superblock.features().has_64bit(),
        )?;
        let inode_table = descriptor_block_address(
            &bytes,
            BG_INODE_TABLE_LO_OFFSET,
            BG_INODE_TABLE_HI_OFFSET,
            superblock.features().has_64bit(),
        )?;
        let free_blocks_count = descriptor_count(
            &bytes,
            BG_FREE_BLOCKS_LO_OFFSET,
            BG_FREE_BLOCKS_HI_OFFSET,
            superblock.features().has_64bit(),
        )?;
        Ok(Self {
            offset,
            bytes,
            block_bitmap,
            inode_table,
            free_blocks_count,
        })
    }

    pub(crate) const fn offset(&self) -> ByteOffset {
        self.offset
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn block_bitmap(&self) -> BlockAddress {
        self.block_bitmap
    }

    pub(crate) const fn inode_table(&self) -> BlockAddress {
        self.inode_table
    }

    pub(crate) const fn free_blocks_count(&self) -> u32 {
        self.free_blocks_count
    }

    pub(crate) fn apply_free_blocks_delta(&mut self, delta: i32, has_64bit: bool) -> Result<()> {
        let updated = if delta.is_negative() {
            self.free_blocks_count
                .checked_sub(delta.unsigned_abs())
                .ok_or(Error::InvalidSuperblock)?
        } else {
            self.free_blocks_count
                .checked_add(u32::try_from(delta).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?
        };
        put_le_u16(
            &mut self.bytes,
            BG_FREE_BLOCKS_LO_OFFSET,
            u16::try_from(updated & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if has_64bit {
            put_le_u16(
                &mut self.bytes,
                BG_FREE_BLOCKS_HI_OFFSET,
                u16::try_from(updated >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        self.free_blocks_count = updated;
        Ok(())
    }
}

fn descriptor_offset(
    block_size: BlockSize,
    descriptor_size: u16,
    group: u32,
) -> Result<ByteOffset> {
    let bgdt_start_block = if block_size.bytes() == 1024 {
        2_u64
    } else {
        1_u64
    };
    let table_offset = block_size
        .offset_of(BlockAddress::new(bgdt_start_block))?
        .get();
    let descriptor_offset = u64::from(group)
        .checked_mul(u64::from(descriptor_size))
        .ok_or(Error::ArithmeticOverflow)?;
    Ok(ByteOffset::new(
        table_offset
            .checked_add(descriptor_offset)
            .ok_or(Error::ArithmeticOverflow)?,
    ))
}

fn descriptor_block_address(
    bytes: &[u8],
    lo_offset: usize,
    hi_offset: usize,
    has_64bit: bool,
) -> Result<BlockAddress> {
    let low = u64::from(le_u32(bytes, lo_offset)?);
    let high = if has_64bit {
        u64::from(le_u32(bytes, hi_offset)?)
    } else {
        0
    };
    Ok(BlockAddress::new((high << 32) | low))
}

fn descriptor_count(
    bytes: &[u8],
    lo_offset: usize,
    hi_offset: usize,
    has_64bit: bool,
) -> Result<u32> {
    let low = u32::from(le_u16(bytes, lo_offset)?);
    let high = if has_64bit {
        u32::from(le_u16(bytes, hi_offset)?)
    } else {
        0
    };
    Ok((high << 16) | low)
}
