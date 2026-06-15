use alloc::vec::Vec;

use crate::block::{BlockAddress, BlockReader, BlockSize, ByteOffset};
use crate::checksum::{crc16, crc32c};
use crate::endian::{le_u16, le_u32, put_le_u16};
use crate::error::{Error, Result};
use crate::superblock::{
    BlockGroupDescriptorChecksum, BlockGroupDescriptorLayout, BlockGroupDescriptorSize,
    BlockGroupId, FreeBlockDelta, Superblock,
};

const BG_BLOCK_BITMAP_LO_OFFSET: usize = 0;
const BG_INODE_TABLE_LO_OFFSET: usize = 8;
const BG_FREE_BLOCKS_LO_OFFSET: usize = 12;
const BG_CHECKSUM_OFFSET: usize = 30;
const BG_CHECKSUM_SIZE: usize = 2;
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
        group: BlockGroupId,
    ) -> Result<Self> {
        if group.as_u32() >= superblock.block_group_count()?.as_u32() {
            return Err(Error::InvalidSuperblock);
        }
        let offset =
            descriptor_offset(superblock.block_size(), superblock.descriptor_size(), group)?;
        let mut bytes = alloc::vec![0_u8; usize::from(superblock.descriptor_size().as_u16())];
        reader.read_exact_at(offset, &mut bytes)?;
        verify_block_group_descriptor_checksum(superblock, group, &bytes)?;
        let block_bitmap = descriptor_block_address(
            &bytes,
            BG_BLOCK_BITMAP_LO_OFFSET,
            BG_BLOCK_BITMAP_HI_OFFSET,
            superblock.descriptor_layout(),
        )?;
        let inode_table = descriptor_block_address(
            &bytes,
            BG_INODE_TABLE_LO_OFFSET,
            BG_INODE_TABLE_HI_OFFSET,
            superblock.descriptor_layout(),
        )?;
        let free_blocks_count = descriptor_count(
            &bytes,
            BG_FREE_BLOCKS_LO_OFFSET,
            BG_FREE_BLOCKS_HI_OFFSET,
            superblock.descriptor_layout(),
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

    pub(crate) fn apply_free_blocks_delta(
        &mut self,
        delta: FreeBlockDelta,
        superblock: &Superblock,
        group: BlockGroupId,
    ) -> Result<()> {
        let raw_delta = i32::try_from(delta.as_i64()).map_err(|_| Error::ArithmeticOverflow)?;
        let updated = if raw_delta.is_negative() {
            self.free_blocks_count
                .checked_sub(raw_delta.unsigned_abs())
                .ok_or(Error::InvalidSuperblock)?
        } else {
            self.free_blocks_count
                .checked_add(u32::try_from(raw_delta).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?
        };
        put_le_u16(
            &mut self.bytes,
            BG_FREE_BLOCKS_LO_OFFSET,
            u16::try_from(updated & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if superblock.descriptor_layout().has_high_fields() {
            put_le_u16(
                &mut self.bytes,
                BG_FREE_BLOCKS_HI_OFFSET,
                u16::try_from(updated >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        self.free_blocks_count = updated;
        write_block_group_descriptor_checksum(superblock, group, &mut self.bytes)?;
        Ok(())
    }
}

pub(crate) fn write_block_group_descriptor_checksum(
    superblock: &Superblock,
    group: BlockGroupId,
    bytes: &mut [u8],
) -> Result<()> {
    if superblock.descriptor_checksum() == BlockGroupDescriptorChecksum::None {
        return Ok(());
    }
    let checksum = block_group_descriptor_checksum(superblock, group, bytes)?;
    put_le_u16(bytes, BG_CHECKSUM_OFFSET, checksum)
}

fn verify_block_group_descriptor_checksum(
    superblock: &Superblock,
    group: BlockGroupId,
    bytes: &[u8],
) -> Result<()> {
    if superblock.descriptor_checksum() == BlockGroupDescriptorChecksum::None {
        return Ok(());
    }
    let expected = le_u16(bytes, BG_CHECKSUM_OFFSET)?;
    if block_group_descriptor_checksum(superblock, group, bytes)? == expected {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch)
    }
}

fn block_group_descriptor_checksum(
    superblock: &Superblock,
    group: BlockGroupId,
    bytes: &[u8],
) -> Result<u16> {
    match superblock.descriptor_checksum() {
        BlockGroupDescriptorChecksum::None => Ok(0),
        BlockGroupDescriptorChecksum::GdtCrc16 => gdt_checksum(superblock, group, bytes),
        BlockGroupDescriptorChecksum::MetadataCrc32c => metadata_checksum(superblock, group, bytes),
    }
}

fn gdt_checksum(superblock: &Superblock, group: BlockGroupId, bytes: &[u8]) -> Result<u16> {
    let checksum_end = BG_CHECKSUM_OFFSET
        .checked_add(BG_CHECKSUM_SIZE)
        .ok_or(Error::ArithmeticOverflow)?;
    let uuid = superblock.uuid().bytes();
    let group_bytes = group.as_u32().to_le_bytes();
    let mut checksum = crc16(u16::MAX, &uuid);
    checksum = crc16(checksum, &group_bytes);
    checksum = crc16(
        checksum,
        bytes
            .get(..BG_CHECKSUM_OFFSET)
            .ok_or(Error::TruncatedStructure)?,
    );
    if checksum_end < bytes.len() {
        checksum = crc16(
            checksum,
            bytes.get(checksum_end..).ok_or(Error::TruncatedStructure)?,
        );
    }
    Ok(checksum)
}

fn metadata_checksum(superblock: &Superblock, group: BlockGroupId, bytes: &[u8]) -> Result<u16> {
    let checksum_end = BG_CHECKSUM_OFFSET
        .checked_add(BG_CHECKSUM_SIZE)
        .ok_or(Error::ArithmeticOverflow)?;
    let group_bytes = group.as_u32().to_le_bytes();
    let zero_checksum = [0_u8; BG_CHECKSUM_SIZE];
    let mut checksum = crc32c(superblock.checksum_seed().as_u32(), &group_bytes);
    checksum = crc32c(
        checksum,
        bytes
            .get(..BG_CHECKSUM_OFFSET)
            .ok_or(Error::TruncatedStructure)?,
    );
    checksum = crc32c(checksum, &zero_checksum);
    if checksum_end < bytes.len() {
        checksum = crc32c(
            checksum,
            bytes.get(checksum_end..).ok_or(Error::TruncatedStructure)?,
        );
    }
    u16::try_from(checksum & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)
}

fn descriptor_offset(
    block_size: BlockSize,
    descriptor_size: BlockGroupDescriptorSize,
    group: BlockGroupId,
) -> Result<ByteOffset> {
    let bgdt_start_block = if block_size.bytes() == 1024 {
        2_u64
    } else {
        1_u64
    };
    let table_offset = block_size
        .offset_of(BlockAddress::new(bgdt_start_block))?
        .get();
    let descriptor_offset = u64::from(group.as_u32())
        .checked_mul(u64::from(descriptor_size.as_u16()))
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
    layout: BlockGroupDescriptorLayout,
) -> Result<BlockAddress> {
    let low = u64::from(le_u32(bytes, lo_offset)?);
    let high = if layout.has_high_fields() {
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
    layout: BlockGroupDescriptorLayout,
) -> Result<u32> {
    let low = u32::from(le_u16(bytes, lo_offset)?);
    let high = if layout.has_high_fields() {
        u32::from(le_u16(bytes, hi_offset)?)
    } else {
        0
    };
    Ok((high << 16) | low)
}
