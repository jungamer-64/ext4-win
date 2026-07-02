//! Block group descriptor parsing, accounting updates, and bitmap allocation.
//!
//! Group descriptors are the boundary between global superblock geometry and
//! per-group allocation state. This module keeps raw descriptor layout details
//! here so volume transactions can work with typed block addresses and counts.

use alloc::vec::Vec;

use crate::disk::block::{BlockAddress, BlockReader, BlockSize, ByteOffset};
use crate::disk::checksum::{crc16, crc32c};
use crate::disk::endian::{DiskOffset, le_u16, le_u32, put_le_u16};
use crate::disk_format::superblock::{
    BlockGroupDescriptorChecksum, BlockGroupDescriptorLayout, BlockGroupDescriptorSize,
    BlockGroupId, FreeClusterDelta, Superblock,
};
use crate::error::{Error, Result};

// Low 32-bit descriptor fields are present in both 32-byte and 64-byte layouts.
/// Offset of `bg_block_bitmap_lo` in a block group descriptor.
const BG_BLOCK_BITMAP_LO_OFFSET: usize = 0;
/// Offset of `bg_inode_bitmap_lo` in a block group descriptor.
const BG_INODE_BITMAP_LO_OFFSET: usize = 4;
/// Offset of `bg_inode_table_lo` in a block group descriptor.
const BG_INODE_TABLE_LO_OFFSET: usize = 8;
/// Offset of `bg_free_blocks_count_lo` in a block group descriptor.
const BG_FREE_BLOCKS_LO_OFFSET: usize = 12;
/// Offset of `bg_free_inodes_count_lo` in a block group descriptor.
const BG_FREE_INODES_LO_OFFSET: usize = 14;
/// Offset of `bg_used_dirs_count_lo` in a block group descriptor.
const BG_USED_DIRS_LO_OFFSET: usize = 16;
/// Offset of the low block bitmap checksum field.
const BG_BLOCK_BITMAP_CSUM_LO_OFFSET: usize = 24;
/// Offset of the low inode bitmap checksum field.
const BG_INODE_BITMAP_CSUM_LO_OFFSET: usize = 26;
/// Offset of `bg_itable_unused_lo` in a block group descriptor.
const BG_ITABLE_UNUSED_LO_OFFSET: usize = 28;
/// Offset of the descriptor checksum field.
const BG_CHECKSUM_OFFSET: usize = 30;
/// Width of the descriptor checksum field.
const BG_CHECKSUM_SIZE: usize = 2;
// High 32-bit fields exist only when the validated descriptor layout is 64-bit.
/// Offset of `bg_block_bitmap_hi` in a 64-bit block group descriptor.
const BG_BLOCK_BITMAP_HI_OFFSET: usize = 32;
/// Offset of `bg_inode_bitmap_hi` in a 64-bit block group descriptor.
const BG_INODE_BITMAP_HI_OFFSET: usize = 36;
/// Offset of `bg_inode_table_hi` in a 64-bit block group descriptor.
const BG_INODE_TABLE_HI_OFFSET: usize = 40;
/// Offset of `bg_free_blocks_count_hi` in a 64-bit block group descriptor.
const BG_FREE_BLOCKS_HI_OFFSET: usize = 44;
/// Offset of `bg_free_inodes_count_hi` in a 64-bit block group descriptor.
const BG_FREE_INODES_HI_OFFSET: usize = 46;
/// Offset of `bg_used_dirs_count_hi` in a 64-bit block group descriptor.
const BG_USED_DIRS_HI_OFFSET: usize = 48;
/// Offset of `bg_itable_unused_hi` in a 64-bit block group descriptor.
const BG_ITABLE_UNUSED_HI_OFFSET: usize = 50;
/// Offset of the high block bitmap checksum field.
const BG_BLOCK_BITMAP_CSUM_HI_OFFSET: usize = 56;
/// Offset of the high inode bitmap checksum field.
const BG_INODE_BITMAP_CSUM_HI_OFFSET: usize = 58;

/// Builds a block-group descriptor field offset.
const fn disk_offset(offset: usize) -> DiskOffset {
    DiskOffset::new(offset)
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Decoded block group descriptor backed by its writable raw bytes.
pub(crate) struct BlockGroupDescriptor {
    /// Absolute byte offset of this descriptor in the descriptor table.
    offset: ByteOffset,
    /// Raw descriptor bytes kept as the single writable representation.
    bytes: Vec<u8>,
    /// Block bitmap address decoded from the descriptor layout.
    block_bitmap: BlockAddress,
    /// Inode bitmap address decoded from the descriptor layout.
    inode_bitmap: BlockAddress,
    /// First inode-table block decoded from the descriptor layout.
    inode_table: BlockAddress,
    /// Free cluster count materialized from low/high descriptor fields.
    free_clusters_count: u32,
    /// Free inode count materialized from low/high descriptor fields.
    free_inodes_count: u32,
    /// Directory inode count used by allocation policy.
    used_dirs_count: u32,
    /// Unused inode-table tail count mirrored into the descriptor.
    itable_unused_count: u32,
}

impl BlockGroupDescriptor {
    /// Reads, verifies, and decodes a descriptor for one block group.
    /// # Errors
    ///
    /// Returns an error when the group is outside the mounted geometry, descriptor I/O fails, the
    /// descriptor checksum is invalid, or any descriptor field is truncated.
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
        let inode_bitmap = descriptor_block_address(
            &bytes,
            BG_INODE_BITMAP_LO_OFFSET,
            BG_INODE_BITMAP_HI_OFFSET,
            superblock.descriptor_layout(),
        )?;
        let inode_table = descriptor_block_address(
            &bytes,
            BG_INODE_TABLE_LO_OFFSET,
            BG_INODE_TABLE_HI_OFFSET,
            superblock.descriptor_layout(),
        )?;
        let free_clusters_count = descriptor_count(
            &bytes,
            BG_FREE_BLOCKS_LO_OFFSET,
            BG_FREE_BLOCKS_HI_OFFSET,
            superblock.descriptor_layout(),
        )?;
        let free_inodes_count = descriptor_count(
            &bytes,
            BG_FREE_INODES_LO_OFFSET,
            BG_FREE_INODES_HI_OFFSET,
            superblock.descriptor_layout(),
        )?;
        let used_dirs_count = descriptor_count(
            &bytes,
            BG_USED_DIRS_LO_OFFSET,
            BG_USED_DIRS_HI_OFFSET,
            superblock.descriptor_layout(),
        )?;
        let itable_unused_count = descriptor_count(
            &bytes,
            BG_ITABLE_UNUSED_LO_OFFSET,
            BG_ITABLE_UNUSED_HI_OFFSET,
            superblock.descriptor_layout(),
        )?;
        Ok(Self {
            offset,
            bytes,
            block_bitmap,
            inode_bitmap,
            inode_table,
            free_clusters_count,
            free_inodes_count,
            used_dirs_count,
            itable_unused_count,
        })
    }

    /// Returns the descriptor-table offset that must be rewritten after mutation.
    pub(crate) const fn offset(&self) -> ByteOffset {
        self.offset
    }

    /// Returns raw descriptor bytes with all in-memory mutations applied.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the block bitmap address.
    pub(crate) const fn block_bitmap(&self) -> BlockAddress {
        self.block_bitmap
    }

    /// Returns the inode bitmap address.
    pub(crate) const fn inode_bitmap(&self) -> BlockAddress {
        self.inode_bitmap
    }

    /// Returns the first inode table block address.
    pub(crate) const fn inode_table(&self) -> BlockAddress {
        self.inode_table
    }

    /// Returns the decoded free inode count.
    pub(crate) const fn free_inodes_count(&self) -> u32 {
        self.free_inodes_count
    }

    /// Applies a free-cluster accounting delta and refreshes the descriptor checksum.
    /// # Errors
    ///
    /// Returns an error when the delta underflows or overflows the free-cluster count, the count
    /// fields cannot be written, or checksum refresh fails.
    pub(crate) fn apply_free_clusters_delta(
        &mut self,
        delta: FreeClusterDelta,
        superblock: &Superblock,
        group: BlockGroupId,
    ) -> Result<()> {
        let raw_delta = i32::try_from(delta.as_i64()).map_err(|_| Error::ArithmeticOverflow)?;
        let updated = if raw_delta.is_negative() {
            self.free_clusters_count
                .checked_sub(raw_delta.unsigned_abs())
                .ok_or(Error::InvalidSuperblock)?
        } else {
            self.free_clusters_count
                .checked_add(u32::try_from(raw_delta).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?
        };
        put_le_u16(
            &mut self.bytes,
            disk_offset(BG_FREE_BLOCKS_LO_OFFSET),
            u16::try_from(updated & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if superblock.descriptor_layout().has_high_fields() {
            put_le_u16(
                &mut self.bytes,
                disk_offset(BG_FREE_BLOCKS_HI_OFFSET),
                u16::try_from(updated >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        self.free_clusters_count = updated;
        write_block_group_descriptor_checksum(superblock, group, &mut self.bytes)?;
        Ok(())
    }

    /// Applies a free-inode accounting delta and refreshes the descriptor checksum.
    /// # Errors
    ///
    /// Returns an error when the delta underflows or overflows the free-inode count, the count fields
    /// cannot be written, or checksum refresh fails.
    pub(crate) fn apply_free_inodes_delta(
        &mut self,
        delta: i64,
        superblock: &Superblock,
        group: BlockGroupId,
    ) -> Result<()> {
        self.free_inodes_count = apply_u32_delta(self.free_inodes_count, delta)?;
        write_descriptor_count(
            &mut self.bytes,
            BG_FREE_INODES_LO_OFFSET,
            BG_FREE_INODES_HI_OFFSET,
            self.free_inodes_count,
            superblock.descriptor_layout(),
        )?;
        write_block_group_descriptor_checksum(superblock, group, &mut self.bytes)
    }

    /// Applies a directory-count delta and refreshes the descriptor checksum.
    /// # Errors
    ///
    /// Returns an error when the delta underflows or overflows the used-directory count, the count
    /// fields cannot be written, or checksum refresh fails.
    pub(crate) fn apply_used_dirs_delta(
        &mut self,
        delta: i64,
        superblock: &Superblock,
        group: BlockGroupId,
    ) -> Result<()> {
        self.used_dirs_count = apply_u32_delta(self.used_dirs_count, delta)?;
        write_descriptor_count(
            &mut self.bytes,
            BG_USED_DIRS_LO_OFFSET,
            BG_USED_DIRS_HI_OFFSET,
            self.used_dirs_count,
            superblock.descriptor_layout(),
        )?;
        write_block_group_descriptor_checksum(superblock, group, &mut self.bytes)
    }

    /// Recomputes the block bitmap checksum fields for this group.
    /// # Errors
    ///
    /// Returns an error when the block bitmap checksum fields or descriptor checksum cannot be
    /// rewritten.
    pub(crate) fn refresh_block_bitmap_checksum(
        &mut self,
        superblock: &Superblock,
        group: BlockGroupId,
        bitmap: &[u8],
    ) -> Result<()> {
        self.refresh_bitmap_checksum(
            superblock,
            group,
            bitmap,
            BG_BLOCK_BITMAP_CSUM_LO_OFFSET,
            BG_BLOCK_BITMAP_CSUM_HI_OFFSET,
        )
    }

    /// Recomputes the inode bitmap checksum fields for this group.
    /// # Errors
    ///
    /// Returns an error when the inode bitmap checksum fields or descriptor checksum cannot be
    /// rewritten.
    pub(crate) fn refresh_inode_bitmap_checksum(
        &mut self,
        superblock: &Superblock,
        group: BlockGroupId,
        bitmap: &[u8],
    ) -> Result<()> {
        self.refresh_bitmap_checksum(
            superblock,
            group,
            bitmap,
            BG_INODE_BITMAP_CSUM_LO_OFFSET,
            BG_INODE_BITMAP_CSUM_HI_OFFSET,
        )
    }

    /// Writes a metadata CRC32C bitmap checksum and refreshes the descriptor checksum.
    /// # Errors
    ///
    /// Returns an error when the checksum cannot be split into descriptor fields or the descriptor
    /// checksum cannot be refreshed.
    fn refresh_bitmap_checksum(
        &mut self,
        superblock: &Superblock,
        group: BlockGroupId,
        bitmap: &[u8],
        lo_offset: usize,
        hi_offset: usize,
    ) -> Result<()> {
        if superblock.descriptor_checksum() != BlockGroupDescriptorChecksum::MetadataCrc32c {
            return Ok(());
        }
        let checksum = bitmap_checksum(superblock, group, bitmap);
        put_le_u16(
            &mut self.bytes,
            disk_offset(lo_offset),
            u16::try_from(checksum & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if superblock.descriptor_layout().has_high_fields() {
            put_le_u16(
                &mut self.bytes,
                disk_offset(hi_offset),
                u16::try_from(checksum >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        write_block_group_descriptor_checksum(superblock, group, &mut self.bytes)
    }
}

/// Writes the active block group descriptor checksum into the raw descriptor.
/// # Errors
///
/// Returns an error when the descriptor checksum cannot be computed or written to the checksum
/// field.
pub(crate) fn write_block_group_descriptor_checksum(
    superblock: &Superblock,
    group: BlockGroupId,
    bytes: &mut [u8],
) -> Result<()> {
    if superblock.descriptor_checksum() == BlockGroupDescriptorChecksum::None {
        return Ok(());
    }
    let checksum = block_group_descriptor_checksum(superblock, group, bytes)?;
    put_le_u16(bytes, disk_offset(BG_CHECKSUM_OFFSET), checksum)
}

/// Verifies the block group descriptor checksum selected by the superblock.
/// # Errors
///
/// Returns an error when the stored checksum field cannot be read or the computed checksum does not
/// match it.
fn verify_block_group_descriptor_checksum(
    superblock: &Superblock,
    group: BlockGroupId,
    bytes: &[u8],
) -> Result<()> {
    if superblock.descriptor_checksum() == BlockGroupDescriptorChecksum::None {
        return Ok(());
    }
    let expected = le_u16(bytes, disk_offset(BG_CHECKSUM_OFFSET))?;
    if block_group_descriptor_checksum(superblock, group, bytes)? == expected {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch)
    }
}

/// Computes the descriptor checksum using the validated checksum mode.
/// # Errors
///
/// Returns an error when the selected checksum algorithm cannot slice the descriptor around the
/// checksum field.
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

/// Computes the legacy GDT CRC16 descriptor checksum.
/// # Errors
///
/// Returns an error when checksum-field offset arithmetic overflows or the descriptor cannot be
/// sliced around the checksum field.
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

/// Computes the metadata_csum CRC32C descriptor checksum.
/// # Errors
///
/// Returns an error when checksum-field offset arithmetic overflows or the descriptor cannot be
/// sliced around the checksum field.
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

/// Computes the absolute byte offset of one descriptor table entry.
/// # Errors
///
/// Returns an error when the descriptor table byte offset overflows the device offset range.
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

/// Combines low and optional high descriptor fields into a block address.
/// # Errors
///
/// Returns an error when either block-address field is outside the supplied descriptor bytes.
fn descriptor_block_address(
    bytes: &[u8],
    lo_offset: usize,
    hi_offset: usize,
    layout: BlockGroupDescriptorLayout,
) -> Result<BlockAddress> {
    let low = u64::from(le_u32(bytes, disk_offset(lo_offset))?);
    let high = if layout.has_high_fields() {
        u64::from(le_u32(bytes, disk_offset(hi_offset))?)
    } else {
        0
    };
    Ok(BlockAddress::new((high << 32) | low))
}

/// Combines low and optional high descriptor fields into a 32-bit count.
/// # Errors
///
/// Returns an error when either count field is outside the supplied descriptor bytes.
fn descriptor_count(
    bytes: &[u8],
    lo_offset: usize,
    hi_offset: usize,
    layout: BlockGroupDescriptorLayout,
) -> Result<u32> {
    let low = u32::from(le_u16(bytes, disk_offset(lo_offset))?);
    let high = if layout.has_high_fields() {
        u32::from(le_u16(bytes, disk_offset(hi_offset))?)
    } else {
        0
    };
    Ok((high << 16) | low)
}

/// Splits a 32-bit count across the low and optional high descriptor fields.
/// # Errors
///
/// Returns an error when either count field cannot be written to the supplied descriptor bytes.
fn write_descriptor_count(
    bytes: &mut [u8],
    lo_offset: usize,
    hi_offset: usize,
    value: u32,
    layout: BlockGroupDescriptorLayout,
) -> Result<()> {
    put_le_u16(
        bytes,
        disk_offset(lo_offset),
        u16::try_from(value & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    if layout.has_high_fields() {
        put_le_u16(
            bytes,
            disk_offset(hi_offset),
            u16::try_from(value >> 16).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
    }
    Ok(())
}

/// Applies a signed accounting delta without underflowing the descriptor count.
/// # Errors
///
/// Returns an error when `delta` is outside `u32` bounds or applying it would underflow or overflow
/// the descriptor count.
fn apply_u32_delta(current: u32, delta: i64) -> Result<u32> {
    if delta.is_negative() {
        current
            .checked_sub(
                u32::try_from(delta.unsigned_abs()).map_err(|_| Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::InvalidSuperblock)
    } else {
        current
            .checked_add(u32::try_from(delta).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)
    }
}

/// Computes the metadata_csum checksum for a group bitmap payload.
fn bitmap_checksum(superblock: &Superblock, group: BlockGroupId, bitmap: &[u8]) -> u32 {
    let group_bytes = group.as_u32().to_le_bytes();
    let checksum = crc32c(superblock.checksum_seed().as_u32(), &group_bytes);
    crc32c(checksum, bitmap)
}
