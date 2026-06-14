//! Extent tree parsing for read-only file data mapping.

use alloc::vec::Vec;

use crate::block::BlockAddress;
use crate::endian::{le_u16, le_u32};
use crate::error::{Error, Result};

const EXTENT_MAGIC: u16 = 0xF30A;
const EXTENT_HEADER_SIZE: usize = 12;
const EXTENT_ENTRY_SIZE: usize = 12;
const EXTENT_LEN_UNINITIALIZED: u16 = 0x8000;

/// A leaf extent mapping a logical block run to a physical block run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extent {
    logical_start: u32,
    len: u16,
    physical_start: BlockAddress,
}

impl Extent {
    /// Logical first file block covered by this extent.
    #[must_use]
    pub const fn logical_start(self) -> u32 {
        self.logical_start
    }

    /// Number of blocks covered by this extent.
    #[must_use]
    pub const fn len(self) -> u16 {
        self.len
    }

    /// Returns true when the extent has no blocks.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// First physical block covered by this extent.
    #[must_use]
    pub const fn physical_start(self) -> BlockAddress {
        self.physical_start
    }

    /// Maps a logical block if it falls inside this extent.
    pub fn map_logical(self, logical_block: u64) -> Option<BlockAddress> {
        let start = u64::from(self.logical_start);
        let end = start.checked_add(u64::from(self.len))?;
        if logical_block < start || logical_block >= end {
            return None;
        }
        let logical_offset = logical_block.checked_sub(start)?;
        Some(BlockAddress::new(
            self.physical_start.get().checked_add(logical_offset)?,
        ))
    }
}

/// Parsed extent root from an inode's `i_block`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtentRoot {
    extents: Vec<Extent>,
}

impl ExtentRoot {
    /// Parses a v1-supported depth-0 extent root.
    ///
    /// # Errors
    /// Returns an error when the extent header is malformed, contains a deeper
    /// tree than v1 supports, or has invalid entry bounds.
    pub fn parse_inode_root(raw: &[u8; 60]) -> Result<Self> {
        if le_u16(raw, 0)? != EXTENT_MAGIC {
            return Err(Error::InvalidExtentTree);
        }
        let entries = usize::from(le_u16(raw, 2)?);
        let max_entries = usize::from(le_u16(raw, 4)?);
        let depth = le_u16(raw, 6)?;
        if depth != 0 {
            return Err(Error::UnsupportedExtentDepth);
        }
        if entries > max_entries {
            return Err(Error::InvalidExtentTree);
        }

        let mut extents = Vec::with_capacity(entries);
        for entry_index in 0..entries {
            let offset = EXTENT_HEADER_SIZE
                .checked_add(
                    entry_index
                        .checked_mul(EXTENT_ENTRY_SIZE)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            let end = offset
                .checked_add(EXTENT_ENTRY_SIZE)
                .ok_or(Error::ArithmeticOverflow)?;
            if end > raw.len() {
                return Err(Error::InvalidExtentTree);
            }

            let logical_start = le_u32(raw, offset)?;
            let raw_len = le_u16(raw, offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?)?;
            let len = raw_len & !EXTENT_LEN_UNINITIALIZED;
            let start_hi = u64::from(le_u16(
                raw,
                offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?,
            )?);
            let start_lo = u64::from(le_u32(
                raw,
                offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?,
            )?);
            let physical_start = BlockAddress::new((start_hi << 32) | start_lo);
            extents.push(Extent {
                logical_start,
                len,
                physical_start,
            });
        }

        Ok(Self { extents })
    }

    /// Maps a logical file block to a physical block, or `None` for a sparse hole.
    pub fn map_logical(&self, logical_block: u64) -> Option<BlockAddress> {
        for extent in &self.extents {
            if let Some(block) = extent.map_logical(logical_block) {
                return Some(block);
            }
        }
        None
    }

    /// Leaf extents in on-disk order.
    #[must_use]
    pub fn extents(&self) -> &[Extent] {
        &self.extents
    }
}
