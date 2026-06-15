//! Extent tree parsing for read-only file data mapping.

use alloc::vec::Vec;

use crate::block::{BlockAddress, BlockReader, BlockSize};
use crate::endian::{le_u16, le_u32, put_le_u16, put_le_u32};
use crate::error::{Error, Result};
use crate::inode::InodeExtentRoot;

/// Magic value stored at the start of every ext4 extent header.
const EXTENT_MAGIC: u16 = 0xF30A;
/// Size of an extent or index header in bytes.
const EXTENT_HEADER_SIZE: usize = 12;
/// Size of one extent leaf or index entry in bytes.
const EXTENT_ENTRY_SIZE: usize = 12;
/// High bit of `ee_len` marking uninitialized extents.
const EXTENT_LEN_UNINITIALIZED: u16 = 0x8000;
/// Bytes available in an inode `i_block` extent root.
const INODE_ROOT_BYTES: usize = 60;
/// Maximum leaf extents that fit in an inode root without external blocks.
const INODE_ROOT_EXTENT_CAPACITY: usize = 4;
/// ext4 extent trees are bounded; deeper trees are rejected before recursion.
const MAX_EXTENT_DEPTH: u16 = 5;

/// Logical block address inside a file.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogicalBlock(u32);

impl LogicalBlock {
    /// Creates a logical block address from an on-disk extent field.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the logical block value for on-disk encoding.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the logical block value widened for arithmetic.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        u64::from(self.0)
    }
}

impl TryFrom<u64> for LogicalBlock {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self> {
        Ok(Self(
            u32::try_from(value).map_err(|_| Error::ArithmeticOverflow)?,
        ))
    }
}

/// Non-zero length of an extent in blocks.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExtentLength(u16);

impl ExtentLength {
    /// Creates an extent length.
    ///
    /// # Errors
    /// Returns an error when the extent length is zero.
    pub fn new(value: u16) -> Result<Self> {
        if value == 0 {
            Err(Error::InvalidExtentTree)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the length in blocks.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the length widened for arithmetic.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        u32::from(self.0)
    }

    /// Returns the length widened for arithmetic.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        u64::from(self.0)
    }

    /// Returns this length plus one while preserving the non-zero invariant.
    pub(crate) fn checked_add_one(self) -> Result<Self> {
        Self::new(self.0.checked_add(1).ok_or(Error::ArithmeticOverflow)?)
    }
}

/// Result of mapping a logical file block through an extent tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockMapping {
    /// The logical block is backed by this physical block.
    Physical(BlockAddress),
    /// The logical block is backed by an uninitialized extent and reads as zero.
    Uninitialized,
    /// The logical block is a sparse hole.
    Hole,
}

/// Initialization state encoded in an ext4 leaf extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentInitialization {
    /// Extent payload contains initialized file data.
    Initialized,
    /// Extent payload is allocated but must read as zero until initialized.
    Uninitialized,
}

/// A leaf extent mapping a logical block run to a physical block run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extent {
    /// First logical file block covered by this run.
    logical_start: LogicalBlock,
    /// Non-zero number of logical blocks in this run.
    len: ExtentLength,
    /// First physical filesystem block backing this run.
    physical_start: BlockAddress,
    /// Initialization state encoded in `ee_len`.
    initialization: ExtentInitialization,
}

impl Extent {
    /// Creates an initialized extent after callers have validated fields.
    pub(crate) fn initialized(
        logical_start: LogicalBlock,
        len: ExtentLength,
        physical_start: BlockAddress,
    ) -> Self {
        Self {
            logical_start,
            len,
            physical_start,
            initialization: ExtentInitialization::Initialized,
        }
    }

    /// Creates an uninitialized extent after callers have validated fields.
    pub(crate) fn uninitialized(
        logical_start: LogicalBlock,
        len: ExtentLength,
        physical_start: BlockAddress,
    ) -> Self {
        Self {
            logical_start,
            len,
            physical_start,
            initialization: ExtentInitialization::Uninitialized,
        }
    }

    /// Logical first file block covered by this extent.
    #[must_use]
    pub const fn logical_start(self) -> LogicalBlock {
        self.logical_start
    }

    /// Number of blocks covered by this extent.
    #[must_use]
    pub const fn len(self) -> ExtentLength {
        self.len
    }

    /// First physical block covered by this extent.
    #[must_use]
    pub const fn physical_start(self) -> BlockAddress {
        self.physical_start
    }

    /// Initialization state of this extent.
    #[must_use]
    pub const fn initialization(self) -> ExtentInitialization {
        self.initialization
    }

    /// Returns the exclusive logical end of this extent.
    pub(crate) fn end_logical(self) -> Result<u32> {
        self.logical_start
            .as_u32()
            .checked_add(self.len.as_u32())
            .ok_or(Error::ArithmeticOverflow)
    }

    /// Maps a logical block if it falls inside this extent.
    pub fn map_logical(self, logical_block: LogicalBlock) -> BlockMapping {
        let start = self.logical_start.as_u64();
        let end = match start.checked_add(self.len.as_u64()) {
            Some(end) => end,
            None => return BlockMapping::Hole,
        };
        if logical_block.as_u64() < start || logical_block.as_u64() >= end {
            return BlockMapping::Hole;
        }
        let Some(logical_offset) = logical_block.as_u64().checked_sub(start) else {
            return BlockMapping::Hole;
        };
        let Some(physical) = self.physical_start.get().checked_add(logical_offset) else {
            return BlockMapping::Hole;
        };
        match self.initialization {
            ExtentInitialization::Initialized => BlockMapping::Physical(BlockAddress::new(physical)),
            ExtentInitialization::Uninitialized => BlockMapping::Uninitialized,
        }
    }
}

/// Parsed extent tree from an inode's `i_block` and external extent blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtentTree {
    /// Leaf extents collected in on-disk traversal order.
    extents: Vec<Extent>,
}

impl ExtentTree {
    /// Parses a depth-0 inode extent root.
    ///
    /// # Errors
    /// Returns an error when the extent header is malformed, contains a deeper
    /// tree, or has invalid entry bounds.
    pub fn parse_inode_root(root: &InodeExtentRoot) -> Result<Self> {
        let raw = root.bytes();
        let entries = header_entries(raw)?;
        let mut extents = Vec::with_capacity(entries);
        if parse_node(raw, None, &mut extents)? != 0 {
            return Err(Error::UnsupportedExtentDepth);
        }
        Ok(Self { extents })
    }

    /// Loads an extent tree, following external index blocks up to the ext4 depth limit.
    ///
    /// # Errors
    /// Returns an error when the tree is malformed, too deep, or an index block
    /// cannot be read.
    pub fn load_inode_tree(
        root: &InodeExtentRoot,
        block_size: BlockSize,
        reader: &impl BlockReader,
    ) -> Result<Self> {
        let mut extents = Vec::new();
        parse_node_recursive(root.bytes(), block_size, reader, &mut extents)?;
        Ok(Self { extents })
    }

    /// Maps a logical file block to a physical block or sparse hole.
    #[must_use]
    pub fn map_logical(&self, logical_block: LogicalBlock) -> BlockMapping {
        for extent in &self.extents {
            if let BlockMapping::Physical(block) = extent.map_logical(logical_block) {
                return BlockMapping::Physical(block);
            }
        }
        BlockMapping::Hole
    }

    /// Leaf extents in on-disk order.
    #[must_use]
    pub fn extents(&self) -> &[Extent] {
        &self.extents
    }
}

/// Internal parse_node_recursive operation used by this module's domain boundary.
fn parse_node_recursive(
    raw: &[u8],
    block_size: BlockSize,
    reader: &impl BlockReader,
    extents: &mut Vec<Extent>,
) -> Result<()> {
    // The inode root and external extent blocks share the same header format;
    // recursion only begins after the root confirms a non-zero depth.
    let depth = parse_node(raw, None, extents)?;
    if depth == 0 {
        return Ok(());
    }
    parse_index_node(raw, depth, block_size, reader, extents)
}

/// Internal parse_index_node operation used by this module's domain boundary.
fn parse_index_node(
    raw: &[u8],
    depth: u16,
    block_size: BlockSize,
    reader: &impl BlockReader,
    extents: &mut Vec<Extent>,
) -> Result<()> {
    // Index entries point at child extent blocks; each child depth must be one
    // less than the parent to prevent malformed cycles from masquerading as a tree.
    let entries = header_entries(raw)?;
    for entry_index in 0..entries {
        let offset = entry_offset(entry_index)?;
        let end = offset
            .checked_add(EXTENT_ENTRY_SIZE)
            .ok_or(Error::ArithmeticOverflow)?;
        if end > raw.len() {
            return Err(Error::InvalidExtentTree);
        }
        let leaf_lo = u64::from(le_u32(
            raw,
            offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
        )?);
        let leaf_hi = u64::from(le_u16(
            raw,
            offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?,
        )?);
        let leaf = BlockAddress::new((leaf_hi << 32) | leaf_lo);
        let mut child = alloc::vec![0_u8; usize::try_from(block_size.bytes())
            .map_err(|_| Error::ArithmeticOverflow)?];
        reader.read_exact_at(block_size.offset_of(leaf)?, &mut child)?;
        let child_depth = parse_node(
            &child,
            Some(depth.checked_sub(1).ok_or(Error::InvalidExtentTree)?),
            extents,
        )?;
        if child_depth > 0 {
            parse_index_node(&child, child_depth, block_size, reader, extents)?;
        }
    }
    Ok(())
}

/// Internal parse_node operation used by this module's domain boundary.
fn parse_node(raw: &[u8], expected_depth: Option<u16>, extents: &mut Vec<Extent>) -> Result<u16> {
    if le_u16(raw, 0)? != EXTENT_MAGIC {
        return Err(Error::InvalidExtentTree);
    }
    let entries = header_entries(raw)?;
    let max_entries = usize::from(le_u16(raw, 4)?);
    let depth = le_u16(raw, 6)?;
    if depth > MAX_EXTENT_DEPTH {
        return Err(Error::UnsupportedExtentDepth);
    }
    if let Some(expected) = expected_depth
        && depth != expected
    {
        return Err(Error::InvalidExtentTree);
    }
    if entries > max_entries {
        return Err(Error::InvalidExtentTree);
    }
    if depth != 0 {
        return Ok(depth);
    }
    for entry_index in 0..entries {
        let offset = entry_offset(entry_index)?;
        let end = offset
            .checked_add(EXTENT_ENTRY_SIZE)
            .ok_or(Error::ArithmeticOverflow)?;
        if end > raw.len() {
            return Err(Error::InvalidExtentTree);
        }
        extents.push(parse_extent(raw, offset)?);
    }
    Ok(depth)
}

/// Parses one leaf extent entry from `raw`.
fn parse_extent(raw: &[u8], offset: usize) -> Result<Extent> {
    let logical_start = LogicalBlock::from_u32(le_u32(raw, offset)?);
    let raw_len = le_u16(raw, offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?)?;
    let len = ExtentLength::new(raw_len & !EXTENT_LEN_UNINITIALIZED)?;
    let initialization = if raw_len & EXTENT_LEN_UNINITIALIZED == 0 {
        ExtentInitialization::Initialized
    } else {
        ExtentInitialization::Uninitialized
    };
    let start_hi = u64::from(le_u16(
        raw,
        offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?,
    )?);
    let start_lo = u64::from(le_u32(
        raw,
        offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?,
    )?);
    let physical_start = BlockAddress::new((start_hi << 32) | start_lo);
    Ok(match initialization {
        ExtentInitialization::Initialized => Extent::initialized(logical_start, len, physical_start),
        ExtentInitialization::Uninitialized => {
            Extent::uninitialized(logical_start, len, physical_start)
        }
    })
}

/// Reads the extent-header entry count after validating header size.
fn header_entries(raw: &[u8]) -> Result<usize> {
    if raw.len() < EXTENT_HEADER_SIZE {
        return Err(Error::InvalidExtentTree);
    }
    Ok(usize::from(le_u16(raw, 2)?))
}

/// Computes the byte offset of one extent or index entry.
fn entry_offset(entry_index: usize) -> Result<usize> {
    EXTENT_HEADER_SIZE
        .checked_add(
            entry_index
                .checked_mul(EXTENT_ENTRY_SIZE)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)
}
