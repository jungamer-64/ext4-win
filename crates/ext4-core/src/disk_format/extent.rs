//! Extent tree parsing, mapping, and mutation serialization.

use alloc::vec::Vec;

use crate::disk::block::{BlockAddress, BlockSize};
use crate::disk::checksum::crc32c;
use crate::disk::endian::{DiskOffset, le_u16, le_u32, put_le_u16, put_le_u32};
use crate::disk::io::BlockSource;
use crate::disk_format::inode::{InodeExtentRoot, InodeId};
use crate::error::{Error, Result};
use crate::memory::{self, FallibleVec};

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
/// Maximum entries that fit in the inode root.
const INODE_ROOT_ENTRY_CAPACITY: usize = 4;
/// Checksum tail bytes reserved at the end of external extent blocks.
const EXTENT_TAIL_SIZE: usize = 4;
/// ext4 extent trees are bounded; deeper trees are rejected before recursion.
const MAX_EXTENT_DEPTH: u16 = 5;

/// Builds an extent-tree field offset.
const fn disk_offset(offset: usize) -> DiskOffset {
    DiskOffset::new(offset)
}

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

/// Checksum context required for external extent blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtentTreeContext {
    /// Metadata checksum fields when the volume advertises metadata checksums.
    checksum: Option<ExtentBlockChecksum>,
}

impl ExtentTreeContext {
    /// Creates a context for a filesystem without external extent checksums.
    #[must_use]
    pub const fn none() -> Self {
        Self { checksum: None }
    }

    /// Creates a metadata-checksum context for one inode extent tree.
    #[must_use]
    pub const fn metadata_csum(seed: u32, inode_id: InodeId, generation: u32) -> Self {
        Self {
            checksum: Some(ExtentBlockChecksum {
                seed,
                inode_id,
                generation,
            }),
        }
    }
}

/// Metadata checksum fields for one inode extent tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExtentBlockChecksum {
    /// Filesystem checksum seed.
    seed: u32,
    /// Inode number owning the extent tree.
    inode_id: InodeId,
    /// Inode generation owning the extent tree.
    generation: u32,
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
        Self::from_parts(
            logical_start,
            len,
            physical_start,
            ExtentInitialization::Initialized,
        )
    }

    /// Creates an uninitialized extent after callers have validated fields.
    pub(crate) fn uninitialized(
        logical_start: LogicalBlock,
        len: ExtentLength,
        physical_start: BlockAddress,
    ) -> Self {
        Self::from_parts(
            logical_start,
            len,
            physical_start,
            ExtentInitialization::Uninitialized,
        )
    }

    /// Creates a typed extent from fully validated parts.
    const fn from_parts(
        logical_start: LogicalBlock,
        len: ExtentLength,
        physical_start: BlockAddress,
        initialization: ExtentInitialization,
    ) -> Self {
        Self {
            logical_start,
            len,
            physical_start,
            initialization,
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
    /// # Errors
    ///
    /// Returns an error when `logical_start + len` overflows the on-disk logical block range.
    pub(crate) fn end_logical(self) -> Result<u32> {
        self.logical_start
            .as_u32()
            .checked_add(self.len.as_u32())
            .ok_or(Error::ArithmeticOverflow)
    }

    /// Maps a logical block if it falls inside this extent.
    #[must_use]
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
            ExtentInitialization::Initialized => {
                BlockMapping::Physical(BlockAddress::new(physical))
            }
            ExtentInitialization::Uninitialized => BlockMapping::Uninitialized,
        }
    }
}

/// Parsed extent tree from an inode's `i_block` and external extent blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtentTree {
    /// Leaf extents collected in on-disk traversal order.
    extents: Vec<Extent>,
    /// External extent metadata blocks visited while loading the tree.
    metadata_blocks: Vec<BlockAddress>,
}

impl ExtentTree {
    /// Loads an extent tree, following external index blocks up to the ext4 depth limit.
    ///
    /// # Errors
    /// Returns an error when the tree is malformed, too deep, has a bad
    /// metadata checksum, or an index block cannot be read.
    pub async fn load_inode_tree(
        root: &InodeExtentRoot,
        block_size: BlockSize,
        reader: &mut impl BlockSource,
        context: ExtentTreeContext,
    ) -> Result<Self> {
        let mut extents = Vec::new();
        let mut metadata_blocks = Vec::new();
        load_external_extent_nodes(
            root.bytes(),
            block_size,
            reader,
            context,
            &mut extents,
            &mut metadata_blocks,
        )
        .await?;
        normalize_extents(&mut extents)?;
        Ok(Self {
            extents,
            metadata_blocks,
        })
    }

    /// Maps a logical file block to a physical block, uninitialized extent, or sparse hole.
    #[must_use]
    pub fn map_logical(&self, logical_block: LogicalBlock) -> BlockMapping {
        map_extents(self.extents.as_slice(), logical_block)
    }

    /// Leaf extents in normalized logical order.
    #[must_use]
    pub fn extents(&self) -> &[Extent] {
        &self.extents
    }

    /// External extent metadata blocks visited while loading this tree.
    #[must_use]
    pub fn metadata_blocks(&self) -> &[BlockAddress] {
        &self.metadata_blocks
    }
}

/// Mutable extent tree used by write transactions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutableExtentTree {
    /// Normalized leaf extents.
    extents: Vec<Extent>,
    /// External extent metadata blocks reserved for serialization.
    metadata_blocks: Vec<BlockAddress>,
}

impl MutableExtentTree {
    /// Creates a mutable tree from normalized extents.
    ///
    /// # Errors
    /// Returns an error when the extents overlap or cannot be merged safely.
    pub fn from_extents(mut extents: Vec<Extent>) -> Result<Self> {
        normalize_extents(&mut extents)?;
        Ok(Self {
            extents,
            metadata_blocks: Vec::new(),
        })
    }

    /// Loads a mutable extent tree from an inode root.
    ///
    /// # Errors
    /// Returns an error when loading the backing immutable tree fails.
    pub async fn load_inode_tree(
        root: &InodeExtentRoot,
        block_size: BlockSize,
        reader: &mut impl BlockSource,
        context: ExtentTreeContext,
    ) -> Result<Self> {
        let tree = ExtentTree::load_inode_tree(root, block_size, reader, context).await?;
        Ok(Self {
            extents: tree.extents,
            metadata_blocks: tree.metadata_blocks,
        })
    }

    /// Maps a logical file block to a physical block, uninitialized extent, or sparse hole.
    #[must_use]
    pub fn map_logical(&self, logical_block: LogicalBlock) -> BlockMapping {
        map_extents(self.extents.as_slice(), logical_block)
    }

    /// Normalized leaf extents.
    #[must_use]
    pub fn extents(&self) -> &[Extent] {
        self.extents.as_slice()
    }

    /// Replaces the leaf extents and restores normalized order.
    ///
    /// # Errors
    /// Returns an error when the replacement extents overlap.
    pub(crate) fn replace_extents(&mut self, mut extents: Vec<Extent>) -> Result<()> {
        normalize_extents(&mut extents)?;
        self.extents = extents;
        Ok(())
    }

    /// Returns true when any leaf extent is uninitialized.
    #[must_use]
    pub fn contains_uninitialized(&self) -> bool {
        self.extents
            .iter()
            .any(|extent| extent.initialization() == ExtentInitialization::Uninitialized)
    }

    /// Inserts one initialized logical block mapping, extending adjacent extents when possible.
    ///
    /// # Errors
    /// Returns an error when the insertion overlaps an existing mapping.
    pub fn insert_or_extend_initialized(
        &mut self,
        logical_block: LogicalBlock,
        physical_block: BlockAddress,
    ) -> Result<()> {
        self.extents.try_push(Extent::initialized(
            logical_block,
            ExtentLength::new(1)?,
            physical_block,
        ))?;
        normalize_extents(&mut self.extents)
    }

    /// External extent metadata blocks currently reserved for this tree.
    #[must_use]
    pub fn metadata_blocks(&self) -> &[BlockAddress] {
        self.metadata_blocks.as_slice()
    }

    /// Replaces external extent metadata block reservations.
    pub fn set_metadata_blocks(&mut self, metadata_blocks: Vec<BlockAddress>) {
        self.metadata_blocks = metadata_blocks;
    }

    /// Computes the number of external extent metadata blocks required to serialize this tree.
    ///
    /// # Errors
    /// Returns an error when the tree would exceed the ext4 maximum depth.
    pub fn required_metadata_blocks(&self, block_size: BlockSize) -> Result<usize> {
        required_metadata_blocks(self.extents.len(), block_size)
    }

    /// Serializes this tree into an inode root plus external extent metadata blocks.
    ///
    /// # Errors
    /// Returns an error when the reserved metadata block count does not match
    /// the required tree shape or the tree exceeds the supported ext4 depth.
    pub fn serialize(
        &self,
        block_size: BlockSize,
        context: ExtentTreeContext,
    ) -> Result<SerializedExtentTree> {
        let required = self.required_metadata_blocks(block_size)?;
        if self.metadata_blocks.len() != required {
            return Err(Error::InvalidExtentTree);
        }
        if self.extents.len() <= INODE_ROOT_ENTRY_CAPACITY {
            return Ok(SerializedExtentTree {
                inode_root: serialize_extent_root(self.extents.as_slice())?,
                external_blocks: Vec::new(),
            });
        }

        let capacity = external_entry_capacity(block_size)?;
        let mut block_index = 0_usize;
        let mut external_blocks = Vec::new();
        let mut nodes = Vec::new();

        for chunk in self.extents.chunks(capacity) {
            let block = *self
                .metadata_blocks
                .get(block_index)
                .ok_or(Error::InvalidExtentTree)?;
            block_index = block_index
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?;
            let bytes = serialize_external_extent_node(block_size, 0, chunk, context)?;
            let block_bytes = memory::copied_slice(&bytes)?;
            external_blocks.try_push(SerializedExtentBlock {
                block,
                bytes: block_bytes,
            })?;
            nodes.try_push(SerializedNode {
                first_logical: chunk
                    .first()
                    .ok_or(Error::InvalidExtentTree)?
                    .logical_start(),
                depth: 0,
                block,
                bytes,
            })?;
        }

        while nodes.len() > INODE_ROOT_ENTRY_CAPACITY {
            let child_depth = nodes.first().ok_or(Error::InvalidExtentTree)?.depth;
            let parent_depth = child_depth
                .checked_add(1)
                .ok_or(Error::UnsupportedExtentDepth)?;
            if parent_depth >= MAX_EXTENT_DEPTH {
                return Err(Error::UnsupportedExtentDepth);
            }
            let mut parents = Vec::new();
            for chunk in nodes.chunks(capacity) {
                let block = *self
                    .metadata_blocks
                    .get(block_index)
                    .ok_or(Error::InvalidExtentTree)?;
                block_index = block_index
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow)?;
                let bytes =
                    serialize_external_index_node(block_size, parent_depth, chunk, context)?;
                let block_bytes = memory::copied_slice(&bytes)?;
                external_blocks.try_push(SerializedExtentBlock {
                    block,
                    bytes: block_bytes,
                })?;
                parents.try_push(SerializedNode {
                    first_logical: chunk.first().ok_or(Error::InvalidExtentTree)?.first_logical,
                    depth: parent_depth,
                    block,
                    bytes,
                })?;
            }
            nodes = parents;
        }

        let child_depth = nodes.first().ok_or(Error::InvalidExtentTree)?.depth;
        let root_depth = child_depth
            .checked_add(1)
            .ok_or(Error::UnsupportedExtentDepth)?;
        if root_depth > MAX_EXTENT_DEPTH {
            return Err(Error::UnsupportedExtentDepth);
        }
        Ok(SerializedExtentTree {
            inode_root: serialize_index_root(root_depth, nodes.as_slice())?,
            external_blocks,
        })
    }
}

/// Serialized extent tree ready to stage in a transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SerializedExtentTree {
    /// Inode `i_block` extent root bytes.
    inode_root: [u8; INODE_ROOT_BYTES],
    /// External extent metadata block images.
    external_blocks: Vec<SerializedExtentBlock>,
}

impl SerializedExtentTree {
    /// Inode `i_block` extent root bytes.
    #[must_use]
    pub const fn inode_root(&self) -> &[u8; INODE_ROOT_BYTES] {
        &self.inode_root
    }

    /// External extent metadata block images.
    #[must_use]
    pub fn external_blocks(&self) -> &[SerializedExtentBlock] {
        self.external_blocks.as_slice()
    }
}

/// Serialized external extent metadata block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SerializedExtentBlock {
    /// Physical block that stores this extent metadata node.
    block: BlockAddress,
    /// Full block image.
    bytes: Vec<u8>,
}

impl SerializedExtentBlock {
    /// Physical block that stores this extent metadata node.
    #[must_use]
    pub const fn block(&self) -> BlockAddress {
        self.block
    }

    /// Full block image.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Serialized external node used while building parent indexes.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SerializedNode {
    /// First logical block covered by this child node.
    first_logical: LogicalBlock,
    /// Node depth, where leaf nodes are zero.
    depth: u16,
    /// Physical block containing this node.
    block: BlockAddress,
    /// Full block image.
    bytes: Vec<u8>,
}

/// External extent node waiting to be read in depth-first disk order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingExtentNode {
    /// Physical block containing the child node.
    block: BlockAddress,
    /// Depth required by the parent index entry.
    expected_depth: u16,
}

/// Walks an extent node and all index children, collecting leaf extents.
/// # Errors
///
/// Returns an error when the current node is malformed, an index child cannot be read, a child
/// checksum fails, or recursive parsing rejects a child node.
async fn load_external_extent_nodes(
    raw: &[u8],
    block_size: BlockSize,
    reader: &mut impl BlockSource,
    context: ExtentTreeContext,
    extents: &mut Vec<Extent>,
    metadata_blocks: &mut Vec<BlockAddress>,
) -> Result<()> {
    let depth = parse_node(raw, None, extents)?;
    if depth == 0 {
        return Ok(());
    }
    let mut pending = Vec::new();
    push_index_children(raw, depth, &mut pending)?;
    while let Some(child) = pending.pop() {
        if metadata_blocks.contains(&child.block) {
            return Err(Error::InvalidExtentTree);
        }
        metadata_blocks.try_push(child.block)?;
        let mut bytes = memory::repeated_vec(
            0_u8,
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        reader
            .read_exact_at(block_size.offset_of(child.block)?, &mut bytes)
            .await?;
        verify_external_extent_block_checksum(context, bytes.as_slice())?;
        let child_depth = parse_node(bytes.as_slice(), Some(child.expected_depth), extents)?;
        if child_depth > 0 {
            push_index_children(bytes.as_slice(), child_depth, &mut pending)?;
        }
    }
    Ok(())
}

/// Pushes an index node's children in reverse so stack traversal preserves disk order.
/// # Errors
///
/// Returns an error when an index entry is truncated or its parent depth cannot select a child.
fn push_index_children(raw: &[u8], depth: u16, pending: &mut Vec<PendingExtentNode>) -> Result<()> {
    let entries = header_entries(raw)?;
    let expected_depth = depth.checked_sub(1).ok_or(Error::InvalidExtentTree)?;
    for entry_index in (0..entries).rev() {
        let offset = entry_offset(entry_index)?;
        let end = offset
            .checked_add(EXTENT_ENTRY_SIZE)
            .ok_or(Error::ArithmeticOverflow)?;
        if end > raw.len() {
            return Err(Error::InvalidExtentTree);
        }
        let leaf_lo = u64::from(le_u32(
            raw,
            disk_offset(offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?),
        )?);
        let leaf_hi = u64::from(le_u16(
            raw,
            disk_offset(offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?),
        )?);
        let leaf = BlockAddress::new((leaf_hi << 32) | leaf_lo);
        pending.try_push(PendingExtentNode {
            block: leaf,
            expected_depth,
        })?;
    }
    Ok(())
}

/// Parses one extent tree node and appends leaf extents when the node is a leaf.
/// # Errors
///
/// Returns an error when the header magic is wrong, the depth or entry count is unsupported, the
/// expected depth does not match, or a leaf entry is truncated or invalid.
fn parse_node(raw: &[u8], expected_depth: Option<u16>, extents: &mut Vec<Extent>) -> Result<u16> {
    if le_u16(raw, disk_offset(0))? != EXTENT_MAGIC {
        return Err(Error::InvalidExtentTree);
    }
    let entries = header_entries(raw)?;
    let max_entries = usize::from(le_u16(raw, disk_offset(4))?);
    let depth = le_u16(raw, disk_offset(6))?;
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
        extents.try_push(parse_extent(raw, offset)?)?;
    }
    Ok(depth)
}

/// Parses one leaf extent entry from `raw`.
/// # Errors
///
/// Returns an error when any extent field is outside `raw` or the encoded extent length is zero.
fn parse_extent(raw: &[u8], offset: usize) -> Result<Extent> {
    let logical_start = LogicalBlock::from_u32(le_u32(raw, disk_offset(offset))?);
    let raw_len = le_u16(
        raw,
        disk_offset(offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?),
    )?;
    let len = ExtentLength::new(raw_len & !EXTENT_LEN_UNINITIALIZED)?;
    let initialization = if raw_len & EXTENT_LEN_UNINITIALIZED == 0 {
        ExtentInitialization::Initialized
    } else {
        ExtentInitialization::Uninitialized
    };
    let start_hi = u64::from(le_u16(
        raw,
        disk_offset(offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?),
    )?);
    let start_lo = u64::from(le_u32(
        raw,
        disk_offset(offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?),
    )?);
    let physical_start = BlockAddress::new((start_hi << 32) | start_lo);
    Ok(match initialization {
        ExtentInitialization::Initialized => {
            Extent::initialized(logical_start, len, physical_start)
        }
        ExtentInitialization::Uninitialized => {
            Extent::uninitialized(logical_start, len, physical_start)
        }
    })
}

/// Reads the extent-header entry count after validating header size.
/// # Errors
///
/// Returns an error when the node is smaller than an ext4 extent header.
fn header_entries(raw: &[u8]) -> Result<usize> {
    if raw.len() < EXTENT_HEADER_SIZE {
        return Err(Error::InvalidExtentTree);
    }
    Ok(usize::from(le_u16(raw, disk_offset(2))?))
}

/// Computes the byte offset of one extent or index entry.
/// # Errors
///
/// Returns an error when multiplying the entry index by the on-disk entry size overflows.
fn entry_offset(entry_index: usize) -> Result<usize> {
    EXTENT_HEADER_SIZE
        .checked_add(
            entry_index
                .checked_mul(EXTENT_ENTRY_SIZE)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)
}

/// Maps a logical block through a normalized extent list.
fn map_extents(extents: &[Extent], logical_block: LogicalBlock) -> BlockMapping {
    for extent in extents {
        match extent.map_logical(logical_block) {
            BlockMapping::Physical(block) => return BlockMapping::Physical(block),
            BlockMapping::Uninitialized => return BlockMapping::Uninitialized,
            BlockMapping::Hole => {}
        }
    }
    BlockMapping::Hole
}

/// Restores logical order, merges adjacent compatible extents, and rejects overlaps.
/// # Errors
///
/// Returns an error when extents overlap, adjacency calculations overflow, or a merged length cannot
/// be represented as an ext4 extent length.
fn normalize_extents(extents: &mut Vec<Extent>) -> Result<()> {
    extents.sort_by_key(|extent| extent.logical_start());
    let mut normalized: Vec<Extent> = Vec::new();
    for extent in extents.iter().copied() {
        if let Some(last) = normalized.last_mut() {
            let last_end = last.end_logical()?;
            if extent.logical_start().as_u32() < last_end {
                return Err(Error::InvalidExtentTree);
            }
            if extent.logical_start().as_u32() == last_end
                && extent.initialization() == last.initialization()
                && last
                    .physical_start()
                    .get()
                    .checked_add(last.len().as_u64())
                    .ok_or(Error::ArithmeticOverflow)?
                    == extent.physical_start().get()
            {
                let combined = last
                    .len()
                    .as_u32()
                    .checked_add(extent.len().as_u32())
                    .ok_or(Error::ArithmeticOverflow)?;
                let len = ExtentLength::new(
                    u16::try_from(combined).map_err(|_| Error::ArithmeticOverflow)?,
                )?;
                *last = Extent::from_parts(
                    last.logical_start(),
                    len,
                    last.physical_start(),
                    last.initialization(),
                );
                continue;
            }
        }
        normalized.try_push(extent)?;
    }
    *extents = normalized;
    Ok(())
}

/// Computes external extent metadata block count for a normalized leaf count.
/// # Errors
///
/// Returns an error when node fan-out arithmetic overflows or the serialized tree would exceed the
/// supported ext4 depth.
fn required_metadata_blocks(extent_count: usize, block_size: BlockSize) -> Result<usize> {
    if extent_count <= INODE_ROOT_ENTRY_CAPACITY {
        return Ok(0);
    }
    let capacity = external_entry_capacity(block_size)?;
    let mut level_nodes = round_up_div_usize(extent_count, capacity)?;
    let mut total = level_nodes;
    let mut root_depth = 1_u16;
    while level_nodes > INODE_ROOT_ENTRY_CAPACITY {
        level_nodes = round_up_div_usize(level_nodes, capacity)?;
        total = total
            .checked_add(level_nodes)
            .ok_or(Error::ArithmeticOverflow)?;
        root_depth = root_depth
            .checked_add(1)
            .ok_or(Error::UnsupportedExtentDepth)?;
        if root_depth > MAX_EXTENT_DEPTH {
            return Err(Error::UnsupportedExtentDepth);
        }
    }
    Ok(total)
}

/// Number of extent/index entries that fit in one external extent block.
/// # Errors
///
/// Returns an error when the block size cannot hold an extent header, checksum tail, and at least
/// one entry.
fn external_entry_capacity(block_size: BlockSize) -> Result<usize> {
    let bytes = usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
    let payload = bytes
        .checked_sub(EXTENT_HEADER_SIZE)
        .and_then(|value| value.checked_sub(EXTENT_TAIL_SIZE))
        .ok_or(Error::InvalidExtentTree)?;
    let capacity = payload
        .checked_div(EXTENT_ENTRY_SIZE)
        .ok_or(Error::ArithmeticOverflow)?;
    if capacity == 0 {
        Err(Error::InvalidExtentTree)
    } else {
        Ok(capacity)
    }
}

/// Integer ceiling division for tree packing.
/// # Errors
///
/// Returns an error when the divisor is zero or rounded addition overflows.
fn round_up_div_usize(value: usize, divisor: usize) -> Result<usize> {
    if divisor == 0 {
        return Err(Error::ArithmeticOverflow);
    }
    let adjusted = value
        .checked_add(divisor.checked_sub(1).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::ArithmeticOverflow)?;
    adjusted
        .checked_div(divisor)
        .ok_or(Error::ArithmeticOverflow)
}

/// Serializes a root containing leaf extent entries.
/// # Errors
///
/// Returns an error when the root header cannot represent the entry count or an extent entry would
/// exceed the fixed inode root bytes.
fn serialize_extent_root(extents: &[Extent]) -> Result<[u8; INODE_ROOT_BYTES]> {
    let mut raw = [0_u8; INODE_ROOT_BYTES];
    write_header(&mut raw, extents.len(), INODE_ROOT_ENTRY_CAPACITY, 0)?;
    for (entry_index, extent) in extents.iter().copied().enumerate() {
        write_extent_entry(&mut raw, entry_offset(entry_index)?, extent)?;
    }
    Ok(raw)
}

/// Serializes a root containing index entries.
/// # Errors
///
/// Returns an error when the root header cannot represent the index count or an index entry would
/// exceed the fixed inode root bytes.
fn serialize_index_root(depth: u16, nodes: &[SerializedNode]) -> Result<[u8; INODE_ROOT_BYTES]> {
    let mut raw = [0_u8; INODE_ROOT_BYTES];
    write_header(&mut raw, nodes.len(), INODE_ROOT_ENTRY_CAPACITY, depth)?;
    for (entry_index, node) in nodes.iter().enumerate() {
        write_index_entry(&mut raw, entry_offset(entry_index)?, node)?;
    }
    Ok(raw)
}

/// Serializes an external leaf extent node.
/// # Errors
///
/// Returns an error when the block cannot hold the leaf entries, a field write exceeds the block, or
/// checksum refresh fails.
fn serialize_external_extent_node(
    block_size: BlockSize,
    depth: u16,
    extents: &[Extent],
    context: ExtentTreeContext,
) -> Result<Vec<u8>> {
    let capacity = external_entry_capacity(block_size)?;
    let mut raw = memory::repeated_vec(
        0_u8,
        usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    write_header(raw.as_mut_slice(), extents.len(), capacity, depth)?;
    for (entry_index, extent) in extents.iter().copied().enumerate() {
        write_extent_entry(raw.as_mut_slice(), entry_offset(entry_index)?, extent)?;
    }
    refresh_external_extent_block_checksum(context, raw.as_mut_slice())?;
    Ok(raw)
}

/// Serializes an external index node.
/// # Errors
///
/// Returns an error when the block cannot hold the child index entries, a field write exceeds the
/// block, or checksum refresh fails.
fn serialize_external_index_node(
    block_size: BlockSize,
    depth: u16,
    nodes: &[SerializedNode],
    context: ExtentTreeContext,
) -> Result<Vec<u8>> {
    let capacity = external_entry_capacity(block_size)?;
    let mut raw = memory::repeated_vec(
        0_u8,
        usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    write_header(raw.as_mut_slice(), nodes.len(), capacity, depth)?;
    for (entry_index, node) in nodes.iter().enumerate() {
        write_index_entry(raw.as_mut_slice(), entry_offset(entry_index)?, node)?;
    }
    refresh_external_extent_block_checksum(context, raw.as_mut_slice())?;
    Ok(raw)
}

/// Writes a common extent header.
/// # Errors
///
/// Returns an error when `entries` exceeds `max_entries` or either count cannot be encoded as an
/// ext4 header field.
fn write_header(raw: &mut [u8], entries: usize, max_entries: usize, depth: u16) -> Result<()> {
    if entries > max_entries {
        return Err(Error::InvalidExtentTree);
    }
    put_le_u16(raw, disk_offset(0), EXTENT_MAGIC)?;
    put_le_u16(
        raw,
        disk_offset(2),
        u16::try_from(entries).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    put_le_u16(
        raw,
        disk_offset(4),
        u16::try_from(max_entries).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    put_le_u16(raw, disk_offset(6), depth)?;
    put_le_u32(raw, disk_offset(8), 0)
}

/// Writes one leaf extent entry.
/// # Errors
///
/// Returns an error when the entry would exceed `raw` or the physical block address cannot be split
/// into ext4 low/high fields.
fn write_extent_entry(raw: &mut [u8], offset: usize, extent: Extent) -> Result<()> {
    let end = offset
        .checked_add(EXTENT_ENTRY_SIZE)
        .ok_or(Error::ArithmeticOverflow)?;
    if end > raw.len() {
        return Err(Error::InvalidExtentTree);
    }
    let len = match extent.initialization() {
        ExtentInitialization::Initialized => extent.len().as_u16(),
        ExtentInitialization::Uninitialized => extent.len().as_u16() | EXTENT_LEN_UNINITIALIZED,
    };
    put_le_u32(raw, disk_offset(offset), extent.logical_start().as_u32())?;
    put_le_u16(
        raw,
        disk_offset(offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?),
        len,
    )?;
    put_le_u16(
        raw,
        disk_offset(offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?),
        u16::try_from(extent.physical_start().get() >> 32)
            .map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    put_le_u32(
        raw,
        disk_offset(offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?),
        u32::try_from(extent.physical_start().get() & u64::from(u32::MAX))
            .map_err(|_| Error::ArithmeticOverflow)?,
    )
}

/// Writes one index entry.
/// # Errors
///
/// Returns an error when the entry would exceed `raw` or the child block address cannot be split
/// into ext4 low/high fields.
fn write_index_entry(raw: &mut [u8], offset: usize, node: &SerializedNode) -> Result<()> {
    let end = offset
        .checked_add(EXTENT_ENTRY_SIZE)
        .ok_or(Error::ArithmeticOverflow)?;
    if end > raw.len() {
        return Err(Error::InvalidExtentTree);
    }
    put_le_u32(raw, disk_offset(offset), node.first_logical.as_u32())?;
    put_le_u32(
        raw,
        disk_offset(offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?),
        u32::try_from(node.block.get() & u64::from(u32::MAX))
            .map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    put_le_u16(
        raw,
        disk_offset(offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?),
        u16::try_from(node.block.get() >> 32).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    put_le_u16(
        raw,
        disk_offset(offset.checked_add(10).ok_or(Error::ArithmeticOverflow)?),
        0,
    )
}

/// Verifies an external extent block checksum when metadata checksums are enabled.
/// # Errors
///
/// Returns an error when the block is too small for a checksum tail or the stored checksum differs
/// from the computed CRC32C.
fn verify_external_extent_block_checksum(context: ExtentTreeContext, raw: &[u8]) -> Result<()> {
    let Some(checksum) = context.checksum else {
        return Ok(());
    };
    let offset = raw
        .len()
        .checked_sub(EXTENT_TAIL_SIZE)
        .ok_or(Error::InvalidExtentTree)?;
    let expected = le_u32(raw, disk_offset(offset))?;
    if extent_block_checksum(checksum, raw, offset)? == expected {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch)
    }
}

/// Refreshes an external extent block checksum when metadata checksums are enabled.
/// # Errors
///
/// Returns an error when the block is too small for a checksum tail or the checksum field cannot be
/// zeroed and rewritten.
fn refresh_external_extent_block_checksum(
    context: ExtentTreeContext,
    raw: &mut [u8],
) -> Result<()> {
    let Some(checksum) = context.checksum else {
        return Ok(());
    };
    let offset = raw
        .len()
        .checked_sub(EXTENT_TAIL_SIZE)
        .ok_or(Error::InvalidExtentTree)?;
    put_le_u32(raw, disk_offset(offset), 0)?;
    let checksum = extent_block_checksum(checksum, raw, offset)?;
    put_le_u32(raw, disk_offset(offset), checksum)
}

/// Computes the crc32c checksum for one external extent block.
/// # Errors
///
/// Returns an error when the pre-tail or post-tail ranges cannot be sliced from `raw`, or the tail
/// offset arithmetic overflows.
fn extent_block_checksum(
    checksum: ExtentBlockChecksum,
    raw: &[u8],
    checksum_offset: usize,
) -> Result<u32> {
    let zero_checksum = [0_u8; EXTENT_TAIL_SIZE];
    let mut seed = crc32c(checksum.seed, &checksum.inode_id.as_u32().to_le_bytes());
    seed = crc32c(seed, &checksum.generation.to_le_bytes());
    let mut value = crc32c(
        seed,
        raw.get(..checksum_offset)
            .ok_or(Error::TruncatedStructure)?,
    );
    value = crc32c(value, &zero_checksum);
    let checksum_end = checksum_offset
        .checked_add(EXTENT_TAIL_SIZE)
        .ok_or(Error::ArithmeticOverflow)?;
    if checksum_end < raw.len() {
        value = crc32c(
            value,
            raw.get(checksum_end..).ok_or(Error::TruncatedStructure)?,
        );
    }
    Ok(value)
}
