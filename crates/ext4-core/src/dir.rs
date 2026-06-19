//! Directory entry parsing and directory layout validation.

use alloc::vec::Vec;

use crate::checksum::crc32c;
use crate::endian::{le_u16, le_u32, put_le_u16, put_le_u32};
use crate::error::{Error, Result};
use crate::inode::InodeId;
use crate::name::Ext4Name;
use crate::superblock::{ChecksumSeed, DirectoryHashSeed, DirectoryHashVersion};

/// Bytes occupied by the fixed header of an ext4 directory record.
const DIRENT_HEADER_SIZE: usize = 8;
/// Directory records are padded to four-byte boundaries on disk.
const DIRENT_ALIGNMENT: usize = 4;
/// Byte offset of `dx_root_info` inside an HTree root directory block.
const DX_ROOT_INFO_OFFSET: usize = 24;
/// Fixed byte length of `dx_root_info`.
const DX_ROOT_INFO_LEN: u8 = 8;
/// Byte offset of the root `dx_countlimit` table header.
const DX_ROOT_COUNT_OFFSET: usize = 32;
/// Byte offset of an interior-node `dx_countlimit` table header.
const DX_NODE_COUNT_OFFSET: usize = 8;
/// Bytes occupied by one HTree index entry.
const DX_ENTRY_BYTES: usize = 8;
/// Bytes occupied by an HTree checksum tail.
const DX_TAIL_BYTES: usize = 8;
/// Bytes occupied by a directory leaf checksum tail.
const DIRENT_TAIL_BYTES: usize = 12;
/// File-type marker used by ext4 directory checksum tails.
const DIRENT_TAIL_FILE_TYPE: u8 = 0xde;
/// HTree block pointers reserve their upper four bits.
const DX_BLOCK_MASK: u32 = 0x0fff_ffff;
/// Maximum HTree indirect depth accepted while `largedir` remains unsupported.
const DX_MAX_DEPTH_WITHOUT_LARGEDIR: u8 = 2;
/// Default seed used by ext4 when all four superblock seed words are zero.
const DEFAULT_HASH_SEED: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
/// TEA delta used by ext4 directory hashing.
const TEA_DELTA: u32 = 0x9e37_79b9;
/// Largest HTree hash value reserved as end-of-directory marker.
const HTREE_EOF_HASH: u32 = 0xffff_fffe;
/// Replacement hash used when a name hashes to the reserved EOF marker.
const HTREE_BEFORE_EOF_HASH: u32 = 0xffff_fffc;

/// File type recorded in an ext4 directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryEntryKind {
    /// Unknown file type.
    Unknown,
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Character device.
    CharacterDevice,
    /// Block device.
    BlockDevice,
    /// FIFO.
    Fifo,
    /// Socket.
    Socket,
}

impl DirectoryEntryKind {
    /// Decodes the ext4 dirent file-type byte.
    fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::File,
            2 => Self::Directory,
            3 => Self::CharacterDevice,
            4 => Self::BlockDevice,
            5 => Self::Fifo,
            6 => Self::Socket,
            7 => Self::Symlink,
            _ => Self::Unknown,
        }
    }

    /// Encodes the ext4 dirent file-type byte.
    pub(crate) const fn to_raw(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::File => 1,
            Self::Directory => 2,
            Self::CharacterDevice => 3,
            Self::BlockDevice => 4,
            Self::Fifo => 5,
            Self::Socket => 6,
            Self::Symlink => 7,
        }
    }
}

/// Valid directory entry exposed by the ext4 domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    /// Non-zero inode referenced by the entry.
    inode: InodeId,
    /// Validated ext4 name bytes.
    name: Ext4Name,
    /// File type recorded in the directory entry.
    kind: DirectoryEntryKind,
}

impl DirectoryEntry {
    /// Creates a live directory entry from validated domain values.
    pub(crate) fn new(inode: InodeId, name: &Ext4Name, kind: DirectoryEntryKind) -> Self {
        Self {
            inode,
            name: name.clone(),
            kind,
        }
    }

    /// Parses a directory file payload into live directory entries.
    ///
    /// # Errors
    /// Returns an error when any directory record has invalid length, alignment,
    /// or name bounds.
    pub fn parse_all(bytes: &[u8]) -> Result<Vec<Self>> {
        let mut entries = Vec::new();
        let mut offset = 0_usize;

        while offset < bytes.len() {
            let remaining = bytes
                .len()
                .checked_sub(offset)
                .ok_or(Error::ArithmeticOverflow)?;
            if remaining < DIRENT_HEADER_SIZE {
                return Err(Error::InvalidDirectoryEntry);
            }

            let inode = le_u32(bytes, offset)?;
            let rec_len = usize::from(le_u16(
                bytes,
                offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
            )?);
            let name_len = usize::from(
                *bytes
                    .get(offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?)
                    .ok_or(Error::InvalidDirectoryEntry)?,
            );
            let file_type = *bytes
                .get(offset.checked_add(7).ok_or(Error::ArithmeticOverflow)?)
                .ok_or(Error::InvalidDirectoryEntry)?;

            if rec_len < DIRENT_HEADER_SIZE || rec_len > remaining || rec_len % 4 != 0 {
                return Err(Error::InvalidDirectoryEntry);
            }
            let payload_len = rec_len
                .checked_sub(DIRENT_HEADER_SIZE)
                .ok_or(Error::InvalidDirectoryEntry)?;
            if name_len > payload_len {
                return Err(Error::InvalidDirectoryEntry);
            }

            if inode != 0 {
                let name_start = offset
                    .checked_add(DIRENT_HEADER_SIZE)
                    .ok_or(Error::ArithmeticOverflow)?;
                let name_end = name_start
                    .checked_add(name_len)
                    .ok_or(Error::ArithmeticOverflow)?;
                entries.push(Self {
                    inode: InodeId::try_from(inode)?,
                    name: Ext4Name::from_disk(
                        bytes
                            .get(name_start..name_end)
                            .ok_or(Error::InvalidDirectoryEntry)?,
                    )?,
                    kind: DirectoryEntryKind::from_raw(file_type),
                });
            }

            offset = offset
                .checked_add(rec_len)
                .ok_or(Error::ArithmeticOverflow)?;
        }

        Ok(entries)
    }

    /// Inode referenced by this entry.
    #[must_use]
    pub const fn inode(&self) -> InodeId {
        self.inode
    }

    /// Raw ext4 entry name.
    #[must_use]
    pub const fn name(&self) -> &Ext4Name {
        &self.name
    }

    /// Directory entry file type.
    #[must_use]
    pub const fn kind(&self) -> DirectoryEntryKind {
        self.kind
    }
}

/// One logical directory file block supplied by the volume layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryBlockData {
    /// Logical block number inside the directory file.
    logical: u32,
    /// Raw block bytes.
    bytes: Vec<u8>,
}

impl DirectoryBlockData {
    /// Creates a directory block payload with its logical block number.
    pub(crate) fn new(logical: u32, bytes: Vec<u8>) -> Self {
        Self { logical, bytes }
    }

    /// Logical block number inside the directory file.
    #[must_use]
    pub(crate) const fn logical(&self) -> u32 {
        self.logical
    }

    /// Raw block bytes.
    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Directory layout selected by inode flags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryLayout {
    /// Plain linear directory.
    Linear(LinearDirectory),
    /// HTree-indexed directory.
    HTree(HtreeDirectory),
}

impl DirectoryLayout {
    /// Parses a directory file into the layout selected by the inode flags.
    pub(crate) fn parse(
        indexed: bool,
        blocks: Vec<DirectoryBlockData>,
        hash_seed: DirectoryHashSeed,
        default_hash_version: DirectoryHashVersion,
        checksum: DirectoryChecksum,
    ) -> Result<Self> {
        if indexed {
            Ok(Self::HTree(HtreeDirectory::parse(
                &blocks,
                hash_seed,
                default_hash_version,
                checksum,
            )?))
        } else {
            Ok(Self::Linear(LinearDirectory::parse(blocks)?))
        }
    }

    /// Returns all live entries in directory traversal order.
    pub(crate) fn entries(&self) -> Vec<DirectoryEntry> {
        match self {
            Self::Linear(directory) => directory.entries.clone(),
            Self::HTree(directory) => directory.entries(),
        }
    }

    /// Finds one exact ext4 child name.
    pub(crate) fn find(&self, name: &Ext4Name) -> Option<DirectoryEntry> {
        match self {
            Self::Linear(directory) => directory.find(name),
            Self::HTree(directory) => directory.find(name),
        }
    }
}

/// Linear directory represented as its validated live dirents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinearDirectory {
    /// Live entries in physical block order.
    entries: Vec<DirectoryEntry>,
}

impl LinearDirectory {
    /// Parses all logical blocks as linear directory blocks.
    fn parse(blocks: Vec<DirectoryBlockData>) -> Result<Self> {
        let mut entries = Vec::new();
        for block in blocks {
            entries.extend(DirectoryEntry::parse_all(block.bytes())?);
        }
        Ok(Self { entries })
    }

    /// Finds one exact ext4 name.
    fn find(&self, name: &Ext4Name) -> Option<DirectoryEntry> {
        self.entries
            .iter()
            .find(|entry| entry.name() == name)
            .cloned()
    }
}

/// Metadata checksum context for directory data and index blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryChecksum {
    /// Directory metadata checksums are disabled.
    None,
    /// CRC32C directory metadata checksums are enabled.
    Crc32c {
        /// Inode-local checksum seed.
        inode_seed: u32,
    },
}

impl DirectoryChecksum {
    /// Builds the ext4 inode-local metadata checksum seed.
    #[must_use]
    pub(crate) fn metadata_csum(
        checksum_seed: ChecksumSeed,
        inode_id: InodeId,
        generation: u32,
    ) -> Self {
        let mut seed = crc32c(checksum_seed.as_u32(), &inode_id.as_u32().to_le_bytes());
        seed = crc32c(seed, &generation.to_le_bytes());
        Self::Crc32c { inode_seed: seed }
    }

    /// Returns the bytes reserved for a leaf dirent tail.
    #[must_use]
    fn dirent_tail_bytes(self) -> usize {
        match self {
            Self::None => 0,
            Self::Crc32c { .. } => DIRENT_TAIL_BYTES,
        }
    }

    /// Returns the bytes reserved for an HTree dx tail.
    #[must_use]
    fn dx_tail_bytes(self) -> usize {
        match self {
            Self::None => 0,
            Self::Crc32c { .. } => DX_TAIL_BYTES,
        }
    }

    /// Writes and checksums a leaf checksum tail when enabled.
    fn write_dirent_tail(self, bytes: &mut [u8], tail_offset: usize) -> Result<()> {
        let Self::Crc32c { inode_seed } = self else {
            return Ok(());
        };
        put_le_u32(bytes, tail_offset, 0)?;
        put_le_u16(
            bytes,
            tail_offset
                .checked_add(4)
                .ok_or(Error::ArithmeticOverflow)?,
            u16::try_from(DIRENT_TAIL_BYTES).map_err(|_| Error::InvalidDirectoryEntry)?,
        )?;
        *bytes
            .get_mut(
                tail_offset
                    .checked_add(6)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::InvalidDirectoryEntry)? = 0;
        *bytes
            .get_mut(
                tail_offset
                    .checked_add(7)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::InvalidDirectoryEntry)? = DIRENT_TAIL_FILE_TYPE;
        put_le_u32(
            bytes,
            tail_offset
                .checked_add(8)
                .ok_or(Error::ArithmeticOverflow)?,
            crc32c(
                inode_seed,
                bytes
                    .get(..tail_offset)
                    .ok_or(Error::InvalidDirectoryEntry)?,
            ),
        )
    }

    /// Verifies a leaf checksum tail when enabled.
    fn verify_dirent_tail(self, bytes: &[u8]) -> Result<()> {
        let Self::Crc32c { inode_seed } = self else {
            return Ok(());
        };
        let tail_offset = bytes
            .len()
            .checked_sub(DIRENT_TAIL_BYTES)
            .ok_or(Error::InvalidDirectoryEntry)?;
        if le_u32(bytes, tail_offset)? != 0
            || usize::from(le_u16(
                bytes,
                tail_offset
                    .checked_add(4)
                    .ok_or(Error::ArithmeticOverflow)?,
            )?) != DIRENT_TAIL_BYTES
            || *bytes
                .get(
                    tail_offset
                        .checked_add(6)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::InvalidDirectoryEntry)?
                != 0
            || *bytes
                .get(
                    tail_offset
                        .checked_add(7)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::InvalidDirectoryEntry)?
                != DIRENT_TAIL_FILE_TYPE
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        let expected = crc32c(
            inode_seed,
            bytes
                .get(..tail_offset)
                .ok_or(Error::InvalidDirectoryEntry)?,
        );
        let actual = le_u32(
            bytes,
            tail_offset
                .checked_add(8)
                .ok_or(Error::ArithmeticOverflow)?,
        )?;
        if actual != expected {
            return Err(Error::ChecksumMismatch);
        }
        Ok(())
    }

    /// Writes and checksums an HTree dx tail when enabled.
    fn write_dx_tail(
        self,
        bytes: &mut [u8],
        count_offset: usize,
        count: usize,
        limit: usize,
    ) -> Result<()> {
        let Self::Crc32c { inode_seed } = self else {
            return Ok(());
        };
        let tail_offset = count_offset
            .checked_add(
                limit
                    .checked_mul(DX_ENTRY_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let checksum_offset = tail_offset
            .checked_add(4)
            .ok_or(Error::ArithmeticOverflow)?;
        if checksum_offset
            .checked_add(4)
            .ok_or(Error::ArithmeticOverflow)?
            > bytes.len()
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        put_le_u32(bytes, tail_offset, 0)?;
        put_le_u32(bytes, checksum_offset, 0)?;
        let table_end = count_offset
            .checked_add(
                count
                    .checked_mul(DX_ENTRY_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let mut checksum = crc32c(
            inode_seed,
            bytes.get(..table_end).ok_or(Error::InvalidDirectoryEntry)?,
        );
        checksum = crc32c(
            checksum,
            bytes
                .get(tail_offset..checksum_offset)
                .ok_or(Error::InvalidDirectoryEntry)?,
        );
        checksum = crc32c(checksum, &0_u32.to_le_bytes());
        put_le_u32(bytes, checksum_offset, checksum)
    }

    /// Verifies an HTree dx tail when enabled.
    fn verify_dx_tail(
        self,
        bytes: &[u8],
        count_offset: usize,
        count: usize,
        limit: usize,
    ) -> Result<()> {
        let Self::Crc32c { inode_seed } = self else {
            return Ok(());
        };
        let tail_offset = count_offset
            .checked_add(
                limit
                    .checked_mul(DX_ENTRY_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let checksum_offset = tail_offset
            .checked_add(4)
            .ok_or(Error::ArithmeticOverflow)?;
        if checksum_offset
            .checked_add(4)
            .ok_or(Error::ArithmeticOverflow)?
            > bytes.len()
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        if le_u32(bytes, tail_offset)? != 0 {
            return Err(Error::InvalidDirectoryEntry);
        }
        let table_end = count_offset
            .checked_add(
                count
                    .checked_mul(DX_ENTRY_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let mut checksum = crc32c(
            inode_seed,
            bytes.get(..table_end).ok_or(Error::InvalidDirectoryEntry)?,
        );
        checksum = crc32c(
            checksum,
            bytes
                .get(tail_offset..checksum_offset)
                .ok_or(Error::InvalidDirectoryEntry)?,
        );
        checksum = crc32c(checksum, &0_u32.to_le_bytes());
        if le_u32(bytes, checksum_offset)? != checksum {
            return Err(Error::ChecksumMismatch);
        }
        Ok(())
    }
}

/// Canonical HTree directory image addressed by logical block number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HtreeDirectoryImage {
    /// Directory logical blocks from zero through `blocks.len() - 1`.
    blocks: Vec<Vec<u8>>,
}

impl HtreeDirectoryImage {
    /// Returns the generated logical block count.
    #[must_use]
    pub(crate) fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns generated blocks in logical block order.
    #[must_use]
    pub(crate) fn blocks(&self) -> &[Vec<u8>] {
        &self.blocks
    }
}

/// Builds a canonical HTree directory image from child entries.
pub(crate) fn build_htree_directory(
    self_inode: InodeId,
    parent_inode: InodeId,
    children: &[DirectoryEntry],
    block_size: usize,
    hash_seed: DirectoryHashSeed,
    hash_version: DirectoryHashVersion,
    checksum: DirectoryChecksum,
) -> Result<HtreeDirectoryImage> {
    if block_size < DX_ROOT_COUNT_OFFSET + DX_ENTRY_BYTES {
        return Err(Error::InvalidDirectoryEntry);
    }
    let hash = DirectoryHashContext::new(hash_seed, hash_version);
    let mut hashed = Vec::new();
    for entry in children {
        let name = entry.name().bytes();
        if name == b"." || name == b".." {
            continue;
        }
        hashed.push(HashedDirectoryEntry {
            hash: hash.hash_name(entry.name()),
            entry: entry.clone(),
        });
    }
    hashed.sort_by(|left, right| {
        left.hash
            .major
            .cmp(&right.hash.major)
            .then(left.hash.minor.cmp(&right.hash.minor))
            .then(left.entry.name().bytes().cmp(right.entry.name().bytes()))
    });

    let leaves = pack_htree_leaves(hashed, block_size, checksum)?;
    let root_limit = dx_capacity(block_size, DX_ROOT_COUNT_OFFSET, checksum)?;
    let node_limit = dx_capacity(block_size, DX_NODE_COUNT_OFFSET, checksum)?;
    let plan = HtreeBuildPlan::new(&leaves, root_limit, node_limit)?;
    let mut blocks = alloc::vec![alloc::vec![0_u8; block_size]; plan.block_count()?];

    for (index, leaf) in leaves.iter().enumerate() {
        let logical = plan.leaf_logical(index)?;
        let block = blocks
            .get_mut(usize::try_from(logical).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::InvalidDirectoryEntry)?;
        write_leaf_block(block, &leaf.entries, checksum)?;
    }
    for node in plan.nodes(&leaves)? {
        let block = blocks
            .get_mut(usize::try_from(node.logical).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::InvalidDirectoryEntry)?;
        write_index_node(block, &node.entries, checksum)?;
    }
    write_htree_root(
        blocks.get_mut(0).ok_or(Error::InvalidDirectoryEntry)?,
        self_inode,
        parent_inode,
        hash_version,
        plan.depth,
        &plan.root_entries(&leaves)?,
        checksum,
    )?;
    Ok(HtreeDirectoryImage { blocks })
}

/// Directory entry paired with its ext4 directory hash.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HashedDirectoryEntry {
    /// Hash result for the entry name.
    hash: DirectoryHash,
    /// Entry payload.
    entry: DirectoryEntry,
}

/// Packed HTree leaf before serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PackedLeaf {
    /// First hash routed to this leaf.
    start_hash: u32,
    /// Last hash stored in this leaf.
    last_hash: u32,
    /// Entries assigned to this leaf.
    entries: Vec<DirectoryEntry>,
}

/// Packs sorted entries into leaf blocks.
fn pack_htree_leaves(
    hashed: Vec<HashedDirectoryEntry>,
    block_size: usize,
    checksum: DirectoryChecksum,
) -> Result<Vec<PackedLeaf>> {
    let live_limit = block_size
        .checked_sub(checksum.dirent_tail_bytes())
        .ok_or(Error::InvalidDirectoryEntry)?;
    if live_limit < DIRENT_HEADER_SIZE {
        return Err(Error::InvalidDirectoryEntry);
    }
    let mut leaves = Vec::new();
    let mut current = Vec::new();
    let mut current_len = 0_usize;
    let mut current_start = 0_u32;
    let mut current_last = 0_u32;

    for item in hashed {
        let needed = required_name_rec_len(item.entry.name().bytes().len())?;
        if needed > live_limit {
            return Err(Error::DirectoryTooLarge);
        }
        if !current.is_empty()
            && current_len
                .checked_add(needed)
                .ok_or(Error::ArithmeticOverflow)?
                > live_limit
        {
            leaves.push(PackedLeaf {
                start_hash: current_start,
                last_hash: current_last,
                entries: current,
            });
            current = Vec::new();
            current_len = 0;
        }
        if current.is_empty() {
            current_start = if leaves.is_empty() {
                0
            } else if leaves
                .last()
                .map(|leaf| leaf.last_hash == item.hash.major)
                .unwrap_or(false)
            {
                item.hash.major | 1
            } else {
                item.hash.major
            };
        }
        current_len = current_len
            .checked_add(needed)
            .ok_or(Error::ArithmeticOverflow)?;
        current_last = item.hash.major;
        current.push(item.entry);
    }

    if current.is_empty() {
        leaves.push(PackedLeaf {
            start_hash: 0,
            last_hash: 0,
            entries: Vec::new(),
        });
    } else {
        leaves.push(PackedLeaf {
            start_hash: current_start,
            last_hash: current_last,
            entries: current,
        });
    }
    Ok(leaves)
}

/// HTree rebuild plan with logical block assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HtreeBuildPlan {
    /// Indirect levels recorded in the root.
    depth: u8,
    /// Number of root children.
    root_count: usize,
    /// Number of first-level index nodes.
    upper_nodes: usize,
    /// Number of second-level index nodes.
    lower_nodes: usize,
    /// Number of leaf blocks.
    leaf_count: usize,
    /// Maximum entries in an interior node.
    node_limit: usize,
}

impl HtreeBuildPlan {
    /// Selects the shallowest HTree that can route all leaves.
    fn new(leaves: &[PackedLeaf], root_limit: usize, node_limit: usize) -> Result<Self> {
        if root_limit == 0 || node_limit == 0 {
            return Err(Error::InvalidDirectoryEntry);
        }
        let leaf_count = leaves.len();
        if leaf_count <= root_limit {
            return Ok(Self {
                depth: 0,
                root_count: leaf_count,
                upper_nodes: 0,
                lower_nodes: 0,
                leaf_count,
                node_limit,
            });
        }
        let lower_nodes = round_up_div_usize(leaf_count, node_limit)?;
        if lower_nodes <= root_limit {
            return Ok(Self {
                depth: 1,
                root_count: lower_nodes,
                upper_nodes: 0,
                lower_nodes,
                leaf_count,
                node_limit,
            });
        }
        let upper_nodes = round_up_div_usize(lower_nodes, node_limit)?;
        if upper_nodes <= root_limit {
            return Ok(Self {
                depth: 2,
                root_count: upper_nodes,
                upper_nodes,
                lower_nodes,
                leaf_count,
                node_limit,
            });
        }
        Err(Error::DirectoryTooLarge)
    }

    /// Total generated directory logical blocks.
    fn block_count(&self) -> Result<usize> {
        checked_sum_usize(&[1, self.upper_nodes, self.lower_nodes, self.leaf_count])
    }

    /// Returns the logical block number for one leaf index.
    fn leaf_logical(&self, index: usize) -> Result<u32> {
        if index >= self.leaf_count {
            return Err(Error::InvalidDirectoryEntry);
        }
        usize_to_u32(checked_sum_usize(&[
            1,
            self.upper_nodes,
            self.lower_nodes,
            index,
        ])?)
    }

    /// Returns the logical block number for a lower index node.
    fn lower_node_logical(&self, lower: usize) -> Result<u32> {
        usize_to_u32(checked_sum_usize(&[1, self.upper_nodes, lower])?)
    }

    /// Returns the logical block number for an upper index node.
    fn upper_node_logical(&self, upper: usize) -> Result<u32> {
        usize_to_u32(checked_sum_usize(&[1, upper])?)
    }

    /// Returns all index nodes that must be serialized.
    fn nodes(&self, leaves: &[PackedLeaf]) -> Result<Vec<PlannedIndexNode>> {
        let mut nodes = Vec::new();
        if self.depth == 0 {
            return Ok(nodes);
        }
        for lower in 0..self.lower_nodes {
            let first_leaf = lower
                .checked_mul(self.node_limit)
                .ok_or(Error::ArithmeticOverflow)?;
            let last_leaf = leaves.len().min(
                first_leaf
                    .checked_add(self.node_limit)
                    .ok_or(Error::ArithmeticOverflow)?,
            );
            let mut entries = Vec::new();
            for (leaf_index, leaf) in leaves.iter().enumerate().take(last_leaf).skip(first_leaf) {
                entries.push(DxEntry {
                    hash: leaf.start_hash,
                    block: self.leaf_logical(leaf_index)?,
                });
            }
            let logical = self.lower_node_logical(lower)?;
            nodes.push(PlannedIndexNode { logical, entries });
        }
        if self.depth == 2 {
            for upper in 0..self.upper_nodes {
                let first_lower = upper
                    .checked_mul(self.node_limit)
                    .ok_or(Error::ArithmeticOverflow)?;
                let last_lower = self.lower_nodes.min(
                    first_lower
                        .checked_add(self.node_limit)
                        .ok_or(Error::ArithmeticOverflow)?,
                );
                let mut entries = Vec::new();
                for lower in first_lower..last_lower {
                    let first_leaf = lower
                        .checked_mul(self.node_limit)
                        .ok_or(Error::ArithmeticOverflow)?;
                    entries.push(DxEntry {
                        hash: leaves
                            .get(first_leaf)
                            .ok_or(Error::InvalidDirectoryEntry)?
                            .start_hash,
                        block: self.lower_node_logical(lower)?,
                    });
                }
                nodes.push(PlannedIndexNode {
                    logical: self.upper_node_logical(upper)?,
                    entries,
                });
            }
        }
        Ok(nodes)
    }

    /// Returns root index entries.
    fn root_entries(&self, leaves: &[PackedLeaf]) -> Result<Vec<DxEntry>> {
        let mut entries = Vec::new();
        match self.depth {
            0 => {
                for (index, leaf) in leaves.iter().enumerate().take(self.root_count) {
                    entries.push(DxEntry {
                        hash: leaf.start_hash,
                        block: self.leaf_logical(index)?,
                    });
                }
            }
            1 => {
                for lower in 0..self.root_count {
                    let first_leaf = lower
                        .checked_mul(self.node_limit)
                        .ok_or(Error::ArithmeticOverflow)?;
                    entries.push(DxEntry {
                        hash: leaves
                            .get(first_leaf)
                            .ok_or(Error::InvalidDirectoryEntry)?
                            .start_hash,
                        block: usize_to_u32(checked_sum_usize(&[1, lower])?)?,
                    });
                }
            }
            2 => {
                for upper in 0..self.root_count {
                    let first_lower = upper
                        .checked_mul(self.node_limit)
                        .ok_or(Error::ArithmeticOverflow)?;
                    let first_leaf = first_lower
                        .checked_mul(self.node_limit)
                        .ok_or(Error::ArithmeticOverflow)?;
                    entries.push(DxEntry {
                        hash: leaves
                            .get(first_leaf)
                            .ok_or(Error::InvalidDirectoryEntry)?
                            .start_hash,
                        block: self.upper_node_logical(upper)?,
                    });
                }
            }
            _ => return Err(Error::DirectoryTooLarge),
        }
        Ok(entries)
    }
}

/// Planned HTree interior node.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PlannedIndexNode {
    /// Directory logical block number.
    logical: u32,
    /// Child index entries.
    entries: Vec<DxEntry>,
}

/// Calculates how many dx entries fit in one root or node block.
fn dx_capacity(
    block_size: usize,
    count_offset: usize,
    checksum: DirectoryChecksum,
) -> Result<usize> {
    block_size
        .checked_sub(checksum.dx_tail_bytes())
        .and_then(|bytes| bytes.checked_sub(count_offset))
        .ok_or(Error::InvalidDirectoryEntry)?
        .checked_div(DX_ENTRY_BYTES)
        .ok_or(Error::InvalidDirectoryEntry)
}

/// Serializes an HTree leaf block.
fn write_leaf_block(
    bytes: &mut [u8],
    entries: &[DirectoryEntry],
    checksum: DirectoryChecksum,
) -> Result<()> {
    bytes.fill(0);
    let live_limit = bytes
        .len()
        .checked_sub(checksum.dirent_tail_bytes())
        .ok_or(Error::InvalidDirectoryEntry)?;
    if entries.is_empty() {
        put_le_u16(bytes, 4, checked_u16(live_limit)?)?;
    } else {
        let mut offset = 0_usize;
        let last_index = entries
            .len()
            .checked_sub(1)
            .ok_or(Error::InvalidDirectoryEntry)?;
        for (index, entry) in entries.iter().enumerate() {
            let rec_len = if index == last_index {
                live_limit
                    .checked_sub(offset)
                    .ok_or(Error::ArithmeticOverflow)?
            } else {
                required_name_rec_len(entry.name().bytes().len())?
            };
            write_entry(
                bytes,
                offset,
                entry.inode(),
                checked_u16(rec_len)?,
                entry.name().bytes(),
                entry.kind(),
            )?;
            offset = offset
                .checked_add(rec_len)
                .ok_or(Error::ArithmeticOverflow)?;
        }
    }
    checksum.write_dirent_tail(bytes, live_limit)
}

/// Serializes an HTree interior node.
fn write_index_node(
    bytes: &mut [u8],
    entries: &[DxEntry],
    checksum: DirectoryChecksum,
) -> Result<()> {
    bytes.fill(0);
    put_le_u16(bytes, 4, checked_u16(bytes.len())?)?;
    write_dx_table(bytes, DX_NODE_COUNT_OFFSET, entries, checksum)
}

/// Serializes the HTree root block.
fn write_htree_root(
    bytes: &mut [u8],
    self_inode: InodeId,
    parent_inode: InodeId,
    hash_version: DirectoryHashVersion,
    depth: u8,
    entries: &[DxEntry],
    checksum: DirectoryChecksum,
) -> Result<()> {
    bytes.fill(0);
    write_entry(
        bytes,
        0,
        self_inode,
        checked_u16(checked_rec_len(DIRENT_HEADER_SIZE + 1)?)?,
        b".",
        DirectoryEntryKind::Directory,
    )?;
    write_entry(
        bytes,
        checked_rec_len(DIRENT_HEADER_SIZE + 1)?,
        parent_inode,
        checked_u16(
            bytes
                .len()
                .checked_sub(checked_rec_len(DIRENT_HEADER_SIZE + 1)?)
                .ok_or(Error::ArithmeticOverflow)?,
        )?,
        b"..",
        DirectoryEntryKind::Directory,
    )?;
    put_le_u32(bytes, DX_ROOT_INFO_OFFSET, 0)?;
    *bytes
        .get_mut(DX_ROOT_INFO_OFFSET + 4)
        .ok_or(Error::InvalidDirectoryEntry)? = hash_version.to_raw();
    *bytes
        .get_mut(DX_ROOT_INFO_OFFSET + 5)
        .ok_or(Error::InvalidDirectoryEntry)? = DX_ROOT_INFO_LEN;
    *bytes
        .get_mut(DX_ROOT_INFO_OFFSET + 6)
        .ok_or(Error::InvalidDirectoryEntry)? = depth;
    *bytes
        .get_mut(DX_ROOT_INFO_OFFSET + 7)
        .ok_or(Error::InvalidDirectoryEntry)? = 0;
    write_dx_table(bytes, DX_ROOT_COUNT_OFFSET, entries, checksum)
}

/// Serializes a dx_countlimit/dx_entry table.
fn write_dx_table(
    bytes: &mut [u8],
    count_offset: usize,
    entries: &[DxEntry],
    checksum: DirectoryChecksum,
) -> Result<()> {
    let limit = dx_capacity(bytes.len(), count_offset, checksum)?;
    if entries.is_empty() || entries.len() > limit {
        return Err(Error::InvalidDirectoryEntry);
    }
    put_le_u16(bytes, count_offset, checked_u16(limit)?)?;
    put_le_u16(
        bytes,
        count_offset
            .checked_add(2)
            .ok_or(Error::ArithmeticOverflow)?,
        checked_u16(entries.len())?,
    )?;
    for (index, entry) in entries.iter().enumerate() {
        let offset = count_offset
            .checked_add(
                index
                    .checked_mul(DX_ENTRY_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        if index != 0 {
            put_le_u32(bytes, offset, entry.hash)?;
        }
        put_le_u32(
            bytes,
            offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
            entry.block & DX_BLOCK_MASK,
        )?;
    }
    checksum.write_dx_tail(bytes, count_offset, entries.len(), limit)
}

/// Integer ceil division for HTree fan-out planning.
fn round_up_div_usize(value: usize, divisor: usize) -> Result<usize> {
    if divisor == 0 {
        return Err(Error::ArithmeticOverflow);
    }
    value
        .checked_add(divisor.checked_sub(1).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::ArithmeticOverflow)?
        .checked_div(divisor)
        .ok_or(Error::ArithmeticOverflow)
}

/// Sums usize values with overflow checking.
fn checked_sum_usize(values: &[usize]) -> Result<usize> {
    let mut sum = 0_usize;
    for value in values {
        sum = sum.checked_add(*value).ok_or(Error::ArithmeticOverflow)?;
    }
    Ok(sum)
}

/// Converts a usize logical block value into the on-disk u32 range.
fn usize_to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::ArithmeticOverflow)
}

/// HTree directory represented as dot entries plus indexed leaf blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HtreeDirectory {
    /// Directory hash context selected by the root info.
    hash: DirectoryHashContext,
    /// `.` and `..` entries stored in the root block.
    dot_entries: Vec<DirectoryEntry>,
    /// Leaf blocks in index traversal order.
    leaves: Vec<HtreeLeaf>,
}

impl HtreeDirectory {
    /// Parses an HTree directory from logical directory blocks.
    fn parse(
        blocks: &[DirectoryBlockData],
        hash_seed: DirectoryHashSeed,
        default_hash_version: DirectoryHashVersion,
        checksum: DirectoryChecksum,
    ) -> Result<Self> {
        let root_block = find_directory_block(blocks, 0)?;
        let root = HtreeRoot::parse(
            root_block.bytes(),
            hash_seed,
            default_hash_version,
            checksum,
        )?;
        let leaf_blocks = root.leaf_blocks(blocks, checksum)?;
        let mut leaves = Vec::new();
        for indexed_leaf in leaf_blocks {
            let block = find_directory_block(blocks, indexed_leaf.logical)?;
            leaves.push(HtreeLeaf::parse(
                indexed_leaf.start_hash,
                block.bytes(),
                checksum,
            )?);
        }
        Ok(Self {
            hash: root.hash,
            dot_entries: root.dot_entries,
            leaves,
        })
    }

    /// Returns all live entries in HTree traversal order.
    fn entries(&self) -> Vec<DirectoryEntry> {
        let mut entries = self.dot_entries.clone();
        for leaf in &self.leaves {
            entries.extend(leaf.entries.iter().cloned());
        }
        entries
    }

    /// Finds an exact ext4 name through the hash-selected leaf chain.
    fn find(&self, name: &Ext4Name) -> Option<DirectoryEntry> {
        let hash = self.hash.hash_name(name).major;
        let start = self
            .leaves
            .iter()
            .rposition(|leaf| leaf.start_hash & !1 <= hash)
            .unwrap_or(0);
        let mut chain_start = start;
        while let Some(previous) = chain_start.checked_sub(1) {
            if !self.same_hash_chain(previous, chain_start) {
                break;
            }
            chain_start = previous;
        }
        for leaf in self.leaves.iter().skip(chain_start) {
            let leaf_hash = leaf.start_hash & !1;
            if leaf_hash > hash {
                break;
            }
            if let Some(entry) = leaf.find(name) {
                return Some(entry);
            }
        }
        None
    }

    /// Returns whether two adjacent leaves belong to the same collision chain.
    fn same_hash_chain(&self, left: usize, right: usize) -> bool {
        match (self.leaves.get(left), self.leaves.get(right)) {
            (Some(left), Some(right)) => left.start_hash & !1 == right.start_hash & !1,
            _ => false,
        }
    }
}

/// One HTree leaf after root/node traversal.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HtreeLeaf {
    /// First hash value routed to this leaf.
    start_hash: u32,
    /// Live entries stored in the leaf block.
    entries: Vec<DirectoryEntry>,
}

impl HtreeLeaf {
    /// Parses one leaf block as dirents.
    fn parse(start_hash: u32, bytes: &[u8], checksum: DirectoryChecksum) -> Result<Self> {
        checksum.verify_dirent_tail(bytes)?;
        Ok(Self {
            start_hash,
            entries: DirectoryEntry::parse_all(bytes)?,
        })
    }

    /// Finds one exact ext4 name in this leaf.
    fn find(&self, name: &Ext4Name) -> Option<DirectoryEntry> {
        self.entries
            .iter()
            .find(|entry| entry.name() == name)
            .cloned()
    }
}

/// Parsed HTree root block.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HtreeRoot {
    /// Directory hash context selected by root info.
    hash: DirectoryHashContext,
    /// `.` and `..` entries stored before the root info.
    dot_entries: Vec<DirectoryEntry>,
    /// Number of index levels between root entries and leaf blocks.
    indirect_levels: u8,
    /// Root index table.
    index: DxIndex,
}

impl HtreeRoot {
    /// Parses and validates an HTree root block.
    fn parse(
        bytes: &[u8],
        hash_seed: DirectoryHashSeed,
        _default_hash_version: DirectoryHashVersion,
        checksum: DirectoryChecksum,
    ) -> Result<Self> {
        if bytes.len() < DX_ROOT_COUNT_OFFSET + DX_ENTRY_BYTES {
            return Err(Error::InvalidDirectoryEntry);
        }
        let dot = parse_live_entry_at(bytes, 0)?;
        if dot.name().bytes() != b"." {
            return Err(Error::InvalidDirectoryEntry);
        }
        let dotdot = parse_live_entry_at(bytes, checked_rec_len(DIRENT_HEADER_SIZE + 1)?)?;
        if dotdot.name().bytes() != b".." {
            return Err(Error::InvalidDirectoryEntry);
        }
        if le_u32(bytes, DX_ROOT_INFO_OFFSET)? != 0 {
            return Err(Error::InvalidDirectoryEntry);
        }
        let root_hash_version = *bytes
            .get(DX_ROOT_INFO_OFFSET + 4)
            .ok_or(Error::InvalidDirectoryEntry)?;
        let hash_version = DirectoryHashVersion::from_raw(root_hash_version)?;
        let info_len = *bytes
            .get(DX_ROOT_INFO_OFFSET + 5)
            .ok_or(Error::InvalidDirectoryEntry)?;
        if info_len != DX_ROOT_INFO_LEN {
            return Err(Error::InvalidDirectoryEntry);
        }
        let indirect_levels = *bytes
            .get(DX_ROOT_INFO_OFFSET + 6)
            .ok_or(Error::InvalidDirectoryEntry)?;
        if indirect_levels > DX_MAX_DEPTH_WITHOUT_LARGEDIR {
            return Err(Error::DirectoryTooLarge);
        }
        let index = DxIndex::parse(bytes, DX_ROOT_COUNT_OFFSET, checksum)?;
        Ok(Self {
            hash: DirectoryHashContext::new(hash_seed, hash_version),
            dot_entries: alloc::vec![dot, dotdot],
            indirect_levels,
            index,
        })
    }

    /// Resolves all leaf logical blocks in index traversal order.
    fn leaf_blocks(
        &self,
        blocks: &[DirectoryBlockData],
        checksum: DirectoryChecksum,
    ) -> Result<Vec<IndexedLeafBlock>> {
        let mut leaves = Vec::new();
        let mut visited = Vec::new();
        for entry in &self.index.entries {
            collect_leaf_blocks(
                blocks,
                entry.block,
                entry.hash,
                self.indirect_levels,
                checksum,
                &mut visited,
                &mut leaves,
            )?;
        }
        Ok(leaves)
    }
}

/// Logical leaf block selected by an HTree index entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IndexedLeafBlock {
    /// First hash value routed to this leaf.
    start_hash: u32,
    /// Logical block number inside the directory file.
    logical: u32,
}

/// HTree index table.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DxIndex {
    /// Entries in on-disk order.
    entries: Vec<DxEntry>,
}

impl DxIndex {
    /// Parses a root or interior HTree index table.
    fn parse(bytes: &[u8], count_offset: usize, checksum: DirectoryChecksum) -> Result<Self> {
        let limit = usize::from(le_u16(bytes, count_offset)?);
        let count = usize::from(le_u16(
            bytes,
            count_offset
                .checked_add(2)
                .ok_or(Error::ArithmeticOverflow)?,
        )?);
        let capacity = dx_capacity(bytes.len(), count_offset, checksum)?;
        if count == 0 || count > limit || limit > capacity {
            return Err(Error::InvalidDirectoryEntry);
        }
        checksum.verify_dx_tail(bytes, count_offset, count, limit)?;
        let end = count_offset
            .checked_add(
                count
                    .checked_mul(DX_ENTRY_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        if end > bytes.len() {
            return Err(Error::InvalidDirectoryEntry);
        }
        let mut entries = Vec::new();
        for index in 0..count {
            let entry_offset = count_offset
                .checked_add(
                    index
                        .checked_mul(DX_ENTRY_BYTES)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            let hash = if index == 0 {
                0
            } else {
                le_u32(bytes, entry_offset)?
            };
            let block = le_u32(
                bytes,
                entry_offset
                    .checked_add(4)
                    .ok_or(Error::ArithmeticOverflow)?,
            )? & DX_BLOCK_MASK;
            if block == 0 {
                return Err(Error::InvalidDirectoryEntry);
            }
            entries.push(DxEntry { hash, block });
        }
        Ok(Self { entries })
    }
}

/// One HTree index entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DxEntry {
    /// First hash value routed to `block`.
    hash: u32,
    /// Directory logical block pointer.
    block: u32,
}

/// Recursively resolves index nodes into leaf logical blocks.
fn collect_leaf_blocks(
    blocks: &[DirectoryBlockData],
    logical: u32,
    start_hash: u32,
    depth: u8,
    checksum: DirectoryChecksum,
    visited: &mut Vec<u32>,
    leaves: &mut Vec<IndexedLeafBlock>,
) -> Result<()> {
    if visited.contains(&logical) {
        return Err(Error::InvalidDirectoryEntry);
    }
    visited.push(logical);
    if depth == 0 {
        leaves.push(IndexedLeafBlock {
            start_hash,
            logical,
        });
        return Ok(());
    }
    let block = find_directory_block(blocks, logical)?;
    let node = DxIndex::parse(block.bytes(), DX_NODE_COUNT_OFFSET, checksum)?;
    for entry in node.entries {
        collect_leaf_blocks(
            blocks,
            entry.block,
            entry.hash,
            depth.checked_sub(1).ok_or(Error::InvalidDirectoryEntry)?,
            checksum,
            visited,
            leaves,
        )?;
    }
    Ok(())
}

/// Finds one supplied logical directory block.
fn find_directory_block(
    blocks: &[DirectoryBlockData],
    logical: u32,
) -> Result<&DirectoryBlockData> {
    blocks
        .iter()
        .find(|block| block.logical() == logical)
        .ok_or(Error::InvalidDirectoryEntry)
}

/// Mutable ext4 directory block with checked dirent surgery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryBlock {
    /// Raw directory block bytes; all mutations update this single buffer.
    bytes: Vec<u8>,
}

impl DirectoryBlock {
    /// Wraps an existing directory block for checked mutation.
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Creates a zero-filled directory block with the filesystem block size.
    pub(crate) fn empty(block_size: usize) -> Self {
        Self {
            bytes: alloc::vec![0_u8; block_size],
        }
    }

    /// Returns the mutated directory block bytes.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Initializes `.` and `..`, leaving the second entry to own remaining space.
    pub(crate) fn initialize_dot_entries(
        &mut self,
        self_inode: InodeId,
        parent_inode: InodeId,
    ) -> Result<()> {
        let block_len = self.bytes.len();
        if block_len
            < checked_rec_len(DIRENT_HEADER_SIZE)?
                .checked_mul(2)
                .ok_or(Error::ArithmeticOverflow)?
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        write_entry(
            &mut self.bytes,
            0,
            self_inode,
            checked_u16(checked_rec_len(DIRENT_HEADER_SIZE + 1)?)?,
            b".",
            DirectoryEntryKind::Directory,
        )?;
        let dotdot_offset = checked_rec_len(DIRENT_HEADER_SIZE + 1)?;
        write_entry(
            &mut self.bytes,
            dotdot_offset,
            parent_inode,
            checked_u16(
                block_len
                    .checked_sub(dotdot_offset)
                    .ok_or(Error::ArithmeticOverflow)?,
            )?,
            b"..",
            DirectoryEntryKind::Directory,
        )
    }

    /// Initializes the block as one free dirent slot.
    pub(crate) fn initialize_free_space(&mut self) -> Result<()> {
        let rec_len = checked_u16(self.bytes.len())?;
        self.bytes.fill(0);
        put_le_u16(&mut self.bytes, 4, rec_len)
    }

    /// Parses live entries from the current block image.
    pub(crate) fn entries(&self) -> Result<Vec<DirectoryEntry>> {
        DirectoryEntry::parse_all(&self.bytes)
    }

    /// Checks whether a live entry already owns `name`.
    pub(crate) fn contains_name(&self, name: &Ext4Name) -> Result<bool> {
        for entry in self.entries()? {
            if entry.name() == name {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Inserts a live entry by reusing free space or splitting an oversized record.
    pub(crate) fn insert(
        &mut self,
        inode: InodeId,
        name: &Ext4Name,
        kind: DirectoryEntryKind,
    ) -> Result<bool> {
        if self.contains_name(name)? {
            return Err(Error::NameAlreadyExists);
        }
        let needed = checked_rec_len(
            DIRENT_HEADER_SIZE
                .checked_add(name.bytes().len())
                .ok_or(Error::ArithmeticOverflow)?,
        )?;
        let mut offset = 0_usize;
        while offset < self.bytes.len() {
            let rec_len = usize::from(le_u16(
                &self.bytes,
                offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
            )?);
            if rec_len < DIRENT_HEADER_SIZE
                || offset
                    .checked_add(rec_len)
                    .ok_or(Error::ArithmeticOverflow)?
                    > self.bytes.len()
            {
                return Err(Error::InvalidDirectoryEntry);
            }
            let live_inode = le_u32(&self.bytes, offset)?;
            let name_len = usize::from(
                *self
                    .bytes
                    .get(offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?)
                    .ok_or(Error::InvalidDirectoryEntry)?,
            );
            if live_inode == 0 && rec_len >= needed {
                write_entry(
                    &mut self.bytes,
                    offset,
                    inode,
                    checked_u16(rec_len)?,
                    name.bytes(),
                    kind,
                )?;
                return Ok(true);
            }
            let used = checked_rec_len(
                DIRENT_HEADER_SIZE
                    .checked_add(name_len)
                    .ok_or(Error::ArithmeticOverflow)?,
            )?;
            if live_inode != 0
                && rec_len >= used.checked_add(needed).ok_or(Error::ArithmeticOverflow)?
            {
                put_le_u16(
                    &mut self.bytes,
                    offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
                    checked_u16(used)?,
                )?;
                let insert_offset = offset.checked_add(used).ok_or(Error::ArithmeticOverflow)?;
                let insert_len = rec_len.checked_sub(used).ok_or(Error::ArithmeticOverflow)?;
                write_entry(
                    &mut self.bytes,
                    insert_offset,
                    inode,
                    checked_u16(insert_len)?,
                    name.bytes(),
                    kind,
                )?;
                return Ok(true);
            }
            offset = offset
                .checked_add(rec_len)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(false)
    }

    /// Removes a live entry by clearing its inode while preserving record length.
    pub(crate) fn remove(&mut self, name: &Ext4Name) -> Result<Option<DirectoryEntry>> {
        let mut offset = 0_usize;
        while offset < self.bytes.len() {
            let rec_len = usize::from(le_u16(
                &self.bytes,
                offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
            )?);
            if rec_len < DIRENT_HEADER_SIZE
                || offset
                    .checked_add(rec_len)
                    .ok_or(Error::ArithmeticOverflow)?
                    > self.bytes.len()
            {
                return Err(Error::InvalidDirectoryEntry);
            }
            let inode = le_u32(&self.bytes, offset)?;
            let name_len = usize::from(
                *self
                    .bytes
                    .get(offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?)
                    .ok_or(Error::InvalidDirectoryEntry)?,
            );
            let name_start = offset
                .checked_add(DIRENT_HEADER_SIZE)
                .ok_or(Error::ArithmeticOverflow)?;
            let name_end = name_start
                .checked_add(name_len)
                .ok_or(Error::ArithmeticOverflow)?;
            if inode != 0
                && self
                    .bytes
                    .get(name_start..name_end)
                    .ok_or(Error::InvalidDirectoryEntry)?
                    == name.bytes()
            {
                let kind = DirectoryEntryKind::from_raw(
                    *self
                        .bytes
                        .get(offset.checked_add(7).ok_or(Error::ArithmeticOverflow)?)
                        .ok_or(Error::InvalidDirectoryEntry)?,
                );
                let removed = DirectoryEntry {
                    inode: InodeId::try_from(inode)?,
                    name: Ext4Name::from_disk(name.bytes())?,
                    kind,
                };
                put_le_u32(&mut self.bytes, offset, 0)?;
                return Ok(Some(removed));
            }
            offset = offset
                .checked_add(rec_len)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(None)
    }

    /// Renames a live entry inside this directory block.
    pub(crate) fn rename(
        &mut self,
        old_name: &Ext4Name,
        new_name: &Ext4Name,
    ) -> Result<Option<DirectoryEntry>> {
        if self.contains_name(new_name)? {
            return Err(Error::NameAlreadyExists);
        }

        let original = self.bytes.clone();
        let Some(entry) = self.remove(old_name)? else {
            return Ok(None);
        };
        let renamed = self.insert(entry.inode(), new_name, entry.kind())?;
        if renamed {
            Ok(Some(entry))
        } else {
            self.bytes = original;
            Err(Error::NoSpace)
        }
    }

    /// Replaces the inode and kind of an existing entry without changing its name.
    pub(crate) fn replace(
        &mut self,
        name: &Ext4Name,
        inode: InodeId,
        kind: DirectoryEntryKind,
    ) -> Result<Option<DirectoryEntry>> {
        let mut offset = 0_usize;
        while offset < self.bytes.len() {
            let rec_len = usize::from(le_u16(
                &self.bytes,
                offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
            )?);
            if rec_len < DIRENT_HEADER_SIZE
                || offset
                    .checked_add(rec_len)
                    .ok_or(Error::ArithmeticOverflow)?
                    > self.bytes.len()
            {
                return Err(Error::InvalidDirectoryEntry);
            }
            let live_inode = le_u32(&self.bytes, offset)?;
            let name_len = usize::from(
                *self
                    .bytes
                    .get(offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?)
                    .ok_or(Error::InvalidDirectoryEntry)?,
            );
            let name_start = offset
                .checked_add(DIRENT_HEADER_SIZE)
                .ok_or(Error::ArithmeticOverflow)?;
            let name_end = name_start
                .checked_add(name_len)
                .ok_or(Error::ArithmeticOverflow)?;
            if live_inode != 0
                && self
                    .bytes
                    .get(name_start..name_end)
                    .ok_or(Error::InvalidDirectoryEntry)?
                    == name.bytes()
            {
                let previous = DirectoryEntry {
                    inode: InodeId::try_from(live_inode)?,
                    name: Ext4Name::from_disk(name.bytes())?,
                    kind: DirectoryEntryKind::from_raw(
                        *self
                            .bytes
                            .get(offset.checked_add(7).ok_or(Error::ArithmeticOverflow)?)
                            .ok_or(Error::InvalidDirectoryEntry)?,
                    ),
                };
                write_entry(
                    &mut self.bytes,
                    offset,
                    inode,
                    checked_u16(rec_len)?,
                    name.bytes(),
                    kind,
                )?;
                return Ok(Some(previous));
            }
            offset = offset
                .checked_add(rec_len)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(None)
    }
}

/// Directory hash result used for HTree leaf routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryHash {
    /// Primary 32-bit HTree hash.
    pub(crate) major: u32,
    /// Secondary hash used to order collisions.
    pub(crate) minor: u32,
}

/// Hash context derived from the superblock seed and HTree root version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryHashContext {
    /// Effective hash seed after applying ext4's all-zero default.
    seed: [u32; 4],
    /// Hash algorithm version selected by the directory root.
    version: DirectoryHashVersion,
}

impl DirectoryHashContext {
    /// Builds a hash context from validated superblock/root metadata.
    pub(crate) fn new(seed: DirectoryHashSeed, version: DirectoryHashVersion) -> Self {
        let words = seed.words();
        let seed = if words.iter().any(|word| *word != 0) {
            words
        } else {
            DEFAULT_HASH_SEED
        };
        Self { seed, version }
    }

    /// Hashes one ext4 name for HTree routing.
    pub(crate) fn hash_name(self, name: &Ext4Name) -> DirectoryHash {
        let bytes = name.bytes();
        let mut hash = match self.version {
            DirectoryHashVersion::Legacy => legacy_hash(bytes, true),
            DirectoryHashVersion::LegacyUnsigned => legacy_hash(bytes, false),
            DirectoryHashVersion::HalfMd4 | DirectoryHashVersion::HalfMd4Unsigned => {
                let mut state = self.seed;
                let signed = self.version.uses_signed_bytes();
                let mut input = bytes;
                while !input.is_empty() {
                    let block = str2hashbuf::<8>(input, signed);
                    half_md4_transform(&mut state, &block);
                    input = input.get(input.len().min(32)..).unwrap_or(&[]);
                }
                DirectoryHash {
                    major: state[1],
                    minor: state[2],
                }
            }
            DirectoryHashVersion::Tea | DirectoryHashVersion::TeaUnsigned => {
                let mut state = self.seed;
                let signed = self.version.uses_signed_bytes();
                let mut input = bytes;
                while !input.is_empty() {
                    let block = str2hashbuf::<4>(input, signed);
                    tea_transform(&mut state, &block);
                    input = input.get(input.len().min(16)..).unwrap_or(&[]);
                }
                DirectoryHash {
                    major: state[0],
                    minor: state[1],
                }
            }
        };
        hash.major &= !1;
        if hash.major == HTREE_EOF_HASH {
            hash.major = HTREE_BEFORE_EOF_HASH;
        }
        hash
    }
}

/// Parses one live directory entry at a fixed offset.
fn parse_live_entry_at(bytes: &[u8], offset: usize) -> Result<DirectoryEntry> {
    let rec_len = usize::from(le_u16(
        bytes,
        offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
    )?);
    if rec_len < DIRENT_HEADER_SIZE
        || offset
            .checked_add(rec_len)
            .ok_or(Error::ArithmeticOverflow)?
            > bytes.len()
    {
        return Err(Error::InvalidDirectoryEntry);
    }
    let inode = le_u32(bytes, offset)?;
    if inode == 0 {
        return Err(Error::InvalidDirectoryEntry);
    }
    let name_len = usize::from(
        *bytes
            .get(offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?)
            .ok_or(Error::InvalidDirectoryEntry)?,
    );
    let payload_len = rec_len
        .checked_sub(DIRENT_HEADER_SIZE)
        .ok_or(Error::InvalidDirectoryEntry)?;
    if name_len > payload_len {
        return Err(Error::InvalidDirectoryEntry);
    }
    let name_start = offset
        .checked_add(DIRENT_HEADER_SIZE)
        .ok_or(Error::ArithmeticOverflow)?;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(Error::ArithmeticOverflow)?;
    Ok(DirectoryEntry {
        inode: InodeId::try_from(inode)?,
        name: Ext4Name::from_disk(
            bytes
                .get(name_start..name_end)
                .ok_or(Error::InvalidDirectoryEntry)?,
        )?,
        kind: DirectoryEntryKind::from_raw(
            *bytes
                .get(offset.checked_add(7).ok_or(Error::ArithmeticOverflow)?)
                .ok_or(Error::InvalidDirectoryEntry)?,
        ),
    })
}

/// Calculates the legacy ext2 directory hash.
fn legacy_hash(bytes: &[u8], signed: bool) -> DirectoryHash {
    let mut hash0 = 0x12a3_fe2d_u32;
    let mut hash1 = 0x37ab_e8f9_u32;
    for byte in bytes {
        let value = hash_byte(*byte, signed);
        let mut hash = hash1.wrapping_add(hash0 ^ value.wrapping_mul(7_152_373));
        if hash & 0x8000_0000 != 0 {
            hash = hash.wrapping_sub(0x7fff_ffff);
        }
        hash1 = hash0;
        hash0 = hash;
    }
    DirectoryHash {
        major: hash0.wrapping_shl(1),
        minor: 0,
    }
}

/// Converts a directory name chunk into the integer buffer consumed by ext4 hash transforms.
fn str2hashbuf<const WORDS: usize>(bytes: &[u8], signed: bool) -> [u32; WORDS] {
    let len = bytes.len();
    let mut pad = u32::try_from(len).unwrap_or(u32::MAX);
    pad |= pad.wrapping_shl(8);
    pad |= pad.wrapping_shl(16);
    let mut value = pad;
    let mut buffer = [0_u32; WORDS];
    let mut written = 0_usize;
    let limit = len.min(WORDS.saturating_mul(4));
    for (index, byte) in bytes.iter().take(limit).enumerate() {
        value = hash_byte(*byte, signed).wrapping_add(value.wrapping_shl(8));
        if index % 4 == 3 {
            if let Some(slot) = buffer.get_mut(written) {
                *slot = value;
            }
            written = written.saturating_add(1);
            value = pad;
        }
    }
    if let Some(slot) = buffer.get_mut(written) {
        *slot = value;
        written = written.saturating_add(1);
    }
    while let Some(slot) = buffer.get_mut(written) {
        *slot = pad;
        written = written.saturating_add(1);
    }
    buffer
}

/// Returns one name byte as the signed or unsigned integer ext4 expects.
fn hash_byte(byte: u8, signed: bool) -> u32 {
    if signed {
        let signed_value = if byte < 128 {
            i32::from(byte)
        } else {
            i32::from(byte).wrapping_sub(256)
        };
        u32::from_ne_bytes(signed_value.to_ne_bytes())
    } else {
        u32::from(byte)
    }
}

/// Applies the ext4 TEA directory hash transform.
fn tea_transform(state: &mut [u32; 4], input: &[u32; 4]) {
    let mut sum = 0_u32;
    let mut b0 = state[0];
    let mut b1 = state[1];
    let [a, b, c, d] = *input;
    for _ in 0..16 {
        sum = sum.wrapping_add(TEA_DELTA);
        b0 = b0.wrapping_add(
            b1.wrapping_shl(4).wrapping_add(a)
                ^ b1.wrapping_add(sum)
                ^ b1.wrapping_shr(5).wrapping_add(b),
        );
        b1 = b1.wrapping_add(
            b0.wrapping_shl(4).wrapping_add(c)
                ^ b0.wrapping_add(sum)
                ^ b0.wrapping_shr(5).wrapping_add(d),
        );
    }
    state[0] = state[0].wrapping_add(b0);
    state[1] = state[1].wrapping_add(b1);
}

/// Applies the ext4 half-MD4 directory hash transform.
fn half_md4_transform(state: &mut [u32; 4], input: &[u32; 8]) -> u32 {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let [x0, x1, x2, x3, x4, x5, x6, x7] = *input;

    md4_round(md4_f, &mut a, b, c, d, x0, 3);
    md4_round(md4_f, &mut d, a, b, c, x1, 7);
    md4_round(md4_f, &mut c, d, a, b, x2, 11);
    md4_round(md4_f, &mut b, c, d, a, x3, 19);
    md4_round(md4_f, &mut a, b, c, d, x4, 3);
    md4_round(md4_f, &mut d, a, b, c, x5, 7);
    md4_round(md4_f, &mut c, d, a, b, x6, 11);
    md4_round(md4_f, &mut b, c, d, a, x7, 19);

    md4_round(md4_g, &mut a, b, c, d, x1.wrapping_add(0x5a82_7999), 3);
    md4_round(md4_g, &mut d, a, b, c, x3.wrapping_add(0x5a82_7999), 5);
    md4_round(md4_g, &mut c, d, a, b, x5.wrapping_add(0x5a82_7999), 9);
    md4_round(md4_g, &mut b, c, d, a, x7.wrapping_add(0x5a82_7999), 13);
    md4_round(md4_g, &mut a, b, c, d, x0.wrapping_add(0x5a82_7999), 3);
    md4_round(md4_g, &mut d, a, b, c, x2.wrapping_add(0x5a82_7999), 5);
    md4_round(md4_g, &mut c, d, a, b, x4.wrapping_add(0x5a82_7999), 9);
    md4_round(md4_g, &mut b, c, d, a, x6.wrapping_add(0x5a82_7999), 13);

    md4_round(md4_h, &mut a, b, c, d, x3.wrapping_add(0x6ed9_eba1), 3);
    md4_round(md4_h, &mut d, a, b, c, x7.wrapping_add(0x6ed9_eba1), 9);
    md4_round(md4_h, &mut c, d, a, b, x2.wrapping_add(0x6ed9_eba1), 11);
    md4_round(md4_h, &mut b, c, d, a, x6.wrapping_add(0x6ed9_eba1), 15);
    md4_round(md4_h, &mut a, b, c, d, x1.wrapping_add(0x6ed9_eba1), 3);
    md4_round(md4_h, &mut d, a, b, c, x5.wrapping_add(0x6ed9_eba1), 9);
    md4_round(md4_h, &mut c, d, a, b, x0.wrapping_add(0x6ed9_eba1), 11);
    md4_round(md4_h, &mut b, c, d, a, x4.wrapping_add(0x6ed9_eba1), 15);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[1]
}

/// Applies one half-MD4 round operation.
fn md4_round(
    function: fn(u32, u32, u32) -> u32,
    value: &mut u32,
    b: u32,
    c: u32,
    d: u32,
    x: u32,
    shift: u32,
) {
    *value = value
        .wrapping_add(function(b, c, d))
        .wrapping_add(x)
        .rotate_left(shift);
}

/// MD4 F function.
fn md4_f(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

/// MD4 G function.
fn md4_g(x: u32, y: u32, z: u32) -> u32 {
    (x & y).wrapping_add((x ^ y) & z)
}

/// MD4 H function.
fn md4_h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// Writes one ext4 directory record into a checked block slice.
fn write_entry(
    bytes: &mut [u8],
    offset: usize,
    inode: InodeId,
    rec_len: u16,
    name: &[u8],
    kind: DirectoryEntryKind,
) -> Result<()> {
    // The record length is owned by the caller so existing free-space shape can
    // be preserved when inserting into a hole or splitting a live entry.
    let rec_len_usize = usize::from(rec_len);
    if rec_len_usize < required_name_rec_len(name.len())?
        || offset
            .checked_add(rec_len_usize)
            .ok_or(Error::ArithmeticOverflow)?
            > bytes.len()
    {
        return Err(Error::InvalidDirectoryEntry);
    }
    put_le_u32(bytes, offset, inode.as_u32())?;
    put_le_u16(
        bytes,
        offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
        rec_len,
    )?;
    *bytes
        .get_mut(offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::InvalidDirectoryEntry)? =
        u8::try_from(name.len()).map_err(|_| Error::InvalidName)?;
    *bytes
        .get_mut(offset.checked_add(7).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::InvalidDirectoryEntry)? = kind.to_raw();
    let name_start = offset
        .checked_add(DIRENT_HEADER_SIZE)
        .ok_or(Error::ArithmeticOverflow)?;
    let name_end = name_start
        .checked_add(name.len())
        .ok_or(Error::ArithmeticOverflow)?;
    bytes
        .get_mut(name_start..name_end)
        .ok_or(Error::InvalidDirectoryEntry)?
        .copy_from_slice(name);
    if name_end
        < offset
            .checked_add(rec_len_usize)
            .ok_or(Error::ArithmeticOverflow)?
    {
        bytes
            .get_mut(
                name_end
                    ..offset
                        .checked_add(rec_len_usize)
                        .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::InvalidDirectoryEntry)?
            .fill(0);
    }
    Ok(())
}

/// Returns the aligned record length required for a name payload.
fn required_name_rec_len(name_len: usize) -> Result<usize> {
    checked_rec_len(
        DIRENT_HEADER_SIZE
            .checked_add(name_len)
            .ok_or(Error::ArithmeticOverflow)?,
    )
}

/// Rounds a directory record length up to the ext4 alignment and `u16` range.
fn checked_rec_len(value: usize) -> Result<usize> {
    let adjusted = value
        .checked_add(
            DIRENT_ALIGNMENT
                .checked_sub(1)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)?;
    let aligned = adjusted
        .checked_div(DIRENT_ALIGNMENT)
        .ok_or(Error::ArithmeticOverflow)?
        .checked_mul(DIRENT_ALIGNMENT)
        .ok_or(Error::ArithmeticOverflow)?;
    if aligned > usize::from(u16::MAX) {
        return Err(Error::InvalidDirectoryEntry);
    }
    Ok(aligned)
}

/// Converts a checked record length into the on-disk `rec_len` field.
fn checked_u16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::InvalidDirectoryEntry)
}

#[cfg(test)]
mod tests {
    use super::{
        DirectoryBlockData, DirectoryChecksum, DirectoryEntry, DirectoryEntryKind,
        DirectoryHashSeed, DirectoryHashVersion, DirectoryLayout, Error, HtreeBuildPlan, Result,
        build_htree_directory,
    };
    use crate::inode::InodeId;
    use crate::name::Ext4Name;

    fn inode(value: u32) -> Result<InodeId> {
        InodeId::try_from(value)
    }

    fn name(index: usize, len: usize) -> Result<Ext4Name> {
        let mut bytes = alloc::vec![b'x'; len];
        let mut value = index;
        let suffix_len = len.min(8);
        for slot in bytes.iter_mut().rev().take(suffix_len) {
            let digit = u8::try_from(value.checked_rem(26).ok_or(Error::ArithmeticOverflow)?)
                .map_err(|_| Error::ArithmeticOverflow)?;
            *slot = b'a'.checked_add(digit).ok_or(Error::ArithmeticOverflow)?;
            value = value.checked_div(26).ok_or(Error::ArithmeticOverflow)?;
        }
        Ext4Name::new(&bytes)
    }

    fn entries(count: usize, name_len: usize) -> Result<alloc::vec::Vec<DirectoryEntry>> {
        let mut entries = alloc::vec::Vec::new();
        for index in 0..count {
            let inode_number =
                u32::try_from(index.checked_add(11).ok_or(Error::ArithmeticOverflow)?)
                    .map_err(|_| Error::ArithmeticOverflow)?;
            entries.push(DirectoryEntry::new(
                inode(inode_number)?,
                &name(index, name_len)?,
                DirectoryEntryKind::File,
            ));
        }
        Ok(entries)
    }

    #[test]
    fn htree_builder_serializes_depth_one_index_nodes() -> Result<()> {
        let children = entries(600, 255)?;
        let image = build_htree_directory(
            inode(2)?,
            inode(2)?,
            &children,
            1024,
            DirectoryHashSeed::from_words([0; 4]),
            DirectoryHashVersion::Legacy,
            DirectoryChecksum::None,
        )?;
        let mut blocks = alloc::vec::Vec::new();
        for (logical, bytes) in image.blocks().iter().enumerate() {
            blocks.push(DirectoryBlockData::new(
                u32::try_from(logical).map_err(|_| Error::ArithmeticOverflow)?,
                bytes.clone(),
            ));
        }
        let layout = DirectoryLayout::parse(
            true,
            blocks,
            DirectoryHashSeed::from_words([0; 4]),
            DirectoryHashVersion::Legacy,
            DirectoryChecksum::None,
        )?;

        if *image
            .blocks()
            .first()
            .and_then(|block| block.get(30))
            .ok_or(Error::InvalidDirectoryEntry)?
            != 1
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        if layout.entries().len()
            != children
                .len()
                .checked_add(2)
                .ok_or(Error::ArithmeticOverflow)?
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        Ok(())
    }

    #[test]
    fn htree_build_plan_grows_root_to_depth_two() -> Result<()> {
        let leaves = alloc::vec![
            super::PackedLeaf {
                start_hash: 0,
                last_hash: 0,
                entries: alloc::vec![]
            };
            181
        ];
        let plan = HtreeBuildPlan::new(&leaves, 12, 15)?;

        if plan.depth != 2 || plan.block_count()? != 196 {
            return Err(Error::InvalidDirectoryEntry);
        }
        Ok(())
    }
}
