//! Directory entry parsing and directory layout validation.

use alloc::vec::Vec;

use crate::disk::checksum::ext4_crc32c;
use crate::disk::endian::{DiskOffset, le_u16, le_u32, put_le_u16, put_le_u32};
use crate::disk_format::inode::{DirectoryStorageKind, InodeId};
use crate::disk_format::superblock::{
    ChecksumSeed, DirectoryHashByteInterpretation, DirectoryHashSeed, DirectoryHashVersion,
};
use crate::error::{Error, Result};
use crate::memory::{self, FallibleVec};
use crate::platform::name::Ext4Name;

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

/// Builds a directory-block field offset.
const fn disk_offset(offset: usize) -> DiskOffset {
    DiskOffset::new(offset)
}
/// Maximum HTree indirect depth accepted while `largedir` remains unsupported.
const DX_MAX_DEPTH_WITHOUT_LARGEDIR: u8 = 2;

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
    /// # Errors
    ///
    /// Returns an error when copying the raw directory name bytes cannot allocate.
    pub(crate) fn new(inode: InodeId, name: &Ext4Name, kind: DirectoryEntryKind) -> Result<Self> {
        Ok(Self {
            inode,
            name: Ext4Name::from_disk(name.bytes())?,
            kind,
        })
    }

    /// Copies this directory entry without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the raw directory name bytes cannot allocate.
    pub(crate) fn try_clone(&self) -> Result<Self> {
        Self::new(self.inode, &self.name, self.kind)
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

            let inode = le_u32(bytes, disk_offset(offset))?;
            let rec_len = usize::from(le_u16(bytes, disk_offset(offset).checked_add_bytes(4)?)?);
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
                entries.try_push(Self {
                    inode: InodeId::try_from(inode)?,
                    name: Ext4Name::from_disk(
                        bytes
                            .get(name_start..name_end)
                            .ok_or(Error::InvalidDirectoryEntry)?,
                    )?,
                    kind: DirectoryEntryKind::from_raw(file_type),
                })?;
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

    /// Consumes this entry into its validated components without copying its owned name.
    #[must_use]
    pub(crate) fn into_parts(self) -> (InodeId, Ext4Name, DirectoryEntryKind) {
        (self.inode, self.name, self.kind)
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
    /// Parses a directory file into the storage shape selected by the inode.
    /// # Errors
    ///
    /// Returns an error when the selected storage shape cannot parse the supplied directory blocks.
    pub(crate) fn from_storage_kind(
        storage: DirectoryStorageKind,
        blocks: Vec<DirectoryBlockData>,
        hash_seed: DirectoryHashSeed,
        default_hash_version: DirectoryHashVersion,
        checksum: DirectoryChecksum,
    ) -> Result<Self> {
        match storage {
            DirectoryStorageKind::Linear => Ok(Self::Linear(LinearDirectory::parse(blocks)?)),
            DirectoryStorageKind::HTree => Ok(Self::HTree(HtreeDirectory::parse(
                &blocks,
                hash_seed,
                default_hash_version,
                checksum,
            )?)),
        }
    }

    /// Returns all live entries in directory traversal order.
    /// # Errors
    ///
    /// Returns an error when cloning the live entries cannot allocate.
    pub(crate) fn entries(&self) -> Result<Vec<DirectoryEntry>> {
        match self {
            Self::Linear(directory) => directory.entries(),
            Self::HTree(directory) => directory.entries(),
        }
    }

    /// Finds one exact ext4 child name.
    /// # Errors
    ///
    /// Returns an error when cloning the matched directory entry cannot allocate.
    pub(crate) fn find(&self, name: &Ext4Name) -> Result<Option<DirectoryEntry>> {
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
    /// # Errors
    ///
    /// Returns an error when any block contains a malformed linear dirent stream.
    fn parse(blocks: Vec<DirectoryBlockData>) -> Result<Self> {
        let mut entries = Vec::new();
        for block in blocks {
            let block_entries = DirectoryEntry::parse_all(block.bytes())?;
            entries
                .try_reserve_exact(block_entries.len())
                .map_err(|_| Error::OutOfMemory)?;
            for entry in block_entries {
                entries.try_push(entry)?;
            }
        }
        Ok(Self { entries })
    }

    /// Returns all live entries in physical order.
    /// # Errors
    ///
    /// Returns an error when cloning the live entries cannot allocate.
    fn entries(&self) -> Result<Vec<DirectoryEntry>> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.entries.len())
            .map_err(|_| Error::OutOfMemory)?;
        for entry in &self.entries {
            entries.try_push(entry.try_clone()?)?;
        }
        Ok(entries)
    }

    /// Finds one exact ext4 name.
    /// # Errors
    ///
    /// Returns an error when cloning the matched directory entry cannot allocate.
    fn find(&self, name: &Ext4Name) -> Result<Option<DirectoryEntry>> {
        self.entries
            .iter()
            .find(|entry| entry.name() == name)
            .map(DirectoryEntry::try_clone)
            .transpose()
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
        let mut seed = ext4_crc32c(checksum_seed.as_u32(), &inode_id.as_u32().to_le_bytes());
        seed = ext4_crc32c(seed, &generation.to_le_bytes());
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
    /// # Errors
    ///
    /// Returns an error when the tail offset is outside the block or the tail fields cannot be
    /// encoded.
    fn write_dirent_tail(self, bytes: &mut [u8], tail_offset: usize) -> Result<()> {
        let Self::Crc32c { inode_seed } = self else {
            return Ok(());
        };
        put_le_u32(bytes, disk_offset(tail_offset), 0)?;
        put_le_u16(
            bytes,
            disk_offset(tail_offset).checked_add_bytes(4)?,
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
            disk_offset(tail_offset).checked_add_bytes(8)?,
            ext4_crc32c(
                inode_seed,
                bytes
                    .get(..tail_offset)
                    .ok_or(Error::InvalidDirectoryEntry)?,
            ),
        )
    }

    /// Verifies a leaf checksum tail when enabled.
    /// # Errors
    ///
    /// Returns an error when the block is too small, the tail fields are invalid, or the CRC32C
    /// value does not match the live dirent bytes.
    fn verify_dirent_tail(self, bytes: &[u8]) -> Result<()> {
        let Self::Crc32c { inode_seed } = self else {
            return Ok(());
        };
        let tail_offset = bytes
            .len()
            .checked_sub(DIRENT_TAIL_BYTES)
            .ok_or(Error::InvalidDirectoryEntry)?;
        if le_u32(bytes, disk_offset(tail_offset))? != 0
            || usize::from(le_u16(
                bytes,
                disk_offset(tail_offset).checked_add_bytes(4)?,
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
        let expected = ext4_crc32c(
            inode_seed,
            bytes
                .get(..tail_offset)
                .ok_or(Error::InvalidDirectoryEntry)?,
        );
        let actual = le_u32(bytes, disk_offset(tail_offset).checked_add_bytes(8)?)?;
        if actual != expected {
            return Err(Error::ChecksumMismatch);
        }
        Ok(())
    }

    /// Writes and checksums an HTree dx tail when enabled.
    /// # Errors
    ///
    /// Returns an error when the dx table geometry overflows or the checksum tail would fall outside
    /// the block.
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
        put_le_u32(bytes, disk_offset(tail_offset), 0)?;
        put_le_u32(bytes, disk_offset(checksum_offset), 0)?;
        let table_end = count_offset
            .checked_add(
                count
                    .checked_mul(DX_ENTRY_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let mut checksum = ext4_crc32c(
            inode_seed,
            bytes.get(..table_end).ok_or(Error::InvalidDirectoryEntry)?,
        );
        checksum = ext4_crc32c(
            checksum,
            bytes
                .get(tail_offset..checksum_offset)
                .ok_or(Error::InvalidDirectoryEntry)?,
        );
        checksum = ext4_crc32c(checksum, &0_u32.to_le_bytes());
        put_le_u32(bytes, disk_offset(checksum_offset), checksum)
    }

    /// Verifies an HTree dx tail when enabled.
    /// # Errors
    ///
    /// Returns an error when the dx tail is outside the block, the reserved field is nonzero, or the
    /// stored CRC32C does not match the index bytes.
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
        if le_u32(bytes, disk_offset(tail_offset))? != 0 {
            return Err(Error::InvalidDirectoryEntry);
        }
        let table_end = count_offset
            .checked_add(
                count
                    .checked_mul(DX_ENTRY_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let mut checksum = ext4_crc32c(
            inode_seed,
            bytes.get(..table_end).ok_or(Error::InvalidDirectoryEntry)?,
        );
        checksum = ext4_crc32c(
            checksum,
            bytes
                .get(tail_offset..checksum_offset)
                .ok_or(Error::InvalidDirectoryEntry)?,
        );
        checksum = ext4_crc32c(checksum, &0_u32.to_le_bytes());
        if le_u32(bytes, disk_offset(checksum_offset))? != checksum {
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
/// # Errors
///
/// Returns an error when the block size cannot hold an HTree root, leaf packing exceeds supported
/// limits, logical block planning overflows, or block serialization fails.
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
    let hash = DirectoryHashScheme::from_metadata(hash_seed, hash_version);
    let mut hashed = Vec::new();
    for entry in children {
        let name = entry.name().bytes();
        if name == b"." || name == b".." {
            continue;
        }
        hashed.try_push(HashedDirectoryEntry {
            hash: hash.hash(entry.name()),
            entry: entry.try_clone()?,
        })?;
    }
    memory::heap_sort_by(&mut hashed, |left, right| {
        left.hash
            .major
            .cmp(&right.hash.major)
            .then(left.hash.minor.cmp(&right.hash.minor))
            .then(left.entry.name().bytes().cmp(right.entry.name().bytes()))
    })?;

    let leaves = pack_htree_leaves(hashed, block_size, checksum)?;
    let root_limit = dx_capacity(block_size, DX_ROOT_COUNT_OFFSET, checksum)?;
    let node_limit = dx_capacity(block_size, DX_NODE_COUNT_OFFSET, checksum)?;
    let plan = HtreeBuildPlan::new(&leaves, root_limit, node_limit)?;
    let block_count = plan.block_count()?;
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(block_count)
        .map_err(|_| Error::OutOfMemory)?;
    for _ in 0..block_count {
        blocks.try_push(memory::repeated_vec(0_u8, block_size)?)?;
    }

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
/// # Errors
///
/// Returns an error when the usable leaf area is too small, an entry cannot fit in one leaf, or leaf
/// size accounting overflows.
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
            leaves.try_push(PackedLeaf {
                start_hash: current_start,
                last_hash: current_last,
                entries: current,
            })?;
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
        current.try_push(item.entry)?;
    }

    if current.is_empty() {
        leaves.try_push(PackedLeaf {
            start_hash: 0,
            last_hash: 0,
            entries: Vec::new(),
        })?;
    } else {
        leaves.try_push(PackedLeaf {
            start_hash: current_start,
            last_hash: current_last,
            entries: current,
        })?;
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
    /// # Errors
    ///
    /// Returns an error when the root or node fan-out is zero, arithmetic overflows, or more than two
    /// indirect levels would be required.
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
    /// # Errors
    ///
    /// Returns an error when summing the root, index, and leaf block counts overflows.
    fn block_count(&self) -> Result<usize> {
        checked_sum_usize(&[1, self.upper_nodes, self.lower_nodes, self.leaf_count])
    }

    /// Returns the logical block number for one leaf index.
    /// # Errors
    ///
    /// Returns an error when the leaf index is outside the plan or the logical block number cannot
    /// be represented on disk.
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
    /// # Errors
    ///
    /// Returns an error when the lower-node logical block number overflows `u32`.
    fn lower_node_logical(&self, lower: usize) -> Result<u32> {
        usize_to_u32(checked_sum_usize(&[1, self.upper_nodes, lower])?)
    }

    /// Returns the logical block number for an upper index node.
    /// # Errors
    ///
    /// Returns an error when the upper-node logical block number overflows `u32`.
    fn upper_node_logical(&self, upper: usize) -> Result<u32> {
        usize_to_u32(checked_sum_usize(&[1, upper])?)
    }

    /// Returns all index nodes that must be serialized.
    /// # Errors
    ///
    /// Returns an error when node fan-out arithmetic overflows or a planned node cannot be tied to a
    /// leaf start hash.
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
                entries.try_push(DxEntry {
                    hash: leaf.start_hash,
                    block: self.leaf_logical(leaf_index)?,
                })?;
            }
            let logical = self.lower_node_logical(lower)?;
            nodes.try_push(PlannedIndexNode { logical, entries })?;
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
                    entries.try_push(DxEntry {
                        hash: leaves
                            .get(first_leaf)
                            .ok_or(Error::InvalidDirectoryEntry)?
                            .start_hash,
                        block: self.lower_node_logical(lower)?,
                    })?;
                }
                nodes.try_push(PlannedIndexNode {
                    logical: self.upper_node_logical(upper)?,
                    entries,
                })?;
            }
        }
        Ok(nodes)
    }

    /// Returns root index entries.
    /// # Errors
    ///
    /// Returns an error when root routing arithmetic overflows, a planned leaf is missing, or the
    /// stored depth exceeds the supported HTree profile.
    fn root_entries(&self, leaves: &[PackedLeaf]) -> Result<Vec<DxEntry>> {
        let mut entries = Vec::new();
        match self.depth {
            0 => {
                for (index, leaf) in leaves.iter().enumerate().take(self.root_count) {
                    entries.try_push(DxEntry {
                        hash: leaf.start_hash,
                        block: self.leaf_logical(index)?,
                    })?;
                }
            }
            1 => {
                for lower in 0..self.root_count {
                    let first_leaf = lower
                        .checked_mul(self.node_limit)
                        .ok_or(Error::ArithmeticOverflow)?;
                    entries.try_push(DxEntry {
                        hash: leaves
                            .get(first_leaf)
                            .ok_or(Error::InvalidDirectoryEntry)?
                            .start_hash,
                        block: usize_to_u32(checked_sum_usize(&[1, lower])?)?,
                    })?;
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
                    entries.try_push(DxEntry {
                        hash: leaves
                            .get(first_leaf)
                            .ok_or(Error::InvalidDirectoryEntry)?
                            .start_hash,
                        block: self.upper_node_logical(upper)?,
                    })?;
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
/// # Errors
///
/// Returns an error when the block cannot hold the count/limit field and at least one dx entry.
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
/// # Errors
///
/// Returns an error when the leaf's dirent area is invalid, record lengths overflow, an entry cannot
/// be written, or the checksum tail cannot be serialized.
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
        put_le_u16(bytes, disk_offset(4), checked_u16(live_limit)?)?;
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
/// # Errors
///
/// Returns an error when the block length or dx table cannot be represented in ext4 fields.
fn write_index_node(
    bytes: &mut [u8],
    entries: &[DxEntry],
    checksum: DirectoryChecksum,
) -> Result<()> {
    bytes.fill(0);
    put_le_u16(bytes, disk_offset(4), checked_u16(bytes.len())?)?;
    write_dx_table(bytes, DX_NODE_COUNT_OFFSET, entries, checksum)
}

/// Serializes the HTree root block.
/// # Errors
///
/// Returns an error when dot entries, root metadata fields, or the root dx table cannot be written
/// into the supplied block.
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
    put_le_u32(bytes, disk_offset(DX_ROOT_INFO_OFFSET), 0)?;
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
/// # Errors
///
/// Returns an error when the table capacity is invalid, the entry count is zero or exceeds capacity,
/// an offset overflows, or the checksum tail cannot be written.
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
    put_le_u16(bytes, disk_offset(count_offset), checked_u16(limit)?)?;
    put_le_u16(
        bytes,
        disk_offset(count_offset).checked_add_bytes(2)?,
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
            put_le_u32(bytes, disk_offset(offset), entry.hash)?;
        }
        put_le_u32(
            bytes,
            disk_offset(offset).checked_add_bytes(4)?,
            entry.block & DX_BLOCK_MASK,
        )?;
    }
    checksum.write_dx_tail(bytes, count_offset, entries.len(), limit)
}

/// Integer ceil division for HTree fan-out planning.
/// # Errors
///
/// Returns an error when the divisor is zero or the rounded addition overflows.
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
/// # Errors
///
/// Returns an error when the accumulated sum exceeds `usize`.
fn checked_sum_usize(values: &[usize]) -> Result<usize> {
    let mut sum = 0_usize;
    for value in values {
        sum = sum.checked_add(*value).ok_or(Error::ArithmeticOverflow)?;
    }
    Ok(sum)
}

/// Converts a usize logical block value into the on-disk u32 range.
/// # Errors
///
/// Returns an error when the logical block number exceeds the on-disk `u32` field.
fn usize_to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::ArithmeticOverflow)
}

/// HTree directory represented as dot entries plus indexed leaf blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HtreeDirectory {
    /// Directory hash context selected by the root info.
    hash: DirectoryHashScheme,
    /// `.` and `..` entries stored in the root block.
    dot_entries: Vec<DirectoryEntry>,
    /// Leaf blocks in index traversal order.
    leaves: Vec<HtreeLeaf>,
}

impl HtreeDirectory {
    /// Parses an HTree directory from logical directory blocks.
    /// # Errors
    ///
    /// Returns an error when the root block is missing or any referenced index or leaf block is
    /// malformed.
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
            leaves.try_push(HtreeLeaf::parse(
                indexed_leaf.start_hash,
                block.bytes(),
                checksum,
            )?)?;
        }
        Ok(Self {
            hash: root.hash,
            dot_entries: root.dot_entries,
            leaves,
        })
    }

    /// Returns all live entries in HTree traversal order.
    /// # Errors
    ///
    /// Returns an error when cloning the live entries cannot allocate.
    fn entries(&self) -> Result<Vec<DirectoryEntry>> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.dot_entries.len())
            .map_err(|_| Error::OutOfMemory)?;
        for entry in &self.dot_entries {
            entries.try_push(entry.try_clone()?)?;
        }
        for leaf in &self.leaves {
            entries
                .try_reserve_exact(leaf.entries.len())
                .map_err(|_| Error::OutOfMemory)?;
            for entry in &leaf.entries {
                entries.try_push(entry.try_clone()?)?;
            }
        }
        Ok(entries)
    }

    /// Finds an exact ext4 name through the hash-selected leaf chain.
    /// # Errors
    ///
    /// Returns an error when cloning the matched directory entry cannot allocate.
    fn find(&self, name: &Ext4Name) -> Result<Option<DirectoryEntry>> {
        let hash = self.hash.hash(name).major;
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
            if let Some(entry) = leaf.find(name)? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
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
    /// # Errors
    ///
    /// Returns an error when the leaf checksum tail is invalid or the leaf dirent stream is
    /// malformed.
    fn parse(start_hash: u32, bytes: &[u8], checksum: DirectoryChecksum) -> Result<Self> {
        checksum.verify_dirent_tail(bytes)?;
        Ok(Self {
            start_hash,
            entries: DirectoryEntry::parse_all(bytes)?,
        })
    }

    /// Finds one exact ext4 name in this leaf.
    /// # Errors
    ///
    /// Returns an error when cloning the matched directory entry cannot allocate.
    fn find(&self, name: &Ext4Name) -> Result<Option<DirectoryEntry>> {
        self.entries
            .iter()
            .find(|entry| entry.name() == name)
            .map(DirectoryEntry::try_clone)
            .transpose()
    }
}

/// Parsed HTree root block.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HtreeRoot {
    /// Directory hash context selected by root info.
    hash: DirectoryHashScheme,
    /// `.` and `..` entries stored before the root info.
    dot_entries: Vec<DirectoryEntry>,
    /// Number of index levels between root entries and leaf blocks.
    indirect_levels: u8,
    /// Root index table.
    index: DxIndex,
}

impl HtreeRoot {
    /// Parses and validates an HTree root block.
    /// # Errors
    ///
    /// Returns an error when the root is too small, lacks valid `.`/`..` entries, carries
    /// unsupported hash metadata, or has an invalid root index.
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
        if le_u32(bytes, disk_offset(DX_ROOT_INFO_OFFSET))? != 0 {
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
            hash: DirectoryHashScheme::from_metadata(hash_seed, hash_version),
            dot_entries: {
                let mut dot_entries = Vec::new();
                dot_entries.try_push(dot)?;
                dot_entries.try_push(dotdot)?;
                dot_entries
            },
            indirect_levels,
            index,
        })
    }

    /// Resolves all leaf logical blocks in index traversal order.
    /// # Errors
    ///
    /// Returns an error when any root entry points at a missing, cyclic, or malformed index block.
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
    /// # Errors
    ///
    /// Returns an error when count/limit fields are inconsistent, the table extends outside the
    /// block, a child pointer is zero, or the dx tail checksum is invalid.
    fn parse(bytes: &[u8], count_offset: usize, checksum: DirectoryChecksum) -> Result<Self> {
        let limit = usize::from(le_u16(bytes, disk_offset(count_offset))?);
        let count = usize::from(le_u16(
            bytes,
            disk_offset(count_offset).checked_add_bytes(2)?,
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
                le_u32(bytes, disk_offset(entry_offset))?
            };
            let block =
                le_u32(bytes, disk_offset(entry_offset).checked_add_bytes(4)?)? & DX_BLOCK_MASK;
            if block == 0 {
                return Err(Error::InvalidDirectoryEntry);
            }
            entries.try_push(DxEntry { hash, block })?;
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
/// # Errors
///
/// Returns an error when traversal detects a cycle, an index node is missing, or a nested dx table
/// is malformed.
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
    visited.try_push(logical)?;
    if depth == 0 {
        leaves.try_push(IndexedLeafBlock {
            start_hash,
            logical,
        })?;
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
/// # Errors
///
/// Returns an error when no supplied block has the requested logical block number.
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
    /// # Errors
    ///
    /// Returns an error when allocating the block-sized byte buffer fails.
    pub(crate) fn empty(block_size: usize) -> Result<Self> {
        Ok(Self {
            bytes: memory::repeated_vec(0_u8, block_size)?,
        })
    }

    /// Returns the mutated directory block bytes.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Initializes `.` and `..`, leaving the second entry to own remaining space.
    /// # Errors
    ///
    /// Returns an error when the block cannot hold both dot entries or either entry cannot be
    /// encoded in the available record space.
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
    /// # Errors
    ///
    /// Returns an error when the block length cannot be represented as an ext4 `rec_len`.
    pub(crate) fn initialize_free_space(&mut self) -> Result<()> {
        let rec_len = checked_u16(self.bytes.len())?;
        self.bytes.fill(0);
        put_le_u16(&mut self.bytes, disk_offset(4), rec_len)
    }

    /// Parses live entries from the current block image.
    /// # Errors
    ///
    /// Returns an error when the current block image is not a valid ext4 dirent stream.
    pub(crate) fn entries(&self) -> Result<Vec<DirectoryEntry>> {
        DirectoryEntry::parse_all(&self.bytes)
    }

    /// Checks whether a live entry already owns `name`.
    /// # Errors
    ///
    /// Returns an error when the current block cannot be parsed before the lookup.
    pub(crate) fn contains_name(&self, name: &Ext4Name) -> Result<bool> {
        for entry in self.entries()? {
            if entry.name() == name {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Inserts a live entry by reusing free space or splitting an oversized record.
    /// # Errors
    ///
    /// Returns an error when the name already exists, record accounting overflows, an existing
    /// dirent is malformed, or the new entry cannot be encoded.
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
                disk_offset(offset).checked_add_bytes(4)?,
            )?);
            if rec_len < DIRENT_HEADER_SIZE
                || offset
                    .checked_add(rec_len)
                    .ok_or(Error::ArithmeticOverflow)?
                    > self.bytes.len()
            {
                return Err(Error::InvalidDirectoryEntry);
            }
            let live_inode = le_u32(&self.bytes, disk_offset(offset))?;
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
                    disk_offset(offset).checked_add_bytes(4)?,
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
    /// # Errors
    ///
    /// Returns an error when a scanned dirent is malformed or the removed entry's inode/name cannot
    /// be converted back into domain types.
    pub(crate) fn remove(&mut self, name: &Ext4Name) -> Result<Option<DirectoryEntry>> {
        let mut offset = 0_usize;
        while offset < self.bytes.len() {
            let rec_len = usize::from(le_u16(
                &self.bytes,
                disk_offset(offset).checked_add_bytes(4)?,
            )?);
            if rec_len < DIRENT_HEADER_SIZE
                || offset
                    .checked_add(rec_len)
                    .ok_or(Error::ArithmeticOverflow)?
                    > self.bytes.len()
            {
                return Err(Error::InvalidDirectoryEntry);
            }
            let inode = le_u32(&self.bytes, disk_offset(offset))?;
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
                put_le_u32(&mut self.bytes, disk_offset(offset), 0)?;
                return Ok(Some(removed));
            }
            offset = offset
                .checked_add(rec_len)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(None)
    }

    /// Renames a live entry inside this directory block.
    /// # Errors
    ///
    /// Returns an error when the target name already exists, the source block is malformed, or the
    /// renamed entry no longer fits after removal.
    pub(crate) fn rename(
        &mut self,
        old_name: &Ext4Name,
        new_name: &Ext4Name,
    ) -> Result<Option<DirectoryEntry>> {
        if self.contains_name(new_name)? {
            return Err(Error::NameAlreadyExists);
        }

        let original = memory::copied_slice(&self.bytes)?;
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
    /// # Errors
    ///
    /// Returns an error when a scanned dirent is malformed, the previous entry cannot be decoded, or
    /// the replacement entry cannot be written in place.
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
                disk_offset(offset).checked_add_bytes(4)?,
            )?);
            if rec_len < DIRENT_HEADER_SIZE
                || offset
                    .checked_add(rec_len)
                    .ok_or(Error::ArithmeticOverflow)?
                    > self.bytes.len()
            {
                return Err(Error::InvalidDirectoryEntry);
            }
            let live_inode = le_u32(&self.bytes, disk_offset(offset))?;
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

/// Parses one live directory entry at a fixed offset.
/// # Errors
///
/// Returns an error when the record length, inode, name length, name bytes, or file-type byte is not
/// a valid live ext4 dirent at `offset`.
fn parse_live_entry_at(bytes: &[u8], offset: usize) -> Result<DirectoryEntry> {
    let rec_len = usize::from(le_u16(bytes, disk_offset(offset).checked_add_bytes(4)?)?);
    if rec_len < DIRENT_HEADER_SIZE
        || offset
            .checked_add(rec_len)
            .ok_or(Error::ArithmeticOverflow)?
            > bytes.len()
    {
        return Err(Error::InvalidDirectoryEntry);
    }
    let inode = le_u32(bytes, disk_offset(offset))?;
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

/// Writes one ext4 directory record into a checked block slice.
/// # Errors
///
/// Returns an error when `rec_len` cannot hold the name payload, the record would exceed the block,
/// the name length is not representable, or any field write is out of range.
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
    put_le_u32(bytes, disk_offset(offset), inode.as_u32())?;
    put_le_u16(bytes, disk_offset(offset).checked_add_bytes(4)?, rec_len)?;
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
    memory::copy_exact(
        bytes
            .get_mut(name_start..name_end)
            .ok_or(Error::InvalidDirectoryEntry)?,
        name,
    )?;
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
/// # Errors
///
/// Returns an error when adding the dirent header to the name length overflows or the aligned length
/// cannot be represented by ext4.
fn required_name_rec_len(name_len: usize) -> Result<usize> {
    checked_rec_len(
        DIRENT_HEADER_SIZE
            .checked_add(name_len)
            .ok_or(Error::ArithmeticOverflow)?,
    )
}

/// Rounds a directory record length up to the ext4 alignment and `u16` range.
/// # Errors
///
/// Returns an error when alignment arithmetic overflows or the aligned value exceeds `u16::MAX`.
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
/// # Errors
///
/// Returns an error when the record length cannot be represented as an ext4 `u16` field.
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
    use crate::disk_format::inode::{DirectoryStorageKind, InodeId};
    use crate::platform::name::Ext4Name;

    /// Builds a test inode id.
    /// # Errors
    ///
    /// Returns an error when `value` is outside the inode-id domain.
    fn inode(value: u32) -> Result<InodeId> {
        InodeId::try_from(value)
    }

    /// Builds a deterministic test ext4 name.
    /// # Errors
    ///
    /// Returns an error when suffix arithmetic overflows or the generated bytes are not a valid
    /// ext4 name.
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

    /// Builds deterministic directory entries for HTree tests.
    /// # Errors
    ///
    /// Returns an error when inode numbering, name generation, or entry construction fails.
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
            )?);
        }
        Ok(entries)
    }

    #[test]
    /// # Errors
    ///
    /// Returns an error when HTree serialization or validation of the generated image fails.
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
        let layout = DirectoryLayout::from_storage_kind(
            DirectoryStorageKind::HTree,
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
        if layout.entries()?.len()
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
    /// # Errors
    ///
    /// Returns an error when the depth-two HTree plan cannot be built or has unexpected geometry.
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

use core::array;

/// Seed prescribed by the ext4 format when every stored seed word is zero.
const FORMAT_DEFAULT_SEED: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
/// Primary value reserved by the HTree format for the end marker.
const END_MARKER_HASH: u32 = 0xffff_fffe;
/// Greatest primary value available to an ordinary directory name.
const LAST_NAME_HASH: u32 = 0xffff_fffc;
/// Number of bytes consumed by one half-MD4 compression step.
const HALF_MD4_INPUT_BYTES: usize = 32;
/// Number of bytes consumed by one TEA compression step.
const TEA_INPUT_BYTES: usize = 16;
/// Additive increment applied by each TEA round.
const TEA_ROUND_INCREMENT: u32 = 0x9e37_79b9;
/// Update order shared by each eight-step half-MD4 round.
const LANE_UPDATE_ORDER: [Lane; 8] = [
    Lane::A,
    Lane::D,
    Lane::C,
    Lane::B,
    Lane::A,
    Lane::D,
    Lane::C,
    Lane::B,
];

/// Hash pair consumed by HTree routing and collision ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DirectoryHash {
    /// Primary HTree routing value.
    pub(crate) major: u32,
    /// Secondary value used to order primary-hash collisions.
    pub(crate) minor: u32,
}

impl DirectoryHash {
    /// Converts an algorithm result into the HTree name-key domain.
    const fn from_algorithm(major: u32, minor: u32) -> Self {
        let major = major & !1;
        let major = if major == END_MARKER_HASH {
            LAST_NAME_HASH
        } else {
            major
        };
        Self { major, minor }
    }
}

/// Immutable hash scheme selected by validated superblock and HTree-root metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryHashScheme {
    /// Effective seed after applying the format-defined zero-seed rule.
    seed: HashState,
    /// Algorithm and byte interpretation selected by the root version.
    version: DirectoryHashVersion,
}

impl DirectoryHashScheme {
    /// Builds the scheme selected by validated on-disk metadata.
    #[must_use]
    pub(crate) fn from_metadata(seed: DirectoryHashSeed, version: DirectoryHashVersion) -> Self {
        let words = seed.words();
        let effective = if words.iter().any(|word| *word != 0) {
            words
        } else {
            FORMAT_DEFAULT_SEED
        };
        Self {
            seed: HashState::from_words(effective),
            version,
        }
    }

    /// Produces the normalized HTree key for one validated ext4 name.
    #[must_use]
    pub(crate) fn hash(self, name: &Ext4Name) -> DirectoryHash {
        let (major, minor) = match self.version {
            DirectoryHashVersion::Legacy => rolling_hash(name.bytes(), NameByteEncoding::Signed),
            DirectoryHashVersion::LegacyUnsigned => {
                rolling_hash(name.bytes(), NameByteEncoding::Unsigned)
            }
            DirectoryHashVersion::HalfMd4 => {
                self.hash_with_half_md4(name.bytes(), NameByteEncoding::Signed)
            }
            DirectoryHashVersion::HalfMd4Unsigned => {
                self.hash_with_half_md4(name.bytes(), NameByteEncoding::Unsigned)
            }
            DirectoryHashVersion::Tea => self.hash_with_tea(name.bytes(), NameByteEncoding::Signed),
            DirectoryHashVersion::TeaUnsigned => {
                self.hash_with_tea(name.bytes(), NameByteEncoding::Unsigned)
            }
        };
        DirectoryHash::from_algorithm(major, minor)
    }

    /// Compresses the full name in 32-byte half-MD4 input blocks.
    fn hash_with_half_md4(self, bytes: &[u8], encoding: NameByteEncoding) -> (u32, u32) {
        let mut state = self.seed;
        let mut start = 0_usize;
        while start < bytes.len() {
            let block = NameWordBlock::<8>::at(bytes, start, encoding);
            state.compress_half_md4(block);
            start = start.saturating_add(HALF_MD4_INPUT_BYTES);
        }
        (state.b, state.c)
    }

    /// Compresses the full name in 16-byte TEA input blocks.
    fn hash_with_tea(self, bytes: &[u8], encoding: NameByteEncoding) -> (u32, u32) {
        let mut state = self.seed;
        let mut start = 0_usize;
        while start < bytes.len() {
            let block = NameWordBlock::<4>::at(bytes, start, encoding);
            state.compress_tea(block);
            start = start.saturating_add(TEA_INPUT_BYTES);
        }
        (state.a, state.b)
    }
}

/// Signedness assigned to name bytes by an on-disk hash version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NameByteEncoding {
    /// Sign-extend each byte before incorporating it.
    Signed,
    /// Zero-extend each byte before incorporating it.
    Unsigned,
}

impl NameByteEncoding {
    /// Converts one raw name byte into the algorithm's 32-bit arithmetic domain.
    fn value(self, byte: u8) -> u32 {
        match self {
            Self::Signed => {
                let signed = i8::from_ne_bytes([byte]);
                u32::from_ne_bytes(i32::from(signed).to_ne_bytes())
            }
            Self::Unsigned => u32::from(byte),
        }
    }
}

/// Fixed-width words derived from the remaining name length and current input block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NameWordBlock<const WORDS: usize> {
    /// Words presented to the selected compression function.
    words: [u32; WORDS],
}

impl<const WORDS: usize> NameWordBlock<WORDS> {
    /// Encodes one block beginning at `start`, padding it with the remaining byte count.
    fn at(bytes: &[u8], start: usize, encoding: NameByteEncoding) -> Self {
        let remaining = bytes.len().saturating_sub(start);
        let remaining_word = u32::try_from(remaining).unwrap_or(u32::MAX);
        let padding = remaining_word.wrapping_mul(0x0101_0101);
        let block_limit = remaining.min(WORDS.saturating_mul(4));
        let words = array::from_fn(|word_index| {
            let word_start = word_index.saturating_mul(4);
            if word_start >= block_limit {
                return padding;
            }
            let mut value = padding;
            for byte_in_word in 0..4_usize {
                let relative = word_start.saturating_add(byte_in_word);
                if relative >= block_limit {
                    break;
                }
                let absolute = start.saturating_add(relative);
                if let Some(byte) = bytes.get(absolute) {
                    value = encoding.value(*byte).wrapping_add(value.wrapping_shl(8));
                }
            }
            value
        });
        Self { words }
    }
}

/// Four-word chaining state shared by the seeded directory hash algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HashState {
    /// First chaining word.
    a: u32,
    /// Second chaining word.
    b: u32,
    /// Third chaining word.
    c: u32,
    /// Fourth chaining word.
    d: u32,
}

impl HashState {
    /// Constructs state from the four format-order seed words.
    const fn from_words(words: [u32; 4]) -> Self {
        let [a, b, c, d] = words;
        Self { a, b, c, d }
    }

    /// Adds one half-MD4 compression result into the chaining state.
    fn compress_half_md4(&mut self, input: NameWordBlock<8>) {
        let [x0, x1, x2, x3, x4, x5, x6, x7] = input.words;
        let mut working = *self;
        working.apply_half_md4_round(
            HalfMd4Mix::Choice,
            [x0, x1, x2, x3, x4, x5, x6, x7],
            [3, 7, 11, 19, 3, 7, 11, 19],
            0,
        );
        working.apply_half_md4_round(
            HalfMd4Mix::Majority,
            [x1, x3, x5, x7, x0, x2, x4, x6],
            [3, 5, 9, 13, 3, 5, 9, 13],
            0x5a82_7999,
        );
        working.apply_half_md4_round(
            HalfMd4Mix::Parity,
            [x3, x7, x2, x6, x1, x5, x0, x4],
            [3, 9, 11, 15, 3, 9, 11, 15],
            0x6ed9_eba1,
        );
        self.a = self.a.wrapping_add(working.a);
        self.b = self.b.wrapping_add(working.b);
        self.c = self.c.wrapping_add(working.c);
        self.d = self.d.wrapping_add(working.d);
    }

    /// Applies one eight-step half-MD4 schedule to the working words.
    fn apply_half_md4_round(
        &mut self,
        mixing: HalfMd4Mix,
        messages: [u32; 8],
        rotations: [u32; 8],
        bias: u32,
    ) {
        for ((target, message), rotation) in
            LANE_UPDATE_ORDER.into_iter().zip(messages).zip(rotations)
        {
            let (current, first, second, third) = self.arguments(target);
            let next = current
                .wrapping_add(mixing.combine(first, second, third))
                .wrapping_add(message)
                .wrapping_add(bias)
                .rotate_left(rotation);
            self.write(target, next);
        }
    }

    /// Adds one 16-round TEA compression result into the first two chaining words.
    fn compress_tea(&mut self, input: NameWordBlock<4>) {
        let [key0, key1, key2, key3] = input.words;
        let mut left = self.a;
        let mut right = self.b;
        let mut sum = 0_u32;
        for _ in 0..16 {
            sum = sum.wrapping_add(TEA_ROUND_INCREMENT);
            left = left.wrapping_add(
                right.wrapping_shl(4).wrapping_add(key0)
                    ^ right.wrapping_add(sum)
                    ^ right.wrapping_shr(5).wrapping_add(key1),
            );
            right = right.wrapping_add(
                left.wrapping_shl(4).wrapping_add(key2)
                    ^ left.wrapping_add(sum)
                    ^ left.wrapping_shr(5).wrapping_add(key3),
            );
        }
        self.a = self.a.wrapping_add(left);
        self.b = self.b.wrapping_add(right);
    }

    /// Returns the current lane followed by its three cyclic inputs.
    const fn arguments(self, target: Lane) -> (u32, u32, u32, u32) {
        match target {
            Lane::A => (self.a, self.b, self.c, self.d),
            Lane::B => (self.b, self.c, self.d, self.a),
            Lane::C => (self.c, self.d, self.a, self.b),
            Lane::D => (self.d, self.a, self.b, self.c),
        }
    }

    /// Replaces one working lane selected by the fixed round schedule.
    const fn write(&mut self, target: Lane, value: u32) {
        match target {
            Lane::A => self.a = value,
            Lane::B => self.b = value,
            Lane::C => self.c = value,
            Lane::D => self.d = value,
        }
    }
}

/// One of the four working words updated by a half-MD4 step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lane {
    /// First word.
    A,
    /// Second word.
    B,
    /// Third word.
    C,
    /// Fourth word.
    D,
}

/// Boolean mixing rule used by one half-MD4 round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HalfMd4Mix {
    /// Selects between the second and third inputs using the first.
    Choice,
    /// Selects bits held by at least two inputs.
    Majority,
    /// Computes the parity of all three inputs.
    Parity,
}

impl HalfMd4Mix {
    /// Combines three working words according to this round's rule.
    const fn combine(self, first: u32, second: u32, third: u32) -> u32 {
        match self {
            Self::Choice => (first & second) | (!first & third),
            Self::Majority => (first & second) | (first & third) | (second & third),
            Self::Parity => first ^ second ^ third,
        }
    }
}

/// Computes the legacy two-accumulator directory-name hash.
fn rolling_hash(bytes: &[u8], encoding: NameByteEncoding) -> (u32, u32) {
    let (current, _) = bytes.iter().fold(
        (0x12a3_fe2d_u32, 0x37ab_e8f9_u32),
        |(current, previous), byte| {
            let candidate =
                previous.wrapping_add(current ^ encoding.value(*byte).wrapping_mul(7_152_373));
            let next = if candidate & 0x8000_0000 == 0 {
                candidate
            } else {
                candidate.wrapping_sub(0x7fff_ffff)
            };
            (next, current)
        },
    );
    (current.wrapping_shl(1), 0)
}

#[cfg(test)]
mod directory_hash_tests {
    //! Black-box known-answer coverage for the ext4 directory-hash boundary.

    use alloc::vec;

    use super::{DirectoryHash, DirectoryHashScheme};
    use crate::disk_format::superblock::{DirectoryHashSeed, DirectoryHashVersion};
    use crate::platform::name::Ext4Name;

    /// Seed supplied to the independent e2fsprogs `debugfs dx_hash` oracle.
    const ORACLE_SEED: DirectoryHashSeed =
        DirectoryHashSeed::from_words([0x0403_0201, 0x0807_0605, 0x0c0b_0a09, 0x100f_0e0d]);

    /// # Panics
    ///
    /// Panics when signed and unsigned algorithms diverge from independently observed high-byte
    /// results.
    #[test]
    fn all_versions_match_high_byte_known_answers() {
        let Ok(name) = Ext4Name::from_disk(&[0x80, b'x']) else {
            return;
        };
        let cases = [
            (
                DirectoryHashVersion::Legacy,
                DirectoryHash {
                    major: 0x65ea_0956,
                    minor: 0,
                },
            ),
            (
                DirectoryHashVersion::HalfMd4,
                DirectoryHash {
                    major: 0xdc70_7c86,
                    minor: 0x60a8_887b,
                },
            ),
            (
                DirectoryHashVersion::Tea,
                DirectoryHash {
                    major: 0x1115_3a44,
                    minor: 0x7023_4016,
                },
            ),
            (
                DirectoryHashVersion::LegacyUnsigned,
                DirectoryHash {
                    major: 0xf734_1b56,
                    minor: 0,
                },
            ),
            (
                DirectoryHashVersion::HalfMd4Unsigned,
                DirectoryHash {
                    major: 0xed95_09f8,
                    minor: 0x76dd_19a1,
                },
            ),
            (
                DirectoryHashVersion::TeaUnsigned,
                DirectoryHash {
                    major: 0xdfb6_ad00,
                    minor: 0xcd05_b7a7,
                },
            ),
        ];
        for (version, expected) in cases {
            assert_eq!(
                DirectoryHashScheme::from_metadata(ORACLE_SEED, version).hash(&name),
                expected,
                "version {version:?}"
            );
        }
    }

    /// # Panics
    ///
    /// Panics when either block compressor stops honoring the name-length transition around its
    /// input width.
    #[test]
    fn block_boundaries_match_known_answers() {
        let cases = [
            (DirectoryHashVersion::Tea, 15, 0x6e56_3772, 0xef88_3696),
            (DirectoryHashVersion::Tea, 16, 0x4325_a512, 0x34c3_9657),
            (DirectoryHashVersion::Tea, 17, 0xc4b7_b762, 0xe449_15cc),
            (DirectoryHashVersion::HalfMd4, 31, 0x762e_6440, 0xeb1f_c23b),
            (DirectoryHashVersion::HalfMd4, 32, 0xbc1d_a53a, 0x0757_10a8),
            (DirectoryHashVersion::HalfMd4, 33, 0x3001_1dd6, 0x553a_1a34),
        ];
        for (version, length, major, minor) in cases {
            let bytes = vec![b'x'; length];
            let Ok(name) = Ext4Name::new(&bytes) else {
                return;
            };
            assert_eq!(
                DirectoryHashScheme::from_metadata(ORACLE_SEED, version).hash(&name),
                DirectoryHash { major, minor },
                "version {version:?}, length {length}"
            );
        }
    }

    /// # Panics
    ///
    /// Panics when full ext4 component length is not processed across every compression block.
    #[test]
    fn maximum_name_length_matches_known_answers() {
        let bytes = vec![b'x'; 255];
        let Ok(name) = Ext4Name::new(&bytes) else {
            return;
        };
        let cases = [
            (
                DirectoryHashVersion::Legacy,
                DirectoryHash {
                    major: 0x3055_7da6,
                    minor: 0,
                },
            ),
            (
                DirectoryHashVersion::HalfMd4,
                DirectoryHash {
                    major: 0xac45_f49a,
                    minor: 0x874d_addc,
                },
            ),
            (
                DirectoryHashVersion::Tea,
                DirectoryHash {
                    major: 0x7ba0_0f18,
                    minor: 0xcaea_b6ab,
                },
            ),
        ];
        for (version, expected) in cases {
            assert_eq!(
                DirectoryHashScheme::from_metadata(ORACLE_SEED, version).hash(&name),
                expected
            );
        }
    }
}
