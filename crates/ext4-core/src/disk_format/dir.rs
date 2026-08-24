//! Directory entry parsing and directory layout validation.

use alloc::vec::Vec;

use crate::disk::checksum::ext4_crc32c;
use crate::disk::endian::{DiskOffset, le_u16, le_u32, put_le_u16, put_le_u32};
use crate::disk_format::inode::InodeId;
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
            hash: DirectoryHashContext::new(hash_seed, hash_version),
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

/// Mutable ext4 directory block with checked dirent surgery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryBlock {
    /// Raw directory block bytes; all mutations update this single buffer.
    bytes: Vec<u8>,
    /// Inode-local checksum context for leaf-directory mutations.
    checksum: DirectoryChecksum,
}

impl DirectoryBlock {
    /// Wraps an existing directory block for checked mutation.
    pub(crate) fn new(bytes: Vec<u8>, checksum: DirectoryChecksum) -> Self {
        Self { bytes, checksum }
    }

    /// Creates a zero-filled directory block with the filesystem block size.
    /// # Errors
    ///
    /// Returns an error when allocating the block-sized byte buffer fails.
    pub(crate) fn empty(block_size: usize, checksum: DirectoryChecksum) -> Result<Self> {
        Ok(Self {
            bytes: memory::repeated_vec(0_u8, block_size)?,
            checksum,
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
        let live_limit = self.live_limit()?;
        if live_limit
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
                live_limit
                    .checked_sub(dotdot_offset)
                    .ok_or(Error::ArithmeticOverflow)?,
            )?,
            b"..",
            DirectoryEntryKind::Directory,
        )?;
        self.refresh_leaf_checksum()
    }

    /// Initializes the block as one free dirent slot.
    /// # Errors
    ///
    /// Returns an error when the block length cannot be represented as an ext4 `rec_len`.
    pub(crate) fn initialize_free_space(&mut self) -> Result<()> {
        let live_limit = self.live_limit()?;
        let rec_len = checked_u16(live_limit)?;
        self.bytes.fill(0);
        put_le_u16(&mut self.bytes, disk_offset(4), rec_len)?;
        self.refresh_leaf_checksum()
    }

    /// Parses live entries from the current block image.
    /// # Errors
    ///
    /// Returns an error when the current block image is not a valid ext4 dirent stream.
    pub(crate) fn entries(&self) -> Result<Vec<DirectoryEntry>> {
        self.verify_leaf_checksum()?;
        DirectoryEntry::parse_all(
            self.bytes
                .get(..self.live_limit()?)
                .ok_or(Error::InvalidDirectoryEntry)?,
        )
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
        let live_limit = self.live_limit()?;
        let needed = checked_rec_len(
            DIRENT_HEADER_SIZE
                .checked_add(name.bytes().len())
                .ok_or(Error::ArithmeticOverflow)?,
        )?;
        let mut offset = 0_usize;
        while offset < live_limit {
            let rec_len = usize::from(le_u16(
                &self.bytes,
                disk_offset(offset).checked_add_bytes(4)?,
            )?);
            if rec_len < DIRENT_HEADER_SIZE
                || offset
                    .checked_add(rec_len)
                    .ok_or(Error::ArithmeticOverflow)?
                    > live_limit
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
                self.refresh_leaf_checksum()?;
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
                self.refresh_leaf_checksum()?;
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
        self.verify_leaf_checksum()?;
        let live_limit = self.live_limit()?;
        let mut offset = 0_usize;
        while offset < live_limit {
            let rec_len = usize::from(le_u16(
                &self.bytes,
                disk_offset(offset).checked_add_bytes(4)?,
            )?);
            if rec_len < DIRENT_HEADER_SIZE
                || offset
                    .checked_add(rec_len)
                    .ok_or(Error::ArithmeticOverflow)?
                    > live_limit
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
                self.refresh_leaf_checksum()?;
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
        self.verify_leaf_checksum()?;
        let live_limit = self.live_limit()?;
        let mut offset = 0_usize;
        while offset < live_limit {
            let rec_len = usize::from(le_u16(
                &self.bytes,
                disk_offset(offset).checked_add_bytes(4)?,
            )?);
            if rec_len < DIRENT_HEADER_SIZE
                || offset
                    .checked_add(rec_len)
                    .ok_or(Error::ArithmeticOverflow)?
                    > live_limit
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
                self.refresh_leaf_checksum()?;
                return Ok(Some(previous));
            }
            offset = offset
                .checked_add(rec_len)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(None)
    }

    /// Returns the byte boundary owned by live directory entries.
    /// # Errors
    ///
    /// Returns an error when the block cannot contain the checksum tail required by its inode.
    fn live_limit(&self) -> Result<usize> {
        self.bytes
            .len()
            .checked_sub(self.checksum.dirent_tail_bytes())
            .ok_or(Error::InvalidDirectoryEntry)
    }

    /// Verifies the checksum tail before interpreting this block as a leaf.
    /// # Errors
    ///
    /// Returns an error when the tail is malformed or its checksum does not match the dirents.
    fn verify_leaf_checksum(&self) -> Result<()> {
        self.checksum.verify_dirent_tail(&self.bytes)
    }

    /// Rebuilds the checksum tail from the current authoritative dirent bytes.
    /// # Errors
    ///
    /// Returns an error when the checksum tail cannot be encoded at the leaf boundary.
    fn refresh_leaf_checksum(&mut self) -> Result<()> {
        let live_limit = self.live_limit()?;
        self.checksum.write_dirent_tail(&mut self.bytes, live_limit)
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
            DirectoryHashVersion::Legacy => {
                legacy_hash(bytes, DirectoryHashByteInterpretation::Signed)
            }
            DirectoryHashVersion::LegacyUnsigned => {
                legacy_hash(bytes, DirectoryHashByteInterpretation::Unsigned)
            }
            DirectoryHashVersion::HalfMd4 | DirectoryHashVersion::HalfMd4Unsigned => {
                let mut state = self.seed;
                let interpretation = self.version.byte_interpretation();
                let mut input = bytes;
                while !input.is_empty() {
                    let block = str2hashbuf::<8>(input, interpretation);
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
                let interpretation = self.version.byte_interpretation();
                let mut input = bytes;
                while !input.is_empty() {
                    let block = str2hashbuf::<4>(input, interpretation);
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

/// Calculates the legacy ext2 directory hash.
fn legacy_hash(bytes: &[u8], interpretation: DirectoryHashByteInterpretation) -> DirectoryHash {
    let mut hash0 = 0x12a3_fe2d_u32;
    let mut hash1 = 0x37ab_e8f9_u32;
    for byte in bytes {
        let value = hash_byte(*byte, interpretation);
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
fn str2hashbuf<const WORDS: usize>(
    bytes: &[u8],
    interpretation: DirectoryHashByteInterpretation,
) -> [u32; WORDS] {
    let len = bytes.len();
    let mut pad = u32::try_from(len).unwrap_or(u32::MAX);
    pad |= pad.wrapping_shl(8);
    pad |= pad.wrapping_shl(16);
    let mut value = pad;
    let mut buffer = [0_u32; WORDS];
    let mut written = 0_usize;
    let limit = len.min(WORDS.saturating_mul(4));
    for (index, byte) in bytes.iter().take(limit).enumerate() {
        value = hash_byte(*byte, interpretation).wrapping_add(value.wrapping_shl(8));
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
fn hash_byte(byte: u8, interpretation: DirectoryHashByteInterpretation) -> u32 {
    match interpretation {
        DirectoryHashByteInterpretation::Signed => {
            let signed_value = if byte < 128 {
                i32::from(byte)
            } else {
                i32::from(byte).wrapping_sub(256)
            };
            u32::from_ne_bytes(signed_value.to_ne_bytes())
        }
        DirectoryHashByteInterpretation::Unsigned => u32::from(byte),
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
