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
