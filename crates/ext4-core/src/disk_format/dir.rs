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

    /// Returns the minimum aligned bytes needed to serialize this entry.
    /// # Errors
    ///
    /// Returns an error when record-length arithmetic cannot be represented.
    pub(crate) fn encoded_len(&self) -> Result<usize> {
        required_name_rec_len(self.name.bytes().len())
    }
}

/// One live dirent and its byte coordinate inside a directory block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryRecord {
    /// Byte offset of the record header inside its logical block.
    offset: u32,
    /// Validated live entry stored at that coordinate.
    entry: DirectoryEntry,
}

impl DirectoryRecord {
    /// Returns the record's byte offset inside its logical block.
    pub(crate) const fn offset(&self) -> u32 {
        self.offset
    }

    /// Borrows the validated live entry.
    pub(crate) const fn entry(&self) -> &DirectoryEntry {
        &self.entry
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
    pub(crate) fn dirent_tail_bytes(self) -> usize {
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
        let (tail_offset, checksum_offset) = dx_tail_offsets(bytes.len(), count_offset, limit)?;
        put_le_u32(bytes, disk_offset(tail_offset), 0)?;
        put_le_u32(bytes, disk_offset(checksum_offset), 0)?;
        let checksum = dx_tail_checksum(
            inode_seed,
            bytes,
            count_offset,
            count,
            tail_offset,
            checksum_offset,
        )?;
        put_le_u32(bytes, disk_offset(checksum_offset), checksum)
    }

    /// Verifies an HTree dx tail when enabled.
    /// # Errors
    ///
    /// Returns an error when the dx tail is outside the block or the stored CRC32C does not match
    /// the index bytes. The first tail word is checksum-covered but semantically unused.
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
        let (tail_offset, checksum_offset) = dx_tail_offsets(bytes.len(), count_offset, limit)?;
        let checksum = dx_tail_checksum(
            inode_seed,
            bytes,
            count_offset,
            count,
            tail_offset,
            checksum_offset,
        )?;
        if le_u32(bytes, disk_offset(checksum_offset))? != checksum {
            return Err(Error::ChecksumMismatch);
        }
        Ok(())
    }
}

/// Returns the reserved/checksum word offsets for one checksum-enabled index table.
/// # Errors
///
/// Returns an error when table geometry overflows or places either tail word outside the block.
fn dx_tail_offsets(
    block_bytes: usize,
    count_offset: usize,
    limit: usize,
) -> Result<(usize, usize)> {
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
        > block_bytes
    {
        return Err(Error::InvalidDirectoryEntry);
    }
    Ok((tail_offset, checksum_offset))
}

/// Calculates one index-block checksum while treating the stored checksum word as zero.
/// # Errors
///
/// Returns an error when the used table or reserved tail word falls outside `bytes`.
fn dx_tail_checksum(
    inode_seed: u32,
    bytes: &[u8],
    count_offset: usize,
    count: usize,
    tail_offset: usize,
    checksum_offset: usize,
) -> Result<u32> {
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
    Ok(ext4_crc32c(checksum, &0_u32.to_le_bytes()))
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
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HtreeRoot {
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
    pub(crate) fn parse(
        bytes: &[u8],
        directory_inode: InodeId,
        hash_seed: DirectoryHashSeed,
        maximum_indirect_levels: u8,
        checksum: DirectoryChecksum,
    ) -> Result<Self> {
        if bytes.len() < DX_ROOT_COUNT_OFFSET + DX_ENTRY_BYTES {
            return Err(Error::InvalidDirectoryEntry);
        }
        let dot = parse_live_entry_at(bytes, 0)?;
        if dot.inode() != directory_inode
            || dot.name().bytes() != b"."
            || dot.kind() != DirectoryEntryKind::Directory
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        if usize::from(le_u16(bytes, disk_offset(4))?) != checked_rec_len(DIRENT_HEADER_SIZE + 1)? {
            return Err(Error::InvalidDirectoryEntry);
        }
        let dotdot = parse_live_entry_at(bytes, checked_rec_len(DIRENT_HEADER_SIZE + 1)?)?;
        if dotdot.name().bytes() != b".." || dotdot.kind() != DirectoryEntryKind::Directory {
            return Err(Error::InvalidDirectoryEntry);
        }
        let dotdot_offset = checked_rec_len(DIRENT_HEADER_SIZE + 1)?;
        if usize::from(le_u16(
            bytes,
            disk_offset(dotdot_offset).checked_add_bytes(4)?,
        )?) != bytes
            .len()
            .checked_sub(dotdot_offset)
            .ok_or(Error::ArithmeticOverflow)?
        {
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
        if indirect_levels > maximum_indirect_levels
            || *bytes
                .get(DX_ROOT_INFO_OFFSET + 7)
                .ok_or(Error::InvalidDirectoryEntry)?
                != 0
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        let index = DxIndex::parse_at(bytes, DX_ROOT_COUNT_OFFSET, checksum)?;
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

    /// Returns the hash context selected by this root.
    pub(crate) const fn hash_context(&self) -> DirectoryHashContext {
        self.hash
    }

    /// Returns the two special entries stored in this root.
    pub(crate) fn dot_entries(&self) -> &[DirectoryEntry] {
        &self.dot_entries
    }

    /// Returns the number of index blocks between the root and a leaf.
    pub(crate) const fn indirect_levels(&self) -> u8 {
        self.indirect_levels
    }

    /// Returns the root routing table.
    pub(crate) const fn index(&self) -> &DxIndex {
        &self.index
    }
}

/// HTree index table.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DxIndex {
    /// Entries in on-disk order.
    entries: Vec<DxEntry>,
    /// Canonical table capacity encoded in the count/limit header.
    limit: usize,
}

impl DxIndex {
    /// Copies this routing table without an infallible allocation path.
    /// # Errors
    ///
    /// Returns an error when allocating the copied route vector fails.
    pub(crate) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            entries: memory::copied_slice(&self.entries)?,
            limit: self.limit,
        })
    }

    /// Parses a root or interior HTree index table.
    /// # Errors
    ///
    /// Returns an error when count/limit fields are inconsistent, the table extends outside the
    /// block, a child pointer is zero, or the dx tail checksum is invalid.
    fn parse_at(bytes: &[u8], count_offset: usize, checksum: DirectoryChecksum) -> Result<Self> {
        let limit = usize::from(le_u16(bytes, disk_offset(count_offset))?);
        let count = usize::from(le_u16(
            bytes,
            disk_offset(count_offset).checked_add_bytes(2)?,
        )?);
        let capacity = dx_capacity(bytes.len(), count_offset, checksum)?;
        if count == 0 || count > limit || limit != capacity {
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
            let raw_block = le_u32(bytes, disk_offset(entry_offset).checked_add_bytes(4)?)?;
            if raw_block == 0 || raw_block & !DX_BLOCK_MASK != 0 {
                return Err(Error::InvalidDirectoryEntry);
            }
            let block = raw_block & DX_BLOCK_MASK;
            if entries
                .last()
                .is_some_and(|previous: &DxEntry| previous.hash > hash)
            {
                return Err(Error::InvalidDirectoryEntry);
            }
            entries.try_push(DxEntry { hash, block })?;
        }
        Ok(Self { entries, limit })
    }

    /// Parses an interior-node routing table.
    /// # Errors
    ///
    /// Returns an error when the fake dirent header, count/limit table, ordering, pointer range, or
    /// checksum tail is invalid.
    pub(crate) fn parse_node(bytes: &[u8], checksum: DirectoryChecksum) -> Result<Self> {
        if le_u32(bytes, disk_offset(0))? != 0
            || usize::from(le_u16(bytes, disk_offset(4))?) != bytes.len()
            || *bytes.get(6).ok_or(Error::InvalidDirectoryEntry)? != 0
            || *bytes.get(7).ok_or(Error::InvalidDirectoryEntry)? != 0
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        Self::parse_at(bytes, DX_NODE_COUNT_OFFSET, checksum)
    }

    /// Selects the last child whose stored boundary is not greater than `major`.
    pub(crate) fn select(&self, major: u32) -> usize {
        self.entries
            .iter()
            .rposition(|entry| entry.hash <= major)
            .unwrap_or(0)
    }

    /// Returns the number of routed children.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns one routed child.
    pub(crate) fn entry(&self, index: usize) -> Option<DxEntry> {
        self.entries.get(index).copied()
    }

    /// Resolves a selected route's effective boundary across an index-node sentinel.
    /// # Errors
    ///
    /// Returns an error when `selected` does not identify an entry in this table.
    pub(crate) fn route_boundary(&self, selected: usize, inherited: u32) -> Result<u32> {
        let entry = self.entry(selected).ok_or(Error::InvalidDirectoryEntry)?;
        if selected == 0 {
            Ok(inherited)
        } else {
            Ok(entry.hash())
        }
    }

    /// Builds a routing table for a root block.
    /// # Errors
    ///
    /// Returns an error when the block geometry or supplied route set is invalid.
    pub(crate) fn root(
        block_size: usize,
        checksum: DirectoryChecksum,
        entries: Vec<DxEntry>,
    ) -> Result<Self> {
        Self::from_routes(
            dx_capacity(block_size, DX_ROOT_COUNT_OFFSET, checksum)?,
            entries,
        )
    }

    /// Inserts one route after the selected child, splitting by entry median when full.
    /// # Errors
    ///
    /// Returns an error when the selected route is absent, allocation fails, or arithmetic
    /// overflows.
    pub(crate) fn insert_after(
        &mut self,
        selected: usize,
        route: DxEntry,
    ) -> Result<Option<DxIndexSplit>> {
        if selected >= self.entries.len() {
            return Err(Error::InvalidDirectoryEntry);
        }
        let insert_at = selected.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        if self
            .entries
            .get(selected)
            .is_none_or(|left| left.hash > route.hash)
            || self
                .entries
                .get(insert_at)
                .is_some_and(|right| route.hash > right.hash)
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        self.entries.try_insert(insert_at, route)?;
        if self.entries.len() <= self.limit {
            return Ok(None);
        }
        let median = self
            .entries
            .len()
            .checked_div(2)
            .ok_or(Error::ArithmeticOverflow)?;
        let right_len = self
            .entries
            .len()
            .checked_sub(median)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut right_entries = Vec::new();
        right_entries
            .try_reserve_exact(right_len)
            .map_err(|_| Error::OutOfMemory)?;
        while self.entries.len() > median {
            right_entries.try_push(self.entries.try_remove_at(median)?)?;
        }
        let boundary = right_entries
            .first()
            .map(|entry| entry.hash)
            .ok_or(Error::InvalidDirectoryEntry)?;
        if let Some(first) = right_entries.first_mut() {
            first.hash = 0;
        }
        if let Some(first) = self.entries.first_mut() {
            first.hash = 0;
        }
        Ok(Some(DxIndexSplit {
            boundary,
            right: Self {
                entries: right_entries,
                limit: self.limit,
            },
        }))
    }

    /// Returns whether another route would exceed this table's capacity.
    pub(crate) fn is_full(&self) -> bool {
        self.entries.len() >= self.limit
    }

    /// Builds one checked table from an already owned route set.
    /// # Errors
    ///
    /// Returns an error when the route set is empty, exceeds `limit`, or is not ordered.
    fn from_routes(limit: usize, mut entries: Vec<DxEntry>) -> Result<Self> {
        if entries.is_empty() || entries.len() > limit {
            return Err(Error::InvalidDirectoryEntry);
        }
        if let Some(first) = entries.first_mut() {
            first.hash = 0;
        }
        for index in 1..entries.len() {
            let previous = index.checked_sub(1).ok_or(Error::ArithmeticOverflow)?;
            if entries
                .get(previous)
                .zip(entries.get(index))
                .is_none_or(|(left, right)| left.hash > right.hash)
            {
                return Err(Error::InvalidDirectoryEntry);
            }
        }
        Ok(Self { entries, limit })
    }

    /// Serializes this index table into an already initialized root or node block.
    /// # Errors
    ///
    /// Returns an error when capacity, route encoding, checksum geometry, or field arithmetic is
    /// invalid.
    fn write_at(
        &self,
        bytes: &mut [u8],
        count_offset: usize,
        checksum: DirectoryChecksum,
    ) -> Result<()> {
        let limit = dx_capacity(bytes.len(), count_offset, checksum)?;
        if limit != self.limit || self.entries.is_empty() || self.entries.len() > limit {
            return Err(Error::InvalidDirectoryEntry);
        }
        let table_end = count_offset
            .checked_add(
                limit
                    .checked_mul(DX_ENTRY_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        bytes
            .get_mut(count_offset..table_end)
            .ok_or(Error::InvalidDirectoryEntry)?
            .fill(0);
        put_le_u16(bytes, disk_offset(count_offset), checked_u16(limit)?)?;
        put_le_u16(
            bytes,
            disk_offset(count_offset).checked_add_bytes(2)?,
            checked_u16(self.entries.len())?,
        )?;
        for (index, entry) in self.entries.iter().enumerate() {
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
                entry.block,
            )?;
        }
        checksum.write_dx_tail(bytes, count_offset, self.entries.len(), limit)
    }
}

/// Primary-hash interval routed by one validated root-to-leaf HTree path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HtreeHashRange {
    /// Inclusive lower primary-hash boundary.
    lower: u32,
    /// Optional upper boundary and whether equality is admitted for a continued collision.
    upper: Option<(u32, bool)>,
}

impl HtreeHashRange {
    /// Creates the unconstrained range owned by the root table.
    pub(crate) const fn root() -> Self {
        Self {
            lower: 0,
            upper: None,
        }
    }

    /// Intersects this range with one selected index-table route.
    /// # Errors
    ///
    /// Returns an error when `selected` is absent or the resulting interval is empty.
    pub(crate) fn descend(self, index: &DxIndex, selected: usize) -> Result<Self> {
        for entry_index in 1..index.len() {
            let boundary = index
                .entry(entry_index)
                .map(|entry| entry.hash() & !1)
                .ok_or(Error::InvalidDirectoryEntry)?;
            if boundary < self.lower
                || self.upper.is_some_and(|(end, inclusive)| {
                    boundary > end || (boundary == end && !inclusive)
                })
            {
                return Err(Error::InvalidDirectoryEntry);
            }
        }
        let selected_entry = index.entry(selected).ok_or(Error::InvalidDirectoryEntry)?;
        let selected_lower = if selected == 0 {
            self.lower
        } else {
            selected_entry.hash() & !1
        };
        let lower = selected_lower;
        let next = selected
            .checked_add(1)
            .and_then(|next| index.entry(next))
            .map(|entry| (entry.hash() & !1, entry.hash() & 1 != 0));
        let upper = match (self.upper, next) {
            (None, None) => None,
            (Some(bound), None) | (None, Some(bound)) => Some(bound),
            (Some(left), Some(right)) => Some(match left.0.cmp(&right.0) {
                core::cmp::Ordering::Less => left,
                core::cmp::Ordering::Greater => right,
                core::cmp::Ordering::Equal => (left.0, left.1 && right.1),
            }),
        };
        if upper.is_some_and(|(end, inclusive)| end < lower || (end == lower && !inclusive)) {
            return Err(Error::InvalidDirectoryEntry);
        }
        Ok(Self { lower, upper })
    }

    /// Validates every live leaf entry against this path's routed hash interval.
    /// # Errors
    ///
    /// Returns an error when a special root name appears in a leaf or a name hashes outside the
    /// selected interval.
    pub(crate) fn validate_leaf(
        self,
        entries: &[DirectoryEntry],
        hash: DirectoryHashContext,
    ) -> Result<()> {
        for entry in entries {
            if matches!(entry.name().bytes(), b"." | b"..") {
                return Err(Error::InvalidDirectoryEntry);
            }
            let major = hash.hash_name(entry.name()).major;
            if major < self.lower
                || self
                    .upper
                    .is_some_and(|(end, inclusive)| major > end || (major == end && !inclusive))
            {
                return Err(Error::InvalidDirectoryEntry);
            }
        }
        Ok(())
    }
}

/// Right sibling produced by a median index split.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DxIndexSplit {
    /// Hash boundary inserted into the parent.
    boundary: u32,
    /// Right half whose first in-block hash is canonical zero.
    right: DxIndex,
}

impl DxIndexSplit {
    /// Returns the parent routing boundary.
    pub(crate) const fn boundary(&self) -> u32 {
        self.boundary
    }

    /// Consumes the split into its right sibling table.
    pub(crate) fn into_right(self) -> DxIndex {
        self.right
    }
}

/// One HTree index entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DxEntry {
    /// First hash value routed to `block`.
    hash: u32,
    /// Directory logical block pointer.
    block: u32,
}

impl DxEntry {
    /// Creates one checked in-memory route.
    /// # Errors
    ///
    /// Returns an error when the logical block does not fit the on-disk pointer field.
    pub(crate) fn new(hash: u32, block: u32) -> Result<Self> {
        if block == 0 || block & !DX_BLOCK_MASK != 0 {
            return Err(Error::DirectoryIndexFull);
        }
        Ok(Self { hash, block })
    }
    /// Returns the stored hash boundary, including its continuation bit.
    pub(crate) const fn hash(self) -> u32 {
        self.hash
    }

    /// Returns the child logical block number.
    pub(crate) const fn block(self) -> u32 {
        self.block
    }
}

/// Serializes one interior-node index block.
/// # Errors
///
/// Returns an error when the block geometry, fake dirent, routing table, or checksum tail cannot be
/// represented.
pub(crate) fn write_htree_node(
    bytes: &mut [u8],
    index: &DxIndex,
    checksum: DirectoryChecksum,
) -> Result<()> {
    bytes.fill(0);
    put_le_u16(bytes, disk_offset(4), checked_u16(bytes.len())?)?;
    index.write_at(bytes, DX_NODE_COUNT_OFFSET, checksum)
}

/// Rewrites only the routing authority and depth in an existing HTree root block.
/// # Errors
///
/// Returns an error when the existing root metadata is truncated or the new routing table cannot be
/// represented with the root's canonical capacity/checksum layout.
pub(crate) fn write_htree_root_index(
    bytes: &mut [u8],
    indirect_levels: u8,
    index: &DxIndex,
    checksum: DirectoryChecksum,
) -> Result<()> {
    *bytes
        .get_mut(DX_ROOT_INFO_OFFSET + 6)
        .ok_or(Error::InvalidDirectoryEntry)? = indirect_levels;
    index.write_at(bytes, DX_ROOT_COUNT_OFFSET, checksum)
}

/// Creates a new HTree root from the fixed root fields and a project-local routing table.
/// # Errors
///
/// Returns an error when the block cannot hold the special entries/root metadata/index table or an
/// encoded field is outside its on-disk range.
pub(crate) fn create_htree_root(
    block_size: usize,
    self_inode: InodeId,
    parent_inode: InodeId,
    hash_version: DirectoryHashVersion,
    index: &DxIndex,
    checksum: DirectoryChecksum,
) -> Result<Vec<u8>> {
    let mut bytes = memory::repeated_vec(0_u8, block_size)?;
    let dot_len = checked_rec_len(DIRENT_HEADER_SIZE + 1)?;
    write_entry(
        &mut bytes,
        0,
        self_inode,
        checked_u16(dot_len)?,
        b".",
        DirectoryEntryKind::Directory,
    )?;
    write_entry(
        &mut bytes,
        dot_len,
        parent_inode,
        checked_u16(
            block_size
                .checked_sub(dot_len)
                .ok_or(Error::ArithmeticOverflow)?,
        )?,
        b"..",
        DirectoryEntryKind::Directory,
    )?;
    put_le_u32(&mut bytes, disk_offset(DX_ROOT_INFO_OFFSET), 0)?;
    *bytes
        .get_mut(DX_ROOT_INFO_OFFSET + 4)
        .ok_or(Error::InvalidDirectoryEntry)? = hash_version.to_raw();
    *bytes
        .get_mut(DX_ROOT_INFO_OFFSET + 5)
        .ok_or(Error::InvalidDirectoryEntry)? = DX_ROOT_INFO_LEN;
    *bytes
        .get_mut(DX_ROOT_INFO_OFFSET + 6)
        .ok_or(Error::InvalidDirectoryEntry)? = 0;
    *bytes
        .get_mut(DX_ROOT_INFO_OFFSET + 7)
        .ok_or(Error::InvalidDirectoryEntry)? = 0;
    index.write_at(&mut bytes, DX_ROOT_COUNT_OFFSET, checksum)?;
    Ok(bytes)
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

    /// Serializes one leaf-local entry set into a fresh block image.
    /// # Errors
    ///
    /// Returns an error when the entries cannot fit, a record cannot be represented, or allocation
    /// fails.
    pub(crate) fn from_entries(
        block_size: usize,
        checksum: DirectoryChecksum,
        entries: &[DirectoryEntry],
    ) -> Result<Self> {
        let mut block = Self::empty(block_size, checksum)?;
        let live_limit = block.live_limit()?;
        if entries.is_empty() {
            block.initialize_free_space()?;
            return Ok(block);
        }
        let mut minimum = 0_usize;
        for entry in entries {
            minimum = minimum
                .checked_add(entry.encoded_len()?)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        if minimum > live_limit {
            return Err(Error::NoSpace);
        }
        let mut offset = 0_usize;
        for (index, entry) in entries.iter().enumerate() {
            let last = index.checked_add(1).ok_or(Error::ArithmeticOverflow)? == entries.len();
            let rec_len = if last {
                live_limit
                    .checked_sub(offset)
                    .ok_or(Error::ArithmeticOverflow)?
            } else {
                entry.encoded_len()?
            };
            write_entry(
                &mut block.bytes,
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
        block.refresh_leaf_checksum()?;
        Ok(block)
    }

    /// Returns the mutated directory block bytes.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Borrows the authoritative block image.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
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

    /// Parses live entries together with their physical byte coordinates.
    /// # Errors
    ///
    /// Returns an error when the checksum or any record boundary, alignment, name length, or live
    /// inode is invalid.
    pub(crate) fn records(&self) -> Result<Vec<DirectoryRecord>> {
        self.verify_leaf_checksum()?;
        let live_limit = self.live_limit()?;
        let mut records = Vec::new();
        let mut offset = 0_usize;
        while offset < live_limit {
            let remaining = live_limit
                .checked_sub(offset)
                .ok_or(Error::ArithmeticOverflow)?;
            if remaining < DIRENT_HEADER_SIZE {
                return Err(Error::InvalidDirectoryEntry);
            }
            let rec_len = usize::from(le_u16(
                &self.bytes,
                disk_offset(offset).checked_add_bytes(4)?,
            )?);
            if rec_len < DIRENT_HEADER_SIZE
                || !rec_len.is_multiple_of(DIRENT_ALIGNMENT)
                || rec_len > remaining
            {
                return Err(Error::InvalidDirectoryEntry);
            }
            let name_len = usize::from(
                *self
                    .bytes
                    .get(offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?)
                    .ok_or(Error::InvalidDirectoryEntry)?,
            );
            if name_len
                > rec_len
                    .checked_sub(DIRENT_HEADER_SIZE)
                    .ok_or(Error::InvalidDirectoryEntry)?
            {
                return Err(Error::InvalidDirectoryEntry);
            }
            if le_u32(&self.bytes, disk_offset(offset))? != 0 {
                records.try_push(DirectoryRecord {
                    offset: u32::try_from(offset).map_err(|_| Error::ArithmeticOverflow)?,
                    entry: parse_live_entry_at(
                        self.bytes
                            .get(..live_limit)
                            .ok_or(Error::InvalidDirectoryEntry)?,
                        offset,
                    )?,
                })?;
            }
            offset = offset
                .checked_add(rec_len)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(records)
    }

    /// Finds one exact name in this leaf block.
    /// # Errors
    ///
    /// Returns an error when the block checksum or dirent stream is invalid.
    pub(crate) fn find(&self, name: &Ext4Name) -> Result<Option<DirectoryEntry>> {
        self.entries()?
            .into_iter()
            .find(|entry| entry.name() == name)
            .map_or(Ok(None), |entry| Ok(Some(entry)))
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
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    /// Builds a fixed nonzero inode id for directory-format tests.
    /// # Errors
    ///
    /// Returns an error if the fixed fixture leaves the inode-id domain.
    fn inode(value: u32) -> Result<InodeId> {
        InodeId::try_from(value)
    }

    /// Builds a one-leaf root block using only production format constructors.
    /// # Errors
    ///
    /// Returns an error when the fixed root fields cannot be represented.
    fn root_block(checksum: DirectoryChecksum) -> Result<Vec<u8>> {
        let mut routes = Vec::new();
        routes.try_push(DxEntry::new(0, 1)?)?;
        let index = DxIndex::root(1_024, checksum, routes)?;
        create_htree_root(
            1_024,
            inode(11)?,
            inode(2)?,
            DirectoryHashVersion::HalfMd4,
            &index,
            checksum,
        )
    }

    /// Converts fallible fixture construction into an assertion-friendly optional value.
    /// # Panics
    ///
    /// Panics when production constructors reject the fixed test fixture.
    fn test_value<T>(result: Result<T>) -> Option<T> {
        assert!(result.is_ok());
        result.ok()
    }

    /// # Panics
    ///
    /// Panics when canonical HTree root fields stop being enforced.
    #[test]
    fn htree_root_rejects_reserved_depth_capacity_and_special_entry_corruption() {
        let seed = DirectoryHashSeed::from_words([1, 2, 3, 4]);
        let Some(root) = test_value(root_block(DirectoryChecksum::None)) else {
            return;
        };
        let Some(directory_inode) = test_value(inode(11)) else {
            return;
        };
        assert!(
            HtreeRoot::parse(&root, directory_inode, seed, 0, DirectoryChecksum::None,).is_ok()
        );

        let mut excessive_depth = root.clone();
        let depth_offset = DX_ROOT_INFO_OFFSET.checked_add(6);
        assert!(depth_offset.is_some());
        let Some(depth_offset) = depth_offset else {
            return;
        };
        let depth = excessive_depth.get_mut(depth_offset);
        assert!(depth.is_some());
        let Some(depth) = depth else {
            return;
        };
        *depth = 1;
        assert_eq!(
            HtreeRoot::parse(
                &excessive_depth,
                directory_inode,
                seed,
                0,
                DirectoryChecksum::None,
            ),
            Err(Error::InvalidDirectoryEntry)
        );

        let mut reserved = root.clone();
        let reserved_offset = DX_ROOT_INFO_OFFSET.checked_add(7);
        assert!(reserved_offset.is_some());
        let Some(reserved_offset) = reserved_offset else {
            return;
        };
        let reserved_byte = reserved.get_mut(reserved_offset);
        assert!(reserved_byte.is_some());
        let Some(reserved_byte) = reserved_byte else {
            return;
        };
        *reserved_byte = 1;
        assert_eq!(
            HtreeRoot::parse(&reserved, directory_inode, seed, 1, DirectoryChecksum::None,),
            Err(Error::InvalidDirectoryEntry)
        );

        let mut noncanonical_limit = root.clone();
        let Some(limit) = test_value(le_u16(
            &noncanonical_limit,
            disk_offset(DX_ROOT_COUNT_OFFSET),
        )) else {
            return;
        };
        let reduced_limit = limit.checked_sub(1);
        assert!(reduced_limit.is_some());
        let Some(reduced_limit) = reduced_limit else {
            return;
        };
        let write_limit = put_le_u16(
            &mut noncanonical_limit,
            disk_offset(DX_ROOT_COUNT_OFFSET),
            reduced_limit,
        );
        assert!(write_limit.is_ok());
        if write_limit.is_err() {
            return;
        }
        assert_eq!(
            HtreeRoot::parse(
                &noncanonical_limit,
                directory_inode,
                seed,
                0,
                DirectoryChecksum::None,
            ),
            Err(Error::InvalidDirectoryEntry)
        );

        let mut wrong_self = root;
        let Some(wrong_inode) = test_value(inode(12)) else {
            return;
        };
        let write_inode = put_le_u32(&mut wrong_self, disk_offset(0), wrong_inode.as_u32());
        assert!(write_inode.is_ok());
        if write_inode.is_err() {
            return;
        }
        assert_eq!(
            HtreeRoot::parse(
                &wrong_self,
                directory_inode,
                seed,
                0,
                DirectoryChecksum::None,
            ),
            Err(Error::InvalidDirectoryEntry)
        );
    }

    /// # Panics
    ///
    /// Panics when index checksums stop covering used routing bytes.
    #[test]
    fn htree_root_checksum_rejects_routing_corruption() {
        let Some(directory_inode) = test_value(inode(11)) else {
            return;
        };
        let checksum = DirectoryChecksum::metadata_csum(
            ChecksumSeed::from_u32(0x1234_5678),
            directory_inode,
            9,
        );
        let Some(mut root) = test_value(root_block(checksum)) else {
            return;
        };
        let seed = DirectoryHashSeed::from_words([0; 4]);
        assert!(HtreeRoot::parse(&root, directory_inode, seed, 0, checksum).is_ok());
        let route_offset = DX_ROOT_COUNT_OFFSET.checked_add(4);
        assert!(route_offset.is_some());
        let Some(route_offset) = route_offset else {
            return;
        };
        let route_byte = root.get_mut(route_offset);
        assert!(route_byte.is_some());
        let Some(route_byte) = route_byte else {
            return;
        };
        *route_byte ^= 0x40;
        assert_eq!(
            HtreeRoot::parse(&root, directory_inode, seed, 0, checksum),
            Err(Error::ChecksumMismatch)
        );
    }

    /// # Panics
    ///
    /// Panics when the semantically unused index-tail word is rejected or omitted from checksum
    /// coverage.
    #[test]
    fn htree_tail_reserved_word_is_unused_but_checksum_covered() {
        let Some(directory_inode) = test_value(inode(11)) else {
            return;
        };
        let checksum = DirectoryChecksum::metadata_csum(
            ChecksumSeed::from_u32(0x1234_5678),
            directory_inode,
            9,
        );
        assert!(matches!(checksum, DirectoryChecksum::Crc32c { .. }));
        let DirectoryChecksum::Crc32c { inode_seed } = checksum else {
            return;
        };
        let Some(mut root) = test_value(root_block(checksum)) else {
            return;
        };
        let seed = DirectoryHashSeed::from_words([0; 4]);
        let Some(limit) =
            test_value(le_u16(&root, disk_offset(DX_ROOT_COUNT_OFFSET)).map(usize::from))
        else {
            return;
        };
        let Some(count_offset) = test_value(disk_offset(DX_ROOT_COUNT_OFFSET).checked_add_bytes(2))
        else {
            return;
        };
        let Some(count) = test_value(le_u16(&root, count_offset).map(usize::from)) else {
            return;
        };
        let Some((tail_offset, checksum_offset)) =
            test_value(dx_tail_offsets(root.len(), DX_ROOT_COUNT_OFFSET, limit))
        else {
            return;
        };
        assert!(put_le_u32(&mut root, disk_offset(tail_offset), 0xde00_000c).is_ok());
        assert!(put_le_u32(&mut root, disk_offset(checksum_offset), 0).is_ok());
        let Some(expected) = test_value(dx_tail_checksum(
            inode_seed,
            &root,
            DX_ROOT_COUNT_OFFSET,
            count,
            tail_offset,
            checksum_offset,
        )) else {
            return;
        };
        assert!(put_le_u32(&mut root, disk_offset(checksum_offset), expected).is_ok());
        assert!(HtreeRoot::parse(&root, directory_inode, seed, 0, checksum).is_ok());

        let Some(reserved) = root.get_mut(tail_offset) else {
            return;
        };
        *reserved ^= 1;
        assert_eq!(
            HtreeRoot::parse(&root, directory_inode, seed, 0, checksum),
            Err(Error::ChecksumMismatch)
        );
    }

    /// # Panics
    ///
    /// Panics when median split ordering or capacity semantics drift.
    #[test]
    fn index_insert_splits_at_entry_median_and_rejects_disordered_routes() {
        let Some(first) = test_value(DxEntry::new(0, 1)) else {
            return;
        };
        let Some(second) = test_value(DxEntry::new(20, 2)) else {
            return;
        };
        let mut index = DxIndex {
            entries: vec![first, second],
            limit: 2,
        };
        let Some(route) = test_value(DxEntry::new(10, 3)) else {
            return;
        };
        let Some(split_result) = test_value(index.insert_after(0, route)) else {
            return;
        };
        assert!(split_result.is_some());
        let Some(split) = split_result else {
            return;
        };
        assert_eq!(index.len(), 1);
        assert_eq!(split.boundary(), 10);
        let right = split.into_right();
        assert_eq!(right.len(), 2);
        assert_eq!(right.entry(0).map(DxEntry::hash), Some(0));
        assert_eq!(right.entry(1).map(DxEntry::hash), Some(20));

        let Some(first) = test_value(DxEntry::new(0, 1)) else {
            return;
        };
        let Some(second) = test_value(DxEntry::new(20, 2)) else {
            return;
        };
        let mut ordered = DxIndex {
            entries: vec![first, second],
            limit: 3,
        };
        let Some(disordered) = test_value(DxEntry::new(30, 3)) else {
            return;
        };
        assert_eq!(
            ordered.insert_after(0, disordered),
            Err(Error::InvalidDirectoryEntry)
        );
    }

    /// # Panics
    ///
    /// Panics when a child table's zero sentinel stops inheriting its parent route boundary.
    #[test]
    fn index_first_route_inherits_the_effective_parent_boundary() {
        let Some(parent_first) = test_value(DxEntry::new(0, 10)) else {
            return;
        };
        let Some(parent_second) = test_value(DxEntry::new(0x1234_5679, 20)) else {
            return;
        };
        let Some(parent) = test_value(DxIndex::from_routes(3, vec![parent_first, parent_second]))
        else {
            return;
        };
        let Some(parent_boundary) = test_value(parent.route_boundary(1, 0)) else {
            return;
        };
        assert_eq!(parent_boundary, 0x1234_5679);

        let Some(child_first) = test_value(DxEntry::new(0, 30)) else {
            return;
        };
        let Some(child) = test_value(DxIndex::from_routes(2, vec![child_first])) else {
            return;
        };
        assert_eq!(
            child.route_boundary(0, parent_boundary),
            Ok(parent_boundary)
        );
    }

    /// # Panics
    ///
    /// Panics when collision-continuation boundaries stop controlling leaf admission.
    #[test]
    fn leaf_hash_range_admits_upper_equality_only_for_continuations() {
        let hash = DirectoryHashContext::new(
            DirectoryHashSeed::from_words([1, 2, 3, 4]),
            DirectoryHashVersion::HalfMd4,
        );
        let Some(first_inode) = test_value(inode(12)) else {
            return;
        };
        let Some(first_name) = test_value(Ext4Name::new(b"alpha")) else {
            return;
        };
        let Some(first) = test_value(DirectoryEntry::new(
            first_inode,
            &first_name,
            DirectoryEntryKind::File,
        )) else {
            return;
        };
        let Some(second_inode) = test_value(inode(13)) else {
            return;
        };
        let Some(second_name) = test_value(Ext4Name::new(b"omega")) else {
            return;
        };
        let Some(second) = test_value(DirectoryEntry::new(
            second_inode,
            &second_name,
            DirectoryEntryKind::File,
        )) else {
            return;
        };
        let (lower_entry, upper_entry) =
            if hash.hash_name(first.name()).major < hash.hash_name(second.name()).major {
                (first, second)
            } else {
                (second, first)
            };
        let upper = hash.hash_name(upper_entry.name()).major;

        let Some(exclusive_first) = test_value(DxEntry::new(0, 1)) else {
            return;
        };
        let Some(exclusive_upper) = test_value(DxEntry::new(upper, 2)) else {
            return;
        };
        let Some(exclusive) = test_value(DxIndex::from_routes(
            3,
            vec![exclusive_first, exclusive_upper],
        )) else {
            return;
        };
        let Some(range) = test_value(HtreeHashRange::root().descend(&exclusive, 0)) else {
            return;
        };
        let Some(lower_clone) = test_value(lower_entry.try_clone()) else {
            return;
        };
        assert!(range.validate_leaf(&[lower_clone], hash).is_ok());
        let Some(upper_clone) = test_value(upper_entry.try_clone()) else {
            return;
        };
        assert_eq!(
            range.validate_leaf(&[upper_clone], hash),
            Err(Error::InvalidDirectoryEntry)
        );

        let Some(continued_first) = test_value(DxEntry::new(0, 1)) else {
            return;
        };
        let Some(continued_upper) = test_value(DxEntry::new(upper | 1, 2)) else {
            return;
        };
        let Some(continued) = test_value(DxIndex::from_routes(
            3,
            vec![continued_first, continued_upper],
        )) else {
            return;
        };
        assert!(
            HtreeHashRange::root()
                .descend(&continued, 0)
                .and_then(|range| range.validate_leaf(&[upper_entry], hash))
                .is_ok()
        );
    }

    /// # Panics
    ///
    /// Panics when chunked half-MD4 hashing diverges from an independently generated long-name
    /// known-answer vector.
    #[test]
    fn half_md4_hashes_maximum_length_name_across_all_chunks() {
        let hash = DirectoryHashContext::new(
            DirectoryHashSeed::from_words([0x3be8_72af, 0xff4d_af2f, 0x5752_a385, 0xe752_9d11]),
            DirectoryHashVersion::HalfMd4,
        );
        let mut bytes = b"depth-49999-".to_vec();
        bytes.resize(255, b'x');
        let Some(name) = test_value(Ext4Name::new(&bytes)) else {
            return;
        };
        assert_eq!(
            hash.hash_name(&name),
            DirectoryHash {
                major: 0x1d7e_9c3e,
                minor: 0x9457_ab15,
            }
        );
    }
}
