//! Directory entry parsing and directory layout validation.

use alloc::vec::Vec;

use crate::disk::checksum::ext4_crc32c;
use crate::disk::endian::{DiskOffset, le_u16, le_u32, put_le_u16, put_le_u32};
use crate::disk_format::directory_hash::{DirectoryHash, DirectoryHashScheme};
use crate::disk_format::inode::InodeId;
use crate::disk_format::name::Ext4Name;
use crate::disk_format::superblock::{
    ChecksumSeed, DirectoryHashSeed, DirectoryHashSignedness, DirectoryHashVersion,
};
use crate::error::{Error, Result};
use crate::memory::{self, FallibleVec};

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

/// Record layout selected by the owning directory's encryption and comparison state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryEntryEncoding {
    /// The aligned name is the complete live record payload.
    Standard,
    /// Non-dot entries also carry the keyed primary and secondary hashes.
    EncryptedCasefold,
}

impl DirectoryEntryEncoding {
    /// Selects the external record layout from the owning directory flags.
    pub(crate) const fn for_inode(inode: &crate::disk_format::inode::Inode) -> Self {
        if inode.flags().has_casefold() && inode.protection().is_encrypted() {
            Self::EncryptedCasefold
        } else {
            Self::Standard
        }
    }
    /// Accounts for the aligned trailer while exempting the two format-defined dot records.
    /// # Errors
    /// Rejects short ciphertext and unrepresentable record geometry.
    fn record_len(self, name: &[u8]) -> Result<usize> {
        let prefix = required_name_rec_len(name.len())?;
        if self == Self::EncryptedCasefold && !matches!(name, b"." | b"..") {
            if name.len() < 16 {
                return Err(Error::InvalidDirectoryEntry);
            }
            prefix.checked_add(8).ok_or(Error::ArithmeticOverflow)
        } else {
            Ok(prefix)
        }
    }
}

/// A stored name and the routing information that belongs to that exact ciphertext.
#[derive(Debug, Eq, PartialEq)]
enum DirectoryEntryName {
    /// Ordinary records, including dot entries in every directory.
    Unhashed(Ext4Name),
    /// The encrypted spelling and its plaintext comparison-key hash travel together.
    EncryptedCasefold {
        /// Filename ciphertext as stored on disk.
        ciphertext: Ext4Name,
        /// Keyed hash of its normalized plaintext name.
        hash: DirectoryHash,
    },
}

/// Valid directory entry exposed by the ext4 domain.
#[derive(Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    /// Non-zero inode referenced by the entry.
    inode: InodeId,
    /// Stored name and its format-required routing data.
    name: DirectoryEntryName,
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
            name: DirectoryEntryName::Unhashed(Ext4Name::from_disk(name.bytes())?),
            kind,
        })
    }

    /// Joins ciphertext to the hash of the normalized plaintext that produced it.
    /// # Errors
    /// Rejects invalid ciphertext geometry, reserved routing values or allocation failure.
    pub(crate) fn encrypted_casefold(
        inode: InodeId,
        ciphertext: &Ext4Name,
        kind: DirectoryEntryKind,
        hash: DirectoryHash,
    ) -> Result<Self> {
        if matches!(ciphertext.bytes(), b"." | b"..") {
            return Err(Error::InvalidDirectoryEntry);
        }
        DirectoryEntryEncoding::EncryptedCasefold.record_len(ciphertext.bytes())?;
        let hash = DirectoryHash::from_stored(hash.major, hash.minor)?;
        Ok(Self {
            inode,
            name: DirectoryEntryName::EncryptedCasefold {
                ciphertext: ciphertext.try_to_owned_name()?,
                hash,
            },
            kind,
        })
    }

    /// Borrows a stored keyed hash without decrypting the name or reinterpreting ciphertext.
    pub(crate) const fn stored_hash(&self) -> Option<DirectoryHash> {
        match self.name {
            DirectoryEntryName::Unhashed(_) => None,
            DirectoryEntryName::EncryptedCasefold { hash, .. } => Some(hash),
        }
    }

    /// Requires agreement between a complete record and the directory that will own it.
    /// # Errors
    /// Rejects a hashless encrypted folded name or a trailer in an ordinary directory.
    fn require_encoding(&self, encoding: DirectoryEntryEncoding) -> Result<()> {
        let expects_hash = encoding == DirectoryEntryEncoding::EncryptedCasefold
            && !matches!(self.name().bytes(), b"." | b"..");
        if expects_hash != self.stored_hash().is_some() {
            return Err(Error::InvalidDirectoryEntry);
        }
        Ok(())
    }

    /// Copies this directory entry without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the raw directory name bytes cannot allocate.
    pub(crate) fn try_clone(&self) -> Result<Self> {
        match &self.name {
            DirectoryEntryName::Unhashed(name) => Self::new(self.inode, name, self.kind),
            DirectoryEntryName::EncryptedCasefold { ciphertext, hash } => {
                Self::encrypted_casefold(self.inode, ciphertext, self.kind, *hash)
            }
        }
    }

    /// Parses a directory file payload into live directory entries.
    ///
    /// # Errors
    /// Returns an error when any directory record has invalid length, alignment,
    /// or name bounds.
    pub(crate) fn parse_all(bytes: &[u8], encoding: DirectoryEntryEncoding) -> Result<Vec<Self>> {
        let mut entries = Vec::new();
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let record = decode_record_at(bytes, offset, encoding)?;
            if let Some(entry) = record.entry {
                entries.try_push(entry.to_owned()?)?;
            }
            offset = offset
                .checked_add(record.length)
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
        match &self.name {
            DirectoryEntryName::Unhashed(name) => name,
            DirectoryEntryName::EncryptedCasefold { ciphertext, .. } => ciphertext,
        }
    }

    /// Directory entry file type.
    #[must_use]
    pub const fn kind(&self) -> DirectoryEntryKind {
        self.kind
    }

    /// Returns the minimum aligned bytes needed to serialize this entry.
    /// # Errors
    ///
    /// Returns an error when record-length arithmetic cannot be represented.
    pub(crate) fn encoded_len(&self) -> Result<usize> {
        match self.name {
            DirectoryEntryName::Unhashed(_) => DirectoryEntryEncoding::Standard,
            DirectoryEntryName::EncryptedCasefold { .. } => {
                DirectoryEntryEncoding::EncryptedCasefold
            }
        }
        .record_len(self.name().bytes())
    }
}

/// One live dirent and its byte coordinate inside a directory block.
#[derive(Debug, Eq, PartialEq)]
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

/// Source of the name hashes selected by an HTree root and its owning directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryIndexHash {
    /// Hash comparison bytes using the root-selected unkeyed algorithm.
    Computed(DirectoryHashScheme),
    /// Keyed plaintext hashes reside in encrypted casefold leaf records.
    StoredKeyed,
}
impl DirectoryIndexHash {
    /// Admits exactly the root version prescribed by the directory record layout.
    /// # Errors
    /// Rejects an unknown version or disagreement between keyed hashes and directory flags.
    fn from_root(
        seed: DirectoryHashSeed,
        version: u8,
        signedness: DirectoryHashSignedness,
        encoding: DirectoryEntryEncoding,
    ) -> Result<Self> {
        match (encoding, version) {
            (DirectoryEntryEncoding::EncryptedCasefold, 6) => Ok(Self::StoredKeyed),
            (DirectoryEntryEncoding::EncryptedCasefold, _)
            | (DirectoryEntryEncoding::Standard, 6) => Err(Error::UnsupportedDirectoryHash),
            (DirectoryEntryEncoding::Standard, version) => {
                Ok(Self::Computed(DirectoryHashScheme::from_metadata(
                    seed,
                    DirectoryHashVersion::from_raw(version)?,
                    signedness,
                )))
            }
        }
    }
    /// Requests an algorithm only when ciphertext-independent stored hashes are not required.
    /// # Errors
    /// Rejects attempts to hash ciphertext under a keyed plaintext profile.
    pub(crate) fn computed(self) -> Result<DirectoryHashScheme> {
        match self {
            Self::Computed(scheme) => Ok(scheme),
            Self::StoredKeyed => Err(Error::UnsupportedDirectoryHash),
        }
    }
    /// Reads the entry's authoritative stored hash or derives its comparison-key hash.
    /// # Errors
    /// Rejects layout disagreement, invalid encoding or normalization allocation failure.
    pub(crate) fn entry_hash(
        self,
        entry: &DirectoryEntry,
        names: super::name::NameSemantics,
    ) -> Result<DirectoryHash> {
        match (self, entry.stored_hash()) {
            (Self::Computed(scheme), None) => names.hash(entry.name(), scheme),
            (Self::StoredKeyed, Some(hash)) => Ok(hash),
            _ => Err(Error::InvalidDirectoryEntry),
        }
    }
    /// Encodes the actual root hash version, including the keyed profile's format identifier.
    const fn to_raw(self) -> u8 {
        match self {
            Self::Computed(scheme) => scheme.root_version(),
            Self::StoredKeyed => 6,
        }
    }
}

/// Parsed HTree root block.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HtreeRoot {
    /// Directory hash scheme selected by root info.
    hash: DirectoryIndexHash,
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
        hash_signedness: DirectoryHashSignedness,
        maximum_indirect_levels: u8,
        checksum: DirectoryChecksum,
        encoding: DirectoryEntryEncoding,
    ) -> Result<Self> {
        if bytes.len() < DX_ROOT_COUNT_OFFSET + DX_ENTRY_BYTES {
            return Err(Error::InvalidDirectoryEntry);
        }
        let dot = parse_live_entry_at(bytes, 0, DirectoryEntryEncoding::Standard)?;
        if dot.inode() != directory_inode
            || dot.name().bytes() != b"."
            || dot.kind() != DirectoryEntryKind::Directory
        {
            return Err(Error::InvalidDirectoryEntry);
        }
        if read_record_length(bytes, 0)? != checked_rec_len(DIRENT_HEADER_SIZE + 1)? {
            return Err(Error::InvalidDirectoryEntry);
        }
        let dotdot = parse_live_entry_at(
            bytes,
            checked_rec_len(DIRENT_HEADER_SIZE + 1)?,
            DirectoryEntryEncoding::Standard,
        )?;
        if dotdot.name().bytes() != b".." || dotdot.kind() != DirectoryEntryKind::Directory {
            return Err(Error::InvalidDirectoryEntry);
        }
        let dotdot_offset = checked_rec_len(DIRENT_HEADER_SIZE + 1)?;
        if read_record_length(bytes, dotdot_offset)?
            != bytes
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
        let hash =
            DirectoryIndexHash::from_root(hash_seed, root_hash_version, hash_signedness, encoding)?;
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
            hash,
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

    /// Returns the hash scheme selected by this root.
    pub(crate) const fn hash_profile(&self) -> DirectoryIndexHash {
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
            || read_record_length(bytes, 0)? != bytes.len()
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
        hash: DirectoryHashScheme,
        names: super::name::NameSemantics,
    ) -> Result<()> {
        for entry in entries {
            if matches!(entry.name().bytes(), b"." | b"..") {
                return Err(Error::InvalidDirectoryEntry);
            }
            let major = names.hash(entry.name(), hash)?.major;
            self.validate_hash(major)?;
        }
        Ok(())
    }
    /// Checks an already computed primary hash against this routing interval.
    /// # Errors
    /// Returns an error if the hash is outside the selected interval.
    pub(crate) fn validate_hash(self, major: u32) -> Result<()> {
        if major < self.lower
            || self
                .upper
                .is_some_and(|(end, inclusive)| major > end || (major == end && !inclusive))
        {
            return Err(Error::InvalidDirectoryEntry);
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
    put_le_u16(
        bytes,
        disk_offset(4),
        encode_record_length(bytes.len(), bytes.len())?,
    )?;
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
    hash: DirectoryIndexHash,
    index: &DxIndex,
    checksum: DirectoryChecksum,
) -> Result<Vec<u8>> {
    let mut bytes = memory::repeated_vec(0_u8, block_size)?;
    let dot_len = checked_rec_len(DIRENT_HEADER_SIZE + 1)?;
    write_entry(
        &mut bytes,
        0,
        dot_len,
        &DirectoryEntry::new(
            self_inode,
            &Ext4Name::new(b".")?,
            DirectoryEntryKind::Directory,
        )?,
    )?;
    write_entry(
        &mut bytes,
        dot_len,
        block_size
            .checked_sub(dot_len)
            .ok_or(Error::ArithmeticOverflow)?,
        &DirectoryEntry::new(
            parent_inode,
            &Ext4Name::new(b"..")?,
            DirectoryEntryKind::Directory,
        )?,
    )?;
    put_le_u32(&mut bytes, disk_offset(DX_ROOT_INFO_OFFSET), 0)?;
    *bytes
        .get_mut(DX_ROOT_INFO_OFFSET + 4)
        .ok_or(Error::InvalidDirectoryEntry)? = hash.to_raw();
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
    /// Required interpretation of live non-dot record payloads.
    encoding: DirectoryEntryEncoding,
}

impl DirectoryBlock {
    /// Wraps an existing directory block for checked mutation.
    pub(crate) fn new(
        bytes: Vec<u8>,
        checksum: DirectoryChecksum,
        encoding: DirectoryEntryEncoding,
    ) -> Self {
        Self {
            bytes,
            checksum,
            encoding,
        }
    }

    /// Creates a zero-filled directory block with the filesystem block size.
    /// # Errors
    ///
    /// Returns an error when allocating the block-sized byte buffer fails.
    pub(crate) fn empty(
        block_size: usize,
        checksum: DirectoryChecksum,
        encoding: DirectoryEntryEncoding,
    ) -> Result<Self> {
        Ok(Self {
            bytes: memory::repeated_vec(0_u8, block_size)?,
            checksum,
            encoding,
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
        encoding: DirectoryEntryEncoding,
    ) -> Result<Self> {
        let mut block = Self::empty(block_size, checksum, encoding)?;
        let live_limit = block.live_limit()?;
        if entries.is_empty() {
            block.initialize_free_space()?;
            return Ok(block);
        }
        let mut minimum = 0_usize;
        for entry in entries {
            entry.require_encoding(encoding)?;
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
            write_entry(&mut block.bytes, offset, rec_len, entry)?;
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
            checked_rec_len(DIRENT_HEADER_SIZE + 1)?,
            &DirectoryEntry::new(
                self_inode,
                &Ext4Name::new(b".")?,
                DirectoryEntryKind::Directory,
            )?,
        )?;
        let dotdot_offset = checked_rec_len(DIRENT_HEADER_SIZE + 1)?;
        write_entry(
            &mut self.bytes,
            dotdot_offset,
            live_limit
                .checked_sub(dotdot_offset)
                .ok_or(Error::ArithmeticOverflow)?,
            &DirectoryEntry::new(
                parent_inode,
                &Ext4Name::new(b"..")?,
                DirectoryEntryKind::Directory,
            )?,
        )?;
        self.refresh_leaf_checksum()
    }

    /// Initializes the block as one free dirent slot.
    /// # Errors
    ///
    /// Returns an error when the block length cannot be represented as an ext4 `rec_len`.
    pub(crate) fn initialize_free_space(&mut self) -> Result<()> {
        let live_limit = self.live_limit()?;
        let rec_len = encode_record_length(live_limit, self.bytes.len())?;
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
            self.encoding,
        )
    }

    /// Parses live entries together with their physical byte coordinates.
    /// # Errors
    ///
    /// Returns an error when the checksum or any record boundary, alignment, name length, or live
    /// inode is invalid.
    pub(crate) fn records(&self) -> Result<Vec<DirectoryRecord>> {
        self.verify_leaf_checksum()?;
        let bytes = self
            .bytes
            .get(..self.live_limit()?)
            .ok_or(Error::InvalidDirectoryEntry)?;
        let mut records = Vec::new();
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let record = decode_record_at(bytes, offset, self.encoding)?;
            if let Some(entry) = record.entry {
                records.try_push(DirectoryRecord {
                    offset: u32::try_from(offset).map_err(|_| Error::ArithmeticOverflow)?,
                    entry: entry.to_owned()?,
                })?;
            }
            offset = offset
                .checked_add(record.length)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(records)
    }

    /// Checks whether a live entry already owns `name`.
    /// # Errors
    ///
    /// Returns an error when the current block cannot be parsed before the lookup.
    pub(crate) fn contains_name(&self, name: &Ext4Name) -> Result<bool> {
        self.verify_leaf_checksum()?;
        let bytes = self
            .bytes
            .get(..self.live_limit()?)
            .ok_or(Error::InvalidDirectoryEntry)?;
        let mut offset = 0_usize;
        let mut found = false;
        while offset < bytes.len() {
            let record = decode_record_at(bytes, offset, self.encoding)?;
            found |= record
                .entry
                .is_some_and(|entry| entry.name() == name.bytes());
            offset = offset
                .checked_add(record.length)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(found)
    }

    /// Inserts a live entry by reusing free space or splitting an oversized record.
    /// # Errors
    ///
    /// Returns an error when the name already exists, record accounting overflows, an existing
    /// dirent is malformed, or the new entry cannot be encoded.
    pub(crate) fn insert(&mut self, entry: &DirectoryEntry) -> Result<bool> {
        entry.require_encoding(self.encoding)?;
        let name = entry.name();
        if self.contains_name(name)? {
            return Err(Error::NameAlreadyExists);
        }
        let live_limit = self.live_limit()?;
        let needed = entry.encoded_len()?;
        let mut offset = 0_usize;
        while offset < live_limit {
            let record = decode_record_at(
                self.bytes
                    .get(..live_limit)
                    .ok_or(Error::InvalidDirectoryEntry)?,
                offset,
                self.encoding,
            )?;
            let length = record.length;
            let used = match record.entry {
                None => 0,
                Some(live) => self.encoding.record_len(live.name())?,
            };
            if length
                .checked_sub(used)
                .ok_or(Error::InvalidDirectoryEntry)?
                >= needed
            {
                let insert_offset = offset.checked_add(used).ok_or(Error::ArithmeticOverflow)?;
                if used != 0 {
                    let encoded = encode_record_length(used, self.bytes.len())?;
                    put_le_u16(
                        &mut self.bytes,
                        disk_offset(offset).checked_add_bytes(4)?,
                        encoded,
                    )?;
                }
                write_entry(
                    &mut self.bytes,
                    insert_offset,
                    length.checked_sub(used).ok_or(Error::ArithmeticOverflow)?,
                    entry,
                )?;
                self.refresh_leaf_checksum()?;
                return Ok(true);
            }
            offset = offset
                .checked_add(length)
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
            let record = decode_record_at(
                self.bytes
                    .get(..live_limit)
                    .ok_or(Error::InvalidDirectoryEntry)?,
                offset,
                self.encoding,
            )?;
            if let Some(entry) = record.entry.filter(|entry| entry.name() == name.bytes()) {
                let removed = entry.to_owned()?;
                put_le_u32(&mut self.bytes, disk_offset(offset), 0)?;
                self.refresh_leaf_checksum()?;
                return Ok(Some(removed));
            }
            offset = offset
                .checked_add(record.length)
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
        replacement: &DirectoryEntry,
    ) -> Result<Option<DirectoryEntry>> {
        replacement.require_encoding(self.encoding)?;
        if self.contains_name(replacement.name())? {
            return Err(Error::NameAlreadyExists);
        }

        let original = memory::copied_slice(&self.bytes)?;
        let Some(entry) = self.remove(old_name)? else {
            return Ok(None);
        };
        let renamed = self.insert(replacement)?;
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
            let record = decode_record_at(
                self.bytes
                    .get(..live_limit)
                    .ok_or(Error::InvalidDirectoryEntry)?,
                offset,
                self.encoding,
            )?;
            if let Some(entry) = record.entry.filter(|entry| entry.name() == name.bytes()) {
                let previous = entry.to_owned()?;
                put_le_u32(&mut self.bytes, disk_offset(offset), inode.as_u32())?;
                *self
                    .bytes
                    .get_mut(offset.checked_add(7).ok_or(Error::ArithmeticOverflow)?)
                    .ok_or(Error::InvalidDirectoryEntry)? = kind.to_raw();
                self.refresh_leaf_checksum()?;
                return Ok(Some(previous));
            }
            offset = offset
                .checked_add(record.length)
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

/// Decodes the full-block marker only in a 64 KiB directory block.
/// # Errors
/// Rejects truncated fields and full-block markers in smaller blocks.
fn read_record_length(bytes: &[u8], offset: usize) -> Result<usize> {
    let raw = le_u16(bytes, disk_offset(offset).checked_add_bytes(4)?)?;
    if matches!(raw, 0 | u16::MAX) {
        if bytes.len() == 65_536 {
            Ok(65_536)
        } else {
            Err(Error::InvalidDirectoryEntry)
        }
    } else {
        Ok(usize::from(raw))
    }
}

/// Encodes aligned byte lengths, including the 64 KiB full-block marker.
/// # Errors
/// Rejects lengths outside their containing block or the supported directory-block domain.
fn encode_record_length(length: usize, block_bytes: usize) -> Result<u16> {
    if length < DIRENT_HEADER_SIZE
        || !length.is_multiple_of(DIRENT_ALIGNMENT)
        || length > block_bytes
        || block_bytes > 65_536
    {
        return Err(Error::InvalidDirectoryEntry);
    }
    if length == 65_536 {
        Ok(u16::MAX)
    } else {
        checked_u16(length)
    }
}

/// Borrowed name representation tied to the immutable record bytes that established it.
#[derive(Clone, Copy, Debug)]
enum DirectoryEntryNameView<'bytes> {
    /// Ordinary record name, including dot entries.
    Unhashed(&'bytes [u8]),
    /// Ciphertext and the keyed comparison hash stored in the same validated record.
    EncryptedCasefold {
        /// Borrowed filename ciphertext.
        ciphertext: &'bytes [u8],
        /// Validated primary and secondary hash words.
        hash: DirectoryHash,
    },
}

/// Allocation-free live entry whose name and optional trailer have been bounded by its record.
#[derive(Clone, Copy, Debug)]
struct DirectoryEntryView<'bytes> {
    /// Referenced live inode.
    inode: InodeId,
    /// Validated borrowed name representation.
    name: DirectoryEntryNameView<'bytes>,
    /// On-disk file kind.
    kind: DirectoryEntryKind,
}
impl<'bytes> DirectoryEntryView<'bytes> {
    /// Borrows the complete stored name bytes.
    const fn name(self) -> &'bytes [u8] {
        match self.name {
            DirectoryEntryNameView::Unhashed(name) => name,
            DirectoryEntryNameView::EncryptedCasefold { ciphertext, .. } => ciphertext,
        }
    }
    /// Acquires ownership without changing the record's name/hash relation.
    /// # Errors
    /// Returns physical allocation failure while copying its name.
    fn to_owned(self) -> Result<DirectoryEntry> {
        let name = match self.name {
            DirectoryEntryNameView::Unhashed(name) => {
                DirectoryEntryName::Unhashed(Ext4Name::from_disk(name)?)
            }
            DirectoryEntryNameView::EncryptedCasefold { ciphertext, hash } => {
                DirectoryEntryName::EncryptedCasefold {
                    ciphertext: Ext4Name::from_disk(ciphertext)?,
                    hash,
                }
            }
        };
        Ok(DirectoryEntry {
            inode: self.inode,
            name,
            kind: self.kind,
        })
    }
}

/// One validated free or live record and the byte extent used to advance to its successor.
#[derive(Clone, Copy, Debug)]
struct DirectoryRecordView<'bytes> {
    /// Complete aligned record extent, including free space owned by a live entry.
    length: usize,
    /// Absence denotes an unallocated record with no live name or hash authority.
    entry: Option<DirectoryEntryView<'bytes>>,
}

/// Establishes record-local bounds before reading a live name or its keyed hash trailer.
/// # Errors
/// Rejects truncation, misalignment, malformed names, short ciphertext and reserved hash values.
fn decode_record_at(
    bytes: &[u8],
    offset: usize,
    encoding: DirectoryEntryEncoding,
) -> Result<DirectoryRecordView<'_>> {
    let length = read_record_length(bytes, offset)?;
    if length < DIRENT_HEADER_SIZE || !length.is_multiple_of(DIRENT_ALIGNMENT) {
        return Err(Error::InvalidDirectoryEntry);
    }
    let end = offset
        .checked_add(length)
        .ok_or(Error::ArithmeticOverflow)?;
    let record = bytes.get(offset..end).ok_or(Error::InvalidDirectoryEntry)?;
    let inode = le_u32(record, disk_offset(0))?;
    let name_len = usize::from(*record.get(6).ok_or(Error::InvalidDirectoryEntry)?);
    let name_end = DIRENT_HEADER_SIZE
        .checked_add(name_len)
        .ok_or(Error::ArithmeticOverflow)?;
    let name = record
        .get(DIRENT_HEADER_SIZE..name_end)
        .ok_or(Error::InvalidDirectoryEntry)?;
    if inode == 0 {
        return Ok(DirectoryRecordView {
            length,
            entry: None,
        });
    }
    if name.is_empty() {
        return Err(Error::InvalidName);
    }
    if encoding.record_len(name)? > length {
        return Err(Error::InvalidDirectoryEntry);
    }
    let name =
        if encoding == DirectoryEntryEncoding::EncryptedCasefold && !matches!(name, b"." | b"..") {
            let trailer = required_name_rec_len(name_len)?;
            DirectoryEntryNameView::EncryptedCasefold {
                ciphertext: name,
                hash: DirectoryHash::from_stored(
                    le_u32(record, disk_offset(trailer))?,
                    le_u32(record, disk_offset(trailer).checked_add_bytes(4)?)?,
                )?,
            }
        } else {
            DirectoryEntryNameView::Unhashed(name)
        };
    Ok(DirectoryRecordView {
        length,
        entry: Some(DirectoryEntryView {
            inode: InodeId::try_from(inode)?,
            name,
            kind: DirectoryEntryKind::from_raw(*record.get(7).ok_or(Error::InvalidDirectoryEntry)?),
        }),
    })
}

/// Owns one required live record using the same validation as leaf traversal and mutation.
/// # Errors
/// Rejects malformed or free records and propagates name allocation failure.
fn parse_live_entry_at(
    bytes: &[u8],
    offset: usize,
    encoding: DirectoryEntryEncoding,
) -> Result<DirectoryEntry> {
    decode_record_at(bytes, offset, encoding)?
        .entry
        .ok_or(Error::InvalidDirectoryEntry)?
        .to_owned()
}

/// Writes one ext4 directory record into a checked block slice.
/// # Errors
///
/// Returns an error when `rec_len` cannot hold the name payload, the record would exceed the block,
/// the name length is not representable, or any field write is out of range.
fn write_entry(
    bytes: &mut [u8],
    offset: usize,
    rec_len: usize,
    entry: &DirectoryEntry,
) -> Result<()> {
    let name = entry.name().bytes();
    // The record length is owned by the caller so existing free-space shape can
    // be preserved when inserting into a hole or splitting a live entry.
    let encoded_length = encode_record_length(rec_len, bytes.len())?;
    if rec_len < entry.encoded_len()?
        || offset
            .checked_add(rec_len)
            .ok_or(Error::ArithmeticOverflow)?
            > bytes.len()
    {
        return Err(Error::InvalidDirectoryEntry);
    }
    put_le_u32(bytes, disk_offset(offset), entry.inode().as_u32())?;
    put_le_u16(
        bytes,
        disk_offset(offset).checked_add_bytes(4)?,
        encoded_length,
    )?;
    *bytes
        .get_mut(offset.checked_add(6).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::InvalidDirectoryEntry)? =
        u8::try_from(name.len()).map_err(|_| Error::InvalidName)?;
    *bytes
        .get_mut(offset.checked_add(7).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::InvalidDirectoryEntry)? = entry.kind().to_raw();
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
            .checked_add(rec_len)
            .ok_or(Error::ArithmeticOverflow)?
    {
        bytes
            .get_mut(
                name_end
                    ..offset
                        .checked_add(rec_len)
                        .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::InvalidDirectoryEntry)?
            .fill(0);
    }
    if let Some(hash) = entry.stored_hash() {
        let trailer = offset
            .checked_add(required_name_rec_len(name.len())?)
            .ok_or(Error::ArithmeticOverflow)?;
        put_le_u32(bytes, disk_offset(trailer), hash.major)?;
        put_le_u32(
            bytes,
            disk_offset(trailer).checked_add_bytes(4)?,
            hash.minor,
        )?;
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

/// Converts an index count or limit into its on-disk field.
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

    /// # Errors
    /// Returns fixture allocation or record operation failure.
    /// # Panics
    /// Fails if aligned trailer words or complete stored name/hash relations are changed.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "literal on-disk vectors independently observe trailer offsets and mutation preservation"
    )]
    fn encrypted_casefold_records_preserve_keyed_hashes() -> Result<()> {
        let encoding = DirectoryEntryEncoding::EncryptedCasefold;
        let mut bytes = memory::repeated_vec(0, 128)?;
        memory::copy_exact(
            bytes.get_mut(..8).ok_or(Error::InvalidDirectoryEntry)?,
            &[12, 0, 0, 0, 128, 0, 17, 1],
        )?;
        memory::copy_exact(
            bytes.get_mut(8..25).ok_or(Error::InvalidDirectoryEntry)?,
            b"0123456789ABCDEF!",
        )?;
        let trailer = [0x78, 0x56, 0x34, 0x12, 0x01, 0xef, 0xcd, 0xab];
        memory::copy_exact(
            bytes.get_mut(28..36).ok_or(Error::InvalidDirectoryEntry)?,
            &trailer,
        )?;
        let mut block = DirectoryBlock::new(bytes, DirectoryChecksum::None, encoding);
        let entry = block.entries()?.pop().ok_or(Error::InvalidDirectoryEntry)?;
        assert_eq!(
            entry.stored_hash(),
            Some(DirectoryHash {
                major: 0x1234_5678,
                minor: 0xabcd_ef01
            })
        );
        assert_eq!(entry.encoded_len()?, 36);
        let second = DirectoryEntry::encrypted_casefold(
            inode(13)?,
            &Ext4Name::from_disk(b"SECONDciphertext!")?,
            DirectoryEntryKind::File,
            DirectoryHash {
                major: 0x1020_3040,
                minor: 7,
            },
        )?;
        assert!(block.insert(&second)?);
        assert_eq!(read_record_length(block.bytes(), 0)?, 36);
        assert_eq!(block.bytes().get(28..36), Some(trailer.as_slice()));
        let previous = block
            .replace(entry.name(), inode(14)?, DirectoryEntryKind::Symlink)?
            .ok_or(Error::DirectoryEntryNotFound)?;
        assert_eq!(previous, entry);
        assert_eq!(block.bytes().get(28..36), Some(trailer.as_slice()));
        let renamed = DirectoryEntry::encrypted_casefold(
            inode(14)?,
            &Ext4Name::from_disk(b"renamedciphertextbytes")?,
            DirectoryEntryKind::Symlink,
            DirectoryHash {
                major: 0xa0b0_c0d0,
                minor: 0x0bad_f00d,
            },
        )?;
        let removed = block
            .rename(entry.name(), &renamed)?
            .ok_or(Error::DirectoryEntryNotFound)?;
        assert_eq!(removed.stored_hash(), entry.stored_hash());
        assert_eq!(removed.inode(), inode(14)?);
        let entries = block.entries()?;
        assert!(entries.contains(&second));
        assert!(entries.contains(&renamed));
        let mut rebuilt =
            DirectoryBlock::from_entries(128, DirectoryChecksum::None, &entries, encoding)?;
        assert_eq!(rebuilt.remove(renamed.name())?, Some(renamed));
        assert_eq!(rebuilt.remove(second.name())?, Some(second));
        assert!(rebuilt.entries()?.is_empty());
        let mut dots = DirectoryBlock::empty(128, DirectoryChecksum::None, encoding)?;
        dots.initialize_dot_entries(inode(2)?, inode(2)?)?;
        assert!(
            dots.entries()?
                .iter()
                .all(|entry| entry.stored_hash().is_none())
        );
        assert!(dots.insert(&entry)?);
        assert_eq!(dots.entries()?.len(), 3);
        assert!(
            DirectoryBlock::from_entries(
                128,
                DirectoryChecksum::None,
                &[entry],
                DirectoryEntryEncoding::Standard
            )
            .is_err()
        );
        assert!(
            dots.insert(&DirectoryEntry::new(
                inode(20)?,
                &Ext4Name::new(b"hashlessciphertext")?,
                DirectoryEntryKind::File
            )?)
            .is_err()
        );
        Ok(())
    }

    /// # Errors
    /// Returns fixture encoding or allocation failure.
    /// # Panics
    /// Fails if a name-only bound admits a trailer outside the same record or checksums omit it.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "malformed independent vectors exercise record-local trailer bounds and checksum coverage"
    )]
    fn encrypted_casefold_trailers_require_complete_record_bounds() -> Result<()> {
        let encoding = DirectoryEntryEncoding::EncryptedCasefold;
        for (name_len, rec_len, major) in [
            (17, 28, 0x1234_5678),
            (15, 32, 0x1234_5678),
            (17, 40, 3),
            (17, 40, 0xffff_fffe),
        ] {
            let mut bytes = memory::repeated_vec(0x61, 40)?;
            put_le_u32(&mut bytes, disk_offset(0), 12)?;
            put_le_u16(&mut bytes, disk_offset(4), rec_len)?;
            *bytes.get_mut(6).ok_or(Error::InvalidDirectoryEntry)? = name_len;
            *bytes.get_mut(7).ok_or(Error::InvalidDirectoryEntry)? = 1;
            put_le_u32(&mut bytes, disk_offset(28), major)?;
            assert!(decode_record_at(&bytes, 0, encoding).is_err());
        }
        let checksum = DirectoryChecksum::metadata_csum(ChecksumSeed::from_u32(7), inode(2)?, 0);
        let entry = DirectoryEntry::encrypted_casefold(
            inode(12)?,
            &Ext4Name::from_disk(b"0123456789ABCDEF!")?,
            DirectoryEntryKind::File,
            DirectoryHash {
                major: 0x1234_5678,
                minor: 1,
            },
        )?;
        let mut bytes =
            DirectoryBlock::from_entries(128, checksum, &[entry], encoding)?.into_bytes();
        *bytes.get_mut(28).ok_or(Error::InvalidDirectoryEntry)? ^= 2;
        assert_eq!(
            DirectoryBlock::new(bytes, checksum, encoding).entries(),
            Err(Error::ChecksumMismatch)
        );
        Ok(())
    }

    /// # Errors
    /// Returns fixture allocation, parsing or mutation failure.
    /// # Panics
    /// Fails if independent full-block wire markers lose their byte-length meaning.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions compare independently encoded disk fields with directory behavior"
    )]
    fn full_block_dirents_support_64k_read_and_mutation() -> Result<()> {
        for marker in [0_u16, u16::MAX] {
            let mut bytes = memory::repeated_vec(0, 65_536)?;
            put_le_u16(&mut bytes, disk_offset(4), marker)?;
            let mut block = DirectoryBlock::new(
                bytes,
                DirectoryChecksum::None,
                DirectoryEntryEncoding::Standard,
            );
            assert!(block.entries()?.is_empty());
            assert!(block.records()?.is_empty());
            let name = Ext4Name::new(b"file")?;
            assert!(block.insert(&DirectoryEntry::new(
                inode(12)?,
                &name,
                DirectoryEntryKind::File
            )?)?);
            assert_eq!(
                block
                    .entries()?
                    .into_iter()
                    .find(|entry| entry.name() == &name)
                    .map(|entry| entry.inode()),
                Some(inode(12)?)
            );
            assert!(block.insert(&DirectoryEntry::new(
                inode(13)?,
                &Ext4Name::new(b"second")?,
                DirectoryEntryKind::File
            )?)?);
            assert_eq!(block.records()?.len(), 2);
            assert!(block.remove(&name)?.is_some());
        }
        let mut block = DirectoryBlock::empty(
            65_536,
            DirectoryChecksum::None,
            DirectoryEntryEncoding::Standard,
        )?;
        block.initialize_free_space()?;
        assert_eq!(le_u16(block.bytes(), disk_offset(4))?, u16::MAX);
        let mut routes = Vec::new();
        routes.try_push(DxEntry::new(0, 1)?)?;
        let index = DxIndex::from_routes(
            dx_capacity(65_536, DX_NODE_COUNT_OFFSET, DirectoryChecksum::None)?,
            routes,
        )?;
        let mut bytes = memory::repeated_vec(0, 65_536)?;
        write_htree_node(&mut bytes, &index, DirectoryChecksum::None)?;
        assert_eq!(
            DxIndex::parse_node(&bytes, DirectoryChecksum::None)?.len(),
            1
        );
        let small = memory::repeated_vec(0, 4096)?;
        assert!(DirectoryEntry::parse_all(&small, DirectoryEntryEncoding::Standard).is_err());
        Ok(())
    }

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
            HtreeRoot::parse(
                &root,
                directory_inode,
                seed,
                DirectoryHashSignedness::Signed,
                0,
                DirectoryChecksum::None,
            )
            .is_ok()
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
                DirectoryHashSignedness::Signed,
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
            HtreeRoot::parse(
                &reserved,
                directory_inode,
                seed,
                DirectoryHashSignedness::Signed,
                1,
                DirectoryChecksum::None,
            ),
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
                DirectoryHashSignedness::Signed,
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
                DirectoryHashSignedness::Signed,
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
        assert!(
            HtreeRoot::parse(
                &root,
                directory_inode,
                seed,
                DirectoryHashSignedness::Signed,
                0,
                checksum
            )
            .is_ok()
        );
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
            HtreeRoot::parse(
                &root,
                directory_inode,
                seed,
                DirectoryHashSignedness::Signed,
                0,
                checksum
            ),
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
        assert!(
            HtreeRoot::parse(
                &root,
                directory_inode,
                seed,
                DirectoryHashSignedness::Signed,
                0,
                checksum
            )
            .is_ok()
        );

        let Some(reserved) = root.get_mut(tail_offset) else {
            return;
        };
        *reserved ^= 1;
        assert_eq!(
            HtreeRoot::parse(
                &root,
                directory_inode,
                seed,
                DirectoryHashSignedness::Signed,
                0,
                checksum
            ),
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
        let hash = DirectoryHashScheme::from_metadata(
            DirectoryHashSeed::from_words([1, 2, 3, 4]),
            DirectoryHashVersion::HalfMd4,
            DirectoryHashSignedness::Signed,
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
            if hash.hash(first.name().bytes()).major < hash.hash(second.name().bytes()).major {
                (first, second)
            } else {
                (second, first)
            };
        let upper = hash.hash(upper_entry.name().bytes()).major;

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
        assert!(
            range
                .validate_leaf(
                    &[lower_clone],
                    hash,
                    super::super::name::NameSemantics::Bytewise
                )
                .is_ok()
        );
        let Some(upper_clone) = test_value(upper_entry.try_clone()) else {
            return;
        };
        assert_eq!(
            range.validate_leaf(
                &[upper_clone],
                hash,
                super::super::name::NameSemantics::Bytewise
            ),
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
                .and_then(|range| range.validate_leaf(
                    &[upper_entry],
                    hash,
                    super::super::name::NameSemantics::Bytewise
                ))
                .is_ok()
        );
    }
}
