//! Inode parsing and domain typing.

use crate::endian::{le_u16, le_u32};
use crate::error::{Error, Result};

/// Mask selecting file-type bits from `i_mode`.
const MODE_KIND_MASK: u16 = 0xF000;
/// ext4 directory file-type bits in `i_mode`.
const MODE_DIRECTORY: u16 = 0x4000;
/// ext4 regular-file file-type bits in `i_mode`.
const MODE_REGULAR: u16 = 0x8000;
/// ext4 symlink file-type bits in `i_mode`.
const MODE_SYMLINK: u16 = 0xA000;
/// Low UID field offset inside an inode record.
const INODE_UID_LO_OFFSET: usize = 2;
/// Low GID field offset inside an inode record.
const INODE_GID_LO_OFFSET: usize = 24;
/// High UID field offset inside a large inode record.
const INODE_UID_HI_OFFSET: usize = 120;
/// High GID field offset inside a large inode record.
const INODE_GID_HI_OFFSET: usize = 122;
/// Inode flag selecting extent-based data mapping.
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
/// Inode flag selecting indexed directory data.
const EXT4_INDEX_FL: u32 = 0x0000_1000;
/// Inode flag rejecting write-domain mutation.
const EXT4_IMMUTABLE_FL: u32 = 0x0000_0010;
/// Inode flag rejecting non-append mutation.
const EXT4_APPEND_FL: u32 = 0x0000_0020;
/// Inode flag rejected because encrypted payload interpretation is unsupported.
const EXT4_ENCRYPT_FL: u32 = 0x0000_0800;
/// Inode flag rejected for write-domain mutation of inline-data files.
const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;
/// Inode flag rejected because casefolded lookup semantics are unsupported.
const EXT4_CASEFOLD_FL: u32 = 0x4000_0000;
/// Permission and special-mode bits allowed apart from the inode file type.
const PERMISSION_BITS: u16 = 0o7777;

/// Byte offset inside a regular file or symlink payload.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileOffset(u64);

impl FileOffset {
    /// First byte in a file.
    pub const ZERO: Self = Self(0);

    /// Creates a file offset from a byte count.
    #[must_use]
    pub const fn from_bytes(value: u64) -> Self {
        Self(value)
    }

    /// Returns the offset in bytes for on-disk extent arithmetic.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// Adds a byte length to this offset.
    ///
    /// # Errors
    /// Returns an error when the resulting offset would overflow.
    pub fn checked_add_len(self, len: usize) -> Result<Self> {
        Ok(Self(
            self.0
                .checked_add(u64::try_from(len).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?,
        ))
    }
}

/// Size of a regular file or symlink payload in bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileSize(u64);

impl FileSize {
    /// Creates a file size from bytes parsed at an on-disk boundary.
    #[must_use]
    pub const fn from_bytes(value: u64) -> Self {
        Self(value)
    }

    /// Returns the size in bytes for on-disk encoding boundaries.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// Converts the size to `usize`.
    ///
    /// # Errors
    /// Returns an error when the size cannot be represented on this host.
    pub fn to_usize(self) -> Result<usize> {
        usize::try_from(self.0).map_err(|_| Error::ArithmeticOverflow)
    }

    /// Returns the byte distance from an offset to EOF.
    ///
    /// # Errors
    /// Returns an error when the offset is beyond EOF.
    pub fn remaining_from(self, offset: FileOffset) -> Result<u64> {
        self.0
            .checked_sub(offset.bytes())
            .ok_or(Error::ArithmeticOverflow)
    }
}

/// Number of bytes read into a caller buffer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadBytes(usize);

impl ReadBytes {
    /// Creates a read length from a completed buffer copy count.
    #[must_use]
    pub const fn from_usize(value: usize) -> Self {
        Self(value)
    }

    /// Returns the completed read byte count.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

/// Ext4 inode timestamp supplied by the caller at a mutation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Timestamp {
    /// Low 32-bit Unix seconds stored by ext4 timestamp fields.
    seconds: u32,
}

impl Ext4Timestamp {
    /// Creates an ext4 timestamp from low 32-bit Unix seconds.
    #[must_use]
    pub const fn from_unix_seconds(seconds: u32) -> Self {
        Self { seconds }
    }

    /// Returns the low 32-bit Unix seconds stored in this timestamp.
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.seconds
    }
}

/// Low 32-bit ext4 UID used at inode creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Uid(u32);

impl Ext4Uid {
    /// Creates an ext4 uid.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the uid for inode encoding.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Low 32-bit ext4 GID used at inode creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Gid(u32);

impl Ext4Gid {
    /// Creates an ext4 gid.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the gid for inode encoding.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Ext4 inode owner supplied at a creation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Owner {
    /// Low 32-bit user id.
    uid: Ext4Uid,
    /// Low 32-bit group id.
    gid: Ext4Gid,
}

impl Ext4Owner {
    /// Creates an ext4 owner.
    #[must_use]
    pub const fn new(uid: Ext4Uid, gid: Ext4Gid) -> Self {
        Self { uid, gid }
    }

    /// UID component.
    #[must_use]
    pub const fn uid(self) -> Ext4Uid {
        self.uid
    }

    /// GID component.
    #[must_use]
    pub const fn gid(self) -> Ext4Gid {
        self.gid
    }
}

/// Permission and special mode bits without an inode file type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Permissions(u16);

impl Ext4Permissions {
    /// Creates permission bits for a newly allocated inode.
    ///
    /// # Errors
    /// Returns an error when file-type bits are present.
    pub fn new(value: u16) -> Result<Self> {
        if value & !PERMISSION_BITS != 0 {
            Err(Error::InvalidInode)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns permission bits for inode encoding.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// POSIX security state representable in ext4 inode owner and mode fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Security {
    /// Owner encoded in uid/gid fields.
    owner: Ext4Owner,
    /// Permission and special mode bits without file type bits.
    permissions: Ext4Permissions,
}

impl Ext4Security {
    /// Creates representable ext4 security state.
    #[must_use]
    pub const fn new(owner: Ext4Owner, permissions: Ext4Permissions) -> Self {
        Self { owner, permissions }
    }

    /// Owner component.
    #[must_use]
    pub const fn owner(self) -> Ext4Owner {
        self.owner
    }

    /// Permission component.
    #[must_use]
    pub const fn permissions(self) -> Ext4Permissions {
        self.permissions
    }
}

/// Metadata required to create a regular file inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewFileMetadata {
    /// Owner encoded into the new inode.
    owner: Ext4Owner,
    /// Permission bits encoded with the regular-file mode.
    permissions: Ext4Permissions,
}

impl NewFileMetadata {
    /// Creates regular file metadata.
    #[must_use]
    pub const fn new(owner: Ext4Owner, permissions: Ext4Permissions) -> Self {
        Self { owner, permissions }
    }

    /// Owner for the new inode.
    #[must_use]
    pub const fn owner(self) -> Ext4Owner {
        self.owner
    }

    /// Permission bits for the new inode.
    #[must_use]
    pub const fn permissions(self) -> Ext4Permissions {
        self.permissions
    }
}

/// Metadata required to create a directory inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewDirectoryMetadata {
    /// Owner encoded into the new inode.
    owner: Ext4Owner,
    /// Permission bits encoded with the directory mode.
    permissions: Ext4Permissions,
}

impl NewDirectoryMetadata {
    /// Creates directory metadata.
    #[must_use]
    pub const fn new(owner: Ext4Owner, permissions: Ext4Permissions) -> Self {
        Self { owner, permissions }
    }

    /// Owner for the new inode.
    #[must_use]
    pub const fn owner(self) -> Ext4Owner {
        self.owner
    }

    /// Permission bits for the new inode.
    #[must_use]
    pub const fn permissions(self) -> Ext4Permissions {
        self.permissions
    }
}

/// Stable ext4 inode identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InodeId(u32);

impl InodeId {
    /// Root directory inode.
    pub const ROOT: Self = Self(2);

    /// Returns the raw inode number for on-disk encoding boundaries.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for InodeId {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        if value == 0 {
            Err(Error::InvalidInode)
        } else {
            Ok(Self(value))
        }
    }
}

/// Inode node kind accepted by the ext4 core domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InodeKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// Typed representation of an inode's data pointer area.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InodeStorage {
    /// Extent root stored in `i_block`.
    Extents(InodeExtentRoot),
    /// Inline bytes stored directly in `i_block`.
    InlineBytes(InodeInlineBytes),
    /// A legacy block map unsupported by this implementation.
    UnsupportedBlockMap,
}

/// Raw extent root bytes isolated behind an inode-storage type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InodeExtentRoot {
    /// Exact `i_block` bytes when the inode has the extents flag.
    bytes: [u8; 60],
}

impl InodeExtentRoot {
    /// Creates an extent root from the 60-byte inode storage field.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 60]) -> Self {
        Self { bytes }
    }

    /// Returns the encoded extent root for the extent parser boundary.
    #[must_use]
    pub(crate) const fn bytes(&self) -> &[u8; 60] {
        &self.bytes
    }
}

/// Inline bytes isolated behind an inode-storage type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InodeInlineBytes {
    /// Exact `i_block` bytes when a symlink payload is stored inline.
    bytes: [u8; 60],
}

impl InodeInlineBytes {
    /// Creates inline bytes from the 60-byte inode storage field.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 60]) -> Self {
        Self { bytes }
    }

    /// Returns the inline prefix with the requested file size.
    ///
    /// # Errors
    /// Returns an error when the requested file size is larger than inline storage.
    pub fn prefix(&self, size: FileSize) -> Result<&[u8]> {
        self.bytes
            .get(..size.to_usize()?)
            .ok_or(Error::TruncatedStructure)
    }
}

/// Parsed ext4 inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inode {
    /// Stable inode number used by directory entries and checksum seeds.
    id: InodeId,
    /// Supported inode kind selected from `i_mode`.
    kind: InodeKind,
    /// Combined low/high inode size.
    size: FileSize,
    /// POSIX security state parsed from owner and mode fields.
    security: Ext4Security,
    /// Raw link count used by directory removal checks.
    links_count: u16,
    /// Raw inode flags kept for capability predicates.
    flags: u32,
    /// Inode generation used by metadata checksums.
    generation: u32,
    /// Typed interpretation of the 60-byte `i_block` field.
    storage: InodeStorage,
}

impl Inode {
    /// Parses a single inode record.
    ///
    /// # Errors
    /// Returns an error when the inode record is truncated or has an unsupported
    /// inode kind.
    pub fn parse(id: InodeId, raw: &[u8]) -> Result<Self> {
        if raw.len() < 128 {
            return Err(Error::TruncatedStructure);
        }
        let mode = le_u16(raw, 0)?;
        let permissions = Ext4Permissions::new(mode & PERMISSION_BITS)?;
        let owner = Ext4Owner::new(
            Ext4Uid::from_u32(parse_uid(raw)?),
            Ext4Gid::from_u32(parse_gid(raw)?),
        );
        let kind = match mode & MODE_KIND_MASK {
            MODE_REGULAR => InodeKind::File,
            MODE_DIRECTORY => InodeKind::Directory,
            MODE_SYMLINK => InodeKind::Symlink,
            _ => return Err(Error::WrongInodeKind),
        };
        let size =
            FileSize::from_bytes(u64::from(le_u32(raw, 4)?) | (u64::from(le_u32(raw, 108)?) << 32));
        let links_count = le_u16(raw, 26)?;
        let flags = le_u32(raw, 32)?;
        let generation = le_u32(raw, 100)?;
        let block_slice = raw.get(40..100).ok_or(Error::TruncatedStructure)?;
        let mut block = [0_u8; 60];
        block.copy_from_slice(block_slice);
        let storage = if flags & EXT4_EXTENTS_FL != 0 {
            InodeStorage::Extents(InodeExtentRoot::from_bytes(block))
        } else if kind == InodeKind::Symlink && size.to_usize()? <= block.len() {
            InodeStorage::InlineBytes(InodeInlineBytes::from_bytes(block))
        } else {
            InodeStorage::UnsupportedBlockMap
        };
        Ok(Self {
            id,
            kind,
            size,
            security: Ext4Security::new(owner, permissions),
            links_count,
            flags,
            generation,
            storage,
        })
    }

    /// Inode identifier.
    #[must_use]
    pub const fn id(&self) -> InodeId {
        self.id
    }

    /// Node kind.
    #[must_use]
    pub const fn kind(&self) -> InodeKind {
        self.kind
    }

    /// File size in bytes.
    #[must_use]
    pub const fn size(&self) -> FileSize {
        self.size
    }

    /// POSIX security state parsed from owner and mode fields.
    #[must_use]
    pub const fn security(&self) -> Ext4Security {
        self.security
    }

    /// POSIX owner parsed from uid/gid fields.
    #[must_use]
    pub const fn owner(&self) -> Ext4Owner {
        self.security.owner()
    }

    /// Permission bits parsed from `i_mode` without file-type bits.
    #[must_use]
    pub const fn permissions(&self) -> Ext4Permissions {
        self.security.permissions()
    }

    /// Raw link count.
    #[must_use]
    pub const fn links_count(&self) -> u16 {
        self.links_count
    }

    /// Inode generation used by metadata checksums.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Returns true when this directory uses htree indexes.
    #[must_use]
    pub fn is_indexed_directory(&self) -> bool {
        self.kind == InodeKind::Directory && self.flags & EXT4_INDEX_FL != 0
    }

    /// Returns true when the inode can be changed by the write domain.
    #[must_use]
    pub const fn supports_basic_mutation(&self) -> bool {
        self.flags
            & (EXT4_IMMUTABLE_FL
                | EXT4_APPEND_FL
                | EXT4_ENCRYPT_FL
                | EXT4_INLINE_DATA_FL
                | EXT4_CASEFOLD_FL)
            == 0
    }

    /// Data storage selected by inode flags and node kind.
    #[must_use]
    pub const fn storage(&self) -> &InodeStorage {
        &self.storage
    }

    /// Returns the extent root when this inode uses extents.
    ///
    /// # Errors
    /// Returns an error when this inode uses an unsupported block map or inline storage.
    pub fn extent_root(&self) -> Result<&InodeExtentRoot> {
        match &self.storage {
            InodeStorage::Extents(root) => Ok(root),
            InodeStorage::InlineBytes(_) | InodeStorage::UnsupportedBlockMap => {
                Err(Error::UnsupportedBlockMap)
            }
        }
    }

    /// Returns inline bytes when this inode stores data directly in `i_block`.
    ///
    /// # Errors
    /// Returns an error when this inode uses extents or an unsupported block map.
    pub fn inline_bytes(&self) -> Result<&InodeInlineBytes> {
        match &self.storage {
            InodeStorage::InlineBytes(bytes) => Ok(bytes),
            InodeStorage::Extents(_) | InodeStorage::UnsupportedBlockMap => {
                Err(Error::UnsupportedBlockMap)
            }
        }
    }
}

/// Combines the low and optional high inode UID fields.
fn parse_uid(raw: &[u8]) -> Result<u32> {
    let low = u32::from(le_u16(raw, INODE_UID_LO_OFFSET)?);
    let high_offset_end = INODE_UID_HI_OFFSET
        .checked_add(2)
        .ok_or(Error::ArithmeticOverflow)?;
    let high = if raw.len() >= high_offset_end {
        u32::from(le_u16(raw, INODE_UID_HI_OFFSET)?) << 16
    } else {
        0
    };
    Ok(low | high)
}

/// Combines the low and optional high inode GID fields.
fn parse_gid(raw: &[u8]) -> Result<u32> {
    let low = u32::from(le_u16(raw, INODE_GID_LO_OFFSET)?);
    let high_offset_end = INODE_GID_HI_OFFSET
        .checked_add(2)
        .ok_or(Error::ArithmeticOverflow)?;
    let high = if raw.len() >= high_offset_end {
        u32::from(le_u16(raw, INODE_GID_HI_OFFSET)?) << 16
    } else {
        0
    };
    Ok(low | high)
}
