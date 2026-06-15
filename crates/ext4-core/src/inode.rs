//! Inode parsing and domain typing.

use crate::endian::{le_u16, le_u32};
use crate::error::{Error, Result};

const MODE_KIND_MASK: u16 = 0xF000;
const MODE_DIRECTORY: u16 = 0x4000;
const MODE_REGULAR: u16 = 0x8000;
const MODE_SYMLINK: u16 = 0xA000;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

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
    id: InodeId,
    kind: InodeKind,
    size: FileSize,
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
        let kind = match mode & MODE_KIND_MASK {
            MODE_REGULAR => InodeKind::File,
            MODE_DIRECTORY => InodeKind::Directory,
            MODE_SYMLINK => InodeKind::Symlink,
            _ => return Err(Error::WrongInodeKind),
        };
        let size =
            FileSize::from_bytes(u64::from(le_u32(raw, 4)?) | (u64::from(le_u32(raw, 108)?) << 32));
        let flags = le_u32(raw, 32)?;
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
