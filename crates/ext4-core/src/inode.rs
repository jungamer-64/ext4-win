//! Inode parsing and domain typing.

use crate::endian::{le_u16, le_u32};
use crate::error::{Error, Result};

const MODE_KIND_MASK: u16 = 0xF000;
const MODE_DIRECTORY: u16 = 0x4000;
const MODE_REGULAR: u16 = 0x8000;
const MODE_SYMLINK: u16 = 0xA000;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

/// Stable ext4 inode identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InodeId(u32);

impl InodeId {
    /// Root directory inode.
    pub const ROOT: Self = Self(2);

    /// Creates an inode identifier.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw inode number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Inode node kind accepted by the read-only domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InodeKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// Parsed ext4 inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inode {
    id: InodeId,
    kind: InodeKind,
    mode: u16,
    size: u64,
    flags: u32,
    block: [u8; 60],
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
        let size = u64::from(le_u32(raw, 4)?) | (u64::from(le_u32(raw, 108)?) << 32);
        let flags = le_u32(raw, 32)?;
        let block_slice = raw.get(40..100).ok_or(Error::TruncatedStructure)?;
        let mut block = [0_u8; 60];
        block.copy_from_slice(block_slice);
        Ok(Self {
            id,
            kind,
            mode,
            size,
            flags,
            block,
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

    /// Raw mode bits.
    #[must_use]
    pub const fn mode(&self) -> u16 {
        self.mode
    }

    /// File size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Raw inode flags.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Raw `i_block` payload.
    #[must_use]
    pub const fn block(&self) -> &[u8; 60] {
        &self.block
    }

    /// Returns true when the inode uses extents.
    #[must_use]
    pub const fn has_extents(&self) -> bool {
        self.flags & EXT4_EXTENTS_FL != 0
    }
}
