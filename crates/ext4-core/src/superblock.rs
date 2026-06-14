//! Superblock parsing and mount-policy validation.

use crate::block::{BlockReader, BlockSize, ByteOffset};
use crate::endian::{le_u16, le_u32};
use crate::error::{Error, Result};

const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_SIZE: usize = 1024;
const EXT4_SUPER_MAGIC: u16 = 0xEF53;
const EXT4_VALID_FS: u16 = 0x0001;

const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const SUPPORTED_INCOMPAT: u32 = INCOMPAT_FILETYPE | INCOMPAT_EXTENTS;

const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
const RO_COMPAT_HUGE_FILE: u32 = 0x0008;
const RO_COMPAT_DIR_NLINK: u32 = 0x0020;
const RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
const SUPPORTED_RO_COMPAT: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE;

/// Validated ext4 feature flags accepted by the v1 read-only mount policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureSet {
    compat: u32,
    incompat: u32,
    read_only_compat: u32,
}

impl FeatureSet {
    /// Validates raw superblock feature flags.
    ///
    /// # Errors
    /// Returns an error when the advertised feature set is outside the v1
    /// conservative read-only mount policy.
    pub fn validate(compat: u32, incompat: u32, read_only_compat: u32) -> Result<Self> {
        if incompat & !SUPPORTED_INCOMPAT != 0 {
            return Err(Error::UnsupportedIncompatFeature);
        }
        if read_only_compat & !SUPPORTED_RO_COMPAT != 0 {
            return Err(Error::UnsupportedReadOnlyFeature);
        }
        if incompat & INCOMPAT_EXTENTS == 0 {
            return Err(Error::UnsupportedIncompatFeature);
        }
        Ok(Self {
            compat,
            incompat,
            read_only_compat,
        })
    }

    /// Raw compatible feature flags.
    #[must_use]
    pub const fn compat(self) -> u32 {
        self.compat
    }

    /// Raw incompatible feature flags.
    #[must_use]
    pub const fn incompat(self) -> u32 {
        self.incompat
    }

    /// Raw read-only-compatible feature flags.
    #[must_use]
    pub const fn read_only_compat(self) -> u32 {
        self.read_only_compat
    }
}

/// Superblock whose structural fields and mount policy are validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
    block_size: BlockSize,
    inode_count: u32,
    block_count: u32,
    first_data_block: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    first_inode: u32,
    features: FeatureSet,
}

impl Superblock {
    /// Reads and validates the primary ext4 superblock from a block device.
    ///
    /// # Errors
    /// Returns an error when the primary superblock cannot be read or does not
    /// satisfy the clean v1 mount policy.
    pub fn read_from(device: &impl BlockReader) -> Result<Self> {
        let mut raw = [0_u8; SUPERBLOCK_SIZE];
        device.read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)?;
        Self::parse(&raw)
    }

    /// Parses and validates a 1024-byte superblock payload.
    ///
    /// # Errors
    /// Returns an error when the payload is truncated, has invalid ext4 magic,
    /// is dirty, advertises unsupported features, or contains invalid geometry.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < SUPERBLOCK_SIZE {
            return Err(Error::TruncatedStructure);
        }
        if le_u16(raw, 56)? != EXT4_SUPER_MAGIC {
            return Err(Error::InvalidMagic);
        }
        if le_u16(raw, 58)? & EXT4_VALID_FS == 0 {
            return Err(Error::DirtyVolume);
        }

        let inode_count = le_u32(raw, 0)?;
        let block_count = le_u32(raw, 4)?;
        let first_data_block = le_u32(raw, 20)?;
        let block_size = BlockSize::from_superblock_log(le_u32(raw, 24)?)?;
        let blocks_per_group = le_u32(raw, 32)?;
        let inodes_per_group = le_u32(raw, 40)?;
        let first_inode = le_u32(raw, 84)?;
        let inode_size = le_u16(raw, 88)?;
        let features = FeatureSet::validate(le_u32(raw, 92)?, le_u32(raw, 96)?, le_u32(raw, 100)?)?;

        if inode_count == 0
            || block_count == 0
            || blocks_per_group == 0
            || inodes_per_group == 0
            || inode_size < 128
            || u32::from(inode_size) > block_size.bytes()
        {
            return Err(Error::InvalidSuperblock);
        }

        Ok(Self {
            block_size,
            inode_count,
            block_count,
            first_data_block,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            first_inode,
            features,
        })
    }

    /// Validated block size.
    #[must_use]
    pub const fn block_size(self) -> BlockSize {
        self.block_size
    }

    /// Total inodes recorded by the superblock.
    #[must_use]
    pub const fn inode_count(self) -> u32 {
        self.inode_count
    }

    /// Total low 32-bit block count.
    #[must_use]
    pub const fn block_count(self) -> u32 {
        self.block_count
    }

    /// First data block.
    #[must_use]
    pub const fn first_data_block(self) -> u32 {
        self.first_data_block
    }

    /// Blocks per block group.
    #[must_use]
    pub const fn blocks_per_group(self) -> u32 {
        self.blocks_per_group
    }

    /// Inodes per block group.
    #[must_use]
    pub const fn inodes_per_group(self) -> u32 {
        self.inodes_per_group
    }

    /// Inode record size in bytes.
    #[must_use]
    pub const fn inode_size(self) -> u16 {
        self.inode_size
    }

    /// First non-reserved inode.
    #[must_use]
    pub const fn first_inode(self) -> u32 {
        self.first_inode
    }

    /// Validated feature set.
    #[must_use]
    pub const fn features(self) -> FeatureSet {
        self.features
    }

    /// Number of block groups implied by the superblock.
    ///
    /// # Errors
    /// Returns an error when validated geometry cannot be combined without
    /// overflow.
    pub fn block_group_count(self) -> Result<u32> {
        let data_blocks = self
            .block_count
            .checked_sub(self.first_data_block)
            .ok_or(Error::InvalidSuperblock)?;
        let numerator = data_blocks
            .checked_add(
                self.blocks_per_group
                    .checked_sub(1)
                    .ok_or(Error::InvalidSuperblock)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        numerator
            .checked_div(self.blocks_per_group)
            .ok_or(Error::InvalidSuperblock)
    }
}
