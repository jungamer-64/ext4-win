//! Superblock parsing and mount-policy validation.

use crate::block::{BlockReader, BlockSize, ByteOffset};
use crate::checksum::verify_crc32c;
use crate::endian::{le_u16, le_u32};
use crate::error::{Error, Result};

const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_SIZE: usize = 1024;
const EXT4_SUPER_MAGIC: u16 = 0xEF53;
const EXT4_VALID_FS: u16 = 0x0001;

const COMPAT_HAS_JOURNAL: u32 = 0x0004;
const COMPAT_EXT_ATTR: u32 = 0x0008;
const COMPAT_RESIZE_INODE: u32 = 0x0010;
const COMPAT_DIR_INDEX: u32 = 0x0020;
const COMPAT_FAST_COMMIT: u32 = 0x0400;
const COMPAT_ORPHAN_FILE: u32 = 0x1000;

const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_RECOVER: u32 = 0x0004;
const INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const INCOMPAT_META_BG: u32 = 0x0010;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_MMP: u32 = 0x0100;
const INCOMPAT_FLEX_BG: u32 = 0x0200;
const INCOMPAT_EA_INODE: u32 = 0x0400;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INCOMPAT_ENCRYPT: u32 = 0x0001_0000;
const INCOMPAT_CASEFOLD: u32 = 0x0002_0000;
const SUPPORTED_READ_INCOMPAT: u32 =
    INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG;
const REQUIRED_WRITE_INCOMPAT: u32 =
    INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG;

const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
const RO_COMPAT_HUGE_FILE: u32 = 0x0008;
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
const RO_COMPAT_DIR_NLINK: u32 = 0x0020;
const RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
const RO_COMPAT_BIGALLOC: u32 = 0x0200;
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
const RO_COMPAT_READONLY: u32 = 0x1000;
const RO_COMPAT_PROJECT: u32 = 0x2000;
const RO_COMPAT_VERITY: u32 = 0x8000;
const RO_COMPAT_ORPHAN_PRESENT: u32 = 0x0001_0000;
const SUPPORTED_READ_RO_COMPAT: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_METADATA_CSUM
    | RO_COMPAT_READONLY
    | RO_COMPAT_PROJECT;
const REQUIRED_WRITE_COMPAT: u32 =
    COMPAT_HAS_JOURNAL | COMPAT_EXT_ATTR | COMPAT_RESIZE_INODE | COMPAT_DIR_INDEX;
const SUPPORTED_WRITE_COMPAT: u32 = REQUIRED_WRITE_COMPAT;
const REJECTED_WRITE_COMPAT: u32 = COMPAT_FAST_COMMIT | COMPAT_ORPHAN_FILE;
const REJECTED_WRITE_INCOMPAT: u32 = INCOMPAT_RECOVER
    | INCOMPAT_JOURNAL_DEV
    | INCOMPAT_META_BG
    | INCOMPAT_MMP
    | INCOMPAT_EA_INODE
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR
    | INCOMPAT_INLINE_DATA
    | INCOMPAT_ENCRYPT
    | INCOMPAT_CASEFOLD;
const REQUIRED_WRITE_RO_COMPAT: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_METADATA_CSUM;
const SUPPORTED_WRITE_RO_COMPAT: u32 = REQUIRED_WRITE_RO_COMPAT;
const REJECTED_WRITE_RO_COMPAT: u32 = RO_COMPAT_GDT_CSUM
    | RO_COMPAT_BIGALLOC
    | RO_COMPAT_READONLY
    | RO_COMPAT_VERITY
    | RO_COMPAT_ORPHAN_PRESENT;
const DEFAULT_64BIT_DESCRIPTOR_SIZE: u16 = 64;

/// Validated ext4 feature flags accepted by a mount policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureSet {
    compat: u32,
    incompat: u32,
    read_only_compat: u32,
}

impl FeatureSet {
    /// Validates raw superblock feature flags for read-only traversal.
    ///
    /// # Errors
    /// Returns an error when the advertised feature set is outside the
    /// read-only mount policy.
    pub fn read_only(compat: u32, incompat: u32, read_only_compat: u32) -> Result<Self> {
        if incompat & !SUPPORTED_READ_INCOMPAT != 0 {
            return Err(Error::UnsupportedIncompatFeature);
        }
        if read_only_compat & !SUPPORTED_READ_RO_COMPAT != 0 {
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

    /// Validates raw superblock feature flags for journaled read-write mode.
    ///
    /// # Errors
    /// Returns an error when required write features are absent or any
    /// unsupported write feature is present.
    pub fn read_write(compat: u32, incompat: u32, read_only_compat: u32) -> Result<Self> {
        if compat & REQUIRED_WRITE_COMPAT != REQUIRED_WRITE_COMPAT {
            return Err(Error::UnsupportedWriteFeature);
        }
        if compat & !SUPPORTED_WRITE_COMPAT != 0 {
            return Err(Error::UnsupportedWriteFeature);
        }
        if compat & REJECTED_WRITE_COMPAT != 0 {
            return Err(Error::UnsupportedWriteFeature);
        }
        if incompat & REQUIRED_WRITE_INCOMPAT != REQUIRED_WRITE_INCOMPAT {
            return Err(Error::UnsupportedWriteFeature);
        }
        if incompat & !REQUIRED_WRITE_INCOMPAT != 0 {
            return Err(Error::UnsupportedWriteFeature);
        }
        if incompat & REJECTED_WRITE_INCOMPAT != 0 {
            return Err(Error::UnsupportedWriteFeature);
        }
        if read_only_compat & REQUIRED_WRITE_RO_COMPAT != REQUIRED_WRITE_RO_COMPAT {
            return Err(Error::UnsupportedWriteFeature);
        }
        if read_only_compat & !SUPPORTED_WRITE_RO_COMPAT != 0 {
            return Err(Error::UnsupportedWriteFeature);
        }
        if read_only_compat & REJECTED_WRITE_RO_COMPAT != 0 {
            return Err(Error::UnsupportedWriteFeature);
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

    /// Returns true when the filesystem uses 64-bit block fields.
    #[must_use]
    pub const fn has_64bit(self) -> bool {
        self.incompat & INCOMPAT_64BIT != 0
    }

    /// Returns true when the filesystem has an internal journal.
    #[must_use]
    pub const fn has_journal(self) -> bool {
        self.compat & COMPAT_HAS_JOURNAL != 0
    }

    /// Returns true when metadata checksums are enabled.
    #[must_use]
    pub const fn has_metadata_csum(self) -> bool {
        self.read_only_compat & RO_COMPAT_METADATA_CSUM != 0
    }
}

/// Superblock whose structural fields and mount policy are validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
    block_size: BlockSize,
    inode_count: u32,
    block_count: u64,
    free_blocks_count: u64,
    first_data_block: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    first_inode: u32,
    descriptor_size: u16,
    journal_inode: u32,
    checksum_seed: u32,
    features: FeatureSet,
}

impl Superblock {
    /// Reads and validates the primary ext4 superblock from a block device for read-only mode.
    ///
    /// # Errors
    /// Returns an error when the primary superblock cannot be read or does not
    /// satisfy the clean v1 mount policy.
    pub fn read_from(device: &impl BlockReader) -> Result<Self> {
        let mut raw = [0_u8; SUPERBLOCK_SIZE];
        device.read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)?;
        Self::parse(&raw)
    }

    /// Reads and validates the primary ext4 superblock for read-write mode.
    ///
    /// # Errors
    /// Returns an error when the superblock cannot support journaled writes.
    pub fn read_write_from(device: &impl BlockReader) -> Result<Self> {
        let mut raw = [0_u8; SUPERBLOCK_SIZE];
        device.read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)?;
        Self::parse_read_write(&raw)
    }

    /// Parses and validates a 1024-byte superblock payload.
    ///
    /// # Errors
    /// Returns an error when the payload is truncated, has invalid ext4 magic,
    /// is dirty, advertises unsupported features, or contains invalid geometry.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        Self::parse_with_policy(raw, FeatureSet::read_only)
    }

    /// Parses and validates a 1024-byte superblock payload for read-write mode.
    ///
    /// # Errors
    /// Returns an error when the payload cannot support journaled writes.
    pub fn parse_read_write(raw: &[u8]) -> Result<Self> {
        Self::parse_with_policy(raw, FeatureSet::read_write)
    }

    fn parse_with_policy(
        raw: &[u8],
        validate_features: fn(u32, u32, u32) -> Result<FeatureSet>,
    ) -> Result<Self> {
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
        let block_count_lo = le_u32(raw, 4)?;
        let free_blocks_count_lo = le_u32(raw, 12)?;
        let first_data_block = le_u32(raw, 20)?;
        let block_size = BlockSize::from_superblock_log(le_u32(raw, 24)?)?;
        let blocks_per_group = le_u32(raw, 32)?;
        let inodes_per_group = le_u32(raw, 40)?;
        let first_inode = le_u32(raw, 84)?;
        let inode_size = le_u16(raw, 88)?;
        let features = validate_features(le_u32(raw, 92)?, le_u32(raw, 96)?, le_u32(raw, 100)?)?;
        let descriptor_size = if features.has_64bit() {
            let raw_size = le_u16(raw, 254)?;
            if raw_size == 0 {
                DEFAULT_64BIT_DESCRIPTOR_SIZE
            } else {
                raw_size
            }
        } else {
            32
        };
        let block_count = u64::from(block_count_lo)
            | if features.has_64bit() {
                u64::from(le_u32(raw, 336)?) << 32
            } else {
                0
            };
        let free_blocks_count = u64::from(free_blocks_count_lo)
            | if features.has_64bit() {
                u64::from(le_u32(raw, 344)?) << 32
            } else {
                0
            };
        if features.has_metadata_csum() && le_u32(raw, 1020)? != 0 {
            verify_crc32c(0, raw, 1020)?;
        }
        let journal_inode = le_u32(raw, 224)?;
        let checksum_seed = if features.incompat & INCOMPAT_CSUM_SEED != 0 {
            le_u32(raw, 624)?
        } else {
            0
        };

        if inode_count == 0
            || block_count == 0
            || blocks_per_group == 0
            || inodes_per_group == 0
            || inode_size < 128
            || u32::from(inode_size) > block_size.bytes()
            || descriptor_size < 32
            || u32::from(descriptor_size) > block_size.bytes()
        {
            return Err(Error::InvalidSuperblock);
        }

        Ok(Self {
            block_size,
            inode_count,
            block_count,
            free_blocks_count,
            first_data_block,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            first_inode,
            descriptor_size,
            journal_inode,
            checksum_seed,
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
    pub const fn block_count(self) -> u64 {
        self.block_count
    }

    /// Total free block count.
    #[must_use]
    pub const fn free_blocks_count(self) -> u64 {
        self.free_blocks_count
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

    /// Block group descriptor size in bytes.
    #[must_use]
    pub const fn descriptor_size(self) -> u16 {
        self.descriptor_size
    }

    /// Internal journal inode number.
    #[must_use]
    pub const fn journal_inode(self) -> u32 {
        self.journal_inode
    }

    /// Metadata checksum seed.
    #[must_use]
    pub const fn checksum_seed(self) -> u32 {
        self.checksum_seed
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
            .checked_sub(u64::from(self.first_data_block))
            .ok_or(Error::InvalidSuperblock)?;
        let numerator = data_blocks
            .checked_add(
                u64::from(self.blocks_per_group)
                    .checked_sub(1)
                    .ok_or(Error::InvalidSuperblock)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let groups = numerator
            .checked_div(u64::from(self.blocks_per_group))
            .ok_or(Error::InvalidSuperblock)?;
        u32::try_from(groups).map_err(|_| Error::ArithmeticOverflow)
    }
}
