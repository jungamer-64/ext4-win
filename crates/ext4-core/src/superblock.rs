//! Superblock parsing and mount-policy validation.

use crate::block::{BlockAddress, BlockReader, BlockSize, BlockWriter, ByteOffset};
use crate::checksum::{crc32c, verify_crc32c};
use crate::endian::{le_u16, le_u32, put_le_u32};
use crate::error::{Error, Result};
use crate::inode::InodeId;

// ext4 superblock and feature-policy constants. Feature masks stay here so the
// mount boundary is the only place where unsupported on-disk formats enter.
/// Internal constant SUPERBLOCK_OFFSET used by on-disk layout and policy checks.
const SUPERBLOCK_OFFSET: u64 = 1024;
/// Internal constant SUPERBLOCK_SIZE used by on-disk layout and policy checks.
const SUPERBLOCK_SIZE: usize = 1024;
/// Internal constant EXT4_SUPER_MAGIC used by on-disk layout and policy checks.
const EXT4_SUPER_MAGIC: u16 = 0xEF53;
/// Internal constant EXT4_VALID_FS used by on-disk layout and policy checks.
const EXT4_VALID_FS: u16 = 0x0001;

// Compatible feature bits can usually be ignored for reads, but the write domain
// requires an explicit supported set because mutation changes their invariants.
/// Internal constant COMPAT_HAS_JOURNAL used by on-disk layout and policy checks.
const COMPAT_HAS_JOURNAL: u32 = 0x0004;
/// Internal constant COMPAT_EXT_ATTR used by on-disk layout and policy checks.
const COMPAT_EXT_ATTR: u32 = 0x0008;
/// Internal constant COMPAT_RESIZE_INODE used by on-disk layout and policy checks.
const COMPAT_RESIZE_INODE: u32 = 0x0010;
/// Internal constant COMPAT_DIR_INDEX used by on-disk layout and policy checks.
const COMPAT_DIR_INDEX: u32 = 0x0020;
/// Internal constant COMPAT_FAST_COMMIT used by on-disk layout and policy checks.
const COMPAT_FAST_COMMIT: u32 = 0x0400;
/// Internal constant COMPAT_ORPHAN_FILE used by on-disk layout and policy checks.
const COMPAT_ORPHAN_FILE: u32 = 0x1000;

// Incompatible feature bits affect core interpretation and must be accepted or
// rejected before constructing a mounted volume.
/// Internal constant INCOMPAT_FILETYPE used by on-disk layout and policy checks.
const INCOMPAT_FILETYPE: u32 = 0x0002;
/// Internal constant INCOMPAT_RECOVER used by on-disk layout and policy checks.
const INCOMPAT_RECOVER: u32 = 0x0004;
/// Internal constant INCOMPAT_JOURNAL_DEV used by on-disk layout and policy checks.
const INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
/// Internal constant INCOMPAT_META_BG used by on-disk layout and policy checks.
const INCOMPAT_META_BG: u32 = 0x0010;
/// Internal constant INCOMPAT_EXTENTS used by on-disk layout and policy checks.
const INCOMPAT_EXTENTS: u32 = 0x0040;
/// Internal constant INCOMPAT_64BIT used by on-disk layout and policy checks.
const INCOMPAT_64BIT: u32 = 0x0080;
/// Internal constant INCOMPAT_MMP used by on-disk layout and policy checks.
const INCOMPAT_MMP: u32 = 0x0100;
/// Internal constant INCOMPAT_FLEX_BG used by on-disk layout and policy checks.
const INCOMPAT_FLEX_BG: u32 = 0x0200;
/// Internal constant INCOMPAT_EA_INODE used by on-disk layout and policy checks.
const INCOMPAT_EA_INODE: u32 = 0x0400;
/// Internal constant INCOMPAT_CSUM_SEED used by on-disk layout and policy checks.
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
/// Internal constant INCOMPAT_LARGEDIR used by on-disk layout and policy checks.
const INCOMPAT_LARGEDIR: u32 = 0x4000;
/// Internal constant INCOMPAT_INLINE_DATA used by on-disk layout and policy checks.
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
/// Internal constant INCOMPAT_ENCRYPT used by on-disk layout and policy checks.
const INCOMPAT_ENCRYPT: u32 = 0x0001_0000;
/// Internal constant INCOMPAT_CASEFOLD used by on-disk layout and policy checks.
const INCOMPAT_CASEFOLD: u32 = 0x0002_0000;
/// Internal constant SUPPORTED_READ_INCOMPAT used by on-disk layout and policy checks.
const SUPPORTED_READ_INCOMPAT: u32 =
    INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG | INCOMPAT_CSUM_SEED;
/// Internal constant REQUIRED_WRITE_INCOMPAT used by on-disk layout and policy checks.
const REQUIRED_WRITE_INCOMPAT: u32 =
    INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG;
/// Internal constant SUPPORTED_WRITE_INCOMPAT used by on-disk layout and policy checks.
const SUPPORTED_WRITE_INCOMPAT: u32 =
    REQUIRED_WRITE_INCOMPAT | INCOMPAT_RECOVER | INCOMPAT_JOURNAL_DEV | INCOMPAT_CSUM_SEED;

// Read-only compatible feature bits are safe for read traversal but still need
// write-domain screening before metadata can be changed.
/// Internal constant RO_COMPAT_SPARSE_SUPER used by on-disk layout and policy checks.
const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
/// Internal constant RO_COMPAT_LARGE_FILE used by on-disk layout and policy checks.
const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
/// Internal constant RO_COMPAT_HUGE_FILE used by on-disk layout and policy checks.
const RO_COMPAT_HUGE_FILE: u32 = 0x0008;
/// Internal constant RO_COMPAT_GDT_CSUM used by on-disk layout and policy checks.
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
/// Internal constant RO_COMPAT_DIR_NLINK used by on-disk layout and policy checks.
const RO_COMPAT_DIR_NLINK: u32 = 0x0020;
/// Internal constant RO_COMPAT_EXTRA_ISIZE used by on-disk layout and policy checks.
const RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
/// Internal constant RO_COMPAT_QUOTA used by on-disk layout and policy checks.
const RO_COMPAT_QUOTA: u32 = 0x0100;
/// Internal constant RO_COMPAT_BIGALLOC used by on-disk layout and policy checks.
const RO_COMPAT_BIGALLOC: u32 = 0x0200;
/// Internal constant RO_COMPAT_METADATA_CSUM used by on-disk layout and policy checks.
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
/// Internal constant RO_COMPAT_READONLY used by on-disk layout and policy checks.
const RO_COMPAT_READONLY: u32 = 0x1000;
/// Internal constant RO_COMPAT_PROJECT used by on-disk layout and policy checks.
const RO_COMPAT_PROJECT: u32 = 0x2000;
/// Internal constant RO_COMPAT_VERITY used by on-disk layout and policy checks.
const RO_COMPAT_VERITY: u32 = 0x8000;
/// Internal constant RO_COMPAT_ORPHAN_PRESENT used by on-disk layout and policy checks.
const RO_COMPAT_ORPHAN_PRESENT: u32 = 0x0001_0000;
/// Internal constant SUPPORTED_READ_RO_COMPAT used by on-disk layout and policy checks.
const SUPPORTED_READ_RO_COMPAT: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_GDT_CSUM
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_QUOTA
    | RO_COMPAT_METADATA_CSUM
    | RO_COMPAT_READONLY
    | RO_COMPAT_PROJECT;
/// Internal constant REQUIRED_WRITE_COMPAT used by on-disk layout and policy checks.
const REQUIRED_WRITE_COMPAT: u32 =
    COMPAT_HAS_JOURNAL | COMPAT_EXT_ATTR | COMPAT_RESIZE_INODE | COMPAT_DIR_INDEX;
/// Internal constant SUPPORTED_WRITE_COMPAT used by on-disk layout and policy checks.
const SUPPORTED_WRITE_COMPAT: u32 = REQUIRED_WRITE_COMPAT;
/// Internal constant REJECTED_WRITE_COMPAT used by on-disk layout and policy checks.
const REJECTED_WRITE_COMPAT: u32 = COMPAT_FAST_COMMIT | COMPAT_ORPHAN_FILE;
/// Internal constant REJECTED_WRITE_INCOMPAT used by on-disk layout and policy checks.
const REJECTED_WRITE_INCOMPAT: u32 = INCOMPAT_META_BG
    | INCOMPAT_MMP
    | INCOMPAT_EA_INODE
    | INCOMPAT_LARGEDIR
    | INCOMPAT_INLINE_DATA
    | INCOMPAT_ENCRYPT
    | INCOMPAT_CASEFOLD;
/// Internal constant REQUIRED_WRITE_RO_COMPAT used by on-disk layout and policy checks.
const REQUIRED_WRITE_RO_COMPAT: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_METADATA_CSUM;
/// Internal constant SUPPORTED_WRITE_RO_COMPAT used by on-disk layout and policy checks.
const SUPPORTED_WRITE_RO_COMPAT: u32 = REQUIRED_WRITE_RO_COMPAT;
/// Internal constant REJECTED_WRITE_RO_COMPAT used by on-disk layout and policy checks.
const REJECTED_WRITE_RO_COMPAT: u32 = RO_COMPAT_GDT_CSUM
    | RO_COMPAT_BIGALLOC
    | RO_COMPAT_READONLY
    | RO_COMPAT_VERITY
    | RO_COMPAT_ORPHAN_PRESENT;
/// Descriptor size implied by ext4 64-bit group descriptors when not explicit.
const DEFAULT_64BIT_DESCRIPTOR_SIZE: u16 = 64;

/// Total number of inodes recorded by a validated superblock.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InodeCount(u32);

impl InodeCount {
    /// Creates an inode count.
    ///
    /// # Errors
    /// Returns an error when the count is zero.
    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            Err(Error::InvalidSuperblock)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the count for on-disk geometry arithmetic.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Total number of blocks recorded by a validated superblock.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockCount(u64);

impl BlockCount {
    /// Creates a block count.
    ///
    /// # Errors
    /// Returns an error when the count is zero.
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(Error::InvalidSuperblock)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the count for on-disk geometry arithmetic.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Number of free blocks recorded by a validated superblock.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FreeBlockCount(u64);

impl FreeBlockCount {
    /// Creates a free-block count.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the count for on-disk geometry arithmetic.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Number of free inodes recorded by a validated superblock.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FreeInodeCount(u32);

impl FreeInodeCount {
    /// Creates a free-inode count.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the count for on-disk accounting.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Blocks per ext4 block group.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlocksPerGroup(u32);

impl BlocksPerGroup {
    /// Creates a blocks-per-group value.
    ///
    /// # Errors
    /// Returns an error when the value is zero.
    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            Err(Error::InvalidSuperblock)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the value for on-disk geometry arithmetic.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Inodes per ext4 block group.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InodesPerGroup(u32);

impl InodesPerGroup {
    /// Creates an inodes-per-group value.
    ///
    /// # Errors
    /// Returns an error when the value is zero.
    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            Err(Error::InvalidSuperblock)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the value for on-disk geometry arithmetic.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Size of one inode record in bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InodeRecordSize(u16);

impl InodeRecordSize {
    /// Creates an inode record size.
    ///
    /// # Errors
    /// Returns an error when the value cannot contain a v1-supported inode.
    pub fn new(value: u16, block_size: BlockSize) -> Result<Self> {
        if value < 128 || u32::from(value) > block_size.bytes() {
            Err(Error::InvalidSuperblock)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the size for on-disk geometry arithmetic.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// Size of one block group descriptor in bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockGroupDescriptorSize(u16);

impl BlockGroupDescriptorSize {
    /// Creates a descriptor size.
    ///
    /// # Errors
    /// Returns an error when the descriptor cannot fit in one block.
    pub fn new(value: u16, block_size: BlockSize) -> Result<Self> {
        if value < 32 || u32::from(value) > block_size.bytes() {
            Err(Error::InvalidSuperblock)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the size for on-disk geometry arithmetic.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// Ext4 block group identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockGroupId(u32);

impl BlockGroupId {
    /// Creates a block group identifier from validated geometry iteration.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the identifier for descriptor-table arithmetic.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Number of ext4 block groups.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockGroupCount(u32);

impl BlockGroupCount {
    /// Creates a block group count.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the count for group iteration.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Signed free-block count delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreeBlockDelta(i64);

impl FreeBlockDelta {
    /// Zero free-block delta.
    pub const ZERO: Self = Self(0);

    /// Creates a free-block delta from a signed count.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        Self(value)
    }

    /// Returns the delta for checked arithmetic at metadata encoding boundaries.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0
    }

    /// Returns true when the delta has no effect.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Adds another delta.
    ///
    /// # Errors
    /// Returns an error when the signed delta would overflow.
    pub fn checked_add(self, delta: i64) -> Result<Self> {
        Ok(Self(
            self.0.checked_add(delta).ok_or(Error::ArithmeticOverflow)?,
        ))
    }
}

/// Signed free-inode count delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreeInodeDelta(i64);

impl FreeInodeDelta {
    /// Zero free-inode delta.
    pub const ZERO: Self = Self(0);

    /// Creates a free-inode delta from a signed count.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        Self(value)
    }

    /// Returns the delta for checked arithmetic at metadata encoding boundaries.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0
    }

    /// Returns true when the delta has no effect.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Adds another delta.
    ///
    /// # Errors
    /// Returns an error when the signed delta would overflow.
    pub fn checked_add(self, delta: i64) -> Result<Self> {
        Ok(Self(
            self.0.checked_add(delta).ok_or(Error::ArithmeticOverflow)?,
        ))
    }
}

/// Filesystem UUID recorded by the superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemUuid([u8; 16]);

impl FilesystemUuid {
    /// Creates a filesystem UUID from the superblock bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns UUID bytes for checksum and external-boundary comparison.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// External journal UUID recorded by the superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalUuid([u8; 16]);

impl JournalUuid {
    /// Creates a journal UUID from the superblock bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns UUID bytes for external journal validation.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Metadata checksum seed recorded by the superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChecksumSeed(u32);

impl ChecksumSeed {
    /// Creates a checksum seed from the superblock field.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the seed for checksum calculation.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Journal placement mode selected by validated superblock features.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalMode {
    /// The filesystem has no journal.
    None,
    /// The journal is stored in this filesystem inode.
    Internal(InodeId),
    /// The journal is stored on an external device with this UUID.
    External(JournalUuid),
}

/// Recovery state advertised by the superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryState {
    /// No journal recovery is pending.
    Clean,
    /// Journal recovery is required before mounting cleanly.
    NeedsRecovery,
}

/// Metadata checksum mode selected by validated features.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataChecksum {
    /// Metadata checksums are absent.
    None,
    /// CRC32C metadata checksums are present.
    Crc32c,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal BlockGroupDescriptorLayout states used to make module control flow explicit.
pub(crate) enum BlockGroupDescriptorLayout {
    /// Internal Standard32 variant for this domain state.
    Standard32,
    /// Internal SixtyFourBit variant for this domain state.
    SixtyFourBit,
}

impl BlockGroupDescriptorLayout {
    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn has_high_fields(self) -> bool {
        matches!(self, Self::SixtyFourBit)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal BlockGroupDescriptorChecksum states used to make module control flow explicit.
pub(crate) enum BlockGroupDescriptorChecksum {
    /// Internal None variant for this domain state.
    None,
    /// Internal GdtCrc16 variant for this domain state.
    GdtCrc16,
    /// Internal MetadataCrc32c variant for this domain state.
    MetadataCrc32c,
}

/// Validated ext4 feature flags accepted by a mount policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FeatureSet {
    /// Internal compat state carried by this domain type.
    compat: u32,
    /// Internal incompat state carried by this domain type.
    incompat: u32,
    /// Internal read_only_compat state carried by this domain type.
    read_only_compat: u32,
}

impl FeatureSet {
    /// Validates raw superblock feature flags for read-only traversal.
    ///
    /// # Errors
    /// Returns an error when the advertised feature set is outside the
    /// read-only mount policy.
    pub(crate) fn read_only(compat: u32, incompat: u32, read_only_compat: u32) -> Result<Self> {
        if incompat & !SUPPORTED_READ_INCOMPAT != 0 {
            return Err(Error::UnsupportedIncompatFeature);
        }
        if read_only_compat & !SUPPORTED_READ_RO_COMPAT != 0 {
            return Err(Error::UnsupportedReadOnlyFeature);
        }
        if incompat & INCOMPAT_CSUM_SEED != 0 && read_only_compat & RO_COMPAT_METADATA_CSUM == 0 {
            return Err(Error::UnsupportedIncompatFeature);
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
    pub(crate) fn read_write(compat: u32, incompat: u32, read_only_compat: u32) -> Result<Self> {
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
        if incompat & !SUPPORTED_WRITE_INCOMPAT != 0 {
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

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn has_64bit(self) -> bool {
        self.incompat & INCOMPAT_64BIT != 0
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn has_journal(self) -> bool {
        self.compat & COMPAT_HAS_JOURNAL != 0
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn has_external_journal(self) -> bool {
        self.incompat & INCOMPAT_JOURNAL_DEV != 0
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn has_metadata_csum(self) -> bool {
        self.read_only_compat & RO_COMPAT_METADATA_CSUM != 0
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn has_gdt_csum(self) -> bool {
        self.read_only_compat & RO_COMPAT_GDT_CSUM != 0
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn has_checksum_seed(self) -> bool {
        self.incompat & INCOMPAT_CSUM_SEED != 0
    }
}

/// Superblock whose structural fields and mount policy are validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
    /// Internal block_size state carried by this domain type.
    block_size: BlockSize,
    /// Internal inode_count state carried by this domain type.
    inode_count: InodeCount,
    /// Internal block_count state carried by this domain type.
    block_count: BlockCount,
    /// Internal free_blocks_count state carried by this domain type.
    free_blocks_count: FreeBlockCount,
    /// Internal free_inodes_count state carried by this domain type.
    free_inodes_count: FreeInodeCount,
    /// Internal first_data_block state carried by this domain type.
    first_data_block: BlockAddress,
    /// Internal blocks_per_group state carried by this domain type.
    blocks_per_group: BlocksPerGroup,
    /// Internal inodes_per_group state carried by this domain type.
    inodes_per_group: InodesPerGroup,
    /// Internal inode_size state carried by this domain type.
    inode_size: InodeRecordSize,
    /// Internal first_inode state carried by this domain type.
    first_inode: InodeId,
    /// Internal descriptor_size state carried by this domain type.
    descriptor_size: BlockGroupDescriptorSize,
    /// Internal journal_mode state carried by this domain type.
    journal_mode: JournalMode,
    /// Internal uuid state carried by this domain type.
    uuid: FilesystemUuid,
    /// Internal checksum_seed state carried by this domain type.
    checksum_seed: ChecksumSeed,
    /// Internal features state carried by this domain type.
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

    /// Internal parse_with_policy operation used by this module's domain boundary.
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

        let inode_count = InodeCount::new(le_u32(raw, 0)?)?;
        let block_count_lo = le_u32(raw, 4)?;
        let free_blocks_count_lo = le_u32(raw, 12)?;
        let free_inodes_count = FreeInodeCount::new(le_u32(raw, 16)?);
        let first_data_block = BlockAddress::new(u64::from(le_u32(raw, 20)?));
        let block_size = BlockSize::from_superblock_log(le_u32(raw, 24)?)?;
        let blocks_per_group = BlocksPerGroup::new(le_u32(raw, 32)?)?;
        let inodes_per_group = InodesPerGroup::new(le_u32(raw, 40)?)?;
        let first_inode = InodeId::try_from(le_u32(raw, 84)?)?;
        let inode_size = InodeRecordSize::new(le_u16(raw, 88)?, block_size)?;
        let features = validate_features(le_u32(raw, 92)?, le_u32(raw, 96)?, le_u32(raw, 100)?)?;
        let raw_descriptor_size = if features.has_64bit() {
            let raw_size = le_u16(raw, 254)?;
            if raw_size == 0 {
                DEFAULT_64BIT_DESCRIPTOR_SIZE
            } else {
                raw_size
            }
        } else {
            32
        };
        let descriptor_size = BlockGroupDescriptorSize::new(raw_descriptor_size, block_size)?;
        let block_count = BlockCount::new(
            u64::from(block_count_lo)
                | if features.has_64bit() {
                    u64::from(le_u32(raw, 336)?) << 32
                } else {
                    0
                },
        )?;
        let free_blocks_count = FreeBlockCount::new(
            u64::from(free_blocks_count_lo)
                | if features.has_64bit() {
                    u64::from(le_u32(raw, 344)?) << 32
                } else {
                    0
                },
        );
        if features.has_metadata_csum() && le_u32(raw, 1020)? != 0 {
            verify_crc32c(0, raw, 1020)?;
        }
        let journal_inode = le_u32(raw, 224)?;
        let mut uuid = [0_u8; 16];
        uuid.copy_from_slice(raw.get(104..120).ok_or(Error::TruncatedStructure)?);
        let mut journal_uuid = [0_u8; 16];
        journal_uuid.copy_from_slice(raw.get(208..224).ok_or(Error::TruncatedStructure)?);
        let journal_uuid = JournalUuid::from_bytes(journal_uuid);
        let journal_mode = if features.has_journal() {
            if features.has_external_journal() {
                if journal_inode != 0 {
                    return Err(Error::InvalidSuperblock);
                }
                JournalMode::External(journal_uuid)
            } else {
                JournalMode::Internal(InodeId::try_from(journal_inode)?)
            }
        } else {
            JournalMode::None
        };
        let checksum_seed = if features.has_checksum_seed() {
            ChecksumSeed::from_u32(le_u32(raw, 624)?)
        } else if features.has_metadata_csum() {
            ChecksumSeed::from_u32(crc32c(u32::MAX, &uuid))
        } else {
            ChecksumSeed::from_u32(0)
        };
        let uuid = FilesystemUuid::from_bytes(uuid);

        Ok(Self {
            block_size,
            inode_count,
            block_count,
            free_blocks_count,
            free_inodes_count,
            first_data_block,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            first_inode,
            descriptor_size,
            journal_mode,
            uuid,
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
    pub const fn inode_count(self) -> InodeCount {
        self.inode_count
    }

    /// Total block count.
    #[must_use]
    pub const fn block_count(self) -> BlockCount {
        self.block_count
    }

    /// Total free block count.
    #[must_use]
    pub const fn free_blocks_count(self) -> FreeBlockCount {
        self.free_blocks_count
    }

    /// Total free inode count.
    #[must_use]
    pub const fn free_inodes_count(self) -> FreeInodeCount {
        self.free_inodes_count
    }

    /// First data block.
    #[must_use]
    pub const fn first_data_block(self) -> BlockAddress {
        self.first_data_block
    }

    /// Blocks per block group.
    #[must_use]
    pub const fn blocks_per_group(self) -> BlocksPerGroup {
        self.blocks_per_group
    }

    /// Inodes per block group.
    #[must_use]
    pub const fn inodes_per_group(self) -> InodesPerGroup {
        self.inodes_per_group
    }

    /// Inode record size in bytes.
    #[must_use]
    pub const fn inode_size(self) -> InodeRecordSize {
        self.inode_size
    }

    /// First non-reserved inode.
    #[must_use]
    pub const fn first_inode(self) -> InodeId {
        self.first_inode
    }

    /// Block group descriptor size in bytes.
    #[must_use]
    pub const fn descriptor_size(self) -> BlockGroupDescriptorSize {
        self.descriptor_size
    }

    /// Journal placement mode.
    #[must_use]
    pub const fn journal_mode(self) -> JournalMode {
        self.journal_mode
    }

    /// Filesystem UUID.
    #[must_use]
    pub const fn uuid(self) -> FilesystemUuid {
        self.uuid
    }

    /// Metadata checksum seed.
    #[must_use]
    pub const fn checksum_seed(self) -> ChecksumSeed {
        self.checksum_seed
    }

    /// Metadata checksum mode.
    #[must_use]
    pub const fn metadata_checksum(self) -> MetadataChecksum {
        if self.features.has_metadata_csum() {
            MetadataChecksum::Crc32c
        } else {
            MetadataChecksum::None
        }
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn descriptor_layout(self) -> BlockGroupDescriptorLayout {
        if self.features.has_64bit() {
            BlockGroupDescriptorLayout::SixtyFourBit
        } else {
            BlockGroupDescriptorLayout::Standard32
        }
    }

    /// Internal fn operation used by this module's domain boundary.
    pub(crate) const fn descriptor_checksum(self) -> BlockGroupDescriptorChecksum {
        if self.features.has_metadata_csum() {
            BlockGroupDescriptorChecksum::MetadataCrc32c
        } else if self.features.has_gdt_csum() {
            BlockGroupDescriptorChecksum::GdtCrc16
        } else {
            BlockGroupDescriptorChecksum::None
        }
    }

    /// Returns the journal recovery state.
    #[must_use]
    pub const fn recovery_state(self) -> RecoveryState {
        if self.features.incompat & INCOMPAT_RECOVER != 0 {
            RecoveryState::NeedsRecovery
        } else {
            RecoveryState::Clean
        }
    }

    /// Clears the recovery-required incompat bit in the primary superblock.
    ///
    /// # Errors
    /// Returns an error when the primary superblock cannot be read or written.
    pub fn clear_recover_on_device(device: &mut impl BlockWriter) -> Result<()> {
        let mut raw = [0_u8; SUPERBLOCK_SIZE];
        device.read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)?;
        let incompat = le_u32(&raw, 96)? & !INCOMPAT_RECOVER;
        put_le_u32(&mut raw, 96, incompat)?;
        Self::refresh_checksum(&mut raw)?;
        device.write_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &raw)?;
        device.flush()
    }

    /// Recomputes the primary superblock checksum when the on-disk checksum is present.
    pub(crate) fn refresh_checksum(raw: &mut [u8]) -> Result<()> {
        if le_u32(raw, 1020)? == 0 {
            return Ok(());
        }
        put_le_u32(raw, 1020, 0)?;
        let checksum = crc32c(0, raw);
        put_le_u32(raw, 1020, checksum)
    }

    /// Number of block groups implied by the superblock.
    ///
    /// # Errors
    /// Returns an error when validated geometry cannot be combined without
    /// overflow.
    pub fn block_group_count(self) -> Result<BlockGroupCount> {
        let data_blocks = self
            .block_count
            .as_u64()
            .checked_sub(self.first_data_block.get())
            .ok_or(Error::InvalidSuperblock)?;
        let numerator = data_blocks
            .checked_add(
                u64::from(self.blocks_per_group.as_u32())
                    .checked_sub(1)
                    .ok_or(Error::InvalidSuperblock)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let groups = numerator
            .checked_div(u64::from(self.blocks_per_group.as_u32()))
            .ok_or(Error::InvalidSuperblock)?;
        Ok(BlockGroupCount::from_u32(
            u32::try_from(groups).map_err(|_| Error::ArithmeticOverflow)?,
        ))
    }
}
