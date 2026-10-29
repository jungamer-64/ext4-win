//! Superblock parsing and mount-policy validation.

use crate::disk::block::{BlockAddress, BlockSize, ByteOffset};
use crate::disk::checksum::ext4_crc32c;
use crate::disk::endian::{DiskOffset, le_u16, le_u32, le_u64, put_le_u16, put_le_u32};
use crate::disk::storage::OperationDevice;
use crate::disk_format::inode::{
    DirectorySizeEncoding, FileSizeEncoding, InodeBlockCountEncoding, InodeDataEncoding, InodeId,
};
use crate::error::{Error, Result};
use crate::memory;
use core::num::NonZeroU32;

// ext4 superblock and feature-policy constants. Feature masks stay here so the
// mount boundary is the only place where unsupported on-disk formats enter.
/// Byte offset of the primary ext4 superblock from the start of the device.
const SUPERBLOCK_OFFSET: u64 = 1024;
/// Fixed byte length of an ext4 superblock.
const SUPERBLOCK_SIZE: usize = 1024;
/// Byte offset of `s_r_blocks_count_lo` inside the superblock.
const RESERVED_BLOCKS_COUNT_LO_OFFSET: usize = 8;
/// Byte offset of `s_r_blocks_count_hi` inside the superblock.
const RESERVED_BLOCKS_COUNT_HI_OFFSET: usize = 340;
/// Byte offset of `s_free_blocks_count_lo` inside the superblock.
const FREE_BLOCKS_COUNT_LO_OFFSET: usize = 12;
/// Byte offset of `s_free_blocks_count_hi` inside the superblock.
const FREE_BLOCKS_COUNT_HI_OFFSET: usize = 344;
/// Byte offset of `s_checksum` and exclusive end of the superblock checksum input.
const SUPERBLOCK_CHECKSUM_OFFSET: usize = 1020;
/// Byte offset of `s_reserved_gdt_blocks` inside the superblock.
const RESERVED_GDT_BLOCKS_OFFSET: usize = 206;
/// Magic value stored in `s_magic`.
const EXT4_SUPER_MAGIC: u16 = 0xEF53;

/// Recognition only: an ext-family filesystem or a standalone journal device.
///
/// A signature does not grant mount or write authority. Geometry, feature support,
/// checksums and recovery remain the responsibility of the core mount protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtVolumeSignature {
    /// An ext2/3/4 filesystem candidate, subject to mount-policy validation.
    Filesystem,
    /// A journal device, never a user-visible filesystem namespace.
    ExternalJournal,
}

impl ExtVolumeSignature {
    /// Device-relative offset of the recognition input.
    pub const BYTE_OFFSET: u64 = SUPERBLOCK_OFFSET;
    /// Complete primary-superblock length required by recognition.
    pub const BYTE_LEN: usize = SUPERBLOCK_SIZE;

    /// Classifies a primary superblock without rejecting recoverable checksum damage.
    ///
    /// Returns `None` for other signatures. The caller must supply bytes beginning
    /// at [`Self::BYTE_OFFSET`], not an entire disk prefix or a partition-table GUID.
    /// # Errors
    /// Returns [`Error::TruncatedStructure`] if the superblock is incomplete.
    pub fn recognize(superblock: &[u8]) -> Result<Option<Self>> {
        let raw = superblock
            .get(..SUPERBLOCK_SIZE)
            .ok_or(Error::TruncatedStructure)?;
        if le_u16(raw, disk_offset(0x38))? != EXT4_SUPER_MAGIC {
            return Ok(None);
        }
        let kind = if le_u32(raw, disk_offset(0x60))? & INCOMPAT_JOURNAL_DEV == 0 {
            Self::Filesystem
        } else {
            Self::ExternalJournal
        };
        Ok(Some(kind))
    }
}

#[cfg(test)]
mod recognition_tests {
    use super::ExtVolumeSignature;
    use crate::Error;

    /// # Panics
    /// Panics if the ext magic is confused with a different signature or byte order.
    #[test]
    fn recognition_uses_the_superblock_magic_and_complete_input() {
        let raw: [u8; 1024] = core::array::from_fn(|offset| match offset {
            0x38 => 0x53,
            0x39 => 0xef,
            _ => 0,
        });
        assert_eq!(
            ExtVolumeSignature::recognize(&raw),
            Ok(Some(ExtVolumeSignature::Filesystem))
        );
        assert_eq!(ExtVolumeSignature::recognize(&[0; 1024]), Ok(None));
        assert_eq!(
            ExtVolumeSignature::recognize(&[0; 1023]),
            Err(Error::TruncatedStructure)
        );
        let swapped: [u8; 1024] = core::array::from_fn(|offset| match offset {
            0x38 => 0xef,
            0x39 => 0x53,
            _ => 0,
        });
        assert_eq!(ExtVolumeSignature::recognize(&swapped), Ok(None));
    }

    /// # Panics
    /// Panics if a journal device is offered as a filesystem or recognition becomes mount policy.
    #[test]
    fn journal_identity_and_mount_admission_are_separate_facts() {
        let journal: [u8; 1024] = core::array::from_fn(|offset| match offset {
            0x38 => 0x53,
            0x39 => 0xef,
            0x60 => 8,
            _ => 0,
        });
        assert_eq!(
            ExtVolumeSignature::recognize(&journal),
            Ok(Some(ExtVolumeSignature::ExternalJournal))
        );
        // Unknown features, invalid geometry and checksum damage must reach the
        // mount/recovery protocol, not turn a recognizable filesystem into another format.
        let candidate: [u8; 1024] = core::array::from_fn(|offset| match offset {
            0x38 => 0x53,
            0x39 => 0xef,
            0x60 => 0xf7,
            0x61..=0x67 => 0xff,
            _ => 0,
        });
        assert_eq!(
            ExtVolumeSignature::recognize(&candidate),
            Ok(Some(ExtVolumeSignature::Filesystem))
        );
    }
}
/// Clean filesystem bit stored in `s_state`.
const EXT4_VALID_FS: u16 = 0x0001;
/// Recorded filesystem error suppresses orphan cleanup on ordinary RO mounts.
const EXT4_ERROR_FS: u16 = 0x0002;
/// Fixed inode number assigned to online-resize metadata by ext4.
const EXT4_RESIZE_INODE_ID: u32 = 7;
/// Byte offset of `s_volume_name` inside the superblock.
const VOLUME_LABEL_OFFSET: usize = 120;
/// Fixed byte width of `s_volume_name`.
const VOLUME_LABEL_BYTES: usize = 16;
/// Byte offset of `s_hash_seed[0]` inside the superblock.
const DIRECTORY_HASH_SEED_OFFSET: usize = 236;
/// Number of 32-bit words in `s_hash_seed`.
const DIRECTORY_HASH_SEED_WORDS: usize = 4;
/// Byte offset of `s_def_hash_version` inside the superblock.
const DEFAULT_DIRECTORY_HASH_VERSION_OFFSET: usize = 252;
/// Filesystem-wide directory hash byte interpretation in `s_flags`.
const FILESYSTEM_FLAGS_OFFSET: usize = 0x160;
/// Signed and unsigned directory hash selectors in `s_flags`.
const SIGNED_DIRECTORY_HASH: u32 = 1;
/// Unsigned interpretation takes precedence when the selector is present.
const UNSIGNED_DIRECTORY_HASH: u32 = 2;

/// Builds a typed superblock field offset.
const fn disk_offset(offset: usize) -> DiskOffset {
    DiskOffset::new(offset)
}

// Compatible feature bits can usually be ignored for reads, but the write domain
// requires an explicit supported set because mutation changes their invariants.
/// Compatible feature bit for a filesystem journal.
const COMPAT_HAS_JOURNAL: u32 = 0x0004;
/// Compatible feature bit for extended attributes.
const COMPAT_EXT_ATTR: u32 = 0x0008;
/// Compatible feature bit for reserved resize inode support.
const COMPAT_RESIZE_INODE: u32 = 0x0010;
/// Compatible feature bit for hashed directory indexes.
const COMPAT_DIR_INDEX: u32 = 0x0020;
/// Compatible feature bit for fast commit journal areas.
const COMPAT_FAST_COMMIT: u32 = 0x0400;
/// Compatible feature bit for orphan file tracking.
const COMPAT_ORPHAN_FILE: u32 = 0x1000;

// Incompatible feature bits affect core interpretation and must be accepted or
// rejected before constructing a mounted volume.
/// Incompatible feature bit for directory entry file types.
const INCOMPAT_FILETYPE: u32 = 0x0002;
/// Incompatible feature bit indicating pending journal recovery.
const INCOMPAT_RECOVER: u32 = 0x0004;
/// Incompatible feature bit for external journal devices.
const INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
/// Incompatible feature bit for meta block groups.
const INCOMPAT_META_BG: u32 = 0x0010;
/// Incompatible feature bit for extent-based file mapping.
const INCOMPAT_EXTENTS: u32 = 0x0040;
/// Incompatible feature bit for 64-bit block group descriptors.
const INCOMPAT_64BIT: u32 = 0x0080;
/// Incompatible feature bit for multiple-mount protection.
const INCOMPAT_MMP: u32 = 0x0100;
/// Incompatible feature bit for flexible block groups.
const INCOMPAT_FLEX_BG: u32 = 0x0200;
/// Incompatible feature bit for extended-attribute inodes.
const INCOMPAT_EA_INODE: u32 = 0x0400;
/// Incompatible feature bit for an explicit metadata checksum seed.
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
/// Incompatible feature bit for large directory formats.
const INCOMPAT_LARGEDIR: u32 = 0x4000;
/// Incompatible feature bit for inline file data.
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
/// Incompatible feature bit for encrypted filenames or file data.
const INCOMPAT_ENCRYPT: u32 = 0x0001_0000;
/// Incompatible feature bit for casefolded directory lookup.
const INCOMPAT_CASEFOLD: u32 = 0x0002_0000;
// Read-only compatible feature bits are safe for read traversal but still need
// write-domain screening before metadata can be changed.
/// Read-only compatible feature bit for sparse superblock backups.
const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
/// Read-only compatible feature bit for files larger than 2 GiB.
const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
/// Read-only compatible feature bit for huge file block counts.
const RO_COMPAT_HUGE_FILE: u32 = 0x0008;
/// Read-only compatible feature bit for legacy GDT checksums.
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
/// Read-only compatible feature bit for directory link counts beyond 65000.
const RO_COMPAT_DIR_NLINK: u32 = 0x0020;
/// Read-only compatible feature bit for extended inode extra size.
const RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
/// Read-only compatible feature bit for quota inodes.
const RO_COMPAT_QUOTA: u32 = 0x0100;
/// Read-only compatible feature bit for cluster-based allocation.
const RO_COMPAT_BIGALLOC: u32 = 0x0200;
/// Read-only compatible feature bit for metadata CRC32C checksums.
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
/// Read-only compatible feature bit that forces read-only mounts.
const RO_COMPAT_READONLY: u32 = 0x1000;
/// Read-only compatible feature bit for project quotas.
const RO_COMPAT_PROJECT: u32 = 0x2000;
/// Read-only compatible feature bit for fs-verity protected files.
const RO_COMPAT_VERITY: u32 = 0x8000;
/// Read-only compatible feature bit indicating orphan cleanup is required.
const RO_COMPAT_ORPHAN_PRESENT: u32 = 0x0001_0000;
/// Descriptor size implied by ext4 64-bit group descriptors when not explicit.
const DEFAULT_64BIT_DESCRIPTOR_SIZE: u16 = 64;

/// Total number of inodes recorded by a validated superblock.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InodeCount(u32);

impl InodeCount {
    /// Creates an inode count.
    ///
    /// # Errors
    /// Returns an error when the filesystem inode count is zero.
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
    /// Returns an error when the filesystem block count is zero.
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

/// Absolute ext4 allocation cluster address.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClusterAddress(u64);

impl ClusterAddress {
    /// Creates an absolute allocation cluster address.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw cluster address.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Total number of allocation clusters recorded by validated geometry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClusterCount(u64);

impl ClusterCount {
    /// Creates a cluster count.
    ///
    /// # Errors
    /// Returns an error when the allocation cluster count is zero.
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(Error::InvalidClusterGeometry)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the count for allocation geometry arithmetic.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Validated ext4 allocation cluster size in bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClusterSize(NonZeroU32);

impl ClusterSize {
    /// Creates a cluster size from validated superblock geometry.
    ///
    /// # Errors
    /// Returns an error when the allocation cluster size is zero.
    pub fn new(value: u32) -> Result<Self> {
        Ok(Self(
            NonZeroU32::new(value).ok_or(Error::InvalidClusterGeometry)?,
        ))
    }

    /// Returns the allocation cluster size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.0.get()
    }
}

/// Number of filesystem blocks in one allocation cluster.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlocksPerCluster(u32);

impl BlocksPerCluster {
    /// Creates a blocks-per-cluster value.
    ///
    /// # Errors
    /// Returns an error when the block-to-cluster ratio is zero.
    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            Err(Error::InvalidClusterGeometry)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the allocation ratio for block-to-cluster conversion.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Allocation clusters per ext4 block group.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClustersPerGroup(u32);

impl ClustersPerGroup {
    /// Creates a clusters-per-group value.
    ///
    /// # Errors
    /// Returns an error when the allocation clusters-per-group value is zero.
    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            Err(Error::InvalidClusterGeometry)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the value for allocation geometry arithmetic.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Number of free allocation clusters recorded by a validated superblock.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FreeClusterCount(u64);

impl FreeClusterCount {
    /// Creates a free-cluster count.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the count for on-disk accounting.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Allocation clusters withheld from ordinary allocation by `s_r_blocks_count`.
/// The on-disk reservation is measured in blocks and need not be cluster aligned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReservedClusterCount(u64);

impl ReservedClusterCount {
    /// Validates the block reservation and withholds any partially reserved cluster.
    /// # Errors
    /// Returns truncated fields, a reservation exceeding the filesystem, or invalid geometry.
    fn parse(
        raw: &[u8],
        has_high_field: bool,
        block_count: BlockCount,
        blocks_per_cluster: BlocksPerCluster,
    ) -> Result<Self> {
        let low = u64::from(le_u32(raw, disk_offset(RESERVED_BLOCKS_COUNT_LO_OFFSET))?);
        let high = if has_high_field {
            u64::from(le_u32(raw, disk_offset(RESERVED_BLOCKS_COUNT_HI_OFFSET))?) << 32
        } else {
            0
        };
        let blocks = low | high;
        if blocks > block_count.as_u64() {
            return Err(Error::InvalidSuperblock);
        }
        let ratio = u64::from(blocks_per_cluster.as_u32());
        let clusters = blocks
            .checked_div(ratio)
            .and_then(|whole| whole.checked_add(u64::from(!blocks.is_multiple_of(ratio))))
            .ok_or(Error::InvalidClusterGeometry)?;
        Ok(Self(clusters))
    }

    /// Preserves physical free space while excluding the ordinary allocation reserve.
    const fn available(self, free: FreeClusterCount) -> FreeClusterCount {
        FreeClusterCount::new(free.as_u64().saturating_sub(self.0))
    }
}

/// Free filesystem-block count encoded in the ext4 superblock.
///
/// This is deliberately distinct from [`FreeClusterCount`]: bigalloc keeps
/// `s_free_blocks_count` in filesystem blocks even though allocation bitmaps
/// and block-group descriptor counters use clusters.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OnDiskFreeBlockCount(u64);

impl OnDiskFreeBlockCount {
    /// Decodes the low and optional high free-block fields.
    /// # Errors
    ///
    /// Returns an error when either selected field lies outside the supplied superblock bytes.
    fn parse(raw: &[u8], has_high_field: bool) -> Result<Self> {
        let low = u64::from(le_u32(raw, disk_offset(FREE_BLOCKS_COUNT_LO_OFFSET))?);
        let high = if has_high_field {
            u64::from(le_u32(raw, disk_offset(FREE_BLOCKS_COUNT_HI_OFFSET))?) << 32
        } else {
            0
        };
        Ok(Self(low | high))
    }

    /// Converts the on-disk block count into the allocation-domain cluster count.
    /// # Errors
    ///
    /// Returns an error when the block count is not cluster-aligned or exceeds the mounted cluster
    /// count.
    fn into_free_cluster_count(
        self,
        blocks_per_cluster: BlocksPerCluster,
        cluster_count: ClusterCount,
    ) -> Result<FreeClusterCount> {
        let blocks_per_cluster = u64::from(blocks_per_cluster.as_u32());
        let clusters = self
            .0
            .checked_div(blocks_per_cluster)
            .ok_or(Error::InvalidClusterGeometry)?;
        if self.0.checked_rem(blocks_per_cluster) != Some(0) || clusters > cluster_count.as_u64() {
            return Err(Error::InvalidClusterGeometry);
        }
        Ok(FreeClusterCount::new(clusters))
    }

    /// Applies a cluster-domain delta while preserving the superblock's block unit.
    /// # Errors
    ///
    /// Returns an error when the converted block delta overflows, underflows the current count, or
    /// produces a count outside the mounted cluster geometry.
    fn apply_cluster_delta(
        self,
        delta: FreeClusterDelta,
        blocks_per_cluster: BlocksPerCluster,
        cluster_count: ClusterCount,
    ) -> Result<Self> {
        let block_delta = delta
            .as_i64()
            .checked_mul(i64::from(blocks_per_cluster.as_u32()))
            .ok_or(Error::ArithmeticOverflow)?;
        let updated = if block_delta.is_negative() {
            self.0
                .checked_sub(block_delta.unsigned_abs())
                .ok_or(Error::InvalidClusterGeometry)?
        } else {
            self.0
                .checked_add(u64::try_from(block_delta).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?
        };
        let updated = Self(updated);
        updated.into_free_cluster_count(blocks_per_cluster, cluster_count)?;
        Ok(updated)
    }

    /// Writes the low and optional high free-block fields.
    /// # Errors
    ///
    /// Returns an error when either selected field cannot be represented or lies outside the
    /// supplied superblock bytes.
    fn write_to(self, raw: &mut [u8], has_high_field: bool) -> Result<()> {
        put_le_u32(
            raw,
            disk_offset(FREE_BLOCKS_COUNT_LO_OFFSET),
            u32::try_from(self.0 & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if has_high_field {
            put_le_u32(
                raw,
                disk_offset(FREE_BLOCKS_COUNT_HI_OFFSET),
                u32::try_from(self.0 >> 32).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(())
    }
}

/// Signed free-cluster count delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreeClusterDelta(i64);

impl FreeClusterDelta {
    /// Zero free-cluster delta.
    pub(crate) const ZERO: Self = Self(0);

    /// Creates a free-cluster delta from a signed count.
    #[must_use]
    pub(crate) const fn from_i64(value: i64) -> Self {
        Self(value)
    }

    /// Returns the delta for checked arithmetic at metadata encoding boundaries.
    #[must_use]
    pub(crate) const fn as_i64(self) -> i64 {
        self.0
    }

    /// Returns true when the delta has no effect.
    #[must_use]
    pub(crate) const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Adds another delta.
    ///
    /// # Errors
    /// Returns an error when the signed delta would overflow.
    pub(crate) fn checked_add(self, delta: i64) -> Result<Self> {
        Ok(Self(
            self.0.checked_add(delta).ok_or(Error::ArithmeticOverflow)?,
        ))
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

    /// Returns the raw free-inode count.
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
    /// Returns an error when the block group block count is zero.
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

/// Descriptor-table expansion blocks reserved after each backup descriptor table.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ReservedGdtBlockCount(u16);

impl ReservedGdtBlockCount {
    /// Creates a reserved descriptor-table block count from its on-disk field.
    #[must_use]
    const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the count for block-address arithmetic.
    #[must_use]
    pub(crate) fn as_u64(self) -> u64 {
        u64::from(self.0)
    }
}

/// Inodes per ext4 block group.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InodesPerGroup(u32);

impl InodesPerGroup {
    /// Creates an inodes-per-group value.
    ///
    /// # Errors
    /// Returns an error when the block group inode count is zero.
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

    /// Returns whether no external-journal identifier was recorded.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        matches!(self.0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }
}

/// Ext4 volume label stored in `s_volume_name`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4VolumeLabel {
    /// Label bytes without trailing NUL padding.
    bytes: [u8; VOLUME_LABEL_BYTES],
    /// Length of the live label prefix.
    len: u8,
}

impl Ext4VolumeLabel {
    /// Maximum byte length accepted by ext4 `s_volume_name`.
    pub const MAX_BYTES: usize = VOLUME_LABEL_BYTES;

    /// Creates a volume label from non-NUL bytes.
    ///
    /// # Errors
    /// Returns an error when the label is longer than the on-disk field or
    /// contains NUL, which is reserved for fixed-field padding.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > VOLUME_LABEL_BYTES || bytes.contains(&0) {
            return Err(Error::InvalidName);
        }
        let mut label = [0_u8; VOLUME_LABEL_BYTES];
        let len = u8::try_from(bytes.len()).map_err(|_| Error::ArithmeticOverflow)?;
        memory::copy_exact(
            label
                .get_mut(..bytes.len())
                .ok_or(Error::ArithmeticOverflow)?,
            bytes,
        )?;
        Ok(Self { bytes: label, len })
    }

    /// Parses the fixed superblock label field.
    /// # Errors
    ///
    /// Returns an error when the fixed label field is truncated or the decoded bytes violate volume
    /// label rules.
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        let field = raw
            .get(VOLUME_LABEL_OFFSET..VOLUME_LABEL_OFFSET + VOLUME_LABEL_BYTES)
            .ok_or(Error::TruncatedStructure)?;
        let len = field
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(field.len());
        Self::new(field.get(..len).ok_or(Error::TruncatedStructure)?)
    }

    /// Writes this label to the fixed superblock label field.
    /// # Errors
    ///
    /// Returns an error when the fixed label field is truncated or this label's stored length is
    /// inconsistent with its bytes.
    pub(crate) fn write_to(self, raw: &mut [u8]) -> Result<()> {
        let field = raw
            .get_mut(VOLUME_LABEL_OFFSET..VOLUME_LABEL_OFFSET + VOLUME_LABEL_BYTES)
            .ok_or(Error::TruncatedStructure)?;
        field.fill(0);
        let len = usize::from(self.len);
        let source = self.bytes.get(..len).ok_or(Error::InvalidName)?;
        memory::copy_exact(
            field.get_mut(..len).ok_or(Error::TruncatedStructure)?,
            source,
        )
    }

    /// Returns the non-padding bytes of this label.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
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

/// Directory hash seed stored in `s_hash_seed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryHashSeed([u32; DIRECTORY_HASH_SEED_WORDS]);

impl DirectoryHashSeed {
    /// Creates a directory hash seed from the four raw superblock words.
    #[must_use]
    pub(crate) const fn from_words(words: [u32; DIRECTORY_HASH_SEED_WORDS]) -> Self {
        Self(words)
    }

    /// Returns the words in on-disk order.
    #[must_use]
    pub(crate) const fn words(self) -> [u32; DIRECTORY_HASH_SEED_WORDS] {
        self.0
    }
}

/// Supported ext4 directory hash algorithm versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryHashVersion {
    /// Legacy ext2 hash with signed byte interpretation.
    Legacy,
    /// Half-MD4 hash with signed byte interpretation.
    HalfMd4,
    /// TEA hash with signed byte interpretation.
    Tea,
    /// Legacy ext2 hash with unsigned byte interpretation.
    LegacyUnsigned,
    /// Half-MD4 hash with unsigned byte interpretation.
    HalfMd4Unsigned,
    /// TEA hash with unsigned byte interpretation.
    TeaUnsigned,
}

/// Filesystem-wide byte interpretation for base HTree hash versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryHashSignedness {
    /// Sign-extend name bytes before hashing.
    Signed,
    /// Zero-extend name bytes before hashing.
    Unsigned,
}

impl DirectoryHashSignedness {
    /// Selects the persisted interpretation; an unselected filesystem uses signed bytes.
    const fn from_flags(flags: u32) -> Self {
        if flags & UNSIGNED_DIRECTORY_HASH != 0 {
            Self::Unsigned
        } else {
            Self::Signed
        }
    }
}

impl DirectoryHashVersion {
    /// Resolves a base version using the filesystem selector. Explicit unsigned versions retain
    /// their byte interpretation independently of the selector.
    pub(crate) const fn effective(self, signedness: DirectoryHashSignedness) -> Self {
        match (self, signedness) {
            (Self::Legacy, DirectoryHashSignedness::Unsigned) => Self::LegacyUnsigned,
            (Self::HalfMd4, DirectoryHashSignedness::Unsigned) => Self::HalfMd4Unsigned,
            (Self::Tea, DirectoryHashSignedness::Unsigned) => Self::TeaUnsigned,
            _ => self,
        }
    }

    /// Converts the on-disk version byte to a supported hash version.
    /// # Errors
    ///
    /// Returns an error when the version byte is not one of the ext4 hash algorithms supported by
    /// this mount profile.
    pub(crate) fn from_raw(raw: u8) -> Result<Self> {
        match raw {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::HalfMd4),
            2 => Ok(Self::Tea),
            3 => Ok(Self::LegacyUnsigned),
            4 => Ok(Self::HalfMd4Unsigned),
            5 => Ok(Self::TeaUnsigned),
            _ => Err(Error::UnsupportedDirectoryHash),
        }
    }

    /// Encodes this version for `dx_root_info.hash_version`.
    #[must_use]
    pub(crate) const fn to_raw(self) -> u8 {
        match self {
            Self::Legacy => 0,
            Self::HalfMd4 => 1,
            Self::Tea => 2,
            Self::LegacyUnsigned => 3,
            Self::HalfMd4Unsigned => 4,
            Self::TeaUnsigned => 5,
        }
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

/// Durable write-session boundary, including orphan tracking when the feature is enabled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteSessionState {
    /// The journal and every orphan cleanup have completed before the final filesystem flush.
    Closed,
    /// Recovery may be required until an explicit clean close completes.
    Active,
}

/// Special inode and validity marker of the on-disk orphan file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OrphanFile {
    /// Allocated inode containing orphan-entry blocks.
    pub(crate) inode: InodeId,
    /// Whether the last write session may have left entries to recover.
    pub(crate) present: bool,
}

/// Primary checksum admission; only authenticated journal payloads can repair damaged metadata.
#[derive(Debug)]
pub(crate) enum PrimarySuperblockRead {
    /// The on-disk image is already fully valid.
    Valid(Superblock),
    /// Every structural field needed to locate and validate JBD2 is supported, but the primary
    /// checksum is invalid. A committed journal payload must repair the primary block before this
    /// provisional value may become mounted state.
    ChecksumInvalid(ChecksumInvalidSuperblock),
}

/// Structurally validated primary metadata that has not established checksum authority.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChecksumInvalidSuperblock(Superblock);

impl ChecksumInvalidSuperblock {
    /// Returns the provisional geometry and journal placement solely for recovery bootstrap.
    pub(crate) const fn recovery_bootstrap(self) -> Superblock {
        self.0
    }
}

/// Whether the primary-superblock checksum participates in parsing admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SuperblockChecksumValidation {
    /// Require the checksum selected by the feature set.
    Required,
    /// Validate every other structural field while withholding mounted-state authority.
    DeferredToJournalReplay,
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
/// Block group descriptor field layout selected by the 64-bit feature bit.
pub(crate) enum BlockGroupDescriptorLayout {
    /// Descriptor contains only the standard 32-byte field set.
    Standard32,
    /// Descriptor contains the high 64-bit extension fields.
    SixtyFourBit,
}

impl BlockGroupDescriptorLayout {
    /// Returns whether descriptor fields have high 32-bit companions.
    pub(crate) const fn has_high_fields(self) -> bool {
        matches!(self, Self::SixtyFourBit)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Checksum algorithm used for block group descriptors.
pub(crate) enum BlockGroupDescriptorChecksum {
    /// Descriptor checksums are not present.
    None,
    /// Legacy GDT CRC16 descriptor checksum.
    GdtCrc16,
    /// Metadata CRC32C descriptor checksum.
    MetadataCrc32c,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Validated allocation geometry derived from block and cluster superblock fields.
struct ClusterGeometry {
    /// Allocation cluster size.
    cluster_size: ClusterSize,
    /// Block-to-cluster ratio.
    blocks_per_cluster: BlocksPerCluster,
    /// Clusters represented by one group bitmap.
    clusters_per_group: ClustersPerGroup,
    /// Total allocation clusters addressable by the filesystem.
    cluster_count: ClusterCount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Raw superblock fields needed to validate allocation-cluster geometry.
struct RawClusterGeometry {
    /// Total block count.
    block_count: BlockCount,
    /// First data block.
    first_data_block: BlockAddress,
    /// Block size selected by `s_log_block_size`.
    block_size: BlockSize,
    /// Raw `s_log_block_size`.
    log_block_size: u32,
    /// Raw `s_log_cluster_size`.
    log_cluster_size: u32,
    /// Blocks per group.
    blocks_per_group: BlocksPerGroup,
    /// Raw `s_clusters_per_group`.
    clusters_per_group: u32,
    /// Allocation bitmap addressing domain selected by validated features.
    allocation_bitmap_domain: AllocationBitmapDomain,
}

impl ClusterGeometry {
    /// Validates cluster fields against feature flags and block geometry.
    /// # Errors
    ///
    /// Returns an error when block and cluster feature bits disagree, cluster ratios are invalid, or
    /// derived cluster counts overflow.
    fn new(raw: RawClusterGeometry) -> Result<Self> {
        match raw.allocation_bitmap_domain {
            AllocationBitmapDomain::Blocks => {
                if raw.log_cluster_size != raw.log_block_size
                    || raw.clusters_per_group != raw.blocks_per_group.as_u32()
                {
                    return Err(Error::InvalidClusterGeometry);
                }
            }
            AllocationBitmapDomain::Clusters => {}
        }
        if raw.log_cluster_size < raw.log_block_size || raw.log_cluster_size > 31 {
            return Err(Error::InvalidClusterGeometry);
        }

        let ratio_shift = raw
            .log_cluster_size
            .checked_sub(raw.log_block_size)
            .ok_or(Error::InvalidClusterGeometry)?;
        let blocks_per_cluster = BlocksPerCluster::new(
            1_u32
                .checked_shl(ratio_shift)
                .ok_or(Error::ArithmeticOverflow)?,
        )?;
        match raw.allocation_bitmap_domain {
            AllocationBitmapDomain::Blocks => {}
            AllocationBitmapDomain::Clusters => {
                if blocks_per_cluster.as_u32() == 1 {
                    return Err(Error::InvalidClusterGeometry);
                }
            }
        }
        let cluster_size = ClusterSize::new(
            raw.block_size
                .bytes()
                .checked_mul(blocks_per_cluster.as_u32())
                .ok_or(Error::ArithmeticOverflow)?,
        )?;
        let clusters_per_group = ClustersPerGroup::new(raw.clusters_per_group)?;
        if clusters_per_group
            .as_u32()
            .checked_mul(blocks_per_cluster.as_u32())
            .ok_or(Error::ArithmeticOverflow)?
            != raw.blocks_per_group.as_u32()
        {
            return Err(Error::InvalidClusterGeometry);
        }
        let data_blocks = raw
            .block_count
            .as_u64()
            .checked_sub(raw.first_data_block.get())
            .ok_or(Error::InvalidClusterGeometry)?;
        let cluster_count = ClusterCount::new(round_up_div(
            data_blocks,
            u64::from(blocks_per_cluster.as_u32()),
        )?)?;

        Ok(Self {
            cluster_size,
            blocks_per_cluster,
            clusters_per_group,
            cluster_count,
        })
    }
}

/// Superblock copy placement selected by sparse-super feature bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SparseSuperblockLayout {
    /// Every block group carries backup metadata.
    FullCopies,
    /// Only group zero, one, and powers of three, five, or seven carry backups.
    SparseCopies,
}

/// Directory indexing capability selected by compatible feature bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryIndexing {
    /// Indexed directories are outside this mounted profile.
    Disabled,
    /// HTree indexing is enabled with at most one interior index level.
    Standard,
    /// Pre-enabled `INCOMPAT_LARGEDIR` permits two interior index levels.
    LargeDirectory,
}

impl DirectoryIndexing {
    /// Verifies that an indexed directory can be interpreted.
    /// # Errors
    ///
    /// Returns an error when the mounted feature policy disables HTree directory indexing.
    pub(crate) const fn require_supported(self) -> Result<u8> {
        match self {
            Self::Standard => Ok(1),
            Self::LargeDirectory => Ok(2),
            Self::Disabled => Err(Error::UnsupportedDirectoryHash),
        }
    }
}

/// Allocation bitmap addressing domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AllocationBitmapDomain {
    /// One bitmap bit addresses one filesystem block.
    Blocks,
    /// One bitmap bit addresses one allocation cluster.
    Clusters,
}

/// Source used to construct the mounted checksum seed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChecksumSeedSource {
    /// Checksums are disabled for metadata that uses this seed.
    Zero,
    /// The seed is derived from the filesystem UUID.
    FilesystemUuid,
    /// The seed is stored explicitly in the superblock.
    SuperblockField,
}

impl ChecksumSeedSource {
    /// Reads or derives the checksum seed selected by this source.
    /// # Errors
    ///
    /// Returns an error when the explicit checksum seed field is selected but truncated.
    fn seed(self, raw: &[u8], uuid: &[u8; 16]) -> Result<ChecksumSeed> {
        match self {
            Self::Zero => Ok(ChecksumSeed::from_u32(0)),
            Self::FilesystemUuid => Ok(ChecksumSeed::from_u32(ext4_crc32c(u32::MAX, uuid))),
            Self::SuperblockField => Ok(ChecksumSeed::from_u32(le_u32(raw, disk_offset(624))?)),
        }
    }
}

/// Public extended-attribute mutation capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XattrMutationSupport {
    /// Public xattrs are not advertised by this mounted profile.
    Disabled,
    /// Public xattrs can be read and mutated.
    Enabled,
}

impl XattrMutationSupport {
    /// Verifies that xattr mutation is supported.
    /// # Errors
    ///
    /// Returns an error when the mounted feature policy disables public xattr mutation.
    pub(crate) const fn require_supported(self) -> Result<()> {
        match self {
            Self::Enabled => Ok(()),
            Self::Disabled => Err(Error::UnsupportedWriteFeature),
        }
    }
}

/// Inode timestamp encoding available in inode records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InodeTimestampEncoding {
    /// Only legacy second-resolution fields are written.
    LegacySeconds,
    /// Extended inode timestamp fields may be written when the record is wide enough.
    ExtraFields,
}

/// Compatible feature-mask domain. Unknown bits remain observable; this value grants no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibleFeatures(u32);
impl CompatibleFeatures {
    /// Captures a wire observation without admitting its features for mounting.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    /// Compatible bits in ext4 numbering, independent of the other two feature-mask domains.
    pub const fn bits(self) -> u32 {
        self.0
    }
}
/// Incompatible feature-mask domain, distinct from the equally sized compatible masks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncompatibleFeatures(u32);
impl IncompatibleFeatures {
    /// Captures a wire observation without admitting its features for mounting.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    /// Incompatible bits in ext4 numbering.
    pub const fn bits(self) -> u32 {
        self.0
    }
}
/// Read-only-compatible feature-mask domain; its presence does not itself select media authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnlyCompatibleFeatures(u32);
impl ReadOnlyCompatibleFeatures {
    /// Captures a wire observation without admitting its features for mounting.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    /// Read-only-compatible bits in ext4 numbering.
    pub const fn bits(self) -> u32 {
        self.0
    }
}
/// Declared on-disk facts. Acceptance, session access and operation authority remain independent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemFeatures {
    /// Compatible on-disk features, including journal format selection.
    pub compatible: CompatibleFeatures,
    /// Features that readers must understand before interpreting the filesystem.
    pub incompatible: IncompatibleFeatures,
    /// Features whose interpretation constrains write admission.
    pub read_only_compatible: ReadOnlyCompatibleFeatures,
}
/// Named format facts for administrative observation, without a claim of implementation support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemFeature {
    /// Filesystem-wide Unicode directory comparison encoding.
    Casefold,
    /// Inode-body file and directory payloads.
    InlineData,
    /// Attribute entries may reference separate value inodes.
    AttributeValueInodes,
    /// Independent physical-media ownership record.
    MultipleMountProtection,
    /// Delta records in a reserved journal area.
    FastCommit,
    /// Per-inode fscrypt policies may be present.
    Encryption,
    /// Allocation bitmaps address clusters larger than filesystem blocks.
    BigAllocation,
    /// CRC32C metadata authentication.
    MetadataChecksums,
    /// Hash-indexed directories.
    DirectoryIndex,
    /// File-content verification metadata.
    Verity,
}
impl FilesystemFeatures {
    /// Observes a declaration; callers must not treat this as admission or write permission.
    pub const fn contains(self, feature: FilesystemFeature) -> bool {
        match feature {
            FilesystemFeature::Casefold => self.incompatible.bits() & INCOMPAT_CASEFOLD != 0,
            FilesystemFeature::InlineData => self.incompatible.bits() & INCOMPAT_INLINE_DATA != 0,
            FilesystemFeature::AttributeValueInodes => {
                self.incompatible.bits() & INCOMPAT_EA_INODE != 0
            }
            FilesystemFeature::MultipleMountProtection => {
                self.incompatible.bits() & INCOMPAT_MMP != 0
            }
            FilesystemFeature::FastCommit => self.compatible.bits() & COMPAT_FAST_COMMIT != 0,
            FilesystemFeature::Encryption => self.incompatible.bits() & INCOMPAT_ENCRYPT != 0,
            FilesystemFeature::BigAllocation => {
                self.read_only_compatible.bits() & RO_COMPAT_BIGALLOC != 0
            }
            FilesystemFeature::MetadataChecksums => {
                self.read_only_compatible.bits() & RO_COMPAT_METADATA_CSUM != 0
            }
            FilesystemFeature::DirectoryIndex => self.compatible.bits() & COMPAT_DIR_INDEX != 0,
            FilesystemFeature::Verity => self.read_only_compatible.bits() & RO_COMPAT_VERITY != 0,
        }
    }
}

/// Validated ext4 capabilities accepted by a mount policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FeatureSet {
    /// Immutable declared masks; typed semantic projections cannot change independently.
    declared: FilesystemFeatures,
}

impl FeatureSet {
    /// Validates raw superblock feature flags for journaled read-write mode.
    ///
    /// # Errors
    /// Returns an error when write-domain invariants cannot be maintained for
    /// the advertised feature profile.
    pub(crate) fn read_write(compat: u32, incompat: u32, read_only_compat: u32) -> Result<Self> {
        if compat & COMPAT_HAS_JOURNAL == 0 {
            return Err(Error::UnsupportedWriteFeature);
        }
        Self::mutable(compat, incompat, read_only_compat)
    }

    /// Validates metadata updates independently of journal availability.
    /// # Errors
    /// Rejects features whose mutable metadata is not implemented.
    fn mutable(compat: u32, incompat: u32, read_only_compat: u32) -> Result<Self> {
        Self::read_only(compat, incompat, read_only_compat).map_err(|error| match error {
            Error::UnsupportedReadOnlyFeature => Error::UnsupportedWriteFeature,
            error => error,
        })?;
        if compat & COMPAT_FAST_COMMIT != 0
            || compat
                & !(COMPAT_HAS_JOURNAL
                    | COMPAT_EXT_ATTR
                    | COMPAT_RESIZE_INODE
                    | COMPAT_DIR_INDEX
                    | COMPAT_ORPHAN_FILE)
                != 0
        {
            return Err(Error::UnsupportedWriteFeature);
        }
        if read_only_compat
            & !(RO_COMPAT_SPARSE_SUPER
                | RO_COMPAT_LARGE_FILE
                | RO_COMPAT_HUGE_FILE
                | RO_COMPAT_GDT_CSUM
                | RO_COMPAT_DIR_NLINK
                | RO_COMPAT_EXTRA_ISIZE
                | RO_COMPAT_BIGALLOC
                | RO_COMPAT_METADATA_CSUM
                | RO_COMPAT_VERITY
                | RO_COMPAT_READONLY
                | RO_COMPAT_QUOTA
                | RO_COMPAT_PROJECT
                | RO_COMPAT_ORPHAN_PRESENT)
            != 0
        {
            return Err(Error::UnsupportedWriteFeature);
        }
        if read_only_compat & (RO_COMPAT_READONLY | RO_COMPAT_QUOTA | RO_COMPAT_PROJECT) != 0 {
            return Err(Error::UnsupportedWriteFeature);
        }
        Ok(Self::from_raw(compat, incompat, read_only_compat))
    }

    /// Establishes read-format invariants without granting mutation authority.
    /// # Errors
    /// Rejects unsupported incompatible features and contradictory declarations.
    fn read_only(compat: u32, incompat: u32, read_only_compat: u32) -> Result<Self> {
        if incompat & (INCOMPAT_FILETYPE | INCOMPAT_EXTENTS)
            != (INCOMPAT_FILETYPE | INCOMPAT_EXTENTS)
        {
            return Err(Error::UnsupportedReadOnlyFeature);
        }
        if incompat & INCOMPAT_JOURNAL_DEV != 0 {
            return Err(Error::UnsupportedReadOnlyFeature);
        }
        if incompat
            & !(INCOMPAT_FILETYPE
                | INCOMPAT_RECOVER
                | INCOMPAT_EXTENTS
                | INCOMPAT_64BIT
                | INCOMPAT_FLEX_BG
                | INCOMPAT_CSUM_SEED
                | INCOMPAT_ENCRYPT
                | INCOMPAT_META_BG
                | INCOMPAT_MMP
                | INCOMPAT_EA_INODE
                | INCOMPAT_LARGEDIR
                | INCOMPAT_INLINE_DATA
                | INCOMPAT_CASEFOLD)
            != 0
        {
            return Err(Error::UnsupportedReadOnlyFeature);
        }
        if incompat & INCOMPAT_META_BG != 0 {
            return Err(Error::UnsupportedReadOnlyFeature);
        }
        if incompat & (INCOMPAT_INLINE_DATA | INCOMPAT_EA_INODE) != 0
            && compat & COMPAT_EXT_ATTR == 0
        {
            return Err(Error::UnsupportedReadOnlyFeature);
        }
        if incompat & INCOMPAT_CSUM_SEED != 0 && read_only_compat & RO_COMPAT_METADATA_CSUM == 0 {
            return Err(Error::UnsupportedReadOnlyFeature);
        }
        if read_only_compat & RO_COMPAT_ORPHAN_PRESENT != 0 && compat & COMPAT_ORPHAN_FILE == 0 {
            return Err(Error::InvalidOrphanTracking);
        }
        Ok(Self::from_raw(compat, incompat, read_only_compat))
    }

    /// Keeps one immutable authority for all typed format interpretations.
    const fn from_raw(compat: u32, incompat: u32, read_only_compat: u32) -> Self {
        Self {
            declared: FilesystemFeatures {
                compatible: CompatibleFeatures(compat),
                incompatible: IncompatibleFeatures(incompat),
                read_only_compatible: ReadOnlyCompatibleFeatures(read_only_compat),
            },
        }
    }

    /// Returns the descriptor layout implied by validated feature bits.
    pub(crate) const fn descriptor_layout(self) -> BlockGroupDescriptorLayout {
        if self.declared.incompatible.bits() & INCOMPAT_64BIT != 0 {
            BlockGroupDescriptorLayout::SixtyFourBit
        } else {
            BlockGroupDescriptorLayout::Standard32
        }
    }

    /// Returns the sparse-superblock layout.
    pub(crate) const fn sparse_superblock_layout(self) -> SparseSuperblockLayout {
        if self.declared.read_only_compatible.bits() & RO_COMPAT_SPARSE_SUPER != 0 {
            SparseSuperblockLayout::SparseCopies
        } else {
            SparseSuperblockLayout::FullCopies
        }
    }

    /// Returns the directory indexing capability.
    pub(crate) const fn directory_indexing(self) -> DirectoryIndexing {
        if self.declared.compatible.bits() & COMPAT_DIR_INDEX == 0 {
            DirectoryIndexing::Disabled
        } else if self.declared.incompatible.bits() & INCOMPAT_LARGEDIR != 0 {
            DirectoryIndexing::LargeDirectory
        } else {
            DirectoryIndexing::Standard
        }
    }

    /// Mounted directory reference accounting.
    pub(crate) const fn directory_links(self) -> crate::disk_format::inode::DirectoryLinkEncoding {
        if self.declared.read_only_compatible.bits() & RO_COMPAT_DIR_NLINK != 0 {
            crate::disk_format::inode::DirectoryLinkEncoding::Uncounted
        } else {
            crate::disk_format::inode::DirectoryLinkEncoding::Counted
        }
    }

    /// Returns the allocation bitmap addressing domain.
    pub(crate) const fn allocation_bitmap_domain(self) -> AllocationBitmapDomain {
        if self.declared.read_only_compatible.bits() & RO_COMPAT_BIGALLOC != 0 {
            AllocationBitmapDomain::Clusters
        } else {
            AllocationBitmapDomain::Blocks
        }
    }

    /// Returns the checksum seed source.
    pub(crate) const fn checksum_seed_source(self) -> ChecksumSeedSource {
        if self.declared.incompatible.bits() & INCOMPAT_CSUM_SEED != 0 {
            ChecksumSeedSource::SuperblockField
        } else if matches!(self.metadata_checksum(), MetadataChecksum::Crc32c) {
            ChecksumSeedSource::FilesystemUuid
        } else {
            ChecksumSeedSource::Zero
        }
    }

    /// Returns the public xattr mutation capability.
    pub(crate) const fn xattr_mutation(self) -> XattrMutationSupport {
        if self.declared.compatible.bits() & COMPAT_EXT_ATTR != 0 {
            XattrMutationSupport::Enabled
        } else {
            XattrMutationSupport::Disabled
        }
    }

    /// Whether the filesystem declares that verity inodes may be stored.
    pub(crate) const fn verity(self) -> bool {
        self.declared.read_only_compatible.bits() & RO_COMPAT_VERITY != 0
    }

    /// Inode-body payload storage admitted for files and directories.
    pub(crate) const fn inline_data(self) -> bool {
        self.declared.incompatible.bits() & INCOMPAT_INLINE_DATA != 0
    }

    /// Separate value inodes may be referenced by attribute entries.
    pub(crate) const fn attribute_values(self) -> bool {
        self.declared.incompatible.bits() & INCOMPAT_EA_INODE != 0
    }

    /// File-size encoding supported by inode records.
    pub(crate) const fn file_size_encoding(self) -> FileSizeEncoding {
        if self.declared.read_only_compatible.bits() & RO_COMPAT_LARGE_FILE != 0 {
            FileSizeEncoding::LargeFile
        } else {
            FileSizeEncoding::Legacy
        }
    }

    /// Directory-size encoding selected by the incompatible large-directory feature.
    pub(crate) const fn directory_size_encoding(self) -> DirectorySizeEncoding {
        if self.declared.incompatible.bits() & INCOMPAT_LARGEDIR != 0 {
            DirectorySizeEncoding::LargeDirectory
        } else {
            DirectorySizeEncoding::Standard
        }
    }

    /// Inode block-count encoding supported by inode records.
    pub(crate) const fn inode_block_count_encoding(self) -> InodeBlockCountEncoding {
        if self.declared.read_only_compatible.bits() & RO_COMPAT_HUGE_FILE != 0 {
            InodeBlockCountEncoding::HugeFile
        } else {
            InodeBlockCountEncoding::LegacySectors
        }
    }

    /// Returns the inode timestamp encoding capability.
    pub(crate) const fn inode_timestamp_encoding(self) -> InodeTimestampEncoding {
        if self.declared.read_only_compatible.bits() & RO_COMPAT_EXTRA_ISIZE != 0 {
            InodeTimestampEncoding::ExtraFields
        } else {
            InodeTimestampEncoding::LegacySeconds
        }
    }

    /// Returns the metadata checksum mode.
    pub(crate) const fn metadata_checksum(self) -> MetadataChecksum {
        if self.declared.read_only_compatible.bits() & RO_COMPAT_METADATA_CSUM != 0 {
            MetadataChecksum::Crc32c
        } else {
            MetadataChecksum::None
        }
    }

    /// Returns the active block group descriptor checksum mode.
    pub(crate) const fn descriptor_checksum(self) -> BlockGroupDescriptorChecksum {
        if matches!(self.metadata_checksum(), MetadataChecksum::Crc32c) {
            BlockGroupDescriptorChecksum::MetadataCrc32c
        } else if self.declared.read_only_compatible.bits() & RO_COMPAT_GDT_CSUM != 0 {
            BlockGroupDescriptorChecksum::GdtCrc16
        } else {
            BlockGroupDescriptorChecksum::None
        }
    }

    /// Returns the journal recovery state.
    pub(crate) const fn recovery_state(self) -> RecoveryState {
        if self.declared.incompatible.bits() & INCOMPAT_RECOVER != 0 {
            RecoveryState::NeedsRecovery
        } else {
            RecoveryState::Clean
        }
    }

    /// Returns whether the filesystem advertises a journal.
    pub(crate) const fn has_journal(self) -> bool {
        self.declared.compatible.bits() & COMPAT_HAS_JOURNAL != 0
    }

    /// Returns whether the 64-bit descriptor feature is present.
    pub(crate) const fn has_64bit(self) -> bool {
        self.declared.incompatible.bits() & INCOMPAT_64BIT != 0
    }

    /// Returns whether the reserved online-resize metadata inode is present.
    pub(crate) const fn has_resize_inode(self) -> bool {
        self.declared.compatible.bits() & COMPAT_RESIZE_INODE != 0
    }
}

/// Superblock whose structural fields and mount policy are validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
    /// On-disk health flags; observation does not imply cleanup permission.
    state: u16,
    /// Validated filesystem block size.
    block_size: BlockSize,
    /// Total inode count.
    inode_count: InodeCount,
    /// Total block count.
    block_count: BlockCount,
    /// Allocation cluster size.
    cluster_size: ClusterSize,
    /// Blocks covered by one allocation cluster.
    blocks_per_cluster: BlocksPerCluster,
    /// Total allocation cluster count.
    cluster_count: ClusterCount,
    /// Total free cluster count advertised by the superblock.
    free_clusters_count: FreeClusterCount,
    /// Mount-fixed reservation in the allocation domain; it is not allocated bitmap space.
    reserved_clusters_count: ReservedClusterCount,
    /// Total free inode count advertised by the superblock.
    free_inodes_count: FreeInodeCount,
    /// First block that can contain filesystem data.
    first_data_block: BlockAddress,
    /// Blocks assigned to each block group.
    blocks_per_group: BlocksPerGroup,
    /// Expansion blocks reserved after each primary or backup descriptor table.
    reserved_gdt_blocks: ReservedGdtBlockCount,
    /// Allocation clusters assigned to each block group.
    clusters_per_group: ClustersPerGroup,
    /// Inodes assigned to each block group.
    inodes_per_group: InodesPerGroup,
    /// Validated inode record size.
    inode_size: InodeRecordSize,
    /// First non-reserved inode number.
    first_inode: InodeId,
    /// Validated block group descriptor size.
    descriptor_size: BlockGroupDescriptorSize,
    /// Journal placement selected from superblock feature fields.
    journal_mode: JournalMode,
    /// Validated special orphan-file identity and entry-validity marker.
    orphan_file: Option<OrphanFile>,
    /// Head of the fallback orphan chain; each member stores its successor in i_dtime.
    last_orphan: Option<InodeId>,
    /// Filesystem UUID used for checksums and journal matching.
    uuid: FilesystemUuid,
    /// Filesystem volume label stored in the superblock.
    volume_label: Ext4VolumeLabel,
    /// Seed used for metadata CRC32C calculations.
    checksum_seed: ChecksumSeed,
    /// Seed used by indexed directory hashing.
    directory_hash_seed: DirectoryHashSeed,
    /// Byte interpretation selected by the filesystem flags.
    directory_hash_signedness: DirectoryHashSignedness,
    /// Default hash version used when an HTree root does not override it.
    default_directory_hash_version: DirectoryHashVersion,
    /// Encoding capability present only when the filesystem advertises casefold.
    casefold: Option<super::name::NameSemantics>,
    /// Independent media ownership record; journal replay never establishes its lease.
    mmp: Option<super::mmp::MmpParameters>,
    /// Feature bits validated for this mount policy.
    features: FeatureSet,
}

impl Superblock {
    /// Compares the immutable interpretation fixed by a mounted session. Allocation counters,
    /// health, labels and journal/orphan session markers may legitimately differ on media.
    pub(crate) fn same_media_identity(self, other: Self) -> bool {
        self.uuid == other.uuid
            && self.block_size == other.block_size
            && self.inode_count == other.inode_count
            && self.block_count == other.block_count
            && self.reserved_clusters_count == other.reserved_clusters_count
            && self.cluster_size == other.cluster_size
            && self.first_data_block == other.first_data_block
            && self.blocks_per_group == other.blocks_per_group
            && self.reserved_gdt_blocks == other.reserved_gdt_blocks
            && self.clusters_per_group == other.clusters_per_group
            && self.inodes_per_group == other.inodes_per_group
            && self.inode_size == other.inode_size
            && self.first_inode == other.first_inode
            && self.descriptor_size == other.descriptor_size
            && self.journal_mode == other.journal_mode
            && self.orphan_file.map(|file| file.inode) == other.orphan_file.map(|file| file.inode)
            && self.checksum_seed == other.checksum_seed
            && self.directory_hash_seed == other.directory_hash_seed
            && self.directory_hash_signedness == other.directory_hash_signedness
            && self.default_directory_hash_version == other.default_directory_hash_version
            && self.casefold == other.casefold
            && self.mmp == other.mmp
            && self.features.declared.compatible == other.features.declared.compatible
            && self.features.declared.incompatible.bits() & !INCOMPAT_RECOVER
                == other.features.declared.incompatible.bits() & !INCOMPAT_RECOVER
            && self.features.declared.read_only_compatible.bits() & !RO_COMPAT_ORPHAN_PRESENT
                == other.features.declared.read_only_compatible.bits() & !RO_COMPAT_ORPHAN_PRESENT
    }

    /// Reports persistent health requiring an offline filesystem check, independently of the
    /// journal recovery marker maintained during every writable session.
    #[must_use]
    pub const fn requires_check(self) -> bool {
        self.state & (EXT4_VALID_FS | EXT4_ERROR_FS) != EXT4_VALID_FS
    }

    /// Records an explicit check requirement without changing unrelated session state.
    pub(crate) fn mark_filesystem_error(&mut self) {
        self.state |= EXT4_ERROR_FS;
    }

    /// Adds the persistent error-state bit to an already authenticated superblock image.
    /// # Errors
    /// Returns a truncated state field; the caller refreshes the complete metadata checksum.
    pub(crate) fn mark_filesystem_error_in_raw(raw: &mut [u8]) -> Result<()> {
        let state = le_u16(raw, disk_offset(58))?;
        put_le_u16(raw, disk_offset(58), state | EXT4_ERROR_FS)
    }
    /// Reads only the magic and policy-selection identity. This does not admit any filesystem.
    /// # Errors
    /// Returns read suspension, truncated input or invalid magic.
    pub(crate) fn probe_uuid(device: &mut OperationDevice<'_>) -> Result<FilesystemUuid> {
        let mut raw = [0_u8; SUPERBLOCK_SIZE];
        device.read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)?;
        if le_u16(&raw, disk_offset(56))? != EXT4_SUPER_MAGIC {
            return Err(Error::InvalidMagic);
        }
        let mut uuid = [0; 16];
        memory::copy_exact(
            &mut uuid,
            raw.get(104..120).ok_or(Error::TruncatedStructure)?,
        )?;
        Ok(FilesystemUuid::from_bytes(uuid))
    }

    /// Selects strict read-only validation or journal-authenticated writable/private recovery.
    /// # Errors
    /// Returns read suspension, checksum, feature or geometry failures.
    pub(crate) fn read_for_mount(
        device: &mut OperationDevice<'_>,
        access: crate::MountAccess,
    ) -> Result<PrimarySuperblockRead> {
        match access {
            crate::MountAccess::ReadOnly {
                recovery: crate::ReadOnlyRecovery::Replay | crate::ReadOnlyRecovery::NoLoad,
            } => {
                let mut raw = [0_u8; SUPERBLOCK_SIZE];
                device.read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)?;
                Self::parse_read_only(&raw).map(PrimarySuperblockRead::Valid)
            }
            _ => Self::read_write_from(device),
        }
    }

    /// Reads and validates the primary ext4 superblock for read-write mode.
    ///
    /// # Errors
    /// Returns an error when the superblock cannot support journaled writes.
    pub(crate) fn read_write_from(
        device: &mut OperationDevice<'_>,
    ) -> Result<PrimarySuperblockRead> {
        let mut raw = [0_u8; SUPERBLOCK_SIZE];
        device.read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)?;
        match Self::parse_read_write(&raw) {
            Ok(superblock) => Ok(PrimarySuperblockRead::Valid(superblock)),
            Err(Error::ChecksumMismatch) => Self::parse_with_policy(
                &raw,
                FeatureSet::read_write,
                crate::MediaAccess::ReadWrite,
                SuperblockChecksumValidation::DeferredToJournalReplay,
            )
            .map(ChecksumInvalidSuperblock)
            .map(PrimarySuperblockRead::ChecksumInvalid),
            Err(error) => Err(error),
        }
    }

    /// Parses and validates a 1024-byte superblock payload for read-write mode.
    ///
    /// # Errors
    /// Returns an error when the payload cannot support journaled writes.
    pub fn parse_read_write(raw: &[u8]) -> Result<Self> {
        Self::parse_with_policy(
            raw,
            FeatureSet::read_write,
            crate::MediaAccess::ReadWrite,
            SuperblockChecksumValidation::Required,
        )
    }

    /// Validates a read-only view without requiring a journal or writable-compatible features.
    /// # Errors
    /// Rejects invalid checksums, geometry and unsupported read formats.
    pub fn parse_read_only(raw: &[u8]) -> Result<Self> {
        Self::parse_with_policy(
            raw,
            FeatureSet::read_only,
            crate::MediaAccess::ReadOnly,
            SuperblockChecksumValidation::Required,
        )
    }

    /// Parses an admitted metadata update, including no-journal orphan cleanup.
    /// # Errors
    /// Rejects unsupported updates and malformed or unauthenticated bytes.
    pub(crate) fn parse_mutable(raw: &[u8]) -> Result<Self> {
        Self::parse_with_policy(
            raw,
            FeatureSet::mutable,
            crate::MediaAccess::ReadOnly,
            SuperblockChecksumValidation::Required,
        )
    }

    /// Orphan cleanup requires implemented writable features and no recorded filesystem error.
    pub(crate) fn permits_orphan_cleanup(self) -> bool {
        self.state & EXT4_ERROR_FS == 0
            && FeatureSet::mutable(
                self.features.declared.compatible.bits(),
                self.features.declared.incompatible.bits(),
                self.features.declared.read_only_compatible.bits(),
            )
            .is_ok()
    }

    /// Clears recovery markers after ordinary RO recovery without recording a writable mount.
    /// # Errors
    /// Returns source-read suspension, checksum or field-encoding failure before publication.
    pub(crate) fn prepare_read_only_completion(
        device: &mut OperationDevice<'_>,
        unix_seconds: u64,
    ) -> Result<Option<[u8; SUPERBLOCK_SIZE]>> {
        let mut raw = [0; SUPERBLOCK_SIZE];
        device.read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)?;
        Self::parse_read_only(&raw)?;
        let incompat = le_u32(&raw, disk_offset(96))?;
        let ro = le_u32(&raw, disk_offset(100))?;
        if incompat & INCOMPAT_RECOVER == 0 && ro & RO_COMPAT_ORPHAN_PRESENT == 0 {
            return Ok(None);
        }
        put_le_u32(&mut raw, disk_offset(96), incompat & !INCOMPAT_RECOVER)?;
        put_le_u32(&mut raw, disk_offset(100), ro & !RO_COMPAT_ORPHAN_PRESENT)?;
        Self::update_write_time(&mut raw, unix_seconds)?;
        Self::refresh_checksum(&mut raw)?;
        Ok(Some(raw))
    }

    /// Parses a raw superblock with the supplied feature validation policy.
    /// # Errors
    ///
    /// Returns an error when the payload is truncated, has invalid magic or dirty state, fails the
    /// feature policy, contains invalid geometry, or carries an invalid checksum/journal/hash field.
    fn parse_with_policy(
        raw: &[u8],
        validate_features: fn(u32, u32, u32) -> Result<FeatureSet>,
        access: crate::MediaAccess,
        checksum_validation: SuperblockChecksumValidation,
    ) -> Result<Self> {
        if raw.len() < SUPERBLOCK_SIZE {
            return Err(Error::TruncatedStructure);
        }
        if le_u16(raw, disk_offset(56))? != EXT4_SUPER_MAGIC {
            return Err(Error::InvalidMagic);
        }
        // Feature fields and dynamic inode geometry are defined by revision one.
        if le_u32(raw, disk_offset(76))? != 1 {
            return Err(Error::UnsupportedWriteFeature);
        }
        let state = le_u16(raw, disk_offset(58))?;
        if access == crate::MediaAccess::ReadWrite && state & EXT4_VALID_FS == 0 {
            return Err(Error::DirtyVolume);
        }

        let inode_count = InodeCount::new(le_u32(raw, disk_offset(0))?)?;
        let block_count_lo = le_u32(raw, disk_offset(4))?;
        let free_inodes_count = FreeInodeCount::new(le_u32(raw, disk_offset(16))?);
        let first_data_block = BlockAddress::new(u64::from(le_u32(raw, disk_offset(20))?));
        let log_block_size = le_u32(raw, disk_offset(24))?;
        let log_cluster_size = le_u32(raw, disk_offset(28))?;
        let block_size = BlockSize::from_superblock_log(log_block_size)?;
        let blocks_per_group = BlocksPerGroup::new(le_u32(raw, disk_offset(32))?)?;
        let reserved_gdt_blocks =
            ReservedGdtBlockCount::new(le_u16(raw, disk_offset(RESERVED_GDT_BLOCKS_OFFSET))?);
        let raw_clusters_per_group = le_u32(raw, disk_offset(36))?;
        let inodes_per_group = InodesPerGroup::new(le_u32(raw, disk_offset(40))?)?;
        let first_inode = InodeId::try_from(le_u32(raw, disk_offset(84))?)?;
        let inode_size = InodeRecordSize::new(le_u16(raw, disk_offset(88))?, block_size)?;
        let features = validate_features(
            le_u32(raw, disk_offset(92))?,
            le_u32(raw, disk_offset(96))?,
            le_u32(raw, disk_offset(100))?,
        )?;
        if features.metadata_checksum() == MetadataChecksum::Crc32c
            && *raw.get(0x175).ok_or(Error::TruncatedStructure)? != 1
        {
            return Err(Error::UnsupportedWriteFeature);
        }
        let raw_descriptor_size = if features.has_64bit() {
            let raw_size = le_u16(raw, disk_offset(254))?;
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
                    u64::from(le_u32(raw, disk_offset(336))?) << 32
                } else {
                    0
                },
        )?;
        let free_blocks_count = OnDiskFreeBlockCount::parse(raw, features.has_64bit())?;
        let geometry = ClusterGeometry::new(RawClusterGeometry {
            block_count,
            first_data_block,
            block_size,
            log_block_size,
            log_cluster_size,
            blocks_per_group,
            clusters_per_group: raw_clusters_per_group,
            allocation_bitmap_domain: features.allocation_bitmap_domain(),
        })?;
        let free_clusters_count = free_blocks_count
            .into_free_cluster_count(geometry.blocks_per_cluster, geometry.cluster_count)?;
        let reserved_clusters_count = ReservedClusterCount::parse(
            raw,
            features.has_64bit(),
            block_count,
            geometry.blocks_per_cluster,
        )?;
        match (features.metadata_checksum(), checksum_validation) {
            (MetadataChecksum::None, _) => {}
            (MetadataChecksum::Crc32c, SuperblockChecksumValidation::DeferredToJournalReplay) => {}
            (MetadataChecksum::Crc32c, SuperblockChecksumValidation::Required) => {
                let expected = le_u32(raw, disk_offset(SUPERBLOCK_CHECKSUM_OFFSET))?;
                let checksum_input = raw
                    .get(..SUPERBLOCK_CHECKSUM_OFFSET)
                    .ok_or(Error::TruncatedStructure)?;
                if ext4_crc32c(u32::MAX, checksum_input) != expected {
                    return Err(Error::ChecksumMismatch);
                }
            }
        }
        let journal_inode = le_u32(raw, disk_offset(224))?;
        let mut uuid = [0_u8; 16];
        memory::copy_exact(
            &mut uuid,
            raw.get(104..120).ok_or(Error::TruncatedStructure)?,
        )?;
        let volume_label = Ext4VolumeLabel::parse(raw)?;
        let mut journal_uuid = [0_u8; 16];
        memory::copy_exact(
            &mut journal_uuid,
            raw.get(208..224).ok_or(Error::TruncatedStructure)?,
        )?;
        let journal_uuid = JournalUuid::from_bytes(journal_uuid);
        let journal_mode = if features.has_journal() {
            if journal_inode == 0 {
                if journal_uuid.is_zero() {
                    return Err(Error::InvalidSuperblock);
                }
                JournalMode::External(journal_uuid)
            } else {
                if !journal_uuid.is_zero() {
                    return Err(Error::InvalidSuperblock);
                }
                JournalMode::Internal(InodeId::try_from(journal_inode)?)
            }
        } else {
            JournalMode::None
        };
        let checksum_seed = features.checksum_seed_source().seed(raw, &uuid)?;
        let orphan_id = |value| -> Result<Option<InodeId>> {
            if value == 0 {
                return Ok(None);
            }
            if value > inode_count.as_u32() {
                return Err(Error::InvalidOrphanTracking);
            }
            Ok(Some(InodeId::try_from(value)?))
        };
        let orphan_file = if le_u32(raw, disk_offset(92))? & COMPAT_ORPHAN_FILE != 0 {
            Some(OrphanFile {
                inode: orphan_id(le_u32(raw, disk_offset(0x280))?)?
                    .ok_or(Error::InvalidOrphanTracking)?,
                present: le_u32(raw, disk_offset(100))? & RO_COMPAT_ORPHAN_PRESENT != 0,
            })
        } else {
            None
        };
        let last_orphan = orphan_id(le_u32(raw, disk_offset(0xe8))?)?;
        let directory_hash_seed = DirectoryHashSeed::from_words([
            le_u32(raw, disk_offset(DIRECTORY_HASH_SEED_OFFSET))?,
            le_u32(raw, disk_offset(DIRECTORY_HASH_SEED_OFFSET + 4))?,
            le_u32(raw, disk_offset(DIRECTORY_HASH_SEED_OFFSET + 8))?,
            le_u32(raw, disk_offset(DIRECTORY_HASH_SEED_OFFSET + 12))?,
        ]);
        let default_directory_hash_version = DirectoryHashVersion::from_raw(
            *raw.get(DEFAULT_DIRECTORY_HASH_VERSION_OFFSET)
                .ok_or(Error::TruncatedStructure)?,
        )?;
        let directory_hash_signedness =
            DirectoryHashSignedness::from_flags(le_u32(raw, disk_offset(FILESYSTEM_FLAGS_OFFSET))?);
        let uuid = FilesystemUuid::from_bytes(uuid);
        let casefold = if le_u32(raw, disk_offset(96))? & INCOMPAT_CASEFOLD != 0 {
            Some(super::name::NameSemantics::from_encoding(
                le_u16(raw, disk_offset(0x27c))?,
                le_u16(raw, disk_offset(0x27e))?,
            )?)
        } else {
            None
        };

        let mmp = if le_u32(raw, disk_offset(96))? & INCOMPAT_MMP != 0 {
            let block = BlockAddress::new(le_u64(raw, disk_offset(0x168))?);
            if block.get() <= first_data_block.get() || block.get() >= block_count.as_u64() {
                return Err(Error::MmpCorrupt);
            }
            Some(super::mmp::MmpParameters {
                block,
                bytes: block_size,
                seed: (features.metadata_checksum() == MetadataChecksum::Crc32c)
                    .then_some(checksum_seed.as_u32()),
                update_seconds: le_u16(raw, disk_offset(0x166))?,
            })
        } else {
            None
        };
        Ok(Self {
            block_size,
            inode_count,
            block_count,
            state,
            cluster_size: geometry.cluster_size,
            blocks_per_cluster: geometry.blocks_per_cluster,
            cluster_count: geometry.cluster_count,
            free_clusters_count,
            reserved_clusters_count,
            free_inodes_count,
            first_data_block,
            blocks_per_group,
            reserved_gdt_blocks,
            clusters_per_group: geometry.clusters_per_group,
            inodes_per_group,
            inode_size,
            first_inode,
            descriptor_size,
            journal_mode,
            orphan_file,
            last_orphan,
            uuid,
            volume_label,
            checksum_seed,
            directory_hash_seed,
            directory_hash_signedness,
            default_directory_hash_version,
            casefold,
            mmp,
            features,
        })
    }

    /// Declared format features of this validated superblock, without granting mutation authority.
    #[must_use]
    pub const fn features(self) -> FilesystemFeatures {
        self.features.declared
    }

    /// Independent ownership placement selected by the primary superblock.
    pub(crate) const fn mmp(self) -> Option<super::mmp::MmpParameters> {
        self.mmp
    }

    /// Requires the feature and encoding needed to change a directory's comparison state.
    /// # Errors
    /// Rejects a filesystem without a declared casefold encoding.
    pub(crate) fn require_casefold(self) -> Result<()> {
        self.casefold
            .ok_or(Error::UnsupportedWriteFeature)
            .map(|_names| ())
    }

    /// Selects one directory's comparison contract from immutable mounted encoding authority.
    /// # Errors
    /// Rejects undeclared casefold state or a non-directory inode.
    pub(crate) fn name_semantics(
        self,
        inode: &super::inode::Inode,
    ) -> Result<super::name::NameSemantics> {
        if !inode.flags().has_casefold() {
            return Ok(super::name::NameSemantics::Bytewise);
        }
        if inode.kind() != super::inode::InodeKind::Directory {
            return Err(Error::InvalidInode);
        }
        self.casefold.ok_or(Error::InvalidInode)
    }

    /// Filesystem block containing the primary superblock for this block size.
    pub(crate) const fn primary_block(block_size: BlockSize) -> BlockAddress {
        if block_size.bytes() == 1024 {
            BlockAddress::new(1)
        } else {
            BlockAddress::new(0)
        }
    }

    /// Validates the primary-superblock payload embedded in a journaled filesystem block.
    /// # Errors
    ///
    /// Returns an error when the block does not contain a complete, checksum-valid primary
    /// superblock accepted by the read-write feature policy.
    pub(crate) fn parse_primary_block(block: &[u8], block_size: BlockSize) -> Result<Self> {
        let offset = if block_size.bytes() == 1024 {
            0
        } else {
            usize::try_from(SUPERBLOCK_OFFSET).map_err(|_| Error::ArithmeticOverflow)?
        };
        let end = offset
            .checked_add(SUPERBLOCK_SIZE)
            .ok_or(Error::ArithmeticOverflow)?;
        Self::parse_read_write(block.get(offset..end).ok_or(Error::TruncatedStructure)?)
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

    /// Allocation cluster size.
    #[must_use]
    pub const fn cluster_size(self) -> ClusterSize {
        self.cluster_size
    }

    /// Blocks covered by one allocation cluster.
    #[must_use]
    pub const fn blocks_per_cluster(self) -> BlocksPerCluster {
        self.blocks_per_cluster
    }

    /// Total allocation cluster count.
    #[must_use]
    pub const fn cluster_count(self) -> ClusterCount {
        self.cluster_count
    }

    /// Total free allocation cluster count.
    #[must_use]
    pub const fn free_cluster_count(self) -> FreeClusterCount {
        self.free_clusters_count
    }

    /// Free whole clusters available without authority to consume reserved blocks.
    /// The reservation may exceed current free space; that leaves zero available clusters.
    #[must_use]
    pub const fn available_cluster_count(self) -> FreeClusterCount {
        self.reserved_clusters_count
            .available(self.free_clusters_count)
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

    /// Descriptor-table expansion blocks reserved in every superblock group.
    #[must_use]
    pub(crate) const fn reserved_gdt_blocks(self) -> ReservedGdtBlockCount {
        self.reserved_gdt_blocks
    }

    /// Allocation clusters per block group.
    #[must_use]
    pub const fn clusters_per_group(self) -> ClustersPerGroup {
        self.clusters_per_group
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

    /// Returns whether `inode` is the reserved online-resize metadata inode.
    pub(crate) const fn is_resize_inode(self, inode: InodeId) -> bool {
        self.features.has_resize_inode() && inode.as_u32() == EXT4_RESIZE_INODE_ID
    }

    /// Keeps filesystem-owned metadata outside the user namespace, including file-ID opens.
    /// Root is the only namespace inode below `s_first_ino`; configured journal and orphan
    /// inodes remain private even when their numbers are in the ordinary allocation range.
    /// # Errors
    /// Returns invalid inode for a reserved, metadata-owned, or out-of-volume identity.
    pub(crate) fn require_namespace_inode(self, inode: InodeId) -> Result<()> {
        if (inode != InodeId::ROOT && inode.as_u32() < self.first_inode.as_u32())
            || inode.as_u32() > self.inode_count.as_u32()
            || self.journal_mode == JournalMode::Internal(inode)
            || self.orphan_file.is_some_and(|file| file.inode == inode)
        {
            return Err(Error::InvalidInode);
        }
        Ok(())
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

    /// Filesystem volume label.
    #[must_use]
    pub const fn volume_label(self) -> Ext4VolumeLabel {
        self.volume_label
    }

    /// Metadata checksum seed.
    #[must_use]
    pub const fn checksum_seed(self) -> ChecksumSeed {
        self.checksum_seed
    }

    /// Directory hash seed used by indexed directories.
    #[must_use]
    pub(crate) const fn directory_hash_seed(self) -> DirectoryHashSeed {
        self.directory_hash_seed
    }

    /// Filesystem-wide byte interpretation applied to base hash versions.
    pub(crate) const fn directory_hash_signedness(self) -> DirectoryHashSignedness {
        self.directory_hash_signedness
    }

    /// Default directory hash algorithm recorded by the superblock.
    #[must_use]
    pub(crate) const fn default_directory_hash_version(self) -> DirectoryHashVersion {
        self.default_directory_hash_version
    }

    /// Returns the directory indexing capability.
    #[must_use]
    pub(crate) const fn directory_indexing(self) -> DirectoryIndexing {
        self.features.directory_indexing()
    }

    /// Returns the public xattr mutation capability.
    #[must_use]
    pub(crate) const fn xattr_mutation(self) -> XattrMutationSupport {
        self.features.xattr_mutation()
    }

    /// Requires filesystem-level admission before creating a verity inode.
    /// # Errors
    /// Returns [`Error::UnsupportedVerity`] when the filesystem lacks `RO_COMPAT_VERITY`.
    pub(crate) const fn require_verity(self) -> Result<()> {
        if self.features.verity() {
            Ok(())
        } else {
            Err(Error::UnsupportedVerity)
        }
    }

    /// Physical attribute-value storage admitted by the filesystem feature set.
    pub(crate) const fn attribute_value_storage(
        self,
    ) -> crate::disk_format::xattr::AttributeValueStorage {
        if self.features.attribute_values() {
            crate::disk_format::xattr::AttributeValueStorage::Inodes
        } else {
            crate::disk_format::xattr::AttributeValueStorage::LocalOnly
        }
    }
    /// Whether new files may select inode-body storage without changing feature flags.
    pub(crate) const fn supports_inline_data(self) -> bool {
        self.features.inline_data()
    }

    /// Returns the single mounted encoding for inode size and allocation fields.
    #[must_use]
    pub(crate) const fn inode_data_encoding(self) -> InodeDataEncoding {
        InodeDataEncoding::new(
            self.features.file_size_encoding(),
            self.features.directory_size_encoding(),
            self.features.inode_block_count_encoding(),
            self.block_size,
            self.features.directory_links(),
            self.features.inline_data(),
            self.features.attribute_values(),
            self.casefold.is_some(),
        )
    }

    /// Returns the inode timestamp encoding capability.
    #[must_use]
    pub(crate) const fn inode_timestamp_encoding(self) -> InodeTimestampEncoding {
        self.features.inode_timestamp_encoding()
    }

    /// Metadata checksum mode.
    #[must_use]
    pub const fn metadata_checksum(self) -> MetadataChecksum {
        self.features.metadata_checksum()
    }

    /// Returns the descriptor layout implied by validated feature bits.
    pub(crate) const fn descriptor_layout(self) -> BlockGroupDescriptorLayout {
        self.features.descriptor_layout()
    }

    /// Returns the active block group descriptor checksum mode.
    pub(crate) const fn descriptor_checksum(self) -> BlockGroupDescriptorChecksum {
        self.features.descriptor_checksum()
    }

    /// Returns the sparse-superblock layout.
    pub(crate) const fn sparse_superblock_layout(self) -> SparseSuperblockLayout {
        self.features.sparse_superblock_layout()
    }

    /// Returns the journal recovery state.
    #[must_use]
    pub const fn recovery_state(self) -> RecoveryState {
        self.features.recovery_state()
    }

    /// Orphan-file identity, when that on-disk feature is enabled.
    pub(crate) const fn orphan_file(self) -> Option<OrphanFile> {
        self.orphan_file
    }

    /// First fallback-chain member still requiring recovery.
    pub(crate) const fn last_orphan(self) -> Option<InodeId> {
        self.last_orphan
    }

    /// Prepares session markers and clocks for one journal commit. Opening increments the
    /// unsigned mount count modulo 2^16 and sets both clocks; closing preserves mount facts.
    /// Hash interpretation is fixed before any directory mutation can publish.
    /// # Errors
    /// Returns an error when reading, validating, or checksumming the primary image fails.
    pub(crate) fn prepare_write_session(
        device: &mut OperationDevice<'_>,
        state: WriteSessionState,
        unix_seconds: u64,
    ) -> Result<[u8; SUPERBLOCK_SIZE]> {
        let mut raw = [0_u8; SUPERBLOCK_SIZE];
        device.read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)?;
        let superblock = Self::parse_read_write(&raw)?;
        if state == WriteSessionState::Closed && superblock.last_orphan.is_some() {
            return Err(Error::InvalidOrphanTracking);
        }
        let mut incompat = le_u32(&raw, disk_offset(96))? & !INCOMPAT_RECOVER;
        let mut ro_compat = le_u32(&raw, disk_offset(100))? & !RO_COMPAT_ORPHAN_PRESENT;
        Self::update_write_time(&mut raw, unix_seconds)?;
        if state == WriteSessionState::Active {
            let count = le_u16(&raw, disk_offset(0x34))?.wrapping_add(1);
            put_le_u16(&mut raw, disk_offset(0x34), count)?;
            Self::write_timestamp(&mut raw, 0x2c, 0x275, unix_seconds)?;
            incompat |= INCOMPAT_RECOVER;
            let flags = le_u32(&raw, disk_offset(FILESYSTEM_FLAGS_OFFSET))?;
            if flags & (SIGNED_DIRECTORY_HASH | UNSIGNED_DIRECTORY_HASH) == 0 {
                // Persist the chosen interpretation before any directory mutation can publish.
                put_le_u32(
                    &mut raw,
                    disk_offset(FILESYSTEM_FLAGS_OFFSET),
                    flags | SIGNED_DIRECTORY_HASH,
                )?;
            }
            if superblock.orphan_file.is_some() {
                ro_compat |= RO_COMPAT_ORPHAN_PRESENT;
            }
        }
        put_le_u32(&mut raw, disk_offset(96), incompat)?;
        put_le_u32(&mut raw, disk_offset(100), ro_compat)?;
        Self::refresh_checksum(&mut raw)?;
        Ok(raw)
    }

    /// Updates the superblock write clock; callers refresh its checksum after all edits.
    /// # Errors
    /// Returns a truncated-field error without publishing any bytes.
    pub(crate) fn update_write_time(raw: &mut [u8], unix_seconds: u64) -> Result<()> {
        Self::write_timestamp(raw, 0x30, 0x274, unix_seconds)
    }

    /// Superblock clocks are unsigned 40-bit Unix seconds, independent of inode timestamp encoding.
    /// Values beyond that domain saturate rather than wrapping into an earlier date.
    /// # Errors
    /// Returns a truncated-field error before the image can be submitted.
    fn write_timestamp(raw: &mut [u8], low: usize, high: usize, seconds: u64) -> Result<()> {
        let seconds = seconds.min(0xff_ffff_ffff).to_le_bytes();
        memory::copy_exact(
            raw.get_mut(low..low.checked_add(4).ok_or(Error::ArithmeticOverflow)?)
                .ok_or(Error::TruncatedStructure)?,
            seconds.get(..4).ok_or(Error::TruncatedStructure)?,
        )?;
        *raw.get_mut(high).ok_or(Error::TruncatedStructure)? =
            *seconds.get(4).ok_or(Error::TruncatedStructure)?;
        Ok(())
    }

    /// Recomputes the primary superblock checksum when the on-disk checksum is present.
    /// # Errors
    ///
    /// Returns an error when the checksum field cannot be read, zeroed, or rewritten.
    pub(crate) fn refresh_checksum(raw: &mut [u8]) -> Result<()> {
        if le_u32(raw, disk_offset(100))? & RO_COMPAT_METADATA_CSUM == 0 {
            return Ok(());
        }
        let checksum_input = raw
            .get(..SUPERBLOCK_CHECKSUM_OFFSET)
            .ok_or(Error::TruncatedStructure)?;
        let checksum = ext4_crc32c(u32::MAX, checksum_input);
        put_le_u32(raw, disk_offset(SUPERBLOCK_CHECKSUM_OFFSET), checksum)
    }

    /// Number of block groups implied by the superblock.
    ///
    /// # Errors
    /// Returns an error when validated geometry cannot be combined without
    /// overflow.
    pub fn block_group_count(self) -> Result<BlockGroupCount> {
        let groups = round_up_div(
            self.cluster_count.as_u64(),
            u64::from(self.clusters_per_group.as_u32()),
        )?;
        Ok(BlockGroupCount::from_u32(
            u32::try_from(groups).map_err(|_| Error::ArithmeticOverflow)?,
        ))
    }

    /// Returns the allocation cluster containing a physical block.
    /// # Errors
    ///
    /// Returns an error when `block` is outside the filesystem data range or division by the
    /// validated blocks-per-cluster value fails.
    pub(crate) fn cluster_of_block(self, block: BlockAddress) -> Result<ClusterAddress> {
        if block.get() >= self.block_count.as_u64() {
            return Err(Error::InvalidClusterGeometry);
        }
        let relative = block
            .get()
            .checked_sub(self.first_data_block.get())
            .ok_or(Error::InvalidClusterGeometry)?;
        let cluster = relative
            .checked_div(u64::from(self.blocks_per_cluster.as_u32()))
            .ok_or(Error::InvalidClusterGeometry)?;
        if cluster >= self.cluster_count.as_u64() {
            return Err(Error::InvalidClusterGeometry);
        }
        Ok(ClusterAddress::new(cluster))
    }

    /// Returns the first block covered by an allocation cluster.
    /// # Errors
    ///
    /// Returns an error when `cluster` is outside the filesystem or translating it to a block number
    /// overflows.
    pub(crate) fn first_block_of_cluster(self, cluster: ClusterAddress) -> Result<BlockAddress> {
        if cluster.get() >= self.cluster_count.as_u64() {
            return Err(Error::InvalidClusterGeometry);
        }
        Ok(BlockAddress::new(
            self.first_data_block
                .get()
                .checked_add(
                    cluster
                        .get()
                        .checked_mul(u64::from(self.blocks_per_cluster.as_u32()))
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?,
        ))
    }

    /// Returns the number of physical blocks present in a cluster.
    /// # Errors
    ///
    /// Returns an error when the cluster start is invalid or lies beyond the validated block count.
    pub(crate) fn blocks_in_cluster(self, cluster: ClusterAddress) -> Result<u32> {
        let start = self.first_block_of_cluster(cluster)?.get();
        let remaining = self
            .block_count
            .as_u64()
            .checked_sub(start)
            .ok_or(Error::InvalidClusterGeometry)?;
        Ok(core::cmp::min(
            self.blocks_per_cluster.as_u32(),
            u32::try_from(remaining).unwrap_or(u32::MAX),
        ))
    }

    /// Returns the block group containing an allocation cluster.
    /// # Errors
    ///
    /// Returns an error when `cluster` is outside the filesystem or the derived group number exceeds
    /// the on-disk `u32` range.
    pub(crate) fn cluster_group_of(self, cluster: ClusterAddress) -> Result<BlockGroupId> {
        if cluster.get() >= self.cluster_count.as_u64() {
            return Err(Error::InvalidClusterGeometry);
        }
        let group = cluster
            .get()
            .checked_div(u64::from(self.clusters_per_group.as_u32()))
            .ok_or(Error::InvalidClusterGeometry)?;
        Ok(BlockGroupId::from_u32(
            u32::try_from(group).map_err(|_| Error::ArithmeticOverflow)?,
        ))
    }

    /// Returns the group-local bitmap bit for an allocation cluster.
    /// # Errors
    ///
    /// Returns an error when the group start overflows, `cluster` precedes the group, or the derived
    /// bit is outside the group's bitmap domain.
    pub(crate) fn cluster_bit_in_group(
        self,
        cluster: ClusterAddress,
        group: BlockGroupId,
    ) -> Result<u32> {
        let group_start = u64::from(group.as_u32())
            .checked_mul(u64::from(self.clusters_per_group.as_u32()))
            .ok_or(Error::ArithmeticOverflow)?;
        let bit = cluster
            .get()
            .checked_sub(group_start)
            .ok_or(Error::InvalidClusterGeometry)?;
        if bit >= u64::from(self.clusters_per_group.as_u32()) {
            return Err(Error::InvalidClusterGeometry);
        }
        u32::try_from(bit).map_err(|_| Error::ArithmeticOverflow)
    }

    /// Returns the allocation cluster count present in a possibly partial group.
    /// # Errors
    ///
    /// Returns an error when the group start overflows or the group begins beyond the validated
    /// cluster count.
    pub(crate) fn clusters_in_group(self, group: BlockGroupId) -> Result<u32> {
        let group_start = u64::from(group.as_u32())
            .checked_mul(u64::from(self.clusters_per_group.as_u32()))
            .ok_or(Error::ArithmeticOverflow)?;
        let remaining = self
            .cluster_count
            .as_u64()
            .checked_sub(group_start)
            .ok_or(Error::InvalidClusterGeometry)?;
        Ok(core::cmp::min(
            self.clusters_per_group.as_u32(),
            u32::try_from(remaining).unwrap_or(u32::MAX),
        ))
    }

    /// Applies a committed free-cluster delta to the mounted superblock image.
    /// # Errors
    ///
    /// Returns an error when the delta underflows or overflows the free-cluster count, or the result
    /// exceeds the mounted cluster count.
    pub(crate) fn apply_free_cluster_delta(&mut self, delta: FreeClusterDelta) -> Result<()> {
        let raw_delta = delta.as_i64();
        let updated = if raw_delta.is_negative() {
            self.free_clusters_count
                .as_u64()
                .checked_sub(raw_delta.unsigned_abs())
                .ok_or(Error::InvalidClusterGeometry)?
        } else {
            self.free_clusters_count
                .as_u64()
                .checked_add(u64::try_from(raw_delta).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?
        };
        if updated > self.cluster_count.as_u64() {
            return Err(Error::InvalidClusterGeometry);
        }
        self.free_clusters_count = FreeClusterCount::new(updated);
        Ok(())
    }

    /// Applies one committed free-inode delta to this in-memory epoch image.
    /// # Errors
    ///
    /// Returns an error when the delta underflows, overflows, or exceeds total inode count.
    pub(crate) fn apply_free_inode_delta(&mut self, delta: i64) -> Result<()> {
        let current = u64::from(self.free_inodes_count.as_u32());
        let updated = if delta.is_negative() {
            current
                .checked_sub(delta.unsigned_abs())
                .ok_or(Error::InvalidSuperblock)?
        } else {
            current
                .checked_add(u64::try_from(delta).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?
        };
        if updated > u64::from(self.inode_count.as_u32()) {
            return Err(Error::InvalidSuperblock);
        }
        self.free_inodes_count =
            FreeInodeCount::new(u32::try_from(updated).map_err(|_| Error::ArithmeticOverflow)?);
        Ok(())
    }

    /// Applies a committed volume-label replacement to this in-memory epoch image.
    pub(crate) fn apply_volume_label(&mut self, label: Ext4VolumeLabel) {
        self.volume_label = label;
    }

    /// Applies an allocation-cluster delta to the block-based superblock free-space fields.
    /// # Errors
    ///
    /// Returns an error when the raw count is not cluster-aligned, the converted delta overflows,
    /// or the updated count exceeds the mounted allocation geometry.
    pub(crate) fn apply_free_cluster_delta_to_raw(
        self,
        raw: &mut [u8],
        delta: FreeClusterDelta,
    ) -> Result<()> {
        let current = OnDiskFreeBlockCount::parse(raw, self.descriptor_layout().has_high_fields())?;
        let updated =
            current.apply_cluster_delta(delta, self.blocks_per_cluster, self.cluster_count)?;
        updated.write_to(raw, self.descriptor_layout().has_high_fields())
    }
}

/// Divides with upward rounding and overflow checking.
/// # Errors
///
/// Returns an error when the divisor is zero or the rounded addition overflows.
fn round_up_div(value: u64, divisor: u64) -> Result<u64> {
    if divisor == 0 {
        return Err(Error::InvalidClusterGeometry);
    }
    let adjusted = value
        .checked_add(
            divisor
                .checked_sub(1)
                .ok_or(Error::InvalidClusterGeometry)?,
        )
        .ok_or(Error::ArithmeticOverflow)?;
    adjusted
        .checked_div(divisor)
        .ok_or(Error::InvalidClusterGeometry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::endian::put_le_u16;

    /// # Errors
    /// Returns independent field encoding or superblock validation failure.
    /// # Panics
    /// Fails if the 64bit feature does not control the reserved count's high word.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions compare independently encoded block counts with available allocation space"
    )]
    fn reserved_block_words_follow_the_64bit_feature() -> Result<()> {
        for wide in [false, true] {
            let mut raw = primary(false, false, false)?;
            for (offset, value) in [
                (4, 64),
                (8, 3),
                (12, 32),
                (
                    96,
                    INCOMPAT_EXTENTS | INCOMPAT_FILETYPE | if wide { INCOMPAT_64BIT } else { 0 },
                ),
                (336, 2),
                (340, 1),
                (344, 1),
            ] {
                put_le_u32(&mut raw, disk_offset(offset), value)?;
            }
            Superblock::refresh_checksum(&mut raw)?;
            for parsed in [
                Superblock::parse_read_only(&raw)?,
                Superblock::parse_read_write(&raw)?,
            ] {
                assert_eq!(parsed.available_cluster_count().as_u64(), 29);
                assert_eq!(
                    parsed.free_cluster_count().as_u64(),
                    if wide { 0x1_0000_0020 } else { 32 }
                );
            }
        }
        Ok(())
    }

    /// # Errors
    /// Returns independent field encoding or superblock validation failure.
    /// # Panics
    /// Fails if a partial reserved cluster is offered for allocation or availability underflows.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions compare block-unit reservation vectors with whole-cluster availability"
    )]
    fn reserved_blocks_exclude_whole_bigalloc_clusters() -> Result<()> {
        for (reserved, available) in [
            (0, 16),
            (1, 15),
            (3, 15),
            (4, 15),
            (5, 14),
            (64, 0),
            (65, 0),
            (4096, 0),
        ] {
            let mut raw = primary(false, false, false)?;
            for (offset, value) in [
                (8, reserved),
                (12, 64),
                (20, 0),
                (24, 2),
                (28, 4),
                (32, 32768),
                (36, 8192),
                (100, RO_COMPAT_METADATA_CSUM | RO_COMPAT_BIGALLOC),
            ] {
                put_le_u32(&mut raw, disk_offset(offset), value)?;
            }
            Superblock::refresh_checksum(&mut raw)?;
            for parsed in [
                Superblock::parse_read_only(&raw)?,
                Superblock::parse_read_write(&raw)?,
            ] {
                assert_eq!(parsed.free_cluster_count().as_u64(), 16);
                assert_eq!(parsed.available_cluster_count().as_u64(), available);
            }
        }
        Ok(())
    }

    /// # Errors
    /// Returns independent field encoding or checksum generation failure.
    /// # Panics
    /// Fails if a reservation beyond the filesystem is admitted, or free space bounds it instead.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check reservation bounds independently of current free space"
    )]
    fn reserved_block_count_is_bounded_by_total_space() -> Result<()> {
        for (low, high, wide) in [(4097, 0, false), (0, 1, true)] {
            let mut raw = primary(false, false, false)?;
            put_le_u32(&mut raw, disk_offset(8), low)?;
            put_le_u32(&mut raw, disk_offset(340), high)?;
            if wide {
                put_le_u32(
                    &mut raw,
                    disk_offset(96),
                    INCOMPAT_EXTENTS | INCOMPAT_FILETYPE | INCOMPAT_64BIT,
                )?;
            }
            Superblock::refresh_checksum(&mut raw)?;
            assert_eq!(
                Superblock::parse_read_only(&raw),
                Err(Error::InvalidSuperblock)
            );
            assert_eq!(
                Superblock::parse_read_write(&raw),
                Err(Error::InvalidSuperblock)
            );
        }
        Ok(())
    }

    /// # Errors
    /// Returns independent fixture serialization or superblock parsing failure.
    /// # Panics
    /// Fails if recovery-session state replaces the persistent ext4 health-word authority.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions compare independent ext4 s_state vectors with parsed health"
    )]
    fn health_state_vectors_are_independent_of_journal_recovery() -> Result<()> {
        for recovery in [false, true] {
            for (state, requires_check) in [(0, true), (1, false), (2, true), (3, true)] {
                let mut raw = primary(false, recovery, false)?;
                put_le_u16(&mut raw, disk_offset(58), state)?;
                Superblock::refresh_checksum(&mut raw)?;
                assert_eq!(
                    Superblock::parse_read_only(&raw)?.requires_check(),
                    requires_check
                );
            }
        }
        Ok(())
    }

    /// Independently assembled minimal primary geometry with a required CRC32C checksum.
    /// # Errors
    /// Returns an error for wire-field serialization.
    fn primary(orphan_file: bool, recovery: bool, present: bool) -> Result<[u8; 1024]> {
        let mut bytes = [0; 1024];
        for (offset, value) in [
            (0, 128),
            (4, 4096),
            (20, 1),
            (32, 8192),
            (36, 8192),
            (40, 128),
            (76, 1),
            (84, 11),
            (224, 8),
            (0x280, 12),
            (
                92,
                COMPAT_HAS_JOURNAL | if orphan_file { COMPAT_ORPHAN_FILE } else { 0 },
            ),
            (
                96,
                INCOMPAT_EXTENTS | INCOMPAT_FILETYPE | if recovery { INCOMPAT_RECOVER } else { 0 },
            ),
            (
                100,
                RO_COMPAT_METADATA_CSUM | if present { RO_COMPAT_ORPHAN_PRESENT } else { 0 },
            ),
        ] {
            put_le_u32(&mut bytes, disk_offset(offset), value)?;
        }
        put_le_u16(&mut bytes, disk_offset(56), EXT4_SUPER_MAGIC)?;
        put_le_u16(&mut bytes, disk_offset(58), EXT4_VALID_FS)?;
        put_le_u16(&mut bytes, disk_offset(88), 256)?;
        *bytes.get_mut(0x175).ok_or(Error::TruncatedStructure)? = 1;
        Superblock::refresh_checksum(&mut bytes)?;
        Ok(bytes)
    }

    /// # Errors
    /// Returns fixture construction or parsing failures.
    /// # Panics
    /// Fails if metadata-owned inodes become namespace nodes or root/ordinary admission is lost.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions exercise namespace identity ownership independently of inode contents"
    )]
    fn namespace_admission_excludes_filesystem_metadata() -> Result<()> {
        let mut bytes = primary(true, false, false)?;
        put_le_u32(&mut bytes, disk_offset(224), 31)?;
        Superblock::refresh_checksum(&mut bytes)?;
        let superblock = Superblock::parse_read_write(&bytes)?;
        assert_eq!(superblock.require_namespace_inode(InodeId::ROOT), Ok(()));
        assert_eq!(
            superblock.require_namespace_inode(InodeId::try_from(11)?),
            Ok(())
        );
        for number in [7, 12, 31, 129] {
            assert_eq!(
                superblock.require_namespace_inode(InodeId::try_from(number)?),
                Err(Error::InvalidInode),
            );
        }
        Ok(())
    }

    /// # Panics
    ///
    /// Panics when pre-enabled large-directory capability stops selecting the wider size/depth
    /// profile or becomes required for standard HTree mounts.
    #[test]
    fn large_directory_feature_selects_explicit_size_and_index_profiles() {
        let required_incompat = INCOMPAT_FILETYPE | INCOMPAT_EXTENTS;
        let standard =
            FeatureSet::read_write(COMPAT_HAS_JOURNAL | COMPAT_DIR_INDEX, required_incompat, 0);
        assert!(standard.is_ok());
        let Ok(standard) = standard else {
            return;
        };
        assert_eq!(standard.directory_indexing(), DirectoryIndexing::Standard);
        assert_eq!(standard.directory_indexing().require_supported(), Ok(1));
        assert_eq!(
            standard.directory_size_encoding(),
            DirectorySizeEncoding::Standard
        );

        let large = FeatureSet::read_write(
            COMPAT_HAS_JOURNAL | COMPAT_DIR_INDEX,
            required_incompat | INCOMPAT_LARGEDIR,
            0,
        );
        assert!(large.is_ok());
        let Ok(large) = large else {
            return;
        };
        assert_eq!(
            large.directory_indexing(),
            DirectoryIndexing::LargeDirectory
        );
        assert_eq!(large.directory_indexing().require_supported(), Ok(2));
        assert_eq!(
            large.directory_size_encoding(),
            DirectorySizeEncoding::LargeDirectory
        );

        let size_only =
            FeatureSet::read_write(COMPAT_HAS_JOURNAL, required_incompat | INCOMPAT_LARGEDIR, 0);
        assert!(size_only.is_ok());
        let Ok(size_only) = size_only else {
            return;
        };
        assert_eq!(size_only.directory_indexing(), DirectoryIndexing::Disabled);
        assert_eq!(
            size_only.directory_indexing().require_supported(),
            Err(Error::UnsupportedDirectoryHash)
        );
        assert_eq!(
            size_only.directory_size_encoding(),
            DirectorySizeEncoding::LargeDirectory
        );
    }
}
