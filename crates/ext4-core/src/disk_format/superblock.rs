//! Superblock parsing and mount-policy validation.

use crate::disk::block::{BlockAddress, BlockSize, ByteOffset};
use crate::disk::checksum::{crc32c, verify_crc32c};
use crate::disk::endian::{DiskOffset, le_u16, le_u32, put_le_u32};
use crate::disk::io::{BlockSource, BlockStorage};
use crate::disk_format::inode::InodeId;
use crate::error::{Error, Result};

// ext4 superblock and feature-policy constants. Feature masks stay here so the
// mount boundary is the only place where unsupported on-disk formats enter.
/// Byte offset of the primary ext4 superblock from the start of the device.
const SUPERBLOCK_OFFSET: u64 = 1024;
/// Fixed byte length of an ext4 superblock.
const SUPERBLOCK_SIZE: usize = 1024;
/// Magic value stored in `s_magic`.
const EXT4_SUPER_MAGIC: u16 = 0xEF53;
/// Clean filesystem bit stored in `s_state`.
const EXT4_VALID_FS: u16 = 0x0001;
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
/// Incompatible feature mask accepted for read-only traversal.
#[cfg(test)]
const SUPPORTED_READ_INCOMPAT: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_FLEX_BG
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_ENCRYPT;
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
/// Read-only compatible feature mask accepted for read-only traversal.
#[cfg(test)]
const SUPPORTED_READ_RO_COMPAT: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_GDT_CSUM
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_QUOTA
    | RO_COMPAT_BIGALLOC
    | RO_COMPAT_METADATA_CSUM
    | RO_COMPAT_READONLY
    | RO_COMPAT_PROJECT
    | RO_COMPAT_VERITY;
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
pub struct ClusterSize(u32);

impl ClusterSize {
    /// Creates a cluster size from validated superblock geometry.
    ///
    /// # Errors
    /// Returns an error when the allocation cluster size is zero.
    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            Err(Error::InvalidClusterGeometry)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the allocation cluster size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.0
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
        label
            .get_mut(..bytes.len())
            .ok_or(Error::ArithmeticOverflow)?
            .copy_from_slice(bytes);
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
        field
            .get_mut(..len)
            .ok_or(Error::TruncatedStructure)?
            .copy_from_slice(source);
        Ok(())
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

/// Byte interpretation used by ext4 directory hash algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryHashByteInterpretation {
    /// Interpret each name byte through signed 8-bit extension.
    Signed,
    /// Interpret each name byte as an unsigned value.
    Unsigned,
}

impl DirectoryHashVersion {
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

    /// Returns how this version interprets name bytes.
    #[must_use]
    pub(crate) const fn byte_interpretation(self) -> DirectoryHashByteInterpretation {
        match self {
            Self::Legacy | Self::HalfMd4 | Self::Tea => DirectoryHashByteInterpretation::Signed,
            Self::LegacyUnsigned | Self::HalfMd4Unsigned | Self::TeaUnsigned => {
                DirectoryHashByteInterpretation::Unsigned
            }
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

/// Journal placement class selected by validated feature flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalFeature {
    /// The filesystem has no journal.
    None,
    /// The journal lives in an ext4 inode on the filesystem device.
    Internal,
    /// The journal lives on a separate JBD2 device.
    External,
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
    /// HTree indexed directories are part of this mounted profile.
    Enabled,
}

impl DirectoryIndexing {
    /// Verifies that an indexed directory can be interpreted.
    /// # Errors
    ///
    /// Returns an error when the mounted feature policy disables HTree directory indexing.
    pub(crate) const fn require_supported(self) -> Result<()> {
        match self {
            Self::Enabled => Ok(()),
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
            Self::FilesystemUuid => Ok(ChecksumSeed::from_u32(crc32c(u32::MAX, uuid))),
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

/// File-size encoding available in inode records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileSizeEncoding {
    /// Only the pre-large-file size profile is supported.
    Legacy,
    /// The inode high size field is available.
    LargeFile,
}

impl FileSizeEncoding {
    /// Verifies that `bytes` can be encoded by this profile.
    /// # Errors
    ///
    /// Returns an error when the legacy inode size profile is active and `bytes` exceeds its limit.
    pub(crate) const fn require_supported(self, bytes: u64, legacy_limit: u64) -> Result<()> {
        match self {
            Self::LargeFile => Ok(()),
            Self::Legacy => {
                if bytes > legacy_limit {
                    Err(Error::UnsupportedInodeMutation)
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Inode block-count encoding available in inode records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InodeBlockCountEncoding {
    /// `i_blocks` is limited to the legacy sector count.
    LegacySectors,
    /// Huge-file block count semantics are available.
    HugeFile,
}

impl InodeBlockCountEncoding {
    /// Verifies that `sectors` can be encoded by this profile.
    /// # Errors
    ///
    /// Returns an error when the legacy inode block-count profile is active and `sectors` exceeds
    /// its limit.
    pub(crate) const fn require_supported(self, sectors: u64, legacy_limit: u64) -> Result<()> {
        match self {
            Self::HugeFile => Ok(()),
            Self::LegacySectors => {
                if sectors > legacy_limit {
                    Err(Error::UnsupportedInodeMutation)
                } else {
                    Ok(())
                }
            }
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

/// Validated ext4 capabilities accepted by a mount policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FeatureSet {
    /// Block group descriptor layout selected by the 64-bit feature.
    descriptor_layout: BlockGroupDescriptorLayout,
    /// Journal placement class selected by feature flags.
    journal: JournalFeature,
    /// Journal recovery state selected by `INCOMPAT_RECOVER`.
    recovery_state: RecoveryState,
    /// Metadata checksum algorithm selected by read-only-compatible features.
    metadata_checksum: MetadataChecksum,
    /// Block group descriptor checksum algorithm.
    descriptor_checksum: BlockGroupDescriptorChecksum,
    /// Superblock copy placement selected by sparse-super feature bits.
    sparse_superblock_layout: SparseSuperblockLayout,
    /// Directory indexing capability.
    directory_indexing: DirectoryIndexing,
    /// Allocation bitmap addressing domain.
    allocation_bitmap_domain: AllocationBitmapDomain,
    /// Source used to construct mounted checksum seeds.
    checksum_seed_source: ChecksumSeedSource,
    /// Public xattr mutation capability.
    xattr_mutation: XattrMutationSupport,
    /// File-size encoding supported by inode records.
    file_size_encoding: FileSizeEncoding,
    /// Inode block-count encoding supported by inode records.
    inode_block_count_encoding: InodeBlockCountEncoding,
    /// Timestamp encoding supported by inode records.
    inode_timestamp_encoding: InodeTimestampEncoding,
}

impl FeatureSet {
    /// Validates raw superblock feature flags for read-only traversal.
    ///
    /// # Errors
    /// Returns an error when the advertised feature set is outside the
    /// read-only mount policy.
    #[cfg(test)]
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
        Ok(Self::from_raw(compat, incompat, read_only_compat))
    }

    /// Validates raw superblock feature flags for journaled read-write mode.
    ///
    /// # Errors
    /// Returns an error when write-domain invariants cannot be maintained for
    /// the advertised feature profile.
    pub(crate) fn read_write(compat: u32, incompat: u32, read_only_compat: u32) -> Result<Self> {
        if compat & COMPAT_HAS_JOURNAL == 0 {
            return Err(Error::UnsupportedWriteFeature);
        }
        if compat & (COMPAT_FAST_COMMIT | COMPAT_ORPHAN_FILE) != 0 {
            return Err(Error::UnsupportedWriteFeature);
        }
        if compat & !(COMPAT_HAS_JOURNAL | COMPAT_EXT_ATTR | COMPAT_RESIZE_INODE | COMPAT_DIR_INDEX)
            != 0
        {
            return Err(Error::UnsupportedWriteFeature);
        }
        if incompat & (INCOMPAT_FILETYPE | INCOMPAT_EXTENTS)
            != (INCOMPAT_FILETYPE | INCOMPAT_EXTENTS)
        {
            return Err(Error::UnsupportedWriteFeature);
        }
        if incompat
            & !(INCOMPAT_FILETYPE
                | INCOMPAT_RECOVER
                | INCOMPAT_JOURNAL_DEV
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
            return Err(Error::UnsupportedWriteFeature);
        }
        if incompat
            & (INCOMPAT_META_BG
                | INCOMPAT_MMP
                | INCOMPAT_EA_INODE
                | INCOMPAT_LARGEDIR
                | INCOMPAT_INLINE_DATA
                | INCOMPAT_CASEFOLD)
            != 0
        {
            return Err(Error::UnsupportedWriteFeature);
        }
        if incompat & INCOMPAT_CSUM_SEED != 0 && read_only_compat & RO_COMPAT_METADATA_CSUM == 0 {
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
        if read_only_compat
            & (RO_COMPAT_READONLY | RO_COMPAT_QUOTA | RO_COMPAT_PROJECT | RO_COMPAT_ORPHAN_PRESENT)
            != 0
        {
            return Err(Error::UnsupportedWriteFeature);
        }
        Ok(Self::from_raw(compat, incompat, read_only_compat))
    }

    /// Converts validated raw flags into internal write/read capabilities.
    fn from_raw(compat: u32, incompat: u32, read_only_compat: u32) -> Self {
        let metadata_checksum = if read_only_compat & RO_COMPAT_METADATA_CSUM != 0 {
            MetadataChecksum::Crc32c
        } else {
            MetadataChecksum::None
        };
        let descriptor_checksum = if metadata_checksum == MetadataChecksum::Crc32c {
            BlockGroupDescriptorChecksum::MetadataCrc32c
        } else if read_only_compat & RO_COMPAT_GDT_CSUM != 0 {
            BlockGroupDescriptorChecksum::GdtCrc16
        } else {
            BlockGroupDescriptorChecksum::None
        };
        let journal = if compat & COMPAT_HAS_JOURNAL == 0 {
            JournalFeature::None
        } else if incompat & INCOMPAT_JOURNAL_DEV != 0 {
            JournalFeature::External
        } else {
            JournalFeature::Internal
        };
        let recovery_state = if incompat & INCOMPAT_RECOVER != 0 {
            RecoveryState::NeedsRecovery
        } else {
            RecoveryState::Clean
        };

        Self {
            descriptor_layout: if incompat & INCOMPAT_64BIT != 0 {
                BlockGroupDescriptorLayout::SixtyFourBit
            } else {
                BlockGroupDescriptorLayout::Standard32
            },
            journal,
            recovery_state,
            metadata_checksum,
            descriptor_checksum,
            sparse_superblock_layout: if read_only_compat & RO_COMPAT_SPARSE_SUPER != 0 {
                SparseSuperblockLayout::SparseCopies
            } else {
                SparseSuperblockLayout::FullCopies
            },
            directory_indexing: if compat & COMPAT_DIR_INDEX != 0 {
                DirectoryIndexing::Enabled
            } else {
                DirectoryIndexing::Disabled
            },
            allocation_bitmap_domain: if read_only_compat & RO_COMPAT_BIGALLOC != 0 {
                AllocationBitmapDomain::Clusters
            } else {
                AllocationBitmapDomain::Blocks
            },
            checksum_seed_source: if incompat & INCOMPAT_CSUM_SEED != 0 {
                ChecksumSeedSource::SuperblockField
            } else if metadata_checksum == MetadataChecksum::Crc32c {
                ChecksumSeedSource::FilesystemUuid
            } else {
                ChecksumSeedSource::Zero
            },
            xattr_mutation: if compat & COMPAT_EXT_ATTR != 0 {
                XattrMutationSupport::Enabled
            } else {
                XattrMutationSupport::Disabled
            },
            file_size_encoding: if read_only_compat & RO_COMPAT_LARGE_FILE != 0 {
                FileSizeEncoding::LargeFile
            } else {
                FileSizeEncoding::Legacy
            },
            inode_block_count_encoding: if read_only_compat & RO_COMPAT_HUGE_FILE != 0 {
                InodeBlockCountEncoding::HugeFile
            } else {
                InodeBlockCountEncoding::LegacySectors
            },
            inode_timestamp_encoding: if read_only_compat & RO_COMPAT_EXTRA_ISIZE != 0 {
                InodeTimestampEncoding::ExtraFields
            } else {
                InodeTimestampEncoding::LegacySeconds
            },
        }
    }

    /// Returns whether the 64-bit descriptor feature is present.
    pub(crate) const fn has_64bit(self) -> bool {
        matches!(
            self.descriptor_layout,
            BlockGroupDescriptorLayout::SixtyFourBit
        )
    }

    /// Returns the descriptor layout selected by validated feature flags.
    pub(crate) const fn descriptor_layout(self) -> BlockGroupDescriptorLayout {
        self.descriptor_layout
    }

    /// Returns whether the filesystem advertises a journal.
    pub(crate) const fn has_journal(self) -> bool {
        !matches!(self.journal, JournalFeature::None)
    }

    /// Returns whether the journal lives on a separate journal device.
    pub(crate) const fn has_external_journal(self) -> bool {
        matches!(self.journal, JournalFeature::External)
    }

    /// Returns the metadata checksum mode.
    pub(crate) const fn metadata_checksum(self) -> MetadataChecksum {
        self.metadata_checksum
    }

    /// Returns the block group descriptor checksum mode.
    pub(crate) const fn descriptor_checksum(self) -> BlockGroupDescriptorChecksum {
        self.descriptor_checksum
    }

    /// Returns the sparse-superblock layout.
    pub(crate) const fn sparse_superblock_layout(self) -> SparseSuperblockLayout {
        self.sparse_superblock_layout
    }

    /// Returns the directory indexing capability.
    pub(crate) const fn directory_indexing(self) -> DirectoryIndexing {
        self.directory_indexing
    }

    /// Returns the allocation bitmap addressing domain.
    pub(crate) const fn allocation_bitmap_domain(self) -> AllocationBitmapDomain {
        self.allocation_bitmap_domain
    }

    /// Returns the checksum seed source.
    pub(crate) const fn checksum_seed_source(self) -> ChecksumSeedSource {
        self.checksum_seed_source
    }

    /// Returns the public xattr mutation capability.
    pub(crate) const fn xattr_mutation(self) -> XattrMutationSupport {
        self.xattr_mutation
    }

    /// Returns the file-size encoding capability.
    pub(crate) const fn file_size_encoding(self) -> FileSizeEncoding {
        self.file_size_encoding
    }

    /// Returns the inode block-count encoding capability.
    pub(crate) const fn inode_block_count_encoding(self) -> InodeBlockCountEncoding {
        self.inode_block_count_encoding
    }

    /// Returns the inode timestamp encoding capability.
    pub(crate) const fn inode_timestamp_encoding(self) -> InodeTimestampEncoding {
        self.inode_timestamp_encoding
    }

    /// Returns the journal recovery state.
    pub(crate) const fn recovery_state(self) -> RecoveryState {
        self.recovery_state
    }
}

/// Superblock whose structural fields and mount policy are validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
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
    /// Total free inode count advertised by the superblock.
    free_inodes_count: FreeInodeCount,
    /// First block that can contain filesystem data.
    first_data_block: BlockAddress,
    /// Blocks assigned to each block group.
    blocks_per_group: BlocksPerGroup,
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
    /// Filesystem UUID used for checksums and journal matching.
    uuid: FilesystemUuid,
    /// Filesystem volume label stored in the superblock.
    volume_label: Ext4VolumeLabel,
    /// Seed used for metadata CRC32C calculations.
    checksum_seed: ChecksumSeed,
    /// Seed used by indexed directory hashing.
    directory_hash_seed: DirectoryHashSeed,
    /// Default hash version used when an HTree root does not override it.
    default_directory_hash_version: DirectoryHashVersion,
    /// Feature bits validated for this mount policy.
    features: FeatureSet,
}

impl Superblock {
    /// Reads and validates the primary ext4 superblock from a block device for read-only mode.
    ///
    /// # Errors
    /// Returns an error when the primary superblock cannot be read or does not
    /// satisfy the clean v1 mount policy.
    #[cfg(test)]
    pub async fn read_from(device: &mut impl BlockSource) -> Result<Self> {
        let mut raw = [0_u8; SUPERBLOCK_SIZE];
        device
            .read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)
            .await?;
        Self::parse(&raw)
    }

    /// Reads and validates the primary ext4 superblock for read-write mode.
    ///
    /// # Errors
    /// Returns an error when the superblock cannot support journaled writes.
    pub async fn read_write_from(device: &mut impl BlockSource) -> Result<Self> {
        let mut raw = [0_u8; SUPERBLOCK_SIZE];
        device
            .read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)
            .await?;
        Self::parse_read_write(&raw)
    }

    /// Parses and validates a 1024-byte superblock payload.
    ///
    /// # Errors
    /// Returns an error when the payload is truncated, has invalid ext4 magic,
    /// is dirty, advertises unsupported features, or contains invalid geometry.
    #[cfg(test)]
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

    /// Parses a raw superblock with the supplied feature validation policy.
    /// # Errors
    ///
    /// Returns an error when the payload is truncated, has invalid magic or dirty state, fails the
    /// feature policy, contains invalid geometry, or carries an invalid checksum/journal/hash field.
    fn parse_with_policy(
        raw: &[u8],
        validate_features: fn(u32, u32, u32) -> Result<FeatureSet>,
    ) -> Result<Self> {
        if raw.len() < SUPERBLOCK_SIZE {
            return Err(Error::TruncatedStructure);
        }
        if le_u16(raw, disk_offset(56))? != EXT4_SUPER_MAGIC {
            return Err(Error::InvalidMagic);
        }
        if le_u16(raw, disk_offset(58))? & EXT4_VALID_FS == 0 {
            return Err(Error::DirtyVolume);
        }

        let inode_count = InodeCount::new(le_u32(raw, disk_offset(0))?)?;
        let block_count_lo = le_u32(raw, disk_offset(4))?;
        let free_blocks_count_lo = le_u32(raw, disk_offset(12))?;
        let free_inodes_count = FreeInodeCount::new(le_u32(raw, disk_offset(16))?);
        let first_data_block = BlockAddress::new(u64::from(le_u32(raw, disk_offset(20))?));
        let log_block_size = le_u32(raw, disk_offset(24))?;
        let log_cluster_size = le_u32(raw, disk_offset(28))?;
        let block_size = BlockSize::from_superblock_log(log_block_size)?;
        let blocks_per_group = BlocksPerGroup::new(le_u32(raw, disk_offset(32))?)?;
        let raw_clusters_per_group = le_u32(raw, disk_offset(36))?;
        let inodes_per_group = InodesPerGroup::new(le_u32(raw, disk_offset(40))?)?;
        let first_inode = InodeId::try_from(le_u32(raw, disk_offset(84))?)?;
        let inode_size = InodeRecordSize::new(le_u16(raw, disk_offset(88))?, block_size)?;
        let features = validate_features(
            le_u32(raw, disk_offset(92))?,
            le_u32(raw, disk_offset(96))?,
            le_u32(raw, disk_offset(100))?,
        )?;
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
        let free_clusters_count = FreeClusterCount::new(
            u64::from(free_blocks_count_lo)
                | if features.has_64bit() {
                    u64::from(le_u32(raw, disk_offset(344))?) << 32
                } else {
                    0
                },
        );
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
        if free_clusters_count.as_u64() > geometry.cluster_count.as_u64() {
            return Err(Error::InvalidClusterGeometry);
        }
        match features.metadata_checksum() {
            MetadataChecksum::None => {}
            MetadataChecksum::Crc32c => {
                if le_u32(raw, disk_offset(1020))? != 0 {
                    verify_crc32c(0, raw, disk_offset(1020))?;
                }
            }
        }
        let journal_inode = le_u32(raw, disk_offset(224))?;
        let mut uuid = [0_u8; 16];
        uuid.copy_from_slice(raw.get(104..120).ok_or(Error::TruncatedStructure)?);
        let volume_label = Ext4VolumeLabel::parse(raw)?;
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
        let checksum_seed = features.checksum_seed_source().seed(raw, &uuid)?;
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
        let uuid = FilesystemUuid::from_bytes(uuid);

        Ok(Self {
            block_size,
            inode_count,
            block_count,
            cluster_size: geometry.cluster_size,
            blocks_per_cluster: geometry.blocks_per_cluster,
            cluster_count: geometry.cluster_count,
            free_clusters_count,
            free_inodes_count,
            first_data_block,
            blocks_per_group,
            clusters_per_group: geometry.clusters_per_group,
            inodes_per_group,
            inode_size,
            first_inode,
            descriptor_size,
            journal_mode,
            uuid,
            volume_label,
            checksum_seed,
            directory_hash_seed,
            default_directory_hash_version,
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

    /// Returns the file-size encoding capability.
    #[must_use]
    pub(crate) const fn file_size_encoding(self) -> FileSizeEncoding {
        self.features.file_size_encoding()
    }

    /// Returns the inode block-count encoding capability.
    #[must_use]
    pub(crate) const fn inode_block_count_encoding(self) -> InodeBlockCountEncoding {
        self.features.inode_block_count_encoding()
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

    /// Clears the recovery-required incompat bit in the primary superblock.
    ///
    /// # Errors
    /// Returns an error when the primary superblock cannot be read or written.
    pub async fn clear_recover_on_device(device: &mut impl BlockStorage) -> Result<()> {
        let mut raw = [0_u8; SUPERBLOCK_SIZE];
        device
            .read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut raw)
            .await?;
        let incompat = le_u32(&raw, disk_offset(96))? & !INCOMPAT_RECOVER;
        put_le_u32(&mut raw, disk_offset(96), incompat)?;
        Self::refresh_checksum(&mut raw)?;
        device
            .write_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &raw)
            .await?;
        device.flush().await
    }

    /// Recomputes the primary superblock checksum when the on-disk checksum is present.
    /// # Errors
    ///
    /// Returns an error when the checksum field cannot be read, zeroed, or rewritten.
    pub(crate) fn refresh_checksum(raw: &mut [u8]) -> Result<()> {
        if le_u32(raw, disk_offset(1020))? == 0 {
            return Ok(());
        }
        put_le_u32(raw, disk_offset(1020), 0)?;
        let checksum = crc32c(0, raw);
        put_le_u32(raw, disk_offset(1020), checksum)
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
