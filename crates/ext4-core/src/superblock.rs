//! Superblock parsing and mount-policy validation.

use crate::block::{BlockAddress, BlockReader, BlockSize, BlockWriter, ByteOffset};
use crate::checksum::{crc32c, verify_crc32c};
use crate::endian::{le_u16, le_u32, put_le_u32};
use crate::error::{Error, Result};
use crate::inode::InodeId;

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
const SUPPORTED_READ_INCOMPAT: u32 =
    INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG | INCOMPAT_CSUM_SEED;
/// Incompatible feature bits required before journaled writes are allowed.
const REQUIRED_WRITE_INCOMPAT: u32 =
    INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG;
/// Incompatible feature mask accepted by the write mount policy.
const SUPPORTED_WRITE_INCOMPAT: u32 =
    REQUIRED_WRITE_INCOMPAT | INCOMPAT_RECOVER | INCOMPAT_JOURNAL_DEV | INCOMPAT_CSUM_SEED;

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
/// Compatible feature bits required before journaled writes are allowed.
const REQUIRED_WRITE_COMPAT: u32 =
    COMPAT_HAS_JOURNAL | COMPAT_EXT_ATTR | COMPAT_RESIZE_INODE | COMPAT_DIR_INDEX;
/// Compatible feature mask accepted by the write mount policy.
const SUPPORTED_WRITE_COMPAT: u32 = REQUIRED_WRITE_COMPAT;
/// Compatible feature bits rejected by the write mount policy.
const REJECTED_WRITE_COMPAT: u32 = COMPAT_FAST_COMMIT | COMPAT_ORPHAN_FILE;
/// Incompatible feature bits rejected by the write mount policy.
const REJECTED_WRITE_INCOMPAT: u32 = INCOMPAT_META_BG
    | INCOMPAT_MMP
    | INCOMPAT_EA_INODE
    | INCOMPAT_LARGEDIR
    | INCOMPAT_INLINE_DATA
    | INCOMPAT_ENCRYPT
    | INCOMPAT_CASEFOLD;
/// Read-only compatible feature bits required before journaled writes are allowed.
const REQUIRED_WRITE_RO_COMPAT: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_METADATA_CSUM;
/// Read-only compatible feature mask accepted by the write mount policy.
const SUPPORTED_WRITE_RO_COMPAT: u32 = REQUIRED_WRITE_RO_COMPAT;
/// Read-only compatible feature bits rejected by the write mount policy.
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

/// Validated ext4 feature flags accepted by a mount policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FeatureSet {
    /// Compatible feature bits from `s_feature_compat`.
    compat: u32,
    /// Incompatible feature bits from `s_feature_incompat`.
    incompat: u32,
    /// Read-only compatible feature bits from `s_feature_ro_compat`.
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

    /// Returns whether the 64-bit descriptor feature is present.
    pub(crate) const fn has_64bit(self) -> bool {
        self.incompat & INCOMPAT_64BIT != 0
    }

    /// Returns whether the filesystem advertises a journal.
    pub(crate) const fn has_journal(self) -> bool {
        self.compat & COMPAT_HAS_JOURNAL != 0
    }

    /// Returns whether the journal lives on a separate journal device.
    pub(crate) const fn has_external_journal(self) -> bool {
        self.incompat & INCOMPAT_JOURNAL_DEV != 0
    }

    /// Returns whether metadata CRC32C checksums are enabled.
    pub(crate) const fn has_metadata_csum(self) -> bool {
        self.read_only_compat & RO_COMPAT_METADATA_CSUM != 0
    }

    /// Returns whether legacy GDT checksums are enabled.
    pub(crate) const fn has_gdt_csum(self) -> bool {
        self.read_only_compat & RO_COMPAT_GDT_CSUM != 0
    }

    /// Returns whether the checksum seed is stored explicitly in the superblock.
    pub(crate) const fn has_checksum_seed(self) -> bool {
        self.incompat & INCOMPAT_CSUM_SEED != 0
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
    /// Total free block count advertised by the superblock.
    free_blocks_count: FreeBlockCount,
    /// Total free inode count advertised by the superblock.
    free_inodes_count: FreeInodeCount,
    /// First block that can contain filesystem data.
    first_data_block: BlockAddress,
    /// Blocks assigned to each block group.
    blocks_per_group: BlocksPerGroup,
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
    /// Feature bits validated for this mount policy.
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

    /// Parses a raw superblock with the supplied feature validation policy.
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
            volume_label,
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

    /// Metadata checksum mode.
    #[must_use]
    pub const fn metadata_checksum(self) -> MetadataChecksum {
        if self.features.has_metadata_csum() {
            MetadataChecksum::Crc32c
        } else {
            MetadataChecksum::None
        }
    }

    /// Returns the descriptor layout implied by validated feature bits.
    pub(crate) const fn descriptor_layout(self) -> BlockGroupDescriptorLayout {
        if self.features.has_64bit() {
            BlockGroupDescriptorLayout::SixtyFourBit
        } else {
            BlockGroupDescriptorLayout::Standard32
        }
    }

    /// Returns the active block group descriptor checksum mode.
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
