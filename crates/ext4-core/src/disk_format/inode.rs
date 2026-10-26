//! Inode parsing and domain typing.

use alloc::vec::Vec;
use core::num::NonZeroU16;

use crate::disk::block::BlockSize;
use crate::disk::endian::{DiskOffset, le_u16, le_u32};
use crate::error::{Error, Result};
use crate::memory;

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
/// Access time field offset inside an inode record.
const INODE_ATIME_OFFSET: usize = 8;
/// Change time field offset inside an inode record.
const INODE_CTIME_OFFSET: usize = 12;
/// Modification time field offset inside an inode record.
const INODE_MTIME_OFFSET: usize = 16;
/// Creation time field offset inside a large inode record.
const INODE_CRTIME_OFFSET: usize = 144;

/// Builds an inode-record field offset.
const fn disk_offset(offset: usize) -> DiskOffset {
    DiskOffset::new(offset)
}
/// Inode flag selecting extent-based data mapping.
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
/// Inode flag selecting filesystem-block units for `i_blocks`.
const EXT4_HUGE_FILE_FL: u32 = 0x0004_0000;
/// File data must be included in the journal transaction.
const EXT4_JOURNAL_DATA_FL: u32 = 0x0000_4000;
/// Inode flag selecting indexed directory data.
const EXT4_INDEX_FL: u32 = 0x0000_1000;
/// Inode flag rejecting write-domain mutation.
const EXT4_IMMUTABLE_FL: u32 = 0x0000_0010;
/// Inode flag rejecting non-append mutation.
const EXT4_APPEND_FL: u32 = 0x0000_0020;
/// Retired allocation clusters must be overwritten with zeroes.
const EXT4_SECRM_FL: u32 = 0x0000_0001;
/// Inode flag rejected because encrypted payload interpretation is unsupported.
const EXT4_ENCRYPT_FL: u32 = 0x0000_0800;
/// Inode-body payload storage flag.
const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;
/// Inode flag selecting the filesystem Unicode directory comparison contract.
const EXT4_CASEFOLD_FL: u32 = 0x4000_0000;
/// Inode flag selecting fs-verity authenticated file contents.
const EXT4_VERITY_FL: u32 = 0x0010_0000;
/// Persistent direct-access flag, incompatible with fs-verity.
const EXT4_DAX_FL: u32 = 0x0200_0000;
/// Creation inherits policy and hints, excluding mapping and per-inode protection state.
const INHERITABLE_INODE_FLAGS: u32 = 0x6201_C4CF;
/// Directory-specific inheritance: dirsync, project inheritance, and casefolding.
const DIRECTORY_INHERITANCE_FLAGS: u32 = 0x6001_0000;
/// Symbolic links inherit only the no-dump and no-atime hints.
const SYMLINK_INHERITANCE_FLAGS: u32 = 0x0000_00C0;
/// Largest regular-file size accepted without the large-file feature.
const LEGACY_FILE_SIZE_LIMIT: u64 = 0x7fff_ffff;
/// Largest legacy `i_blocks` sector count.
const LEGACY_I_BLOCKS_LIMIT: u64 = 0xffff_ffff;
/// Largest value stored across `i_blocks_lo` and `i_blocks_high`.
const WIDE_I_BLOCKS_LIMIT: u64 = 0xffff_ffff_ffff;
/// Unit used by sector-count `i_blocks` encodings.
const SECTOR_BYTES: u64 = 512;
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

    /// Converts a file byte coordinate to its containing logical extent block.
    /// # Errors
    /// Returns an error when the logical block number exceeds the ext4 extent domain.
    pub(crate) fn logical_block(
        self,
        block_size: BlockSize,
    ) -> Result<crate::disk_format::extent::LogicalBlock> {
        crate::disk_format::extent::LogicalBlock::try_from(
            self.bytes()
                .checked_div(u64::from(block_size.bytes()))
                .ok_or(Error::InvalidSuperblock)?,
        )
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

/// Size of a directory data stream in bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DirectorySize(u64);

impl DirectorySize {
    /// Creates a directory size at the inode/directory boundary.
    pub(crate) const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Returns the directory data-stream size in bytes.
    pub(crate) const fn bytes(self) -> u64 {
        self.0
    }

    /// Projects this validated directory quantity into the common inode size view.
    const fn file_size(self) -> FileSize {
        FileSize::from_bytes(self.0)
    }
}

/// Number of bytes allocated to an inode by ext4 allocation accounting.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileAllocationSize(u64);

impl FileAllocationSize {
    /// Creates an allocation size from a byte count.
    #[must_use]
    pub const fn from_bytes(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inode allocation charge in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

/// File-size encoding selected by the mounted superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileSizeEncoding {
    /// Only the pre-large-file size range is valid.
    Legacy,
    /// Both inode size halves form one 64-bit value.
    LargeFile,
}

/// Directory-size encoding selected by `INCOMPAT_LARGEDIR`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectorySizeEncoding {
    /// Directory size is limited to the standard signed 31-bit byte range.
    Standard,
    /// Both inode size halves form one directory-size value.
    LargeDirectory,
}

/// Block-count encoding selected by the mounted superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InodeBlockCountEncoding {
    /// `i_blocks` contains at most a 32-bit sector count.
    LegacySectors,
    /// `i_blocks_high` and huge-file block units are available.
    HugeFile,
}

/// Unit represented by a validated encoded inode block count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InodeBlockCountUnit {
    /// The encoded count is measured in 512-byte sectors.
    Sectors,
    /// The encoded count is measured in filesystem blocks.
    FileSystemBlocks,
}

/// Validated low and high inode size fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EncodedInodeSize {
    /// Encoded `i_size_lo` value.
    low: u32,
    /// Encoded `i_size_high` value.
    high: u32,
}

impl EncodedInodeSize {
    /// Returns the encoded low size field.
    pub(crate) const fn low(self) -> u32 {
        self.low
    }

    /// Returns the encoded high size field.
    pub(crate) const fn high(self) -> u32 {
        self.high
    }
}

/// Validated inode block-count fields and their selected unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EncodedInodeBlockCount {
    /// Encoded `i_blocks_lo` value.
    low: u32,
    /// Encoded `i_blocks_high` value.
    high: u16,
    /// Unit selected by the huge-file inode flag.
    unit: InodeBlockCountUnit,
}

impl EncodedInodeBlockCount {
    /// Returns the encoded low block-count field.
    pub(crate) const fn low(self) -> u32 {
        self.low
    }

    /// Returns the encoded high block-count field.
    pub(crate) const fn high(self) -> u16 {
        self.high
    }

    /// Returns the unit selected for the encoded count.
    pub(crate) const fn unit(self) -> InodeBlockCountUnit {
        self.unit
    }
}

/// Directory reference accounting selected by DIR_NLINK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryLinkEncoding {
    /// Every directory keeps its exact reference count.
    Counted,
    /// Indexed directories may retain an uncounted reference state.
    Uncounted,
}

/// Mounted inode size and allocation-count encoding policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InodeDataEncoding {
    /// Mounted large-file feature selection.
    file_size: FileSizeEncoding,
    /// Mounted large-directory feature selection.
    directory_size: DirectorySizeEncoding,
    /// Mounted huge-file feature selection.
    block_count: InodeBlockCountEncoding,
    /// Mounted block geometry used by size limits and block units.
    block_size: BlockSize,
    /// Mounted directory reference-count format.
    directory_links: DirectoryLinkEncoding,
    /// Whether inode-body payload interpretation is admitted by the superblock.
    inline_data: bool,
    /// External attribute values are admitted by the mounted feature profile.
    attribute_values: bool,
    /// Directory comparison flags require a declared and admitted filesystem encoding.
    casefold: bool,
}

impl InodeDataEncoding {
    /// Builds the single inode data encoding selected by mounted features and geometry.
    #[expect(
        clippy::too_many_arguments,
        reason = "the mounted inode codec binds independent size, allocation, link and feature capabilities once"
    )]
    pub(crate) const fn new(
        file_size: FileSizeEncoding,
        directory_size: DirectorySizeEncoding,
        block_count: InodeBlockCountEncoding,
        block_size: BlockSize,
        directory_links: DirectoryLinkEncoding,
        inline_data: bool,
        attribute_values: bool,
        casefold: bool,
    ) -> Self {
        Self {
            file_size,
            directory_size,
            block_count,
            block_size,
            directory_links,
            inline_data,
            attribute_values,
            casefold,
        }
    }

    /// Mounted reference-count policy for indexed directories.
    pub(crate) const fn directory_links(self) -> DirectoryLinkEncoding {
        self.directory_links
    }

    /// Returns the largest byte size addressable by the extent logical-block field.
    pub(crate) fn maximum_file_size(self) -> FileSize {
        FileSize::from_bytes((1_u64 << 32).saturating_mul(u64::from(self.block_size.bytes())))
    }

    /// Validates and splits a file size for inode serialization.
    ///
    /// # Errors
    /// Returns an error when the mounted feature profile or extent logical-block domain cannot
    /// represent `size`.
    pub(crate) fn encode_file_size(self, size: FileSize) -> Result<EncodedInodeSize> {
        let bytes = size.bytes();
        if self.file_size == FileSizeEncoding::Legacy && bytes > LEGACY_FILE_SIZE_LIMIT {
            return Err(Error::UnsupportedInodeMutation);
        }
        if bytes > self.maximum_file_size().bytes() {
            return Err(Error::InvalidWriteRange);
        }
        Ok(EncodedInodeSize {
            low: u32::try_from(bytes & u64::from(u32::MAX))
                .map_err(|_| Error::ArithmeticOverflow)?,
            high: u32::try_from(bytes >> 32).map_err(|_| Error::ArithmeticOverflow)?,
        })
    }

    /// Validates and splits a directory size for inode serialization.
    /// # Errors
    ///
    /// Returns [`Error::DirectorySizeLimit`] when the mounted standard profile cannot represent the
    /// requested growth, or an invalid-write error when extent addressing cannot represent it.
    pub(crate) fn encode_directory_size(self, size: DirectorySize) -> Result<EncodedInodeSize> {
        if self.directory_size == DirectorySizeEncoding::Standard
            && size.bytes() > LEGACY_FILE_SIZE_LIMIT
        {
            return Err(Error::DirectorySizeLimit);
        }
        let size = size.file_size();
        if size.bytes() > self.maximum_file_size().bytes() {
            return Err(Error::InvalidWriteRange);
        }
        Ok(EncodedInodeSize {
            low: u32::try_from(size.bytes() & u64::from(u32::MAX))
                .map_err(|_| Error::ArithmeticOverflow)?,
            high: u32::try_from(size.bytes() >> 32).map_err(|_| Error::ArithmeticOverflow)?,
        })
    }

    /// Parses and validates the combined inode size fields.
    ///
    /// # Errors
    /// Returns an error when the fields contradict the mounted large-file feature or exceed the
    /// extent logical-block domain.
    pub(crate) fn decode_size(self, kind: InodeKind, low: u32, high: u32) -> Result<FileSize> {
        let size = FileSize::from_bytes(u64::from(low) | (u64::from(high) << 32));
        let outside_profile = match kind {
            InodeKind::Directory => {
                self.directory_size == DirectorySizeEncoding::Standard
                    && size.bytes() > LEGACY_FILE_SIZE_LIMIT
            }
            InodeKind::File | InodeKind::Symlink => {
                self.file_size == FileSizeEncoding::Legacy && size.bytes() > LEGACY_FILE_SIZE_LIMIT
            }
        };
        if outside_profile {
            return Err(Error::InvalidInode);
        }
        if size.bytes() > self.maximum_file_size().bytes() {
            return Err(Error::InvalidInode);
        }
        Ok(size)
    }

    /// Encodes one inode allocation charge using ext4 sector or filesystem-block units.
    ///
    /// # Errors
    /// Returns an error when `allocation_size` is not block aligned or cannot fit the active
    /// `i_blocks` representation.
    pub(crate) fn encode_allocation_size(
        self,
        allocation_size: FileAllocationSize,
    ) -> Result<EncodedInodeBlockCount> {
        let bytes = allocation_size.bytes();
        let block_bytes = u64::from(self.block_size.bytes());
        if !bytes.is_multiple_of(block_bytes) {
            return Err(Error::InvalidWriteRange);
        }
        let sectors = bytes
            .checked_div(SECTOR_BYTES)
            .ok_or(Error::ArithmeticOverflow)?;
        if sectors <= LEGACY_I_BLOCKS_LIMIT {
            return split_block_count(sectors, InodeBlockCountUnit::Sectors);
        }
        if self.block_count == InodeBlockCountEncoding::LegacySectors {
            return Err(Error::UnsupportedInodeMutation);
        }
        if sectors <= WIDE_I_BLOCKS_LIMIT {
            return split_block_count(sectors, InodeBlockCountUnit::Sectors);
        }
        let blocks = bytes
            .checked_div(block_bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        if blocks > WIDE_I_BLOCKS_LIMIT {
            return Err(Error::UnsupportedInodeMutation);
        }
        split_block_count(blocks, InodeBlockCountUnit::FileSystemBlocks)
    }

    /// Decodes inode block-count fields under the mounted feature and inode-flag policy.
    ///
    /// # Errors
    /// Returns an error when high count bits or filesystem-block units are present without the
    /// huge-file feature, or when byte conversion overflows.
    pub(crate) fn decode_allocation_size(
        self,
        low: u32,
        high: u16,
        flags: InodeFlags,
    ) -> Result<FileAllocationSize> {
        let count = u64::from(low) | (u64::from(high) << 32);
        let bytes = if flags.has_huge_file_blocks() {
            if self.block_count != InodeBlockCountEncoding::HugeFile {
                return Err(Error::InvalidInode);
            }
            count
                .checked_mul(u64::from(self.block_size.bytes()))
                .ok_or(Error::ArithmeticOverflow)?
        } else {
            if self.block_count == InodeBlockCountEncoding::LegacySectors
                && count > LEGACY_I_BLOCKS_LIMIT
            {
                return Err(Error::InvalidInode);
            }
            count
                .checked_mul(SECTOR_BYTES)
                .ok_or(Error::ArithmeticOverflow)?
        };
        Ok(FileAllocationSize::from_bytes(bytes))
    }
}

/// Splits one validated 48-bit inode block count.
///
/// # Errors
/// Returns an error when `count` exceeds the combined low/high field width.
fn split_block_count(count: u64, unit: InodeBlockCountUnit) -> Result<EncodedInodeBlockCount> {
    if count > WIDE_I_BLOCKS_LIMIT {
        return Err(Error::UnsupportedInodeMutation);
    }
    Ok(EncodedInodeBlockCount {
        low: u32::try_from(count & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        high: u16::try_from(count >> 32).map_err(|_| Error::ArithmeticOverflow)?,
        unit,
    })
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

/// Ext4 time with signed Unix seconds and nanosecond precision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Timestamp {
    /// Seconds in the signed base field plus the two-bit ext4 epoch domain.
    seconds: i64,
    /// Fractional second, strictly below one billion.
    nanoseconds: u32,
}

impl Ext4Timestamp {
    /// Constructs a whole-second time representable even without extended fields.
    #[must_use]
    pub fn from_seconds(seconds: i32) -> Self {
        Self {
            seconds: i64::from(seconds),
            nanoseconds: 0,
        }
    }

    /// Constructs a time in the ext4 signed-seconds and two-bit epoch range.
    /// # Errors
    /// Returns [`Error::InvalidTimestamp`] for out-of-range seconds or nanoseconds.
    pub const fn new(seconds: i64, nanoseconds: u32) -> Result<Self> {
        if seconds < -2_147_483_648 || seconds > 15_032_385_535 || nanoseconds >= 1_000_000_000 {
            return Err(Error::InvalidTimestamp);
        }
        Ok(Self {
            seconds,
            nanoseconds,
        })
    }

    /// Signed Unix seconds.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Nanoseconds within the second.
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}

/// Validated boundary between extended inode fields and in-inode xattrs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InodeRecordLayout {
    /// Exclusive end of declared fields; bytes beyond this belong to xattrs.
    extra_end: usize,
}

impl InodeRecordLayout {
    /// Validates the declared field span against the actual inode record.
    /// # Errors
    /// Returns an invalid inode or truncated field for an out-of-record declaration.
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 128 {
            return Err(Error::TruncatedStructure);
        }
        let extra = if raw.len() == 128 {
            0
        } else {
            usize::from(le_u16(raw, disk_offset(128))?)
        };
        let extra_end = 128_usize
            .checked_add(extra)
            .ok_or(Error::ArithmeticOverflow)?;
        if extra_end > raw.len() {
            return Err(Error::InvalidInode);
        }
        Ok(Self { extra_end })
    }

    /// Checks storage declared for a complete extra field, excluding xattr bytes.
    pub(crate) fn contains(self, offset: usize, width: usize) -> bool {
        offset >= 128
            && offset
                .checked_add(width)
                .is_some_and(|end| end <= self.extra_end)
    }

    /// Start of the inode's xattr body.
    pub(crate) const fn xattr_offset(self) -> usize {
        self.extra_end
    }
}

impl Ext4Timestamp {
    /// Decodes the signed base and the optional ext4 epoch/nanosecond extension.
    /// # Errors
    /// Returns invalid inode for an out-of-range nanosecond field.
    pub(crate) fn decode(seconds: u32, extra: Option<u32>) -> Result<Self> {
        let base = i64::from(i32::from_le_bytes(seconds.to_le_bytes()));
        let extension = extra.unwrap_or(0);
        let epoch = i64::from(extension & 3)
            .checked_mul(4_294_967_296)
            .ok_or(Error::ArithmeticOverflow)?;
        Self::new(
            base.checked_add(epoch).ok_or(Error::ArithmeticOverflow)?,
            extension >> 2,
        )
        .map_err(|_| Error::InvalidInode)
    }

    /// Signed-base bits at the on-disk serialization boundary.
    /// # Errors
    /// Returns arithmetic overflow if the private timestamp invariant is violated.
    pub(crate) fn base_seconds_bits(self) -> Result<u32> {
        u32::try_from(self.seconds.rem_euclid(4_294_967_296)).map_err(|_| Error::ArithmeticOverflow)
    }

    /// Encodes the field at its available precision; unextended fields store whole seconds.
    /// # Errors
    /// Returns invalid timestamp when seconds require an absent epoch extension.
    pub(crate) fn encode(self, extended: bool) -> Result<(u32, Option<u32>)> {
        let seconds = self.base_seconds_bits()?;
        let signed = i64::from(i32::from_le_bytes(seconds.to_le_bytes()));
        if !extended {
            if self.seconds != signed {
                return Err(Error::InvalidTimestamp);
            }
            return Ok((seconds, None));
        }
        let epoch = u32::try_from(
            self.seconds
                .checked_sub(signed)
                .ok_or(Error::ArithmeticOverflow)?
                .checked_div(4_294_967_296)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .map_err(|_| Error::InvalidTimestamp)?;
        Ok((seconds, Some((self.nanoseconds << 2) | epoch)))
    }
}

/// ext4 inode timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Times {
    /// Last access time.
    accessed: Ext4Timestamp,
    /// Last modification time.
    modified: Ext4Timestamp,
    /// Last metadata change time.
    changed: Ext4Timestamp,
    /// Creation time when the inode declares storage for it.
    created: Option<Ext4Timestamp>,
}

impl Ext4Times {
    /// Creates a full timestamp set.
    #[must_use]
    pub const fn new(
        accessed: Ext4Timestamp,
        modified: Ext4Timestamp,
        changed: Ext4Timestamp,
        created: Option<Ext4Timestamp>,
    ) -> Self {
        Self {
            accessed,
            modified,
            changed,
            created,
        }
    }

    /// Last access time.
    #[must_use]
    pub const fn accessed(self) -> Ext4Timestamp {
        self.accessed
    }

    /// Last modification time.
    #[must_use]
    pub const fn modified(self) -> Ext4Timestamp {
        self.modified
    }

    /// Last metadata change time.
    #[must_use]
    pub const fn changed(self) -> Ext4Timestamp {
        self.changed
    }

    /// Creation time when the inode declares storage for it.
    #[must_use]
    pub const fn created(self) -> Option<Ext4Timestamp> {
        self.created
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

    /// Applies setid retirement for contents or ownership changes.
    /// Non-executable setgid is not an execution privilege and remains intact.
    pub(crate) const fn without_file_privileges(self) -> Self {
        let removed = if self.0 & 0o010 != 0 { 0o6000 } else { 0o4000 };
        Self(self.0 & !removed)
    }

    /// Returns permission bits for inode encoding.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// ext4 `i_mode` decoded into supported inode kind and permission bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InodeMode {
    /// Supported inode kind selected by the file-type bits.
    kind: InodeKind,
    /// Permission and special-mode bits without file-type bits.
    permissions: Ext4Permissions,
}

impl InodeMode {
    /// Creates a typed inode mode from supported domain parts.
    #[must_use]
    pub const fn new(kind: InodeKind, permissions: Ext4Permissions) -> Self {
        Self { kind, permissions }
    }

    /// Creates a regular-file mode.
    #[must_use]
    pub const fn regular_file(permissions: Ext4Permissions) -> Self {
        Self::new(InodeKind::File, permissions)
    }

    /// Creates a directory mode.
    #[must_use]
    pub const fn directory(permissions: Ext4Permissions) -> Self {
        Self::new(InodeKind::Directory, permissions)
    }

    /// Creates a symbolic-link mode.
    #[must_use]
    pub const fn symlink(permissions: Ext4Permissions) -> Self {
        Self::new(InodeKind::Symlink, permissions)
    }

    /// Parses raw on-disk `i_mode` bits into the supported domain.
    ///
    /// # Errors
    /// Returns an error when the mode selects an unsupported inode kind or
    /// contains permission bits outside ext4's permission mask.
    pub fn from_disk(value: u16) -> Result<Self> {
        let permissions = Ext4Permissions::new(value & PERMISSION_BITS)?;
        let kind = match value & MODE_KIND_MASK {
            MODE_REGULAR => InodeKind::File,
            MODE_DIRECTORY => InodeKind::Directory,
            MODE_SYMLINK => InodeKind::Symlink,
            _ => return Err(Error::WrongInodeKind),
        };
        Ok(Self { kind, permissions })
    }

    /// Supported inode kind.
    #[must_use]
    pub const fn kind(self) -> InodeKind {
        self.kind
    }

    /// Permission and special-mode bits without file-type bits.
    #[must_use]
    pub const fn permissions(self) -> Ext4Permissions {
        self.permissions
    }

    /// Encodes this mode for the on-disk inode boundary.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        let file_type = match self.kind {
            InodeKind::File => MODE_REGULAR,
            InodeKind::Directory => MODE_DIRECTORY,
            InodeKind::Symlink => MODE_SYMLINK,
        };
        file_type | self.permissions.as_u16()
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

/// Metadata required to create a symbolic link inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewSymlinkMetadata {
    /// Owner encoded into the new inode.
    owner: Ext4Owner,
    /// Permission bits encoded with the symlink mode.
    permissions: Ext4Permissions,
}

impl NewSymlinkMetadata {
    /// Creates symbolic link metadata.
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

/// Symbolic link target accepted by the ext4 domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymlinkTarget {
    /// Non-empty target path bytes.
    bytes: Vec<u8>,
}

impl SymlinkTarget {
    /// Maximum target size stored inline inside the inode `i_block` field.
    pub const INLINE_CAPACITY: usize = 60;

    /// Validates and stores a symbolic link target.
    ///
    /// # Errors
    /// Returns an error when the target is empty, contains a NUL byte, or is
    /// too large for ext4's 32-bit low size field used by this domain.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.contains(&0) || u32::try_from(bytes.len()).is_err() {
            return Err(Error::InvalidName);
        }
        Ok(Self {
            bytes: memory::copied_slice(bytes)?,
        })
    }

    /// Returns the raw target bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns whether the target fits in the inode body.
    #[must_use]
    pub fn is_inline(&self) -> bool {
        self.bytes.len() < Self::INLINE_CAPACITY
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

/// Live namespace link count, including ext4's uncounted-directory state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Ext4LinkCount {
    /// Exact nonzero namespace reference count.
    Known(NonZeroU16),
    /// An indexed directory whose references are not counted under DIR_NLINK.
    UncountedDirectory,
}

impl Ext4LinkCount {
    /// Link count for a newly linked file or symlink.
    pub const ONE: Self = Self::Known(NonZeroU16::MIN);
    /// Link count for a newly created directory with `.` and its parent entry.
    pub const TWO: Self = Self::Known(match NonZeroU16::new(2) {
        Some(value) => value,
        None => NonZeroU16::MIN,
    });

    /// Creates a live inode link count.
    ///
    /// # Errors
    /// Returns an error when the count is zero, which belongs to deleted inode
    /// serialization rather than the live inode domain.
    pub fn new(value: u16) -> Result<Self> {
        NonZeroU16::new(value)
            .map(Self::Known)
            .ok_or(Error::InvalidInode)
    }

    /// Returns the raw count for on-disk encoding.
    #[must_use]
    pub const fn on_disk_count(self) -> u16 {
        match self {
            Self::Known(count) => count.get(),
            Self::UncountedDirectory => 1,
        }
    }

    /// Returns the next representable live link count.
    ///
    /// # Errors
    /// Returns an error when the ext4 link-count field is saturated.
    pub fn incremented(self) -> Result<Self> {
        let count = self.known_count().ok_or(Error::InvalidInode)?;
        if count >= 65_000 {
            return Err(Error::TooManyLinks);
        }
        Self::new(count.checked_add(1).ok_or(Error::TooManyLinks)?)
    }

    /// Decrements this live link count and reports the live/deleted boundary.
    #[must_use]
    pub fn decremented(self) -> LinkCountAfterDecrement {
        if self == Self::UncountedDirectory {
            return LinkCountAfterDecrement::StillLinked(self);
        }
        match self
            .on_disk_count()
            .checked_sub(1)
            .and_then(NonZeroU16::new)
        {
            Some(updated) => LinkCountAfterDecrement::StillLinked(Self::Known(updated)),
            None => LinkCountAfterDecrement::Unlinked,
        }
    }
    /// Exact count, absent for directories whose references are not counted.
    #[must_use]
    pub const fn known_count(self) -> Option<u16> {
        match self {
            Self::Known(count) => Some(count.get()),
            Self::UncountedDirectory => None,
        }
    }

    /// Adds a child-directory reference under the inode's indexing and mounted feature policy.
    /// # Errors
    /// Returns too many links when counting is required at saturation, or invalid inode below two.
    pub(crate) fn directory_incremented(
        self,
        encoding: DirectoryLinkEncoding,
        indexed: bool,
    ) -> Result<Self> {
        let Some(count) = self.known_count() else {
            return Ok(self);
        };
        if count < 2 {
            return Err(Error::InvalidInode);
        }
        if count >= 65_000 {
            if encoding == DirectoryLinkEncoding::Uncounted && indexed {
                return Ok(Self::UncountedDirectory);
            }
            return Err(Error::TooManyLinks);
        }
        Self::new(count.checked_add(1).ok_or(Error::TooManyLinks)?)
    }

    /// Removes a child-directory reference while retaining the uncounted state.
    /// # Errors
    /// Returns invalid inode when a counted directory has no child reference to remove.
    pub(crate) fn directory_decremented(self) -> Result<Self> {
        let Some(count) = self.known_count() else {
            return Ok(self);
        };
        if count <= 2 {
            return Err(Error::InvalidInode);
        }
        Self::new(count.checked_sub(1).ok_or(Error::InvalidInode)?)
    }
}

/// Result of decrementing a live inode link count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkCountAfterDecrement {
    /// At least one directory entry still references the inode.
    StillLinked(Ext4LinkCount),
    /// No directory entry references the inode anymore.
    Unlinked,
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

/// Directory storage shape selected by a validated directory inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryStorageKind {
    /// Directory entries are stored as a linear dirent stream.
    Linear,
    /// Directory entries are indexed by an ext4 HTree.
    HTree,
}

/// Inode generation used by metadata checksums.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InodeGeneration(u32);

impl InodeGeneration {
    /// Creates an inode generation from the on-disk field.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the generation value for checksum boundaries.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// File-data persistence selected by the inode, independently of mutation permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileDataPersistence {
    /// Home data must precede metadata commit.
    Ordered,
    /// Data participates in journal commit and checkpoint.
    Journaled,
}

/// ext4 inode flags decoded behind a typed capability boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InodeFlags(u32);

impl InodeFlags {
    /// Whether releasing the final owner of an allocation requires physical zero completion.
    pub(crate) const fn zero_on_deallocation(self) -> bool {
        self.0 & EXT4_SECRM_FL != 0
    }

    /// Makes zero-on-deallocation a persistent inode policy.
    pub(crate) const fn with_zero_on_deallocation(self) -> Self {
        Self(self.0 | EXT4_SECRM_FL)
    }
    /// Selects the parent's policy applicable to the child's inode kind.
    pub(crate) const fn inherited_by(self, kind: InodeKind) -> Self {
        let mask = match kind {
            InodeKind::Directory => INHERITABLE_INODE_FLAGS,
            InodeKind::File => INHERITABLE_INODE_FLAGS & !DIRECTORY_INHERITANCE_FLAGS,
            InodeKind::Symlink => SYMLINK_INHERITANCE_FLAGS,
        };
        Self(self.0 & mask)
    }

    /// Creates flags from the on-disk `i_flags` field.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw flags for on-disk encoding.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns flags with the extent-tree bit set.
    #[must_use]
    pub const fn with_extent_tree(self) -> Self {
        Self(self.0 | EXT4_EXTENTS_FL)
    }

    /// Returns flags with filesystem-block `i_blocks` units selected.
    #[must_use]
    pub(crate) const fn with_huge_file_blocks(self) -> Self {
        Self(self.0 | EXT4_HUGE_FILE_FL)
    }

    /// Returns flags with sector `i_blocks` units selected.
    #[must_use]
    pub(crate) const fn without_huge_file_blocks(self) -> Self {
        Self(self.0 & !EXT4_HUGE_FILE_FL)
    }

    /// Clears only the directory routing representation; namespace metadata remains unchanged.
    pub(crate) const fn without_indexed_directory(self) -> Self {
        Self(self.0 & !EXT4_INDEX_FL)
    }

    /// Directory storage and routing may be reconstructed independently of recorded metadata policy.
    pub(crate) const fn same_directory_policy(self, other: Self) -> bool {
        let layout = EXT4_INDEX_FL | EXT4_EXTENTS_FL | EXT4_INLINE_DATA_FL;
        self.0 & !layout == other.0 & !layout
    }

    /// Returns flags with the indexed-directory bit set.
    #[must_use]
    pub const fn with_indexed_directory(self) -> Self {
        Self(self.0 | EXT4_INDEX_FL)
    }

    /// Returns flags with the fscrypt bit set.
    #[must_use]
    pub const fn with_encryption(self) -> Self {
        Self(self.0 | EXT4_ENCRYPT_FL)
    }

    /// Sets fs-verity while preserving its exclusion of persistent direct access.
    /// # Errors
    /// Returns [`Error::UnsupportedInodeMutation`] when the DAX flag is set.
    pub const fn with_verity(self) -> Result<Self> {
        if self.0 & EXT4_DAX_FL != 0 {
            Err(Error::UnsupportedInodeMutation)
        } else {
            Ok(Self(self.0 | EXT4_VERITY_FL))
        }
    }

    /// Whether this inode owns an external attribute value rather than namespace metadata.
    pub(crate) const fn is_attribute_value(self) -> bool {
        self.0 & 0x0020_0000 != 0
    }
    /// Selects an external attribute value with ordinary extent storage.
    pub(crate) const fn into_attribute_value(self) -> Self {
        Self((self.0 & !EXT4_INLINE_DATA_FL) | 0x0020_0000 | EXT4_EXTENTS_FL)
    }
    /// Directory entries use the mounted Unicode comparison contract.
    pub(crate) const fn has_casefold(self) -> bool {
        self.0 & EXT4_CASEFOLD_FL != 0
    }
    /// Selects the directory comparison state without changing unrelated inode flags.
    pub(crate) const fn with_casefold(self, state: super::name::DirectoryCasefold) -> Self {
        match state {
            super::name::DirectoryCasefold::Disabled => Self(self.0 & !EXT4_CASEFOLD_FL),
            super::name::DirectoryCasefold::Enabled => Self(self.0 | EXT4_CASEFOLD_FL),
        }
    }
    /// Whether i_block and the inode-body private attribute contain the payload.
    pub(crate) const fn has_inline_data(self) -> bool {
        self.0 & EXT4_INLINE_DATA_FL != 0
    }
    /// Selects inode-body storage for a newly initialized unencrypted object.
    pub(crate) const fn into_inline_storage(self) -> Self {
        Self((self.0 & !EXT4_EXTENTS_FL) | EXT4_INLINE_DATA_FL)
    }
    /// Selects extent storage while retiring inline payload interpretation.
    pub(crate) const fn into_extent_storage(self) -> Self {
        Self((self.0 & !EXT4_INLINE_DATA_FL) | EXT4_EXTENTS_FL)
    }
    /// Returns whether the inode uses an extent tree.
    #[must_use]
    pub const fn has_extent_tree(self) -> bool {
        self.0 & EXT4_EXTENTS_FL != 0
    }

    /// Returns whether `i_blocks` is measured in filesystem blocks.
    #[must_use]
    pub(crate) const fn has_huge_file_blocks(self) -> bool {
        self.0 & EXT4_HUGE_FILE_FL != 0
    }

    /// Returns whether this directory is indexed by an HTree.
    #[must_use]
    pub const fn has_indexed_directory(self) -> bool {
        self.0 & EXT4_INDEX_FL != 0
    }

    /// Returns the protection state selected by fscrypt/fs-verity flags.
    #[must_use]
    pub const fn protection(self) -> InodeProtection {
        match (self.0 & EXT4_ENCRYPT_FL != 0, self.0 & EXT4_VERITY_FL != 0) {
            (false, false) => InodeProtection::Plain,
            (true, false) => InodeProtection::Encrypted,
            (false, true) => InodeProtection::Verity,
            (true, true) => InodeProtection::EncryptedVerity,
        }
    }

    /// Creates a metadata mutation capability for these flags.
    ///
    /// # Errors
    /// Returns an error when immutable or append-only semantics reject writes.
    pub fn metadata_mutation(self) -> Result<MetadataMutationCapability> {
        self.require_common_mutation()?;
        if self.0 & EXT4_APPEND_FL != 0 {
            return Err(Error::UnsupportedInodeMutation);
        }
        Ok(MetadataMutationCapability { _private: () })
    }

    /// Creates a directory entry mutation capability for these flags.
    ///
    /// # Errors
    /// Returns an error when flags imply unsupported directory write semantics.
    pub fn directory_entry_mutation(self) -> Result<DirectoryEntryMutationCapability> {
        self.require_common_mutation()?;
        if self.0 & EXT4_APPEND_FL != 0 {
            return Err(Error::UnsupportedInodeMutation);
        }
        Ok(DirectoryEntryMutationCapability { _private: () })
    }

    /// Creates a file payload mutation capability for these flags.
    ///
    /// # Errors
    /// Returns an error when flags imply unsupported data write semantics.
    pub fn file_payload_mutation(self) -> Result<FilePayloadMutationCapability> {
        self.require_file_mutation()?;
        Ok(FilePayloadMutationCapability { _private: () })
    }

    /// Creates a file size mutation capability for these flags.
    ///
    /// # Errors
    /// Returns an error when flags imply unsupported size write semantics.
    pub fn file_size_mutation(self) -> Result<FileSizeMutationCapability> {
        self.require_file_mutation()?;
        Ok(FileSizeMutationCapability { _private: () })
    }

    /// Authorizes changing a name or link count belonging to this inode.
    ///
    /// # Errors
    /// Returns an error when immutable or append-only semantics reject the change.
    pub fn namespace_mutation(self) -> Result<NamespaceMutationCapability> {
        self.require_common_mutation()?;
        if self.0 & EXT4_APPEND_FL != 0 {
            return Err(Error::UnsupportedInodeMutation);
        }
        Ok(NamespaceMutationCapability { _private: () })
    }

    /// Rejects inode flags that make every mutation unsupported.
    /// # Errors
    ///
    /// Returns an error when immutable flags exclude the inode from mutation.
    fn require_common_mutation(self) -> Result<()> {
        if self.0 & EXT4_IMMUTABLE_FL != 0 {
            Err(Error::UnsupportedInodeMutation)
        } else {
            Ok(())
        }
    }

    /// Rejects inode flags that make file payload or size mutation unsupported.
    /// # Errors
    ///
    /// Returns an error when common mutation is unsupported or append-only, casefold, or fs-verity
    /// flags reject file data changes.
    fn require_file_mutation(self) -> Result<()> {
        self.require_common_mutation()?;
        if self.0 & (EXT4_APPEND_FL | EXT4_CASEFOLD_FL | EXT4_VERITY_FL) != 0 {
            Err(Error::UnsupportedInodeMutation)
        } else {
            Ok(())
        }
    }
}

/// Capability proving metadata mutation is allowed by inode flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataMutationCapability {
    /// Prevents construction outside this module.
    _private: (),
}

/// Capability proving directory-entry mutation is allowed by inode flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntryMutationCapability {
    /// Prevents construction outside this module.
    _private: (),
}

/// Capability proving file payload mutation is allowed by inode flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilePayloadMutationCapability {
    /// Prevents construction outside this module.
    _private: (),
}

/// Capability proving file size mutation is allowed by inode flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSizeMutationCapability {
    /// Prevents construction outside this module.
    _private: (),
}

/// Capability proving namespace and link-count changes are allowed by inode flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceMutationCapability {
    /// Prevents construction outside this module.
    _private: (),
}

/// Contents protection attached to an inode by ext4 flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InodeProtection {
    /// No fscrypt or fs-verity semantics are attached.
    Plain,
    /// File or directory is protected by fscrypt.
    Encrypted,
    /// Regular file data is protected by fs-verity.
    Verity,
    /// File data is encrypted and protected by fs-verity.
    EncryptedVerity,
}

impl InodeProtection {
    /// Returns whether fscrypt semantics apply to this inode.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::Encrypted | Self::EncryptedVerity)
    }

    /// Returns whether fs-verity semantics apply to this inode.
    #[must_use]
    pub const fn is_verity(self) -> bool {
        matches!(self, Self::Verity | Self::EncryptedVerity)
    }
}

/// Typed representation of an inode's data pointer area.
#[derive(Debug, Eq, PartialEq)]
pub enum InodeStorage {
    /// Extent root stored in `i_block`.
    Extents(InodeExtentRoot),
    /// Inline bytes stored directly in `i_block`.
    FastSymlink(InodeFastSymlink),
    /// File bytes or separate directory regions authenticated by the inode checksum.
    InlineData(InodeInlineData),
    /// A legacy block map unsupported by this implementation.
    UnsupportedBlockMap,
}

/// Complete inline storage with file and directory interpretations kept distinct.
#[derive(Debug, Eq, PartialEq)]
pub enum InodeInlineData {
    /// Visible file payload, bounded by its inode size.
    File(alloc::vec::Vec<u8>),
    /// Directory parent identity and two independently bounded dirent regions.
    Directory {
        /// Parent represented instead of an on-disk dot-dot dirent.
        parent: InodeId,
        /// Dirents after the four-byte parent prefix in i_block.
        first: [u8; 56],
        /// Separate dirent region stored in system.data.
        second: alloc::vec::Vec<u8>,
    },
}
impl InodeInlineData {
    /// Interprets an inode-checksummed body without treating directory regions as one block.
    /// # Errors
    /// Rejects invalid size, missing system.data, symlink storage, or unsupported protection.
    fn parse(kind: InodeKind, size: FileSize, block: [u8; 60], raw: &[u8]) -> Result<Self> {
        let offset = InodeRecordLayout::parse(raw)?.xattr_offset();
        let set = crate::disk_format::xattr::parse_inline_xattrs(
            raw.get(offset..).ok_or(Error::InvalidInode)?,
        )?;
        let tail = set.inline_data().ok_or(Error::InvalidInode)?;
        let capacity = block
            .len()
            .checked_add(tail.len())
            .ok_or(Error::ArithmeticOverflow)?;
        match kind {
            InodeKind::File => {
                if size.to_usize()? > capacity {
                    return Err(Error::InvalidInode);
                }
                let mut bytes = memory::copied_slice(&block)?;
                bytes
                    .try_reserve_exact(tail.len())
                    .map_err(|_| Error::OutOfMemory)?;
                crate::memory::FallibleVec::try_extend_from_slice(&mut bytes, tail)?;
                bytes.truncate(size.to_usize()?);
                Ok(Self::File(bytes))
            }
            InodeKind::Directory => {
                if size.to_usize()? != capacity {
                    return Err(Error::InvalidInode);
                }
                let parent = InodeId::try_from(le_u32(&block, disk_offset(0))?)?;
                let mut first = [0; 56];
                memory::copy_exact(&mut first, block.get(4..).ok_or(Error::InvalidInode)?)?;
                Ok(Self::Directory {
                    parent,
                    first,
                    second: memory::copied_slice(tail)?,
                })
            }
            InodeKind::Symlink => Err(Error::InvalidInode),
        }
    }
    /// Parses the two independently bounded directory regions and supplies implicit dot entries.
    /// # Errors
    /// Rejects file storage, malformed records and explicit dot entries in inline regions.
    pub(crate) fn directory_entries(
        &self,
        id: InodeId,
    ) -> Result<alloc::vec::Vec<crate::disk_format::dir::DirectoryEntry>> {
        use crate::disk_format::dir::{DirectoryEntry, DirectoryEntryKind};
        let Self::Directory {
            parent,
            first,
            second,
        } = self
        else {
            return Err(Error::WrongInodeKind);
        };
        let mut entries = alloc::vec::Vec::new();
        crate::memory::FallibleVec::try_push(
            &mut entries,
            DirectoryEntry::new(
                id,
                &crate::Ext4Name::new(b".")?,
                DirectoryEntryKind::Directory,
            )?,
        )?;
        crate::memory::FallibleVec::try_push(
            &mut entries,
            DirectoryEntry::new(
                *parent,
                &crate::Ext4Name::new(b"..")?,
                DirectoryEntryKind::Directory,
            )?,
        )?;
        for region in [first.as_slice(), second.as_slice()] {
            for entry in
                DirectoryEntry::parse_all(region, super::dir::DirectoryEntryEncoding::Standard)?
            {
                if matches!(entry.name().bytes(), b"." | b"..") {
                    return Err(Error::InvalidDirectoryEntry);
                }
                crate::memory::FallibleVec::try_push(&mut entries, entry)?;
            }
        }
        Ok(entries)
    }
    /// Borrows file bytes while rejecting the separate directory representation.
    /// # Errors
    /// Returns wrong-inode-kind for directories.
    pub(crate) fn file(&self) -> Result<&[u8]> {
        match self {
            Self::File(bytes) => Ok(bytes),
            Self::Directory { .. } => Err(Error::WrongInodeKind),
        }
    }
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
pub struct InodeFastSymlink {
    /// Exact `i_block` bytes when a symlink payload is stored inline.
    bytes: [u8; 60],
}

impl InodeFastSymlink {
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
#[derive(Debug, Eq, PartialEq)]
pub struct Inode {
    /// Parsed allocation and storage facts, independent of namespace reachability.
    data: InodeData,
    /// Nonzero link count for this live inode.
    links_count: Ext4LinkCount,
    /// Namespace ownership; attribute-value inodes have no such authority.
    owner: Ext4Owner,
    /// Namespace timestamps, distinct from overloaded attribute-inode fields.
    times: Ext4Times,
}

/// Allocation and reference metadata for an external attribute value; never a namespace inode.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AttributeInode {
    /// Shared allocation geometry, without any namespace owner or timestamp interpretation.
    data: InodeData,
    /// Positive count of physical attribute entries referring to this value inode.
    references: core::num::NonZeroU64,
    /// CRC32C of the complete value using the mounted checksum seed.
    value_checksum: u32,
}
impl AttributeInode {
    /// Validates the value-inode header without interpreting its hash/refcount as timestamps.
    /// # Errors
    /// Rejects namespace inodes, unsupported storage/protection, zero references and wrong link count.
    pub(crate) fn parse(id: InodeId, raw: &[u8], encoding: InodeDataEncoding) -> Result<Self> {
        let data = InodeData::parse(id, raw, encoding)?;
        if !encoding.attribute_values
            || !data.flags.is_attribute_value()
            || data.kind() != InodeKind::File
            || !data.flags.has_extent_tree()
            || data.flags.has_inline_data()
            || data.flags.protection().is_encrypted()
            || data.flags.protection().is_verity()
            || le_u16(raw, disk_offset(26))? != 1
        {
            return Err(Error::InvalidXattr);
        }
        // The high half occupies i_ctime; the low half occupies Linux i_osd1/i_version.
        let count = (u64::from(le_u32(raw, disk_offset(12))?) << 32)
            | u64::from(le_u32(raw, disk_offset(36))?);
        let references = core::num::NonZeroU64::new(count).ok_or(Error::InvalidXattr)?;
        Ok(Self {
            data,
            references,
            value_checksum: le_u32(raw, disk_offset(8))?,
        })
    }
    /// Allocation geometry carries no namespace mutation authority.
    pub(crate) const fn data(&self) -> &InodeData {
        &self.data
    }
    /// Positive physical-entry reference count.
    pub(crate) const fn references(&self) -> u64 {
        self.references.get()
    }
    /// Expected checksum of the complete opaque value.
    pub(crate) const fn value_checksum(&self) -> u32 {
        self.value_checksum
    }
}

/// Inode storage facts shared by live access and unlinked-inode recovery.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InodeData {
    /// Stable inode number used by directory entries and checksum seeds.
    id: InodeId,
    /// Supported inode kind and permission bits selected from `i_mode`.
    mode: InodeMode,
    /// Combined low/high inode size.
    size: FileSize,
    /// Decoded inode allocation charge.
    allocation_size: FileAllocationSize,
    /// Inode flags hidden behind typed predicates and capability constructors.
    flags: InodeFlags,
    /// Inode generation used by metadata checksums.
    generation: InodeGeneration,
    /// Typed interpretation of the 60-byte `i_block` field.
    storage: InodeStorage,
}

impl InodeData {
    /// Parses storage facts without granting live namespace access.
    ///
    /// # Errors
    /// Returns an error when the inode record is truncated or has an unsupported
    /// inode kind.
    pub(crate) fn parse(id: InodeId, raw: &[u8], encoding: InodeDataEncoding) -> Result<Self> {
        if raw.len() < 128 {
            return Err(Error::TruncatedStructure);
        }
        let raw_mode = le_u16(raw, disk_offset(0))?;
        let flags = InodeFlags::from_u32(le_u32(raw, disk_offset(32))?);
        if flags.has_casefold()
            && (raw_mode & MODE_KIND_MASK != MODE_DIRECTORY || !encoding.casefold)
        {
            return Err(Error::InvalidInode);
        }
        let mode = InodeMode::from_disk(raw_mode)?;
        let size = encoding.decode_size(
            mode.kind(),
            le_u32(raw, disk_offset(4))?,
            le_u32(raw, disk_offset(108))?,
        )?;
        let allocation_size = encoding.decode_allocation_size(
            le_u32(raw, disk_offset(28))?,
            le_u16(raw, disk_offset(116))?,
            flags,
        )?;
        let generation = InodeGeneration::from_u32(le_u32(raw, disk_offset(100))?);
        let block_slice = raw.get(40..100).ok_or(Error::TruncatedStructure)?;
        let mut block = [0_u8; 60];
        memory::copy_exact(&mut block, block_slice)?;
        let storage = if flags.has_inline_data() {
            if !encoding.inline_data {
                return Err(Error::InvalidInode);
            }
            if flags.has_extent_tree()
                || flags.has_indexed_directory()
                || flags.protection().is_encrypted()
                || flags.protection().is_verity()
            {
                return Err(Error::InvalidInode);
            }
            InodeStorage::InlineData(InodeInlineData::parse(mode.kind(), size, block, raw)?)
        } else if flags.has_extent_tree() {
            InodeStorage::Extents(InodeExtentRoot::from_bytes(block))
        } else if mode.kind() == InodeKind::Symlink && size.to_usize()? < block.len() {
            InodeStorage::FastSymlink(InodeFastSymlink::from_bytes(block))
        } else {
            InodeStorage::UnsupportedBlockMap
        };
        Ok(Self {
            id,
            mode,
            size,
            allocation_size,
            flags,
            generation,
            storage,
        })
    }

    /// Stable identity used to seed extent metadata verification.
    pub(crate) const fn id(&self) -> InodeId {
        self.id
    }
    /// Parsed inode kind.
    pub(crate) const fn kind(&self) -> InodeKind {
        self.mode.kind()
    }
    /// Persisted EOF, including an interrupted truncation's committed target.
    pub(crate) const fn size(&self) -> FileSize {
        self.size
    }
    /// Allocation charge still owned by this inode.
    pub(crate) const fn allocation_size(&self) -> FileAllocationSize {
        self.allocation_size
    }
    /// Checksum generation associated with the inode identity.
    pub(crate) const fn generation(&self) -> InodeGeneration {
        self.generation
    }
    /// Allocation-bearing storage; this does not authorize payload access.
    pub(crate) const fn storage(&self) -> &InodeStorage {
        &self.storage
    }
    /// Protection metadata whose post-EOF allocation must be preserved for linked inodes.
    pub(crate) const fn protection(&self) -> InodeProtection {
        self.flags.protection()
    }
}

impl Inode {
    /// Parses a live inode, rejecting records without a namespace link.
    /// # Errors
    /// Returns an error for malformed storage facts or a zero link count.
    pub(crate) fn parse(id: InodeId, raw: &[u8], encoding: InodeDataEncoding) -> Result<Self> {
        let data = InodeData::parse(id, raw, encoding)?;
        if data.flags.is_attribute_value() {
            return Err(Error::InvalidInode);
        }
        let owner = Ext4Owner::new(
            Ext4Uid::from_u32(parse_uid(raw)?),
            Ext4Gid::from_u32(parse_gid(raw)?),
        );
        let times = parse_times(raw)?;
        let count = le_u16(raw, disk_offset(26))?;
        let links_count = if data.kind() == InodeKind::Directory && count == 1 {
            if encoding.directory_links != DirectoryLinkEncoding::Uncounted
                || !data.flags.has_indexed_directory()
            {
                return Err(Error::InvalidInode);
            }
            Ext4LinkCount::UncountedDirectory
        } else {
            Ext4LinkCount::new(count)?
        };
        Ok(Self {
            data,
            links_count,
            owner,
            times,
        })
    }

    /// Inode identifier.
    #[must_use]
    pub const fn id(&self) -> InodeId {
        self.data.id
    }

    /// Node kind.
    #[must_use]
    pub const fn kind(&self) -> InodeKind {
        self.data.mode.kind()
    }

    /// Storage and inheritance policy encoded by this inode.
    pub(crate) const fn flags(&self) -> InodeFlags {
        self.data.flags
    }

    /// File size in bytes.
    #[must_use]
    pub const fn size(&self) -> FileSize {
        self.data.size
    }

    /// Bytes allocated to this inode according to ext4 `i_blocks`.
    #[must_use]
    pub const fn allocation_size(&self) -> FileAllocationSize {
        self.data.allocation_size
    }

    /// POSIX security state parsed from owner and mode fields.
    #[must_use]
    pub const fn security(&self) -> Ext4Security {
        Ext4Security::new(self.owner, self.data.mode.permissions())
    }

    /// ext4 inode timestamps.
    #[must_use]
    pub const fn times(&self) -> Ext4Times {
        self.times
    }

    /// Live link count.
    #[must_use]
    pub const fn links_count(&self) -> Ext4LinkCount {
        self.links_count
    }

    /// Inode generation used by metadata checksums.
    #[must_use]
    pub const fn generation(&self) -> InodeGeneration {
        self.data.generation
    }

    /// Directory storage shape selected by this directory inode.
    ///
    /// # Errors
    /// Returns an error when the inode is not a directory.
    pub fn directory_storage_kind(&self) -> Result<DirectoryStorageKind> {
        if self.data.mode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if self.data.flags.has_indexed_directory() {
            Ok(DirectoryStorageKind::HTree)
        } else {
            Ok(DirectoryStorageKind::Linear)
        }
    }

    /// Contents protection selected by inode flags.
    #[must_use]
    pub const fn protection(&self) -> InodeProtection {
        self.data.flags.protection()
    }

    /// Builds a metadata mutation capability for this inode.
    ///
    /// # Errors
    /// Returns an error when this inode's flags reject metadata writes.
    pub fn metadata_mutation(&self) -> Result<MetadataMutationCapability> {
        self.data.flags.metadata_mutation()
    }

    /// Builds a directory-entry mutation capability for this inode.
    ///
    /// # Errors
    /// Returns an error when this inode's flags reject directory entry writes.
    pub fn directory_entry_mutation(&self) -> Result<DirectoryEntryMutationCapability> {
        self.data.flags.directory_entry_mutation()
    }

    /// Builds a file payload mutation capability for this inode.
    ///
    /// # Errors
    /// Returns an error when this inode's flags reject file data writes.
    pub fn file_payload_mutation(&self) -> Result<FilePayloadMutationCapability> {
        self.data.flags.file_payload_mutation()
    }

    /// Builds a file-size mutation capability for this inode.
    ///
    /// # Errors
    /// Returns an error when this inode's flags reject file size writes.
    pub fn file_size_mutation(&self) -> Result<FileSizeMutationCapability> {
        self.data.flags.file_size_mutation()
    }

    /// Builds a namespace and link-count mutation capability for this inode.
    ///
    /// # Errors
    /// Returns an error when this inode's flags reject namespace or link-count changes.
    pub fn namespace_mutation(&self) -> Result<NamespaceMutationCapability> {
        self.data.flags.namespace_mutation()
    }

    /// Persistence protocol for this inode's physical data writes.
    pub(crate) fn data_persistence(&self) -> FileDataPersistence {
        if self.data.flags.as_u32() & EXT4_JOURNAL_DATA_FL != 0 {
            FileDataPersistence::Journaled
        } else {
            FileDataPersistence::Ordered
        }
    }

    /// Data storage selected by inode flags and node kind.
    #[must_use]
    pub const fn storage(&self) -> &InodeStorage {
        &self.data.storage
    }

    /// Returns the extent root when this inode uses extents.
    ///
    /// # Errors
    /// Returns an error when this inode uses an unsupported block map or inline storage.
    pub fn extent_root(&self) -> Result<&InodeExtentRoot> {
        match &self.data.storage {
            InodeStorage::Extents(root) => Ok(root),
            InodeStorage::FastSymlink(_)
            | InodeStorage::InlineData(_)
            | InodeStorage::UnsupportedBlockMap => Err(Error::UnsupportedBlockMap),
        }
    }

    /// Borrows a fast symbolic-link target stored directly in `i_block`.
    ///
    /// # Errors
    /// Rejects files, directories and symbolic links with external payload storage.
    pub fn fast_symlink(&self) -> Result<&InodeFastSymlink> {
        match &self.data.storage {
            InodeStorage::FastSymlink(bytes) => Ok(bytes),
            InodeStorage::Extents(_)
            | InodeStorage::InlineData(_)
            | InodeStorage::UnsupportedBlockMap => Err(Error::UnsupportedBlockMap),
        }
    }
}

/// Combines the low and optional high inode UID fields.
/// # Errors
///
/// Returns an error when the low UID field or present high UID field is outside the raw inode bytes.
fn parse_uid(raw: &[u8]) -> Result<u32> {
    let low = u32::from(le_u16(raw, disk_offset(INODE_UID_LO_OFFSET))?);
    let high_offset_end = INODE_UID_HI_OFFSET
        .checked_add(2)
        .ok_or(Error::ArithmeticOverflow)?;
    let high = if raw.len() >= high_offset_end {
        u32::from(le_u16(raw, disk_offset(INODE_UID_HI_OFFSET))?) << 16
    } else {
        0
    };
    Ok(low | high)
}

/// Combines the low and optional high inode GID fields.
/// # Errors
///
/// Returns an error when the low GID field or present high GID field is outside the raw inode bytes.
fn parse_gid(raw: &[u8]) -> Result<u32> {
    let low = u32::from(le_u16(raw, disk_offset(INODE_GID_LO_OFFSET))?);
    let high_offset_end = INODE_GID_HI_OFFSET
        .checked_add(2)
        .ok_or(Error::ArithmeticOverflow)?;
    let high = if raw.len() >= high_offset_end {
        u32::from(le_u16(raw, disk_offset(INODE_GID_HI_OFFSET))?) << 16
    } else {
        0
    };
    Ok(low | high)
}

/// Parses ext4 inode timestamps.
/// # Errors
///
/// Returns an error when any required inode timestamp field is outside the raw inode bytes.
fn parse_times(raw: &[u8]) -> Result<Ext4Times> {
    let layout = InodeRecordLayout::parse(raw)?;
    let read = |base: usize, extra: usize| -> Result<Ext4Timestamp> {
        Ext4Timestamp::decode(
            le_u32(raw, disk_offset(base))?,
            if layout.contains(extra, 4) {
                Some(le_u32(raw, disk_offset(extra))?)
            } else {
                None
            },
        )
    };
    let created = if layout.contains(INODE_CRTIME_OFFSET, 4) {
        Some(read(INODE_CRTIME_OFFSET, 148)?)
    } else {
        None
    };
    Ok(Ext4Times::new(
        read(INODE_ATIME_OFFSET, 140)?,
        read(INODE_MTIME_OFFSET, 136)?,
        read(INODE_CTIME_OFFSET, 132)?,
        created,
    ))
}

#[cfg(test)]
mod tests {
    /// # Errors
    /// Returns malformed reference accounting for an expected valid transition.
    /// # Panics
    /// Fails when DIR_NLINK state changes under increment/decrement or saturation.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions compare ext4 directory reference accounting transitions"
    )]
    fn directory_link_accounting_preserves_uncounted_state() -> crate::Result<()> {
        use super::DirectoryLinkEncoding;
        let uncounted = Ext4LinkCount::UncountedDirectory;
        assert_eq!(uncounted.known_count(), None);
        assert_eq!(uncounted.on_disk_count(), 1);
        assert_eq!(
            uncounted.directory_incremented(DirectoryLinkEncoding::Uncounted, true)?,
            uncounted
        );
        assert_eq!(uncounted.directory_decremented()?, uncounted);
        let limit = Ext4LinkCount::new(65_000)?;
        assert_eq!(
            limit.directory_incremented(DirectoryLinkEncoding::Uncounted, true)?,
            uncounted
        );
        assert_eq!(
            limit.directory_incremented(DirectoryLinkEncoding::Counted, true),
            Err(Error::TooManyLinks)
        );
        assert_eq!(
            limit.directory_incremented(DirectoryLinkEncoding::Uncounted, false),
            Err(Error::TooManyLinks)
        );
        assert_eq!(
            Ext4LinkCount::TWO.directory_decremented(),
            Err(Error::InvalidInode)
        );
        assert_eq!(
            Ext4LinkCount::new(3)?.directory_decremented()?,
            Ext4LinkCount::TWO
        );
        Ok(())
    }

    /// Independent wire vectors cover signed base seconds, every epoch, and fractional precision.
    /// # Errors
    /// Returns a decoding or encoding failure for an expected valid time.
    /// # Panics
    /// Fails when the external ext4 time encoding or inode-field boundary differs.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions compare independent on-disk timestamp vectors"
    )]
    fn timestamp_wire_vectors_and_declared_fields() -> crate::Result<()> {
        use super::{Ext4Timestamp, parse_times};
        use crate::disk::endian::put_le_u16;
        for (low, extra, seconds, nanos) in [
            (0xffff_ffff, 0, -1, 0),
            (0x8000_0000, 1, 2_147_483_648, 0),
            (1, 5, 4_294_967_297, 1),
            (0x8000_0000, 2, 6_442_450_944, 0),
            (0x8000_0000, 3, 10_737_418_240, 0),
            (0x7fff_ffff, 3_999_999_999, 15_032_385_535, 999_999_999),
        ] {
            let time = Ext4Timestamp::decode(low, Some(extra))?;
            assert_eq!(time, Ext4Timestamp::new(seconds, nanos)?);
            assert_eq!(time.encode(true)?, (low, Some(extra)));
        }
        assert_eq!(
            Ext4Timestamp::new(15_032_385_536, 0),
            Err(Error::InvalidTimestamp)
        );
        assert_eq!(
            Ext4Timestamp::new(-2_147_483_649, 0),
            Err(Error::InvalidTimestamp)
        );
        assert_eq!(
            Ext4Timestamp::decode(0, Some(4_000_000_000)),
            Err(Error::InvalidInode)
        );
        assert_eq!(
            Ext4Timestamp::new(2_147_483_648, 0)?.encode(false),
            Err(Error::InvalidTimestamp)
        );
        let mut raw = [0_u8; 256];
        put_le_u16(&mut raw, super::disk_offset(128), 4)?;
        put_le_u32(&mut raw, super::disk_offset(132), 0xea02_0000)?;
        put_le_u32(&mut raw, super::disk_offset(144), 8)?;
        assert_eq!(parse_times(&raw)?.created(), None);
        assert_eq!(parse_times(&raw)?.changed(), Ext4Timestamp::from_seconds(0));
        put_le_u16(&mut raw, super::disk_offset(128), 24)?;
        put_le_u32(&mut raw, super::disk_offset(132), 0)?;
        put_le_u32(&mut raw, super::disk_offset(136), 5)?;
        put_le_u32(&mut raw, super::disk_offset(16), 1)?;
        assert_eq!(
            parse_times(&raw)?.modified(),
            Ext4Timestamp::new(4_294_967_297, 1)?
        );
        assert_eq!(
            parse_times(&raw)?.created(),
            Some(Ext4Timestamp::from_seconds(8))
        );
        Ok(())
    }

    use super::{
        DirectorySize, DirectorySizeEncoding, DirectoryStorageKind, Ext4LinkCount, Ext4Permissions,
        FileAllocationSize, FileSize, FileSizeEncoding, Inode, InodeBlockCountEncoding,
        InodeBlockCountUnit, InodeDataEncoding, InodeFlags, InodeId, InodeKind, InodeMode,
        MODE_DIRECTORY, MODE_REGULAR,
    };
    use crate::disk::block::BlockSize;
    use crate::disk::endian::{put_le_u16, put_le_u32};
    use crate::error::{Error, Result};

    /// Builds the fixed inode id used by inode parser tests.
    /// # Errors
    ///
    /// Returns an error if the fixed test inode number leaves the inode-id domain.
    fn inode_id() -> Result<InodeId> {
        InodeId::try_from(11)
    }

    /// Builds the modern inode encoding used by parser tests.
    /// # Errors
    ///
    /// Returns an error when the fixed 1024-byte block size is unsupported.
    fn inode_data_encoding() -> Result<InodeDataEncoding> {
        Ok(InodeDataEncoding::new(
            FileSizeEncoding::LargeFile,
            DirectorySizeEncoding::LargeDirectory,
            InodeBlockCountEncoding::HugeFile,
            BlockSize::from_superblock_log(0)?,
            crate::disk_format::inode::DirectoryLinkEncoding::Counted,
            false,
            false,
            false,
        ))
    }

    /// Builds a raw 128-byte inode image for parser tests.
    /// # Errors
    ///
    /// Returns an error when a required inode field cannot be written into the fixed image.
    fn inode_bytes(mode: u16, flags: u32) -> Result<[u8; 128]> {
        let mut raw = [0_u8; 128];
        put_le_u16(&mut raw, super::disk_offset(0), mode)?;
        let links = if mode & super::MODE_KIND_MASK == MODE_DIRECTORY {
            2
        } else {
            1
        };
        put_le_u16(&mut raw, super::disk_offset(26), links)?;
        put_le_u32(&mut raw, super::disk_offset(32), flags)?;
        Ok(raw)
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn directory_storage_kind_decodes_linear_and_htree() {
        let linear = inode_id().and_then(|id| {
            inode_bytes(MODE_DIRECTORY, 0)
                .and_then(|bytes| Inode::parse(id, &bytes, inode_data_encoding()?))
        });
        assert!(linear.is_ok());
        let Ok(linear) = linear else {
            return;
        };
        assert_eq!(
            linear.directory_storage_kind(),
            Ok(DirectoryStorageKind::Linear)
        );

        let htree = inode_id().and_then(|id| {
            inode_bytes(MODE_DIRECTORY, super::EXT4_INDEX_FL)
                .and_then(|bytes| Inode::parse(id, &bytes, inode_data_encoding()?))
        });
        assert!(htree.is_ok());
        let Ok(htree) = htree else {
            return;
        };
        assert_eq!(
            htree.directory_storage_kind(),
            Ok(DirectoryStorageKind::HTree)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn directory_storage_kind_rejects_non_directory_inode() {
        let file = inode_id().and_then(|id| {
            inode_bytes(MODE_REGULAR, 0)
                .and_then(|bytes| Inode::parse(id, &bytes, inode_data_encoding()?))
        });
        assert!(file.is_ok());
        let Ok(file) = file else {
            return;
        };
        assert_eq!(file.directory_storage_kind(), Err(Error::WrongInodeKind));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn large_file_encoding_accepts_full_extent_domain() {
        let encoding = inode_data_encoding();
        assert!(encoding.is_ok());
        let Ok(encoding) = encoding else {
            return;
        };

        let above_four_gib = FileSize::from_bytes((1_u64 << 32) + 17);
        let encoded = encoding.encode_file_size(above_four_gib);
        assert!(encoded.is_ok());
        let Ok(encoded) = encoded else {
            return;
        };
        assert_eq!(encoded.low(), 17);
        assert_eq!(encoded.high(), 1);
        assert_eq!(
            encoding.decode_size(InodeKind::File, encoded.low(), encoded.high()),
            Ok(above_four_gib)
        );

        let maximum = encoding.maximum_file_size();
        assert!(encoding.encode_file_size(maximum).is_ok());
        assert_eq!(
            encoding.encode_file_size(FileSize::from_bytes(maximum.bytes() + 1)),
            Err(Error::InvalidWriteRange)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn legacy_file_encoding_rejects_large_file_fields() {
        let block_size = BlockSize::from_superblock_log(0);
        assert!(block_size.is_ok());
        let Ok(block_size) = block_size else {
            return;
        };
        let encoding = InodeDataEncoding::new(
            FileSizeEncoding::Legacy,
            DirectorySizeEncoding::Standard,
            InodeBlockCountEncoding::LegacySectors,
            block_size,
            crate::disk_format::inode::DirectoryLinkEncoding::Counted,
            false,
            false,
            false,
        );

        assert_eq!(
            encoding.encode_file_size(FileSize::from_bytes(0x8000_0000)),
            Err(Error::UnsupportedInodeMutation)
        );
        assert_eq!(
            encoding.decode_size(InodeKind::File, 0x8000_0000, 0),
            Err(Error::InvalidInode)
        );
        assert_eq!(
            encoding.encode_directory_size(DirectorySize::from_bytes(0x8000_0000)),
            Err(Error::DirectorySizeLimit)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn huge_file_encoding_selects_sector_and_filesystem_block_units() {
        let encoding = inode_data_encoding();
        assert!(encoding.is_ok());
        let Ok(encoding) = encoding else {
            return;
        };

        let wide_sectors = 1_u64 << 32;
        let sector_encoded =
            encoding.encode_allocation_size(FileAllocationSize::from_bytes(wide_sectors * 512));
        assert!(sector_encoded.is_ok());
        let Ok(sector_encoded) = sector_encoded else {
            return;
        };
        assert_eq!(sector_encoded.low(), 0);
        assert_eq!(sector_encoded.high(), 1);
        assert_eq!(sector_encoded.unit(), InodeBlockCountUnit::Sectors);

        let largest_block_aligned_wide_sectors = (1_u64 << 48) - 2;
        let wide_sector_encoded = encoding.encode_allocation_size(FileAllocationSize::from_bytes(
            largest_block_aligned_wide_sectors * 512,
        ));
        assert!(wide_sector_encoded.is_ok());
        let Ok(wide_sector_encoded) = wide_sector_encoded else {
            return;
        };
        assert_eq!(wide_sector_encoded.unit(), InodeBlockCountUnit::Sectors);
        assert_eq!(wide_sector_encoded.low(), u32::MAX - 1);
        assert_eq!(wide_sector_encoded.high(), u16::MAX);
        assert_eq!(
            encoding.decode_allocation_size(
                wide_sector_encoded.low(),
                wide_sector_encoded.high(),
                InodeFlags::from_u32(0),
            ),
            Ok(FileAllocationSize::from_bytes(
                largest_block_aligned_wide_sectors * 512
            ))
        );

        let first_block_unit_bytes = (1_u64 << 48) * 512;
        let block_encoded =
            encoding.encode_allocation_size(FileAllocationSize::from_bytes(first_block_unit_bytes));
        assert!(block_encoded.is_ok());
        let Ok(block_encoded) = block_encoded else {
            return;
        };
        assert_eq!(block_encoded.unit(), InodeBlockCountUnit::FileSystemBlocks);
        assert_eq!(
            encoding.decode_allocation_size(
                block_encoded.low(),
                block_encoded.high(),
                InodeFlags::from_u32(0).with_huge_file_blocks(),
            ),
            Ok(FileAllocationSize::from_bytes(first_block_unit_bytes))
        );

        let first_unrepresentable_bytes = (1_u64 << 48) * 1024;
        assert_eq!(
            encoding.encode_allocation_size(FileAllocationSize::from_bytes(
                first_unrepresentable_bytes
            )),
            Err(Error::UnsupportedInodeMutation)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn legacy_block_count_rejects_high_bits_and_huge_units() {
        let block_size = BlockSize::from_superblock_log(0);
        assert!(block_size.is_ok());
        let Ok(block_size) = block_size else {
            return;
        };
        let encoding = InodeDataEncoding::new(
            FileSizeEncoding::LargeFile,
            DirectorySizeEncoding::LargeDirectory,
            InodeBlockCountEncoding::LegacySectors,
            block_size,
            crate::disk_format::inode::DirectoryLinkEncoding::Counted,
            false,
            false,
            false,
        );
        let largest_block_aligned_legacy_sectors = u64::from(u32::MAX) - 1;
        assert!(
            encoding
                .encode_allocation_size(FileAllocationSize::from_bytes(
                    largest_block_aligned_legacy_sectors * 512
                ))
                .is_ok()
        );
        assert_eq!(
            encoding.encode_allocation_size(FileAllocationSize::from_bytes(
                (largest_block_aligned_legacy_sectors + 2) * 512
            )),
            Err(Error::UnsupportedInodeMutation)
        );
        assert_eq!(
            encoding.decode_allocation_size(0, 1, InodeFlags::from_u32(0)),
            Err(Error::InvalidInode)
        );
        assert_eq!(
            encoding.decode_allocation_size(1, 0, InodeFlags::from_u32(0).with_huge_file_blocks(),),
            Err(Error::InvalidInode)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn link_count_rejects_deleted_inode_zero() {
        assert_eq!(Ext4LinkCount::new(0), Err(Error::InvalidInode));
        assert_eq!(Ext4LinkCount::new(1), Ok(Ext4LinkCount::ONE));
        let saturated = Ext4LinkCount::new(u16::MAX);
        assert!(saturated.is_ok());
        if let Ok(saturated) = saturated {
            assert_eq!(saturated.incremented(), Err(Error::TooManyLinks));
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn inode_mode_and_permissions_reject_mixed_domains() {
        assert_eq!(InodeMode::from_disk(0o644), Err(Error::WrongInodeKind));
        assert_eq!(Ext4Permissions::new(MODE_REGULAR), Err(Error::InvalidInode));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn inode_flags_build_operation_capabilities() {
        let immutable = InodeFlags::from_u32(super::EXT4_IMMUTABLE_FL);
        assert_eq!(
            immutable.metadata_mutation(),
            Err(Error::UnsupportedInodeMutation)
        );

        let append_only = InodeFlags::from_u32(super::EXT4_APPEND_FL);
        assert_eq!(
            append_only.metadata_mutation(),
            Err(Error::UnsupportedInodeMutation)
        );
        assert_eq!(
            append_only.directory_entry_mutation(),
            Err(Error::UnsupportedInodeMutation)
        );
        assert_eq!(
            append_only.namespace_mutation(),
            Err(Error::UnsupportedInodeMutation)
        );

        let casefold = InodeFlags::from_u32(super::EXT4_CASEFOLD_FL);
        assert_eq!(
            casefold.file_size_mutation(),
            Err(Error::UnsupportedInodeMutation)
        );

        let verity = InodeFlags::from_u32(super::EXT4_VERITY_FL);
        assert_eq!(
            verity.file_payload_mutation(),
            Err(Error::UnsupportedInodeMutation)
        );

        let encrypted = InodeFlags::from_u32(super::EXT4_ENCRYPT_FL);
        assert!(encrypted.file_payload_mutation().is_ok());
    }
}
