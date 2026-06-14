//! Error types for ext4 domain validation and traversal.

use core::fmt;

/// Result alias used by the ext4 domain.
pub type Result<T> = core::result::Result<T, Error>;

/// Failures that keep invalid or unsupported ext4 state out of the domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A block read fell outside the backing device.
    DeviceRange,
    /// The requested byte range overflowed integer arithmetic.
    ArithmeticOverflow,
    /// A fixed-size on-disk structure was truncated.
    TruncatedStructure,
    /// The superblock magic did not match ext2/3/4.
    InvalidMagic,
    /// The filesystem state was not clean.
    DirtyVolume,
    /// The ext4 block size is outside the v1 supported range.
    UnsupportedBlockSize,
    /// The superblock advertises an incompatible feature.
    UnsupportedIncompatFeature,
    /// The superblock advertises a read-only-compatible feature v1 does not validate.
    UnsupportedReadOnlyFeature,
    /// The superblock contains an invalid structural value.
    InvalidSuperblock,
    /// The inode number is outside the mounted filesystem.
    InvalidInode,
    /// An inode did not contain the requested node kind.
    WrongInodeKind,
    /// The inode does not use extents.
    UnsupportedBlockMap,
    /// The extent tree has a depth v1 does not traverse.
    UnsupportedExtentDepth,
    /// An extent tree structure is malformed.
    InvalidExtentTree,
    /// A directory entry record is malformed.
    InvalidDirectoryEntry,
    /// A directory is too large for v1 eager enumeration.
    DirectoryTooLarge,
    /// An ext4 name is not valid for its domain boundary.
    InvalidName,
    /// A Windows case-insensitive lookup matched multiple ext4 names.
    AmbiguousWindowsName,
    /// The superblock advertises a feature that read-write mode rejects.
    UnsupportedWriteFeature,
    /// The internal journal is absent or outside the supported JBD2 profile.
    UnsupportedJournal,
    /// The journal contains malformed or inconsistent records.
    JournalCorrupt,
    /// A metadata checksum did not match the on-disk structure.
    ChecksumMismatch,
    /// No free block exists for a required allocation.
    NoSpace,
    /// The staged mutation cannot fit in one supported journal transaction.
    TransactionTooLarge,
    /// A write operation was outside the file range accepted by that operation.
    InvalidWriteRange,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DeviceRange => "block read is outside the backing device",
            Self::ArithmeticOverflow => "arithmetic overflow while mapping ext4 data",
            Self::TruncatedStructure => "on-disk structure is truncated",
            Self::InvalidMagic => "invalid ext4 superblock magic",
            Self::DirtyVolume => "ext4 volume is not clean",
            Self::UnsupportedBlockSize => "unsupported ext4 block size",
            Self::UnsupportedIncompatFeature => "unsupported ext4 incompat feature",
            Self::UnsupportedReadOnlyFeature => "unsupported ext4 read-only feature",
            Self::InvalidSuperblock => "invalid ext4 superblock",
            Self::InvalidInode => "invalid ext4 inode",
            Self::WrongInodeKind => "inode has the wrong kind",
            Self::UnsupportedBlockMap => "unsupported inode block map",
            Self::UnsupportedExtentDepth => "unsupported extent tree depth",
            Self::InvalidExtentTree => "invalid extent tree",
            Self::InvalidDirectoryEntry => "invalid directory entry",
            Self::DirectoryTooLarge => "directory is too large for v1 enumeration",
            Self::InvalidName => "invalid name at domain boundary",
            Self::AmbiguousWindowsName => "windows lookup matched multiple ext4 names",
            Self::UnsupportedWriteFeature => "unsupported ext4 feature for read-write mount",
            Self::UnsupportedJournal => "unsupported ext4 journal",
            Self::JournalCorrupt => "ext4 journal is corrupt",
            Self::ChecksumMismatch => "ext4 metadata checksum mismatch",
            Self::NoSpace => "ext4 volume has no free blocks",
            Self::TransactionTooLarge => "ext4 transaction exceeds journal capacity",
            Self::InvalidWriteRange => "invalid ext4 write range",
        })
    }
}
