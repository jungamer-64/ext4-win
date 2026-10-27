//! Error types for ext4 domain validation and traversal.

use core::fmt;

/// Result alias used by the ext4 domain.
pub type Result<T> = core::result::Result<T, Error>;

/// Failures that keep invalid or unsupported ext4 state out of the domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The multiple-mount record has invalid geometry, encoding or authentication.
    MmpCorrupt,
    /// Independent observations show an active mount or offline checker.
    MmpOwnerActive,
    /// Media no longer contains this mount's ownership identity.
    MmpOwnershipLost,
    /// A recovery memory budget cannot admit any resident storage.
    InvalidRecoveryMemoryLimit,
    /// Write-free recovery exceeded its logical resident-storage admission.
    RecoveryMemoryLimitExceeded,
    /// This mount grants no authority to modify backing media.
    ReadOnlyFilesystem,
    /// A block read fell outside the backing device.
    DeviceRange,
    /// The backing device failed an in-range I/O request.
    DeviceIo,
    /// The device refused a zero-progress request until its mounted media identity is verified.
    MediaVerificationRequired,
    /// The physical device no longer belongs to the mounted media identity.
    MediaChanged,
    /// The platform cryptographic provider rejected a valid operation request.
    CryptographicFailure,
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
    /// The superblock cluster geometry is inconsistent.
    InvalidClusterGeometry,
    /// The inode number is outside the mounted filesystem.
    InvalidInode,
    /// A time is outside ext4's range or cannot fit the inode's timestamp fields.
    InvalidTimestamp,
    /// Orphan tracking refers to malformed, duplicated, or inconsistent inode state.
    InvalidOrphanTracking,
    /// The orphan file exceeds the bounded recovery profile.
    OrphanRecoveryLimitExceeded,
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
    /// A directory cannot grow beyond the active standard-size profile.
    DirectorySizeLimit,
    /// An HTree cannot receive another routing entry at the active maximum depth.
    DirectoryIndexFull,
    /// An ext4 path component failed validation.
    InvalidName,
    /// An extended attribute name, value, or set failed validation.
    InvalidXattr,
    /// A POSIX ACL payload failed validation.
    InvalidAcl,
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
    /// Cluster ownership references conflict with allocation state.
    ClusterReferenceConflict,
    /// Read admission supplied metadata that is no longer the published epoch.
    StaleReadContext,
    /// An inode or key dependency changed while a lower read was outstanding.
    ReadConflict,
    /// The staged mutation cannot fit in one supported journal transaction.
    TransactionTooLarge,
    /// A write operation was outside the file range accepted by that operation.
    InvalidWriteRange,
    /// A directory already contains the requested child name.
    NameAlreadyExists,
    /// The inode cannot receive another hard link.
    TooManyLinks,
    /// A directory does not contain the requested child name.
    DirectoryEntryNotFound,
    /// A directory removal target still contains children.
    DirectoryNotEmpty,
    /// A directory move would place the directory below itself.
    DirectoryCycle,
    /// No free inode exists for a required allocation.
    NoFreeInode,
    /// A hashed directory uses a hash profile outside the write domain.
    UnsupportedDirectoryHash,
    /// An inode carries mutation semantics outside the write domain.
    UnsupportedInodeMutation,
    /// An encrypted inode requires a fscrypt key that is not present at mount.
    MissingEncryptionKey,
    /// The encrypted inode operation has no connected crypto data path yet.
    UnsupportedEncryption,
    /// The filesystem does not admit the requested fs-verity operation.
    UnsupportedVerity,
    /// The root directory cannot be removed.
    CannotRemoveRoot,
    /// An fscrypt context, key, or policy is malformed or unsupported.
    InvalidEncryptionContext,
    /// fs-verity metadata, descriptor, or enable parameters are malformed.
    InvalidVerityMetadata,
    /// fs-verity data verification failed.
    VerityMismatch,
    /// Memory allocation failed before the requested operation could complete.
    OutOfMemory,
    /// This loaded core image cannot issue another distinct mount identity; existing mounts remain valid.
    MountIdentityExhausted,
    /// The scheduler canceled an operation before its durability guard consumed cancellation.
    OperationCancelled,
    /// Internal operation resolution suspended until one owned storage transfer completes.
    ///
    /// Public operation entry points consume this control result and expose a storage command;
    /// callers must never receive it as a terminal filesystem error.
    OperationSuspended,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MmpCorrupt => "invalid multiple-mount protection record",
            Self::MmpOwnerActive => "filesystem has another active owner",
            Self::MmpOwnershipLost => "multiple-mount ownership was lost",
            Self::InvalidRecoveryMemoryLimit => "recovery memory limit must be nonzero",
            Self::RecoveryMemoryLimitExceeded => "recovery memory limit exceeded",
            Self::ReadOnlyFilesystem => "filesystem is mounted read only",
            Self::StaleReadContext => "read context is no longer current",
            Self::ReadConflict => "read dependency changed during storage I/O",
            Self::DeviceRange => "block read is outside the backing device",
            Self::DeviceIo => "backing device I/O request failed",
            Self::MediaVerificationRequired => "device requires mounted-media verification before I/O",
            Self::MediaChanged => "physical media identity differs from the mounted filesystem",
            Self::CryptographicFailure => "platform cryptographic operation failed",
            Self::ArithmeticOverflow => "arithmetic overflow while mapping ext4 data",
            Self::TruncatedStructure => "on-disk structure is truncated",
            Self::InvalidMagic => "invalid ext4 superblock magic",
            Self::DirtyVolume => "ext4 volume is not clean",
            Self::UnsupportedBlockSize => "unsupported ext4 block size",
            Self::UnsupportedIncompatFeature => "unsupported ext4 incompat feature",
            Self::UnsupportedReadOnlyFeature => "unsupported ext4 read-only feature",
            Self::InvalidSuperblock => "invalid ext4 superblock",
            Self::InvalidClusterGeometry => "invalid ext4 cluster geometry",
            Self::InvalidInode => "invalid ext4 inode",
            Self::InvalidTimestamp => "timestamp is outside the ext4 inode encoding",
            Self::InvalidOrphanTracking => "invalid ext4 orphan tracking",
            Self::OrphanRecoveryLimitExceeded => "ext4 orphan file exceeds recovery capacity",
            Self::WrongInodeKind => "inode has the wrong kind",
            Self::UnsupportedBlockMap => "unsupported inode block map",
            Self::UnsupportedExtentDepth => "unsupported extent tree depth",
            Self::InvalidExtentTree => "invalid extent tree",
            Self::InvalidDirectoryEntry => "invalid directory entry",
            Self::DirectorySizeLimit => "directory exceeds the mounted size profile",
            Self::DirectoryIndexFull => "directory index reached its maximum depth and fan-out",
            Self::InvalidName => "invalid name at domain boundary",
            Self::InvalidXattr => "invalid ext4 extended attribute",
            Self::InvalidAcl => "invalid POSIX ACL",
            Self::UnsupportedWriteFeature => "unsupported ext4 feature for read-write mount",
            Self::UnsupportedJournal => "unsupported ext4 journal",
            Self::JournalCorrupt => "ext4 journal is corrupt",
            Self::ChecksumMismatch => "ext4 metadata checksum mismatch",
            Self::NoSpace => "ext4 volume has no free clusters",
            Self::ClusterReferenceConflict => {
                "ext4 cluster references conflict with allocation state"
            }
            Self::TransactionTooLarge => "ext4 transaction exceeds journal capacity",
            Self::InvalidWriteRange => "invalid ext4 write range",
            Self::NameAlreadyExists => "directory child name already exists",
            Self::TooManyLinks => "inode cannot receive another hard link",
            Self::DirectoryEntryNotFound => "directory child name was not found",
            Self::DirectoryNotEmpty => "directory is not empty",
            Self::DirectoryCycle => "directory move would create an ancestry cycle",
            Self::NoFreeInode => "ext4 volume has no free inodes",
            Self::UnsupportedDirectoryHash => "unsupported ext4 directory hash",
            Self::UnsupportedInodeMutation => "unsupported ext4 inode mutation",
            Self::MissingEncryptionKey => "missing fscrypt encryption key",
            Self::UnsupportedEncryption => "unsupported ext4 encryption operation",
            Self::UnsupportedVerity => {
                "filesystem does not support the requested fs-verity operation"
            }
            Self::CannotRemoveRoot => "cannot remove the ext4 root directory",
            Self::InvalidEncryptionContext => "invalid ext4 encryption context",
            Self::InvalidVerityMetadata => "invalid ext4 verity metadata",
            Self::VerityMismatch => "ext4 verity verification failed",
            Self::OutOfMemory => "memory allocation failed",
            Self::MountIdentityExhausted => "mount identity space exhausted",
            Self::OperationCancelled => "filesystem operation was canceled",
            Self::OperationSuspended => "filesystem operation is awaiting storage completion",
        })
    }
}
