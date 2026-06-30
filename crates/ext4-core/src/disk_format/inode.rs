//! Inode parsing and domain typing.

use alloc::vec::Vec;
use core::num::NonZeroU16;

use crate::disk::endian::{DiskOffset, le_u16, le_u32};
use crate::error::{Error, Result};

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
/// Inode flag selecting indexed directory data.
const EXT4_INDEX_FL: u32 = 0x0000_1000;
/// Inode flag rejecting write-domain mutation.
const EXT4_IMMUTABLE_FL: u32 = 0x0000_0010;
/// Inode flag rejecting non-append mutation.
const EXT4_APPEND_FL: u32 = 0x0000_0020;
/// Inode flag rejected because encrypted payload interpretation is unsupported.
const EXT4_ENCRYPT_FL: u32 = 0x0000_0800;
/// Inode flag rejected for write-domain mutation of inline-data files.
const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;
/// Inode flag rejected because casefolded lookup semantics are unsupported.
const EXT4_CASEFOLD_FL: u32 = 0x4000_0000;
/// Inode flag selecting fs-verity authenticated file contents.
const EXT4_VERITY_FL: u32 = 0x0010_0000;
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

/// Ext4 inode timestamp supplied by the caller at a mutation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Timestamp {
    /// Low 32-bit Unix seconds stored by ext4 timestamp fields.
    seconds: u32,
}

impl Ext4Timestamp {
    /// Creates an ext4 timestamp from low 32-bit Unix seconds.
    #[must_use]
    pub const fn from_unix_seconds(seconds: u32) -> Self {
        Self { seconds }
    }

    /// Returns the low 32-bit Unix seconds stored in this timestamp.
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.seconds
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
    /// Creation time.
    created: Ext4Timestamp,
}

impl Ext4Times {
    /// Creates a full timestamp set.
    #[must_use]
    pub const fn new(
        accessed: Ext4Timestamp,
        modified: Ext4Timestamp,
        changed: Ext4Timestamp,
        created: Ext4Timestamp,
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

    /// Creation time.
    #[must_use]
    pub const fn created(self) -> Ext4Timestamp {
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
            bytes: bytes.to_vec(),
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
        self.bytes.len() <= Self::INLINE_CAPACITY
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

/// Nonzero link count of a live ext4 inode.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ext4LinkCount(NonZeroU16);

impl Ext4LinkCount {
    /// Link count for a newly linked file or symlink.
    pub const ONE: Self = Self(NonZeroU16::MIN);
    /// Link count for a newly created directory with `.` and its parent entry.
    pub const TWO: Self = Self(match NonZeroU16::new(2) {
        Some(value) => value,
        None => NonZeroU16::MIN,
    });

    /// Creates a live inode link count.
    ///
    /// # Errors
    /// Returns an error when the count is zero, which belongs to deleted inode
    /// serialization rather than the live inode domain.
    pub fn new(value: u16) -> Result<Self> {
        NonZeroU16::new(value).map(Self).ok_or(Error::InvalidInode)
    }

    /// Returns the raw count for on-disk encoding.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }

    /// Returns the next representable live link count.
    ///
    /// # Errors
    /// Returns an error when incrementing would overflow the ext4 field.
    pub fn incremented(self) -> Result<Self> {
        Self::new(self.get().checked_add(1).ok_or(Error::ArithmeticOverflow)?)
    }

    /// Decrements this live link count and reports the live/deleted boundary.
    #[must_use]
    pub fn decremented(self) -> LinkCountAfterDecrement {
        match self.get().checked_sub(1).and_then(NonZeroU16::new) {
            Some(updated) => LinkCountAfterDecrement::StillLinked(Self(updated)),
            None => LinkCountAfterDecrement::Unlinked,
        }
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

/// ext4 inode flags decoded behind a typed capability boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InodeFlags(u32);

impl InodeFlags {
    /// No inode flags.
    pub const EMPTY: Self = Self(0);

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

    /// Returns flags with the fs-verity bit set.
    #[must_use]
    pub const fn with_verity(self) -> Self {
        Self(self.0 | EXT4_VERITY_FL)
    }

    /// Returns whether the inode uses an extent tree.
    #[must_use]
    pub const fn has_extent_tree(self) -> bool {
        self.0 & EXT4_EXTENTS_FL != 0
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
    /// Returns an error when immutable or inline-data semantics reject writes.
    pub fn metadata_mutation(self) -> Result<MetadataMutationCapability> {
        self.require_common_mutation()?;
        Ok(MetadataMutationCapability { _private: () })
    }

    /// Creates a directory entry mutation capability for these flags.
    ///
    /// # Errors
    /// Returns an error when flags imply unsupported directory write semantics.
    pub fn directory_entry_mutation(self) -> Result<DirectoryEntryMutationCapability> {
        self.require_common_mutation()?;
        if self.0 & (EXT4_APPEND_FL | EXT4_CASEFOLD_FL) != 0 {
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

    /// Creates a final deletion mutation capability for these flags.
    ///
    /// # Errors
    /// Returns an error when immutable or inline-data semantics reject deletion.
    pub fn deletion_mutation(self) -> Result<DeletionMutationCapability> {
        self.require_common_mutation()?;
        Ok(DeletionMutationCapability { _private: () })
    }

    /// Rejects inode flags that make every mutation unsupported.
    fn require_common_mutation(self) -> Result<()> {
        if self.0 & (EXT4_IMMUTABLE_FL | EXT4_INLINE_DATA_FL) != 0 {
            Err(Error::UnsupportedInodeMutation)
        } else {
            Ok(())
        }
    }

    /// Rejects inode flags that make file payload or size mutation unsupported.
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

/// Capability proving final deletion is allowed by inode flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionMutationCapability {
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InodeStorage {
    /// Extent root stored in `i_block`.
    Extents(InodeExtentRoot),
    /// Inline bytes stored directly in `i_block`.
    InlineBytes(InodeInlineBytes),
    /// A legacy block map unsupported by this implementation.
    UnsupportedBlockMap,
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
pub struct InodeInlineBytes {
    /// Exact `i_block` bytes when a symlink payload is stored inline.
    bytes: [u8; 60],
}

impl InodeInlineBytes {
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inode {
    /// Stable inode number used by directory entries and checksum seeds.
    id: InodeId,
    /// Supported inode kind and permission bits selected from `i_mode`.
    mode: InodeMode,
    /// Combined low/high inode size.
    size: FileSize,
    /// POSIX owner parsed from uid/gid fields.
    owner: Ext4Owner,
    /// Timestamps parsed from ext4 inode time fields.
    times: Ext4Times,
    /// Nonzero link count for this live inode.
    links_count: Ext4LinkCount,
    /// Inode flags hidden behind typed predicates and capability constructors.
    flags: InodeFlags,
    /// Inode generation used by metadata checksums.
    generation: InodeGeneration,
    /// Typed interpretation of the 60-byte `i_block` field.
    storage: InodeStorage,
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
        let mode = InodeMode::from_disk(le_u16(raw, disk_offset(0))?)?;
        let owner = Ext4Owner::new(
            Ext4Uid::from_u32(parse_uid(raw)?),
            Ext4Gid::from_u32(parse_gid(raw)?),
        );
        let size = FileSize::from_bytes(
            u64::from(le_u32(raw, disk_offset(4))?)
                | (u64::from(le_u32(raw, disk_offset(108))?) << 32),
        );
        let times = parse_times(raw)?;
        let links_count = Ext4LinkCount::new(le_u16(raw, disk_offset(26))?)?;
        let flags = InodeFlags::from_u32(le_u32(raw, disk_offset(32))?);
        let generation = InodeGeneration::from_u32(le_u32(raw, disk_offset(100))?);
        let block_slice = raw.get(40..100).ok_or(Error::TruncatedStructure)?;
        let mut block = [0_u8; 60];
        block.copy_from_slice(block_slice);
        let storage = if flags.has_extent_tree() {
            InodeStorage::Extents(InodeExtentRoot::from_bytes(block))
        } else if mode.kind() == InodeKind::Symlink && size.to_usize()? <= block.len() {
            InodeStorage::InlineBytes(InodeInlineBytes::from_bytes(block))
        } else {
            InodeStorage::UnsupportedBlockMap
        };
        Ok(Self {
            id,
            mode,
            size,
            owner,
            times,
            links_count,
            flags,
            generation,
            storage,
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
        self.mode.kind()
    }

    /// File size in bytes.
    #[must_use]
    pub const fn size(&self) -> FileSize {
        self.size
    }

    /// POSIX security state parsed from owner and mode fields.
    #[must_use]
    pub const fn security(&self) -> Ext4Security {
        Ext4Security::new(self.owner, self.mode.permissions())
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
        self.generation
    }

    /// Directory storage shape selected by this directory inode.
    ///
    /// # Errors
    /// Returns an error when the inode is not a directory.
    pub fn directory_storage_kind(&self) -> Result<DirectoryStorageKind> {
        if self.mode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if self.flags.has_indexed_directory() {
            Ok(DirectoryStorageKind::HTree)
        } else {
            Ok(DirectoryStorageKind::Linear)
        }
    }

    /// Contents protection selected by inode flags.
    #[must_use]
    pub const fn protection(&self) -> InodeProtection {
        self.flags.protection()
    }

    /// Builds a metadata mutation capability for this inode.
    ///
    /// # Errors
    /// Returns an error when this inode's flags reject metadata writes.
    pub fn metadata_mutation(&self) -> Result<MetadataMutationCapability> {
        self.flags.metadata_mutation()
    }

    /// Builds a directory-entry mutation capability for this inode.
    ///
    /// # Errors
    /// Returns an error when this inode's flags reject directory entry writes.
    pub fn directory_entry_mutation(&self) -> Result<DirectoryEntryMutationCapability> {
        self.flags.directory_entry_mutation()
    }

    /// Builds a file payload mutation capability for this inode.
    ///
    /// # Errors
    /// Returns an error when this inode's flags reject file data writes.
    pub fn file_payload_mutation(&self) -> Result<FilePayloadMutationCapability> {
        self.flags.file_payload_mutation()
    }

    /// Builds a file-size mutation capability for this inode.
    ///
    /// # Errors
    /// Returns an error when this inode's flags reject file size writes.
    pub fn file_size_mutation(&self) -> Result<FileSizeMutationCapability> {
        self.flags.file_size_mutation()
    }

    /// Builds a deletion mutation capability for this inode.
    ///
    /// # Errors
    /// Returns an error when this inode's flags reject final deletion.
    pub fn deletion_mutation(&self) -> Result<DeletionMutationCapability> {
        self.flags.deletion_mutation()
    }

    /// Data storage selected by inode flags and node kind.
    #[must_use]
    pub const fn storage(&self) -> &InodeStorage {
        &self.storage
    }

    /// Returns the extent root when this inode uses extents.
    ///
    /// # Errors
    /// Returns an error when this inode uses an unsupported block map or inline storage.
    pub fn extent_root(&self) -> Result<&InodeExtentRoot> {
        match &self.storage {
            InodeStorage::Extents(root) => Ok(root),
            InodeStorage::InlineBytes(_) | InodeStorage::UnsupportedBlockMap => {
                Err(Error::UnsupportedBlockMap)
            }
        }
    }

    /// Returns inline bytes when this inode stores data directly in `i_block`.
    ///
    /// # Errors
    /// Returns an error when this inode uses extents or an unsupported block map.
    pub fn inline_bytes(&self) -> Result<&InodeInlineBytes> {
        match &self.storage {
            InodeStorage::InlineBytes(bytes) => Ok(bytes),
            InodeStorage::Extents(_) | InodeStorage::UnsupportedBlockMap => {
                Err(Error::UnsupportedBlockMap)
            }
        }
    }
}

/// Combines the low and optional high inode UID fields.
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
fn parse_times(raw: &[u8]) -> Result<Ext4Times> {
    let accessed = Ext4Timestamp::from_unix_seconds(le_u32(raw, disk_offset(INODE_ATIME_OFFSET))?);
    let changed = Ext4Timestamp::from_unix_seconds(le_u32(raw, disk_offset(INODE_CTIME_OFFSET))?);
    let modified = Ext4Timestamp::from_unix_seconds(le_u32(raw, disk_offset(INODE_MTIME_OFFSET))?);
    let created = if raw
        .get(
            INODE_CRTIME_OFFSET
                ..INODE_CRTIME_OFFSET
                    .checked_add(core::mem::size_of::<u32>())
                    .ok_or(Error::ArithmeticOverflow)?,
        )
        .is_some()
    {
        Ext4Timestamp::from_unix_seconds(le_u32(raw, disk_offset(INODE_CRTIME_OFFSET))?)
    } else {
        changed
    };
    Ok(Ext4Times::new(accessed, modified, changed, created))
}

#[cfg(test)]
mod tests {
    use super::{
        DirectoryStorageKind, Ext4LinkCount, Ext4Permissions, Inode, InodeFlags, InodeId,
        InodeMode, MODE_DIRECTORY, MODE_REGULAR,
    };
    use crate::disk::endian::{put_le_u16, put_le_u32};
    use crate::error::{Error, Result};

    fn inode_id() -> Result<InodeId> {
        InodeId::try_from(11)
    }

    fn inode_bytes(mode: u16, flags: u32) -> Result<[u8; 128]> {
        let mut raw = [0_u8; 128];
        put_le_u16(&mut raw, super::disk_offset(0), mode)?;
        put_le_u16(&mut raw, super::disk_offset(26), 1)?;
        put_le_u32(&mut raw, super::disk_offset(32), flags)?;
        Ok(raw)
    }

    #[test]
    fn directory_storage_kind_decodes_linear_and_htree() {
        let linear = inode_id().and_then(|id| {
            inode_bytes(MODE_DIRECTORY, 0).and_then(|bytes| Inode::parse(id, &bytes))
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
                .and_then(|bytes| Inode::parse(id, &bytes))
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

    #[test]
    fn directory_storage_kind_rejects_non_directory_inode() {
        let file = inode_id()
            .and_then(|id| inode_bytes(MODE_REGULAR, 0).and_then(|bytes| Inode::parse(id, &bytes)));
        assert!(file.is_ok());
        let Ok(file) = file else {
            return;
        };
        assert_eq!(file.directory_storage_kind(), Err(Error::WrongInodeKind));
    }

    #[test]
    fn link_count_rejects_deleted_inode_zero() {
        assert_eq!(Ext4LinkCount::new(0), Err(Error::InvalidInode));
        assert_eq!(Ext4LinkCount::new(1), Ok(Ext4LinkCount::ONE));
    }

    #[test]
    fn inode_mode_and_permissions_reject_mixed_domains() {
        assert_eq!(InodeMode::from_disk(0o644), Err(Error::WrongInodeKind));
        assert_eq!(Ext4Permissions::new(MODE_REGULAR), Err(Error::InvalidInode));
    }

    #[test]
    fn inode_flags_build_operation_capabilities() {
        let immutable = InodeFlags::from_u32(super::EXT4_IMMUTABLE_FL);
        assert_eq!(
            immutable.metadata_mutation(),
            Err(Error::UnsupportedInodeMutation)
        );

        let append_only = InodeFlags::from_u32(super::EXT4_APPEND_FL);
        assert_eq!(
            append_only.directory_entry_mutation(),
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
