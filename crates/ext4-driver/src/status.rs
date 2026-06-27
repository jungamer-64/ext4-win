//! Driver-local failure domain and NTSTATUS mapping.

use ext4_core::Error;
use wdk_sys::{
    NTSTATUS, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
    STATUS_CANNOT_DELETE, STATUS_DIRECTORY_NOT_EMPTY, STATUS_DISK_FULL,
    STATUS_EA_LIST_INCONSISTENT, STATUS_EA_TOO_LARGE, STATUS_FILE_CORRUPT_ERROR,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_EA_NAME,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_IO_DEVICE_ERROR,
    STATUS_NO_EAS_ON_FILE, STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, STATUS_NOT_SUPPORTED,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    STATUS_OBJECT_TYPE_MISMATCH, STATUS_UNRECOGNIZED_VOLUME, STATUS_VOLUME_DIRTY,
};

/// Driver-local result before NTSTATUS completion mapping.
pub(crate) type DriverResult<T> = Result<T, DriverError>;

/// Driver failure after IRP decoding and ext4-core execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DriverError {
    /// IRP is not valid for this device or stack state.
    InvalidDeviceRequest,
    /// Caller supplied parameters outside the accepted FSD boundary.
    InvalidParameter,
    /// Kernel memory could not be mapped for the current IRP.
    InsufficientResources,
    /// Access is denied by the current FSD policy.
    AccessDenied,
    /// Caller output buffer cannot hold the required fixed payload.
    BufferTooSmall,
    /// Caller output buffer holds a partial variable payload.
    BufferOverflow,
    /// Caller selected an unsupported information class.
    InvalidInfoClass,
    /// Opened node is not a reparse point.
    NotAReparsePoint,
    /// Reparse tag belongs to another handler.
    ReparseTagNotHandled,
    /// EA name is not representable by the Windows EA boundary.
    InvalidEaName,
    /// EA list structure is internally inconsistent.
    EaListInconsistent,
    /// Opened node has no extended attributes.
    NoEasOnFile,
    /// EA payload is too large for the Windows EA boundary.
    EaTooLarge,
    /// Create target already exists where creation requires absence.
    ObjectNameCollision,
    /// Create target name is absent where opening requires presence.
    ObjectNameNotFound,
    /// Intermediate create path component is absent or not a directory.
    ObjectPathNotFound,
    /// Create target kind does not satisfy the requested file/directory constraint.
    ObjectTypeMismatch,
    /// WDK share-access validation rejected this open.
    ShareAccessConflict,
    /// FCB open reference count reached the representable boundary.
    TooManyOpenReferences,
    /// Directory enumeration has no more entries for this cursor.
    NoMoreFiles,
    /// Exact directory enumeration pattern matched no entry.
    NoSuchFile,
    /// Candidate volume does not contain a mountable ext4 filesystem.
    UnrecognizedVolume,
    /// Caller selected a valid but unsupported Windows filesystem behavior.
    NotSupported,
    /// ext4-core rejected the requested filesystem operation.
    Core(Error),
}

impl DriverError {
    /// Maps the driver failure to the NTSTATUS completed to the I/O Manager.
    pub(crate) const fn ntstatus(self) -> NTSTATUS {
        match self {
            Self::InvalidDeviceRequest => STATUS_INVALID_DEVICE_REQUEST,
            Self::InvalidParameter => STATUS_INVALID_PARAMETER,
            Self::InsufficientResources => STATUS_INSUFFICIENT_RESOURCES,
            Self::AccessDenied => STATUS_ACCESS_DENIED,
            Self::BufferTooSmall => STATUS_BUFFER_TOO_SMALL,
            Self::BufferOverflow => STATUS_BUFFER_OVERFLOW,
            Self::InvalidInfoClass => STATUS_INVALID_INFO_CLASS,
            Self::NotAReparsePoint => ntstatus(0xC000_0275),
            Self::ReparseTagNotHandled => ntstatus(0xC000_0279),
            Self::InvalidEaName => STATUS_INVALID_EA_NAME,
            Self::EaListInconsistent => STATUS_EA_LIST_INCONSISTENT,
            Self::NoEasOnFile => STATUS_NO_EAS_ON_FILE,
            Self::EaTooLarge => STATUS_EA_TOO_LARGE,
            Self::ObjectNameCollision => STATUS_OBJECT_NAME_COLLISION,
            Self::ObjectNameNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
            Self::ObjectPathNotFound => STATUS_OBJECT_PATH_NOT_FOUND,
            Self::ObjectTypeMismatch => STATUS_OBJECT_TYPE_MISMATCH,
            Self::ShareAccessConflict => ntstatus(0xC000_0043),
            Self::TooManyOpenReferences => STATUS_INSUFFICIENT_RESOURCES,
            Self::NoMoreFiles => STATUS_NO_MORE_FILES,
            Self::NoSuchFile => STATUS_NO_SUCH_FILE,
            Self::UnrecognizedVolume => STATUS_UNRECOGNIZED_VOLUME,
            Self::NotSupported => STATUS_NOT_SUPPORTED,
            Self::Core(error) => core_error_status(error),
        }
    }
}

impl From<Error> for DriverError {
    fn from(value: Error) -> Self {
        Self::Core(value)
    }
}

/// Converts a hexadecimal NTSTATUS payload into the signed WDK alias.
const fn ntstatus(value: u32) -> NTSTATUS {
    i32::from_ne_bytes(value.to_ne_bytes())
}

/// Maps ext4-core domain errors to the closest NTSTATUS value.
const fn core_error_status(error: Error) -> NTSTATUS {
    match error {
        Error::DirectoryEntryNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        Error::NameAlreadyExists | Error::AmbiguousWindowsName => STATUS_OBJECT_NAME_COLLISION,
        Error::WrongInodeKind => STATUS_OBJECT_TYPE_MISMATCH,
        Error::NoSpace | Error::NoFreeInode => STATUS_DISK_FULL,
        Error::DirectoryNotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        Error::CannotRemoveRoot => STATUS_CANNOT_DELETE,
        Error::MissingEncryptionKey => STATUS_ACCESS_DENIED,
        Error::DirtyVolume => STATUS_VOLUME_DIRTY,
        Error::DeviceIo => STATUS_IO_DEVICE_ERROR,
        Error::VerityMismatch => STATUS_IO_DEVICE_ERROR,
        Error::UnsupportedBlockSize
        | Error::UnsupportedIncompatFeature
        | Error::UnsupportedReadOnlyFeature
        | Error::UnsupportedWriteFeature
        | Error::UnsupportedJournal
        | Error::UnsupportedBlockMap
        | Error::UnsupportedExtentDepth
        | Error::UnsupportedDirectoryHash
        | Error::UnsupportedInodeMutation
        | Error::UnsupportedEncryption
        | Error::UnsupportedVerity
        | Error::DirectoryTooLarge => STATUS_NOT_SUPPORTED,
        Error::DeviceRange
        | Error::ArithmeticOverflow
        | Error::InvalidName
        | Error::InvalidXattr
        | Error::InvalidAcl
        | Error::InvalidEncryptionContext
        | Error::InvalidVerityMetadata
        | Error::InvalidWriteRange
        | Error::TransactionTooLarge => STATUS_INVALID_PARAMETER,
        Error::TruncatedStructure
        | Error::InvalidMagic
        | Error::InvalidSuperblock
        | Error::InvalidClusterGeometry
        | Error::InvalidInode
        | Error::InvalidExtentTree
        | Error::InvalidDirectoryEntry
        | Error::ClusterReferenceConflict
        | Error::JournalCorrupt
        | Error::ChecksumMismatch => STATUS_FILE_CORRUPT_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use ext4_core::Error;
    use wdk_sys::{
        STATUS_DIRECTORY_NOT_EMPTY, STATUS_DISK_FULL, STATUS_FILE_CORRUPT_ERROR,
        STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_COLLISION,
        STATUS_OBJECT_NAME_NOT_FOUND, STATUS_VOLUME_DIRTY,
    };

    use super::DriverError;

    #[test]
    fn core_namespace_errors_map_to_name_statuses() {
        assert_eq!(
            DriverError::from(Error::DirectoryEntryNotFound).ntstatus(),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            DriverError::from(Error::NameAlreadyExists).ntstatus(),
            STATUS_OBJECT_NAME_COLLISION
        );
        assert_eq!(
            DriverError::from(Error::DirectoryNotEmpty).ntstatus(),
            STATUS_DIRECTORY_NOT_EMPTY
        );
    }

    #[test]
    fn core_space_and_mount_errors_map_to_fsd_statuses() {
        assert_eq!(
            DriverError::from(Error::NoFreeInode).ntstatus(),
            STATUS_DISK_FULL
        );
        assert_eq!(
            DriverError::from(Error::DirtyVolume).ntstatus(),
            STATUS_VOLUME_DIRTY
        );
        assert_eq!(
            DriverError::from(Error::UnsupportedDirectoryHash).ntstatus(),
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(
            DriverError::from(Error::UnsupportedVerity).ntstatus(),
            STATUS_NOT_SUPPORTED
        );
    }

    #[test]
    fn corrupt_and_bad_request_errors_remain_separate() {
        assert_eq!(
            DriverError::from(Error::ChecksumMismatch).ntstatus(),
            STATUS_FILE_CORRUPT_ERROR
        );
        assert_eq!(
            DriverError::from(Error::InvalidWriteRange).ntstatus(),
            STATUS_INVALID_PARAMETER
        );
    }
}
