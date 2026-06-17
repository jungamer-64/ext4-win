//! Driver-local failure domain and NTSTATUS mapping.

use ext4_core::Error;
use wdk_sys::{
    NTSTATUS, STATUS_ACCESS_DENIED, STATUS_CANNOT_DELETE, STATUS_DIRECTORY_NOT_EMPTY,
    STATUS_DISK_FULL, STATUS_FILE_CORRUPT_ERROR, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER, STATUS_IO_DEVICE_ERROR,
    STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_TYPE_MISMATCH, STATUS_VOLUME_DIRTY,
};

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
            Self::Core(error) => core_error_status(error),
        }
    }
}

impl From<Error> for DriverError {
    fn from(value: Error) -> Self {
        Self::Core(value)
    }
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
        Error::DirtyVolume => STATUS_VOLUME_DIRTY,
        Error::DeviceIo => STATUS_IO_DEVICE_ERROR,
        Error::UnsupportedBlockSize
        | Error::UnsupportedIncompatFeature
        | Error::UnsupportedReadOnlyFeature
        | Error::UnsupportedWriteFeature
        | Error::UnsupportedJournal
        | Error::UnsupportedBlockMap
        | Error::UnsupportedExtentDepth
        | Error::UnsupportedDirectoryHash
        | Error::UnsupportedInodeMutation
        | Error::DirectoryTooLarge => STATUS_NOT_SUPPORTED,
        Error::DeviceRange
        | Error::ArithmeticOverflow
        | Error::InvalidName
        | Error::InvalidXattr
        | Error::InvalidAcl
        | Error::InvalidEncryptionContext
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
