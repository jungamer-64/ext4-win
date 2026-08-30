//! Filesystem-control and information-class decoding.

use super::*;

/// Decoded file-system-control minor function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileSystemControlMinorFunction {
    /// I/O Manager mount request.
    MountVolume,
    /// User FSCTL request.
    UserFsRequest,
    /// Unsupported file-system-control minor function.
    Unsupported,
}

/// Decoded directory-control minor function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryControlMinorFunction {
    /// Directory enumeration request.
    QueryDirectory,
    /// Directory change notification request.
    NotifyChangeDirectory,
    /// Extended directory change notification request.
    NotifyChangeDirectoryEx,
    /// Unsupported directory-control minor function.
    Unsupported,
}

/// IRP_MN_MOUNT_VOLUME as a stack-location minor function byte.
pub(super) const MOUNT_VOLUME_MINOR_FUNCTION: u32 = 1;

/// Decoded user FSCTL code selected by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FsControlCode {
    /// Windows `FSCTL_REQUEST_OPLOCK_LEVEL_1`.
    RequestOplockLevel1,
    /// Windows `FSCTL_REQUEST_OPLOCK_LEVEL_2`.
    RequestOplockLevel2,
    /// Windows `FSCTL_REQUEST_BATCH_OPLOCK`.
    RequestBatchOplock,
    /// Windows `FSCTL_OPLOCK_BREAK_ACKNOWLEDGE`.
    OplockBreakAcknowledge,
    /// Windows `FSCTL_OPBATCH_ACK_CLOSE_PENDING`.
    OplockBatchAckClosePending,
    /// Windows `FSCTL_OPLOCK_BREAK_NOTIFY`.
    OplockBreakNotify,
    /// Windows `FSCTL_OPLOCK_BREAK_ACK_NO_2`.
    OplockBreakAckNoLevel2,
    /// Windows `FSCTL_REQUEST_FILTER_OPLOCK`.
    RequestFilterOplock,
    /// Windows `FSCTL_REQUEST_OPLOCK` structured request.
    RequestOplock,
    /// Windows `FSCTL_LOCK_VOLUME`.
    LockVolume,
    /// Windows `FSCTL_UNLOCK_VOLUME`.
    UnlockVolume,
    /// Windows `FSCTL_DISMOUNT_VOLUME`.
    DismountVolume,
    /// Windows `FSCTL_IS_VOLUME_MOUNTED`.
    IsVolumeMounted,
    /// Windows `FSCTL_ALLOW_EXTENDED_DASD_IO`.
    AllowExtendedDasdIo,
    /// Windows `FSCTL_GET_REPARSE_POINT`.
    GetReparsePoint,
    /// Windows `FSCTL_SET_REPARSE_POINT`.
    SetReparsePoint,
    /// Windows `FSCTL_DELETE_REPARSE_POINT`.
    DeleteReparsePoint,
    /// ext4win private fscrypt add-key control.
    AddEncryptionKey,
    /// ext4win private fscrypt remove-key control.
    RemoveEncryptionKey,
    /// ext4win private fscrypt key-status control.
    GetEncryptionKeyStatus,
    /// ext4win private fs-verity enable control.
    EnableVerity,
}

/// Oplock-control effect relevant to serialization with an admitted stream mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OplockControlAction {
    /// Requests a new oplock grant and must not cross an active stream mutation.
    Grant,
    /// Advances or observes an already established break and must remain available to drain it.
    BreakContinuation,
}

impl FsControlCode {
    /// Decodes the raw WDK control code at the IRP boundary.
    /// # Errors
    ///
    /// Returns an error when `value` is not one of the supported Windows or ext4win FSCTL codes.
    pub(super) fn from_raw(value: wdk_sys::ULONG) -> Result<Self, DriverError> {
        match value {
            FSCTL_REQUEST_OPLOCK_LEVEL_1 => Ok(Self::RequestOplockLevel1),
            FSCTL_REQUEST_OPLOCK_LEVEL_2 => Ok(Self::RequestOplockLevel2),
            FSCTL_REQUEST_BATCH_OPLOCK => Ok(Self::RequestBatchOplock),
            FSCTL_OPLOCK_BREAK_ACKNOWLEDGE => Ok(Self::OplockBreakAcknowledge),
            FSCTL_OPBATCH_ACK_CLOSE_PENDING => Ok(Self::OplockBatchAckClosePending),
            FSCTL_OPLOCK_BREAK_NOTIFY => Ok(Self::OplockBreakNotify),
            FSCTL_OPLOCK_BREAK_ACK_NO_2 => Ok(Self::OplockBreakAckNoLevel2),
            FSCTL_REQUEST_FILTER_OPLOCK => Ok(Self::RequestFilterOplock),
            FSCTL_REQUEST_OPLOCK => Ok(Self::RequestOplock),
            FSCTL_LOCK_VOLUME => Ok(Self::LockVolume),
            FSCTL_UNLOCK_VOLUME => Ok(Self::UnlockVolume),
            FSCTL_DISMOUNT_VOLUME => Ok(Self::DismountVolume),
            FSCTL_IS_VOLUME_MOUNTED => Ok(Self::IsVolumeMounted),
            FSCTL_ALLOW_EXTENDED_DASD_IO => Ok(Self::AllowExtendedDasdIo),
            FSCTL_GET_REPARSE_POINT => Ok(Self::GetReparsePoint),
            FSCTL_SET_REPARSE_POINT => Ok(Self::SetReparsePoint),
            FSCTL_DELETE_REPARSE_POINT => Ok(Self::DeleteReparsePoint),
            FSCTL_EXT4WIN_ADD_ENCRYPTION_KEY => Ok(Self::AddEncryptionKey),
            FSCTL_EXT4WIN_REMOVE_ENCRYPTION_KEY => Ok(Self::RemoveEncryptionKey),
            FSCTL_EXT4WIN_GET_ENCRYPTION_KEY_STATUS => Ok(Self::GetEncryptionKeyStatus),
            FSCTL_EXT4WIN_ENABLE_VERITY => Ok(Self::EnableVerity),
            _ => Err(DriverError::NotSupported),
        }
    }

    /// Returns whether FsRtl owns this standard oplock control operation.
    pub(crate) const fn is_oplock(self) -> bool {
        matches!(
            self,
            Self::RequestOplockLevel1
                | Self::RequestOplockLevel2
                | Self::RequestBatchOplock
                | Self::OplockBreakAcknowledge
                | Self::OplockBatchAckClosePending
                | Self::OplockBreakNotify
                | Self::OplockBreakAckNoLevel2
                | Self::RequestFilterOplock
                | Self::RequestOplock
        )
    }

    /// Classifies an oplock FSCTL without duplicating FsRtl's complete payload validation.
    ///
    /// Malformed or truncated structured input is classified as a grant. FsRtl remains the
    /// validation authority when no mutation barrier exists, while ambiguous input can never use
    /// the break-continuation lane to bypass that barrier.
    /// # Errors
    ///
    /// Returns invalid-device-request for a non-oplock control code.
    pub(crate) fn oplock_action(
        self,
        structured_input: &[u8],
    ) -> DriverResult<OplockControlAction> {
        match self {
            Self::RequestOplockLevel1
            | Self::RequestOplockLevel2
            | Self::RequestBatchOplock
            | Self::RequestFilterOplock => Ok(OplockControlAction::Grant),
            Self::OplockBreakAcknowledge
            | Self::OplockBatchAckClosePending
            | Self::OplockBreakNotify
            | Self::OplockBreakAckNoLevel2 => Ok(OplockControlAction::BreakContinuation),
            Self::RequestOplock => Ok(structured_oplock_action(structured_input)),
            Self::LockVolume
            | Self::UnlockVolume
            | Self::DismountVolume
            | Self::IsVolumeMounted
            | Self::AllowExtendedDasdIo
            | Self::GetReparsePoint
            | Self::SetReparsePoint
            | Self::DeleteReparsePoint
            | Self::AddEncryptionKey
            | Self::RemoveEncryptionKey
            | Self::GetEncryptionKeyStatus
            | Self::EnableVerity => Err(DriverError::InvalidDeviceRequest),
        }
    }
}

/// Byte offset of `REQUEST_OPLOCK_INPUT_BUFFER::Flags` in the documented buffered ABI.
const REQUEST_OPLOCK_FLAGS_OFFSET: usize = 8;
/// Complete prefix required to inspect `REQUEST_OPLOCK_INPUT_BUFFER::Flags`.
const REQUEST_OPLOCK_FLAGS_END: usize = 12;
/// WDK `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`.
const REQUEST_OPLOCK_INPUT_FLAG_REQUEST: u32 = 0x0000_0001;
/// WDK `REQUEST_OPLOCK_INPUT_FLAG_ACK`.
const REQUEST_OPLOCK_INPUT_FLAG_ACK: u32 = 0x0000_0002;

/// Selects the break-continuation lane only for an unambiguous structured ACK.
fn structured_oplock_action(input: &[u8]) -> OplockControlAction {
    let Some(bytes) = input.get(REQUEST_OPLOCK_FLAGS_OFFSET..REQUEST_OPLOCK_FLAGS_END) else {
        return OplockControlAction::Grant;
    };
    let Ok(flags) = <&[u8; 4]>::try_from(bytes) else {
        return OplockControlAction::Grant;
    };
    let flags = u32::from_le_bytes(*flags);
    if flags & REQUEST_OPLOCK_INPUT_FLAG_ACK != 0 && flags & REQUEST_OPLOCK_INPUT_FLAG_REQUEST == 0
    {
        OplockControlAction::BreakContinuation
    } else {
        OplockControlAction::Grant
    }
}

/// `FSCTL_REQUEST_OPLOCK_LEVEL_1`.
const FSCTL_REQUEST_OPLOCK_LEVEL_1: wdk_sys::ULONG = buffered_file_system_control(0);
/// `FSCTL_REQUEST_OPLOCK_LEVEL_2`.
const FSCTL_REQUEST_OPLOCK_LEVEL_2: wdk_sys::ULONG = buffered_file_system_control(1);
/// `FSCTL_REQUEST_BATCH_OPLOCK`.
const FSCTL_REQUEST_BATCH_OPLOCK: wdk_sys::ULONG = buffered_file_system_control(2);
/// `FSCTL_OPLOCK_BREAK_ACKNOWLEDGE`.
const FSCTL_OPLOCK_BREAK_ACKNOWLEDGE: wdk_sys::ULONG = buffered_file_system_control(3);
/// `FSCTL_OPBATCH_ACK_CLOSE_PENDING`.
const FSCTL_OPBATCH_ACK_CLOSE_PENDING: wdk_sys::ULONG = buffered_file_system_control(4);
/// `FSCTL_OPLOCK_BREAK_NOTIFY`.
const FSCTL_OPLOCK_BREAK_NOTIFY: wdk_sys::ULONG = buffered_file_system_control(5);
/// `FSCTL_OPLOCK_BREAK_ACK_NO_2`.
const FSCTL_OPLOCK_BREAK_ACK_NO_2: wdk_sys::ULONG = buffered_file_system_control(20);
/// `FSCTL_REQUEST_FILTER_OPLOCK`.
const FSCTL_REQUEST_FILTER_OPLOCK: wdk_sys::ULONG = buffered_file_system_control(23);
/// `FSCTL_REQUEST_OPLOCK`.
const FSCTL_REQUEST_OPLOCK: wdk_sys::ULONG = buffered_file_system_control(144);

/// `FSCTL_LOCK_VOLUME`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_LOCK_VOLUME: wdk_sys::ULONG = buffered_file_system_control(6);
/// `FSCTL_UNLOCK_VOLUME`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_UNLOCK_VOLUME: wdk_sys::ULONG = buffered_file_system_control(7);
/// `FSCTL_DISMOUNT_VOLUME`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_DISMOUNT_VOLUME: wdk_sys::ULONG = buffered_file_system_control(8);
/// `FSCTL_IS_VOLUME_MOUNTED`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_IS_VOLUME_MOUNTED: wdk_sys::ULONG = buffered_file_system_control(10);
/// `FSCTL_ALLOW_EXTENDED_DASD_IO`, from
/// `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 32, METHOD_NEITHER, FILE_ANY_ACCESS)`.
const FSCTL_ALLOW_EXTENDED_DASD_IO: wdk_sys::ULONG = neither_file_system_control(32);
/// `FSCTL_GET_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_GET_REPARSE_POINT: wdk_sys::ULONG = 589_992;
/// `FSCTL_SET_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_SET_REPARSE_POINT: wdk_sys::ULONG = 589_988;
/// `FSCTL_DELETE_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_DELETE_REPARSE_POINT: wdk_sys::ULONG = 589_996;

/// Windows `FILE_DEVICE_FILE_SYSTEM`.
const FILE_DEVICE_FILE_SYSTEM: wdk_sys::ULONG = 0x0000_0009;
/// Windows `METHOD_BUFFERED`.
const METHOD_BUFFERED: wdk_sys::ULONG = 0;
/// Windows `METHOD_NEITHER`.
const METHOD_NEITHER: wdk_sys::ULONG = 3;
/// Windows `FILE_ANY_ACCESS`.
const FILE_ANY_ACCESS: wdk_sys::ULONG = 0;
/// ext4win private function code for adding an fscrypt key.
const EXT4WIN_ADD_ENCRYPTION_KEY_FUNCTION: wdk_sys::ULONG = 0x900;
/// ext4win private function code for removing an fscrypt key.
const EXT4WIN_REMOVE_ENCRYPTION_KEY_FUNCTION: wdk_sys::ULONG = 0x901;
/// ext4win private function code for fscrypt key status.
const EXT4WIN_GET_ENCRYPTION_KEY_STATUS_FUNCTION: wdk_sys::ULONG = 0x902;
/// ext4win private function code for enabling fs-verity.
const EXT4WIN_ENABLE_VERITY_FUNCTION: wdk_sys::ULONG = 0x903;

/// Builds a buffered, unrestricted Windows filesystem control code.
const fn buffered_file_system_control(function: wdk_sys::ULONG) -> wdk_sys::ULONG {
    (FILE_DEVICE_FILE_SYSTEM << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_BUFFERED
}

/// Builds an unrestricted Windows filesystem control code with no transfer buffer.
const fn neither_file_system_control(function: wdk_sys::ULONG) -> wdk_sys::ULONG {
    (FILE_DEVICE_FILE_SYSTEM << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_NEITHER
}

/// ext4win FSCTL carrying Linux `struct fscrypt_add_key_arg`.
const FSCTL_EXT4WIN_ADD_ENCRYPTION_KEY: wdk_sys::ULONG =
    buffered_file_system_control(EXT4WIN_ADD_ENCRYPTION_KEY_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fscrypt_remove_key_arg`.
const FSCTL_EXT4WIN_REMOVE_ENCRYPTION_KEY: wdk_sys::ULONG =
    buffered_file_system_control(EXT4WIN_REMOVE_ENCRYPTION_KEY_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fscrypt_get_key_status_arg`.
const FSCTL_EXT4WIN_GET_ENCRYPTION_KEY_STATUS: wdk_sys::ULONG =
    buffered_file_system_control(EXT4WIN_GET_ENCRYPTION_KEY_STATUS_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fsverity_enable_arg`.
const FSCTL_EXT4WIN_ENABLE_VERITY: wdk_sys::ULONG =
    buffered_file_system_control(EXT4WIN_ENABLE_VERITY_FUNCTION);

/// Decoded query-volume filesystem information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueryVolumeInformationClass {
    /// Windows `FileFsVolumeInformation`.
    Volume,
    /// Windows `FileFsSizeInformation`.
    Size,
    /// Windows `FileFsDeviceInformation`.
    Device,
    /// Windows `FileFsAttributeInformation`.
    Attribute,
    /// Windows `FileFsFullSizeInformation`.
    FullSize,
}

impl QueryVolumeInformationClass {
    /// Decodes a raw WDK filesystem information class for volume queries.
    /// # Errors
    ///
    /// Returns an error when the filesystem information class is not supported for volume queries.
    pub(super) fn from_raw(value: wdk_sys::FS_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            FILE_FS_VOLUME_INFORMATION_CLASS => Ok(Self::Volume),
            FILE_FS_SIZE_INFORMATION_CLASS => Ok(Self::Size),
            FILE_FS_DEVICE_INFORMATION_CLASS => Ok(Self::Device),
            FILE_FS_ATTRIBUTE_INFORMATION_CLASS => Ok(Self::Attribute),
            FILE_FS_FULL_SIZE_INFORMATION_CLASS => Ok(Self::FullSize),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded set-volume filesystem information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetVolumeInformationClass {
    /// Windows `FileFsLabelInformation`.
    Label,
}

impl SetVolumeInformationClass {
    /// Decodes a raw WDK filesystem information class for volume mutations.
    /// # Errors
    ///
    /// Returns an error when the filesystem information class is not `FileFsLabelInformation`.
    pub(super) fn from_raw(value: wdk_sys::FS_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            FILE_FS_LABEL_INFORMATION_CLASS => Ok(Self::Label),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// `FileFsVolumeInformation`.
const FILE_FS_VOLUME_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 1;
/// `FileFsLabelInformation`.
const FILE_FS_LABEL_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 2;
/// `FileFsSizeInformation`.
const FILE_FS_SIZE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 3;
/// `FileFsDeviceInformation`.
const FILE_FS_DEVICE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 4;
/// `FileFsAttributeInformation`.
const FILE_FS_ATTRIBUTE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 5;
/// `FileFsFullSizeInformation`.
const FILE_FS_FULL_SIZE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 7;

/// Decoded query-file information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueryFileInformationClass {
    /// Windows `FileBasicInformation`.
    Basic,
    /// Windows `FileStandardInformation`.
    Standard,
    /// Windows `FileHardLinkInformation`.
    HardLink,
    /// Windows `FileStandardLinkInformation`.
    StandardLink,
    /// Windows `FileInternalInformation`.
    Internal,
    /// Windows `FilePositionInformation`.
    Position,
    /// Windows `FileNetworkOpenInformation`.
    NetworkOpen,
    /// Windows `FileNameInformation`.
    Name,
    /// Windows `FileAttributeTagInformation`.
    AttributeTag,
}

impl QueryFileInformationClass {
    /// Decodes a raw WDK file information class for fixed file queries.
    /// # Errors
    ///
    /// Returns an error when the file information class is not implemented for fixed file queries.
    pub(super) fn from_raw(value: wdk_sys::FILE_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation => Ok(Self::Basic),
            wdk_sys::_FILE_INFORMATION_CLASS::FileStandardInformation => Ok(Self::Standard),
            wdk_sys::_FILE_INFORMATION_CLASS::FileHardLinkInformation => Ok(Self::HardLink),
            wdk_sys::_FILE_INFORMATION_CLASS::FileStandardLinkInformation => Ok(Self::StandardLink),
            wdk_sys::_FILE_INFORMATION_CLASS::FileInternalInformation => Ok(Self::Internal),
            wdk_sys::_FILE_INFORMATION_CLASS::FilePositionInformation => Ok(Self::Position),
            wdk_sys::_FILE_INFORMATION_CLASS::FileNetworkOpenInformation => Ok(Self::NetworkOpen),
            wdk_sys::_FILE_INFORMATION_CLASS::FileNameInformation => Ok(Self::Name),
            wdk_sys::_FILE_INFORMATION_CLASS::FileAttributeTagInformation => Ok(Self::AttributeTag),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded set-file information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetFileInformationClass {
    /// Windows `FileBasicInformation`.
    Basic,
    /// Windows `FilePositionInformation`.
    Position,
    /// Windows `FileEndOfFileInformation`.
    EndOfFile,
    /// Windows `FileAllocationInformation`.
    Allocation,
    /// Windows `FileDispositionInformation`.
    Disposition,
    /// Windows `FileDispositionInformationEx`.
    DispositionEx,
    /// Windows `FileLinkInformation`.
    Link,
    /// Windows `FileLinkInformationEx`.
    LinkEx,
    /// Windows `FileRenameInformation`.
    Rename,
    /// Windows `FileRenameInformationEx`.
    RenameEx,
}

impl SetFileInformationClass {
    /// Decodes a raw WDK file information class for file mutations.
    /// # Errors
    ///
    /// Returns an error when the file information class is not implemented for file mutations.
    pub(super) fn from_raw(value: wdk_sys::FILE_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation => Ok(Self::Basic),
            wdk_sys::_FILE_INFORMATION_CLASS::FilePositionInformation => Ok(Self::Position),
            wdk_sys::_FILE_INFORMATION_CLASS::FileEndOfFileInformation => Ok(Self::EndOfFile),
            wdk_sys::_FILE_INFORMATION_CLASS::FileAllocationInformation => Ok(Self::Allocation),
            wdk_sys::_FILE_INFORMATION_CLASS::FileDispositionInformation => Ok(Self::Disposition),
            wdk_sys::_FILE_INFORMATION_CLASS::FileDispositionInformationEx => {
                Ok(Self::DispositionEx)
            }
            wdk_sys::_FILE_INFORMATION_CLASS::FileLinkInformation => Ok(Self::Link),
            wdk_sys::_FILE_INFORMATION_CLASS::FileLinkInformationEx => Ok(Self::LinkEx),
            wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformation => Ok(Self::Rename),
            wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformationEx => Ok(Self::RenameEx),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded query-directory information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryInformationClass {
    /// Windows `FileDirectoryInformation`.
    Directory,
    /// Windows `FileFullDirectoryInformation`.
    Full,
    /// Windows `FileBothDirectoryInformation`.
    Both,
    /// Windows `FileNamesInformation`.
    Names,
    /// Windows `FileIdFullDirectoryInformation`.
    IdFull,
    /// Windows `FileIdBothDirectoryInformation`.
    IdBoth,
    /// Windows `FileIdExtdDirectoryInformation`.
    IdExtd,
    /// Windows `FileIdExtdBothDirectoryInformation`.
    IdExtdBoth,
    /// Windows `FileId64ExtdDirectoryInformation`.
    Id64Extd,
    /// Windows `FileId64ExtdBothDirectoryInformation`.
    Id64ExtdBoth,
}

impl DirectoryInformationClass {
    /// Decodes a raw WDK file information class for directory enumeration.
    /// # Errors
    ///
    /// Returns an error when the file information class is not a supported directory enumeration
    /// class.
    pub(super) fn from_raw(value: wdk_sys::FILE_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation => Ok(Self::Directory),
            wdk_sys::_FILE_INFORMATION_CLASS::FileFullDirectoryInformation => Ok(Self::Full),
            wdk_sys::_FILE_INFORMATION_CLASS::FileBothDirectoryInformation => Ok(Self::Both),
            wdk_sys::_FILE_INFORMATION_CLASS::FileNamesInformation => Ok(Self::Names),
            wdk_sys::_FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation => Ok(Self::IdFull),
            wdk_sys::_FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation => Ok(Self::IdBoth),
            wdk_sys::_FILE_INFORMATION_CLASS::FileIdExtdDirectoryInformation => Ok(Self::IdExtd),
            wdk_sys::_FILE_INFORMATION_CLASS::FileIdExtdBothDirectoryInformation => {
                Ok(Self::IdExtdBoth)
            }
            wdk_sys::_FILE_INFORMATION_CLASS::FileId64ExtdDirectoryInformation => {
                Ok(Self::Id64Extd)
            }
            wdk_sys::_FILE_INFORMATION_CLASS::FileId64ExtdBothDirectoryInformation => {
                Ok(Self::Id64ExtdBoth)
            }
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}
