//! Typed WDK stack projections for supported IRP operations.

use super::*;

/// Decoded mount-volume stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountVolumeStack {
    /// VPB supplied by the I/O Manager for the target volume.
    pub(super) vpb: KernelVpb,
    /// Lower storage device object to mount.
    pub(super) target_device: KernelDevice,
    /// Output buffer length supplied with the mount request.
    pub(super) output_buffer_length: IrpBufferLength,
}

/// Decoded user file-system-control stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FileSystemControlStack {
    /// Input system-buffer length.
    pub(super) input_buffer_length: IrpBufferLength,
    /// Output system-buffer length.
    pub(super) output_buffer_length: IrpBufferLength,
    /// Requested FSCTL code.
    pub(super) fs_control_code: FsControlCode,
}

/// Decoded buffered device-control stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DeviceControlStack {
    /// Input system-buffer length.
    pub(super) input_buffer_length: IrpBufferLength,
    /// Output system-buffer length.
    pub(super) output_buffer_length: IrpBufferLength,
    /// Requested IOCTL code.
    pub(super) io_control_code: wdk_sys::ULONG,
}

impl MountVolumeStack {
    /// Returns the VPB supplied for the mount.
    pub(crate) const fn vpb(self) -> KernelVpb {
        self.vpb
    }

    /// Returns the lower storage device object.
    pub(crate) const fn target_device(self) -> KernelDevice {
        self.target_device
    }

    /// Returns the mount request output buffer length.
    pub(crate) const fn output_buffer_length(self) -> IrpBufferLength {
        self.output_buffer_length
    }
}

impl FileSystemControlStack {
    /// Returns the input system-buffer length.
    pub(crate) const fn input_buffer_length(self) -> IrpBufferLength {
        self.input_buffer_length
    }

    /// Returns the output system-buffer length.
    pub(crate) const fn output_buffer_length(self) -> IrpBufferLength {
        self.output_buffer_length
    }

    /// Returns the FSCTL code.
    pub(crate) const fn fs_control_code(self) -> FsControlCode {
        self.fs_control_code
    }
}

impl DeviceControlStack {
    /// Returns the buffered input extent retained by the I/O Manager.
    pub(crate) const fn input_buffer_length(self) -> IrpBufferLength {
        self.input_buffer_length
    }
    /// Returns the buffered output extent retained by the pending IRP.
    pub(crate) const fn output_buffer_length(self) -> IrpBufferLength {
        self.output_buffer_length
    }

    /// Returns whether this request carries no input or output payload.
    pub(crate) const fn is_payload_free(self) -> bool {
        self.input_buffer_length.is_empty() && self.output_buffer_length.is_empty()
    }

    /// Returns the exact requested IOCTL code.
    pub(crate) const fn io_control_code(self) -> wdk_sys::ULONG {
        self.io_control_code
    }
}

/// Decoded create/open stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateStack {
    /// Caller-supplied initial file attributes, interpreted only when creating or replacing.
    pub(super) file_attributes: u32,
    /// Decoded create parameters.
    pub(super) parameters: CreateParameters,
}

impl CreateStack {
    /// Returns the decoded create parameters.
    pub(crate) const fn parameters(self) -> CreateParameters {
        self.parameters
    }
    /// Returns creation attributes without applying them to an ordinary existing open.
    pub(crate) const fn file_attributes(self) -> u32 {
        self.file_attributes
    }
}

/// Decoded query-volume-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryVolumeStack {
    /// Output buffer length.
    pub(super) length: IrpBufferLength,
    /// Requested filesystem information class.
    pub(super) information_class: QueryVolumeInformationClass,
}

/// Decoded set-volume-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetVolumeStack {
    /// Input buffer length.
    pub(super) length: IrpBufferLength,
    /// Requested filesystem information class.
    pub(super) information_class: SetVolumeInformationClass,
}

/// Decoded query-file-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryFileStack {
    /// Output buffer length.
    pub(super) length: IrpBufferLength,
    /// Requested file information class.
    pub(super) information_class: QueryFileInformationClass,
}

/// Decoded set-file-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetFileStack<'owner> {
    /// Input buffer length.
    pub(super) length: IrpBufferLength,
    /// Mutation semantics, including Windows-resolved destination authority.
    pub(super) operation: SetFileOperation<'owner>,
}

/// Parent selected by the I/O Manager for a rename or hard-link request.
/// The pending set-information IRP retains a supplied target FILE_OBJECT until completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NamespaceParent<'owner> {
    /// A simple new name uses the source link's directory.
    SourceDirectory,
    /// The I/O Manager has opened the exact destination parent on this volume.
    TargetDirectory(ActiveFileObject<'owner>),
}

/// Complete semantic operation decoded from a Windows set-information stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetFileOperation<'owner> {
    /// Explicit metadata and handle-local timestamp policy.
    Basic,
    /// Handle position assignment.
    Position,
    /// Explicit logical EOF change.
    Resize,
    /// Cache Manager notification that only advances on-disk valid-data length.
    AdvanceValidDataLength,
    /// Physical allocation and optional EOF reduction.
    Allocation,
    /// Boolean namespace deletion state.
    Disposition,
    /// Flag-based namespace deletion state.
    DispositionEx,
    /// Boolean hard-link replacement with resolved parent authority.
    Link(NamespaceParent<'owner>),
    /// Flag-based hard-link replacement with resolved parent authority.
    LinkEx(NamespaceParent<'owner>),
    /// Boolean rename replacement with resolved parent authority.
    Rename(NamespaceParent<'owner>),
    /// Flag-based rename replacement with resolved parent authority.
    RenameEx(NamespaceParent<'owner>),
}

/// Decoded query-directory stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryDirectoryStack {
    /// Initial CCB cursor position.
    pub(super) cursor_position: DirectoryCursorPosition,
    /// Directory entry emission cardinality.
    pub(super) entry_emission: DirectoryEntryEmission,
    /// Output buffer length.
    pub(super) length: IrpBufferLength,
    /// Requested directory information class.
    pub(super) information_class: DirectoryInformationClass,
}

/// Decoded directory-change-notification stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NotifyDirectoryStack {
    /// Changes that complete this notification request.
    pub(super) completion_filter: DirectoryChangeFilter,
    /// Directory depth covered by the notification request.
    pub(super) watch_scope: DirectoryWatchScope,
}

/// Output record format selected by `IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryNotifyInformationClass {
    /// `FILE_NOTIFY_INFORMATION` records.
    Standard,
    /// `FILE_NOTIFY_EXTENDED_INFORMATION` records.
    Extended,
    /// `FILE_NOTIFY_FULL_INFORMATION` records.
    Full,
}

impl DirectoryNotifyInformationClass {
    /// Decodes the WDK information-class enum.
    /// # Errors
    ///
    /// Returns invalid-info-class when the value does not identify a defined notification layout.
    pub(super) fn from_raw(
        value: wdk_sys::DIRECTORY_NOTIFY_INFORMATION_CLASS,
    ) -> DriverResult<Self> {
        match value {
            wdk_sys::_DIRECTORY_NOTIFY_INFORMATION_CLASS::DirectoryNotifyInformation => {
                Ok(Self::Standard)
            }
            wdk_sys::_DIRECTORY_NOTIFY_INFORMATION_CLASS::DirectoryNotifyExtendedInformation => {
                Ok(Self::Extended)
            }
            wdk_sys::_DIRECTORY_NOTIFY_INFORMATION_CLASS::DirectoryNotifyFullInformation => {
                Ok(Self::Full)
            }
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded query-EA stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryEaStack {
    /// FILE_OBJECT cursor transition selected by the caller.
    pub(super) cursor_position: EaCursorPosition,
    /// EA entry emission cardinality.
    pub(super) entry_emission: EaEntryEmission,
    /// Output buffer length.
    pub(super) length: IrpBufferLength,
}

/// Decoded set-EA stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetEaStack {
    /// Input FILE_FULL_EA_INFORMATION byte length.
    pub(super) length: IrpBufferLength,
}

/// Decoded query-security stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QuerySecurityStack {
    /// Selected security descriptor components.
    pub(super) selection: SecuritySelection,
    /// Output buffer length.
    pub(super) length: IrpBufferLength,
}

/// Decoded set-security stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetSecurityStack {
    /// Selected security descriptor components.
    pub(super) selection: SecuritySelection,
    /// Caller-supplied security descriptor, valid only during requestor-context capture.
    pub(super) security_descriptor: NonNull<c_void>,
}

/// Starting point selected by a Windows read request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadStartingPoint {
    /// Read from an explicit non-negative file offset.
    Absolute(FileOffset),
    /// Read from the synchronous FILE_OBJECT's current position.
    CurrentFilePosition,
}

impl ReadStartingPoint {
    /// Decodes a signed Windows read offset into its semantic form.
    /// # Errors
    ///
    /// Returns an error for end-of-file or unknown negative sentinel values.
    pub(super) fn from_quad(value: i64) -> DriverResult<Self> {
        if value == signed_special_offset(wdk_sys::FILE_USE_FILE_POINTER_POSITION) {
            return Ok(Self::CurrentFilePosition);
        }
        let offset = u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self::Absolute(FileOffset::from_bytes(offset)))
    }
}

/// Starting point selected by a Windows write request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteStartingPoint {
    /// Write from an explicit non-negative file offset.
    Absolute(FileOffset),
    /// Write from the synchronous FILE_OBJECT's current position.
    CurrentFilePosition,
    /// Resolve the starting point from the latest committed end of file.
    EndOfFile,
}

impl WriteStartingPoint {
    /// Decodes a signed Windows write offset into its semantic form.
    /// # Errors
    ///
    /// Returns an error for unknown negative sentinel values.
    pub(super) fn from_quad(value: i64) -> DriverResult<Self> {
        if value == signed_special_offset(wdk_sys::FILE_USE_FILE_POINTER_POSITION) {
            return Ok(Self::CurrentFilePosition);
        }
        if value == signed_special_offset(wdk_sys::FILE_WRITE_TO_END_OF_FILE) {
            return Ok(Self::EndOfFile);
        }
        let offset = u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self::Absolute(FileOffset::from_bytes(offset)))
    }
}

/// Byte-range lock key carried by one read or write request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ByteRangeLockKey(wdk_sys::ULONG);

impl ByteRangeLockKey {
    /// Wraps the key decoded from an IRP stack location.
    pub(super) const fn from_ulong(value: wdk_sys::ULONG) -> Self {
        Self(value)
    }

    /// Returns the native key for FsRtl range checks.
    #[cfg(not(test))]
    pub(crate) const fn as_ulong(self) -> wdk_sys::ULONG {
        self.0
    }
}

/// Interprets a Windows low-part sentinel as its sign-extended 64-bit offset.
pub(super) fn signed_special_offset(value: u32) -> i64 {
    i64::from(i32::from_ne_bytes(value.to_ne_bytes()))
}

/// Decoded read stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadStack {
    /// Requested byte count.
    pub(super) length: IrpBufferLength,
    /// Semantic starting point decoded from ByteOffset.
    pub(super) starting_point: ReadStartingPoint,
    /// Key used for byte-range lock ownership checks.
    pub(super) key: ByteRangeLockKey,
}

impl ReadStack {
    /// Returns the requested byte count.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested semantic starting point.
    pub(crate) const fn starting_point(self) -> ReadStartingPoint {
        self.starting_point
    }

    /// Returns the byte-range lock key.
    pub(crate) const fn key(self) -> ByteRangeLockKey {
        self.key
    }
}

/// Decoded write stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WriteStack {
    /// Requested byte count.
    pub(super) length: IrpBufferLength,
    /// Semantic starting point decoded from ByteOffset.
    pub(super) starting_point: WriteStartingPoint,
    /// Key used for byte-range lock ownership checks.
    pub(super) key: ByteRangeLockKey,
}

impl WriteStack {
    /// Returns the requested byte count.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested semantic starting point.
    pub(crate) const fn starting_point(self) -> WriteStartingPoint {
        self.starting_point
    }

    /// Returns the byte-range lock key.
    pub(crate) const fn key(self) -> ByteRangeLockKey {
        self.key
    }
}

impl QueryVolumeStack {
    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested filesystem information class.
    pub(crate) const fn information_class(self) -> QueryVolumeInformationClass {
        self.information_class
    }
}

impl SetVolumeStack {
    /// Returns the input buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested filesystem information class.
    pub(crate) const fn information_class(self) -> SetVolumeInformationClass {
        self.information_class
    }
}

impl QueryFileStack {
    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested file information class.
    pub(crate) const fn information_class(self) -> QueryFileInformationClass {
        self.information_class
    }
}

impl<'owner> SetFileStack<'owner> {
    /// Returns the input buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns complete operation semantics without reinterpreting the native stack.
    pub(crate) const fn operation(self) -> SetFileOperation<'owner> {
        self.operation
    }
}

impl QueryDirectoryStack {
    /// Returns the initial directory cursor position.
    pub(crate) const fn cursor_position(self) -> DirectoryCursorPosition {
        self.cursor_position
    }

    /// Returns directory entry emission cardinality.
    pub(crate) const fn entry_emission(self) -> DirectoryEntryEmission {
        self.entry_emission
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested directory information class.
    pub(crate) const fn information_class(self) -> DirectoryInformationClass {
        self.information_class
    }
}

impl NotifyDirectoryStack {
    /// Returns the validated completion-filter set.
    pub(crate) const fn completion_filter(self) -> DirectoryChangeFilter {
        self.completion_filter
    }

    /// Returns the directory depth covered by this request.
    pub(crate) const fn watch_scope(self) -> DirectoryWatchScope {
        self.watch_scope
    }
}

impl QueryEaStack {
    /// Returns the FILE_OBJECT cursor transition selected by the caller.
    pub(crate) const fn cursor_position(self) -> EaCursorPosition {
        self.cursor_position
    }

    /// Returns EA entry emission cardinality.
    pub(crate) const fn entry_emission(self) -> EaEntryEmission {
        self.entry_emission
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }
}

impl SetEaStack {
    /// Returns the input FILE_FULL_EA_INFORMATION byte length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }
}

impl QuerySecurityStack {
    /// Returns selected security descriptor components.
    pub(crate) const fn selection(self) -> SecuritySelection {
        self.selection
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }
}

impl SetSecurityStack {
    /// Returns selected security descriptor components.
    pub(crate) const fn selection(self) -> SecuritySelection {
        self.selection
    }

    /// Returns the caller-supplied descriptor only to requestor-context capture.
    pub(super) const fn security_descriptor_source(self) -> NonNull<c_void> {
        self.security_descriptor
    }
}
