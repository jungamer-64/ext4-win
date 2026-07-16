//! File object IRP handlers and file information packing boundary.

use alloc::boxed::Box;
use core::ptr::NonNull;

use ext4_core::{
    ChildLookup, DirectoryEntry, DirectoryNodeId, Ext4LinkCount, Ext4Name, Ext4Permissions,
    Ext4Security, Ext4Times, Ext4Timestamp, Ext4WindowsAttributes, FileNodeId, FileOffset,
    FileSize, NodeId, RenameTargetCollision, WindowsName, WindowsOverlay,
};
use wdk_sys::LARGE_INTEGER;

use crate::irp::{
    DataIoKind, DirectoryChangeFilter, DirectoryCursorPosition, DirectoryEntryEmission,
    DirectoryEntryIndex, DirectoryInformationClass, DirectoryPatternInput, DirectoryWatchScope,
    DispatchTarget, IrpBufferLength, IrpCompletion, OwnedIrp, QueryDirectoryStack,
    QueryFileInformationClass, QueryFileStack, ReadStartingPoint, RegularFileWriteAccess,
    SetFileInformationClass, SetFileStack, WriteStartingPoint,
};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use crate::state::{
    CleanupStart, CloseReleasePlan, DirectoryCursor, DirectoryNameChange,
    DirectoryNameChangeAction, DirectoryNotificationRegistration, FileControlBlock,
    KernelFileObject, MountedVolumeDevice, OpenedDirectory, OpenedHandle, OpenedLocation,
    OpenedObject, OpenedRegularFile, VolumeControlBlock, WriteCommitment,
    release_cancelled_file_control_block, release_file_control_block,
};
use crate::wire::{LittleEndianInput, LittleEndianOutput, WireByteLen, WireOffset, WireRange};

/// Executes cleanup IRPs.
/// # Errors
///
/// Returns an error when the IRP stack has no opened FILE_OBJECT or cleanup state is invalid.
pub(crate) fn cleanup(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    let file_object = target.current_stack()?.file_object()?;
    cleanup_file_object(target, file_object)?;
    Ok(IrpCompletion::EMPTY)
}

/// Executes close IRPs and releases FILE_OBJECT contexts.
/// # Errors
///
/// Returns an error when the close stack has no FILE_OBJECT.
pub(crate) fn close(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    let file_object = target.current_stack()?.file_object()?;
    release_file_contexts(file_object);
    Ok(IrpCompletion::EMPTY)
}

/// Executes regular file data reads.
/// # Errors
///
/// Returns an error when read stack decoding, output buffer mapping, or ext4 file reading fails.
pub(crate) fn read(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    read_regular_file(target)
}

/// Executes regular file data writes.
/// # Errors
///
/// Returns an error when write stack decoding, input buffer mapping, or ext4 file mutation fails.
pub(crate) fn write(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    write_regular_file(target)
}

/// Flushes cached or ordered file data.
/// # Errors
///
/// Returns an error when the flush target cannot be resolved to a mounted ext4 volume or the
/// lower storage flush fails.
pub(crate) fn flush(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    flush_volume(FlushVolume::decode(target)?)
}

/// Flushes one mounted volume during `IRP_MJ_SHUTDOWN`.
/// # Errors
///
/// Returns an error when shutdown was not addressed to a mounted ext4 volume or the lower storage
/// flush fails.
pub(crate) fn shutdown(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    flush_volume(FlushVolume::from_mounted_device(target.device())?)
}

/// Flushes the VCB selected by a flush or shutdown request.
/// # Errors
///
/// Returns an error when the mounted ext4 volume cannot persist its filesystem-device writes.
fn flush_volume(volume: FlushVolume) -> DriverResult<IrpCompletion> {
    let mut volume = volume.volume();
    let vcb = unsafe {
        // SAFETY: The decoded flush volume is owned by the mounted device or
        // an opened FILE_OBJECT context for the duration of this dispatch.
        volume.as_mut()
    };
    vcb.flush()?;
    Ok(IrpCompletion::EMPTY)
}

/// Executes file information queries.
/// # Errors
///
/// Returns an error when query stack decoding or information packing fails.
pub(crate) fn query(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    QueryFileRequest::decode(target).and_then(query_file_information)
}

/// Executes file information mutations.
/// # Errors
///
/// Returns an error when set stack decoding or the requested file mutation fails.
pub(crate) fn set(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    SetFileRequest::decode(target).and_then(set_file_information)
}

/// Transfers one queued directory-change IRP to the VCB's FsRtl notification list.
pub(crate) fn notify_change_directory(owned: OwnedIrp) -> wdk_sys::NTSTATUS {
    let target = owned.target();
    let registration = DirectoryNotificationRequest::decode(target).and_then(|mut request| {
        let registration = request.registration()?;
        let volume = request.opened_directory().volume();
        let vcb = unsafe {
            // SAFETY: OpenedDirectory was decoded from the live FILE_OBJECT
            // that owns this pending notification IRP.
            volume.as_ref()
        };
        Ok((vcb.directory_change_notifier(), registration))
    });
    match registration {
        Ok((notifier, registration)) => {
            owned.delegate_directory_notification(notifier, registration)
        }
        Err(error) => owned.complete_result(Err(error)),
    }
}

/// Directory notification selected from a valid notify-change IRP.
#[derive(Debug)]
pub(crate) struct DirectoryNotificationRequest {
    /// Opened directory whose FILE_OBJECT owns this notification.
    opened_directory: OpenedDirectory,
    /// Change kinds that may complete this request.
    completion_filter: DirectoryChangeFilter,
    /// Direct-child or descendant directory scope.
    watch_scope: DirectoryWatchScope,
}

impl DirectoryNotificationRequest {
    /// Decodes the active directory-change stack location.
    /// # Errors
    ///
    /// Returns an error when the stack is malformed or its FILE_OBJECT is not an opened directory.
    fn decode(target: DispatchTarget) -> DriverResult<Self> {
        let stack = target.current_stack()?.notify_directory()?;
        Ok(Self {
            opened_directory: OpenedDirectory::decode(stack.file_object())?,
            completion_filter: stack.completion_filter(),
            watch_scope: stack.watch_scope(),
        })
    }

    /// Returns the directory that owns this notification request.
    pub(crate) fn opened_directory(&self) -> &OpenedDirectory {
        &self.opened_directory
    }

    /// Converts this request into the exact FsRtl registration semantics this driver supports.
    /// # Errors
    ///
    /// Returns an error when recursive watching or non-name completion filters are requested.
    fn registration(&mut self) -> DriverResult<DirectoryNotificationRegistration> {
        if self.watch_scope.watches_subtree() {
            return Err(DriverError::NotSupported);
        }
        let full_directory_name = self.opened_directory.notification_directory_name()?;
        Ok(DirectoryNotificationRegistration::new(
            full_directory_name,
            self.opened_directory.notification_context(),
            self.completion_filter.namespace_name_filter()?,
        ))
    }
}

/// Executes byte-range lock requests.
/// # Errors
///
/// Returns an error when the lock stack is malformed or the target is not an opened regular file.
pub(crate) fn lock_control(target: DispatchTarget) -> DriverResult<OpenedRegularFile> {
    let file_object = target.current_stack()?.file_object()?;
    OpenedRegularFile::decode(file_object)
}

/// Decoded mounted volume selected by a flush IRP.
#[derive(Clone, Copy, Debug)]
struct FlushVolume {
    /// Mounted VCB whose backing device must be flushed.
    volume: NonNull<VolumeControlBlock>,
}

impl FlushVolume {
    /// Decodes a mounted volume device without consulting a FILE_OBJECT.
    /// # Errors
    ///
    /// Returns an error when `device` is not a mounted ext4 volume device.
    fn from_mounted_device(device: crate::state::KernelDevice) -> DriverResult<Self> {
        let volume = MountedVolumeDevice::vcb(device).ok_or(DriverError::InvalidDeviceRequest)?;
        Ok(Self { volume })
    }

    /// Decodes the mounted volume affected by a flush IRP.
    /// # Errors
    ///
    /// Returns an error when the current stack is absent, the opened FILE_OBJECT context is invalid,
    /// or a device-level flush is not directed at a mounted volume device.
    fn decode(target: DispatchTarget) -> DriverResult<Self> {
        let stack = target.current_stack()?;
        let volume = match stack.file_object() {
            Ok(file_object) => OpenedObject::decode(file_object)?.volume(),
            Err(DriverError::InvalidParameter) => {
                Self::from_mounted_device(target.device())?.volume
            }
            Err(error) => return Err(error),
        };
        Ok(Self { volume })
    }

    /// Returns the mounted VCB pointer selected by the flush request.
    const fn volume(self) -> NonNull<VolumeControlBlock> {
        self.volume
    }
}

/// Decoded query-file-information request.
#[derive(Debug)]
struct QueryFileRequest {
    /// Dispatch target receiving the query.
    target: DispatchTarget,
    /// Decoded query stack.
    stack: QueryFileStack,
    /// Opened file contexts decoded before handler execution.
    opened_file: OpenedObject,
}

impl QueryFileRequest {
    /// Decodes a query-file-information request.
    /// # Errors
    ///
    /// Returns an error when the current IRP stack is not a query-file stack or its FILE_OBJECT has
    /// no opened ext4 context.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.query_file()?;
        let opened_file = OpenedObject::decode(stack.file_object())?;
        Ok(Self {
            target,
            stack,
            opened_file,
        })
    }
}

/// Decoded set-file-information request.
#[derive(Debug)]
struct SetFileRequest {
    /// Dispatch target receiving the mutation.
    target: DispatchTarget,
    /// Decoded set stack.
    stack: SetFileStack,
    /// Opened file contexts decoded before handler execution.
    opened_file: OpenedObject,
}

impl SetFileRequest {
    /// Decodes a set-file-information request.
    /// # Errors
    ///
    /// Returns an error when the current IRP stack is not a set-file stack or its FILE_OBJECT has no
    /// opened ext4 context.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.set_file()?;
        let opened_file = OpenedObject::decode(stack.file_object())?;
        Ok(Self {
            target,
            stack,
            opened_file,
        })
    }
}

/// Decoded query-directory request.
#[derive(Debug)]
struct QueryDirectoryRequest {
    /// Dispatch target receiving the query.
    target: DispatchTarget,
    /// Decoded query-directory stack.
    stack: QueryDirectoryStack,
    /// Opened directory contexts decoded before handler execution.
    opened_file: OpenedDirectory,
}

impl QueryDirectoryRequest {
    /// Decodes a query-directory request.
    /// # Errors
    ///
    /// Returns an error when the current IRP stack is not a query-directory stack or the FILE_OBJECT
    /// is not an opened directory.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.query_directory()?;
        let opened_file = OpenedDirectory::decode(stack.file_object())?;
        Ok(Self {
            target,
            stack,
            opened_file,
        })
    }
}

/// Packs one supported file information class.
/// # Errors
///
/// Returns an error when metadata cannot be loaded, the output buffer is too small, or the requested
/// information class cannot be packed into its Windows layout.
fn query_file_information(request: QueryFileRequest) -> DriverResult<IrpCompletion> {
    let length = request.stack.length();
    let mut buffer = request.target.buffered_output(length)?;
    let output = buffer.as_mut_slice();
    match request.stack.information_class() {
        QueryFileInformationClass::Basic => {
            pack_basic_information(output, load_file_metadata(&request.opened_file)?)
        }
        QueryFileInformationClass::Standard => {
            pack_standard_information(output, load_file_metadata(&request.opened_file)?)
        }
        QueryFileInformationClass::Internal => {
            pack_internal_information(output, load_file_metadata(&request.opened_file)?)
        }
        QueryFileInformationClass::Position => {
            pack_position_information(output, &request.opened_file)
        }
        QueryFileInformationClass::NetworkOpen => {
            pack_network_open_information(output, load_file_metadata(&request.opened_file)?)
        }
        QueryFileInformationClass::Name => pack_name_information(output, &request.opened_file),
        QueryFileInformationClass::AttributeTag => {
            pack_attribute_tag_information(output, load_file_metadata(&request.opened_file)?)
        }
    }
}

/// Applies one supported set-file-information class.
/// # Errors
///
/// Returns an error when the selected set-information class has invalid input or its ext4 metadata
/// mutation cannot be committed.
fn set_file_information(request: SetFileRequest) -> DriverResult<IrpCompletion> {
    match request.stack.information_class() {
        SetFileInformationClass::Basic => set_basic_information(request),
        SetFileInformationClass::Position => set_position_information(request),
        SetFileInformationClass::EndOfFile => set_end_of_file_information(request),
        SetFileInformationClass::Allocation => set_allocation_information(request),
        SetFileInformationClass::Disposition => set_disposition_information(request),
        SetFileInformationClass::DispositionEx => set_disposition_information_ex(request),
        SetFileInformationClass::Rename => {
            set_rename_information(request, RenameInformationFormat::ReplaceIfExistsByte)
        }
        SetFileInformationClass::RenameEx => {
            set_rename_information(request, RenameInformationFormat::Flags)
        }
    }?;
    Ok(IrpCompletion::EMPTY)
}

/// Applies FILE_POSITION_INFORMATION to the synchronous FILE_OBJECT position.
/// # Errors
///
/// Returns an error when the input is truncated, negative, asynchronous, or misaligned for a
/// no-intermediate-buffering handle.
fn set_position_information(mut request: SetFileRequest) -> DriverResult<()> {
    let info = read_file_information_input::<wdk_sys::FILE_POSITION_INFORMATION>(
        request.target,
        request.stack.length(),
    )?;
    let position = file_offset_from_large_integer(info.CurrentByteOffset)?;
    request
        .opened_file
        .data_transfer_mode()
        .validate_position(position.bytes())?;
    request.opened_file.set_current_file_position(position)
}

/// Applies FILE_BASIC_INFORMATION timestamps and overlay attributes.
/// # Errors
///
/// Returns an error when the input structure is truncated, timestamps or attributes are invalid, or
/// the resulting ext4 metadata transaction fails.
fn set_basic_information(request: SetFileRequest) -> DriverResult<()> {
    let info = read_file_information_input::<wdk_sys::FILE_BASIC_INFORMATION>(
        request.target,
        request.stack.length(),
    )?;
    let metadata = load_file_metadata(&request.opened_file)?;
    let times = set_basic_times(metadata.times, info)?;
    let attributes = set_basic_attributes(metadata, info.FileAttributes)?;
    if times == metadata.times && attributes.is_empty() {
        return Ok(());
    }

    let context = opened_file_context(&request.opened_file);
    let mut vcb = context.volume;
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this synchronous metadata mutation.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let node = transaction.node(context.node)?;
    if times != metadata.times {
        transaction.set_times(node, times)?;
    }
    if let Some(security) = attributes.security() {
        transaction.set_posix_security(node, security)?;
    }
    if let Some(overlay) = attributes.overlay() {
        transaction.set_windows_overlay(node, overlay)?;
    }
    transaction.commit()?;
    Ok(())
}

/// Applies FILE_END_OF_FILE_INFORMATION to a regular file.
/// # Errors
///
/// Returns an error when the input is truncated, the handle is not a regular file, the size is
/// negative, or the file resize transaction fails.
fn set_end_of_file_information(request: SetFileRequest) -> DriverResult<()> {
    let info = read_file_information_input::<wdk_sys::FILE_END_OF_FILE_INFORMATION>(
        request.target,
        request.stack.length(),
    )?;
    let opened_file = OpenedRegularFile::decode(request.stack.file_object())?;
    set_regular_file_size(&opened_file, file_size_from_large_integer(info.EndOfFile)?)
}

/// Applies FILE_ALLOCATION_INFORMATION within the ext4 sparse-file model.
/// # Errors
///
/// Returns an error when the input is truncated, the handle is not a regular file, the requested
/// allocation size is negative, or shrinking to that size fails.
fn set_allocation_information(request: SetFileRequest) -> DriverResult<()> {
    let info = read_file_information_input::<wdk_sys::FILE_ALLOCATION_INFORMATION>(
        request.target,
        request.stack.length(),
    )?;
    let requested = file_size_from_large_integer(info.AllocationSize)?;
    let opened_file = OpenedRegularFile::decode(request.stack.file_object())?;
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open.
        opened_file.volume().as_ref()
    };
    let current = regular_file_size(vcb, opened_file.id())?;
    if requested >= current {
        return Ok(());
    }
    set_regular_file_size(&opened_file, requested)
}

/// Rejects FILE_DISPOSITION_INFORMATION deletion until identity-checked orphan lifecycle exists.
/// # Errors
///
/// Returns an error when the input is truncated or requests deletion.
fn set_disposition_information(request: SetFileRequest) -> DriverResult<()> {
    let info = read_file_information_input::<wdk_sys::FILE_DISPOSITION_INFORMATION>(
        request.target,
        request.stack.length(),
    )?;
    validate_disposition_delete_flag(info.DeleteFile)
}

/// Validates legacy disposition deletion while orphan lifecycle is unavailable.
/// # Errors
///
/// Returns not supported when deletion is requested.
fn validate_disposition_delete_flag(delete_file: wdk_sys::BOOLEAN) -> DriverResult<()> {
    if delete_file == 0 {
        Ok(())
    } else {
        Err(DriverError::NotSupported)
    }
}

/// Rejects FILE_DISPOSITION_INFORMATION_EX deletion until safe orphan lifecycle exists.
/// # Errors
///
/// Returns an error when the extended disposition input is truncated or carries unsupported flags.
fn set_disposition_information_ex(request: SetFileRequest) -> DriverResult<()> {
    let info = read_file_information_input::<wdk_sys::FILE_DISPOSITION_INFORMATION_EX>(
        request.target,
        request.stack.length(),
    )?;
    validate_disposition_ex_flags(info.Flags)
}

/// Validates FILE_DISPOSITION_INFORMATION_EX while deletion is unsupported.
/// # Errors
///
/// Returns not supported for every non-empty disposition request.
fn validate_disposition_ex_flags(flags: wdk_sys::ULONG) -> DriverResult<()> {
    if flags == 0 {
        Ok(())
    } else {
        Err(DriverError::NotSupported)
    }
}

/// Applies FILE_RENAME_INFORMATION to the opened directory-entry location.
/// # Errors
///
/// Returns an error when the rename buffer is malformed, the opened location cannot be renamed,
/// the target parent cannot be resolved, or the ext4 rename transaction fails.
fn set_rename_information(
    mut request: SetFileRequest,
    format: RenameInformationFormat,
) -> DriverResult<()> {
    let rename = RenameTargetPath::parse(request.target, request.stack.length(), format)?;

    let (source_parent, source_name) = match request.opened_file.location() {
        OpenedLocation::DirectoryEntry { parent, name } => (*parent, name.try_to_owned_name()?),
        OpenedLocation::Root => return Err(DriverError::from(ext4_core::Error::CannotRemoveRoot)),
        OpenedLocation::FileReference => return Err(DriverError::NotSupported),
    };

    let mut vcb = request.opened_file.volume();
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this rename request.
        vcb.as_mut()
    };
    let (target_parent, target_name) = resolve_rename_target(vcb, &rename)?;
    let notifications = RenameDirectoryNameChanges::prepare(
        vcb,
        source_parent,
        &source_name,
        request.opened_file.node(),
        target_parent,
        &target_name,
        &rename,
    )?;
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let source_parent = transaction.directory(source_parent)?;
    let target_parent = transaction.directory(target_parent)?;
    transaction.rename_child(
        source_parent,
        &source_name,
        target_parent,
        &target_name,
        rename.target_collision(),
    )?;
    transaction.commit()?;
    if let Some(notifications) = notifications {
        request
            .opened_file
            .replace_location(OpenedLocation::DirectoryEntry {
                parent: target_parent.id(),
                name: target_name,
            });
        notifications.report(vcb);
    }
    Ok(())
}

/// Committed directory-name changes caused by one non-no-op rename operation.
#[derive(Clone, Copy, Debug)]
struct RenameDirectoryNameChanges {
    /// Existing target entry removed by a replace-capable rename.
    replaced_target: Option<DirectoryNameChange>,
    /// Source entry under its former name.
    old_source_name: DirectoryNameChange,
    /// Source entry under its new name.
    new_source_name: DirectoryNameChange,
}

impl RenameDirectoryNameChanges {
    /// Prepares the exact name-change events that a successful rename will publish.
    /// # Errors
    ///
    /// Returns an error when a replace-capable target cannot be read or a visible child name
    /// cannot be represented in the Windows notification namespace.
    fn prepare(
        vcb: &VolumeControlBlock,
        source_parent: DirectoryNodeId,
        source_name: &Ext4Name,
        source_node: NodeId,
        target_parent: DirectoryNodeId,
        target_name: &Ext4Name,
        target: &RenameTargetPath,
    ) -> DriverResult<Option<Self>> {
        if source_parent == target_parent && source_name == target_name {
            return Ok(None);
        }

        let replaced_target = match target.target_collision() {
            RenameTargetCollision::Reject => None,
            RenameTargetCollision::Replace => {
                let parent = vcb.volume().load_directory(target_parent)?;
                match vcb
                    .volume()
                    .lookup_windows_child(&parent, target.target_name())?
                {
                    ChildLookup::Found(child) if *child.node() == source_node => return Ok(None),
                    ChildLookup::Found(child) => Some(DirectoryNameChange::new(
                        target_parent,
                        child.name(),
                        *child.node(),
                        DirectoryNameChangeAction::Removed,
                    )?),
                    ChildLookup::NotFound => None,
                }
            }
        };

        Ok(Some(Self {
            replaced_target,
            old_source_name: DirectoryNameChange::new(
                source_parent,
                source_name,
                source_node,
                DirectoryNameChangeAction::RenamedOldName,
            )?,
            new_source_name: DirectoryNameChange::new(
                target_parent,
                target_name,
                source_node,
                DirectoryNameChangeAction::RenamedNewName,
            )?,
        }))
    }

    /// Reports every name transition after the corresponding ext4 transaction commits.
    fn report(self, vcb: &VolumeControlBlock) {
        if let Some(replaced_target) = self.replaced_target {
            vcb.report_directory_name_change(replaced_target);
        }
        vcb.report_directory_name_change(self.old_source_name);
        vcb.report_directory_name_change(self.new_source_name);
    }
}

/// Sets a regular file size by extending sparse or truncating allocated ranges.
/// # Errors
///
/// Returns an error when the current file size cannot be loaded or the ext4 resize transaction
/// fails.
fn set_regular_file_size(opened_file: &OpenedRegularFile, new_size: FileSize) -> DriverResult<()> {
    let file_id = opened_file.id();
    let mut vcb = opened_file.volume();
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this synchronous size mutation.
        vcb.as_mut()
    };
    let current = regular_file_size(vcb, file_id)?;
    if new_size == current {
        return Ok(());
    }

    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let file = transaction.file(file_id)?;
    if new_size > current {
        transaction.extend_file(file, new_size)?;
    } else {
        transaction.truncate_file(file, new_size)?;
    }
    transaction.commit()?;
    Ok(())
}

/// Packs directory entries into the caller's query-directory buffer.
/// # Errors
///
/// Returns an error when the directory query stack, pattern, output buffer, opened directory, or
/// emitted directory record layout is invalid.
pub(crate) fn query_directory(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    let mut request = QueryDirectoryRequest::decode(target)?;
    let class = request.stack.information_class();
    let pattern = DirectoryPattern::from_stack(request.stack)?;
    let length = request.stack.length();
    let mut buffer = request.target.data_output(length)?;
    let buffer = buffer.as_mut_slice();

    let volume = request.opened_file.volume();
    let vcb = unsafe {
        // SAFETY: OpenedDirectory is decoded from a live FCB whose VCB
        // pointer remains valid for the opened FILE_OBJECT lifetime.
        volume.as_ref()
    };
    let directory_id = request.opened_file.id();
    let directory = vcb.volume().load_directory(directory_id)?;
    let entries = vcb.volume().read_directory(&directory)?;

    let cursor = request.opened_file.cursor_mut();
    initialize_directory_cursor(cursor, request.stack);

    let result = emit_directory_entries(
        vcb,
        cursor,
        request.stack,
        class,
        &pattern,
        &entries,
        buffer,
    )?;
    IrpCompletion::from_usize(result)
}

impl DirectoryInformationClass {
    /// Returns the byte offset where the UTF-16 file name starts.
    const fn name_offset(self) -> usize {
        match self {
            Self::Directory => DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::Full => FULL_DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::Both => BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::Names => NAMES_INFORMATION_NAME_OFFSET,
        }
    }
}

/// Caller-supplied directory filename pattern.
#[derive(Debug, Eq, PartialEq)]
enum DirectoryPattern {
    /// Enumerate every Windows-representable ext4 entry.
    All,
    /// Return the entry with this exact Windows name.
    Exact(WindowsName),
    /// Return entries matched by a caller-supplied wildcard expression.
    Wildcard(DirectoryWildcardPattern),
}

impl DirectoryPattern {
    /// Decodes the optional QueryDirectory filename pattern.
    /// # Errors
    ///
    /// Returns an error when the pattern UNICODE_STRING is malformed, contains unsupported
    /// wildcards, or is not a valid Windows name.
    fn from_stack(stack: QueryDirectoryStack) -> DriverResult<Self> {
        let DirectoryPatternInput::Name(name) = stack.pattern() else {
            return Ok(Self::All);
        };
        let name = unsafe {
            // SAFETY: QueryDirectoryStack stores the non-null UNICODE_STRING
            // pointer supplied by the active IRP stack.
            name.as_ref()
        };
        let units = unicode_string_units(name)?;
        if is_all_directory_pattern(units) {
            return Ok(Self::All);
        }
        if units
            .iter()
            .any(|unit| matches!(*unit, UTF16_ASTERISK | UTF16_QUESTION_MARK))
        {
            return DirectoryWildcardPattern::from_utf16(units).map(Self::Wildcard);
        }
        WindowsName::from_utf16(units)
            .map(Self::Exact)
            .map_err(DriverError::from)
    }

    /// Returns true when the projected Windows name matches this pattern.
    fn matches(&self, name: &WindowsName) -> bool {
        match self {
            Self::All => true,
            Self::Exact(requested) => name.equals(requested),
            Self::Wildcard(pattern) => pattern.matches(name),
        }
    }

    /// Returns the no-entry status for this pattern.
    const fn exhausted_error(&self) -> DriverError {
        match self {
            Self::All => DriverError::NoMoreFiles,
            Self::Exact(_) | Self::Wildcard(_) => DriverError::NoSuchFile,
        }
    }
}

/// Caller-supplied wildcard pattern for Windows-visible long names.
#[derive(Debug, Eq, PartialEq)]
struct DirectoryWildcardPattern {
    /// Parsed pattern tokens.
    tokens: DriverVec<DirectoryWildcardToken>,
}

impl DirectoryWildcardPattern {
    /// Decodes a wildcard pattern for directory enumeration.
    /// # Errors
    ///
    /// Returns an error when the pattern contains a non-wildcard character outside the Windows name
    /// component domain or malformed UTF-16.
    fn from_utf16(units: &[u16]) -> DriverResult<Self> {
        validate_directory_pattern_units(units)?;
        let mut tokens = DriverVec::new();
        for unit in units {
            let token = match *unit {
                UTF16_ASTERISK => DirectoryWildcardToken::AnySequence,
                UTF16_QUESTION_MARK => DirectoryWildcardToken::AnyOne,
                unit => DirectoryWildcardToken::Literal(unit),
            };
            tokens
                .try_push_owned(token)
                .map_err(|error| error.into_parts().0)?;
        }
        Ok(Self { tokens })
    }

    /// Returns true when this pattern matches a Windows-visible long name.
    fn matches(&self, name: &WindowsName) -> bool {
        wildcard_tokens_match(self.tokens.as_slice(), name.utf16())
    }
}

/// One token in a directory wildcard expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryWildcardToken {
    /// Exact UTF-16 code unit match.
    Literal(u16),
    /// Match exactly one UTF-16 code unit.
    AnyOne,
    /// Match zero or more UTF-16 code units.
    AnySequence,
}

/// Validates wildcard pattern units while keeping wildcard syntax out of `WindowsName`.
/// # Errors
///
/// Returns an error when a non-wildcard unit is not valid inside a Windows component or the pattern
/// is malformed UTF-16.
fn validate_directory_pattern_units(units: &[u16]) -> DriverResult<()> {
    if units.iter().any(|unit| {
        matches!(
            *unit,
            0x0000 | 0x0022 | 0x002F | 0x003A | 0x003C | 0x003E | 0x005C | 0x007C
        )
    }) {
        return Err(DriverError::from(ext4_core::Error::InvalidName));
    }
    if core::char::decode_utf16(units.iter().copied()).any(|item| item.is_err()) {
        return Err(DriverError::from(ext4_core::Error::InvalidName));
    }
    Ok(())
}

/// Matches `*` and `?` wildcard tokens against UTF-16 name units.
fn wildcard_tokens_match(pattern: &[DirectoryWildcardToken], name: &[u16]) -> bool {
    let mut pattern_index = 0_usize;
    let mut name_index = 0_usize;
    let mut sequence_restart = None;

    while name_index < name.len() {
        if let Some(token) = pattern.get(pattern_index) {
            match token {
                DirectoryWildcardToken::Literal(unit)
                    if name.get(name_index).copied() == Some(*unit) =>
                {
                    let Some(next_pattern) = pattern_index.checked_add(1) else {
                        return false;
                    };
                    let Some(next_name) = name_index.checked_add(1) else {
                        return false;
                    };
                    pattern_index = next_pattern;
                    name_index = next_name;
                    continue;
                }
                DirectoryWildcardToken::AnyOne => {
                    let Some(next_pattern) = pattern_index.checked_add(1) else {
                        return false;
                    };
                    let Some(next_name) = name_index.checked_add(1) else {
                        return false;
                    };
                    pattern_index = next_pattern;
                    name_index = next_name;
                    continue;
                }
                DirectoryWildcardToken::AnySequence => {
                    let Some(next_pattern) = pattern_index.checked_add(1) else {
                        return false;
                    };
                    sequence_restart = Some((pattern_index, name_index));
                    pattern_index = next_pattern;
                    continue;
                }
                DirectoryWildcardToken::Literal(_) => {}
            }
        }

        let Some((sequence_index, restart_name)) = sequence_restart else {
            return false;
        };
        let Some(next_restart_name) = restart_name.checked_add(1) else {
            return false;
        };
        let Some(next_pattern) = sequence_index.checked_add(1) else {
            return false;
        };
        sequence_restart = Some((sequence_index, next_restart_name));
        pattern_index = next_pattern;
        name_index = next_restart_name;
    }

    while matches!(
        pattern.get(pattern_index),
        Some(DirectoryWildcardToken::AnySequence)
    ) {
        let Some(next_pattern) = pattern_index.checked_add(1) else {
            return false;
        };
        pattern_index = next_pattern;
    }

    pattern_index == pattern.len()
}

/// Variable directory record layout for one emitted entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryRecordLayout {
    /// Byte offset where the file name starts.
    name_offset: usize,
    /// Byte count occupied by required fields and file-name bytes.
    unpadded_size: usize,
    /// Byte count rounded to the next Windows directory-entry alignment.
    padded_size: usize,
}

impl DirectoryRecordLayout {
    /// Computes the class-specific layout for the supplied Windows name.
    /// # Errors
    ///
    /// Returns an error when the UTF-16 file-name byte length or padded record size overflows.
    fn new(class: DirectoryInformationClass, name: &WindowsName) -> DriverResult<Self> {
        let name_offset = class.name_offset();
        let name_bytes = utf16_byte_len(name.utf16())?;
        let unpadded_size = name_offset
            .checked_add(name_bytes)
            .ok_or(DriverError::InvalidParameter)?;
        Ok(Self {
            name_offset,
            unpadded_size,
            padded_size: align_to_eight(unpadded_size)?,
        })
    }
}

/// Bytes before FileName in FILE_DIRECTORY_INFORMATION.
const DIRECTORY_INFORMATION_NAME_OFFSET: usize = 64;
/// Bytes before FileName in FILE_FULL_DIR_INFORMATION.
const FULL_DIRECTORY_INFORMATION_NAME_OFFSET: usize = 68;
/// Bytes before FileName in FILE_BOTH_DIR_INFORMATION.
const BOTH_DIRECTORY_INFORMATION_NAME_OFFSET: usize = 94;
/// Bytes before FileName in FILE_NAMES_INFORMATION.
const NAMES_INFORMATION_NAME_OFFSET: usize = 12;
/// Offset of the common NextEntryOffset field.
const DIRECTORY_NEXT_ENTRY_OFFSET: usize = 0;
/// Offset of the common FileIndex field.
const DIRECTORY_FILE_INDEX_OFFSET: usize = 4;
/// Offset of the common CreationTime field.
const DIRECTORY_CREATION_TIME_OFFSET: usize = 8;
/// Offset of the common LastAccessTime field.
const DIRECTORY_LAST_ACCESS_TIME_OFFSET: usize = 16;
/// Offset of the common LastWriteTime field.
const DIRECTORY_LAST_WRITE_TIME_OFFSET: usize = 24;
/// Offset of the common ChangeTime field.
const DIRECTORY_CHANGE_TIME_OFFSET: usize = 32;
/// Offset of the common EndOfFile field.
const DIRECTORY_END_OF_FILE_OFFSET: usize = 40;
/// Offset of the common AllocationSize field.
const DIRECTORY_ALLOCATION_SIZE_OFFSET: usize = 48;
/// Offset of the common FileAttributes field.
const DIRECTORY_FILE_ATTRIBUTES_OFFSET: usize = 56;
/// Offset of the common FileNameLength field.
const DIRECTORY_FILE_NAME_LENGTH_OFFSET: usize = 60;
/// Offset of FileNameLength in FILE_NAMES_INFORMATION.
const NAMES_INFORMATION_FILE_NAME_LENGTH_OFFSET: usize = 8;
/// Offset of EaSize in FILE_FULL_DIR_INFORMATION and FILE_BOTH_DIR_INFORMATION.
const DIRECTORY_EA_SIZE_OFFSET: usize = 64;
/// Offset of ShortNameLength in FILE_BOTH_DIR_INFORMATION.
const BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET: usize = 68;
/// Windows directory query entry alignment.
const DIRECTORY_ENTRY_ALIGNMENT: usize = 8;
/// UTF-16 `*`.
const UTF16_ASTERISK: u16 = 0x002A;
/// UTF-16 `.`.
const UTF16_DOT: u16 = 0x002E;
/// UTF-16 `?`.
const UTF16_QUESTION_MARK: u16 = 0x003F;

/// Returns the UTF-16 units described by a WDK UNICODE_STRING.
/// # Errors
///
/// Returns an error when the UNICODE_STRING has an odd byte length or a null buffer with nonzero
/// length.
fn unicode_string_units(name: &wdk_sys::UNICODE_STRING) -> DriverResult<&[u16]> {
    if name.Length & 1 != 0 {
        return Err(DriverError::InvalidParameter);
    }
    if name.Length == 0 {
        return Ok(&[]);
    }
    let Some(buffer) = NonNull::new(name.Buffer) else {
        return Err(DriverError::InvalidParameter);
    };
    let units = usize::from(name.Length)
        .checked_div(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)?;
    Ok(unsafe {
        // SAFETY: The caller supplied a non-null UNICODE_STRING buffer with an
        // even byte length for the active IRP stack. The resulting slice is
        // read only and does not outlive this dispatch callback.
        core::slice::from_raw_parts(buffer.as_ptr(), units)
    })
}

/// Returns true for the all-entries patterns accepted without wildcard matching.
fn is_all_directory_pattern(units: &[u16]) -> bool {
    units.is_empty()
        || units == [UTF16_ASTERISK]
        || units == [UTF16_ASTERISK, UTF16_DOT, UTF16_ASTERISK]
}

/// Applies QueryDirectory cursor reset/index flags.
fn initialize_directory_cursor(cursor: &mut DirectoryCursor, stack: QueryDirectoryStack) {
    match stack.cursor_position() {
        DirectoryCursorPosition::Current => {}
        DirectoryCursorPosition::Restart => cursor.seek(DirectoryEntryIndex::from_u32(0)),
        DirectoryCursorPosition::Index(index) => cursor.seek(index),
    }
}

/// Emits directory entries into a caller buffer.
/// # Errors
///
/// Returns an error when cursor arithmetic overflows, a matching entry cannot fit in an empty
/// output buffer, metadata loading fails, or a directory record cannot be packed.
fn emit_directory_entries(
    vcb: &VolumeControlBlock,
    cursor: &mut DirectoryCursor,
    stack: QueryDirectoryStack,
    class: DirectoryInformationClass,
    pattern: &DirectoryPattern,
    entries: &[DirectoryEntry],
    buffer: &mut [u8],
) -> DriverResult<usize> {
    let start =
        usize::try_from(cursor.next_entry().as_u32()).map_err(|_| DriverError::InvalidParameter)?;
    let mut emitted = 0_usize;
    let mut written = 0_usize;
    let mut information = 0_usize;
    let mut previous_start = None;

    for (raw_index, entry) in entries.iter().enumerate().skip(start) {
        let entry_index = u32::try_from(raw_index).map_err(|_| DriverError::InvalidParameter)?;
        let next_entry = entry_index
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;
        let Ok(name) = WindowsName::from_ext4(entry.name()) else {
            cursor.seek(DirectoryEntryIndex::from_u32(next_entry));
            continue;
        };
        if !pattern.matches(&name) {
            cursor.seek(DirectoryEntryIndex::from_u32(next_entry));
            continue;
        }

        let metadata = metadata_from_node(vcb, *entry.node())?;
        let layout = DirectoryRecordLayout::new(class, &name)?;
        let required = written
            .checked_add(layout.unpadded_size)
            .ok_or(DriverError::InvalidParameter)?;
        if required > buffer.len() {
            if emitted == 0 {
                return Err(DriverError::BufferOverflow);
            }
            break;
        }

        if let Some(previous_start) = previous_start {
            let next_offset = written
                .checked_sub(previous_start)
                .ok_or(DriverError::InvalidParameter)?;
            LittleEndianOutput::new(buffer).write_u32(
                record_field_offset(previous_start, DIRECTORY_NEXT_ENTRY_OFFSET)?,
                u32::try_from(next_offset).map_err(|_| DriverError::InvalidParameter)?,
            )?;
        }

        pack_directory_record(buffer, written, class, entry_index, &name, metadata, layout)?;
        previous_start = Some(written);
        information = required;
        emitted = emitted
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;
        written = written
            .checked_add(layout.padded_size)
            .ok_or(DriverError::InvalidParameter)?;
        cursor.seek(DirectoryEntryIndex::from_u32(next_entry));

        if matches!(stack.entry_emission(), DirectoryEntryEmission::Single) {
            break;
        }
    }

    if emitted == 0 {
        Err(pattern.exhausted_error())
    } else {
        Ok(information)
    }
}

/// Packs one variable-length directory information record.
/// # Errors
///
/// Returns an error when any fixed field or UTF-16 name range falls outside the output buffer.
fn pack_directory_record(
    buffer: &mut [u8],
    start: usize,
    class: DirectoryInformationClass,
    file_index: u32,
    name: &WindowsName,
    metadata: FileMetadata,
    layout: DirectoryRecordLayout,
) -> DriverResult<()> {
    clear_record(buffer, start, layout.unpadded_size)?;
    LittleEndianOutput::new(buffer)
        .write_u32(record_field_offset(start, DIRECTORY_NEXT_ENTRY_OFFSET)?, 0)?;
    LittleEndianOutput::new(buffer).write_u32(
        record_field_offset(start, DIRECTORY_FILE_INDEX_OFFSET)?,
        file_index,
    )?;
    if matches!(class, DirectoryInformationClass::Names) {
        LittleEndianOutput::new(buffer).write_u32(
            record_field_offset(start, NAMES_INFORMATION_FILE_NAME_LENGTH_OFFSET)?,
            u32::try_from(utf16_byte_len(name.utf16())?)
                .map_err(|_| DriverError::InvalidParameter)?,
        )?;
        return write_utf16(
            buffer,
            field_offset(start, layout.name_offset)?,
            name.utf16(),
        );
    }
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_CREATION_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.created()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_LAST_ACCESS_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.accessed()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_LAST_WRITE_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.modified()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_CHANGE_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.changed()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_END_OF_FILE_OFFSET)?,
        &signed_i64(metadata.size.bytes())?.to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_ALLOCATION_SIZE_OFFSET)?,
        &signed_i64(allocation_size(metadata)?)?.to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_u32(
        record_field_offset(start, DIRECTORY_FILE_ATTRIBUTES_OFFSET)?,
        file_attributes(metadata),
    )?;
    LittleEndianOutput::new(buffer).write_u32(
        record_field_offset(start, DIRECTORY_FILE_NAME_LENGTH_OFFSET)?,
        u32::try_from(utf16_byte_len(name.utf16())?).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    match class {
        DirectoryInformationClass::Directory | DirectoryInformationClass::Names => {}
        DirectoryInformationClass::Full => {
            LittleEndianOutput::new(buffer)
                .write_u32(record_field_offset(start, DIRECTORY_EA_SIZE_OFFSET)?, 0)?;
        }
        DirectoryInformationClass::Both => {
            LittleEndianOutput::new(buffer)
                .write_u32(record_field_offset(start, DIRECTORY_EA_SIZE_OFFSET)?, 0)?;
            LittleEndianOutput::new(buffer).write_u8(
                record_field_offset(start, BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET)?,
                0,
            )?;
        }
    }
    write_utf16(
        buffer,
        field_offset(start, layout.name_offset)?,
        name.utf16(),
    )
}

/// Clears a record before individual fields are written.
/// # Errors
///
/// Returns an error when the target record range falls outside `buffer`.
fn clear_record(buffer: &mut [u8], start: usize, length: usize) -> DriverResult<()> {
    let record = mutable_bytes(buffer, start, length)?;
    record.fill(0);
    Ok(())
}

/// Writes UTF-16 code units as Windows little-endian bytes.
/// # Errors
///
/// Returns an error when the UTF-16 output range overflows or extends beyond `buffer`.
fn write_utf16(buffer: &mut [u8], offset: usize, units: &[u16]) -> DriverResult<()> {
    let mut cursor = offset;
    for unit in units {
        LittleEndianOutput::new(buffer).write_u16(wire_offset(cursor), *unit)?;
        cursor = cursor.checked_add(2).ok_or(DriverError::InvalidParameter)?;
    }
    Ok(())
}

/// Returns a checked mutable byte range.
/// # Errors
///
/// Returns an error when `offset..offset + length` overflows or is outside `buffer`.
fn mutable_bytes(buffer: &mut [u8], offset: usize, length: usize) -> DriverResult<&mut [u8]> {
    wire_range(offset, length)?
        .write_to(buffer)
        .map_err(|_| DriverError::BufferOverflow)
}

/// Builds a wire offset after the caller has checked domain arithmetic.
const fn wire_offset(offset: usize) -> WireOffset {
    WireOffset::new(offset)
}

/// Builds a checked wire byte range from raw FILE_INFORMATION_CLASS fields.
/// # Errors
///
/// Returns an error when a file-information `offset + length` cannot be represented as a wire
/// range.
fn wire_range(offset: usize, length: usize) -> DriverResult<WireRange> {
    WireRange::new(wire_offset(offset), WireByteLen::new(length))
}

/// Computes an absolute field offset from a record start.
/// # Errors
///
/// Returns an error when the raw directory-record `start + offset` overflows.
fn field_offset(start: usize, offset: usize) -> DriverResult<usize> {
    start
        .checked_add(offset)
        .ok_or(DriverError::InvalidParameter)
}

/// Computes an absolute directory record field offset for wire output.
/// # Errors
///
/// Returns an error when the directory-record field offset cannot be represented as a wire offset.
fn record_field_offset(start: usize, offset: usize) -> DriverResult<WireOffset> {
    field_offset(start, offset).map(wire_offset)
}

/// Returns the byte count for UTF-16 code units.
/// # Errors
///
/// Returns an error when a file-information UTF-16 code-unit count cannot be doubled without
/// overflow.
fn utf16_byte_len(units: &[u16]) -> DriverResult<usize> {
    units
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)
}

/// Aligns a directory record size to an eight-byte boundary.
/// # Errors
///
/// Returns an error when the padding addition or aligned-size multiplication overflows.
fn align_to_eight(value: usize) -> DriverResult<usize> {
    let adjustment = DIRECTORY_ENTRY_ALIGNMENT
        .checked_sub(1)
        .ok_or(DriverError::InvalidParameter)?;
    let adjusted = value
        .checked_add(adjustment)
        .ok_or(DriverError::InvalidParameter)?;
    let units = adjusted
        .checked_div(DIRECTORY_ENTRY_ALIGNMENT)
        .ok_or(DriverError::InvalidParameter)?;
    units
        .checked_mul(DIRECTORY_ENTRY_ALIGNMENT)
        .ok_or(DriverError::InvalidParameter)
}

/// Converts an unsigned byte count to a signed Windows large-integer payload.
/// # Errors
///
/// Returns an error when a file-information byte count exceeds the signed LARGE_INTEGER range.
fn signed_i64(value: u64) -> DriverResult<i64> {
    i64::try_from(value).map_err(|_| DriverError::InvalidParameter)
}

/// Converts an ext4 timestamp to a Windows time QuadPart.
fn windows_time_quad(timestamp: Ext4Timestamp) -> i64 {
    let time = windows_time(timestamp);
    unsafe {
        // SAFETY: `QuadPart` is the active LARGE_INTEGER representation used
        // by this driver for Windows time values.
        time.QuadPart
    }
}

/// Releases resources owned by one FILE_OBJECT handle lifecycle.
/// # Errors
///
/// Returns an error when the FILE_OBJECT has no opened context.
fn cleanup_file_object(target: DispatchTarget, file_object: KernelFileObject) -> DriverResult<()> {
    let opened_file = OpenedObject::decode(file_object)?;
    let cleanup_was_published = file_object.cleanup_complete();
    match (opened_file.begin_cleanup(), cleanup_was_published) {
        (CleanupStart::First, false) => {}
        (CleanupStart::AlreadyComplete, true) => return Ok(()),
        (CleanupStart::First, true) | (CleanupStart::AlreadyComplete, false) => {
            crate::kernel::fatal::KernelWideInconsistency::file_object_lifecycle_corruption()
                .bugcheck();
        }
    }
    cleanup_directory_notification(&opened_file);
    opened_file
        .file_control_block()
        .release_handle_byte_range_locks(target, file_object);
    opened_file.release_share_access_for_cleanup();
    opened_file.finish_cleanup();
    file_object.mark_cleanup_complete();
    Ok(())
}

/// Releases FsRtl notification records owned by a FILE_OBJECT during its cleanup transition.
fn cleanup_directory_notification(opened_file: &OpenedObject) {
    let volume = opened_file.volume();
    let vcb = unsafe {
        // SAFETY: The opened FILE_OBJECT keeps its FCB and mounted VCB alive
        // throughout cleanup, before the CCB context is released at close.
        volume.as_ref()
    };
    vcb.directory_change_notifier()
        .cleanup(opened_file.notification_context());
}

/// Open file state needed for journaled metadata mutations.
#[derive(Clone, Copy, Debug)]
struct OpenedFileContext {
    /// Mounted VCB owning the open file.
    volume: NonNull<VolumeControlBlock>,
    /// ext4 node opened by this FILE_OBJECT.
    node: NodeId,
}

/// Returns the opened FCB identity and VCB pointer.
fn opened_file_context(opened_file: &OpenedObject) -> OpenedFileContext {
    OpenedFileContext {
        volume: opened_file.volume(),
        node: opened_file.node(),
    }
}

/// Reads a fixed-size set-information input structure.
/// # Errors
///
/// Returns an error when the buffered input is smaller than `T`.
fn read_file_information_input<T: Copy>(
    target: DispatchTarget,
    length: IrpBufferLength,
) -> DriverResult<T> {
    target.buffered_input(length)?.read_unaligned()
}

/// Decoded FILE_RENAME_INFORMATION target path.
#[derive(Debug, Eq, PartialEq)]
struct RenameTargetPath {
    /// Root-relative target path.
    path: NonEmptyWindowsPath,
    /// Target collision behavior requested by the Windows rename input.
    target_collision: RenameTargetCollision,
}

impl RenameTargetPath {
    /// Decodes a FILE_RENAME_INFORMATION variable-length input buffer.
    /// # Errors
    ///
    /// Returns an error when the rename input buffer is truncated, uses unsupported flags or root
    /// handles, has an invalid name length, or encodes an invalid target path.
    fn parse(
        target: DispatchTarget,
        length: IrpBufferLength,
        format: RenameInformationFormat,
    ) -> DriverResult<Self> {
        let input = target.buffered_input(length)?;
        let bytes = input.as_slice();
        let target_collision = format.target_collision(bytes)?;
        reject_root_directory(bytes)?;
        let name_length = usize::try_from(
            LittleEndianInput::new(bytes).read_u32(wire_offset(FILE_RENAME_NAME_LENGTH_OFFSET))?,
        )
        .map_err(|_| DriverError::InvalidParameter)?;
        if name_length == 0 || name_length & 1 != 0 {
            return Err(DriverError::InvalidParameter);
        }
        let name_bytes = input_range(bytes, FILE_RENAME_NAME_OFFSET, name_length)?;
        let units = utf16_units_from_le_bytes(name_bytes)?;
        Ok(Self {
            path: NonEmptyWindowsPath::from_utf16_path(units.as_slice())?,
            target_collision,
        })
    }

    /// Returns parent components before the target name.
    fn parents(&self) -> &[WindowsName] {
        self.path.parents()
    }

    /// Returns the final target name.
    fn target_name(&self) -> &WindowsName {
        self.path.target_name()
    }

    /// Returns the collision behavior selected at the Windows boundary.
    const fn target_collision(&self) -> RenameTargetCollision {
        self.target_collision
    }
}

/// FILE_RENAME_INFORMATION union arm selected by the information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenameInformationFormat {
    /// `FileRenameInformation` exposes a BOOLEAN ReplaceIfExists field.
    ReplaceIfExistsByte,
    /// `FileRenameInformationEx` exposes a ULONG Flags field.
    Flags,
}

impl RenameInformationFormat {
    /// Decodes target-collision semantics from the selected rename input format.
    /// # Errors
    ///
    /// Returns an error when unsupported rename-ex flags are set.
    fn target_collision(self, bytes: &[u8]) -> DriverResult<RenameTargetCollision> {
        match self {
            Self::ReplaceIfExistsByte => match bytes
                .get(FILE_RENAME_REPLACE_IF_EXISTS_OFFSET)
                .ok_or(DriverError::BufferTooSmall)?
            {
                0 => Ok(RenameTargetCollision::Reject),
                _ => Ok(RenameTargetCollision::Replace),
            },
            Self::Flags => {
                let flags = LittleEndianInput::new(bytes)
                    .read_u32(wire_offset(FILE_RENAME_FLAGS_OFFSET))?;
                if flags & !SUPPORTED_RENAME_EX_FLAGS != 0 {
                    return Err(DriverError::NotSupported);
                }
                if flags & wdk_sys::FILE_RENAME_REPLACE_IF_EXISTS != 0 {
                    Ok(RenameTargetCollision::Replace)
                } else {
                    Ok(RenameTargetCollision::Reject)
                }
            }
        }
    }
}

/// Non-empty root-relative Windows path.
#[derive(Debug, Eq, PartialEq)]
struct NonEmptyWindowsPath {
    /// Parent path components from root to target parent.
    parents: DriverVec<WindowsName>,
    /// Final path component being renamed to.
    target_name: WindowsName,
}

impl NonEmptyWindowsPath {
    /// Splits a root-relative UTF-16 path into validated Windows components.
    /// # Errors
    ///
    /// Returns an error when the path is empty after root separators are removed or any component is
    /// not a valid Windows name.
    fn from_utf16_path(units: &[u16]) -> DriverResult<Self> {
        let mut trimmed = units;
        while let Some(rest) = trimmed.strip_prefix(&[UTF16_BACKSLASH]) {
            trimmed = rest;
        }
        if trimmed.is_empty() {
            return Err(DriverError::InvalidParameter);
        }
        let mut components = DriverVec::new();
        for component in trimmed.split(|unit| *unit == UTF16_BACKSLASH) {
            components
                .try_push_owned(WindowsName::from_utf16(component)?)
                .map_err(|error| error.into_parts().0)?;
        }
        let target_name = components.pop().ok_or(DriverError::InvalidParameter)?;
        Ok(Self {
            parents: components,
            target_name,
        })
    }

    /// Parent path components from root to target parent.
    fn parents(&self) -> &[WindowsName] {
        self.parents.as_slice()
    }

    /// Final path component.
    const fn target_name(&self) -> &WindowsName {
        &self.target_name
    }
}

/// Offset of FILE_RENAME_INFORMATION ReplaceIfExists.
const FILE_RENAME_REPLACE_IF_EXISTS_OFFSET: usize = 0;
/// Offset of FILE_RENAME_INFORMATION_EX Flags.
const FILE_RENAME_FLAGS_OFFSET: usize = 0;
/// Offset of FILE_RENAME_INFORMATION RootDirectory.
const FILE_RENAME_ROOT_DIRECTORY_OFFSET: usize = 8;
/// Offset of FILE_RENAME_INFORMATION FileNameLength.
const FILE_RENAME_NAME_LENGTH_OFFSET: usize = 16;
/// Offset of FILE_RENAME_INFORMATION FileName.
const FILE_RENAME_NAME_OFFSET: usize = 20;
/// FILE_DISPOSITION_INFORMATION_EX flags handled by this driver.
/// FILE_RENAME_INFORMATION_EX flags handled by this driver.
const SUPPORTED_RENAME_EX_FLAGS: wdk_sys::ULONG =
    wdk_sys::FILE_RENAME_IGNORE_READONLY_ATTRIBUTE | wdk_sys::FILE_RENAME_REPLACE_IF_EXISTS;
/// UTF-16 backslash separator.
const UTF16_BACKSLASH: u16 = 0x005C;

/// Rejects FILE_RENAME_INFORMATION payloads carrying an unsupported root handle.
/// # Errors
///
/// Returns an error when the root-directory handle field is present and nonzero.
fn reject_root_directory(bytes: &[u8]) -> DriverResult<()> {
    if input_range(
        bytes,
        FILE_RENAME_ROOT_DIRECTORY_OFFSET,
        core::mem::size_of::<wdk_sys::HANDLE>(),
    )?
    .iter()
    .any(|byte| *byte != 0)
    {
        Err(DriverError::NotSupported)
    } else {
        Ok(())
    }
}

/// Decodes little-endian UTF-16 units from a byte buffer.
/// # Errors
///
/// Returns an error when `bytes` has an odd length or cannot be split into two-byte units.
fn utf16_units_from_le_bytes(bytes: &[u8]) -> DriverResult<DriverVec<u16>> {
    if bytes.len() & 1 != 0 {
        return Err(DriverError::InvalidParameter);
    }
    let mut units = DriverVec::new();
    let (chunks, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(DriverError::InvalidParameter);
    }
    for chunk in chunks {
        let unit = u16::from_le_bytes(*chunk);
        units.try_push(unit)?;
    }
    Ok(units)
}

/// Resolves the target parent directory and final ext4 name for a rename.
/// # Errors
///
/// Returns an error when any parent component is absent or not a directory, or the target Windows
/// name cannot be converted to an ext4 name.
fn resolve_rename_target(
    vcb: &VolumeControlBlock,
    target: &RenameTargetPath,
) -> DriverResult<(DirectoryNodeId, Ext4Name)> {
    let mut parent_id = DirectoryNodeId::ROOT;
    for component in target.parents() {
        let parent = vcb
            .volume()
            .load_directory(parent_id)
            .map_err(|_| DriverError::ObjectPathNotFound)?;
        let child = vcb.volume().lookup_windows_child(&parent, component)?;
        match child {
            ChildLookup::Found(child) => {
                let NodeId::Directory(directory_id) = *child.node() else {
                    return Err(DriverError::ObjectPathNotFound);
                };
                if vcb
                    .volume()
                    .read_windows_symlink_reparse_point(NodeId::Directory(directory_id))?
                    .is_some()
                {
                    return Err(DriverError::NotSupported);
                }
                parent_id = directory_id;
            }
            ChildLookup::NotFound => return Err(DriverError::ObjectPathNotFound),
        };
    }
    Ok((parent_id, target.target_name().to_ext4()?))
}

/// Returns an immutable checked input byte range.
/// # Errors
///
/// Returns an error when `offset..offset + length` overflows or is outside `bytes`.
fn input_range(bytes: &[u8], offset: usize, length: usize) -> DriverResult<&[u8]> {
    wire_range(offset, length)?.read_from(bytes)
}

/// Builds a complete ext4 timestamp set from FILE_BASIC_INFORMATION.
/// # Errors
///
/// Returns an error when any supplied Windows timestamp is negative, unsupported, or cannot be
/// converted to Unix seconds.
fn set_basic_times(
    current: Ext4Times,
    info: wdk_sys::FILE_BASIC_INFORMATION,
) -> DriverResult<Ext4Times> {
    Ok(Ext4Times::new(
        windows_time_field(info.LastAccessTime, current.accessed())?,
        windows_time_field(info.LastWriteTime, current.modified())?,
        windows_time_field(info.ChangeTime, current.changed())?,
        windows_time_field(info.CreationTime, current.created())?,
    ))
}

/// Selects one timestamp field, preserving the current value for sentinel inputs.
/// # Errors
///
/// Returns an error when `value` is a negative non-sentinel timestamp or Windows cannot convert it
/// to Unix seconds.
fn windows_time_field(value: LARGE_INTEGER, current: Ext4Timestamp) -> DriverResult<Ext4Timestamp> {
    let quad = large_integer_quad(value);
    if quad == WINDOWS_TIME_UNCHANGED || quad == WINDOWS_TIME_PRESERVE {
        return Ok(current);
    }
    if quad < 0 {
        return Err(DriverError::InvalidParameter);
    }
    let mut time = value;
    let mut seconds: wdk_sys::ULONG = 0;
    let converted = unsafe {
        // SAFETY: Both pointers reference writable stack storage valid for the
        // duration of the conversion call.
        crate::kernel::ffi::RtlTimeToSecondsSince1970(
            core::ptr::addr_of_mut!(time),
            core::ptr::addr_of_mut!(seconds),
        )
    };
    if converted == 0 {
        return Err(DriverError::InvalidParameter);
    }
    Ok(Ext4Timestamp::from_unix_seconds(seconds))
}

/// Windows FILE_BASIC_INFORMATION sentinel for preserving a timestamp.
const WINDOWS_TIME_UNCHANGED: i64 = 0;
/// Additional Windows sentinel used by callers to preserve timestamp state.
const WINDOWS_TIME_PRESERVE: i64 = -1;
/// POSIX write bits that make Windows READONLY false.
const POSIX_WRITE_BITS: u16 = 0o222;
/// Owner write bit restored when Windows READONLY is cleared.
const POSIX_OWNER_WRITE_BIT: u16 = 0o200;

/// Domain updates derived from FILE_BASIC_INFORMATION attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BasicAttributeUpdate {
    /// POSIX security update needed to reflect FILE_ATTRIBUTE_READONLY.
    security: Option<Ext4Security>,
    /// Windows overlay xattr update for attributes not owned by POSIX mode or node kind.
    overlay: Option<WindowsOverlay>,
}

impl BasicAttributeUpdate {
    /// Creates an empty attribute update.
    const fn empty() -> Self {
        Self {
            security: None,
            overlay: None,
        }
    }

    /// Creates an attribute update from independent domain mutations.
    const fn new(security: Option<Ext4Security>, overlay: Option<WindowsOverlay>) -> Self {
        Self { security, overlay }
    }

    /// Returns whether this update has no domain mutations.
    const fn is_empty(self) -> bool {
        self.security.is_none() && self.overlay.is_none()
    }

    /// POSIX security update.
    const fn security(self) -> Option<Ext4Security> {
        self.security
    }

    /// Windows overlay update.
    const fn overlay(self) -> Option<WindowsOverlay> {
        self.overlay
    }
}

/// Builds overlay metadata from FILE_BASIC_INFORMATION attributes.
/// # Errors
///
/// Returns an error when requested attributes contradict the node kind or include unsupported bits.
fn set_basic_attributes(
    metadata: FileMetadata,
    attributes: wdk_sys::ULONG,
) -> DriverResult<BasicAttributeUpdate> {
    if attributes == 0 {
        return Ok(BasicAttributeUpdate::empty());
    }
    validate_kind_attribute(metadata, attributes)?;

    let accepted = Ext4WindowsAttributes::SUPPORTED_MASK
        | wdk_sys::FILE_ATTRIBUTE_READONLY
        | wdk_sys::FILE_ATTRIBUTE_NORMAL
        | wdk_sys::FILE_ATTRIBUTE_DIRECTORY
        | wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT;
    if attributes & !accepted != 0 {
        return Err(DriverError::NotSupported);
    }

    let security = readonly_security_update(metadata.security, attributes)?;
    let overlay_bits = attributes & Ext4WindowsAttributes::SUPPORTED_MASK;
    let overlay = if overlay_bits == metadata.overlay_attributes {
        None
    } else {
        Some(WindowsOverlay::new(Ext4WindowsAttributes::new(
            overlay_bits,
        )?))
    };
    Ok(BasicAttributeUpdate::new(security, overlay))
}

/// Builds a POSIX security update for FILE_ATTRIBUTE_READONLY.
/// # Errors
///
/// Returns an error when the adjusted permissions cannot be represented.
fn readonly_security_update(
    security: Ext4Security,
    attributes: wdk_sys::ULONG,
) -> DriverResult<Option<Ext4Security>> {
    let current_permissions = security.permissions().as_u16();
    let requested_permissions = if attributes & wdk_sys::FILE_ATTRIBUTE_READONLY != 0 {
        current_permissions & !POSIX_WRITE_BITS
    } else {
        current_permissions | POSIX_OWNER_WRITE_BIT
    };
    if requested_permissions == current_permissions {
        return Ok(None);
    }
    Ok(Some(Ext4Security::new(
        security.owner(),
        Ext4Permissions::new(requested_permissions)?,
    )))
}

/// Rejects node-kind attributes that contradict the opened ext4 node or reparse state.
/// # Errors
///
/// Returns an error when directory or reparse-point attributes do not match opened metadata.
fn validate_kind_attribute(metadata: FileMetadata, attributes: wdk_sys::ULONG) -> DriverResult<()> {
    if attributes & wdk_sys::FILE_ATTRIBUTE_DIRECTORY != 0
        && metadata.kind != FileMetadataKind::Directory
    {
        return Err(DriverError::InvalidParameter);
    }
    if attributes & wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT != 0
        && metadata.reparse_point == FileMetadataReparsePoint::None
    {
        return Err(DriverError::InvalidParameter);
    }
    Ok(())
}

/// Returns a non-negative file size from a Windows LARGE_INTEGER.
/// # Errors
///
/// Returns an error when the LARGE_INTEGER contains a negative size.
fn file_size_from_large_integer(value: LARGE_INTEGER) -> DriverResult<FileSize> {
    let value = large_integer_quad(value);
    if value < 0 {
        return Err(DriverError::InvalidParameter);
    }
    Ok(FileSize::from_bytes(
        u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?,
    ))
}

/// Returns a non-negative file offset from a Windows LARGE_INTEGER.
/// # Errors
///
/// Returns an error when the LARGE_INTEGER contains a negative offset.
fn file_offset_from_large_integer(value: LARGE_INTEGER) -> DriverResult<FileOffset> {
    let value = large_integer_quad(value);
    Ok(FileOffset::from_bytes(
        u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?,
    ))
}

/// Returns the current size of a regular file inode.
/// # Errors
///
/// Returns an error when `file_id` cannot be loaded as a regular file.
fn regular_file_size(vcb: &VolumeControlBlock, file_id: FileNodeId) -> DriverResult<FileSize> {
    Ok(vcb.volume().load_file(file_id)?.size())
}

/// Returns the signed payload of a LARGE_INTEGER.
fn large_integer_quad(value: LARGE_INTEGER) -> i64 {
    unsafe {
        // SAFETY: `QuadPart` is the LARGE_INTEGER representation used by this
        // driver for Windows time and file-size values.
        value.QuadPart
    }
}

/// File metadata needed by fixed-size Windows information classes.
#[derive(Clone, Copy, Debug)]
struct FileMetadata {
    /// Stable ext4 inode id encoded for Windows file-index payloads.
    file_index: u32,
    /// Open node kind.
    kind: FileMetadataKind,
    /// Payload size in bytes.
    size: FileSize,
    /// POSIX security metadata.
    security: Ext4Security,
    /// ext4 inode timestamps.
    times: Ext4Times,
    /// ext4 inode link count.
    links_count: Ext4LinkCount,
    /// Windows-specific overlay attributes.
    overlay_attributes: u32,
    /// Windows reparse metadata projected from a native symlink or private xattr.
    reparse_point: FileMetadataReparsePoint,
    /// Mounted volume block size.
    block_size: ext4_core::BlockSize,
}

/// Node kind projected to Windows information flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileMetadataKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// Reparse metadata projected to Windows file-information records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileMetadataReparsePoint {
    /// The node has no Windows reparse metadata.
    None,
    /// The node represents a symbolic-link reparse point.
    SymbolicLink,
}

/// Loads metadata for the opened file currently being queried.
/// # Errors
///
/// Returns an error when the opened node metadata or Windows overlay xattr cannot be loaded.
fn load_file_metadata(opened_file: &OpenedObject) -> DriverResult<FileMetadata> {
    let fcb = opened_file.file_control_block();
    let vcb = volume_control_block(fcb);
    metadata_from_node(vcb, fcb.node())
}

/// Builds Windows-facing metadata from a loaded ext4 node.
/// # Errors
///
/// Returns an error when `node_id` cannot be loaded as its typed ext4 node or its Windows overlay
/// xattr is malformed.
fn metadata_from_node(vcb: &VolumeControlBlock, node_id: NodeId) -> DriverResult<FileMetadata> {
    let overlay_attributes = vcb
        .volume()
        .read_windows_overlay(node_id)?
        .map(|overlay| overlay.attributes().bits())
        .unwrap_or(0);
    let reparse_point = match node_id {
        NodeId::Symlink(_) => FileMetadataReparsePoint::SymbolicLink,
        NodeId::File(_) | NodeId::Directory(_) => {
            if vcb
                .volume()
                .read_windows_symlink_reparse_point(node_id)?
                .is_some()
            {
                FileMetadataReparsePoint::SymbolicLink
            } else {
                FileMetadataReparsePoint::None
            }
        }
    };

    let file_index = node_id.file_index();
    let block_size = vcb.volume().geometry().block_size();
    match node_id {
        NodeId::File(file_id) => {
            let file = vcb.volume().load_file(file_id)?;
            Ok(FileMetadata {
                file_index,
                kind: FileMetadataKind::File,
                size: file.size(),
                security: file.security(),
                times: file.times(),
                links_count: file.links_count(),
                overlay_attributes,
                reparse_point,
                block_size,
            })
        }
        NodeId::Directory(directory_id) => {
            let directory = vcb.volume().load_directory(directory_id)?;
            Ok(FileMetadata {
                file_index,
                kind: FileMetadataKind::Directory,
                size: directory.size(),
                security: directory.security(),
                times: directory.times(),
                links_count: directory.links_count(),
                overlay_attributes,
                reparse_point,
                block_size,
            })
        }
        NodeId::Symlink(symlink_id) => {
            let symlink = vcb.volume().load_symlink(symlink_id)?;
            Ok(FileMetadata {
                file_index,
                kind: FileMetadataKind::Symlink,
                size: symlink.size(),
                security: symlink.security(),
                times: symlink.times(),
                links_count: symlink.links_count(),
                overlay_attributes,
                reparse_point,
                block_size,
            })
        }
    }
}

/// Packs FILE_BASIC_INFORMATION.
/// # Errors
///
/// Returns an error when the output buffer is too small for `FILE_BASIC_INFORMATION`.
fn pack_basic_information(
    output: &mut [u8],
    metadata: FileMetadata,
) -> DriverResult<IrpCompletion> {
    write_fixed(
        output,
        wdk_sys::FILE_BASIC_INFORMATION {
            CreationTime: windows_time(metadata.times.created()),
            LastAccessTime: windows_time(metadata.times.accessed()),
            LastWriteTime: windows_time(metadata.times.modified()),
            ChangeTime: windows_time(metadata.times.changed()),
            FileAttributes: file_attributes(metadata),
        },
    )
}

/// Packs FILE_STANDARD_INFORMATION.
/// # Errors
///
/// Returns an error when allocation or EOF sizes cannot be represented, or the output buffer is too
/// small for `FILE_STANDARD_INFORMATION`.
fn pack_standard_information(
    output: &mut [u8],
    metadata: FileMetadata,
) -> DriverResult<IrpCompletion> {
    write_fixed(
        output,
        wdk_sys::FILE_STANDARD_INFORMATION {
            AllocationSize: large_integer_from_u64(allocation_size(metadata)?)?,
            EndOfFile: large_integer_from_u64(metadata.size.bytes())?,
            NumberOfLinks: wdk_sys::ULONG::from(metadata.links_count.get()),
            DeletePending: boolean(false),
            Directory: boolean(metadata.kind == FileMetadataKind::Directory),
        },
    )
}

/// Packs FILE_INTERNAL_INFORMATION.
/// # Errors
///
/// Returns an error when the output buffer is too small for `FILE_INTERNAL_INFORMATION`.
fn pack_internal_information(
    output: &mut [u8],
    metadata: FileMetadata,
) -> DriverResult<IrpCompletion> {
    write_fixed(
        output,
        wdk_sys::FILE_INTERNAL_INFORMATION {
            IndexNumber: LARGE_INTEGER {
                QuadPart: i64::from(metadata.file_index),
            },
        },
    )
}

/// Packs FILE_POSITION_INFORMATION.
/// # Errors
///
/// Returns an error when the handle has no synchronous current position or the output buffer is
/// too small for `FILE_POSITION_INFORMATION`.
fn pack_position_information(
    output: &mut [u8],
    opened_file: &OpenedObject,
) -> DriverResult<IrpCompletion> {
    let current = opened_file.current_file_position()?;
    write_fixed(
        output,
        wdk_sys::FILE_POSITION_INFORMATION {
            CurrentByteOffset: large_integer_from_u64(current.bytes())?,
        },
    )
}

/// Packs FILE_NETWORK_OPEN_INFORMATION.
/// # Errors
///
/// Returns an error when sizes cannot be represented as signed Windows values or the output buffer
/// is too small for `FILE_NETWORK_OPEN_INFORMATION`.
fn pack_network_open_information(
    output: &mut [u8],
    metadata: FileMetadata,
) -> DriverResult<IrpCompletion> {
    write_fixed(
        output,
        wdk_sys::FILE_NETWORK_OPEN_INFORMATION {
            CreationTime: windows_time(metadata.times.created()),
            LastAccessTime: windows_time(metadata.times.accessed()),
            LastWriteTime: windows_time(metadata.times.modified()),
            ChangeTime: windows_time(metadata.times.changed()),
            AllocationSize: large_integer_from_u64(allocation_size(metadata)?)?,
            EndOfFile: large_integer_from_u64(metadata.size.bytes())?,
            FileAttributes: file_attributes(metadata),
        },
    )
}

/// Packs FILE_NAME_INFORMATION.
/// # Errors
///
/// Returns an error when the opened location cannot be projected to UTF-16, the name length
/// overflows, or the output buffer is too small.
fn pack_name_information(
    output: &mut [u8],
    opened_file: &OpenedObject,
) -> DriverResult<IrpCompletion> {
    let units = opened_location_name_units(opened_file.location())?;
    let name_bytes = utf16_byte_len(units.as_slice())?;
    let required = FILE_NAME_INFORMATION_NAME_OFFSET
        .checked_add(name_bytes)
        .ok_or(DriverError::InvalidParameter)?;
    if output.len() < required {
        return Err(DriverError::BufferOverflow);
    }
    clear_record(output, 0, required)?;
    LittleEndianOutput::new(output).write_u32(
        WireOffset::new(FILE_NAME_INFORMATION_NAME_LENGTH_OFFSET),
        u32::try_from(name_bytes).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    write_utf16(output, FILE_NAME_INFORMATION_NAME_OFFSET, units.as_slice())?;
    IrpCompletion::from_usize(required)
}

/// Packs FILE_ATTRIBUTE_TAG_INFORMATION.
/// # Errors
///
/// Returns an error when the output buffer is too small for `FILE_ATTRIBUTE_TAG_INFORMATION`.
fn pack_attribute_tag_information(
    output: &mut [u8],
    metadata: FileMetadata,
) -> DriverResult<IrpCompletion> {
    write_fixed(
        output,
        wdk_sys::FILE_ATTRIBUTE_TAG_INFORMATION {
            FileAttributes: file_attributes(metadata),
            ReparseTag: reparse_tag(metadata.reparse_point),
        },
    )
}

/// Projects an opened location to the name payload returned to Windows.
/// # Errors
///
/// Returns an error when the location has no path name or a child ext4 name cannot be represented
/// as a Windows UTF-16 name.
fn opened_location_name_units(location: &OpenedLocation) -> DriverResult<DriverVec<u16>> {
    match location {
        OpenedLocation::Root => DriverVec::try_copied_from_slice(&[UTF16_BACKSLASH]),
        OpenedLocation::DirectoryEntry { name, .. } => {
            DriverVec::try_copied_from_slice(WindowsName::from_ext4(name)?.utf16())
        }
        OpenedLocation::FileReference => Err(DriverError::NotSupported),
    }
}

/// Returns the reparse tag associated with file metadata.
const fn reparse_tag(reparse_point: FileMetadataReparsePoint) -> wdk_sys::ULONG {
    match reparse_point {
        FileMetadataReparsePoint::None => 0,
        FileMetadataReparsePoint::SymbolicLink => wdk_sys::IO_REPARSE_TAG_SYMLINK,
    }
}

/// Offset of FileNameLength in FILE_NAME_INFORMATION.
const FILE_NAME_INFORMATION_NAME_LENGTH_OFFSET: usize = 0;
/// Offset of FileName in FILE_NAME_INFORMATION.
const FILE_NAME_INFORMATION_NAME_OFFSET: usize = 4;

/// Writes one fixed-size information structure into the caller's buffer.
/// # Errors
///
/// Returns an error when `output` is smaller than `T`.
fn write_fixed<T>(output: &mut [u8], value: T) -> DriverResult<IrpCompletion> {
    let size = core::mem::size_of::<T>();
    if output.len() < size {
        return Err(DriverError::BufferTooSmall);
    }
    unsafe {
        // SAFETY: The output slice is at least `size_of::<T>()` bytes and the
        // write does not read from the destination. Unaligned write avoids
        // imposing an alignment requirement on the system buffer.
        output.as_mut_ptr().cast::<T>().write_unaligned(value);
    }
    IrpCompletion::from_usize(size)
}

/// Converts an ext4 timestamp to a Windows system-time LARGE_INTEGER.
fn windows_time(timestamp: Ext4Timestamp) -> LARGE_INTEGER {
    let mut time = LARGE_INTEGER { QuadPart: 0 };
    unsafe {
        // SAFETY: `time` points to writable stack storage for the conversion
        // result.
        crate::kernel::ffi::RtlSecondsSince1970ToTime(
            timestamp.seconds(),
            core::ptr::addr_of_mut!(time),
        );
    }
    time
}

/// Returns Windows file attribute bits for an ext4 node.
fn file_attributes(metadata: FileMetadata) -> wdk_sys::ULONG {
    let mut attributes = metadata.overlay_attributes;
    if metadata.security.permissions().as_u16() & 0o222 == 0 {
        attributes |= wdk_sys::FILE_ATTRIBUTE_READONLY;
    }
    match metadata.kind {
        FileMetadataKind::File => {}
        FileMetadataKind::Directory => attributes |= wdk_sys::FILE_ATTRIBUTE_DIRECTORY,
        FileMetadataKind::Symlink => {}
    }
    if metadata.reparse_point == FileMetadataReparsePoint::SymbolicLink {
        attributes |= wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT;
    }
    if attributes == 0 {
        wdk_sys::FILE_ATTRIBUTE_NORMAL
    } else {
        attributes
    }
}

/// Returns allocation size rounded to a volume allocation unit.
/// # Errors
///
/// Returns an error when block-size rounding arithmetic overflows.
fn allocation_size(metadata: FileMetadata) -> DriverResult<u64> {
    let size = metadata.size.bytes();
    if size == 0 {
        return Ok(0);
    }
    let block_size = u64::from(metadata.block_size.bytes());
    let adjustment = block_size
        .checked_sub(1)
        .ok_or(DriverError::InvalidParameter)?;
    let adjusted = size
        .checked_add(adjustment)
        .ok_or(DriverError::InvalidParameter)?;
    let blocks = adjusted
        .checked_div(block_size)
        .ok_or(DriverError::InvalidParameter)?;
    blocks
        .checked_mul(block_size)
        .ok_or(DriverError::InvalidParameter)
}

/// Creates a signed LARGE_INTEGER from an unsigned byte count.
/// # Errors
///
/// Returns an error when `value` exceeds the signed LARGE_INTEGER range.
fn large_integer_from_u64(value: u64) -> DriverResult<LARGE_INTEGER> {
    Ok(LARGE_INTEGER {
        QuadPart: i64::try_from(value).map_err(|_| DriverError::InvalidParameter)?,
    })
}

/// Converts a Rust boolean to WDK BOOLEAN.
fn boolean(value: bool) -> wdk_sys::BOOLEAN {
    u8::from(value)
}

/// Fully resolved signed Windows file range used by data I/O and byte locks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolvedFileRange {
    /// First byte affected by the operation.
    start: FileOffset,
    /// Maximum byte count requested by the operation.
    length: usize,
}

impl ResolvedFileRange {
    /// Validates a resolved file range against the signed Windows offset domain.
    /// # Errors
    ///
    /// Returns an error when the end offset overflows or exceeds `i64::MAX`.
    fn new(start: FileOffset, length: usize) -> DriverResult<Self> {
        let end = start.checked_add_len(length)?;
        let _signed_end = i64::try_from(end.bytes()).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self { start, length })
    }

    /// Returns the resolved starting byte.
    const fn start(self) -> FileOffset {
        self.start
    }

    /// Returns the requested byte count.
    const fn length(self) -> usize {
        self.length
    }
}

/// Read starting source after paging policy is applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedReadStart {
    /// Explicit offset independent of FILE_OBJECT state.
    Absolute(FileOffset),
    /// Synchronous FILE_OBJECT current position.
    CurrentFilePosition,
}

/// Applies paging policy to a decoded read starting point.
/// # Errors
///
/// Returns an error when paging I/O requests a handle position.
fn select_read_start(
    kind: DataIoKind,
    starting_point: ReadStartingPoint,
) -> DriverResult<SelectedReadStart> {
    match (kind, starting_point) {
        (DataIoKind::Handle, ReadStartingPoint::Absolute(offset))
        | (DataIoKind::Paging, ReadStartingPoint::Absolute(offset)) => {
            Ok(SelectedReadStart::Absolute(offset))
        }
        (DataIoKind::Handle, ReadStartingPoint::CurrentFilePosition) => {
            Ok(SelectedReadStart::CurrentFilePosition)
        }
        (DataIoKind::Paging, ReadStartingPoint::CurrentFilePosition) => {
            Err(DriverError::InvalidParameter)
        }
    }
}

/// Resolves a selected read source to a concrete file offset.
/// # Errors
///
/// Returns an error when the selected synchronous position is absent.
fn resolve_read_start(
    opened_file: &OpenedRegularFile,
    kind: DataIoKind,
    starting_point: ReadStartingPoint,
) -> DriverResult<FileOffset> {
    match select_read_start(kind, starting_point)? {
        SelectedReadStart::Absolute(offset) => Ok(offset),
        SelectedReadStart::CurrentFilePosition => opened_file.current_file_position(),
    }
}

/// Write starting source after paging and access policy are applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedWriteStart {
    /// Explicit offset independent of FILE_OBJECT state.
    Absolute(FileOffset),
    /// Synchronous FILE_OBJECT current position.
    CurrentFilePosition,
    /// Latest committed regular-file end.
    EndOfFile,
}

/// Applies paging and write-authority policy to a decoded write starting point.
/// # Errors
///
/// Returns an error for denied handle writes or paging sentinel positions.
fn select_write_start(
    write_access: RegularFileWriteAccess,
    kind: DataIoKind,
    starting_point: WriteStartingPoint,
) -> DriverResult<SelectedWriteStart> {
    if kind == DataIoKind::Paging {
        return match starting_point {
            WriteStartingPoint::Absolute(offset) => Ok(SelectedWriteStart::Absolute(offset)),
            WriteStartingPoint::CurrentFilePosition | WriteStartingPoint::EndOfFile => {
                Err(DriverError::InvalidParameter)
            }
        };
    }

    match write_access {
        RegularFileWriteAccess::Denied => Err(DriverError::AccessDenied),
        RegularFileWriteAccess::AppendOnly => Ok(SelectedWriteStart::EndOfFile),
        RegularFileWriteAccess::Positional => match starting_point {
            WriteStartingPoint::Absolute(offset) => Ok(SelectedWriteStart::Absolute(offset)),
            WriteStartingPoint::CurrentFilePosition => Ok(SelectedWriteStart::CurrentFilePosition),
            WriteStartingPoint::EndOfFile => Ok(SelectedWriteStart::EndOfFile),
        },
    }
}

/// Resolves a write starting point after write authority and I/O origin are known.
/// # Errors
///
/// Returns an error for denied handle writes, paging sentinels, absent synchronous position, or an
/// end of file outside the signed Windows offset domain.
fn resolve_write_start(
    opened_file: &OpenedRegularFile,
    kind: DataIoKind,
    starting_point: WriteStartingPoint,
) -> DriverResult<FileOffset> {
    let current_position = if kind == DataIoKind::Handle
        && starting_point == WriteStartingPoint::CurrentFilePosition
    {
        Some(opened_file.current_file_position()?)
    } else {
        None
    };
    match select_write_start(opened_file.write_access(), kind, starting_point)? {
        SelectedWriteStart::Absolute(offset) => Ok(offset),
        SelectedWriteStart::CurrentFilePosition => {
            current_position.ok_or(DriverError::InvalidParameter)
        }
        SelectedWriteStart::EndOfFile => regular_file_end(opened_file),
    }
}

/// Returns the latest committed EOF as a signed-Windows-compatible file offset.
/// # Errors
///
/// Returns an error when the file cannot be loaded or EOF exceeds `i64::MAX`.
fn regular_file_end(opened_file: &OpenedRegularFile) -> DriverResult<FileOffset> {
    let vcb = unsafe {
        // SAFETY: The opened regular file retains its mounted VCB for the FILE_OBJECT lifetime.
        opened_file.volume().as_ref()
    };
    let end = FileOffset::from_bytes(regular_file_size(vcb, opened_file.id())?.bytes());
    let _signed_end = i64::try_from(end.bytes()).map_err(|_| DriverError::InvalidParameter)?;
    Ok(end)
}

/// Reads a regular file through ext4-core into the IRP output buffer.
/// # Errors
///
/// Returns an error when the read stack or output buffer is invalid, the FILE_OBJECT is not a
/// regular file, or ext4 data read fails.
fn read_regular_file(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    let stack = target.current_stack()?.read()?;
    let mut opened_file = OpenedRegularFile::decode(stack.file_object())?;
    let kind = target.data_io_kind();
    let length = stack.length();
    let range = ResolvedFileRange::new(
        resolve_read_start(&opened_file, kind, stack.starting_point())?,
        length.as_usize(),
    )?;
    let data_transfer_mode = opened_file.data_transfer_mode();
    data_transfer_mode.validate_range(range.start().bytes(), range.length())?;
    if length.is_empty() {
        opened_file.update_current_file_position(kind, range.start(), 0)?;
        return Ok(IrpCompletion::EMPTY);
    }
    let mut output = target.data_output(length)?;
    data_transfer_mode.validate_buffer(output.address())?;
    if kind == DataIoKind::Handle
        && !opened_file.file_control_block().permits_byte_range_read(
            target,
            opened_file.file_object(),
            range.start(),
            range.length(),
            stack.key(),
        )?
    {
        return Err(DriverError::FileLockConflict);
    }
    let vcb = unsafe {
        // SAFETY: OpenedRegularFile is decoded from a live FCB whose VCB
        // pointer remains valid for the opened FILE_OBJECT lifetime.
        opened_file.volume().as_ref()
    };

    let file = vcb.volume().load_file(opened_file.id())?;
    let bytes_read = vcb
        .volume()
        .read_file(&file, range.start(), output.as_mut_slice())?;
    let bytes_read = bytes_read.as_usize();
    opened_file.update_current_file_position(kind, range.start(), bytes_read)?;
    IrpCompletion::from_usize(bytes_read)
}

/// Writes a regular file range through an ext4 journal transaction.
/// # Errors
///
/// Returns an error when the write stack or input buffer is invalid, the FILE_OBJECT is not a
/// regular file, or the ext4 write transaction fails.
fn write_regular_file(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    let stack = target.current_stack()?.write()?;
    let mut opened_file = OpenedRegularFile::decode(stack.file_object())?;
    let kind = target.data_io_kind();
    let length = stack.length();
    let range = ResolvedFileRange::new(
        resolve_write_start(&opened_file, kind, stack.starting_point())?,
        length.as_usize(),
    )?;
    let data_transfer_mode = opened_file.data_transfer_mode();
    data_transfer_mode.validate_range(range.start().bytes(), range.length())?;
    if length.is_empty() {
        opened_file.update_current_file_position(kind, range.start(), 0)?;
        return Ok(IrpCompletion::EMPTY);
    }
    let input = target.data_input(length)?;
    data_transfer_mode.validate_buffer(input.address())?;
    if kind == DataIoKind::Handle
        && !opened_file.file_control_block().permits_byte_range_write(
            target,
            opened_file.file_object(),
            range.start(),
            range.length(),
            stack.key(),
        )?
    {
        return Err(DriverError::FileLockConflict);
    }
    let mut vcb = opened_file.volume();
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this synchronous write path.
        vcb.as_mut()
    };

    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let file = transaction.file(opened_file.id())?;
    transaction.write_file_range(file, range.start(), input.as_slice())?;
    transaction.commit()?;
    if matches!(
        opened_file.write_commitment(),
        WriteCommitment::FlushThrough
    ) {
        vcb.flush()?;
    }
    let bytes_written = input.as_slice().len();
    opened_file.update_current_file_position(kind, range.start(), bytes_written)?;
    IrpCompletion::from_usize(bytes_written)
}

/// Returns the mounted VCB referenced by an FCB.
fn volume_control_block(fcb: &FileControlBlock) -> &VolumeControlBlock {
    unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open.
        fcb.volume().as_ref()
    }
}

/// Detaches and releases heap-owned FCB and CCB pointers stored on a FILE_OBJECT.
fn release_file_contexts(file_object: KernelFileObject) {
    let contexts = unsafe {
        // SAFETY: Close receives the final live FILE_OBJECT and reads only its filesystem-owned
        // context pointers before deciding whether they can be released.
        let object = file_object.as_ref();
        (object.FsContext, object.FsContext2)
    };
    match contexts {
        (fcb, handle) if fcb.is_null() && handle.is_null() => return,
        (fcb, handle) if fcb.is_null() || handle.is_null() => {
            crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                .bugcheck();
        }
        _ => {}
    }
    let close_kind = file_object.close_kind_or_bugcheck();
    let release_plan = {
        let opened = match OpenedObject::decode(file_object) {
            Ok(opened) => opened,
            Err(_) => {
                crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                    .bugcheck();
            }
        };
        opened.close_release_plan(close_kind)
    };

    let (fcb, handle) = unsafe {
        // SAFETY: Close receives the final FILE_OBJECT and may clear its
        // filesystem-owned context pointers before releasing either allocation.
        let object = file_object.as_mut();
        (
            core::mem::replace(&mut object.FsContext, core::ptr::null_mut()),
            core::mem::replace(&mut object.FsContext2, core::ptr::null_mut()),
        )
    };
    let Some(fcb) = NonNull::new(fcb.cast::<FileControlBlock>()) else {
        crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption().bugcheck();
    };
    let Some(handle) = NonNull::new(handle.cast::<OpenedHandle>()) else {
        crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption().bugcheck();
    };
    match release_plan {
        CloseReleasePlan::CleanedHandle => release_file_control_block(fcb),
        CloseReleasePlan::CancelledOpen => {
            release_cancelled_file_control_block(fcb, file_object);
        }
    }
    unsafe {
        // SAFETY: Successful create stores Box<OpenedHandle> in FsContext2. Close detached the
        // unique owning pointer before selecting this terminal drop.
        drop(Box::from_raw(handle.as_ptr()));
    }
}

#[cfg(test)]
mod tests {
    use crate::irp::{
        DataIoKind, DirectoryInformationClass, DispatchTarget, ReadStartingPoint,
        RegularFileWriteAccess, WriteStartingPoint,
    };
    use crate::kernel::status::DriverError;
    use crate::state::OpenedLocation;
    use ext4_core::{
        BlockSize, DirectoryNodeId, Ext4Gid, Ext4LinkCount, Ext4Name, Ext4Owner, Ext4Permissions,
        Ext4Security, Ext4Times, Ext4Timestamp, Ext4Uid, FileOffset, FileSize, WindowsName,
    };

    fn test_metadata(kind: super::FileMetadataKind) -> Option<super::FileMetadata> {
        test_metadata_with_permissions(kind, 0o644, 0)
    }

    fn test_metadata_with_permissions(
        kind: super::FileMetadataKind,
        permissions: u16,
        overlay_attributes: u32,
    ) -> Option<super::FileMetadata> {
        let timestamp = Ext4Timestamp::from_unix_seconds(1);
        Some(super::FileMetadata {
            file_index: 1,
            kind,
            size: FileSize::from_bytes(0),
            security: Ext4Security::new(
                Ext4Owner::new(Ext4Uid::from_u32(0), Ext4Gid::from_u32(0)),
                Ext4Permissions::new(permissions).ok()?,
            ),
            times: Ext4Times::new(timestamp, timestamp, timestamp, timestamp),
            links_count: Ext4LinkCount::ONE,
            overlay_attributes,
            reparse_point: match kind {
                super::FileMetadataKind::File | super::FileMetadataKind::Directory => {
                    super::FileMetadataReparsePoint::None
                }
                super::FileMetadataKind::Symlink => super::FileMetadataReparsePoint::SymbolicLink,
            },
            block_size: BlockSize::from_superblock_log(0).ok()?,
        })
    }

    /// Reads one little-endian u32 from a test output buffer.
    fn le_u32(buffer: &[u8], offset: usize) -> Option<u32> {
        let end = offset.checked_add(core::mem::size_of::<u32>())?;
        let bytes = buffer.get(offset..end)?;
        let bytes = <[u8; 4]>::try_from(bytes).ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    /// Writes one little-endian u32 into a test input buffer.
    fn put_le_u32(buffer: &mut [u8], offset: usize, value: u32) -> bool {
        let Some(end) = offset.checked_add(core::mem::size_of::<u32>()) else {
            return false;
        };
        let Some(target) = buffer.get_mut(offset..end) else {
            return false;
        };
        target.copy_from_slice(&value.to_le_bytes());
        true
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn basic_attributes_set_readonly_updates_posix_permissions() {
        let metadata = test_metadata_with_permissions(super::FileMetadataKind::File, 0o664, 0);
        assert!(metadata.is_some());
        let Some(metadata) = metadata else {
            return;
        };

        let update = super::set_basic_attributes(metadata, wdk_sys::FILE_ATTRIBUTE_READONLY);
        assert!(update.is_ok());
        if let Ok(update) = update {
            assert_eq!(
                update
                    .security()
                    .map(|security| security.permissions().as_u16()),
                Some(0o444)
            );
            assert_eq!(update.overlay(), None);
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn basic_attributes_clear_readonly_restores_owner_write() {
        let metadata = test_metadata_with_permissions(super::FileMetadataKind::File, 0o444, 0);
        assert!(metadata.is_some());
        let Some(metadata) = metadata else {
            return;
        };

        let update = super::set_basic_attributes(metadata, wdk_sys::FILE_ATTRIBUTE_NORMAL);
        assert!(update.is_ok());
        if let Ok(update) = update {
            assert_eq!(
                update
                    .security()
                    .map(|security| security.permissions().as_u16()),
                Some(0o644)
            );
            assert_eq!(update.overlay(), None);
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn basic_attributes_zero_preserves_existing_attributes() {
        let metadata = test_metadata_with_permissions(super::FileMetadataKind::File, 0o444, 0);
        assert!(metadata.is_some());
        let Some(metadata) = metadata else {
            return;
        };

        let update = super::set_basic_attributes(metadata, 0);
        assert!(update.is_ok());
        if let Ok(update) = update {
            assert!(update.is_empty());
        }
    }

    /// Builds a dispatch target whose IRP points at the supplied current stack.
    /// # Errors
    ///
    /// Returns an error when the local test device or IRP pointer cannot be decoded.
    fn target_from_stack(
        stack: &mut wdk_sys::IO_STACK_LOCATION,
        irp: &mut wdk_sys::IRP,
        device: &mut wdk_sys::DEVICE_OBJECT,
    ) -> Result<DispatchTarget, DriverError> {
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(*stack);
        DispatchTarget::decode(
            core::ptr::addr_of_mut!(*device),
            core::ptr::addr_of_mut!(*irp),
        )
    }

    /// # Panics
    ///
    /// Panics when paging read policy accepts a FILE_OBJECT current-position dependency.
    #[test]
    fn read_start_selection_separates_handle_and_paging_io() {
        let explicit = FileOffset::from_bytes(4096);
        assert_eq!(
            super::select_read_start(DataIoKind::Paging, ReadStartingPoint::Absolute(explicit),),
            Ok(super::SelectedReadStart::Absolute(explicit))
        );
        assert_eq!(
            super::select_read_start(DataIoKind::Handle, ReadStartingPoint::CurrentFilePosition,),
            Ok(super::SelectedReadStart::CurrentFilePosition)
        );
        assert_eq!(
            super::select_read_start(DataIoKind::Paging, ReadStartingPoint::CurrentFilePosition,),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when append-only writes retain a caller-selected starting point.
    #[test]
    fn append_only_write_selection_always_uses_end_of_file() {
        for starting_point in [
            WriteStartingPoint::Absolute(FileOffset::from_bytes(1)),
            WriteStartingPoint::CurrentFilePosition,
            WriteStartingPoint::EndOfFile,
        ] {
            assert_eq!(
                super::select_write_start(
                    RegularFileWriteAccess::AppendOnly,
                    DataIoKind::Handle,
                    starting_point,
                ),
                Ok(super::SelectedWriteStart::EndOfFile)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when denied, positional, or paging write policy selects the wrong source.
    #[test]
    fn write_start_selection_enforces_access_and_paging_policy() {
        let explicit = FileOffset::from_bytes(8192);
        assert_eq!(
            super::select_write_start(
                RegularFileWriteAccess::Denied,
                DataIoKind::Handle,
                WriteStartingPoint::Absolute(explicit),
            ),
            Err(DriverError::AccessDenied)
        );
        assert_eq!(
            super::select_write_start(
                RegularFileWriteAccess::Positional,
                DataIoKind::Handle,
                WriteStartingPoint::CurrentFilePosition,
            ),
            Ok(super::SelectedWriteStart::CurrentFilePosition)
        );
        assert_eq!(
            super::select_write_start(
                RegularFileWriteAccess::Denied,
                DataIoKind::Paging,
                WriteStartingPoint::Absolute(explicit),
            ),
            Ok(super::SelectedWriteStart::Absolute(explicit))
        );
        assert_eq!(
            super::select_write_start(
                RegularFileWriteAccess::Positional,
                DataIoKind::Paging,
                WriteStartingPoint::EndOfFile,
            ),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when resolved ranges cross the signed Windows file-offset boundary.
    #[test]
    fn resolved_file_range_rejects_signed_end_overflow() {
        assert!(super::ResolvedFileRange::new(FileOffset::from_bytes(4096), 0).is_ok());
        assert_eq!(
            super::ResolvedFileRange::new(FileOffset::from_bytes(i64::MAX.unsigned_abs()), 1,)
                .err(),
            Some(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when legacy disposition deletion can bypass orphan-lifecycle admission.
    #[test]
    fn disposition_delete_flag_rejects_deletion() {
        assert_eq!(super::validate_disposition_delete_flag(0), Ok(()));
        assert_eq!(
            super::validate_disposition_delete_flag(1),
            Err(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn flush_volume_rejects_unmounted_device_without_file_object() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let mut irp = wdk_sys::IRP::default();
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let target = target_from_stack(&mut stack, &mut irp, &mut device);
        assert!(target.is_ok());

        if let Ok(target) = target {
            assert_eq!(
                super::FlushVolume::decode(target).err(),
                Some(DriverError::InvalidDeviceRequest)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn directory_wildcard_pattern_matches_long_windows_names() {
        let pattern = super::DirectoryWildcardPattern::from_utf16(&[
            u16::from(b'f'),
            super::UTF16_ASTERISK,
            u16::from(b'.'),
            u16::from(b't'),
            u16::from(b'?'),
            u16::from(b't'),
        ]);
        assert!(pattern.is_ok());
        let Ok(pattern) = pattern else {
            return;
        };
        let matched = WindowsName::from_utf16(&[
            u16::from(b'f'),
            u16::from(b'i'),
            u16::from(b'l'),
            u16::from(b'e'),
            u16::from(b'.'),
            u16::from(b't'),
            u16::from(b'x'),
            u16::from(b't'),
        ]);
        assert!(matched.is_ok());
        let Ok(matched) = matched else {
            return;
        };
        let rejected = WindowsName::from_utf16(&[
            u16::from(b'f'),
            u16::from(b'i'),
            u16::from(b'l'),
            u16::from(b'e'),
            u16::from(b'.'),
            u16::from(b't'),
            u16::from(b'x'),
        ]);
        assert!(rejected.is_ok());
        let Ok(rejected) = rejected else {
            return;
        };

        assert!(pattern.matches(&matched));
        assert!(!pattern.matches(&rejected));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn directory_wildcard_pattern_rejects_non_name_units() {
        assert_eq!(
            super::DirectoryWildcardPattern::from_utf16(&[
                u16::from(b'a'),
                super::UTF16_BACKSLASH,
                super::UTF16_ASTERISK,
            ]),
            Err(DriverError::from(ext4_core::Error::InvalidName))
        );
        assert_eq!(
            super::DirectoryWildcardPattern::from_utf16(&[0xD800, super::UTF16_ASTERISK]),
            Err(DriverError::from(ext4_core::Error::InvalidName))
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rename_target_path_rejects_empty_and_root_only_names() {
        assert_eq!(
            super::NonEmptyWindowsPath::from_utf16_path(&[]),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            super::NonEmptyWindowsPath::from_utf16_path(&[super::UTF16_BACKSLASH]),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn opened_location_name_units_project_root_and_child_names() {
        let root_units: &[u16] = &[super::UTF16_BACKSLASH];
        let projected_root = super::opened_location_name_units(&OpenedLocation::Root);
        assert!(projected_root.is_ok());
        if let Ok(projected_root) = projected_root {
            assert_eq!(projected_root.as_slice(), root_units);
        }

        let name = Ext4Name::new(b"file");
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let location = OpenedLocation::DirectoryEntry {
            parent: DirectoryNodeId::ROOT,
            name,
        };
        let child_units: &[u16] = &[
            u16::from(b'f'),
            u16::from(b'i'),
            u16::from(b'l'),
            u16::from(b'e'),
        ];
        let projected_child = super::opened_location_name_units(&location);
        assert!(projected_child.is_ok());
        if let Ok(projected_child) = projected_child {
            assert_eq!(projected_child.as_slice(), child_units);
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn opened_location_name_units_rejects_file_reference_location() {
        assert_eq!(
            super::opened_location_name_units(&OpenedLocation::FileReference),
            Err(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_names_information_record_uses_name_only_layout() {
        let name = WindowsName::from_utf16(&[u16::from(b'a')]);
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let layout = super::DirectoryRecordLayout::new(DirectoryInformationClass::Names, &name);
        assert!(layout.is_ok());
        let Ok(layout) = layout else {
            return;
        };
        let mut buffer = [0_u8; 24];
        let metadata = test_metadata(super::FileMetadataKind::File);
        assert!(metadata.is_some());
        let Some(metadata) = metadata else {
            return;
        };

        let packed = super::pack_directory_record(
            &mut buffer,
            0,
            DirectoryInformationClass::Names,
            7,
            &name,
            metadata,
            layout,
        );
        assert!(packed.is_ok());

        assert_eq!(le_u32(&buffer, super::DIRECTORY_NEXT_ENTRY_OFFSET), Some(0));
        assert_eq!(le_u32(&buffer, super::DIRECTORY_FILE_INDEX_OFFSET), Some(7));
        assert_eq!(
            le_u32(&buffer, super::NAMES_INFORMATION_FILE_NAME_LENGTH_OFFSET),
            Some(2)
        );
        let name_bytes = buffer.get(super::NAMES_INFORMATION_NAME_OFFSET..24);
        assert!(name_bytes.is_some());
        let Some(name_bytes) = name_bytes else {
            return;
        };
        let expected_name: &[u8] = &[b'a', 0];
        assert_eq!(name_bytes.get(..2), Some(expected_name));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn reparse_metadata_controls_attribute_tag_and_file_attributes() {
        assert_eq!(super::reparse_tag(super::FileMetadataReparsePoint::None), 0);
        assert_eq!(
            super::reparse_tag(super::FileMetadataReparsePoint::SymbolicLink),
            wdk_sys::IO_REPARSE_TAG_SYMLINK
        );

        let metadata = test_metadata(super::FileMetadataKind::File);
        assert!(metadata.is_some());
        let Some(mut metadata) = metadata else {
            return;
        };
        metadata.reparse_point = super::FileMetadataReparsePoint::SymbolicLink;
        assert_ne!(
            super::file_attributes(metadata) & wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn disposition_ex_flags_reject_all_delete_semantics() {
        assert_eq!(super::validate_disposition_ex_flags(0), Ok(()));
        assert_eq!(
            super::validate_disposition_ex_flags(
                wdk_sys::FILE_DISPOSITION_DELETE | wdk_sys::FILE_DISPOSITION_ON_CLOSE
            ),
            Err(DriverError::NotSupported)
        );
        assert_eq!(
            super::validate_disposition_ex_flags(wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS),
            Err(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rename_ex_flags_decode_collision_and_reject_unsupported_semantics() {
        let mut input = [0_u8; super::FILE_RENAME_NAME_OFFSET + 2];
        assert!(put_le_u32(
            &mut input,
            super::FILE_RENAME_FLAGS_OFFSET,
            wdk_sys::FILE_RENAME_IGNORE_READONLY_ATTRIBUTE,
        ));
        assert_eq!(
            super::RenameInformationFormat::Flags.target_collision(&input),
            Ok(ext4_core::RenameTargetCollision::Reject)
        );

        assert!(put_le_u32(
            &mut input,
            super::FILE_RENAME_FLAGS_OFFSET,
            wdk_sys::FILE_RENAME_REPLACE_IF_EXISTS,
        ));
        assert_eq!(
            super::RenameInformationFormat::Flags.target_collision(&input),
            Ok(ext4_core::RenameTargetCollision::Replace)
        );

        assert!(put_le_u32(
            &mut input,
            super::FILE_RENAME_FLAGS_OFFSET,
            wdk_sys::FILE_RENAME_POSIX_SEMANTICS,
        ));
        assert_eq!(
            super::RenameInformationFormat::Flags.target_collision(&input),
            Err(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rename_root_directory_field_is_not_supported() {
        let mut input = [0_u8; super::FILE_RENAME_ROOT_DIRECTORY_OFFSET + 8];
        let Some(root_directory) = input.get_mut(
            super::FILE_RENAME_ROOT_DIRECTORY_OFFSET
                ..super::FILE_RENAME_ROOT_DIRECTORY_OFFSET
                    + core::mem::size_of::<wdk_sys::HANDLE>(),
        ) else {
            return;
        };
        let Some(first_byte) = root_directory.get_mut(0) else {
            return;
        };
        *first_byte = 1;

        assert_eq!(
            super::reject_root_directory(&input),
            Err(DriverError::NotSupported)
        );
    }
    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rename_replace_flag_decode_boundary_selects_replace_collision() {
        let mut input = [0_u8; super::FILE_RENAME_NAME_OFFSET + 2];
        let Some(replace_flag) = input.get_mut(super::FILE_RENAME_REPLACE_IF_EXISTS_OFFSET) else {
            return;
        };
        *replace_flag = 1;
        let name_length = input.get_mut(
            super::FILE_RENAME_NAME_LENGTH_OFFSET
                ..super::FILE_RENAME_NAME_LENGTH_OFFSET + core::mem::size_of::<u32>(),
        );
        assert!(
            name_length.is_some(),
            "test rename buffer contains the name length field"
        );
        let Some(name_length) = name_length else {
            return;
        };
        name_length.copy_from_slice(&2_u32.to_le_bytes());
        let name =
            input.get_mut(super::FILE_RENAME_NAME_OFFSET..super::FILE_RENAME_NAME_OFFSET + 2);
        assert!(
            name.is_some(),
            "test rename buffer contains the first UTF-16 code unit"
        );
        let Some(name) = name else {
            return;
        };
        name.copy_from_slice(&u16::from(b'a').to_le_bytes());

        let mut file_object = wdk_sys::FILE_OBJECT::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: core::ptr::addr_of_mut!(file_object),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.SetFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10 {
            Length: u32::try_from(input.len()).unwrap_or(u32::MAX),
            __bindgen_padding_0: 0,
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformation,
            FileObject: core::ptr::null_mut(),
            __bindgen_anon_1:
                wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10__bindgen_ty_1::default(),
        };

        let mut irp = wdk_sys::IRP::default();
        irp.AssociatedIrp.SystemBuffer = input.as_mut_ptr().cast();
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack);

        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let target = DispatchTarget::decode(
            core::ptr::addr_of_mut!(device),
            core::ptr::addr_of_mut!(irp),
        );
        assert!(target.is_ok());
        if let Ok(target) = target {
            let stack = target.current_stack().and_then(|stack| stack.set_file());
            assert!(stack.is_ok());
            let Ok(stack) = stack else {
                return;
            };
            let parsed = super::RenameTargetPath::parse(
                target,
                stack.length(),
                super::RenameInformationFormat::ReplaceIfExistsByte,
            );
            assert!(parsed.is_ok());
            if let Ok(parsed) = parsed {
                assert_eq!(
                    parsed.target_collision(),
                    ext4_core::RenameTargetCollision::Replace
                );
            }
        }
    }
}
