//! File object IRP handlers and file information packing boundary.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{
    ChildLookup, DirectoryEntry, DirectoryNodeId, Ext4Name, Ext4Security, Ext4Times, Ext4Timestamp,
    Ext4WindowsAttributes, FileNodeId, FileSize, InodeId, LoadedNode, NodeId, WindowsName,
    WindowsOverlay,
};
use wdk_sys::{LARGE_INTEGER, NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_SUCCESS};

use crate::irp::{
    DirectoryCursorPosition, DirectoryEntryEmission, DirectoryInformationClass,
    DirectoryPatternInput, DispatchTarget, IrpBufferLength, QueryDirectoryStack,
    QueryFileInformationClass, QueryFileStack, SetFileInformationClass, SetFileStack,
};
use crate::state::{
    CloseDisposition, ContextControlBlock, DirectoryCursor, FileControlBlock, OpenedPath,
    VolumeControlBlock, context_control_block, file_control_block, release_file_control_block,
};
use crate::status::{DriverError, DriverResult};
use crate::wire::{CheckedByteRange, LittleEndianInput, LittleEndianOutput};

/// Handles cleanup IRPs.
pub(crate) fn cleanup(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(|target| target.current_stack()) {
        Ok(stack) => match stack.file_object() {
            Ok(file_object) => match cleanup_file_object(file_object) {
                Ok(()) => STATUS_SUCCESS,
                Err(error) => error.ntstatus(),
            },
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Handles close IRPs and releases FILE_OBJECT contexts.
pub(crate) fn close(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(|target| target.current_stack()) {
        Ok(stack) => match stack.file_object() {
            Ok(file_object) => {
                release_file_contexts(file_object);
                STATUS_SUCCESS
            }
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Handles regular file data reads.
pub(crate) fn read(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(read_regular_file) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => error.ntstatus(),
    }
}

/// Handles regular file data writes.
pub(crate) fn write(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(write_regular_file) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => error.ntstatus(),
    }
}

/// Flushes cached or ordered file data.
pub(crate) fn flush(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(_target) => STATUS_SUCCESS,
        Err(error) => error.ntstatus(),
    }
}

/// Handles file information queries.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(QueryFileRequest::decode) {
        Ok(request) => query_file_information(request),
        Err(error) => error.ntstatus(),
    }
}

/// Handles file information mutations.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(SetFileRequest::decode) {
        Ok(request) => set_file_information(request),
        Err(error) => error.ntstatus(),
    }
}

/// Handles directory enumeration and notification.
pub(crate) fn directory_control(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => match target.current_stack() {
            Ok(stack) if u32::from(stack.minor_function()) == wdk_sys::IRP_MN_QUERY_DIRECTORY => {
                query_directory(target)
            }
            Ok(stack)
                if u32::from(stack.minor_function()) == wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY
                    || u32::from(stack.minor_function())
                        == wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX =>
            {
                DriverError::NotSupported.ntstatus()
            }
            Ok(_) => DriverError::InvalidDeviceRequest.ntstatus(),
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Handles byte-range lock requests.
pub(crate) fn lock_control(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Rejects a decoded file-object request until its domain path exists.
fn decoded_not_supported(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            let _device = target.device();
            let _irp = target.irp();
            DriverError::NotSupported.ntstatus()
        }
        Err(error) => error.ntstatus(),
    }
}

/// Decoded query-file-information request.
#[derive(Clone, Copy, Debug)]
struct QueryFileRequest {
    /// Dispatch target receiving the query.
    target: DispatchTarget,
    /// Decoded query stack.
    stack: QueryFileStack,
}

impl QueryFileRequest {
    /// Decodes a query-file-information request.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        Ok(Self {
            target,
            stack: target.current_stack()?.query_file()?,
        })
    }
}

/// Decoded set-file-information request.
#[derive(Clone, Copy, Debug)]
struct SetFileRequest {
    /// Dispatch target receiving the mutation.
    target: DispatchTarget,
    /// Decoded set stack.
    stack: SetFileStack,
}

impl SetFileRequest {
    /// Decodes a set-file-information request.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        Ok(Self {
            target,
            stack: target.current_stack()?.set_file()?,
        })
    }
}

/// Decoded query-directory request.
#[derive(Clone, Copy, Debug)]
struct QueryDirectoryRequest {
    /// Dispatch target receiving the query.
    target: DispatchTarget,
    /// Decoded query-directory stack.
    stack: QueryDirectoryStack,
}

impl QueryDirectoryRequest {
    /// Decodes a query-directory request.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        Ok(Self {
            target,
            stack: target.current_stack()?.query_directory()?,
        })
    }
}

/// Handles fixed-size file information queries.
fn query_file_information(request: QueryFileRequest) -> NTSTATUS {
    match pack_file_information(request) {
        Ok(information) => {
            request.target.set_information(information);
            STATUS_SUCCESS
        }
        Err(error) => error.ntstatus(),
    }
}

/// Packs one supported file information class.
fn pack_file_information(request: QueryFileRequest) -> DriverResult<wdk_sys::ULONG_PTR> {
    let metadata = load_file_metadata(request.stack.file_object())?;
    let buffer = request
        .target
        .system_buffer()
        .ok_or(DriverError::InvalidParameter)?;
    let length = request.stack.length().as_usize();
    match request.stack.information_class() {
        QueryFileInformationClass::Basic => pack_basic_information(buffer, length, metadata),
        QueryFileInformationClass::Standard => pack_standard_information(buffer, length, metadata),
        QueryFileInformationClass::Internal => pack_internal_information(buffer, length, metadata),
        QueryFileInformationClass::Position => {
            pack_position_information(buffer, length, request.stack.file_object())
        }
        QueryFileInformationClass::NetworkOpen => {
            pack_network_open_information(buffer, length, metadata)
        }
    }
}

/// Handles supported file information mutations.
fn set_file_information(request: SetFileRequest) -> NTSTATUS {
    match apply_file_information(request) {
        Ok(()) => {
            request.target.set_information(0);
            STATUS_SUCCESS
        }
        Err(error) => error.ntstatus(),
    }
}

/// Applies one supported set-file-information class.
fn apply_file_information(request: SetFileRequest) -> DriverResult<()> {
    match request.stack.information_class() {
        SetFileInformationClass::Basic => set_basic_information(request),
        SetFileInformationClass::EndOfFile => set_end_of_file_information(request),
        SetFileInformationClass::Allocation => set_allocation_information(request),
        SetFileInformationClass::Disposition => set_disposition_information(request),
        SetFileInformationClass::DispositionEx => Err(DriverError::NotSupported),
        SetFileInformationClass::Rename => set_rename_information(request),
        SetFileInformationClass::RenameEx => Err(DriverError::NotSupported),
    }
}

/// Applies FILE_BASIC_INFORMATION timestamps and overlay attributes.
fn set_basic_information(request: SetFileRequest) -> DriverResult<()> {
    let info = read_file_information_input::<wdk_sys::FILE_BASIC_INFORMATION>(
        request.target,
        request.stack.length(),
    )?;
    let metadata = load_file_metadata(request.stack.file_object())?;
    let times = set_basic_times(metadata.times, info)?;
    let overlay = set_basic_overlay(metadata, info.FileAttributes)?;
    if times == metadata.times && overlay.is_none() {
        return Ok(());
    }

    let context = opened_file_context(request.stack.file_object())?;
    let mut vcb = context.volume;
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this synchronous metadata mutation.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::time::current_ext4_timestamp()?);
    let node = transaction.node(context.node)?;
    if times != metadata.times {
        transaction.set_times(node, times)?;
    }
    if let Some(overlay) = overlay {
        transaction.set_windows_overlay(node, overlay)?;
    }
    transaction.commit()?;
    Ok(())
}

/// Applies FILE_END_OF_FILE_INFORMATION to a regular file.
fn set_end_of_file_information(request: SetFileRequest) -> DriverResult<()> {
    let info = read_file_information_input::<wdk_sys::FILE_END_OF_FILE_INFORMATION>(
        request.target,
        request.stack.length(),
    )?;
    set_regular_file_size(
        request.stack.file_object(),
        file_size_from_large_integer(info.EndOfFile)?,
    )
}

/// Applies FILE_ALLOCATION_INFORMATION within the ext4 sparse-file model.
fn set_allocation_information(request: SetFileRequest) -> DriverResult<()> {
    let info = read_file_information_input::<wdk_sys::FILE_ALLOCATION_INFORMATION>(
        request.target,
        request.stack.length(),
    )?;
    let requested = file_size_from_large_integer(info.AllocationSize)?;
    let context = opened_file_context(request.stack.file_object())?;
    let NodeId::File(file_id) = context.node else {
        return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
    };
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open.
        context.volume.as_ref()
    };
    let current = regular_file_size(vcb, file_id)?;
    if requested >= current {
        return Ok(());
    }
    set_regular_file_size(request.stack.file_object(), requested)
}

/// Applies FILE_DISPOSITION_INFORMATION to the handle-local close disposition.
fn set_disposition_information(request: SetFileRequest) -> DriverResult<()> {
    let info = read_file_information_input::<wdk_sys::FILE_DISPOSITION_INFORMATION>(
        request.target,
        request.stack.length(),
    )?;
    let mut ccb = context_control_block(request.stack.file_object())?;
    let ccb = unsafe {
        // SAFETY: Successful create stores Box<ContextControlBlock> in
        // FsContext2 until close releases it, and this mutation runs while the
        // FILE_OBJECT is active.
        ccb.as_mut()
    };
    if info.DeleteFile == 0 {
        ccb.keep_on_close();
    } else {
        ccb.mark_delete_on_close();
    }
    Ok(())
}

/// Applies FILE_RENAME_INFORMATION to the opened path.
fn set_rename_information(request: SetFileRequest) -> DriverResult<()> {
    let rename = RenameInformation::parse(request.target, request.stack.length())?;

    let fcb = file_control_block(request.stack.file_object())?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this mutation runs while the
        // FILE_OBJECT is active.
        fcb.as_ref()
    };
    let mut ccb = context_control_block(request.stack.file_object())?;
    let ccb = unsafe {
        // SAFETY: Successful create stores Box<ContextControlBlock> in
        // FsContext2 until close releases it, and this mutation runs while the
        // FILE_OBJECT is active.
        ccb.as_mut()
    };
    let OpenedPath::Child {
        parent: source_parent,
        name: source_name,
    } = ccb.path().clone()
    else {
        return Err(DriverError::from(ext4_core::Error::CannotRemoveRoot));
    };

    let mut vcb = fcb.volume();
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this rename request.
        vcb.as_mut()
    };
    let (target_parent, target_name) = resolve_rename_target(vcb, &rename.name)?;
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::time::current_ext4_timestamp()?);
    let source_parent = transaction.directory(source_parent)?;
    let target_parent = transaction.directory(target_parent)?;
    transaction.rename_child(source_parent, &source_name, target_parent, &target_name)?;
    transaction.commit()?;
    ccb.replace_path(OpenedPath::Child {
        parent: target_parent.id(),
        name: target_name,
    });
    Ok(())
}

/// Sets a regular file size by extending sparse or truncating allocated ranges.
fn set_regular_file_size(
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    new_size: FileSize,
) -> DriverResult<()> {
    let context = opened_file_context(file_object)?;
    let NodeId::File(file_id) = context.node else {
        return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
    };
    let mut vcb = context.volume;
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
        .begin_transaction(crate::time::current_ext4_timestamp()?);
    let file = transaction.file(file_id)?;
    if new_size > current {
        transaction.extend_file(file, new_size)?;
    } else {
        transaction.truncate_file(file, new_size)?;
    }
    transaction.commit()?;
    Ok(())
}

/// Handles directory enumeration queries.
fn query_directory(target: DispatchTarget) -> NTSTATUS {
    match QueryDirectoryRequest::decode(target) {
        Ok(request) => match pack_directory_information(request) {
            Ok(information) => {
                target.set_information(information);
                STATUS_SUCCESS
            }
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Packs directory entries into the caller's query-directory buffer.
fn pack_directory_information(request: QueryDirectoryRequest) -> DriverResult<wdk_sys::ULONG_PTR> {
    let class = request.stack.information_class();
    let pattern = DirectoryPattern::from_stack(request.stack)?;
    let length = request.stack.length().as_usize();
    let mut buffer = request.target.data_buffer(length)?;
    let buffer = buffer.as_mut_slice();

    let fcb = file_control_block(request.stack.file_object())?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this query runs while the FILE_OBJECT is
        // active.
        fcb.as_ref()
    };
    let vcb = volume_control_block(fcb);
    let NodeId::Directory(directory_id) = fcb.node() else {
        return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
    };
    let directory = match vcb.volume().load_node(directory_id.inode())? {
        LoadedNode::Directory(directory) => directory,
        LoadedNode::File(_) | LoadedNode::Symlink(_) => {
            return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
        }
    };
    let entries = vcb.volume().read_directory(&directory)?;

    let mut ccb = context_control_block(request.stack.file_object())?;
    let ccb = unsafe {
        // SAFETY: Successful create stores Box<ContextControlBlock> in
        // FsContext2 until close releases it, and this query runs while the
        // FILE_OBJECT is active.
        ccb.as_mut()
    };
    let Some(cursor) = ccb.directory_cursor_mut() else {
        return Err(DriverError::InvalidParameter);
    };
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
    wdk_sys::ULONG_PTR::try_from(result).map_err(|_| DriverError::InvalidParameter)
}

impl DirectoryInformationClass {
    /// Returns the byte offset where the UTF-16 file name starts.
    const fn name_offset(self) -> usize {
        match self {
            Self::Directory => DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::Full => FULL_DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::Both => BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
        }
    }
}

/// Caller-supplied directory filename pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
enum DirectoryPattern {
    /// Enumerate every Windows-representable ext4 entry.
    All,
    /// Return the entry with this exact Windows name.
    Exact(WindowsName),
}

impl DirectoryPattern {
    /// Decodes the optional QueryDirectory filename pattern.
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
            return Err(DriverError::NotSupported);
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
        }
    }

    /// Returns the no-entry status for this pattern.
    const fn exhausted_error(&self) -> DriverError {
        match self {
            Self::All => DriverError::NoMoreFiles,
            Self::Exact(_) => DriverError::NoSuchFile,
        }
    }
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
        DirectoryCursorPosition::Restart => cursor.seek(0),
        DirectoryCursorPosition::Index(index) => cursor.seek(index.as_u32()),
    }
}

/// Emits directory entries into a caller buffer.
fn emit_directory_entries(
    vcb: &VolumeControlBlock,
    cursor: &mut DirectoryCursor,
    stack: QueryDirectoryStack,
    class: DirectoryInformationClass,
    pattern: &DirectoryPattern,
    entries: &[DirectoryEntry],
    buffer: &mut [u8],
) -> DriverResult<usize> {
    let start = usize::try_from(cursor.next_entry()).map_err(|_| DriverError::InvalidParameter)?;
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
            cursor.seek(next_entry);
            continue;
        };
        if !pattern.matches(&name) {
            cursor.seek(next_entry);
            continue;
        }

        let node = vcb.volume().load_node(entry.inode())?;
        let metadata = metadata_from_node(vcb, node.id(), node)?;
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
                field_offset(previous_start, DIRECTORY_NEXT_ENTRY_OFFSET)?,
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
        cursor.seek(next_entry);

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
        .write_u32(field_offset(start, DIRECTORY_NEXT_ENTRY_OFFSET)?, 0)?;
    LittleEndianOutput::new(buffer).write_u32(
        field_offset(start, DIRECTORY_FILE_INDEX_OFFSET)?,
        file_index,
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        field_offset(start, DIRECTORY_CREATION_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.created()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        field_offset(start, DIRECTORY_LAST_ACCESS_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.accessed()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        field_offset(start, DIRECTORY_LAST_WRITE_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.modified()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        field_offset(start, DIRECTORY_CHANGE_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.changed()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        field_offset(start, DIRECTORY_END_OF_FILE_OFFSET)?,
        &signed_i64(metadata.size.bytes())?.to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        field_offset(start, DIRECTORY_ALLOCATION_SIZE_OFFSET)?,
        &signed_i64(allocation_size(metadata)?)?.to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_u32(
        field_offset(start, DIRECTORY_FILE_ATTRIBUTES_OFFSET)?,
        file_attributes(metadata),
    )?;
    LittleEndianOutput::new(buffer).write_u32(
        field_offset(start, DIRECTORY_FILE_NAME_LENGTH_OFFSET)?,
        u32::try_from(utf16_byte_len(name.utf16())?).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    match class {
        DirectoryInformationClass::Directory => {}
        DirectoryInformationClass::Full => {
            LittleEndianOutput::new(buffer)
                .write_u32(field_offset(start, DIRECTORY_EA_SIZE_OFFSET)?, 0)?;
        }
        DirectoryInformationClass::Both => {
            LittleEndianOutput::new(buffer)
                .write_u32(field_offset(start, DIRECTORY_EA_SIZE_OFFSET)?, 0)?;
            LittleEndianOutput::new(buffer).write_u8(
                field_offset(start, BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET)?,
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
fn clear_record(buffer: &mut [u8], start: usize, length: usize) -> DriverResult<()> {
    let record = mutable_bytes(buffer, start, length)?;
    record.fill(0);
    Ok(())
}

/// Writes UTF-16 code units as Windows little-endian bytes.
fn write_utf16(buffer: &mut [u8], offset: usize, units: &[u16]) -> DriverResult<()> {
    let mut cursor = offset;
    for unit in units {
        LittleEndianOutput::new(buffer).write_u16(cursor, *unit)?;
        cursor = cursor.checked_add(2).ok_or(DriverError::InvalidParameter)?;
    }
    Ok(())
}

/// Returns a checked mutable byte range.
fn mutable_bytes(buffer: &mut [u8], offset: usize, length: usize) -> DriverResult<&mut [u8]> {
    let range = CheckedByteRange::new(offset, length)?;
    range
        .write_to(buffer)
        .map_err(|_| DriverError::BufferOverflow)
}

/// Computes an absolute field offset from a record start.
fn field_offset(start: usize, offset: usize) -> DriverResult<usize> {
    start
        .checked_add(offset)
        .ok_or(DriverError::InvalidParameter)
}

/// Returns the byte count for UTF-16 code units.
fn utf16_byte_len(units: &[u16]) -> DriverResult<usize> {
    units
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)
}

/// Aligns a directory record size to an eight-byte boundary.
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

/// Applies cleanup-time namespace mutations requested by this handle.
fn cleanup_file_object(file_object: NonNull<wdk_sys::FILE_OBJECT>) -> DriverResult<()> {
    let fcb = file_control_block(file_object)?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and cleanup runs while the FILE_OBJECT is
        // active.
        fcb.as_ref()
    };
    let mut ccb = context_control_block(file_object)?;
    let ccb = unsafe {
        // SAFETY: Successful create stores Box<ContextControlBlock> in
        // FsContext2 until close releases it, and cleanup runs while the
        // FILE_OBJECT is active.
        ccb.as_mut()
    };
    if ccb.close_disposition() == CloseDisposition::Keep {
        return Ok(());
    }
    let OpenedPath::Child { parent, name } = ccb.path().clone() else {
        return Err(DriverError::from(ext4_core::Error::CannotRemoveRoot));
    };

    let mut vcb = fcb.volume();
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this cleanup namespace mutation.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::time::current_ext4_timestamp()?);
    let parent = transaction.directory(parent)?;
    match fcb.node() {
        NodeId::File(_) => transaction.unlink_file(parent, &name)?,
        NodeId::Directory(_) => transaction.remove_empty_directory(parent, &name)?,
        NodeId::Symlink(_) => transaction.remove_symlink(parent, &name)?,
    }
    transaction.commit()?;
    ccb.keep_on_close();
    Ok(())
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
fn opened_file_context(
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
) -> Result<OpenedFileContext, DriverError> {
    let fcb = file_control_block(file_object)?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this access runs while the FILE_OBJECT
        // is active.
        fcb.as_ref()
    };
    Ok(OpenedFileContext {
        volume: fcb.volume(),
        node: fcb.node(),
    })
}

/// Reads a fixed-size set-information input structure.
fn read_file_information_input<T: Copy>(
    target: DispatchTarget,
    length: IrpBufferLength,
) -> DriverResult<T> {
    let length = length.as_usize();
    let buffer = system_buffer_input(target, length)?;
    let size = core::mem::size_of::<T>();
    if length < size {
        return Err(DriverError::BufferTooSmall);
    }
    Ok(unsafe {
        // SAFETY: The set-information system buffer is at least `size` bytes
        // and is copied out immediately. Unaligned read avoids imposing a
        // stronger alignment contract on the I/O Manager buffer.
        buffer.address.cast::<T>().as_ptr().read_unaligned()
    })
}

/// Immutable system buffer view for set-information parsing.
#[derive(Clone, Copy, Debug)]
struct SystemBufferInput {
    /// First byte of the system buffer.
    address: NonNull<u8>,
    /// Byte length supplied by the IRP stack.
    length: usize,
}

impl SystemBufferInput {
    /// Returns the system buffer as bytes.
    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: SystemBufferInput is constructed only after the active
            // IRP exposes a kernel-addressable system buffer for `length`
            // bytes. The returned slice is consumed within this dispatch path.
            core::slice::from_raw_parts(self.address.as_ptr(), self.length)
        }
    }
}

/// Returns a checked immutable view of the set-information system buffer.
fn system_buffer_input(target: DispatchTarget, length: usize) -> DriverResult<SystemBufferInput> {
    let address = target
        .system_buffer()
        .ok_or(DriverError::InvalidParameter)?
        .cast::<u8>();
    let max_slice_len = usize::try_from(isize::MAX).map_err(|_| DriverError::InvalidParameter)?;
    if length > max_slice_len {
        return Err(DriverError::InvalidParameter);
    }
    Ok(SystemBufferInput { address, length })
}

/// Decoded FILE_RENAME_INFORMATION payload.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RenameInformation {
    /// Root-relative target path components.
    name: Vec<WindowsName>,
}

impl RenameInformation {
    /// Decodes a FILE_RENAME_INFORMATION variable-length input buffer.
    fn parse(target: DispatchTarget, length: IrpBufferLength) -> DriverResult<Self> {
        let length = length.as_usize();
        let input = system_buffer_input(target, length)?;
        let bytes = input.as_slice();
        match bytes
            .get(FILE_RENAME_REPLACE_IF_EXISTS_OFFSET)
            .ok_or(DriverError::BufferTooSmall)?
        {
            0 => {}
            _ => return Err(DriverError::NotSupported),
        }
        if root_directory_is_present(bytes)? {
            return Err(DriverError::NotSupported);
        }
        let name_length = usize::try_from(
            LittleEndianInput::new(bytes).read_u32(FILE_RENAME_NAME_LENGTH_OFFSET)?,
        )
        .map_err(|_| DriverError::InvalidParameter)?;
        if name_length == 0 || name_length & 1 != 0 {
            return Err(DriverError::InvalidParameter);
        }
        let name_bytes = input_range(bytes, FILE_RENAME_NAME_OFFSET, name_length)?;
        let units = utf16_units_from_le_bytes(name_bytes)?;
        Ok(Self {
            name: windows_path_components(&units)?,
        })
    }
}

/// Offset of FILE_RENAME_INFORMATION ReplaceIfExists.
const FILE_RENAME_REPLACE_IF_EXISTS_OFFSET: usize = 0;
/// Offset of FILE_RENAME_INFORMATION RootDirectory.
const FILE_RENAME_ROOT_DIRECTORY_OFFSET: usize = 8;
/// Offset of FILE_RENAME_INFORMATION FileNameLength.
const FILE_RENAME_NAME_LENGTH_OFFSET: usize = 16;
/// Offset of FILE_RENAME_INFORMATION FileName.
const FILE_RENAME_NAME_OFFSET: usize = 20;
/// UTF-16 backslash separator.
const UTF16_BACKSLASH: u16 = 0x005C;

/// Returns true when FILE_RENAME_INFORMATION carries an unsupported root handle.
fn root_directory_is_present(bytes: &[u8]) -> DriverResult<bool> {
    Ok(input_range(
        bytes,
        FILE_RENAME_ROOT_DIRECTORY_OFFSET,
        core::mem::size_of::<wdk_sys::HANDLE>(),
    )?
    .iter()
    .any(|byte| *byte != 0))
}

/// Decodes little-endian UTF-16 units from a byte buffer.
fn utf16_units_from_le_bytes(bytes: &[u8]) -> DriverResult<Vec<u16>> {
    if bytes.len() & 1 != 0 {
        return Err(DriverError::InvalidParameter);
    }
    let mut units = Vec::new();
    for chunk in bytes.chunks_exact(core::mem::size_of::<u16>()) {
        let unit = u16::from_le_bytes(
            chunk
                .try_into()
                .map_err(|_| DriverError::InvalidParameter)?,
        );
        units.push(unit);
    }
    Ok(units)
}

/// Splits a root-relative UTF-16 path into validated Windows components.
fn windows_path_components(units: &[u16]) -> DriverResult<Vec<WindowsName>> {
    let mut trimmed = units;
    while let Some(rest) = trimmed.strip_prefix(&[UTF16_BACKSLASH]) {
        trimmed = rest;
    }
    if trimmed.is_empty() {
        return Err(DriverError::InvalidParameter);
    }
    let mut components = Vec::new();
    for component in trimmed.split(|unit| *unit == UTF16_BACKSLASH) {
        components.push(WindowsName::from_utf16(component)?);
    }
    Ok(components)
}

/// Resolves the target parent directory and final ext4 name for a rename.
fn resolve_rename_target(
    vcb: &VolumeControlBlock,
    components: &[WindowsName],
) -> DriverResult<(DirectoryNodeId, Ext4Name)> {
    let (target_name, parents) = components
        .split_last()
        .ok_or(DriverError::InvalidParameter)?;
    let mut parent_id = DirectoryNodeId::ROOT;
    for component in parents {
        let parent = match vcb.volume().load_node(parent_id.inode())? {
            LoadedNode::Directory(directory) => directory,
            LoadedNode::File(_) | LoadedNode::Symlink(_) => {
                return Err(DriverError::ObjectPathNotFound);
            }
        };
        let child = vcb.volume().lookup_windows_child(&parent, component)?;
        match child {
            ChildLookup::Found(child) => {
                let NodeId::Directory(directory_id) = *child.node() else {
                    return Err(DriverError::ObjectPathNotFound);
                };
                parent_id = directory_id;
            }
            ChildLookup::NotFound => return Err(DriverError::ObjectPathNotFound),
        };
    }
    Ok((parent_id, target_name.to_ext4()?))
}

/// Returns an immutable checked input byte range.
fn input_range(bytes: &[u8], offset: usize, length: usize) -> DriverResult<&[u8]> {
    let range = CheckedByteRange::new(offset, length)?;
    range.read_from(bytes)
}

/// Builds a complete ext4 timestamp set from FILE_BASIC_INFORMATION.
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
        crate::ffi::RtlTimeToSecondsSince1970(
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

/// Builds overlay metadata from FILE_BASIC_INFORMATION attributes.
fn set_basic_overlay(
    metadata: FileMetadata,
    attributes: wdk_sys::ULONG,
) -> DriverResult<Option<WindowsOverlay>> {
    if attributes == 0 {
        return Ok(None);
    }
    validate_kind_attribute(metadata.kind, attributes)?;
    let current_readonly = metadata.security.permissions().as_u16() & 0o222 == 0;
    let requested_readonly = attributes & wdk_sys::FILE_ATTRIBUTE_READONLY != 0;
    if requested_readonly != current_readonly {
        return Err(DriverError::NotSupported);
    }

    let accepted = Ext4WindowsAttributes::SUPPORTED_MASK
        | wdk_sys::FILE_ATTRIBUTE_READONLY
        | wdk_sys::FILE_ATTRIBUTE_NORMAL
        | wdk_sys::FILE_ATTRIBUTE_DIRECTORY
        | wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT;
    if attributes & !accepted != 0 {
        return Err(DriverError::NotSupported);
    }

    let overlay_bits = attributes & Ext4WindowsAttributes::SUPPORTED_MASK;
    if overlay_bits == metadata.overlay_attributes {
        return Ok(None);
    }
    let attributes = Ext4WindowsAttributes::new(overlay_bits)?;
    Ok(Some(WindowsOverlay::new(attributes)))
}

/// Rejects node-kind attributes that contradict the opened ext4 node.
fn validate_kind_attribute(kind: FileMetadataKind, attributes: wdk_sys::ULONG) -> DriverResult<()> {
    if attributes & wdk_sys::FILE_ATTRIBUTE_DIRECTORY != 0 && kind != FileMetadataKind::Directory {
        return Err(DriverError::InvalidParameter);
    }
    if attributes & wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT != 0 && kind != FileMetadataKind::Symlink
    {
        return Err(DriverError::InvalidParameter);
    }
    Ok(())
}

/// Returns a non-negative file size from a Windows LARGE_INTEGER.
fn file_size_from_large_integer(value: LARGE_INTEGER) -> DriverResult<FileSize> {
    let value = large_integer_quad(value);
    if value < 0 {
        return Err(DriverError::InvalidParameter);
    }
    Ok(FileSize::from_bytes(
        u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?,
    ))
}

/// Returns the current size of a regular file inode.
fn regular_file_size(vcb: &VolumeControlBlock, file_id: FileNodeId) -> DriverResult<FileSize> {
    match vcb.volume().load_node(file_id.inode())? {
        LoadedNode::File(file) => Ok(file.size()),
        LoadedNode::Directory(_) | LoadedNode::Symlink(_) => {
            Err(DriverError::from(ext4_core::Error::WrongInodeKind))
        }
    }
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
    /// Stable ext4 inode id.
    inode: InodeId,
    /// Open node kind.
    kind: FileMetadataKind,
    /// Payload size in bytes.
    size: FileSize,
    /// POSIX security metadata.
    security: Ext4Security,
    /// ext4 inode timestamps.
    times: Ext4Times,
    /// ext4 inode link count.
    links_count: u16,
    /// Windows-specific overlay attributes.
    overlay_attributes: u32,
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

/// Loads metadata for the file object currently being queried.
fn load_file_metadata(file_object: NonNull<wdk_sys::FILE_OBJECT>) -> DriverResult<FileMetadata> {
    let fcb = file_control_block(file_object)?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this query runs while the FILE_OBJECT is
        // active.
        fcb.as_ref()
    };
    let vcb = volume_control_block(fcb);
    let node_id = fcb.node();
    let node = vcb.volume().load_node(node_id.inode())?;
    let metadata = metadata_from_node(vcb, node_id, node)?;
    if fcb_node_matches_metadata(fcb.node(), metadata.kind) {
        Ok(metadata)
    } else {
        Err(DriverError::Core(ext4_core::Error::WrongInodeKind))
    }
}

/// Returns true when an FCB node identity still matches loaded core metadata.
const fn fcb_node_matches_metadata(node: NodeId, kind: FileMetadataKind) -> bool {
    matches!(
        (node, kind),
        (NodeId::File(_), FileMetadataKind::File)
            | (NodeId::Directory(_), FileMetadataKind::Directory)
            | (NodeId::Symlink(_), FileMetadataKind::Symlink)
    )
}

/// Builds Windows-facing metadata from a loaded ext4 node.
fn metadata_from_node(
    vcb: &VolumeControlBlock,
    node_id: NodeId,
    node: LoadedNode,
) -> DriverResult<FileMetadata> {
    let inode = node_id.inode();
    let overlay_attributes = vcb
        .volume()
        .read_windows_overlay(inode)?
        .map(|overlay| overlay.attributes().bits())
        .unwrap_or(0);

    let block_size = vcb.volume().superblock().block_size();
    match node {
        LoadedNode::File(file) => Ok(FileMetadata {
            inode,
            kind: FileMetadataKind::File,
            size: file.size(),
            security: file.security(),
            times: file.times(),
            links_count: file.links_count(),
            overlay_attributes,
            block_size,
        }),
        LoadedNode::Directory(directory) => Ok(FileMetadata {
            inode,
            kind: FileMetadataKind::Directory,
            size: directory.size(),
            security: directory.security(),
            times: directory.times(),
            links_count: directory.links_count(),
            overlay_attributes,
            block_size,
        }),
        LoadedNode::Symlink(symlink) => Ok(FileMetadata {
            inode,
            kind: FileMetadataKind::Symlink,
            size: symlink.size(),
            security: symlink.security(),
            times: symlink.times(),
            links_count: symlink.links_count(),
            overlay_attributes,
            block_size,
        }),
    }
}

/// Packs FILE_BASIC_INFORMATION.
fn pack_basic_information(
    buffer: NonNull<c_void>,
    length: usize,
    metadata: FileMetadata,
) -> DriverResult<wdk_sys::ULONG_PTR> {
    write_fixed(
        buffer,
        length,
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
fn pack_standard_information(
    buffer: NonNull<c_void>,
    length: usize,
    metadata: FileMetadata,
) -> DriverResult<wdk_sys::ULONG_PTR> {
    write_fixed(
        buffer,
        length,
        wdk_sys::FILE_STANDARD_INFORMATION {
            AllocationSize: large_integer_from_u64(allocation_size(metadata)?)?,
            EndOfFile: large_integer_from_u64(metadata.size.bytes())?,
            NumberOfLinks: wdk_sys::ULONG::from(metadata.links_count),
            DeletePending: boolean(false),
            Directory: boolean(metadata.kind == FileMetadataKind::Directory),
        },
    )
}

/// Packs FILE_INTERNAL_INFORMATION.
fn pack_internal_information(
    buffer: NonNull<c_void>,
    length: usize,
    metadata: FileMetadata,
) -> DriverResult<wdk_sys::ULONG_PTR> {
    write_fixed(
        buffer,
        length,
        wdk_sys::FILE_INTERNAL_INFORMATION {
            IndexNumber: LARGE_INTEGER {
                QuadPart: i64::from(metadata.inode.as_u32()),
            },
        },
    )
}

/// Packs FILE_POSITION_INFORMATION.
fn pack_position_information(
    buffer: NonNull<c_void>,
    length: usize,
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
) -> DriverResult<wdk_sys::ULONG_PTR> {
    let file_object = unsafe {
        // SAFETY: The FILE_OBJECT pointer comes from the active IRP stack and
        // is read only for the current byte offset field.
        file_object.as_ref()
    };
    let current = unsafe {
        // SAFETY: CurrentByteOffset is read through its QuadPart arm.
        file_object.CurrentByteOffset.QuadPart
    };
    write_fixed(
        buffer,
        length,
        wdk_sys::FILE_POSITION_INFORMATION {
            CurrentByteOffset: LARGE_INTEGER { QuadPart: current },
        },
    )
}

/// Packs FILE_NETWORK_OPEN_INFORMATION.
fn pack_network_open_information(
    buffer: NonNull<c_void>,
    length: usize,
    metadata: FileMetadata,
) -> DriverResult<wdk_sys::ULONG_PTR> {
    write_fixed(
        buffer,
        length,
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

/// Writes one fixed-size information structure into the caller's buffer.
fn write_fixed<T>(
    buffer: NonNull<c_void>,
    length: usize,
    value: T,
) -> DriverResult<wdk_sys::ULONG_PTR> {
    let size = core::mem::size_of::<T>();
    if length < size {
        return Err(DriverError::BufferTooSmall);
    }
    let target = buffer.cast::<T>().as_ptr();
    unsafe {
        // SAFETY: The caller supplied a system buffer of at least `size`
        // bytes, and `target` is aligned according to the WDK buffer contract
        // for fixed-size query information outputs.
        target.write(value);
    }
    wdk_sys::ULONG_PTR::try_from(size).map_err(|_| DriverError::InvalidParameter)
}

/// Converts an ext4 timestamp to a Windows system-time LARGE_INTEGER.
fn windows_time(timestamp: Ext4Timestamp) -> LARGE_INTEGER {
    let mut time = LARGE_INTEGER { QuadPart: 0 };
    unsafe {
        // SAFETY: `time` points to writable stack storage for the conversion
        // result.
        crate::ffi::RtlSecondsSince1970ToTime(timestamp.seconds(), core::ptr::addr_of_mut!(time));
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
        FileMetadataKind::Symlink => attributes |= wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT,
    }
    if attributes == 0 {
        wdk_sys::FILE_ATTRIBUTE_NORMAL
    } else {
        attributes
    }
}

/// Returns allocation size rounded to a volume allocation unit.
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
fn large_integer_from_u64(value: u64) -> DriverResult<LARGE_INTEGER> {
    Ok(LARGE_INTEGER {
        QuadPart: i64::try_from(value).map_err(|_| DriverError::InvalidParameter)?,
    })
}

/// Converts a Rust boolean to WDK BOOLEAN.
fn boolean(value: bool) -> wdk_sys::BOOLEAN {
    u8::from(value)
}

/// Reads a regular file through ext4-core into the IRP output buffer.
fn read_regular_file(target: DispatchTarget) -> Result<(), DriverError> {
    let stack = target.current_stack()?.read()?;
    let length = stack.length().as_usize();
    if length == 0 {
        target.set_information(0);
        return Ok(());
    }
    let mut output = target.data_buffer(length)?;
    let fcb = file_control_block(stack.file_object())?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this read runs while the FILE_OBJECT is
        // active.
        fcb.as_ref()
    };
    let vcb = volume_control_block(fcb);
    let NodeId::File(file_id) = fcb.node() else {
        return Err(DriverError::Core(ext4_core::Error::WrongInodeKind));
    };

    let node = vcb.volume().load_node(file_id.inode())?;
    let LoadedNode::File(file) = node else {
        return Err(DriverError::Core(ext4_core::Error::WrongInodeKind));
    };
    let bytes_read = vcb
        .volume()
        .read_file(&file, stack.byte_offset(), output.as_mut_slice())?;
    target.set_information(
        wdk_sys::ULONG_PTR::try_from(bytes_read.as_usize())
            .map_err(|_| DriverError::InvalidParameter)?,
    );
    Ok(())
}

/// Writes a regular file range through an ext4 journal transaction.
fn write_regular_file(target: DispatchTarget) -> Result<(), DriverError> {
    let stack = target.current_stack()?.write()?;
    let length = stack.length().as_usize();
    if length == 0 {
        target.set_information(0);
        return Ok(());
    }
    let input = target.data_buffer(length)?;
    let fcb = file_control_block(stack.file_object())?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this write runs while the FILE_OBJECT is
        // active.
        fcb.as_ref()
    };
    let mut vcb = fcb.volume();
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this synchronous write path.
        vcb.as_mut()
    };
    let NodeId::File(file_id) = fcb.node() else {
        return Err(DriverError::Core(ext4_core::Error::WrongInodeKind));
    };

    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::time::current_ext4_timestamp()?);
    let file = transaction.file(file_id)?;
    transaction.overwrite_file_range(file, stack.byte_offset(), input.as_slice())?;
    transaction.commit()?;
    target.set_information(
        wdk_sys::ULONG_PTR::try_from(length).map_err(|_| DriverError::InvalidParameter)?,
    );
    Ok(())
}

/// Returns the mounted VCB referenced by an FCB.
fn volume_control_block(fcb: &FileControlBlock) -> &VolumeControlBlock {
    unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open.
        fcb.volume().as_ref()
    }
}

/// Releases heap-owned FCB and CCB pointers stored on a FILE_OBJECT.
fn release_file_contexts(mut file_object: core::ptr::NonNull<wdk_sys::FILE_OBJECT>) {
    let file_object_ptr = file_object;
    let file_object = unsafe {
        // SAFETY: Close receives the final FILE_OBJECT and may clear its
        // filesystem-owned context pointers.
        file_object.as_mut()
    };
    let fcb = core::mem::replace(&mut file_object.FsContext, core::ptr::null_mut());
    if let Some(mut fcb) = NonNull::new(fcb.cast::<FileControlBlock>()) {
        let fcb_ref = unsafe {
            // SAFETY: Successful create stores a live VCB-owned FCB in
            // FsContext until this close path removes the handle reference.
            fcb.as_mut()
        };
        fcb_ref.remove_share_access(file_object_ptr);
        release_file_control_block(fcb);
    }
    let ccb = core::mem::replace(&mut file_object.FsContext2, core::ptr::null_mut());
    if !ccb.is_null() {
        unsafe {
            // SAFETY: Successful create stores Box<ContextControlBlock> in
            // FsContext2, and close is the unique release point.
            drop(Box::from_raw(ccb.cast::<ContextControlBlock>()));
        }
    }
}

#[cfg(test)]
mod tests {
    use core::ptr::NonNull;

    use wdk_sys::STATUS_NOT_SUPPORTED;

    #[test]
    fn rename_replace_request_is_rejected_at_decode_boundary() {
        let mut input = [0_u8; super::FILE_RENAME_NAME_OFFSET + 2];
        input[super::FILE_RENAME_REPLACE_IF_EXISTS_OFFSET] = 1;
        let name_length = input.get_mut(
            super::FILE_RENAME_NAME_LENGTH_OFFSET
                ..super::FILE_RENAME_NAME_LENGTH_OFFSET + core::mem::size_of::<u32>(),
        );
        assert!(name_length.is_some());
        let Some(name_length) = name_length else {
            return;
        };
        name_length.copy_from_slice(&2_u32.to_le_bytes());
        let name =
            input.get_mut(super::FILE_RENAME_NAME_OFFSET..super::FILE_RENAME_NAME_OFFSET + 2);
        assert!(name.is_some());
        let Some(name) = name else {
            return;
        };
        name.copy_from_slice(&u16::from(b'a').to_le_bytes());

        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: file_object.as_ptr(),
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

        let device = NonNull::<wdk_sys::DEVICE_OBJECT>::dangling();
        assert_eq!(
            super::set(device.as_ptr(), core::ptr::addr_of_mut!(irp)),
            STATUS_NOT_SUPPORTED
        );
    }
}
