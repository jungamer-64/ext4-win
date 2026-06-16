//! File object IRP handlers and file information packing boundary.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{
    DirectoryEntry, Ext4Security, Ext4Times, Ext4Timestamp, FileOffset, FileSize, InodeId, Node,
    WindowsName,
};
use wdk_sys::{
    LARGE_INTEGER, NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER,
    STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

use crate::irp::{DispatchTarget, QueryDirectoryStack, QueryFileStack};
use crate::state::{
    ContextControlBlock, DirectoryCursor, FileControlBlock, FileSystemNode, VolumeControlBlock,
};
use crate::status::DriverError;

/// Handles cleanup IRPs.
pub(crate) fn cleanup(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(_target) => STATUS_SUCCESS,
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
    decoded_not_supported(device, irp)
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
                STATUS_NOT_SUPPORTED
            }
            Ok(_) => STATUS_INVALID_DEVICE_REQUEST,
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Handles security descriptor queries.
pub(crate) fn query_security(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            let _device = target.device();
            let _irp = target.irp();
            crate::status::DriverError::AccessDenied.ntstatus()
        }
        Err(error) => error.ntstatus(),
    }
}

/// Handles security descriptor mutations.
pub(crate) fn set_security(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles extended-attribute queries.
pub(crate) fn query_ea(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles extended-attribute mutations.
pub(crate) fn set_ea(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
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
            STATUS_NOT_SUPPORTED
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
        Err(status) => status,
    }
}

/// Packs one supported file information class.
fn pack_file_information(request: QueryFileRequest) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
    let metadata = load_file_metadata(request.stack.file_object())?;
    let buffer = request
        .target
        .system_buffer()
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let length = usize::try_from(request.stack.length()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    match request.stack.information_class() {
        wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation => {
            pack_basic_information(buffer, length, metadata)
        }
        wdk_sys::_FILE_INFORMATION_CLASS::FileStandardInformation => {
            pack_standard_information(buffer, length, metadata)
        }
        wdk_sys::_FILE_INFORMATION_CLASS::FileInternalInformation => {
            pack_internal_information(buffer, length, metadata)
        }
        wdk_sys::_FILE_INFORMATION_CLASS::FilePositionInformation => {
            pack_position_information(buffer, length, request.stack.file_object())
        }
        wdk_sys::_FILE_INFORMATION_CLASS::FileNetworkOpenInformation => {
            pack_network_open_information(buffer, length, metadata)
        }
        _ => Err(STATUS_INVALID_INFO_CLASS),
    }
}

/// Handles directory enumeration queries.
fn query_directory(target: DispatchTarget) -> NTSTATUS {
    match QueryDirectoryRequest::decode(target) {
        Ok(request) => match pack_directory_information(request) {
            Ok(information) => {
                target.set_information(information);
                STATUS_SUCCESS
            }
            Err(status) => status,
        },
        Err(error) => error.ntstatus(),
    }
}

/// Packs directory entries into the caller's query-directory buffer.
fn pack_directory_information(
    request: QueryDirectoryRequest,
) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
    let class = DirectoryInformationClass::from_raw(request.stack.information_class())?;
    let pattern = DirectoryPattern::from_stack(request.stack)?;
    let length = usize::try_from(request.stack.length()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let mut buffer = request
        .target
        .data_buffer(length)
        .map_err(DriverError::ntstatus)?;
    let buffer = buffer.as_mut_slice();

    let fcb = file_control_block(request.stack.file_object()).map_err(DriverError::ntstatus)?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this query runs while the FILE_OBJECT is
        // active.
        fcb.as_ref()
    };
    let vcb = volume_control_block(fcb);
    let FileSystemNode::Directory(inode) = fcb.node() else {
        return Err(DriverError::from(ext4_core::Error::WrongInodeKind).ntstatus());
    };
    let directory = match vcb
        .volume()
        .read_node(inode)
        .map_err(|error| DriverError::from(error).ntstatus())?
    {
        Node::Directory(directory) => directory,
        Node::File(_) | Node::Symlink(_) => {
            return Err(DriverError::from(ext4_core::Error::WrongInodeKind).ntstatus());
        }
    };
    let entries = vcb
        .volume()
        .read_directory(&directory)
        .map_err(|error| DriverError::from(error).ntstatus())?;

    let mut ccb =
        context_control_block(request.stack.file_object()).map_err(DriverError::ntstatus)?;
    let ccb = unsafe {
        // SAFETY: Successful create stores Box<ContextControlBlock> in
        // FsContext2 until close releases it, and this query runs while the
        // FILE_OBJECT is active.
        ccb.as_mut()
    };
    let ContextControlBlock::Directory(cursor) = ccb else {
        return Err(STATUS_INVALID_PARAMETER);
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
    wdk_sys::ULONG_PTR::try_from(result).map_err(|_| STATUS_INVALID_PARAMETER)
}

/// Directory information classes supported by the variable-length packer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryInformationClass {
    /// FILE_DIRECTORY_INFORMATION.
    Directory,
    /// FILE_FULL_DIR_INFORMATION.
    Full,
    /// FILE_BOTH_DIR_INFORMATION.
    Both,
}

impl DirectoryInformationClass {
    /// Decodes the WDK information class.
    fn from_raw(value: wdk_sys::FILE_INFORMATION_CLASS) -> Result<Self, NTSTATUS> {
        match value {
            wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation => Ok(Self::Directory),
            wdk_sys::_FILE_INFORMATION_CLASS::FileFullDirectoryInformation => Ok(Self::Full),
            wdk_sys::_FILE_INFORMATION_CLASS::FileBothDirectoryInformation => Ok(Self::Both),
            _ => Err(STATUS_INVALID_INFO_CLASS),
        }
    }

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
    fn from_stack(stack: QueryDirectoryStack) -> Result<Self, NTSTATUS> {
        let Some(name) = stack.file_name() else {
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
            return Err(STATUS_NOT_SUPPORTED);
        }
        WindowsName::from_utf16(units)
            .map(Self::Exact)
            .map_err(|_| STATUS_INVALID_PARAMETER)
    }

    /// Returns true when the projected Windows name matches this pattern.
    fn matches(&self, name: &WindowsName) -> bool {
        match self {
            Self::All => true,
            Self::Exact(requested) => name.equals(requested),
        }
    }

    /// Returns the no-entry status for this pattern.
    const fn exhausted_status(&self) -> NTSTATUS {
        match self {
            Self::All => STATUS_NO_MORE_FILES,
            Self::Exact(_) => STATUS_NO_SUCH_FILE,
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
    fn new(class: DirectoryInformationClass, name: &WindowsName) -> Result<Self, NTSTATUS> {
        let name_offset = class.name_offset();
        let name_bytes = utf16_byte_len(name.utf16())?;
        let unpadded_size = name_offset
            .checked_add(name_bytes)
            .ok_or(STATUS_INVALID_PARAMETER)?;
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
fn unicode_string_units(name: &wdk_sys::UNICODE_STRING) -> Result<&[u16], NTSTATUS> {
    if name.Length & 1 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if name.Length == 0 {
        return Ok(&[]);
    }
    let Some(buffer) = NonNull::new(name.Buffer) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let units = usize::from(name.Length)
        .checked_div(core::mem::size_of::<u16>())
        .ok_or(STATUS_INVALID_PARAMETER)?;
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
    if query_directory_flag(stack, wdk_sys::SL_RESTART_SCAN) || stack.file_name().is_some() {
        cursor.seek(0);
    }
    if query_directory_flag(stack, wdk_sys::SL_INDEX_SPECIFIED) {
        cursor.seek(stack.file_index());
    }
}

/// Returns true when a QueryDirectory stack flag is set.
fn query_directory_flag(stack: QueryDirectoryStack, flag: wdk_sys::ULONG) -> bool {
    u32::from(stack.flags()) & flag != 0
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
) -> Result<usize, NTSTATUS> {
    let start = usize::try_from(cursor.next_entry()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let mut emitted = 0_usize;
    let mut written = 0_usize;
    let mut information = 0_usize;
    let mut previous_start = None;

    for (raw_index, entry) in entries.iter().enumerate().skip(start) {
        let entry_index = u32::try_from(raw_index).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let next_entry = entry_index.checked_add(1).ok_or(STATUS_INVALID_PARAMETER)?;
        let Ok(name) = WindowsName::from_ext4(entry.name()) else {
            cursor.seek(next_entry);
            continue;
        };
        if !pattern.matches(&name) {
            cursor.seek(next_entry);
            continue;
        }

        let node = vcb
            .volume()
            .read_node(entry.inode())
            .map_err(|error| DriverError::from(error).ntstatus())?;
        let metadata = metadata_from_node(vcb, entry.inode(), node)?;
        let layout = DirectoryRecordLayout::new(class, &name)?;
        let required = written
            .checked_add(layout.unpadded_size)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if required > buffer.len() {
            if emitted == 0 {
                return Err(STATUS_BUFFER_OVERFLOW);
            }
            break;
        }

        if let Some(previous_start) = previous_start {
            let next_offset = written
                .checked_sub(previous_start)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            write_u32(
                buffer,
                field_offset(previous_start, DIRECTORY_NEXT_ENTRY_OFFSET)?,
                u32::try_from(next_offset).map_err(|_| STATUS_INVALID_PARAMETER)?,
            )?;
        }

        pack_directory_record(buffer, written, class, entry_index, &name, metadata, layout)?;
        previous_start = Some(written);
        information = required;
        emitted = emitted.checked_add(1).ok_or(STATUS_INVALID_PARAMETER)?;
        written = written
            .checked_add(layout.padded_size)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        cursor.seek(next_entry);

        if query_directory_flag(stack, wdk_sys::SL_RETURN_SINGLE_ENTRY) {
            break;
        }
    }

    if emitted == 0 {
        Err(pattern.exhausted_status())
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
) -> Result<(), NTSTATUS> {
    clear_record(buffer, start, layout.unpadded_size)?;
    write_u32(buffer, field_offset(start, DIRECTORY_NEXT_ENTRY_OFFSET)?, 0)?;
    write_u32(
        buffer,
        field_offset(start, DIRECTORY_FILE_INDEX_OFFSET)?,
        file_index,
    )?;
    write_i64(
        buffer,
        field_offset(start, DIRECTORY_CREATION_TIME_OFFSET)?,
        windows_time_quad(metadata.times.created()),
    )?;
    write_i64(
        buffer,
        field_offset(start, DIRECTORY_LAST_ACCESS_TIME_OFFSET)?,
        windows_time_quad(metadata.times.accessed()),
    )?;
    write_i64(
        buffer,
        field_offset(start, DIRECTORY_LAST_WRITE_TIME_OFFSET)?,
        windows_time_quad(metadata.times.modified()),
    )?;
    write_i64(
        buffer,
        field_offset(start, DIRECTORY_CHANGE_TIME_OFFSET)?,
        windows_time_quad(metadata.times.changed()),
    )?;
    write_i64(
        buffer,
        field_offset(start, DIRECTORY_END_OF_FILE_OFFSET)?,
        signed_i64(metadata.size.bytes())?,
    )?;
    write_i64(
        buffer,
        field_offset(start, DIRECTORY_ALLOCATION_SIZE_OFFSET)?,
        signed_i64(allocation_size(metadata)?)?,
    )?;
    write_u32(
        buffer,
        field_offset(start, DIRECTORY_FILE_ATTRIBUTES_OFFSET)?,
        file_attributes(metadata),
    )?;
    write_u32(
        buffer,
        field_offset(start, DIRECTORY_FILE_NAME_LENGTH_OFFSET)?,
        u32::try_from(utf16_byte_len(name.utf16())?).map_err(|_| STATUS_INVALID_PARAMETER)?,
    )?;
    match class {
        DirectoryInformationClass::Directory => {}
        DirectoryInformationClass::Full => {
            write_u32(buffer, field_offset(start, DIRECTORY_EA_SIZE_OFFSET)?, 0)?;
        }
        DirectoryInformationClass::Both => {
            write_u32(buffer, field_offset(start, DIRECTORY_EA_SIZE_OFFSET)?, 0)?;
            write_u8(
                buffer,
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
fn clear_record(buffer: &mut [u8], start: usize, length: usize) -> Result<(), NTSTATUS> {
    let record = mutable_bytes(buffer, start, length)?;
    record.fill(0);
    Ok(())
}

/// Writes one byte into a buffer.
fn write_u8(buffer: &mut [u8], offset: usize, value: u8) -> Result<(), NTSTATUS> {
    write_bytes(buffer, offset, &[value])
}

/// Writes a little-endian u32 field.
fn write_u32(buffer: &mut [u8], offset: usize, value: u32) -> Result<(), NTSTATUS> {
    write_bytes(buffer, offset, &value.to_le_bytes())
}

/// Writes a little-endian i64 field.
fn write_i64(buffer: &mut [u8], offset: usize, value: i64) -> Result<(), NTSTATUS> {
    write_bytes(buffer, offset, &value.to_le_bytes())
}

/// Writes UTF-16 code units as Windows little-endian bytes.
fn write_utf16(buffer: &mut [u8], offset: usize, units: &[u16]) -> Result<(), NTSTATUS> {
    let mut cursor = offset;
    for unit in units {
        write_bytes(buffer, cursor, &unit.to_le_bytes())?;
        cursor = cursor.checked_add(2).ok_or(STATUS_INVALID_PARAMETER)?;
    }
    Ok(())
}

/// Writes raw bytes into a checked buffer range.
fn write_bytes(buffer: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), NTSTATUS> {
    let output = mutable_bytes(buffer, offset, bytes.len())?;
    output.copy_from_slice(bytes);
    Ok(())
}

/// Returns a checked mutable byte range.
fn mutable_bytes(buffer: &mut [u8], offset: usize, length: usize) -> Result<&mut [u8], NTSTATUS> {
    let end = offset.checked_add(length).ok_or(STATUS_INVALID_PARAMETER)?;
    buffer.get_mut(offset..end).ok_or(STATUS_BUFFER_OVERFLOW)
}

/// Computes an absolute field offset from a record start.
fn field_offset(start: usize, offset: usize) -> Result<usize, NTSTATUS> {
    start.checked_add(offset).ok_or(STATUS_INVALID_PARAMETER)
}

/// Returns the byte count for UTF-16 code units.
fn utf16_byte_len(units: &[u16]) -> Result<usize, NTSTATUS> {
    units
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(STATUS_INVALID_PARAMETER)
}

/// Aligns a directory record size to an eight-byte boundary.
fn align_to_eight(value: usize) -> Result<usize, NTSTATUS> {
    let adjustment = DIRECTORY_ENTRY_ALIGNMENT
        .checked_sub(1)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let adjusted = value
        .checked_add(adjustment)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let units = adjusted
        .checked_div(DIRECTORY_ENTRY_ALIGNMENT)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    units
        .checked_mul(DIRECTORY_ENTRY_ALIGNMENT)
        .ok_or(STATUS_INVALID_PARAMETER)
}

/// Converts an unsigned byte count to a signed Windows large-integer payload.
fn signed_i64(value: u64) -> Result<i64, NTSTATUS> {
    i64::try_from(value).map_err(|_| STATUS_INVALID_PARAMETER)
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

/// Returns the CCB stored on a successfully opened FILE_OBJECT.
fn context_control_block(
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
) -> Result<NonNull<ContextControlBlock>, DriverError> {
    let file_object = unsafe {
        // SAFETY: The FILE_OBJECT pointer comes from the active IRP stack and
        // is read only for filesystem-owned context pointers.
        file_object.as_ref()
    };
    NonNull::new(file_object.FsContext2.cast::<ContextControlBlock>())
        .ok_or(DriverError::InvalidParameter)
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
fn load_file_metadata(
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
) -> Result<FileMetadata, NTSTATUS> {
    let fcb = file_control_block(file_object).map_err(DriverError::ntstatus)?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this query runs while the FILE_OBJECT is
        // active.
        fcb.as_ref()
    };
    let vcb = volume_control_block(fcb);
    let inode = fcb.node().inode();
    let node = vcb
        .volume()
        .read_node(inode)
        .map_err(|error| DriverError::from(error).ntstatus())?;
    let metadata = metadata_from_node(vcb, inode, node)?;
    if fcb_node_matches_metadata(fcb.node(), metadata.kind) {
        Ok(metadata)
    } else {
        Err(DriverError::Core(ext4_core::Error::WrongInodeKind).ntstatus())
    }
}

/// Returns true when an FCB node identity still matches loaded core metadata.
const fn fcb_node_matches_metadata(node: FileSystemNode, kind: FileMetadataKind) -> bool {
    matches!(
        (node, kind),
        (FileSystemNode::File(_), FileMetadataKind::File)
            | (FileSystemNode::Directory(_), FileMetadataKind::Directory)
            | (FileSystemNode::Symlink(_), FileMetadataKind::Symlink)
    )
}

/// Builds Windows-facing metadata from a loaded ext4 node.
fn metadata_from_node(
    vcb: &VolumeControlBlock,
    inode: InodeId,
    node: Node,
) -> Result<FileMetadata, NTSTATUS> {
    let overlay_attributes = vcb
        .volume()
        .read_windows_overlay(inode)
        .map_err(|error| DriverError::from(error).ntstatus())?
        .map(|overlay| overlay.attributes().bits())
        .unwrap_or(0);

    let block_size = vcb.volume().superblock().block_size();
    match node {
        Node::File(file) => Ok(FileMetadata {
            inode,
            kind: FileMetadataKind::File,
            size: file.size(),
            security: file.security(),
            times: file.times(),
            links_count: file.links_count(),
            overlay_attributes,
            block_size,
        }),
        Node::Directory(directory) => Ok(FileMetadata {
            inode,
            kind: FileMetadataKind::Directory,
            size: directory.size(),
            security: directory.security(),
            times: directory.times(),
            links_count: directory.links_count(),
            overlay_attributes,
            block_size,
        }),
        Node::Symlink(symlink) => Ok(FileMetadata {
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
) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
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
) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
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
) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
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
) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
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
) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
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
) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
    let size = core::mem::size_of::<T>();
    if length < size {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let target = buffer.cast::<T>().as_ptr();
    unsafe {
        // SAFETY: The caller supplied a system buffer of at least `size`
        // bytes, and `target` is aligned according to the WDK buffer contract
        // for fixed-size query information outputs.
        target.write(value);
    }
    wdk_sys::ULONG_PTR::try_from(size).map_err(|_| STATUS_INVALID_PARAMETER)
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
fn allocation_size(metadata: FileMetadata) -> Result<u64, NTSTATUS> {
    let size = metadata.size.bytes();
    if size == 0 {
        return Ok(0);
    }
    let block_size = u64::from(metadata.block_size.bytes());
    let adjustment = block_size.checked_sub(1).ok_or(STATUS_INVALID_PARAMETER)?;
    let adjusted = size
        .checked_add(adjustment)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let blocks = adjusted
        .checked_div(block_size)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    blocks
        .checked_mul(block_size)
        .ok_or(STATUS_INVALID_PARAMETER)
}

/// Creates a signed LARGE_INTEGER from an unsigned byte count.
fn large_integer_from_u64(value: u64) -> Result<LARGE_INTEGER, NTSTATUS> {
    Ok(LARGE_INTEGER {
        QuadPart: i64::try_from(value).map_err(|_| STATUS_INVALID_PARAMETER)?,
    })
}

/// Converts a Rust boolean to WDK BOOLEAN.
fn boolean(value: bool) -> wdk_sys::BOOLEAN {
    u8::from(value)
}

/// Reads a regular file through ext4-core into the IRP output buffer.
fn read_regular_file(target: DispatchTarget) -> Result<(), DriverError> {
    let stack = target.current_stack()?.read()?;
    let length = usize::try_from(stack.length()).map_err(|_| DriverError::InvalidParameter)?;
    if length == 0 {
        target.set_information(0);
        return Ok(());
    }
    let offset = u64::try_from(stack.byte_offset()).map_err(|_| DriverError::InvalidParameter)?;
    let mut output = target.data_buffer(length)?;
    let fcb = file_control_block(stack.file_object())?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this read runs while the FILE_OBJECT is
        // active.
        fcb.as_ref()
    };
    let vcb = volume_control_block(fcb);
    let FileSystemNode::File(inode) = fcb.node() else {
        return Err(DriverError::Core(ext4_core::Error::WrongInodeKind));
    };

    let node = vcb.volume().read_node(inode)?;
    let Node::File(file) = node else {
        return Err(DriverError::Core(ext4_core::Error::WrongInodeKind));
    };
    let bytes_read =
        vcb.volume()
            .read_file(&file, FileOffset::from_bytes(offset), output.as_mut_slice())?;
    target.set_information(
        wdk_sys::ULONG_PTR::try_from(bytes_read.as_usize())
            .map_err(|_| DriverError::InvalidParameter)?,
    );
    Ok(())
}

/// Writes a regular file range through an ext4 journal transaction.
fn write_regular_file(target: DispatchTarget) -> Result<(), DriverError> {
    let stack = target.current_stack()?.write()?;
    let length = usize::try_from(stack.length()).map_err(|_| DriverError::InvalidParameter)?;
    if length == 0 {
        target.set_information(0);
        return Ok(());
    }
    let offset = u64::try_from(stack.byte_offset()).map_err(|_| DriverError::InvalidParameter)?;
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
    let FileSystemNode::File(inode) = fcb.node() else {
        return Err(DriverError::Core(ext4_core::Error::WrongInodeKind));
    };

    let mut transaction = vcb.volume_mut().begin_transaction(current_time()?);
    let file = transaction.file(inode)?;
    transaction.overwrite_file_range(file, FileOffset::from_bytes(offset), input.as_slice())?;
    transaction.commit()?;
    target.set_information(
        wdk_sys::ULONG_PTR::try_from(length).map_err(|_| DriverError::InvalidParameter)?,
    );
    Ok(())
}

/// Returns the current system time as an ext4 inode timestamp.
fn current_time() -> Result<Ext4Timestamp, DriverError> {
    let mut time = wdk_sys::LARGE_INTEGER { QuadPart: 0 };
    unsafe {
        // SAFETY: `time` points to writable stack storage for the kernel to
        // receive the current system time.
        crate::ffi::KeQuerySystemTimePrecise(core::ptr::addr_of_mut!(time));
    }
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

/// Returns the FCB stored on a successfully opened FILE_OBJECT.
fn file_control_block(
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
) -> Result<NonNull<FileControlBlock>, DriverError> {
    let file_object = unsafe {
        // SAFETY: The FILE_OBJECT pointer comes from the active IRP stack and
        // is read only for filesystem-owned context pointers.
        file_object.as_ref()
    };
    NonNull::new(file_object.FsContext.cast::<FileControlBlock>())
        .ok_or(DriverError::InvalidParameter)
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
    let file_object = unsafe {
        // SAFETY: Close receives the final FILE_OBJECT and may clear its
        // filesystem-owned context pointers.
        file_object.as_mut()
    };
    let fcb = core::mem::replace(&mut file_object.FsContext, core::ptr::null_mut());
    if !fcb.is_null() {
        unsafe {
            // SAFETY: Successful create stores Box<FileControlBlock> in
            // FsContext, and close is the unique release point.
            drop(Box::from_raw(fcb.cast::<FileControlBlock>()));
        }
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
