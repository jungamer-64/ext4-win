//! File object IRP handlers and file information packing boundary.

use alloc::boxed::Box;
use core::ptr::NonNull;

use core::ffi::c_void;

use ext4_core::{Ext4Security, Ext4Times, Ext4Timestamp, FileOffset, FileSize, InodeId, Node};
use wdk_sys::{
    LARGE_INTEGER, NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

use crate::irp::{DispatchTarget, QueryFileStack};
use crate::state::{ContextControlBlock, FileControlBlock, FileSystemNode, VolumeControlBlock};
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
    decoded_not_supported(device, irp)
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
    let overlay_attributes = vcb
        .volume()
        .read_windows_overlay(inode)
        .map_err(|error| DriverError::from(error).ntstatus())?
        .map(|overlay| overlay.attributes().bits())
        .unwrap_or(0);

    let block_size = vcb.volume().superblock().block_size();
    match (
        fcb.node(),
        vcb.volume()
            .read_node(inode)
            .map_err(|error| DriverError::from(error).ntstatus())?,
    ) {
        (FileSystemNode::File(_), Node::File(file)) => Ok(FileMetadata {
            inode,
            kind: FileMetadataKind::File,
            size: file.size(),
            security: file.security(),
            times: file.times(),
            links_count: file.links_count(),
            overlay_attributes,
            block_size,
        }),
        (FileSystemNode::Directory(_), Node::Directory(directory)) => Ok(FileMetadata {
            inode,
            kind: FileMetadataKind::Directory,
            size: directory.size(),
            security: directory.security(),
            times: directory.times(),
            links_count: directory.links_count(),
            overlay_attributes,
            block_size,
        }),
        (FileSystemNode::Symlink(_), Node::Symlink(symlink)) => Ok(FileMetadata {
            inode,
            kind: FileMetadataKind::Symlink,
            size: symlink.size(),
            security: symlink.security(),
            times: symlink.times(),
            links_count: symlink.links_count(),
            overlay_attributes,
            block_size,
        }),
        _ => Err(DriverError::Core(ext4_core::Error::WrongInodeKind).ntstatus()),
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
