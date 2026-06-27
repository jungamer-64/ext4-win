//! Reparse-point FSCTL packing for ext4 symbolic links.

use alloc::string::String;
use alloc::vec::Vec;

use ext4_core::{LoadedNode, NodeId, SymlinkNodeId, SymlinkTarget};
use wdk_sys::{NTSTATUS, STATUS_SUCCESS};

use crate::irp::{DispatchTarget, FileSystemControlStack};
use crate::metadata;
use crate::state::{
    FileControlBlock, OpenedPath, VolumeControlBlock, context_control_block, file_control_block,
};
use crate::status::{DriverError, DriverResult};

/// `FSCTL_GET_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
pub(crate) const FSCTL_GET_REPARSE_POINT: wdk_sys::ULONG = 589_992;

/// `FSCTL_SET_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
pub(crate) const FSCTL_SET_REPARSE_POINT: wdk_sys::ULONG = 589_988;

/// `FSCTL_DELETE_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
pub(crate) const FSCTL_DELETE_REPARSE_POINT: wdk_sys::ULONG = 589_996;

/// Reparse buffer header before the tag-specific payload.
const REPARSE_DATA_BUFFER_HEADER_SIZE: usize = 8;
/// SymbolicLinkReparseBuffer header before `PathBuffer`.
const SYMLINK_REPARSE_BUFFER_HEADER_SIZE: usize = 12;
/// Offset of `PathBuffer` inside `REPARSE_DATA_BUFFER`.
const SYMLINK_PATH_BUFFER_OFFSET: usize =
    REPARSE_DATA_BUFFER_HEADER_SIZE + SYMLINK_REPARSE_BUFFER_HEADER_SIZE;

/// Handles `FSCTL_GET_REPARSE_POINT` for an opened ext4 symlink.
pub(crate) fn get_reparse_point(target: DispatchTarget, stack: FileSystemControlStack) -> NTSTATUS {
    match read_symlink_target(stack).and_then(|symlink_target| {
        let length = stack.output_buffer_length().as_usize();
        let mut output = target.data_buffer(length)?;
        let written =
            pack_symlink_reparse_buffer(symlink_target.as_slice(), output.as_mut_slice())?;
        target.set_information(
            wdk_sys::ULONG_PTR::try_from(written).map_err(|_| DriverError::InvalidParameter)?,
        );
        Ok(())
    }) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => error.ntstatus(),
    }
}

/// Handles `FSCTL_SET_REPARSE_POINT` by replacing the opened node with an ext4 symlink.
pub(crate) fn set_reparse_point(target: DispatchTarget, stack: FileSystemControlStack) -> NTSTATUS {
    match parse_symlink_reparse_target(target, stack)
        .and_then(|symlink_target| replace_opened_path_with_symlink(stack, &symlink_target))
    {
        Ok(()) => {
            target.set_information(0);
            STATUS_SUCCESS
        }
        Err(error) => error.ntstatus(),
    }
}

/// Reads the target bytes for the symlink opened by the FSCTL.
fn read_symlink_target(stack: FileSystemControlStack) -> DriverResult<Vec<u8>> {
    let fcb = file_control_block(stack.file_object())?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this FSCTL runs while the FILE_OBJECT
        // is active.
        fcb.as_ref()
    };
    let NodeId::Symlink(symlink_id) = fcb.node() else {
        return Err(DriverError::NotAReparsePoint);
    };
    let vcb = volume_control_block(fcb);
    read_core_symlink(vcb, symlink_id)
}

/// Reads a symlink inode through ext4-core.
fn read_core_symlink(vcb: &VolumeControlBlock, symlink_id: SymlinkNodeId) -> DriverResult<Vec<u8>> {
    let node = vcb.volume().load_node(symlink_id.inode())?;
    let LoadedNode::Symlink(symlink) = node else {
        return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
    };
    Ok(vcb.volume().read_symlink(&symlink)?)
}

/// Parses a Windows symbolic-link reparse input buffer into an ext4 symlink target.
fn parse_symlink_reparse_target(
    target: DispatchTarget,
    stack: FileSystemControlStack,
) -> DriverResult<SymlinkTarget> {
    let length = stack.input_buffer_length().as_usize();
    let input = target.data_buffer(length)?;
    parse_symlink_reparse_buffer(input.as_slice())
}

/// Replaces the opened child entry with a newly-created symlink inode.
fn replace_opened_path_with_symlink(
    stack: FileSystemControlStack,
    target: &SymlinkTarget,
) -> DriverResult<()> {
    let mut fcb = file_control_block(stack.file_object())?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this FSCTL runs while the FILE_OBJECT
        // is active.
        fcb.as_mut()
    };
    let mut ccb = context_control_block(stack.file_object())?;
    let ccb = unsafe {
        // SAFETY: Successful create stores Box<ContextControlBlock> in
        // FsContext2 until close releases it, and this FSCTL runs while the
        // FILE_OBJECT is active.
        ccb.as_mut()
    };
    let OpenedPath::Child { parent, name } = ccb.path().clone() else {
        return Err(DriverError::NotSupported);
    };

    let mut vcb = fcb.volume();
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this namespace conversion.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::time::current_ext4_timestamp()?);
    let parent_directory = transaction.directory(parent)?;
    match fcb.node() {
        NodeId::File(_) => transaction.unlink_file(parent_directory, &name)?,
        NodeId::Directory(_) => transaction.remove_empty_directory(parent_directory, &name)?,
        NodeId::Symlink(_) => transaction.remove_symlink(parent_directory, &name)?,
    }
    let symlink = transaction.create_symlink(
        parent_directory,
        &name,
        target,
        metadata::default_symlink_metadata()?,
    )?;
    transaction.commit()?;
    let node = NodeId::Symlink(symlink.id());
    fcb.replace_node(node);
    ccb.replace_node(node);
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

/// Packs ext4 symlink bytes into a Windows symbolic-link reparse buffer.
fn pack_symlink_reparse_buffer(target: &[u8], output: &mut [u8]) -> DriverResult<usize> {
    let target = core::str::from_utf8(target).map_err(|_| DriverError::NotSupported)?;
    let path: Vec<u16> = target.encode_utf16().collect();
    let path_bytes = utf16_byte_len(path.as_slice())?;
    let print_name_offset = u16::try_from(path_bytes).map_err(|_| DriverError::NotSupported)?;
    let path_buffer_bytes = path_bytes
        .checked_mul(2)
        .ok_or(DriverError::InvalidParameter)?;
    let reparse_data_length = SYMLINK_REPARSE_BUFFER_HEADER_SIZE
        .checked_add(path_buffer_bytes)
        .ok_or(DriverError::InvalidParameter)?;
    let total_length = REPARSE_DATA_BUFFER_HEADER_SIZE
        .checked_add(reparse_data_length)
        .ok_or(DriverError::InvalidParameter)?;
    if output.len() < total_length {
        return Err(DriverError::BufferTooSmall);
    }
    let reparse_data_length =
        u16::try_from(reparse_data_length).map_err(|_| DriverError::NotSupported)?;
    let path_bytes = u16::try_from(path_bytes).map_err(|_| DriverError::NotSupported)?;
    let flags = if is_relative_symlink_target(target.as_bytes()) {
        wdk_sys::SYMLINK_FLAG_RELATIVE
    } else {
        0
    };

    write_u32(output, 0, wdk_sys::IO_REPARSE_TAG_SYMLINK)?;
    write_u16(output, 4, reparse_data_length)?;
    write_u16(output, 6, 0)?;
    write_u16(output, 8, 0)?;
    write_u16(output, 10, path_bytes)?;
    write_u16(output, 12, print_name_offset)?;
    write_u16(output, 14, path_bytes)?;
    write_u32(output, 16, flags)?;
    write_utf16(output, SYMLINK_PATH_BUFFER_OFFSET, path.as_slice())?;
    write_utf16(
        output,
        SYMLINK_PATH_BUFFER_OFFSET
            .checked_add(usize::from(path_bytes))
            .ok_or(DriverError::InvalidParameter)?,
        path.as_slice(),
    )?;
    Ok(total_length)
}

/// Parses a Windows symbolic-link reparse buffer.
fn parse_symlink_reparse_buffer(input: &[u8]) -> DriverResult<SymlinkTarget> {
    let tag = read_u32(input, 0)?;
    if tag != wdk_sys::IO_REPARSE_TAG_SYMLINK {
        return Err(DriverError::ReparseTagNotHandled);
    }
    let reparse_data_length = usize::from(read_u16(input, 4)?);
    let total_length = REPARSE_DATA_BUFFER_HEADER_SIZE
        .checked_add(reparse_data_length)
        .ok_or(DriverError::InvalidParameter)?;
    if input.len() < total_length {
        return Err(DriverError::BufferTooSmall);
    }
    if reparse_data_length < SYMLINK_REPARSE_BUFFER_HEADER_SIZE {
        return Err(DriverError::InvalidParameter);
    }

    let substitute_name_offset = usize::from(read_u16(input, 8)?);
    let substitute_name_length = usize::from(read_u16(input, 10)?);
    let flags = read_u32(input, 16)?;
    if flags & !wdk_sys::SYMLINK_FLAG_RELATIVE != 0 {
        return Err(DriverError::NotSupported);
    }

    let path_buffer_length = reparse_data_length
        .checked_sub(SYMLINK_REPARSE_BUFFER_HEADER_SIZE)
        .ok_or(DriverError::InvalidParameter)?;
    let units = reparse_path_units(
        input,
        path_buffer_length,
        substitute_name_offset,
        substitute_name_length,
    )?;
    let target = String::from_utf16(units.as_slice()).map_err(|_| DriverError::InvalidParameter)?;
    Ok(SymlinkTarget::new(target.as_bytes())?)
}

/// Reads a UTF-16 path slice from a symbolic-link reparse path buffer.
fn reparse_path_units(
    input: &[u8],
    path_buffer_length: usize,
    offset: usize,
    length: usize,
) -> DriverResult<Vec<u16>> {
    if !offset.is_multiple_of(2) || !length.is_multiple_of(2) {
        return Err(DriverError::InvalidParameter);
    }
    let path_buffer_end = SYMLINK_PATH_BUFFER_OFFSET
        .checked_add(path_buffer_length)
        .ok_or(DriverError::InvalidParameter)?;
    let start = SYMLINK_PATH_BUFFER_OFFSET
        .checked_add(offset)
        .ok_or(DriverError::InvalidParameter)?;
    let end = start
        .checked_add(length)
        .ok_or(DriverError::InvalidParameter)?;
    if end > path_buffer_end {
        return Err(DriverError::InvalidParameter);
    }
    let bytes = input.get(start..end).ok_or(DriverError::BufferTooSmall)?;
    let mut chunks = bytes.chunks_exact(core::mem::size_of::<u16>());
    let mut units = Vec::new();
    for chunk in &mut chunks {
        let unit: [u8; 2] = chunk
            .try_into()
            .map_err(|_| DriverError::InvalidParameter)?;
        units.push(u16::from_le_bytes(unit));
    }
    if !chunks.remainder().is_empty() {
        return Err(DriverError::InvalidParameter);
    }
    Ok(units)
}

/// Reads a little-endian `u16` from an unaligned input buffer.
fn read_u16(input: &[u8], offset: usize) -> DriverResult<u16> {
    let end = offset
        .checked_add(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)?;
    let bytes = input.get(offset..end).ok_or(DriverError::BufferTooSmall)?;
    let bytes: [u8; 2] = bytes
        .try_into()
        .map_err(|_| DriverError::InvalidParameter)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Reads a little-endian `u32` from an unaligned input buffer.
fn read_u32(input: &[u8], offset: usize) -> DriverResult<u32> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(DriverError::InvalidParameter)?;
    let bytes = input.get(offset..end).ok_or(DriverError::BufferTooSmall)?;
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| DriverError::InvalidParameter)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Returns the byte count for UTF-16 code units.
fn utf16_byte_len(units: &[u16]) -> DriverResult<usize> {
    units
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)
}

/// Returns whether a symlink target should carry `SYMLINK_FLAG_RELATIVE`.
fn is_relative_symlink_target(target: &[u8]) -> bool {
    if target.starts_with(b"/") || target.starts_with(b"\\") {
        return false;
    }
    if target.get(1).copied() == Some(b':') {
        return false;
    }
    true
}

/// Writes a little-endian `u16` into an unaligned output buffer.
fn write_u16(output: &mut [u8], offset: usize, value: u16) -> DriverResult<()> {
    let end = offset
        .checked_add(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)?;
    let Some(target) = output.get_mut(offset..end) else {
        return Err(DriverError::BufferTooSmall);
    };
    target.copy_from_slice(value.to_le_bytes().as_slice());
    Ok(())
}

/// Writes a little-endian `u32` into an unaligned output buffer.
fn write_u32(output: &mut [u8], offset: usize, value: u32) -> DriverResult<()> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(DriverError::InvalidParameter)?;
    let Some(target) = output.get_mut(offset..end) else {
        return Err(DriverError::BufferTooSmall);
    };
    target.copy_from_slice(value.to_le_bytes().as_slice());
    Ok(())
}

/// Writes UTF-16 code units into the reparse path buffer.
fn write_utf16(output: &mut [u8], offset: usize, units: &[u16]) -> DriverResult<()> {
    for (index, unit) in units.iter().enumerate() {
        let unit_offset = index
            .checked_mul(core::mem::size_of::<u16>())
            .and_then(|byte_offset| offset.checked_add(byte_offset))
            .ok_or(DriverError::InvalidParameter)?;
        write_u16(output, unit_offset, *unit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::status::DriverError;

    use super::{
        SYMLINK_PATH_BUFFER_OFFSET, pack_symlink_reparse_buffer, parse_symlink_reparse_buffer,
        write_u32,
    };

    fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
        let end = offset.checked_add(core::mem::size_of::<u16>())?;
        let slice = bytes.get(offset..end)?;
        let array: [u8; 2] = slice.try_into().ok()?;
        Some(u16::from_le_bytes(array))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
        let end = offset.checked_add(core::mem::size_of::<u32>())?;
        let slice = bytes.get(offset..end)?;
        let array: [u8; 4] = slice.try_into().ok()?;
        Some(u32::from_le_bytes(array))
    }

    #[test]
    fn packs_relative_symlink_reparse_buffer() {
        let mut output = vec![0; 128];
        const WRITTEN_LENGTH: usize = 52;
        const REPARSE_DATA_LENGTH: u16 = 44;

        assert_eq!(
            pack_symlink_reparse_buffer(b"dir/file", output.as_mut_slice()),
            Ok(WRITTEN_LENGTH)
        );
        assert_eq!(
            read_u32(output.as_slice(), 0),
            Some(wdk_sys::IO_REPARSE_TAG_SYMLINK)
        );
        assert_eq!(read_u16(output.as_slice(), 4), Some(REPARSE_DATA_LENGTH));
        assert_eq!(read_u16(output.as_slice(), 8), Some(0));
        assert_eq!(read_u16(output.as_slice(), 10), Some(16));
        assert_eq!(read_u16(output.as_slice(), 12), Some(16));
        assert_eq!(read_u16(output.as_slice(), 14), Some(16));
        assert_eq!(
            read_u32(output.as_slice(), 16),
            Some(wdk_sys::SYMLINK_FLAG_RELATIVE)
        );
        assert_eq!(
            read_u16(output.as_slice(), SYMLINK_PATH_BUFFER_OFFSET),
            Some(u16::from(b'd'))
        );
    }

    #[test]
    fn packs_absolute_symlink_without_relative_flag() {
        let mut output = vec![0; 128];
        const WRITTEN_LENGTH: usize = 72;

        assert_eq!(
            pack_symlink_reparse_buffer(br"\??\C:\target", output.as_mut_slice()),
            Ok(WRITTEN_LENGTH)
        );
        assert_eq!(read_u32(output.as_slice(), 16), Some(0));
    }

    #[test]
    fn rejects_too_small_reparse_buffer() {
        const TOO_SMALL_BUFFER_LENGTH: usize = 19;
        let mut output = vec![0; TOO_SMALL_BUFFER_LENGTH];

        assert_eq!(
            pack_symlink_reparse_buffer(b"target", output.as_mut_slice()),
            Err(DriverError::BufferTooSmall)
        );
    }

    #[test]
    fn parses_symlink_reparse_buffer_target() {
        let mut input = vec![0; 128];
        let expected = Vec::from(&b"dir/file"[..]);
        assert_eq!(
            pack_symlink_reparse_buffer(expected.as_slice(), input.as_mut_slice()),
            Ok(52)
        );

        assert_eq!(
            parse_symlink_reparse_buffer(input.as_slice()).map(|target| target.bytes().to_vec()),
            Ok(expected)
        );
    }

    #[test]
    fn rejects_unhandled_reparse_tag_on_set() {
        let mut input = vec![0; 128];
        assert_eq!(
            pack_symlink_reparse_buffer(b"target", input.as_mut_slice()),
            Ok(44)
        );
        assert_eq!(write_u32(input.as_mut_slice(), 0, 0), Ok(()));

        assert_eq!(
            parse_symlink_reparse_buffer(input.as_slice()),
            Err(DriverError::ReparseTagNotHandled)
        );
    }

    #[test]
    fn rejects_unsupported_symlink_reparse_flags() {
        let mut input = vec![0; 128];
        assert_eq!(
            pack_symlink_reparse_buffer(b"target", input.as_mut_slice()),
            Ok(44)
        );
        assert_eq!(write_u32(input.as_mut_slice(), 16, 2), Ok(()));

        assert_eq!(
            parse_symlink_reparse_buffer(input.as_slice()),
            Err(DriverError::NotSupported)
        );
    }
}
