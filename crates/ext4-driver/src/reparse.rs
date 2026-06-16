//! Reparse-point FSCTL packing for ext4 symbolic links.

use alloc::vec::Vec;

use ext4_core::{InodeId, Node};
use wdk_sys::{
    NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
};

use crate::irp::{DispatchTarget, FileSystemControlStack};
use crate::state::{FileControlBlock, FileSystemNode, VolumeControlBlock, file_control_block};
use crate::status::DriverError;

/// `FSCTL_GET_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
pub(crate) const FSCTL_GET_REPARSE_POINT: wdk_sys::ULONG = 589_992;

/// `FSCTL_SET_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
pub(crate) const FSCTL_SET_REPARSE_POINT: wdk_sys::ULONG = 589_988;

/// `FSCTL_DELETE_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
pub(crate) const FSCTL_DELETE_REPARSE_POINT: wdk_sys::ULONG = 589_996;

/// The opened node is not a reparse point.
const STATUS_NOT_A_REPARSE_POINT: NTSTATUS = ntstatus(0xC000_0275);

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
        let length =
            usize::try_from(stack.output_buffer_length()).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let mut output = target
            .data_buffer(length)
            .map_err(|error| error.ntstatus())?;
        let written =
            pack_symlink_reparse_buffer(symlink_target.as_slice(), output.as_mut_slice())?;
        target.set_information(
            wdk_sys::ULONG_PTR::try_from(written).map_err(|_| STATUS_INVALID_PARAMETER)?,
        );
        Ok(())
    }) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// Reads the target bytes for the symlink opened by the FSCTL.
fn read_symlink_target(stack: FileSystemControlStack) -> Result<Vec<u8>, NTSTATUS> {
    let fcb = file_control_block(stack.file_object()).map_err(DriverError::ntstatus)?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this FSCTL runs while the FILE_OBJECT
        // is active.
        fcb.as_ref()
    };
    let FileSystemNode::Symlink(inode) = fcb.node() else {
        return Err(STATUS_NOT_A_REPARSE_POINT);
    };
    let vcb = volume_control_block(fcb);
    read_core_symlink(vcb, inode)
}

/// Reads a symlink inode through ext4-core.
fn read_core_symlink(vcb: &VolumeControlBlock, inode: InodeId) -> Result<Vec<u8>, NTSTATUS> {
    let node = vcb
        .volume()
        .read_node(inode)
        .map_err(|error| DriverError::from(error).ntstatus())?;
    let Node::Symlink(symlink) = node else {
        return Err(DriverError::from(ext4_core::Error::WrongInodeKind).ntstatus());
    };
    vcb.volume()
        .read_symlink(&symlink)
        .map_err(|error| DriverError::from(error).ntstatus())
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
fn pack_symlink_reparse_buffer(target: &[u8], output: &mut [u8]) -> Result<usize, NTSTATUS> {
    let target = core::str::from_utf8(target).map_err(|_| STATUS_NOT_SUPPORTED)?;
    let path: Vec<u16> = target.encode_utf16().collect();
    let path_bytes = utf16_byte_len(path.as_slice())?;
    let print_name_offset = u16::try_from(path_bytes).map_err(|_| STATUS_NOT_SUPPORTED)?;
    let path_buffer_bytes = path_bytes.checked_mul(2).ok_or(STATUS_INVALID_PARAMETER)?;
    let reparse_data_length = SYMLINK_REPARSE_BUFFER_HEADER_SIZE
        .checked_add(path_buffer_bytes)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let total_length = REPARSE_DATA_BUFFER_HEADER_SIZE
        .checked_add(reparse_data_length)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if output.len() < total_length {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let reparse_data_length =
        u16::try_from(reparse_data_length).map_err(|_| STATUS_NOT_SUPPORTED)?;
    let path_bytes = u16::try_from(path_bytes).map_err(|_| STATUS_NOT_SUPPORTED)?;
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
            .ok_or(STATUS_INVALID_PARAMETER)?,
        path.as_slice(),
    )?;
    Ok(total_length)
}

/// Returns the byte count for UTF-16 code units.
fn utf16_byte_len(units: &[u16]) -> Result<usize, NTSTATUS> {
    units
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(STATUS_INVALID_PARAMETER)
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

/// Converts a hexadecimal NTSTATUS payload into the signed WDK alias.
const fn ntstatus(value: u32) -> NTSTATUS {
    i32::from_ne_bytes(value.to_ne_bytes())
}

/// Writes a little-endian `u16` into an unaligned output buffer.
fn write_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), NTSTATUS> {
    let end = offset
        .checked_add(core::mem::size_of::<u16>())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let Some(target) = output.get_mut(offset..end) else {
        return Err(STATUS_BUFFER_TOO_SMALL);
    };
    target.copy_from_slice(value.to_le_bytes().as_slice());
    Ok(())
}

/// Writes a little-endian `u32` into an unaligned output buffer.
fn write_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), NTSTATUS> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let Some(target) = output.get_mut(offset..end) else {
        return Err(STATUS_BUFFER_TOO_SMALL);
    };
    target.copy_from_slice(value.to_le_bytes().as_slice());
    Ok(())
}

/// Writes UTF-16 code units into the reparse path buffer.
fn write_utf16(output: &mut [u8], offset: usize, units: &[u16]) -> Result<(), NTSTATUS> {
    for (index, unit) in units.iter().enumerate() {
        let unit_offset = index
            .checked_mul(core::mem::size_of::<u16>())
            .and_then(|byte_offset| offset.checked_add(byte_offset))
            .ok_or(STATUS_INVALID_PARAMETER)?;
        write_u16(output, unit_offset, *unit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{SYMLINK_PATH_BUFFER_OFFSET, pack_symlink_reparse_buffer};

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
            Err(wdk_sys::STATUS_BUFFER_TOO_SMALL)
        );
    }
}
