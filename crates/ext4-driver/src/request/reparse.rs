//! Reparse-point FSCTL packing for ext4 symbolic links.

use alloc::vec::Vec;

use crate::irp::{DispatchTarget, FileSystemControlStack, IrpCompletion};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use crate::state::{FileControlBlock, OpenedSymlink, VolumeControlBlock};
use crate::wire::{LittleEndianOutput, WireOffset};
use ext4_core::SymlinkNodeId;

/// Reparse buffer header before the tag-specific payload.
const REPARSE_DATA_BUFFER_HEADER_SIZE: usize = 8;
/// SymbolicLinkReparseBuffer header before `PathBuffer`.
const SYMLINK_REPARSE_BUFFER_HEADER_SIZE: usize = 12;
/// Offset of `PathBuffer` inside `REPARSE_DATA_BUFFER`.
const SYMLINK_PATH_BUFFER_OFFSET: usize =
    REPARSE_DATA_BUFFER_HEADER_SIZE + SYMLINK_REPARSE_BUFFER_HEADER_SIZE;

/// Creates a wire offset from a reparse-buffer byte position.
const fn wire_offset(offset: usize) -> WireOffset {
    WireOffset::new(offset)
}

/// Handles `FSCTL_GET_REPARSE_POINT` for an opened ext4 symlink.
/// # Errors
///
/// Returns an error when the opened object is not a symlink, the symlink target cannot be read, or
/// the output buffer cannot hold the reparse data.
pub(crate) fn get_reparse_point(
    target: DispatchTarget,
    stack: FileSystemControlStack,
) -> DriverResult<IrpCompletion> {
    let symlink_target = read_symlink_target(stack)?;
    let length = stack.output_buffer_length();
    let mut output = target.buffered_output(length)?;
    let written = pack_symlink_reparse_buffer(symlink_target.as_slice(), output.as_mut_slice())?;
    IrpCompletion::from_usize(written)
}

/// Handles `FSCTL_SET_REPARSE_POINT` by replacing the opened node with an ext4 symlink.
/// # Errors
///
/// Returns an error when the reparse input is malformed or the opened location cannot be replaced
/// by a symlink in an ext4 transaction.
/// Reads the target bytes for the symlink opened by the FSCTL.
/// # Errors
///
/// Returns an error when the FSCTL FILE_OBJECT is not an opened symlink or the symlink target cannot
/// be read.
fn read_symlink_target(stack: FileSystemControlStack) -> DriverResult<Vec<u8>> {
    let opened_file = OpenedSymlink::decode(stack.file_object())?;
    let fcb = opened_file.file_control_block();
    let vcb = volume_control_block(fcb);
    read_core_symlink(vcb, opened_file.id())
}

/// Reads a symlink inode through ext4-core.
/// # Errors
///
/// Returns an error when `symlink_id` cannot be loaded or its target bytes cannot be read.
fn read_core_symlink(vcb: &VolumeControlBlock, symlink_id: SymlinkNodeId) -> DriverResult<Vec<u8>> {
    let symlink = vcb.volume().load_symlink(symlink_id)?;
    Ok(vcb.volume().read_symlink(&symlink)?)
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
/// # Errors
///
/// Returns an error when the ext4 target is not UTF-8, path length fields overflow, or the output
/// buffer is too small.
fn pack_symlink_reparse_buffer(target: &[u8], output: &mut [u8]) -> DriverResult<usize> {
    let target = core::str::from_utf8(target).map_err(|_| DriverError::NotSupported)?;
    let mut path = DriverVec::try_with_capacity(target.len())?;
    for unit in target.encode_utf16() {
        path.try_push(unit)?;
    }
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

    let mut output = LittleEndianOutput::new(output);
    output.write_u32(wire_offset(0), wdk_sys::IO_REPARSE_TAG_SYMLINK)?;
    output.write_u16(wire_offset(4), reparse_data_length)?;
    output.write_u16(wire_offset(6), 0)?;
    output.write_u16(wire_offset(8), 0)?;
    output.write_u16(wire_offset(10), path_bytes)?;
    output.write_u16(wire_offset(12), print_name_offset)?;
    output.write_u16(wire_offset(14), path_bytes)?;
    output.write_u32(wire_offset(16), flags)?;
    write_utf16(&mut output, SYMLINK_PATH_BUFFER_OFFSET, path.as_slice())?;
    write_utf16(
        &mut output,
        SYMLINK_PATH_BUFFER_OFFSET
            .checked_add(usize::from(path_bytes))
            .ok_or(DriverError::InvalidParameter)?,
        path.as_slice(),
    )?;
    Ok(total_length)
}

/// Returns the byte count for UTF-16 code units.
/// # Errors
///
/// Returns an error when the code-unit count cannot be doubled without overflow.
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

/// Writes UTF-16 code units into the reparse path buffer.
/// # Errors
///
/// Returns an error when a UTF-16 code-unit offset overflows or falls outside the output buffer.
fn write_utf16(
    output: &mut LittleEndianOutput<'_>,
    offset: usize,
    units: &[u16],
) -> DriverResult<()> {
    for (index, unit) in units.iter().enumerate() {
        let unit_offset = index
            .checked_mul(core::mem::size_of::<u16>())
            .and_then(|byte_offset| offset.checked_add(byte_offset))
            .ok_or(DriverError::InvalidParameter)?;
        output.write_u16(wire_offset(unit_offset), *unit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::kernel::status::DriverError;
    use crate::wire::LittleEndianInput;

    use super::{SYMLINK_PATH_BUFFER_OFFSET, pack_symlink_reparse_buffer, wire_offset};

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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
            LittleEndianInput::new(output.as_slice()).read_u32(wire_offset(0)),
            Ok(wdk_sys::IO_REPARSE_TAG_SYMLINK)
        );
        let output = LittleEndianInput::new(output.as_slice());
        assert_eq!(output.read_u16(wire_offset(4)), Ok(REPARSE_DATA_LENGTH));
        assert_eq!(output.read_u16(wire_offset(8)), Ok(0));
        assert_eq!(output.read_u16(wire_offset(10)), Ok(16));
        assert_eq!(output.read_u16(wire_offset(12)), Ok(16));
        assert_eq!(output.read_u16(wire_offset(14)), Ok(16));
        assert_eq!(
            output.read_u32(wire_offset(16)),
            Ok(wdk_sys::SYMLINK_FLAG_RELATIVE)
        );
        assert_eq!(
            output.read_u16(wire_offset(SYMLINK_PATH_BUFFER_OFFSET)),
            Ok(u16::from(b'd'))
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn packs_absolute_symlink_without_relative_flag() {
        let mut output = vec![0; 128];
        const WRITTEN_LENGTH: usize = 72;

        assert_eq!(
            pack_symlink_reparse_buffer(br"\??\C:\target", output.as_mut_slice()),
            Ok(WRITTEN_LENGTH)
        );
        assert_eq!(
            LittleEndianInput::new(output.as_slice()).read_u32(wire_offset(16)),
            Ok(0)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rejects_too_small_reparse_buffer() {
        const TOO_SMALL_BUFFER_LENGTH: usize = 19;
        let mut output = vec![0; TOO_SMALL_BUFFER_LENGTH];

        assert_eq!(
            pack_symlink_reparse_buffer(b"target", output.as_mut_slice()),
            Err(DriverError::BufferTooSmall)
        );
    }

}
