//! Reparse-point FSCTL packing for ext4 symbolic links.

use alloc::vec::Vec;

use crate::irp::{DispatchTarget, FileSystemControlStack, IrpCompletion};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use crate::request::metadata;
use crate::state::{FileControlBlock, OpenedObject, OpenedPath, OpenedSymlink, VolumeControlBlock};
use crate::wire::{LittleEndianInput, LittleEndianOutput, WireByteLen, WireOffset, WireRange};
use ext4_core::{NodeId, SymlinkNodeId, SymlinkTarget};

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

/// Creates a checked reparse-buffer range.
/// # Errors
///
/// Returns an error when `offset + length` cannot be represented as a reparse-buffer wire range.
fn wire_range(offset: usize, length: usize) -> DriverResult<WireRange> {
    WireRange::new(wire_offset(offset), WireByteLen::new(length))
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
/// Returns an error when the reparse input is malformed or the opened path cannot be replaced by a
/// symlink in an ext4 transaction.
pub(crate) fn set_reparse_point(
    target: DispatchTarget,
    stack: FileSystemControlStack,
) -> DriverResult<IrpCompletion> {
    let symlink_target = parse_symlink_reparse_target(target, stack)?;
    replace_opened_path_with_symlink(stack, &symlink_target)?;
    Ok(IrpCompletion::EMPTY)
}

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

/// Parses a Windows symbolic-link reparse input buffer into an ext4 symlink target.
/// # Errors
///
/// Returns an error when the FSCTL input buffer is unavailable or the symbolic-link reparse buffer
/// is malformed.
fn parse_symlink_reparse_target(
    target: DispatchTarget,
    stack: FileSystemControlStack,
) -> DriverResult<SymlinkTarget> {
    let length = stack.input_buffer_length();
    let input = target.buffered_input(length)?;
    parse_symlink_reparse_buffer(input.as_slice())
}

/// Replaces the opened child entry with a newly-created symlink inode.
/// # Errors
///
/// Returns an error when the opened object is the root, its current node cannot be removed, or the
/// replacement symlink cannot be created and committed.
fn replace_opened_path_with_symlink(
    stack: FileSystemControlStack,
    target: &SymlinkTarget,
) -> DriverResult<()> {
    let mut opened_file = OpenedObject::decode(stack.file_object())?;
    let (parent, name) = match opened_file.path() {
        OpenedPath::Child { parent, name } => (*parent, name.try_clone()?),
        OpenedPath::Root => return Err(DriverError::NotSupported),
    };

    let mut vcb = opened_file.volume();
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this namespace conversion.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let parent_directory = transaction.directory(parent)?;
    match opened_file.node() {
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
    opened_file.replace_with_symlink(symlink.id());
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

/// Parses a Windows symbolic-link reparse buffer.
/// # Errors
///
/// Returns an error when the tag is not symbolic-link, lengths are inconsistent, flags are
/// unsupported, UTF-16 is invalid, or the target is not a valid ext4 symlink.
fn parse_symlink_reparse_buffer(input: &[u8]) -> DriverResult<SymlinkTarget> {
    let input_len = input.len();
    let input = LittleEndianInput::new(input);
    let tag = input.read_u32(wire_offset(0))?;
    if tag != wdk_sys::IO_REPARSE_TAG_SYMLINK {
        return Err(DriverError::ReparseTagNotHandled);
    }
    let reparse_data_length = usize::from(input.read_u16(wire_offset(4))?);
    let total_length = REPARSE_DATA_BUFFER_HEADER_SIZE
        .checked_add(reparse_data_length)
        .ok_or(DriverError::InvalidParameter)?;
    if input_len < total_length {
        return Err(DriverError::BufferTooSmall);
    }
    if reparse_data_length < SYMLINK_REPARSE_BUFFER_HEADER_SIZE {
        return Err(DriverError::InvalidParameter);
    }

    let substitute_name_offset = usize::from(input.read_u16(wire_offset(8))?);
    let substitute_name_length = usize::from(input.read_u16(wire_offset(10))?);
    let flags = input.read_u32(wire_offset(16))?;
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
    let target = utf16_to_utf8_bytes(units.as_slice())?;
    Ok(SymlinkTarget::new(target.as_slice())?)
}

/// Reads a UTF-16 path slice from a symbolic-link reparse path buffer.
/// # Errors
///
/// Returns an error when path offsets are not UTF-16 aligned, overflow, or point outside the reparse
/// path buffer.
fn reparse_path_units(
    input: LittleEndianInput<'_>,
    path_buffer_length: usize,
    offset: usize,
    length: usize,
) -> DriverResult<DriverVec<u16>> {
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
    let bytes = input.range(wire_range(start, length)?)?;
    let mut units = DriverVec::new();
    let (chunks, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(DriverError::InvalidParameter);
    }
    for chunk in chunks {
        units.try_push(u16::from_le_bytes(*chunk))?;
    }
    Ok(units)
}

/// Converts UTF-16 units into UTF-8 bytes without using infallible string allocation.
/// # Errors
///
/// Returns an error when the UTF-16 input is malformed or allocation fails.
fn utf16_to_utf8_bytes(units: &[u16]) -> DriverResult<DriverVec<u8>> {
    let capacity = units
        .len()
        .checked_mul(3)
        .ok_or(DriverError::InvalidParameter)?;
    let mut bytes = DriverVec::try_with_capacity(capacity)?;
    for decoded in char::decode_utf16(units.iter().copied()) {
        let character = decoded.map_err(|_| DriverError::InvalidParameter)?;
        let mut encoded = [0_u8; 4];
        bytes.try_extend_from_copy_slice(character.encode_utf8(&mut encoded).as_bytes())?;
    }
    Ok(bytes)
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
    use crate::wire::{LittleEndianInput, LittleEndianOutput};

    use super::{
        SYMLINK_PATH_BUFFER_OFFSET, pack_symlink_reparse_buffer, parse_symlink_reparse_buffer,
        wire_offset,
    };

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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rejects_unhandled_reparse_tag_on_set() {
        let mut input = vec![0; 128];
        assert_eq!(
            pack_symlink_reparse_buffer(b"target", input.as_mut_slice()),
            Ok(44)
        );
        assert_eq!(
            LittleEndianOutput::new(input.as_mut_slice()).write_u32(wire_offset(0), 0),
            Ok(())
        );

        assert_eq!(
            parse_symlink_reparse_buffer(input.as_slice()),
            Err(DriverError::ReparseTagNotHandled)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rejects_unsupported_symlink_reparse_flags() {
        let mut input = vec![0; 128];
        assert_eq!(
            pack_symlink_reparse_buffer(b"target", input.as_mut_slice()),
            Ok(44)
        );
        assert_eq!(
            LittleEndianOutput::new(input.as_mut_slice()).write_u32(wire_offset(16), 2),
            Ok(())
        );

        assert_eq!(
            parse_symlink_reparse_buffer(input.as_slice()),
            Err(DriverError::NotSupported)
        );
    }
}
