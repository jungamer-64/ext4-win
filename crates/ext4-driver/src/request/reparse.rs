//! Reparse-point FSCTL packing and xattr-backed mutation.

use alloc::vec::Vec;

use crate::irp::{DispatchTarget, FileSystemControlStack, IrpCompletion};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use crate::state::{OpenedLocation, OpenedObject, VolumeControlBlock};
use crate::wire::{LittleEndianInput, LittleEndianOutput, WireByteLen, WireOffset, WireRange};
use ext4_core::{NodeId, SymlinkNodeId, SymlinkTarget, WindowsSymlinkReparsePoint};

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

/// Handles `FSCTL_GET_REPARSE_POINT` for a driver-owned or native symlink reparse point.
/// # Errors
///
/// Returns an error when the opened object is not a reparse point, its target cannot be read, or
/// the output buffer cannot hold the reparse data.
pub(crate) fn get_reparse_point(
    target: DispatchTarget,
    stack: FileSystemControlStack,
) -> DriverResult<IrpCompletion> {
    let opened = OpenedObject::decode(stack.file_object())?;
    let length = stack.output_buffer_length();
    let mut output = target.buffered_output(length)?;
    let written = pack_opened_reparse_point(&opened, output.as_mut_slice())?;
    IrpCompletion::from_usize(written)
}

/// Handles `FSCTL_SET_REPARSE_POINT` by storing Windows metadata on the opened node.
/// # Errors
///
/// Returns an error when the input is malformed, the opened node is a native symbolic link, or
/// the reparse xattr cannot be committed.
pub(crate) fn set_reparse_point(
    target: DispatchTarget,
    stack: FileSystemControlStack,
) -> DriverResult<IrpCompletion> {
    let input = target.buffered_input(stack.input_buffer_length())?;
    let reparse_point = parse_symlink_reparse_buffer(input.as_slice())?;
    let opened = OpenedObject::decode(stack.file_object())?;
    set_opened_reparse_point(&opened, reparse_point)?;
    Ok(IrpCompletion::EMPTY)
}

/// Handles `FSCTL_DELETE_REPARSE_POINT` by removing driver-owned Windows metadata.
/// # Errors
///
/// Returns an error when the input is malformed, the opened object is not a driver-owned reparse
/// point, or the xattr mutation cannot be committed.
pub(crate) fn delete_reparse_point(
    target: DispatchTarget,
    stack: FileSystemControlStack,
) -> DriverResult<IrpCompletion> {
    let input = target.buffered_input(stack.input_buffer_length())?;
    parse_delete_reparse_buffer(input.as_slice())?;
    let opened = OpenedObject::decode(stack.file_object())?;
    delete_opened_reparse_point(&opened)?;
    Ok(IrpCompletion::EMPTY)
}

/// Packs the reparse point represented by one opened object.
/// # Errors
///
/// Returns an error when the object has no reparse metadata, the target cannot be read, or the
/// output cannot hold the symbolic-link reparse buffer.
fn pack_opened_reparse_point(opened: &OpenedObject, output: &mut [u8]) -> DriverResult<usize> {
    let vcb = unsafe {
        // SAFETY: The decoded FCB owns a live mounted VCB for the whole FILE_OBJECT lifetime.
        opened.volume().as_ref()
    };
    match opened.node() {
        NodeId::File(_) | NodeId::Directory(_) => {
            let Some(reparse_point) = vcb
                .volume()
                .read_windows_symlink_reparse_point(opened.node())?
            else {
                return Err(DriverError::NotAReparsePoint);
            };
            pack_symlink_reparse_buffer(
                reparse_point.target().bytes(),
                reparse_point.is_relative(),
                output,
            )
        }
        NodeId::Symlink(symlink) => {
            let target = read_core_symlink(vcb, symlink)?;
            pack_symlink_reparse_buffer(
                target.as_slice(),
                is_relative_symlink_target(target.as_slice()),
                output,
            )
        }
    }
}

/// Stores a Windows reparse point on an opened regular file or directory.
/// # Errors
///
/// Returns an error when the opened object is the volume root or a native symlink, or the xattr
/// mutation cannot be committed.
fn set_opened_reparse_point(
    opened: &OpenedObject,
    reparse_point: WindowsSymlinkReparsePoint,
) -> DriverResult<()> {
    if matches!(opened.location(), OpenedLocation::Root) {
        return Err(DriverError::NotSupported);
    }
    match opened.node() {
        NodeId::File(_) | NodeId::Directory(_) => {}
        NodeId::Symlink(_) => return Err(DriverError::NotSupported),
    }
    let mut vcb = opened.volume();
    let vcb = unsafe {
        // SAFETY: The decoded FCB owns a live mounted VCB. The mutable borrow is the synchronous
        // transaction boundary for this reparse metadata mutation.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let node = transaction.node(opened.node())?;
    transaction.set_windows_symlink_reparse_point(node, reparse_point)?;
    transaction.commit()?;
    Ok(())
}

/// Removes Windows reparse metadata from an opened regular file or directory.
/// # Errors
///
/// Returns an error when the opened object is the volume root or a native symlink, has no
/// driver-owned reparse metadata, or the xattr mutation cannot be committed.
fn delete_opened_reparse_point(opened: &OpenedObject) -> DriverResult<()> {
    if matches!(opened.location(), OpenedLocation::Root) {
        return Err(DriverError::NotSupported);
    }
    match opened.node() {
        NodeId::File(_) | NodeId::Directory(_) => {}
        NodeId::Symlink(_) => return Err(DriverError::NotSupported),
    }
    let mut vcb = opened.volume();
    let vcb = unsafe {
        // SAFETY: The decoded FCB owns a live mounted VCB. The mutable borrow is the synchronous
        // transaction boundary for this reparse metadata mutation.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let node = transaction.node(opened.node())?;
    if transaction
        .remove_windows_symlink_reparse_point(node)?
        .is_none()
    {
        return Err(DriverError::NotAReparsePoint);
    }
    transaction.commit()?;
    Ok(())
}

/// Reads a symlink inode through ext4-core.
/// # Errors
///
/// Returns an error when `symlink_id` cannot be loaded or its target bytes cannot be read.
fn read_core_symlink(vcb: &VolumeControlBlock, symlink_id: SymlinkNodeId) -> DriverResult<Vec<u8>> {
    let symlink = vcb.volume().load_symlink(symlink_id)?;
    Ok(vcb.volume().read_symlink(&symlink)?)
}

/// Packs symbolic-link data into a Windows symbolic-link reparse buffer.
/// # Errors
///
/// Returns an error when the target is not UTF-8, path length fields overflow, or the output
/// buffer is too small.
fn pack_symlink_reparse_buffer(
    target: &[u8],
    relative: bool,
    output: &mut [u8],
) -> DriverResult<usize> {
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
    let flags = if relative {
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

/// Parses a Windows symbolic-link reparse buffer into driver-owned reparse metadata.
/// # Errors
///
/// Returns an error when the tag, paths, flags, or UTF-16 target are unsupported or malformed.
fn parse_symlink_reparse_buffer(input: &[u8]) -> DriverResult<WindowsSymlinkReparsePoint> {
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
    let print_name_offset = usize::from(input.read_u16(wire_offset(12))?);
    let print_name_length = usize::from(input.read_u16(wire_offset(14))?);
    let flags = input.read_u32(wire_offset(16))?;
    if flags & !wdk_sys::SYMLINK_FLAG_RELATIVE != 0 {
        return Err(DriverError::NotSupported);
    }

    let path_buffer_length = reparse_data_length
        .checked_sub(SYMLINK_REPARSE_BUFFER_HEADER_SIZE)
        .ok_or(DriverError::InvalidParameter)?;
    let substitute_range = symlink_path_range(
        path_buffer_length,
        substitute_name_offset,
        substitute_name_length,
    )?;
    let _print_range =
        symlink_path_range(path_buffer_length, print_name_offset, print_name_length)?;
    let units = reparse_path_units(input, substitute_range)?;
    let target = utf16_to_utf8_bytes(units.as_slice())?;
    Ok(WindowsSymlinkReparsePoint::new(
        SymlinkTarget::new(target.as_slice())?,
        flags & wdk_sys::SYMLINK_FLAG_RELATIVE != 0,
    ))
}

/// Parses the exact header accepted by `FSCTL_DELETE_REPARSE_POINT` for symbolic links.
/// # Errors
///
/// Returns an error when the input is not exactly a header for a symbolic-link reparse point with
/// an empty tag-specific payload.
fn parse_delete_reparse_buffer(input: &[u8]) -> DriverResult<()> {
    if input.len() < REPARSE_DATA_BUFFER_HEADER_SIZE {
        return Err(DriverError::BufferTooSmall);
    }
    if input.len() != REPARSE_DATA_BUFFER_HEADER_SIZE {
        return Err(DriverError::InvalidParameter);
    }
    let input = LittleEndianInput::new(input);
    if input.read_u32(wire_offset(0))? != wdk_sys::IO_REPARSE_TAG_SYMLINK {
        return Err(DriverError::ReparseTagNotHandled);
    }
    if input.read_u16(wire_offset(4))? != 0 {
        return Err(DriverError::InvalidParameter);
    }
    Ok(())
}

/// Validates and returns one path range inside a symbolic-link reparse buffer.
/// # Errors
///
/// Returns an error when the range is not UTF-16 aligned, overflows, or lies outside `PathBuffer`.
fn symlink_path_range(
    path_buffer_length: usize,
    offset: usize,
    length: usize,
) -> DriverResult<WireRange> {
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
    wire_range(start, length)
}

/// Reads UTF-16 units from a validated symbolic-link path range.
/// # Errors
///
/// Returns an error when the range cannot be read or allocation fails.
fn reparse_path_units(
    input: LittleEndianInput<'_>,
    range: WireRange,
) -> DriverResult<DriverVec<u16>> {
    let bytes = input.range(range)?;
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

/// Returns whether a native ext4 symlink target should carry `SYMLINK_FLAG_RELATIVE`.
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
        SYMLINK_PATH_BUFFER_OFFSET, pack_symlink_reparse_buffer, parse_delete_reparse_buffer,
        parse_symlink_reparse_buffer, wire_offset,
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
            pack_symlink_reparse_buffer(b"dir/file", true, output.as_mut_slice()),
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
            pack_symlink_reparse_buffer(br"\??\C:\target", false, output.as_mut_slice()),
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
            pack_symlink_reparse_buffer(b"target", true, output.as_mut_slice()),
            Err(DriverError::BufferTooSmall)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn parses_symlink_reparse_buffer_target_and_relative_flag() {
        let mut input = vec![0; 128];
        let expected = Vec::from(&b"dir/file"[..]);
        assert_eq!(
            pack_symlink_reparse_buffer(expected.as_slice(), true, input.as_mut_slice()),
            Ok(52)
        );

        let parsed = parse_symlink_reparse_buffer(input.as_slice());
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else {
            return;
        };
        assert_eq!(parsed.target().bytes(), expected.as_slice());
        assert!(parsed.is_relative());
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rejects_unhandled_reparse_tag_on_set() {
        let mut input = vec![0; 128];
        assert_eq!(
            pack_symlink_reparse_buffer(b"target", true, input.as_mut_slice()),
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
            pack_symlink_reparse_buffer(b"target", true, input.as_mut_slice()),
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn delete_reparse_requires_exact_empty_symlink_header() {
        let mut input = [0_u8; 8];
        assert_eq!(
            LittleEndianOutput::new(&mut input)
                .write_u32(wire_offset(0), wdk_sys::IO_REPARSE_TAG_SYMLINK),
            Ok(())
        );
        assert_eq!(parse_delete_reparse_buffer(&input), Ok(()));

        assert_eq!(
            parse_delete_reparse_buffer(&[0_u8; 7]),
            Err(DriverError::BufferTooSmall)
        );
        assert_eq!(
            parse_delete_reparse_buffer(&[0_u8; 9]),
            Err(DriverError::InvalidParameter)
        );

        let mut nonempty_payload = input;
        assert_eq!(
            LittleEndianOutput::new(&mut nonempty_payload).write_u16(wire_offset(4), 2),
            Ok(())
        );
        assert_eq!(
            parse_delete_reparse_buffer(&nonempty_payload),
            Err(DriverError::InvalidParameter)
        );

        let mut unhandled_tag = input;
        assert_eq!(
            LittleEndianOutput::new(&mut unhandled_tag).write_u32(wire_offset(0), 0),
            Ok(())
        );
        assert_eq!(
            parse_delete_reparse_buffer(&unhandled_tag),
            Err(DriverError::ReparseTagNotHandled)
        );
    }
}
