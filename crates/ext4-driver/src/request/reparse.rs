//! Reparse-point FSCTL packing and xattr-backed mutation.

use alloc::vec::Vec;

use crate::irp::{DispatchTarget, IrpCompletion};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use crate::state::{OpenedLocation, OpenedObject, VolumeControlBlock, VolumeOperationLane};
use crate::wire::{LittleEndianInput, LittleEndianOutput, WireByteLen, WireOffset, WireRange};
use ext4_core::{NodeId, SymlinkNodeId, SymlinkTarget, WindowsSymlinkReparsePoint};

/// Reparse buffer header before the tag-specific payload.
const REPARSE_DATA_BUFFER_HEADER_SIZE: usize = 8;
/// SymbolicLinkReparseBuffer header before `PathBuffer`.
const SYMLINK_REPARSE_BUFFER_HEADER_SIZE: usize = 12;
/// Offset of `PathBuffer` inside `REPARSE_DATA_BUFFER`.
const SYMLINK_PATH_BUFFER_OFFSET: usize =
    REPARSE_DATA_BUFFER_HEADER_SIZE + SYMLINK_REPARSE_BUFFER_HEADER_SIZE;
/// Maximum byte size accepted by Windows for one complete reparse data buffer.
const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;
/// Maximum target length when substitute and print names share one UTF-16 path region.
const MAXIMUM_SYMLINK_PATH_CODE_UNITS: usize =
    (MAXIMUM_REPARSE_DATA_BUFFER_SIZE - SYMLINK_PATH_BUFFER_OFFSET) / core::mem::size_of::<u16>();

/// Reparse metadata attached to one ext4 node without forcing its target into Windows wire form.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum NodeSymlinkReparsePoint {
    /// Symbolic-link metadata stored in the driver's private Windows xattr.
    WindowsSymlink(WindowsSymlinkReparsePoint),
    /// A native ext4 symbolic-link inode whose target is loaded only when redirection is required.
    NativeSymlink(SymlinkNodeId),
}

impl NodeSymlinkReparsePoint {
    /// Loads the reparse classification for `node` without converting its target to UTF-16.
    /// # Errors
    ///
    /// Returns an error when driver-owned Windows reparse metadata is malformed or cannot be read.
    pub(crate) async fn load(
        operations: &mut VolumeOperationLane,
        node: NodeId,
    ) -> DriverResult<Option<Self>> {
        match node {
            NodeId::Symlink(symlink) => Ok(Some(Self::NativeSymlink(symlink))),
            NodeId::File(_) | NodeId::Directory(_) => Ok(operations
                .journaled_mut()
                .read_windows_symlink_reparse_point(node)
                .await?
                .map(Self::WindowsSymlink)),
        }
    }

    /// Converts this classified node into the owned symbolic-link data shared by create redirects
    /// and `FSCTL_GET_REPARSE_POINT`.
    /// # Errors
    ///
    /// Returns an error when a native target cannot be read, the target is not UTF-8, allocation
    /// fails, or the resulting Windows reparse buffer would exceed 16 KiB.
    pub(crate) async fn into_symlink_data(
        self,
        operations: &mut VolumeOperationLane,
    ) -> DriverResult<SymlinkReparseData> {
        match self {
            Self::WindowsSymlink(reparse_point) => {
                SymlinkReparseData::from_windows_reparse_point(&reparse_point)
            }
            Self::NativeSymlink(symlink) => {
                let target = read_core_symlink(operations, symlink).await?;
                SymlinkReparseData::from_native_ext4_target(target.as_slice())
            }
        }
    }
}

/// Owned Windows symbolic-link target ready for either reparse wire boundary.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SymlinkReparseData {
    /// Target shared by the substitute and print name fields.
    path: DriverVec<u16>,
    /// Whether the symbolic-link target is relative to its containing directory.
    relative: bool,
}

/// Byte length of the create path suffix that Windows has not yet parsed.
///
/// Construction from UTF-16 keeps the wire unit and its `u16` representability out of create
/// request code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnparsedPathLength(u16);

impl UnparsedPathLength {
    /// No unparsed UTF-16 suffix remains.
    pub(crate) const ZERO: Self = Self(0);

    /// Creates a checked byte length from an unparsed UTF-16 path suffix.
    /// # Errors
    ///
    /// Returns an error when twice the code-unit count cannot be represented by the Windows
    /// `USHORT` field.
    pub(crate) fn from_utf16_suffix(suffix: &[u16]) -> DriverResult<Self> {
        let bytes = utf16_byte_len(suffix)?;
        Ok(Self(
            u16::try_from(bytes).map_err(|_| DriverError::InvalidParameter)?,
        ))
    }

    /// Returns the validated byte length only at the wire encoder boundary.
    const fn wire_value(self) -> u16 {
        self.0
    }
}

/// Derived symbolic-link wire lengths used by all output modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SymlinkReparseLayout {
    /// Byte length of one UTF-16 target copy.
    path_bytes: u16,
    /// Tag-specific byte length written to `ReparseDataLength`.
    reparse_data_length: u16,
    /// Complete `REPARSE_DATA_BUFFER` byte length.
    total_length: usize,
}

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
pub(crate) async fn get_reparse_point(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    let (length, node, operations) = {
        let stack = target.current_stack()?.file_system_control()?;
        let opened = OpenedObject::decode(stack.file_object())?;
        let node = opened.node();
        let operations = unsafe {
            // SAFETY: Queued filesystem-control requests run one at a time on the mounted-device
            // executor, so this request owns the unique operation-lane capability until completion.
            VolumeControlBlock::claim_operation_lane(opened.volume())
        };
        (stack.output_buffer_length(), node, operations)
    };
    let data = {
        let mut operations = operations;
        load_node_reparse_data(operations.lane_mut(), node).await?
    };
    let mut output = target.buffered_output(length)?;
    let written = data.pack_fsctl(output.as_mut_slice())?;
    IrpCompletion::from_usize(written)
}

/// Handles `FSCTL_SET_REPARSE_POINT` by storing Windows metadata on the opened node.
/// # Errors
///
/// Returns an error when the input is malformed, the opened node is a native symbolic link, or
/// the reparse xattr cannot be committed.
pub(crate) async fn set_reparse_point(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    let (reparse_point, node, mut operations) = {
        let stack = target.current_stack()?.file_system_control()?;
        let input = target.buffered_input(stack.input_buffer_length())?;
        let reparse_point = parse_symlink_reparse_buffer(input.as_slice())?;
        let opened = OpenedObject::decode(stack.file_object())?;
        let node = opened.node();
        validate_mutable_reparse_node(opened.location(), node)?;
        let operations = unsafe {
            // SAFETY: Queued filesystem-control requests run one at a time on the mounted-device
            // executor, so this request owns the unique operation-lane capability until completion.
            VolumeControlBlock::claim_operation_lane(opened.volume())
        };
        (reparse_point, node, operations)
    };
    set_node_reparse_point(operations.lane_mut(), node, reparse_point).await?;
    Ok(IrpCompletion::EMPTY)
}

/// Handles `FSCTL_DELETE_REPARSE_POINT` by removing driver-owned Windows metadata.
/// # Errors
///
/// Returns an error when the input is malformed, the opened object is not a driver-owned reparse
/// point, or the xattr mutation cannot be committed.
pub(crate) async fn delete_reparse_point(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    let (node, mut operations) = {
        let stack = target.current_stack()?.file_system_control()?;
        let input = target.buffered_input(stack.input_buffer_length())?;
        parse_delete_reparse_buffer(input.as_slice())?;
        let opened = OpenedObject::decode(stack.file_object())?;
        let node = opened.node();
        validate_mutable_reparse_node(opened.location(), node)?;
        let operations = unsafe {
            // SAFETY: Queued filesystem-control requests run one at a time on the mounted-device
            // executor, so this request owns the unique operation-lane capability until completion.
            VolumeControlBlock::claim_operation_lane(opened.volume())
        };
        (node, operations)
    };
    delete_node_reparse_point(operations.lane_mut(), node).await?;
    Ok(IrpCompletion::EMPTY)
}

/// Packs the reparse point represented by one opened object.
/// # Errors
///
/// Returns an error when the object has no reparse metadata, the target cannot be read, or the
/// output cannot hold the symbolic-link reparse buffer.
async fn load_node_reparse_data(
    operations: &mut VolumeOperationLane,
    node: NodeId,
) -> DriverResult<SymlinkReparseData> {
    let reparse_point = NodeSymlinkReparsePoint::load(operations, node)
        .await?
        .ok_or(DriverError::NotAReparsePoint)?;
    reparse_point.into_symlink_data(operations).await
}

/// Validates that an opened object can carry driver-owned Windows reparse metadata.
/// # Errors
///
/// Returns an error when the opened object is the volume root or a native symbolic link.
fn validate_mutable_reparse_node(location: &OpenedLocation, node: NodeId) -> DriverResult<()> {
    if matches!(location, OpenedLocation::Root) {
        return Err(DriverError::NotSupported);
    }
    match node {
        NodeId::File(_) | NodeId::Directory(_) => Ok(()),
        NodeId::Symlink(_) => Err(DriverError::NotSupported),
    }
}

/// Stores a Windows reparse point on a validated regular file or directory.
/// # Errors
///
/// Returns an error when the reparse xattr mutation cannot be committed.
async fn set_node_reparse_point(
    operations: &mut VolumeOperationLane,
    node: NodeId,
    reparse_point: WindowsSymlinkReparsePoint,
) -> DriverResult<()> {
    let mut transaction = operations
        .journaled_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let node = transaction.node(node).await?;
    transaction
        .set_windows_symlink_reparse_point(node, reparse_point)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Removes Windows reparse metadata from a validated regular file or directory.
/// # Errors
///
/// Returns an error when the node has no driver-owned reparse metadata or the xattr mutation
/// cannot be committed.
async fn delete_node_reparse_point(
    operations: &mut VolumeOperationLane,
    node: NodeId,
) -> DriverResult<()> {
    let mut transaction = operations
        .journaled_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let node = transaction.node(node).await?;
    if transaction
        .remove_windows_symlink_reparse_point(node)
        .await?
        .is_none()
    {
        return Err(DriverError::NotAReparsePoint);
    }
    transaction.commit().await?;
    Ok(())
}

/// Reads a symlink inode through ext4-core.
/// # Errors
///
/// Returns an error when `symlink_id` cannot be loaded or its target bytes cannot be read.
async fn read_core_symlink(
    operations: &mut VolumeOperationLane,
    symlink_id: SymlinkNodeId,
) -> DriverResult<Vec<u8>> {
    let symlink = operations.journaled_mut().load_symlink(symlink_id).await?;
    Ok(operations.journaled_mut().read_symlink(&symlink).await?)
}

impl SymlinkReparseData {
    /// Converts driver-owned Windows xattr metadata without changing its target path syntax.
    /// # Errors
    ///
    /// Returns an error when the target is not UTF-8, allocation fails, or the symbolic-link
    /// reparse buffer would exceed 16 KiB.
    fn from_windows_reparse_point(
        reparse_point: &WindowsSymlinkReparsePoint,
    ) -> DriverResult<Self> {
        let target = reparse_point.target().bytes();
        let target = core::str::from_utf8(target).map_err(|_| DriverError::NotSupported)?;
        Self::from_windows_path_characters(
            target.chars(),
            target.len(),
            reparse_point.is_relative(),
        )
    }

    /// Converts a native ext4 target into Windows path syntax before encoding it as UTF-16.
    /// # Errors
    ///
    /// Returns an error when the target is not UTF-8, one of its component characters cannot be
    /// represented by the Windows namespace, allocation fails, or the symbolic-link reparse
    /// buffer would exceed 16 KiB.
    fn from_native_ext4_target(target: &[u8]) -> DriverResult<Self> {
        let target = core::str::from_utf8(target).map_err(|_| DriverError::NotSupported)?;
        if target
            .chars()
            .any(native_symlink_character_is_unrepresentable_on_windows)
        {
            return Err(DriverError::NotSupported);
        }
        let mut previous_was_separator = false;
        Self::from_windows_path_characters(
            target.chars().filter_map(|character| {
                if character != '/' {
                    previous_was_separator = false;
                    return Some(character);
                }
                if previous_was_separator {
                    return None;
                }
                previous_was_separator = true;
                Some('\\')
            }),
            target.len(),
            // Every native ext4 target stays on the mounted volume. A leading POSIX `/` becomes
            // Windows root-relative syntax, which is still a relative symbolic-link form.
            true,
        )
    }

    /// Builds owned reparse data from a character stream already expressed in Windows syntax.
    /// # Errors
    ///
    /// Returns an error when allocation fails or the symbolic-link reparse buffer would exceed
    /// 16 KiB.
    fn from_windows_path_characters(
        characters: impl Iterator<Item = char>,
        capacity_hint: usize,
        relative: bool,
    ) -> DriverResult<Self> {
        let capacity = core::cmp::min(capacity_hint, MAXIMUM_SYMLINK_PATH_CODE_UNITS);
        let mut path = DriverVec::try_with_capacity(capacity)?;
        for character in characters {
            let mut encoded = [0_u16; 2];
            for unit in character.encode_utf16(&mut encoded).iter().copied() {
                if path.len() == MAXIMUM_SYMLINK_PATH_CODE_UNITS {
                    return Err(DriverError::NotSupported);
                }
                path.try_push(unit)?;
            }
        }
        let data = Self { path, relative };
        let _layout = data.layout()?;
        Ok(data)
    }

    /// Returns the complete byte length required by either output representation.
    /// # Errors
    ///
    /// Returns an error when a derived length overflows its Windows wire field or the complete
    /// reparse buffer would exceed 16 KiB.
    pub(crate) fn required_length(&self) -> DriverResult<usize> {
        Ok(self.layout()?.total_length)
    }

    /// Packs an `FSCTL_GET_REPARSE_POINT` response with the reserved header field cleared.
    /// # Errors
    ///
    /// Returns an error when a derived length is not representable or `output` is too small.
    pub(crate) fn pack_fsctl(&self, output: &mut [u8]) -> DriverResult<usize> {
        self.pack(UnparsedPathLength::ZERO, output)
    }

    /// Packs a create redirect carrying the checked byte length of the unparsed UTF-16 suffix.
    /// # Errors
    ///
    /// Returns an error when a derived length is not representable or `output` is too small.
    pub(crate) fn pack_create_redirect(
        &self,
        unparsed_path_length: UnparsedPathLength,
        output: &mut [u8],
    ) -> DriverResult<usize> {
        self.pack(unparsed_path_length, output)
    }

    /// Computes every derived wire length from the single owned UTF-16 target.
    /// # Errors
    ///
    /// Returns an error when a derived length overflows its Windows wire field or the complete
    /// reparse buffer would exceed 16 KiB.
    fn layout(&self) -> DriverResult<SymlinkReparseLayout> {
        let path_bytes = utf16_byte_len(self.path.as_slice())?;
        let reparse_data_length = SYMLINK_REPARSE_BUFFER_HEADER_SIZE
            .checked_add(path_bytes)
            .ok_or(DriverError::InvalidParameter)?;
        let total_length = REPARSE_DATA_BUFFER_HEADER_SIZE
            .checked_add(reparse_data_length)
            .ok_or(DriverError::InvalidParameter)?;
        if total_length > MAXIMUM_REPARSE_DATA_BUFFER_SIZE {
            return Err(DriverError::NotSupported);
        }
        Ok(SymlinkReparseLayout {
            path_bytes: u16::try_from(path_bytes).map_err(|_| DriverError::NotSupported)?,
            reparse_data_length: u16::try_from(reparse_data_length)
                .map_err(|_| DriverError::NotSupported)?,
            total_length,
        })
    }

    /// Writes the common symbolic-link layout with one already-validated reserved-field value.
    /// # Errors
    ///
    /// Returns an error when a derived length is not representable or `output` is too small.
    fn pack(
        &self,
        unparsed_path_length: UnparsedPathLength,
        output: &mut [u8],
    ) -> DriverResult<usize> {
        let layout = self.layout()?;
        if output.len() < layout.total_length {
            return Err(DriverError::BufferTooSmall);
        }
        let flags = if self.relative {
            wdk_sys::SYMLINK_FLAG_RELATIVE
        } else {
            0
        };

        let mut output = LittleEndianOutput::new(output);
        output.write_u32(wire_offset(0), wdk_sys::IO_REPARSE_TAG_SYMLINK)?;
        output.write_u16(wire_offset(4), layout.reparse_data_length)?;
        output.write_u16(wire_offset(6), unparsed_path_length.wire_value())?;
        output.write_u16(wire_offset(8), 0)?;
        output.write_u16(wire_offset(10), layout.path_bytes)?;
        output.write_u16(wire_offset(12), 0)?;
        output.write_u16(wire_offset(14), layout.path_bytes)?;
        output.write_u32(wire_offset(16), flags)?;
        write_utf16(
            &mut output,
            SYMLINK_PATH_BUFFER_OFFSET,
            self.path.as_slice(),
        )?;
        Ok(layout.total_length)
    }
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
    if total_length > MAXIMUM_REPARSE_DATA_BUFFER_SIZE {
        return Err(DriverError::InvalidParameter);
    }
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

/// Returns whether one native ext4 path character cannot be represented losslessly in a Windows
/// path component.
const fn native_symlink_character_is_unrepresentable_on_windows(character: char) -> bool {
    matches!(
        character,
        '\0'..='\u{1F}' | '"' | '*' | ':' | '<' | '>' | '?' | '\\' | '|'
    )
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
    use ext4_core::{SymlinkTarget, WindowsSymlinkReparsePoint};

    use super::{
        MAXIMUM_REPARSE_DATA_BUFFER_SIZE, MAXIMUM_SYMLINK_PATH_CODE_UNITS,
        SYMLINK_PATH_BUFFER_OFFSET, SymlinkReparseData, UnparsedPathLength,
        parse_delete_reparse_buffer, parse_symlink_reparse_buffer, wire_offset,
    };

    /// Builds Windows-xattr symbolic-link test data through its production conversion path.
    /// # Errors
    ///
    /// Returns an error when the target is not valid xattr metadata or cannot be represented.
    fn windows_symlink_data(
        target: &[u8],
        relative: bool,
    ) -> Result<SymlinkReparseData, DriverError> {
        let reparse_point = WindowsSymlinkReparsePoint::new(SymlinkTarget::new(target)?, relative);
        SymlinkReparseData::from_windows_reparse_point(&reparse_point)
    }

    /// Builds and packs Windows-xattr symbolic-link test data through the production FSCTL path.
    /// # Errors
    ///
    /// Returns an error when the test target or output buffer is not representable.
    fn pack_fsctl_target(
        target: &[u8],
        relative: bool,
        output: &mut [u8],
    ) -> Result<usize, DriverError> {
        windows_symlink_data(target, relative)?.pack_fsctl(output)
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn packs_relative_symlink_reparse_buffer() {
        let mut output = vec![0; 128];
        const WRITTEN_LENGTH: usize = 36;
        const REPARSE_DATA_LENGTH: u16 = 28;

        assert_eq!(
            pack_fsctl_target(br"dir\file", true, output.as_mut_slice()),
            Ok(WRITTEN_LENGTH)
        );
        assert_eq!(
            LittleEndianInput::new(output.as_slice()).read_u32(wire_offset(0)),
            Ok(wdk_sys::IO_REPARSE_TAG_SYMLINK)
        );
        let output = LittleEndianInput::new(output.as_slice());
        assert_eq!(output.read_u16(wire_offset(4)), Ok(REPARSE_DATA_LENGTH));
        assert_eq!(output.read_u16(wire_offset(6)), Ok(0));
        assert_eq!(output.read_u16(wire_offset(8)), Ok(0));
        assert_eq!(output.read_u16(wire_offset(10)), Ok(16));
        assert_eq!(output.read_u16(wire_offset(12)), Ok(0));
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
        const WRITTEN_LENGTH: usize = 46;

        assert_eq!(
            pack_fsctl_target(br"\??\C:\target", false, output.as_mut_slice()),
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
    fn native_relative_target_uses_windows_separators_on_wire() {
        let data = SymlinkReparseData::from_native_ext4_target(b"dir/file");
        assert!(data.is_ok());
        let Ok(data) = data else {
            return;
        };
        let mut output = vec![0; 128];
        assert_eq!(data.pack_fsctl(output.as_mut_slice()), Ok(36));
        assert_eq!(
            LittleEndianInput::new(output.as_slice()).read_u32(wire_offset(16)),
            Ok(wdk_sys::SYMLINK_FLAG_RELATIVE)
        );

        let parsed = parse_symlink_reparse_buffer(output.as_slice());
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else {
            return;
        };
        assert_eq!(parsed.target().bytes(), br"dir\file");
        assert!(parsed.is_relative());
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn native_rooted_target_becomes_windows_root_relative() {
        let data = SymlinkReparseData::from_native_ext4_target(b"/dir/file");
        assert!(data.is_ok());
        let Ok(data) = data else {
            return;
        };
        let mut output = vec![0; 128];
        assert_eq!(data.pack_fsctl(output.as_mut_slice()), Ok(38));
        assert_eq!(
            LittleEndianInput::new(output.as_slice()).read_u32(wire_offset(16)),
            Ok(wdk_sys::SYMLINK_FLAG_RELATIVE)
        );

        let parsed = parse_symlink_reparse_buffer(output.as_slice());
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else {
            return;
        };
        assert_eq!(parsed.target().bytes(), br"\dir\file");
        assert!(parsed.is_relative());
    }

    /// # Panics
    ///
    /// Panics when native POSIX separator normalization changes target meaning or accepts a path
    /// component that Windows cannot represent losslessly.
    #[test]
    fn native_target_normalization_collapses_separators_and_rejects_windows_metacharacters() {
        let data = SymlinkReparseData::from_native_ext4_target(b"/dir//child/");
        assert!(data.is_ok());
        let Ok(data) = data else {
            return;
        };
        let mut output = vec![0; 128];
        assert_eq!(data.pack_fsctl(output.as_mut_slice()), Ok(42));
        let parsed = parse_symlink_reparse_buffer(output.as_slice());
        assert!(parsed.is_ok());
        if let Ok(parsed) = parsed {
            assert_eq!(parsed.target().bytes(), br"\dir\child\");
            assert!(parsed.is_relative());
        }

        for target in [
            br"dir\child".as_slice(),
            b"drive:name",
            b"wild?card",
            b"control\x1F",
        ] {
            assert_eq!(
                SymlinkReparseData::from_native_ext4_target(target),
                Err(DriverError::NotSupported)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rejects_too_small_reparse_buffer() {
        const TOO_SMALL_BUFFER_LENGTH: usize = 19;
        let mut output = vec![0; TOO_SMALL_BUFFER_LENGTH];

        assert_eq!(
            pack_fsctl_target(b"target", true, output.as_mut_slice()),
            Err(DriverError::BufferTooSmall)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_redirect_packs_checked_unparsed_utf16_byte_length() {
        let mut output = vec![0; 128];
        let suffix = Vec::from([u16::from(b'n'), u16::from(b'e'), u16::from(b'x')]);
        let unparsed_path_length = UnparsedPathLength::from_utf16_suffix(suffix.as_slice());
        assert_eq!(unparsed_path_length, Ok(UnparsedPathLength(6)));
        let Ok(unparsed_path_length) = unparsed_path_length else {
            return;
        };

        assert_eq!(
            windows_symlink_data(b"target", true).and_then(|data| {
                data.pack_create_redirect(unparsed_path_length, output.as_mut_slice())
            }),
            Ok(32)
        );
        assert_eq!(
            LittleEndianInput::new(output.as_slice()).read_u16(wire_offset(6)),
            Ok(6)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn unparsed_path_length_checks_utf16_byte_representation() {
        assert_eq!(
            UnparsedPathLength::from_utf16_suffix(&[]),
            Ok(UnparsedPathLength::ZERO)
        );
        let largest_suffix = vec![0_u16; usize::from(u16::MAX) / 2];
        assert_eq!(
            UnparsedPathLength::from_utf16_suffix(largest_suffix.as_slice()),
            Ok(UnparsedPathLength(u16::MAX - 1))
        );
        let oversized_suffix = vec![0_u16; usize::from(u16::MAX) / 2 + 1];
        assert_eq!(
            UnparsedPathLength::from_utf16_suffix(oversized_suffix.as_slice()),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn symbolic_link_output_honors_windows_sixteen_kibibyte_limit() {
        let largest_target = vec![b'a'; MAXIMUM_SYMLINK_PATH_CODE_UNITS];
        let largest = windows_symlink_data(largest_target.as_slice(), true);
        assert!(largest.is_ok());
        let Ok(largest) = largest else {
            return;
        };
        assert_eq!(
            largest.required_length(),
            Ok(MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
        );
        let mut output = vec![0; MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
        assert_eq!(
            largest.pack_fsctl(output.as_mut_slice()),
            Ok(MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
        );

        let oversized_target = vec![b'a'; MAXIMUM_SYMLINK_PATH_CODE_UNITS + 1];
        assert_eq!(
            windows_symlink_data(oversized_target.as_slice(), true),
            Err(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn parses_symlink_reparse_buffer_target_and_relative_flag() {
        let mut input = vec![0; 128];
        let expected = Vec::from(&br"dir\file"[..]);
        assert_eq!(
            pack_fsctl_target(expected.as_slice(), true, input.as_mut_slice()),
            Ok(36)
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
            pack_fsctl_target(b"target", true, input.as_mut_slice()),
            Ok(32)
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
            pack_fsctl_target(b"target", true, input.as_mut_slice()),
            Ok(32)
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
    fn rejects_symlink_input_larger_than_windows_reparse_limit() {
        let mut input = [0_u8; 8];
        let oversized_data_length =
            u16::try_from(MAXIMUM_REPARSE_DATA_BUFFER_SIZE - input.len() + 1);
        assert!(oversized_data_length.is_ok());
        let Ok(oversized_data_length) = oversized_data_length else {
            return;
        };
        let mut output = LittleEndianOutput::new(&mut input);
        assert_eq!(
            output.write_u32(wire_offset(0), wdk_sys::IO_REPARSE_TAG_SYMLINK),
            Ok(())
        );
        assert_eq!(
            output.write_u16(wire_offset(4), oversized_data_length),
            Ok(())
        );

        assert_eq!(
            parse_symlink_reparse_buffer(&input),
            Err(DriverError::InvalidParameter)
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
