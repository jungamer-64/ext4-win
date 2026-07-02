//! Windows extended-attribute IRP handling.

use alloc::vec::Vec;
use ext4_core::{XattrName, XattrNamespace, XattrValue};
use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIRP};

use crate::irp::{
    DispatchTarget, EaEntryEmission, EaNameSelection, IrpCompletion, QueryEaStack, SetEaStack,
};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::{self, FallibleVec};
use crate::state::{FileControlBlock, OpenedObject, VolumeControlBlock};
use crate::wire::{LittleEndianInput, LittleEndianOutput, WireByteLen, WireOffset, WireRange};

/// Local xattr prefix used to store Windows EA records under `user.*`.
const EA_XATTR_PREFIX: &[u8] = b"ext4win.ea.";
/// Reserved public EA-name prefix that would collide with ext4win metadata.
const RESERVED_EA_NAME_PREFIX: &[u8] = b"ext4win.";
/// Bytes before `EaName` in `FILE_FULL_EA_INFORMATION`.
const FILE_FULL_EA_NAME_OFFSET: usize = 8;
/// Bytes before `EaName` in `FILE_GET_EA_INFORMATION`.
const FILE_GET_EA_NAME_OFFSET: usize = 5;
/// EA records are DWORD-aligned when another record follows.
const EA_RECORD_ALIGNMENT: usize = 4;

/// Creates a wire offset from an EA record-relative byte position.
const fn wire_offset(offset: usize) -> WireOffset {
    WireOffset::new(offset)
}

/// Creates a checked wire range from an EA record-relative byte position.
/// # Errors
///
/// Returns an error when `offset + length` cannot be represented as an EA wire range.
fn wire_range(offset: usize, length: usize) -> DriverResult<WireRange> {
    WireRange::new(wire_offset(offset), WireByteLen::new(length))
}

/// Handles IRP_MJ_QUERY_EA.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => target
            .finish_result(QueryEaRequest::decode(target).and_then(|request| query_ea(&request))),
        Err(error) => DispatchTarget::finish_decode_error(irp, error),
    }
}

/// Handles IRP_MJ_SET_EA.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            target.finish_result(SetEaRequest::decode(target).and_then(|request| set_ea(&request)))
        }
        Err(error) => DispatchTarget::finish_decode_error(irp, error),
    }
}

/// Decoded query-EA request.
#[derive(Debug)]
struct QueryEaRequest {
    /// Dispatch target receiving output.
    target: DispatchTarget,
    /// Decoded query-EA stack.
    stack: QueryEaStack,
    /// Opened file contexts decoded before EA handling.
    opened_file: OpenedObject,
}

impl QueryEaRequest {
    /// Decodes a query-EA request.
    /// # Errors
    ///
    /// Returns an error when the current stack is not a query-EA stack or its FILE_OBJECT has no
    /// opened ext4 context.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.query_ea()?;
        let opened_file = OpenedObject::decode(stack.file_object())?;
        Ok(Self {
            target,
            stack,
            opened_file,
        })
    }
}

/// Decoded set-EA request.
#[derive(Debug)]
struct SetEaRequest {
    /// Dispatch target carrying input.
    target: DispatchTarget,
    /// Decoded set-EA stack.
    stack: SetEaStack,
    /// Opened file contexts decoded before EA handling.
    opened_file: OpenedObject,
}

impl SetEaRequest {
    /// Decodes a set-EA request.
    /// # Errors
    ///
    /// Returns an error when the current stack is not a set-EA stack or its FILE_OBJECT has no
    /// opened ext4 context.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.set_ea()?;
        let opened_file = OpenedObject::decode(stack.file_object())?;
        Ok(Self {
            target,
            stack,
            opened_file,
        })
    }
}

/// Validated Windows EA name.
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsEaName {
    /// Windows EA name bytes.
    bytes: Vec<u8>,
}

impl WindowsEaName {
    /// Validates and stores a Windows EA name.
    /// # Errors
    ///
    /// Returns an error when the EA name is empty, contains NUL, uses the reserved ext4win prefix,
    /// or exceeds the one-byte FILE_FULL_EA_INFORMATION name length.
    fn new(name: &[u8]) -> DriverResult<Self> {
        if name.is_empty() || name.contains(&0) {
            return Err(DriverError::InvalidEaName);
        }
        if name.starts_with(RESERVED_EA_NAME_PREFIX) {
            return Err(DriverError::InvalidEaName);
        }
        u8::try_from(name.len()).map_err(|_| DriverError::InvalidEaName)?;
        Ok(Self {
            bytes: memory::copied_slice(name)?,
        })
    }

    /// Returns name bytes for Windows and xattr encoding.
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the name length.
    fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Copies this EA name without using infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the EA name bytes cannot allocate.
    fn try_clone(&self) -> DriverResult<Self> {
        Ok(Self {
            bytes: memory::copied_slice(self.as_bytes())?,
        })
    }
}

/// Validated Windows EA value.
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsEaValue {
    /// Windows EA value bytes.
    bytes: Vec<u8>,
}

impl WindowsEaValue {
    /// Stores a Windows EA value representable by FILE_FULL_EA_INFORMATION.
    /// # Errors
    ///
    /// Returns an error when the value exceeds the two-byte FILE_FULL_EA_INFORMATION value length.
    fn new(value: &[u8]) -> DriverResult<Self> {
        u16::try_from(value.len()).map_err(|_| DriverError::EaTooLarge)?;
        Ok(Self {
            bytes: memory::copied_slice(value)?,
        })
    }

    /// Returns value bytes.
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns whether this value removes the EA.
    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the value length.
    fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Copies this EA value without using infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the EA value bytes cannot allocate.
    fn try_clone(&self) -> DriverResult<Self> {
        Ok(Self {
            bytes: memory::copied_slice(self.as_bytes())?,
        })
    }
}

/// Windows EA entry after parsing or before packing.
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsEaRecord {
    /// Windows EA name.
    name: WindowsEaName,
    /// Windows EA value.
    value: WindowsEaValue,
}

impl WindowsEaRecord {
    /// Creates a flagless Windows EA record.
    fn new(name: WindowsEaName, value: WindowsEaValue) -> Self {
        Self { name, value }
    }

    /// Creates a Windows EA record from wire fields.
    /// # Errors
    ///
    /// Returns an error when the record has unsupported flags or invalid EA name/value fields.
    fn from_wire(flags: u8, name: &[u8], value: &[u8]) -> DriverResult<Self> {
        if flags != 0 {
            return Err(DriverError::NotSupported);
        }
        Ok(Self::new(
            WindowsEaName::new(name)?,
            WindowsEaValue::new(value)?,
        ))
    }

    /// Copies this EA record without using infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the record name or value cannot allocate.
    fn try_clone(&self) -> DriverResult<Self> {
        Ok(Self::new(self.name.try_clone()?, self.value.try_clone()?))
    }
}

/// Query-EA name selection.
#[derive(Clone, Debug, Eq, PartialEq)]
enum WindowsEaSelection {
    /// Return every persisted EA.
    All,
    /// Return only the requested names.
    Names(Vec<WindowsEaName>),
}

/// Performs an EA query against mounted ext4 xattrs.
/// # Errors
///
/// Returns an error when selected EAs cannot be loaded, no EAs match, the output buffer is too
/// small, or packed EA records cannot be emitted.
fn query_ea(request: &QueryEaRequest) -> DriverResult<IrpCompletion> {
    let mut entries = collect_query_entries(&request.opened_file, request.stack)?;
    if matches!(request.stack.entry_emission(), EaEntryEmission::Single) && entries.len() > 1 {
        entries.truncate(1);
    }
    if entries.is_empty() {
        return Err(DriverError::NoEasOnFile);
    }

    let length = request.stack.length();
    let required = packed_full_ea_length(entries.as_slice())?;
    if length.as_usize() < required {
        return Err(DriverError::BufferTooSmall);
    }
    let mut output = request.target.data_output(length)?;
    let written = pack_full_ea_entries(entries.as_slice(), output.as_mut_slice())?;
    IrpCompletion::from_usize(written)
}

/// Applies set-EA records to `user.ext4win.ea.*` xattrs.
/// # Errors
///
/// Returns an error when the set-EA input list is malformed or the xattr update transaction fails.
fn set_ea(request: &SetEaRequest) -> DriverResult<IrpCompletion> {
    let entries = parse_set_ea_entries(request.target, request.stack)?;
    apply_set_ea_entries(&request.opened_file, entries.as_slice())?;
    Ok(IrpCompletion::EMPTY)
}

/// Collects Windows EA entries selected by a query request.
/// # Errors
///
/// Returns an error when persisted EAs or the caller's requested EA-name list cannot be parsed.
fn collect_query_entries(
    opened_file: &OpenedObject,
    stack: QueryEaStack,
) -> DriverResult<Vec<WindowsEaRecord>> {
    let entries = load_windows_eas(opened_file)?;
    match requested_ea_names(stack)? {
        WindowsEaSelection::All => Ok(entries),
        WindowsEaSelection::Names(names) => {
            let mut selected = Vec::new();
            for requested in names {
                if let Some(entry) = entries.iter().find(|entry| entry.name == requested) {
                    selected.try_push(entry.try_clone()?)?;
                }
            }
            Ok(selected)
        }
    }
}

/// Reads all ext4win Windows EA xattrs for the opened node.
/// # Errors
///
/// Returns an error when node xattrs cannot be read or any stored ext4win EA name/value no longer
/// fits the Windows EA record domain.
fn load_windows_eas(opened_file: &OpenedObject) -> DriverResult<Vec<WindowsEaRecord>> {
    let fcb = opened_file.file_control_block();
    let vcb = volume_control_block(fcb);
    let xattrs = vcb.volume().read_xattrs(fcb.node())?;
    let mut entries = Vec::new();
    for (name, value) in xattrs.entries() {
        if name.namespace() != XattrNamespace::User {
            continue;
        }
        let Some(ea_name) = name.local().strip_prefix(EA_XATTR_PREFIX) else {
            continue;
        };
        entries.try_push(WindowsEaRecord::new(
            WindowsEaName::new(ea_name)?,
            WindowsEaValue::new(value.bytes())?,
        ))?;
    }
    Ok(entries)
}

/// Applies parsed set-EA records in one journal transaction.
/// # Errors
///
/// Returns an error when EA names cannot be mapped to xattrs or the journaled xattr set/remove
/// operation fails.
fn apply_set_ea_entries(
    opened_file: &OpenedObject,
    entries: &[WindowsEaRecord],
) -> DriverResult<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let fcb = opened_file.file_control_block();
    let node_id = fcb.node();
    let mut vcb = fcb.volume();
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this EA mutation.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let node = transaction.node(node_id)?;
    for entry in entries {
        let name = xattr_name_from_ea_name(&entry.name)?;
        if entry.value.is_empty() {
            transaction.remove_xattr(node, &name)?;
        } else {
            transaction.set_xattr(node, name, XattrValue::new(entry.value.as_bytes())?)?;
        }
    }
    transaction.commit()?;
    Ok(())
}

/// Parses the set-EA input buffer.
/// # Errors
///
/// Returns an error when the IRP input buffer is unavailable or the FILE_FULL_EA_INFORMATION list is
/// malformed.
fn parse_set_ea_entries(
    target: DispatchTarget,
    stack: SetEaStack,
) -> DriverResult<Vec<WindowsEaRecord>> {
    let length = stack.length();
    if length.is_empty() {
        return Ok(Vec::new());
    }
    let input = target.data_input(length)?;
    parse_full_ea_list(input.as_slice())
}

/// Parses FILE_GET_EA_INFORMATION selection from the query stack.
/// # Errors
///
/// Returns an error when the caller's EA-name selection buffer is malformed.
fn requested_ea_names(stack: QueryEaStack) -> DriverResult<WindowsEaSelection> {
    match stack.name_selection() {
        EaNameSelection::All => Ok(WindowsEaSelection::All),
        EaNameSelection::Names { address, length } => {
            let bytes = unsafe {
                // SAFETY: QueryEa supplies EaList/EaListLength as a kernel-addressable
                // input list for the lifetime of this dispatch callback.
                core::slice::from_raw_parts(address.as_ptr(), length.as_usize())
            };
            parse_get_ea_list(bytes).map(WindowsEaSelection::Names)
        }
    }
}

/// Parses a FILE_FULL_EA_INFORMATION list.
/// # Errors
///
/// Returns an error when record offsets, name terminators, name/value ranges, flags, or alignment
/// are inconsistent.
fn parse_full_ea_list(input: &[u8]) -> DriverResult<Vec<WindowsEaRecord>> {
    let fields = LittleEndianInput::new(input);
    let mut offset = 0;
    let mut entries = Vec::new();
    loop {
        if offset >= input.len() {
            return Err(DriverError::EaListInconsistent);
        }
        let next = usize::try_from(fields.read_u32(wire_offset(offset))?)
            .map_err(|_| DriverError::EaListInconsistent)?;
        let flags = fields.read_u8(wire_offset(
            offset.checked_add(4).ok_or(DriverError::InvalidParameter)?,
        ))?;
        let name_len = usize::from(fields.read_u8(wire_offset(
            offset.checked_add(5).ok_or(DriverError::InvalidParameter)?,
        ))?);
        let value_len = usize::from(fields.read_u16(wire_offset(
            offset.checked_add(6).ok_or(DriverError::InvalidParameter)?,
        ))?);
        let name_start = offset
            .checked_add(FILE_FULL_EA_NAME_OFFSET)
            .ok_or(DriverError::InvalidParameter)?;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(DriverError::InvalidParameter)?;
        let value_start = name_end
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;
        let value_end = value_start
            .checked_add(value_len)
            .ok_or(DriverError::InvalidParameter)?;
        let name = input
            .get(name_start..name_end)
            .ok_or(DriverError::EaListInconsistent)?;
        if input.get(name_end).copied() != Some(0) {
            return Err(DriverError::EaListInconsistent);
        }
        let value = input
            .get(value_start..value_end)
            .ok_or(DriverError::EaListInconsistent)?;
        entries.try_push(WindowsEaRecord::from_wire(flags, name, value)?)?;

        let raw_len = full_ea_record_length(name.len(), value.len())?;
        if next == 0 {
            return Ok(entries);
        }
        if !next.is_multiple_of(EA_RECORD_ALIGNMENT) || next < align_to_four(raw_len)? {
            return Err(DriverError::EaListInconsistent);
        }
        offset = offset
            .checked_add(next)
            .ok_or(DriverError::EaListInconsistent)?;
    }
}

/// Parses a FILE_GET_EA_INFORMATION list.
/// # Errors
///
/// Returns an error when record offsets, name terminators, name ranges, or alignment are
/// inconsistent.
fn parse_get_ea_list(input: &[u8]) -> DriverResult<Vec<WindowsEaName>> {
    let fields = LittleEndianInput::new(input);
    let mut offset = 0;
    let mut names = Vec::new();
    loop {
        if offset >= input.len() {
            return Err(DriverError::EaListInconsistent);
        }
        let next = usize::try_from(fields.read_u32(wire_offset(offset))?)
            .map_err(|_| DriverError::EaListInconsistent)?;
        let name_len = usize::from(fields.read_u8(wire_offset(
            offset.checked_add(4).ok_or(DriverError::InvalidParameter)?,
        ))?);
        let name_start = offset
            .checked_add(FILE_GET_EA_NAME_OFFSET)
            .ok_or(DriverError::InvalidParameter)?;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(DriverError::InvalidParameter)?;
        let name = input
            .get(name_start..name_end)
            .ok_or(DriverError::EaListInconsistent)?;
        if input.get(name_end).copied() != Some(0) {
            return Err(DriverError::EaListInconsistent);
        }
        names.try_push(WindowsEaName::new(name)?)?;

        let raw_len = get_ea_record_length(name.len())?;
        if next == 0 {
            return Ok(names);
        }
        if !next.is_multiple_of(EA_RECORD_ALIGNMENT) || next < align_to_four(raw_len)? {
            return Err(DriverError::EaListInconsistent);
        }
        offset = offset
            .checked_add(next)
            .ok_or(DriverError::EaListInconsistent)?;
    }
}

/// Packs FILE_FULL_EA_INFORMATION records.
/// # Errors
///
/// Returns an error when the output buffer is too small or any packed record field cannot be
/// represented.
fn pack_full_ea_entries(entries: &[WindowsEaRecord], output: &mut [u8]) -> DriverResult<usize> {
    let required = packed_full_ea_length(entries)?;
    if output.len() < required {
        return Err(DriverError::BufferTooSmall);
    }
    if required == 0 {
        return Ok(0);
    }
    let mut output = LittleEndianOutput::new(output);
    output.range_mut(wire_range(0, required)?)?.fill(0);

    let last_index = entries
        .len()
        .checked_sub(1)
        .ok_or(DriverError::InvalidParameter)?;
    let mut offset: usize = 0;
    for (index, entry) in entries.iter().enumerate() {
        let raw_len = full_ea_record_length(entry.name.len(), entry.value.len())?;
        let is_last = index == last_index;
        let stride = if is_last {
            raw_len
        } else {
            align_to_four(raw_len)?
        };
        let next = if is_last {
            0
        } else {
            u32::try_from(stride).map_err(|_| DriverError::EaTooLarge)?
        };
        let name_len = u8::try_from(entry.name.len()).map_err(|_| DriverError::InvalidEaName)?;
        let value_len = u16::try_from(entry.value.len()).map_err(|_| DriverError::EaTooLarge)?;
        output.write_u32(wire_offset(offset), next)?;
        output.write_u8(
            wire_offset(offset.checked_add(4).ok_or(DriverError::InvalidParameter)?),
            0,
        )?;
        output.write_u8(
            wire_offset(offset.checked_add(5).ok_or(DriverError::InvalidParameter)?),
            name_len,
        )?;
        output.write_u16(
            wire_offset(offset.checked_add(6).ok_or(DriverError::InvalidParameter)?),
            value_len,
        )?;
        let name_start = offset
            .checked_add(FILE_FULL_EA_NAME_OFFSET)
            .ok_or(DriverError::InvalidParameter)?;
        output.write_bytes(wire_offset(name_start), entry.name.as_bytes())?;
        output.write_u8(
            wire_offset(
                name_start
                    .checked_add(entry.name.len())
                    .ok_or(DriverError::InvalidParameter)?,
            ),
            0,
        )?;
        output.write_bytes(
            wire_offset(
                name_start
                    .checked_add(entry.name.len())
                    .and_then(|value_start| value_start.checked_add(1))
                    .ok_or(DriverError::InvalidParameter)?,
            ),
            entry.value.as_bytes(),
        )?;
        offset = offset
            .checked_add(stride)
            .ok_or(DriverError::InvalidParameter)?;
    }
    Ok(offset)
}

/// Returns the packed byte count for a full EA list.
/// # Errors
///
/// Returns an error when a record length or total packed list length exceeds the Windows EA size
/// domain.
fn packed_full_ea_length(entries: &[WindowsEaRecord]) -> DriverResult<usize> {
    if entries.is_empty() {
        return Ok(0);
    }
    let last_index = entries
        .len()
        .checked_sub(1)
        .ok_or(DriverError::InvalidParameter)?;
    let mut total = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let raw = full_ea_record_length(entry.name.len(), entry.value.len())?;
        let size = if index == last_index {
            raw
        } else {
            align_to_four(raw)?
        };
        total = total.checked_add(size).ok_or(DriverError::EaTooLarge)?;
    }
    Ok(total)
}

/// Returns the unaligned FILE_FULL_EA_INFORMATION record length.
/// # Errors
///
/// Returns an error when name/value lengths overflow the full-EA record size.
fn full_ea_record_length(name_len: usize, value_len: usize) -> DriverResult<usize> {
    FILE_FULL_EA_NAME_OFFSET
        .checked_add(name_len)
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(value_len))
        .ok_or(DriverError::EaTooLarge)
}

/// Returns the unaligned FILE_GET_EA_INFORMATION record length.
/// # Errors
///
/// Returns an error when the name length overflows the get-EA record size.
fn get_ea_record_length(name_len: usize) -> DriverResult<usize> {
    FILE_GET_EA_NAME_OFFSET
        .checked_add(name_len)
        .and_then(|length| length.checked_add(1))
        .ok_or(DriverError::EaListInconsistent)
}

/// Maps a Windows EA name to the ext4 xattr namespace.
/// # Errors
///
/// Returns an error when the reserved prefix plus EA name cannot form a valid `user.*` xattr name.
fn xattr_name_from_ea_name(name: &WindowsEaName) -> DriverResult<XattrName> {
    let local_len = EA_XATTR_PREFIX
        .len()
        .checked_add(name.len())
        .ok_or(DriverError::InvalidEaName)?;
    let mut local = Vec::new();
    local
        .try_reserve_exact(local_len)
        .map_err(|_| DriverError::InsufficientResources)?;
    local.try_extend_from_slice(EA_XATTR_PREFIX)?;
    local.try_extend_from_slice(name.as_bytes())?;
    Ok(XattrName::new(XattrNamespace::User, local.as_slice())?)
}

/// Returns the mounted VCB referenced by an FCB.
fn volume_control_block(fcb: &FileControlBlock) -> &VolumeControlBlock {
    unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open.
        fcb.volume().as_ref()
    }
}

/// Aligns a byte count to a four-byte boundary.
/// # Errors
///
/// Returns an error when padding arithmetic overflows.
fn align_to_four(value: usize) -> DriverResult<usize> {
    let adjustment = EA_RECORD_ALIGNMENT
        .checked_sub(1)
        .ok_or(DriverError::InvalidParameter)?;
    let adjusted = value
        .checked_add(adjustment)
        .ok_or(DriverError::EaTooLarge)?;
    let units = adjusted
        .checked_div(EA_RECORD_ALIGNMENT)
        .ok_or(DriverError::InvalidParameter)?;
    units
        .checked_mul(EA_RECORD_ALIGNMENT)
        .ok_or(DriverError::EaTooLarge)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::{
        kernel::status::DriverError,
        wire::{LittleEndianInput, LittleEndianOutput},
    };

    use super::{
        WindowsEaName, WindowsEaRecord, WindowsEaValue, pack_full_ea_entries, parse_full_ea_list,
        parse_get_ea_list, wire_offset, xattr_name_from_ea_name,
    };

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn full_ea_records_round_trip() {
        let alpha = WindowsEaName::new(b"alpha");
        let beta = WindowsEaName::new(b"beta");
        let one = WindowsEaValue::new(b"one");
        let two = WindowsEaValue::new(b"two");
        assert!(alpha.is_ok());
        assert!(beta.is_ok());
        assert!(one.is_ok());
        assert!(two.is_ok());
        let (Ok(alpha), Ok(beta), Ok(one), Ok(two)) = (alpha, beta, one, two) else {
            return;
        };
        let entries = vec![
            WindowsEaRecord::new(alpha, one),
            WindowsEaRecord::new(beta, two),
        ];
        let mut output = vec![0; 64];

        assert_eq!(
            pack_full_ea_entries(entries.as_slice(), output.as_mut_slice()),
            Ok(36)
        );
        let fields = LittleEndianInput::new(output.as_slice());
        assert_eq!(fields.read_u32(wire_offset(0)), Ok(20));
        assert_eq!(fields.read_u16(wire_offset(6)), Ok(3));
        assert_eq!(
            parse_full_ea_list(output.get(..36).unwrap_or(&[])),
            Ok(entries)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn get_ea_records_parse_names() {
        let mut input = vec![0; 32];
        {
            let mut output = LittleEndianOutput::new(input.as_mut_slice());
            assert_eq!(output.write_u32(wire_offset(0), 12), Ok(()));
            assert_eq!(output.write_u8(wire_offset(4), 5), Ok(()));
            assert_eq!(output.write_bytes(wire_offset(5), b"alpha"), Ok(()));
            assert_eq!(output.write_u8(wire_offset(10), 0), Ok(()));
            assert_eq!(output.write_u8(wire_offset(16), 4), Ok(()));
            assert_eq!(output.write_bytes(wire_offset(17), b"beta"), Ok(()));
            assert_eq!(output.write_u8(wire_offset(21), 0), Ok(()));
        }
        let alpha = WindowsEaName::new(b"alpha");
        let beta = WindowsEaName::new(b"beta");
        assert!(alpha.is_ok());
        assert!(beta.is_ok());
        let (Ok(alpha), Ok(beta)) = (alpha, beta) else {
            return;
        };

        assert_eq!(
            parse_get_ea_list(input.get(..22).unwrap_or(&[])),
            Ok(vec![alpha, beta])
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn ea_name_maps_to_ext4win_user_xattr() {
        let ea_name = WindowsEaName::new(b"alpha");
        assert!(ea_name.is_ok());
        let Ok(ea_name) = ea_name else {
            return;
        };
        let name = xattr_name_from_ea_name(&ea_name);
        assert!(name.is_ok());
        if let Ok(name) = name {
            assert_eq!(name.qualified(), Ok(b"user.ext4win.ea.alpha".to_vec()));
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn invalid_ea_names_are_rejected() {
        assert_eq!(WindowsEaName::new(b""), Err(DriverError::InvalidEaName));
        assert_eq!(
            WindowsEaName::new(b"has\0nul"),
            Err(DriverError::InvalidEaName)
        );
        assert_eq!(
            WindowsEaName::new(b"ext4win.attributes"),
            Err(DriverError::InvalidEaName)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn inconsistent_full_ea_list_is_rejected() {
        let mut input = vec![0; 16];
        {
            let mut output = LittleEndianOutput::new(input.as_mut_slice());
            assert_eq!(output.write_u8(wire_offset(5), 3), Ok(()));
            assert_eq!(output.write_bytes(wire_offset(8), b"abc"), Ok(()));
            assert_eq!(output.write_u8(wire_offset(11), b'x'), Ok(()));
        }

        assert_eq!(
            parse_full_ea_list(input.as_slice()),
            Err(DriverError::EaListInconsistent)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn nonzero_ea_flags_are_rejected() {
        let mut input = vec![0; 16];
        {
            let mut output = LittleEndianOutput::new(input.as_mut_slice());
            assert_eq!(output.write_u8(wire_offset(4), 1), Ok(()));
            assert_eq!(output.write_u8(wire_offset(5), 3), Ok(()));
            assert_eq!(output.write_bytes(wire_offset(8), b"abc"), Ok(()));
            assert_eq!(output.write_u8(wire_offset(11), 0), Ok(()));
        }

        assert_eq!(
            parse_full_ea_list(input.as_slice()),
            Err(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn ea_value_rejects_lengths_outside_windows_wire_field() {
        let Some(length) = usize::from(u16::MAX).checked_add(1) else {
            return;
        };
        let value = vec![0; length];
        assert_eq!(
            WindowsEaValue::new(value.as_slice()),
            Err(DriverError::EaTooLarge)
        );
    }
}
