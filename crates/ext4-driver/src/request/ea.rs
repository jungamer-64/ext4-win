//! Windows extended-attribute IRP handling.

use alloc::vec::Vec;
use ext4_core::{XattrName, XattrNamespace, XattrValue};
use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_SUCCESS};

use crate::irp::{
    DispatchTarget, DriverCompletion, EaEntryEmission, EaNameSelection, QueryEaStack, SetEaStack,
};
use crate::state::{FileControlBlock, OpenedFileObject, VolumeControlBlock};
use crate::status::{DriverError, DriverResult};
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
fn wire_range(offset: usize, length: usize) -> DriverResult<WireRange> {
    WireRange::new(wire_offset(offset), WireByteLen::new(length))
}

/// Handles IRP_MJ_QUERY_EA.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(QueryEaRequest::decode) {
        Ok(request) => match query_ea(&request) {
            Ok(completion) => {
                request.target.complete(completion);
                STATUS_SUCCESS
            }
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Handles IRP_MJ_SET_EA.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(SetEaRequest::decode) {
        Ok(request) => match set_ea(&request) {
            Ok(completion) => {
                request.target.complete(completion);
                STATUS_SUCCESS
            }
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
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
    opened_file: OpenedFileObject,
}

impl QueryEaRequest {
    /// Decodes a query-EA request.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.query_ea()?;
        let opened_file = OpenedFileObject::decode(stack.file_object())?;
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
    opened_file: OpenedFileObject,
}

impl SetEaRequest {
    /// Decodes a set-EA request.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.set_ea()?;
        let opened_file = OpenedFileObject::decode(stack.file_object())?;
        Ok(Self {
            target,
            stack,
            opened_file,
        })
    }
}

/// Windows EA entry after parsing or before packing.
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsEaEntry {
    /// EA flags. ext4win currently persists only flagless EAs.
    flags: u8,
    /// Windows EA name bytes.
    name: Vec<u8>,
    /// Windows EA value bytes.
    value: Vec<u8>,
}

/// Performs an EA query against mounted ext4 xattrs.
fn query_ea(request: &QueryEaRequest) -> DriverResult<DriverCompletion> {
    let mut entries = collect_query_entries(&request.opened_file, request.stack)?;
    if matches!(request.stack.entry_emission(), EaEntryEmission::Single) && entries.len() > 1 {
        entries.truncate(1);
    }
    if entries.is_empty() {
        return Err(DriverError::NoEasOnFile);
    }

    let length = request.stack.length().as_usize();
    let required = packed_full_ea_length(entries.as_slice())?;
    if length < required {
        return Err(DriverError::BufferTooSmall);
    }
    let mut output = request.target.data_buffer(length)?;
    let written = pack_full_ea_entries(entries.as_slice(), output.as_mut_slice())?;
    DriverCompletion::from_usize(written)
}

/// Applies set-EA records to `user.ext4win.ea.*` xattrs.
fn set_ea(request: &SetEaRequest) -> DriverResult<DriverCompletion> {
    let entries = parse_set_ea_entries(request.target, request.stack)?;
    apply_set_ea_entries(&request.opened_file, entries.as_slice())?;
    Ok(DriverCompletion::EMPTY)
}

/// Collects Windows EA entries selected by a query request.
fn collect_query_entries(
    opened_file: &OpenedFileObject,
    stack: QueryEaStack,
) -> DriverResult<Vec<WindowsEaEntry>> {
    let entries = load_windows_eas(opened_file)?;
    let Some(names) = requested_ea_names(stack)? else {
        return Ok(entries);
    };
    let mut selected = Vec::new();
    for requested in names {
        if let Some(entry) = entries.iter().find(|entry| entry.name == requested) {
            selected.push(entry.clone());
        }
    }
    Ok(selected)
}

/// Reads all ext4win Windows EA xattrs for the opened node.
fn load_windows_eas(opened_file: &OpenedFileObject) -> DriverResult<Vec<WindowsEaEntry>> {
    let fcb = opened_file.file_control_block();
    let vcb = volume_control_block(fcb);
    let xattrs = vcb.volume().read_xattrs(fcb.node().inode())?;
    let mut entries = Vec::new();
    for (name, value) in xattrs.entries() {
        if name.namespace() != XattrNamespace::User {
            continue;
        }
        let Some(ea_name) = name.local().strip_prefix(EA_XATTR_PREFIX) else {
            continue;
        };
        validate_ea_name(ea_name)?;
        entries.push(WindowsEaEntry {
            flags: 0,
            name: ea_name.to_vec(),
            value: value.bytes().to_vec(),
        });
    }
    Ok(entries)
}

/// Applies parsed set-EA records in one journal transaction.
fn apply_set_ea_entries(
    opened_file: &OpenedFileObject,
    entries: &[WindowsEaEntry],
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
        .begin_transaction(crate::time::current_ext4_timestamp()?);
    let node = transaction.node(node_id)?;
    for entry in entries {
        let name = xattr_name_from_ea_name(entry.name.as_slice())?;
        if entry.value.is_empty() {
            transaction.remove_xattr(node, &name)?;
        } else {
            transaction.set_xattr(node, name, XattrValue::new(entry.value.as_slice())?)?;
        }
    }
    transaction.commit()?;
    Ok(())
}

/// Parses the set-EA input buffer.
fn parse_set_ea_entries(
    target: DispatchTarget,
    stack: SetEaStack,
) -> DriverResult<Vec<WindowsEaEntry>> {
    let length = stack.length().as_usize();
    if length == 0 {
        return Ok(Vec::new());
    }
    let input = target.data_buffer(length)?;
    parse_full_ea_list(input.as_slice())
}

/// Parses an optional FILE_GET_EA_INFORMATION list from the query stack.
fn requested_ea_names(stack: QueryEaStack) -> DriverResult<Option<Vec<Vec<u8>>>> {
    match stack.name_selection() {
        EaNameSelection::All => Ok(None),
        EaNameSelection::Names { address, length } => {
            let bytes = unsafe {
                // SAFETY: QueryEa supplies EaList/EaListLength as a kernel-addressable
                // input list for the lifetime of this dispatch callback.
                core::slice::from_raw_parts(address.as_ptr(), length.as_usize())
            };
            parse_get_ea_list(bytes).map(Some)
        }
    }
}

/// Parses a FILE_FULL_EA_INFORMATION list.
fn parse_full_ea_list(input: &[u8]) -> DriverResult<Vec<WindowsEaEntry>> {
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
        if flags != 0 {
            return Err(DriverError::NotSupported);
        }
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
        validate_ea_name(name)?;
        if input.get(name_end).copied() != Some(0) {
            return Err(DriverError::EaListInconsistent);
        }
        let value = input
            .get(value_start..value_end)
            .ok_or(DriverError::EaListInconsistent)?;
        entries.push(WindowsEaEntry {
            flags,
            name: name.to_vec(),
            value: value.to_vec(),
        });

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
fn parse_get_ea_list(input: &[u8]) -> DriverResult<Vec<Vec<u8>>> {
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
        validate_ea_name(name)?;
        if input.get(name_end).copied() != Some(0) {
            return Err(DriverError::EaListInconsistent);
        }
        names.push(name.to_vec());

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
fn pack_full_ea_entries(entries: &[WindowsEaEntry], output: &mut [u8]) -> DriverResult<usize> {
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
            entry.flags,
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
        output.write_bytes(wire_offset(name_start), entry.name.as_slice())?;
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
            entry.value.as_slice(),
        )?;
        offset = offset
            .checked_add(stride)
            .ok_or(DriverError::InvalidParameter)?;
    }
    Ok(offset)
}

/// Returns the packed byte count for a full EA list.
fn packed_full_ea_length(entries: &[WindowsEaEntry]) -> DriverResult<usize> {
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
fn full_ea_record_length(name_len: usize, value_len: usize) -> DriverResult<usize> {
    FILE_FULL_EA_NAME_OFFSET
        .checked_add(name_len)
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(value_len))
        .ok_or(DriverError::EaTooLarge)
}

/// Returns the unaligned FILE_GET_EA_INFORMATION record length.
fn get_ea_record_length(name_len: usize) -> DriverResult<usize> {
    FILE_GET_EA_NAME_OFFSET
        .checked_add(name_len)
        .and_then(|length| length.checked_add(1))
        .ok_or(DriverError::EaListInconsistent)
}

/// Maps a Windows EA name to the ext4 xattr namespace.
fn xattr_name_from_ea_name(name: &[u8]) -> DriverResult<XattrName> {
    validate_ea_name(name)?;
    let local_len = EA_XATTR_PREFIX
        .len()
        .checked_add(name.len())
        .ok_or(DriverError::InvalidEaName)?;
    let mut local = Vec::with_capacity(local_len);
    local.extend_from_slice(EA_XATTR_PREFIX);
    local.extend_from_slice(name);
    Ok(XattrName::new(XattrNamespace::User, local.as_slice())?)
}

/// Validates a Windows EA name before mapping it to ext4.
fn validate_ea_name(name: &[u8]) -> DriverResult<()> {
    if name.is_empty() || name.contains(&0) {
        return Err(DriverError::InvalidEaName);
    }
    if name.starts_with(RESERVED_EA_NAME_PREFIX) {
        return Err(DriverError::InvalidEaName);
    }
    u8::try_from(name.len()).map_err(|_| DriverError::InvalidEaName)?;
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

/// Aligns a byte count to a four-byte boundary.
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
    use alloc::{vec, vec::Vec};

    use crate::{
        status::DriverError,
        wire::{LittleEndianInput, LittleEndianOutput},
    };

    use super::{
        WindowsEaEntry, pack_full_ea_entries, parse_full_ea_list, parse_get_ea_list, wire_offset,
        xattr_name_from_ea_name,
    };

    #[test]
    fn full_ea_records_round_trip() {
        let entries = vec![
            WindowsEaEntry {
                flags: 0,
                name: Vec::from(&b"alpha"[..]),
                value: Vec::from(&b"one"[..]),
            },
            WindowsEaEntry {
                flags: 0,
                name: Vec::from(&b"beta"[..]),
                value: Vec::from(&b"two"[..]),
            },
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

        assert_eq!(
            parse_get_ea_list(input.get(..22).unwrap_or(&[])),
            Ok(vec![Vec::from(&b"alpha"[..]), Vec::from(&b"beta"[..])])
        );
    }

    #[test]
    fn ea_name_maps_to_ext4win_user_xattr() {
        let name = xattr_name_from_ea_name(b"alpha");
        assert!(name.is_ok());
        if let Ok(name) = name {
            assert_eq!(name.qualified(), b"user.ext4win.ea.alpha");
        }
    }

    #[test]
    fn invalid_ea_names_are_rejected() {
        assert_eq!(
            xattr_name_from_ea_name(b""),
            Err(DriverError::InvalidEaName)
        );
        assert_eq!(
            xattr_name_from_ea_name(b"has\0nul"),
            Err(DriverError::InvalidEaName)
        );
        assert_eq!(
            xattr_name_from_ea_name(b"ext4win.attributes"),
            Err(DriverError::InvalidEaName)
        );
    }

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
}
