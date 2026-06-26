//! Windows extended-attribute IRP handling.

use alloc::vec::Vec;
use core::ptr::NonNull;

use ext4_core::{XattrName, XattrNamespace, XattrValue};
use wdk_sys::{
    NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER,
    STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

use crate::irp::{DispatchTarget, EaEntryEmission, EaNameSelection, QueryEaStack, SetEaStack};
use crate::state::{FileControlBlock, VolumeControlBlock, file_control_block};
use crate::status::DriverError;

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

/// The caller supplied an invalid EA name.
const STATUS_INVALID_EA_NAME: NTSTATUS = ntstatus(0x8000_0013);
/// The caller supplied a malformed EA list.
const STATUS_EA_LIST_INCONSISTENT: NTSTATUS = ntstatus(0x8000_0014);
/// No EA records exist for this file or query.
const STATUS_NO_EAS_ON_FILE: NTSTATUS = ntstatus(0xC000_0052);
/// A Windows EA record cannot be represented by the on-wire EA layout.
const STATUS_EA_TOO_LARGE: NTSTATUS = ntstatus(0xC000_0050);

/// Handles IRP_MJ_QUERY_EA.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(QueryEaRequest::decode) {
        Ok(request) => query_ea(request),
        Err(error) => error.ntstatus(),
    }
}

/// Handles IRP_MJ_SET_EA.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(SetEaRequest::decode) {
        Ok(request) => set_ea(request),
        Err(error) => error.ntstatus(),
    }
}

/// Decoded query-EA request.
#[derive(Clone, Copy, Debug)]
struct QueryEaRequest {
    /// Dispatch target receiving output.
    target: DispatchTarget,
    /// Decoded query-EA stack.
    stack: QueryEaStack,
}

impl QueryEaRequest {
    /// Decodes a query-EA request.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        Ok(Self {
            target,
            stack: target.current_stack()?.query_ea()?,
        })
    }
}

/// Decoded set-EA request.
#[derive(Clone, Copy, Debug)]
struct SetEaRequest {
    /// Dispatch target carrying input.
    target: DispatchTarget,
    /// Decoded set-EA stack.
    stack: SetEaStack,
}

impl SetEaRequest {
    /// Decodes a set-EA request.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        Ok(Self {
            target,
            stack: target.current_stack()?.set_ea()?,
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
fn query_ea(request: QueryEaRequest) -> NTSTATUS {
    match collect_query_entries(request.stack).and_then(|mut entries| {
        if matches!(request.stack.entry_emission(), EaEntryEmission::Single) && entries.len() > 1 {
            entries.truncate(1);
        }
        if entries.is_empty() {
            return Err(STATUS_NO_EAS_ON_FILE);
        }

        let length = request.stack.length().as_usize();
        let required = packed_full_ea_length(entries.as_slice())?;
        if length < required {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        let mut output = request
            .target
            .data_buffer(length)
            .map_err(|error| error.ntstatus())?;
        let written = pack_full_ea_entries(entries.as_slice(), output.as_mut_slice())?;
        request.target.set_information(
            wdk_sys::ULONG_PTR::try_from(written).map_err(|_| STATUS_INVALID_PARAMETER)?,
        );
        Ok(())
    }) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// Applies set-EA records to `user.ext4win.ea.*` xattrs.
fn set_ea(request: SetEaRequest) -> NTSTATUS {
    match parse_set_ea_entries(request.target, request.stack)
        .and_then(|entries| apply_set_ea_entries(request.stack, entries.as_slice()))
    {
        Ok(()) => {
            request.target.set_information(0);
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// Collects Windows EA entries selected by a query request.
fn collect_query_entries(stack: QueryEaStack) -> Result<Vec<WindowsEaEntry>, NTSTATUS> {
    let entries = load_windows_eas(stack.file_object())?;
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
fn load_windows_eas(
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
) -> Result<Vec<WindowsEaEntry>, NTSTATUS> {
    let fcb = file_control_block(file_object).map_err(DriverError::ntstatus)?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this query runs while the FILE_OBJECT
        // is active.
        fcb.as_ref()
    };
    let vcb = volume_control_block(fcb);
    let xattrs = vcb
        .volume()
        .read_xattrs(fcb.node().inode())
        .map_err(|error| DriverError::from(error).ntstatus())?;
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
fn apply_set_ea_entries(stack: SetEaStack, entries: &[WindowsEaEntry]) -> Result<(), NTSTATUS> {
    if entries.is_empty() {
        return Ok(());
    }
    let fcb = file_control_block(stack.file_object()).map_err(DriverError::ntstatus)?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this mutation runs while the FILE_OBJECT
        // is active.
        fcb.as_ref()
    };
    let inode = fcb.node().inode();
    let mut vcb = fcb.volume();
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open. The mutable borrow is the
        // transaction boundary for this EA mutation.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::time::current_ext4_timestamp().map_err(DriverError::ntstatus)?);
    let node = transaction
        .node(inode)
        .map_err(|error| DriverError::from(error).ntstatus())?;
    for entry in entries {
        let name = xattr_name_from_ea_name(entry.name.as_slice())?;
        if entry.value.is_empty() {
            transaction
                .remove_xattr(node, &name)
                .map_err(|error| DriverError::from(error).ntstatus())?;
        } else {
            transaction
                .set_xattr(
                    node,
                    name,
                    XattrValue::new(entry.value.as_slice())
                        .map_err(|error| DriverError::from(error).ntstatus())?,
                )
                .map_err(|error| DriverError::from(error).ntstatus())?;
        }
    }
    transaction
        .commit()
        .map_err(|error| DriverError::from(error).ntstatus())
}

/// Parses the set-EA input buffer.
fn parse_set_ea_entries(
    target: DispatchTarget,
    stack: SetEaStack,
) -> Result<Vec<WindowsEaEntry>, NTSTATUS> {
    let length = stack.length().as_usize();
    if length == 0 {
        return Ok(Vec::new());
    }
    let input = target
        .data_buffer(length)
        .map_err(|error| error.ntstatus())?;
    parse_full_ea_list(input.as_slice())
}

/// Parses an optional FILE_GET_EA_INFORMATION list from the query stack.
fn requested_ea_names(stack: QueryEaStack) -> Result<Option<Vec<Vec<u8>>>, NTSTATUS> {
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
fn parse_full_ea_list(input: &[u8]) -> Result<Vec<WindowsEaEntry>, NTSTATUS> {
    let mut offset = 0;
    let mut entries = Vec::new();
    loop {
        if offset >= input.len() {
            return Err(STATUS_EA_LIST_INCONSISTENT);
        }
        let next =
            usize::try_from(read_u32(input, offset)?).map_err(|_| STATUS_EA_LIST_INCONSISTENT)?;
        let flags = read_u8(
            input,
            offset.checked_add(4).ok_or(STATUS_INVALID_PARAMETER)?,
        )?;
        if flags != 0 {
            return Err(STATUS_NOT_SUPPORTED);
        }
        let name_len = usize::from(read_u8(
            input,
            offset.checked_add(5).ok_or(STATUS_INVALID_PARAMETER)?,
        )?);
        let value_len = usize::from(read_u16(
            input,
            offset.checked_add(6).ok_or(STATUS_INVALID_PARAMETER)?,
        )?);
        let name_start = offset
            .checked_add(FILE_FULL_EA_NAME_OFFSET)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let value_start = name_end.checked_add(1).ok_or(STATUS_INVALID_PARAMETER)?;
        let value_end = value_start
            .checked_add(value_len)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let name = input
            .get(name_start..name_end)
            .ok_or(STATUS_EA_LIST_INCONSISTENT)?;
        validate_ea_name(name)?;
        if input.get(name_end).copied() != Some(0) {
            return Err(STATUS_EA_LIST_INCONSISTENT);
        }
        let value = input
            .get(value_start..value_end)
            .ok_or(STATUS_EA_LIST_INCONSISTENT)?;
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
            return Err(STATUS_EA_LIST_INCONSISTENT);
        }
        offset = offset
            .checked_add(next)
            .ok_or(STATUS_EA_LIST_INCONSISTENT)?;
    }
}

/// Parses a FILE_GET_EA_INFORMATION list.
fn parse_get_ea_list(input: &[u8]) -> Result<Vec<Vec<u8>>, NTSTATUS> {
    let mut offset = 0;
    let mut names = Vec::new();
    loop {
        if offset >= input.len() {
            return Err(STATUS_EA_LIST_INCONSISTENT);
        }
        let next =
            usize::try_from(read_u32(input, offset)?).map_err(|_| STATUS_EA_LIST_INCONSISTENT)?;
        let name_len = usize::from(read_u8(
            input,
            offset.checked_add(4).ok_or(STATUS_INVALID_PARAMETER)?,
        )?);
        let name_start = offset
            .checked_add(FILE_GET_EA_NAME_OFFSET)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let name = input
            .get(name_start..name_end)
            .ok_or(STATUS_EA_LIST_INCONSISTENT)?;
        validate_ea_name(name)?;
        if input.get(name_end).copied() != Some(0) {
            return Err(STATUS_EA_LIST_INCONSISTENT);
        }
        names.push(name.to_vec());

        let raw_len = get_ea_record_length(name.len())?;
        if next == 0 {
            return Ok(names);
        }
        if !next.is_multiple_of(EA_RECORD_ALIGNMENT) || next < align_to_four(raw_len)? {
            return Err(STATUS_EA_LIST_INCONSISTENT);
        }
        offset = offset
            .checked_add(next)
            .ok_or(STATUS_EA_LIST_INCONSISTENT)?;
    }
}

/// Packs FILE_FULL_EA_INFORMATION records.
fn pack_full_ea_entries(entries: &[WindowsEaEntry], output: &mut [u8]) -> Result<usize, NTSTATUS> {
    let required = packed_full_ea_length(entries)?;
    if output.len() < required {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    if required == 0 {
        return Ok(0);
    }
    output
        .get_mut(..required)
        .ok_or(STATUS_BUFFER_TOO_SMALL)?
        .fill(0);

    let last_index = entries
        .len()
        .checked_sub(1)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let mut offset = 0;
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
            u32::try_from(stride).map_err(|_| STATUS_EA_TOO_LARGE)?
        };
        let name_len = u8::try_from(entry.name.len()).map_err(|_| STATUS_INVALID_EA_NAME)?;
        let value_len = u16::try_from(entry.value.len()).map_err(|_| STATUS_EA_TOO_LARGE)?;
        write_u32(output, offset, next)?;
        write_u8(
            output,
            offset.checked_add(4).ok_or(STATUS_INVALID_PARAMETER)?,
            entry.flags,
        )?;
        write_u8(
            output,
            offset.checked_add(5).ok_or(STATUS_INVALID_PARAMETER)?,
            name_len,
        )?;
        write_u16(
            output,
            offset.checked_add(6).ok_or(STATUS_INVALID_PARAMETER)?,
            value_len,
        )?;
        let name_start = offset
            .checked_add(FILE_FULL_EA_NAME_OFFSET)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        write_bytes(output, name_start, entry.name.as_slice())?;
        write_u8(
            output,
            name_start
                .checked_add(entry.name.len())
                .ok_or(STATUS_INVALID_PARAMETER)?,
            0,
        )?;
        write_bytes(
            output,
            name_start
                .checked_add(entry.name.len())
                .and_then(|value_start| value_start.checked_add(1))
                .ok_or(STATUS_INVALID_PARAMETER)?,
            entry.value.as_slice(),
        )?;
        offset = offset.checked_add(stride).ok_or(STATUS_INVALID_PARAMETER)?;
    }
    Ok(offset)
}

/// Returns the packed byte count for a full EA list.
fn packed_full_ea_length(entries: &[WindowsEaEntry]) -> Result<usize, NTSTATUS> {
    if entries.is_empty() {
        return Ok(0);
    }
    let last_index = entries
        .len()
        .checked_sub(1)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let mut total = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let raw = full_ea_record_length(entry.name.len(), entry.value.len())?;
        let size = if index == last_index {
            raw
        } else {
            align_to_four(raw)?
        };
        total = total.checked_add(size).ok_or(STATUS_EA_TOO_LARGE)?;
    }
    Ok(total)
}

/// Returns the unaligned FILE_FULL_EA_INFORMATION record length.
fn full_ea_record_length(name_len: usize, value_len: usize) -> Result<usize, NTSTATUS> {
    FILE_FULL_EA_NAME_OFFSET
        .checked_add(name_len)
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(value_len))
        .ok_or(STATUS_EA_TOO_LARGE)
}

/// Returns the unaligned FILE_GET_EA_INFORMATION record length.
fn get_ea_record_length(name_len: usize) -> Result<usize, NTSTATUS> {
    FILE_GET_EA_NAME_OFFSET
        .checked_add(name_len)
        .and_then(|length| length.checked_add(1))
        .ok_or(STATUS_EA_LIST_INCONSISTENT)
}

/// Maps a Windows EA name to the ext4 xattr namespace.
fn xattr_name_from_ea_name(name: &[u8]) -> Result<XattrName, NTSTATUS> {
    validate_ea_name(name)?;
    let local_len = EA_XATTR_PREFIX
        .len()
        .checked_add(name.len())
        .ok_or(STATUS_INVALID_EA_NAME)?;
    let mut local = Vec::with_capacity(local_len);
    local.extend_from_slice(EA_XATTR_PREFIX);
    local.extend_from_slice(name);
    XattrName::new(XattrNamespace::User, local.as_slice())
        .map_err(|error| DriverError::from(error).ntstatus())
}

/// Validates a Windows EA name before mapping it to ext4.
fn validate_ea_name(name: &[u8]) -> Result<(), NTSTATUS> {
    if name.is_empty() || name.contains(&0) {
        return Err(STATUS_INVALID_EA_NAME);
    }
    if name.starts_with(RESERVED_EA_NAME_PREFIX) {
        return Err(STATUS_INVALID_EA_NAME);
    }
    u8::try_from(name.len()).map_err(|_| STATUS_INVALID_EA_NAME)?;
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
fn align_to_four(value: usize) -> Result<usize, NTSTATUS> {
    let adjustment = EA_RECORD_ALIGNMENT
        .checked_sub(1)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let adjusted = value.checked_add(adjustment).ok_or(STATUS_EA_TOO_LARGE)?;
    let units = adjusted
        .checked_div(EA_RECORD_ALIGNMENT)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    units
        .checked_mul(EA_RECORD_ALIGNMENT)
        .ok_or(STATUS_EA_TOO_LARGE)
}

/// Converts a hexadecimal NTSTATUS payload into the signed WDK alias.
const fn ntstatus(value: u32) -> NTSTATUS {
    i32::from_ne_bytes(value.to_ne_bytes())
}

/// Reads one byte from an input buffer.
fn read_u8(input: &[u8], offset: usize) -> Result<u8, NTSTATUS> {
    input.get(offset).copied().ok_or(STATUS_BUFFER_TOO_SMALL)
}

/// Reads a little-endian `u16` from an unaligned input buffer.
fn read_u16(input: &[u8], offset: usize) -> Result<u16, NTSTATUS> {
    let end = offset
        .checked_add(core::mem::size_of::<u16>())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let bytes = input.get(offset..end).ok_or(STATUS_BUFFER_TOO_SMALL)?;
    let bytes: [u8; 2] = bytes.try_into().map_err(|_| STATUS_INVALID_PARAMETER)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Reads a little-endian `u32` from an unaligned input buffer.
fn read_u32(input: &[u8], offset: usize) -> Result<u32, NTSTATUS> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let bytes = input.get(offset..end).ok_or(STATUS_BUFFER_TOO_SMALL)?;
    let bytes: [u8; 4] = bytes.try_into().map_err(|_| STATUS_INVALID_PARAMETER)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Writes one byte into an output buffer.
fn write_u8(output: &mut [u8], offset: usize, value: u8) -> Result<(), NTSTATUS> {
    let Some(target) = output.get_mut(offset) else {
        return Err(STATUS_BUFFER_TOO_SMALL);
    };
    *target = value;
    Ok(())
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

/// Writes a byte slice into an output buffer.
fn write_bytes(output: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), NTSTATUS> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let Some(target) = output.get_mut(offset..end) else {
        return Err(STATUS_BUFFER_TOO_SMALL);
    };
    target.copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use wdk_sys::{STATUS_INVALID_EA_NAME, STATUS_NOT_SUPPORTED};

    use super::{
        STATUS_EA_LIST_INCONSISTENT, WindowsEaEntry, pack_full_ea_entries, parse_full_ea_list,
        parse_get_ea_list, read_u16, read_u32, write_bytes, write_u8, write_u32,
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
        assert_eq!(read_u32(output.as_slice(), 0), Ok(20));
        assert_eq!(read_u16(output.as_slice(), 6), Ok(3));
        assert_eq!(
            parse_full_ea_list(output.get(..36).unwrap_or(&[])),
            Ok(entries)
        );
    }

    #[test]
    fn get_ea_records_parse_names() {
        let mut input = vec![0; 32];
        assert_eq!(write_u32(input.as_mut_slice(), 0, 12), Ok(()));
        assert_eq!(write_u8(input.as_mut_slice(), 4, 5), Ok(()));
        assert_eq!(write_bytes(input.as_mut_slice(), 5, b"alpha"), Ok(()));
        assert_eq!(write_u8(input.as_mut_slice(), 10, 0), Ok(()));
        assert_eq!(write_u8(input.as_mut_slice(), 16, 4), Ok(()));
        assert_eq!(write_bytes(input.as_mut_slice(), 17, b"beta"), Ok(()));
        assert_eq!(write_u8(input.as_mut_slice(), 21, 0), Ok(()));

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
        assert_eq!(xattr_name_from_ea_name(b""), Err(STATUS_INVALID_EA_NAME));
        assert_eq!(
            xattr_name_from_ea_name(b"has\0nul"),
            Err(STATUS_INVALID_EA_NAME)
        );
        assert_eq!(
            xattr_name_from_ea_name(b"ext4win.attributes"),
            Err(STATUS_INVALID_EA_NAME)
        );
    }

    #[test]
    fn inconsistent_full_ea_list_is_rejected() {
        let mut input = vec![0; 16];
        assert_eq!(write_u8(input.as_mut_slice(), 5, 3), Ok(()));
        assert_eq!(write_bytes(input.as_mut_slice(), 8, b"abc"), Ok(()));
        assert_eq!(write_u8(input.as_mut_slice(), 11, b'x'), Ok(()));

        assert_eq!(
            parse_full_ea_list(input.as_slice()),
            Err(STATUS_EA_LIST_INCONSISTENT)
        );
    }

    #[test]
    fn nonzero_ea_flags_are_rejected() {
        let mut input = vec![0; 16];
        assert_eq!(write_u8(input.as_mut_slice(), 4, 1), Ok(()));
        assert_eq!(write_u8(input.as_mut_slice(), 5, 3), Ok(()));
        assert_eq!(write_bytes(input.as_mut_slice(), 8, b"abc"), Ok(()));
        assert_eq!(write_u8(input.as_mut_slice(), 11, 0), Ok(()));

        assert_eq!(
            parse_full_ea_list(input.as_slice()),
            Err(STATUS_NOT_SUPPORTED)
        );
    }
}
