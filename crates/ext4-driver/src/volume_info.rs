//! Volume information query and mutation boundary.

use alloc::vec::Vec;
use core::ffi::c_void;

use ext4_core::{BlockSize, Ext4VolumeLabel};
use wdk_sys::{
    FILE_CASE_PRESERVED_NAMES, FILE_CASE_SENSITIVE_SEARCH, FILE_FS_ATTRIBUTE_INFORMATION,
    FILE_FS_LABEL_INFORMATION, FILE_FS_SIZE_INFORMATION, FILE_FS_VOLUME_INFORMATION,
    FILE_SUPPORTS_EXTENDED_ATTRIBUTES, FILE_SUPPORTS_REPARSE_POINTS, FILE_UNICODE_ON_DISK,
    LARGE_INTEGER, NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

use crate::{
    irp::{DispatchTarget, QueryVolumeStack, SetVolumeStack},
    state::{KernelDevice, MountedVolumeDevice, VolumeControlBlock},
    status::DriverError,
};

/// Filesystem name exposed through `FileFsAttributeInformation`.
const FILE_SYSTEM_NAME: &[u16] = &[0x0045, 0x0058, 0x0054, 0x0034, 0x0057, 0x0049, 0x004E];
/// Sector size reported to Windows.
const BYTES_PER_SECTOR: u32 = 512;
/// `FileFsVolumeInformation`.
const FILE_FS_VOLUME_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 1;
/// `FileFsLabelInformation`.
const FILE_FS_LABEL_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 2;
/// `FileFsSizeInformation`.
const FILE_FS_SIZE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 3;
/// `FileFsAttributeInformation`.
const FILE_FS_ATTRIBUTE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 5;

/// Handles volume information queries.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(QueryVolumeRequest::decode) {
        Ok(request) => query_volume(request),
        Err(error) => error.ntstatus(),
    }
}

/// Handles volume information mutations.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(SetVolumeRequest::decode) {
        Ok(request) => set_volume(request),
        Err(error) => error.ntstatus(),
    }
}

/// Decoded query-volume request.
#[derive(Clone, Copy, Debug)]
struct QueryVolumeRequest {
    /// Mounted device receiving the query.
    device: KernelDevice,
    /// IRP target for buffer and result accounting.
    target: DispatchTarget,
    /// Query stack parameters.
    stack: QueryVolumeStack,
}

impl QueryVolumeRequest {
    /// Decodes query-volume parameters.
    fn decode(target: DispatchTarget) -> Result<Self, crate::status::DriverError> {
        Ok(Self {
            device: KernelDevice::from_non_null(target.device()),
            target,
            stack: target.current_stack()?.query_volume()?,
        })
    }
}

/// Decoded set-volume request.
#[derive(Clone, Copy, Debug)]
struct SetVolumeRequest {
    /// Mounted device receiving the mutation.
    device: KernelDevice,
    /// IRP target for input buffer access.
    target: DispatchTarget,
    /// Set stack parameters.
    stack: SetVolumeStack,
}

impl SetVolumeRequest {
    /// Decodes set-volume parameters.
    fn decode(target: DispatchTarget) -> Result<Self, crate::status::DriverError> {
        Ok(Self {
            device: KernelDevice::from_non_null(target.device()),
            target,
            stack: target.current_stack()?.set_volume()?,
        })
    }
}

/// Immutable system buffer decoded from a set-volume IRP.
#[derive(Clone, Copy, Debug)]
struct SystemBufferInput {
    /// First buffer byte.
    buffer: core::ptr::NonNull<u8>,
    /// Buffer byte count.
    length: usize,
}

impl SystemBufferInput {
    /// Returns the system buffer as bytes.
    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: SystemBufferInput is constructed only from the active IRP
            // system buffer and a validated byte length. The returned slice is
            // consumed synchronously before IRP completion.
            core::slice::from_raw_parts(self.buffer.as_ptr(), self.length)
        }
    }
}

/// Executes one volume information query.
fn query_volume(request: QueryVolumeRequest) -> NTSTATUS {
    let Some(mut vcb) = MountedVolumeDevice::vcb(request.device) else {
        return crate::status::DriverError::InvalidDeviceRequest.ntstatus();
    };
    let vcb = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns a live VCB pointer stored in
        // this mounted device extension.
        vcb.as_mut()
    };
    let Some(buffer) = request.target.system_buffer() else {
        return STATUS_INVALID_PARAMETER;
    };
    let length = match usize::try_from(request.stack.length()) {
        Ok(length) => length,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };
    let written = match request.stack.information_class() {
        FILE_FS_VOLUME_INFORMATION_CLASS => pack_volume_information(vcb, buffer, length),
        FILE_FS_SIZE_INFORMATION_CLASS => pack_size_information(vcb, buffer, length),
        FILE_FS_ATTRIBUTE_INFORMATION_CLASS => pack_attribute_information(buffer, length),
        _ => return STATUS_INVALID_INFO_CLASS,
    };
    match written {
        Ok(bytes) => {
            request.target.set_information(bytes);
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// Executes one volume information mutation.
fn set_volume(request: SetVolumeRequest) -> NTSTATUS {
    match request.stack.information_class() {
        FILE_FS_LABEL_INFORMATION_CLASS => match set_volume_label(request) {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => status,
        },
        _ => STATUS_INVALID_INFO_CLASS,
    }
}

/// Applies `FILE_FS_LABEL_INFORMATION` to the mounted ext4 superblock.
fn set_volume_label(request: SetVolumeRequest) -> Result<(), NTSTATUS> {
    let length = usize::try_from(request.stack.length()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let input = system_buffer_input(request.target, length)?;
    let label = volume_label_from_file_fs_label(input.as_slice())?;
    let Some(mut vcb) = MountedVolumeDevice::vcb(request.device) else {
        return Err(DriverError::InvalidDeviceRequest.ntstatus());
    };
    let vcb = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns a live VCB pointer stored in
        // this mounted device extension. The mutable borrow is the transaction
        // boundary for this label mutation.
        vcb.as_mut()
    };
    if vcb.volume_label() == label {
        return Ok(());
    }

    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::time::current_ext4_timestamp().map_err(DriverError::ntstatus)?);
    transaction.set_volume_label(label);
    transaction
        .commit()
        .map_err(|error| DriverError::from(error).ntstatus())?;
    MountedVolumeDevice::refresh_vpb_label(request.device, vcb).ok_or(STATUS_INVALID_PARAMETER)
}

/// Decodes a Windows label information buffer into an ext4 volume label.
fn volume_label_from_file_fs_label(input: &[u8]) -> Result<Ext4VolumeLabel, NTSTATUS> {
    let header = core::mem::offset_of!(FILE_FS_LABEL_INFORMATION, VolumeLabel);
    if input.len() < header {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let label_length =
        usize::try_from(read_u32(input, 0)?).map_err(|_| STATUS_INVALID_PARAMETER)?;
    if !label_length.is_multiple_of(core::mem::size_of::<u16>()) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let end = header
        .checked_add(label_length)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let label_input = input.get(header..end).ok_or(STATUS_BUFFER_TOO_SMALL)?;
    let mut label = Vec::new();
    for unit in label_input.chunks_exact(core::mem::size_of::<u16>()) {
        let array: [u8; 2] = unit.try_into().map_err(|_| STATUS_INVALID_PARAMETER)?;
        let unit = u16::from_le_bytes(array);
        label.push(u8::try_from(unit).map_err(|_| STATUS_NOT_SUPPORTED)?);
    }
    Ext4VolumeLabel::new(label.as_slice()).map_err(|error| DriverError::from(error).ntstatus())
}

/// Packs `FILE_FS_VOLUME_INFORMATION`.
fn pack_volume_information(
    vcb: &VolumeControlBlock,
    buffer: core::ptr::NonNull<c_void>,
    length: usize,
) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
    let label = vcb.volume_label();
    let label_bytes = label.bytes();
    let header = core::mem::offset_of!(FILE_FS_VOLUME_INFORMATION, VolumeLabel);
    let label_len = label_bytes
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let required = header
        .checked_add(label_len)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if length < required {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }

    let info = unsafe {
        // SAFETY: The system buffer is writable for the requested query and the
        // length check above guarantees the fixed header is present.
        buffer
            .as_ptr()
            .cast::<FILE_FS_VOLUME_INFORMATION>()
            .as_mut()
    }
    .ok_or(STATUS_INVALID_PARAMETER)?;
    info.VolumeCreationTime = LARGE_INTEGER { QuadPart: 0 };
    info.VolumeSerialNumber = vcb.serial_number().ok_or(STATUS_INVALID_PARAMETER)?;
    info.VolumeLabelLength = u32::try_from(label_len).map_err(|_| STATUS_INVALID_PARAMETER)?;
    info.SupportsObjects = 0;

    let output = unsafe {
        // SAFETY: The system buffer is valid for `required` bytes by the check
        // above, and is reinterpreted only as bytes for label writing.
        core::slice::from_raw_parts_mut(buffer.as_ptr().cast::<u8>(), required)
    };
    let label_output = output
        .get_mut(header..required)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    for (chunk, byte) in label_output
        .chunks_exact_mut(2)
        .zip(label_bytes.iter().copied())
    {
        chunk.copy_from_slice(&u16::from(byte).to_le_bytes());
    }
    information_length(required)
}

/// Packs `FILE_FS_SIZE_INFORMATION`.
fn pack_size_information(
    vcb: &VolumeControlBlock,
    buffer: core::ptr::NonNull<c_void>,
    length: usize,
) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
    if length < core::mem::size_of::<FILE_FS_SIZE_INFORMATION>() {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let superblock = vcb.volume().superblock();
    let info = unsafe {
        // SAFETY: The caller supplied at least FILE_FS_SIZE_INFORMATION bytes.
        buffer.as_ptr().cast::<FILE_FS_SIZE_INFORMATION>().as_mut()
    }
    .ok_or(STATUS_INVALID_PARAMETER)?;
    info.TotalAllocationUnits = LARGE_INTEGER {
        QuadPart: i64::try_from(superblock.block_count().as_u64())
            .map_err(|_| STATUS_INVALID_PARAMETER)?,
    };
    info.AvailableAllocationUnits = LARGE_INTEGER {
        QuadPart: i64::try_from(superblock.free_blocks_count().as_u64())
            .map_err(|_| STATUS_INVALID_PARAMETER)?,
    };
    info.SectorsPerAllocationUnit = sectors_per_allocation_unit(superblock.block_size())?;
    info.BytesPerSector = BYTES_PER_SECTOR;
    information_length(core::mem::size_of::<FILE_FS_SIZE_INFORMATION>())
}

/// Packs `FILE_FS_ATTRIBUTE_INFORMATION`.
fn pack_attribute_information(
    buffer: core::ptr::NonNull<c_void>,
    length: usize,
) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
    let header = core::mem::offset_of!(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName);
    let name_len = FILE_SYSTEM_NAME
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let required = header
        .checked_add(name_len)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if length < required {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let info = unsafe {
        // SAFETY: The system buffer is writable for the requested query and the
        // length check above guarantees the fixed header is present.
        buffer
            .as_ptr()
            .cast::<FILE_FS_ATTRIBUTE_INFORMATION>()
            .as_mut()
    }
    .ok_or(STATUS_INVALID_PARAMETER)?;
    info.FileSystemAttributes = FILE_CASE_SENSITIVE_SEARCH
        | FILE_CASE_PRESERVED_NAMES
        | FILE_UNICODE_ON_DISK
        | FILE_SUPPORTS_REPARSE_POINTS
        | FILE_SUPPORTS_EXTENDED_ATTRIBUTES;
    info.MaximumComponentNameLength = 255;
    info.FileSystemNameLength = u32::try_from(name_len).map_err(|_| STATUS_INVALID_PARAMETER)?;

    let output = unsafe {
        // SAFETY: The system buffer is valid for `required` bytes by the check
        // above, and is reinterpreted only as bytes for name writing.
        core::slice::from_raw_parts_mut(buffer.as_ptr().cast::<u8>(), required)
    };
    let name_output = output
        .get_mut(header..required)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    for (chunk, unit) in name_output
        .chunks_exact_mut(2)
        .zip(FILE_SYSTEM_NAME.iter().copied())
    {
        chunk.copy_from_slice(&unit.to_le_bytes());
    }
    information_length(required)
}

/// Returns the set-volume system buffer.
fn system_buffer_input(
    target: DispatchTarget,
    length: usize,
) -> Result<SystemBufferInput, NTSTATUS> {
    let buffer = target.system_buffer().ok_or(STATUS_INVALID_PARAMETER)?;
    if length > usize::try_from(isize::MAX).map_err(|_| STATUS_INVALID_PARAMETER)? {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(SystemBufferInput {
        buffer: buffer.cast(),
        length,
    })
}

/// Reads a little-endian `u32`.
fn read_u32(input: &[u8], offset: usize) -> Result<u32, NTSTATUS> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let bytes = input.get(offset..end).ok_or(STATUS_INVALID_PARAMETER)?;
    let array: [u8; 4] = bytes.try_into().map_err(|_| STATUS_INVALID_PARAMETER)?;
    Ok(u32::from_le_bytes(array))
}

/// Returns sectors per ext4 block for Windows allocation units.
fn sectors_per_allocation_unit(block_size: BlockSize) -> Result<u32, NTSTATUS> {
    block_size
        .bytes()
        .checked_div(BYTES_PER_SECTOR)
        .filter(|sectors| *sectors != 0)
        .ok_or(STATUS_INVALID_PARAMETER)
}

/// Converts a byte count to `IO_STATUS_BLOCK::Information`.
fn information_length(value: usize) -> Result<wdk_sys::ULONG_PTR, NTSTATUS> {
    wdk_sys::ULONG_PTR::try_from(value).map_err(|_| STATUS_INVALID_PARAMETER)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::volume_label_from_file_fs_label;

    #[test]
    fn file_fs_label_information_decodes_byte_representable_utf16() {
        let input = label_information_bytes(b"EXT4");
        let label = volume_label_from_file_fs_label(input.as_slice());
        assert!(label.is_ok());
        if let Ok(label) = label {
            assert_eq!(label.bytes(), b"EXT4");
        }
    }

    #[test]
    fn file_fs_label_information_rejects_odd_label_byte_length() {
        let input = vec![1, 0, 0, 0, b'E'];
        assert_eq!(
            volume_label_from_file_fs_label(input.as_slice()),
            Err(wdk_sys::STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn file_fs_label_information_rejects_unrepresentable_utf16() {
        let input = vec![2, 0, 0, 0, 0x00, 0x01];
        assert_eq!(
            volume_label_from_file_fs_label(input.as_slice()),
            Err(wdk_sys::STATUS_NOT_SUPPORTED)
        );
    }

    #[test]
    fn file_fs_label_information_rejects_ext4_invalid_label() {
        let input = label_information_bytes(&[0]);
        assert_eq!(
            volume_label_from_file_fs_label(input.as_slice()),
            Err(wdk_sys::STATUS_INVALID_PARAMETER)
        );
    }

    /// Builds a FILE_FS_LABEL_INFORMATION byte image from label bytes.
    fn label_information_bytes(label: &[u8]) -> alloc::vec::Vec<u8> {
        let label_bytes = label.len().checked_mul(2);
        assert!(label_bytes.is_some());
        let Some(label_bytes) = label_bytes else {
            return Vec::new();
        };
        let mut input = Vec::new();
        let label_len = u32::try_from(label_bytes);
        assert!(label_len.is_ok());
        if let Ok(label_len) = label_len {
            input.extend_from_slice(label_len.to_le_bytes().as_slice());
            for byte in label {
                input.extend_from_slice(u16::from(*byte).to_le_bytes().as_slice());
            }
        }
        input
    }
}
