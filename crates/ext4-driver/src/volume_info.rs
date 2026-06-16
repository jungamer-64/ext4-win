//! Volume information query and mutation boundary.

use core::ffi::c_void;

use ext4_core::BlockSize;
use wdk_sys::{
    FILE_CASE_PRESERVED_NAMES, FILE_CASE_SENSITIVE_SEARCH, FILE_FS_ATTRIBUTE_INFORMATION,
    FILE_FS_SIZE_INFORMATION, FILE_FS_VOLUME_INFORMATION, FILE_SUPPORTS_EXTENDED_ATTRIBUTES,
    FILE_SUPPORTS_REPARSE_POINTS, FILE_UNICODE_ON_DISK, LARGE_INTEGER, NTSTATUS, PDEVICE_OBJECT,
    PIRP, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER,
    STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

use crate::{
    irp::{DispatchTarget, QueryVolumeStack},
    state::{KernelDevice, MountedVolumeDevice, VolumeControlBlock},
};

/// Filesystem name exposed through `FileFsAttributeInformation`.
const FILE_SYSTEM_NAME: &[u16] = &[0x0045, 0x0058, 0x0054, 0x0034, 0x0057, 0x0049, 0x004E];
/// Sector size reported to Windows.
const BYTES_PER_SECTOR: u32 = 512;
/// `FileFsVolumeInformation`.
const FILE_FS_VOLUME_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 1;
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
    match DispatchTarget::decode(device, irp) {
        Ok(_target) => STATUS_NOT_SUPPORTED,
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
