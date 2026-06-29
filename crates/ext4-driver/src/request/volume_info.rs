//! Volume information query and mutation boundary.

use alloc::vec::Vec;
use ext4_core::{ClusterSize, Ext4VolumeLabel};
use wdk_sys::{
    FILE_CASE_PRESERVED_NAMES, FILE_CASE_SENSITIVE_SEARCH, FILE_FS_ATTRIBUTE_INFORMATION,
    FILE_FS_DEVICE_INFORMATION, FILE_FS_FULL_SIZE_INFORMATION, FILE_FS_LABEL_INFORMATION,
    FILE_FS_SIZE_INFORMATION, FILE_FS_VOLUME_INFORMATION, FILE_SUPPORTS_EXTENDED_ATTRIBUTES,
    FILE_SUPPORTS_REPARSE_POINTS, FILE_UNICODE_ON_DISK, LARGE_INTEGER, NTSTATUS, PDEVICE_OBJECT,
    PIRP, STATUS_SUCCESS,
};

use crate::{
    irp::{
        DispatchTarget, DriverCompletion, QueryVolumeInformationClass, QueryVolumeStack,
        SetVolumeInformationClass, SetVolumeStack,
    },
    kernel::status::{DriverError, DriverResult},
    state::{KernelDevice, MountedVolumeDevice, VolumeControlBlock},
    wire::{LittleEndianInput, LittleEndianOutput, WireOffset, WireRange},
};

/// Filesystem name exposed through `FileFsAttributeInformation`.
const FILE_SYSTEM_NAME: &[u16] = &[0x0045, 0x0058, 0x0054, 0x0034, 0x0057, 0x0049, 0x004E];
/// Sector size reported to Windows.
const BYTES_PER_SECTOR: u32 = 512;

/// Handles volume information queries.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(QueryVolumeRequest::decode) {
        Ok(request) => match query_volume(request) {
            Ok(completion) => {
                request.target.complete(completion);
                STATUS_SUCCESS
            }
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Handles volume information mutations.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(SetVolumeRequest::decode) {
        Ok(request) => match set_volume(request) {
            Ok(completion) => {
                request.target.complete(completion);
                STATUS_SUCCESS
            }
            Err(error) => error.ntstatus(),
        },
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
    fn decode(target: DispatchTarget) -> Result<Self, crate::kernel::status::DriverError> {
        Ok(Self {
            device: target.device(),
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
    fn decode(target: DispatchTarget) -> Result<Self, crate::kernel::status::DriverError> {
        Ok(Self {
            device: target.device(),
            target,
            stack: target.current_stack()?.set_volume()?,
        })
    }
}

/// Executes one volume information query.
fn query_volume(request: QueryVolumeRequest) -> DriverResult<DriverCompletion> {
    let Some(mut vcb) = MountedVolumeDevice::vcb(request.device) else {
        return Err(DriverError::InvalidDeviceRequest);
    };
    let vcb = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns a live VCB pointer stored in
        // this mounted device extension.
        vcb.as_mut()
    };
    let length = request.stack.length().as_usize();
    let mut buffer = request.target.buffered_output(length)?;
    let output = buffer.as_mut_slice();
    match request.stack.information_class() {
        QueryVolumeInformationClass::Volume => pack_volume_information(vcb, output),
        QueryVolumeInformationClass::Size => pack_size_information(vcb, output),
        QueryVolumeInformationClass::Device => pack_device_information(output),
        QueryVolumeInformationClass::Attribute => pack_attribute_information(output),
        QueryVolumeInformationClass::FullSize => pack_full_size_information(vcb, output),
    }
}

/// Executes one volume information mutation.
fn set_volume(request: SetVolumeRequest) -> DriverResult<DriverCompletion> {
    match request.stack.information_class() {
        SetVolumeInformationClass::Label => set_volume_label(request),
    }?;
    Ok(DriverCompletion::EMPTY)
}

/// Applies `FILE_FS_LABEL_INFORMATION` to the mounted ext4 superblock.
fn set_volume_label(request: SetVolumeRequest) -> DriverResult<()> {
    let length = request.stack.length().as_usize();
    let input = request.target.buffered_input(length)?;
    let label = volume_label_from_file_fs_label(input.as_slice())?;
    let Some(mut vcb) = MountedVolumeDevice::vcb(request.device) else {
        return Err(DriverError::InvalidDeviceRequest);
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
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    transaction.set_volume_label(label);
    transaction.commit()?;
    MountedVolumeDevice::refresh_vpb_label(request.device, vcb).ok_or(DriverError::InvalidParameter)
}

/// Decodes a Windows label information buffer into an ext4 volume label.
fn volume_label_from_file_fs_label(input: &[u8]) -> DriverResult<Ext4VolumeLabel> {
    let header = core::mem::offset_of!(FILE_FS_LABEL_INFORMATION, VolumeLabel);
    if input.len() < header {
        return Err(DriverError::BufferTooSmall);
    }
    let input = LittleEndianInput::new(input);
    let label_length = usize::try_from(input.read_u32(WireOffset::new(0))?)
        .map_err(|_| DriverError::InvalidParameter)?;
    if !label_length.is_multiple_of(core::mem::size_of::<u16>()) {
        return Err(DriverError::InvalidParameter);
    }
    let end = header
        .checked_add(label_length)
        .ok_or(DriverError::InvalidParameter)?;
    let label_input = input.range(WireRange::span(
        WireOffset::new(header),
        WireOffset::new(end),
    )?)?;
    let mut label = Vec::new();
    for unit in label_input.chunks_exact(core::mem::size_of::<u16>()) {
        let array: [u8; 2] = unit.try_into().map_err(|_| DriverError::InvalidParameter)?;
        let unit = u16::from_le_bytes(array);
        label.push(u8::try_from(unit).map_err(|_| DriverError::NotSupported)?);
    }
    Ext4VolumeLabel::new(label.as_slice()).map_err(|_| DriverError::InvalidParameter)
}

/// Packs `FILE_FS_VOLUME_INFORMATION`.
fn pack_volume_information(
    vcb: &VolumeControlBlock,
    output: &mut [u8],
) -> DriverResult<DriverCompletion> {
    let label = vcb.volume_label();
    let label_bytes = label.bytes();
    let header = core::mem::offset_of!(FILE_FS_VOLUME_INFORMATION, VolumeLabel);
    let label_len = label_bytes
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)?;
    let required = header
        .checked_add(label_len)
        .ok_or(DriverError::InvalidParameter)?;
    if output.len() < required {
        return Err(DriverError::BufferTooSmall);
    }

    let output = output
        .get_mut(..required)
        .ok_or(DriverError::BufferTooSmall)?;
    let mut writer = LittleEndianOutput::new(output);
    writer.write_bytes(
        WireOffset::new(core::mem::offset_of!(
            FILE_FS_VOLUME_INFORMATION,
            VolumeCreationTime
        )),
        0_i64.to_le_bytes().as_slice(),
    )?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            FILE_FS_VOLUME_INFORMATION,
            VolumeSerialNumber
        )),
        vcb.serial_number().as_u32(),
    )?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            FILE_FS_VOLUME_INFORMATION,
            VolumeLabelLength
        )),
        u32::try_from(label_len).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    writer.write_u8(
        WireOffset::new(core::mem::offset_of!(
            FILE_FS_VOLUME_INFORMATION,
            SupportsObjects
        )),
        0,
    )?;

    let label_output = writer.range_mut(WireRange::span(
        WireOffset::new(header),
        WireOffset::new(required),
    )?)?;
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
    output: &mut [u8],
) -> DriverResult<DriverCompletion> {
    let geometry = vcb.volume().geometry();
    write_fixed(
        output,
        FILE_FS_SIZE_INFORMATION {
            TotalAllocationUnits: LARGE_INTEGER {
                QuadPart: i64::try_from(geometry.cluster_count().as_u64())
                    .map_err(|_| DriverError::InvalidParameter)?,
            },
            AvailableAllocationUnits: LARGE_INTEGER {
                QuadPart: i64::try_from(geometry.free_cluster_count().as_u64())
                    .map_err(|_| DriverError::InvalidParameter)?,
            },
            SectorsPerAllocationUnit: sectors_per_allocation_unit(geometry.cluster_size())?,
            BytesPerSector: BYTES_PER_SECTOR,
        },
    )
}

/// Packs `FILE_FS_DEVICE_INFORMATION`.
fn pack_device_information(output: &mut [u8]) -> DriverResult<DriverCompletion> {
    write_fixed(
        output,
        FILE_FS_DEVICE_INFORMATION {
            DeviceType: wdk_sys::FILE_DEVICE_DISK_FILE_SYSTEM,
            Characteristics: 0,
        },
    )
}

/// Packs `FILE_FS_FULL_SIZE_INFORMATION`.
fn pack_full_size_information(
    vcb: &VolumeControlBlock,
    output: &mut [u8],
) -> DriverResult<DriverCompletion> {
    let geometry = vcb.volume().geometry();
    let available = LARGE_INTEGER {
        QuadPart: i64::try_from(geometry.free_cluster_count().as_u64())
            .map_err(|_| DriverError::InvalidParameter)?,
    };
    write_fixed(
        output,
        FILE_FS_FULL_SIZE_INFORMATION {
            TotalAllocationUnits: LARGE_INTEGER {
                QuadPart: i64::try_from(geometry.cluster_count().as_u64())
                    .map_err(|_| DriverError::InvalidParameter)?,
            },
            CallerAvailableAllocationUnits: available,
            ActualAvailableAllocationUnits: available,
            SectorsPerAllocationUnit: sectors_per_allocation_unit(geometry.cluster_size())?,
            BytesPerSector: BYTES_PER_SECTOR,
        },
    )
}

/// Packs `FILE_FS_ATTRIBUTE_INFORMATION`.
fn pack_attribute_information(output: &mut [u8]) -> DriverResult<DriverCompletion> {
    let header = core::mem::offset_of!(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName);
    let name_len = FILE_SYSTEM_NAME
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)?;
    let required = header
        .checked_add(name_len)
        .ok_or(DriverError::InvalidParameter)?;
    if output.len() < required {
        return Err(DriverError::BufferTooSmall);
    }
    let output = output
        .get_mut(..required)
        .ok_or(DriverError::BufferTooSmall)?;
    let mut writer = LittleEndianOutput::new(output);
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            FILE_FS_ATTRIBUTE_INFORMATION,
            FileSystemAttributes
        )),
        FILE_CASE_SENSITIVE_SEARCH
            | FILE_CASE_PRESERVED_NAMES
            | FILE_UNICODE_ON_DISK
            | FILE_SUPPORTS_REPARSE_POINTS
            | FILE_SUPPORTS_EXTENDED_ATTRIBUTES,
    )?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            FILE_FS_ATTRIBUTE_INFORMATION,
            MaximumComponentNameLength
        )),
        255,
    )?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            FILE_FS_ATTRIBUTE_INFORMATION,
            FileSystemNameLength
        )),
        u32::try_from(name_len).map_err(|_| DriverError::InvalidParameter)?,
    )?;

    let name_output = writer.range_mut(WireRange::span(
        WireOffset::new(header),
        WireOffset::new(required),
    )?)?;
    for (chunk, unit) in name_output
        .chunks_exact_mut(2)
        .zip(FILE_SYSTEM_NAME.iter().copied())
    {
        chunk.copy_from_slice(&unit.to_le_bytes());
    }
    information_length(required)
}

/// Returns sectors per ext4 allocation cluster for Windows allocation units.
fn sectors_per_allocation_unit(cluster_size: ClusterSize) -> DriverResult<u32> {
    cluster_size
        .bytes()
        .checked_div(BYTES_PER_SECTOR)
        .filter(|sectors| *sectors != 0)
        .ok_or(DriverError::InvalidParameter)
}

/// Converts a byte count to `IO_STATUS_BLOCK::Information`.
fn information_length(value: usize) -> DriverResult<DriverCompletion> {
    DriverCompletion::from_usize(value)
}

/// Writes one fixed-size WDK information structure into an output byte buffer.
fn write_fixed<T>(output: &mut [u8], value: T) -> DriverResult<DriverCompletion> {
    let size = core::mem::size_of::<T>();
    if output.len() < size {
        return Err(DriverError::BufferTooSmall);
    }
    unsafe {
        // SAFETY: The output slice is at least `size_of::<T>()` bytes and the
        // write does not read from the destination. Unaligned write avoids
        // imposing an alignment requirement on the system buffer.
        output.as_mut_ptr().cast::<T>().write_unaligned(value);
    }
    information_length(size)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use crate::{
        irp::DriverCompletion,
        kernel::status::DriverError,
        wire::{LittleEndianInput, WireOffset},
    };

    use super::{pack_device_information, volume_label_from_file_fs_label};

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
            Err(DriverError::InvalidParameter)
        );
    }

    #[test]
    fn file_fs_label_information_rejects_unrepresentable_utf16() {
        let input = vec![2, 0, 0, 0, 0x00, 0x01];
        assert_eq!(
            volume_label_from_file_fs_label(input.as_slice()),
            Err(DriverError::NotSupported)
        );
    }

    #[test]
    fn file_fs_label_information_rejects_ext4_invalid_label() {
        let input = label_information_bytes(&[0]);
        assert_eq!(
            volume_label_from_file_fs_label(input.as_slice()),
            Err(DriverError::InvalidParameter)
        );
    }

    #[test]
    fn device_information_reports_disk_file_system_without_device_flags() {
        let mut buffer = vec![0; core::mem::size_of::<wdk_sys::FILE_FS_DEVICE_INFORMATION>()];
        let written = pack_device_information(buffer.as_mut_slice());
        assert!(written.is_ok());
        if let Ok(written) = written {
            assert_eq!(DriverCompletion::from_usize(buffer.len()), Ok(written));
            let output = LittleEndianInput::new(buffer.as_slice());
            assert_eq!(
                output.read_u32(WireOffset::new(0)),
                Ok(wdk_sys::FILE_DEVICE_DISK_FILE_SYSTEM)
            );
            assert_eq!(output.read_u32(WireOffset::new(4)), Ok(0));
        }
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
