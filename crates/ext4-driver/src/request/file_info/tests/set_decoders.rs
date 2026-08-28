use super::*;
use crate::request::file_info::test_support::*;
use alloc::vec;

/// # Panics
///
/// Panics when fixed set-information records accept truncated or incorrectly packed fields.
#[test]
fn fixed_set_information_decoders_are_field_checked_and_length_bounded() {
    let basic_size = core::mem::size_of::<wdk_sys::FILE_BASIC_INFORMATION>();
    let mut basic = vec![0xA5_u8; basic_size];
    let times = [-7_i64, 11, -13, 17];
    for (offset, value) in [
        (
            core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, CreationTime),
            times[0],
        ),
        (
            core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, LastAccessTime),
            times[1],
        ),
        (
            core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, LastWriteTime),
            times[2],
        ),
        (
            core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, ChangeTime),
            times[3],
        ),
    ] {
        assert!(put_le_i64(&mut basic, offset, value));
    }
    let attributes = 0x1234_5678;
    assert!(put_le_u32(
        &mut basic,
        core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, FileAttributes),
        attributes,
    ));
    let decoded = super::decode_basic_information_record(&basic);
    assert!(decoded.is_ok());
    let Ok(decoded) = decoded else {
        return;
    };
    assert_eq!(super::large_integer_quad(decoded.CreationTime), times[0]);
    assert_eq!(super::large_integer_quad(decoded.LastAccessTime), times[1]);
    assert_eq!(super::large_integer_quad(decoded.LastWriteTime), times[2]);
    assert_eq!(super::large_integer_quad(decoded.ChangeTime), times[3]);
    assert_eq!(decoded.FileAttributes, attributes);

    let eof_value = -0x0102_0304_0506_0708_i64;
    let eof_size = core::mem::size_of::<wdk_sys::FILE_END_OF_FILE_INFORMATION>();
    let mut eof = vec![0xA5_u8; eof_size];
    assert!(put_le_i64(
        &mut eof,
        core::mem::offset_of!(wdk_sys::FILE_END_OF_FILE_INFORMATION, EndOfFile),
        eof_value,
    ));
    assert_eq!(
        super::decode_end_of_file_record(&eof).map(super::large_integer_quad),
        Ok(eof_value)
    );

    let allocation_value = 0x0102_0304_0506_0708_i64;
    let allocation_size = core::mem::size_of::<wdk_sys::FILE_ALLOCATION_INFORMATION>();
    let mut allocation = vec![0xA5_u8; allocation_size];
    assert!(put_le_i64(
        &mut allocation,
        core::mem::offset_of!(wdk_sys::FILE_ALLOCATION_INFORMATION, AllocationSize),
        allocation_value,
    ));
    assert_eq!(
        super::decode_allocation_size_record(&allocation).map(super::large_integer_quad),
        Ok(allocation_value)
    );

    let position_value = -91_i64;
    let position_size = core::mem::size_of::<wdk_sys::FILE_POSITION_INFORMATION>();
    let mut position = vec![0xA5_u8; position_size];
    assert!(put_le_i64(
        &mut position,
        core::mem::offset_of!(wdk_sys::FILE_POSITION_INFORMATION, CurrentByteOffset),
        position_value,
    ));
    assert_eq!(
        super::decode_position_record(&position).map(super::large_integer_quad),
        Ok(position_value)
    );

    let legacy_size = core::mem::size_of::<wdk_sys::FILE_DISPOSITION_INFORMATION>();
    let mut legacy = vec![0xA5_u8; legacy_size];
    let legacy_offset = core::mem::offset_of!(wdk_sys::FILE_DISPOSITION_INFORMATION, DeleteFile);
    let Some(delete_file) = legacy.get_mut(legacy_offset) else {
        return;
    };
    *delete_file = 1;
    assert_eq!(super::decode_legacy_disposition_record(&legacy), Ok(true));

    let extended_size = core::mem::size_of::<wdk_sys::FILE_DISPOSITION_INFORMATION_EX>();
    let mut extended = vec![0xA5_u8; extended_size];
    let flags = 0x8765_4321;
    assert!(put_le_u32(
        &mut extended,
        core::mem::offset_of!(wdk_sys::FILE_DISPOSITION_INFORMATION_EX, Flags),
        flags,
    ));
    assert_eq!(
        super::decode_extended_disposition_record(&extended),
        Ok(flags)
    );

    for result in [
        basic
            .len()
            .checked_sub(1)
            .and_then(|length| basic.get(..length))
            .and_then(|input| super::decode_basic_information_record(input).err()),
        eof.len()
            .checked_sub(1)
            .and_then(|length| eof.get(..length))
            .and_then(|input| super::decode_end_of_file_record(input).err()),
        allocation
            .len()
            .checked_sub(1)
            .and_then(|length| allocation.get(..length))
            .and_then(|input| super::decode_allocation_size_record(input).err()),
        position
            .len()
            .checked_sub(1)
            .and_then(|length| position.get(..length))
            .and_then(|input| super::decode_position_record(input).err()),
        legacy
            .len()
            .checked_sub(1)
            .and_then(|length| legacy.get(..length))
            .and_then(|input| super::decode_legacy_disposition_record(input).err()),
        extended
            .len()
            .checked_sub(1)
            .and_then(|length| extended.get(..length))
            .and_then(|input| super::decode_extended_disposition_record(input).err()),
    ] {
        assert_eq!(result, Some(DriverError::BufferTooSmall));
    }
}
