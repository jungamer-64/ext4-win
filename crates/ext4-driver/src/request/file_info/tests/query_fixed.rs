use crate::kernel::status::DriverError;
use crate::request::file_info::test_support::*;
use alloc::vec;

/// # Panics
/// Panics if stream enumeration publishes a partial record or invents a directory data stream.
#[test]
fn unnamed_stream_information_has_exact_windows_record_and_preserves_short_output() {
    let sizes = crate::kernel::stream::StreamSizes::EMPTY;
    for capacity in [0, 23, 31, 32, 37] {
        let mut output = vec![0xA5; capacity];
        assert_eq!(
            super::pack_stream_information(&mut output, super::FileMetadataKind::File, sizes),
            Err(DriverError::BufferTooSmall)
        );
        assert!(output.iter().all(|byte| *byte == 0xA5));
    }
    let mut output = [0xA5; 40];
    assert_eq!(
        super::pack_stream_information(&mut output, super::FileMetadataKind::File, sizes),
        crate::irp::IrpCompletion::from_usize(38)
    );
    let mut expected = [0; 38];
    expected[4] = 14;
    for (byte, value) in expected[24..]
        .iter_mut()
        .zip([58, 0, 58, 0, 36, 0, 68, 0, 65, 0, 84, 0, 65, 0])
    {
        *byte = value;
    }
    assert_eq!(&output[..38], &expected);
    assert_eq!(&output[38..], &[0xA5; 2]);
    assert_eq!(
        super::pack_stream_information(&mut output, super::FileMetadataKind::Directory, sizes),
        Ok(crate::irp::IrpCompletion::EMPTY)
    );
}

/// # Panics
///
/// Panics if EA information changes its Windows layout or overwrites bytes past the record.
#[test]
fn ea_information_reports_charge_and_rejects_short_output_before_writing() {
    let mut output = [0xA5_u8; 8];
    let completion = super::pack_ea_information(&mut output, 37);
    assert_eq!(completion, crate::irp::IrpCompletion::from_usize(4));
    assert_eq!(output, [37, 0, 0, 0, 0xA5, 0xA5, 0xA5, 0xA5]);
    let mut short = [0xA5_u8; 3];
    assert_eq!(
        super::pack_ea_information(&mut short, 37),
        Err(DriverError::BufferTooSmall)
    );
    assert_eq!(short, [0xA5; 3]);
}

/// # Panics
///
/// Panics when a fixed information packer exposes stale padding bytes.
#[test]
fn fixed_query_information_packers_clear_every_padding_byte() {
    let stream_sizes = crate::kernel::stream::StreamSizes::EMPTY;
    let metadata = test_metadata(super::FileMetadataKind::File);
    assert!(metadata.is_some());
    let Some(metadata) = metadata else {
        return;
    };

    let mut basic = vec![0xA5_u8; core::mem::size_of::<wdk_sys::FILE_BASIC_INFORMATION>()];
    assert!(super::pack_basic_information(&mut basic, metadata).is_ok());
    assert_padding_zero(
        &basic,
        &[
            (
                core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, CreationTime),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, LastAccessTime),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, LastWriteTime),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, ChangeTime),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, FileAttributes),
                4,
            ),
        ],
    );

    let mut standard = vec![0xA5_u8; core::mem::size_of::<wdk_sys::FILE_STANDARD_INFORMATION>()];
    assert!(
        super::pack_standard_information(
            &mut standard,
            metadata,
            crate::state::LinkDeletionInformation {
                selected_pending: false,
                pending_links: 0
            },
            stream_sizes
        )
        .is_ok()
    );
    assert_padding_zero(
        &standard,
        &[
            (
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, AllocationSize),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, EndOfFile),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, NumberOfLinks),
                4,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, DeletePending),
                1,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, Directory),
                1,
            ),
        ],
    );

    let mut standard_link =
        vec![0xA5_u8; core::mem::size_of::<wdk_sys::FILE_STANDARD_LINK_INFORMATION>()];
    assert!(
        super::pack_standard_link_information(
            &mut standard_link,
            metadata,
            crate::state::LinkDeletionInformation {
                selected_pending: false,
                pending_links: 0
            }
        )
        .is_ok()
    );
    assert_padding_zero(
        &standard_link,
        &[
            (
                core::mem::offset_of!(
                    wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                    NumberOfAccessibleLinks
                ),
                4,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, TotalNumberOfLinks),
                4,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, DeletePending),
                1,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, Directory),
                1,
            ),
        ],
    );

    let mut network = vec![0xA5_u8; core::mem::size_of::<wdk_sys::FILE_NETWORK_OPEN_INFORMATION>()];
    assert!(super::pack_network_open_information(&mut network, metadata, stream_sizes).is_ok());
    assert_padding_zero(
        &network,
        &[
            (
                core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, CreationTime),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, LastAccessTime),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, LastWriteTime),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, ChangeTime),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, AllocationSize),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, EndOfFile),
                8,
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, FileAttributes),
                4,
            ),
        ],
    );
}

/// # Panics
///
/// Panics if only a marked directory stops reporting the case-sensitive flag, or a short buffer
/// receives a partial record.
#[test]
fn case_sensitive_information_reports_only_marked_directories() {
    use crate::metadata::DirectoryNameComparison;
    for (comparison, flags) in [
        (
            DirectoryNameComparison::CaseSensitive,
            wdk_sys::FILE_CS_FLAG_CASE_SENSITIVE_DIR,
        ),
        (DirectoryNameComparison::Casefold, 0),
        (DirectoryNameComparison::CallerSelected, 0),
    ] {
        let mut output = [0xA5_u8; 8];
        assert_eq!(
            super::pack_case_sensitive_information(&mut output, comparison),
            crate::irp::IrpCompletion::from_usize(4)
        );
        assert_eq!(output.get(..4), Some(flags.to_le_bytes().as_slice()));
        assert_eq!(output.get(4..), Some([0xA5_u8; 4].as_slice()));
    }
    let mut short = [0xA5_u8; 3];
    assert_eq!(
        super::pack_case_sensitive_information(&mut short, DirectoryNameComparison::CaseSensitive),
        Err(DriverError::BufferTooSmall)
    );
    assert_eq!(short, [0xA5; 3]);
}

/// # Panics
///
/// Panics if `FILE_ID_INFORMATION` disagrees with the internal file reference or the volume
/// serial, or a short buffer receives a partial record.
#[test]
fn id_information_reuses_the_internal_reference_and_volume_serial() {
    let metadata = test_metadata(super::FileMetadataKind::File);
    let file_id = crate::metadata::WindowsFileId::from_u64(0x0000_0009_0000_0010);
    assert!(metadata.is_some() && file_id.is_ok());
    let (Some(mut metadata), Ok(file_id)) = (metadata, file_id) else {
        return;
    };
    metadata.file_id = file_id;
    let serial =
        crate::state::VolumeSerialNumber::from_uuid(ext4_core::FilesystemUuid::from_bytes([
            0x78, 0x56, 0x34, 0x12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ]));

    let mut internal = [0xA5_u8; 8];
    assert!(super::pack_internal_information(&mut internal, metadata).is_ok());
    let mut output = [0xA5_u8; 32];
    assert_eq!(
        super::pack_id_information(&mut output, serial, metadata),
        crate::irp::IrpCompletion::from_usize(24)
    );
    assert_eq!(
        output.get(..8),
        Some(0x1234_5678_u64.to_le_bytes().as_slice())
    );
    assert_eq!(output.get(8..16), Some(internal.as_slice()));
    assert_eq!(output.get(16..24), Some([0_u8; 8].as_slice()));
    assert_eq!(output.get(24..), Some([0xA5_u8; 8].as_slice()));

    let mut short = [0xA5_u8; 23];
    assert_eq!(
        super::pack_id_information(&mut short, serial, metadata),
        Err(DriverError::BufferTooSmall)
    );
    assert_eq!(short, [0xA5; 23]);
}
