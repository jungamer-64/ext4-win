use crate::request::file_info::test_support::*;
use alloc::vec;

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
    assert!(super::pack_standard_information(&mut standard, metadata, false, stream_sizes).is_ok());
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
    assert!(super::pack_standard_link_information(&mut standard_link, metadata, false).is_ok());
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
