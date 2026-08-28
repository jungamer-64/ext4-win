use super::*;
use crate::request::file_info::test_support::*;
use alloc::vec;

/// # Panics
///
/// Panics when a large EOF or sparse allocation charge is truncated or recomputed by a Windows
/// information packer.
#[test]
fn large_file_information_preserves_eof_and_inode_allocation_size() {
    let metadata = test_metadata(super::FileMetadataKind::File);
    assert!(metadata.is_some());
    let Some(mut metadata) = metadata else {
        return;
    };
    let eof = (1_u64 << 32) + 17;
    let allocation_size = 4096_u64;
    metadata.size = FileSize::from_bytes(eof);
    metadata.allocation_size = FileAllocationSize::from_bytes(allocation_size);
    let stream_sizes = ext4_core::ClusterSize::new(4_096)
        .map_err(DriverError::from)
        .and_then(|cluster| {
            crate::kernel::stream::StreamSizes::try_from_ext4(
                metadata.size,
                metadata.allocation_size,
                cluster,
            )
        });
    assert!(stream_sizes.is_ok());
    let Ok(stream_sizes) = stream_sizes else {
        return;
    };

    let mut standard = [0_u8; core::mem::size_of::<wdk_sys::FILE_STANDARD_INFORMATION>()];
    assert!(super::pack_standard_information(&mut standard, metadata, false, stream_sizes).is_ok());
    assert_eq!(
        standard[core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, DeletePending)],
        0
    );
    assert!(super::pack_standard_information(&mut standard, metadata, true, stream_sizes).is_ok());
    assert_eq!(
        standard[core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, DeletePending)],
        1
    );
    assert_eq!(le_i64(&standard, 0), i64::try_from(allocation_size).ok());
    assert_eq!(le_i64(&standard, 8), i64::try_from(eof).ok());

    let mut network = [0_u8; core::mem::size_of::<wdk_sys::FILE_NETWORK_OPEN_INFORMATION>()];
    assert!(super::pack_network_open_information(&mut network, metadata, stream_sizes).is_ok());
    assert_eq!(le_i64(&network, 32), i64::try_from(allocation_size).ok());
    assert_eq!(le_i64(&network, 40), i64::try_from(eof).ok());

    let name = WindowsName::from_utf16(&[u16::from(b'a')]);
    assert!(name.is_ok());
    let Ok(name) = name else {
        return;
    };
    let layout = crate::request::file_info::directory::DirectoryRecordLayout::new(
        DirectoryInformationClass::Directory,
        &name,
    );
    assert!(layout.is_ok());
    let Ok(layout) = layout else {
        return;
    };
    let mut directory = [0_u8; 72];
    assert!(
        crate::request::file_info::directory::pack_directory_record(
            &mut directory,
            0,
            DirectoryInformationClass::Directory,
            1,
            &name,
            metadata,
            layout,
        )
        .is_ok()
    );
    assert_eq!(
        le_i64(
            &directory,
            crate::request::file_info::directory::DIRECTORY_ALLOCATION_SIZE_OFFSET,
        ),
        i64::try_from(allocation_size).ok()
    );
    assert_eq!(
        le_i64(
            &directory,
            crate::request::file_info::directory::DIRECTORY_END_OF_FILE_OFFSET,
        ),
        i64::try_from(eof).ok()
    );

    assert_eq!(
        crate::request::file_info::set::file_size_from_large_integer(wdk_sys::LARGE_INTEGER {
            QuadPart: i64::try_from(eof).unwrap_or(i64::MAX),
        }),
        Ok(FileSize::from_bytes(eof))
    );
}

/// # Errors
///
/// Returns a fixture construction or information-packing error.
/// # Panics
///
/// Panics if handle queries recompute sizes from ext4 metadata or accept a short fixed buffer.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture failures use Result; assertions verify the Windows wire contract"
)]
fn file_information_uses_stream_sizes_and_rejects_short_buffers() -> Result<(), DriverError> {
    let mut metadata = test_metadata(super::FileMetadataKind::File)
        .ok_or(DriverError::InternalInvariantViolation)?;
    metadata.size = FileSize::from_bytes(1);
    metadata.allocation_size = FileAllocationSize::from_bytes(512);
    let stream_sizes = crate::kernel::stream::StreamSizes::try_from_ext4(
        FileSize::from_bytes(8_193),
        FileAllocationSize::from_bytes(4_096),
        ext4_core::ClusterSize::new(4_096)?,
    )?;
    let mut standard = [0xA5; core::mem::size_of::<wdk_sys::FILE_STANDARD_INFORMATION>()];
    for length in 0..standard.len() {
        let short = standard
            .get_mut(..length)
            .ok_or(DriverError::InternalInvariantViolation)?;
        assert_eq!(
            super::pack_standard_information(short, metadata, false, stream_sizes),
            Err(DriverError::BufferTooSmall)
        );
    }
    super::pack_standard_information(&mut standard, metadata, false, stream_sizes)?;
    assert_eq!(le_i64(&standard, 0), Some(4_096));
    assert_eq!(le_i64(&standard, 8), Some(8_193));

    let mut network = [0xA5; core::mem::size_of::<wdk_sys::FILE_NETWORK_OPEN_INFORMATION>()];
    for length in 0..network.len() {
        let short = network
            .get_mut(..length)
            .ok_or(DriverError::InternalInvariantViolation)?;
        assert_eq!(
            super::pack_network_open_information(short, metadata, stream_sizes),
            Err(DriverError::BufferTooSmall)
        );
    }
    super::pack_network_open_information(&mut network, metadata, stream_sizes)?;
    assert_eq!(le_i64(&network, 32), Some(4_096));
    assert_eq!(le_i64(&network, 40), Some(8_193));
    Ok(())
}

/// # Panics
///
/// Panics when fixed-layout link information no longer preserves its Windows link lifecycle
/// contract.
#[test]
fn standard_link_information_projects_link_lifecycle_and_node_kind() {
    let metadata = test_metadata(super::FileMetadataKind::File);
    assert!(metadata.is_some());
    let Some(mut metadata) = metadata else {
        return;
    };
    let three_links = Ext4LinkCount::new(3);
    assert!(three_links.is_ok());
    let Ok(three_links) = three_links else {
        return;
    };
    metadata.links_count = three_links;
    let size = core::mem::size_of::<wdk_sys::FILE_STANDARD_LINK_INFORMATION>();

    let mut live = vec![0_u8; size];
    assert_eq!(
        super::pack_standard_link_information(&mut live, metadata, false),
        IrpCompletion::from_usize(size)
    );
    assert_eq!(
        le_u32(
            &live,
            core::mem::offset_of!(
                wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                NumberOfAccessibleLinks
            )
        ),
        Some(3)
    );
    assert_eq!(
        le_u32(
            &live,
            core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, TotalNumberOfLinks)
        ),
        Some(3)
    );
    assert_eq!(
        byte_at(
            &live,
            core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, DeletePending)
        ),
        Some(0)
    );
    assert_eq!(
        byte_at(
            &live,
            core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, Directory)
        ),
        Some(0)
    );

    let mut pending = vec![0_u8; size];
    assert_eq!(
        super::pack_standard_link_information(&mut pending, metadata, true),
        IrpCompletion::from_usize(size)
    );
    assert_eq!(
        le_u32(
            &pending,
            core::mem::offset_of!(
                wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                NumberOfAccessibleLinks
            )
        ),
        Some(2)
    );
    assert_eq!(
        le_u32(
            &pending,
            core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, TotalNumberOfLinks)
        ),
        Some(3)
    );
    assert_eq!(
        byte_at(
            &pending,
            core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, DeletePending)
        ),
        Some(1)
    );

    metadata.links_count = Ext4LinkCount::ONE;
    let mut single_pending = vec![0_u8; size];
    assert_eq!(
        super::pack_standard_link_information(&mut single_pending, metadata, true),
        IrpCompletion::from_usize(size)
    );
    assert_eq!(
        le_u32(
            &single_pending,
            core::mem::offset_of!(
                wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                NumberOfAccessibleLinks
            )
        ),
        Some(0)
    );
    assert_eq!(
        le_u32(
            &single_pending,
            core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, TotalNumberOfLinks)
        ),
        Some(1)
    );

    metadata.kind = super::FileMetadataKind::Directory;
    let five_links = Ext4LinkCount::new(5);
    assert!(five_links.is_ok());
    let Ok(five_links) = five_links else {
        return;
    };
    metadata.links_count = five_links;
    let mut directory = vec![0_u8; size];
    assert_eq!(
        super::pack_standard_link_information(&mut directory, metadata, false),
        IrpCompletion::from_usize(size)
    );
    assert_eq!(
        le_u32(
            &directory,
            core::mem::offset_of!(
                wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                NumberOfAccessibleLinks
            )
        ),
        Some(1)
    );
    assert_eq!(
        le_u32(
            &directory,
            core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, TotalNumberOfLinks)
        ),
        Some(1)
    );
    assert_eq!(
        byte_at(
            &directory,
            core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, Directory)
        ),
        Some(1)
    );

    let mut standard = vec![0_u8; core::mem::size_of::<wdk_sys::FILE_STANDARD_INFORMATION>()];
    assert_eq!(
        super::pack_standard_information(
            &mut standard,
            metadata,
            false,
            crate::kernel::stream::StreamSizes::EMPTY
        ),
        IrpCompletion::from_usize(standard.len())
    );
    assert_eq!(
        le_u32(
            &standard,
            core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, NumberOfLinks)
        ),
        Some(1)
    );

    metadata.kind = super::FileMetadataKind::Symlink;
    metadata.links_count = three_links;
    let mut symlink = vec![0_u8; size];
    assert_eq!(
        super::pack_standard_link_information(&mut symlink, metadata, false),
        IrpCompletion::from_usize(size)
    );
    assert_eq!(
        le_u32(
            &symlink,
            core::mem::offset_of!(
                wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                NumberOfAccessibleLinks
            )
        ),
        Some(3)
    );
    assert_eq!(
        byte_at(
            &symlink,
            core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, Directory)
        ),
        Some(0)
    );
}
