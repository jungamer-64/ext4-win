use super::*;
use crate::request::file_info::test_support::*;
use alloc::vec;

/// # Panics
/// Fails if directory metadata truncates a 64-bit EOF or reports logical size as physical charge.
#[test]
fn directory_metadata_preserves_large_eof_and_allocation_charge() {
    let result = (|| -> DriverResult<()> {
        let Some(mut file) = test_metadata(super::FileMetadataKind::File) else {
            return Err(DriverError::InternalInvariantViolation);
        };
        let eof = (1_u64 << 32) + 17;
        file.size = FileSize::from_bytes(eof);
        file.allocation_size = FileAllocationSize::from_bytes(4096);
        let name = WindowsName::from_utf16(&[u16::from(b'a')])?;
        let class = DirectoryInformationClass::Directory;
        let layout = DirectoryRecordLayout::new(class, &name)?;
        let mut buffer = vec![0; layout.padded_size];
        pack_directory_record(
            &mut buffer,
            0,
            class,
            1,
            &name,
            DirectoryMetadata { file, ea_size: 0 },
            layout,
        )?;
        assert_eq!(
            le_i64(&buffer, DIRECTORY_END_OF_FILE_OFFSET),
            i64::try_from(eof).ok()
        );
        assert_eq!(
            le_i64(&buffer, DIRECTORY_ALLOCATION_SIZE_OFFSET),
            Some(4096)
        );
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if regular-file enumeration loses its EA byte charge in a legacy or extended class.
#[test]
fn directory_metadata_returns_regular_file_ea_charge() {
    let result = (|| -> DriverResult<()> {
        let Some(file) = test_metadata(super::FileMetadataKind::File) else {
            return Err(DriverError::InternalInvariantViolation);
        };
        let name = WindowsName::from_utf16(&[u16::from(b'a')])?;
        for class in [
            DirectoryInformationClass::Full,
            DirectoryInformationClass::Both,
            DirectoryInformationClass::IdBoth,
            DirectoryInformationClass::IdExtd,
        ] {
            let layout = DirectoryRecordLayout::new(class, &name)?;
            let mut buffer = vec![0; layout.padded_size];
            pack_directory_record(
                &mut buffer,
                0,
                class,
                1,
                &name,
                DirectoryMetadata { file, ea_size: 29 },
                layout,
            )?;
            assert_eq!(le_u32(&buffer, DIRECTORY_EA_SIZE_OFFSET), Some(29));
        }
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
///
/// Panics when the names-only directory record loses its Windows wire layout.
#[test]
fn file_names_information_record_uses_name_only_layout() {
    let name = WindowsName::from_utf16(&[u16::from(b'a')]);
    assert!(name.is_ok());
    let Ok(name) = name else {
        return;
    };
    let mut buffer = [0_u8; 24];
    let packed = super::pack_name_record(&mut buffer, 0, 7, &name);
    assert!(packed.is_ok());

    assert_eq!(le_u32(&buffer, super::DIRECTORY_NEXT_ENTRY_OFFSET), Some(0));
    assert_eq!(le_u32(&buffer, super::DIRECTORY_FILE_INDEX_OFFSET), Some(7));
    assert_eq!(
        le_u32(&buffer, super::NAMES_INFORMATION_FILE_NAME_LENGTH_OFFSET),
        Some(2)
    );
    let name_bytes = buffer.get(super::NAMES_INFORMATION_NAME_OFFSET..24);
    assert!(name_bytes.is_some());
    let Some(name_bytes) = name_bytes else {
        return;
    };
    let expected_name: &[u8] = &[b'a', 0];
    assert_eq!(name_bytes.get(..2), Some(expected_name));
}

/// # Panics
///
/// Panics when an identity-bearing directory record loses its inode identity, reparse tag,
/// short-name emptiness, or class-specific file-name offset.
#[test]
fn identity_directory_records_preserve_exact_windows_layouts() {
    let name = WindowsName::from_utf16(&[u16::from(b'a')]);
    assert!(name.is_ok());
    let Ok(name) = name else {
        return;
    };
    let metadata = test_metadata(super::FileMetadataKind::Symlink);
    assert!(metadata.is_some());
    let Some(mut metadata) = metadata else {
        return;
    };
    metadata.file_index = 0x1234_5678;

    for (class, name_offset, file_id_offset, file_id_width, reparse_offset, short_offset) in [
        (
            DirectoryInformationClass::IdFull,
            super::ID_FULL_DIRECTORY_INFORMATION_NAME_OFFSET,
            super::ID_FULL_DIRECTORY_FILE_ID_OFFSET,
            8,
            None,
            None,
        ),
        (
            DirectoryInformationClass::IdBoth,
            super::ID_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
            super::ID_BOTH_DIRECTORY_FILE_ID_OFFSET,
            8,
            None,
            Some(super::ID_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET),
        ),
        (
            DirectoryInformationClass::IdExtd,
            super::ID_EXTD_DIRECTORY_INFORMATION_NAME_OFFSET,
            super::ID_EXTD_DIRECTORY_FILE_ID_OFFSET,
            16,
            Some(super::DIRECTORY_REPARSE_TAG_OFFSET),
            None,
        ),
        (
            DirectoryInformationClass::IdExtdBoth,
            super::ID_EXTD_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
            super::ID_EXTD_BOTH_DIRECTORY_FILE_ID_OFFSET,
            16,
            Some(super::DIRECTORY_REPARSE_TAG_OFFSET),
            Some(super::ID_EXTD_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET),
        ),
        (
            DirectoryInformationClass::Id64Extd,
            super::ID_64_EXTD_DIRECTORY_INFORMATION_NAME_OFFSET,
            super::ID_64_EXTD_DIRECTORY_FILE_ID_OFFSET,
            8,
            Some(super::DIRECTORY_REPARSE_TAG_OFFSET),
            None,
        ),
        (
            DirectoryInformationClass::Id64ExtdBoth,
            super::ID_64_EXTD_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
            super::ID_64_EXTD_BOTH_DIRECTORY_FILE_ID_OFFSET,
            8,
            Some(super::DIRECTORY_REPARSE_TAG_OFFSET),
            Some(super::ID_64_EXTD_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET),
        ),
    ] {
        let layout = super::DirectoryRecordLayout::new(class, &name);
        assert!(layout.is_ok());
        let Ok(layout) = layout else {
            continue;
        };
        assert_eq!(layout.name_offset, name_offset);
        let mut buffer = vec![0xFF_u8; layout.padded_size];
        assert!(
            super::pack_directory_record(
                &mut buffer,
                0,
                class,
                7,
                &name,
                super::DirectoryMetadata {
                    file: metadata,
                    ea_size: 44
                },
                layout,
            )
            .is_ok()
        );
        assert_eq!(
            le_u64(&buffer, file_id_offset),
            Some(u64::from(metadata.file_index))
        );
        if file_id_width == 16 {
            assert_eq!(
                buffer.get(file_id_offset + 8..file_id_offset + 16),
                Some([0_u8; 8].as_slice())
            );
        }
        if let Some(offset) = reparse_offset {
            assert_eq!(
                le_u32(&buffer, offset),
                Some(wdk_sys::IO_REPARSE_TAG_SYMLINK)
            );
        }
        assert_eq!(
            le_u32(&buffer, super::DIRECTORY_EA_SIZE_OFFSET),
            Some(if reparse_offset.is_some() {
                44
            } else {
                wdk_sys::IO_REPARSE_TAG_SYMLINK
            })
        );
        if let Some(offset) = short_offset {
            assert_eq!(byte_at(&buffer, offset), Some(0));
        }
        assert_eq!(
            buffer.get(name_offset..name_offset + 2),
            Some([b'a', 0].as_slice())
        );
    }
}
