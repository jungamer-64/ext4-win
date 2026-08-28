use super::*;
use crate::request::file_info::test_support::*;
use alloc::vec;

fn windows_hard_links(entries: &[(u64, &[u16])]) -> Option<super::WindowsHardLinks> {
    let mut projected = crate::memory::DriverVec::try_with_capacity(entries.len()).ok()?;
    for (parent_file_id, units) in entries {
        let entry = super::WindowsHardLinkEntry {
            parent_file_id: *parent_file_id,
            name: WindowsName::from_utf16(units).ok()?,
        };
        projected.try_push_owned(entry).ok()?;
    }
    Some(super::WindowsHardLinks { entries: projected })
}

/// # Panics
///
/// Panics when a short standard-link output buffer is accepted or mutated.
#[test]
fn standard_link_information_rejects_short_output() {
    let metadata = test_metadata(super::FileMetadataKind::File);
    assert!(metadata.is_some());
    let Some(metadata) = metadata else {
        return;
    };
    let mut output =
        vec![0xA5_u8; core::mem::size_of::<wdk_sys::FILE_STANDARD_LINK_INFORMATION>() - 1];
    assert_eq!(
        super::pack_standard_link_information(&mut output, metadata, false),
        Err(DriverError::BufferTooSmall)
    );
    assert!(output.iter().all(|byte| *byte == 0xA5));
}

/// # Panics
///
/// Panics when FILE_LINKS_INFORMATION loses its header, alignment, parent ids, character
/// counts, names, or exact completion length.
#[test]
fn hard_link_information_packs_complete_aligned_entries() {
    let links = windows_hard_links(&[(7, &[u16::from(b'a')]), (11, &[u16::from(b'b'), 0x00E9])]);
    assert!(links.is_some());
    let Some(links) = links else {
        return;
    };
    let mut output = vec![0xA5_u8; 56];

    let packed = super::pack_hard_link_information(&mut output, &links);
    assert_eq!(
        packed,
        Ok(super::HardLinkInformationPacking {
            information: 56,
            all_entries_returned: true,
        })
    );
    assert_eq!(
        le_u32(&output, super::HARD_LINKS_BYTES_NEEDED_OFFSET),
        Some(56)
    );
    assert_eq!(
        le_u32(&output, super::HARD_LINKS_ENTRIES_RETURNED_OFFSET),
        Some(2)
    );

    let first = super::HARD_LINKS_HEADER_SIZE;
    assert_eq!(
        le_u32(&output, first + super::HARD_LINK_ENTRY_NEXT_OFFSET),
        Some(24)
    );
    assert_eq!(
        le_u64(&output, first + super::HARD_LINK_ENTRY_PARENT_ID_OFFSET),
        Some(7)
    );
    assert_eq!(
        le_u32(&output, first + super::HARD_LINK_ENTRY_NAME_LENGTH_OFFSET),
        Some(1)
    );
    assert_eq!(
        output.get(
            first + super::HARD_LINK_ENTRY_NAME_OFFSET
                ..first + super::HARD_LINK_ENTRY_NAME_OFFSET + 2
        ),
        Some([b'a', 0].as_slice())
    );
    let first_name_end = first + super::HARD_LINK_ENTRY_NAME_OFFSET + 2;
    let second = first + 24;
    assert_eq!(output.get(first_name_end..second), Some([0, 0].as_slice()));
    assert_eq!(
        le_u32(&output, second + super::HARD_LINK_ENTRY_NEXT_OFFSET),
        Some(0)
    );
    assert_eq!(
        le_u64(&output, second + super::HARD_LINK_ENTRY_PARENT_ID_OFFSET),
        Some(11)
    );
    assert_eq!(
        le_u32(&output, second + super::HARD_LINK_ENTRY_NAME_LENGTH_OFFSET),
        Some(2)
    );
    assert_eq!(
        output.get(
            second + super::HARD_LINK_ENTRY_NAME_OFFSET
                ..second + super::HARD_LINK_ENTRY_NAME_OFFSET + 4
        ),
        Some([b'b', 0, 0xE9, 0].as_slice())
    );
    assert_eq!(
        packed.and_then(super::HardLinkInformationPacking::completion),
        IrpCompletion::from_usize(56)
    );
}

/// # Panics
///
/// Panics when short hard-link output fails to report BytesNeeded, emits a partial record, or
/// returns the wrong overflow information length.
#[test]
fn hard_link_information_returns_only_complete_entries_on_overflow() {
    let links = windows_hard_links(&[(7, &[u16::from(b'a')]), (11, &[u16::from(b'b'), 0x00E9])]);
    assert!(links.is_some());
    let Some(links) = links else {
        return;
    };

    let mut one_entry = vec![0xA5_u8; 30];
    let packed = super::pack_hard_link_information(&mut one_entry, &links);
    assert_eq!(
        packed,
        Ok(super::HardLinkInformationPacking {
            information: 30,
            all_entries_returned: false,
        })
    );
    assert_eq!(
        le_u32(&one_entry, super::HARD_LINKS_BYTES_NEEDED_OFFSET),
        Some(56)
    );
    assert_eq!(
        le_u32(&one_entry, super::HARD_LINKS_ENTRIES_RETURNED_OFFSET),
        Some(1)
    );
    assert_eq!(
        le_u32(
            &one_entry,
            super::HARD_LINKS_HEADER_SIZE + super::HARD_LINK_ENTRY_NEXT_OFFSET
        ),
        Some(0)
    );
    assert_eq!(
        packed.and_then(super::HardLinkInformationPacking::completion),
        IrpCompletion::buffer_overflow(30)
    );

    let mut header_only = [0xA5_u8; super::HARD_LINKS_HEADER_SIZE];
    let packed = super::pack_hard_link_information(&mut header_only, &links);
    assert_eq!(
        packed,
        Ok(super::HardLinkInformationPacking {
            information: super::HARD_LINKS_HEADER_SIZE,
            all_entries_returned: false,
        })
    );
    assert_eq!(
        le_u32(&header_only, super::HARD_LINKS_BYTES_NEEDED_OFFSET),
        Some(56)
    );
    assert_eq!(
        le_u32(&header_only, super::HARD_LINKS_ENTRIES_RETURNED_OFFSET),
        Some(0)
    );

    let mut truncated = [0xA5_u8; super::HARD_LINKS_HEADER_SIZE - 1];
    assert_eq!(
        super::pack_hard_link_information(&mut truncated, &links),
        Err(DriverError::InfoLengthMismatch)
    );
    assert!(truncated.iter().all(|byte| *byte == 0xA5));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn reparse_metadata_controls_attribute_tag_and_file_attributes() {
    assert_eq!(super::reparse_tag(super::FileMetadataReparsePoint::None), 0);
    assert_eq!(
        super::reparse_tag(super::FileMetadataReparsePoint::SymbolicLink),
        wdk_sys::IO_REPARSE_TAG_SYMLINK
    );

    let metadata = test_metadata(super::FileMetadataKind::File);
    assert!(metadata.is_some());
    let Some(mut metadata) = metadata else {
        return;
    };
    metadata.reparse_point = super::FileMetadataReparsePoint::SymbolicLink;
    assert_ne!(
        super::file_attributes(metadata) & wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT,
        0
    );
}
