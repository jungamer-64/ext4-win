/// # Panics
///
/// Panics when Windows directory indices wrap instead of becoming the required zero sentinel.
#[test]
fn directory_file_index_uses_zero_beyond_the_u32_ordinal_domain() {
    assert_eq!(super::directory_file_index(0), 0);
    assert_eq!(super::directory_file_index(u64::from(u32::MAX)), u32::MAX);
    assert_eq!(super::directory_file_index(u64::from(u32::MAX) + 1), 0);
}

/// # Panics
/// Fails if name projection failure consumes an entry or an unsupported name stalls the scan.
#[test]
fn directory_name_selection_preserves_cursor_on_allocation_failure() {
    use super::*;
    let result = (|| -> DriverResult<()> {
        let name = ext4_core::Ext4Name::new(b"caf\xC3\xA9")?;
        let pattern = DirectoryPattern::All;
        let mut cursor = DirectoryCursor::start();
        cursor.seek_ordinal(4);
        let before = cursor;
        let mut next = cursor;
        next.seek_ordinal(5);

        assert_eq!(
            select_directory_name(
                Err(DriverError::InsufficientResources),
                None,
                &pattern,
                &mut cursor,
                &next,
            ),
            Err(DriverError::InsufficientResources)
        );
        assert_eq!(cursor, before);
        let selected = select_directory_name(
            WindowsName::from_ext4(&name),
            None,
            &pattern,
            &mut cursor,
            &next,
        )?;
        let expected = [0x0063, 0x0061, 0x0066, 0x00E9];
        assert_eq!(
            selected.as_ref().map(WindowsName::utf16),
            Some(expected.as_slice())
        );
        assert_eq!(cursor, before);

        for bytes in [b"a:b".as_slice(), b"\xFF".as_slice()] {
            cursor = before;
            let name = ext4_core::Ext4Name::new(bytes)?;
            assert_eq!(
                select_directory_name(
                    WindowsName::from_ext4(&name),
                    None,
                    &pattern,
                    &mut cursor,
                    &next,
                ),
                Ok(None)
            );
            assert_eq!(cursor, next);
        }
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if exact-fit, first-call prefix, or deferred-name buffer contracts change.
#[test]
fn directory_capacity_preserves_first_and_subsequent_call_semantics() {
    use super::*;
    let result = (|| -> DriverResult<()> {
        let name = WindowsName::from_utf16(&[u16::from(b'x'); 255])?;
        for class in [
            DirectoryInformationClass::Names,
            DirectoryInformationClass::Directory,
            DirectoryInformationClass::IdBoth,
        ] {
            let layout = DirectoryRecordLayout::new(class, &name)?;
            assert_eq!(
                layout.admit(0, layout.name_offset - 1, true, true),
                Err(DriverError::BufferTooSmall)
            );
            assert_eq!(
                layout.admit(0, layout.name_offset, true, true)?,
                Some(DirectoryRecordExtent::Prefix(layout.name_offset))
            );
            assert_eq!(
                layout.admit(0, layout.unpadded_size - 1, true, true)?,
                Some(DirectoryRecordExtent::Prefix(layout.unpadded_size - 1))
            );
            assert_eq!(
                layout.admit(0, layout.unpadded_size, true, true)?,
                Some(DirectoryRecordExtent::Complete)
            );
            assert_eq!(
                layout.admit(0, layout.unpadded_size - 1, true, false)?,
                None
            );
            assert_eq!(
                layout.admit(16, 16 + layout.unpadded_size - 1, false, true)?,
                None
            );
            assert_eq!(
                layout.admit(16, 16 + layout.unpadded_size, false, false)?,
                Some(DirectoryRecordExtent::Complete)
            );
        }
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}
