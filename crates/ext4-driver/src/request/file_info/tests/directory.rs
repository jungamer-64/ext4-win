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
