use super::*;

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn rename_target_path_rejects_empty_and_root_only_names() {
    assert_eq!(
        super::NonEmptyWindowsPath::from_utf16_path(&[]),
        Err(DriverError::InvalidParameter)
    );
    assert_eq!(
        super::NonEmptyWindowsPath::from_utf16_path(&[super::UTF16_BACKSLASH]),
        Err(DriverError::InvalidParameter)
    );
}
