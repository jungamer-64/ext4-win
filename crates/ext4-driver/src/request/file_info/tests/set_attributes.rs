use crate::request::file_info::test_support::*;

/// # Panics
///
/// Panics when setting read-only attributes fails to update the POSIX write bits.
#[test]
fn basic_attributes_set_readonly_updates_posix_permissions() {
    let metadata = test_metadata_with_permissions(super::FileMetadataKind::File, 0o664, 0);
    assert!(metadata.is_some());
    let Some(metadata) = metadata else {
        return;
    };

    let update = super::set_basic_attributes(metadata, wdk_sys::FILE_ATTRIBUTE_READONLY);
    assert!(update.is_ok());
    if let Ok(update) = update {
        assert_eq!(
            update
                .security()
                .map(|security| security.permissions().as_u16()),
            Some(0o444)
        );
        assert_eq!(update.overlay(), None);
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn basic_attributes_clear_readonly_restores_owner_write() {
    let metadata = test_metadata_with_permissions(super::FileMetadataKind::File, 0o444, 0);
    assert!(metadata.is_some());
    let Some(metadata) = metadata else {
        return;
    };

    let update = super::set_basic_attributes(metadata, wdk_sys::FILE_ATTRIBUTE_NORMAL);
    assert!(update.is_ok());
    if let Ok(update) = update {
        assert_eq!(
            update
                .security()
                .map(|security| security.permissions().as_u16()),
            Some(0o644)
        );
        assert_eq!(update.overlay(), None);
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn basic_attributes_zero_preserves_existing_attributes() {
    let metadata = test_metadata_with_permissions(super::FileMetadataKind::File, 0o444, 0);
    assert!(metadata.is_some());
    let Some(metadata) = metadata else {
        return;
    };

    let update = super::set_basic_attributes(metadata, 0);
    assert!(update.is_ok());
    if let Ok(update) = update {
        assert!(update.is_empty());
    }
}
