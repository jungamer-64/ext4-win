use crate::request::file_info::test_support::*;
use ext4_core::{Ext4Times, Ext4Timestamp};

/// # Panics
/// Fails if attribute side effects overwrite explicit times or lose an unsuppressed change time.
#[test]
fn attribute_changes_preserve_only_explicit_or_suppressed_change_time() {
    use crate::state::{AutomaticTimeUpdate, HandleTimestampPolicy};
    let old = Ext4Timestamp::from_seconds(10);
    let changed = Ext4Timestamp::from_seconds(20);
    let before = Ext4Times::new(old, old, old, Some(old));
    let after = Ext4Times::new(old, old, changed, Some(old));
    let mut update = super::BasicTimeUpdates {
        created: None,
        accessed: super::BasicTimeUpdate::Keep,
        modified: super::BasicTimeUpdate::Keep,
        changed: super::BasicTimeUpdate::Keep,
    };
    assert_eq!(
        update.times(before, after, HandleTimestampPolicy::AUTOMATIC),
        after
    );
    let suppressed = HandleTimestampPolicy {
        changed: AutomaticTimeUpdate::Suppressed,
        ..HandleTimestampPolicy::AUTOMATIC
    };
    assert_eq!(update.times(before, after, suppressed), before);
    update.changed = super::BasicTimeUpdate::Suppress;
    assert_eq!(
        update.times(before, after, HandleTimestampPolicy::AUTOMATIC),
        before
    );
    update.changed = super::BasicTimeUpdate::Resume;
    assert_eq!(update.times(before, after, suppressed), after);
    update.changed = super::BasicTimeUpdate::Set(old);
    assert_eq!(
        update.times(before, after, HandleTimestampPolicy::AUTOMATIC),
        before
    );
}

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
        assert_eq!(update.security(), None);
        assert_eq!(update.overlay(), None);
    }
}
