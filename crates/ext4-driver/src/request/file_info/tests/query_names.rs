use super::*;

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn opened_location_name_units_project_root_and_child_names() {
    let root_units: &[u16] = &[super::UTF16_BACKSLASH];
    let projected_root = super::opened_location_name_units(&OpenedLocation::Root);
    assert!(projected_root.is_ok());
    if let Ok(projected_root) = projected_root {
        assert_eq!(projected_root.as_slice(), root_units);
    }

    let name = Ext4Name::new(b"file");
    assert!(name.is_ok());
    let Ok(name) = name else {
        return;
    };
    let location = OpenedLocation::DirectoryEntry {
        parent: DirectoryNodeId::ROOT,
        name,
    };
    let child_units: &[u16] = &[
        u16::from(b'f'),
        u16::from(b'i'),
        u16::from(b'l'),
        u16::from(b'e'),
    ];
    let projected_child = super::opened_location_name_units(&location);
    assert!(projected_child.is_ok());
    if let Ok(projected_child) = projected_child {
        assert_eq!(projected_child.as_slice(), child_units);
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn opened_location_name_units_rejects_file_reference_location() {
    assert_eq!(
        super::opened_location_name_units(&OpenedLocation::FileReference),
        Err(DriverError::NotSupported)
    );
}
