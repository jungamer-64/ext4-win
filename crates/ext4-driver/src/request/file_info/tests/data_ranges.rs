use super::*;

/// # Panics
///
/// Panics when read-start selection mixes handle-position and paging-I/O semantics.
#[test]
fn read_start_selection_separates_handle_and_paging_io() {
    let explicit = FileOffset::from_bytes(4096);
    assert_eq!(
        super::select_read_start(DataIoKind::Paging, ReadStartingPoint::Absolute(explicit),),
        Ok(super::SelectedReadStart::Absolute(explicit))
    );
    assert_eq!(
        super::select_read_start(DataIoKind::Handle, ReadStartingPoint::CurrentFilePosition,),
        Ok(super::SelectedReadStart::CurrentFilePosition)
    );
    assert_eq!(
        super::select_read_start(DataIoKind::Paging, ReadStartingPoint::CurrentFilePosition,),
        Err(DriverError::InvalidParameter)
    );
}

/// # Panics
///
/// Panics when append-only writes retain a caller-selected starting point.
#[test]
fn append_only_write_selection_always_uses_end_of_file() {
    for starting_point in [
        WriteStartingPoint::Absolute(FileOffset::from_bytes(1)),
        WriteStartingPoint::CurrentFilePosition,
        WriteStartingPoint::EndOfFile,
    ] {
        assert_eq!(
            super::select_write_start(
                RegularFileWriteAccess::AppendOnly,
                DataIoKind::Handle,
                starting_point,
            ),
            Ok(super::SelectedWriteStart::EndOfFile)
        );
    }
}

/// # Panics
///
/// Panics when denied, positional, or paging write policy selects the wrong source.
#[test]
fn write_start_selection_enforces_access_and_paging_policy() {
    let explicit = FileOffset::from_bytes(8192);
    assert_eq!(
        super::select_write_start(
            RegularFileWriteAccess::Denied,
            DataIoKind::Handle,
            WriteStartingPoint::Absolute(explicit),
        ),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(
        super::select_write_start(
            RegularFileWriteAccess::Denied,
            DataIoKind::Handle,
            WriteStartingPoint::CurrentFilePosition,
        ),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(
        super::select_write_start(
            RegularFileWriteAccess::Positional,
            DataIoKind::Handle,
            WriteStartingPoint::CurrentFilePosition,
        ),
        Ok(super::SelectedWriteStart::CurrentFilePosition)
    );
    assert_eq!(
        super::select_write_start(
            RegularFileWriteAccess::Denied,
            DataIoKind::Paging,
            WriteStartingPoint::Absolute(explicit),
        ),
        Ok(super::SelectedWriteStart::Absolute(explicit))
    );
    assert_eq!(
        super::select_write_start(
            RegularFileWriteAccess::Positional,
            DataIoKind::Paging,
            WriteStartingPoint::EndOfFile,
        ),
        Err(DriverError::InvalidParameter)
    );
}

/// # Panics
///
/// Panics when access policy reads a handle position before selecting the write source.
#[test]
fn write_start_policy_precedes_current_position_binding() {
    let denied_position_read = core::cell::Cell::new(false);
    let denied = super::select_write_start(
        RegularFileWriteAccess::Denied,
        DataIoKind::Handle,
        WriteStartingPoint::CurrentFilePosition,
    )
    .and_then(|selected| {
        selected.bind_current_position(|| {
            denied_position_read.set(true);
            Err(DriverError::InvalidParameter)
        })
    });
    assert_eq!(denied, Err(DriverError::AccessDenied));
    assert!(!denied_position_read.get());

    let append_position_read = core::cell::Cell::new(false);
    let append = super::select_write_start(
        RegularFileWriteAccess::AppendOnly,
        DataIoKind::Handle,
        WriteStartingPoint::CurrentFilePosition,
    )
    .and_then(|selected| {
        selected.bind_current_position(|| {
            append_position_read.set(true);
            Err(DriverError::InvalidParameter)
        })
    });
    assert_eq!(append, Ok(super::WriteRangeAnchor::LatestEndOfFile));
    assert!(!append_position_read.get());

    let position = FileOffset::from_bytes(12288);
    let positional = super::select_write_start(
        RegularFileWriteAccess::Positional,
        DataIoKind::Handle,
        WriteStartingPoint::CurrentFilePosition,
    )
    .and_then(|selected| selected.bind_current_position(|| Ok(position)));
    assert_eq!(positional, Ok(super::WriteRangeAnchor::Fixed(position)));
}

/// # Panics
///
/// Panics when resolved ranges cross the signed Windows file-offset boundary.
#[test]
fn resolved_file_range_rejects_signed_end_overflow() {
    assert!(super::ResolvedFileRange::new(FileOffset::from_bytes(4096), 0).is_ok());
    assert_eq!(
        super::ResolvedFileRange::new(FileOffset::from_bytes(i64::MAX.unsigned_abs()), 1,).err(),
        Some(DriverError::InvalidParameter)
    );
}
