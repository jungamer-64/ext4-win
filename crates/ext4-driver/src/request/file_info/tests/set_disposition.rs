use super::*;

/// # Panics
///
/// Panics when extended disposition flags lose their non-POSIX or on-close semantics.
#[test]
fn extended_disposition_decodes_non_posix_and_on_close_semantics() {
    assert_eq!(
        super::decode_extended_disposition(0),
        Ok(super::FileDispositionRequest::keep(
            super::FileDispositionTarget::Mutable
        ))
    );
    assert_eq!(
        super::decode_extended_disposition(wdk_sys::FILE_DISPOSITION_DELETE),
        Ok(super::FileDispositionRequest::delete(
            super::FileDispositionTarget::Mutable,
            super::DeleteReadonlyRequest::Enforce
        ))
    );
    assert_eq!(
        super::decode_extended_disposition(
            wdk_sys::FILE_DISPOSITION_DELETE | wdk_sys::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
        ),
        Ok(super::FileDispositionRequest::delete(
            super::FileDispositionTarget::Mutable,
            super::DeleteReadonlyRequest::Ignore
        ))
    );
    assert_eq!(
        super::decode_extended_disposition(wdk_sys::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE),
        Ok(super::FileDispositionRequest::keep(
            super::FileDispositionTarget::Mutable
        ))
    );
    for inactive in [
        wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS,
        wdk_sys::FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK,
    ] {
        assert_eq!(
            super::decode_extended_disposition(inactive),
            Ok(super::FileDispositionRequest::keep(
                super::FileDispositionTarget::Mutable
            ))
        );
    }
    assert_eq!(
        super::decode_extended_disposition(wdk_sys::FILE_DISPOSITION_ON_CLOSE),
        Ok(super::FileDispositionRequest::keep(
            super::FileDispositionTarget::CreateDeleteOnClose
        ))
    );
    assert_eq!(
        super::decode_extended_disposition(
            wdk_sys::FILE_DISPOSITION_DELETE | wdk_sys::FILE_DISPOSITION_ON_CLOSE
        ),
        Ok(super::FileDispositionRequest::delete(
            super::FileDispositionTarget::CreateDeleteOnClose,
            super::DeleteReadonlyRequest::Enforce
        ))
    );
    assert_eq!(
        super::decode_extended_disposition(
            wdk_sys::FILE_DISPOSITION_DELETE
                | wdk_sys::FILE_DISPOSITION_ON_CLOSE
                | wdk_sys::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
        ),
        Ok(super::FileDispositionRequest::delete(
            super::FileDispositionTarget::CreateDeleteOnClose,
            super::DeleteReadonlyRequest::Ignore
        ))
    );
    for unsupported in [
        wdk_sys::FILE_DISPOSITION_DELETE | wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS,
        wdk_sys::FILE_DISPOSITION_DELETE | wdk_sys::FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK,
        wdk_sys::FILE_DISPOSITION_DELETE
            | wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS
            | wdk_sys::FILE_DISPOSITION_ON_CLOSE,
        0x20,
    ] {
        assert_eq!(
            super::decode_extended_disposition(unsupported),
            Err(DriverError::NotSupported)
        );
    }
}

/// # Panics
///
/// Panics when ON_CLOSE can target a handle not opened with FILE_DELETE_ON_CLOSE.
#[test]
fn on_close_disposition_requires_create_delete_on_close() {
    assert_eq!(
        super::FileDispositionTarget::Mutable.validate(CreateDeletion::Retain),
        Ok(())
    );
    assert_eq!(
        super::FileDispositionTarget::Mutable.validate(CreateDeletion::DeleteOnClose),
        Ok(())
    );
    assert_eq!(
        super::FileDispositionTarget::CreateDeleteOnClose.validate(CreateDeletion::Retain),
        Err(DriverError::NotSupported)
    );
    assert_eq!(
        super::FileDispositionTarget::CreateDeleteOnClose.validate(CreateDeletion::DeleteOnClose),
        Ok(())
    );
}

/// # Panics
///
/// Panics when read-only deletion can bypass `FILE_WRITE_ATTRIBUTES`.
#[test]
fn readonly_deletion_override_requires_file_attributes_write_access() {
    let ordinary = wdk_sys::FILE_ATTRIBUTE_NORMAL;
    let readonly = wdk_sys::FILE_ATTRIBUTE_READONLY;

    assert_eq!(
        super::DeleteReadonlyPolicy::Enforce.validate_attributes(ordinary),
        Ok(())
    );
    assert_eq!(
        super::DeleteReadonlyPolicy::Ignore(FileAttributesWriteAccess::Denied)
            .validate_attributes(ordinary),
        Ok(())
    );
    assert_eq!(
        super::DeleteReadonlyPolicy::Enforce.validate_attributes(readonly),
        Err(DriverError::CannotDelete)
    );
    assert_eq!(
        super::DeleteReadonlyPolicy::Ignore(FileAttributesWriteAccess::Denied)
            .validate_attributes(readonly),
        Err(DriverError::CannotDelete)
    );
    assert_eq!(
        super::DeleteReadonlyPolicy::Ignore(FileAttributesWriteAccess::Granted)
            .validate_attributes(readonly),
        Ok(())
    );
}
