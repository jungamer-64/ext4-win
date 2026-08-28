use super::*;

/// # Panics
///
/// Panics when the Windows wildcard matcher loses long-name matching semantics.
#[test]
fn directory_wildcard_pattern_matches_long_windows_names() {
    let pattern = super::DirectoryWildcardPattern::from_utf16(&[
        u16::from(b'f'),
        super::UTF16_ASTERISK,
        u16::from(b'.'),
        u16::from(b't'),
        u16::from(b'?'),
        u16::from(b't'),
    ]);
    assert!(pattern.is_ok());
    let Ok(pattern) = pattern else {
        return;
    };
    let matched = WindowsName::from_utf16(&[
        u16::from(b'f'),
        u16::from(b'i'),
        u16::from(b'l'),
        u16::from(b'e'),
        u16::from(b'.'),
        u16::from(b't'),
        u16::from(b'x'),
        u16::from(b't'),
    ]);
    assert!(matched.is_ok());
    let Ok(matched) = matched else {
        return;
    };
    let rejected = WindowsName::from_utf16(&[
        u16::from(b'f'),
        u16::from(b'i'),
        u16::from(b'l'),
        u16::from(b'e'),
        u16::from(b'.'),
        u16::from(b't'),
        u16::from(b'x'),
    ]);
    assert!(rejected.is_ok());
    let Ok(rejected) = rejected else {
        return;
    };

    assert!(pattern.matches(&matched));
    assert!(!pattern.matches(&rejected));
}

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
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn directory_wildcard_pattern_rejects_non_name_units() {
    assert_eq!(
        super::DirectoryWildcardPattern::from_utf16(&[
            u16::from(b'a'),
            super::UTF16_BACKSLASH,
            super::UTF16_ASTERISK,
        ]),
        Err(DriverError::from(ext4_core::Error::InvalidName))
    );
    assert_eq!(
        super::DirectoryWildcardPattern::from_utf16(&[0xD800, super::UTF16_ASTERISK]),
        Err(DriverError::from(ext4_core::Error::InvalidName))
    );
}

/// # Panics
///
/// Panics when exhausted enumeration and explicit-search patterns expose the same status.
#[test]
fn directory_pattern_exhaustion_preserves_search_error_semantics() {
    assert_eq!(
        super::DirectoryPattern::All.exhausted_error(),
        DriverError::NoMoreFiles
    );

    let exact = WindowsName::from_utf16(&[u16::from(b'a')]);
    assert!(exact.is_ok());
    let Ok(exact) = exact else {
        return;
    };
    assert_eq!(
        super::DirectoryPattern::Exact(exact).exhausted_error(),
        DriverError::NoSuchFile
    );

    let wildcard = super::DirectoryWildcardPattern::from_utf16(&[super::UTF16_ASTERISK]);
    assert!(wildcard.is_ok());
    let Ok(wildcard) = wildcard else {
        return;
    };
    assert_eq!(
        super::DirectoryPattern::Wildcard(wildcard).exhausted_error(),
        DriverError::NoSuchFile
    );
}

/// # Panics
///
/// Panics when a queue-owned UTF-16 pattern is not converted into the same wildcard domain
/// used by the directory emitter.
#[test]
fn prepared_directory_pattern_uses_owned_utf16_units() {
    let mut units = crate::memory::DriverVec::new();
    assert!(
        units
            .try_extend_from_copy_slice(&[
                u16::from(b'f'),
                super::UTF16_ASTERISK,
                u16::from(b'.'),
                u16::from(b't'),
                u16::from(b'x'),
                u16::from(b't'),
            ])
            .is_ok()
    );
    let pattern =
        super::DirectoryPattern::from_prepared(&crate::irp::PreparedDirectoryPattern::Name(units));
    assert!(matches!(pattern, Ok(super::DirectoryPattern::Wildcard(_))));
}
