use super::*;

/// # Panics
/// Fails if a literal or wildcard search ignores the open-time case policy or Windows Unicode folding.
#[test]
fn directory_search_uses_opened_case_policy_for_literal_and_wildcard_names() {
    let result = (|| -> DriverResult<()> {
        for (expression, name) in [
            ("*.TXT", "report.txt"),
            ("REPORT.TXT", "report.txt"),
            ("ä*.txt", "Ärger.TXT"),
        ] {
            let units = expression.encode_utf16().collect::<alloc::vec::Vec<_>>();
            let name =
                WindowsName::from_utf16(&name.encode_utf16().collect::<alloc::vec::Vec<_>>())?;
            let insensitive = DirectoryNameExpression::from_utf16(
                &units,
                crate::kernel::name_expression::NameCase::Insensitive,
            )?;
            let sensitive = DirectoryNameExpression::from_utf16(
                &units,
                crate::kernel::name_expression::NameCase::Exact,
            )?;
            assert_eq!(insensitive.matches(&name), Ok(true));
            assert_eq!(sensitive.matches(&name), Ok(false));
        }
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
///
/// Panics when the Windows wildcard matcher loses long-name matching semantics.
#[test]
fn directory_wildcard_pattern_matches_long_windows_names() {
    let pattern = super::DirectoryNameExpression::from_utf16(
        &[
            u16::from(b'f'),
            super::UTF16_ASTERISK,
            u16::from(b'.'),
            u16::from(b't'),
            u16::from(b'?'),
            u16::from(b't'),
        ],
        crate::kernel::name_expression::NameCase::Exact,
    );
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

    assert_eq!(pattern.matches(&matched), Ok(true));
    assert_eq!(pattern.matches(&rejected), Ok(false));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn directory_wildcard_pattern_rejects_non_name_units() {
    assert_eq!(
        super::DirectoryNameExpression::from_utf16(
            &[u16::from(b'a'), 0x005C, super::UTF16_ASTERISK,],
            crate::kernel::name_expression::NameCase::Exact
        ),
        Err(DriverError::from(ext4_core::Error::InvalidName))
    );
    assert_eq!(
        super::DirectoryNameExpression::from_utf16(
            &[0xD800, super::UTF16_ASTERISK],
            crate::kernel::name_expression::NameCase::Exact
        ),
        Err(DriverError::from(ext4_core::Error::InvalidName))
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
    let pattern = super::DirectoryPattern::from_prepared(
        &crate::irp::PreparedDirectoryPattern::Name(units),
        crate::kernel::name_expression::NameCase::Exact,
    );
    assert!(matches!(
        pattern,
        Ok(super::DirectoryPattern::Expression(_))
    ));
}

/// # Panics
/// Fails if a later expression or restart replaces the first captured search.
#[test]
fn initial_search_expression_survives_restart_and_later_requests() {
    let result = (|| -> DriverResult<()> {
        let search = DirectorySearch::new();
        let selected = WindowsName::from_utf16(&[u16::from(b'a')])?;
        let rejected = WindowsName::from_utf16(&[u16::from(b'b')])?;
        let original = search.capture_pattern(DirectoryPattern::Expression(
            DirectoryNameExpression::from_utf16(
                selected.utf16(),
                crate::kernel::name_expression::NameCase::Exact,
            )?,
        ))?;
        let mut cursor = search.cursor();
        cursor.seek_ordinal(37);
        search.publish_after_copy(cursor, || Ok(()))?;
        assert_eq!(search.cursor().ordinal(), 37);
        let later = search.capture_pattern(DirectoryPattern::All)?;
        let mut cursor = search.cursor();
        cursor.restart();
        search.publish_after_copy(cursor, || Ok(()))?;
        assert_eq!(search.cursor(), DirectoryScanCursor::start());
        assert_eq!(original.get().matches(&rejected), Ok(false));
        assert_eq!(later.get().matches(&rejected), Ok(false));
        assert!(
            !search
                .expression()?
                .ok_or(DriverError::InternalInvariantViolation)?
                .get()
                .matches(&rejected)?
        );
        assert!(search.completed());
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if unsuccessful output publication consumes records or marks an initial query complete.
#[test]
fn directory_publication_requires_successful_copy() {
    let search = DirectorySearch::new();
    let mut next = DirectoryScanCursor::start();
    next.seek_ordinal(128);
    for failure in [
        DriverError::BufferOverflow,
        DriverError::from(ext4_core::Error::OperationCancelled),
    ] {
        assert_eq!(
            search.publish_after_copy(next, || Err(failure)),
            Err(failure)
        );
        assert_eq!(search.cursor(), DirectoryScanCursor::start());
        assert!(!search.completed());
    }
    assert_eq!(search.publish_after_copy(next, || Ok(())), Ok(()));
    assert_eq!(search.cursor(), next);
    assert!(search.completed());
}

/// # Panics
/// Fails if DOS wildcard expressions are rejected or lose their Windows meaning.
#[test]
fn directory_dos_expressions_match_native_vectors() {
    let result = (|| -> DriverResult<()> {
        for (expression, name, expected) in [
            ("a>.txt", "a.txt", true),
            ("a>.txt", "ab.txt", true),
            ("a>.txt", "abc.txt", false),
            ("a\"", "a", true),
            ("a\"", "a.", true),
            ("<.txt", "a.b.txt", true),
            ("<.txt", "a.b.dat", false),
        ] {
            let mut units = DriverVec::new();
            for unit in expression.encode_utf16() {
                units
                    .try_push_owned(unit)
                    .map_err(|failure| failure.into_parts().0)?;
            }
            let pattern = DirectoryPattern::from_prepared(
                &PreparedDirectoryPattern::Name(units),
                crate::kernel::name_expression::NameCase::Exact,
            )?;
            let name = name.encode_utf16().collect::<alloc::vec::Vec<_>>();
            assert_eq!(
                pattern.matches(&WindowsName::from_utf16(&name)?),
                Ok(expected)
            );
        }
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}
