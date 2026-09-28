//! Search expression and published continuation owned by one directory handle.

use crate::irp::PreparedDirectoryPattern;
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::{DriverShared, DriverSharedLease, DriverVec};
use ext4_core::{DirectoryScanCursor, WindowsName};

/// The first expression is captured once, even across restart and failed output copies.
#[derive(Debug)]
pub(crate) struct DirectorySearch {
    /// Last continuation published after a successful requestor copy.
    pub(crate) cursor: DirectoryScanCursor,
    /// None means the first request has not yet captured its expression.
    pattern: Option<DriverShared<DirectoryPattern>>,
    /// Distinguishes initial no-match/overflow semantics from subsequent queries.
    pub(crate) completed: bool,
}
impl DirectorySearch {
    /// Creates a handle that has neither captured a pattern nor consumed an entry.
    pub(crate) const fn new() -> Self {
        Self {
            cursor: DirectoryScanCursor::start(),
            pattern: None,
            completed: false,
        }
    }
    /// Publishes one request's continuation only after its output copy succeeds.
    /// The exclusive handle lane retains this search through the entire transition.
    /// # Errors
    /// A failed or cancelled copy leaves the previous publication unchanged.
    pub(crate) fn publish_after_copy(
        &mut self,
        cursor: DirectoryScanCursor,
        copy: impl FnOnce() -> DriverResult<()>,
    ) -> DriverResult<()> {
        copy()?;
        self.cursor = cursor;
        self.completed = true;
        Ok(())
    }

    /// Leases the original expression without parsing later caller input.
    /// # Errors
    /// Returns reference-budget exhaustion without changing the search.
    pub(crate) fn expression(&self) -> DriverResult<Option<DriverSharedLease<DirectoryPattern>>> {
        self.pattern
            .as_ref()
            .map(DriverShared::try_acquire)
            .transpose()
    }

    /// Only the first request selects an expression. The handle lane excludes competing queries.
    /// # Errors
    /// Returns allocation or reference-budget exhaustion.
    pub(crate) fn capture_pattern(
        &mut self,
        input: DirectoryPattern,
    ) -> DriverResult<DriverSharedLease<DirectoryPattern>> {
        if self.pattern.is_none() {
            self.pattern = Some(DriverShared::try_new(input)?);
        }
        self.pattern
            .as_ref()
            .ok_or(DriverError::InternalInvariantViolation)?
            .try_acquire()
    }
}

/// Caller-supplied directory filename pattern.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DirectoryPattern {
    /// Enumerate every Windows-representable ext4 entry.
    All,
    /// Return the entry with this exact Windows name.
    Exact(WindowsName),
    /// Return entries matched by a caller-supplied wildcard expression.
    Wildcard(DirectoryWildcardPattern),
}

impl DirectoryPattern {
    /// Decodes the captured QueryDirectory filename pattern.
    /// # Errors
    ///
    /// Returns an error when the pattern UNICODE_STRING is malformed, contains unsupported
    /// wildcards, or is not a valid Windows name.
    pub(crate) fn from_prepared(pattern: &PreparedDirectoryPattern) -> DriverResult<Self> {
        let PreparedDirectoryPattern::Name(units) = pattern else {
            return Ok(Self::All);
        };
        let units = units.as_slice();
        if is_all_directory_pattern(units) {
            return Ok(Self::All);
        }
        if units
            .iter()
            .any(|unit| matches!(*unit, UTF16_ASTERISK | UTF16_QUESTION_MARK))
        {
            return DirectoryWildcardPattern::from_utf16(units).map(Self::Wildcard);
        }
        WindowsName::from_utf16(units)
            .map(Self::Exact)
            .map_err(DriverError::from)
    }

    /// Returns true when the projected Windows name matches this pattern.
    pub(crate) fn matches(&self, name: &WindowsName) -> bool {
        match self {
            Self::All => true,
            Self::Exact(requested) => name.equals(requested),
            Self::Wildcard(pattern) => pattern.matches(name),
        }
    }
}

/// Caller-supplied wildcard pattern for Windows-visible long names.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DirectoryWildcardPattern {
    /// Parsed pattern tokens.
    tokens: DriverVec<DirectoryWildcardToken>,
}

impl DirectoryWildcardPattern {
    /// Decodes a wildcard pattern for directory enumeration.
    /// # Errors
    ///
    /// Returns an error when the pattern contains a non-wildcard character outside the Windows name
    /// component domain or malformed UTF-16.
    fn from_utf16(units: &[u16]) -> DriverResult<Self> {
        validate_directory_pattern_units(units)?;
        let mut tokens = DriverVec::new();
        for unit in units {
            let token = match *unit {
                UTF16_ASTERISK => DirectoryWildcardToken::AnySequence,
                UTF16_QUESTION_MARK => DirectoryWildcardToken::AnyOne,
                unit => DirectoryWildcardToken::Literal(unit),
            };
            tokens
                .try_push_owned(token)
                .map_err(|error| error.into_parts().0)?;
        }
        Ok(Self { tokens })
    }

    /// Returns true when this pattern matches a Windows-visible long name.
    fn matches(&self, name: &WindowsName) -> bool {
        wildcard_tokens_match(self.tokens.as_slice(), name.utf16())
    }
}

/// One token in a directory wildcard expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryWildcardToken {
    /// Exact UTF-16 code unit match.
    Literal(u16),
    /// Match exactly one UTF-16 code unit.
    AnyOne,
    /// Match zero or more UTF-16 code units.
    AnySequence,
}

/// Validates wildcard pattern units while keeping wildcard syntax out of `WindowsName`.
/// # Errors
///
/// Returns an error when a non-wildcard unit is not valid inside a Windows component or the pattern
/// is malformed UTF-16.
fn validate_directory_pattern_units(units: &[u16]) -> DriverResult<()> {
    if units.iter().any(|unit| {
        matches!(
            *unit,
            0x0000 | 0x0022 | 0x002F | 0x003A | 0x003C | 0x003E | 0x005C | 0x007C
        )
    }) {
        return Err(DriverError::from(ext4_core::Error::InvalidName));
    }
    if core::char::decode_utf16(units.iter().copied()).any(|item| item.is_err()) {
        return Err(DriverError::from(ext4_core::Error::InvalidName));
    }
    Ok(())
}

/// Matches `*` and `?` wildcard tokens against UTF-16 name units.
fn wildcard_tokens_match(pattern: &[DirectoryWildcardToken], name: &[u16]) -> bool {
    let mut pattern_index = 0_usize;
    let mut name_index = 0_usize;
    let mut sequence_restart = None;

    while name_index < name.len() {
        if let Some(token) = pattern.get(pattern_index) {
            match token {
                DirectoryWildcardToken::Literal(unit)
                    if name.get(name_index).copied() == Some(*unit) =>
                {
                    let Some(next_pattern) = pattern_index.checked_add(1) else {
                        return false;
                    };
                    let Some(next_name) = name_index.checked_add(1) else {
                        return false;
                    };
                    pattern_index = next_pattern;
                    name_index = next_name;
                    continue;
                }
                DirectoryWildcardToken::AnyOne => {
                    let Some(next_pattern) = pattern_index.checked_add(1) else {
                        return false;
                    };
                    let Some(next_name) = name_index.checked_add(1) else {
                        return false;
                    };
                    pattern_index = next_pattern;
                    name_index = next_name;
                    continue;
                }
                DirectoryWildcardToken::AnySequence => {
                    let Some(next_pattern) = pattern_index.checked_add(1) else {
                        return false;
                    };
                    sequence_restart = Some((pattern_index, name_index));
                    pattern_index = next_pattern;
                    continue;
                }
                DirectoryWildcardToken::Literal(_) => {}
            }
        }

        let Some((sequence_index, restart_name)) = sequence_restart else {
            return false;
        };
        let Some(next_restart_name) = restart_name.checked_add(1) else {
            return false;
        };
        let Some(next_pattern) = sequence_index.checked_add(1) else {
            return false;
        };
        sequence_restart = Some((sequence_index, next_restart_name));
        pattern_index = next_pattern;
        name_index = next_restart_name;
    }

    while matches!(
        pattern.get(pattern_index),
        Some(DirectoryWildcardToken::AnySequence)
    ) {
        let Some(next_pattern) = pattern_index.checked_add(1) else {
            return false;
        };
        pattern_index = next_pattern;
    }

    pattern_index == pattern.len()
}

/// UTF-16 `*`.
const UTF16_ASTERISK: u16 = 0x002A;
/// UTF-16 `.`.
const UTF16_DOT: u16 = 0x002E;
/// UTF-16 `?`.
const UTF16_QUESTION_MARK: u16 = 0x003F;

/// Returns true for the all-entries patterns accepted without wildcard matching.
fn is_all_directory_pattern(units: &[u16]) -> bool {
    units.is_empty()
        || units == [UTF16_ASTERISK]
        || units == [UTF16_ASTERISK, UTF16_DOT, UTF16_ASTERISK]
}

#[cfg(test)]
#[path = "tests/directory_search.rs"]
mod tests;
