//! Search expression and published continuation owned by one directory handle.

use crate::irp::PreparedDirectoryPattern;
use crate::kernel::name_expression::NameCase;
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::{DriverShared, DriverSharedLease, DriverVec};
use crate::namespace::WindowsName;
use core::cell::{Cell, OnceCell};
use ext4_core::DirectoryScanCursor;

/// The first expression is captured once, even across restart and failed output copies.
#[derive(Debug)]
pub(crate) struct DirectorySearch {
    /// Last continuation published after a successful requestor copy.
    cursor: Cell<DirectoryScanCursor>,
    /// Unset until the first request captures its expression.
    pattern: OnceCell<DriverShared<DirectoryPattern>>,
    /// Distinguishes initial no-match/overflow semantics from subsequent queries.
    completed: Cell<bool>,
}
impl DirectorySearch {
    /// Creates a handle that has neither captured a pattern nor consumed an entry.
    pub(crate) const fn new() -> Self {
        Self {
            cursor: Cell::new(DirectoryScanCursor::start()),
            pattern: OnceCell::new(),
            completed: Cell::new(false),
        }
    }
    /// Publishes one request's continuation only after its output copy succeeds.
    /// The exclusive handle lane retains this search through the entire transition.
    /// # Errors
    /// A failed or cancelled copy leaves the previous publication unchanged.
    pub(crate) fn publish_after_copy(
        &self,
        cursor: DirectoryScanCursor,
        copy: impl FnOnce() -> DriverResult<()>,
    ) -> DriverResult<()> {
        copy()?;
        self.cursor.set(cursor);
        self.completed.set(true);
        Ok(())
    }

    /// Returns the continuation last published by a completed output copy.
    pub(crate) fn cursor(&self) -> DirectoryScanCursor {
        self.cursor.get()
    }

    /// Returns whether a query has published its result for this handle.
    pub(crate) fn completed(&self) -> bool {
        self.completed.get()
    }

    /// Leases the original expression without parsing later caller input.
    /// # Errors
    /// Returns reference-budget exhaustion without changing the search.
    pub(crate) fn expression(&self) -> DriverResult<Option<DriverSharedLease<DirectoryPattern>>> {
        self.pattern
            .get()
            .map(DriverShared::try_acquire)
            .transpose()
    }

    /// Only the first request selects an expression. The handle lane excludes competing queries.
    /// # Errors
    /// Returns allocation or reference-budget exhaustion.
    pub(crate) fn capture_pattern(
        &self,
        input: DirectoryPattern,
    ) -> DriverResult<DriverSharedLease<DirectoryPattern>> {
        if self.pattern.get().is_none() {
            self.pattern
                .set(DriverShared::try_new(input)?)
                .map_err(|_| DriverError::InternalInvariantViolation)?;
        }
        self.pattern
            .get()
            .ok_or(DriverError::InternalInvariantViolation)?
            .try_acquire()
    }
}

/// Filename expression captured once together with the directory handle's comparison policy.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DirectoryPattern {
    /// Every Windows-representable entry.
    All,
    /// A complete Windows name expression, with or without wildcard characters.
    Expression(DirectoryNameExpression),
}

impl DirectoryPattern {
    /// Captures the original expression and open-time case policy before enumeration.
    /// # Errors
    /// Returns malformed UTF-16/name, counted-string overflow, or allocation failure.
    pub(crate) fn from_prepared(
        pattern: &PreparedDirectoryPattern,
        matching: NameCase,
    ) -> DriverResult<Self> {
        let PreparedDirectoryPattern::Name(units) = pattern else {
            return Ok(Self::All);
        };
        if is_all_directory_pattern(units.as_slice()) {
            return Ok(Self::All);
        }
        DirectoryNameExpression::from_utf16(units.as_slice(), matching).map(Self::Expression)
    }

    /// Matches through the same Windows expression contract for literal and wildcard names.
    /// # Errors
    /// Returns native evaluation failure before cursor publication.
    pub(crate) fn matches(&self, name: &WindowsName) -> DriverResult<bool> {
        match self {
            Self::All => Ok(true),
            Self::Expression(expression) => expression.matches(name),
        }
    }
}

/// Owned expression normalized once for the Windows comparison table selected at open.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DirectoryNameExpression {
    /// UTF-16 expression; insensitive expressions are uppercase as required by FsRtl.
    units: DriverVec<u16>,
    /// Immutable comparison mode from the directory FILE_OBJECT.
    matching: NameCase,
}

impl DirectoryNameExpression {
    /// Captures a well-formed expression while preserving DOS wildcard syntax.
    /// # Errors
    /// Returns invalid-name for separators, NUL or malformed UTF-16, or preparation failure.
    fn from_utf16(units: &[u16], matching: NameCase) -> DriverResult<Self> {
        if units
            .iter()
            .any(|unit| matches!(*unit, 0 | 0x002F | 0x003A | 0x005C | 0x007C))
            || core::char::decode_utf16(units.iter().copied()).any(|item| item.is_err())
        {
            return Err(DriverError::from(ext4_core::Error::InvalidName));
        }
        let mut units = DriverVec::try_copied_from_slice(units)?;
        if matching == NameCase::Insensitive {
            crate::kernel::name_expression::uppercase(units.as_mut_slice())?;
        }
        Ok(Self { units, matching })
    }

    /// Evaluates a normalized Windows expression at the native boundary.
    /// # Errors
    /// Returns native expression evaluation failure.
    fn matches(&self, name: &WindowsName) -> DriverResult<bool> {
        crate::kernel::name_expression::matches(
            self.units.as_slice(),
            name.utf16(),
            self.matching == NameCase::Insensitive,
        )
    }
}
/// UTF-16 `*`.
const UTF16_ASTERISK: u16 = 0x002A;
/// UTF-16 `.`.
const UTF16_DOT: u16 = 0x002E;

/// Returns true for the all-entries patterns accepted without wildcard matching.
fn is_all_directory_pattern(units: &[u16]) -> bool {
    units.is_empty()
        || units == [UTF16_ASTERISK]
        || units == [UTF16_ASTERISK, UTF16_DOT, UTF16_ASTERISK]
}

#[cfg(test)]
#[path = "tests/directory_search.rs"]
mod tests;
