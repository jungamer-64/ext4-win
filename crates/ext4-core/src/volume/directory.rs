//! Bounded directory enumeration domain types.

use alloc::vec::Vec;
use core::num::NonZeroU8;

use crate::error::{Error, Result};
use crate::memory;
use crate::platform::name::Ext4Name;

use super::node::DirectoryEntry;

/// Maximum number of raw live dirents returned by one core scan operation.
pub const MAX_DIRECTORY_SCAN_ENTRIES: usize = 128;
/// Raw-entry bound in the cursor limit's compact representation.
const MAX_DIRECTORY_SCAN_ENTRIES_U8: u8 = 128;

/// Validated raw-entry budget for one bounded directory scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryScanLimit(NonZeroU8);

impl DirectoryScanLimit {
    /// Largest supported raw-entry budget.
    pub const MAX: Self = Self(match NonZeroU8::new(MAX_DIRECTORY_SCAN_ENTRIES_U8) {
        Some(value) => value,
        None => NonZeroU8::MIN,
    });

    /// Validates a caller-selected raw-entry budget.
    /// # Errors
    ///
    /// Returns an error when `entries` is zero or exceeds the core bound.
    pub fn new(entries: usize) -> Result<Self> {
        if entries == 0 || entries > MAX_DIRECTORY_SCAN_ENTRIES {
            return Err(Error::InvalidDirectoryScanLimit);
        }
        Ok(Self(
            NonZeroU8::new(u8::try_from(entries).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::InvalidDirectoryScanLimit)?,
        ))
    }

    /// Returns the validated raw-entry budget.
    pub fn entries(self) -> usize {
        usize::from(self.0.get())
    }
}

/// Inline HTree name retained by a cursor without allocating in driver handle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryCursorName {
    /// Valid raw-name prefix.
    bytes: [u8; 255],
    /// Length of the valid prefix.
    len: u8,
}

impl DirectoryCursorName {
    /// Empty sentinel stored for cursor positions without an HTree name key.
    const EMPTY: Self = Self {
        bytes: [0_u8; 255],
        len: 0,
    };

    /// Copies one validated ext4 name into fixed cursor storage.
    /// # Errors
    ///
    /// Returns an error if the validated name length cannot be represented by the inline cursor.
    pub(crate) fn from_name(name: &Ext4Name) -> Result<Self> {
        let mut bytes = [0_u8; 255];
        memory::copy_exact(
            bytes
                .get_mut(..name.bytes().len())
                .ok_or(Error::ArithmeticOverflow)?,
            name.bytes(),
        )?;
        Ok(Self {
            bytes,
            len: u8::try_from(name.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
        })
    }

    /// Returns the valid raw-name prefix.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// Storage-specific continuation position hidden behind the scan-cursor contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryScanPosition {
    /// No raw entry has been consumed.
    Start,
    /// The `.` entry has been consumed.
    AfterDot,
    /// The `..` entry has been consumed.
    AfterDotDot,
    /// Resume a linear directory at a physical block/record coordinate.
    Linear {
        /// Directory logical block containing the next record.
        logical: u32,
        /// Byte offset of the next record inside `logical`.
        offset: u32,
    },
    /// Resume an indexed directory strictly after one stable semantic key.
    HTree {
        /// Primary hash of the last consumed key.
        major: u32,
        /// Secondary hash of the last consumed key.
        minor: u32,
    },
    /// Reconstruct a cursor by scanning to a Windows-supplied ordinal.
    Ordinal(u64),
    /// The prior scan observed end of directory.
    End,
}

/// Opaque live-directory continuation cursor.
///
/// The cursor is not a snapshot. Its storage coordinate/key is interpreted against the committed
/// directory image observed by each scan call. `ordinal` is the caller-visible sequence number and
/// the fallback used for explicit ordinal seeks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryScanCursor {
    /// Storage-specific coordinate paired with `ordinal`.
    pub(crate) position: DirectoryScanPosition,
    /// Raw live-entry ordinal assigned to the next result.
    pub(crate) ordinal: u64,
    /// Raw name completing an HTree key; empty for every other position.
    pub(crate) htree_name: DirectoryCursorName,
}

impl DirectoryScanCursor {
    /// Creates a cursor before the first live entry.
    #[must_use]
    pub const fn start() -> Self {
        Self {
            position: DirectoryScanPosition::Start,
            ordinal: 0,
            htree_name: DirectoryCursorName::EMPTY,
        }
    }

    /// Resets this cursor before the first live entry.
    pub fn restart(&mut self) {
        *self = Self::start();
    }

    /// Requests a live scan beginning at the supplied raw-entry ordinal.
    pub fn seek_ordinal(&mut self, ordinal: u64) {
        self.position = DirectoryScanPosition::Ordinal(ordinal);
        self.ordinal = ordinal;
        self.htree_name = DirectoryCursorName::EMPTY;
    }

    /// Returns the ordinal assigned to the next raw live entry.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Constructs the continuation after consuming one non-HTree-key entry.
    /// # Errors
    ///
    /// Returns an error when incrementing the ordinal overflows.
    pub(crate) fn after_entry(position: DirectoryScanPosition, ordinal: u64) -> Result<Self> {
        Ok(Self {
            position,
            ordinal: ordinal.checked_add(1).ok_or(Error::ArithmeticOverflow)?,
            htree_name: DirectoryCursorName::EMPTY,
        })
    }

    /// Constructs the continuation after consuming one complete HTree key.
    /// # Errors
    ///
    /// Returns an error when copying the name or incrementing the ordinal cannot be represented.
    pub(crate) fn after_htree_entry(
        major: u32,
        minor: u32,
        name: &Ext4Name,
        ordinal: u64,
    ) -> Result<Self> {
        Ok(Self {
            position: DirectoryScanPosition::HTree { major, minor },
            ordinal: ordinal.checked_add(1).ok_or(Error::ArithmeticOverflow)?,
            htree_name: DirectoryCursorName::from_name(name)?,
        })
    }

    /// Constructs a cursor that has observed the end of the live directory.
    pub(crate) const fn end(ordinal: u64) -> Self {
        Self {
            position: DirectoryScanPosition::End,
            ordinal,
            htree_name: DirectoryCursorName::EMPTY,
        }
    }
}

impl Default for DirectoryScanCursor {
    fn default() -> Self {
        Self::start()
    }
}

/// One validated entry from a bounded scan, with the cursor that consumes it.
#[derive(Debug, Eq, PartialEq)]
pub struct ScannedDirectoryEntry {
    /// Validated caller-visible entry.
    entry: DirectoryEntry,
    /// Raw live-entry ordinal assigned to this result.
    ordinal: u64,
    /// Cursor that consumes exactly this result.
    next_cursor: DirectoryScanCursor,
}

impl ScannedDirectoryEntry {
    /// Joins one projected entry to its ordinal and consumption cursor.
    pub(crate) const fn new(
        entry: DirectoryEntry,
        ordinal: u64,
        next_cursor: DirectoryScanCursor,
    ) -> Self {
        Self {
            entry,
            ordinal,
            next_cursor,
        }
    }

    /// Returns the validated public directory entry.
    #[must_use]
    pub const fn entry(&self) -> &DirectoryEntry {
        &self.entry
    }

    /// Returns this raw entry's 64-bit enumeration ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Returns the cursor obtained by consuming this raw entry.
    #[must_use]
    pub const fn next_cursor(&self) -> &DirectoryScanCursor {
        &self.next_cursor
    }

    /// Consumes this scan record into its validated entry.
    #[must_use]
    pub fn into_entry(self) -> DirectoryEntry {
        self.entry
    }
}

/// One bounded live-directory scan result.
#[derive(Debug, Eq, PartialEq)]
pub struct DirectoryScanBatch {
    /// Bounded projected entries returned by this call.
    entries: Vec<ScannedDirectoryEntry>,
    /// Cursor after all entries in `entries`.
    continuation: DirectoryScanCursor,
    /// Whether this call observed the end of the live directory.
    exhausted: bool,
}

impl DirectoryScanBatch {
    /// Constructs one internally validated bounded scan result.
    pub(crate) const fn new(
        entries: Vec<ScannedDirectoryEntry>,
        continuation: DirectoryScanCursor,
        exhausted: bool,
    ) -> Self {
        Self {
            entries,
            continuation,
            exhausted,
        }
    }

    /// Returns the raw live entries produced by this bounded scan.
    #[must_use]
    pub fn entries(&self) -> &[ScannedDirectoryEntry] {
        &self.entries
    }

    /// Consumes the batch into its bounded scan records.
    #[must_use]
    pub fn into_entries(self) -> Vec<ScannedDirectoryEntry> {
        self.entries
    }

    /// Returns the cursor after every entry in this batch.
    #[must_use]
    pub const fn continuation(&self) -> &DirectoryScanCursor {
        &self.continuation
    }

    /// Returns whether this call observed end of directory.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    ///
    /// Panics when the raw-entry batch bound accepts zero or an oversized request.
    #[test]
    fn scan_limit_enforces_the_single_batch_raw_entry_budget() {
        assert_eq!(
            DirectoryScanLimit::new(0),
            Err(Error::InvalidDirectoryScanLimit)
        );
        assert_eq!(
            DirectoryScanLimit::new(MAX_DIRECTORY_SCAN_ENTRIES + 1),
            Err(Error::InvalidDirectoryScanLimit)
        );
        assert_eq!(
            DirectoryScanLimit::new(MAX_DIRECTORY_SCAN_ENTRIES),
            Ok(DirectoryScanLimit::MAX)
        );
    }

    /// # Panics
    ///
    /// Panics when explicit ordinal seeks truncate the live 64-bit cursor domain.
    #[test]
    fn scan_cursor_preserves_ordinals_beyond_windows_file_index() {
        let mut cursor = DirectoryScanCursor::start();
        let ordinal = u64::from(u32::MAX) + 1;
        cursor.seek_ordinal(ordinal);
        assert_eq!(cursor.ordinal(), ordinal);
        assert_eq!(cursor.position, DirectoryScanPosition::Ordinal(ordinal));
        cursor.restart();
        assert_eq!(cursor, DirectoryScanCursor::start());
    }
}
