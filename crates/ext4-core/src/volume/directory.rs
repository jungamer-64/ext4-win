//! Directory lookup and bounded enumeration domain types.

use crate::disk_format::name::Ext4Name;
use crate::error::{Error, Result};
use crate::memory;

use super::node::{DirectoryChild, DirectoryEntry, DirectoryNodeId};

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
    /// Reconstruct a cursor by scanning to a caller-supplied ordinal.
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
    /// Parent whose scan established this namespace relation.
    parent: DirectoryNodeId,
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
        parent: DirectoryNodeId,
        entry: DirectoryEntry,
        ordinal: u64,
        next_cursor: DirectoryScanCursor,
    ) -> Self {
        Self {
            parent,
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

    /// Consumes this record into the child relation established by its directory scan.
    #[must_use]
    pub fn into_child(self) -> DirectoryChild {
        self.entry.into_child(self.parent)
    }

    /// Consumes this scan record into its validated entry.
    #[must_use]
    pub fn into_entry(self) -> DirectoryEntry {
        self.entry
    }
}

/// Owned query preparation keeps derived keys local while traversal borrows only their narrow capability.
#[derive(Debug)]
pub(super) enum PreparedDirectoryLookup<'name> {
    /// Unencrypted caller component, borrowed without allocating on the ordinary lookup path.
    Plain(&'name Ext4Name),
    /// Encrypted spelling for a bytewise directory.
    Encrypted(Ext4Name),
    /// Complete keyless identity and route.
    NoKey(crate::protection::fscrypt::FscryptNoKeyName),
    /// A normalized plaintext key paired with candidate decryption and keyed routing.
    EncryptedCasefold {
        /// Authoritative comparison key derived from the caller's complete original name.
        comparison: crate::disk_format::name::NameKey<'name>,
        /// Operation-owned candidate decryption capability.
        key: crate::protection::fscrypt::FscryptFilenamesKey,
        /// Keyed plaintext route, never a hash of ciphertext bytes.
        hash: crate::disk_format::directory_hash::DirectoryHash,
    },
}
impl<'name> PreparedDirectoryLookup<'name> {
    /// Prepares plaintext equality and its route from one selected directory key.
    /// # Errors
    /// Returns encoding, allocation, key derivation or encryption failure.
    pub(super) fn encrypted(
        name: &'name Ext4Name,
        names: crate::disk_format::name::NameSemantics,
        key: crate::protection::fscrypt::FscryptInodeKey<'_>,
        crypto: &mut dyn crate::CryptographicOperation,
    ) -> Result<Self> {
        if names == crate::disk_format::name::NameSemantics::Bytewise {
            return Ok(Self::Encrypted(key.encrypt_name(name, crypto)?));
        }
        let comparison = names.key(name.bytes())?;
        let hash = key.directory_hash_key(crypto)?.hash(comparison.bytes());
        Ok(Self::EncryptedCasefold {
            comparison,
            key: key.filenames_key(crypto)?,
            hash,
        })
    }

    /// Borrows one immutable prepared query for bounded traversal.
    pub(super) fn query(&self) -> DirectoryLookup<'_> {
        match self {
            Self::Plain(name) => DirectoryLookup::Name(name),
            Self::Encrypted(name) => DirectoryLookup::Name(name),
            Self::NoKey(name) => DirectoryLookup::NoKey(name),
            Self::EncryptedCasefold {
                comparison,
                key,
                hash,
            } => DirectoryLookup::EncryptedCasefold {
                comparison: comparison.bytes(),
                key,
                hash: *hash,
            },
        }
    }
}

/// Lookup semantics independent of traversal through committed or staged directory blocks.
#[derive(Clone, Copy)]
pub(super) enum DirectoryLookup<'name> {
    /// Component interpreted using the directory's comparison semantics.
    Name(&'name Ext4Name),
    /// Exact stored identity retains any keyed route paired with its ciphertext.
    Stored(&'name crate::disk_format::dir::DirectoryEntry),
    /// Normalized plaintext equality after filtering and decrypting the keyed-hash candidates.
    EncryptedCasefold {
        /// Complete plaintext comparison bytes.
        comparison: &'name [u8],
        /// Operation-local filename decryption capability.
        key: &'name crate::protection::fscrypt::FscryptFilenamesKey,
        /// Keyed route derived from the same plaintext comparison bytes.
        hash: crate::disk_format::directory_hash::DirectoryHash,
    },
    /// Keyless ciphertext identity, including long-name digest queries.
    NoKey(&'name crate::protection::fscrypt::FscryptNoKeyName),
}
impl DirectoryLookup<'_> {
    /// Returns exact bytes when present in the query.
    pub(super) fn exact(&self) -> Option<&Ext4Name> {
        match self {
            Self::Name(name) => Some(name),
            Self::Stored(entry) => Some(entry.name()),
            Self::NoKey(name) => name.direct(),
            Self::EncryptedCasefold { .. } => None,
        }
    }
    /// Routes a query using the directory's authoritative hash profile.
    /// # Errors
    /// Returns invalid encoding or allocation failure before index selection.
    pub(super) fn major(
        &self,
        scheme: crate::disk_format::dir::DirectoryIndexHash,
        names: crate::disk_format::name::NameSemantics,
    ) -> Result<u32> {
        match *self {
            Self::Stored(entry) => Ok(scheme.entry_hash(entry, names)?.major),
            Self::Name(name) => Ok(names.hash(name, scheme.computed()?)?.major),
            Self::NoKey(name) => match (scheme, name.direct()) {
                (
                    crate::disk_format::dir::DirectoryIndexHash::Computed(algorithm),
                    Some(ciphertext),
                ) => Ok(algorithm.hash(ciphertext.bytes()).major),
                _ => Ok(name.hash().major),
            },
            Self::EncryptedCasefold { hash, .. } => {
                if scheme != crate::disk_format::dir::DirectoryIndexHash::StoredKeyed {
                    return Err(Error::UnsupportedDirectoryHash);
                }
                Ok(hash.major)
            }
        }
    }
    /// Selects a verified candidate from one leaf.
    /// # Errors
    /// Returns hash-provider failures while checking a digest query.
    pub(super) fn find(
        &self,
        entries: alloc::vec::Vec<crate::disk_format::dir::DirectoryEntry>,
        crypto: &mut dyn crate::CryptographicOperation,
        names: crate::disk_format::name::NameSemantics,
    ) -> Result<Option<crate::disk_format::dir::DirectoryEntry>> {
        match self {
            Self::Stored(stored) => {
                return Ok(entries.into_iter().find(|entry| {
                    entry.name() == stored.name() && entry.stored_hash() == stored.stored_hash()
                }));
            }
            Self::Name(name) => {
                let key = names.key(name.bytes())?;
                for entry in entries {
                    if names.key(entry.name().bytes())?.bytes() == key.bytes() {
                        return Ok(Some(entry));
                    }
                }
            }
            Self::EncryptedCasefold {
                comparison,
                key,
                hash,
            } => {
                for entry in entries {
                    if matches!(entry.name().bytes(), b"." | b"..") {
                        continue;
                    }
                    let stored = entry.stored_hash().ok_or(Error::InvalidDirectoryEntry)?;
                    if stored != *hash {
                        continue;
                    }
                    let plaintext =
                        Ext4Name::new(&key.decrypt_filename(entry.name().bytes(), crypto)?)?;
                    if names.key(plaintext.bytes())?.bytes() == *comparison {
                        return Ok(Some(entry));
                    }
                }
            }
            Self::NoKey(name) => {
                for entry in entries {
                    if entry.stored_hash().is_none_or(|hash| hash == name.hash())
                        && name.matches(entry.name().bytes(), crypto)?
                    {
                        return Ok(Some(entry));
                    }
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns malformed independent display framing or query routing failure.
    /// # Panics
    /// Fails if an unkeyed route trusts a stale hint when the complete ciphertext is available.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "literal ciphertext and independently calculated format hash observe routing authority"
    )]
    fn complete_keyless_identity_uses_the_current_unkeyed_profile() -> Result<()> {
        use crate::disk_format::{
            dir::DirectoryIndexHash,
            directory_hash::DirectoryHashScheme,
            name::NameSemantics,
            superblock::{DirectoryHashSeed, DirectoryHashSignedness, DirectoryHashVersion},
        };
        let name = crate::protection::fscrypt::FscryptNoKeyName::from_display(
            b"_fscrypt_AAAAAAAAAAAwMTIzNDU2Nzg5QUJDREVG",
        )?
        .ok_or(Error::InvalidName)?;
        assert_eq!(name.hash().major, 0);
        let scheme = DirectoryHashScheme::from_metadata(
            DirectoryHashSeed::from_words([0; 4]),
            DirectoryHashVersion::Legacy,
            DirectoryHashSignedness::Signed,
        );
        assert_eq!(
            DirectoryLookup::NoKey(&name).major(
                DirectoryIndexHash::Computed(scheme),
                NameSemantics::Bytewise
            )?,
            0xf4ca76fc
        );
        Ok(())
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
