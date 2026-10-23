//! Validated ext4 directory-entry names.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::memory;

/// Raw ext4 directory entry name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ext4Name {
    /// Validated ext4 component bytes.
    bytes: Vec<u8>,
}

impl Ext4Name {
    /// Validates and stores an ext4 name.
    ///
    /// # Errors
    /// Returns an error when the name is empty, too long, or contains bytes
    /// forbidden by ext4 path components.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 255 {
            return Err(Error::InvalidName);
        }
        if bytes.iter().any(|byte| *byte == 0 || *byte == b'/') {
            return Err(Error::InvalidName);
        }
        Ok(Self {
            bytes: memory::copied_slice(bytes)?,
        })
    }

    /// Stores a raw on-disk dirent name.
    ///
    /// Encrypted ext4 directories can contain ciphertext bytes that are not
    /// valid plaintext path components. External callers must continue to use
    /// [`Self::new`] for user-provided names.
    /// # Errors
    ///
    /// Returns an error when the on-disk name is empty or exceeds the ext4 component length limit.
    pub(crate) fn from_disk(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 255 {
            return Err(Error::InvalidName);
        }
        Ok(Self {
            bytes: memory::copied_slice(bytes)?,
        })
    }

    /// Returns the raw ext4 name bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Copies this ext4 name into a new owned name without using infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the name bytes cannot allocate.
    pub fn try_to_owned_name(&self) -> Result<Self> {
        Ok(Self {
            bytes: memory::copied_slice(&self.bytes)?,
        })
    }
}

/// Fixed-version scalar normalization backed by authenticated generated data.
mod normalization;

/// Directory comparison semantics, selected from its inode and mounted encoding contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NameSemantics {
    /// Opaque byte equality and byte-derived index hashes.
    Bytewise,
    /// Unicode 12.1 full folding with an explicit invalid-input policy.
    Folded(InvalidEncodingPolicy),
}
/// Filesystem policy for malformed UTF-8 or scalars absent from its supported Unicode age.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InvalidEncodingPolicy {
    /// Reject the name before any mutation or index routing.
    Reject,
    /// The entire original name remains an opaque byte sequence.
    Opaque,
}
/// Comparison bytes have no on-disk component-length restriction; original names retain theirs.
#[derive(Debug)]
pub(crate) enum NameKey<'a> {
    /// Borrowed raw component, including a whole-name invalid-encoding fallback.
    Opaque(&'a [u8]),
    /// Complete normalized name, potentially longer than an on-disk directory component.
    Unicode(Vec<u8>),
}
impl NameKey<'_> {
    /// Bytes used identically by equality and index hashing.
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Opaque(bytes) => bytes,
            Self::Unicode(bytes) => bytes,
        }
    }
}
impl NameSemantics {
    /// Admits the exact filesystem encoding identifier and flags supported by this implementation.
    /// # Errors
    /// Rejects an unsupported encoding or unknown strictness bits before mounted authority.
    pub(crate) fn from_encoding(encoding: u16, flags: u16) -> Result<Self> {
        if encoding != 1 || flags & !1 != 0 {
            return Err(Error::UnsupportedWriteFeature);
        }
        Ok(Self::Folded(if flags == 1 {
            InvalidEncodingPolicy::Reject
        } else {
            InvalidEncodingPolicy::Opaque
        }))
    }
    /// Derives comparison bytes while retaining allocation failures independently of input policy.
    /// # Errors
    /// Returns invalid names under strict policy or allocation failure under either policy.
    pub(crate) fn key(self, bytes: &[u8]) -> Result<NameKey<'_>> {
        match self {
            Self::Bytewise => Ok(NameKey::Opaque(bytes)),
            Self::Folded(policy) => match normalization::fold(bytes) {
                Ok(bytes) => Ok(NameKey::Unicode(bytes)),
                Err(Error::InvalidName) if policy == InvalidEncodingPolicy::Opaque => {
                    Ok(NameKey::Opaque(bytes))
                }
                Err(error) => Err(error),
            },
        }
    }
    /// Compares full components without changing their stored spelling.
    /// # Errors
    /// Returns invalid encoding or allocation failures before equality can be established.
    pub(crate) fn equivalent(self, left: &Ext4Name, right: &Ext4Name) -> Result<bool> {
        Ok(self.key(left.bytes())?.bytes() == self.key(right.bytes())?.bytes())
    }
    /// Computes the exact comparison-key bytes consumed by the selected index algorithm.
    /// # Errors
    /// Returns invalid encoding or allocation failures before routing a query.
    pub(crate) fn hash(
        self,
        name: &Ext4Name,
        scheme: super::directory_hash::DirectoryHashScheme,
    ) -> Result<super::directory_hash::DirectoryHash> {
        Ok(scheme.hash(self.key(name.bytes())?.bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Errors
    /// Propagates component construction, encoding admission or normalization failures.
    /// # Panics
    /// Fails if full folding, canonical order, age limits or whole-name fallback diverge.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions observe independent Unicode vectors and strict policy outcomes"
    )]
    fn unicode_name_keys_preserve_filesystem_semantics() -> Result<()> {
        let names = NameSemantics::from_encoding(1, 1)?;
        for (left, right) in [
            ("Straße", "STRASSE"),
            ("İ", "i\u{307}"),
            ("Σςσ", "σσσ"),
            ("Å", "a\u{30a}"),
            ("각", "\u{1100}\u{1161}\u{11a8}"),
            ("A\u{345}\u{35d}\u{345}B", "a\u{35d}\u{3b9}\u{3b9}b"),
            ("ab\u{200d}cd", "ABCD"),
        ] {
            assert!(names.equivalent(
                &Ext4Name::new(left.as_bytes())?,
                &Ext4Name::new(right.as_bytes())?
            )?);
        }
        assert!(!names.equivalent(&Ext4Name::new("Ⓐ".as_bytes())?, &Ext4Name::new(b"a")?)?);
        let invalid = Ext4Name::new(b"Ab\xff")?;
        assert_eq!(names.key(invalid.bytes()).err(), Some(Error::InvalidName));
        let opaque = NameSemantics::from_encoding(1, 0)?;
        assert!(!opaque.equivalent(&invalid, &Ext4Name::new(b"ab\xff")?)?);
        assert_eq!(opaque.key(invalid.bytes())?.bytes(), invalid.bytes());
        let future = "\u{1fae0}".as_bytes();
        assert_eq!(names.key(future).err(), Some(Error::InvalidName));
        assert_eq!(opaque.key(future)?.bytes(), future);
        let long = "ΐ".repeat(85);
        let component = Ext4Name::new(long.as_bytes())?;
        assert!(names.key(component.bytes())?.bytes().len() > 255);
        Ok(())
    }
    /// # Errors
    /// Returns malformed official fields, normalization rejection or physical allocation failure.
    /// # Panics
    /// Fails if canonically equivalent official vectors acquire different comparison keys.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "official Unicode normalization columns are an independent semantic oracle"
    )]
    fn official_canonical_equivalence_vectors() -> Result<()> {
        let text = include_str!("../../data/unicode-12.1.0/NormalizationTest.txt");
        for line in text.lines() {
            let data = line.split('#').next().unwrap_or("").trim();
            if data.is_empty() || data.starts_with('@') {
                continue;
            }
            let mut values = Vec::new();
            for column in data.split(';').take(5) {
                let mut bytes = Vec::new();
                for value in column.split_whitespace() {
                    let scalar = u32::from_str_radix(value, 16).map_err(|_| Error::InvalidName)?;
                    let cp = char::from_u32(scalar).ok_or(Error::InvalidName)?;
                    let mut encoded = [0; 4];
                    use crate::memory::FallibleVec as _;
                    bytes.try_extend_from_slice(cp.encode_utf8(&mut encoded).as_bytes())?;
                }
                use crate::memory::FallibleVec as _;
                values.try_push(normalization::fold(&bytes)?)?;
            }
            for index in [0, 1] {
                assert_eq!(values.get(index), values.get(2), "{line}");
            }
            assert_eq!(values.get(3), values.get(4), "{line}");
        }
        Ok(())
    }
}
