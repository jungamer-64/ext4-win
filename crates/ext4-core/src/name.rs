//! Ext4 names and the conservative Windows namespace projection.

use alloc::vec::Vec;
use core::str;

use crate::error::{Error, Result};

/// Raw ext4 directory entry name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ext4Name {
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
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the raw ext4 name bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Name that can be losslessly exposed through the Windows UTF-16 namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsName {
    utf16: Vec<u16>,
}

impl WindowsName {
    /// Converts a raw ext4 name if Windows can represent it without escaping.
    ///
    /// # Errors
    /// Returns an error when the ext4 bytes are not UTF-8 or contain a
    /// character that Windows path lookup cannot expose losslessly.
    pub fn from_ext4(name: &Ext4Name) -> Result<Self> {
        let text = str::from_utf8(name.bytes()).map_err(|_| Error::InvalidName)?;
        if text.chars().any(|ch| {
            matches!(
                ch,
                '\0' | '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
            )
        }) {
            return Err(Error::InvalidName);
        }
        Ok(Self {
            utf16: text.encode_utf16().collect(),
        })
    }

    /// Returns the UTF-16 Windows name.
    #[must_use]
    pub fn utf16(&self) -> &[u16] {
        &self.utf16
    }

    /// Returns true when the name exactly equals a requested UTF-16 name.
    #[must_use]
    pub fn equals_utf16(&self, requested: &[u16]) -> bool {
        self.utf16 == requested
    }

    /// Returns true for the v1 ASCII-only case-insensitive comparison.
    #[must_use]
    pub fn equals_ascii_case_insensitive(&self, requested: &[u16]) -> bool {
        self.utf16.len() == requested.len()
            && self
                .utf16
                .iter()
                .zip(requested)
                .all(|(left, right)| fold_ascii_u16(*left) == fold_ascii_u16(*right))
    }
}

fn fold_ascii_u16(value: u16) -> u16 {
    match value {
        0x0041..=0x005A => value | 0x0020,
        _ => value,
    }
}
