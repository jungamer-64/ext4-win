//! Ext4 names and the conservative Windows namespace projection.

use alloc::vec::Vec;
use core::{char, str};

use crate::error::{Error, Result};
use crate::memory::{self, FallibleVec};

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

/// Name that can be losslessly exposed through the Windows UTF-16 namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsName {
    /// Validated Windows component encoded as UTF-16.
    utf16: Vec<u16>,
}

impl WindowsName {
    /// Validates and stores a Windows UTF-16 lookup component.
    ///
    /// # Errors
    /// Returns an error when the requested component is empty or contains a
    /// separator or wildcard character that is not a file-name component.
    pub fn from_utf16(utf16: &[u16]) -> Result<Self> {
        if utf16.is_empty()
            || utf16.iter().any(|unit| {
                matches!(
                    *unit,
                    0x0000
                        | 0x0022
                        | 0x002A
                        | 0x002F
                        | 0x003A
                        | 0x003C
                        | 0x003E
                        | 0x003F
                        | 0x005C
                        | 0x007C
                )
            })
        {
            return Err(Error::InvalidName);
        }
        Ok(Self {
            utf16: memory::copied_slice(utf16)?,
        })
    }

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
        let mut utf16 = Vec::new();
        utf16
            .try_reserve(text.len())
            .map_err(|_| Error::OutOfMemory)?;
        for unit in text.encode_utf16() {
            utf16.try_push(unit)?;
        }
        Ok(Self { utf16 })
    }

    /// Converts this Windows name to the ext4 UTF-8 name stored on disk.
    ///
    /// # Errors
    /// Returns an error when the Windows UTF-16 contains an unpaired surrogate
    /// or the encoded ext4 name violates ext4 component limits.
    pub fn to_ext4(&self) -> Result<Ext4Name> {
        let mut bytes = Vec::new();
        for item in char::decode_utf16(self.utf16.iter().copied()) {
            let ch = item.map_err(|_| Error::InvalidName)?;
            let mut encoded = [0_u8; 4];
            let text = ch.encode_utf8(&mut encoded);
            bytes.try_extend_from_slice(text.as_bytes())?;
        }
        Ext4Name::new(&bytes)
    }

    /// Returns the UTF-16 Windows name.
    #[must_use]
    pub fn utf16(&self) -> &[u16] {
        &self.utf16
    }

    /// Returns true when the name exactly equals another Windows name.
    #[must_use]
    pub fn equals(&self, requested: &Self) -> bool {
        self.utf16 == requested.utf16
    }

    /// Returns true for the v1 ASCII-only case-insensitive comparison.
    #[must_use]
    pub fn equals_ascii_case_insensitive(&self, requested: &Self) -> bool {
        self.utf16.len() == requested.utf16.len()
            && self
                .utf16
                .iter()
                .zip(&requested.utf16)
                .all(|(left, right)| fold_ascii_u16(*left) == fold_ascii_u16(*right))
    }
}

/// Applies the Windows v1 ASCII-only case fold to one UTF-16 code unit.
fn fold_ascii_u16(value: u16) -> u16 {
    match value {
        0x0041..=0x005A => value | 0x0020,
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::WindowsName;

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn windows_name_converts_to_ext4_utf8_name() {
        let name = WindowsName::from_utf16(&[0x0063, 0x0061, 0x0066, 0x00E9]);
        assert!(name.is_ok());
        if let Ok(name) = name {
            let ext4 = name.to_ext4();
            assert!(ext4.is_ok());
            if let Ok(ext4) = ext4 {
                assert_eq!(ext4.bytes(), b"caf\xC3\xA9");
            }
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn windows_name_rejects_unpaired_surrogate_for_ext4_creation() {
        let name = WindowsName::from_utf16(&[0xD800]);
        assert!(name.is_ok());
        if let Ok(name) = name {
            assert!(name.to_ext4().is_err());
        }
    }
}
