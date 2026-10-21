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

