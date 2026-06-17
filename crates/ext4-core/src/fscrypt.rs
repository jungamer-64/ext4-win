//! fscrypt mount-key domain.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Filesystem-wide fscrypt master-key identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FscryptKeyIdentifier([u8; 16]);

impl FscryptKeyIdentifier {
    /// Creates a key identifier from the 16-byte fscrypt v2 key id.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw key identifier bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Raw fscrypt master key material supplied at the mount boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FscryptMasterKey {
    /// Stable fscrypt v2 identifier.
    identifier: FscryptKeyIdentifier,
    /// Raw key bytes before per-file derivation.
    bytes: Vec<u8>,
}

impl FscryptMasterKey {
    /// Creates a mount-scoped fscrypt master key.
    ///
    /// # Errors
    /// Returns an error when the key material is empty.
    pub fn new(identifier: FscryptKeyIdentifier, bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::InvalidEncryptionContext);
        }
        Ok(Self {
            identifier,
            bytes: bytes.to_vec(),
        })
    }

    /// Stable fscrypt v2 identifier.
    #[must_use]
    pub const fn identifier(&self) -> FscryptKeyIdentifier {
        self.identifier
    }

    /// Raw key material.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
