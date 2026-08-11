//! Operation-scoped cryptographic execution boundary.

use crate::Result;

/// Cryptographic primitives consumed by one filesystem operation.
///
/// Implementations own every mutable algorithm object and work buffer used by
/// these calls. Mount-scoped provider handles remain outside the ext4 domain.
/// No method may retain an input or output reference after it returns.
pub trait CryptographicOperation {
    /// Fills an exact caller-owned buffer with cryptographically secure random bytes.
    /// # Errors
    ///
    /// Returns an error when the platform provider cannot produce the requested bytes.
    fn fill_random(&mut self, output: &mut [u8]) -> Result<()>;

    /// Expands fscrypt input key material with HKDF-SHA512 and no salt.
    /// # Errors
    ///
    /// Returns an error when the platform provider rejects the key, info, or output length.
    fn hkdf_sha512(&mut self, key: &[u8], info: &[u8], output: &mut [u8]) -> Result<()>;

    /// Encrypts one fscrypt data unit with AES-256-XTS.
    /// # Errors
    ///
    /// Returns an error when the key, data-unit number, or buffer is rejected.
    fn encrypt_aes_256_xts(
        &mut self,
        key: &[u8; 64],
        data_unit: u64,
        buffer: &mut [u8],
    ) -> Result<()>;

    /// Decrypts one fscrypt data unit with AES-256-XTS.
    /// # Errors
    ///
    /// Returns an error when the key, data-unit number, or buffer is rejected.
    fn decrypt_aes_256_xts(
        &mut self,
        key: &[u8; 64],
        data_unit: u64,
        buffer: &mut [u8],
    ) -> Result<()>;

    /// Encrypts one fscrypt filename buffer with AES-256-CBC-CS3 and a zero IV.
    /// # Errors
    ///
    /// Returns an error when the key or ciphertext-stealing buffer is rejected.
    fn encrypt_aes_256_cbc_cs3(&mut self, key: &[u8; 32], buffer: &mut [u8]) -> Result<()>;

    /// Decrypts one fscrypt filename buffer with AES-256-CBC-CS3 and a zero IV.
    /// # Errors
    ///
    /// Returns an error when the key or ciphertext-stealing buffer is rejected.
    fn decrypt_aes_256_cbc_cs3(&mut self, key: &[u8; 32], buffer: &mut [u8]) -> Result<()>;

    /// Hashes one byte string with SHA-256.
    /// # Errors
    ///
    /// Returns an error when the platform hash object cannot process the input.
    fn sha256(&mut self, input: &[u8]) -> Result<[u8; 32]>;

    /// Hashes one byte string with SHA-512.
    /// # Errors
    ///
    /// Returns an error when the platform hash object cannot process the input.
    fn sha512(&mut self, input: &[u8]) -> Result<[u8; 64]>;
}
