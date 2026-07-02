//! fscrypt v2 policy, context, and mount-key domain.

use alloc::vec::Vec;
use core::fmt;

use aes::Aes256;
use aes::cipher::{Array, KeyInit, consts::U32, consts::U64};
use cts::{CbcCs3, Decrypt as CtsDecrypt, Encrypt as CtsEncrypt, KeyIvInit};
use hkdf::Hkdf;
use sha2::Sha512;
use xts_mode::{Xts128, get_tweak_default};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::memory::{self, FallibleVec};

/// Serialized fscrypt v2 policy size.
#[cfg(test)]
pub const FSCRYPT_POLICY_V2_BYTES: usize = 24;
/// Serialized fscrypt v2 context size.
pub const FSCRYPT_CONTEXT_V2_BYTES: usize = 40;

/// Prefix used for reversible no-key filename display names.
const FSCRYPT_NOKEY_NAME_PREFIX: &[u8] = b"_fscrypt_";
/// fscrypt v2 policy version byte.
#[cfg(test)]
const FSCRYPT_POLICY_V2: u8 = 2;
/// fscrypt v2 context version byte.
const FSCRYPT_CONTEXT_V2: u8 = 2;
/// fscrypt AES-256-XTS mode number.
const FSCRYPT_MODE_AES_256_XTS: u8 = 1;
/// fscrypt AES-256-CBC-CTS filename mode number.
const FSCRYPT_MODE_AES_256_CTS: u8 = 4;
/// Mask selecting the fscrypt filename padding policy.
const FSCRYPT_POLICY_FLAGS_PAD_MASK: u8 = 0x03;
/// All fscrypt policy flags accepted by the first v2 AES domain.
const FSCRYPT_SUPPORTED_POLICY_FLAGS: u8 = FSCRYPT_POLICY_FLAGS_PAD_MASK;
/// Minimum raw key length for AES-256 fscrypt policies.
const FSCRYPT_AES_256_MIN_MASTER_KEY_BYTES: usize = 32;
/// Maximum raw key length accepted by fscrypt for software keys.
const FSCRYPT_MAX_RAW_KEY_BYTES: usize = 64;
/// Length of fscrypt v2 key identifiers.
const FSCRYPT_KEY_IDENTIFIER_BYTES: usize = 16;
/// Length of per-file fscrypt nonces.
const FSCRYPT_FILE_NONCE_BYTES: usize = 16;
/// AES-256-XTS key bytes derived for file contents.
const FSCRYPT_AES_256_XTS_KEY_BYTES: usize = 64;
/// AES-256-CBC-CTS key bytes derived for filenames.
const FSCRYPT_AES_256_CBC_CTS_KEY_BYTES: usize = 32;
/// Prefix used by Linux fscrypt before the HKDF context byte.
const FSCRYPT_HKDF_INFO_PREFIX: &[u8; 8] = b"fscrypt\0";
/// Offset of the version field in a v2 policy or context.
const FSCRYPT_VERSION_OFFSET: usize = 0;
/// Offset of the contents-mode field in a v2 policy or context.
const FSCRYPT_CONTENTS_MODE_OFFSET: usize = 1;
/// Offset of the filenames-mode field in a v2 policy or context.
const FSCRYPT_FILENAMES_MODE_OFFSET: usize = 2;
/// Offset of the flags field in a v2 policy or context.
const FSCRYPT_FLAGS_OFFSET: usize = 3;
/// Offset of the log2 data-unit-size field in a v2 policy or context.
const FSCRYPT_LOG2_DATA_UNIT_SIZE_OFFSET: usize = 4;
/// Offset of the reserved field in a v2 policy or context.
const FSCRYPT_RESERVED_OFFSET: usize = 5;
/// Offset of the master-key identifier in a v2 policy or context.
const FSCRYPT_MASTER_KEY_IDENTIFIER_OFFSET: usize = 8;
/// Offset of the per-file nonce in a v2 context.
const FSCRYPT_NONCE_OFFSET: usize = 24;
/// URL-safe base64 alphabet used for no-key display names.
const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Filesystem-wide fscrypt v2 raw-key identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FscryptKeyIdentifier([u8; FSCRYPT_KEY_IDENTIFIER_BYTES]);

/// Mount-local fscrypt master-key presence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FscryptKeyPresence {
    /// The key is installed in this mount context.
    Present,
    /// The key is absent from this mount context.
    Absent,
}

impl FscryptKeyIdentifier {
    /// Creates a key identifier from the 16-byte fscrypt v2 key id.
    #[must_use]
    pub const fn new(bytes: [u8; FSCRYPT_KEY_IDENTIFIER_BYTES]) -> Self {
        Self(bytes)
    }

    /// Derives the fscrypt v2 identifier for a raw software master key.
    ///
    /// # Errors
    /// Returns an error when the raw key length is outside the supported
    /// AES-256 fscrypt v2 range.
    pub fn for_raw_master_key(bytes: &[u8]) -> Result<Self> {
        validate_raw_master_key(bytes)?;
        let mut identifier = [0_u8; FSCRYPT_KEY_IDENTIFIER_BYTES];
        fscrypt_hkdf_expand(
            bytes,
            FscryptHkdfContext::KeyIdentifierForRawKey,
            &[],
            &mut identifier,
        )?;
        Ok(Self(identifier))
    }

    /// Returns the raw key identifier bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; FSCRYPT_KEY_IDENTIFIER_BYTES] {
        self.0
    }
}

/// Per-file fscrypt nonce stored in the encryption context xattr.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FscryptFileNonce([u8; FSCRYPT_FILE_NONCE_BYTES]);

impl FscryptFileNonce {
    /// Creates a per-file nonce from the 16-byte on-disk value.
    #[must_use]
    pub const fn new(bytes: [u8; FSCRYPT_FILE_NONCE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the raw nonce bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; FSCRYPT_FILE_NONCE_BYTES] {
        self.0
    }
}

/// fscrypt contents encryption mode accepted by this driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FscryptContentsMode {
    /// AES-256-XTS for regular file contents.
    Aes256Xts,
}

impl FscryptContentsMode {
    /// Parses a serialized fscrypt contents-mode byte.
    /// # Errors
    ///
    /// Returns an error when the contents mode is not the supported AES-256-XTS profile.
    fn parse(value: u8) -> Result<Self> {
        match value {
            FSCRYPT_MODE_AES_256_XTS => Ok(Self::Aes256Xts),
            _ => Err(Error::InvalidEncryptionContext),
        }
    }

    /// Returns the Linux fscrypt mode number.
    #[must_use]
    pub const fn mode_number(self) -> u8 {
        match self {
            Self::Aes256Xts => FSCRYPT_MODE_AES_256_XTS,
        }
    }
}

/// fscrypt filenames encryption mode accepted by this driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FscryptFilenamesMode {
    /// AES-256-CBC-CTS for directory entry names.
    Aes256CbcCts,
}

impl FscryptFilenamesMode {
    /// Parses a serialized fscrypt filenames-mode byte.
    /// # Errors
    ///
    /// Returns an error when the filenames mode is not the supported AES-256-CBC-CTS profile.
    fn parse(value: u8) -> Result<Self> {
        match value {
            FSCRYPT_MODE_AES_256_CTS => Ok(Self::Aes256CbcCts),
            _ => Err(Error::InvalidEncryptionContext),
        }
    }

    /// Returns the Linux fscrypt mode number.
    #[must_use]
    pub const fn mode_number(self) -> u8 {
        match self {
            Self::Aes256CbcCts => FSCRYPT_MODE_AES_256_CTS,
        }
    }
}

/// fscrypt filename padding encoded in policy flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FscryptFilenamePadding {
    /// Pad encrypted names to a 4-byte boundary.
    Pad4,
    /// Pad encrypted names to an 8-byte boundary.
    Pad8,
    /// Pad encrypted names to a 16-byte boundary.
    Pad16,
    /// Pad encrypted names to a 32-byte boundary.
    Pad32,
}

impl FscryptFilenamePadding {
    /// Parses a supported v2 policy flags byte.
    /// # Errors
    ///
    /// Returns an error when unsupported policy flag bits are set.
    fn parse(flags: u8) -> Result<Self> {
        if flags & !FSCRYPT_SUPPORTED_POLICY_FLAGS != 0 {
            return Err(Error::InvalidEncryptionContext);
        }
        match flags & FSCRYPT_POLICY_FLAGS_PAD_MASK {
            0x00 => Ok(Self::Pad4),
            0x01 => Ok(Self::Pad8),
            0x02 => Ok(Self::Pad16),
            0x03 => Ok(Self::Pad32),
            _ => Err(Error::InvalidEncryptionContext),
        }
    }

    /// Returns the serialized flags bits for this padding policy.
    #[must_use]
    pub const fn flags(self) -> u8 {
        match self {
            Self::Pad4 => 0x00,
            Self::Pad8 => 0x01,
            Self::Pad16 => 0x02,
            Self::Pad32 => 0x03,
        }
    }

    /// Returns the plaintext filename length-hiding alignment in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Pad4 => 4,
            Self::Pad8 => 8,
            Self::Pad16 => 16,
            Self::Pad32 => 32,
        }
    }
}

/// fscrypt contents data-unit size accepted by this driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FscryptDataUnitSize {
    /// Use the ext4 filesystem block size.
    FilesystemBlock,
}

impl FscryptDataUnitSize {
    /// Parses the v2 policy data-unit-size byte.
    /// # Errors
    ///
    /// Returns an error when the data-unit size is not the filesystem-block default.
    fn parse(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::FilesystemBlock),
            _ => Err(Error::InvalidEncryptionContext),
        }
    }

    /// Returns the serialized log2 data-unit-size byte.
    #[must_use]
    pub const fn log2_value(self) -> u8 {
        match self {
            Self::FilesystemBlock => 0,
        }
    }
}

/// Validated fscrypt v2 policy in the supported AES configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FscryptPolicyV2 {
    /// Contents encryption mode.
    contents_mode: FscryptContentsMode,
    /// Filenames encryption mode.
    filenames_mode: FscryptFilenamesMode,
    /// Filename padding policy.
    filename_padding: FscryptFilenamePadding,
    /// Contents data-unit size.
    data_unit_size: FscryptDataUnitSize,
    /// Master-key identifier.
    master_key_identifier: FscryptKeyIdentifier,
}

impl FscryptPolicyV2 {
    /// Parses a Linux `struct fscrypt_policy_v2` byte image.
    ///
    /// # Errors
    /// Returns an error when the image is not exactly v2 AES-256-XTS plus
    /// AES-256-CBC-CTS with only supported flags.
    #[cfg(test)]
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        require_exact_len(bytes, FSCRYPT_POLICY_V2_BYTES)?;
        parse_policy_fields(bytes, FSCRYPT_POLICY_V2)
    }

    /// Serializes this policy as Linux `struct fscrypt_policy_v2` bytes.
    #[must_use]
    #[cfg(test)]
    pub fn to_bytes(self) -> [u8; FSCRYPT_POLICY_V2_BYTES] {
        let mut bytes = [0_u8; FSCRYPT_POLICY_V2_BYTES];
        write_policy_fields(&mut bytes, FSCRYPT_POLICY_V2, self);
        bytes
    }

    /// Contents encryption mode.
    #[must_use]
    pub const fn contents_mode(self) -> FscryptContentsMode {
        self.contents_mode
    }

    /// Filenames encryption mode.
    #[must_use]
    pub const fn filenames_mode(self) -> FscryptFilenamesMode {
        self.filenames_mode
    }

    /// Filename padding policy.
    #[must_use]
    pub const fn filename_padding(self) -> FscryptFilenamePadding {
        self.filename_padding
    }

    /// Contents data-unit size.
    #[must_use]
    pub const fn data_unit_size(self) -> FscryptDataUnitSize {
        self.data_unit_size
    }

    /// Master-key identifier selected by this policy.
    #[must_use]
    pub const fn master_key_identifier(self) -> FscryptKeyIdentifier {
        self.master_key_identifier
    }
}

/// Validated on-disk fscrypt v2 context in the supported AES configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FscryptContextV2 {
    /// Policy fields inherited by this inode.
    policy: FscryptPolicyV2,
    /// Per-file nonce.
    nonce: FscryptFileNonce,
}

impl FscryptContextV2 {
    /// Creates a per-inode v2 context from an inherited policy and new nonce.
    #[must_use]
    pub const fn new(policy: FscryptPolicyV2, nonce: FscryptFileNonce) -> Self {
        Self { policy, nonce }
    }

    /// Parses a Linux `struct fscrypt_context_v2` byte image.
    ///
    /// # Errors
    /// Returns an error when the image is not exactly a supported fscrypt v2
    /// context.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        require_exact_len(bytes, FSCRYPT_CONTEXT_V2_BYTES)?;
        let policy = parse_policy_fields(bytes, FSCRYPT_CONTEXT_V2)?;
        let nonce = FscryptFileNonce::new(fixed(bytes, FSCRYPT_NONCE_OFFSET)?);
        Ok(Self { policy, nonce })
    }

    /// Serializes this context as Linux `struct fscrypt_context_v2` bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; FSCRYPT_CONTEXT_V2_BYTES] {
        let mut bytes = [0_u8; FSCRYPT_CONTEXT_V2_BYTES];
        write_policy_fields(&mut bytes, FSCRYPT_CONTEXT_V2, self.policy);
        bytes[FSCRYPT_NONCE_OFFSET..FSCRYPT_NONCE_OFFSET + FSCRYPT_FILE_NONCE_BYTES]
            .copy_from_slice(&self.nonce.bytes());
        bytes
    }

    /// Policy fields from this context.
    #[must_use]
    pub const fn policy(self) -> FscryptPolicyV2 {
        self.policy
    }

    /// Per-file nonce from this context.
    #[must_use]
    pub const fn nonce(self) -> FscryptFileNonce {
        self.nonce
    }
}

/// Reversible Windows-safe projection of an encrypted dirent name without keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FscryptNoKeyName {
    /// On-disk encrypted filename bytes.
    ciphertext: Vec<u8>,
}

impl FscryptNoKeyName {
    /// Builds a displayable no-key name from on-disk ciphertext bytes.
    /// # Errors
    ///
    /// Returns an error when the ciphertext length is invalid or its Windows-safe display encoding
    /// would exceed the ext4 name limit.
    pub(crate) fn from_ciphertext(ciphertext: &[u8]) -> Result<Self> {
        validate_ciphertext_filename_len(ciphertext.len())?;
        let name = Self {
            ciphertext: memory::copied_slice(ciphertext)?,
        };
        let _display = name.display_bytes()?;
        Ok(name)
    }

    /// Decodes a display name created by [`Self::display_bytes`].
    /// # Errors
    ///
    /// Returns an error when a prefixed no-key display name is not canonical base64url or decodes to
    /// an invalid ciphertext length.
    pub(crate) fn from_display(display: &[u8]) -> Result<Option<Self>> {
        if !display.starts_with(FSCRYPT_NOKEY_NAME_PREFIX) {
            return Ok(None);
        }
        let encoded = display
            .get(FSCRYPT_NOKEY_NAME_PREFIX.len()..)
            .ok_or(Error::InvalidName)?;
        let ciphertext = base64url_decode_nopad(encoded)?;
        Ok(Some(Self::from_ciphertext(&ciphertext)?))
    }

    /// Returns the Windows-safe encoded display name.
    /// # Errors
    ///
    /// Returns an error when encoded-length arithmetic overflows or the display name would exceed
    /// the ext4 component length limit.
    pub(crate) fn display_bytes(&self) -> Result<Vec<u8>> {
        let encoded_len = base64url_nopad_len(self.ciphertext.len())?;
        let display_len = FSCRYPT_NOKEY_NAME_PREFIX
            .len()
            .checked_add(encoded_len)
            .ok_or(Error::ArithmeticOverflow)?;
        if display_len > 255 {
            return Err(Error::InvalidName);
        }
        let mut display = Vec::new();
        display
            .try_reserve_exact(display_len)
            .map_err(|_| Error::OutOfMemory)?;
        display.try_extend_from_slice(FSCRYPT_NOKEY_NAME_PREFIX)?;
        base64url_encode_nopad(&self.ciphertext, &mut display)?;
        Ok(display)
    }

    /// Returns the on-disk encrypted filename bytes.
    pub(crate) fn ciphertext_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Source of fresh fscrypt per-file nonces for new encrypted inodes.
pub trait FscryptNonceGenerator {
    /// Returns the next nonce to store in a newly-created fscrypt context.
    ///
    /// # Errors
    /// Returns an error when the mount cannot create a fresh encrypted inode.
    fn next_file_nonce(&mut self) -> Result<FscryptFileNonce>;
}

/// Mount nonce source used when encrypted inode creation is unavailable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg(test)]
pub struct FscryptNoNonceGenerator;

#[cfg(test)]
impl FscryptNonceGenerator for FscryptNoNonceGenerator {
    fn next_file_nonce(&mut self) -> Result<FscryptFileNonce> {
        Err(Error::UnsupportedEncryption)
    }
}

/// Raw fscrypt master key material supplied at the mount boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct FscryptMasterKey {
    /// Stable fscrypt v2 identifier derived from the raw key.
    identifier: FscryptKeyIdentifier,
    /// Raw key bytes before per-file derivation.
    bytes: Vec<u8>,
}

impl FscryptMasterKey {
    /// Creates a mount-scoped fscrypt master key from raw software key bytes.
    ///
    /// # Errors
    /// Returns an error when the key material is outside the AES-256 fscrypt
    /// range.
    pub fn from_raw(bytes: &[u8]) -> Result<Self> {
        let identifier = FscryptKeyIdentifier::for_raw_master_key(bytes)?;
        Ok(Self {
            identifier,
            bytes: memory::copied_slice(bytes)?,
        })
    }

    /// Stable fscrypt v2 identifier.
    #[must_use]
    pub const fn identifier(&self) -> FscryptKeyIdentifier {
        self.identifier
    }

    /// Derives the AES-256-XTS per-file contents key for a regular file.
    ///
    /// # Errors
    /// Returns an error when HKDF expansion fails.
    pub fn derive_contents_key(&self, nonce: FscryptFileNonce) -> Result<FscryptContentsKey> {
        let mut bytes = [0_u8; FSCRYPT_AES_256_XTS_KEY_BYTES];
        fscrypt_hkdf_expand(
            &self.bytes,
            FscryptHkdfContext::PerFileEncryptionKey,
            &nonce.bytes(),
            &mut bytes,
        )?;
        Ok(FscryptContentsKey { bytes })
    }

    /// Derives the AES-256-CBC-CTS per-file filename key for a directory.
    ///
    /// # Errors
    /// Returns an error when HKDF expansion fails.
    pub fn derive_filenames_key(&self, nonce: FscryptFileNonce) -> Result<FscryptFilenamesKey> {
        let mut bytes = [0_u8; FSCRYPT_AES_256_CBC_CTS_KEY_BYTES];
        fscrypt_hkdf_expand(
            &self.bytes,
            FscryptHkdfContext::PerFileEncryptionKey,
            &nonce.bytes(),
            &mut bytes,
        )?;
        Ok(FscryptFilenamesKey { bytes })
    }
}

impl Drop for FscryptMasterKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for FscryptMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FscryptMasterKey")
            .field("identifier", &self.identifier)
            .field("key_bytes", &self.bytes.len())
            .finish()
    }
}

/// Sorted unique mount-scoped fscrypt master-key set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FscryptKeySet {
    /// Keys sorted by fscrypt v2 identifier.
    keys: Vec<FscryptMasterKey>,
}

impl FscryptKeySet {
    /// Creates an empty fscrypt key set.
    #[must_use]
    pub const fn empty() -> Self {
        Self { keys: Vec::new() }
    }

    /// Creates a sorted key set from mount-supplied keys.
    ///
    /// # Errors
    /// Returns an error when two keys have the same v2 identifier.
    pub fn from_keys(mut keys: Vec<FscryptMasterKey>) -> Result<Self> {
        keys.sort_by_key(FscryptMasterKey::identifier);
        if keys
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left.identifier() == right.identifier()))
        {
            return Err(Error::InvalidEncryptionContext);
        }
        Ok(Self { keys })
    }

    /// Returns true when no fscrypt keys are available.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Adds one mount-scoped key while preserving identifier uniqueness.
    ///
    /// # Errors
    /// Returns an error when a key with the same identifier is already present.
    pub fn insert(&mut self, key: FscryptMasterKey) -> Result<()> {
        match self
            .keys
            .binary_search_by_key(&key.identifier(), FscryptMasterKey::identifier)
        {
            Ok(_) => Err(Error::InvalidEncryptionContext),
            Err(index) => {
                self.keys.insert(index, key);
                Ok(())
            }
        }
    }

    /// Removes a key by identifier.
    #[must_use]
    pub fn remove(&mut self, identifier: FscryptKeyIdentifier) -> Option<FscryptMasterKey> {
        self.keys
            .binary_search_by_key(&identifier, FscryptMasterKey::identifier)
            .ok()
            .map(|index| self.keys.remove(index))
    }

    /// Returns whether a key with the identifier is present.
    #[must_use]
    pub fn contains(&self, identifier: FscryptKeyIdentifier) -> bool {
        self.get(identifier).is_some()
    }

    /// Returns keys in stable identifier order.
    #[must_use]
    pub fn keys(&self) -> &[FscryptMasterKey] {
        &self.keys
    }

    /// Looks up a key by v2 identifier.
    #[must_use]
    pub fn get(&self, identifier: FscryptKeyIdentifier) -> Option<&FscryptMasterKey> {
        self.keys
            .binary_search_by_key(&identifier, FscryptMasterKey::identifier)
            .ok()
            .and_then(|index| self.keys.get(index))
    }
}

/// Derived AES-256-XTS key bytes for fscrypt contents encryption.
#[derive(Eq, PartialEq)]
pub struct FscryptContentsKey {
    /// Raw AES-256-XTS key bytes.
    bytes: [u8; FSCRYPT_AES_256_XTS_KEY_BYTES],
}

impl FscryptContentsKey {
    /// Returns raw AES-256-XTS key bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; FSCRYPT_AES_256_XTS_KEY_BYTES] {
        &self.bytes
    }

    /// Encrypts one fscrypt contents data unit in place.
    ///
    /// # Errors
    /// Returns an error when the data unit is smaller than one AES block.
    pub fn encrypt_block(&self, logical_block: u64, block: &mut [u8]) -> Result<()> {
        if block.len() < 16 {
            return Err(Error::InvalidWriteRange);
        }
        let xts = aes_256_xts(self.bytes);
        xts.encrypt_sector(block, get_tweak_default(u128::from(logical_block)));
        Ok(())
    }

    /// Decrypts one fscrypt contents data unit in place.
    ///
    /// # Errors
    /// Returns an error when the data unit is smaller than one AES block.
    pub fn decrypt_block(&self, logical_block: u64, block: &mut [u8]) -> Result<()> {
        if block.len() < 16 {
            return Err(Error::InvalidWriteRange);
        }
        let xts = aes_256_xts(self.bytes);
        xts.decrypt_sector(block, get_tweak_default(u128::from(logical_block)));
        Ok(())
    }
}

impl Drop for FscryptContentsKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for FscryptContentsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FscryptContentsKey")
            .field("key_bytes", &self.bytes.len())
            .finish()
    }
}

/// Derived AES-256-CBC-CTS key bytes for fscrypt filename encryption.
#[derive(Eq, PartialEq)]
pub struct FscryptFilenamesKey {
    /// Raw AES-256-CBC-CTS key bytes.
    bytes: [u8; FSCRYPT_AES_256_CBC_CTS_KEY_BYTES],
}

impl FscryptFilenamesKey {
    /// Returns raw AES-256-CBC-CTS key bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; FSCRYPT_AES_256_CBC_CTS_KEY_BYTES] {
        &self.bytes
    }

    /// Encrypts a plaintext filename using fscrypt AES-256-CBC-CTS.
    ///
    /// # Errors
    /// Returns an error when the plaintext name is invalid or the CTS operation
    /// fails.
    pub fn encrypt_filename(
        &self,
        plaintext: &[u8],
        padding: FscryptFilenamePadding,
    ) -> Result<Vec<u8>> {
        let padded_len = padded_filename_len(plaintext.len(), padding)?;
        let mut ciphertext = memory::repeated_vec(0_u8, padded_len)?;
        ciphertext
            .get_mut(..plaintext.len())
            .ok_or(Error::InvalidName)?
            .copy_from_slice(plaintext);
        aes_256_cbc_cts(self.bytes)
            .encrypt(&mut ciphertext)
            .map_err(|_| Error::InvalidName)?;
        Ok(ciphertext)
    }

    /// Decrypts a ciphertext filename using fscrypt AES-256-CBC-CTS.
    ///
    /// # Errors
    /// Returns an error when the ciphertext length or recovered plaintext
    /// padding is invalid.
    pub fn decrypt_filename(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 || ciphertext.len() > 255 {
            return Err(Error::InvalidName);
        }
        let mut plaintext = memory::copied_slice(ciphertext)?;
        aes_256_cbc_cts(self.bytes)
            .decrypt(&mut plaintext)
            .map_err(|_| Error::InvalidName)?;
        let Some(last) = plaintext.iter().rposition(|byte| *byte != 0) else {
            return Err(Error::InvalidName);
        };
        let len = last.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        if plaintext.get(..len).ok_or(Error::InvalidName)?.contains(&0) {
            return Err(Error::InvalidName);
        }
        plaintext.truncate(len);
        Ok(plaintext)
    }
}

impl Drop for FscryptFilenamesKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for FscryptFilenamesKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FscryptFilenamesKey")
            .field("key_bytes", &self.bytes.len())
            .finish()
    }
}

/// HKDF output namespaces used by fscrypt v2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FscryptHkdfContext {
    /// `HKDF_CONTEXT_KEY_IDENTIFIER_FOR_RAW_KEY`.
    KeyIdentifierForRawKey,
    /// `HKDF_CONTEXT_PER_FILE_ENC_KEY`.
    PerFileEncryptionKey,
}

impl FscryptHkdfContext {
    /// Returns the Linux fscrypt HKDF context byte.
    const fn value(self) -> u8 {
        match self {
            Self::KeyIdentifierForRawKey => 1,
            Self::PerFileEncryptionKey => 2,
        }
    }
}

/// Validates the supported raw master-key size range.
/// # Errors
///
/// Returns an error when the raw key is shorter than the AES-256 minimum or longer than fscrypt
/// accepts.
fn validate_raw_master_key(bytes: &[u8]) -> Result<()> {
    if bytes.len() < FSCRYPT_AES_256_MIN_MASTER_KEY_BYTES || bytes.len() > FSCRYPT_MAX_RAW_KEY_BYTES
    {
        return Err(Error::InvalidEncryptionContext);
    }
    Ok(())
}

/// Validates the on-disk ciphertext filename length.
/// # Errors
///
/// Returns an error when the ciphertext name is empty or longer than one ext4 component.
fn validate_ciphertext_filename_len(len: usize) -> Result<()> {
    if len == 0 || len > 255 {
        return Err(Error::InvalidName);
    }
    Ok(())
}

/// Returns the unpadded base64url length for `len` source bytes.
/// # Errors
///
/// Returns an error when base64 output-length arithmetic overflows.
fn base64url_nopad_len(len: usize) -> Result<usize> {
    let full_groups = len.checked_div(3).ok_or(Error::ArithmeticOverflow)?;
    let full_chars = full_groups
        .checked_mul(4)
        .ok_or(Error::ArithmeticOverflow)?;
    match len % 3 {
        0 => Ok(full_chars),
        1 => full_chars.checked_add(2).ok_or(Error::ArithmeticOverflow),
        2 => full_chars.checked_add(3).ok_or(Error::ArithmeticOverflow),
        _ => Err(Error::ArithmeticOverflow),
    }
}

/// Encodes bytes with URL-safe base64 and no padding.
/// # Errors
///
/// Returns an error when chunk slicing fails or a six-bit value is outside the base64url alphabet.
fn base64url_encode_nopad(bytes: &[u8], output: &mut Vec<u8>) -> Result<()> {
    let mut remaining = bytes;
    while remaining.len() >= 3 {
        let chunk = remaining.get(..3).ok_or(Error::InvalidName)?;
        let b0 = *chunk.first().ok_or(Error::InvalidName)?;
        let b1 = *chunk.get(1).ok_or(Error::InvalidName)?;
        let b2 = *chunk.get(2).ok_or(Error::InvalidName)?;
        push_base64url(output, b0 >> 2)?;
        push_base64url(output, ((b0 & 0x03) << 4) | (b1 >> 4))?;
        push_base64url(output, ((b1 & 0x0f) << 2) | (b2 >> 6))?;
        push_base64url(output, b2 & 0x3f)?;
        remaining = remaining.get(3..).ok_or(Error::InvalidName)?;
    }

    match remaining.len() {
        0 => Ok(()),
        1 => {
            let b0 = *remaining.first().ok_or(Error::InvalidName)?;
            push_base64url(output, b0 >> 2)?;
            push_base64url(output, (b0 & 0x03) << 4)
        }
        2 => {
            let b0 = *remaining.first().ok_or(Error::InvalidName)?;
            let b1 = *remaining.get(1).ok_or(Error::InvalidName)?;
            push_base64url(output, b0 >> 2)?;
            push_base64url(output, ((b0 & 0x03) << 4) | (b1 >> 4))?;
            push_base64url(output, (b1 & 0x0f) << 2)
        }
        _ => Err(Error::InvalidName),
    }
}

/// Appends one base64url alphabet byte.
/// # Errors
///
/// Returns an error when `value` is outside the six-bit base64url alphabet range.
fn push_base64url(output: &mut Vec<u8>, value: u8) -> Result<()> {
    output.try_push(base64url_alphabet_byte(value)?)?;
    Ok(())
}

/// Returns one base64url alphabet byte by six-bit value.
/// # Errors
///
/// Returns an error when `value` is greater than 63.
fn base64url_alphabet_byte(value: u8) -> Result<u8> {
    BASE64URL_ALPHABET
        .get(usize::from(value))
        .copied()
        .ok_or(Error::InvalidName)
}

/// Decodes URL-safe base64 without padding.
/// # Errors
///
/// Returns an error when the input length is not valid for unpadded base64url, contains a non
/// alphabet byte, or has nonzero canonical pad bits.
fn base64url_decode_nopad(encoded: &[u8]) -> Result<Vec<u8>> {
    if encoded.is_empty() || encoded.len() % 4 == 1 {
        return Err(Error::InvalidName);
    }
    let capacity = base64url_decoded_len(encoded.len())?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| Error::OutOfMemory)?;
    let mut remaining = encoded;
    while remaining.len() >= 4 {
        let chunk = remaining.get(..4).ok_or(Error::InvalidName)?;
        let c0 = base64url_value(*chunk.first().ok_or(Error::InvalidName)?)?;
        let c1 = base64url_value(*chunk.get(1).ok_or(Error::InvalidName)?)?;
        let c2 = base64url_value(*chunk.get(2).ok_or(Error::InvalidName)?)?;
        let c3 = base64url_value(*chunk.get(3).ok_or(Error::InvalidName)?)?;
        output.try_push((c0 << 2) | (c1 >> 4))?;
        output.try_push((c1 << 4) | (c2 >> 2))?;
        output.try_push((c2 << 6) | c3)?;
        remaining = remaining.get(4..).ok_or(Error::InvalidName)?;
    }

    match remaining.len() {
        0 => Ok(output),
        2 => {
            let c0 = base64url_value(*remaining.first().ok_or(Error::InvalidName)?)?;
            let c1 = base64url_value(*remaining.get(1).ok_or(Error::InvalidName)?)?;
            if c1 & 0x0f != 0 {
                return Err(Error::InvalidName);
            }
            output.try_push((c0 << 2) | (c1 >> 4))?;
            Ok(output)
        }
        3 => {
            let c0 = base64url_value(*remaining.first().ok_or(Error::InvalidName)?)?;
            let c1 = base64url_value(*remaining.get(1).ok_or(Error::InvalidName)?)?;
            let c2 = base64url_value(*remaining.get(2).ok_or(Error::InvalidName)?)?;
            if c2 & 0x03 != 0 {
                return Err(Error::InvalidName);
            }
            output.try_push((c0 << 2) | (c1 >> 4))?;
            output.try_push((c1 << 4) | (c2 >> 2))?;
            Ok(output)
        }
        _ => Err(Error::InvalidName),
    }
}

/// Returns decoded byte capacity for an unpadded base64url string.
/// # Errors
///
/// Returns an error when decoded-length arithmetic overflows or the encoded length has a remainder
/// impossible for unpadded base64url.
fn base64url_decoded_len(len: usize) -> Result<usize> {
    let full_groups = len.checked_div(4).ok_or(Error::ArithmeticOverflow)?;
    let full_bytes = full_groups
        .checked_mul(3)
        .ok_or(Error::ArithmeticOverflow)?;
    match len % 4 {
        0 => Ok(full_bytes),
        2 => full_bytes.checked_add(1).ok_or(Error::ArithmeticOverflow),
        3 => full_bytes.checked_add(2).ok_or(Error::ArithmeticOverflow),
        _ => Err(Error::InvalidName),
    }
}

/// Decodes one base64url alphabet byte.
/// # Errors
///
/// Returns an error when `byte` is not in the URL-safe base64 alphabet.
fn base64url_value(byte: u8) -> Result<u8> {
    match byte {
        b'A'..=b'Z' => byte.checked_sub(b'A').ok_or(Error::ArithmeticOverflow),
        b'a'..=b'z' => byte
            .checked_sub(b'a')
            .and_then(|value| value.checked_add(26))
            .ok_or(Error::ArithmeticOverflow),
        b'0'..=b'9' => byte
            .checked_sub(b'0')
            .and_then(|value| value.checked_add(52))
            .ok_or(Error::ArithmeticOverflow),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(Error::InvalidName),
    }
}

/// Parses policy fields shared by v2 policies and contexts.
/// # Errors
///
/// Returns an error when the version, modes, flags, data-unit size, reserved bytes, or key
/// identifier fields are not a supported fscrypt v2 AES profile.
fn parse_policy_fields(bytes: &[u8], version: u8) -> Result<FscryptPolicyV2> {
    if byte(bytes, FSCRYPT_VERSION_OFFSET)? != version {
        return Err(Error::InvalidEncryptionContext);
    }
    let contents_mode = FscryptContentsMode::parse(byte(bytes, FSCRYPT_CONTENTS_MODE_OFFSET)?)?;
    let filenames_mode = FscryptFilenamesMode::parse(byte(bytes, FSCRYPT_FILENAMES_MODE_OFFSET)?)?;
    let filename_padding = FscryptFilenamePadding::parse(byte(bytes, FSCRYPT_FLAGS_OFFSET)?)?;
    let data_unit_size =
        FscryptDataUnitSize::parse(byte(bytes, FSCRYPT_LOG2_DATA_UNIT_SIZE_OFFSET)?)?;
    let reserved: [u8; 3] = fixed(bytes, FSCRYPT_RESERVED_OFFSET)?;
    if reserved != [0_u8; 3] {
        return Err(Error::InvalidEncryptionContext);
    }
    let master_key_identifier =
        FscryptKeyIdentifier::new(fixed(bytes, FSCRYPT_MASTER_KEY_IDENTIFIER_OFFSET)?);
    Ok(FscryptPolicyV2 {
        contents_mode,
        filenames_mode,
        filename_padding,
        data_unit_size,
        master_key_identifier,
    })
}

/// Writes policy fields shared by v2 policies and contexts.
fn write_policy_fields(bytes: &mut [u8], version: u8, policy: FscryptPolicyV2) {
    put_byte(bytes, FSCRYPT_VERSION_OFFSET, version);
    put_byte(
        bytes,
        FSCRYPT_CONTENTS_MODE_OFFSET,
        policy.contents_mode().mode_number(),
    );
    put_byte(
        bytes,
        FSCRYPT_FILENAMES_MODE_OFFSET,
        policy.filenames_mode().mode_number(),
    );
    put_byte(
        bytes,
        FSCRYPT_FLAGS_OFFSET,
        policy.filename_padding().flags(),
    );
    put_byte(
        bytes,
        FSCRYPT_LOG2_DATA_UNIT_SIZE_OFFSET,
        policy.data_unit_size().log2_value(),
    );
    put_bytes(
        bytes,
        FSCRYPT_MASTER_KEY_IDENTIFIER_OFFSET,
        &policy.master_key_identifier().bytes(),
    );
}

/// Writes one byte at a compile-time fscrypt structure offset.
fn put_byte(bytes: &mut [u8], offset: usize, value: u8) {
    if let Some(slot) = bytes.get_mut(offset) {
        *slot = value;
    }
}

/// Writes a byte slice at a compile-time fscrypt structure offset.
fn put_bytes(bytes: &mut [u8], offset: usize, value: &[u8]) {
    let Some(end) = offset.checked_add(value.len()) else {
        return;
    };
    if let Some(slot) = bytes.get_mut(offset..end) {
        slot.copy_from_slice(value);
    }
}

/// Expands an fscrypt v2 HKDF output for one namespace and info value.
/// # Errors
///
/// Returns an error when HKDF info construction overflows or the requested output length is invalid
/// for HKDF-SHA512.
fn fscrypt_hkdf_expand(
    master_key: &[u8],
    context: FscryptHkdfContext,
    info: &[u8],
    output: &mut [u8],
) -> Result<()> {
    let info_len = FSCRYPT_HKDF_INFO_PREFIX
        .len()
        .checked_add(1)
        .and_then(|len| len.checked_add(info.len()))
        .ok_or(Error::ArithmeticOverflow)?;
    let mut prefixed_info = Vec::new();
    prefixed_info
        .try_reserve_exact(info_len)
        .map_err(|_| Error::OutOfMemory)?;
    prefixed_info.try_extend_from_slice(FSCRYPT_HKDF_INFO_PREFIX)?;
    prefixed_info.try_push(context.value())?;
    prefixed_info.try_extend_from_slice(info)?;

    Hkdf::<Sha512>::new(None, master_key)
        .expand(&prefixed_info, output)
        .map_err(|_| Error::InvalidEncryptionContext)
}

/// Builds an AES-256-XTS context from a fscrypt contents key.
fn aes_256_xts(key: [u8; FSCRYPT_AES_256_XTS_KEY_BYTES]) -> Xts128<Aes256> {
    let key = Array::<u8, U64>(key);
    let (key_1, key_2) = key.split::<U32>();
    Xts128::<Aes256>::new(Aes256::new(&key_1), Aes256::new(&key_2))
}

/// Builds an AES-256-CBC-CTS filename cipher with fscrypt's all-zero IV.
fn aes_256_cbc_cts(key: [u8; FSCRYPT_AES_256_CBC_CTS_KEY_BYTES]) -> CbcCs3<Aes256> {
    CbcCs3::<Aes256>::new(&key.into(), &[0_u8; 16].into())
}

/// Returns the padded filename length accepted by fscrypt AES-CBC-CTS.
/// # Errors
///
/// Returns an error when the plaintext name length is outside ext4 bounds or padding arithmetic
/// overflows.
fn padded_filename_len(len: usize, padding: FscryptFilenamePadding) -> Result<usize> {
    if len == 0 || len > 255 {
        return Err(Error::InvalidName);
    }
    let minimum = len.max(16);
    let alignment = padding.bytes();
    let adjusted = minimum
        .checked_add(alignment.checked_sub(1).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::ArithmeticOverflow)?;
    let padded = adjusted
        .checked_div(alignment)
        .ok_or(Error::ArithmeticOverflow)?
        .checked_mul(alignment)
        .ok_or(Error::ArithmeticOverflow)?;
    Ok(padded.min(255))
}

/// Requires an exact serialized structure length.
/// # Errors
///
/// Returns an error when `bytes` is shorter or longer than the expected serialized fscrypt
/// structure.
fn require_exact_len(bytes: &[u8], expected: usize) -> Result<()> {
    match bytes.len().cmp(&expected) {
        core::cmp::Ordering::Less => Err(Error::TruncatedStructure),
        core::cmp::Ordering::Equal => Ok(()),
        core::cmp::Ordering::Greater => Err(Error::InvalidEncryptionContext),
    }
}

/// Reads one byte from a checked offset.
/// # Errors
///
/// Returns an error when `offset` is outside the serialized fscrypt structure.
fn byte(bytes: &[u8], offset: usize) -> Result<u8> {
    bytes.get(offset).copied().ok_or(Error::TruncatedStructure)
}

/// Copies a fixed byte array from a checked offset.
/// # Errors
///
/// Returns an error when the fixed-width field overflows or is outside the serialized fscrypt
/// structure.
fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(Error::ArithmeticOverflow)?;
    let slice = bytes.get(offset..end).ok_or(Error::TruncatedStructure)?;
    let mut output = [0_u8; N];
    output.copy_from_slice(slice);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    /// Master key used by fscrypt HKDF vector tests.
    const VECTOR_MASTER_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    /// Per-file nonce used by fscrypt HKDF vector tests.
    const VECTOR_NONCE: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    /// Expected v2 identifier for `VECTOR_MASTER_KEY`.
    const VECTOR_IDENTIFIER: [u8; 16] = [
        0x37, 0xd7, 0xd7, 0x6a, 0x59, 0x40, 0x00, 0x83, 0x28, 0x9c, 0x18, 0x55, 0x26, 0x73, 0x0d,
        0x34,
    ];
    /// Expected AES-256-XTS per-file key.
    const VECTOR_CONTENTS_KEY: [u8; 64] = [
        0xe0, 0x80, 0x03, 0x95, 0x2a, 0x49, 0xa8, 0xfe, 0x90, 0x56, 0x87, 0x3d, 0x11, 0xe4, 0xcb,
        0x82, 0xe0, 0xa5, 0x21, 0x90, 0x20, 0x96, 0x0c, 0x35, 0x38, 0x71, 0x30, 0xa2, 0xa1, 0x93,
        0x82, 0x3e, 0xda, 0x7f, 0xd6, 0x41, 0xa7, 0xeb, 0x36, 0x5a, 0x44, 0xa3, 0x90, 0xc1, 0x8e,
        0x3c, 0x69, 0xf4, 0xa7, 0x73, 0x9a, 0xe4, 0x13, 0xdc, 0xc2, 0x0a, 0x2d, 0x42, 0x66, 0xe2,
        0xd2, 0x4c, 0x7f, 0x2a,
    ];
    /// Expected AES-256-CBC-CTS filename key.
    const VECTOR_FILENAMES_KEY: [u8; 32] = [
        0xe0, 0x80, 0x03, 0x95, 0x2a, 0x49, 0xa8, 0xfe, 0x90, 0x56, 0x87, 0x3d, 0x11, 0xe4, 0xcb,
        0x82, 0xe0, 0xa5, 0x21, 0x90, 0x20, 0x96, 0x0c, 0x35, 0x38, 0x71, 0x30, 0xa2, 0xa1, 0x93,
        0x82, 0x3e,
    ];

    macro_rules! must {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(error) => {
                    let unexpected_error: Option<()> = None;
                    assert!(
                        unexpected_error.is_some(),
                        "unexpected fscrypt error: {error:?}"
                    );
                    return;
                }
            }
        };
    }

    macro_rules! some {
        ($option:expr) => {
            match $option {
                Some(value) => value,
                None => {
                    let missing_value: Option<()> = None;
                    assert!(missing_value.is_some(), "missing fscrypt test value");
                    return;
                }
            }
        };
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_v2_policy_parses_supported_aes_profile() {
        let policy = valid_policy_bytes();

        let parsed = FscryptPolicyV2::parse(&policy);

        assert_eq!(
            parsed,
            Ok(FscryptPolicyV2 {
                contents_mode: FscryptContentsMode::Aes256Xts,
                filenames_mode: FscryptFilenamesMode::Aes256CbcCts,
                filename_padding: FscryptFilenamePadding::Pad32,
                data_unit_size: FscryptDataUnitSize::FilesystemBlock,
                master_key_identifier: FscryptKeyIdentifier::new([0x42; 16]),
            })
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_v2_context_parses_nonce_and_policy() {
        let mut context = [0_u8; FSCRYPT_CONTEXT_V2_BYTES];
        context[..FSCRYPT_POLICY_V2_BYTES].copy_from_slice(&valid_policy_bytes());
        context[FSCRYPT_NONCE_OFFSET..FSCRYPT_CONTEXT_V2_BYTES].copy_from_slice(&VECTOR_NONCE);

        let parsed = must!(FscryptContextV2::parse(&context));

        assert_eq!(parsed.nonce(), FscryptFileNonce::new(VECTOR_NONCE));
        assert_eq!(
            parsed.policy().master_key_identifier(),
            FscryptKeyIdentifier::new([0x42; 16])
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_v2_context_serializes_linux_layout() {
        let parsed = must!(FscryptContextV2::parse(&valid_context_bytes()));

        assert_eq!(parsed.policy().to_bytes(), valid_policy_bytes());
        assert_eq!(parsed.to_bytes(), valid_context_bytes());
        assert_eq!(
            FscryptContextV2::new(parsed.policy(), parsed.nonce()).to_bytes(),
            valid_context_bytes()
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_v2_context_rejects_unsupported_features() {
        let mut unsupported_contents = valid_context_bytes();
        unsupported_contents[FSCRYPT_CONTENTS_MODE_OFFSET] = 9;
        assert_eq!(
            FscryptContextV2::parse(&unsupported_contents),
            Err(Error::InvalidEncryptionContext)
        );

        let mut unsupported_names = valid_context_bytes();
        unsupported_names[FSCRYPT_FILENAMES_MODE_OFFSET] = 10;
        assert_eq!(
            FscryptContextV2::parse(&unsupported_names),
            Err(Error::InvalidEncryptionContext)
        );

        let mut direct_key = valid_context_bytes();
        direct_key[FSCRYPT_FLAGS_OFFSET] = 0x04;
        assert_eq!(
            FscryptContextV2::parse(&direct_key),
            Err(Error::InvalidEncryptionContext)
        );

        let mut custom_data_unit = valid_context_bytes();
        custom_data_unit[FSCRYPT_LOG2_DATA_UNIT_SIZE_OFFSET] = 12;
        assert_eq!(
            FscryptContextV2::parse(&custom_data_unit),
            Err(Error::InvalidEncryptionContext)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_v2_context_rejects_wrong_size_and_reserved_bytes() {
        let context = valid_context_bytes();
        assert_eq!(
            FscryptContextV2::parse(&context[..39]),
            Err(Error::TruncatedStructure)
        );

        let mut long_context = context.to_vec();
        long_context.push(0);
        assert_eq!(
            FscryptContextV2::parse(&long_context),
            Err(Error::InvalidEncryptionContext)
        );

        let mut reserved = valid_context_bytes();
        reserved[FSCRYPT_RESERVED_OFFSET] = 1;
        assert_eq!(
            FscryptContextV2::parse(&reserved),
            Err(Error::InvalidEncryptionContext)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_master_key_derives_identifier_and_per_file_keys() {
        let master_key = must!(FscryptMasterKey::from_raw(&VECTOR_MASTER_KEY));
        let nonce = FscryptFileNonce::new(VECTOR_NONCE);

        assert_eq!(master_key.identifier().bytes(), VECTOR_IDENTIFIER);
        assert_eq!(
            must!(master_key.derive_contents_key(nonce)).bytes(),
            &VECTOR_CONTENTS_KEY
        );
        assert_eq!(
            must!(master_key.derive_filenames_key(nonce)).bytes(),
            &VECTOR_FILENAMES_KEY
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_master_key_rejects_invalid_raw_key_sizes() {
        assert_eq!(
            FscryptMasterKey::from_raw(&[0_u8; 31]),
            Err(Error::InvalidEncryptionContext)
        );
        assert_eq!(
            FscryptMasterKey::from_raw(&[0_u8; 65]),
            Err(Error::InvalidEncryptionContext)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_key_set_is_sorted_unique_by_identifier() {
        let first = must!(FscryptMasterKey::from_raw(&[1_u8; 32]));
        let second = must!(FscryptMasterKey::from_raw(&[2_u8; 32]));
        let second_identifier = second.identifier();

        let set = must!(FscryptKeySet::from_keys(vec![second, first]));

        assert!(set.get(second_identifier).is_some());
        assert_eq!(set.keys().len(), 2);
        assert!(
            set.keys().windows(2).all(
                |pair| matches!(pair, [left, right] if left.identifier() < right.identifier())
            )
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_key_set_rejects_duplicate_identifiers() {
        let first = must!(FscryptMasterKey::from_raw(&[1_u8; 32]));
        let duplicate = must!(FscryptMasterKey::from_raw(&[1_u8; 32]));

        assert_eq!(
            FscryptKeySet::from_keys(vec![first, duplicate]),
            Err(Error::InvalidEncryptionContext)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_key_set_insert_and_remove_update_mount_state() {
        let first = must!(FscryptMasterKey::from_raw(&[1_u8; 32]));
        let duplicate = must!(FscryptMasterKey::from_raw(&[1_u8; 32]));
        let identifier = first.identifier();

        let mut set = FscryptKeySet::empty();
        must!(set.insert(first));

        assert!(set.contains(identifier));
        assert_eq!(set.insert(duplicate), Err(Error::InvalidEncryptionContext));
        assert!(set.remove(identifier).is_some());
        assert!(!set.contains(identifier));
        assert!(set.remove(identifier).is_none());
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_filename_key_encrypts_and_decrypts_padded_name() {
        let master_key = must!(FscryptMasterKey::from_raw(&VECTOR_MASTER_KEY));
        let key = must!(master_key.derive_filenames_key(FscryptFileNonce::new(VECTOR_NONCE)));

        let ciphertext = must!(key.encrypt_filename(b"secret.txt", FscryptFilenamePadding::Pad32));

        assert_eq!(ciphertext.len(), 32);
        assert_ne!(&ciphertext, b"secret.txt");
        assert_eq!(must!(key.decrypt_filename(&ciphertext)), b"secret.txt");
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_nokey_name_roundtrips_ciphertext_with_windows_safe_bytes() {
        let ciphertext = b"\x00\xff/opaque encrypted name";
        let name = must!(FscryptNoKeyName::from_ciphertext(ciphertext));
        let display = must!(name.display_bytes());

        assert!(display.starts_with(FSCRYPT_NOKEY_NAME_PREFIX));
        assert!(
            display
                .iter()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-') })
        );
        assert_eq!(
            some!(must!(FscryptNoKeyName::from_display(&display))).ciphertext_bytes(),
            ciphertext
        );
        assert_eq!(FscryptNoKeyName::from_display(b"plain"), Ok(None));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fscrypt_nokey_name_rejects_noncanonical_display() {
        assert_eq!(
            FscryptNoKeyName::from_display(b"_fscrypt_A"),
            Err(Error::InvalidName)
        );
        assert_eq!(
            FscryptNoKeyName::from_display(b"_fscrypt_A!"),
            Err(Error::InvalidName)
        );
        assert_eq!(
            FscryptNoKeyName::from_display(b"_fscrypt_AB"),
            Err(Error::InvalidName)
        );
    }

    /// Builds a supported fscrypt v2 policy byte image.
    fn valid_policy_bytes() -> [u8; FSCRYPT_POLICY_V2_BYTES] {
        let mut bytes = [0_u8; FSCRYPT_POLICY_V2_BYTES];
        bytes[FSCRYPT_VERSION_OFFSET] = FSCRYPT_POLICY_V2;
        bytes[FSCRYPT_CONTENTS_MODE_OFFSET] = FSCRYPT_MODE_AES_256_XTS;
        bytes[FSCRYPT_FILENAMES_MODE_OFFSET] = FSCRYPT_MODE_AES_256_CTS;
        bytes[FSCRYPT_FLAGS_OFFSET] = FscryptFilenamePadding::Pad32.flags();
        bytes[FSCRYPT_MASTER_KEY_IDENTIFIER_OFFSET
            ..FSCRYPT_MASTER_KEY_IDENTIFIER_OFFSET + FSCRYPT_KEY_IDENTIFIER_BYTES]
            .copy_from_slice(&[0x42; 16]);
        bytes
    }

    /// Builds a supported fscrypt v2 context byte image.
    fn valid_context_bytes() -> [u8; FSCRYPT_CONTEXT_V2_BYTES] {
        let mut bytes = [0_u8; FSCRYPT_CONTEXT_V2_BYTES];
        bytes[..FSCRYPT_POLICY_V2_BYTES].copy_from_slice(&valid_policy_bytes());
        bytes[FSCRYPT_NONCE_OFFSET..FSCRYPT_CONTEXT_V2_BYTES].copy_from_slice(&VECTOR_NONCE);
        bytes
    }
}
