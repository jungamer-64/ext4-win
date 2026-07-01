//! fs-verity descriptor and Merkle tree domain.

use alloc::{vec, vec::Vec};

use sha2::{Digest, Sha256, Sha512};

use crate::disk::block::BlockSize;
use crate::disk_format::inode::FileSize;
use crate::error::{Error, Result};

/// Serialized Linux `struct fsverity_descriptor` size without signature bytes.
pub const FSVERITY_DESCRIPTOR_BYTES: usize = 256;
/// Minimum fs-verity Merkle/data block size.
pub const FSVERITY_MIN_BLOCK_BYTES: u32 = 1024;
/// Maximum block size representable by the descriptor's log2 field in this domain.
pub const FSVERITY_MAX_BLOCK_BYTES: u32 = 65_536;
/// ext4 stores verity metadata after padding file data to a 64 KiB boundary.
pub const EXT4_VERITY_METADATA_ALIGNMENT_BYTES: u64 = 65_536;

/// Linux fs-verity descriptor version.
const FSVERITY_DESCRIPTOR_VERSION: u8 = 1;
/// Linux fs-verity SHA-256 algorithm id.
const FSVERITY_HASH_ALG_SHA256: u8 = 1;
/// Linux fs-verity SHA-512 algorithm id.
const FSVERITY_HASH_ALG_SHA512: u8 = 2;
/// Maximum fs-verity digest bytes stored in descriptor fields.
const FSVERITY_MAX_DIGEST_BYTES: usize = 64;
/// Maximum fs-verity salt bytes stored in descriptor fields.
const FSVERITY_MAX_SALT_BYTES: usize = 32;
/// Maximum builtin signature bytes accepted by Linux fs-verity UAPI.
pub const FSVERITY_MAX_SIGNATURE_BYTES: usize = 16_128;
/// Offset of descriptor version.
const DESCRIPTOR_VERSION_OFFSET: usize = 0;
/// Offset of descriptor hash algorithm.
const DESCRIPTOR_HASH_ALGORITHM_OFFSET: usize = 1;
/// Offset of descriptor log2 block size.
const DESCRIPTOR_LOG_BLOCKSIZE_OFFSET: usize = 2;
/// Offset of descriptor salt size.
const DESCRIPTOR_SALT_SIZE_OFFSET: usize = 3;
/// Offset of descriptor reserved word at 0x04.
const DESCRIPTOR_RESERVED_0X04_OFFSET: usize = 4;
/// Offset of descriptor data size.
const DESCRIPTOR_DATA_SIZE_OFFSET: usize = 8;
/// Offset of descriptor root hash bytes.
const DESCRIPTOR_ROOT_HASH_OFFSET: usize = 16;
/// Offset of descriptor salt bytes.
const DESCRIPTOR_SALT_OFFSET: usize = 80;
/// Offset of descriptor trailing reserved bytes.
const DESCRIPTOR_RESERVED_OFFSET: usize = 112;
/// Size of descriptor trailing reserved bytes.
const DESCRIPTOR_RESERVED_BYTES: usize = 144;

/// ext4 post-EOF fs-verity metadata layout for one inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4VerityMetadataLayout {
    /// Byte offset where the Merkle tree starts in the inode payload stream.
    merkle_tree_offset: u64,
    /// Serialized Merkle tree byte count.
    merkle_tree_bytes: u64,
    /// Byte offset where the descriptor plus optional signature starts.
    descriptor_offset: u64,
    /// Descriptor plus optional signature byte count.
    descriptor_bytes: u32,
    /// Byte offset of the little-endian descriptor-size tail.
    descriptor_size_offset: u64,
    /// First byte after all ext4 verity metadata.
    metadata_end: u64,
}

impl Ext4VerityMetadataLayout {
    /// Computes the ext4 post-EOF fs-verity metadata layout.
    ///
    /// # Errors
    /// Returns an error when sizes overflow or descriptor bytes cannot contain
    /// the fixed Linux `fsverity_descriptor`.
    pub fn new(
        file_size: FileSize,
        filesystem_block_size: BlockSize,
        merkle_tree_bytes: u64,
        descriptor_bytes: u32,
    ) -> Result<Self> {
        if usize::try_from(descriptor_bytes).map_err(|_| Error::ArithmeticOverflow)?
            < FSVERITY_DESCRIPTOR_BYTES
        {
            return Err(Error::InvalidVerityMetadata);
        }
        let merkle_tree_offset =
            align_up_u64(file_size.bytes(), EXT4_VERITY_METADATA_ALIGNMENT_BYTES)?;
        let tree_end = merkle_tree_offset
            .checked_add(merkle_tree_bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        let descriptor_offset = align_up_u64(tree_end, u64::from(filesystem_block_size.bytes()))?;
        let descriptor_end = descriptor_offset
            .checked_add(u64::from(descriptor_bytes))
            .ok_or(Error::ArithmeticOverflow)?;
        let descriptor_size_offset = align_up_u64(
            descriptor_end
                .checked_add(4)
                .ok_or(Error::ArithmeticOverflow)?,
            u64::from(filesystem_block_size.bytes()),
        )?
        .checked_sub(4)
        .ok_or(Error::ArithmeticOverflow)?;
        let metadata_end = descriptor_size_offset
            .checked_add(4)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Self {
            merkle_tree_offset,
            merkle_tree_bytes,
            descriptor_offset,
            descriptor_bytes,
            descriptor_size_offset,
            metadata_end,
        })
    }

    /// Computes the descriptor offset when only the ext4 metadata end and
    /// descriptor-size tail are known.
    ///
    /// # Errors
    /// Returns an error when the descriptor cannot contain a Linux
    /// `fsverity_descriptor` or the slot arithmetic underflows.
    pub fn descriptor_offset_from_metadata_end(
        filesystem_block_size: BlockSize,
        metadata_end: u64,
        descriptor_bytes: u32,
    ) -> Result<u64> {
        if usize::try_from(descriptor_bytes).map_err(|_| Error::ArithmeticOverflow)?
            < FSVERITY_DESCRIPTOR_BYTES
        {
            return Err(Error::InvalidVerityMetadata);
        }
        let slot_bytes = align_up_u64(
            u64::from(descriptor_bytes)
                .checked_add(4)
                .ok_or(Error::ArithmeticOverflow)?,
            u64::from(filesystem_block_size.bytes()),
        )?;
        metadata_end
            .checked_sub(slot_bytes)
            .ok_or(Error::InvalidVerityMetadata)
    }

    /// Reconstructs and validates the ext4 metadata layout after the descriptor
    /// has been parsed.
    ///
    /// # Errors
    /// Returns an error when descriptor-derived Merkle tree size does not place
    /// the metadata end at the supplied inode payload end.
    pub fn from_metadata_end(
        file_size: FileSize,
        filesystem_block_size: BlockSize,
        metadata_end: u64,
        descriptor_bytes: u32,
        descriptor: &FsverityDescriptor,
    ) -> Result<Self> {
        if descriptor.data_size() != file_size.bytes() {
            return Err(Error::InvalidVerityMetadata);
        }
        let merkle_tree_bytes = FsverityMerkleTree::stored_tree_bytes_for_descriptor(descriptor)?;
        let layout = Self::new(
            file_size,
            filesystem_block_size,
            merkle_tree_bytes,
            descriptor_bytes,
        )?;
        if layout.metadata_end != metadata_end {
            return Err(Error::InvalidVerityMetadata);
        }
        Ok(layout)
    }

    /// Merkle tree byte offset.
    #[must_use]
    pub const fn merkle_tree_offset(self) -> u64 {
        self.merkle_tree_offset
    }

    /// Merkle tree byte count.
    #[must_use]
    pub const fn merkle_tree_bytes(self) -> u64 {
        self.merkle_tree_bytes
    }

    /// Descriptor byte offset.
    #[must_use]
    pub const fn descriptor_offset(self) -> u64 {
        self.descriptor_offset
    }

    /// Descriptor plus optional signature byte count.
    #[must_use]
    pub const fn descriptor_bytes(self) -> u32 {
        self.descriptor_bytes
    }

    /// Descriptor-size tail byte offset.
    #[must_use]
    pub const fn descriptor_size_offset(self) -> u64 {
        self.descriptor_size_offset
    }

    /// First byte after all verity metadata.
    #[must_use]
    pub const fn metadata_end(self) -> u64 {
        self.metadata_end
    }
}

/// Parsed ext4 post-EOF fs-verity metadata for one inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ext4VerityMetadata {
    /// Validated byte layout in the inode payload stream.
    layout: Ext4VerityMetadataLayout,
    /// Linux fs-verity descriptor.
    descriptor: FsverityDescriptor,
    /// Optional builtin signature bytes after the fixed descriptor.
    signature: Vec<u8>,
    /// Stored Merkle tree bytes in ext4 root-to-leaf order.
    merkle_tree: FsverityMerkleTree,
}

impl Ext4VerityMetadata {
    /// Creates parsed ext4 verity metadata from already-located inode payload
    /// slices.
    ///
    /// # Errors
    /// Returns an error when descriptor/signature sizes do not match the layout
    /// or the stored Merkle tree size is inconsistent with the descriptor.
    pub fn new(
        layout: Ext4VerityMetadataLayout,
        descriptor: FsverityDescriptor,
        signature: Vec<u8>,
        merkle_tree_bytes: Vec<u8>,
    ) -> Result<Self> {
        let descriptor_with_signature = u32::try_from(
            FSVERITY_DESCRIPTOR_BYTES
                .checked_add(signature.len())
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .map_err(|_| Error::ArithmeticOverflow)?;
        if descriptor_with_signature != layout.descriptor_bytes() {
            return Err(Error::InvalidVerityMetadata);
        }
        if u64::try_from(merkle_tree_bytes.len()).map_err(|_| Error::ArithmeticOverflow)?
            != layout.merkle_tree_bytes()
        {
            return Err(Error::InvalidVerityMetadata);
        }
        let merkle_tree = FsverityMerkleTree::from_stored_blocks(&descriptor, merkle_tree_bytes)?;
        Ok(Self {
            layout,
            descriptor,
            signature,
            merkle_tree,
        })
    }

    /// Linux fs-verity descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &FsverityDescriptor {
        &self.descriptor
    }

    /// Stored Merkle tree.
    #[must_use]
    pub const fn merkle_tree(&self) -> &FsverityMerkleTree {
        &self.merkle_tree
    }
}
/// fs-verity hash algorithm accepted by this driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsverityHashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl FsverityHashAlgorithm {
    /// Parses a Linux fs-verity hash algorithm id.
    pub(crate) const fn parse_u8(value: u8) -> Result<Self> {
        match value {
            FSVERITY_HASH_ALG_SHA256 => Ok(Self::Sha256),
            FSVERITY_HASH_ALG_SHA512 => Ok(Self::Sha512),
            _ => Err(Error::InvalidVerityMetadata),
        }
    }

    /// Parses a Linux fs-verity hash algorithm id widened by an ioctl payload.
    ///
    /// # Errors
    /// Returns an error when the algorithm id is not in the supported fs-verity
    /// SHA-256/SHA-512 domain.
    pub const fn parse_u32(value: u32) -> Result<Self> {
        match value {
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha512),
            _ => Err(Error::InvalidVerityMetadata),
        }
    }

    /// Returns the Linux fs-verity hash algorithm id.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Sha256 => FSVERITY_HASH_ALG_SHA256,
            Self::Sha512 => FSVERITY_HASH_ALG_SHA512,
        }
    }

    /// Returns digest length in bytes.
    #[must_use]
    pub const fn digest_bytes(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Returns the hash compression-function input size in bytes.
    const fn compression_input_bytes(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }
}

/// Power-of-two fs-verity Merkle/data block size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsverityBlockSize {
    /// Block size in bytes.
    bytes: u32,
    /// Base-2 logarithm stored in the descriptor.
    log2: u8,
}

impl FsverityBlockSize {
    /// Creates a validated fs-verity block size.
    ///
    /// # Errors
    /// Returns an error when the block size is not a supported power of two.
    pub fn new(bytes: u32) -> Result<Self> {
        if !bytes.is_power_of_two()
            || !(FSVERITY_MIN_BLOCK_BYTES..=FSVERITY_MAX_BLOCK_BYTES).contains(&bytes)
        {
            return Err(Error::InvalidVerityMetadata);
        }
        Ok(Self {
            bytes,
            log2: u8::try_from(bytes.trailing_zeros()).map_err(|_| Error::ArithmeticOverflow)?,
        })
    }

    /// Creates a block size from the descriptor log2 field.
    ///
    /// # Errors
    /// Returns an error when the log2 value is outside this domain.
    pub fn from_log2(log2: u8) -> Result<Self> {
        let bytes = 1_u32
            .checked_shl(u32::from(log2))
            .ok_or(Error::InvalidVerityMetadata)?;
        Self::new(bytes)
    }

    /// Returns the block size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.bytes
    }

    /// Returns the block size as a host `usize`.
    ///
    /// # Errors
    /// Returns an error when the block size is not representable as `usize`.
    pub fn to_usize(self) -> Result<usize> {
        usize::try_from(self.bytes).map_err(|_| Error::ArithmeticOverflow)
    }

    /// Returns the descriptor log2 value.
    #[must_use]
    pub const fn log2(self) -> u8 {
        self.log2
    }
}

/// fs-verity salt bytes used before every data or tree block hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsveritySalt {
    /// Salt bytes.
    bytes: Vec<u8>,
}

impl FsveritySalt {
    /// Creates a validated fs-verity salt.
    ///
    /// # Errors
    /// Returns an error when the salt exceeds the Linux descriptor capacity.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > FSVERITY_MAX_SALT_BYTES {
            return Err(Error::InvalidVerityMetadata);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Creates an empty fs-verity salt.
    #[must_use]
    pub fn empty() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Returns raw salt bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns true when no salt is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Optional builtin fs-verity signature bytes stored after the descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsveritySignature {
    /// Signature bytes.
    bytes: Vec<u8>,
}

impl FsveritySignature {
    /// Creates validated signature bytes.
    ///
    /// # Errors
    /// Returns an error when the signature exceeds the Linux fs-verity limit.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > FSVERITY_MAX_SIGNATURE_BYTES {
            return Err(Error::InvalidVerityMetadata);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Creates an empty signature.
    #[must_use]
    pub fn empty() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Signature bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes this signature into raw bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

/// Parameters for generating fs-verity metadata for a regular file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsverityEnable {
    /// Hash algorithm.
    algorithm: FsverityHashAlgorithm,
    /// Data and Merkle tree block size.
    block_size: FsverityBlockSize,
    /// Merkle tree salt.
    salt: FsveritySalt,
    /// Optional builtin signature bytes.
    signature: FsveritySignature,
}

impl FsverityEnable {
    /// Creates an fs-verity enable request from validated components.
    #[must_use]
    pub fn new(
        algorithm: FsverityHashAlgorithm,
        block_size: FsverityBlockSize,
        salt: FsveritySalt,
        signature: FsveritySignature,
    ) -> Self {
        Self {
            algorithm,
            block_size,
            salt,
            signature,
        }
    }

    /// Hash algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> FsverityHashAlgorithm {
        self.algorithm
    }

    /// Data and Merkle tree block size.
    #[must_use]
    pub const fn block_size(&self) -> FsverityBlockSize {
        self.block_size
    }

    /// Merkle tree salt.
    #[must_use]
    pub const fn salt(&self) -> &FsveritySalt {
        &self.salt
    }

    /// Optional builtin signature.
    #[must_use]
    pub const fn signature(&self) -> &FsveritySignature {
        &self.signature
    }
}

/// fs-verity digest bytes tied to their hash algorithm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsverityDigest {
    /// Algorithm that produced this digest.
    algorithm: FsverityHashAlgorithm,
    /// Digest bytes.
    bytes: Vec<u8>,
}

impl FsverityDigest {
    /// Creates a digest after checking the length required by the algorithm.
    ///
    /// # Errors
    /// Returns an error when the digest length does not match the algorithm.
    pub fn new(algorithm: FsverityHashAlgorithm, bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != algorithm.digest_bytes() {
            return Err(Error::InvalidVerityMetadata);
        }
        Ok(Self { algorithm, bytes })
    }

    /// Algorithm that produced this digest.
    #[must_use]
    pub const fn algorithm(&self) -> FsverityHashAlgorithm {
        self.algorithm
    }

    /// Raw digest bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Root hash field stored in an fs-verity descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsverityRootHash {
    /// Fixed descriptor field; unused suffix bytes are zero.
    bytes: [u8; FSVERITY_MAX_DIGEST_BYTES],
}

impl FsverityRootHash {
    /// Creates a descriptor root hash from an algorithm digest.
    ///
    /// # Errors
    /// Returns an error when the digest length does not match the algorithm.
    pub fn from_digest(digest: &FsverityDigest) -> Result<Self> {
        let mut bytes = [0_u8; FSVERITY_MAX_DIGEST_BYTES];
        let target = bytes
            .get_mut(..digest.bytes().len())
            .ok_or(Error::InvalidVerityMetadata)?;
        target.copy_from_slice(digest.bytes());
        Ok(Self { bytes })
    }

    /// Creates an all-zero root hash for an empty file.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            bytes: [0_u8; FSVERITY_MAX_DIGEST_BYTES],
        }
    }

    /// Parses and validates the fixed descriptor root-hash field.
    fn parse(
        algorithm: FsverityHashAlgorithm,
        bytes: [u8; FSVERITY_MAX_DIGEST_BYTES],
    ) -> Result<Self> {
        let digest_bytes = algorithm.digest_bytes();
        if bytes
            .get(digest_bytes..)
            .ok_or(Error::InvalidVerityMetadata)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(Error::InvalidVerityMetadata);
        }
        Ok(Self { bytes })
    }

    /// Returns the fixed 64-byte descriptor field.
    #[must_use]
    pub const fn descriptor_bytes(self) -> [u8; FSVERITY_MAX_DIGEST_BYTES] {
        self.bytes
    }

    /// Returns the digest-length prefix for the given algorithm.
    ///
    /// # Errors
    /// Returns an error when the root hash does not contain the requested
    /// algorithm's digest length.
    pub fn digest_bytes(&self, algorithm: FsverityHashAlgorithm) -> Result<&[u8]> {
        self.bytes
            .get(..algorithm.digest_bytes())
            .ok_or(Error::InvalidVerityMetadata)
    }
}

/// Validated fs-verity descriptor without the optional signature blob.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsverityDescriptor {
    /// Hash algorithm.
    algorithm: FsverityHashAlgorithm,
    /// Merkle/data block size.
    block_size: FsverityBlockSize,
    /// Size of the file data covered by the Merkle tree.
    data_size: u64,
    /// Root hash of the Merkle tree.
    root_hash: FsverityRootHash,
    /// Salt used by the Merkle tree.
    salt: FsveritySalt,
}

impl FsverityDescriptor {
    /// Creates a descriptor from validated components.
    ///
    /// # Errors
    /// Returns an error when the salt or root hash are incompatible with the
    /// requested algorithm.
    pub fn new(
        algorithm: FsverityHashAlgorithm,
        block_size: FsverityBlockSize,
        data_size: u64,
        root_hash: FsverityRootHash,
        salt: FsveritySalt,
    ) -> Result<Self> {
        let _root_prefix = root_hash.digest_bytes(algorithm)?;
        Ok(Self {
            algorithm,
            block_size,
            data_size,
            root_hash,
            salt,
        })
    }

    /// Parses a Linux `struct fsverity_descriptor` byte image.
    ///
    /// # Errors
    /// Returns an error when the descriptor is malformed or unsupported.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        require_exact_len(bytes, FSVERITY_DESCRIPTOR_BYTES)?;
        if byte(bytes, DESCRIPTOR_VERSION_OFFSET)? != FSVERITY_DESCRIPTOR_VERSION {
            return Err(Error::InvalidVerityMetadata);
        }
        let algorithm =
            FsverityHashAlgorithm::parse_u8(byte(bytes, DESCRIPTOR_HASH_ALGORITHM_OFFSET)?)?;
        let block_size =
            FsverityBlockSize::from_log2(byte(bytes, DESCRIPTOR_LOG_BLOCKSIZE_OFFSET)?)?;
        let salt_size = usize::from(byte(bytes, DESCRIPTOR_SALT_SIZE_OFFSET)?);
        if salt_size > FSVERITY_MAX_SALT_BYTES {
            return Err(Error::InvalidVerityMetadata);
        }
        if le_u32(bytes, DESCRIPTOR_RESERVED_0X04_OFFSET)? != 0 {
            return Err(Error::InvalidVerityMetadata);
        }
        let data_size = le_u64(bytes, DESCRIPTOR_DATA_SIZE_OFFSET)?;
        let root_hash =
            FsverityRootHash::parse(algorithm, fixed(bytes, DESCRIPTOR_ROOT_HASH_OFFSET)?)?;
        let salt = parse_salt(bytes, salt_size)?;
        if fixed::<DESCRIPTOR_RESERVED_BYTES>(bytes, DESCRIPTOR_RESERVED_OFFSET)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(Error::InvalidVerityMetadata);
        }
        Self::new(algorithm, block_size, data_size, root_hash, salt)
    }

    /// Serializes the descriptor in Linux `struct fsverity_descriptor` layout.
    ///
    /// # Errors
    /// Returns an error when a field cannot fit the fixed descriptor layout.
    pub fn to_bytes(&self) -> Result<[u8; FSVERITY_DESCRIPTOR_BYTES]> {
        let mut bytes = [0_u8; FSVERITY_DESCRIPTOR_BYTES];
        set_byte(
            &mut bytes,
            DESCRIPTOR_VERSION_OFFSET,
            FSVERITY_DESCRIPTOR_VERSION,
        )?;
        set_byte(
            &mut bytes,
            DESCRIPTOR_HASH_ALGORITHM_OFFSET,
            self.algorithm.id(),
        )?;
        set_byte(
            &mut bytes,
            DESCRIPTOR_LOG_BLOCKSIZE_OFFSET,
            self.block_size.log2(),
        )?;
        set_byte(
            &mut bytes,
            DESCRIPTOR_SALT_SIZE_OFFSET,
            u8::try_from(self.salt.bytes().len()).map_err(|_| Error::InvalidVerityMetadata)?,
        )?;
        put_le_u64(&mut bytes, DESCRIPTOR_DATA_SIZE_OFFSET, self.data_size)?;
        copy_into(
            &mut bytes,
            DESCRIPTOR_ROOT_HASH_OFFSET,
            &self.root_hash.descriptor_bytes(),
        )?;
        copy_into(&mut bytes, DESCRIPTOR_SALT_OFFSET, self.salt.bytes())?;
        Ok(bytes)
    }

    /// Hash algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> FsverityHashAlgorithm {
        self.algorithm
    }

    /// Merkle/data block size.
    #[must_use]
    pub const fn block_size(&self) -> FsverityBlockSize {
        self.block_size
    }

    /// Covered file data size.
    #[must_use]
    pub const fn data_size(&self) -> u64 {
        self.data_size
    }

    /// Merkle tree root hash.
    #[must_use]
    pub const fn root_hash(&self) -> FsverityRootHash {
        self.root_hash
    }

    /// Salt used by the Merkle tree.
    #[must_use]
    pub const fn salt(&self) -> &FsveritySalt {
        &self.salt
    }
}

/// Merkle tree metadata in ext4 storage order, root level before leaf level.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsverityMerkleTree {
    /// Hash algorithm.
    algorithm: FsverityHashAlgorithm,
    /// Merkle/data block size.
    block_size: FsverityBlockSize,
    /// Root hash produced by the tree.
    root_hash: FsverityRootHash,
    /// Serialized tree blocks in ext4 root-to-leaf order.
    blocks: Vec<u8>,
}

impl FsverityMerkleTree {
    /// Builds an fs-verity Merkle tree over plaintext file data.
    ///
    /// # Errors
    /// Returns an error when the block geometry overflows host arithmetic.
    pub fn build(
        data: &[u8],
        algorithm: FsverityHashAlgorithm,
        block_size: FsverityBlockSize,
        salt: &FsveritySalt,
    ) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self {
                algorithm,
                block_size,
                root_hash: FsverityRootHash::zero(),
                blocks: Vec::new(),
            });
        }

        let block_bytes = block_size.to_usize()?;
        let mut hashes = hash_data_blocks(data, algorithm, block_bytes, salt)?;
        let mut levels = Vec::new();
        while hashes.len() > 1 {
            let (level_blocks, parent_hashes) = hash_level(&hashes, algorithm, block_bytes, salt)?;
            levels.push(level_blocks);
            hashes = parent_hashes;
        }
        let root_digest = hashes.pop().ok_or(Error::InvalidVerityMetadata)?;
        levels.reverse();
        let mut blocks = Vec::new();
        for level in levels {
            blocks.extend_from_slice(&level);
        }
        Ok(Self {
            algorithm,
            block_size,
            root_hash: FsverityRootHash::from_digest(&root_digest)?,
            blocks,
        })
    }

    /// Creates a stored Merkle tree image already read from ext4 post-EOF
    /// metadata.
    ///
    /// # Errors
    /// Returns an error when the stored tree byte count does not match the
    /// descriptor's data size, hash algorithm, and Merkle block geometry.
    pub fn from_stored_blocks(descriptor: &FsverityDescriptor, blocks: Vec<u8>) -> Result<Self> {
        if u64::try_from(blocks.len()).map_err(|_| Error::ArithmeticOverflow)?
            != Self::stored_tree_bytes_for_descriptor(descriptor)?
        {
            return Err(Error::InvalidVerityMetadata);
        }
        Ok(Self {
            algorithm: descriptor.algorithm(),
            block_size: descriptor.block_size(),
            root_hash: descriptor.root_hash(),
            blocks,
        })
    }

    /// Returns the serialized Merkle tree byte count implied by a descriptor.
    ///
    /// # Errors
    /// Returns an error when the descriptor geometry overflows arithmetic.
    pub fn stored_tree_bytes_for_descriptor(descriptor: &FsverityDescriptor) -> Result<u64> {
        stored_tree_bytes_for_data_size(
            descriptor.algorithm(),
            descriptor.block_size(),
            descriptor.data_size(),
        )
    }

    /// Verifies plaintext file data against a descriptor and stored tree bytes.
    ///
    /// # Errors
    /// Returns `VerityMismatch` when either the data root hash or stored tree
    /// bytes do not match the descriptor.
    pub fn verify_data(&self, data: &[u8], descriptor: &FsverityDescriptor) -> Result<()> {
        if self.algorithm != descriptor.algorithm()
            || self.block_size != descriptor.block_size()
            || u64::try_from(data.len()).map_err(|_| Error::ArithmeticOverflow)?
                != descriptor.data_size()
        {
            return Err(Error::VerityMismatch);
        }
        let rebuilt = Self::build(
            data,
            descriptor.algorithm(),
            descriptor.block_size(),
            descriptor.salt(),
        )?;
        if rebuilt.root_hash != descriptor.root_hash() || rebuilt.blocks != self.blocks {
            return Err(Error::VerityMismatch);
        }
        Ok(())
    }

    /// Root hash produced by this tree.
    #[must_use]
    pub const fn root_hash(&self) -> FsverityRootHash {
        self.root_hash
    }

    /// Serialized tree bytes in ext4 root-to-leaf order.
    #[must_use]
    pub fn blocks(&self) -> &[u8] {
        &self.blocks
    }
}

/// Computes the serialized Merkle tree byte count for one file.
fn stored_tree_bytes_for_data_size(
    algorithm: FsverityHashAlgorithm,
    block_size: FsverityBlockSize,
    data_size: u64,
) -> Result<u64> {
    if data_size == 0 {
        return Ok(0);
    }
    let block_bytes = u64::from(block_size.bytes());
    let digest_bytes =
        u64::try_from(algorithm.digest_bytes()).map_err(|_| Error::ArithmeticOverflow)?;
    let mut hash_count = round_up_div_u64(data_size, block_bytes)?;
    let mut tree_bytes = 0_u64;
    while hash_count > 1 {
        let level_input_bytes = hash_count
            .checked_mul(digest_bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        let level_blocks = round_up_div_u64(level_input_bytes, block_bytes)?;
        tree_bytes = tree_bytes
            .checked_add(
                level_blocks
                    .checked_mul(block_bytes)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        hash_count = level_blocks;
    }
    Ok(tree_bytes)
}

/// Parses salt and requires unused descriptor salt bytes to be zero.
fn parse_salt(bytes: &[u8], salt_size: usize) -> Result<FsveritySalt> {
    let salt_end = DESCRIPTOR_SALT_OFFSET
        .checked_add(salt_size)
        .ok_or(Error::ArithmeticOverflow)?;
    let salt = bytes
        .get(DESCRIPTOR_SALT_OFFSET..salt_end)
        .ok_or(Error::TruncatedStructure)?;
    let salt_field_end = DESCRIPTOR_SALT_OFFSET
        .checked_add(FSVERITY_MAX_SALT_BYTES)
        .ok_or(Error::ArithmeticOverflow)?;
    if bytes
        .get(salt_end..salt_field_end)
        .ok_or(Error::TruncatedStructure)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::InvalidVerityMetadata);
    }
    FsveritySalt::new(salt)
}

/// Aligns an offset upward to a positive byte boundary.
fn align_up_u64(value: u64, alignment: u64) -> Result<u64> {
    if alignment == 0 {
        return Err(Error::ArithmeticOverflow);
    }
    let remainder = value
        .checked_rem(alignment)
        .ok_or(Error::ArithmeticOverflow)?;
    if remainder == 0 {
        return Ok(value);
    }
    let delta = alignment
        .checked_sub(remainder)
        .ok_or(Error::ArithmeticOverflow)?;
    value.checked_add(delta).ok_or(Error::ArithmeticOverflow)
}

/// Divides and rounds up without accepting a zero divisor.
fn round_up_div_u64(value: u64, divisor: u64) -> Result<u64> {
    if divisor == 0 {
        return Err(Error::ArithmeticOverflow);
    }
    let delta = divisor.checked_sub(1).ok_or(Error::ArithmeticOverflow)?;
    let adjusted = value.checked_add(delta).ok_or(Error::ArithmeticOverflow)?;
    adjusted
        .checked_div(divisor)
        .ok_or(Error::ArithmeticOverflow)
}

/// Hashes every data block, padding the final block with zeroes.
fn hash_data_blocks(
    data: &[u8],
    algorithm: FsverityHashAlgorithm,
    block_bytes: usize,
    salt: &FsveritySalt,
) -> Result<Vec<FsverityDigest>> {
    let mut hashes = Vec::new();
    for chunk in data.chunks(block_bytes) {
        let mut block = vec![0_u8; block_bytes];
        block
            .get_mut(..chunk.len())
            .ok_or(Error::InvalidVerityMetadata)?
            .copy_from_slice(chunk);
        hashes.push(hash_block(algorithm, salt, &block)?);
    }
    Ok(hashes)
}

/// Hashes one Merkle level into parent hashes.
fn hash_level(
    hashes: &[FsverityDigest],
    algorithm: FsverityHashAlgorithm,
    block_bytes: usize,
    salt: &FsveritySalt,
) -> Result<(Vec<u8>, Vec<FsverityDigest>)> {
    let digest_bytes = algorithm.digest_bytes();
    let hashes_per_block = block_bytes
        .checked_div(digest_bytes)
        .ok_or(Error::ArithmeticOverflow)?;
    if hashes_per_block == 0 {
        return Err(Error::InvalidVerityMetadata);
    }
    let mut level_blocks = Vec::new();
    let mut parent_hashes = Vec::new();
    for hash_group in hashes.chunks(hashes_per_block) {
        let mut block = vec![0_u8; block_bytes];
        for (index, hash) in hash_group.iter().enumerate() {
            if hash.algorithm() != algorithm {
                return Err(Error::InvalidVerityMetadata);
            }
            let offset = index
                .checked_mul(digest_bytes)
                .ok_or(Error::ArithmeticOverflow)?;
            copy_into(&mut block, offset, hash.bytes())?;
        }
        parent_hashes.push(hash_block(algorithm, salt, &block)?);
        level_blocks.extend_from_slice(&block);
    }
    Ok((level_blocks, parent_hashes))
}

/// Hashes one fs-verity data or Merkle block with padded salt.
fn hash_block(
    algorithm: FsverityHashAlgorithm,
    salt: &FsveritySalt,
    block: &[u8],
) -> Result<FsverityDigest> {
    let mut input = Vec::new();
    if !salt.is_empty() {
        let padded_salt_bytes = algorithm.compression_input_bytes();
        input.resize(padded_salt_bytes, 0);
        input
            .get_mut(..salt.bytes().len())
            .ok_or(Error::InvalidVerityMetadata)?
            .copy_from_slice(salt.bytes());
    }
    input.extend_from_slice(block);
    FsverityDigest::new(algorithm, hash_bytes(algorithm, &input))
}

/// Hashes an arbitrary byte slice with the selected algorithm.
fn hash_bytes(algorithm: FsverityHashAlgorithm, bytes: &[u8]) -> Vec<u8> {
    match algorithm {
        FsverityHashAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
        FsverityHashAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
    }
}

/// Requires an exact serialized structure length.
fn require_exact_len(bytes: &[u8], expected: usize) -> Result<()> {
    match bytes.len().cmp(&expected) {
        core::cmp::Ordering::Less => Err(Error::TruncatedStructure),
        core::cmp::Ordering::Equal => Ok(()),
        core::cmp::Ordering::Greater => Err(Error::InvalidVerityMetadata),
    }
}

/// Reads one byte from a checked offset.
fn byte(bytes: &[u8], offset: usize) -> Result<u8> {
    bytes.get(offset).copied().ok_or(Error::TruncatedStructure)
}

/// Reads a little-endian `u32` at a checked offset.
fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(fixed(bytes, offset)?))
}

/// Reads a little-endian `u64` at a checked offset.
fn le_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(fixed(bytes, offset)?))
}

/// Writes a little-endian `u64` at a checked offset.
fn put_le_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    copy_into(bytes, offset, &value.to_le_bytes())
}

/// Writes one byte at a checked offset.
fn set_byte(bytes: &mut [u8], offset: usize, value: u8) -> Result<()> {
    let target = bytes.get_mut(offset).ok_or(Error::TruncatedStructure)?;
    *target = value;
    Ok(())
}

/// Copies a fixed byte array from a checked offset.
fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(Error::ArithmeticOverflow)?;
    let slice = bytes.get(offset..end).ok_or(Error::TruncatedStructure)?;
    let mut output = [0_u8; N];
    output.copy_from_slice(slice);
    Ok(output)
}

/// Copies source bytes into a checked destination offset.
fn copy_into(target: &mut [u8], offset: usize, source: &[u8]) -> Result<()> {
    let end = offset
        .checked_add(source.len())
        .ok_or(Error::ArithmeticOverflow)?;
    target
        .get_mut(offset..end)
        .ok_or(Error::TruncatedStructure)?
        .copy_from_slice(source);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Salt used by fs-verity vector tests.
    const VECTOR_SALT: [u8; 3] = [1, 2, 3];
    /// Expected SHA-256 root hash for `hello world`, 1024-byte block, salt 010203.
    const SMALL_SHA256_ROOT: [u8; 32] = [
        0x79, 0x75, 0x77, 0xb8, 0xb6, 0xdc, 0x80, 0x3f, 0xca, 0xb3, 0x6d, 0x85, 0x17, 0x03, 0xee,
        0x04, 0x5b, 0xe0, 0x1a, 0x28, 0x68, 0x30, 0x40, 0x13, 0x80, 0xc6, 0x96, 0xee, 0x9b, 0x58,
        0x98, 0x84,
    ];
    /// Expected SHA-256 root hash for the multi-block vector.
    const LARGE_SHA256_ROOT: [u8; 32] = [
        0xf9, 0x23, 0xae, 0x67, 0x3b, 0x4f, 0xb5, 0x21, 0xc4, 0x5a, 0xb4, 0xc2, 0xfe, 0xea, 0x57,
        0x8e, 0xbd, 0x6a, 0xcf, 0x44, 0x9c, 0x5f, 0xe5, 0xa1, 0x0c, 0x7f, 0x3e, 0x80, 0x36, 0x36,
        0x98, 0xef,
    ];
    /// First two leaf hashes in the multi-block tree.
    const LARGE_TREE_FIRST_64: [u8; 64] = [
        0x39, 0x10, 0xb8, 0xaf, 0x79, 0xe8, 0x2b, 0xb3, 0xee, 0xd8, 0xc0, 0x75, 0xbd, 0x86, 0xa0,
        0xf7, 0x16, 0xb5, 0x0e, 0x04, 0x49, 0xb5, 0x62, 0x05, 0x30, 0xf6, 0xdf, 0xca, 0xa1, 0x3a,
        0xc2, 0x5b, 0x39, 0x10, 0xb8, 0xaf, 0x79, 0xe8, 0x2b, 0xb3, 0xee, 0xd8, 0xc0, 0x75, 0xbd,
        0x86, 0xa0, 0xf7, 0x16, 0xb5, 0x0e, 0x04, 0x49, 0xb5, 0x62, 0x05, 0x30, 0xf6, 0xdf, 0xca,
        0xa1, 0x3a, 0xc2, 0x5b,
    ];

    macro_rules! must {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(error) => {
                    let unexpected_error: Option<()> = None;
                    assert!(
                        unexpected_error.is_some(),
                        "unexpected verity error: {error:?}"
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
                    assert!(missing_value.is_some(), "missing verity test value");
                    return;
                }
            }
        };
    }

    #[test]
    fn ext4_verity_metadata_layout_places_descriptor_size_tail() {
        let layout = must!(Ext4VerityMetadataLayout::new(
            FileSize::from_bytes(1),
            must!(BlockSize::from_superblock_log(2)),
            8192,
            must!(
                u32::try_from(FSVERITY_DESCRIPTOR_BYTES + 16)
                    .map_err(|_| Error::ArithmeticOverflow)
            ),
        ));

        assert_eq!(layout.merkle_tree_offset(), 65_536);
        assert_eq!(layout.merkle_tree_bytes(), 8192);
        assert_eq!(layout.descriptor_offset(), 73_728);
        assert_eq!(layout.descriptor_bytes(), 272);
        assert_eq!(layout.descriptor_size_offset(), 77_820);
        assert_eq!(layout.metadata_end(), 77_824);
    }

    #[test]
    fn ext4_verity_metadata_layout_rejects_bad_descriptor_and_overflow() {
        assert_eq!(
            Ext4VerityMetadataLayout::new(
                FileSize::from_bytes(0),
                must!(BlockSize::from_superblock_log(0)),
                0,
                must!(
                    u32::try_from(FSVERITY_DESCRIPTOR_BYTES - 1)
                        .map_err(|_| Error::ArithmeticOverflow)
                ),
            ),
            Err(Error::InvalidVerityMetadata)
        );
        assert_eq!(
            Ext4VerityMetadataLayout::new(
                FileSize::from_bytes(u64::MAX),
                must!(BlockSize::from_superblock_log(0)),
                0,
                must!(
                    u32::try_from(FSVERITY_DESCRIPTOR_BYTES).map_err(|_| Error::ArithmeticOverflow)
                ),
            ),
            Err(Error::ArithmeticOverflow)
        );
    }

    #[test]
    fn fsverity_descriptor_round_trips_supported_layout() {
        let descriptor = must!(small_descriptor());
        let bytes = must!(descriptor.to_bytes());

        assert_eq!(FsverityDescriptor::parse(&bytes), Ok(descriptor));
    }

    #[test]
    fn fsverity_descriptor_rejects_reserved_and_unused_salt_bytes() {
        let mut reserved_word = must!(must!(small_descriptor()).to_bytes());
        must!(put_le_u64(
            &mut reserved_word,
            DESCRIPTOR_RESERVED_0X04_OFFSET,
            1
        ));
        assert_eq!(
            FsverityDescriptor::parse(&reserved_word),
            Err(Error::InvalidVerityMetadata)
        );

        let mut unused_salt = must!(must!(small_descriptor()).to_bytes());
        must!(set_byte(
            &mut unused_salt,
            some!(DESCRIPTOR_SALT_OFFSET.checked_add(4)),
            9,
        ));
        assert_eq!(
            FsverityDescriptor::parse(&unused_salt),
            Err(Error::InvalidVerityMetadata)
        );

        let mut trailing_reserved = must!(must!(small_descriptor()).to_bytes());
        must!(set_byte(
            &mut trailing_reserved,
            DESCRIPTOR_RESERVED_OFFSET,
            1
        ));
        assert_eq!(
            FsverityDescriptor::parse(&trailing_reserved),
            Err(Error::InvalidVerityMetadata)
        );
    }

    #[test]
    fn fsverity_descriptor_rejects_unsupported_algorithm_and_block_size() {
        let mut algorithm = must!(must!(small_descriptor()).to_bytes());
        must!(set_byte(
            &mut algorithm,
            DESCRIPTOR_HASH_ALGORITHM_OFFSET,
            99
        ));
        assert_eq!(
            FsverityDescriptor::parse(&algorithm),
            Err(Error::InvalidVerityMetadata)
        );

        let mut block_size = must!(must!(small_descriptor()).to_bytes());
        must!(set_byte(
            &mut block_size,
            DESCRIPTOR_LOG_BLOCKSIZE_OFFSET,
            9
        ));
        assert_eq!(
            FsverityDescriptor::parse(&block_size),
            Err(Error::InvalidVerityMetadata)
        );
    }

    #[test]
    fn fsverity_merkle_tree_matches_sha256_single_block_vector() {
        let block_size = must!(FsverityBlockSize::new(1024));
        let salt = must!(FsveritySalt::new(&VECTOR_SALT));
        let tree = must!(FsverityMerkleTree::build(
            b"hello world",
            FsverityHashAlgorithm::Sha256,
            block_size,
            &salt,
        ));

        assert_eq!(
            must!(tree.root_hash().digest_bytes(FsverityHashAlgorithm::Sha256)),
            &SMALL_SHA256_ROOT
        );
        assert!(tree.blocks().is_empty());
    }

    #[test]
    fn fsverity_merkle_tree_matches_sha256_multi_block_vector() {
        let block_size = must!(FsverityBlockSize::new(1024));
        let salt = must!(FsveritySalt::new(&VECTOR_SALT));
        let data = must!(repeating_data(3500));
        let tree = must!(FsverityMerkleTree::build(
            &data,
            FsverityHashAlgorithm::Sha256,
            block_size,
            &salt
        ));

        assert_eq!(
            must!(tree.root_hash().digest_bytes(FsverityHashAlgorithm::Sha256)),
            &LARGE_SHA256_ROOT
        );
        assert_eq!(tree.blocks().len(), 1024);
        assert_eq!(
            some!(tree.blocks().get(..LARGE_TREE_FIRST_64.len())),
            &LARGE_TREE_FIRST_64
        );
    }

    #[test]
    fn fsverity_merkle_tree_verify_rejects_data_and_tree_corruption() {
        let block_size = must!(FsverityBlockSize::new(1024));
        let salt = must!(FsveritySalt::new(&VECTOR_SALT));
        let data = must!(repeating_data(3500));
        let tree = must!(FsverityMerkleTree::build(
            &data,
            FsverityHashAlgorithm::Sha256,
            block_size,
            &salt
        ));
        let descriptor = must!(FsverityDescriptor::new(
            FsverityHashAlgorithm::Sha256,
            block_size,
            must!(u64::try_from(data.len()).map_err(|_| Error::ArithmeticOverflow)),
            tree.root_hash(),
            salt,
        ));

        must!(tree.verify_data(&data, &descriptor));

        let mut corrupt_data = data.clone();
        must!(set_byte(&mut corrupt_data, 17, 0xff));
        assert_eq!(
            tree.verify_data(&corrupt_data, &descriptor),
            Err(Error::VerityMismatch)
        );

        let mut corrupt_tree = tree.clone();
        must!(set_byte(&mut corrupt_tree.blocks, 0, 0xff));
        assert_eq!(
            corrupt_tree.verify_data(&data, &descriptor),
            Err(Error::VerityMismatch)
        );
    }

    #[test]
    fn fsverity_empty_file_has_zero_root_and_no_tree_blocks() {
        let block_size = must!(FsverityBlockSize::new(1024));
        let salt = FsveritySalt::empty();
        let tree = must!(FsverityMerkleTree::build(
            &[],
            FsverityHashAlgorithm::Sha512,
            block_size,
            &salt
        ));

        assert_eq!(tree.root_hash(), FsverityRootHash::zero());
        assert!(tree.blocks().is_empty());
    }

    /// Builds the single-block vector descriptor.
    fn small_descriptor() -> Result<FsverityDescriptor> {
        let digest =
            FsverityDigest::new(FsverityHashAlgorithm::Sha256, SMALL_SHA256_ROOT.to_vec())?;
        FsverityDescriptor::new(
            FsverityHashAlgorithm::Sha256,
            FsverityBlockSize::new(1024)?,
            11,
            FsverityRootHash::from_digest(&digest)?,
            FsveritySalt::new(&VECTOR_SALT)?,
        )
    }

    /// Builds deterministic multi-block test data.
    fn repeating_data(len: usize) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        for index in 0..len {
            data.push(u8::try_from(index % 256).map_err(|_| Error::ArithmeticOverflow)?);
        }
        Ok(data)
    }
}
