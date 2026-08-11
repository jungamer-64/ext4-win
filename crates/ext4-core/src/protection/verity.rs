//! fs-verity descriptor and Merkle tree domain.

use alloc::vec::Vec;

use crate::disk::block::BlockSize;
use crate::disk_format::inode::FileSize;
use crate::error::{Error, Result};
use crate::memory::{self, FallibleVec};
use crate::protection::crypto::CryptographicOperation;

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
        let descriptor_bytes_u64 = validated_descriptor_bytes(descriptor_bytes)?;
        let merkle_tree_offset =
            align_up_u64(file_size.bytes(), EXT4_VERITY_METADATA_ALIGNMENT_BYTES)?;
        let tree_end = merkle_tree_offset
            .checked_add(merkle_tree_bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        let descriptor_offset = align_up_u64(tree_end, u64::from(filesystem_block_size.bytes()))?;
        let descriptor_end = descriptor_offset
            .checked_add(descriptor_bytes_u64)
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
        let descriptor_bytes_u64 = validated_descriptor_bytes(descriptor_bytes)?;
        let slot_bytes = align_up_u64(
            descriptor_bytes_u64
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
    /// # Errors
    ///
    /// Returns an error when the algorithm id is not SHA-256 or SHA-512.
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
            bytes: memory::copied_slice(bytes)?,
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

    /// Copies this salt without using infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the salt bytes cannot allocate.
    pub(crate) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            bytes: memory::copied_slice(&self.bytes)?,
        })
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
            bytes: memory::copied_slice(bytes)?,
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
        memory::copy_exact(target, digest.bytes())?;
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
    /// # Errors
    ///
    /// Returns an error when bytes beyond the selected algorithm digest length are nonzero.
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

    /// Hashes one zero-padded data or Merkle block using this descriptor's algorithm and salt.
    /// # Errors
    ///
    /// Returns an error when `block` is not exactly the descriptor block size or hashing cannot
    /// allocate its bounded digest input.
    fn hash_block(
        &self,
        block: &[u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<FsverityDigest> {
        if block.len() != self.block_size.to_usize()? {
            return Err(Error::InvalidVerityMetadata);
        }
        hash_block(self.algorithm, &self.salt, block, crypto)
    }

    /// Returns the descriptor root digest in the selected algorithm width.
    /// # Errors
    ///
    /// Returns an error when the root field is inconsistent with the descriptor algorithm.
    fn root_digest_bytes(&self) -> Result<&[u8]> {
        self.root_hash.digest_bytes(self.algorithm)
    }
}

/// One stored Merkle level, ordered from the data-adjacent leaf toward the root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FsverityMerkleLevel {
    /// First serialized tree block occupied by this level.
    start_block: u64,
    /// Number of child digests represented by the level.
    child_hashes: u64,
    /// Number of serialized tree blocks occupied by the level.
    blocks: u64,
}

/// Descriptor-derived tree geometry shared by metadata sizing and read verification.
#[derive(Clone, Debug, Eq, PartialEq)]
struct FsverityTreeGeometry {
    /// Merkle levels in leaf-to-root verification order.
    levels: Vec<FsverityMerkleLevel>,
    /// Number of digest slots in one Merkle block.
    hashes_per_block: u64,
    /// Number of data blocks covered by the descriptor.
    data_blocks: u64,
    /// Total serialized tree bytes.
    tree_bytes: u64,
}

impl FsverityTreeGeometry {
    /// Computes the one canonical Merkle topology for a descriptor.
    ///
    /// # Errors
    /// Returns an error when level sizing or serialized offsets overflow.
    fn from_descriptor(descriptor: &FsverityDescriptor) -> Result<Self> {
        let block_bytes = u64::from(descriptor.block_size().bytes());
        let digest_bytes = u64::try_from(descriptor.algorithm().digest_bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let hashes_per_block = block_bytes
            .checked_div(digest_bytes)
            .ok_or(Error::InvalidVerityMetadata)?;
        if hashes_per_block < 2 {
            return Err(Error::InvalidVerityMetadata);
        }

        let data_blocks = round_up_div_u64(descriptor.data_size(), block_bytes)?;
        let mut levels = Vec::new();
        let mut child_hashes = data_blocks;
        while child_hashes > 1 {
            let blocks = round_up_div_u64(child_hashes, hashes_per_block)?;
            levels.try_push(FsverityMerkleLevel {
                start_block: 0,
                child_hashes,
                blocks,
            })?;
            child_hashes = blocks;
        }

        let mut tree_blocks = 0_u64;
        for level in levels.iter_mut().rev() {
            level.start_block = tree_blocks;
            tree_blocks = tree_blocks
                .checked_add(level.blocks)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        let tree_bytes = tree_blocks
            .checked_mul(block_bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Self {
            levels,
            hashes_per_block,
            data_blocks,
            tree_bytes,
        })
    }
}

/// Relative location of the next Merkle proof block selected by verification state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FsverityMerkleBlockLocation {
    /// Byte offset from the beginning of the serialized Merkle tree.
    tree_byte_offset: u64,
}

impl FsverityMerkleBlockLocation {
    /// Byte offset from the beginning of the serialized Merkle tree.
    #[must_use]
    pub(crate) const fn tree_byte_offset(self) -> u64 {
        self.tree_byte_offset
    }
}

/// Descriptor and canonical geometry used to authenticate requested data blocks independently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FsverityVerifier {
    /// Root, hash parameters, and covered data size.
    descriptor: FsverityDescriptor,
    /// Canonical Merkle topology.
    geometry: FsverityTreeGeometry,
}

impl FsverityVerifier {
    /// Creates a verifier without reading or retaining stored Merkle blocks.
    ///
    /// # Errors
    /// Returns an error when descriptor-derived geometry is not representable.
    pub(crate) fn new(descriptor: FsverityDescriptor) -> Result<Self> {
        let geometry = FsverityTreeGeometry::from_descriptor(&descriptor)?;
        Ok(Self {
            descriptor,
            geometry,
        })
    }

    /// Merkle/data block size.
    #[must_use]
    pub(crate) const fn block_size(&self) -> FsverityBlockSize {
        self.descriptor.block_size()
    }

    /// Covered file data size.
    #[must_use]
    pub(crate) const fn data_size(&self) -> u64 {
        self.descriptor.data_size()
    }

    /// Total serialized Merkle tree bytes.
    #[must_use]
    pub(crate) const fn tree_bytes(&self) -> u64 {
        self.geometry.tree_bytes
    }

    /// Begins authentication of one zero-padded data block.
    ///
    /// # Errors
    /// Returns an error when the block index is outside the covered data, the block has the wrong
    /// size, or hashing fails.
    pub(crate) fn begin_data_block(
        &self,
        data_block: u64,
        bytes: &[u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<FsverityDataBlockVerification<'_>> {
        if data_block >= self.geometry.data_blocks {
            return Err(Error::InvalidVerityMetadata);
        }
        Ok(FsverityDataBlockVerification {
            verifier: self,
            child_index: data_block,
            next_level: 0,
            digest: self.descriptor.hash_block(bytes, crypto)?,
        })
    }
}

/// Leaf-to-root state machine authenticating one data block before it can be published.
pub(crate) struct FsverityDataBlockVerification<'verifier> {
    /// Descriptor and canonical topology.
    verifier: &'verifier FsverityVerifier,
    /// Child index selected in the next Merkle level.
    child_index: u64,
    /// Next leaf-to-root level to authenticate.
    next_level: usize,
    /// Digest of the data or Merkle block authenticated by the next level.
    digest: FsverityDigest,
}

impl FsverityDataBlockVerification<'_> {
    /// Locates the next proof block without advancing state.
    ///
    /// # Errors
    /// Returns an error when the state contradicts descriptor-derived geometry.
    pub(crate) fn next_merkle_block(&self) -> Result<Option<FsverityMerkleBlockLocation>> {
        let Some(level) = self.verifier.geometry.levels.get(self.next_level) else {
            return Ok(None);
        };
        let (block_index, _digest_offset) = self.location_within_level(*level, self.child_index)?;
        let tree_block = level
            .start_block
            .checked_add(block_index)
            .ok_or(Error::ArithmeticOverflow)?;
        let tree_byte_offset = tree_block
            .checked_mul(u64::from(self.verifier.block_size().bytes()))
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Some(FsverityMerkleBlockLocation { tree_byte_offset }))
    }

    /// Authenticates the next proof block and advances exactly one level toward the root.
    ///
    /// # Errors
    /// Returns an error when no proof block remains, a digest slot or block is malformed, or the
    /// child digest does not match.
    pub(crate) fn verify_merkle_block(
        &mut self,
        block: &[u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<()> {
        let level = self
            .verifier
            .geometry
            .levels
            .get(self.next_level)
            .copied()
            .ok_or(Error::InvalidVerityMetadata)?;
        let (block_index, digest_offset) = self.location_within_level(level, self.child_index)?;
        let digest_end = digest_offset
            .checked_add(self.verifier.descriptor.algorithm().digest_bytes())
            .ok_or(Error::ArithmeticOverflow)?;
        if block
            .get(digest_offset..digest_end)
            .ok_or(Error::InvalidVerityMetadata)?
            != self.digest.bytes()
        {
            return Err(Error::VerityMismatch);
        }
        self.digest = self.verifier.descriptor.hash_block(block, crypto)?;
        self.child_index = block_index;
        self.next_level = self
            .next_level
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(())
    }

    /// Requires a complete proof and authenticates its final digest against the descriptor root.
    ///
    /// # Errors
    /// Returns an error when one or more levels were skipped or the computed root differs.
    pub(crate) fn finish(self) -> Result<()> {
        if self.next_level != self.verifier.geometry.levels.len() {
            return Err(Error::InvalidVerityMetadata);
        }
        if self.digest.bytes() == self.verifier.descriptor.root_digest_bytes()? {
            Ok(())
        } else {
            Err(Error::VerityMismatch)
        }
    }

    /// Selects a Merkle block and digest slot within one validated level.
    ///
    /// # Errors
    /// Returns an error when the child is outside the level or offset arithmetic overflows.
    fn location_within_level(
        &self,
        level: FsverityMerkleLevel,
        child_index: u64,
    ) -> Result<(u64, usize)> {
        if child_index >= level.child_hashes {
            return Err(Error::InvalidVerityMetadata);
        }
        let block_index = child_index
            .checked_div(self.verifier.geometry.hashes_per_block)
            .ok_or(Error::InvalidVerityMetadata)?;
        if block_index >= level.blocks {
            return Err(Error::InvalidVerityMetadata);
        }
        let digest_slot = child_index
            .checked_rem(self.verifier.geometry.hashes_per_block)
            .ok_or(Error::InvalidVerityMetadata)?;
        let digest_offset = digest_slot
            .checked_mul(
                u64::try_from(self.verifier.descriptor.algorithm().digest_bytes())
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        Ok((
            block_index,
            usize::try_from(digest_offset).map_err(|_| Error::ArithmeticOverflow)?,
        ))
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
        crypto: &mut dyn CryptographicOperation,
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
        let mut hashes = hash_data_blocks(data, algorithm, block_bytes, salt, crypto)?;
        let mut levels = Vec::new();
        while hashes.len() > 1 {
            let (level_blocks, parent_hashes) =
                hash_level(&hashes, algorithm, block_bytes, salt, crypto)?;
            levels.try_push(level_blocks)?;
            hashes = parent_hashes;
        }
        let root_digest = hashes.pop().ok_or(Error::InvalidVerityMetadata)?;
        levels.reverse();
        let mut blocks = Vec::new();
        for level in levels {
            blocks.try_extend_from_slice(&level)?;
        }
        Ok(Self {
            algorithm,
            block_size,
            root_hash: FsverityRootHash::from_digest(&root_digest)?,
            blocks,
        })
    }

    /// Returns the serialized Merkle tree byte count implied by a descriptor.
    ///
    /// # Errors
    /// Returns an error when the descriptor geometry overflows arithmetic.
    pub fn stored_tree_bytes_for_descriptor(descriptor: &FsverityDescriptor) -> Result<u64> {
        Ok(FsverityTreeGeometry::from_descriptor(descriptor)?.tree_bytes)
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

/// Validates descriptor-plus-signature byte count and widens it for layout arithmetic.
///
/// # Errors
/// Returns an error when the fixed descriptor is truncated or the signature exceeds the Linux
/// UAPI limit.
fn validated_descriptor_bytes(descriptor_bytes: u32) -> Result<u64> {
    let descriptor_bytes_usize =
        usize::try_from(descriptor_bytes).map_err(|_| Error::ArithmeticOverflow)?;
    let maximum_descriptor_bytes = FSVERITY_DESCRIPTOR_BYTES
        .checked_add(FSVERITY_MAX_SIGNATURE_BYTES)
        .ok_or(Error::ArithmeticOverflow)?;
    if !(FSVERITY_DESCRIPTOR_BYTES..=maximum_descriptor_bytes).contains(&descriptor_bytes_usize) {
        return Err(Error::InvalidVerityMetadata);
    }
    Ok(u64::from(descriptor_bytes))
}

/// Parses salt and requires unused descriptor salt bytes to be zero.
/// # Errors
///
/// Returns an error when the salt field range is truncated, size arithmetic overflows, or unused
/// salt bytes are nonzero.
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
/// # Errors
///
/// Returns an error when `alignment` is zero or rounding `value` up overflows.
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
/// # Errors
///
/// Returns an error when `divisor` is zero or rounded addition overflows.
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
/// # Errors
///
/// Returns an error when a data chunk cannot be copied into its zero-padded Merkle block.
fn hash_data_blocks(
    data: &[u8],
    algorithm: FsverityHashAlgorithm,
    block_bytes: usize,
    salt: &FsveritySalt,
    crypto: &mut dyn CryptographicOperation,
) -> Result<Vec<FsverityDigest>> {
    let mut hashes = Vec::new();
    for chunk in data.chunks(block_bytes) {
        let mut block = memory::repeated_vec(0_u8, block_bytes)?;
        memory::copy_exact(
            block
                .get_mut(..chunk.len())
                .ok_or(Error::InvalidVerityMetadata)?,
            chunk,
        )?;
        hashes.try_push(hash_block(algorithm, salt, &block, crypto)?)?;
    }
    Ok(hashes)
}

/// Hashes one Merkle level into parent hashes.
/// # Errors
///
/// Returns an error when the block cannot hold at least one digest, a child digest uses the wrong
/// algorithm, or digest placement arithmetic overflows.
fn hash_level(
    hashes: &[FsverityDigest],
    algorithm: FsverityHashAlgorithm,
    block_bytes: usize,
    salt: &FsveritySalt,
    crypto: &mut dyn CryptographicOperation,
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
        let mut block = memory::repeated_vec(0_u8, block_bytes)?;
        for (index, hash) in hash_group.iter().enumerate() {
            if hash.algorithm() != algorithm {
                return Err(Error::InvalidVerityMetadata);
            }
            let offset = index
                .checked_mul(digest_bytes)
                .ok_or(Error::ArithmeticOverflow)?;
            copy_into(&mut block, offset, hash.bytes())?;
        }
        parent_hashes.try_push(hash_block(algorithm, salt, &block, crypto)?)?;
        level_blocks.try_extend_from_slice(&block)?;
    }
    Ok((level_blocks, parent_hashes))
}

/// Hashes one fs-verity data or Merkle block with padded salt.
/// # Errors
///
/// Returns an error when the salt does not fit in the algorithm's padded salt block or the produced
/// digest length is invalid.
fn hash_block(
    algorithm: FsverityHashAlgorithm,
    salt: &FsveritySalt,
    block: &[u8],
    crypto: &mut dyn CryptographicOperation,
) -> Result<FsverityDigest> {
    let mut input = Vec::new();
    if !salt.is_empty() {
        let padded_salt_bytes = algorithm.compression_input_bytes();
        input = memory::repeated_vec(0_u8, padded_salt_bytes)?;
        memory::copy_exact(
            input
                .get_mut(..salt.bytes().len())
                .ok_or(Error::InvalidVerityMetadata)?,
            salt.bytes(),
        )?;
    }
    input.try_extend_from_slice(block)?;
    FsverityDigest::new(algorithm, hash_bytes(algorithm, &input, crypto)?)
}

/// Hashes an arbitrary byte slice through the operation-owned provider.
/// # Errors
///
/// Returns an error when digest allocation or provider execution fails.
fn hash_bytes(
    algorithm: FsverityHashAlgorithm,
    bytes: &[u8],
    crypto: &mut dyn CryptographicOperation,
) -> Result<Vec<u8>> {
    match algorithm {
        FsverityHashAlgorithm::Sha256 => memory::copied_slice(&crypto.sha256(bytes)?),
        FsverityHashAlgorithm::Sha512 => memory::copied_slice(&crypto.sha512(bytes)?),
    }
}

/// Requires an exact serialized structure length.
/// # Errors
///
/// Returns an error when `bytes` is shorter or longer than the expected serialized fs-verity
/// structure.
fn require_exact_len(bytes: &[u8], expected: usize) -> Result<()> {
    match bytes.len().cmp(&expected) {
        core::cmp::Ordering::Less => Err(Error::TruncatedStructure),
        core::cmp::Ordering::Equal => Ok(()),
        core::cmp::Ordering::Greater => Err(Error::InvalidVerityMetadata),
    }
}

/// Reads one byte from a checked offset.
/// # Errors
///
/// Returns an error when `offset` is outside the serialized fs-verity structure.
fn byte(bytes: &[u8], offset: usize) -> Result<u8> {
    bytes.get(offset).copied().ok_or(Error::TruncatedStructure)
}

/// Reads a little-endian `u32` at a checked offset.
/// # Errors
///
/// Returns an error when the four-byte fs-verity field is not fully present at `offset`.
fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(fixed(bytes, offset)?))
}

/// Reads a little-endian `u64` at a checked offset.
/// # Errors
///
/// Returns an error when the eight-byte fs-verity field is not fully present at `offset`.
fn le_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(fixed(bytes, offset)?))
}

/// Writes a little-endian `u64` at a checked offset.
/// # Errors
///
/// Returns an error when the eight-byte field cannot be written at `offset`.
fn put_le_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    copy_into(bytes, offset, &value.to_le_bytes())
}

/// Writes one byte at a checked offset.
/// # Errors
///
/// Returns an error when `offset` is outside the destination structure.
fn set_byte(bytes: &mut [u8], offset: usize, value: u8) -> Result<()> {
    let target = bytes.get_mut(offset).ok_or(Error::TruncatedStructure)?;
    *target = value;
    Ok(())
}

/// Copies a fixed byte array from a checked offset.
/// # Errors
///
/// Returns an error when the fixed-width field overflows or is outside the source structure.
fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(Error::ArithmeticOverflow)?;
    let slice = bytes.get(offset..end).ok_or(Error::TruncatedStructure)?;
    let mut output = [0_u8; N];
    memory::copy_exact(&mut output, slice)?;
    Ok(output)
}

/// Copies source bytes into a checked destination offset.
/// # Errors
///
/// Returns an error when the destination range overflows or is outside the target structure.
fn copy_into(target: &mut [u8], offset: usize, source: &[u8]) -> Result<()> {
    let end = offset
        .checked_add(source.len())
        .ok_or(Error::ArithmeticOverflow)?;
    memory::copy_exact(
        target
            .get_mut(offset..end)
            .ok_or(Error::TruncatedStructure)?,
        source,
    )
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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
        assert_eq!(layout.descriptor_bytes, 272);
        assert_eq!(layout.descriptor_size_offset(), 77_820);
        assert_eq!(layout.metadata_end(), 77_824);
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn ext4_verity_metadata_layout_rejects_bad_descriptor_and_overflow() {
        let oversized_descriptor = must!(
            FSVERITY_DESCRIPTOR_BYTES
                .checked_add(FSVERITY_MAX_SIGNATURE_BYTES)
                .and_then(|bytes| bytes.checked_add(1))
                .ok_or(Error::ArithmeticOverflow)
        );
        let oversized_descriptor =
            must!(u32::try_from(oversized_descriptor).map_err(|_| Error::ArithmeticOverflow));

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
                FileSize::from_bytes(0),
                must!(BlockSize::from_superblock_log(0)),
                0,
                oversized_descriptor,
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn fsverity_descriptor_round_trips_supported_layout() {
        let descriptor = must!(small_descriptor());
        let bytes = must!(descriptor.to_bytes());

        assert_eq!(FsverityDescriptor::parse(&bytes), Ok(descriptor));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when proof geometry, state transitions, or corruption detection diverge from the
    /// tree image built by the same fs-verity domain.
    #[test]
    fn fsverity_verifier_authenticates_only_one_requested_block_path() {
        let block_size = must!(FsverityBlockSize::new(1024));
        let block_bytes = must!(block_size.to_usize());
        let salt = must!(FsveritySalt::new(&VECTOR_SALT));
        let data_bytes = must!(
            block_bytes
                .checked_mul(130)
                .and_then(|bytes| bytes.checked_sub(17))
                .ok_or(Error::ArithmeticOverflow)
        );
        let data = must!(repeating_data(data_bytes));
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
            must!(salt.try_clone())
        ));
        let verifier = must!(FsverityVerifier::new(descriptor));
        assert_eq!(
            must!(u64::try_from(tree.blocks().len()).map_err(|_| Error::ArithmeticOverflow)),
            verifier.tree_bytes()
        );

        let data_block_index = 129_u64;
        let block_start =
            must!(usize::try_from(data_block_index).map_err(|_| Error::ArithmeticOverflow))
                .checked_mul(block_bytes)
                .ok_or(Error::ArithmeticOverflow);
        let block_start = must!(block_start);
        let mut data_block = must!(memory::repeated_vec(0_u8, block_bytes));
        let tail = some!(data.get(block_start..));
        some!(data_block.get_mut(..tail.len())).copy_from_slice(tail);

        let mut verification = must!(verifier.begin_data_block(data_block_index, &data_block));
        let first = some!(must!(verification.next_merkle_block()));
        assert_eq!(first.tree_byte_offset(), 5120);
        while let Some(location) = must!(verification.next_merkle_block()) {
            let start = must!(
                usize::try_from(location.tree_byte_offset()).map_err(|_| Error::ArithmeticOverflow)
            );
            let end = must!(
                start
                    .checked_add(block_bytes)
                    .ok_or(Error::ArithmeticOverflow)
            );
            must!(verification.verify_merkle_block(some!(tree.blocks().get(start..end))));
        }
        assert_eq!(verification.finish(), Ok(()));

        let incomplete = must!(verifier.begin_data_block(data_block_index, &data_block));
        assert_eq!(incomplete.finish(), Err(Error::InvalidVerityMetadata));

        *some!(data_block.get_mut(0)) ^= 0x80;
        let mut corrupted = must!(verifier.begin_data_block(data_block_index, &data_block));
        let location = some!(must!(corrupted.next_merkle_block()));
        let start = must!(
            usize::try_from(location.tree_byte_offset()).map_err(|_| Error::ArithmeticOverflow)
        );
        let end = must!(
            start
                .checked_add(block_bytes)
                .ok_or(Error::ArithmeticOverflow)
        );
        assert_eq!(
            corrupted.verify_merkle_block(some!(tree.blocks().get(start..end))),
            Err(Error::VerityMismatch)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when requested-block authentication diverges from stored SHA-256 or SHA-512 trees.
    #[test]
    fn fsverity_requested_block_verifier_walks_only_its_authentication_path() {
        let block_size = must!(FsverityBlockSize::new(1024));
        let salt = must!(FsveritySalt::new(&VECTOR_SALT));
        let data = must!(repeating_data(40 * 1024));

        for algorithm in [FsverityHashAlgorithm::Sha256, FsverityHashAlgorithm::Sha512] {
            let tree = must!(FsverityMerkleTree::build(
                &data, algorithm, block_size, &salt
            ));
            let descriptor = must!(FsverityDescriptor::new(
                algorithm,
                block_size,
                u64::try_from(data.len()).unwrap_or(u64::MAX),
                tree.root_hash(),
                salt.clone(),
            ));
            let verifier = must!(FsverityVerifier::new(descriptor));

            assert_eq!(
                verifier.tree_bytes(),
                u64::try_from(tree.blocks().len()).unwrap_or(u64::MAX)
            );
            for data_block in [0_u64, 17, 39] {
                assert_eq!(
                    verify_stored_data_block(&verifier, &data, tree.blocks(), data_block),
                    Ok(())
                );
            }
        }
    }

    /// # Panics
    ///
    /// Panics when data, leaf, parent, or descriptor-root corruption survives range verification.
    #[test]
    fn fsverity_requested_block_verifier_rejects_every_proof_layer_corruption() {
        let algorithm = FsverityHashAlgorithm::Sha512;
        let block_size = must!(FsverityBlockSize::new(1024));
        let salt = must!(FsveritySalt::new(&VECTOR_SALT));
        let data = must!(repeating_data(40 * 1024));
        let tree = must!(FsverityMerkleTree::build(
            &data, algorithm, block_size, &salt
        ));
        let descriptor = must!(FsverityDescriptor::new(
            algorithm,
            block_size,
            u64::try_from(data.len()).unwrap_or(u64::MAX),
            tree.root_hash(),
            salt.clone(),
        ));
        let verifier = must!(FsverityVerifier::new(descriptor));

        let mut corrupt_data = data.clone();
        *some!(corrupt_data.get_mut(0)) ^= 0x80;
        assert_eq!(
            verify_stored_data_block(&verifier, &corrupt_data, tree.blocks(), 0),
            Err(Error::VerityMismatch)
        );

        let mut corrupt_leaf = tree.blocks().to_vec();
        *some!(corrupt_leaf.get_mut(1024)) ^= 0x80;
        assert_eq!(
            verify_stored_data_block(&verifier, &data, &corrupt_leaf, 0),
            Err(Error::VerityMismatch)
        );

        let mut corrupt_parent = tree.blocks().to_vec();
        *some!(corrupt_parent.get_mut(900)) ^= 0x80;
        assert_eq!(
            verify_stored_data_block(&verifier, &data, &corrupt_parent, 0),
            Err(Error::VerityMismatch)
        );

        let wrong_root = must!(FsverityDescriptor::new(
            algorithm,
            block_size,
            u64::try_from(data.len()).unwrap_or(u64::MAX),
            FsverityRootHash::zero(),
            salt,
        ));
        let wrong_root_verifier = must!(FsverityVerifier::new(wrong_root));
        assert_eq!(
            verify_stored_data_block(&wrong_root_verifier, &data, tree.blocks(), 0),
            Err(Error::VerityMismatch)
        );
    }

    /// Authenticates one stored data block through only the proof blocks selected by the verifier.
    /// # Errors
    ///
    /// Returns an error when the selected data/proof range is absent or authentication fails.
    fn verify_stored_data_block(
        verifier: &FsverityVerifier,
        data: &[u8],
        tree: &[u8],
        data_block: u64,
    ) -> Result<()> {
        let block_bytes = verifier.block_size().to_usize()?;
        let start = usize::try_from(data_block)
            .map_err(|_| Error::ArithmeticOverflow)?
            .checked_mul(block_bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        let end = start
            .checked_add(block_bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut verification = verifier.begin_data_block(
            data_block,
            data.get(start..end).ok_or(Error::InvalidVerityMetadata)?,
        )?;
        while let Some(location) = verification.next_merkle_block()? {
            let proof_start = usize::try_from(location.tree_byte_offset())
                .map_err(|_| Error::ArithmeticOverflow)?;
            let proof_end = proof_start
                .checked_add(block_bytes)
                .ok_or(Error::ArithmeticOverflow)?;
            verification.verify_merkle_block(
                tree.get(proof_start..proof_end)
                    .ok_or(Error::InvalidVerityMetadata)?,
            )?;
        }
        verification.finish()
    }

    /// Builds the single-block vector descriptor.
    /// # Errors
    ///
    /// Returns an error when the fixed digest, block size, root hash, salt, or descriptor fields are
    /// rejected by their domain constructors.
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
    /// # Errors
    ///
    /// Returns an error when a generated byte index cannot be represented as `u8`.
    fn repeating_data(len: usize) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        for index in 0..len {
            data.push(u8::try_from(index % 256).map_err(|_| Error::ArithmeticOverflow)?);
        }
        Ok(data)
    }
}
