//! Block-device boundary and strongly typed byte/block positions.

use crate::error::{Error, Result};

/// Absolute byte offset on a backing block device.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ByteOffset(u64);

impl ByteOffset {
    /// Creates an absolute byte offset.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw byte offset.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Absolute ext4 block address.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockAddress(u64);

impl BlockAddress {
    /// Creates an absolute ext4 block address.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw block address.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Validated ext4 block size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockSize(u32);

impl BlockSize {
    /// Creates a v1-supported ext4 block size from `s_log_block_size`.
    ///
    /// # Errors
    /// Returns an error when the encoded block size is outside the v1 range or
    /// cannot be computed without overflow.
    pub fn from_superblock_log(log_block_size: u32) -> Result<Self> {
        if log_block_size > 2 {
            return Err(Error::UnsupportedBlockSize);
        }

        let shift = log_block_size
            .checked_add(10)
            .ok_or(Error::ArithmeticOverflow)?;
        let bytes = 1_u32.checked_shl(shift).ok_or(Error::ArithmeticOverflow)?;
        Ok(Self(bytes))
    }

    /// Returns the block size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.0
    }

    /// Maps a block number to an absolute byte offset.
    ///
    /// # Errors
    /// Returns an error when the block-to-byte multiplication overflows.
    pub fn offset_of(self, block: BlockAddress) -> Result<ByteOffset> {
        let bytes = block
            .get()
            .checked_mul(u64::from(self.0))
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(ByteOffset::new(bytes))
    }
}

/// Minimal random-access block-device interface used by ext4-core.
pub trait BlockDevice {
    /// Total readable length in bytes.
    fn len(&self) -> u64;

    /// Reads exactly `out.len()` bytes at `offset`.
    ///
    /// # Errors
    /// Returns an error when the requested range cannot be read in full.
    fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<()>;

    /// Returns true when the device has no bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// In-memory block device used by host tests and parser fixtures.
#[derive(Clone, Copy, Debug)]
pub struct SliceBlockDevice<'a> {
    bytes: &'a [u8],
}

impl<'a> SliceBlockDevice<'a> {
    /// Creates a read-only in-memory device.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl BlockDevice for SliceBlockDevice<'_> {
    fn len(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }

    fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
        let end = start.checked_add(out.len()).ok_or(Error::DeviceRange)?;
        let source = self.bytes.get(start..end).ok_or(Error::DeviceRange)?;
        out.copy_from_slice(source);
        Ok(())
    }
}
