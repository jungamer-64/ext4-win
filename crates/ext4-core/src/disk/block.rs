//! Block-device boundary and strongly typed byte/block positions.

use crate::error::{Error, Result};

/// Total byte length of a backing block device.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeviceLength(u64);

impl DeviceLength {
    /// Creates a device length from bytes reported by an external device boundary.
    #[must_use]
    pub const fn from_bytes(value: u64) -> Self {
        Self(value)
    }

    /// Returns the device length in bytes for range arithmetic at I/O boundaries.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// Returns true when the device has no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

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
    /// Creates a supported ext4 block size from `s_log_block_size`.
    ///
    /// # Errors
    /// Returns an error when the encoded block size is outside the supported range or
    /// cannot be computed without overflow.
    pub fn from_superblock_log(log_block_size: u32) -> Result<Self> {
        if log_block_size > 6 {
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
