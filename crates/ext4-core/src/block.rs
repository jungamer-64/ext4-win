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

/// Minimal random-access block reader used by ext4-core.
pub trait BlockReader {
    /// Total readable length in bytes.
    fn len(&self) -> DeviceLength;

    /// Reads exactly `out.len()` bytes at `offset`.
    ///
    /// # Errors
    /// Returns an error when the requested range cannot be read in full.
    fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<()>;

    /// Returns true when the device has no bytes.
    fn is_empty(&self) -> bool {
        self.len().is_empty()
    }
}

/// Random-access block writer used by journaled ext4 mutations.
pub trait BlockWriter: BlockReader {
    /// Writes exactly `bytes.len()` bytes at `offset`.
    ///
    /// # Errors
    /// Returns an error when the requested range cannot be written in full.
    fn write_exact_at(&mut self, offset: ByteOffset, bytes: &[u8]) -> Result<()>;

    /// Persists all previous writes according to the backing device contract.
    ///
    /// # Errors
    /// Returns an error when the backing device cannot guarantee persistence.
    fn flush(&mut self) -> Result<()>;
}

impl<T: BlockReader + ?Sized> BlockReader for &mut T {
    fn len(&self) -> DeviceLength {
        (**self).len()
    }

    fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        (**self).read_exact_at(offset, out)
    }
}

impl<T: BlockWriter + ?Sized> BlockWriter for &mut T {
    fn write_exact_at(&mut self, offset: ByteOffset, bytes: &[u8]) -> Result<()> {
        (**self).write_exact_at(offset, bytes)
    }

    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }
}

/// In-memory block device used by host tests and parser fixtures.
#[derive(Clone, Copy, Debug)]
pub struct SliceBlockDevice<'a> {
    /// Whole device image exposed through checked random-access reads.
    bytes: &'a [u8],
}

impl<'a> SliceBlockDevice<'a> {
    /// Creates a read-only in-memory device.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl BlockReader for SliceBlockDevice<'_> {
    fn len(&self) -> DeviceLength {
        DeviceLength::from_bytes(u64::try_from(self.bytes.len()).unwrap_or(u64::MAX))
    }

    fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
        let end = start.checked_add(out.len()).ok_or(Error::DeviceRange)?;
        let source = self.bytes.get(start..end).ok_or(Error::DeviceRange)?;
        out.copy_from_slice(source);
        Ok(())
    }
}

/// Mutable in-memory block device used by write transaction tests.
#[derive(Debug)]
pub struct SliceBlockDeviceMut<'a> {
    /// Whole mutable device image exposed through checked random-access I/O.
    bytes: &'a mut [u8],
}

impl<'a> SliceBlockDeviceMut<'a> {
    /// Creates a mutable read-write in-memory device.
    #[must_use]
    pub const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }
}

impl BlockReader for SliceBlockDeviceMut<'_> {
    fn len(&self) -> DeviceLength {
        DeviceLength::from_bytes(u64::try_from(self.bytes.len()).unwrap_or(u64::MAX))
    }

    fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
        let end = start.checked_add(out.len()).ok_or(Error::DeviceRange)?;
        let source = self.bytes.get(start..end).ok_or(Error::DeviceRange)?;
        out.copy_from_slice(source);
        Ok(())
    }
}

impl BlockWriter for SliceBlockDeviceMut<'_> {
    fn write_exact_at(&mut self, offset: ByteOffset, bytes: &[u8]) -> Result<()> {
        let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
        let end = start.checked_add(bytes.len()).ok_or(Error::DeviceRange)?;
        let target = self.bytes.get_mut(start..end).ok_or(Error::DeviceRange)?;
        target.copy_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
