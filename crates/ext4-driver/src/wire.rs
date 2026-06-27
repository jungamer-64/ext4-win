//! Checked byte-range and little-endian wire helpers for external payloads.

use crate::status::{DriverError, DriverResult};

/// A byte range whose end offset has been overflow-checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CheckedByteRange {
    /// Inclusive byte start.
    start: usize,
    /// Exclusive byte end.
    end: usize,
}

impl CheckedByteRange {
    /// Builds a checked byte range from an offset and length.
    pub(crate) fn new(offset: usize, length: usize) -> DriverResult<Self> {
        let end = offset
            .checked_add(length)
            .ok_or(DriverError::InvalidParameter)?;
        Ok(Self { start: offset, end })
    }

    /// Borrows this range from an input payload.
    pub(crate) fn read_from<'a>(self, bytes: &'a [u8]) -> DriverResult<&'a [u8]> {
        bytes
            .get(self.start..self.end)
            .ok_or(DriverError::BufferTooSmall)
    }

    /// Borrows this range from an output payload.
    pub(crate) fn write_to<'a>(self, bytes: &'a mut [u8]) -> DriverResult<&'a mut [u8]> {
        bytes
            .get_mut(self.start..self.end)
            .ok_or(DriverError::BufferTooSmall)
    }
}

/// Little-endian reader over a checked external payload.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LittleEndianInput<'a> {
    /// External payload bytes.
    bytes: &'a [u8],
}

impl<'a> LittleEndianInput<'a> {
    /// Wraps external payload bytes.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Borrows a checked range from the payload.
    pub(crate) fn range(self, offset: usize, length: usize) -> DriverResult<&'a [u8]> {
        CheckedByteRange::new(offset, length)?.read_from(self.bytes)
    }

    /// Returns whether a checked range contains only zero bytes.
    pub(crate) fn all_zero(self, offset: usize, length: usize) -> DriverResult<bool> {
        Ok(self.range(offset, length)?.iter().all(|byte| *byte == 0))
    }

    /// Copies a fixed-size byte array from a checked range.
    pub(crate) fn fixed<const N: usize>(self, offset: usize) -> DriverResult<[u8; N]> {
        let mut bytes = [0_u8; N];
        bytes.copy_from_slice(self.range(offset, N)?);
        Ok(bytes)
    }

    /// Reads a little-endian `u16` from the payload.
    pub(crate) fn read_u16(self, offset: usize) -> DriverResult<u16> {
        Ok(u16::from_le_bytes(self.fixed(offset)?))
    }

    /// Reads a little-endian `u32` from the payload.
    pub(crate) fn read_u32(self, offset: usize) -> DriverResult<u32> {
        Ok(u32::from_le_bytes(self.fixed(offset)?))
    }

    /// Reads a little-endian `u64` from the payload.
    pub(crate) fn read_u64(self, offset: usize) -> DriverResult<u64> {
        Ok(u64::from_le_bytes(self.fixed(offset)?))
    }
}

/// Little-endian writer over a checked external payload.
#[derive(Debug)]
pub(crate) struct LittleEndianOutput<'a> {
    /// External payload bytes.
    bytes: &'a mut [u8],
}

impl<'a> LittleEndianOutput<'a> {
    /// Wraps external payload bytes.
    pub(crate) fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    /// Borrows a checked mutable range from the payload.
    pub(crate) fn range_mut(&mut self, offset: usize, length: usize) -> DriverResult<&mut [u8]> {
        CheckedByteRange::new(offset, length)?.write_to(self.bytes)
    }

    /// Writes raw bytes into a checked range.
    pub(crate) fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> DriverResult<()> {
        self.range_mut(offset, bytes.len())?.copy_from_slice(bytes);
        Ok(())
    }

    /// Writes a little-endian `u16` into the payload.
    pub(crate) fn write_u16(&mut self, offset: usize, value: u16) -> DriverResult<()> {
        self.write_bytes(offset, value.to_le_bytes().as_slice())
    }

    /// Writes a little-endian `u32` into the payload.
    pub(crate) fn write_u32(&mut self, offset: usize, value: u32) -> DriverResult<()> {
        self.write_bytes(offset, value.to_le_bytes().as_slice())
    }

    /// Writes a little-endian `u64` into the payload.
    #[cfg(test)]
    pub(crate) fn write_u64(&mut self, offset: usize, value: u64) -> DriverResult<()> {
        self.write_bytes(offset, value.to_le_bytes().as_slice())
    }
}
