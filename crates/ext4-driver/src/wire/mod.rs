//! Checked byte-range and little-endian wire helpers for external payloads.

use crate::kernel::status::{DriverError, DriverResult};

/// Byte offset inside one decoded wire payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WireOffset {
    /// Zero-based byte offset.
    bytes: usize,
}

impl WireOffset {
    /// Creates a wire byte offset.
    pub(crate) const fn new(bytes: usize) -> Self {
        Self { bytes }
    }

    /// Returns the raw byte offset for slice indexing at the wire boundary.
    const fn as_usize(self) -> usize {
        self.bytes
    }

    /// Adds a checked wire length to this offset.
    fn checked_add(self, length: WireByteLen) -> DriverResult<Self> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(length.as_usize())
                .ok_or(DriverError::InvalidParameter)?,
        })
    }
}

/// Byte length inside one decoded wire payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WireByteLen {
    /// Number of bytes.
    bytes: usize,
}

impl WireByteLen {
    /// Creates a wire byte length.
    pub(crate) const fn new(bytes: usize) -> Self {
        Self { bytes }
    }

    /// Returns the byte length for slice indexing at the wire boundary.
    const fn as_usize(self) -> usize {
        self.bytes
    }
}

/// A wire byte range whose end offset has been overflow-checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WireRange {
    /// Inclusive byte start.
    start: usize,
    /// Exclusive byte end.
    end: usize,
}

impl WireRange {
    /// Builds a checked wire byte range from an offset and length.
    pub(crate) fn new(offset: WireOffset, length: WireByteLen) -> DriverResult<Self> {
        let end = offset.checked_add(length)?;
        Ok(Self {
            start: offset.as_usize(),
            end: end.as_usize(),
        })
    }

    /// Builds a checked wire byte range from start and end offsets.
    pub(crate) fn span(start: WireOffset, end: WireOffset) -> DriverResult<Self> {
        if end.as_usize() < start.as_usize() {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self {
            start: start.as_usize(),
            end: end.as_usize(),
        })
    }

    /// Borrows this range from an input payload.
    pub(crate) fn read_from(self, bytes: &[u8]) -> DriverResult<&[u8]> {
        bytes
            .get(self.start..self.end)
            .ok_or(DriverError::BufferTooSmall)
    }

    /// Borrows this range from an output payload.
    pub(crate) fn write_to(self, bytes: &mut [u8]) -> DriverResult<&mut [u8]> {
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
    pub(crate) fn range(self, range: WireRange) -> DriverResult<&'a [u8]> {
        range.read_from(self.bytes)
    }

    /// Returns whether a checked range contains only zero bytes.
    pub(crate) fn all_zero(self, range: WireRange) -> DriverResult<bool> {
        Ok(self.range(range)?.iter().all(|byte| *byte == 0))
    }

    /// Copies a fixed-size byte array from a checked range.
    pub(crate) fn fixed<const N: usize>(self, offset: WireOffset) -> DriverResult<[u8; N]> {
        let mut bytes = [0_u8; N];
        bytes.copy_from_slice(self.range(WireRange::new(offset, WireByteLen::new(N))?)?);
        Ok(bytes)
    }

    /// Reads a little-endian `u16` from the payload.
    pub(crate) fn read_u16(self, offset: WireOffset) -> DriverResult<u16> {
        Ok(u16::from_le_bytes(self.fixed(offset)?))
    }

    /// Reads one byte from the payload.
    pub(crate) fn read_u8(self, offset: WireOffset) -> DriverResult<u8> {
        self.bytes
            .get(offset.as_usize())
            .copied()
            .ok_or(DriverError::BufferTooSmall)
    }

    /// Reads a little-endian `u32` from the payload.
    pub(crate) fn read_u32(self, offset: WireOffset) -> DriverResult<u32> {
        Ok(u32::from_le_bytes(self.fixed(offset)?))
    }

    /// Reads a little-endian `u64` from the payload.
    pub(crate) fn read_u64(self, offset: WireOffset) -> DriverResult<u64> {
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
    pub(crate) fn range_mut(&mut self, range: WireRange) -> DriverResult<&mut [u8]> {
        range.write_to(self.bytes)
    }

    /// Writes raw bytes into a checked range.
    pub(crate) fn write_bytes(&mut self, offset: WireOffset, bytes: &[u8]) -> DriverResult<()> {
        self.range_mut(WireRange::new(offset, WireByteLen::new(bytes.len()))?)?
            .copy_from_slice(bytes);
        Ok(())
    }

    /// Writes a little-endian `u16` into the payload.
    pub(crate) fn write_u16(&mut self, offset: WireOffset, value: u16) -> DriverResult<()> {
        self.write_bytes(offset, value.to_le_bytes().as_slice())
    }

    /// Writes one byte into the payload.
    pub(crate) fn write_u8(&mut self, offset: WireOffset, value: u8) -> DriverResult<()> {
        *self
            .bytes
            .get_mut(offset.as_usize())
            .ok_or(DriverError::BufferTooSmall)? = value;
        Ok(())
    }

    /// Writes a little-endian `u32` into the payload.
    pub(crate) fn write_u32(&mut self, offset: WireOffset, value: u32) -> DriverResult<()> {
        self.write_bytes(offset, value.to_le_bytes().as_slice())
    }

    /// Writes a little-endian `u64` into the payload.
    #[cfg(test)]
    pub(crate) fn write_u64(&mut self, offset: WireOffset, value: u64) -> DriverResult<()> {
        self.write_bytes(offset, value.to_le_bytes().as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::{WireByteLen, WireOffset, WireRange};
    use crate::kernel::status::DriverError;

    #[test]
    fn wire_range_rejects_overflowing_end() {
        assert_eq!(
            WireRange::new(WireOffset::new(usize::MAX), WireByteLen::new(1)),
            Err(DriverError::InvalidParameter)
        );
    }

    #[test]
    fn wire_range_rejects_end_before_start() {
        assert_eq!(
            WireRange::span(WireOffset::new(8), WireOffset::new(4)),
            Err(DriverError::InvalidParameter)
        );
    }

    #[test]
    fn wire_range_rejects_short_buffers() {
        let range = WireRange::new(WireOffset::new(2), WireByteLen::new(4));
        assert!(range.is_ok());
        let Ok(range) = range else {
            return;
        };
        assert_eq!(range.read_from(&[0; 5]), Err(DriverError::BufferTooSmall));

        let mut bytes = [0; 5];
        assert_eq!(range.write_to(&mut bytes), Err(DriverError::BufferTooSmall));
    }
}
