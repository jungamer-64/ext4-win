//! Checked byte-range and little-endian wire helpers for external payloads.

use crate::{
    kernel::status::{DriverError, DriverResult},
    memory,
};

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
    /// # Errors
    ///
    /// Returns an error when adding `length` to this offset overflows.
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
    /// # Errors
    ///
    /// Returns an error when `offset + length` overflows.
    pub(crate) fn new(offset: WireOffset, length: WireByteLen) -> DriverResult<Self> {
        let end = offset.checked_add(length)?;
        Ok(Self {
            start: offset.as_usize(),
            end: end.as_usize(),
        })
    }

    /// Builds a checked wire byte range from start and end offsets.
    /// # Errors
    ///
    /// Returns an error when `end` is before `start`.
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
    /// # Errors
    ///
    /// Returns an error when this input range is not fully present in `bytes`.
    pub(crate) fn read_from(self, bytes: &[u8]) -> DriverResult<&[u8]> {
        bytes
            .get(self.start..self.end)
            .ok_or(DriverError::BufferTooSmall)
    }

    /// Borrows this range from an output payload.
    /// # Errors
    ///
    /// Returns an error when this output range is not fully present in `bytes`.
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
    /// # Errors
    ///
    /// Returns an error when `range` is not fully present in this little-endian input payload.
    pub(crate) fn range(self, range: WireRange) -> DriverResult<&'a [u8]> {
        range.read_from(self.bytes)
    }

    /// Returns whether a checked range contains only zero bytes.
    /// # Errors
    ///
    /// Returns an error when `range` is not fully present before the zero scan.
    pub(crate) fn all_zero(self, range: WireRange) -> DriverResult<bool> {
        Ok(self.range(range)?.iter().all(|byte| *byte == 0))
    }

    /// Copies a fixed-size byte array from a checked range.
    /// # Errors
    ///
    /// Returns an error when the `N`-byte range starting at `offset` is not present.
    pub(crate) fn fixed<const N: usize>(self, offset: WireOffset) -> DriverResult<[u8; N]> {
        let mut bytes = [0_u8; N];
        memory::copy_exact(
            &mut bytes,
            self.range(WireRange::new(offset, WireByteLen::new(N))?)?,
        )?;
        Ok(bytes)
    }

    /// Reads a little-endian `u16` from the payload.
    /// # Errors
    ///
    /// Returns an error when the two-byte little-endian wire field is not fully present at
    /// `offset`.
    pub(crate) fn read_u16(self, offset: WireOffset) -> DriverResult<u16> {
        Ok(u16::from_le_bytes(self.fixed(offset)?))
    }

    /// Reads one byte from the payload.
    /// # Errors
    ///
    /// Returns an error when `offset` is outside this input payload.
    pub(crate) fn read_u8(self, offset: WireOffset) -> DriverResult<u8> {
        self.bytes
            .get(offset.as_usize())
            .copied()
            .ok_or(DriverError::BufferTooSmall)
    }

    /// Reads a little-endian `u32` from the payload.
    /// # Errors
    ///
    /// Returns an error when the four-byte little-endian wire field is not fully present at
    /// `offset`.
    pub(crate) fn read_u32(self, offset: WireOffset) -> DriverResult<u32> {
        Ok(u32::from_le_bytes(self.fixed(offset)?))
    }

    /// Reads a little-endian `u64` from the payload.
    /// # Errors
    ///
    /// Returns an error when the eight-byte little-endian field is not fully present at `offset`.
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
    /// # Errors
    ///
    /// Returns an error when `range` is not fully present in this output payload.
    pub(crate) fn range_mut(&mut self, range: WireRange) -> DriverResult<&mut [u8]> {
        range.write_to(self.bytes)
    }

    /// Writes raw bytes into a checked range.
    /// # Errors
    ///
    /// Returns an error when the destination range for `bytes` is not fully present.
    pub(crate) fn write_bytes(&mut self, offset: WireOffset, bytes: &[u8]) -> DriverResult<()> {
        memory::copy_exact(
            self.range_mut(WireRange::new(offset, WireByteLen::new(bytes.len()))?)?,
            bytes,
        )
    }

    /// Writes a little-endian `u16` into the payload.
    /// # Errors
    ///
    /// Returns an error when the two-byte little-endian wire field cannot be written at `offset`.
    pub(crate) fn write_u16(&mut self, offset: WireOffset, value: u16) -> DriverResult<()> {
        self.write_bytes(offset, value.to_le_bytes().as_slice())
    }

    /// Writes one byte into the payload.
    /// # Errors
    ///
    /// Returns an error when `offset` is outside this output payload.
    pub(crate) fn write_u8(&mut self, offset: WireOffset, value: u8) -> DriverResult<()> {
        *self
            .bytes
            .get_mut(offset.as_usize())
            .ok_or(DriverError::BufferTooSmall)? = value;
        Ok(())
    }

    /// Writes a little-endian `u32` into the payload.
    /// # Errors
    ///
    /// Returns an error when the four-byte little-endian wire field cannot be written at `offset`.
    pub(crate) fn write_u32(&mut self, offset: WireOffset, value: u32) -> DriverResult<()> {
        self.write_bytes(offset, value.to_le_bytes().as_slice())
    }

    /// Writes a little-endian `u64` into the payload.
    /// # Errors
    ///
    /// Returns an error when the eight-byte little-endian wire field cannot be written at `offset`.
    pub(crate) fn write_u64(&mut self, offset: WireOffset, value: u64) -> DriverResult<()> {
        self.write_bytes(offset, value.to_le_bytes().as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::{LittleEndianInput, LittleEndianOutput, WireByteLen, WireOffset, WireRange};
    use crate::kernel::status::DriverError;

    /// # Panics
    ///
    /// Panics when the checked range contract disagrees with the generated payload boundary.
    #[test]
    fn generated_wire_ranges_match_payload_boundaries() {
        let payload = [0_u8; 32];
        for payload_len in 0..=payload.len() {
            let view = payload.get(..payload_len);
            assert!(view.is_some());
            let Some(view) = view else {
                continue;
            };
            for offset in 0..=34 {
                for length in 0..=8 {
                    let range = WireRange::new(WireOffset::new(offset), WireByteLen::new(length));
                    assert!(range.is_ok());
                    if let Ok(range) = range {
                        let expected = offset
                            .checked_add(length)
                            .is_some_and(|end| end <= payload_len);
                        assert_eq!(range.read_from(view).is_ok(), expected);
                    }
                }
            }
        }
    }

    /// # Panics
    ///
    /// Panics when a scalar wire value cannot round-trip at an aligned or unaligned byte offset.
    #[test]
    fn generated_scalar_fields_are_alignment_independent() {
        for offset in 0..=8 {
            let offset_value = u64::try_from(offset);
            assert!(offset_value.is_ok());
            let Ok(offset_value) = offset_value else {
                continue;
            };
            let value = 0x8070_6050_4030_2010_u64 ^ offset_value;
            let mut payload = [0_u8; 16];
            let mut output = LittleEndianOutput::new(&mut payload);
            assert_eq!(output.write_u64(WireOffset::new(offset), value), Ok(()));
            assert_eq!(
                LittleEndianInput::new(&payload).read_u64(WireOffset::new(offset)),
                Ok(value)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn wire_range_rejects_overflowing_end() {
        assert_eq!(
            WireRange::new(WireOffset::new(usize::MAX), WireByteLen::new(1)),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn wire_range_rejects_end_before_start() {
        assert_eq!(
            WireRange::span(WireOffset::new(8), WireOffset::new(4)),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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
