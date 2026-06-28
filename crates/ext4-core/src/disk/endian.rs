//! Fixed-width endian reads and writes for on-disk ext4/JBD2 structures.
//!
//! All callers go through these helpers so truncation and offset overflow map to
//! the same domain errors instead of becoming unchecked indexing.

use crate::error::{Error, Result};

/// Byte offset inside one on-disk ext4/JBD2 structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiskOffset {
    /// Zero-based byte offset.
    bytes: usize,
}

impl DiskOffset {
    /// Creates an on-disk byte offset.
    #[must_use]
    pub const fn new(bytes: usize) -> Self {
        Self { bytes }
    }

    /// Returns the raw byte offset for slice indexing at this boundary.
    const fn as_usize(self) -> usize {
        self.bytes
    }

    /// Adds a checked on-disk byte length to this offset.
    pub(crate) fn checked_add(self, length: DiskByteLen) -> Result<Self> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(length.as_usize())
                .ok_or(Error::ArithmeticOverflow)?,
        })
    }

    /// Adds a checked raw byte count at the endian boundary.
    pub(crate) fn checked_add_bytes(self, bytes: usize) -> Result<Self> {
        self.checked_add(DiskByteLen::new(bytes))
    }
}

/// Byte length inside one on-disk ext4/JBD2 structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiskByteLen {
    /// Number of bytes.
    bytes: usize,
}

impl DiskByteLen {
    /// Creates an on-disk byte length.
    #[must_use]
    pub const fn new(bytes: usize) -> Self {
        Self { bytes }
    }

    /// Returns the byte length for slice indexing at this boundary.
    const fn as_usize(self) -> usize {
        self.bytes
    }
}

/// A checked on-disk byte range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiskRange {
    /// Inclusive byte start.
    start: usize,
    /// Exclusive byte end.
    end: usize,
}

impl DiskRange {
    /// Builds a checked disk byte range from an offset and length.
    pub fn new(offset: DiskOffset, length: DiskByteLen) -> Result<Self> {
        let end = offset.checked_add(length)?;
        Ok(Self {
            start: offset.as_usize(),
            end: end.as_usize(),
        })
    }

    /// Builds a checked disk byte range from start and end offsets.
    pub fn span(start: DiskOffset, end: DiskOffset) -> Result<Self> {
        if end.as_usize() < start.as_usize() {
            return Err(Error::TruncatedStructure);
        }
        Ok(Self {
            start: start.as_usize(),
            end: end.as_usize(),
        })
    }

    /// Borrows this range from an on-disk input structure.
    pub fn read_from(self, bytes: &[u8]) -> Result<&[u8]> {
        bytes
            .get(self.start..self.end)
            .ok_or(Error::TruncatedStructure)
    }

    /// Borrows this range from an on-disk output structure.
    pub fn write_to(self, bytes: &mut [u8]) -> Result<&mut [u8]> {
        bytes
            .get_mut(self.start..self.end)
            .ok_or(Error::TruncatedStructure)
    }
}

/// Reads a little-endian `u16` at `offset`.
pub fn le_u16(bytes: &[u8], offset: DiskOffset) -> Result<u16> {
    let raw = fixed::<2>(bytes, offset)?;
    Ok(u16::from_le_bytes(raw))
}

/// Reads a little-endian `u32` at `offset`.
pub fn le_u32(bytes: &[u8], offset: DiskOffset) -> Result<u32> {
    let raw = fixed::<4>(bytes, offset)?;
    Ok(u32::from_le_bytes(raw))
}

/// Reads a big-endian `u32` at `offset`.
pub fn be_u32(bytes: &[u8], offset: DiskOffset) -> Result<u32> {
    let raw = fixed::<4>(bytes, offset)?;
    Ok(u32::from_be_bytes(raw))
}

/// Reads a big-endian `u16` at `offset`.
pub fn be_u16(bytes: &[u8], offset: DiskOffset) -> Result<u16> {
    let raw = fixed::<2>(bytes, offset)?;
    Ok(u16::from_be_bytes(raw))
}

/// Reads a big-endian `u64` at `offset`.
pub fn be_u64(bytes: &[u8], offset: DiskOffset) -> Result<u64> {
    let raw = fixed::<8>(bytes, offset)?;
    Ok(u64::from_be_bytes(raw))
}

/// Writes a little-endian `u16` at `offset`.
pub fn put_le_u16(bytes: &mut [u8], offset: DiskOffset, value: u16) -> Result<()> {
    put_fixed(bytes, offset, &value.to_le_bytes())
}

/// Writes a little-endian `u32` at `offset`.
pub fn put_le_u32(bytes: &mut [u8], offset: DiskOffset, value: u32) -> Result<()> {
    put_fixed(bytes, offset, &value.to_le_bytes())
}

/// Writes a big-endian `u32` at `offset`.
pub fn put_be_u32(bytes: &mut [u8], offset: DiskOffset, value: u32) -> Result<()> {
    put_fixed(bytes, offset, &value.to_be_bytes())
}

/// Writes a big-endian `u16` at `offset`.
pub fn put_be_u16(bytes: &mut [u8], offset: DiskOffset, value: u16) -> Result<()> {
    put_fixed(bytes, offset, &value.to_be_bytes())
}

/// Copies an exact-width byte array out of a checked range.
fn fixed<const N: usize>(bytes: &[u8], offset: DiskOffset) -> Result<[u8; N]> {
    let range = DiskRange::new(offset, DiskByteLen::new(N))?;
    let slice = range.read_from(bytes)?;
    let mut raw = [0_u8; N];
    raw.copy_from_slice(slice);
    Ok(raw)
}

/// Copies an exact-width byte array into a checked mutable range.
fn put_fixed(bytes: &mut [u8], offset: DiskOffset, source: &[u8]) -> Result<()> {
    let target = DiskRange::new(offset, DiskByteLen::new(source.len()))?.write_to(bytes)?;
    target.copy_from_slice(source);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DiskByteLen, DiskOffset, DiskRange};
    use crate::error::Error;

    #[test]
    fn disk_range_rejects_overflowing_end() {
        assert_eq!(
            DiskRange::new(DiskOffset::new(usize::MAX), DiskByteLen::new(1)),
            Err(Error::ArithmeticOverflow)
        );
    }

    #[test]
    fn disk_range_rejects_end_before_start() {
        assert_eq!(
            DiskRange::span(DiskOffset::new(8), DiskOffset::new(4)),
            Err(Error::TruncatedStructure)
        );
    }

    #[test]
    fn disk_range_rejects_short_buffers() {
        let range = DiskRange::new(DiskOffset::new(2), DiskByteLen::new(4));
        assert!(range.is_ok());
        let Ok(range) = range else {
            return;
        };
        assert_eq!(range.read_from(&[0; 5]), Err(Error::TruncatedStructure));

        let mut bytes = [0; 5];
        assert_eq!(range.write_to(&mut bytes), Err(Error::TruncatedStructure));
    }
}
