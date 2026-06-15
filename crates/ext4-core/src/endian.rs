//! Fixed-width endian reads and writes for on-disk ext4/JBD2 structures.
//!
//! All callers go through these helpers so truncation and offset overflow map to
//! the same domain errors instead of becoming unchecked indexing.

use crate::error::{Error, Result};

/// Reads a little-endian `u16` at `offset`.
pub fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = fixed::<2>(bytes, offset)?;
    Ok(u16::from_le_bytes(raw))
}

/// Reads a little-endian `u32` at `offset`.
pub fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = fixed::<4>(bytes, offset)?;
    Ok(u32::from_le_bytes(raw))
}

/// Reads a big-endian `u32` at `offset`.
pub fn be_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = fixed::<4>(bytes, offset)?;
    Ok(u32::from_be_bytes(raw))
}

/// Reads a big-endian `u16` at `offset`.
pub fn be_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = fixed::<2>(bytes, offset)?;
    Ok(u16::from_be_bytes(raw))
}

/// Reads a big-endian `u64` at `offset`.
pub fn be_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw = fixed::<8>(bytes, offset)?;
    Ok(u64::from_be_bytes(raw))
}

/// Writes a little-endian `u16` at `offset`.
pub fn put_le_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<()> {
    put_fixed(bytes, offset, &value.to_le_bytes())
}

/// Writes a little-endian `u32` at `offset`.
pub fn put_le_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    put_fixed(bytes, offset, &value.to_le_bytes())
}

/// Writes a big-endian `u32` at `offset`.
pub fn put_be_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    put_fixed(bytes, offset, &value.to_be_bytes())
}

/// Writes a big-endian `u16` at `offset`.
pub fn put_be_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<()> {
    put_fixed(bytes, offset, &value.to_be_bytes())
}

/// Copies an exact-width byte array out of a checked range.
fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(Error::ArithmeticOverflow)?;
    let slice = bytes.get(offset..end).ok_or(Error::TruncatedStructure)?;
    let mut raw = [0_u8; N];
    raw.copy_from_slice(slice);
    Ok(raw)
}

/// Copies an exact-width byte array into a checked mutable range.
fn put_fixed(bytes: &mut [u8], offset: usize, source: &[u8]) -> Result<()> {
    let end = offset
        .checked_add(source.len())
        .ok_or(Error::ArithmeticOverflow)?;
    let target = bytes
        .get_mut(offset..end)
        .ok_or(Error::TruncatedStructure)?;
    target.copy_from_slice(source);
    Ok(())
}
