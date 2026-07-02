//! Checksum algorithms and verification helpers used at on-disk boundaries.
//!
//! The rest of the domain should call these helpers with already-selected seeds
//! and byte ranges. Feature-specific seed construction stays with the parser that
//! understands that structure.

use crate::disk::endian::{DiskByteLen, DiskOffset, DiskRange, le_u32};
use crate::error::{Error, Result};
use crate::memory;

/// Reversed Castagnoli polynomial used by ext4 metadata checksums.
const CRC32C_POLY_REVERSED: u32 = 0x82F6_3B78;
/// Reversed CRC16 polynomial used by legacy group descriptor checksums.
const CRC16_POLY_REVERSED: u16 = 0xA001;

/// Computes ext4's CRC32C value with the supplied seed.
pub(crate) fn crc32c(seed: u32, bytes: &[u8]) -> u32 {
    let mut crc = !seed;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _bit in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC32C_POLY_REVERSED & mask);
        }
    }
    !crc
}

/// Computes ext4's legacy CRC16 value with the supplied seed.
pub(crate) fn crc16(seed: u16, bytes: &[u8]) -> u16 {
    let mut crc = seed;
    for byte in bytes {
        crc ^= u16::from(*byte);
        for _bit in 0..8 {
            let mask = 0_u16.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC16_POLY_REVERSED & mask);
        }
    }
    crc
}

/// Verifies a little-endian CRC32C field after zeroing the checksum bytes.
/// # Errors
///
/// Returns an error when the checksum field cannot be read, the checksum range cannot be zeroed, or
/// the computed CRC32C does not match the stored value.
pub(crate) fn verify_crc32c(seed: u32, bytes: &[u8], checksum_offset: DiskOffset) -> Result<()> {
    let expected = le_u32(bytes, checksum_offset)?;
    let mut checked = memory::copied_slice(bytes)?;
    let checksum_end = checksum_offset.checked_add(DiskByteLen::new(4))?;
    DiskRange::span(checksum_offset, checksum_end)?
        .write_to(&mut checked)?
        .fill(0);
    if crc32c(seed, &checked) == expected {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch)
    }
}
