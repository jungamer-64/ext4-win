//! Multiple-mount record encoding. These bytes bypass journal and metadata caches.

use crate::disk::checksum::ext4_crc32c;
use crate::disk::endian::{DiskOffset, le_u16, le_u32, put_fixed, put_le_u16, put_le_u32};
use crate::{Error, Result};

/// Immutable physical placement and checksum domain selected by primary metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MmpParameters {
    /// Dedicated filesystem block, never a journal destination.
    pub(crate) block: crate::disk::block::BlockAddress,
    /// Lower transfers preserve the entire filesystem block.
    pub(crate) bytes: crate::BlockSize,
    /// Metadata checksum feature selects authentication, including explicit seed support.
    pub(crate) seed: Option<u32>,
    /// Requested heartbeat period; zero on disk selects the format's minimum interval.
    pub(crate) update_seconds: u16,
}

/// Fixed record size; larger filesystem blocks retain their remaining bytes.
pub(crate) const RECORD_BYTES: usize = 1024;
/// Released media ownership.
pub(crate) const CLEAN: u32 = 0xff4d_4d50;
/// Offline checker ownership; it cannot be reclaimed by a mount.
pub(crate) const CHECKER: u32 = 0xe24d_4d50;
/// Greatest ordinary sequence value.
pub(crate) const LAST_SEQUENCE: u32 = 0xe24d_4d4f;
/// Minimum advertised observation interval, in seconds.
pub(crate) const MIN_INTERVAL: u16 = 5;

/// Observable owner state used when comparing independent device reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MmpRecord {
    /// Ordinary sequence or a reserved clean/checker marker.
    pub(crate) sequence: u32,
    /// UTC seconds are diagnostic; elapsed-time admission never uses the wall clock.
    time: u64,
    /// Owner identifier compared together with the sequence.
    pub(crate) node: [u8; 64],
    /// Peer-advertised observation interval, in seconds.
    pub(crate) interval: u16,
}

impl MmpRecord {
    /// Authenticates the fixed record before interpreting any ownership field.
    /// # Errors
    /// Rejects a short record, reserved sequence, bad magic or checksum.
    pub(crate) fn parse(bytes: &[u8], seed: Option<u32>) -> Result<Self> {
        let record = bytes.get(..RECORD_BYTES).ok_or(Error::MmpCorrupt)?;
        let word = |offset| le_u32(record, DiskOffset::new(offset));
        if word(0)? != 0x004d_4d50 {
            return Err(Error::MmpCorrupt);
        }
        if let Some(seed) = seed
            && ext4_crc32c(seed, record.get(..1020).ok_or(Error::MmpCorrupt)?) != word(1020)?
        {
            return Err(Error::MmpCorrupt);
        }
        let sequence = word(4)?;
        if sequence > LAST_SEQUENCE && sequence != CLEAN && sequence != CHECKER {
            return Err(Error::MmpCorrupt);
        }
        Ok(Self {
            sequence,
            time: u64::from_le_bytes(
                record
                    .get(8..16)
                    .ok_or(Error::MmpCorrupt)?
                    .try_into()
                    .map_err(|_error| Error::MmpCorrupt)?,
            ),
            node: record
                .get(16..80)
                .ok_or(Error::MmpCorrupt)?
                .try_into()
                .map_err(|_error| Error::MmpCorrupt)?,
            interval: le_u16(record, DiskOffset::new(112))?,
        })
    }

    /// Encodes a complete record while preserving bytes outside its fixed extent.
    /// # Errors
    /// Rejects a destination shorter than the complete fixed record.
    pub(crate) fn write(
        bytes: &mut [u8],
        seed: Option<u32>,
        sequence: u32,
        time: u64,
        node: &[u8; 64],
        interval: u16,
    ) -> Result<()> {
        let record = bytes.get_mut(..RECORD_BYTES).ok_or(Error::MmpCorrupt)?;
        record.fill(0);
        put_le_u32(record, DiskOffset::new(0), 0x004d_4d50)?;
        put_le_u32(record, DiskOffset::new(4), sequence)?;
        put_fixed(record, DiskOffset::new(8), &time.to_le_bytes())?;
        put_fixed(record, DiskOffset::new(16), node)?;
        put_fixed(record, DiskOffset::new(80), b"ext4-win")?;
        put_le_u16(record, DiskOffset::new(112), interval)?;
        if let Some(seed) = seed {
            let checksum = ext4_crc32c(seed, record.get(..1020).ok_or(Error::MmpCorrupt)?);
            put_le_u32(record, DiskOffset::new(1020), checksum)?;
        }
        Ok(())
    }
}
