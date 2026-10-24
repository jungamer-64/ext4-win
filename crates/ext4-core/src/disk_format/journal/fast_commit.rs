//! Delta-log framing establishes only a committed boundary, never metadata-write authority.
//!
//! Each TLV fits in one journal block. HEAD selects the expected JBD2 transaction; a TAIL
//! authenticates its preceding records with CRC32C seeded at zero. Its checksum and trailing
//! padding are excluded. CRC accumulation restarts after each tail. Bytes beyond the last valid
//! tail have no recovery authority; consumers must authenticate their reread before using data.
use super::{BlockSize, JournalSequence, disk_offset, ext4_crc32c, le_u16, le_u32};
use crate::{Error, Result};

/// Complete authenticated prefix observed during a write-free scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedPrefix {
    /// First byte beyond the final complete tail, relative to the delta area's first block.
    pub(super) end: u64,
    /// Number of semantic records before that boundary, excluding framing and padding.
    pub(super) records: usize,
}

/// A block scan either needs another block or has stopped at an uncommitted or stale suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScanStep {
    /// The declared area bounds how many further blocks may be supplied.
    Continue,
    /// Only this prefix may supply records; absence means no complete delta commit exists.
    Finished(Option<AuthenticatedPrefix>),
}

/// Framing state cannot accept payload before a matching initial HEAD or after termination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Framing {
    /// The first block must begin with HEAD; other contents belong to stale or unused space.
    Initial,
    /// The next tail authenticates the running CRC, including its own header and TID.
    Records(u32),
    /// No subsequent block may be mixed into this scan.
    Ended,
}

/// Allocation-free authentication state; retained counters are bounded by the physical log area.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FrameAuthenticator {
    /// Full-journal scan establishes the only transaction whose deltas may follow it.
    expected: JournalSequence,
    /// Exact block width admitted by journal geometry.
    block_bytes: usize,
    /// Stream position before the next complete block.
    consumed: u64,
    /// Number of semantic records observed, including any uncommitted suffix.
    records: usize,
    /// Last complete tail, independent of the currently uncommitted suffix.
    committed: Option<AuthenticatedPrefix>,
    /// HEAD/CRC/termination protocol, without a separate readiness flag.
    framing: Framing,
}
impl FrameAuthenticator {
    /// Starts a fresh bounded stream from its first reserved block.
    /// # Errors
    /// Rejects an unrepresentable block width.
    pub(super) fn new(expected: JournalSequence, block_size: BlockSize) -> Result<Self> {
        Ok(Self {
            expected,
            block_bytes: usize::try_from(block_size.bytes())
                .map_err(|_| Error::ArithmeticOverflow)?,
            consumed: 0,
            records: 0,
            committed: None,
            framing: Framing::Initial,
        })
    }
    /// A complete declared area can end with an uncommitted suffix.
    pub(super) const fn finish(self) -> Option<AuthenticatedPrefix> {
        self.committed
    }

    /// Ends admission of more input while retaining only previously authenticated records.
    fn stop(&mut self) -> ScanStep {
        self.framing = Framing::Ended;
        ScanStep::Finished(self.committed)
    }

    /// Authenticates one complete block without retaining pointers or allocating payload storage.
    /// # Errors
    /// Rejects transfer/state mismatch, unknown HEAD features, a bad first committed checksum or
    /// counter overflow. An incomplete suffix cannot extend an earlier committed prefix.
    pub(super) fn inspect(&mut self, block: &[u8]) -> Result<ScanStep> {
        if block.len() != self.block_bytes || self.framing == Framing::Ended {
            return Err(Error::JournalCorrupt);
        }
        if self.framing == Framing::Initial && le_u16(block, disk_offset(0))? != 9 {
            return Ok(self.stop());
        }
        let mut offset = 0_usize;
        while let Some(header) = block.get(offset..).and_then(|remaining| remaining.get(..4)) {
            let tag = le_u16(header, disk_offset(0))?;
            let length = usize::from(le_u16(header, disk_offset(2))?);
            let value_start = offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?;
            let Some(end) = value_start.checked_add(length) else {
                return Ok(self.stop());
            };
            let Some(value) = block.get(value_start..end) else {
                return Ok(self.stop());
            };
            let valid_length = match tag {
                1 => length == 16,
                2 => length == 12,
                3..=5 => (9..=263).contains(&length),
                6 => length >= 132,
                7 => true,
                8 => length >= 8,
                9 => length == 8,
                _ => false,
            };
            if !valid_length {
                return Ok(self.stop());
            }
            let mut crc = match self.framing {
                Framing::Initial => 0,
                Framing::Records(crc) => crc,
                Framing::Ended => return Err(Error::JournalCorrupt),
            };
            if tag == 9 {
                if le_u32(value, disk_offset(0))? != 0 {
                    return Err(Error::UnsupportedJournal);
                }
                if le_u32(value, disk_offset(4))? != self.expected.get() {
                    return Ok(self.stop());
                }
            }
            if tag == 8 {
                let checksum_end = value_start
                    .checked_add(4)
                    .ok_or(Error::ArithmeticOverflow)?;
                crc = ext4_crc32c(
                    crc,
                    block
                        .get(offset..checksum_end)
                        .ok_or(Error::JournalCorrupt)?,
                );
                if le_u32(value, disk_offset(0))? != self.expected.get()
                    || le_u32(value, disk_offset(4))? != crc
                {
                    return if self.committed.is_some() {
                        Ok(self.stop())
                    } else {
                        Err(Error::ChecksumMismatch)
                    };
                }
                self.committed = Some(AuthenticatedPrefix {
                    end: self
                        .consumed
                        .checked_add(u64::try_from(end).map_err(|_| Error::ArithmeticOverflow)?)
                        .ok_or(Error::ArithmeticOverflow)?,
                    records: self.records,
                });
                self.framing = Framing::Records(0);
            } else {
                crc = ext4_crc32c(crc, block.get(offset..end).ok_or(Error::JournalCorrupt)?);
                self.framing = Framing::Records(crc);
                if (1..=6).contains(&tag) {
                    self.records = self
                        .records
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow)?;
                }
            }
            offset = end;
        }
        self.consumed = self
            .consumed
            .checked_add(u64::try_from(block.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(ScanStep::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Independent wire vector: HEAD, LINK(parent=2, inode=12, name=x), padded TAIL.
    /// CRC32C values were calculated by a separate bitwise polynomial implementation.
    fn first_block() -> [u8; 4096] {
        let mut block = [0; 4096];
        for (target, value) in block.iter_mut().zip([
            9, 0, 8, 0, 0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 4, 0, 9, 0, 2, 0, 0, 0, 12, 0, 0, 0,
            b'x', 8, 0, 0xe3, 0x0f, 0x78, 0x56, 0x34, 0x12, 0x9b, 0xeb, 0x88, 0xf9,
        ]) {
            *target = value;
        }
        block
    }
    /// Another independently checksummed batch starts without repeating HEAD.
    fn second_block() -> [u8; 4096] {
        let mut block = [0; 4096];
        for (target, value) in block.iter_mut().zip([
            5, 0, 9, 0, 2, 0, 0, 0, 12, 0, 0, 0, b'x', 8, 0, 0xef, 0x0f, 0x78, 0x56, 0x34, 0x12, 2,
            0xd6, 0x27, 0xf6,
        ]) {
            *target = value;
        }
        block
    }
    /// # Panics
    /// Fails if TID binding, per-tail CRC restart or padding exclusion differs from wire vectors.
    #[test]
    fn independent_complete_batches_preserve_only_the_committed_prefix() {
        let result = (|| -> Result<()> {
            let mut scan = FrameAuthenticator::new(
                JournalSequence::new(0x1234_5678),
                BlockSize::from_superblock_log(2)?,
            )?;
            let mut first = first_block();
            first[4095] = 0xa5; // TAIL padding is outside its authenticated content.
            assert_eq!(scan.inspect(&first)?, ScanStep::Continue);
            assert_eq!(
                scan.finish(),
                Some(AuthenticatedPrefix {
                    end: 4096,
                    records: 1
                })
            );
            assert_eq!(scan.inspect(&second_block())?, ScanStep::Continue);
            let committed = Some(AuthenticatedPrefix {
                end: 8192,
                records: 2,
            });
            assert_eq!(scan.finish(), committed);
            assert_eq!(scan.inspect(&[0; 4096])?, ScanStep::Finished(committed));
            assert_eq!(scan.inspect(&first), Err(Error::JournalCorrupt));
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }
    /// # Panics
    /// Fails if corruption extends a prefix, stale TIDs replay, or uncommitted records are admitted.
    #[test]
    fn torn_or_stale_suffix_never_acquires_recovery_authority() {
        let result = (|| -> Result<()> {
            let size = BlockSize::from_superblock_log(2)?;
            let expected = JournalSequence::new(0x1234_5678);
            let mut corrupt = first_block();
            corrupt[24] = b'y';
            assert_eq!(
                FrameAuthenticator::new(expected, size)?.inspect(&corrupt),
                Err(Error::ChecksumMismatch)
            );
            let mut scan = FrameAuthenticator::new(expected, size)?;
            scan.inspect(&first_block())?;
            let mut second = second_block();
            second[21] ^= 1;
            assert_eq!(
                scan.inspect(&second)?,
                ScanStep::Finished(Some(AuthenticatedPrefix {
                    end: 4096,
                    records: 1
                }))
            );
            assert_eq!(
                FrameAuthenticator::new(JournalSequence::new(0), size)?.inspect(&first_block())?,
                ScanStep::Finished(None)
            );
            let mut unknown = first_block();
            unknown[4] = 1;
            assert_eq!(
                FrameAuthenticator::new(expected, size)?.inspect(&unknown),
                Err(Error::UnsupportedJournal)
            );
            let mut torn = first_block();
            torn[25] = 0;
            torn[26] = 0;
            assert_eq!(
                FrameAuthenticator::new(expected, size)?.inspect(&torn)?,
                ScanStep::Finished(None)
            );
            let mut overrun = first_block();
            overrun[14] = 0xff;
            overrun[15] = 0xff;
            assert_eq!(
                FrameAuthenticator::new(expected, size)?.inspect(&overrun)?,
                ScanStep::Finished(None)
            );
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }
}
