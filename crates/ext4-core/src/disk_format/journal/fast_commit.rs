//! Delta-log framing establishes only a committed boundary, never metadata-write authority.
//!
//! Each TLV fits in one journal block. HEAD selects the expected JBD2 transaction; a TAIL
//! authenticates its preceding records with CRC32C seeded at zero. Its checksum and trailing
//! padding are excluded. CRC accumulation restarts after each tail. Bytes beyond the last valid
//! tail have no recovery authority; consumers must authenticate their reread before using data.
use super::{BlockSize, JournalSequence, disk_offset, ext4_crc32c, le_u16, le_u32};
use crate::disk_format::{
    extent::{Extent, LogicalBlock, parse_extent},
    inode::InodeId,
    name::Ext4Name,
};
use crate::memory;
use crate::{Error, Result};
use alloc::vec::Vec;

/// Context-free wire interpretation, independent of inode allocation and mutation permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tag {
    AddRange,
    RemoveRange,
    Create,
    Link,
    Unlink,
    Inode,
    Padding,
    Tail,
    Head,
}
impl Tag {
    /// The fixed opcode and value-length contract is shared by authentication and decoding.
    /// # Errors
    /// Rejects unknown opcodes and structurally invalid values before any payload interpretation.
    fn parse(raw: u16, length: usize) -> Result<Self> {
        let tag = match raw {
            1 if length == 16 => Self::AddRange,
            2 if length == 12 => Self::RemoveRange,
            3 if (9..=263).contains(&length) => Self::Create,
            4 if (9..=263).contains(&length) => Self::Link,
            5 if (9..=263).contains(&length) => Self::Unlink,
            6 if length >= 132 => Self::Inode,
            7 => Self::Padding,
            8 if length >= 8 => Self::Tail,
            9 if length == 8 => Self::Head,
            _ => return Err(Error::JournalCorrupt),
        };
        Ok(tag)
    }
    /// Framing and padding do not count toward semantic replay allocation.
    const fn is_delta(self) -> bool {
        matches!(
            self,
            Self::AddRange
                | Self::RemoveRange
                | Self::Create
                | Self::Link
                | Self::Unlink
                | Self::Inode
        )
    }
}

/// An immutable borrowed record cannot cross its block or outlive the returned transfer buffer.
struct Tlv<'a> {
    /// Validated opcode and value-width relation.
    tag: Tag,
    /// Header and complete value used by the running CRC.
    encoded: &'a [u8],
    /// Bounded little-endian value excluding its header.
    value: &'a [u8],
    /// Next record position within this same block.
    end: usize,
}
impl<'a> Tlv<'a> {
    /// Establishes the header/value bounds together, without copying or allocation.
    /// # Errors
    /// Rejects truncation, unknown tags and values that cross the block boundary.
    fn read(block: &'a [u8], offset: usize) -> Result<Self> {
        let remaining = block.get(offset..).ok_or(Error::JournalCorrupt)?;
        let length = usize::from(le_u16(remaining, disk_offset(2))?);
        let tag = Tag::parse(le_u16(remaining, disk_offset(0))?, length)?;
        let width = 4_usize
            .checked_add(length)
            .ok_or(Error::ArithmeticOverflow)?;
        let encoded = remaining.get(..width).ok_or(Error::JournalCorrupt)?;
        Ok(Self {
            tag,
            encoded,
            value: encoded.get(4..).ok_or(Error::JournalCorrupt)?,
            end: offset.checked_add(width).ok_or(Error::ArithmeticOverflow)?,
        })
    }
}

/// Half-open file-block range; an exclusive endpoint may be exactly one past the u32 domain.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LogicalRange {
    /// File-relative start, never a physical filesystem block.
    pub(crate) first: LogicalBlock,
    /// Exclusive logical block coordinate, including the one-past boundary.
    pub(crate) end: u64,
}
impl LogicalRange {
    /// Establishes nonempty checked range arithmetic at the wire boundary.
    /// # Errors
    /// Rejects zero length or a range beyond the complete logical block address domain.
    fn new(first: u32, length: u32) -> Result<Self> {
        let end = u64::from(first)
            .checked_add(u64::from(length))
            .ok_or(Error::JournalCorrupt)?;
        if length == 0 || end > 1_u64 << 32 {
            return Err(Error::JournalCorrupt);
        }
        Ok(Self {
            first: LogicalBlock::from_u32(first),
            end,
        })
    }
}
/// Create includes inode/directory initialization; linking and unlinking existing identities do not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NamespaceChange {
    Create,
    Link,
    Unlink,
}

/// Decoded delta operands still require filesystem-specific admission before metadata editing.
#[derive(Debug)]
pub(crate) enum ParsedDelta {
    /// Assigns an initialized or unwritten extent to a logical range.
    AddRange {
        /// Target identity, independent of physical block numbers.
        inode: InodeId,
        /// Checked extent-format coordinates.
        extent: Extent,
    },
    /// Removes mappings without interpreting length as a physical address.
    RemoveRange {
        /// Target inode.
        inode: InodeId,
        /// Complete checked file-relative range.
        range: LogicalRange,
    },
    /// Enforces a directory-entry postcondition; replay must restore final link counts separately.
    Namespace {
        /// Exact semantic postcondition, including creation initialization.
        change: NamespaceChange,
        /// Parent inode identity.
        parent: InodeId,
        /// Recorded target for links and conditional unlink.
        inode: InodeId,
        /// Opaque on-disk name, interpreted under the parent's actual policy.
        name: Ext4Name,
    },
    /// Partial raw inode image; layout, flags, allocation and checksum admission remain separate.
    Inode {
        /// Stable target identity.
        inode: InodeId,
        /// At least the base inode width, bounded by its single TLV.
        encoded: Vec<u8>,
    },
}
impl ParsedDelta {
    /// Decodes only semantic records after their complete TLV bounds have been established.
    /// # Errors
    /// Rejects zero inode identities, invalid extents/ranges and allocation failure.
    fn decode(record: &Tlv<'_>) -> Result<Option<Self>> {
        let value = record.value;
        let inode = |offset| InodeId::try_from(le_u32(value, disk_offset(offset))?);
        Ok(Some(match record.tag {
            Tag::AddRange => Self::AddRange {
                inode: inode(0)?,
                extent: parse_extent(value, 4)?,
            },
            Tag::RemoveRange => Self::RemoveRange {
                inode: inode(0)?,
                range: LogicalRange::new(
                    le_u32(value, disk_offset(4))?,
                    le_u32(value, disk_offset(8))?,
                )?,
            },
            Tag::Create | Tag::Link | Tag::Unlink => Self::Namespace {
                change: match record.tag {
                    Tag::Create => NamespaceChange::Create,
                    Tag::Link => NamespaceChange::Link,
                    _ => NamespaceChange::Unlink,
                },
                parent: inode(0)?,
                inode: inode(4)?,
                name: Ext4Name::from_disk(value.get(8..).ok_or(Error::JournalCorrupt)?)?,
            },
            Tag::Inode => Self::Inode {
                inode: inode(0)?,
                encoded: memory::copied_slice(value.get(4..).ok_or(Error::JournalCorrupt)?)?,
            },
            Tag::Padding | Tag::Head | Tag::Tail => return Ok(None),
        }))
    }
}

/// All retained records have been decoded from the exact reread's authenticated complete prefix.
#[derive(Debug)]
pub(crate) struct DeltaProgram {
    /// Unique owned operands; there is no independent raw-byte cache.
    records: Vec<ParsedDelta>,
}
impl DeltaProgram {
    /// Moves the immutable program into its sole filesystem recovery consumer.
    pub(crate) fn into_records(self) -> Vec<ParsedDelta> {
        self.records
    }
}

/// Owns the second pass without issuing writes or borrowing a lower transfer across completion.
#[derive(Debug)]
pub(super) struct ProgramDecoder {
    /// First-pass bounds are resource observations, not a substitute for reread authentication.
    expected: AuthenticatedPrefix,
    /// Sole stream position and CRC source for the second pass.
    authentication: FrameAuthenticator,
    /// Fallibly reserved before reading operands; changed record counts cannot grow the reservation.
    records: Vec<ParsedDelta>,
}
impl ProgramDecoder {
    /// Reserves the exact authenticated operand count before any replay effect.
    /// # Errors
    /// Returns allocation or coordinate-width failure.
    pub(super) fn new(
        tid: JournalSequence,
        size: BlockSize,
        expected: AuthenticatedPrefix,
    ) -> Result<Self> {
        let mut records = Vec::new();
        records
            .try_reserve_exact(expected.records)
            .map_err(|_| Error::OutOfMemory)?;
        Ok(Self {
            expected,
            authentication: FrameAuthenticator::new(tid, size)?,
            records,
        })
    }
    /// Byte coordinates are converted to a zero-based area index only at this checked boundary.
    /// # Errors
    /// Rejects index overflow or a stream position not aligned to its fixed block width.
    pub(super) fn next_block_index(&self) -> Result<u32> {
        let unit = u64::try_from(self.authentication.block_bytes)
            .map_err(|_| Error::ArithmeticOverflow)?;
        if !self.authentication.consumed.is_multiple_of(unit) {
            return Err(Error::JournalCorrupt);
        }
        u32::try_from(
            self.authentication
                .consumed
                .checked_div(unit)
                .ok_or(Error::JournalCorrupt)?,
        )
        .map_err(|_| Error::JournalCorrupt)
    }
    /// Copies only bounded semantic operands and verifies the exact reread before yielding a program.
    /// # Errors
    /// Rejects changed framing/checksums, invalid operands, exceeded reservation or allocation failure.
    pub(super) fn accept(&mut self, block: &[u8]) -> Result<bool> {
        let remaining = self
            .expected
            .end
            .checked_sub(self.authentication.consumed)
            .ok_or(Error::JournalCorrupt)?;
        if remaining == 0 || block.len() != self.authentication.block_bytes {
            return Err(Error::JournalCorrupt);
        }
        let limit = block
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let mut offset = 0_usize;
        while offset.checked_add(4).is_some_and(|end| end <= limit) {
            let record = Tlv::read(block, offset)?;
            if record.end > limit {
                return Err(Error::JournalCorrupt);
            }
            if let Some(delta) = ParsedDelta::decode(&record)? {
                self.records
                    .push_within_capacity(delta)
                    .map_err(|_delta| Error::JournalCorrupt)?;
            }
            offset = record.end;
        }
        let step = self.authentication.inspect(block)?;
        let done = self.authentication.consumed >= self.expected.end;
        if (!done && matches!(step, ScanStep::Finished(_)))
            || (done && self.authentication.finish() != Some(self.expected))
        {
            return Err(Error::ChecksumMismatch);
        }
        Ok(done)
    }
    /// The complete immutable program exists only after reread authentication and bounded decoding.
    /// # Errors
    /// Rejects partial input, changed commitment or a record-count mismatch.
    pub(super) fn finish(self) -> Result<DeltaProgram> {
        if self.authentication.consumed < self.expected.end
            || self.authentication.finish() != Some(self.expected)
            || self.records.len() != self.expected.records
        {
            return Err(Error::JournalCorrupt);
        }
        Ok(DeltaProgram {
            records: self.records,
        })
    }
}

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
        let block_start = self.consumed;
        self.consumed = self
            .consumed
            .checked_add(u64::try_from(block.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        if self.framing == Framing::Initial
            && !Tlv::read(block, 0).is_ok_and(|record| record.tag == Tag::Head)
        {
            return Ok(self.stop());
        }
        let mut offset = 0_usize;
        while offset.checked_add(4).is_some_and(|end| end <= block.len()) {
            let record = match Tlv::read(block, offset) {
                Ok(record) => record,
                Err(_error) => return Ok(self.stop()),
            };
            let tag = record.tag;
            let value = record.value;
            let end = record.end;
            let mut crc = match self.framing {
                Framing::Initial => 0,
                Framing::Records(crc) => crc,
                Framing::Ended => return Err(Error::JournalCorrupt),
            };
            if tag == Tag::Head {
                if le_u32(value, disk_offset(0))? != 0 {
                    return Err(Error::UnsupportedJournal);
                }
                if le_u32(value, disk_offset(4))? != self.expected.get() {
                    return Ok(self.stop());
                }
            }
            if tag == Tag::Tail {
                crc = ext4_crc32c(crc, record.encoded.get(..8).ok_or(Error::JournalCorrupt)?);
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
                    end: block_start
                        .checked_add(u64::try_from(end).map_err(|_| Error::ArithmeticOverflow)?)
                        .ok_or(Error::ArithmeticOverflow)?,
                    records: self.records,
                });
                self.framing = Framing::Records(0);
            } else {
                crc = ext4_crc32c(crc, record.encoded);
                self.framing = Framing::Records(crc);
                if tag.is_delta() {
                    self.records = self
                        .records
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow)?;
                }
            }
            offset = end;
        }
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
