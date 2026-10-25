//! Complete delta batches are allocated and encoded before the first device write.
use super::*;
use crate::{disk_format::extent::ExtentInitialization, memory::FallibleVec};

/// Borrowed semantic inputs keep generated snapshots and decoded programs under their own owners.
#[derive(Clone, Copy, Debug)]
pub(in crate::disk_format::journal) enum DeltaRecord<'a> {
    /// Logical mapping assignment, distinct from the physical address it references.
    AddRange {
        /// Inode identity.
        inode: InodeId,
        /// Validated extent shape.
        extent: Extent,
    },
    /// Removal is a file-coordinate postcondition, not a device write or deallocation procedure.
    RemoveRange {
        /// Inode identity.
        inode: InodeId,
        /// Checked logical span.
        range: LogicalRange,
    },
    /// Namespace outcome and creation initialization remain different semantic facts.
    Namespace {
        /// Operation-specific postcondition.
        change: NamespaceChange,
        /// Directory identity.
        parent: InodeId,
        /// Target identity.
        inode: InodeId,
        /// Raw, retained on-disk component.
        name: &'a [u8],
    },
    /// Complete inode metadata prefix; unrelated inode-body attributes remain outside the input.
    Inode {
        /// Inode identity.
        inode: InodeId,
        /// Stable bytes borrowed from the owning commit image.
        encoded: &'a [u8],
    },
}
impl<'a> From<&'a ParsedDelta> for DeltaRecord<'a> {
    fn from(record: &'a ParsedDelta) -> Self {
        match record {
            ParsedDelta::AddRange { inode, extent } => Self::AddRange {
                inode: *inode,
                extent: *extent,
            },
            ParsedDelta::RemoveRange { inode, range } => Self::RemoveRange {
                inode: *inode,
                range: *range,
            },
            ParsedDelta::Namespace {
                change,
                parent,
                inode,
                name,
            } => Self::Namespace {
                change: *change,
                parent: *parent,
                inode: *inode,
                name: name.bytes(),
            },
            ParsedDelta::Inode { inode, encoded } => Self::Inode {
                inode: *inode,
                encoded,
            },
        }
    }
}

/// Owns every encoded block and a finite physical block budget, without lower I/O authority.
struct Encoder {
    /// Completed blocks contain only records or authenticated padding, never a tail.
    blocks: Vec<Vec<u8>>,
    /// Unique current block, initialized before any header is written.
    current: Vec<u8>,
    /// First unused byte of the current block.
    used: usize,
    /// CRC for all encoded records and padding preceding the eventual tail checksum.
    crc: u32,
    /// Complete block limit; exhaustion is a full-commit fallback before any effect.
    limit: usize,
}
impl Encoder {
    /// Admits the physical budget before allocating its first block.
    /// # Errors
    /// Returns zero-capacity, arithmetic or allocation failure.
    fn new(size: BlockSize, limit: u32) -> Result<Self> {
        if limit == 0 {
            return Err(Error::TransactionTooLarge);
        }
        Ok(Self {
            blocks: Vec::new(),
            current: memory::repeated_vec(
                0,
                usize::try_from(size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
            )?,
            used: 0,
            crc: 0,
            limit: usize::try_from(limit).map_err(|_| Error::ArithmeticOverflow)?,
        })
    }
    /// Copies one bounded scalar or payload component without partial scalar publication.
    /// # Errors
    /// Rejects a destination outside this preallocated block.
    fn put(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        memory::copy_exact(
            self.current
                .get_mut(offset..end)
                .ok_or(Error::JournalCorrupt)?,
            bytes,
        )
    }
    /// Completes the current block with a PAD TLV before transferring its buffer into the plan.
    /// # Errors
    /// Distinguishes physical-area exhaustion from malformed state and allocation failure.
    fn next_block(&mut self) -> Result<()> {
        if self
            .blocks
            .len()
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?
            >= self.limit
        {
            return Err(Error::TransactionTooLarge);
        }
        let remaining = self
            .current
            .len()
            .checked_sub(self.used)
            .ok_or(Error::JournalCorrupt)?;
        let padding = remaining.checked_sub(4).ok_or(Error::JournalCorrupt)?;
        self.put(self.used, &Tag::Padding.code().to_le_bytes())?;
        self.put(
            self.used.checked_add(2).ok_or(Error::ArithmeticOverflow)?,
            &u16::try_from(padding)
                .map_err(|_| Error::TransactionTooLarge)?
                .to_le_bytes(),
        )?;
        self.crc = ext4_crc32c(
            self.crc,
            self.current.get(self.used..).ok_or(Error::JournalCorrupt)?,
        );
        let fresh = memory::repeated_vec(0, self.current.len())?;
        self.blocks
            .try_push(core::mem::replace(&mut self.current, fresh))?;
        self.used = 0;
        Ok(())
    }
    /// Leaves room for a padding header so no subsequent record can straddle a block.
    /// # Errors
    /// Returns an unrepresentable TLV, exhausted area or allocation failure before effects.
    fn append(&mut self, tag: Tag, pieces: &[&[u8]]) -> Result<()> {
        let length = pieces.iter().try_fold(0_usize, |count, piece| {
            count
                .checked_add(piece.len())
                .ok_or(Error::ArithmeticOverflow)
        })?;
        let encoded_length = u16::try_from(length).map_err(|_| Error::TransactionTooLarge)?;
        Tag::parse(tag.code(), length)?;
        let reserved = length.checked_add(8).ok_or(Error::ArithmeticOverflow)?;
        if reserved > self.current.len() {
            return Err(Error::TransactionTooLarge);
        }
        if self
            .current
            .len()
            .checked_sub(self.used)
            .ok_or(Error::JournalCorrupt)?
            < reserved
        {
            self.next_block()?;
        }
        let start = self.used;
        self.put(start, &tag.code().to_le_bytes())?;
        self.put(
            start.checked_add(2).ok_or(Error::ArithmeticOverflow)?,
            &encoded_length.to_le_bytes(),
        )?;
        self.used = start.checked_add(4).ok_or(Error::ArithmeticOverflow)?;
        for bytes in pieces {
            self.put(self.used, bytes)?;
            self.used = self
                .used
                .checked_add(bytes.len())
                .ok_or(Error::ArithmeticOverflow)?;
        }
        self.crc = ext4_crc32c(
            self.crc,
            self.current
                .get(start..self.used)
                .ok_or(Error::JournalCorrupt)?,
        );
        Ok(())
    }
    /// Tail padding cannot contain a later commit; only header and TID extend its checksum.
    /// # Errors
    /// Returns physical-budget, coordinate or allocation failure before publishing the write plan.
    fn finish(mut self, tid: JournalSequence) -> Result<Vec<Vec<u8>>> {
        if self
            .current
            .len()
            .checked_sub(self.used)
            .ok_or(Error::JournalCorrupt)?
            < 12
        {
            self.next_block()?;
        }
        let length = self
            .current
            .len()
            .checked_sub(self.used)
            .and_then(|value| value.checked_sub(4))
            .ok_or(Error::JournalCorrupt)?;
        self.put(self.used, &Tag::Tail.code().to_le_bytes())?;
        self.put(
            self.used.checked_add(2).ok_or(Error::ArithmeticOverflow)?,
            &u16::try_from(length)
                .map_err(|_| Error::TransactionTooLarge)?
                .to_le_bytes(),
        )?;
        self.put(
            self.used.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
            &tid.get().to_le_bytes(),
        )?;
        let crc_end = self.used.checked_add(8).ok_or(Error::ArithmeticOverflow)?;
        let crc = ext4_crc32c(
            self.crc,
            self.current
                .get(self.used..crc_end)
                .ok_or(Error::JournalCorrupt)?,
        );
        self.put(crc_end, &crc.to_le_bytes())?;
        self.blocks.try_push(self.current)?;
        Ok(self.blocks)
    }
}

/// Serializes a complete one-tail commit; no encoded block is exposed after a failed attempt.
/// # Errors
/// Returns malformed input, finite-area exhaustion, field-width overflow or allocation failure.
pub(in crate::disk_format::journal) fn encode<'a>(
    size: BlockSize,
    tid: JournalSequence,
    capacity: u32,
    records: impl IntoIterator<Item = Result<DeltaRecord<'a>>>,
) -> Result<Vec<Vec<u8>>> {
    let mut writer = Encoder::new(size, capacity)?;
    writer.append(Tag::Head, &[&0_u32.to_le_bytes(), &tid.get().to_le_bytes()])?;
    for record in records {
        match record? {
            DeltaRecord::Inode { inode, encoded } => {
                writer.append(Tag::Inode, &[&inode.as_u32().to_le_bytes(), encoded])?
            }
            DeltaRecord::Namespace {
                change,
                parent,
                inode,
                name,
            } => {
                let tag = match change {
                    NamespaceChange::Create => Tag::Create,
                    NamespaceChange::Link => Tag::Link,
                    NamespaceChange::Unlink => Tag::Unlink,
                };
                writer.append(
                    tag,
                    &[
                        &parent.as_u32().to_le_bytes(),
                        &inode.as_u32().to_le_bytes(),
                        name,
                    ],
                )?;
            }
            DeltaRecord::RemoveRange { inode, range } => {
                let length = u32::try_from(
                    range
                        .end
                        .checked_sub(range.first.as_u64())
                        .ok_or(Error::JournalCorrupt)?,
                )
                .map_err(|_| Error::JournalCorrupt)?;
                writer.append(
                    Tag::RemoveRange,
                    &[
                        &inode.as_u32().to_le_bytes(),
                        &range.first.as_u32().to_le_bytes(),
                        &length.to_le_bytes(),
                    ],
                )?;
            }
            DeltaRecord::AddRange { inode, extent } => {
                let physical = extent.physical_start().get();
                let low =
                    u32::try_from(physical & 0xffff_ffff).map_err(|_| Error::InvalidExtentTree)?;
                let high = u16::try_from(physical >> 32).map_err(|_| Error::InvalidExtentTree)?;
                let length = match extent.initialization() {
                    ExtentInitialization::Initialized => extent.len().as_u16(),
                    ExtentInitialization::Uninitialized => extent
                        .len()
                        .as_u16()
                        .checked_add(0x8000)
                        .ok_or(Error::InvalidExtentTree)?,
                };
                writer.append(
                    Tag::AddRange,
                    &[
                        &inode.as_u32().to_le_bytes(),
                        &extent.logical_start().as_u32().to_le_bytes(),
                        &length.to_le_bytes(),
                        &high.to_le_bytes(),
                        &low.to_le_bytes(),
                    ],
                )?;
            }
        }
    }
    writer.finish(tid)
}
