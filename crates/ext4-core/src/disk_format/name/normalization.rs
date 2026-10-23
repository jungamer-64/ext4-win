//! Unicode scalar mapping and ordering over authenticated, generated filesystem data.
//!
//! The table's source data and its derivatives are covered by LICENSE-UNICODE,
//! emitted alongside the table in the build output and retained in distributions.
//! The build generator owns its layout and verifies authenticated normalization vectors.

use crate::{Error, Result, memory::FallibleVec as _};
use alloc::vec::Vec;

/// Runtime artifact generated in Cargo's target-specific output directory.
const DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/casefold.bin"));
/// One closed scalar mapping record, including its canonical combining class.
const RECORD_BYTES: usize = 16;

/// Borrowed immutable table sections; offsets never escape their originating byte domain.
#[derive(Clone, Copy, Debug)]
struct Table {
    /// Sorted scalar records with closed casefold and canonical-decomposition mappings.
    records: &'static [u8],
    /// Sorted inclusive ranges of assigned scalars.
    assigned: &'static [u8],
    /// UTF-8 mapping payload, addressed only by record offsets.
    payload: &'static [u8],
}
impl Table {
    /// Establishes section boundaries for the generated artifact.
    /// # Errors
    /// Rejects stale layout markers, truncated sections or overflow.
    fn load() -> Result<Self> {
        if DATA.get(..8) != Some(b"U121CF03") {
            return Err(Error::InvalidName);
        }
        let records_len = usize::try_from(word(DATA, 8)?)
            .map_err(|_| Error::ArithmeticOverflow)?
            .checked_mul(RECORD_BYTES)
            .ok_or(Error::ArithmeticOverflow)?;
        let ranges_len = usize::try_from(word(DATA, 12)?)
            .map_err(|_| Error::ArithmeticOverflow)?
            .checked_mul(8)
            .ok_or(Error::ArithmeticOverflow)?;
        let records_end = 16_usize
            .checked_add(records_len)
            .ok_or(Error::ArithmeticOverflow)?;
        let ranges_end = records_end
            .checked_add(ranges_len)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Self {
            records: DATA.get(16..records_end).ok_or(Error::InvalidName)?,
            assigned: DATA
                .get(records_end..ranges_end)
                .ok_or(Error::InvalidName)?,
            payload: DATA.get(ranges_end..).ok_or(Error::InvalidName)?,
        })
    }
    /// Selects one scalar record without allocating or interpreting a different coordinate space.
    /// # Errors
    /// Rejects malformed artifact fields.
    fn record(self, cp: u32) -> Result<Option<&'static [u8]>> {
        let mut low = 0_usize;
        let mut high = self.records.len() / RECORD_BYTES;
        while low < high {
            let middle = low
                .checked_add(high.checked_sub(low).ok_or(Error::ArithmeticOverflow)? / 2)
                .ok_or(Error::ArithmeticOverflow)?;
            let start = middle
                .checked_mul(RECORD_BYTES)
                .ok_or(Error::ArithmeticOverflow)?;
            let end = start
                .checked_add(RECORD_BYTES)
                .ok_or(Error::ArithmeticOverflow)?;
            let record = self.records.get(start..end).ok_or(Error::InvalidName)?;
            match word(record, 0)?.cmp(&cp) {
                core::cmp::Ordering::Equal => return Ok(Some(record)),
                core::cmp::Ordering::Greater => high = middle,
                core::cmp::Ordering::Less => {
                    low = middle.checked_add(1).ok_or(Error::ArithmeticOverflow)?
                }
            }
        }
        Ok(None)
    }
    /// Checks age membership in the exact supported database, including future-unassigned scalars.
    /// # Errors
    /// Rejects malformed artifact range fields.
    fn admits(self, cp: u32) -> Result<bool> {
        let mut low = 0_usize;
        let mut high = self.assigned.len() / 8;
        while low < high {
            let middle = low
                .checked_add(high.checked_sub(low).ok_or(Error::ArithmeticOverflow)? / 2)
                .ok_or(Error::ArithmeticOverflow)?;
            let start = middle.checked_mul(8).ok_or(Error::ArithmeticOverflow)?;
            let end = start.checked_add(8).ok_or(Error::ArithmeticOverflow)?;
            let range = self.assigned.get(start..end).ok_or(Error::InvalidName)?;
            if cp < word(range, 0)? {
                high = middle;
            } else if cp > word(range, 4)? {
                low = middle.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
            } else {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Reads the canonical ordering class of an already admitted scalar.
    /// # Errors
    /// Rejects malformed artifact records.
    fn class(self, cp: char) -> Result<u8> {
        self.record(u32::from(cp))?
            .map(|record| record.get(12).copied().ok_or(Error::InvalidName))
            .unwrap_or(Ok(0))
    }
    /// Expands each closed scalar mapping, then stably orders the resulting non-starters.
    /// # Errors
    /// Preserves allocation, malformed artifact and invalid Unicode errors.
    fn apply(self, input: &str) -> Result<Vec<(char, u8)>> {
        let mut output = Vec::new();
        let mut segment_start = 0_usize;
        for cp in input.chars() {
            let mut identity = [0; 4];
            let mapping = match self.record(u32::from(cp))? {
                None => cp.encode_utf8(&mut identity),
                Some(record) => {
                    let field = 4_usize;
                    let start = usize::try_from(word(record, field)?)
                        .map_err(|_| Error::ArithmeticOverflow)?;
                    let size = usize::try_from(word(
                        record,
                        field.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
                    )?)
                    .map_err(|_| Error::ArithmeticOverflow)?;
                    let end = start.checked_add(size).ok_or(Error::ArithmeticOverflow)?;
                    core::str::from_utf8(self.payload.get(start..end).ok_or(Error::InvalidName)?)
                        .map_err(|_| Error::InvalidName)?
                }
            };
            // An omitted scalar still separates canonical ordering segments in the filesystem
            // encoding. Removing that boundary would move marks across an invisible starter.
            if mapping.is_empty() {
                segment_start = output.len();
            }
            for mapped in mapping.chars() {
                let class = self.class(mapped)?;
                let mut at = output.len();
                if class != 0 {
                    while at > segment_start {
                        let (_, prior) = output
                            .get(at.checked_sub(1).ok_or(Error::ArithmeticOverflow)?)
                            .ok_or(Error::InvalidName)?;
                        if *prior == 0 || *prior <= class {
                            break;
                        }
                        at = at.checked_sub(1).ok_or(Error::ArithmeticOverflow)?;
                    }
                }
                output.try_insert(at, (mapped, class))?;
                if class == 0 {
                    segment_start = output.len();
                }
            }
        }
        Ok(output)
    }
}
/// Validates the original input, expands closed scalar mappings, then orders their results.
/// ext4 hashes this observable ordering. A mapping that changes a combining class participates
/// using its result class; reordering the original scalar sequence first produces different keys.
/// # Errors
/// Returns invalid UTF-8, unsupported-age scalars, allocation or malformed generated data errors.
pub(super) fn fold(bytes: &[u8]) -> Result<Vec<u8>> {
    let input = core::str::from_utf8(bytes).map_err(|_| Error::InvalidName)?;
    let table = Table::load()?;
    for cp in input.chars() {
        if !table.admits(u32::from(cp))? {
            return Err(Error::InvalidName);
        }
    }
    encode(table.apply(input)?)
}
/// Encodes owned ordered scalars through fallible byte growth.
/// # Errors
/// Returns allocation failure.
fn encode(scalars: Vec<(char, u8)>) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for (cp, _) in scalars {
        let mut bytes = [0; 4];
        output.try_extend_from_slice(cp.encode_utf8(&mut bytes).as_bytes())?;
    }
    Ok(output)
}
/// Reads one little-endian field within its own immutable table section.
/// # Errors
/// Rejects truncated fields and overflow.
fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(Error::InvalidName)?
            .try_into()
            .map_err(|_| Error::InvalidName)?,
    ))
}
