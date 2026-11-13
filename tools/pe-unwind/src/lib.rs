//! AMD64 PE runtime-function table and fixed prolog frame decoding.
//!
//! A fixed frame is the stack a function's prolog allocates, as recorded by its unwind codes:
//! register pushes, fixed allocations and frame-register saves, including chained records. It
//! excludes the return address, callee frames and any dynamic allocation.
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};
use core::fmt;

/// Rejection of an image whose runtime-function table or unwind records cannot be decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnwindError(&'static str);

impl fmt::Display for UnwindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl core::error::Error for UnwindError {}

/// One runtime-function entry and the fixed stack its prolog allocates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFrame {
    /// Inclusive image-relative function start.
    pub begin: u64,
    /// Exclusive image-relative function end.
    pub end: u64,
    /// Fixed prolog allocation decoded from the unwind record chain.
    pub fixed_bytes: u64,
}

/// Every runtime-function entry of one image, ordered by strictly increasing start.
#[derive(Debug)]
pub struct FrameTable {
    /// Preferred image base, for translating link-map addresses to RVAs.
    pub image_base: u64,
    /// Non-overlapping runtime functions in table order.
    pub frames: Vec<RuntimeFrame>,
}

impl FrameTable {
    /// Returns the frame whose entry starts exactly at `rva`.
    ///
    /// # Errors
    ///
    /// Rejects an address strictly inside a runtime function, which is not a function entry.
    /// An address outside every runtime function is a leaf without a prolog and has no frame.
    pub fn entry(&self, rva: u64) -> Result<Option<&RuntimeFrame>, UnwindError> {
        let position = self.frames.partition_point(|frame| frame.begin <= rva);
        let Some(index) = position.checked_sub(1) else {
            return Ok(None);
        };
        let Some(frame) = self.frames.get(index) else {
            return Ok(None);
        };
        if frame.begin == rva {
            Ok(Some(frame))
        } else if rva < frame.end {
            Err(UnwindError("address lies inside a runtime function"))
        } else {
            Ok(None)
        }
    }
}

/// A section's image address and file range.
#[derive(Debug)]
struct Section {
    /// Image-relative start.
    rva: u64,
    /// Initialized byte length.
    size: u64,
    /// Absolute file byte offset.
    offset: usize,
}

/// A parsed image retaining the exact immutable bytes being inspected.
#[derive(Debug)]
struct Image<'a> {
    /// Analysis snapshot.
    bytes: &'a [u8],
    /// Preferred base used only to translate link-map addresses.
    base: u64,
    /// Unique file-backed mappings.
    sections: Vec<Section>,
    /// Exception directory RVA.
    table: u64,
    /// Runtime function directory byte size.
    table_size: u64,
}

/// Reads a fixed-size little-endian field from a checked byte boundary.
/// # Errors
/// Returns an error for overflowing offsets or truncated bytes.
fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], UnwindError> {
    let end = offset
        .checked_add(N)
        .ok_or(UnwindError("PE offset overflow"))?;
    bytes
        .get(offset..end)
        .and_then(|value| <[u8; N]>::try_from(value).ok())
        .ok_or(UnwindError("truncated PE data"))
}
/// Checked arithmetic for byte/RVA range ends.
/// # Errors
/// Returns an overflow error.
fn add(value: u64, amount: u64) -> Result<u64, UnwindError> {
    value
        .checked_add(amount)
        .ok_or(UnwindError("PE address overflow"))
}
/// Reads a 16-bit file field.
/// # Errors
/// Returns a truncated field error.
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, UnwindError> {
    Ok(u16::from_le_bytes(field(bytes, offset)?))
}
/// Reads a 32-bit file field.
/// # Errors
/// Returns a truncated field error.
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, UnwindError> {
    Ok(u32::from_le_bytes(field(bytes, offset)?))
}
/// Computes a checked file offset.
/// # Errors
/// Returns an overflow error.
fn offset(value: usize, amount: usize) -> Result<usize, UnwindError> {
    value
        .checked_add(amount)
        .ok_or(UnwindError("PE offset overflow"))
}
/// Converts a file field to a host offset.
/// # Errors
/// Returns an error when the value does not fit `usize`.
fn host_offset(value: impl TryInto<usize>) -> Result<usize, UnwindError> {
    value
        .try_into()
        .map_err(|_| UnwindError("PE offset does not fit the host"))
}

impl<'a> Image<'a> {
    /// Establishes the AMD64 PE32+ and section mapping boundaries.
    /// # Errors
    /// Returns malformed or truncated PE headers and ranges.
    fn parse(bytes: &'a [u8]) -> Result<Self, UnwindError> {
        if !bytes.starts_with(b"MZ") {
            return Err(UnwindError("missing DOS signature"));
        }
        let pe = host_offset(u32_at(bytes, 0x3c)?)?;
        if field::<4>(bytes, pe)? != *b"PE\0\0" || u16_at(bytes, offset(pe, 4)?)? != 0x8664 {
            return Err(UnwindError("expected an AMD64 PE image"));
        }
        let count = u16_at(bytes, offset(pe, 6)?)?;
        let optional_size = usize::from(u16_at(bytes, offset(pe, 20)?)?);
        let optional = offset(pe, 24)?;
        bytes
            .get(optional..offset(optional, optional_size)?)
            .ok_or(UnwindError("truncated optional header"))?;
        if optional_size < 144
            || u16_at(bytes, optional)? != 0x20b
            || u32_at(bytes, offset(optional, 108)?)? < 4
        {
            return Err(UnwindError("missing PE32+ exception directory"));
        }
        let base = u64::from_le_bytes(field(bytes, offset(optional, 24)?)?);
        let table = u64::from(u32_at(bytes, offset(optional, 136)?)?);
        let table_size = u64::from(u32_at(bytes, offset(optional, 140)?)?);
        let mut sections = Vec::new();
        let mut entry = offset(optional, optional_size)?;
        for _ in 0..count {
            field::<40>(bytes, entry)?;
            let rva = u64::from(u32_at(bytes, offset(entry, 12)?)?);
            let size = u64::from(u32_at(bytes, offset(entry, 16)?)?);
            let raw = host_offset(u32_at(bytes, offset(entry, 20)?)?)?;
            bytes
                .get(raw..offset(raw, host_offset(size)?)?)
                .ok_or(UnwindError("truncated initialized PE section"))?;
            sections.push(Section {
                rva,
                size,
                offset: raw,
            });
            entry = offset(entry, 40)?;
        }
        Ok(Self {
            bytes,
            base,
            sections,
            table,
            table_size,
        })
    }

    /// Converts a file-backed RVA range to a unique checked file range.
    /// # Errors
    /// Returns unmapped, ambiguous, overflowing, or truncated ranges.
    fn at(&self, rva: u64, length: u64) -> Result<&'a [u8], UnwindError> {
        let end = add(rva, length)?;
        let mut matches = self.sections.iter().filter(|section| {
            section.rva <= rva
                && section
                    .rva
                    .checked_add(section.size)
                    .is_some_and(|end_of_section| end <= end_of_section)
        });
        let section = matches
            .next()
            .ok_or(UnwindError("unmapped file-backed RVA"))?;
        if matches.next().is_some() {
            return Err(UnwindError("ambiguous file-backed RVA"));
        }
        let relative = host_offset(
            rva.checked_sub(section.rva)
                .ok_or(UnwindError("RVA underflow"))?,
        )?;
        let start = offset(section.offset, relative)?;
        self.bytes
            .get(start..offset(start, host_offset(length)?)?)
            .ok_or(UnwindError("truncated PE mapping"))
    }

    /// Decodes finite, acyclic x64 unwind records and chained fixed allocations.
    /// # Errors
    /// Returns unmodeled opcodes, truncated operands, invalid flags, or excessive chains.
    fn stack(&self, rva: u64, active: &mut BTreeSet<u64>) -> Result<u64, UnwindError> {
        if !rva.is_multiple_of(4) || active.len() >= 128 || !active.insert(rva) {
            return Err(UnwindError("invalid or excessive chained unwind records"));
        }
        let header = field::<4>(self.at(rva, 4)?, 0)?;
        let [first, _, count, _] = header;
        let version = first & 7;
        let flags = first >> 3;
        if !matches!(version, 1 | 2) || flags & !7 != 0 || (flags & 4 != 0 && flags & 3 != 0) {
            return Err(UnwindError("unsupported unwind version or flags"));
        }
        let count = u64::from(count);
        let codes = self.at(
            add(rva, 4)?,
            count
                .checked_mul(2)
                .ok_or(UnwindError("unwind length overflow"))?,
        )?;
        let mut slots = codes.as_chunks::<2>().0.iter();
        let mut total = 0_u64;
        while let Some([_, encoding]) = slots.next() {
            let opcode = encoding & 15;
            let info = encoding >> 4;
            let mut operand = || {
                slots
                    .next()
                    .map(|slot| u64::from(u16::from_le_bytes(*slot)))
                    .ok_or(UnwindError("truncated unwind operands"))
            };
            let amount = match (opcode, info) {
                (0, _) => 8,
                (1, 0) => operand()?
                    .checked_mul(8)
                    .ok_or(UnwindError("unwind allocation overflow"))?,
                (1, 1) => {
                    let low = operand()?;
                    low | (operand()? << 16)
                }
                (2, _) => add(
                    u64::from(info)
                        .checked_mul(8)
                        .ok_or(UnwindError("unwind overflow"))?,
                    8,
                )?,
                (3, 0) => 0,
                (6, _) if version == 2 => 0,
                (4 | 8, _) => {
                    operand()?;
                    0
                }
                (5 | 9, _) => {
                    operand()?;
                    operand()?;
                    0
                }
                (10, 0 | 1) => add(
                    40,
                    u64::from(info)
                        .checked_mul(8)
                        .ok_or(UnwindError("unwind overflow"))?,
                )?,
                _ => return Err(UnwindError("unsupported unwind opcode")),
            };
            total = add(total, amount)?;
        }
        if flags & 4 != 0 {
            let aligned_slots = add(count, 1)? & !1;
            let chain = self.at(
                add(
                    add(rva, 4)?,
                    aligned_slots
                        .checked_mul(2)
                        .ok_or(UnwindError("unwind chain overflow"))?,
                )?,
                12,
            )?;
            if u32_at(chain, 0)? >= u32_at(chain, 4)? {
                return Err(UnwindError("invalid chained function range"));
            }
            total = add(total, self.stack(u64::from(u32_at(chain, 8)?), active)?)?;
        }
        active.remove(&rva);
        Ok(total)
    }
}

/// Decodes the fixed prolog frame of every runtime function in an AMD64 PE image.
///
/// # Errors
///
/// Returns malformed headers, a missing or malformed runtime-function table, unordered entries,
/// or unwind records outside the modeled opcode set.
pub fn decode(bytes: &[u8]) -> Result<FrameTable, UnwindError> {
    let image = Image::parse(bytes)?;
    if image.table == 0 || image.table_size == 0 || !image.table_size.is_multiple_of(12) {
        return Err(UnwindError("missing or malformed runtime function table"));
    }
    let table = image.at(image.table, image.table_size)?;
    let mut frames = Vec::new();
    let mut previous_end = None;
    for record in table.as_chunks::<12>().0 {
        let begin = u64::from(u32_at(record, 0)?);
        let end = u64::from(u32_at(record, 4)?);
        let unwind = u64::from(u32_at(record, 8)?);
        if begin >= end || previous_end.is_some_and(|previous| begin < previous) || unwind == 0 {
            return Err(UnwindError("invalid runtime function entry"));
        }
        image.at(
            begin,
            end.checked_sub(begin)
                .ok_or(UnwindError("function range underflow"))?,
        )?;
        frames.push(RuntimeFrame {
            begin,
            end,
            fixed_bytes: image.stack(unwind, &mut BTreeSet::new())?,
        });
        previous_end = Some(end);
    }
    Ok(FrameTable {
        image_base: image.base,
        frames,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    /// Writes synthetic PE fields with explicit fixture bounds.
    /// # Errors
    /// Returns a malformed fixture range.
    fn put(bytes: &mut [u8], offset: usize, data: &[u8]) -> Result<(), UnwindError> {
        let end = offset
            .checked_add(data.len())
            .ok_or(UnwindError("fixture offset overflow"))?;
        let destination = bytes
            .get_mut(offset..end)
            .ok_or(UnwindError("fixture field outside buffer"))?;
        for (destination, source) in destination.iter_mut().zip(data) {
            *destination = *source;
        }
        Ok(())
    }

    /// Two independently encoded AMD64 functions at a non-default preferred image base.
    /// # Errors
    /// Returns synthetic-field range failures.
    fn fixture() -> Result<Vec<u8>, UnwindError> {
        let mut bytes = vec![0; 2048];
        for (offset, data) in [
            (0, b"MZ".as_slice()),
            (0x80, b"PE\0\0"),
            (1088, &[1, 8, 3, 0, 8, 1, 32, 0, 1, 0x30]),
            (1104, &[1, 4, 1, 0, 4, 0x22]),
        ] {
            put(&mut bytes, offset, data)?;
        }
        for (offset, value) in [(0x84, 0x8664_u16), (0x86, 2), (0x94, 240), (0x98, 0x20b)] {
            put(&mut bytes, offset, &value.to_le_bytes())?;
        }
        put(&mut bytes, 0xb0, &0x0001_4000_0000_u64.to_le_bytes())?;
        for (offset, value) in [
            (0x3c, 0x80_u32),
            (0x104, 16),
            (0x120, 0x2000),
            (0x124, 24),
            (0x190, 512),
            (0x194, 0x1000),
            (0x198, 512),
            (0x19c, 512),
            (0x1b8, 1024),
            (0x1bc, 0x2000),
            (0x1c0, 1024),
            (0x1c4, 1024),
            (1024, 0x1000),
            (1028, 0x1100),
            (1032, 0x2040),
            (1036, 0x1100),
            (1040, 0x1200),
            (1044, 0x2050),
        ] {
            put(&mut bytes, offset, &value.to_le_bytes())?;
        }
        Ok(bytes)
    }

    /// Fixed allocations, entry lookup, chained records, and malformed wire data.
    /// # Errors
    /// Returns unexpected synthetic-field or parser failures.
    /// # Panics
    /// Panics when a known wire-format result changes.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "known-answer assertions intentionally fail this test after fallible fixture construction"
    )]
    fn unwind_wire_contract() -> Result<(), UnwindError> {
        let mut bytes = fixture()?;
        let decoded = decode(&bytes)?;
        assert_eq!(decoded.image_base, 0x0001_4000_0000);
        assert_eq!(
            decoded
                .frames
                .iter()
                .map(|frame| frame.fixed_bytes)
                .collect::<Vec<_>>(),
            [264, 24]
        );
        assert_eq!(
            decoded.entry(0x1100)?.map(|frame| frame.fixed_bytes),
            Some(24)
        );
        assert_eq!(decoded.entry(0x1300)?, None);
        assert!(decoded.entry(0x1004).is_err());
        put(&mut bytes, 1104, &[2, 4, 3, 0, 1, 6, 3, 6, 4, 0x22])?;
        assert_eq!(
            decode(&bytes)?.frames.last().map(|frame| frame.fixed_bytes),
            Some(24)
        );
        put(&mut bytes, 1104, &[33, 0, 0, 0])?;
        for (offset, value) in [(1108, 0x1000_u32), (1112, 0x1100), (1116, 0x2040)] {
            put(&mut bytes, offset, &value.to_le_bytes())?;
        }
        assert!(
            decode(&bytes)?
                .frames
                .iter()
                .all(|frame| frame.fixed_bytes == 264)
        );
        put(&mut bytes, 1116, &0x2050_u32.to_le_bytes())?;
        assert!(decode(&bytes).is_err());
        bytes = fixture()?;
        put(&mut bytes, 1090, &[1])?;
        assert!(decode(&bytes).is_err());
        bytes = fixture()?;
        put(&mut bytes, 1104, &[3])?;
        assert!(decode(&bytes).is_err());
        assert!(decode(bytes.get(..300).ok_or(UnwindError("fixture prefix"))?).is_err());
        Ok(())
    }
}
