//! AMD64 file-backed RVA and fixed prolog frame analysis, independent of the load address.
use crate::{artifact::field, invalid};
use alloc::collections::{BTreeMap, BTreeSet};
use serde_json::{Value, json};
use std::io;

/// A function range and its fixed prolog usage, excluding dynamic and descendant frames.
#[derive(Debug)]
pub(crate) struct Frame {
    /// Inclusive image-relative function start.
    pub(crate) begin: u64,
    /// Exclusive image-relative function end.
    pub(crate) end: u64,
    /// Fixed allocation decoded from unwind records.
    stack: u64,
    /// Link-map symbols at the function start.
    symbols: Vec<String>,
}
impl Frame {
    /// Produces the diagnostic report without asserting live stack occupancy.
    pub(crate) fn report(&self) -> Value {
        json!({"begin_rva": self.begin, "end_rva": self.end, "fixed_stack_bytes": self.stack, "symbols": self.symbols})
    }
}

/// A section's image address and independently bounded file range.
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

/// Checked arithmetic for byte/RVA range ends.
/// # Errors
/// Returns an overflow error.
fn add(value: u64, amount: u64) -> io::Result<u64> {
    value
        .checked_add(amount)
        .ok_or_else(|| invalid("PE address overflow"))
}
/// Reads a 16-bit file field.
/// # Errors
/// Returns a truncated field error.
fn u16_at(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(field(bytes, offset)?))
}
/// Reads a 32-bit file field.
/// # Errors
/// Returns a truncated field error.
fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(field(bytes, offset)?))
}
/// Computes a checked file offset.
/// # Errors
/// Returns an overflow error.
fn offset(value: usize, amount: usize) -> io::Result<usize> {
    value
        .checked_add(amount)
        .ok_or_else(|| invalid("PE offset overflow"))
}

impl<'a> Image<'a> {
    /// Establishes the AMD64 PE32+ and section mapping boundaries.
    /// # Errors
    /// Returns malformed or truncated PE headers and ranges.
    fn parse(bytes: &'a [u8]) -> io::Result<Self> {
        if !bytes.starts_with(b"MZ") {
            return Err(invalid("missing DOS signature"));
        }
        let pe = usize::try_from(u32_at(bytes, 0x3c)?).map_err(io::Error::other)?;
        if field::<4>(bytes, pe)? != *b"PE\0\0" || u16_at(bytes, offset(pe, 4)?)? != 0x8664 {
            return Err(invalid("expected an AMD64 PE image"));
        }
        let count = u16_at(bytes, offset(pe, 6)?)?;
        let optional_size = usize::from(u16_at(bytes, offset(pe, 20)?)?);
        let optional = offset(pe, 24)?;
        bytes
            .get(optional..offset(optional, optional_size)?)
            .ok_or_else(|| invalid("truncated optional header"))?;
        if optional_size < 144
            || u16_at(bytes, optional)? != 0x20b
            || u32_at(bytes, offset(optional, 108)?)? < 4
        {
            return Err(invalid("missing PE32+ exception directory"));
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
            let raw =
                usize::try_from(u32_at(bytes, offset(entry, 20)?)?).map_err(io::Error::other)?;
            let raw_size = usize::try_from(size).map_err(io::Error::other)?;
            bytes
                .get(raw..offset(raw, raw_size)?)
                .ok_or_else(|| invalid("truncated initialized PE section"))?;
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
            table,
            table_size,
            sections,
        })
    }

    /// Converts a file-backed RVA range to a unique checked file range.
    /// # Errors
    /// Returns unmapped, ambiguous, overflowing, or truncated ranges.
    fn at(&self, rva: u64, length: u64) -> io::Result<&'a [u8]> {
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
            .ok_or_else(|| invalid("unmapped file-backed RVA"))?;
        if matches.next().is_some() {
            return Err(invalid("ambiguous file-backed RVA"));
        }
        let relative = usize::try_from(
            rva.checked_sub(section.rva)
                .ok_or_else(|| invalid("RVA underflow"))?,
        )
        .map_err(io::Error::other)?;
        let start = offset(section.offset, relative)?;
        let length = usize::try_from(length).map_err(io::Error::other)?;
        self.bytes
            .get(start..offset(start, length)?)
            .ok_or_else(|| invalid("truncated PE mapping"))
    }

    /// Decodes finite, acyclic x64 unwind records and chained fixed allocations.
    /// # Errors
    /// Returns unmodeled opcodes, truncated operands, invalid flags, or excessive chains.
    fn stack(&self, rva: u64, active: &mut BTreeSet<u64>) -> io::Result<u64> {
        if !rva.is_multiple_of(4) || active.len() >= 128 || !active.insert(rva) {
            return Err(invalid("invalid or excessive chained unwind records"));
        }
        let header: [u8; 4] = self.at(rva, 4)?.try_into().map_err(io::Error::other)?;
        let version = header
            .first()
            .copied()
            .ok_or_else(|| invalid("unwind header"))?
            & 7;
        let flags = header
            .first()
            .copied()
            .ok_or_else(|| invalid("unwind header"))?
            >> 3;
        if !matches!(version, 1 | 2) || flags & !7 != 0 || (flags & 4 != 0 && flags & 3 != 0) {
            return Err(invalid("unsupported unwind version or flags"));
        }
        let count = u64::from(*header.get(2).ok_or_else(|| invalid("unwind count"))?);
        let codes = self.at(
            add(rva, 4)?,
            count
                .checked_mul(2)
                .ok_or_else(|| invalid("unwind length overflow"))?,
        )?;
        let mut slots = codes.as_chunks::<2>().0.iter();
        let mut total = 0_u64;
        while let Some(slot) = slots.next() {
            let encoding = *slot
                .get(1)
                .ok_or_else(|| invalid("truncated unwind slot"))?;
            let opcode = encoding & 15;
            let info = encoding >> 4;
            let amount = match (opcode, info) {
                (0, _) => 8,
                (1, 0 | 1) => {
                    let first = slots
                        .next()
                        .ok_or_else(|| invalid("truncated unwind allocation"))?;
                    let first = u64::from(u16::from_le_bytes(*first));
                    if info == 0 {
                        first
                            .checked_mul(8)
                            .ok_or_else(|| invalid("unwind allocation overflow"))?
                    } else {
                        let second = slots
                            .next()
                            .ok_or_else(|| invalid("truncated unwind allocation"))?;
                        first | (u64::from(u16::from_le_bytes(*second)) << 16)
                    }
                }
                (2, _) => add(
                    u64::from(info)
                        .checked_mul(8)
                        .ok_or_else(|| invalid("unwind overflow"))?,
                    8,
                )?,
                (3, 0) => 0,
                (6, _) if version == 2 => 0,
                (4 | 8, _) => {
                    slots
                        .next()
                        .ok_or_else(|| invalid("truncated unwind operands"))?;
                    0
                }
                (5 | 9, _) => {
                    slots
                        .next()
                        .ok_or_else(|| invalid("truncated unwind operands"))?;
                    slots
                        .next()
                        .ok_or_else(|| invalid("truncated unwind operands"))?;
                    0
                }
                (10, 0 | 1) => add(
                    40,
                    u64::from(info)
                        .checked_mul(8)
                        .ok_or_else(|| invalid("unwind overflow"))?,
                )?,
                _ => return Err(invalid("unsupported unwind opcode")),
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
                        .ok_or_else(|| invalid("unwind chain overflow"))?,
                )?,
                12,
            )?;
            if u32_at(chain, 0)? >= u32_at(chain, 4)? {
                return Err(invalid("invalid chained function range"));
            }
            total = add(total, self.stack(u64::from(u32_at(chain, 8)?), active)?)?;
        }
        active.remove(&rva);
        Ok(total)
    }
}

/// Ranks fixed frames and resolves symbols using the image's preferred base.
/// # Errors
/// Returns invalid runtime function tables, PE records, or unwind data.
pub(crate) fn frames(bytes: &[u8], map: &str) -> io::Result<Vec<Frame>> {
    let image = Image::parse(bytes)?;
    if image.table == 0 || image.table_size == 0 || image.table_size % 12 != 0 {
        return Err(invalid("missing or malformed runtime function table"));
    }
    let mut symbols = BTreeMap::<u64, Vec<String>>::new();
    for line in map.lines() {
        let mut fields = line.split_whitespace();
        if !fields.next().is_some_and(|value| value.contains(':')) {
            continue;
        }
        if let (Some(name), Some(address)) = (fields.next(), fields.next())
            && address.len() == 16
            && address.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            let absolute = u64::from_str_radix(address, 16).map_err(io::Error::other)?;
            if let Some(rva) = absolute.checked_sub(image.base) {
                symbols.entry(rva).or_default().push(name.into());
            }
        }
    }
    let table = image.at(image.table, image.table_size)?;
    let mut frames = Vec::new();
    let mut previous = None;
    for record in table.as_chunks::<12>().0 {
        let begin = u64::from(u32_at(record, 0)?);
        let end = u64::from(u32_at(record, 4)?);
        let unwind = u64::from(u32_at(record, 8)?);
        if begin >= end || previous.is_some_and(|previous| begin <= previous) || unwind == 0 {
            return Err(invalid("invalid runtime function entry"));
        }
        image.at(
            begin,
            end.checked_sub(begin)
                .ok_or_else(|| invalid("function range underflow"))?,
        )?;
        frames.push(Frame {
            begin,
            end,
            stack: image.stack(unwind, &mut BTreeSet::new())?,
            symbols: symbols.get(&begin).cloned().unwrap_or_default(),
        });
        previous = Some(begin);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "host-only report ordering compares integer frame sizes and has no production kernel allocation constraint"
    )]
    frames.sort_by_key(|frame| core::cmp::Reverse(frame.stack));
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes synthetic PE fields with explicit fixture bounds.
    /// # Errors
    /// Returns a malformed fixture range.
    fn put(bytes: &mut [u8], offset: usize, data: &[u8]) -> io::Result<()> {
        let end = offset
            .checked_add(data.len())
            .ok_or_else(|| invalid("fixture offset overflow"))?;
        let destination = bytes
            .get_mut(offset..end)
            .ok_or_else(|| invalid("fixture field outside buffer"))?;
        for (destination, source) in destination.iter_mut().zip(data) {
            *destination = *source;
        }
        Ok(())
    }

    /// Two independently encoded AMD64 functions at a non-default preferred image base.
    /// # Errors
    /// Returns synthetic-field range failures.
    fn fixture() -> io::Result<Vec<u8>> {
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

    /// Fixed allocations, preferred-base translation, chained records, and malformed wire data.
    /// # Errors
    /// Returns unexpected synthetic-field or parser failures.
    /// # Panics
    /// Panics when a known wire-format result changes.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "known-answer assertions intentionally fail this test after fallible fixture construction"
    )]
    fn unwind_wire_contract() -> io::Result<()> {
        let mut bytes = fixture()?;
        let decoded = frames(&bytes, " 0001:00000000 first 0000000140001000 f\n")?;
        assert_eq!(
            decoded.iter().map(|frame| frame.stack).collect::<Vec<_>>(),
            [264, 24]
        );
        assert_eq!(
            decoded.first().map(|frame| frame.symbols.as_slice()),
            Some(["first".to_owned()].as_slice())
        );
        put(&mut bytes, 1104, &[2, 4, 3, 0, 1, 6, 3, 6, 4, 0x22])?;
        assert_eq!(
            frames(&bytes, "")?.last().map(|frame| frame.stack),
            Some(24)
        );
        put(&mut bytes, 1104, &[33, 0, 0, 0])?;
        for (offset, value) in [(1108, 0x1000_u32), (1112, 0x1100), (1116, 0x2040)] {
            put(&mut bytes, offset, &value.to_le_bytes())?;
        }
        assert!(frames(&bytes, "")?.iter().all(|frame| frame.stack == 264));
        put(&mut bytes, 1116, &0x2050_u32.to_le_bytes())?;
        assert!(frames(&bytes, "").is_err());
        bytes = fixture()?;
        put(&mut bytes, 1090, &[1])?;
        assert!(frames(&bytes, "").is_err());
        bytes = fixture()?;
        put(&mut bytes, 1104, &[3])?;
        assert!(frames(&bytes, "").is_err());
        assert!(
            frames(
                bytes.get(..300).ok_or_else(|| invalid("fixture prefix"))?,
                ""
            )
            .is_err()
        );
        Ok(())
    }
}
