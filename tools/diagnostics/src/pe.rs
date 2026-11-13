//! Link-map attribution of AMD64 fixed prolog frames, independent of the load address.
use crate::invalid;
use alloc::collections::BTreeMap;
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

/// Ranks fixed frames and resolves symbols using the image's preferred base.
/// # Errors
/// Returns invalid runtime function tables, PE records, or unwind data.
pub(crate) fn frames(bytes: &[u8], map: &str) -> io::Result<Vec<Frame>> {
    let table = pe_unwind::decode(bytes).map_err(|error| invalid(error.to_string()))?;
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
            if let Some(rva) = absolute.checked_sub(table.image_base) {
                symbols.entry(rva).or_default().push(name.into());
            }
        }
    }
    let mut frames: Vec<Frame> = table
        .frames
        .iter()
        .map(|frame| Frame {
            begin: frame.begin,
            end: frame.end,
            stack: frame.fixed_bytes,
            symbols: symbols.get(&frame.begin).cloned().unwrap_or_default(),
        })
        .collect();
    #[expect(
        clippy::disallowed_methods,
        reason = "host-only report ordering compares integer frame sizes and has no production kernel allocation constraint"
    )]
    frames.sort_by_key(|frame| core::cmp::Reverse(frame.stack));
    Ok(frames)
}
