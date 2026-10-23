//! Reproducible casefold data from the fixed Unicode Character Database inputs.
//!
//! Inputs are from the [Unicode Character Database](https://www.unicode.org/Public/12.1.0/ucd/).
//! The source data and generated table are covered by LICENSE-UNICODE, authenticated
//! from <https://www.unicode.org/license.txt> and emitted alongside the table.
//! This generator interprets Unicode properties; it does not incorporate another
//! filesystem's normalization code.

extern crate alloc;

use alloc::boxed::Box;
use alloc::{collections::BTreeMap, vec::Vec};
use core::error::Error;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

/// Acquires pinned, authenticated UCD inputs outside the repository.
mod source;

/// Filesystem encoding version, fixing both upstream inputs and the cache namespace.
pub const UNICODE_VERSION: &str = "12.1.0";

/// SPDX license expression for the upstream data and generated table, excluding generator code.
pub const DATA_LICENSE: &str = "Unicode-3.0";

/// Environment inputs affecting source-cache selection or curl discovery.
/// Cargo callers must track these with `rerun-if-env-changed`.
pub const ENVIRONMENT_INPUTS: &[&str] = &[
    "EXT4_UCD_CACHE",
    "TMPDIR",
    "TMP",
    "TEMP",
    "USERPROFILE",
    "PATH",
];

pub use source::license;

/// Terminal host-generation failures retain their underlying diagnostics.
type GenerationResult<T> = Result<T, Box<dyn Error>>;

/// Selects an external cache shared by build generation and distribution notice sealing.
/// # Errors
/// Rejects a relative cache override, whose meaning would depend on the caller's directory.
pub fn cache_directory() -> GenerationResult<PathBuf> {
    let cache = env::var_os("EXT4_UCD_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join(format!("ext4-win-ucd-{UNICODE_VERSION}")));
    if !cache.is_absolute() {
        return Err("EXT4_UCD_CACHE must be an absolute path".into());
    }
    Ok(cache)
}

/// Writes the runtime table with its verbatim notice, returning source-file dependencies.
///
/// `cache` holds pinned upstream inputs; missing entries require HTTPS-capable curl.
/// The caller owns the output directory and must discard its contents on failure.
/// Successful builds can track the returned paths for regeneration.
///
/// # Errors
/// Returns source acquisition, invalid Unicode properties, conformance or write failure.
pub fn generate(output: &Path, cache: &Path) -> GenerationResult<Vec<PathBuf>> {
    let table = build(cache)?;
    let notice = license(cache)?;
    fs::write(output.join("casefold.bin"), table)?;
    fs::write(output.join("LICENSE-UNICODE"), notice)?;
    Ok(source::paths(cache).collect())
}
/// Parsed properties; the UCD is the sole authority for every field.
#[derive(Debug, Default)]
struct Properties {
    /// Canonical decompositions, excluding tagged compatibility mappings.
    decomposition: BTreeMap<u32, Vec<u32>>,
    /// Locale-independent full common/fold mappings.
    folding: BTreeMap<u32, Vec<u32>>,
    /// Nonzero canonical combining classes.
    combining: BTreeMap<u32, u8>,
    /// Default-ignorable scalar ranges.
    ignored: Vec<(u32, u32)>,
    /// Assigned-age ranges supported by this fixed database.
    assigned: Vec<(u32, u32)>,
}
/// Authenticates sources, derives closed scalar mappings and tests canonical equivalence.
/// # Errors
/// Returns source, parser, conversion or normalization-conformance failure.
fn build(cache: &Path) -> GenerationResult<Vec<u8>> {
    let sources = source::load(cache)?;
    let source = |name| {
        sources
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| io::Error::other("missing Unicode source"))
    };
    let mut properties = Properties::default();
    for line in source("UnicodeData.txt")?.lines() {
        let fields: Vec<_> = line.split(';').collect();
        let cp = hex(field(&fields, 0)?)?;
        let class = field(&fields, 3)?.parse()?;
        if class != 0 {
            properties.combining.insert(cp, class);
        }
        let decomposition = field(&fields, 5)?;
        if !decomposition.is_empty() && !decomposition.starts_with('<') {
            properties
                .decomposition
                .insert(cp, sequence(decomposition)?);
        }
    }
    for line in source("CaseFolding.txt")?.lines() {
        let fields = property_fields(line);
        if fields.is_empty() {
            continue;
        }
        if matches!(field(&fields, 1)?, "C" | "F") {
            properties
                .folding
                .insert(hex(field(&fields, 0)?)?, sequence(field(&fields, 2)?)?);
        }
    }
    for line in source("DerivedCoreProperties.txt")?.lines() {
        let fields = property_fields(line);
        if fields.is_empty() {
            continue;
        }
        if field(&fields, 1)? == "Default_Ignorable_Code_Point" {
            properties.ignored.push(range(field(&fields, 0)?)?);
        }
    }
    for line in source("DerivedAge.txt")?.lines() {
        let fields = property_fields(line);
        if fields.is_empty() {
            continue;
        }
        properties.assigned.push(range(field(&fields, 0)?)?);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "task-owned scalar ranges use a total tuple comparator and no user callback"
    )]
    properties.assigned.sort_unstable();
    let mut records = Vec::new();
    let mut payload = Vec::new();
    let mut count = 0_u32;
    for cp in 1..=0x10ffff {
        let Some(scalar) = char::from_u32(cp) else {
            continue;
        };
        let canonical = properties.normalize_stage(&[cp], NormalizationStage::Canonical)?;
        let folded = properties.normalize_stage(&[cp], NormalizationStage::Folded)?;
        let encode = |sequence: Vec<u32>| -> GenerationResult<String> {
            sequence
                .into_iter()
                .map(|cp| {
                    char::from_u32(cp)
                        .ok_or_else(|| io::Error::other("invalid mapped scalar").into())
                })
                .collect()
        };
        let canonical = encode(canonical)?;
        let folded = encode(folded)?;
        let combining = properties.combining.get(&cp).copied().unwrap_or(0);
        let mut identity = [0; 4];
        let identity = scalar.encode_utf8(&mut identity).as_bytes();
        if canonical.as_bytes() == identity && folded.as_bytes() == identity && combining == 0 {
            continue;
        }
        records.extend_from_slice(&cp.to_le_bytes());
        for mapping in [canonical, folded] {
            records.extend_from_slice(&u32::try_from(payload.len())?.to_le_bytes());
            records.extend_from_slice(&u32::try_from(mapping.len())?.to_le_bytes());
            payload.extend_from_slice(mapping.as_bytes());
        }
        records.extend_from_slice(&[combining, 0, 0, 0]);
        count = count
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Unicode record count overflow"))?;
    }
    for line in source("NormalizationTest.txt")?.lines() {
        let fields = property_fields(line);
        if fields.is_empty() || field(&fields, 0)?.starts_with('@') {
            continue;
        }
        let expected = properties.normalize(&sequence(field(&fields, 2)?)?)?;
        for index in [0, 1] {
            if properties.normalize(&sequence(field(&fields, index)?)?)? != expected {
                return Err(io::Error::other(format!(
                    "Unicode canonical equivalence failed: {line}"
                ))
                .into());
            }
        }
        if properties.normalize(&sequence(field(&fields, 3)?)?)?
            != properties.normalize(&sequence(field(&fields, 4)?)?)?
        {
            return Err(io::Error::other("Unicode compatibility-column equivalence failed").into());
        }
    }
    let mut output = Vec::from(*b"U121CF02");
    output.extend_from_slice(&count.to_le_bytes());
    output.extend_from_slice(&u32::try_from(properties.assigned.len())?.to_le_bytes());
    output.extend_from_slice(&records);
    for (start, end) in properties.assigned {
        output.extend_from_slice(&start.to_le_bytes());
        output.extend_from_slice(&end.to_le_bytes());
    }
    output.extend_from_slice(&payload);
    Ok(output)
}
/// Ordered normalization phases with distinct mapping authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizationStage {
    /// Establish canonical order before a case mapping can change a combining class.
    Canonical,
    /// Apply full locale-independent folding after canonical ordering.
    Folded,
}
impl Properties {
    /// Expands independent mappings and applies stable canonical combining-class ordering.
    /// # Errors
    /// Returns malformed recursive mappings or an invalid Unicode scalar.
    fn normalize(&self, input: &[u32]) -> GenerationResult<Vec<u32>> {
        let canonical = self.normalize_stage(input, NormalizationStage::Canonical)?;
        self.normalize_stage(&canonical, NormalizationStage::Folded)
    }
    /// Applies one phase and canonical ordering without crossing its mapping boundary.
    /// # Errors
    /// Returns malformed source mappings or invalid Unicode scalars.
    fn normalize_stage(
        &self,
        input: &[u32],
        stage: NormalizationStage,
    ) -> GenerationResult<Vec<u32>> {
        let mut expanded = Vec::new();
        for cp in input {
            self.expand(*cp, stage, 0, &mut expanded)?;
        }
        let mut result = Vec::new();
        for cp in expanded {
            let class = self.combining.get(&cp).copied().unwrap_or(0);
            let mut index = result.len();
            if class != 0 {
                while let Some(prior) = index.checked_sub(1).and_then(|at| result.get(at)) {
                    let previous = self.combining.get(prior).copied().unwrap_or(0);
                    if previous == 0 || previous <= class {
                        break;
                    }
                    index = index
                        .checked_sub(1)
                        .ok_or_else(|| io::Error::other("combining index underflow"))?;
                }
            }
            #[expect(
                clippy::disallowed_methods,
                reason = "the insertion index starts at length and only decreases; host generator allocation failure terminates the task"
            )]
            result.insert(index, cp);
        }
        Ok(result)
    }
    /// Closes full casefold and canonical decomposition, with normative Hangul decomposition.
    /// # Errors
    /// Returns a cyclic source mapping or invalid scalar.
    fn expand(
        &self,
        cp: u32,
        stage: NormalizationStage,
        depth: u8,
        output: &mut Vec<u32>,
    ) -> GenerationResult<()> {
        if depth >= 32 {
            return Err(io::Error::other("recursive Unicode mapping").into());
        }
        if self
            .ignored
            .iter()
            .any(|(start, end)| *start <= cp && cp <= *end)
        {
            return Ok(());
        }
        let folding = match stage {
            NormalizationStage::Canonical => None,
            NormalizationStage::Folded => self.folding.get(&cp),
        };
        if let Some(mapping) = folding.or_else(|| self.decomposition.get(&cp)) {
            for mapped in mapping {
                self.expand(*mapped, stage, depth.saturating_add(1), output)?;
            }
        } else if let Some(index) = cp.checked_sub(0xac00).filter(|index| *index < 11_172) {
            output.push(
                0x1100_u32
                    .checked_add(index / 588)
                    .ok_or_else(|| io::Error::other("Hangul leading overflow"))?,
            );
            output.push(
                0x1161_u32
                    .checked_add((index % 588) / 28)
                    .ok_or_else(|| io::Error::other("Hangul vowel overflow"))?,
            );
            let trailing = index % 28;
            if trailing != 0 {
                output.push(
                    0x11a7_u32
                        .checked_add(trailing)
                        .ok_or_else(|| io::Error::other("Hangul trailing overflow"))?,
                );
            }
        } else {
            char::from_u32(cp).ok_or_else(|| io::Error::other("invalid Unicode scalar"))?;
            output.push(cp);
        }
        Ok(())
    }
}
/// Discards UCD comments and splits exact semicolon fields.
fn property_fields(line: &str) -> Vec<&str> {
    let data = line.split('#').next().unwrap_or("").trim();
    if data.is_empty() {
        Vec::new()
    } else {
        data.split(';').map(str::trim).collect()
    }
}
/// Acquires one required data column.
/// # Errors
/// Returns malformed input rather than indexing beyond a source line.
fn field<'a>(fields: &[&'a str], index: usize) -> GenerationResult<&'a str> {
    fields
        .get(index)
        .copied()
        .ok_or_else(|| io::Error::other("missing Unicode data column").into())
}
/// Parses one standard hexadecimal code-point field.
/// # Errors
/// Returns an invalid hexadecimal integer.
fn hex(value: &str) -> GenerationResult<u32> {
    Ok(u32::from_str_radix(value, 16)?)
}
/// Parses a space-separated mapping.
/// # Errors
/// Returns an invalid code-point field.
fn sequence(value: &str) -> GenerationResult<Vec<u32>> {
    value.split_whitespace().map(hex).collect()
}
/// Parses one inclusive Unicode property range.
/// # Errors
/// Returns malformed hexadecimal endpoints or a reversed range.
fn range(value: &str) -> GenerationResult<(u32, u32)> {
    let (start, end) = value.split_once("..").unwrap_or((value, value));
    let range = (hex(start)?, hex(end)?);
    if range.0 > range.1 {
        return Err(io::Error::other("reversed Unicode range").into());
    }
    Ok(range)
}
