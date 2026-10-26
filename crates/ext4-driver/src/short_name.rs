//! Persisted Windows aliases belong to exact directory links, never to an inode alone.
//!
//! The ext4 directory remains namespace authority. Each inode's private xattr is a bounded
//! projection keyed by parent allocation incarnation and exact name. External namespace edits
//! leave harmless unused records; readers require the current directory relation before using
//! one. Encrypted directories never publish or persist plaintext aliases. Layout exhaustion
//! admits a link without an alias; failures after storage admission abort the whole mutation.

use crate::kernel::name_expression::NameCase;
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use crate::namespace::WindowsName;
use crate::request::DriverMutationPass;
use ext4_core::{CommittedReadPass, DirectoryNodeId, DirectoryReader, DirectoryScanCursor, Ext4Name,
    NodeId, XattrName, XattrNamespace, XattrValue};

/// Bounded projection budget per inode, independent from the ext4 hard-link limit.
const LINKSET_BYTES: usize = 4096;
/// On-disk linkset encoding version.
const VERSION: [u8; 4] = 1_u32.to_le_bytes();
/// Fixed record prefix: parent inode, parent generation, name length, alias length.
const RECORD_PREFIX: usize = 11;

/// An admitted ASCII DOS component, with no allocation or platform encoding ambiguity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShortName {
    /// Initialized bytes, excluding zero padding.
    bytes: [u8; 12],
    /// Meaningful byte count.
    length: u8,
}

impl ShortName {
    /// Validates the ASCII component returned through FsRtl's UTF-16 boundary.
    /// # Errors
    /// Rejects non-ASCII, overlong or malformed DOS components.
    pub(crate) fn from_utf16(units: &[u16]) -> DriverResult<Self> {
        let mut bytes = [0_u8; 12];
        if units.len() > bytes.len() { return Err(DriverError::InvalidWindowsMetadata); }
        for (target, unit) in bytes.iter_mut().zip(units) {
            *target = u8::try_from(*unit).map_err(|_| DriverError::InvalidWindowsMetadata)?;
        }
        Self::parse(bytes.get(..units.len()).ok_or(DriverError::InvalidWindowsMetadata)?)
    }

    /// Copies into a complete native short-name output and returns its byte length.
    pub(crate) fn copy_utf16(self, units: &mut [u16; 12]) -> u16 {
        for (target, byte) in units.iter_mut().zip(self.bytes()) { *target = u16::from(*byte); }
        u16::from(self.length).saturating_mul(2)
    }
    /// Validates the persisted DOS representation.
    /// # Errors
    /// Rejects invalid DOS characters, base length or extension framing.
    fn parse(bytes: &[u8]) -> DriverResult<Self> {
        let mut parts = bytes.split(|byte| *byte == b'.');
        let base = parts.next().ok_or(DriverError::InvalidWindowsMetadata)?;
        let extension = parts.next();
        if base.is_empty() || base.len() > 8 || extension.is_some_and(|part| part.is_empty() || part.len() > 3)
            || parts.next().is_some() || bytes.len() > 12
            || bytes.iter().any(|byte| *byte != b'.' && !dos_character(*byte))
        {
            return Err(DriverError::InvalidWindowsMetadata);
        }
        let mut result = Self { bytes: [0; 12], length: u8::try_from(bytes.len()).map_err(|_| DriverError::InvalidWindowsMetadata)? };
        crate::memory::copy_exact(result.bytes.get_mut(..bytes.len()).ok_or(DriverError::InvalidWindowsMetadata)?, bytes)?;
        Ok(result)
    }

    /// Borrows initialized ASCII bytes.
    fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.length)).unwrap_or(&[])
    }

    /// Projects the ASCII alias into the Windows component boundary.
    /// # Errors
    /// Returns Windows component allocation or encoding failure.
    pub(crate) fn windows_name(self) -> DriverResult<WindowsName> {
        let mut units = [0_u16; 12];
        for (target, source) in units.iter_mut().zip(self.bytes()) { *target = u16::from(*source); }
        WindowsName::from_utf16(units.get(..usize::from(self.length)).ok_or(DriverError::InvalidWindowsMetadata)?)
    }
}

/// Conservative ASCII subset of the DOS OEM filename alphabet.
const fn dos_character(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
        || matches!(byte, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'(' | b')' | b'-' | b'@' | b'^' | b'_' | b'`' | b'{' | b'}' | b'~')
}

/// Produces one bounded candidate; collision selection remains committed namespace policy.
/// # Errors
/// Rejects an exhausted decimal suffix or a candidate outside its fixed component capacity.
fn candidate(name: &Ext4Name, sequence: u32) -> DriverResult<ShortName> {
    let bytes = name.bytes();
    let dot = bytes.iter().rposition(|byte| *byte == b'.');
    let (base, extension) = match dot {
        Some(index) if index != 0 => (
            bytes.get(..index).ok_or(DriverError::InvalidName)?,
            bytes.get(index.checked_add(1).ok_or(DriverError::InvalidName)?..).ok_or(DriverError::InvalidName)?,
        ),
        _ => (bytes, &[][..]),
    };
    let mut digits = [0_u8; 6];
    let mut digit_count = 0_usize;
    let mut remaining = sequence;
    loop {
        digit_count = digit_count.checked_add(1).ok_or(DriverError::InvalidParameter)?;
        let slot = digits.len().checked_sub(digit_count).ok_or(DriverError::InvalidParameter)?;
        *digits.get_mut(slot).ok_or(DriverError::InvalidParameter)? = b'0'.checked_add(u8::try_from(remaining % 10).map_err(|_| DriverError::InvalidParameter)?).ok_or(DriverError::InvalidParameter)?;
        remaining /= 10;
        if remaining == 0 { break; }
    }
    let prefix_limit = 7_usize.checked_sub(digit_count).ok_or(DriverError::InvalidParameter)?;
    let mut result = [0_u8; 12];
    let mut used = 0_usize;
    for byte in base.iter().filter(|byte| !matches!(**byte, b' ' | b'.')).take(prefix_limit) {
        let upper = byte.to_ascii_uppercase();
        append_candidate(&mut result, &mut used, if dos_character(upper) { upper } else { b'_' })?;
    }
    if used == 0 { append_candidate(&mut result, &mut used, b'_')?; }
    append_candidate(&mut result, &mut used, b'~')?;
    for byte in digits.iter().skip(digits.len().checked_sub(digit_count).ok_or(DriverError::InvalidParameter)?) { append_candidate(&mut result, &mut used, *byte)?; }
    let mut extension_bytes = extension.iter().filter(|byte| !matches!(**byte, b' ' | b'.')).take(3).peekable();
    if extension_bytes.peek().is_some() {
        append_candidate(&mut result, &mut used, b'.')?;
        for byte in extension_bytes {
            let upper = byte.to_ascii_uppercase();
            append_candidate(&mut result, &mut used, if dos_character(upper) { upper } else { b'_' })?;
        }
    }
    ShortName::parse(result.get(..used).ok_or(DriverError::InvalidParameter)?)
}

/// Capacity-checks every byte before advancing the bounded candidate cursor.
/// # Errors
/// Rejects a cursor outside the fixed DOS component capacity.
fn append_candidate(buffer: &mut [u8; 12], used: &mut usize, byte: u8) -> DriverResult<()> {
    *buffer.get_mut(*used).ok_or(DriverError::InvalidParameter)? = byte;
    *used = used.checked_add(1).ok_or(DriverError::InvalidParameter)?;
    Ok(())
}

/// Creates the private attribute key outside the Windows EA namespace.
/// # Errors
/// Returns attribute-name allocation failure.
fn xattr_name() -> DriverResult<XattrName> {
    Ok(XattrName::new(XattrNamespace::User, b"ext4win.shortnames")?)
}

/// One borrowed, fully framed linkset record.
struct LinkRecord<'a> {
    /// Whole encoded record, for lossless retention of unrelated hard links.
    encoded: &'a [u8],
    /// Parent inode number.
    parent: u32,
    /// Parent allocation generation.
    generation: u32,
    /// Exact plaintext ext4 name; never present for encrypted parents.
    name: &'a [u8],
    /// Validated alias.
    alias: ShortName,
}

/// Decodes complete records; no partially validated persisted value reaches lookup.
/// # Errors
/// Returns malformed framing, names, aliases or the visitor's failure.
fn records(bytes: &[u8], mut visit: impl FnMut(LinkRecord<'_>) -> DriverResult<()>) -> DriverResult<()> {
    if bytes.len() > LINKSET_BYTES || bytes.get(..4) != Some(&VERSION) { return Err(DriverError::InvalidWindowsMetadata); }
    let mut remaining = bytes.get(4..).ok_or(DriverError::InvalidWindowsMetadata)?;
    while !remaining.is_empty() {
        let prefix: &[u8; RECORD_PREFIX] = remaining.get(..RECORD_PREFIX).ok_or(DriverError::InvalidWindowsMetadata)?.try_into().map_err(|_| DriverError::InvalidWindowsMetadata)?;
        let parent = u32::from_le_bytes(prefix[..4].try_into().map_err(|_| DriverError::InvalidWindowsMetadata)?);
        let generation = u32::from_le_bytes(prefix[4..8].try_into().map_err(|_| DriverError::InvalidWindowsMetadata)?);
        let length = usize::from(u16::from_le_bytes([prefix[8], prefix[9]]));
        let alias_length = usize::from(prefix[10]);
        let name_end = RECORD_PREFIX.checked_add(length).ok_or(DriverError::InvalidWindowsMetadata)?;
        let end = name_end.checked_add(alias_length).ok_or(DriverError::InvalidWindowsMetadata)?;
        let encoded = remaining.get(..end).ok_or(DriverError::InvalidWindowsMetadata)?;
        let name = encoded.get(RECORD_PREFIX..name_end).ok_or(DriverError::InvalidWindowsMetadata)?;
        Ext4Name::new(name).map_err(|_| DriverError::InvalidWindowsMetadata)?;
        let alias = ShortName::parse(encoded.get(name_end..).ok_or(DriverError::InvalidWindowsMetadata)?)?;
        visit(LinkRecord { encoded, parent, generation, name, alias })?;
        remaining = remaining.get(end..).ok_or(DriverError::InvalidWindowsMetadata)?;
    }
    Ok(())
}

/// Reads a projection only for a current live namespace relation supplied by traversal.
/// # Errors
/// Returns inode/xattr reads, malformed stored metadata or duplicate link records.
pub(crate) fn read_alias(read: &mut impl CommittedReadPass, parent: DirectoryNodeId, name: &Ext4Name, node: NodeId) -> DriverResult<Option<ShortName>> {
    let metadata = read.load_node_metadata(NodeId::Directory(parent))?;
    if metadata.is_encrypted() { return Ok(None); }
    let Some(value) = read.read_xattr(node, &xattr_name()?)? else { return Ok(None); };
    stored_alias(value.bytes(), NodeId::Directory(parent).file_index(), metadata.generation().as_u32(), name.bytes())
}

/// Requires an exact parent incarnation and spelling within a complete validated linkset.
/// # Errors
/// Returns malformed framing or more than one projection for the same link.
fn stored_alias(bytes: &[u8], parent: u32, generation: u32, name: &[u8]) -> DriverResult<Option<ShortName>> {
    let mut found = None;
    records(bytes, |record| {
        if record.parent == parent && record.generation == generation && record.name == name
            && found.replace(record.alias).is_some() {
            return Err(DriverError::InvalidWindowsMetadata);
        }
        Ok(())
    })?;
    Ok(found)
}

/// Suppresses aliases shadowed by a real name introduced through the ext4 namespace.
/// # Errors
/// Returns alias metadata, namespace traversal or Windows encoding failures.
pub(crate) fn visible_alias(read: &mut impl CommittedReadPass, parent: DirectoryNodeId, name: &Ext4Name, node: NodeId) -> DriverResult<Option<ShortName>> {
    let Some(alias) = read_alias(read, parent, name, node)? else { return Ok(None); };
    let windows = alias.windows_name()?;
    let mut reader = DirectoryReader::new(parent, DirectoryScanCursor::start());
    while let Some(entry) = read.next_directory_entry(&mut reader)? {
        if entry.entry().name() != name
            && let Ok(long) = WindowsName::from_ext4(entry.entry().name())
            && NameCase::Insensitive.lookup(&windows).matches(&long)
        { return Ok(None); }
    }
    Ok(Some(alias))
}

/// A chosen alias and parent incarnation retained only within one resolve pass.
pub(crate) struct PreparedAlias {
    /// Parent allocation incarnation, not merely its reusable inode number.
    generation: u32,
    /// Alias proved unused in the committed namespace.
    alias: ShortName,
}

/// Selects a collision-free alias before staging the namespace mutation.
/// # Errors
/// Returns committed namespace, stored-alias, encoding or allocation failures.
pub(crate) fn prepare(read: &mut impl CommittedReadPass, parent: DirectoryNodeId, name: &Ext4Name, preferred: Option<ShortName>) -> DriverResult<Option<PreparedAlias>> {
    let metadata = read.load_node_metadata(NodeId::Directory(parent))?;
    if metadata.is_encrypted() { return Ok(None); }
    match WindowsName::from_ext4(name) {
        Ok(_) => {},
        Err(DriverError::InvalidName) => return Ok(None),
        Err(error) => return Err(error),
    }
    for sequence in 0..=999_999 {
        let alias = if sequence == 0 {
            let Some(alias) = preferred else { continue; }; alias
        } else { candidate(name, sequence)? };
        let windows = alias.windows_name()?;
        let mut occupied = false;
        let mut reader = DirectoryReader::new(parent, DirectoryScanCursor::start());
        while let Some(entry) = read.next_directory_entry(&mut reader)? {
            if entry.entry().name() == name { continue; }
            if let Ok(long) = WindowsName::from_ext4(entry.entry().name()) && NameCase::Insensitive.lookup(&windows).matches(&long) {
                occupied = true; break;
            }
            if read_alias(read, parent, entry.entry().name(), *entry.entry().node())? == Some(alias) { occupied = true; break; }
        }
        if !occupied { return Ok(Some(PreparedAlias { generation: metadata.generation().as_u32(), alias })); }
    }
    Ok(None)
}

/// Publishes the projection in the same journal mutation as its namespace link.
/// # Errors
/// Returns malformed existing records or a staged storage failure; layout exhaustion admits no alias.
pub(crate) fn store(mutation: &mut DriverMutationPass<'_, '_, '_>, parent: DirectoryNodeId, name: &Ext4Name, node: NodeId, prepared: Option<PreparedAlias>) -> DriverResult<()> {
    let Some(prepared) = prepared else { return Ok(()); };
    let xattrs = mutation.staged_xattrs(node)?;
    let key = xattr_name()?;
    let mut bytes = DriverVec::try_copied_from_slice(&VERSION)?;
    if let Some(value) = xattrs.get(&key) {
        records(value.bytes(), |record| {
            if record.parent != NodeId::Directory(parent).file_index() || record.generation != prepared.generation || record.name != name.bytes() {
                bytes.try_extend_from_copy_slice(record.encoded)?;
            }
            Ok(())
        })?;
    }
    let record_length = RECORD_PREFIX.checked_add(name.bytes().len()).and_then(|length| length.checked_add(prepared.alias.bytes().len())).ok_or(DriverError::InvalidWindowsMetadata)?;
    if bytes.len().checked_add(record_length).is_none_or(|length| length > LINKSET_BYTES) { return Ok(()); }
    bytes.try_extend_from_copy_slice(&NodeId::Directory(parent).file_index().to_le_bytes())?;
    bytes.try_extend_from_copy_slice(&prepared.generation.to_le_bytes())?;
    bytes.try_extend_from_copy_slice(&u16::try_from(name.bytes().len()).map_err(|_| DriverError::InvalidName)?.to_le_bytes())?;
    bytes.try_push(prepared.alias.length)?;
    bytes.try_extend_from_copy_slice(name.bytes())?;
    bytes.try_extend_from_copy_slice(prepared.alias.bytes())?;
    if mutation.xattr_fits(node, xattr_name()?, XattrValue::new(bytes.as_slice())?)? {
        let selected = mutation.node(node)?;
        mutation.set_xattr(selected, key, XattrValue::new(bytes.as_slice())?)?;
    }
    Ok(())
}

/// Removes only this link's projection while the inode is still staged and live.
/// # Errors
/// Returns malformed records, inode policy, allocation or xattr staging failures.
pub(crate) fn forget(mutation: &mut DriverMutationPass<'_, '_, '_>, parent: DirectoryNodeId, name: &Ext4Name, node: NodeId) -> DriverResult<()> {
    let key = xattr_name()?;
    let xattrs = mutation.staged_xattrs(node)?;
    let Some(value) = xattrs.get(&key) else { return Ok(()); };
    let mut bytes = DriverVec::try_copied_from_slice(&VERSION)?;
    let mut removed = false;
    records(value.bytes(), |record| {
        if record.parent == NodeId::Directory(parent).file_index() && record.name == name.bytes() { removed = true; }
        else { bytes.try_extend_from_copy_slice(record.encoded)?; }
        Ok(())
    })?;
    if removed {
        let selected = mutation.node(node)?;
        if bytes.len() == VERSION.len() { mutation.remove_xattr(selected, &key)?; }
        else { mutation.set_xattr(selected, key, XattrValue::new(bytes.as_slice())?)?; }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Fails if independent DOS examples or persisted framing lose their contract.
    #[test]
    fn candidates_are_dos_components_with_sequence_and_extension() {
        let result = (|| -> DriverResult<()> {
            let name = Ext4Name::new(b"long document.filename")?;
            assert_eq!(candidate(&name, 1)?.bytes(), b"LONGDO~1.FIL");
            assert_eq!(candidate(&name, 12)?.bytes(), b"LONGD~12.FIL");
            let alias = candidate(&name, 1)?;
            let mut utf16 = [0_u16; 12];
            let length = alias.copy_utf16(&mut utf16);
            assert_eq!(ShortName::from_utf16(utf16.get(..usize::from(length / 2)).ok_or(DriverError::InvalidParameter)?)?, alias);
            Ok(())
        })();
        assert_eq!(result, Ok(()));
        assert!(ShortName::parse(b"BAD NAME.TXT").is_err());
        assert!(ShortName::parse(b"123456789.X").is_err());
        assert!(records(&[1, 0, 0, 0, 5], |_| Ok(())).is_err());
    }

    /// # Panics
    /// Fails if independent persisted vectors cross hard links, parent reuse or exact spellings.
    #[test]
    fn persisted_aliases_are_scoped_to_exact_links_and_parent_incarnations() {
        let bytes = b"\x01\0\0\0\x02\0\0\0\x07\0\0\0\x08\0\x05long-oneONE~1\x03\0\0\0\x09\0\0\0\x08\0\x05long-twoTWO~2";
        let result = (|| -> DriverResult<()> {
            assert_eq!(stored_alias(bytes, 2, 7, b"long-one")?, Some(ShortName::parse(b"ONE~1")?));
            assert_eq!(stored_alias(bytes, 3, 9, b"long-two")?, Some(ShortName::parse(b"TWO~2")?));
            assert_eq!(stored_alias(bytes, 2, 8, b"long-one")?, None);
            assert_eq!(stored_alias(bytes, 2, 7, b"LONG-ONE")?, None);
            assert_eq!(stored_alias(bytes, 3, 9, b"long-one")?, None);
            let mut duplicate = DriverVec::try_copied_from_slice(bytes)?;
            duplicate.try_extend_from_copy_slice(bytes.get(4..28).ok_or(DriverError::InvalidParameter)?)?;
            assert_eq!(stored_alias(duplicate.as_slice(), 2, 7, b"long-one"), Err(DriverError::InvalidWindowsMetadata));
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }
}
