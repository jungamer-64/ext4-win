//! Windows component representation and namespace comparison policy.

use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use core::{char, str};
use ext4_core::{
    ChildLookup, CommittedReadPass, DirectoryNodeId, DirectoryReader, DirectoryScanCursor, Ext4Name,
};

/// Resolves exact ext4 spelling before applying the caller's Windows comparison policy.
/// Both paths use one restart-local read pass; no name or candidate survives an epoch change.
/// # Errors
/// Returns encoding, ext4 traversal, allocation or ambiguous-name failures.
pub(crate) fn lookup_child(
    read: &mut impl CommittedReadPass,
    parent: DirectoryNodeId,
    lookup: WindowsNameLookup<'_>,
) -> DriverResult<ChildLookup> {
    let exact = read.lookup_child(parent, &lookup.name().to_ext4()?)?;
    if matches!(exact, ChildLookup::Found(_)) || matches!(lookup, WindowsNameLookup::Exact(_)) {
        return Ok(exact);
    }
    let mut found = None;
    let mut reader = DirectoryReader::new(parent, DirectoryScanCursor::start());
    while let Some(scanned) = read.next_directory_entry(&mut reader)? {
        let name = match WindowsName::from_ext4(scanned.entry().name()) {
            Ok(name) => name,
            Err(DriverError::InvalidName) => continue,
            Err(error) => return Err(error),
        };
        if lookup.matches(&name) {
            if found.is_some() {
                return Err(DriverError::AmbiguousName);
            }
            found = Some(scanned.into_child());
        }
    }
    if let Some(found) = found {
        return Ok(ChildLookup::Found(found));
    }
    let mut reader = DirectoryReader::new(parent, DirectoryScanCursor::start());
    while let Some(scanned) = read.next_directory_entry(&mut reader)? {
        if let Some(alias) = crate::short_name::read_alias(read, parent, scanned.entry().name(), *scanned.entry().node())?
            && lookup.matches(&alias.windows_name()?)
        {
            if found.is_some() { return Err(DriverError::AmbiguousName); }
            found = Some(scanned.into_child());
        }
    }
    Ok(found.map_or(ChildLookup::NotFound, ChildLookup::Found))
}

/// Name that can be losslessly exposed through the Windows UTF-16 namespace.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WindowsName {
    /// Validated Windows component encoded as UTF-16.
    utf16: DriverVec<u16>,
}

impl WindowsName {
    /// Validates and stores a Windows UTF-16 lookup component.
    ///
    /// # Errors
    /// Returns an error when the requested component is empty or contains a
    /// separator or wildcard character that is not a file-name component.
    pub(crate) fn from_utf16(utf16: &[u16]) -> DriverResult<Self> {
        if utf16.is_empty()
            || utf16.iter().any(|unit| {
                matches!(
                    *unit,
                    0x0000
                        | 0x0022
                        | 0x002A
                        | 0x002F
                        | 0x003A
                        | 0x003C
                        | 0x003E
                        | 0x003F
                        | 0x005C
                        | 0x007C
                )
            })
        {
            return Err(DriverError::InvalidName);
        }
        Ok(Self {
            utf16: DriverVec::try_copied_from_slice(utf16)?,
        })
    }

    /// Converts a raw ext4 name if Windows can represent it without escaping.
    ///
    /// # Errors
    /// Returns an error when the ext4 bytes are not UTF-8 or contain a
    /// character that Windows path lookup cannot expose losslessly.
    pub(crate) fn from_ext4(name: &Ext4Name) -> DriverResult<Self> {
        let text = str::from_utf8(name.bytes()).map_err(|_| DriverError::InvalidName)?;
        if text.chars().any(|ch| {
            matches!(
                ch,
                '\0' | '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
            )
        }) {
            return Err(DriverError::InvalidName);
        }
        let mut utf16 = DriverVec::try_with_capacity(text.len())?;
        for unit in text.encode_utf16() {
            utf16.try_push(unit)?;
        }
        Ok(Self { utf16 })
    }

    /// Converts this Windows name to the ext4 UTF-8 name stored on disk.
    ///
    /// # Errors
    /// Returns an error when the Windows UTF-16 contains an unpaired surrogate
    /// or the encoded ext4 name violates ext4 component limits.
    pub(crate) fn to_ext4(&self) -> DriverResult<Ext4Name> {
        let mut bytes = DriverVec::new();
        for item in char::decode_utf16(self.utf16.iter().copied()) {
            let ch = item.map_err(|_| DriverError::InvalidName)?;
            let mut encoded = [0_u8; 4];
            let text = ch.encode_utf8(&mut encoded);
            bytes.try_extend_from_copy_slice(text.as_bytes())?;
        }
        Ok(Ext4Name::new(bytes.as_slice())?)
    }

    /// Returns the UTF-16 Windows name.
    #[must_use]
    pub(crate) fn utf16(&self) -> &[u16] {
        self.utf16.as_slice()
    }

    /// Returns true when the name exactly equals another Windows name.
    #[must_use]
    pub(crate) fn equals(&self, requested: &Self) -> bool {
        self.utf16 == requested.utf16
    }
}

/// Requested Windows-visible spelling and the caller's comparison authority.
///
/// Lookup first searches the exact ext4 spelling. An insensitive fallback uses the supplied
/// UTF-16 uppercase mapping without Unicode normalization and rejects multiple matching entries.
/// The mapping must remain deterministic throughout a restartable operation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum WindowsNameLookup<'name> {
    /// Accept only the supplied spelling.
    Exact(&'name WindowsName),
    /// Permit an insensitive fallback using the namespace owner's uppercase table.
    CaseInsensitive {
        /// Requested spelling, retained unchanged for the indexed exact lookup.
        name: &'name WindowsName,
        /// Uppercase mapping for one UTF-16 code unit.
        upcase: fn(u16) -> u16,
    },
}

impl<'name> WindowsNameLookup<'name> {
    /// Borrows the original spelling independently of fallback comparison policy.
    pub(crate) const fn name(self) -> &'name WindowsName {
        match self {
            Self::Exact(name) | Self::CaseInsensitive { name, .. } => name,
        }
    }

    /// Compares fallback candidates using only the supplied namespace authority.
    pub(crate) fn matches(self, candidate: &WindowsName) -> bool {
        match self {
            Self::Exact(name) => candidate.equals(name),
            Self::CaseInsensitive { name, upcase } => {
                candidate.utf16.len() == name.utf16.len()
                    && candidate
                        .utf16
                        .iter()
                        .zip(name.utf16.iter())
                        .all(|(left, right)| upcase(*left) == upcase(*right))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WindowsName;

    /// # Errors
    /// Returns name conversion or allocation failure.
    /// # Panics
    /// Fails if exact and insensitive matching disagree with the supplied Unicode mapping.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions verify Windows spelling and supplied mapping after fallible capture"
    )]
    fn lookup_policy_uses_the_supplied_mapping_without_normalization() -> super::DriverResult<()> {
        let upper = WindowsName::from_utf16(&[0x00c9, 0x0041])?;
        let lower = WindowsName::from_utf16(&[0x00e9, 0x0061])?;
        let decomposed = WindowsName::from_utf16(&[0x0045, 0x0301, 0x0041])?;
        let lookup = super::WindowsNameLookup::CaseInsensitive {
            name: &upper,
            upcase: |unit| match unit {
                0x00e9 => 0x00c9,
                0x0061 => 0x0041,
                _ => unit,
            },
        };
        assert!(lookup.matches(&upper));
        assert!(lookup.matches(&lower));
        assert!(!lookup.matches(&decomposed));
        assert!(!super::WindowsNameLookup::Exact(&upper).matches(&lower));
        assert!(WindowsName::from_ext4(&ext4_core::Ext4Name::new(b"a:b")?).is_err());
        Ok(())
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn windows_name_converts_to_ext4_utf8_name() {
        let name = WindowsName::from_utf16(&[0x0063, 0x0061, 0x0066, 0x00E9]);
        assert!(name.is_ok());
        if let Ok(name) = name {
            let ext4 = name.to_ext4();
            assert!(ext4.is_ok());
            if let Ok(ext4) = ext4 {
                assert_eq!(ext4.bytes(), b"caf\xC3\xA9");
            }
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn windows_name_rejects_unpaired_surrogate_for_ext4_creation() {
        let name = WindowsName::from_utf16(&[0xD800]);
        assert!(name.is_ok());
        if let Ok(name) = name {
            assert!(name.to_ext4().is_err());
        }
    }
}
