//! Extended-attribute domain types.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// External ext4 xattr namespace selected by the name prefix.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum XattrNamespace {
    /// `user.*` namespace.
    User,
    /// `system.*` namespace.
    System,
    /// `trusted.*` namespace.
    Trusted,
    /// `security.*` namespace.
    Security,
}

impl XattrNamespace {
    /// Returns the namespace prefix without the trailing dot.
    #[must_use]
    pub const fn prefix(self) -> &'static [u8] {
        match self {
            Self::User => b"user",
            Self::System => b"system",
            Self::Trusted => b"trusted",
            Self::Security => b"security",
        }
    }
}

/// Validated ext4 xattr name split into namespace and local name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct XattrName {
    /// Namespace that owns the local name.
    namespace: XattrNamespace,
    /// Local name without the namespace prefix.
    local: Vec<u8>,
}

impl XattrName {
    /// Creates a validated xattr name.
    ///
    /// # Errors
    /// Returns an error when the local name is empty, contains NUL, or the
    /// fully qualified name is longer than ext4's 255-byte limit.
    pub fn new(namespace: XattrNamespace, local: &[u8]) -> Result<Self> {
        let full_len = namespace
            .prefix()
            .len()
            .checked_add(1)
            .and_then(|len| len.checked_add(local.len()))
            .ok_or(Error::ArithmeticOverflow)?;
        if local.is_empty() || local.contains(&0) || full_len > 255 {
            return Err(Error::InvalidXattr);
        }
        Ok(Self {
            namespace,
            local: local.to_vec(),
        })
    }

    /// Namespace component.
    #[must_use]
    pub const fn namespace(&self) -> XattrNamespace {
        self.namespace
    }

    /// Local name component.
    #[must_use]
    pub fn local(&self) -> &[u8] {
        &self.local
    }

    /// Fully qualified xattr name with namespace prefix.
    #[must_use]
    pub fn qualified(&self) -> Vec<u8> {
        let mut qualified = Vec::with_capacity(
            self.namespace
                .prefix()
                .len()
                .checked_add(1)
                .and_then(|len| len.checked_add(self.local.len()))
                .unwrap_or(0),
        );
        qualified.extend_from_slice(self.namespace.prefix());
        qualified.push(b'.');
        qualified.extend_from_slice(&self.local);
        qualified
    }
}

/// Validated xattr value bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrValue {
    /// Raw value bytes.
    bytes: Vec<u8>,
}

impl XattrValue {
    /// Maximum value length accepted by this domain.
    pub const MAX_BYTES: usize = 65_536;

    /// Creates a validated value.
    ///
    /// # Errors
    /// Returns an error when the value is larger than the domain limit.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::InvalidXattr);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Returns raw value bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Sorted unique xattr set for one inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XattrSet {
    /// Entries sorted by name.
    entries: Vec<XattrEntry>,
}

impl XattrSet {
    /// Creates a sorted unique set from entries.
    ///
    /// # Errors
    /// Returns an error when duplicate names are present.
    pub fn from_entries(entries: Vec<(XattrName, XattrValue)>) -> Result<Self> {
        let mut entries: Vec<_> = entries
            .into_iter()
            .map(|(name, value)| XattrEntry { name, value })
            .collect();
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        if entries
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left.name == right.name))
        {
            return Err(Error::InvalidXattr);
        }
        Ok(Self { entries })
    }

    /// Creates an empty set.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Looks up a value by name.
    #[must_use]
    pub fn get(&self, name: &XattrName) -> Option<&XattrValue> {
        self.entries
            .binary_search_by(|entry| entry.name.cmp(name))
            .ok()
            .and_then(|index| self.entries.get(index))
            .map(|entry| &entry.value)
    }

    /// Inserts or replaces one value.
    pub fn insert(&mut self, name: XattrName, value: XattrValue) {
        match self.entries.binary_search_by(|entry| entry.name.cmp(&name)) {
            Ok(index) => {
                if let Some(entry) = self.entries.get_mut(index) {
                    entry.value = value;
                }
            }
            Err(index) => self.entries.insert(index, XattrEntry { name, value }),
        }
    }

    /// Removes one value.
    #[must_use]
    pub fn remove(&mut self, name: &XattrName) -> Option<XattrValue> {
        self.entries
            .binary_search_by(|entry| entry.name.cmp(name))
            .ok()
            .map(|index| self.entries.remove(index).value)
    }

    /// Returns entries in stable xattr name order.
    #[must_use]
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (&XattrName, &XattrValue)> {
        self.entries.iter().map(|entry| (&entry.name, &entry.value))
    }
}

/// One xattr entry stored by `XattrSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
struct XattrEntry {
    /// Entry name.
    name: XattrName,
    /// Entry value.
    value: XattrValue,
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{XattrName, XattrNamespace, XattrSet, XattrValue};

    #[test]
    fn xattr_name_is_split_from_namespace() {
        let name = XattrName::new(XattrNamespace::User, b"ext4win").ok();
        assert_eq!(
            name.as_ref().map(XattrName::qualified),
            Some(b"user.ext4win".to_vec())
        );
    }

    #[test]
    fn xattr_set_rejects_duplicate_names() {
        let name = XattrName::new(XattrNamespace::System, b"posix_acl_access");
        let value = XattrValue::new(b"acl");
        if let (Ok(name), Ok(value)) = (name, value) {
            assert!(
                XattrSet::from_entries(vec![(name.clone(), value.clone()), (name, value),])
                    .is_err()
            );
        }
    }
}
