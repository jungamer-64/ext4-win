//! POSIX ACL xattr domain.

use alloc::{vec, vec::Vec};

use crate::endian::{le_u16, le_u32, put_le_u16, put_le_u32};
use crate::error::{Error, Result};
use crate::inode::{Ext4Gid, Ext4Permissions, Ext4Uid};
use crate::xattr::{XattrName, XattrNamespace, XattrValue};

/// POSIX ACL xattr payload version.
const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;
/// Bytes occupied by the POSIX ACL xattr header.
const ACL_HEADER_BYTES: usize = 4;
/// Bytes occupied by one POSIX ACL xattr entry.
const ACL_ENTRY_BYTES: usize = 8;
/// ACL entry tag for owning user permissions.
const ACL_USER_OBJ: u16 = 0x0001;
/// ACL entry tag for a named user.
const ACL_USER: u16 = 0x0002;
/// ACL entry tag for owning group permissions.
const ACL_GROUP_OBJ: u16 = 0x0004;
/// ACL entry tag for a named group.
const ACL_GROUP: u16 = 0x0008;
/// ACL entry tag for the mask.
const ACL_MASK: u16 = 0x0010;
/// ACL entry tag for other permissions.
const ACL_OTHER: u16 = 0x0020;
/// Undefined identifier used by non-named ACL entries.
const ACL_UNDEFINED_ID: u32 = u32::MAX;

/// POSIX ACL xattr slot associated with one inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixAclKind {
    /// `system.posix_acl_access`.
    Access,
    /// `system.posix_acl_default`.
    Default,
}

/// POSIX ACL associated with one inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PosixAcl {
    /// Validated ACL entries in canonical order.
    entries: Vec<PosixAclEntry>,
}

impl PosixAcl {
    /// Returns the xattr name for access ACLs.
    ///
    /// # Errors
    /// Returns an error only if the fixed domain name is invalid.
    pub fn access_xattr_name() -> Result<XattrName> {
        XattrName::new(XattrNamespace::System, b"posix_acl_access")
    }

    /// Returns the xattr name for default directory ACLs.
    ///
    /// # Errors
    /// Returns an error only if the fixed domain name is invalid.
    pub fn default_xattr_name() -> Result<XattrName> {
        XattrName::new(XattrNamespace::System, b"posix_acl_default")
    }

    /// Returns the xattr name for the requested POSIX ACL slot.
    ///
    /// # Errors
    /// Returns an error only if the fixed domain name is invalid.
    pub fn xattr_name(kind: PosixAclKind) -> Result<XattrName> {
        match kind {
            PosixAclKind::Access => Self::access_xattr_name(),
            PosixAclKind::Default => Self::default_xattr_name(),
        }
    }

    /// Creates a canonical POSIX ACL.
    ///
    /// # Errors
    /// Returns an error when required owner/group/other entries are missing,
    /// duplicated, or named entries are not protected by a mask entry.
    pub fn new(entries: Vec<PosixAclEntry>) -> Result<Self> {
        validate_acl(&entries)?;
        Ok(Self { entries })
    }

    /// Parses a POSIX ACL xattr value.
    ///
    /// # Errors
    /// Returns an error when the xattr payload is malformed or violates POSIX
    /// ACL structural rules.
    pub fn parse(value: &XattrValue) -> Result<Self> {
        let bytes = value.bytes();
        if bytes.len() < ACL_HEADER_BYTES
            || bytes
                .len()
                .checked_sub(ACL_HEADER_BYTES)
                .ok_or(Error::ArithmeticOverflow)?
                % ACL_ENTRY_BYTES
                != 0
            || le_u32(bytes, 0)? != POSIX_ACL_XATTR_VERSION
        {
            return Err(Error::InvalidAcl);
        }

        let mut entries = Vec::new();
        let mut offset = ACL_HEADER_BYTES;
        while offset < bytes.len() {
            let tag = le_u16(bytes, offset)?;
            let permissions = Ext4Permissions::new(le_u16(
                bytes,
                offset.checked_add(2).ok_or(Error::ArithmeticOverflow)?,
            )?)?;
            let id = le_u32(
                bytes,
                offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
            )?;
            entries.push(parse_entry(tag, permissions, id)?);
            offset = offset
                .checked_add(ACL_ENTRY_BYTES)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Self::new(entries)
    }

    /// Serializes this ACL as a POSIX ACL xattr value.
    ///
    /// # Errors
    /// Returns an error when the serialized value exceeds xattr limits.
    pub fn to_xattr_value(&self) -> Result<XattrValue> {
        let len = ACL_HEADER_BYTES
            .checked_add(
                self.entries
                    .len()
                    .checked_mul(ACL_ENTRY_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let mut bytes = vec![0_u8; len];
        put_le_u32(&mut bytes, 0, POSIX_ACL_XATTR_VERSION)?;
        let mut offset = ACL_HEADER_BYTES;
        for entry in &self.entries {
            let (tag, permissions, id) = entry_fields(entry);
            put_le_u16(&mut bytes, offset, tag)?;
            put_le_u16(
                &mut bytes,
                offset.checked_add(2).ok_or(Error::ArithmeticOverflow)?,
                permissions.as_u16(),
            )?;
            put_le_u32(
                &mut bytes,
                offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
                id,
            )?;
            offset = offset
                .checked_add(ACL_ENTRY_BYTES)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        XattrValue::new(&bytes)
    }

    /// Entries in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[PosixAclEntry] {
        &self.entries
    }
}

/// One POSIX ACL entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixAclEntry {
    /// Permissions for the inode owner.
    UserObj(Ext4Permissions),
    /// Permissions for a named user.
    User(Ext4Uid, Ext4Permissions),
    /// Permissions for the inode group.
    GroupObj(Ext4Permissions),
    /// Permissions for a named group.
    Group(Ext4Gid, Ext4Permissions),
    /// Maximum permissions for named user/group and group object entries.
    Mask(Ext4Permissions),
    /// Permissions for all other users.
    Other(Ext4Permissions),
}

/// Parses one serialized ACL entry.
fn parse_entry(tag: u16, permissions: Ext4Permissions, id: u32) -> Result<PosixAclEntry> {
    match tag {
        ACL_USER_OBJ if id == ACL_UNDEFINED_ID => Ok(PosixAclEntry::UserObj(permissions)),
        ACL_USER if id != ACL_UNDEFINED_ID => {
            Ok(PosixAclEntry::User(Ext4Uid::from_u32(id), permissions))
        }
        ACL_GROUP_OBJ if id == ACL_UNDEFINED_ID => Ok(PosixAclEntry::GroupObj(permissions)),
        ACL_GROUP if id != ACL_UNDEFINED_ID => {
            Ok(PosixAclEntry::Group(Ext4Gid::from_u32(id), permissions))
        }
        ACL_MASK if id == ACL_UNDEFINED_ID => Ok(PosixAclEntry::Mask(permissions)),
        ACL_OTHER if id == ACL_UNDEFINED_ID => Ok(PosixAclEntry::Other(permissions)),
        _ => Err(Error::InvalidAcl),
    }
}

/// Returns serialized ACL fields.
const fn entry_fields(entry: &PosixAclEntry) -> (u16, Ext4Permissions, u32) {
    match *entry {
        PosixAclEntry::UserObj(permissions) => (ACL_USER_OBJ, permissions, ACL_UNDEFINED_ID),
        PosixAclEntry::User(uid, permissions) => (ACL_USER, permissions, uid.as_u32()),
        PosixAclEntry::GroupObj(permissions) => (ACL_GROUP_OBJ, permissions, ACL_UNDEFINED_ID),
        PosixAclEntry::Group(gid, permissions) => (ACL_GROUP, permissions, gid.as_u32()),
        PosixAclEntry::Mask(permissions) => (ACL_MASK, permissions, ACL_UNDEFINED_ID),
        PosixAclEntry::Other(permissions) => (ACL_OTHER, permissions, ACL_UNDEFINED_ID),
    }
}

/// Validates ACL required entries, uniqueness, and canonical order.
fn validate_acl(entries: &[PosixAclEntry]) -> Result<()> {
    let mut seen_user_obj = false;
    let mut seen_group_obj = false;
    let mut seen_mask = false;
    let mut seen_other = false;
    let mut has_named = false;
    let mut previous = None;

    for entry in entries {
        let key = acl_order_key(entry);
        if let Some(previous) = previous
            && previous >= key
        {
            return Err(Error::InvalidAcl);
        }
        previous = Some(key);

        match *entry {
            PosixAclEntry::UserObj(_) => seen_user_obj = unique(seen_user_obj)?,
            PosixAclEntry::User(_, _) | PosixAclEntry::Group(_, _) => has_named = true,
            PosixAclEntry::GroupObj(_) => seen_group_obj = unique(seen_group_obj)?,
            PosixAclEntry::Mask(_) => seen_mask = unique(seen_mask)?,
            PosixAclEntry::Other(_) => seen_other = unique(seen_other)?,
        }
    }

    if !seen_user_obj || !seen_group_obj || !seen_other || (has_named && !seen_mask) {
        return Err(Error::InvalidAcl);
    }
    Ok(())
}

/// Converts a duplicate flag into its updated value.
fn unique(seen: bool) -> Result<bool> {
    if seen {
        Err(Error::InvalidAcl)
    } else {
        Ok(true)
    }
}

/// Canonical ACL order key.
const fn acl_order_key(entry: &PosixAclEntry) -> (u8, u32) {
    match *entry {
        PosixAclEntry::UserObj(_) => (0, 0),
        PosixAclEntry::User(uid, _) => (1, uid.as_u32()),
        PosixAclEntry::GroupObj(_) => (2, 0),
        PosixAclEntry::Group(gid, _) => (3, gid.as_u32()),
        PosixAclEntry::Mask(_) => (4, 0),
        PosixAclEntry::Other(_) => (5, 0),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{PosixAcl, PosixAclEntry};
    use crate::{Ext4Gid, Ext4Permissions, Ext4Uid};

    fn permissions(bits: u16) -> Option<Ext4Permissions> {
        Ext4Permissions::new(bits).ok()
    }

    #[test]
    fn posix_acl_round_trips_xattr_payload() {
        if let (Some(user_obj), Some(user), Some(group_obj), Some(group), Some(mask), Some(other)) = (
            permissions(0o700),
            permissions(0o600),
            permissions(0o050),
            permissions(0o040),
            permissions(0o750),
            permissions(0o005),
        ) {
            let acl = PosixAcl::new(vec![
                PosixAclEntry::UserObj(user_obj),
                PosixAclEntry::User(Ext4Uid::from_u32(1000), user),
                PosixAclEntry::GroupObj(group_obj),
                PosixAclEntry::Group(Ext4Gid::from_u32(100), group),
                PosixAclEntry::Mask(mask),
                PosixAclEntry::Other(other),
            ]);
            assert!(acl.is_ok());
            let Ok(acl) = acl else {
                return;
            };
            let value = acl.to_xattr_value();
            if let Ok(value) = value {
                assert_eq!(PosixAcl::parse(&value), Ok(acl));
            }
        }
    }

    #[test]
    fn named_acl_requires_mask() {
        if let (Some(user_obj), Some(user), Some(group_obj), Some(other)) = (
            permissions(0o700),
            permissions(0o600),
            permissions(0o050),
            permissions(0o005),
        ) {
            assert!(
                PosixAcl::new(vec![
                    PosixAclEntry::UserObj(user_obj),
                    PosixAclEntry::User(Ext4Uid::from_u32(1000), user),
                    PosixAclEntry::GroupObj(group_obj),
                    PosixAclEntry::Other(other),
                ])
                .is_err()
            );
        }
    }
}
