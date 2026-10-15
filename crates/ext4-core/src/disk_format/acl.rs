//! Validated ext4 POSIX ACLs and their relation to inode permission fields.

use alloc::vec::Vec;

use crate::disk::endian::{DiskOffset, le_u16, le_u32};
use crate::disk_format::inode::{Ext4Gid, Ext4Permissions, Ext4Security, Ext4Uid};
use crate::disk_format::xattr::{XattrName, XattrNamespace, XattrValue};
use crate::memory::{self, FallibleVec};
use crate::{Error, Result};

/// Read, write and execute bits in one POSIX ACL entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AclPermissions(u16);

impl AclPermissions {
    /// Returns the three permission bits.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Rejects bits outside an ACL entry's permission domain.
    /// # Errors
    /// Returns invalid ACL for an unknown permission bit.
    fn parse(bits: u16) -> Result<Self> {
        if bits & !7 != 0 {
            Err(Error::InvalidAcl)
        } else {
            Ok(Self(bits))
        }
    }
}

/// One named user entry, independent of the inode owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AclUser {
    /// Filesystem user identity.
    uid: Ext4Uid,
    /// Permissions before application of the ACL mask.
    permissions: AclPermissions,
}
impl AclUser {
    /// Returns the filesystem identity.
    pub const fn uid(self) -> Ext4Uid {
        self.uid
    }
    /// Returns permissions before masking.
    pub const fn permissions(self) -> AclPermissions {
        self.permissions
    }
}

/// One named group entry, independent of the inode owning group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AclGroup {
    /// Filesystem group identity.
    gid: Ext4Gid,
    /// Permissions before application of the ACL mask.
    permissions: AclPermissions,
}
impl AclGroup {
    /// Returns the filesystem identity.
    pub const fn gid(self) -> Ext4Gid {
        self.gid
    }
    /// Returns permissions before masking.
    pub const fn permissions(self) -> AclPermissions {
        self.permissions
    }
}

/// Canonically ordered ACL with unique named identities and a mask whenever names exist.
/// Only named entries carry an identity in the ext4 version-one disk encoding.
#[derive(Debug, Eq, PartialEq)]
pub struct PosixAcl {
    /// Owner class.
    owner: AclPermissions,
    /// Sorted unique named users.
    users: Vec<AclUser>,
    /// Owning group, before masking.
    group: AclPermissions,
    /// Sorted unique named groups.
    groups: Vec<AclGroup>,
    /// Group-class ceiling, required when any named entry exists.
    mask: Option<AclPermissions>,
    /// Class selected only when neither user nor group membership matches.
    other: AclPermissions,
}

impl PosixAcl {
    /// Parses an ext4 version-one ACL payload, including reduced base-entry widths.
    /// # Errors
    /// Rejects truncation, invalid permissions, ordering, duplicate identities or missing mask.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let parse = || -> Result<Self> {
            if le_u32(bytes, DiskOffset::new(0))? != 1 {
                return Err(Error::InvalidAcl);
            }
            let mut cursor = AclCursor { bytes, offset: 4 };
            let owner = cursor.permissions(1)?;
            let mut users: Vec<AclUser> = Vec::new();
            while cursor.tag()? == Some(2) {
                let permissions = cursor.permissions(2)?;
                let uid = Ext4Uid::from_u32(cursor.identity()?);
                if users
                    .last()
                    .is_some_and(|last| last.uid.as_u32() >= uid.as_u32())
                {
                    return Err(Error::InvalidAcl);
                }
                users.try_push(AclUser { uid, permissions })?;
            }
            let group = cursor.permissions(4)?;
            let mut groups: Vec<AclGroup> = Vec::new();
            while cursor.tag()? == Some(8) {
                let permissions = cursor.permissions(8)?;
                let gid = Ext4Gid::from_u32(cursor.identity()?);
                if groups
                    .last()
                    .is_some_and(|last| last.gid.as_u32() >= gid.as_u32())
                {
                    return Err(Error::InvalidAcl);
                }
                groups.try_push(AclGroup { gid, permissions })?;
            }
            let mask = if cursor.tag()? == Some(16) {
                Some(cursor.permissions(16)?)
            } else {
                None
            };
            if mask.is_none() && (!users.is_empty() || !groups.is_empty()) {
                return Err(Error::InvalidAcl);
            }
            let other = cursor.permissions(32)?;
            if cursor.offset != bytes.len() {
                return Err(Error::InvalidAcl);
            }
            Ok(Self {
                owner,
                users,
                group,
                groups,
                mask,
                other,
            })
        };
        parse().map_err(|error| match error {
            Error::OutOfMemory => error,
            _ => Error::InvalidAcl,
        })
    }

    /// Returns the owner permissions.
    pub const fn owner(&self) -> AclPermissions {
        self.owner
    }
    /// Returns unmasked owning-group permissions.
    pub const fn group(&self) -> AclPermissions {
        self.group
    }
    /// Returns permissions for unmatched subjects.
    pub const fn other(&self) -> AclPermissions {
        self.other
    }
    /// Returns the group-class ceiling, when present.
    pub const fn mask(&self) -> Option<AclPermissions> {
        self.mask
    }
    /// Returns sorted named users.
    pub fn users(&self) -> &[AclUser] {
        &self.users
    }
    /// Returns sorted named groups.
    pub fn groups(&self) -> &[AclGroup] {
        &self.groups
    }

    /// Copies an ACL without hiding allocation failure.
    /// # Errors
    /// Returns out-of-memory before exposing a partial copy.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            owner: self.owner,
            users: memory::copied_slice(&self.users)?,
            group: self.group,
            groups: memory::copied_slice(&self.groups)?,
            mask: self.mask,
            other: self.other,
        })
    }

    /// Derives inode rwx bits while retaining its independent special bits.
    /// # Errors
    /// Returns an invalid inode permission encoding.
    pub(crate) fn mode(&self, mode: Ext4Permissions) -> Result<Ext4Permissions> {
        Ext4Permissions::new(
            (mode.as_u16() & !0o777)
                | (self.owner.0 << 6)
                | (self.mask.unwrap_or(self.group).0 << 3)
                | self.other.0,
        )
    }

    /// Applies chmod to the owner, group class and other; named entries remain masked.
    pub(crate) fn chmod(&mut self, mode: Ext4Permissions) {
        let bits = mode.as_u16();
        self.owner = AclPermissions((bits >> 6) & 7);
        if let Some(mask) = &mut self.mask {
            *mask = AclPermissions((bits >> 3) & 7);
        } else {
            self.group = AclPermissions((bits >> 3) & 7);
        }
        self.other = AclPermissions(bits & 7);
    }

    /// Restricts inherited base classes by the requested creation mode.
    fn restrict(&mut self, mode: Ext4Permissions) {
        let bits = mode.as_u16();
        self.owner.0 &= (bits >> 6) & 7;
        if let Some(mask) = &mut self.mask {
            mask.0 &= (bits >> 3) & 7;
        } else {
            self.group.0 &= (bits >> 3) & 7;
        }
        self.other.0 &= bits & 7;
    }

    /// Serializes the ext4 reduced-width ACL payload.
    /// # Errors
    /// Returns buffer allocation failure.
    pub(crate) fn value(&self) -> Result<XattrValue> {
        let mut bytes = Vec::new();
        bytes.try_extend_from_slice(&1_u32.to_le_bytes())?;
        append_entry(&mut bytes, 1, self.owner, None)?;
        for entry in &self.users {
            append_entry(&mut bytes, 2, entry.permissions, Some(entry.uid.as_u32()))?;
        }
        append_entry(&mut bytes, 4, self.group, None)?;
        for entry in &self.groups {
            append_entry(&mut bytes, 8, entry.permissions, Some(entry.gid.as_u32()))?;
        }
        if let Some(mask) = self.mask {
            append_entry(&mut bytes, 16, mask, None)?;
        }
        append_entry(&mut bytes, 32, self.other, None)?;
        XattrValue::new(&bytes)
    }
}

/// Inode owner/mode and access ACL whose permission projections agree.
/// Immutable construction keeps the disk's two representations from becoming independent authorities.
#[derive(Debug, Eq, PartialEq)]
pub struct Ext4Access {
    /// Inode field projection, validated against the optional ACL.
    security: Ext4Security,
    /// Access policy beyond the three inode classes.
    acl: Option<PosixAcl>,
}
impl Ext4Access {
    /// Constructs an inode-class policy when no access ACL exists.
    pub const fn from_mode(security: Ext4Security) -> Self {
        Self {
            security,
            acl: None,
        }
    }
    /// Validates agreement of inode fields and an independently decoded ACL.
    /// # Errors
    /// Returns invalid ACL when its base classes disagree with inode rwx bits.
    pub fn new(security: Ext4Security, acl: Option<PosixAcl>) -> Result<Self> {
        if let Some(acl) = &acl
            && acl.mode(security.permissions())? != security.permissions()
        {
            return Err(Error::InvalidAcl);
        }
        Ok(Self { security, acl })
    }
    /// Returns owner and inode-mode fields.
    pub const fn security(&self) -> Ext4Security {
        self.security
    }
    /// Returns the validated extended access policy, when stored.
    pub const fn acl(&self) -> Option<&PosixAcl> {
        self.acl.as_ref()
    }
    /// Computes the child access policy from the containing directory's default ACL.
    /// # Errors
    /// Returns an invalid permission representation.
    pub(crate) fn inherit(security: Ext4Security, default: Option<PosixAcl>) -> Result<Self> {
        let Some(mut acl) = default else {
            return Ok(Self::from_mode(security));
        };
        acl.restrict(security.permissions());
        let security = Ext4Security::new(security.owner(), acl.mode(security.permissions())?);
        Self::new(security, Some(acl))
    }
}

/// The two ACL xattr roles with distinct inode-kind and inheritance contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AclKind {
    /// Current inode access.
    Access,
    /// Child-creation policy, valid only on directories.
    Default,
}
impl AclKind {
    /// Classifies only the two reserved POSIX ACL slots.
    pub(crate) fn of(name: &XattrName) -> Option<Self> {
        if name.namespace() != XattrNamespace::System {
            return None;
        }
        match name.local() {
            super::xattr::POSIX_ACL_ACCESS_NAME => Some(Self::Access),
            super::xattr::POSIX_ACL_DEFAULT_NAME => Some(Self::Default),
            _ => None,
        }
    }
    /// Decodes the matching reserved slot without allocating a lookup name.
    /// # Errors
    /// Returns invalid ACL or allocation failure from its named entries.
    pub(crate) fn read(self, set: &super::xattr::XattrSet) -> Result<Option<PosixAcl>> {
        set.entries()
            .find(|(name, _)| Self::of(name) == Some(self))
            .map(|(_, value)| {
                if value.bytes() == 1_u32.to_le_bytes() {
                    Ok(None)
                } else {
                    PosixAcl::parse(value.bytes()).map(Some)
                }
            })
            .transpose()
            .map(Option::flatten)
    }

    /// Returns the logical xattr name.
    /// # Errors
    /// Returns name allocation failure.
    pub(crate) fn name(self) -> Result<XattrName> {
        XattrName::new(
            XattrNamespace::System,
            match self {
                Self::Access => super::xattr::POSIX_ACL_ACCESS_NAME,
                Self::Default => super::xattr::POSIX_ACL_DEFAULT_NAME,
            },
        )
    }
}

/// Checked cursor for the variable-width external representation.
struct AclCursor<'a> {
    /// Complete ACL value.
    bytes: &'a [u8],
    /// Next byte field.
    offset: usize,
}
impl AclCursor<'_> {
    /// Inspects the next tag without consuming it.
    /// # Errors
    /// Returns truncated-structure for an incomplete tag.
    fn tag(&self) -> Result<Option<u16>> {
        if self.offset == self.bytes.len() {
            Ok(None)
        } else {
            le_u16(self.bytes, DiskOffset::new(self.offset)).map(Some)
        }
    }
    /// Consumes the fixed header of an expected entry.
    /// # Errors
    /// Returns invalid ACL or truncated fields.
    fn permissions(&mut self, tag: u16) -> Result<AclPermissions> {
        if self.tag()? != Some(tag) {
            return Err(Error::InvalidAcl);
        }
        let offset = self.offset.checked_add(2).ok_or(Error::InvalidAcl)?;
        let permissions = AclPermissions::parse(le_u16(self.bytes, DiskOffset::new(offset))?)?;
        self.offset = self.offset.checked_add(4).ok_or(Error::InvalidAcl)?;
        Ok(permissions)
    }
    /// Consumes the identity following a named entry header.
    /// # Errors
    /// Rejects the undefined-identity sentinel and truncated input.
    fn identity(&mut self) -> Result<u32> {
        let identity = le_u32(self.bytes, DiskOffset::new(self.offset))?;
        if identity == u32::MAX {
            return Err(Error::InvalidAcl);
        }
        self.offset = self.offset.checked_add(4).ok_or(Error::InvalidAcl)?;
        Ok(identity)
    }
}

/// Encodes one external entry with an identity only for named subjects.
/// # Errors
/// Returns output allocation failure.
fn append_entry(
    bytes: &mut Vec<u8>,
    tag: u16,
    permissions: AclPermissions,
    identity: Option<u32>,
) -> Result<()> {
    bytes.try_extend_from_slice(&tag.to_le_bytes())?;
    bytes.try_extend_from_slice(&permissions.0.to_le_bytes())?;
    if let Some(identity) = identity {
        bytes.try_extend_from_slice(&identity.to_le_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns independent fixture decoding or serialization failures.
    /// # Panics
    /// Panics when fixed disk bytes or required validity constraints differ.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions validate independently encoded disk ACL vectors"
    )]
    fn disk_acl_vectors() -> Result<()> {
        let bytes = [
            1, 0, 0, 0, 1, 0, 7, 0, 2, 0, 6, 0, 233, 3, 0, 0, 4, 0, 4, 0, 8, 0, 2, 0, 100, 0, 0, 0,
            16, 0, 6, 0, 32, 0, 0, 0,
        ];
        let acl = PosixAcl::parse(&bytes)?;
        assert_eq!(acl.value()?.bytes(), bytes);
        assert_eq!(
            acl.users().first().ok_or(Error::InvalidAcl)?.uid().as_u32(),
            1001
        );
        assert_eq!(
            acl.groups()
                .first()
                .ok_or(Error::InvalidAcl)?
                .gid()
                .as_u32(),
            100
        );
        for length in 0..bytes.len() {
            assert_eq!(
                PosixAcl::parse(bytes.get(..length).ok_or(Error::InvalidAcl)?),
                Err(Error::InvalidAcl)
            );
        }
        for (offset, value) in [(0, 2), (6, 8), (8, 8), (28, 32)] {
            let mut bad = bytes;
            *bad.get_mut(offset).ok_or(Error::InvalidAcl)? = value;
            assert_eq!(PosixAcl::parse(&bad), Err(Error::InvalidAcl));
        }
        let mut duplicate = bytes[..16].to_vec();
        duplicate.extend_from_slice(&bytes[8..]);
        assert_eq!(PosixAcl::parse(&duplicate), Err(Error::InvalidAcl));
        let mut no_mask = bytes[..28].to_vec();
        no_mask.extend_from_slice(&bytes[32..]);
        assert_eq!(PosixAcl::parse(&no_mask), Err(Error::InvalidAcl));
        Ok(())
    }
}
