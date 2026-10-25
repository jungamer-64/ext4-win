//! Exclusive POSIX-class projection and Windows security descriptor representation.
use crate::Error;
#[cfg(any(windows, test))]
use crate::{BASE_RIGHTS, CONTROLLED_RIGHTS, IdentityMap, Sid, mode_rights};
#[cfg(windows)]
use crate::{rights_mode, u32_at};
#[cfg(windows)]
mod native;
#[cfg(windows)]
use ext4_core::{Ext4Owner, Ext4Permissions, Ext4Security};
#[cfg(windows)]
use native::{NativeAcl, NativeImage};

/// Native ACL's sixteen-bit length plus descriptor header and two maximum-length SIDs.
pub const MAX_DESCRIPTOR_BYTES: usize = 65_691;
/// Supported security-information component selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Components(u32);
impl Components {
    /// Complete owner/group/DACL selection.
    pub const ALL: Self = Self(7);
    /// Validates owner/group/DACL bits.
    /// # Errors
    /// Rejects empty selections and unsupported components.
    pub fn new(bits: u32) -> Result<Self, Error> {
        if bits == 0 || bits & !7 != 0 {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self(bits))
    }
    /// Returns native security-information bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}
/// Owned Windows descriptor built by RTL with exclusive POSIX-class policy.
/// Kernel construction runs in the filesystem actor at PASSIVE_LEVEL. Component storage is
/// borrowed only during synchronous construction; the result owns its aligned self-relative image.
#[cfg(windows)]
#[derive(Debug)]
pub struct Descriptor {
    /// Complete initialized self-relative bytes.
    image: NativeImage,
}
#[cfg(windows)]
impl Descriptor {
    /// Encodes only selected components using one immutable identity table.
    /// # Errors
    /// Returns allocation or malformed representation failures.
    pub fn encode(
        access: &ext4_core::Ext4Access,
        map: &IdentityMap,
        selection: Components,
    ) -> Result<Self, Error> {
        Self::project(access, map, selection, 0)
    }
    /// Encodes an access-check image for a specific, generic-mapped request.
    /// A matching group must supply the complete requested rwx combination; rights from
    /// separate group entries cannot combine to satisfy a composite POSIX request.
    /// # Errors
    /// Returns descriptor length, allocation or identity encoding failure.
    pub fn for_request(
        access: &ext4_core::Ext4Access,
        map: &IdentityMap,
        requested: u32,
    ) -> Result<Self, Error> {
        let required = required_permissions(requested);
        Self::project(access, map, Components::ALL, required)
    }
    /// Resolves policy before building the selected components through Windows RTL.
    /// # Errors
    /// Returns identity, ACL budget, allocation or exact native construction failures.
    fn project(
        access: &ext4_core::Ext4Access,
        map: &IdentityMap,
        selection: Components,
        required: u16,
    ) -> Result<Self, Error> {
        let owner = map.user_sid(access.security().owner().uid())?;
        let group = map.group_sid(access.security().owner().gid())?;
        let acl = if selection.0 & 4 != 0 {
            let mut length = 8_usize;
            project_aces(access, map, required, |_, _, sid| {
                length = length
                    .checked_add(8)
                    .and_then(|v| v.checked_add(sid.bytes().len()))
                    .filter(|v| *v <= usize::from(u16::MAX))
                    .ok_or(Error::RecordTooLarge)?;
                Ok(())
            })?;
            let mut acl = NativeAcl::new(length)?;
            project_aces(access, map, required, |kind, mask, sid| {
                acl.push(kind, mask, sid)
            })?;
            Some(acl)
        } else {
            None
        };
        Ok(Self {
            image: NativeImage::build(owner, group, acl.as_ref(), selection)?,
        })
    }
    /// Complete immutable descriptor image.
    pub fn bytes(&self) -> &[u8] {
        self.image.bytes()
    }
    /// Interprets selected fields using the same owner/mode vocabulary as encoding.
    /// # Errors
    /// Rejects unsupported controls, identities, ACEs, order or permission bundles.
    pub fn decode(
        bytes: &[u8],
        map: &IdentityMap,
        selection: Components,
        current: &ext4_core::Ext4Access,
    ) -> Result<Ext4Security, Error> {
        if bytes.first() != Some(&1) || bytes.len() < 20 {
            return Err(Error::InvalidEncoding);
        }
        let control = u16_at(bytes, 2)?;
        if control & 0x8000 == 0 || control & !0x8004 != 0 || u32_at(bytes, 12)? != 0 {
            return Err(Error::UnrepresentableDescriptor);
        }
        let mut owner = current.security().owner();
        if selection.0 & 1 != 0 {
            owner = Ext4Owner::new(map.uid(sid_component(bytes, 4)?)?, owner.gid());
        }
        if selection.0 & 2 != 0 {
            owner = Ext4Owner::new(owner.uid(), map.gid(sid_component(bytes, 8)?)?);
        }
        let mut permissions = current.security().permissions().as_u16();
        if selection.0 & 4 != 0 {
            if control & 4 == 0 {
                return Err(Error::UnrepresentableDescriptor);
            }
            if current.acl().is_some() {
                let expected = Self::encode(current, map, Components::new(4)?)?;
                if acl_component(bytes)? != acl_component(expected.bytes())? {
                    return Err(Error::UnrepresentableDescriptor);
                }
                return Ok(Ext4Security::new(owner, current.security().permissions()));
            }
            let offset = usize::try_from(u32_at(bytes, 16)?).map_err(|_| Error::InvalidEncoding)?;
            if offset < 20 || offset % 4 != 0 {
                return Err(Error::InvalidEncoding);
            }
            let remaining = bytes.get(offset..).ok_or(Error::InvalidEncoding)?;
            let length = usize::from(u16_at(remaining, 2)?);
            let acl = remaining.get(..length).ok_or(Error::InvalidEncoding)?;
            if acl.first() != Some(&2) || acl.get(1) != Some(&0) || u16_at(acl, 6)? != 0 {
                return Err(Error::InvalidEncoding);
            }
            let count = u16_at(acl, 4)?;
            let mut cursor = AceCursor {
                bytes: acl,
                offset: 8,
                count: 0,
            };
            let owner_bits = cursor.class(map.user_sid(owner.uid())?)?;
            let group_bits = cursor.class(map.group_sid(owner.gid())?)?;
            let other = cursor.next()?;
            if other.kind != 0
                || other.sid != Sid::everyone()?
                || other.mask & BASE_RIGHTS != BASE_RIGHTS
            {
                return Err(Error::UnrepresentableDescriptor);
            }
            let other_bits = rights_mode(other.mask & !BASE_RIGHTS)?;
            if cursor.offset != acl.len() || cursor.count != count {
                return Err(Error::UnrepresentableDescriptor);
            }
            permissions =
                (permissions & !0o777) | (owner_bits << 6) | (group_bits << 3) | other_bits;
        }
        Ok(Ext4Security::new(
            owner,
            Ext4Permissions::new(permissions).map_err(|_| Error::InvalidEncoding)?,
        ))
    }
}
/// Reads one checked sixteen-bit field.
/// # Errors
/// Returns an error for an out-of-bounds encoding or allocation failure.
#[cfg(windows)]
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let end = offset.checked_add(2).ok_or(Error::InvalidEncoding)?;
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(Error::InvalidEncoding)?
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    ))
}
/// Parses a SID referenced by a selected descriptor field.
/// # Errors
/// Returns an error for an out-of-bounds encoding or allocation failure.
#[cfg(windows)]
fn sid_component(bytes: &[u8], field: usize) -> Result<Sid, Error> {
    let offset = usize::try_from(u32_at(bytes, field)?).map_err(|_| Error::InvalidEncoding)?;
    if offset < 20 || offset % 4 != 0 {
        return Err(Error::InvalidEncoding);
    }
    let sid = bytes.get(offset..).ok_or(Error::InvalidEncoding)?;
    let length = usize::from(*sid.get(1).ok_or(Error::InvalidEncoding)?)
        .checked_mul(4)
        .and_then(|v| v.checked_add(8))
        .ok_or(Error::InvalidEncoding)?;
    Sid::parse(sid.get(..length).ok_or(Error::InvalidEncoding)?)
}
/// Decoded plain ACE.
#[cfg(windows)]
struct Ace {
    /// Native allow/deny tag.
    kind: u8,
    /// Specific access mask.
    mask: u32,
    /// Validated principal.
    sid: Sid,
}
/// Sequential ACL parser; only the inode-class projection is representable.
#[cfg(windows)]
struct AceCursor<'a> {
    /// Exact ACL bytes.
    bytes: &'a [u8],
    /// Next ACE byte position.
    offset: usize,
    /// Successfully consumed ACEs.
    count: u16,
}
#[cfg(windows)]
impl AceCursor<'_> {
    /// Consumes one ACE after validating its full length and flags.
    /// # Errors
    /// Returns an error for an out-of-bounds encoding or allocation failure.
    fn next(&mut self) -> Result<Ace, Error> {
        let remaining = self
            .bytes
            .get(self.offset..)
            .ok_or(Error::InvalidEncoding)?;
        let length = usize::from(u16_at(remaining, 2)?);
        if length < 16 || remaining.get(1) != Some(&0) {
            return Err(Error::UnrepresentableDescriptor);
        }
        let bytes = remaining.get(..length).ok_or(Error::InvalidEncoding)?;
        let sid = Sid::parse(bytes.get(8..).ok_or(Error::InvalidEncoding)?)?;
        self.offset = self
            .offset
            .checked_add(length)
            .ok_or(Error::InvalidEncoding)?;
        self.count = self.count.checked_add(1).ok_or(Error::InvalidEncoding)?;
        Ok(Ace {
            kind: *bytes.first().ok_or(Error::InvalidEncoding)?,
            mask: u32_at(bytes, 4)?,
            sid,
        })
    }
    /// Validates exactly one class's optional deny and mandatory allow pair.
    /// # Errors
    /// Returns an error for an out-of-bounds encoding or allocation failure.
    fn class(&mut self, sid: Sid) -> Result<u16, Error> {
        let first = self.next()?;
        let (deny, allow) = if first.kind == 1 {
            (Some(first), self.next()?)
        } else {
            (None, first)
        };
        if allow.kind != 0 || allow.sid != sid {
            return Err(Error::UnrepresentableDescriptor);
        }
        let bits = rights_mode(allow.mask)?;
        let expected = CONTROLLED_RIGHTS & !allow.mask;
        match deny {
            Some(deny) if deny.sid == sid && deny.mask == expected && expected != 0 => {}
            None if expected == 0 => {}
            _ => return Err(Error::UnrepresentableDescriptor),
        }
        Ok(bits)
    }
}

/// Borrows a bounded native DACL for a representability comparison.
/// # Errors
/// Returns invalid descriptor offsets or truncated ACL storage.
#[cfg(windows)]
fn acl_component(bytes: &[u8]) -> Result<&[u8], Error> {
    let offset = usize::try_from(u32_at(bytes, 16)?).map_err(|_| Error::InvalidEncoding)?;
    if offset < 20 || !offset.is_multiple_of(4) {
        return Err(Error::InvalidEncoding);
    }
    let remaining = bytes.get(offset..).ok_or(Error::InvalidEncoding)?;
    remaining
        .get(..usize::from(u16_at(remaining, 2)?))
        .ok_or(Error::InvalidEncoding)
}

/// Rwx classes needed by a generic-mapped native specific-right request.
pub fn required_permissions(requested: u32) -> u16 {
    let read = if requested & crate::READ_RIGHTS != 0 {
        4
    } else {
        0
    };
    let write = if requested & crate::WRITE_RIGHTS != 0 {
        2
    } else {
        0
    };
    let execute = u16::from(requested & crate::EXECUTE_RIGHTS != 0);
    read | write | execute
}
/// Grants only when this one group entry supplies the whole requested combination.
#[cfg(any(windows, test))]
fn group_rights(permissions: u16, required: u16) -> u32 {
    if permissions & required == required {
        mode_rights(permissions)
    } else {
        0
    }
}

/// Explicit ACE order preserves POSIX owner/user precedence and whole-group admission.
/// Windows owns binary representation, never the choice or ordering of these grants.
/// # Errors
/// Returns identity conversion or sink failure before a descriptor is published.
#[cfg(any(windows, test))]
fn project_aces(
    access: &ext4_core::Ext4Access,
    map: &IdentityMap,
    required: u16,
    mut emit: impl FnMut(AceKind, u32, Sid) -> Result<(), Error>,
) -> Result<(), Error> {
    let security = access.security();
    let owner = map.user_sid(security.owner().uid())?;
    let group = map.group_sid(security.owner().gid())?;
    let permissions = security.permissions().as_u16();
    class(&mut emit, owner, (permissions >> 6) & 7)?;
    if let Some(policy) = access.acl() {
        let mask = policy.mask().map_or(7, ext4_core::AclPermissions::bits);
        for entry in policy.users() {
            class(
                &mut emit,
                map.user_sid(entry.uid())?,
                entry.permissions().bits() & mask,
            )?;
        }
        emit(
            AceKind::Allow,
            group_rights(policy.group().bits() & mask, required),
            group,
        )?;
        for entry in policy.groups() {
            emit(
                AceKind::Allow,
                group_rights(entry.permissions().bits() & mask, required),
                map.group_sid(entry.gid())?,
            )?;
        }
        emit(AceKind::Deny, CONTROLLED_RIGHTS, group)?;
        for entry in policy.groups() {
            emit(
                AceKind::Deny,
                CONTROLLED_RIGHTS,
                map.group_sid(entry.gid())?,
            )?;
        }
    } else {
        class(&mut emit, group, (permissions >> 3) & 7)?;
    }
    emit(
        AceKind::Allow,
        BASE_RIGHTS | mode_rights(permissions & 7),
        Sid::everyone()?,
    )
}

/// Policy decision consumed by the Windows ACE construction boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
enum AceKind {
    /// Grant the selected rights.
    Allow,
    /// Stop fallback for a more-specific matching principal.
    Deny,
}

/// Emits an exclusive class before less-specific principals.
/// # Errors
/// Returns the sink failure without emitting subsequent classes.
#[cfg(any(windows, test))]
fn class(
    emit: &mut impl FnMut(AceKind, u32, Sid) -> Result<(), Error>,
    sid: Sid,
    bits: u16,
) -> Result<(), Error> {
    let allow = mode_rights(bits);
    let deny = CONTROLLED_RIGHTS & !allow;
    if deny != 0 {
        emit(AceKind::Deny, deny, sid)?;
    }
    emit(AceKind::Allow, allow, sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns fixture construction failure.
    /// # Panics
    /// Fails if separate group entries combine partial rights for one composite request.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions verify projection after fallible fixture construction"
    )]
    fn composite_group_projection_requires_one_complete_match() -> Result<(), Error> {
        let acl = ext4_core::PosixAcl::parse(&[
            1, 0, 0, 0, 1, 0, 6, 0, 4, 0, 4, 0, 8, 0, 2, 0, 200, 0, 0, 0, 16, 0, 6, 0, 32, 0, 0, 0,
        ])
        .map_err(|_| Error::InvalidEncoding)?;
        let security = ext4_core::Ext4Security::new(
            ext4_core::Ext4Owner::new(
                ext4_core::Ext4Uid::from_u32(1000),
                ext4_core::Ext4Gid::from_u32(100),
            ),
            ext4_core::Ext4Permissions::new(0o660).map_err(|_| Error::InvalidEncoding)?,
        );
        let access =
            ext4_core::Ext4Access::new(security, Some(acl)).map_err(|_| Error::InvalidEncoding)?;
        let mut groups = 0;
        project_aces(&access, &IdentityMap::empty(), 6, |kind, rights, sid| {
            if sid.unix_identity(2).is_some() && kind == AceKind::Allow {
                assert_eq!(rights, 0);
                groups += 1;
            }
            Ok(())
        })?;
        assert_eq!(groups, 2);
        Ok(())
    }
}
