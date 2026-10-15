//! Self-relative inode-security descriptors with exclusive POSIX-class selection.
use crate::{
    BASE_RIGHTS, CONTROLLED_RIGHTS, Error, IdentityMap, Sid, append_reserved, mode_rights, reserve,
    rights_mode, u32_at,
};
use alloc::vec::Vec;
use ext4_core::{Ext4Owner, Ext4Permissions, Ext4Security};

/// Native ACL's sixteen-bit length plus descriptor header and two maximum-length SIDs.
pub const MAX_DESCRIPTOR_BYTES: usize = 65_691;
/// Initial storage sufficient for the complete three-class projection.
const MODE_DESCRIPTOR_BYTES: usize = 488;
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
/// Owned complete byte image; encoding establishes layout before native interpretation.
#[derive(Debug)]
pub struct Descriptor {
    /// Complete initialized self-relative bytes.
    bytes: Vec<u8>,
}
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
    /// Builds the query projection or one request-specific group projection.
    /// # Errors
    /// Returns descriptor length, allocation or identity encoding failure.
    fn project(
        access: &ext4_core::Ext4Access,
        map: &IdentityMap,
        selection: Components,
        required: u16,
    ) -> Result<Self, Error> {
        let security = access.security();
        let mut bytes = Vec::new();
        reserve(&mut bytes, MODE_DESCRIPTOR_BYTES)?;
        append_reserved(&mut bytes, &[0; 20])?;
        put(&mut bytes, 0, &[1])?;
        let mut control = 0x8000_u16;
        let owner = map.user_sid(security.owner().uid())?;
        let group = map.group_sid(security.owner().gid())?;
        if selection.0 & 1 != 0 {
            component(&mut bytes, 4, owner.bytes())?;
        }
        if selection.0 & 2 != 0 {
            component(&mut bytes, 8, group.bytes())?;
        }
        if selection.0 & 4 != 0 {
            control |= 4;
            let mut acl = Vec::new();
            reserve(&mut acl, MODE_DESCRIPTOR_BYTES)?;
            append_reserved(&mut acl, &[0; 8])?;
            let permissions = security.permissions().as_u16();
            let mut count = 0_u16;
            class(&mut acl, &mut count, owner, (permissions >> 6) & 7)?;
            if let Some(policy) = access.acl() {
                let mask = policy.mask().map_or(7, ext4_core::AclPermissions::bits);
                for entry in policy.users() {
                    class(
                        &mut acl,
                        &mut count,
                        map.user_sid(entry.uid())?,
                        entry.permissions().bits() & mask,
                    )?;
                }
                counted_ace(
                    &mut acl,
                    &mut count,
                    0,
                    group_rights(policy.group().bits() & mask, required),
                    group,
                )?;
                for entry in policy.groups() {
                    counted_ace(
                        &mut acl,
                        &mut count,
                        0,
                        group_rights(entry.permissions().bits() & mask, required),
                        map.group_sid(entry.gid())?,
                    )?;
                }
                // Eligible groups grant before matched-group denials prevent fallback.
                // These denials prevent a matched group from falling through to the other class.
                counted_ace(&mut acl, &mut count, 1, CONTROLLED_RIGHTS, group)?;
                for entry in policy.groups() {
                    counted_ace(
                        &mut acl,
                        &mut count,
                        1,
                        CONTROLLED_RIGHTS,
                        map.group_sid(entry.gid())?,
                    )?;
                }
            } else {
                class(&mut acl, &mut count, group, (permissions >> 3) & 7)?;
            }
            counted_ace(
                &mut acl,
                &mut count,
                0,
                BASE_RIGHTS | mode_rights(permissions & 7),
                Sid::everyone()?,
            )?;
            let length = u16::try_from(acl.len()).map_err(|_| Error::InvalidEncoding)?;
            put(&mut acl, 0, &[2])?;
            put(&mut acl, 2, &length.to_le_bytes())?;
            put(&mut acl, 4, &count.to_le_bytes())?;
            component(&mut bytes, 16, &acl)?;
        }
        put(&mut bytes, 2, &control.to_le_bytes())?;
        Ok(Self { bytes })
    }
    /// Complete immutable descriptor image.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
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
/// Writes one already bounded component.
/// # Errors
/// Returns an error for an out-of-bounds encoding or allocation failure.
fn put(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), Error> {
    let end = offset
        .checked_add(value.len())
        .ok_or(Error::InvalidEncoding)?;
    let target = bytes.get_mut(offset..end).ok_or(Error::InvalidEncoding)?;
    for (target, source) in target.iter_mut().zip(value) {
        *target = *source;
    }
    Ok(())
}
/// Appends a relative component, recording its checked byte offset.
/// # Errors
/// Returns an invalid field offset or prepared-buffer exhaustion.
fn component(bytes: &mut Vec<u8>, field: usize, value: &[u8]) -> Result<(), Error> {
    let offset = u32::try_from(bytes.len()).map_err(|_| Error::InvalidEncoding)?;
    put(bytes, field, &offset.to_le_bytes())?;
    reserve(bytes, value.len())?;
    append_reserved(bytes, value)?;
    Ok(())
}
/// Appends one plain explicit ACE with a validated SID.
/// # Errors
/// Returns encoded-length overflow or prepared-buffer exhaustion.
fn ace(bytes: &mut Vec<u8>, kind: u8, mask: u32, sid: Sid) -> Result<(), Error> {
    let length = sid
        .bytes()
        .len()
        .checked_add(8)
        .ok_or(Error::InvalidEncoding)?;
    if bytes
        .len()
        .checked_add(length)
        .ok_or(Error::RecordTooLarge)?
        > usize::from(u16::MAX)
    {
        return Err(Error::RecordTooLarge);
    }
    reserve(bytes, length)?;
    append_reserved(bytes, &[kind, 0])?;
    append_reserved(
        bytes,
        &u16::try_from(length)
            .map_err(|_| Error::InvalidEncoding)?
            .to_le_bytes(),
    )?;
    append_reserved(bytes, &mask.to_le_bytes())?;
    append_reserved(bytes, sid.bytes())?;
    Ok(())
}
/// Reads one checked sixteen-bit field.
/// # Errors
/// Returns an error for an out-of-bounds encoding or allocation failure.
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
struct Ace {
    /// Native allow/deny tag.
    kind: u8,
    /// Specific access mask.
    mask: u32,
    /// Validated principal.
    sid: Sid,
}
/// Sequential ACL parser; only the inode-class projection is representable.
struct AceCursor<'a> {
    /// Exact ACL bytes.
    bytes: &'a [u8],
    /// Next ACE byte position.
    offset: usize,
    /// Successfully consumed ACEs.
    count: u16,
}
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

/// Emits one exclusive user or inode class before less-specific principals.
/// # Errors
/// Returns SID encoding, ACL budget or allocation failures.
fn class(bytes: &mut Vec<u8>, count: &mut u16, sid: Sid, bits: u16) -> Result<(), Error> {
    let allow = mode_rights(bits);
    let deny = CONTROLLED_RIGHTS & !allow;
    if deny != 0 {
        counted_ace(bytes, count, 1, deny, sid)?;
    }
    counted_ace(bytes, count, 0, allow, sid)
}

/// Tracks the native entry count together with successfully encoded ACEs.
/// # Errors
/// Returns encoded ACL length, count or allocation failures.
fn counted_ace(
    bytes: &mut Vec<u8>,
    count: &mut u16,
    kind: u8,
    mask: u32,
    sid: Sid,
) -> Result<(), Error> {
    ace(bytes, kind, mask, sid)?;
    *count = count.checked_add(1).ok_or(Error::RecordTooLarge)?;
    Ok(())
}

/// Borrows a bounded native DACL for a representability comparison.
/// # Errors
/// Returns invalid descriptor offsets or truncated ACL storage.
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
fn group_rights(permissions: u16, required: u16) -> u32 {
    if permissions & required == required {
        mode_rights(permissions)
    } else {
        0
    }
}
