//! Validated SIDs and bounded per-filesystem identity records.
use crate::{Error, MAX_MAPPING_BYTES, reserve, u32_at};
use alloc::vec::Vec;
use ext4_core::{Ext4Gid, Ext4Owner, Ext4Uid, FilesystemUuid};

/// Complete binary SID; validity and length are established once during construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sid {
    /// SID storage, including the maximum fifteen subauthorities.
    bytes: [u8; 68],
    /// Initialized prefix length.
    length: u8,
}
impl Sid {
    /// Validates and copies a complete revision-one SID.
    /// # Errors
    /// Rejects truncation, extra bytes or too many subauthorities.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let count = *input.get(1).ok_or(Error::InvalidEncoding)?;
        let length = usize::from(count)
            .checked_mul(4)
            .and_then(|v| v.checked_add(8))
            .ok_or(Error::InvalidEncoding)?;
        if input.first() != Some(&1) || count > 15 || input.len() != length {
            return Err(Error::InvalidEncoding);
        }
        let mut bytes = [0; 68];
        for (target, source) in bytes.iter_mut().zip(input) {
            *target = *source;
        }
        Ok(Self {
            bytes,
            length: u8::try_from(length).map_err(|_| Error::InvalidEncoding)?,
        })
    }
    /// Borrows only initialized SID bytes.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.length)).unwrap_or(&[])
    }
    /// Returns the Unix identity represented by an unmapped UID/GID SID.
    pub fn unix_identity(&self, domain: u32) -> Option<u32> {
        if self.bytes().get(..8) != Some(&[1, 2, 0, 0, 0, 0, 0, 22])
            || u32_at(self.bytes(), 8).ok()? != domain
        {
            return None;
        }
        u32_at(self.bytes(), 12).ok()
    }
    /// Constructs an unmapped UID or GID presentation SID.
    /// # Errors
    /// Rejects a domain other than user or group.
    pub fn unix(domain: u32, id: u32) -> Result<Self, Error> {
        if domain != 1 && domain != 2 {
            return Err(Error::InvalidEncoding);
        }
        let mut value = [1, 2, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0];
        for (target, source) in value
            .iter_mut()
            .skip(8)
            .zip(domain.to_le_bytes().iter().chain(id.to_le_bytes().iter()))
        {
            *target = *source;
        }
        Self::parse(&value)
    }
    /// Returns the world principal.
    /// # Errors
    /// Returns an error only if the fixed SID definition is invalid.
    pub fn everyone() -> Result<Self, Error> {
        Self::parse(&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0])
    }
}
impl core::fmt::Display for Sid {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let authority = self
            .bytes()
            .iter()
            .skip(2)
            .take(6)
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
        write!(formatter, "S-1-{authority}")?;
        for chunk in self
            .bytes()
            .get(8..)
            .ok_or(core::fmt::Error)?
            .as_chunks::<4>()
            .0
        {
            let value = u32::from_le_bytes(*chunk);
            write!(formatter, "-{value}")?;
        }
        Ok(())
    }
}
impl core::str::FromStr for Sid {
    type Err = Error;
    fn from_str(text: &str) -> Result<Self, Error> {
        let mut parts = text.split('-');
        if parts.next() != Some("S") || parts.next() != Some("1") {
            return Err(Error::InvalidEncoding);
        }
        let authority = parts
            .next()
            .ok_or(Error::InvalidEncoding)?
            .parse::<u64>()
            .map_err(|_| Error::InvalidEncoding)?;
        if authority > 0x0000_ffff_ffff_ffff {
            return Err(Error::InvalidEncoding);
        }
        let mut bytes = [0_u8; 68];
        let header = bytes.get_mut(..8).ok_or(Error::InvalidEncoding)?;
        for (target, source) in header
            .iter_mut()
            .skip(2)
            .zip(authority.to_be_bytes().iter().skip(2))
        {
            *target = *source;
        }
        let mut count = 0_u8;
        for (index, part) in parts.enumerate() {
            if index >= 15 {
                return Err(Error::InvalidEncoding);
            }
            let value = part.parse::<u32>().map_err(|_| Error::InvalidEncoding)?;
            let offset = index
                .checked_mul(4)
                .and_then(|v| v.checked_add(8))
                .ok_or(Error::InvalidEncoding)?;
            let end = offset.checked_add(4).ok_or(Error::InvalidEncoding)?;
            for (target, source) in bytes
                .get_mut(offset..end)
                .ok_or(Error::InvalidEncoding)?
                .iter_mut()
                .zip(value.to_le_bytes())
            {
                *target = source;
            }
            count = count.checked_add(1).ok_or(Error::InvalidEncoding)?;
        }
        *bytes.first_mut().ok_or(Error::InvalidEncoding)? = 1;
        *bytes.get_mut(1).ok_or(Error::InvalidEncoding)? = count;
        let length = usize::from(count)
            .checked_mul(4)
            .and_then(|v| v.checked_add(8))
            .ok_or(Error::InvalidEncoding)?;
        Self::parse(bytes.get(..length).ok_or(Error::InvalidEncoding)?)
    }
}

/// Canonical lowercase RFC-style UUID spelling without native GUID byte-order conversion.
/// # Panics
/// The fixed alphabet is indexed only by masked four-bit values.
#[expect(
    clippy::indexing_slicing,
    reason = "both nibble expressions are confined to 0..16, exactly the fixed hexadecimal alphabet"
)]
pub fn uuid_text(uuid: FilesystemUuid) -> [u8; 36] {
    let mut output = [b'-'; 36];
    let digits = b"0123456789abcdef";
    let source = uuid
        .bytes()
        .into_iter()
        .flat_map(|byte| [byte >> 4, byte & 15]);
    for ((_, target), nibble) in output
        .iter_mut()
        .enumerate()
        .filter(|(index, _)| ![8, 13, 18, 23].contains(index))
        .zip(source)
    {
        *target = digits[usize::from(nibble)];
    }
    output
}
/// Interprets the ext4 UUID's bytes directly, independently of Windows GUID fields.
/// # Errors
/// Rejects non-canonical shape, invalid digits and missing bytes.
pub fn parse_uuid(text: &str) -> Result<FilesystemUuid, Error> {
    if text.len() != 36 {
        return Err(Error::InvalidEncoding);
    }
    let mut bytes = [0_u8; 16];
    let mut digits = [0_u8; 32];
    let mut target = digits.iter_mut();
    for (index, byte) in text.bytes().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            if byte != b'-' {
                return Err(Error::InvalidEncoding);
            }
        } else {
            let value = match byte {
                b'0'..=b'9' => byte.checked_sub(b'0'),
                b'a'..=b'f' => byte.checked_sub(b'a').and_then(|v| v.checked_add(10)),
                b'A'..=b'F' => byte.checked_sub(b'A').and_then(|v| v.checked_add(10)),
                _ => None,
            }
            .ok_or(Error::InvalidEncoding)?;
            *target.next().ok_or(Error::InvalidEncoding)? = value;
        }
    }
    for (target, pair) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
        *target = (pair.first().copied().ok_or(Error::InvalidEncoding)? << 4)
            | pair.get(1).copied().ok_or(Error::InvalidEncoding)?;
    }
    Ok(FilesystemUuid::from_bytes(bytes))
}

/// One Windows user bound to a filesystem user identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserMapping {
    /// Validated Windows principal.
    pub sid: Sid,
    /// Filesystem user identity.
    pub uid: Ext4Uid,
}
/// One Windows group bound to a filesystem group identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupMapping {
    /// Validated Windows principal.
    pub sid: Sid,
    /// Filesystem group identity.
    pub gid: Ext4Gid,
}
/// Immutable bidirectional identity table with one authority per identity domain.
#[derive(Debug, Eq, PartialEq)]
pub struct IdentityMap {
    /// Unique user identities.
    users: Vec<UserMapping>,
    /// Unique group identities.
    groups: Vec<GroupMapping>,
}
impl IdentityMap {
    /// Creates the table used when no mapping is configured.
    pub const fn empty() -> Self {
        Self {
            users: Vec::new(),
            groups: Vec::new(),
        }
    }
    /// Establishes uniqueness before publication.
    /// # Errors
    /// Rejects duplicate SIDs/numeric IDs or a record beyond the byte budget.
    pub fn new(users: Vec<UserMapping>, groups: Vec<GroupMapping>) -> Result<Self, Error> {
        for (index, entry) in users.iter().enumerate() {
            if users
                .iter()
                .take(index)
                .any(|old| old.sid == entry.sid || old.uid == entry.uid)
            {
                return Err(Error::DuplicateIdentity);
            }
        }
        for (index, entry) in groups.iter().enumerate() {
            if groups
                .iter()
                .take(index)
                .any(|old| old.sid == entry.sid || old.gid == entry.gid)
            {
                return Err(Error::DuplicateIdentity);
            }
        }
        let map = Self { users, groups };
        if map.encoded_length()? > MAX_MAPPING_BYTES {
            return Err(Error::RecordTooLarge);
        }
        Ok(map)
    }
    /// Configured user bindings.
    pub fn users(&self) -> &[UserMapping] {
        &self.users
    }
    /// Configured group bindings.
    pub fn groups(&self) -> &[GroupMapping] {
        &self.groups
    }
    /// Projects an inode UID onto a Windows principal, retaining unmapped identity.
    /// # Errors
    /// Propagates invalid fallback SID construction.
    pub fn user_sid(&self, uid: Ext4Uid) -> Result<Sid, Error> {
        match self.users.iter().find(|entry| entry.uid == uid) {
            Some(entry) => Ok(entry.sid),
            None => Sid::unix(1, uid.as_u32()),
        }
    }
    /// Projects an inode GID onto a Windows principal, retaining unmapped identity.
    /// # Errors
    /// Propagates invalid fallback SID construction.
    pub fn group_sid(&self, gid: Ext4Gid) -> Result<Sid, Error> {
        match self.groups.iter().find(|entry| entry.gid == gid) {
            Some(entry) => Ok(entry.sid),
            None => Sid::unix(2, gid.as_u32()),
        }
    }
    /// Interprets an owner SID, including the presentation of an unmapped inode UID.
    /// # Errors
    /// Rejects principals that are not configured or Unix UID SIDs.
    pub fn uid(&self, sid: Sid) -> Result<Ext4Uid, Error> {
        self.users
            .iter()
            .find(|entry| entry.sid == sid)
            .map(|entry| entry.uid)
            .or_else(|| sid.unix_identity(1).map(Ext4Uid::from_u32))
            .ok_or(Error::UnmappedIdentity)
    }
    /// Interprets a group SID, including unmapped inode GID presentation.
    /// # Errors
    /// Rejects principals that are not configured or Unix GID SIDs.
    pub fn gid(&self, sid: Sid) -> Result<Ext4Gid, Error> {
        self.groups
            .iter()
            .find(|entry| entry.sid == sid)
            .map(|entry| entry.gid)
            .or_else(|| sid.unix_identity(2).map(Ext4Gid::from_u32))
            .ok_or(Error::UnmappedIdentity)
    }
    /// Captures creation identity only from explicitly configured effective token principals.
    /// # Errors
    /// Rejects either unmapped token principal; presentation SIDs are not implicit mappings.
    pub fn creator(&self, user: Sid, primary_group: Sid) -> Result<Ext4Owner, Error> {
        let uid = self
            .users
            .iter()
            .find(|entry| entry.sid == user)
            .ok_or(Error::UnmappedIdentity)?
            .uid;
        let gid = self
            .groups
            .iter()
            .find(|entry| entry.sid == primary_group)
            .ok_or(Error::UnmappedIdentity)?
            .gid;
        Ok(Ext4Owner::new(uid, gid))
    }
    /// Complete record byte charge, including header and SID prefixes.
    /// # Errors
    /// Rejects arithmetic overflow.
    fn encoded_length(&self) -> Result<usize, Error> {
        self.users
            .iter()
            .map(|e| e.sid.bytes().len())
            .chain(self.groups.iter().map(|e| e.sid.bytes().len()))
            .try_fold(40_usize, |length, sid| {
                length
                    .checked_add(8)
                    .and_then(|v| v.checked_add(sid))
                    .ok_or(Error::RecordTooLarge)
            })
    }
}

/// One persisted table and its filesystem/publication identity.
#[derive(Debug, Eq, PartialEq)]
pub struct MappingSnapshot {
    /// Filesystem identity, never a Windows volume GUID.
    pub uuid: FilesystemUuid,
    /// Monotonic publication generation.
    pub generation: u64,
    /// Validated immutable table.
    pub map: IdentityMap,
}
impl MappingSnapshot {
    /// Encodes the complete bounded value used for persistence and table replacement.
    /// # Errors
    /// Returns size, arithmetic or allocation failures before any external effect.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let length = self.map.encoded_length()?;
        if length > MAX_MAPPING_BYTES {
            return Err(Error::RecordTooLarge);
        }
        let mut bytes = Vec::new();
        reserve(&mut bytes, length)?;
        bytes.extend_from_slice(b"E4IM\x01\0\0\0");
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(&self.uuid.bytes());
        for count in [self.map.users.len(), self.map.groups.len()] {
            bytes.extend_from_slice(
                &u32::try_from(count)
                    .map_err(|_| Error::RecordTooLarge)?
                    .to_le_bytes(),
            );
        }
        for (id, sid) in self
            .map
            .users
            .iter()
            .map(|e| (e.uid.as_u32(), e.sid))
            .chain(self.map.groups.iter().map(|e| (e.gid.as_u32(), e.sid)))
        {
            bytes.extend_from_slice(&id.to_le_bytes());
            bytes.extend_from_slice(&u32::from(sid.length).to_le_bytes());
            bytes.extend_from_slice(sid.bytes());
        }
        Ok(bytes)
    }
    /// Validates one complete persistent/control record before establishing table authority.
    /// # Errors
    /// Rejects malformed/trailing bytes, oversized records, duplicates and allocation failure.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MAPPING_BYTES {
            return Err(Error::RecordTooLarge);
        }
        if bytes.get(..8) != Some(b"E4IM\x01\0\0\0") {
            return Err(Error::InvalidEncoding);
        }
        let generation = u64::from_le_bytes(
            bytes
                .get(8..16)
                .ok_or(Error::InvalidEncoding)?
                .try_into()
                .map_err(|_| Error::InvalidEncoding)?,
        );
        let uuid = FilesystemUuid::from_bytes(
            bytes
                .get(16..32)
                .ok_or(Error::InvalidEncoding)?
                .try_into()
                .map_err(|_| Error::InvalidEncoding)?,
        );
        let users_count =
            usize::try_from(u32_at(bytes, 32)?).map_err(|_| Error::InvalidEncoding)?;
        let groups_count =
            usize::try_from(u32_at(bytes, 36)?).map_err(|_| Error::InvalidEncoding)?;
        let total = users_count
            .checked_add(groups_count)
            .ok_or(Error::InvalidEncoding)?;
        if total > bytes.len().checked_sub(40).ok_or(Error::InvalidEncoding)? / 16 {
            return Err(Error::InvalidEncoding);
        }
        let mut users = Vec::new();
        let mut groups = Vec::new();
        reserve(&mut users, users_count)?;
        reserve(&mut groups, groups_count)?;
        let mut offset = 40_usize;
        for index in 0..total {
            let id = u32_at(bytes, offset)?;
            offset = offset.checked_add(4).ok_or(Error::InvalidEncoding)?;
            let length =
                usize::try_from(u32_at(bytes, offset)?).map_err(|_| Error::InvalidEncoding)?;
            offset = offset.checked_add(4).ok_or(Error::InvalidEncoding)?;
            let end = offset.checked_add(length).ok_or(Error::InvalidEncoding)?;
            let sid = Sid::parse(bytes.get(offset..end).ok_or(Error::InvalidEncoding)?)?;
            offset = end;
            if index < users_count {
                users.push(UserMapping {
                    uid: Ext4Uid::from_u32(id),
                    sid,
                });
            } else {
                groups.push(GroupMapping {
                    gid: Ext4Gid::from_u32(id),
                    sid,
                });
            }
        }
        if offset != bytes.len() {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self {
            uuid,
            generation,
            map: IdentityMap::new(users, groups)?,
        })
    }
}
