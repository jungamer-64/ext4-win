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
