//! Extended-attribute domain and ext4 xattr block encoding.

use alloc::{vec, vec::Vec};
use core::cmp::Ordering;

use crate::block::BlockAddress;
use crate::checksum::crc32c;
use crate::endian::{DiskOffset, le_u16, le_u32, put_le_u16, put_le_u32};
use crate::error::{Error, Result};
use crate::superblock::{MetadataChecksum, Superblock};

/// ext4 xattr header magic.
const EXT4_XATTR_MAGIC: u32 = 0xEA02_0000;
/// Bytes occupied by an external xattr block header.
const EXT4_XATTR_BLOCK_HEADER_BYTES: usize = 32;
/// Bytes occupied by an in-inode xattr body header.
const EXT4_XATTR_INODE_HEADER_BYTES: usize = 4;
/// Bytes occupied by one serialized xattr entry before the name bytes.
const EXT4_XATTR_ENTRY_BYTES: usize = 16;
/// Bytes required for the zero terminator checked by ext4 entry iteration.
const EXT4_XATTR_TERMINATOR_BYTES: usize = 4;
/// Serialized index for `user.*`.
const EXT4_XATTR_INDEX_USER: u8 = 1;
/// Serialized index for `system.posix_acl_access`.
const EXT4_XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;
/// Serialized index for `system.posix_acl_default`.
const EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;
/// Serialized index for `trusted.*`.
const EXT4_XATTR_INDEX_TRUSTED: u8 = 4;
/// Serialized index for `security.*`.
const EXT4_XATTR_INDEX_SECURITY: u8 = 6;
/// Serialized index for generic `system.*`.
const EXT4_XATTR_INDEX_SYSTEM: u8 = 7;
/// Serialized index for ext4's private fscrypt context xattr.
const EXT4_XATTR_INDEX_ENCRYPTION: u8 = 9;

/// Builds an xattr structure field offset.
const fn disk_offset(offset: usize) -> DiskOffset {
    DiskOffset::new(offset)
}
/// Local name exposed for access ACLs at the public xattr boundary.
const POSIX_ACL_ACCESS_NAME: &[u8] = b"posix_acl_access";
/// Local name exposed for default ACLs at the public xattr boundary.
const POSIX_ACL_DEFAULT_NAME: &[u8] = b"posix_acl_default";
/// On-disk local name for ext4's private fscrypt context xattr.
const ENCRYPTION_CONTEXT_NAME: &[u8] = b"c";

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

    /// Returns true when this set has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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

    /// Consumes the set into owned entries.
    pub(crate) fn into_entries(self) -> Vec<(XattrName, XattrValue)> {
        self.entries
            .into_iter()
            .map(|entry| (entry.name, entry.value))
            .collect()
    }
}

/// Complete ext4 xattr set for one inode, including private filesystem slots.
///
/// Public xattr APIs expose only `public`; filesystem-private slots are kept in
/// the same set so public xattr mutation cannot silently discard them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InodeXattrSet {
    /// User-visible xattrs.
    public: XattrSet,
    /// ext4 private fscrypt context stored at index 9, name "c".
    encryption_context: Option<XattrValue>,
}

impl InodeXattrSet {
    /// Creates an empty inode xattr set.
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self {
            public: XattrSet::empty(),
            encryption_context: None,
        }
    }

    /// Creates a complete inode xattr set from separated domains.
    #[must_use]
    pub(crate) const fn from_parts(
        public: XattrSet,
        encryption_context: Option<XattrValue>,
    ) -> Self {
        Self {
            public,
            encryption_context,
        }
    }

    /// Public xattrs attached to the inode.
    #[must_use]
    pub(crate) const fn public(&self) -> &XattrSet {
        &self.public
    }

    /// Mutable public xattrs attached to the inode.
    pub(crate) const fn public_mut(&mut self) -> &mut XattrSet {
        &mut self.public
    }

    /// Raw fscrypt context xattr value, when the inode is encrypted.
    #[must_use]
    pub(crate) fn encryption_context(&self) -> Option<&XattrValue> {
        self.encryption_context.as_ref()
    }

    /// Replaces the private fscrypt context stored on this inode.
    pub(crate) fn set_encryption_context(&mut self, context: XattrValue) {
        self.encryption_context = Some(context);
    }

    /// Returns true when no public or private xattrs are present.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.public.is_empty() && self.encryption_context.is_none()
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

/// Parses in-inode xattrs from the inode body region after `i_extra_isize`.
pub(crate) fn parse_inline_xattrs(region: &[u8]) -> Result<InodeXattrSet> {
    if region.len() < EXT4_XATTR_INODE_HEADER_BYTES || region.iter().all(|byte| *byte == 0) {
        return Ok(InodeXattrSet::empty());
    }
    if le_u32(region, disk_offset(0))? != EXT4_XATTR_MAGIC {
        return Err(Error::InvalidXattr);
    }
    parse_xattr_entries(
        region,
        EXT4_XATTR_INODE_HEADER_BYTES,
        EXT4_XATTR_INODE_HEADER_BYTES,
        XattrValuePlacement::InInode,
    )
}

/// Serializes a complete xattr set into an in-inode xattr region.
pub(crate) fn serialize_inline_xattrs(set: &InodeXattrSet, capacity: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0_u8; capacity];
    if set.is_empty() {
        return Ok(bytes);
    }
    if capacity < EXT4_XATTR_INODE_HEADER_BYTES {
        return Err(Error::NoSpace);
    }
    put_le_u32(&mut bytes, disk_offset(0), EXT4_XATTR_MAGIC)?;
    serialize_xattr_entries(
        set,
        &mut bytes,
        EXT4_XATTR_INODE_HEADER_BYTES,
        EXT4_XATTR_INODE_HEADER_BYTES,
        XattrValuePlacement::InInode,
    )?;
    Ok(bytes)
}

/// Parses an external xattr block and verifies its checksum when metadata
/// checksums are active.
pub(crate) fn parse_external_xattr_block(
    bytes: &[u8],
    block: BlockAddress,
    superblock: &Superblock,
) -> Result<InodeXattrSet> {
    validate_external_xattr_block(bytes, block, superblock)?;
    parse_xattr_entries(
        bytes,
        EXT4_XATTR_BLOCK_HEADER_BYTES,
        0,
        XattrValuePlacement::ExternalBlock,
    )
}

/// Serializes a complete xattr set into one external xattr block.
pub(crate) fn serialize_external_xattr_block(
    set: &InodeXattrSet,
    block_size: usize,
    block: BlockAddress,
    superblock: &Superblock,
) -> Result<Vec<u8>> {
    if set.is_empty() {
        return Err(Error::InvalidXattr);
    }
    let mut bytes = vec![0_u8; block_size];
    put_le_u32(&mut bytes, disk_offset(0), EXT4_XATTR_MAGIC)?;
    put_le_u32(&mut bytes, disk_offset(4), 1)?;
    put_le_u32(&mut bytes, disk_offset(8), 1)?;
    serialize_xattr_entries(
        set,
        &mut bytes,
        EXT4_XATTR_BLOCK_HEADER_BYTES,
        0,
        XattrValuePlacement::ExternalBlock,
    )?;
    refresh_external_xattr_checksum(&mut bytes, block, superblock)?;
    Ok(bytes)
}

/// Verifies that a set fits in one external xattr block.
pub(crate) fn ensure_external_xattrs_fit(set: &InodeXattrSet, block_size: usize) -> Result<()> {
    let mut bytes = vec![0_u8; block_size];
    serialize_xattr_entries(
        set,
        &mut bytes,
        EXT4_XATTR_BLOCK_HEADER_BYTES,
        0,
        XattrValuePlacement::ExternalBlock,
    )
}

/// Reads the external xattr block reference count.
pub(crate) fn external_xattr_refcount(bytes: &[u8]) -> Result<u32> {
    if le_u32(bytes, disk_offset(0))? != EXT4_XATTR_MAGIC {
        return Err(Error::InvalidXattr);
    }
    let refcount = le_u32(bytes, disk_offset(4))?;
    if refcount == 0 {
        return Err(Error::InvalidXattr);
    }
    Ok(refcount)
}

/// Rewrites the external xattr block reference count and checksum.
pub(crate) fn set_external_xattr_refcount(
    bytes: &mut [u8],
    block: BlockAddress,
    superblock: &Superblock,
    refcount: u32,
) -> Result<()> {
    if refcount == 0 {
        return Err(Error::InvalidXattr);
    }
    if le_u32(bytes, disk_offset(0))? != EXT4_XATTR_MAGIC {
        return Err(Error::InvalidXattr);
    }
    put_le_u32(bytes, disk_offset(4), refcount)?;
    refresh_external_xattr_checksum(bytes, block, superblock)
}

/// Merges inline and external xattr sets while rejecting duplicate logical and
/// private slots.
pub(crate) fn merge_xattr_sets(left: InodeXattrSet, right: InodeXattrSet) -> Result<InodeXattrSet> {
    let mut entries = left.public.into_entries();
    entries.extend(right.public.into_entries());
    let public = XattrSet::from_entries(entries)?;
    let encryption_context = match (left.encryption_context, right.encryption_context) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(_), Some(_)) => return Err(Error::InvalidXattr),
    };
    Ok(InodeXattrSet::from_parts(public, encryption_context))
}

/// Placement rules for serialized xattr values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XattrValuePlacement {
    /// Value offsets are relative to the first in-inode entry.
    InInode,
    /// Value offsets are absolute within the external block.
    ExternalBlock,
}

/// Parsed entry before the value region has been proven non-overlapping.
#[derive(Debug)]
struct ParsedDiskXattr {
    /// Logical xattr slot selected by the on-disk key.
    slot: ParsedDiskXattrSlot,
    /// Value offset as encoded on disk.
    value_offset: usize,
    /// Value byte length.
    value_size: usize,
}

/// Parsed xattr slot before values have been copied into owned sets.
#[derive(Debug)]
enum ParsedDiskXattrSlot {
    /// User-visible xattr.
    Public(XattrName),
    /// ext4 private fscrypt context.
    EncryptionContext,
}

/// Serialized entry paired with its disk-order key.
#[derive(Debug)]
struct SerializedDiskXattr {
    /// Sort key encoded in the ext4 entry.
    key: DiskXattrKey,
    /// Value bytes.
    value: XattrValue,
}

/// ext4 entry sort key.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DiskXattrKey {
    /// On-disk xattr namespace index.
    index: u8,
    /// On-disk local name bytes.
    local: Vec<u8>,
}

impl DiskXattrKey {
    /// Returns the ext4 disk order for xattr entries.
    fn cmp_disk(&self, other: &Self) -> Ordering {
        self.index
            .cmp(&other.index)
            .then_with(|| self.local.len().cmp(&other.local.len()))
            .then_with(|| self.local.cmp(&other.local))
    }
}

/// Parses xattr entries from a complete in-inode region or external block.
fn parse_xattr_entries(
    storage: &[u8],
    entry_offset: usize,
    value_base: usize,
    placement: XattrValuePlacement,
) -> Result<InodeXattrSet> {
    let mut cursor = entry_offset;
    let mut parsed = Vec::new();
    let mut previous_key: Option<DiskXattrKey> = None;
    let entries_end;

    loop {
        if cursor
            .checked_add(EXT4_XATTR_TERMINATOR_BYTES)
            .ok_or(Error::ArithmeticOverflow)?
            > storage.len()
        {
            return Err(Error::InvalidXattr);
        }
        if le_u32(storage, disk_offset(cursor))? == 0 {
            entries_end = align_up(
                cursor
                    .checked_add(EXT4_XATTR_TERMINATOR_BYTES)
                    .ok_or(Error::ArithmeticOverflow)?,
            )?;
            break;
        }

        let header_end = cursor
            .checked_add(EXT4_XATTR_ENTRY_BYTES)
            .ok_or(Error::ArithmeticOverflow)?;
        if header_end > storage.len() {
            return Err(Error::InvalidXattr);
        }
        let name_len = usize::from(*storage.get(cursor).ok_or(Error::InvalidXattr)?);
        let index = *storage
            .get(cursor.checked_add(1).ok_or(Error::ArithmeticOverflow)?)
            .ok_or(Error::InvalidXattr)?;
        let value_offset = usize::from(le_u16(storage, disk_offset(cursor).checked_add_bytes(2)?)?);
        let value_inum = le_u32(storage, disk_offset(cursor).checked_add_bytes(4)?)?;
        let value_size =
            usize::try_from(le_u32(storage, disk_offset(cursor).checked_add_bytes(8)?)?)
                .map_err(|_| Error::ArithmeticOverflow)?;
        let entry_hash = le_u32(storage, disk_offset(cursor).checked_add_bytes(12)?)?;
        if value_inum != 0 || (placement == XattrValuePlacement::InInode && entry_hash != 0) {
            return Err(Error::InvalidXattr);
        }

        let name_start = header_end;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(Error::ArithmeticOverflow)?;
        let local = storage
            .get(name_start..name_end)
            .ok_or(Error::InvalidXattr)?;
        let key = DiskXattrKey {
            index,
            local: local.to_vec(),
        };
        if let Some(previous) = &previous_key
            && previous.cmp_disk(&key) != Ordering::Less
        {
            return Err(Error::InvalidXattr);
        }
        previous_key = Some(key);

        parsed.push(ParsedDiskXattr {
            slot: logical_slot(index, local)?,
            value_offset,
            value_size,
        });
        cursor = align_up(name_end)?;
    }

    let mut public_entries = Vec::new();
    let mut encryption_context = None;
    for entry in parsed {
        let value = if entry.value_size == 0 {
            XattrValue::new(&[])?
        } else {
            let value_start = value_base
                .checked_add(entry.value_offset)
                .ok_or(Error::ArithmeticOverflow)?;
            if value_start % 4 != 0 || value_start < entries_end {
                return Err(Error::InvalidXattr);
            }
            let value_end = value_start
                .checked_add(entry.value_size)
                .ok_or(Error::ArithmeticOverflow)?;
            XattrValue::new(
                storage
                    .get(value_start..value_end)
                    .ok_or(Error::InvalidXattr)?,
            )?
        };
        match entry.slot {
            ParsedDiskXattrSlot::Public(name) => public_entries.push((name, value)),
            ParsedDiskXattrSlot::EncryptionContext => {
                if encryption_context.replace(value).is_some() {
                    return Err(Error::InvalidXattr);
                }
            }
        }
    }
    Ok(InodeXattrSet::from_parts(
        XattrSet::from_entries(public_entries)?,
        encryption_context,
    ))
}

/// Serializes xattr entries into a pre-zeroed storage image.
fn serialize_xattr_entries(
    set: &InodeXattrSet,
    storage: &mut [u8],
    entry_offset: usize,
    value_base: usize,
    placement: XattrValuePlacement,
) -> Result<()> {
    let mut entries = Vec::new();
    for entry in &set.public.entries {
        entries.push(SerializedDiskXattr {
            key: disk_key(&entry.name)?,
            value: entry.value.clone(),
        });
    }
    if let Some(value) = &set.encryption_context {
        entries.push(SerializedDiskXattr {
            key: DiskXattrKey {
                index: EXT4_XATTR_INDEX_ENCRYPTION,
                local: ENCRYPTION_CONTEXT_NAME.to_vec(),
            },
            value: value.clone(),
        });
    }
    entries.sort_by(|left, right| left.key.cmp_disk(&right.key));

    let entries_end = serialized_entries_end(entry_offset, &entries)?;
    if entries_end > storage.len() {
        return Err(Error::NoSpace);
    }

    let mut value_offsets = vec![0_usize; entries.len()];
    let mut value_cursor = storage.len();
    for (index, entry) in entries.iter().enumerate().rev() {
        let value = entry.value.bytes();
        if value.is_empty() {
            continue;
        }
        let raw_start = value_cursor
            .checked_sub(value.len())
            .ok_or(Error::NoSpace)?;
        let value_start = align_down(raw_start);
        if value_start < entries_end || value_start < value_base {
            return Err(Error::NoSpace);
        }
        let value_end = value_start
            .checked_add(value.len())
            .ok_or(Error::ArithmeticOverflow)?;
        storage
            .get_mut(value_start..value_end)
            .ok_or(Error::NoSpace)?
            .copy_from_slice(value);
        *value_offsets
            .get_mut(index)
            .ok_or(Error::ArithmeticOverflow)? = value_start
            .checked_sub(value_base)
            .ok_or(Error::ArithmeticOverflow)?;
        value_cursor = value_start;
    }

    let mut cursor = entry_offset;
    for (index, entry) in entries.iter().enumerate() {
        let name_len = entry.key.local.len();
        if name_len > usize::from(u8::MAX) {
            return Err(Error::InvalidXattr);
        }
        *storage.get_mut(cursor).ok_or(Error::NoSpace)? =
            u8::try_from(name_len).map_err(|_| Error::ArithmeticOverflow)?;
        *storage
            .get_mut(cursor.checked_add(1).ok_or(Error::ArithmeticOverflow)?)
            .ok_or(Error::NoSpace)? = entry.key.index;
        put_le_u16(
            storage,
            disk_offset(cursor).checked_add_bytes(2)?,
            u16::try_from(*value_offsets.get(index).ok_or(Error::ArithmeticOverflow)?)
                .map_err(|_| Error::NoSpace)?,
        )?;
        put_le_u32(storage, disk_offset(cursor).checked_add_bytes(4)?, 0)?;
        put_le_u32(
            storage,
            disk_offset(cursor).checked_add_bytes(8)?,
            u32::try_from(entry.value.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_le_u32(storage, disk_offset(cursor).checked_add_bytes(12)?, 0)?;
        let name_start = cursor
            .checked_add(EXT4_XATTR_ENTRY_BYTES)
            .ok_or(Error::ArithmeticOverflow)?;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(Error::ArithmeticOverflow)?;
        storage
            .get_mut(name_start..name_end)
            .ok_or(Error::NoSpace)?
            .copy_from_slice(&entry.key.local);
        cursor = align_up(name_end)?;
    }

    if placement == XattrValuePlacement::ExternalBlock {
        put_le_u32(storage, disk_offset(12), 0)?;
    }
    Ok(())
}

/// Returns the end of the serialized entry table including terminator padding.
fn serialized_entries_end(entry_offset: usize, entries: &[SerializedDiskXattr]) -> Result<usize> {
    let mut cursor = entry_offset;
    for entry in entries {
        cursor = align_up(
            cursor
                .checked_add(EXT4_XATTR_ENTRY_BYTES)
                .and_then(|value| value.checked_add(entry.key.local.len()))
                .ok_or(Error::ArithmeticOverflow)?,
        )?;
    }
    align_up(
        cursor
            .checked_add(EXT4_XATTR_TERMINATOR_BYTES)
            .ok_or(Error::ArithmeticOverflow)?,
    )
}

/// Converts a logical xattr name to its on-disk key.
fn disk_key(name: &XattrName) -> Result<DiskXattrKey> {
    let (index, local) = match name.namespace() {
        XattrNamespace::User => (EXT4_XATTR_INDEX_USER, name.local()),
        XattrNamespace::Trusted => (EXT4_XATTR_INDEX_TRUSTED, name.local()),
        XattrNamespace::Security => (EXT4_XATTR_INDEX_SECURITY, name.local()),
        XattrNamespace::System if name.local() == POSIX_ACL_ACCESS_NAME => {
            (EXT4_XATTR_INDEX_POSIX_ACL_ACCESS, &[][..])
        }
        XattrNamespace::System if name.local() == POSIX_ACL_DEFAULT_NAME => {
            (EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT, &[][..])
        }
        XattrNamespace::System => (EXT4_XATTR_INDEX_SYSTEM, name.local()),
    };
    Ok(DiskXattrKey {
        index,
        local: local.to_vec(),
    })
}

/// Converts an on-disk xattr key to the logical inode xattr slot.
fn logical_slot(index: u8, local: &[u8]) -> Result<ParsedDiskXattrSlot> {
    match index {
        EXT4_XATTR_INDEX_USER => Ok(ParsedDiskXattrSlot::Public(XattrName::new(
            XattrNamespace::User,
            local,
        )?)),
        EXT4_XATTR_INDEX_TRUSTED => Ok(ParsedDiskXattrSlot::Public(XattrName::new(
            XattrNamespace::Trusted,
            local,
        )?)),
        EXT4_XATTR_INDEX_SECURITY => Ok(ParsedDiskXattrSlot::Public(XattrName::new(
            XattrNamespace::Security,
            local,
        )?)),
        EXT4_XATTR_INDEX_SYSTEM => Ok(ParsedDiskXattrSlot::Public(XattrName::new(
            XattrNamespace::System,
            local,
        )?)),
        EXT4_XATTR_INDEX_POSIX_ACL_ACCESS if local.is_empty() => Ok(ParsedDiskXattrSlot::Public(
            XattrName::new(XattrNamespace::System, POSIX_ACL_ACCESS_NAME)?,
        )),
        EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT if local.is_empty() => Ok(ParsedDiskXattrSlot::Public(
            XattrName::new(XattrNamespace::System, POSIX_ACL_DEFAULT_NAME)?,
        )),
        EXT4_XATTR_INDEX_ENCRYPTION if local == ENCRYPTION_CONTEXT_NAME => {
            Ok(ParsedDiskXattrSlot::EncryptionContext)
        }
        _ => Err(Error::InvalidXattr),
    }
}

/// Validates the external xattr block header and checksum.
fn validate_external_xattr_block(
    bytes: &[u8],
    block: BlockAddress,
    superblock: &Superblock,
) -> Result<()> {
    if bytes.len() < EXT4_XATTR_BLOCK_HEADER_BYTES
        || le_u32(bytes, disk_offset(0))? != EXT4_XATTR_MAGIC
        || le_u32(bytes, disk_offset(4))? == 0
        || le_u32(bytes, disk_offset(8))? != 1
    {
        return Err(Error::InvalidXattr);
    }
    if superblock.metadata_checksum() == MetadataChecksum::Crc32c {
        let expected = le_u32(bytes, disk_offset(16))?;
        let mut checksum_bytes = bytes.to_vec();
        put_le_u32(&mut checksum_bytes, disk_offset(16), 0)?;
        let seed = crc32c(
            superblock.checksum_seed().as_u32(),
            &block.get().to_le_bytes(),
        );
        if crc32c(seed, &checksum_bytes) != expected {
            return Err(Error::ChecksumMismatch);
        }
    }
    Ok(())
}

/// Refreshes the external xattr block checksum.
fn refresh_external_xattr_checksum(
    bytes: &mut [u8],
    block: BlockAddress,
    superblock: &Superblock,
) -> Result<()> {
    put_le_u32(bytes, disk_offset(16), 0)?;
    if superblock.metadata_checksum() == MetadataChecksum::Crc32c {
        let seed = crc32c(
            superblock.checksum_seed().as_u32(),
            &block.get().to_le_bytes(),
        );
        let checksum = crc32c(seed, bytes);
        put_le_u32(bytes, disk_offset(16), checksum)?;
    }
    Ok(())
}

/// Aligns a byte offset upward to an ext4 xattr 4-byte boundary.
fn align_up(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(Error::ArithmeticOverflow)
}

/// Aligns a byte offset downward to an ext4 xattr 4-byte boundary.
const fn align_down(value: usize) -> usize {
    value & !3
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{
        InodeXattrSet, XattrName, XattrNamespace, XattrSet, XattrValue, merge_xattr_sets,
        parse_inline_xattrs, serialize_inline_xattrs,
    };

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

    #[test]
    fn fscrypt_context_is_private_inode_xattr() {
        let name = XattrName::new(XattrNamespace::User, b"visible");
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let value = XattrValue::new(b"public");
        assert!(value.is_ok());
        let Ok(value) = value else {
            return;
        };
        let public = XattrSet::from_entries(vec![(name, value)]);
        assert!(public.is_ok());
        let Ok(public) = public else {
            return;
        };
        let context = XattrValue::new(&[0xA5; 40]);
        assert!(context.is_ok());
        let Ok(context) = context else {
            return;
        };
        let set = InodeXattrSet::from_parts(public.clone(), Some(context.clone()));

        let image = serialize_inline_xattrs(&set, 256);
        assert!(image.is_ok());
        let Ok(image) = image else {
            return;
        };
        let parsed = parse_inline_xattrs(&image);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else {
            return;
        };

        assert_eq!(parsed.public(), &public);
        assert_eq!(parsed.encryption_context(), Some(&context));
    }

    #[test]
    fn duplicate_private_fscrypt_context_is_rejected() {
        let left_context = XattrValue::new(b"a");
        assert!(left_context.is_ok());
        let Ok(left_context) = left_context else {
            return;
        };
        let right_context = XattrValue::new(b"b");
        assert!(right_context.is_ok());
        let Ok(right_context) = right_context else {
            return;
        };
        let left = InodeXattrSet::from_parts(XattrSet::empty(), Some(left_context));
        let right = InodeXattrSet::from_parts(XattrSet::empty(), Some(right_context));

        assert!(merge_xattr_sets(left, right).is_err());
    }
}
