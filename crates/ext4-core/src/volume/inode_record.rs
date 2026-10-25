//! Inode record typestates staged by mounted volume transactions.

use super::scope::*;
use crate::disk_format::inode::{AttributeInode, InodeData, InodeRecordLayout};

mod delta;
pub(super) use delta::DeltaInodeImage;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Raw inode image paired with its identity and device offset. Read-only consumers may borrow
/// immutable table storage; mutation typestates own their independently writable bytes.
pub(super) struct RawInodeRecord<Bytes> {
    /// Inode number represented by this raw record.
    pub(super) id: InodeId,
    /// Absolute device offset of the inode record.
    pub(super) offset: ByteOffset,
    /// Storage ownership determines whether this record can enter a mutation typestate.
    pub(super) bytes: Bytes,
    /// Mounted encoding required to parse and rewrite inode data fields.
    pub(super) encoding: InodeDataEncoding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Legacy double-indirect root owned specifically by ext4's reserved resize inode.
pub(super) struct ResizeInodeBlockMap {
    /// Block containing pointers to the resize inode's indirect pointer blocks.
    double_indirect: BlockAddress,
}

impl ResizeInodeBlockMap {
    /// Returns the double-indirect pointer block.
    pub(super) const fn double_indirect(self) -> BlockAddress {
        self.double_indirect
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Newly allocated zeroed inode record before an inode kind has been written.
pub(super) struct AllocatedInodeRecord {
    /// Raw inode image owned by this typestate.
    raw: RawInodeRecord<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Allocated inode record with a nonzero link count and supported inode kind.
pub(super) struct LiveInodeRecord {
    /// Raw inode image owned by this typestate.
    raw: RawInodeRecord<Vec<u8>>,
}

/// Complete private inline-prefix/size successor applied with its admitted attribute body.
#[derive(Debug)]
pub(super) struct InlinePayloadUpdate {
    /// New i_block contents.
    prefix: [u8; 60],
    /// Size encoded under the selected file or directory contract.
    size: EncodedInodeSize,
}
impl InlinePayloadUpdate {
    /// Retains checked payload fields until the attribute body can be replaced in the same step.
    pub(super) const fn new(prefix: [u8; 60], size: EncodedInodeSize) -> Self {
        Self { prefix, size }
    }
}

/// Allocated external attribute storage with no namespace owner or timestamp interpretation.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct AttributeInodeRecord {
    /// Sole writable record image; header validation establishes its attribute role.
    raw: RawInodeRecord<Vec<u8>>,
}
/// Narrow data-layout authority shared by namespace and attribute-value inode serializers.
pub(super) trait ExtentInodeRecord {
    /// Reads allocation and extent geometry without namespace metadata.
    /// # Errors
    /// Rejects malformed storage encoding.
    fn data(&self) -> Result<InodeData>;
    /// External attribute block contributes to the inode's allocation charge.
    /// # Errors
    /// Rejects truncated pointer fields.
    fn xattr_block(&self) -> Result<Option<BlockAddress>>;
    /// Publishes a complete serialized root into this private inode image.
    /// # Errors
    /// Rejects truncated storage.
    fn set_extent_root_bytes(&mut self, root: &[u8; 60]) -> Result<()>;
    /// Writes the allocation count already checked against mounted units.
    /// # Errors
    /// Rejects truncated allocation fields.
    fn set_encoded_allocation_size(&mut self, size: EncodedInodeBlockCount) -> Result<()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Inode record staged after final unlink and deletion serialization.
pub(super) struct DeletedInodeRecord {
    /// Raw inode image owned by this typestate.
    raw: RawInodeRecord<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq)]
/// Inode record staged for commit after a typed state transition.
pub(super) enum StagedInodeRecord {
    /// Live inode metadata rewrite.
    Live(LiveInodeRecord),
    /// Attribute value data/refcount update with no namespace publication.
    Attribute(AttributeInodeRecord),
    /// Deleted inode cleanup rewrite.
    Deleted(DeletedInodeRecord),
    /// Allocated orphan whose remaining storage still requires recovery.
    Recovering(RecoverableOrphanInode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Index into this transaction's staged inode records.
pub(super) struct StagedInodeIndex(usize);

impl StagedInodeIndex {
    /// Creates a typed staged-inode index from vector position arithmetic.
    pub(super) const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Returns the vector index at the local staging boundary.
    pub(super) const fn get(self) -> usize {
        self.0
    }
}

impl From<LiveInodeRecord> for StagedInodeRecord {
    fn from(record: LiveInodeRecord) -> Self {
        Self::Live(record)
    }
}

impl From<AttributeInodeRecord> for StagedInodeRecord {
    fn from(record: AttributeInodeRecord) -> Self {
        Self::Attribute(record)
    }
}
impl From<DeletedInodeRecord> for StagedInodeRecord {
    fn from(record: DeletedInodeRecord) -> Self {
        Self::Deleted(record)
    }
}

impl RawInodeRecord<Vec<u8>> {
    /// Copies this raw inode image without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the raw inode bytes cannot allocate.
    fn try_clone_record(&self) -> Result<Self> {
        Ok(Self {
            id: self.id,
            offset: self.offset,
            bytes: memory::copied_slice(&self.bytes)?,
            encoding: self.encoding,
        })
    }

    /// Returns this inode record's id.
    pub(super) const fn id(&self) -> InodeId {
        self.id
    }

    /// Returns this inode record's write offset.
    pub(super) const fn offset(&self) -> ByteOffset {
        self.offset
    }

    /// Returns this inode record's serialized bytes.
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Moves this record into the uninitialized allocated-inode state.
    pub(super) fn into_allocated(self) -> AllocatedInodeRecord {
        AllocatedInodeRecord { raw: self }
    }

    /// Establishes attribute-value ownership without constructing a namespace record.
    /// # Errors
    /// Rejects malformed or namespace inode headers.
    pub(super) fn into_attribute(self) -> Result<AttributeInodeRecord> {
        let _header = AttributeInode::parse(self.id, &self.bytes, self.encoding)?;
        Ok(AttributeInodeRecord { raw: self })
    }
    /// Moves this record into the live-inode state after parsing invariants.
    /// # Errors
    ///
    /// Returns an error when the raw inode image cannot be parsed as a supported live inode.
    pub(super) fn into_live(self) -> Result<LiveInodeRecord> {
        let _inode = self.parse()?;
        Ok(LiveInodeRecord { raw: self })
    }
}

impl AllocatedInodeRecord {
    /// Initializes a positive-reference attribute value before allocating its extent payload.
    /// # Errors
    /// Propagates metadata, size or field encoding failures.
    pub(super) fn initialize_attribute_value(
        mut self,
        size: FileSize,
        checksum: u32,
        block_size: BlockSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<AttributeInodeRecord> {
        self.raw.initialize_file(
            NewFileMetadata::new(
                Ext4Owner::new(crate::Ext4Uid::from_u32(0), crate::Ext4Gid::from_u32(0)),
                Ext4Permissions::new(0o600)?,
            ),
            InodeFlags::from_u32(0),
            Ext4Timestamp::from_seconds(0),
            block_size,
            timestamp_encoding,
        )?;
        self.raw
            .set_flags(InodeFlags::from_u32(0).into_attribute_value())?;
        self.raw
            .set_encoded_size(self.raw.encoding.encode_file_size(size)?)?;
        put_le_u32(&mut self.raw.bytes, disk_offset(8), checksum)?;
        put_le_u32(&mut self.raw.bytes, disk_offset(12), 0)?;
        put_le_u32(&mut self.raw.bytes, disk_offset(36), 1)?;
        self.raw.into_attribute()
    }
    /// Initializes this allocation as an empty extent-backed file.
    /// # Errors
    ///
    /// Returns an error when file metadata, timestamps, an empty extent root, or sector counts
    /// cannot be serialized into the allocated inode record.
    pub(super) fn initialize_file(
        mut self,
        metadata: NewFileMetadata,
        parent_flags: InodeFlags,
        now: Ext4Timestamp,
        block_size: BlockSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<LiveInodeRecord> {
        self.raw
            .initialize_file(metadata, parent_flags, now, block_size, timestamp_encoding)?;
        self.raw.into_live()
    }

    /// Initializes a directory entirely inside its inode body without allocating a data block.
    /// # Errors
    /// Propagates unsupported encoding, body capacity or inode-field failures.
    pub(super) fn initialize_inline_directory(
        mut self,
        metadata: NewDirectoryMetadata,
        parent: InodeId,
        parent_flags: InodeFlags,
        now: Ext4Timestamp,
        block_size: BlockSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<LiveInodeRecord> {
        self.raw.initialize_file(
            NewFileMetadata::new(metadata.owner(), metadata.permissions()),
            parent_flags,
            now,
            block_size,
            timestamp_encoding,
        )?;
        self.raw
            .set_mode(InodeMode::directory(metadata.permissions()))?;
        self.raw.set_links_count(Ext4LinkCount::new(2)?)?;
        self.raw.set_encoded_size(
            self.raw
                .encoding
                .encode_directory_size(DirectorySize::from_bytes(60))?,
        )?;
        self.raw.set_flags(
            parent_flags
                .inherited_by(InodeKind::Directory)
                .into_inline_storage(),
        )?;
        let mut region = DirectoryBlock::empty(
            56,
            DirectoryChecksum::None,
            DirectoryEntryEncoding::Standard,
        )?;
        region.initialize_free_space()?;
        let mut prefix = [0; 60];
        memory::copy_exact(
            prefix.get_mut(..4).ok_or(Error::InvalidInode)?,
            &parent.as_u32().to_le_bytes(),
        )?;
        memory::copy_exact(
            prefix.get_mut(4..).ok_or(Error::InvalidInode)?,
            region.bytes(),
        )?;
        self.raw.set_extent_root_bytes(&prefix)?;
        let mut set = InodeXattrSet::empty();
        set.set_inline_data(XattrValue::new(&[])?);
        let body = xattr_storage::serialize_inline_xattrs(
            &set,
            self.raw.writable_inline_xattr_region()?.len(),
        )?;
        memory::copy_exact(self.raw.writable_inline_xattr_region()?, &body)?;
        self.raw.into_live()
    }

    /// Initializes this allocation as a directory owning its first block.
    /// # Errors
    ///
    /// Returns an error when the directory extent for `first_block`, directory size, timestamps, or
    /// allocated sector count cannot be represented in the inode record.
    #[expect(
        clippy::too_many_arguments,
        reason = "directory initialization combines inherited policy, metadata, time, geometry and its allocated storage"
    )]
    pub(super) fn initialize_directory(
        mut self,
        metadata: NewDirectoryMetadata,
        parent_flags: InodeFlags,
        now: Ext4Timestamp,
        block_size: BlockSize,
        first_block: BlockAddress,
        allocation_size: FileAllocationSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<LiveInodeRecord> {
        self.raw.initialize_directory(
            metadata,
            parent_flags,
            now,
            block_size,
            first_block,
            allocation_size,
            timestamp_encoding,
        )?;
        self.raw.into_live()
    }

    /// Initializes this allocation as an inline symbolic link.
    /// # Errors
    ///
    /// Returns an error when `target` is not inline-sized or the inline symlink metadata cannot be
    /// written to the allocated inode record.
    pub(super) fn initialize_inline_symlink(
        mut self,
        metadata: NewSymlinkMetadata,
        parent_flags: InodeFlags,
        now: Ext4Timestamp,
        target: &SymlinkTarget,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<LiveInodeRecord> {
        self.raw.initialize_inline_symlink(
            metadata,
            parent_flags,
            now,
            target,
            timestamp_encoding,
        )?;
        self.raw.into_live()
    }

    /// Initializes this allocation as an extent-backed symbolic link.
    /// # Errors
    ///
    /// Returns an error when `target` is inline-sized or the extent-backed symlink metadata cannot
    /// be written to the allocated inode record.
    pub(super) fn initialize_extent_symlink(
        mut self,
        metadata: NewSymlinkMetadata,
        parent_flags: InodeFlags,
        now: Ext4Timestamp,
        block_size: BlockSize,
        target: &SymlinkTarget,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<LiveInodeRecord> {
        self.raw.initialize_extent_symlink(
            metadata,
            parent_flags,
            now,
            block_size,
            target,
            timestamp_encoding,
        )?;
        self.raw.into_live()
    }
}

/// Stable metadata admits no payload/attribute changes; inline wire records include the full body.
/// # Errors
/// Returns malformed prefix width or truncated inode fields.
fn metadata_delta_record_len(base: &[u8], post: &[u8]) -> Result<Option<usize>> {
    if base.len() != post.len() || base.len() < 128 {
        return Err(Error::InvalidInode);
    }
    if le_u16(base, disk_offset(26))? == 0
        || (le_u16(base, disk_offset(0))? & 0xf000) != (le_u16(post, disk_offset(0))? & 0xf000)
    {
        return Ok(None);
    }
    for span in [26..36, 40..108, 116..120] {
        if base.get(span.clone()) != post.get(span) {
            return Ok(None);
        }
    }
    let prefix = if base.len() == 128 {
        128
    } else {
        let extra = le_u16(base, disk_offset(128))?;
        if extra != le_u16(post, disk_offset(128))? {
            return Ok(None);
        }
        128_usize
            .checked_add(usize::from(extra))
            .ok_or(Error::InvalidInode)?
    };
    if prefix > base.len() {
        return Err(Error::InvalidInode);
    }
    if base.get(prefix..) != post.get(prefix..) {
        return Ok(None);
    }
    let length =
        if InodeFlags::from_u32(le_u32(base, disk_offset(INODE_FLAGS_OFFSET))?).has_inline_data() {
            base.len()
        } else {
            prefix
        };
    Ok(Some(length))
}

impl LiveInodeRecord {
    /// A lossless metadata delta leaves all mapping, allocation and attribute-body bytes unchanged.
    /// Location and complete wire width are bound to the same immutable containing block.
    /// # Errors
    /// Rejects malformed record width or metadata coordinates before journal encoding.
    pub(super) fn metadata_delta_region(
        &self,
        block_start: ByteOffset,
        base_block: &[u8],
        post_block: &[u8],
    ) -> Result<Option<(ByteOffset, usize)>> {
        let Some(relative) = self.raw.offset().get().checked_sub(block_start.get()) else {
            return Ok(None);
        };
        let relative = usize::try_from(relative).map_err(|_| Error::ArithmeticOverflow)?;
        let end = relative
            .checked_add(self.raw.bytes().len())
            .ok_or(Error::ArithmeticOverflow)?;
        let Some(base) = base_block.get(relative..end) else {
            return Ok(None);
        };
        let Some(post) = post_block.get(relative..end) else {
            return Ok(None);
        };
        let Some(prefix) = metadata_delta_record_len(base, post)? else {
            return Ok(None);
        };
        let prefix_end = relative
            .checked_add(prefix)
            .ok_or(Error::ArithmeticOverflow)?;
        if base_block.get(..relative) != post_block.get(..relative)
            || base_block.get(prefix_end..) != post_block.get(prefix_end..)
        {
            return Ok(None);
        }
        Ok(Some((self.raw.offset(), prefix)))
    }

    /// Storage facts passed to the final allocation release boundary without copying the record.
    pub(super) const fn raw(&self) -> &RawInodeRecord<Vec<u8>> {
        &self.raw
    }

    /// Returns this inode record's id.
    pub(super) const fn id(&self) -> InodeId {
        self.raw.id()
    }

    /// Parses the live raw bytes as a validated inode.
    /// # Errors
    ///
    /// Returns an error when the staged live bytes fail inode parsing or supported-kind validation.
    pub(super) fn parse(&self) -> Result<Inode> {
        self.raw.parse()
    }

    /// Selects inline storage for an empty extent-backed allocation before publication.
    /// # Errors
    /// Rejects nonempty, protected or unsupported records and truncated fields.
    pub(super) fn initialize_inline_storage(&mut self) -> Result<()> {
        let inode = self.parse()?;
        if inode.size().bytes() != 0
            || inode.protection().is_encrypted()
            || inode.protection().is_verity()
        {
            return Err(Error::InvalidInode);
        }
        self.raw.set_extent_root_bytes(&[0; 60])?;
        self.raw.set_flags(inode.flags().into_inline_storage())
    }
    /// Atomically retires inline interpretation and establishes an empty extent root.
    /// # Errors
    /// Rejects an absent inline flag or truncated inode fields.
    pub(super) fn replace_inline_storage(&mut self, root: &[u8; 60]) -> Result<()> {
        let flags = self.raw.flags()?;
        if !flags.has_inline_data() {
            return Err(Error::InvalidInode);
        }
        self.raw.set_extent_root_bytes(root)?;
        self.raw.set_flags(flags.into_extent_storage())
    }
    /// Applies complete inline payload and body fields within one private record transition.
    /// # Errors
    /// Rejects non-inline storage, mismatched body capacity or truncated fields.
    pub(super) fn replace_inline_payload(
        &mut self,
        update: InlinePayloadUpdate,
        body: &[u8],
    ) -> Result<()> {
        if !self.raw.flags()?.has_inline_data()
            || body.len() != self.raw.inline_xattr_region()?.len()
        {
            return Err(Error::InvalidInode);
        }
        self.raw.set_extent_root_bytes(&update.prefix)?;
        self.raw.set_encoded_size(update.size)?;
        memory::copy_exact(self.raw.writable_inline_xattr_region()?, body)
    }

    /// Writes a directory comparison state after the transaction validates emptiness and policy.
    /// # Errors
    /// Returns a truncated inode flags field.
    pub(super) fn set_casefold(&mut self, state: crate::DirectoryCasefold) -> Result<()> {
        self.raw.set_flags(self.raw.flags()?.with_casefold(state))
    }

    /// Marks this directory inode as HTree indexed.
    /// # Errors
    ///
    /// Returns an error when the inode flags field cannot be read or rewritten with the directory
    /// index bit set.
    pub(super) fn mark_indexed_directory(&mut self) -> Result<()> {
        let flags = self.raw.flags()?;
        self.raw.set_flags(flags.with_indexed_directory())
    }

    /// Marks this regular file inode as fs-verity protected.
    /// # Errors
    ///
    /// Returns an error when DAX excludes fs-verity or the inode flags cannot be read or rewritten.
    pub(super) fn mark_verity(&mut self) -> Result<()> {
        let flags = self.raw.flags()?;
        self.raw.set_flags(flags.with_verity()?)
    }

    /// Marks this inode as fscrypt protected.
    /// # Errors
    ///
    /// Returns an error when the inode flags field cannot be read or rewritten with the encryption
    /// bit set.
    pub(super) fn mark_encrypted(&mut self) -> Result<()> {
        let flags = self.raw.flags()?;
        self.raw.set_flags(flags.with_encryption())
    }

    /// Updates owner fields.
    /// # Errors
    ///
    /// Returns an error when UID or GID halves cannot be written to the inode owner fields.
    pub(super) fn set_owner(&mut self, owner: Ext4Owner) -> Result<()> {
        self.raw.set_owner(owner)
    }

    /// Updates permission bits without changing the inode kind.
    /// # Errors
    ///
    /// Returns an error when the existing mode cannot be parsed or the updated permission bits
    /// cannot be written back.
    pub(super) fn set_permissions(&mut self, permissions: Ext4Permissions) -> Result<()> {
        self.raw.set_permissions(permissions)
    }

    /// Records an inode-status change without treating it as file access or content modification.
    /// # Errors
    /// Returns timestamp encoding or inode-field boundary failures.
    pub(super) fn touch_metadata(&mut self, now: Ext4Timestamp) -> Result<()> {
        self.raw.touch_metadata(now)
    }

    /// Records a payload, size or directory-entry modification while preserving access time.
    /// # Errors
    /// Returns timestamp encoding or inode-field boundary failures.
    pub(super) fn touch_contents(&mut self, now: Ext4Timestamp) -> Result<()> {
        self.raw.touch_contents(now)
    }

    /// Writes explicit ext4 inode timestamps.
    /// # Errors
    ///
    /// Returns an error when any explicit ext4 timestamp field or required extra timestamp storage
    /// cannot be updated.
    pub(super) fn set_ext4_times(&mut self, times: Ext4Times) -> Result<()> {
        self.raw.set_ext4_times(times)
    }

    /// Writes a file size already validated by the mounted inode encoding.
    /// # Errors
    ///
    /// Returns an error when either inode size field is not writable.
    pub(super) fn set_encoded_size(&mut self, size: EncodedInodeSize) -> Result<()> {
        self.raw.set_encoded_size(size)
    }

    /// Returns the external xattr block referenced by this inode.
    /// # Errors
    ///
    /// Returns an error when the inode's external xattr block reference fields are truncated.
    pub(super) fn xattr_block(&self) -> Result<Option<BlockAddress>> {
        self.raw.xattr_block()
    }

    /// Writes the external xattr block reference.
    /// # Errors
    ///
    /// Returns an error when `block` cannot be encoded by the inode's available xattr block
    /// reference fields.
    pub(super) fn set_xattr_block(&mut self, block: Option<BlockAddress>) -> Result<()> {
        self.raw.set_xattr_block(block)
    }

    /// Returns the in-inode xattr body region.
    /// # Errors
    ///
    /// Returns an error when `i_extra_isize` points outside this inode record.
    pub(super) fn inline_xattr_region(&self) -> Result<&[u8]> {
        self.raw.inline_xattr_region()
    }

    /// Returns mutable in-inode xattr body storage.
    /// # Errors
    ///
    /// Returns an error when the declared field boundary lies outside this inode record.
    pub(super) fn writable_inline_xattr_region(&mut self) -> Result<&mut [u8]> {
        self.raw.writable_inline_xattr_region()
    }

    /// Clears the in-inode xattr body region.
    /// # Errors
    ///
    /// Returns an error when the writable inline xattr region cannot be located.
    pub(super) fn clear_inline_xattr_region(&mut self) -> Result<()> {
        self.raw.clear_inline_xattr_region()
    }

    /// Installs a structural directory count without replaying a second link/unlink operation.
    /// # Errors
    /// Rejects a non-directory record or an unrepresentable count field.
    pub(super) fn replace_directory_links(&mut self, links: Ext4LinkCount) -> Result<()> {
        if self.parse()?.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.raw.set_links_count(links)
    }

    /// Installs the positive namespace census for a file or symlink without a clock mutation.
    /// # Errors
    /// Rejects directories or malformed link fields.
    pub(super) fn replace_file_links(&mut self, links: Ext4LinkCount) -> Result<()> {
        if self.parse()?.kind() == InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.raw.set_links_count(links)
    }

    /// Increments link count.
    /// # Errors
    ///
    /// Returns an error when the inode cannot be parsed, the link count is saturated, or the updated
    /// count cannot be written.
    pub(super) fn increment_links_count(&mut self) -> Result<()> {
        let links = self.parse()?.links_count();
        self.raw.set_links_count(links.incremented()?)
    }

    /// Updates directory reference accounting under this record's validated mounted policy.
    /// # Errors
    /// Returns wrong kind, malformed count, or saturated counted-directory state.
    pub(super) fn increment_directory_links(&mut self) -> Result<()> {
        let inode = self.parse()?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        let indexed = matches!(inode.directory_storage_kind()?, DirectoryStorageKind::HTree);
        let links = inode
            .links_count()
            .directory_incremented(self.raw.encoding.directory_links(), indexed)?;
        self.raw.set_links_count(links)
    }

    /// Removes one child reference without resolving an uncounted directory to an exact count.
    /// # Errors
    /// Returns wrong kind or invalid directory reference state.
    pub(super) fn decrement_directory_links(&mut self) -> Result<()> {
        let inode = self.parse()?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.raw
            .set_links_count(inode.links_count().directory_decremented()?)
    }

    /// Decrements link count and returns the resulting live/deletion boundary.
    /// # Errors
    ///
    /// Returns an error when the inode cannot be parsed or the still-linked count cannot be written
    /// back.
    pub(super) fn decrement_links_count(&mut self) -> Result<LinkCountAfterDecrement> {
        let links = self.parse()?.links_count();
        let boundary = links.decremented();
        if let LinkCountAfterDecrement::StillLinked(updated) = boundary {
            self.raw.set_links_count(updated)?;
        }
        Ok(boundary)
    }

    /// Serializes deletion state after final unlink.
    /// # Errors
    ///
    /// Returns an error when deletion time, zeroed size and allocation fields, or the empty extent
    /// root cannot be serialized.
    pub(super) fn delete(
        mut self,
        now: Ext4Timestamp,
        block_size: BlockSize,
    ) -> Result<DeletedInodeRecord> {
        self.raw.touch_metadata(now)?;
        self.finish_deletion(now.base_seconds_bits()?, block_size)
    }

    /// Final namespace absence supplies retirement authority; recovery has no new event clock.
    /// # Errors
    /// Returns malformed inode fields or failed deletion serialization.
    pub(super) fn retire_replayed(self, block_size: BlockSize) -> Result<DeletedInodeRecord> {
        let recorded = le_u32(&self.raw.bytes, disk_offset(INODE_CTIME_OFFSET))?.max(1);
        self.finish_deletion(recorded, block_size)
    }

    /// Serializes one terminal storage state shared by live deletion and authenticated recovery.
    /// # Errors
    /// Returns malformed size, allocation, attribute or extent fields.
    fn finish_deletion(
        mut self,
        deletion_time: u32,
        block_size: BlockSize,
    ) -> Result<DeletedInodeRecord> {
        let kind = self.parse()?.kind();
        self.raw.set_deletion_time(deletion_time)?;
        self.raw.set_deleted_links_count()?;
        let size = match kind {
            InodeKind::Directory => self
                .raw
                .encoding
                .encode_directory_size(DirectorySize::from_bytes(0))?,
            InodeKind::File | InodeKind::Symlink => self
                .raw
                .encoding
                .encode_file_size(FileSize::from_bytes(0))?,
        };
        self.raw.set_encoded_size(size)?;
        let allocation_size = self
            .raw
            .encoding
            .encode_allocation_size(FileAllocationSize::from_bytes(0))?;
        self.raw.set_encoded_allocation_size(allocation_size)?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.raw.set_extent_root_bytes(serialized.inode_root())?;
        self.raw.set_xattr_block(None)?;
        self.raw.clear_inline_xattr_region()?;
        Ok(DeletedInodeRecord { raw: self.raw })
    }
}

impl AttributeInodeRecord {
    /// Validated value header; hash and reference fields are never decoded as time.
    /// # Errors
    /// Rejects malformed attribute-inode storage.
    pub(super) fn parse(&self) -> Result<AttributeInode> {
        AttributeInode::parse(self.raw.id, &self.raw.bytes, self.raw.encoding)
    }
    /// Record identity for transaction resource admission.
    pub(super) const fn id(&self) -> InodeId {
        self.raw.id
    }
    /// Fallible independent copy for transaction staging.
    /// # Errors
    /// Propagates allocation failure.
    pub(super) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            raw: self.raw.try_clone_record()?,
        })
    }
    /// Writes a still-positive reference count; terminal release consumes this record separately.
    /// # Errors
    /// Rejects zero and truncated fields.
    pub(super) fn set_references(&mut self, references: core::num::NonZeroU64) -> Result<()> {
        put_le_u32(
            &mut self.raw.bytes,
            disk_offset(12),
            u32::try_from(references.get() >> 32).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_le_u32(
            &mut self.raw.bytes,
            disk_offset(36),
            u32::try_from(references.get() & u64::from(u32::MAX))
                .map_err(|_| Error::ArithmeticOverflow)?,
        )
    }
    /// Consumes the final reference after all value blocks have been released in this transaction.
    /// # Errors
    /// Rejects nonterminal reference count or failed inode-field encoding.
    pub(super) fn retire(mut self, block_size: BlockSize) -> Result<DeletedInodeRecord> {
        if self.parse()?.references() != 1 {
            return Err(Error::InvalidXattr);
        }
        // Internal value ownership carries no namespace clock. A nonzero retirement marker
        // records deletion without interpreting the overloaded reference fields as a timestamp.
        self.raw.set_deletion_time(1)?;
        self.raw.set_deleted_links_count()?;
        self.raw.set_encoded_size(
            self.raw
                .encoding
                .encode_file_size(FileSize::from_bytes(0))?,
        )?;
        self.raw.set_encoded_allocation_size(
            self.raw
                .encoding
                .encode_allocation_size(FileAllocationSize::from_bytes(0))?,
        )?;
        self.raw
            .set_flags(InodeFlags::from_u32(0).with_extent_tree())?;
        self.raw.set_xattr_block(None)?;
        self.raw.clear_inline_xattr_region()?;
        let empty = MutableExtentTree::from_extents(Vec::new())?
            .serialize(block_size, ExtentTreeContext::none())?;
        self.raw.set_extent_root_bytes(empty.inode_root())?;
        Ok(DeletedInodeRecord { raw: self.raw })
    }
}
impl ExtentInodeRecord for LiveInodeRecord {
    fn data(&self) -> Result<InodeData> {
        InodeData::parse(self.raw.id, &self.raw.bytes, self.raw.encoding)
    }
    fn xattr_block(&self) -> Result<Option<BlockAddress>> {
        self.raw.xattr_block()
    }
    fn set_extent_root_bytes(&mut self, root: &[u8; 60]) -> Result<()> {
        self.raw.set_extent_root_bytes(root)
    }
    fn set_encoded_allocation_size(&mut self, size: EncodedInodeBlockCount) -> Result<()> {
        self.raw.set_encoded_allocation_size(size)
    }
}
impl ExtentInodeRecord for AttributeInodeRecord {
    fn data(&self) -> Result<InodeData> {
        InodeData::parse(self.raw.id, &self.raw.bytes, self.raw.encoding)
    }
    fn xattr_block(&self) -> Result<Option<BlockAddress>> {
        self.raw.xattr_block()
    }
    fn set_extent_root_bytes(&mut self, root: &[u8; 60]) -> Result<()> {
        self.raw.set_extent_root_bytes(root)
    }
    fn set_encoded_allocation_size(&mut self, size: EncodedInodeBlockCount) -> Result<()> {
        self.raw.set_encoded_allocation_size(size)
    }
}

impl StagedInodeRecord {
    /// Copies this staged inode image without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the staged raw inode bytes cannot allocate.
    pub(super) fn try_clone(&self) -> Result<Self> {
        Ok(match self {
            Self::Live(record) => Self::Live(LiveInodeRecord {
                raw: record.raw.try_clone_record()?,
            }),
            Self::Attribute(record) => Self::Attribute(record.try_clone()?),
            Self::Deleted(record) => Self::Deleted(DeletedInodeRecord {
                raw: record.raw.try_clone_record()?,
            }),
            Self::Recovering(record) => Self::Recovering(record.try_clone()?),
        })
    }

    /// Returns the staged inode id regardless of state.
    pub(super) const fn id(&self) -> InodeId {
        match self {
            Self::Live(record) => record.raw.id(),
            Self::Attribute(record) => record.raw.id(),
            Self::Deleted(record) => record.raw.id(),
            Self::Recovering(record) => record.raw().id(),
        }
    }

    /// Returns a live record clone or rejects deleted state.
    /// # Errors
    ///
    /// Returns an error when the staged record has already crossed into deleted state.
    pub(super) fn clone_live(&self) -> Result<LiveInodeRecord> {
        match self {
            Self::Live(record) => Ok(LiveInodeRecord {
                raw: record.raw.try_clone_record()?,
            }),
            Self::Deleted(_) | Self::Recovering(_) | Self::Attribute(_) => Err(Error::InvalidInode),
        }
    }

    /// Recomputes the inode checksum before writing this staged image.
    /// # Errors
    ///
    /// Returns an error when checksum fields or the inode generation field cannot be accessed.
    pub(super) fn refresh_checksum(&mut self, superblock: &Superblock) -> Result<()> {
        match self {
            Self::Live(record) => record.raw.refresh_checksum(superblock),
            Self::Attribute(record) => record.raw.refresh_checksum(superblock),
            Self::Deleted(record) => record.raw.refresh_checksum(superblock),
            Self::Recovering(record) => record.raw_mut().refresh_checksum(superblock),
        }
    }

    /// Returns this staged image's device offset.
    pub(super) const fn offset(&self) -> ByteOffset {
        match self {
            Self::Live(record) => record.raw.offset(),
            Self::Attribute(record) => record.raw.offset(),
            Self::Deleted(record) => record.raw.offset(),
            Self::Recovering(record) => record.raw().offset(),
        }
    }

    /// Returns the serialized staged inode bytes.
    pub(super) fn bytes(&self) -> &[u8] {
        match self {
            Self::Live(record) => record.raw.bytes(),
            Self::Attribute(record) => record.raw.bytes(),
            Self::Deleted(record) => record.raw.bytes(),
            Self::Recovering(record) => record.raw().bytes(),
        }
    }
}

impl RawInodeRecord<Vec<u8>> {
    /// Initializes a zeroed inode record as an empty extent-backed file.
    /// # Errors
    ///
    /// Returns an error when file metadata, timestamps, empty extent-root serialization, or sector
    /// count serialization fails.
    pub(super) fn initialize_file(
        &mut self,
        metadata: NewFileMetadata,
        parent_flags: InodeFlags,
        now: Ext4Timestamp,
        block_size: BlockSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.bytes.fill(0);
        if timestamp_encoding == InodeTimestampEncoding::ExtraFields {
            self.initialize_extra_fields()?;
        }
        self.set_mode(InodeMode::regular_file(metadata.permissions()))?;
        self.set_owner(metadata.owner())?;
        let size = self.encoding.encode_file_size(FileSize::from_bytes(0))?;
        self.set_encoded_size(size)?;
        self.set_links_count(Ext4LinkCount::ONE)?;
        self.initialize_timestamps(now)?;
        self.set_deletion_time(0)?;
        self.set_flags(
            parent_flags
                .inherited_by(InodeKind::File)
                .with_extent_tree(),
        )?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.set_extent_root_bytes(serialized.inode_root())?;
        let allocation_size = self
            .encoding
            .encode_allocation_size(FileAllocationSize::from_bytes(0))?;
        self.set_encoded_allocation_size(allocation_size)
    }

    /// Initializes a zeroed inode record as a directory owning its first block.
    /// # Errors
    ///
    /// Returns an error when the first directory extent, timestamps, directory size, or allocated
    /// sector count cannot be serialized.
    #[expect(
        clippy::too_many_arguments,
        reason = "directory initialization combines inherited policy, metadata, time, geometry and its allocated storage"
    )]
    pub(super) fn initialize_directory(
        &mut self,
        metadata: NewDirectoryMetadata,
        parent_flags: InodeFlags,
        now: Ext4Timestamp,
        block_size: BlockSize,
        first_block: BlockAddress,
        allocation_size: FileAllocationSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.bytes.fill(0);
        if timestamp_encoding == InodeTimestampEncoding::ExtraFields {
            self.initialize_extra_fields()?;
        }
        self.set_mode(InodeMode::directory(metadata.permissions()))?;
        self.set_owner(metadata.owner())?;
        let size = self
            .encoding
            .encode_directory_size(DirectorySize::from_bytes(u64::from(block_size.bytes())))?;
        self.set_encoded_size(size)?;
        self.set_links_count(Ext4LinkCount::TWO)?;
        self.initialize_timestamps(now)?;
        self.set_deletion_time(0)?;
        self.set_flags(
            parent_flags
                .inherited_by(InodeKind::Directory)
                .with_extent_tree(),
        )?;
        let mut extents = Vec::new();
        extents.try_push(Extent::initialized(
            LogicalBlock::from_u32(0),
            ExtentLength::new(1)?,
            first_block,
        ))?;
        let tree = MutableExtentTree::from_extents(extents)?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.set_extent_root_bytes(serialized.inode_root())?;
        let allocation_size = self.encoding.encode_allocation_size(allocation_size)?;
        self.set_encoded_allocation_size(allocation_size)
    }

    /// Initializes a zeroed inode record as an inline symbolic link.
    /// # Errors
    ///
    /// Returns an error when `target` does not fit inline storage or any symlink inode field is
    /// truncated.
    pub(super) fn initialize_inline_symlink(
        &mut self,
        metadata: NewSymlinkMetadata,
        parent_flags: InodeFlags,
        now: Ext4Timestamp,
        target: &SymlinkTarget,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        if !target.is_inline() {
            return Err(Error::InvalidWriteRange);
        }
        self.bytes.fill(0);
        if timestamp_encoding == InodeTimestampEncoding::ExtraFields {
            self.initialize_extra_fields()?;
        }
        self.set_mode(InodeMode::symlink(metadata.permissions()))?;
        self.set_owner(metadata.owner())?;
        let size = self.encoding.encode_file_size(FileSize::from_bytes(
            u64::try_from(target.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
        ))?;
        self.set_encoded_size(size)?;
        self.set_links_count(Ext4LinkCount::ONE)?;
        self.initialize_timestamps(now)?;
        self.set_deletion_time(0)?;
        self.set_flags(parent_flags.inherited_by(InodeKind::Symlink))?;
        self.set_inline_target(target.bytes())?;
        let allocation_size = self
            .encoding
            .encode_allocation_size(FileAllocationSize::from_bytes(0))?;
        self.set_encoded_allocation_size(allocation_size)
    }

    /// Initializes a zeroed inode record as an extent-backed symbolic link.
    /// # Errors
    ///
    /// Returns an error when `target` should use inline storage or the empty extent-backed symlink
    /// fields cannot be serialized.
    pub(super) fn initialize_extent_symlink(
        &mut self,
        metadata: NewSymlinkMetadata,
        parent_flags: InodeFlags,
        now: Ext4Timestamp,
        block_size: BlockSize,
        target: &SymlinkTarget,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        if target.is_inline() {
            return Err(Error::InvalidWriteRange);
        }
        self.bytes.fill(0);
        if timestamp_encoding == InodeTimestampEncoding::ExtraFields {
            self.initialize_extra_fields()?;
        }
        self.set_mode(InodeMode::symlink(metadata.permissions()))?;
        self.set_owner(metadata.owner())?;
        let size = self.encoding.encode_file_size(FileSize::from_bytes(
            u64::try_from(target.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
        ))?;
        self.set_encoded_size(size)?;
        self.set_links_count(Ext4LinkCount::ONE)?;
        self.initialize_timestamps(now)?;
        self.set_deletion_time(0)?;
        self.set_flags(
            parent_flags
                .inherited_by(InodeKind::Symlink)
                .with_extent_tree(),
        )?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.set_extent_root_bytes(serialized.inode_root())?;
        let allocation_size = self
            .encoding
            .encode_allocation_size(FileAllocationSize::from_bytes(0))?;
        self.set_encoded_allocation_size(allocation_size)
    }

    /// Writes inode type and permission bits into `i_mode`.
    /// # Errors
    ///
    /// Returns an error when the inode mode field is not writable.
    pub(super) fn set_mode(&mut self, mode: InodeMode) -> Result<()> {
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_MODE_OFFSET),
            mode.as_u16(),
        )
    }

    /// Updates inode permission bits without changing the inode type.
    /// # Errors
    ///
    /// Returns an error when the existing mode is truncated, encodes an unsupported kind, or cannot
    /// be rewritten.
    pub(super) fn set_permissions(&mut self, permissions: Ext4Permissions) -> Result<()> {
        let mode = InodeMode::from_disk(le_u16(&self.bytes, disk_offset(INODE_MODE_OFFSET))?)?;
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_MODE_OFFSET),
            InodeMode::new(mode.kind(), permissions).as_u16(),
        )
    }

    /// Writes low and high UID/GID fields when the inode record can hold them.
    /// # Errors
    ///
    /// Returns an error when any UID or GID field required by this inode size is not writable.
    pub(super) fn set_owner(&mut self, owner: Ext4Owner) -> Result<()> {
        let uid = owner.uid().as_u32();
        let gid = owner.gid().as_u32();
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_UID_LO_OFFSET),
            u16::try_from(uid & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_GID_LO_OFFSET),
            u16::try_from(gid & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if self.bytes.len() > INODE_UID_HI_OFFSET {
            put_le_u16(
                &mut self.bytes,
                disk_offset(INODE_UID_HI_OFFSET),
                u16::try_from(uid >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            put_le_u16(
                &mut self.bytes,
                disk_offset(INODE_GID_HI_OFFSET),
                u16::try_from(gid >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(())
    }

    /// Writes the inode link count.
    /// # Errors
    ///
    /// Returns an error when `i_links_count` cannot receive `links`.
    pub(super) fn set_links_count(&mut self, links: Ext4LinkCount) -> Result<()> {
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_LINKS_COUNT_OFFSET),
            links.on_disk_count(),
        )
    }

    /// Writes zero link count at the deleted-inode serialization boundary.
    /// # Errors
    ///
    /// Returns an error when `i_links_count` cannot be cleared for deletion.
    pub(super) fn set_deleted_links_count(&mut self) -> Result<()> {
        put_le_u16(&mut self.bytes, disk_offset(INODE_LINKS_COUNT_OFFSET), 0)
    }

    /// Writes the inode flags field.
    /// # Errors
    ///
    /// Returns an error when the inode flags field is not writable.
    pub(super) fn set_flags(&mut self, flags: InodeFlags) -> Result<()> {
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_FLAGS_OFFSET),
            flags.as_u32(),
        )
    }

    /// Writes a validated low/high inode size pair.
    /// # Errors
    ///
    /// Returns an error when either inode size field is not writable.
    pub(super) fn set_encoded_size(&mut self, size: EncodedInodeSize) -> Result<()> {
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_SIZE_LO_OFFSET),
            size.low(),
        )?;
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_SIZE_HIGH_OFFSET),
            size.high(),
        )
    }

    /// Writes a validated inode block count and synchronizes its unit flag.
    /// # Errors
    ///
    /// Returns an error when block-count or inode-flag fields are not writable.
    pub(super) fn set_encoded_allocation_size(
        &mut self,
        block_count: EncodedInodeBlockCount,
    ) -> Result<()> {
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_BLOCKS_LO_OFFSET),
            block_count.low(),
        )?;
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_BLOCKS_HIGH_OFFSET),
            block_count.high(),
        )?;
        let flags = match block_count.unit() {
            InodeBlockCountUnit::Sectors => self.flags()?.without_huge_file_blocks(),
            InodeBlockCountUnit::FileSystemBlocks => self.flags()?.with_huge_file_blocks(),
        };
        self.set_flags(flags)
    }

    /// Establishes every available timestamp when an inode first becomes live.
    /// # Errors
    /// Returns timestamp encoding or inode-field boundary failures.
    fn initialize_timestamps(&mut self, now: Ext4Timestamp) -> Result<()> {
        self.touch_contents(now)?;
        self.set_timestamp_field(now, INODE_ATIME_OFFSET, INODE_ATIME_EXTRA_OFFSET)?;
        self.set_creation_time(now)
    }

    /// Writes only inode status-change time for metadata changes.
    /// # Errors
    /// Returns timestamp encoding or inode-field boundary failures.
    fn touch_metadata(&mut self, now: Ext4Timestamp) -> Result<()> {
        self.set_timestamp_field(now, INODE_CTIME_OFFSET, INODE_CTIME_EXTRA_OFFSET)
    }

    /// Writes status-change and contents-modification times without implying a read.
    /// # Errors
    /// Returns timestamp encoding or inode-field boundary failures.
    fn touch_contents(&mut self, now: Ext4Timestamp) -> Result<()> {
        self.touch_metadata(now)?;
        self.set_timestamp_field(now, INODE_MTIME_OFFSET, INODE_MTIME_EXTRA_OFFSET)
    }

    /// Writes one time only within this inode's declared field storage.
    /// # Errors
    /// Returns invalid timestamp when its epoch cannot fit, or a malformed inode layout.
    fn set_timestamp_field(
        &mut self,
        time: Ext4Timestamp,
        base: usize,
        extra: usize,
    ) -> Result<()> {
        let layout = InodeRecordLayout::parse(&self.bytes)?;
        let (seconds, extension) = time.encode(layout.contains(extra, 4))?;
        put_le_u32(&mut self.bytes, disk_offset(base), seconds)?;
        if let Some(extension) = extension {
            put_le_u32(&mut self.bytes, disk_offset(extra), extension)?;
        }
        Ok(())
    }

    /// Writes creation time when the inode declares that field.
    /// # Errors
    /// Returns malformed storage or a timestamp outside the available epoch range.
    pub(super) fn set_creation_time(&mut self, now: Ext4Timestamp) -> Result<()> {
        if InodeRecordLayout::parse(&self.bytes)?.contains(INODE_CRTIME_OFFSET, 4) {
            self.set_timestamp_field(now, INODE_CRTIME_OFFSET, INODE_CRTIME_EXTRA_OFFSET)?;
        }
        Ok(())
    }

    /// Writes the inode deletion time field.
    /// # Errors
    ///
    /// Returns an error when the deletion time field is not writable.
    pub(super) fn set_deletion_time(&mut self, seconds: u32) -> Result<()> {
        put_le_u32(&mut self.bytes, disk_offset(INODE_DTIME_OFFSET), seconds)
    }

    /// Writes the serialized extent root into `i_block`.
    /// # Errors
    ///
    /// Returns an error when the inode record is too short to contain the fixed `i_block` payload.
    pub(super) fn set_extent_root_bytes(&mut self, root: &[u8; 60]) -> Result<()> {
        let end = INODE_BLOCK_OFFSET
            .checked_add(root.len())
            .ok_or(Error::ArithmeticOverflow)?;
        memory::copy_exact(
            self.bytes
                .get_mut(INODE_BLOCK_OFFSET..end)
                .ok_or(Error::TruncatedStructure)?,
            root,
        )
    }

    /// Writes explicit ext4 inode timestamps.
    /// # Errors
    ///
    /// Returns an error when explicit timestamp fields or optional extra timestamp fields are not
    /// writable.
    pub(super) fn set_ext4_times(&mut self, times: Ext4Times) -> Result<()> {
        self.set_timestamp_field(
            times.accessed(),
            INODE_ATIME_OFFSET,
            INODE_ATIME_EXTRA_OFFSET,
        )?;
        self.set_timestamp_field(
            times.changed(),
            INODE_CTIME_OFFSET,
            INODE_CTIME_EXTRA_OFFSET,
        )?;
        self.set_timestamp_field(
            times.modified(),
            INODE_MTIME_OFFSET,
            INODE_MTIME_EXTRA_OFFSET,
        )?;
        if let Some(created) = times.created() {
            self.set_creation_time(created)?;
        }
        Ok(())
    }

    /// Writes the external xattr block reference into `i_file_acl`.
    /// # Errors
    ///
    /// Returns an error when the inode lacks high `i_file_acl` storage required by `block` or the
    /// available fields are not writable.
    pub(super) fn set_xattr_block(&mut self, block: Option<BlockAddress>) -> Result<()> {
        let raw = block.map_or(0, BlockAddress::get);
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_FILE_ACL_LO_OFFSET),
            u32::try_from(raw & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        let high = raw >> 32;
        if self.bytes.len() > INODE_FILE_ACL_HI_OFFSET {
            put_le_u16(
                &mut self.bytes,
                disk_offset(INODE_FILE_ACL_HI_OFFSET),
                u16::try_from(high).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        } else if high != 0 {
            return Err(Error::InvalidWriteRange);
        }
        Ok(())
    }

    /// Returns the mutable xattr body without changing the declared field boundary.
    /// # Errors
    ///
    /// Returns an error when the declared field boundary lies outside the inode record.
    pub(super) fn writable_inline_xattr_region(&mut self) -> Result<&mut [u8]> {
        let offset = self.inline_xattr_offset()?;
        self.bytes.get_mut(offset..).ok_or(Error::InvalidXattr)
    }

    /// Clears the in-inode xattr body region.
    /// # Errors
    ///
    /// Returns an error when the inline xattr region cannot be located for mutation.
    pub(super) fn clear_inline_xattr_region(&mut self) -> Result<()> {
        self.writable_inline_xattr_region()?.fill(0);
        Ok(())
    }

    /// Computes the in-inode xattr body offset from `i_extra_isize`.
    /// # Errors
    ///
    /// Returns an error when `i_extra_isize` is truncated, overflows the base inode size, or points
    /// beyond the record.
    pub(super) fn inline_xattr_offset(&self) -> Result<usize> {
        Ok(InodeRecordLayout::parse(&self.bytes)?.xattr_offset())
    }

    /// Writes an inline symbolic link target into `i_block`.
    /// # Errors
    ///
    /// Returns an error when `target` exceeds inline capacity or the `i_block` storage is truncated.
    pub(super) fn set_inline_target(&mut self, target: &[u8]) -> Result<()> {
        if target.len() >= SymlinkTarget::INLINE_CAPACITY {
            return Err(Error::InvalidWriteRange);
        }
        let end = INODE_BLOCK_OFFSET
            .checked_add(SymlinkTarget::INLINE_CAPACITY)
            .ok_or(Error::ArithmeticOverflow)?;
        let block = self
            .bytes
            .get_mut(INODE_BLOCK_OFFSET..end)
            .ok_or(Error::TruncatedStructure)?;
        block.fill(0);
        memory::copy_exact(
            block.get_mut(..target.len()).ok_or(Error::DeviceRange)?,
            target,
        )
    }

    /// Recomputes inode checksum fields when metadata checksums are enabled.
    /// # Errors
    ///
    /// Returns an error when checksum fields cannot be cleared or rewritten, or the generation seed
    /// field is truncated.
    pub(super) fn refresh_checksum(&mut self, superblock: &Superblock) -> Result<()> {
        if superblock.metadata_checksum() != MetadataChecksum::Crc32c {
            return Ok(());
        }
        let (checksum, high) = self.checksum(superblock)?;
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_CHECKSUM_LO_OFFSET),
            u16::try_from(checksum & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if high {
            put_le_u16(
                &mut self.bytes,
                disk_offset(INODE_CHECKSUM_HI_OFFSET),
                u16::try_from(checksum >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(())
    }

    /// Establishes extra-field storage in a newly zeroed inode record.
    /// # Errors
    ///
    /// Returns an error when the `i_extra_isize` field is present but cannot be read or initialized.
    fn initialize_extra_fields(&mut self) -> Result<()> {
        if self.bytes.len() > INODE_EXTRA_ISIZE_OFFSET
            && le_u16(&self.bytes, disk_offset(INODE_EXTRA_ISIZE_OFFSET))? == 0
        {
            put_le_u16(
                &mut self.bytes,
                disk_offset(INODE_EXTRA_ISIZE_OFFSET),
                EXT4_INODE_MIN_EXTRA_ISIZE,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    /// # Panics
    /// Fails if inline metadata emits an incomplete wire record or admits an unlogged body mutation.
    #[test]
    fn inline_metadata_delta_retains_the_complete_unchanged_body() {
        let result = (|| -> Result<()> {
            let mut raw = raw_record(12)?;
            raw.bytes = memory::repeated_vec(0, 256)?;
            raw.encoding = InodeDataEncoding::new(
                crate::disk_format::inode::FileSizeEncoding::LargeFile,
                crate::disk_format::inode::DirectorySizeEncoding::LargeDirectory,
                crate::disk_format::inode::InodeBlockCountEncoding::HugeFile,
                block_size()?,
                crate::disk_format::inode::DirectoryLinkEncoding::Counted,
                true,
                false,
                false,
            );
            let mut original = raw.into_allocated().initialize_file(
                NewFileMetadata::new(owner(), permissions()?),
                InodeFlags::from_u32(0),
                now(),
                block_size()?,
                InodeTimestampEncoding::ExtraFields,
            )?;
            let mut set = InodeXattrSet::empty();
            set.set_inline_data(XattrValue::new(&[])?);
            let body = xattr_storage::serialize_inline_xattrs(
                &set,
                original.raw.inline_xattr_region()?.len(),
            )?;
            original.initialize_inline_storage()?;
            memory::copy_exact(original.raw.writable_inline_xattr_region()?, &body)?;
            let mut successor = original.raw.try_clone_record()?.into_live()?;
            successor.set_permissions(Ext4Permissions::new(0o600)?)?;
            assert_eq!(
                successor.metadata_delta_region(
                    ByteOffset::new(0),
                    original.raw.bytes(),
                    successor.raw.bytes()
                )?,
                Some((ByteOffset::new(0), 256))
            );
            let replayed = DeltaInodeImage::parse(successor.raw.bytes(), 256)?
                .restore(original.raw.try_clone_record()?.into_live()?)?;
            assert_eq!(
                replayed.parse()?.security().permissions(),
                Ext4Permissions::new(0o600)?
            );
            *successor.raw.bytes.last_mut().ok_or(Error::InvalidInode)? ^= 1;
            assert_eq!(
                successor.metadata_delta_region(
                    ByteOffset::new(0),
                    original.raw.bytes(),
                    successor.raw.bytes()
                )?,
                None
            );
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }

    /// # Panics
    /// Fails if recorded roots or block charges override reconstructed extent ownership.
    #[test]
    fn extent_delta_metadata_preserves_mapping_and_derived_block_charge() {
        let result = (|| -> Result<()> {
            let original = initialized_file(12)?;
            let root = memory::copied_slice(
                original
                    .raw
                    .bytes()
                    .get(40..100)
                    .ok_or(Error::InvalidInode)?,
            )?;
            let mut encoded = memory::copied_slice(original.raw.bytes())?;
            put_le_u16(
                &mut encoded,
                disk_offset(INODE_MODE_OFFSET),
                MODE_REGULAR | 0o600,
            )?;
            encoded
                .get_mut(40..100)
                .ok_or(Error::InvalidInode)?
                .fill(0xa5);
            encoded
                .get_mut(28..32)
                .ok_or(Error::InvalidInode)?
                .fill(0xff);
            encoded
                .get_mut(116..118)
                .ok_or(Error::InvalidInode)?
                .fill(0xff);
            let replayed =
                DeltaInodeImage::parse(&encoded, original.raw.bytes.len())?.restore(original)?;
            assert_eq!(mode(replayed.raw()), Ok(MODE_REGULAR | 0o600));
            assert_eq!(replayed.raw.bytes().get(40..100), Some(root.as_slice()));
            assert_eq!(le_u32(replayed.raw.bytes(), disk_offset(28))?, 0);
            assert_eq!(le_u16(replayed.raw.bytes(), disk_offset(116))?, 0);
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }

    /// # Panics
    /// Fails if metadata replay changes allocation, inode identity, attributes or repeated results.
    #[test]
    fn metadata_delta_replay_is_idempotent_and_preserves_storage() {
        let result = (|| -> Result<()> {
            let original = initialized_file(12)?;
            let mut encoded = memory::copied_slice(original.raw.bytes())?;
            put_le_u16(
                &mut encoded,
                disk_offset(INODE_MODE_OFFSET),
                MODE_REGULAR | 0o600,
            )?;
            let replayed =
                DeltaInodeImage::parse(&encoded, original.raw.bytes.len())?.restore(original)?;
            assert_eq!(mode(replayed.raw()), Ok(MODE_REGULAR | 0o600));
            let replayed =
                DeltaInodeImage::parse(&encoded, replayed.raw.bytes.len())?.restore(replayed)?;
            assert_eq!(replayed.raw.bytes(), encoded);
            let mut changed_mapping = memory::copied_slice(&encoded)?;
            *changed_mapping.get_mut(40).ok_or(Error::InvalidInode)? ^= 1;
            let root = memory::copied_slice(
                replayed
                    .raw
                    .bytes()
                    .get(40..100)
                    .ok_or(Error::InvalidInode)?,
            )?;
            let replayed = DeltaInodeImage::parse(&changed_mapping, replayed.raw.bytes.len())?
                .restore(replayed)?;
            assert_eq!(replayed.raw.bytes().get(40..100), Some(root.as_slice()));
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }

    /// # Errors
    /// Returns fixture construction or timestamp encoding failure.
    /// # Panics
    /// Fails if timestamp updates overwrite xattrs or lose declared epoch/precision.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions compare preserved xattr bytes and independent timestamp fields"
    )]
    fn timestamp_updates_preserve_the_declared_xattr_boundary() -> Result<()> {
        let mut record = raw_record(11)?;
        record.bytes = memory::repeated_vec(0_u8, 256)?;
        put_le_u16(&mut record.bytes, disk_offset(128), 4)?;
        put_le_u32(&mut record.bytes, disk_offset(132), 0xea02_0000)?;
        let original = memory::copied_slice(record.bytes.get(132..).ok_or(Error::InvalidInode)?)?;
        record.touch_contents(Ext4Timestamp::new(100, 123)?)?;
        assert_eq!(record.bytes.get(132..), Some(original.as_slice()));
        put_le_u16(&mut record.bytes, disk_offset(128), 32)?;
        record.touch_contents(Ext4Timestamp::new(4_294_967_297, 1)?)?;
        assert_eq!(le_u32(&record.bytes, disk_offset(INODE_MTIME_OFFSET))?, 1);
        assert_eq!(
            le_u32(&record.bytes, disk_offset(INODE_MTIME_EXTRA_OFFSET))?,
            5
        );
        Ok(())
    }

    use super::*;
    use crate::disk_format::inode::{Ext4Gid, Ext4Uid};

    /// Builds an empty raw inode record for typestate tests.
    /// # Errors
    ///
    /// Returns an error when `value` is outside the inode-id domain.
    fn raw_record(value: u32) -> Result<RawInodeRecord<Vec<u8>>> {
        Ok(RawInodeRecord {
            id: InodeId::try_from(value)?,
            offset: ByteOffset::new(0),
            bytes: vec![0_u8; 128],
            encoding: InodeDataEncoding::new(
                crate::disk_format::inode::FileSizeEncoding::LargeFile,
                crate::disk_format::inode::DirectorySizeEncoding::LargeDirectory,
                crate::disk_format::inode::InodeBlockCountEncoding::HugeFile,
                block_size()?,
                crate::disk_format::inode::DirectoryLinkEncoding::Counted,
                false,
                false,
                false,
            ),
        })
    }

    fn owner() -> Ext4Owner {
        Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(1000))
    }

    /// Builds the default permissions used by inode-record tests.
    /// # Errors
    ///
    /// Returns an error when the fixed permission bits leave the ext4 permission domain.
    fn permissions() -> Result<Ext4Permissions> {
        Ext4Permissions::new(0o644)
    }

    fn now() -> Ext4Timestamp {
        Ext4Timestamp::from_seconds(7)
    }

    /// Builds the default 1024-byte test block size.
    /// # Errors
    ///
    /// Returns an error when the fixed superblock log is rejected by the block-size domain.
    fn block_size() -> Result<BlockSize> {
        BlockSize::from_superblock_log(0)
    }

    /// Reads the serialized mode field from a raw test record.
    /// # Errors
    ///
    /// Returns an error when the mode field is truncated.
    fn mode(record: &RawInodeRecord<Vec<u8>>) -> Result<u16> {
        le_u16(record.bytes(), disk_offset(INODE_MODE_OFFSET))
    }

    /// Reads the serialized link-count field from a raw test record.
    /// # Errors
    ///
    /// Returns an error when the link-count field is truncated.
    fn links(record: &RawInodeRecord<Vec<u8>>) -> Result<u16> {
        le_u16(record.bytes(), disk_offset(INODE_LINKS_COUNT_OFFSET))
    }

    /// Reads the serialized flags field from a raw test record.
    /// # Errors
    ///
    /// Returns an error when the flags field is truncated.
    fn flags(record: &RawInodeRecord<Vec<u8>>) -> Result<u32> {
        le_u32(record.bytes(), disk_offset(INODE_FLAGS_OFFSET))
    }

    /// Builds an initialized live file inode for typestate tests.
    /// # Errors
    ///
    /// Returns an error when raw record construction, allocation typestate transition, or file
    /// initialization rejects the fixed fixture values.
    fn initialized_file(value: u32) -> Result<LiveInodeRecord> {
        raw_record(value)?.into_allocated().initialize_file(
            NewFileMetadata::new(owner(), permissions()?),
            InodeFlags::from_u32(0),
            now(),
            block_size()?,
            InodeTimestampEncoding::LegacySeconds,
        )
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn allocated_inode_typestate_serializes_live_inode_kinds() {
        let file = initialized_file(11);
        assert!(file.is_ok());
        let Ok(file) = file else {
            return;
        };
        assert_eq!(
            mode(&file.raw).map(|mode| mode & MODE_KIND_MASK),
            Ok(MODE_REGULAR)
        );
        assert_eq!(links(&file.raw), Ok(1));
        assert_eq!(
            flags(&file.raw).map(|flags| flags & EXT4_EXTENTS_FL),
            Ok(EXT4_EXTENTS_FL)
        );

        let directory = raw_record(12).and_then(|record| {
            record.into_allocated().initialize_directory(
                NewDirectoryMetadata::new(owner(), permissions()?),
                InodeFlags::from_u32(0),
                now(),
                block_size()?,
                BlockAddress::new(8),
                FileAllocationSize::from_bytes(u64::from(block_size()?.bytes())),
                InodeTimestampEncoding::LegacySeconds,
            )
        });
        assert!(directory.is_ok());
        let Ok(mut directory) = directory else {
            return;
        };
        let indexed = directory.mark_indexed_directory();
        assert_eq!(indexed, Ok(()));
        if indexed.is_err() {
            return;
        }
        assert_eq!(
            mode(&directory.raw).map(|mode| mode & MODE_KIND_MASK),
            Ok(MODE_DIRECTORY)
        );
        assert_eq!(links(&directory.raw), Ok(2));
        assert_eq!(
            flags(&directory.raw).map(|flags| flags & EXT4_INDEX_FL),
            Ok(EXT4_INDEX_FL)
        );

        let symlink = SymlinkTarget::new(b"target").and_then(|target| {
            raw_record(13)?.into_allocated().initialize_inline_symlink(
                NewSymlinkMetadata::new(owner(), permissions()?),
                InodeFlags::from_u32(0),
                now(),
                &target,
                InodeTimestampEncoding::LegacySeconds,
            )
        });
        assert!(symlink.is_ok());
        let Ok(symlink) = symlink else {
            return;
        };
        assert_eq!(
            mode(&symlink.raw).map(|mode| mode & MODE_KIND_MASK),
            Ok(MODE_SYMLINK)
        );
        assert_eq!(links(&symlink.raw), Ok(1));
        assert_eq!(flags(&symlink.raw), Ok(0));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn live_inode_link_typestate_serializes_deleted_state() {
        let file = initialized_file(14);
        assert!(file.is_ok());
        let Ok(mut file) = file else {
            return;
        };
        assert_eq!(file.increment_links_count(), Ok(()));
        assert_eq!(
            file.decrement_links_count(),
            Ok(LinkCountAfterDecrement::StillLinked(Ext4LinkCount::ONE))
        );
        assert_eq!(links(&file.raw), Ok(1));

        assert_eq!(
            file.decrement_links_count(),
            Ok(LinkCountAfterDecrement::Unlinked)
        );
        let deleted = block_size().and_then(|block_size| file.delete(now(), block_size));
        assert!(deleted.is_ok());
        let Ok(deleted) = deleted else {
            return;
        };
        assert_eq!(
            mode(&deleted.raw).map(|mode| mode & MODE_KIND_MASK),
            Ok(MODE_REGULAR)
        );
        assert_eq!(links(&deleted.raw), Ok(0));
        assert_eq!(
            flags(&deleted.raw).map(|flags| flags & EXT4_EXTENTS_FL),
            Ok(EXT4_EXTENTS_FL)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn sector_allocation_encoding_clears_stale_huge_file_state() {
        let record = raw_record(15);
        assert!(record.is_ok());
        let Ok(mut record) = record else {
            return;
        };
        assert_eq!(
            record.set_flags(InodeFlags::from_u32(0).with_huge_file_blocks()),
            Ok(())
        );
        assert_eq!(
            put_le_u16(
                &mut record.bytes,
                disk_offset(INODE_BLOCKS_HIGH_OFFSET),
                u16::MAX,
            ),
            Ok(())
        );
        let encoded = record
            .encoding
            .encode_allocation_size(FileAllocationSize::from_bytes(1024));
        assert!(encoded.is_ok());
        let Ok(encoded) = encoded else {
            return;
        };
        assert_eq!(record.set_encoded_allocation_size(encoded), Ok(()));
        assert_eq!(
            record.flags().map(|flags| flags.has_huge_file_blocks()),
            Ok(false)
        );
        assert_eq!(
            le_u16(record.bytes(), disk_offset(INODE_BLOCKS_HIGH_OFFSET)),
            Ok(0)
        );
    }

    /// # Errors
    ///
    /// Returns an inode construction or encoding error.
    /// # Panics
    ///
    /// Panics if one metadata snapshot mixes or omits fields from its coherent inode view.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture failures use Result; assertions verify inode observations"
    )]
    fn metadata_snapshot_preserves_one_complete_inode_view() -> Result<()> {
        let mut record = initialized_file(16)?;
        let eof = FileSize::from_bytes((1_u64 << 32) + 17);
        let charge = FileAllocationSize::from_bytes(4_096);
        record.set_encoded_size(record.raw.encoding.encode_file_size(eof)?)?;
        record.set_encoded_allocation_size(record.raw.encoding.encode_allocation_size(charge)?)?;
        let inode = record.parse()?;
        let snapshot = NodeMetadataSnapshot::from_inode(&inode);
        assert_eq!(snapshot.node().file_index(), 16);
        assert_eq!(snapshot.size(), eof);
        assert_eq!(snapshot.allocation_size(), charge);
        assert_eq!(snapshot.security(), inode.security());
        assert_eq!(snapshot.times(), inode.times());
        assert_eq!(snapshot.links_count(), inode.links_count());
        assert_eq!(snapshot.data_policy(), crate::NodeDataPolicy::Writable);

        record.set_permissions(Ext4Permissions::new(0o444)?)?;
        record.mark_verity()?;
        let verified = NodeMetadataSnapshot::from_inode(&record.parse()?);
        assert_eq!(verified.data_policy(), crate::NodeDataPolicy::ReadOnly);
        assert_eq!(snapshot.data_policy(), crate::NodeDataPolicy::Writable);
        Ok(())
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn resize_inode_block_map_accepts_only_the_reserved_double_indirect_shape() {
        const DOUBLE_INDIRECT_OFFSET: usize = 92;
        let record = raw_record(7);
        assert!(record.is_ok());
        let Ok(mut record) = record else {
            return;
        };
        assert_eq!(
            put_le_u32(
                &mut record.bytes,
                disk_offset(DOUBLE_INDIRECT_OFFSET),
                17_432,
            ),
            Ok(())
        );
        assert_eq!(
            record.resize_inode_block_map(),
            Ok(ResizeInodeBlockMap {
                double_indirect: BlockAddress::new(17_432),
            })
        );

        assert_eq!(
            put_le_u32(&mut record.bytes, disk_offset(INODE_BLOCK_OFFSET), 1),
            Ok(())
        );
        assert_eq!(
            record.resize_inode_block_map(),
            Err(Error::UnsupportedBlockMap)
        );
    }
}

/// Allocated recovery state; the unlinked variant never grants ordinary live-inode access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RecoverableOrphanInode {
    /// All storage must be released before the inode bitmap can be cleared.
    Unlinked(RawInodeRecord<Vec<u8>>),
    /// Namespace links remain; only allocation beyond persisted EOF may be removed.
    Truncating(LiveInodeRecord),
}

impl RecoverableOrphanInode {
    /// Validates the inode storage and chooses the recovery operation from its persistent links.
    /// # Errors
    /// Returns an error for unsupported mappings, invalid linked kinds, or malformed records.
    pub(super) fn parse(raw: RawInodeRecord<Vec<u8>>) -> Result<Self> {
        let data = InodeData::parse(raw.id, &raw.bytes, raw.encoding)?;
        if matches!(data.storage(), InodeStorage::UnsupportedBlockMap) {
            return Err(Error::UnsupportedBlockMap);
        }
        if le_u16(&raw.bytes, disk_offset(INODE_LINKS_COUNT_OFFSET))? == 0 {
            Ok(Self::Unlinked(raw))
        } else {
            if data.kind() != InodeKind::File || data.protection().is_verity() {
                return Err(Error::InvalidOrphanTracking);
            }
            Ok(Self::Truncating(raw.into_live()?))
        }
    }

    /// Copies restart-local bytes without copying recovery authority outside the owning pass.
    /// # Errors
    /// Returns an allocation error.
    fn try_clone(&self) -> Result<Self> {
        Self::parse(self.raw().try_clone_record()?)
    }

    /// Current raw image, including the legacy next pointer while cleanup is incomplete.
    pub(super) const fn raw(&self) -> &RawInodeRecord<Vec<u8>> {
        match self {
            Self::Unlinked(raw) => raw,
            Self::Truncating(live) => &live.raw,
        }
    }

    /// Mutation is confined to the owning recovery pass.
    pub(super) fn raw_mut(&mut self) -> &mut RawInodeRecord<Vec<u8>> {
        match self {
            Self::Unlinked(raw) => raw,
            Self::Truncating(live) => &mut live.raw,
        }
    }

    /// Reads current storage facts without creating live access for an unlinked inode.
    /// # Errors
    /// Returns an error if a staged field is malformed.
    pub(super) fn data(&self) -> Result<InodeData> {
        InodeData::parse(self.raw().id, &self.raw().bytes, self.raw().encoding)
    }

    /// Ends tracking only after the caller has removed the matching persistent entry atomically.
    /// # Errors
    /// Returns an error for malformed terminal storage or inode serialization.
    pub(super) fn finish(self) -> Result<StagedInodeRecord> {
        match self {
            Self::Truncating(mut live) => {
                live.raw.set_deletion_time(0)?;
                Ok(StagedInodeRecord::Live(live))
            }
            Self::Unlinked(mut raw) => {
                // Recovery has no wall-clock authority. Preserve the unlink event's recorded
                // change time as the nonzero freed-inode marker, never a chain successor.
                let deletion_time = le_u32(&raw.bytes, disk_offset(INODE_CTIME_OFFSET))?.max(1);
                raw.set_deletion_time(deletion_time)?;
                let size = match InodeData::parse(raw.id, &raw.bytes, raw.encoding)?.kind() {
                    InodeKind::Directory => raw
                        .encoding
                        .encode_directory_size(DirectorySize::from_bytes(0))?,
                    InodeKind::File | InodeKind::Symlink => {
                        raw.encoding.encode_file_size(FileSize::from_bytes(0))?
                    }
                };
                raw.set_encoded_size(size)?;
                raw.set_encoded_allocation_size(
                    raw.encoding
                        .encode_allocation_size(FileAllocationSize::from_bytes(0))?,
                )?;
                raw.set_xattr_block(None)?;
                Ok(StagedInodeRecord::Deleted(DeletedInodeRecord { raw }))
            }
        }
    }
}

impl<Bytes: AsRef<[u8]>> RawInodeRecord<Bytes> {
    /// Borrows the declared inode-body attribute region under either owned or read-ahead storage.
    /// # Errors
    /// Rejects truncated or out-of-record extra-field declarations.
    pub(super) fn inline_xattr_region(&self) -> Result<&[u8]> {
        let offset = InodeRecordLayout::parse(self.bytes.as_ref())?.xattr_offset();
        self.bytes.as_ref().get(offset..).ok_or(Error::InvalidXattr)
    }

    /// Authenticates persisted inode bytes before interpreting ownership or storage.
    /// # Errors
    /// Returns a checksum mismatch or a malformed record error; no bytes are modified.
    pub(super) fn verify_checksum(&self, superblock: &Superblock) -> Result<()> {
        if superblock.metadata_checksum() != MetadataChecksum::Crc32c {
            return Ok(());
        }
        let (mut expected, high) = self.checksum(superblock)?;
        let mut stored = u32::from(le_u16(
            self.bytes.as_ref(),
            disk_offset(INODE_CHECKSUM_LO_OFFSET),
        )?);
        if high {
            stored |= u32::from(le_u16(
                self.bytes.as_ref(),
                disk_offset(INODE_CHECKSUM_HI_OFFSET),
            )?) << 16;
        } else {
            expected &= u32::from(u16::MAX);
        }
        if stored == expected {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Calculates the inode CRC with only checksum fields excluded, preserving extra-isize.
    /// # Errors
    /// Returns an error for a truncated or out-of-range extra-inode layout.
    fn checksum(&self, superblock: &Superblock) -> Result<(u32, bool)> {
        let high =
            InodeRecordLayout::parse(self.bytes.as_ref())?.contains(INODE_CHECKSUM_HI_OFFSET, 2);
        let seed = ext4_crc32c(
            superblock.checksum_seed().as_u32(),
            &self.id.as_u32().to_le_bytes(),
        );
        let seed = ext4_crc32c(
            seed,
            &le_u32(self.bytes.as_ref(), disk_offset(INODE_GENERATION_OFFSET))?.to_le_bytes(),
        );
        let mut checksum = ext4_crc32c(
            seed,
            self.bytes
                .as_ref()
                .get(..124)
                .ok_or(Error::TruncatedStructure)?,
        );
        checksum = ext4_crc32c(checksum, &[0, 0]);
        if high {
            checksum = ext4_crc32c(
                checksum,
                self.bytes
                    .as_ref()
                    .get(126..130)
                    .ok_or(Error::TruncatedStructure)?,
            );
            checksum = ext4_crc32c(checksum, &[0, 0]);
            checksum = ext4_crc32c(
                checksum,
                self.bytes
                    .as_ref()
                    .get(132..)
                    .ok_or(Error::TruncatedStructure)?,
            );
        } else {
            checksum = ext4_crc32c(
                checksum,
                self.bytes
                    .as_ref()
                    .get(126..)
                    .ok_or(Error::TruncatedStructure)?,
            );
        }
        Ok((checksum, high))
    }

    /// Returns the raw inode mode field without imposing a supported kind.
    /// # Errors
    ///
    /// Returns an error when the inode mode field is not fully present.
    pub(super) fn mode(&self) -> Result<u16> {
        le_u16(self.bytes.as_ref(), disk_offset(INODE_MODE_OFFSET))
    }

    /// Returns whether the raw inode advertises an extent tree.
    /// # Errors
    ///
    /// Returns an error when `i_flags` is truncated before the extent-tree bit can be read.
    pub(super) fn has_extent_tree(&self) -> Result<bool> {
        Ok(self.flags()?.has_extent_tree())
    }

    /// Parses the fixed legacy block-map shape used by ext4's reserved resize inode.
    /// # Errors
    ///
    /// Returns an error when any direct, single-indirect, or triple-indirect slot is nonzero, or the
    /// required double-indirect slot is zero or truncated.
    pub(super) fn resize_inode_block_map(&self) -> Result<ResizeInodeBlockMap> {
        const DOUBLE_INDIRECT_INDEX: usize = 13;
        const TRIPLE_INDIRECT_INDEX: usize = 14;
        for index in 0..DOUBLE_INDIRECT_INDEX {
            if self.legacy_block_pointer(index)?.get() != 0 {
                return Err(Error::UnsupportedBlockMap);
            }
        }
        let double_indirect = self.legacy_block_pointer(DOUBLE_INDIRECT_INDEX)?;
        if double_indirect.get() == 0
            || self.legacy_block_pointer(TRIPLE_INDIRECT_INDEX)?.get() != 0
        {
            return Err(Error::UnsupportedBlockMap);
        }
        Ok(ResizeInodeBlockMap { double_indirect })
    }

    /// Reads one legacy `i_block` pointer by slot index.
    /// # Errors
    ///
    /// Returns an error when slot offset arithmetic overflows or the inode block field is truncated.
    fn legacy_block_pointer(&self, index: usize) -> Result<BlockAddress> {
        let offset = index
            .checked_mul(core::mem::size_of::<u32>())
            .and_then(|value| value.checked_add(INODE_BLOCK_OFFSET))
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(BlockAddress::new(u64::from(le_u32(
            self.bytes.as_ref(),
            disk_offset(offset),
        )?)))
    }

    /// Parses the raw bytes as a validated inode.
    /// # Errors
    ///
    /// Returns an error when required inode fields are truncated or encode an unsupported inode
    /// layout.
    pub(super) fn parse(&self) -> Result<Inode> {
        Inode::parse(self.id, self.bytes.as_ref(), self.encoding)
    }

    /// Reads the inode flags field.
    /// # Errors
    ///
    /// Returns an error when `i_flags` is truncated.
    pub(super) fn flags(&self) -> Result<InodeFlags> {
        Ok(InodeFlags::from_u32(le_u32(
            self.bytes.as_ref(),
            disk_offset(INODE_FLAGS_OFFSET),
        )?))
    }

    /// Returns the external xattr block referenced by `i_file_acl`.
    /// # Errors
    ///
    /// Returns an error when the present low or high `i_file_acl` field is truncated.
    pub(super) fn xattr_block(&self) -> Result<Option<BlockAddress>> {
        if self.bytes.as_ref().len() <= INODE_FILE_ACL_LO_OFFSET {
            return Ok(None);
        }
        let low = u64::from(le_u32(
            self.bytes.as_ref(),
            disk_offset(INODE_FILE_ACL_LO_OFFSET),
        )?);
        let high = if self.bytes.as_ref().len() > INODE_FILE_ACL_HI_OFFSET {
            u64::from(le_u16(
                self.bytes.as_ref(),
                disk_offset(INODE_FILE_ACL_HI_OFFSET),
            )?)
        } else {
            0
        };
        let block = low | (high << 32);
        if block == 0 {
            Ok(None)
        } else {
            Ok(Some(BlockAddress::new(block)))
        }
    }
}
