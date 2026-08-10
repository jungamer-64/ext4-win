//! Inode record typestates staged by mounted volume transactions.

use super::scope::*;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Raw inode record paired with its inode number and device offset.
pub(super) struct RawInodeRecord {
    /// Inode number represented by this raw record.
    pub(super) id: InodeId,
    /// Absolute device offset of the inode record.
    pub(super) offset: ByteOffset,
    /// Writable inode record bytes.
    pub(super) bytes: Vec<u8>,
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
    raw: RawInodeRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Allocated inode record with a nonzero link count and supported inode kind.
pub(super) struct LiveInodeRecord {
    /// Raw inode image owned by this typestate.
    raw: RawInodeRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Inode record staged after final unlink and deletion serialization.
pub(super) struct DeletedInodeRecord {
    /// Raw inode image owned by this typestate.
    raw: RawInodeRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Inode record staged for commit after a typed state transition.
pub(super) enum StagedInodeRecord {
    /// Live inode metadata rewrite.
    Live(LiveInodeRecord),
    /// Deleted inode cleanup rewrite.
    Deleted(DeletedInodeRecord),
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

impl From<DeletedInodeRecord> for StagedInodeRecord {
    fn from(record: DeletedInodeRecord) -> Self {
        Self::Deleted(record)
    }
}

impl RawInodeRecord {
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
    /// Initializes this allocation as an empty extent-backed file.
    /// # Errors
    ///
    /// Returns an error when file metadata, timestamps, an empty extent root, or sector counts
    /// cannot be serialized into the allocated inode record.
    pub(super) fn initialize_file(
        mut self,
        metadata: NewFileMetadata,
        now: Ext4Timestamp,
        block_size: BlockSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<LiveInodeRecord> {
        self.raw
            .initialize_file(metadata, now, block_size, timestamp_encoding)?;
        self.raw.into_live()
    }

    /// Initializes this allocation as a directory owning its first block.
    /// # Errors
    ///
    /// Returns an error when the directory extent for `first_block`, directory size, timestamps, or
    /// allocated sector count cannot be represented in the inode record.
    pub(super) fn initialize_directory(
        mut self,
        metadata: NewDirectoryMetadata,
        now: Ext4Timestamp,
        block_size: BlockSize,
        first_block: BlockAddress,
        allocation_size: FileAllocationSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<LiveInodeRecord> {
        self.raw.initialize_directory(
            metadata,
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
        now: Ext4Timestamp,
        target: &SymlinkTarget,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<LiveInodeRecord> {
        self.raw
            .initialize_inline_symlink(metadata, now, target, timestamp_encoding)?;
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
        now: Ext4Timestamp,
        block_size: BlockSize,
        target: &SymlinkTarget,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<LiveInodeRecord> {
        self.raw.initialize_extent_symlink(
            metadata,
            now,
            block_size,
            target,
            timestamp_encoding,
        )?;
        self.raw.into_live()
    }
}

impl LiveInodeRecord {
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
    /// Returns an error when the inode flags field cannot be read or rewritten with the verity bit
    /// set.
    pub(super) fn mark_verity(&mut self) -> Result<()> {
        let flags = self.raw.flags()?;
        self.raw.set_flags(flags.with_verity())
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

    /// Updates access, change, and modification timestamps.
    /// # Errors
    ///
    /// Returns an error when inode timestamp fields or required extra timestamp storage cannot be
    /// updated.
    pub(super) fn set_timestamps(
        &mut self,
        now: Ext4Timestamp,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.raw.set_timestamps(now, timestamp_encoding)
    }

    /// Writes explicit ext4 inode timestamps.
    /// # Errors
    ///
    /// Returns an error when any explicit ext4 timestamp field or required extra timestamp storage
    /// cannot be updated.
    pub(super) fn set_ext4_times(
        &mut self,
        times: Ext4Times,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.raw.set_ext4_times(times, timestamp_encoding)
    }

    /// Writes a file size already validated by the mounted inode encoding.
    /// # Errors
    ///
    /// Returns an error when either inode size field is not writable.
    pub(super) fn set_encoded_size(&mut self, size: EncodedInodeSize) -> Result<()> {
        self.raw.set_encoded_size(size)
    }

    /// Writes an allocation count already validated by the mounted inode encoding.
    /// # Errors
    ///
    /// Returns an error when block-count or inode-flag fields are not writable.
    pub(super) fn set_encoded_allocation_size(
        &mut self,
        block_count: EncodedInodeBlockCount,
    ) -> Result<()> {
        self.raw.set_encoded_allocation_size(block_count)
    }

    /// Writes serialized extent root bytes.
    /// # Errors
    ///
    /// Returns an error when the inode record does not contain the full `i_block` extent-root
    /// storage.
    pub(super) fn set_extent_root_bytes(&mut self, root: &[u8; 60]) -> Result<()> {
        self.raw.set_extent_root_bytes(root)
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
    /// Returns an error when the extra-inode size marker cannot be initialized or its xattr offset
    /// points outside this inode record.
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

    /// Increments link count.
    /// # Errors
    ///
    /// Returns an error when the inode cannot be parsed, the link count is saturated, or the updated
    /// count cannot be written.
    pub(super) fn increment_links_count(&mut self) -> Result<()> {
        let links = self.parse()?.links_count();
        self.raw.set_links_count(links.incremented()?)
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
        self.raw.set_deletion_time(now.seconds())?;
        self.raw.set_deleted_links_count()?;
        let size = self.raw.encoding.encode_size(FileSize::from_bytes(0))?;
        self.raw.set_encoded_size(size)?;
        let allocation_size = self
            .raw
            .encoding
            .encode_allocation_size(FileAllocationSize::from_bytes(0))?;
        self.raw.set_encoded_allocation_size(allocation_size)?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.raw.set_extent_root_bytes(serialized.inode_root())?;
        Ok(DeletedInodeRecord { raw: self.raw })
    }

    /// Serializes deletion state and refreshes timestamps for file final-unlink.
    /// # Errors
    ///
    /// Returns an error when deletion fields, refreshed timestamps, or the empty extent root cannot
    /// be serialized.
    pub(super) fn delete_and_touch(
        mut self,
        now: Ext4Timestamp,
        block_size: BlockSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<DeletedInodeRecord> {
        self.raw.set_deletion_time(now.seconds())?;
        self.raw.set_deleted_links_count()?;
        let size = self.raw.encoding.encode_size(FileSize::from_bytes(0))?;
        self.raw.set_encoded_size(size)?;
        let allocation_size = self
            .raw
            .encoding
            .encode_allocation_size(FileAllocationSize::from_bytes(0))?;
        self.raw.set_encoded_allocation_size(allocation_size)?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.raw.set_extent_root_bytes(serialized.inode_root())?;
        self.raw.set_timestamps(now, timestamp_encoding)?;
        Ok(DeletedInodeRecord { raw: self.raw })
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
            Self::Deleted(record) => Self::Deleted(DeletedInodeRecord {
                raw: record.raw.try_clone_record()?,
            }),
        })
    }

    /// Returns the staged inode id regardless of state.
    pub(super) const fn id(&self) -> InodeId {
        match self {
            Self::Live(record) => record.raw.id(),
            Self::Deleted(record) => record.raw.id(),
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
            Self::Deleted(_) => Err(Error::InvalidInode),
        }
    }

    /// Recomputes the inode checksum before writing this staged image.
    /// # Errors
    ///
    /// Returns an error when checksum fields or the inode generation field cannot be accessed.
    pub(super) fn refresh_checksum(&mut self, superblock: &Superblock) -> Result<()> {
        match self {
            Self::Live(record) => record.raw.refresh_checksum(superblock),
            Self::Deleted(record) => record.raw.refresh_checksum(superblock),
        }
    }

    /// Returns this staged image's device offset.
    pub(super) const fn offset(&self) -> ByteOffset {
        match self {
            Self::Live(record) => record.raw.offset(),
            Self::Deleted(record) => record.raw.offset(),
        }
    }

    /// Returns the serialized staged inode bytes.
    pub(super) fn bytes(&self) -> &[u8] {
        match self {
            Self::Live(record) => record.raw.bytes(),
            Self::Deleted(record) => record.raw.bytes(),
        }
    }
}

impl RawInodeRecord {
    /// Returns the raw inode mode field without imposing a supported kind.
    /// # Errors
    ///
    /// Returns an error when the inode mode field is not fully present.
    pub(super) fn mode(&self) -> Result<u16> {
        le_u16(&self.bytes, disk_offset(INODE_MODE_OFFSET))
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
            &self.bytes,
            disk_offset(offset),
        )?)))
    }

    /// Parses the raw bytes as a validated inode.
    /// # Errors
    ///
    /// Returns an error when required inode fields are truncated or encode an unsupported inode
    /// layout.
    pub(super) fn parse(&self) -> Result<Inode> {
        Inode::parse(self.id, &self.bytes, self.encoding)
    }

    /// Initializes a zeroed inode record as an empty extent-backed file.
    /// # Errors
    ///
    /// Returns an error when file metadata, timestamps, empty extent-root serialization, or sector
    /// count serialization fails.
    pub(super) fn initialize_file(
        &mut self,
        metadata: NewFileMetadata,
        now: Ext4Timestamp,
        block_size: BlockSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.bytes.fill(0);
        self.set_mode(InodeMode::regular_file(metadata.permissions()))?;
        self.set_owner(metadata.owner())?;
        let size = self.encoding.encode_size(FileSize::from_bytes(0))?;
        self.set_encoded_size(size)?;
        self.set_links_count(Ext4LinkCount::ONE)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(InodeFlags::EMPTY.with_extent_tree())?;
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
    pub(super) fn initialize_directory(
        &mut self,
        metadata: NewDirectoryMetadata,
        now: Ext4Timestamp,
        block_size: BlockSize,
        first_block: BlockAddress,
        allocation_size: FileAllocationSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.bytes.fill(0);
        self.set_mode(InodeMode::directory(metadata.permissions()))?;
        self.set_owner(metadata.owner())?;
        let size = self
            .encoding
            .encode_size(FileSize::from_bytes(u64::from(block_size.bytes())))?;
        self.set_encoded_size(size)?;
        self.set_links_count(Ext4LinkCount::TWO)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(InodeFlags::EMPTY.with_extent_tree())?;
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
        now: Ext4Timestamp,
        target: &SymlinkTarget,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        if !target.is_inline() {
            return Err(Error::InvalidWriteRange);
        }
        self.bytes.fill(0);
        self.set_mode(InodeMode::symlink(metadata.permissions()))?;
        self.set_owner(metadata.owner())?;
        let size = self.encoding.encode_size(FileSize::from_bytes(
            u64::try_from(target.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
        ))?;
        self.set_encoded_size(size)?;
        self.set_links_count(Ext4LinkCount::ONE)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(InodeFlags::EMPTY)?;
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
        now: Ext4Timestamp,
        block_size: BlockSize,
        target: &SymlinkTarget,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        if target.is_inline() {
            return Err(Error::InvalidWriteRange);
        }
        self.bytes.fill(0);
        self.set_mode(InodeMode::symlink(metadata.permissions()))?;
        self.set_owner(metadata.owner())?;
        let size = self.encoding.encode_size(FileSize::from_bytes(
            u64::try_from(target.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
        ))?;
        self.set_encoded_size(size)?;
        self.set_links_count(Ext4LinkCount::ONE)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(InodeFlags::EMPTY.with_extent_tree())?;
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
            links.get(),
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

    /// Reads the inode flags field.
    /// # Errors
    ///
    /// Returns an error when `i_flags` is truncated.
    pub(super) fn flags(&self) -> Result<InodeFlags> {
        Ok(InodeFlags::from_u32(le_u32(
            &self.bytes,
            disk_offset(INODE_FLAGS_OFFSET),
        )?))
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

    /// Updates access, change, and modification timestamps.
    /// # Errors
    ///
    /// Returns an error when base timestamp fields are truncated or extra timestamp storage cannot
    /// be initialized.
    pub(super) fn set_timestamps(
        &mut self,
        now: Ext4Timestamp,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_ATIME_OFFSET),
            now.seconds(),
        )?;
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_CTIME_OFFSET),
            now.seconds(),
        )?;
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_MTIME_OFFSET),
            now.seconds(),
        )?;
        match timestamp_encoding {
            InodeTimestampEncoding::LegacySeconds => {}
            InodeTimestampEncoding::ExtraFields => {
                if self.bytes.len() > INODE_ATIME_EXTRA_OFFSET {
                    self.ensure_extra_isize()?;
                    put_le_u32(&mut self.bytes, disk_offset(INODE_ATIME_EXTRA_OFFSET), 0)?;
                    put_le_u32(&mut self.bytes, disk_offset(INODE_CTIME_EXTRA_OFFSET), 0)?;
                    put_le_u32(&mut self.bytes, disk_offset(INODE_MTIME_EXTRA_OFFSET), 0)?;
                }
            }
        }
        Ok(())
    }

    /// Writes creation time when the inode record has extra timestamp fields.
    /// # Errors
    ///
    /// Returns an error when extra inode storage cannot be initialized or creation-time fields are
    /// not writable.
    pub(super) fn set_creation_time(
        &mut self,
        now: Ext4Timestamp,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        match timestamp_encoding {
            InodeTimestampEncoding::LegacySeconds => {}
            InodeTimestampEncoding::ExtraFields => {
                if self.bytes.len() > INODE_CRTIME_EXTRA_OFFSET {
                    self.ensure_extra_isize()?;
                    put_le_u32(
                        &mut self.bytes,
                        disk_offset(INODE_CRTIME_OFFSET),
                        now.seconds(),
                    )?;
                    put_le_u32(&mut self.bytes, disk_offset(INODE_CRTIME_EXTRA_OFFSET), 0)?;
                }
            }
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
        self.bytes
            .get_mut(INODE_BLOCK_OFFSET..end)
            .ok_or(Error::TruncatedStructure)?
            .copy_from_slice(root);
        Ok(())
    }

    /// Writes explicit ext4 inode timestamps.
    /// # Errors
    ///
    /// Returns an error when explicit timestamp fields or optional extra timestamp fields are not
    /// writable.
    pub(super) fn set_ext4_times(
        &mut self,
        times: Ext4Times,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_ATIME_OFFSET),
            times.accessed().seconds(),
        )?;
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_CTIME_OFFSET),
            times.changed().seconds(),
        )?;
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_MTIME_OFFSET),
            times.modified().seconds(),
        )?;
        match timestamp_encoding {
            InodeTimestampEncoding::LegacySeconds => {}
            InodeTimestampEncoding::ExtraFields => {
                if self.bytes.len() > INODE_ATIME_EXTRA_OFFSET {
                    self.ensure_extra_isize()?;
                    put_le_u32(&mut self.bytes, disk_offset(INODE_ATIME_EXTRA_OFFSET), 0)?;
                    put_le_u32(&mut self.bytes, disk_offset(INODE_CTIME_EXTRA_OFFSET), 0)?;
                    put_le_u32(&mut self.bytes, disk_offset(INODE_MTIME_EXTRA_OFFSET), 0)?;
                }
            }
        }
        self.set_creation_time(times.created(), timestamp_encoding)
    }

    /// Returns the external xattr block referenced by `i_file_acl`.
    /// # Errors
    ///
    /// Returns an error when the present low or high `i_file_acl` field is truncated.
    pub(super) fn xattr_block(&self) -> Result<Option<BlockAddress>> {
        if self.bytes.len() <= INODE_FILE_ACL_LO_OFFSET {
            return Ok(None);
        }
        let low = u64::from(le_u32(&self.bytes, disk_offset(INODE_FILE_ACL_LO_OFFSET))?);
        let high = if self.bytes.len() > INODE_FILE_ACL_HI_OFFSET {
            u64::from(le_u16(&self.bytes, disk_offset(INODE_FILE_ACL_HI_OFFSET))?)
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

    /// Returns the in-inode xattr body region.
    /// # Errors
    ///
    /// Returns an error when `i_extra_isize` is truncated or resolves beyond the inode record.
    pub(super) fn inline_xattr_region(&self) -> Result<&[u8]> {
        let offset = self.inline_xattr_offset()?;
        self.bytes.get(offset..).ok_or(Error::InvalidXattr)
    }

    /// Returns the mutable in-inode xattr body region, initializing extra inode
    /// size before new xattrs are written.
    /// # Errors
    ///
    /// Returns an error when `i_extra_isize` cannot be initialized or resolves beyond the inode
    /// record.
    pub(super) fn writable_inline_xattr_region(&mut self) -> Result<&mut [u8]> {
        self.ensure_extra_isize()?;
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
        if self.bytes.len() <= INODE_EXTRA_ISIZE_OFFSET {
            return Ok(self.bytes.len());
        }
        let offset = 128_usize
            .checked_add(usize::from(le_u16(
                &self.bytes,
                disk_offset(INODE_EXTRA_ISIZE_OFFSET),
            )?))
            .ok_or(Error::ArithmeticOverflow)?;
        if offset > self.bytes.len() {
            return Err(Error::InvalidXattr);
        }
        Ok(offset)
    }

    /// Writes an inline symbolic link target into `i_block`.
    /// # Errors
    ///
    /// Returns an error when `target` exceeds inline capacity or the `i_block` storage is truncated.
    pub(super) fn set_inline_target(&mut self, target: &[u8]) -> Result<()> {
        if target.len() > SymlinkTarget::INLINE_CAPACITY {
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
        block
            .get_mut(..target.len())
            .ok_or(Error::DeviceRange)?
            .copy_from_slice(target);
        Ok(())
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
        if self.bytes.len() <= INODE_CHECKSUM_LO_OFFSET {
            return Ok(());
        }
        self.ensure_extra_isize()?;
        put_le_u16(&mut self.bytes, disk_offset(INODE_CHECKSUM_LO_OFFSET), 0)?;
        if self.bytes.len() > INODE_CHECKSUM_HI_OFFSET {
            put_le_u16(&mut self.bytes, disk_offset(INODE_CHECKSUM_HI_OFFSET), 0)?;
        }
        let seed = ext4_crc32c(
            superblock.checksum_seed().as_u32(),
            &self.id.as_u32().to_le_bytes(),
        );
        let seed = ext4_crc32c(
            seed,
            &le_u32(&self.bytes, disk_offset(INODE_GENERATION_OFFSET))?.to_le_bytes(),
        );
        let checksum = ext4_crc32c(seed, &self.bytes);
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_CHECKSUM_LO_OFFSET),
            u16::try_from(checksum & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if self.bytes.len() > INODE_CHECKSUM_HI_OFFSET {
            put_le_u16(
                &mut self.bytes,
                disk_offset(INODE_CHECKSUM_HI_OFFSET),
                u16::try_from(checksum >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(())
    }

    /// Ensures the inode advertises enough extra space for extended fields.
    /// # Errors
    ///
    /// Returns an error when the `i_extra_isize` field is present but cannot be read or initialized.
    pub(super) fn ensure_extra_isize(&mut self) -> Result<()> {
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
    use super::*;
    use crate::disk_format::inode::{Ext4Gid, Ext4Uid};

    /// Builds an empty raw inode record for typestate tests.
    /// # Errors
    ///
    /// Returns an error when `value` is outside the inode-id domain.
    fn raw_record(value: u32) -> Result<RawInodeRecord> {
        Ok(RawInodeRecord {
            id: InodeId::try_from(value)?,
            offset: ByteOffset::new(0),
            bytes: vec![0_u8; 128],
            encoding: InodeDataEncoding::new(
                crate::disk_format::inode::FileSizeEncoding::LargeFile,
                crate::disk_format::inode::InodeBlockCountEncoding::HugeFile,
                block_size()?,
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
        Ext4Timestamp::from_unix_seconds(7)
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
    fn mode(record: &RawInodeRecord) -> Result<u16> {
        le_u16(record.bytes(), disk_offset(INODE_MODE_OFFSET))
    }

    /// Reads the serialized link-count field from a raw test record.
    /// # Errors
    ///
    /// Returns an error when the link-count field is truncated.
    fn links(record: &RawInodeRecord) -> Result<u16> {
        le_u16(record.bytes(), disk_offset(INODE_LINKS_COUNT_OFFSET))
    }

    /// Reads the serialized flags field from a raw test record.
    /// # Errors
    ///
    /// Returns an error when the flags field is truncated.
    fn flags(record: &RawInodeRecord) -> Result<u32> {
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
        let deleted = block_size().and_then(|block_size| {
            file.delete_and_touch(now(), block_size, InodeTimestampEncoding::LegacySeconds)
        });
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
            record.set_flags(InodeFlags::EMPTY.with_huge_file_blocks()),
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
