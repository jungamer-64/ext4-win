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
    pub(super) fn into_live(self) -> Result<LiveInodeRecord> {
        let _inode = self.parse()?;
        Ok(LiveInodeRecord { raw: self })
    }
}

impl AllocatedInodeRecord {
    /// Initializes this allocation as an empty extent-backed file.
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
    pub(super) fn initialize_directory(
        mut self,
        metadata: NewDirectoryMetadata,
        now: Ext4Timestamp,
        block_size: BlockSize,
        first_block: BlockAddress,
        allocated_blocks: u64,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<LiveInodeRecord> {
        self.raw.initialize_directory(
            metadata,
            now,
            block_size,
            first_block,
            allocated_blocks,
            timestamp_encoding,
        )?;
        self.raw.into_live()
    }

    /// Initializes this allocation as an inline symbolic link.
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
    pub(super) fn parse(&self) -> Result<Inode> {
        self.raw.parse()
    }

    /// Marks this directory inode as HTree indexed.
    pub(super) fn mark_indexed_directory(&mut self) -> Result<()> {
        let flags = self.raw.flags()?;
        self.raw.set_flags(flags.with_indexed_directory())
    }

    /// Marks this regular file inode as fs-verity protected.
    pub(super) fn mark_verity(&mut self) -> Result<()> {
        let flags = self.raw.flags()?;
        self.raw.set_flags(flags.with_verity())
    }

    /// Marks this inode as fscrypt protected.
    pub(super) fn mark_encrypted(&mut self) -> Result<()> {
        let flags = self.raw.flags()?;
        self.raw.set_flags(flags.with_encryption())
    }

    /// Updates owner fields.
    pub(super) fn set_owner(&mut self, owner: Ext4Owner) -> Result<()> {
        self.raw.set_owner(owner)
    }

    /// Updates permission bits without changing the inode kind.
    pub(super) fn set_permissions(&mut self, permissions: Ext4Permissions) -> Result<()> {
        self.raw.set_permissions(permissions)
    }

    /// Updates access, change, and modification timestamps.
    pub(super) fn set_timestamps(
        &mut self,
        now: Ext4Timestamp,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.raw.set_timestamps(now, timestamp_encoding)
    }

    /// Writes explicit ext4 inode timestamps.
    pub(super) fn set_ext4_times(
        &mut self,
        times: Ext4Times,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.raw.set_ext4_times(times, timestamp_encoding)
    }

    /// Updates file size fields.
    pub(super) fn set_size(&mut self, size: FileSize) -> Result<()> {
        self.raw.set_size(size)
    }

    /// Writes serialized extent root bytes.
    pub(super) fn set_extent_root_bytes(&mut self, root: &[u8; 60]) -> Result<()> {
        self.raw.set_extent_root_bytes(root)
    }

    /// Writes allocated sector counts.
    pub(super) fn set_allocated_blocks(&mut self, blocks: u64, block_size: u64) -> Result<()> {
        self.raw.set_allocated_blocks(blocks, block_size)
    }

    /// Returns the external xattr block referenced by this inode.
    pub(super) fn xattr_block(&self) -> Result<Option<BlockAddress>> {
        self.raw.xattr_block()
    }

    /// Writes the external xattr block reference.
    pub(super) fn set_xattr_block(&mut self, block: Option<BlockAddress>) -> Result<()> {
        self.raw.set_xattr_block(block)
    }

    /// Returns the in-inode xattr body region.
    pub(super) fn inline_xattr_region(&self) -> Result<&[u8]> {
        self.raw.inline_xattr_region()
    }

    /// Returns mutable in-inode xattr body storage.
    pub(super) fn writable_inline_xattr_region(&mut self) -> Result<&mut [u8]> {
        self.raw.writable_inline_xattr_region()
    }

    /// Clears the in-inode xattr body region.
    pub(super) fn clear_inline_xattr_region(&mut self) -> Result<()> {
        self.raw.clear_inline_xattr_region()
    }

    /// Increments link count.
    pub(super) fn increment_links_count(&mut self) -> Result<()> {
        let links = self.parse()?.links_count();
        self.raw.set_links_count(links.incremented()?)
    }

    /// Decrements link count and returns the resulting live/deletion boundary.
    pub(super) fn decrement_links_count(&mut self) -> Result<LinkCountAfterDecrement> {
        let links = self.parse()?.links_count();
        let boundary = links.decremented();
        if let LinkCountAfterDecrement::StillLinked(updated) = boundary {
            self.raw.set_links_count(updated)?;
        }
        Ok(boundary)
    }

    /// Serializes deletion state after final unlink.
    pub(super) fn delete(
        mut self,
        now: Ext4Timestamp,
        block_size: BlockSize,
    ) -> Result<DeletedInodeRecord> {
        self.raw.set_deletion_time(now.seconds())?;
        self.raw.set_deleted_links_count()?;
        self.raw.set_size(FileSize::from_bytes(0))?;
        self.raw.set_allocated_blocks(0, 1024)?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.raw.set_extent_root_bytes(serialized.inode_root())?;
        Ok(DeletedInodeRecord { raw: self.raw })
    }

    /// Serializes deletion state and refreshes timestamps for file final-unlink.
    pub(super) fn delete_and_touch(
        mut self,
        now: Ext4Timestamp,
        block_size: BlockSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<DeletedInodeRecord> {
        self.raw.set_deletion_time(now.seconds())?;
        self.raw.set_deleted_links_count()?;
        self.raw.set_size(FileSize::from_bytes(0))?;
        self.raw.set_allocated_blocks(0, 1024)?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.raw.set_extent_root_bytes(serialized.inode_root())?;
        self.raw.set_timestamps(now, timestamp_encoding)?;
        Ok(DeletedInodeRecord { raw: self.raw })
    }
}

impl StagedInodeRecord {
    /// Returns the staged inode id regardless of state.
    pub(super) const fn id(&self) -> InodeId {
        match self {
            Self::Live(record) => record.raw.id(),
            Self::Deleted(record) => record.raw.id(),
        }
    }

    /// Returns a live record clone or rejects deleted state.
    pub(super) fn clone_live(&self) -> Result<LiveInodeRecord> {
        match self {
            Self::Live(record) => Ok(record.clone()),
            Self::Deleted(_) => Err(Error::InvalidInode),
        }
    }

    /// Recomputes the inode checksum before writing this staged image.
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
    pub(super) fn mode(&self) -> Result<u16> {
        le_u16(&self.bytes, disk_offset(INODE_MODE_OFFSET))
    }

    /// Returns whether the raw inode advertises an extent tree.
    pub(super) fn has_extent_tree(&self) -> Result<bool> {
        Ok(self.flags()?.has_extent_tree())
    }

    /// Parses the raw bytes as a validated inode.
    pub(super) fn parse(&self) -> Result<Inode> {
        Inode::parse(self.id, &self.bytes)
    }

    /// Initializes a zeroed inode record as an empty extent-backed file.
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
        self.set_size(FileSize::from_bytes(0))?;
        self.set_links_count(Ext4LinkCount::ONE)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(InodeFlags::EMPTY.with_extent_tree())?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.set_extent_root_bytes(serialized.inode_root())?;
        self.set_allocated_blocks(0, 1024)
    }

    /// Initializes a zeroed inode record as a directory owning its first block.
    pub(super) fn initialize_directory(
        &mut self,
        metadata: NewDirectoryMetadata,
        now: Ext4Timestamp,
        block_size: BlockSize,
        first_block: BlockAddress,
        allocated_blocks: u64,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.bytes.fill(0);
        self.set_mode(InodeMode::directory(metadata.permissions()))?;
        self.set_owner(metadata.owner())?;
        self.set_size(FileSize::from_bytes(u64::from(block_size.bytes())))?;
        self.set_links_count(Ext4LinkCount::TWO)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(InodeFlags::EMPTY.with_extent_tree())?;
        let tree = MutableExtentTree::from_extents(vec![Extent::initialized(
            LogicalBlock::from_u32(0),
            ExtentLength::new(1)?,
            first_block,
        )])?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.set_extent_root_bytes(serialized.inode_root())?;
        self.set_allocated_blocks(allocated_blocks, u64::from(block_size.bytes()))
    }

    /// Initializes a zeroed inode record as an inline symbolic link.
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
        self.set_size(FileSize::from_bytes(
            u64::try_from(target.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
        ))?;
        self.set_links_count(Ext4LinkCount::ONE)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(InodeFlags::EMPTY)?;
        self.set_inline_target(target.bytes())?;
        self.set_allocated_blocks(0, 1024)
    }

    /// Initializes a zeroed inode record as an extent-backed symbolic link.
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
        self.set_size(FileSize::from_bytes(
            u64::try_from(target.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
        ))?;
        self.set_links_count(Ext4LinkCount::ONE)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(InodeFlags::EMPTY.with_extent_tree())?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.set_extent_root_bytes(serialized.inode_root())?;
        self.set_allocated_blocks(0, 1024)
    }

    /// Writes inode type and permission bits into `i_mode`.
    pub(super) fn set_mode(&mut self, mode: InodeMode) -> Result<()> {
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_MODE_OFFSET),
            mode.as_u16(),
        )
    }

    /// Updates inode permission bits without changing the inode type.
    pub(super) fn set_permissions(&mut self, permissions: Ext4Permissions) -> Result<()> {
        let mode = InodeMode::from_disk(le_u16(&self.bytes, disk_offset(INODE_MODE_OFFSET))?)?;
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_MODE_OFFSET),
            InodeMode::new(mode.kind(), permissions).as_u16(),
        )
    }

    /// Writes low and high UID/GID fields when the inode record can hold them.
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
    pub(super) fn set_links_count(&mut self, links: Ext4LinkCount) -> Result<()> {
        put_le_u16(
            &mut self.bytes,
            disk_offset(INODE_LINKS_COUNT_OFFSET),
            links.get(),
        )
    }

    /// Writes zero link count at the deleted-inode serialization boundary.
    pub(super) fn set_deleted_links_count(&mut self) -> Result<()> {
        put_le_u16(&mut self.bytes, disk_offset(INODE_LINKS_COUNT_OFFSET), 0)
    }

    /// Writes the inode flags field.
    pub(super) fn set_flags(&mut self, flags: InodeFlags) -> Result<()> {
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_FLAGS_OFFSET),
            flags.as_u32(),
        )
    }

    /// Reads the inode flags field.
    pub(super) fn flags(&self) -> Result<InodeFlags> {
        Ok(InodeFlags::from_u32(le_u32(
            &self.bytes,
            disk_offset(INODE_FLAGS_OFFSET),
        )?))
    }

    /// Splits a file size across low and high inode size fields.
    pub(super) fn set_size(&mut self, size: FileSize) -> Result<()> {
        let size = size.bytes();
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_SIZE_LO_OFFSET),
            u32::try_from(size & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_SIZE_HIGH_OFFSET),
            u32::try_from(size >> 32).map_err(|_| Error::ArithmeticOverflow)?,
        )
    }

    /// Updates access, change, and modification timestamps.
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
    pub(super) fn set_deletion_time(&mut self, seconds: u32) -> Result<()> {
        put_le_u32(&mut self.bytes, disk_offset(INODE_DTIME_OFFSET), seconds)
    }

    /// Writes the serialized extent root into `i_block`.
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
    pub(super) fn inline_xattr_region(&self) -> Result<&[u8]> {
        let offset = self.inline_xattr_offset()?;
        self.bytes.get(offset..).ok_or(Error::InvalidXattr)
    }

    /// Returns the mutable in-inode xattr body region, initializing extra inode
    /// size before new xattrs are written.
    pub(super) fn writable_inline_xattr_region(&mut self) -> Result<&mut [u8]> {
        self.ensure_extra_isize()?;
        let offset = self.inline_xattr_offset()?;
        self.bytes.get_mut(offset..).ok_or(Error::InvalidXattr)
    }

    /// Clears the in-inode xattr body region.
    pub(super) fn clear_inline_xattr_region(&mut self) -> Result<()> {
        self.writable_inline_xattr_region()?.fill(0);
        Ok(())
    }

    /// Computes the in-inode xattr body offset from `i_extra_isize`.
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

    /// Writes allocated 512-byte sector counts from allocated data blocks.
    pub(super) fn set_allocated_blocks(&mut self, blocks: u64, block_size: u64) -> Result<()> {
        let sectors = blocks
            .checked_mul(block_size)
            .ok_or(Error::ArithmeticOverflow)?
            .checked_div(512)
            .ok_or(Error::ArithmeticOverflow)?;
        put_le_u32(
            &mut self.bytes,
            disk_offset(INODE_BLOCKS_LO_OFFSET),
            u32::try_from(sectors & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if self.bytes.len() > INODE_BLOCKS_HIGH_OFFSET {
            put_le_u16(
                &mut self.bytes,
                disk_offset(INODE_BLOCKS_HIGH_OFFSET),
                u16::try_from((sectors >> 32) & u64::from(u16::MAX))
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(())
    }

    /// Recomputes inode checksum fields when metadata checksums are enabled.
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
        let seed = crc32c(
            superblock.checksum_seed().as_u32(),
            &self.id.as_u32().to_le_bytes(),
        );
        let seed = crc32c(
            seed,
            &le_u32(&self.bytes, disk_offset(INODE_GENERATION_OFFSET))?.to_le_bytes(),
        );
        let checksum = crc32c(seed, &self.bytes);
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
    use super::scope::*;
    use crate::disk_format::inode::{Ext4Gid, Ext4Uid};

    fn raw_record(value: u32) -> Result<RawInodeRecord> {
        Ok(RawInodeRecord {
            id: InodeId::try_from(value)?,
            offset: ByteOffset::new(0),
            bytes: vec![0_u8; 128],
        })
    }

    fn owner() -> Ext4Owner {
        Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(1000))
    }

    fn permissions() -> Result<Ext4Permissions> {
        Ext4Permissions::new(0o644)
    }

    fn now() -> Ext4Timestamp {
        Ext4Timestamp::from_unix_seconds(7)
    }

    fn block_size() -> Result<BlockSize> {
        BlockSize::from_superblock_log(0)
    }

    fn mode(record: &RawInodeRecord) -> Result<u16> {
        le_u16(record.bytes(), disk_offset(INODE_MODE_OFFSET))
    }

    fn links(record: &RawInodeRecord) -> Result<u16> {
        le_u16(record.bytes(), disk_offset(INODE_LINKS_COUNT_OFFSET))
    }

    fn flags(record: &RawInodeRecord) -> Result<u32> {
        le_u32(record.bytes(), disk_offset(INODE_FLAGS_OFFSET))
    }

    fn initialized_file(value: u32) -> Result<LiveInodeRecord> {
        raw_record(value)?.into_allocated().initialize_file(
            NewFileMetadata::new(owner(), permissions()?),
            now(),
            block_size()?,
            InodeTimestampEncoding::LegacySeconds,
        )
    }

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
                1,
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
}
