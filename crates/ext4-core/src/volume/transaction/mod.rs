//! Journaled write transaction domain for mounted ext4 volumes.

use super::*;

mod commit;
mod staging;
mod xattr;

use commit::{
    descriptor_byte_count, directory_entry_kind, map_extents, reject_reserved_directory_name,
    verity_metadata_image,
};
pub(crate) use staging::MetadataBlock;
use staging::{BlockImage, EncryptedBlockBase, GroupDelta, RangeWrite};

/// Regular file selected for mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionFile {
    /// Mutable regular-file inode selected for this transaction.
    id: FileNodeId,
}

impl TransactionFile {
    /// Typed inode identifier backing this transaction file.
    #[must_use]
    pub const fn id(self) -> FileNodeId {
        self.id
    }

    /// Raw inode backing this transaction file.
    const fn inode(self) -> InodeId {
        self.id.inode()
    }
}

/// Directory selected for mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionDirectory {
    /// Mutable directory inode selected for this transaction.
    id: DirectoryNodeId,
}

impl TransactionDirectory {
    /// Typed inode identifier backing this transaction directory.
    #[must_use]
    pub const fn id(self) -> DirectoryNodeId {
        self.id
    }

    /// Raw inode backing this transaction directory.
    const fn inode(self) -> InodeId {
        self.id.inode()
    }
}

/// Symbolic link selected for mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionSymlink {
    /// Mutable symbolic-link inode selected for this transaction.
    id: SymlinkNodeId,
}

impl TransactionSymlink {
    /// Typed inode identifier backing this transaction symlink.
    #[must_use]
    pub const fn id(self) -> SymlinkNodeId {
        self.id
    }
}

/// Inode selected for POSIX metadata mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionNode {
    /// Mutable inode selected for metadata updates.
    id: NodeId,
}

impl TransactionNode {
    /// Typed inode identifier backing this transaction node.
    #[must_use]
    pub const fn id(self) -> NodeId {
        self.id
    }

    /// Raw inode backing this transaction node.
    const fn inode(self) -> InodeId {
        self.id.inode()
    }
}

/// In-progress ext4 write transaction.
#[derive(Debug)]
pub struct JournalTransaction<'a, D: BlockWriter, J = InternalJournal, N = FscryptNoNonceGenerator>
{
    /// Mounted read-write volume being mutated.
    volume: &'a mut MountedVolume<D, JournaledMount<J>, N>,
    /// Timestamp applied consistently to staged inode updates.
    now: Ext4Timestamp,
    /// Inode records staged for rewrite at commit.
    inode_updates: Vec<StagedInodeRecord>,
    /// Block bitmap images staged for allocation changes.
    block_bitmap_updates: Vec<BlockImage>,
    /// Inode bitmap images staged for allocation changes.
    inode_bitmap_updates: Vec<BlockImage>,
    /// Directory block images staged after dirent mutation.
    directory_updates: Vec<BlockImage>,
    /// External extent tree blocks staged after extent mutation.
    extent_updates: Vec<BlockImage>,
    /// External xattr blocks staged after xattr mutation.
    xattr_updates: Vec<BlockImage>,
    /// Per-group allocation count deltas to fold into descriptors.
    group_deltas: Vec<GroupDelta>,
    /// Ordered file data writes that must reach disk before metadata commit.
    data_writes: Vec<RangeWrite>,
    /// Staged cluster-reference changes to apply after journal commit.
    cluster_deltas: Vec<ClusterReferenceDelta>,
    /// Superblock free-cluster delta accumulated by this transaction.
    free_clusters_delta: FreeClusterDelta,
    /// Superblock free-inode delta accumulated by this transaction.
    free_inodes_delta: i64,
    /// Superblock volume label replacement staged by this transaction.
    volume_label_update: Option<Ext4VolumeLabel>,
}

impl<'a, D: BlockWriter, J, N> JournalTransaction<'a, D, J, N> {
    /// Starts an empty journal transaction for a mounted read-write volume.
    pub(super) fn begin(
        volume: &'a mut MountedVolume<D, JournaledMount<J>, N>,
        now: Ext4Timestamp,
    ) -> Self {
        Self {
            volume,
            now,
            inode_updates: Vec::new(),
            block_bitmap_updates: Vec::new(),
            inode_bitmap_updates: Vec::new(),
            directory_updates: Vec::new(),
            extent_updates: Vec::new(),
            xattr_updates: Vec::new(),
            group_deltas: Vec::new(),
            data_writes: Vec::new(),
            cluster_deltas: Vec::new(),
            free_clusters_delta: FreeClusterDelta::ZERO,
            free_inodes_delta: 0,
            volume_label_update: None,
        }
    }
}
impl<D: BlockWriter, J, N: FscryptNonceGenerator> JournalTransaction<'_, D, J, N> {
    /// Verifies that the mounted profile admits xattr storage mutation.
    fn require_xattr_mutation(&self) -> Result<()> {
        self.volume.superblock.xattr_mutation().require_supported()
    }

    /// Verifies that an inode size is representable by the mounted profile.
    fn require_inode_size_supported(&self, size: FileSize) -> Result<()> {
        self.volume
            .superblock
            .file_size_encoding()
            .require_supported(size.bytes(), LEGACY_FILE_SIZE_LIMIT)
    }

    /// Verifies that an inode block charge is representable by the mounted profile.
    fn require_allocated_blocks_supported(&self, blocks: u64) -> Result<()> {
        let sectors = blocks
            .checked_mul(u64::from(self.volume.superblock.block_size().bytes()))
            .ok_or(Error::ArithmeticOverflow)?
            .checked_div(512)
            .ok_or(Error::ArithmeticOverflow)?;
        self.volume
            .superblock
            .inode_block_count_encoding()
            .require_supported(sectors, LEGACY_I_BLOCKS_LIMIT)
    }

    /// Selects any supported inode for POSIX metadata mutation.
    ///
    /// # Errors
    /// Returns an error when the inode cannot be read or carries mutation
    /// semantics outside the write domain.
    pub fn node(&self, id: NodeId) -> Result<TransactionNode> {
        let inode = self.volume.read_inode_record(id.inode())?;
        let _metadata = inode.metadata_mutation()?;
        match (id, inode.kind()) {
            (NodeId::File(_), InodeKind::File)
            | (NodeId::Directory(_), InodeKind::Directory)
            | (NodeId::Symlink(_), InodeKind::Symlink) => Ok(TransactionNode { id }),
            _ => Err(Error::WrongInodeKind),
        }
    }

    /// Selects a regular file for mutation.
    ///
    /// # Errors
    /// Returns an error when the inode is not a regular file or cannot be read.
    pub fn file(&self, id: FileNodeId) -> Result<TransactionFile> {
        let inode = self.volume.read_inode_record(id.inode())?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        Ok(TransactionFile { id })
    }

    /// Selects a directory for mutation.
    ///
    /// # Errors
    /// Returns an error when the inode is not a directory or cannot be read.
    pub fn directory(&self, id: DirectoryNodeId) -> Result<TransactionDirectory> {
        let inode = self.volume.read_inode_record(id.inode())?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        Ok(TransactionDirectory { id })
    }

    /// Selects a symbolic link for mutation.
    ///
    /// # Errors
    /// Returns an error when the inode is not a symbolic link or carries
    /// mutation semantics outside the write domain.
    pub fn symlink(&self, id: SymlinkNodeId) -> Result<TransactionSymlink> {
        let inode = self.volume.read_inode_record(id.inode())?;
        if inode.kind() != InodeKind::Symlink {
            return Err(Error::WrongInodeKind);
        }
        self.require_file_data_mutation(&inode)?;
        Ok(TransactionSymlink { id })
    }

    /// Updates POSIX owner and permission state representable by ext4 inode fields.
    ///
    /// # Errors
    /// Returns an error when the inode leaves the mutable write domain or the
    /// inode record cannot be rewritten.
    pub fn set_posix_security(
        &mut self,
        node: TransactionNode,
        security: Ext4Security,
    ) -> Result<()> {
        let inode_index = self.ensure_inode_update(node.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        let _metadata = inode.metadata_mutation()?;
        raw_inode.set_owner(security.owner())?;
        raw_inode.set_permissions(security.permissions())?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Creates an empty regular file under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent is not mutable, the name exists, no
    /// inode is free, or the parent directory cannot receive another entry.
    pub fn create_file(
        &mut self,
        parent: TransactionDirectory,
        name: &Ext4Name,
        metadata: NewFileMetadata,
    ) -> Result<TransactionFile> {
        self.ensure_child_absent(parent.inode(), name)?;
        self.require_directory_entry_create_mutation(parent.inode())?;
        let parent_inode = self.raw_inode_for_policy(parent.inode())?.parse()?;
        let inherited_context = self.inherited_fscrypt_context(&parent_inode)?;
        let allocated_inode = self.allocate_inode()?;
        let mut raw_inode = allocated_inode.initialize_file(
            metadata,
            self.now,
            self.volume.superblock.block_size(),
            self.volume.superblock.inode_timestamp_encoding(),
        )?;
        self.apply_fscrypt_context(&mut raw_inode, inherited_context)?;
        let inode_id = raw_inode.id();
        self.add_directory_entry(parent.inode(), name, inode_id, DirectoryEntryKind::File)?;
        self.inode_updates.push(raw_inode.into());
        Ok(TransactionFile {
            id: FileNodeId::new(inode_id),
        })
    }

    /// Removes a regular file directory entry and releases its inode when the
    /// final link is removed.
    ///
    /// # Errors
    /// Returns an error when the entry is absent, the child is not a mutable
    /// regular file, or metadata cannot be updated.
    pub fn unlink_file(&mut self, parent: TransactionDirectory, name: &Ext4Name) -> Result<()> {
        let removed = self.remove_directory_entry(parent.inode(), name)?;
        let inode_index = self.ensure_inode_update(removed.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        let _deletion = inode.deletion_mutation()?;
        match raw_inode.decrement_links_count()? {
            LinkCountAfterDecrement::StillLinked(_) => {
                raw_inode
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_inode)?;
            }
            LinkCountAfterDecrement::Unlinked => {
                let tree = self.mutable_extent_tree(&inode)?;
                for extent in tree.extents().iter().copied() {
                    self.free_extent(extent, 0)?;
                }
                for block in tree.metadata_blocks().iter().copied() {
                    self.release_cluster_reference(block)?;
                }
                self.free_inode(raw_inode.id())?;
                let deleted = raw_inode.delete_and_touch(
                    self.now,
                    self.volume.superblock.block_size(),
                    self.volume.superblock.inode_timestamp_encoding(),
                )?;
                self.replace_deleted_inode(inode_index, deleted)?;
            }
        }
        Ok(())
    }

    /// Creates an empty child directory.
    ///
    /// # Errors
    /// Returns an error when the parent is not mutable, the name exists, no
    /// inode or block is free, or metadata cannot be updated.
    pub fn create_directory(
        &mut self,
        parent: TransactionDirectory,
        name: &Ext4Name,
        metadata: NewDirectoryMetadata,
    ) -> Result<TransactionDirectory> {
        self.ensure_child_absent(parent.inode(), name)?;
        self.require_directory_entry_create_mutation(parent.inode())?;
        let parent_inode = self.raw_inode_for_policy(parent.inode())?.parse()?;
        let inherited_context = self.inherited_fscrypt_context(&parent_inode)?;
        let block = self.allocate_cluster()?;
        let allocated_inode = self.allocate_inode()?;
        let block_size = self.volume.superblock.block_size();
        let allocated_blocks = u64::from(
            self.volume
                .superblock
                .blocks_in_cluster(self.volume.superblock.cluster_of_block(block)?)?,
        );
        self.require_allocated_blocks_supported(allocated_blocks)?;
        let mut raw_inode = allocated_inode.initialize_directory(
            metadata,
            self.now,
            block_size,
            block,
            allocated_blocks,
            self.volume.superblock.inode_timestamp_encoding(),
        )?;
        self.apply_fscrypt_context(&mut raw_inode, inherited_context)?;
        let inode_id = raw_inode.id();

        let mut directory = DirectoryBlock::empty(
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        );
        directory.initialize_dot_entries(inode_id, parent.inode())?;
        self.stage_directory_block(block, directory.into_bytes());

        self.add_directory_entry(
            parent.inode(),
            name,
            inode_id,
            DirectoryEntryKind::Directory,
        )?;
        self.increment_directory_links(parent.inode())?;
        let group = InodeBitmapPosition::from_inode(&self.volume.superblock, inode_id)?.group();
        self.record_group_used_dirs_delta(group, 1)?;
        self.inode_updates.push(raw_inode.into());
        Ok(TransactionDirectory {
            id: DirectoryNodeId::new(inode_id),
        })
    }

    /// Creates a symbolic link under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent is not mutable, the name exists, no
    /// inode or data block is free, or the target cannot be represented.
    pub fn create_symlink(
        &mut self,
        parent: TransactionDirectory,
        name: &Ext4Name,
        target: &SymlinkTarget,
        metadata: NewSymlinkMetadata,
    ) -> Result<TransactionSymlink> {
        self.ensure_child_absent(parent.inode(), name)?;
        self.require_directory_entry_create_mutation(parent.inode())?;
        let parent_inode = self.raw_inode_for_policy(parent.inode())?.parse()?;
        if parent_inode.protection().is_encrypted() {
            return Err(Error::UnsupportedEncryption);
        }
        let allocated_inode = self.allocate_inode()?;
        let raw_inode = if target.is_inline() {
            allocated_inode.initialize_inline_symlink(
                metadata,
                self.now,
                target,
                self.volume.superblock.inode_timestamp_encoding(),
            )?
        } else {
            let block_size = self.volume.superblock.block_size();
            let mut raw_inode = allocated_inode.initialize_extent_symlink(
                metadata,
                self.now,
                block_size,
                target,
                self.volume.superblock.inode_timestamp_encoding(),
            )?;
            let block_bytes =
                usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
            let mut tree = MutableExtentTree::from_extents(Vec::new())?;
            for (logical, chunk) in target.bytes().chunks(block_bytes).enumerate() {
                let block = self.allocate_cluster()?;
                let mut bytes = vec![0_u8; block_bytes];
                bytes
                    .get_mut(..chunk.len())
                    .ok_or(Error::DeviceRange)?
                    .copy_from_slice(chunk);
                self.data_writes.push(RangeWrite {
                    offset: block_size.offset_of(block)?,
                    bytes,
                });
                tree.insert_or_extend_initialized(
                    LogicalBlock::try_from(
                        u64::try_from(logical).map_err(|_| Error::ArithmeticOverflow)?,
                    )?,
                    block,
                )?;
            }
            self.stage_extent_tree(&mut raw_inode, tree)?;
            raw_inode
        };
        let inode_id = raw_inode.id();
        self.add_directory_entry(parent.inode(), name, inode_id, DirectoryEntryKind::Symlink)?;
        self.inode_updates.push(raw_inode.into());
        Ok(TransactionSymlink {
            id: SymlinkNodeId::new(inode_id),
        })
    }

    /// Removes an empty child directory.
    ///
    /// # Errors
    /// Returns an error when the entry is absent, not a directory, not empty,
    /// is the root directory, or metadata cannot be updated.
    pub fn remove_empty_directory(
        &mut self,
        parent: TransactionDirectory,
        name: &Ext4Name,
    ) -> Result<()> {
        let removed = self.find_child_entry(parent.inode(), name)?;
        if removed.inode() == InodeId::ROOT {
            return Err(Error::CannotRemoveRoot);
        }
        let inode_index = self.ensure_inode_update(removed.inode())?;
        let raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        let _deletion = inode.deletion_mutation()?;
        if !self.directory_is_empty(&inode)? {
            return Err(Error::DirectoryNotEmpty);
        }
        let _removed = self.remove_directory_entry(parent.inode(), name)?;
        let tree = self.mutable_extent_tree(&inode)?;
        for extent in tree.extents().iter().copied() {
            self.free_extent(extent, 0)?;
        }
        for block in tree.metadata_blocks().iter().copied() {
            self.release_cluster_reference(block)?;
        }
        self.free_inode(raw_inode.id())?;
        let deleted = raw_inode.delete(self.now, self.volume.superblock.block_size())?;
        self.replace_deleted_inode(inode_index, deleted)?;
        self.decrement_directory_links(parent.inode())?;
        let group =
            InodeBitmapPosition::from_inode(&self.volume.superblock, removed.inode())?.group();
        self.record_group_used_dirs_delta(group, -1)
    }

    /// Renames or moves a child entry without replacing an existing target.
    ///
    /// # Errors
    /// Returns an error when the source entry is absent, the target name exists,
    /// either parent is outside the mutable directory domain, or a moved
    /// directory cannot have its parent link updated.
    pub fn rename_child(
        &mut self,
        source_parent: TransactionDirectory,
        source_name: &Ext4Name,
        target_parent: TransactionDirectory,
        target_name: &Ext4Name,
    ) -> Result<()> {
        reject_reserved_directory_name(source_name)?;
        reject_reserved_directory_name(target_name)?;

        let source_parent = source_parent.inode();
        let target_parent = target_parent.inode();
        let source = self.find_child_entry(source_parent, source_name)?;
        if source_parent == target_parent && source_name == target_name {
            return Ok(());
        }
        self.ensure_child_absent(target_parent, target_name)?;

        let child_index = self.ensure_inode_update(source.inode())?;
        let mut child_raw = self.staged_live_inode(child_index)?;
        let child_inode = child_raw.parse()?;
        let _metadata = child_inode.metadata_mutation()?;
        if child_inode.kind() == InodeKind::Directory && source.inode() == InodeId::ROOT {
            return Err(Error::CannotRemoveRoot);
        }
        let kind = directory_entry_kind(child_inode.kind());

        if source_parent == target_parent {
            let renamed = self.rename_directory_entry(
                source_parent,
                source_name,
                target_name,
                source.inode(),
                kind,
            )?;
            if renamed.inode() != source.inode() {
                return Err(Error::InvalidDirectoryEntry);
            }
        } else {
            self.add_directory_entry(target_parent, target_name, source.inode(), kind)?;
            let removed = self.remove_directory_entry(source_parent, source_name)?;
            if removed.inode() != source.inode() {
                return Err(Error::InvalidDirectoryEntry);
            }
            if child_inode.kind() == InodeKind::Directory {
                let dotdot = Ext4Name::new(b"..")?;
                let replaced = self.replace_directory_entry(
                    source.inode(),
                    &dotdot,
                    target_parent,
                    DirectoryEntryKind::Directory,
                )?;
                if replaced.inode() != source_parent {
                    return Err(Error::InvalidDirectoryEntry);
                }
                self.decrement_directory_links(source_parent)?;
                self.increment_directory_links(target_parent)?;
            }
        }

        child_raw.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(child_index, child_raw)?;
        Ok(())
    }

    /// Updates ext4 inode timestamps from a complete timestamp domain value.
    ///
    /// # Errors
    /// Returns an error when the inode leaves the mutable write domain or the
    /// inode record cannot be rewritten.
    pub fn set_times(&mut self, node: TransactionNode, times: Ext4Times) -> Result<()> {
        let inode_index = self.ensure_inode_update(node.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        let _metadata = inode.metadata_mutation()?;
        raw_inode.set_ext4_times(times, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Replaces the ext4 volume label stored in the primary superblock.
    pub fn set_volume_label(&mut self, label: Ext4VolumeLabel) {
        self.volume_label_update = Some(label);
    }

    /// Computes mounted cluster state after a successful commit.
    fn committed_cluster_state(&self) -> Result<(ClusterReferenceIndex, Superblock)> {
        let mut clusters = self.volume.state.clusters.clone();
        clusters.apply_deltas(self.cluster_deltas.as_slice())?;
        let mut superblock = self.volume.superblock;
        superblock.apply_free_cluster_delta(self.free_clusters_delta)?;
        Ok((clusters, superblock))
    }

    /// Removes a symbolic link directory entry and releases its inode.
    ///
    /// # Errors
    /// Returns an error when the entry is absent, not a symbolic link, or
    /// metadata cannot be updated.
    pub fn remove_symlink(&mut self, parent: TransactionDirectory, name: &Ext4Name) -> Result<()> {
        let removed = self.remove_directory_entry(parent.inode(), name)?;
        let inode_index = self.ensure_inode_update(removed.inode())?;
        let raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::Symlink {
            return Err(Error::WrongInodeKind);
        }
        let _deletion = inode.deletion_mutation()?;
        if let Ok(tree) = self.mutable_extent_tree(&inode) {
            for extent in tree.extents().iter().copied() {
                self.free_extent(extent, 0)?;
            }
            for block in tree.metadata_blocks().iter().copied() {
                self.release_cluster_reference(block)?;
            }
        }
        self.free_inode(raw_inode.id())?;
        let deleted = raw_inode.delete(self.now, self.volume.superblock.block_size())?;
        self.replace_deleted_inode(inode_index, deleted)?;
        Ok(())
    }

    /// Overwrites bytes inside an existing regular file range.
    ///
    /// # Errors
    /// Returns an error when the inode is not a regular file, the range extends
    /// beyond EOF, allocation fails, or the updated root extent set cannot fit
    /// in the inode.
    pub fn overwrite_file_range(
        &mut self,
        file: TransactionFile,
        offset: FileOffset,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let inode_index = self.ensure_inode_update(file.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        self.require_file_data_mutation(&inode)?;
        let end_offset = offset.checked_add_len(bytes.len())?;
        if end_offset.bytes() > inode.size().bytes() {
            return Err(Error::InvalidWriteRange);
        }

        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let block_size = usize::try_from(block_size_u64).map_err(|_| Error::ArithmeticOverflow)?;
        let mut tree = self.mutable_extent_tree(&inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let encrypted_contents_key = if inode.protection().is_encrypted() {
            Some(self.volume.fscrypt_contents_key_for_inode(&inode)?)
        } else {
            None
        };
        let mut completed = 0_usize;

        while completed < bytes.len() {
            let position = offset
                .bytes()
                .checked_add(u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let logical_block = position
                .checked_div(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?;
            let in_block = position
                .checked_rem(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?;
            let total_remaining = bytes
                .len()
                .checked_sub(completed)
                .ok_or(Error::ArithmeticOverflow)?;
            let block_remaining = block_size_u64
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            let chunk = usize::try_from(core::cmp::min(
                block_remaining,
                u64::try_from(total_remaining).map_err(|_| Error::ArithmeticOverflow)?,
            ))
            .map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            let logical_block = LogicalBlock::try_from(logical_block)?;
            match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => {
                    if let Some(contents_key) = &encrypted_contents_key {
                        self.stage_encrypted_file_block_update(
                            contents_key,
                            logical_block,
                            physical,
                            in_block,
                            bytes.get(completed..end).ok_or(Error::DeviceRange)?,
                            EncryptedBlockBase::ExistingPlaintext,
                        )?;
                    } else {
                        let write_offset = self
                            .volume
                            .superblock
                            .block_size()
                            .offset_of(physical)?
                            .get()
                            .checked_add(in_block)
                            .ok_or(Error::ArithmeticOverflow)?;
                        self.data_writes.push(RangeWrite {
                            offset: ByteOffset::new(write_offset),
                            bytes: bytes
                                .get(completed..end)
                                .ok_or(Error::DeviceRange)?
                                .to_vec(),
                        });
                    }
                }
                BlockMapping::Uninitialized => return Err(Error::UnsupportedInodeMutation),
                BlockMapping::Hole => {
                    let physical = self.physical_block_for_hole(&tree, logical_block)?;
                    tree.insert_or_extend_initialized(logical_block, physical)?;
                    if let Some(contents_key) = &encrypted_contents_key {
                        self.stage_encrypted_file_block_update(
                            contents_key,
                            logical_block,
                            physical,
                            in_block,
                            bytes.get(completed..end).ok_or(Error::DeviceRange)?,
                            EncryptedBlockBase::ZeroedPlaintext,
                        )?;
                    } else {
                        let mut block = vec![0_u8; block_size];
                        let start =
                            usize::try_from(in_block).map_err(|_| Error::ArithmeticOverflow)?;
                        let block_end =
                            start.checked_add(chunk).ok_or(Error::ArithmeticOverflow)?;
                        block
                            .get_mut(start..block_end)
                            .ok_or(Error::DeviceRange)?
                            .copy_from_slice(bytes.get(completed..end).ok_or(Error::DeviceRange)?);
                        self.data_writes.push(RangeWrite {
                            offset: self.volume.superblock.block_size().offset_of(physical)?,
                            bytes: block,
                        });
                    }
                }
            }

            completed = end;
        }

        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_inode, tree)?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Selects a physical block for a sparse logical block using logical-cluster placement.
    fn physical_block_for_hole(
        &mut self,
        tree: &MutableExtentTree,
        logical_block: LogicalBlock,
    ) -> Result<BlockAddress> {
        let blocks_per_cluster = u64::from(self.volume.superblock.blocks_per_cluster().as_u32());
        let logical = logical_block.as_u64();
        let cluster_offset = logical
            .checked_rem(blocks_per_cluster)
            .ok_or(Error::InvalidClusterGeometry)?;
        let logical_cluster_start = logical
            .checked_sub(cluster_offset)
            .ok_or(Error::ArithmeticOverflow)?;

        for offset in 0..blocks_per_cluster {
            let probe = logical_cluster_start
                .checked_add(offset)
                .ok_or(Error::ArithmeticOverflow)?;
            if probe > u64::from(u32::MAX) {
                break;
            }
            let BlockMapping::Physical(physical) = tree.map_logical(LogicalBlock::try_from(probe)?)
            else {
                continue;
            };
            let cluster = self.volume.superblock.cluster_of_block(physical)?;
            let physical = self.physical_block_in_cluster(cluster, cluster_offset)?;
            self.record_cluster_reference_delta(cluster, 1)?;
            return Ok(physical);
        }

        let first_block = self.allocate_cluster()?;
        let cluster = self.volume.superblock.cluster_of_block(first_block)?;
        self.physical_block_in_cluster(cluster, cluster_offset)
    }

    /// Merges plaintext bytes into one encrypted file block and stages ciphertext.
    fn stage_encrypted_file_block_update(
        &mut self,
        contents_key: &FscryptContentsKey,
        logical_block: LogicalBlock,
        physical: BlockAddress,
        in_block: u64,
        bytes: &[u8],
        block_base: EncryptedBlockBase,
    ) -> Result<()> {
        let mut block = match block_base {
            EncryptedBlockBase::ExistingPlaintext => {
                self.plaintext_file_block_for_update(contents_key, logical_block, physical)?
            }
            EncryptedBlockBase::ZeroedPlaintext => {
                vec![
                    0_u8;
                    usize::try_from(self.volume.superblock.block_size().bytes())
                        .map_err(|_| Error::ArithmeticOverflow)?
                ]
            }
        };
        let start = usize::try_from(in_block).map_err(|_| Error::ArithmeticOverflow)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        block
            .get_mut(start..end)
            .ok_or(Error::DeviceRange)?
            .copy_from_slice(bytes);
        contents_key.encrypt_block(logical_block.as_u64(), &mut block)?;
        self.data_writes.push(RangeWrite {
            offset: self.volume.superblock.block_size().offset_of(physical)?,
            bytes: block,
        });
        Ok(())
    }

    /// Returns the latest plaintext image of one file block for encrypted updates.
    fn plaintext_file_block_for_update(
        &self,
        contents_key: &FscryptContentsKey,
        logical_block: LogicalBlock,
        physical: BlockAddress,
    ) -> Result<Vec<u8>> {
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let block_offset = block_size.offset_of(physical)?;
        let mut block = if let Some(staged) = self
            .data_writes
            .iter()
            .rev()
            .find(|write| write.offset == block_offset && write.bytes.len() == block_bytes)
        {
            staged.bytes.clone()
        } else {
            let mut bytes = vec![0_u8; block_bytes];
            self.volume.device.read_exact_at(block_offset, &mut bytes)?;
            bytes
        };
        contents_key.decrypt_block(logical_block.as_u64(), &mut block)?;
        Ok(block)
    }

    /// Returns a block at `cluster_offset` inside a fully present physical cluster.
    fn physical_block_in_cluster(
        &self,
        cluster: ClusterAddress,
        cluster_offset: u64,
    ) -> Result<BlockAddress> {
        if cluster_offset >= u64::from(self.volume.superblock.blocks_in_cluster(cluster)?) {
            return Err(Error::InvalidClusterGeometry);
        }
        Ok(BlockAddress::new(
            self.volume
                .superblock
                .first_block_of_cluster(cluster)?
                .get()
                .checked_add(cluster_offset)
                .ok_or(Error::ArithmeticOverflow)?,
        ))
    }

    /// Stages a write into an inode extent stream without applying EOF limits.
    fn stage_inode_stream_write(
        &mut self,
        tree: &mut MutableExtentTree,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let mut completed = 0_usize;
        while completed < bytes.len() {
            let position = offset
                .checked_add(u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let logical_block = position
                .checked_div(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?;
            let in_block = position
                .checked_rem(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?;
            let block_remaining = block_size_u64
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            let total_remaining = u64::try_from(
                bytes
                    .len()
                    .checked_sub(completed)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let chunk = usize::try_from(core::cmp::min(block_remaining, total_remaining))
                .map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            let logical_block = LogicalBlock::try_from(logical_block)?;
            let physical = match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => physical,
                BlockMapping::Uninitialized => return Err(Error::UnsupportedInodeMutation),
                BlockMapping::Hole => {
                    let physical = self.physical_block_for_hole(tree, logical_block)?;
                    tree.insert_or_extend_initialized(logical_block, physical)?;
                    physical
                }
            };
            let write_offset = self
                .volume
                .superblock
                .block_size()
                .offset_of(physical)?
                .get()
                .checked_add(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            self.data_writes.push(RangeWrite {
                offset: ByteOffset::new(write_offset),
                bytes: bytes
                    .get(completed..end)
                    .ok_or(Error::DeviceRange)?
                    .to_vec(),
            });
            completed = end;
        }
        Ok(())
    }

    /// Stages a plaintext write into an encrypted inode stream without EOF limits.
    fn stage_encrypted_inode_stream_write(
        &mut self,
        inode: &Inode,
        tree: &mut MutableExtentTree,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let contents_key = self.volume.fscrypt_contents_key_for_inode(inode)?;
        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let mut completed = 0_usize;
        while completed < bytes.len() {
            let position = offset
                .checked_add(u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let logical_block = position
                .checked_div(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?;
            let in_block = position
                .checked_rem(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?;
            let block_remaining = block_size_u64
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            let total_remaining = u64::try_from(
                bytes
                    .len()
                    .checked_sub(completed)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let chunk = usize::try_from(core::cmp::min(block_remaining, total_remaining))
                .map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            let logical_block = LogicalBlock::try_from(logical_block)?;
            let (physical, block_base) = match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => {
                    (physical, EncryptedBlockBase::ExistingPlaintext)
                }
                BlockMapping::Uninitialized => return Err(Error::UnsupportedInodeMutation),
                BlockMapping::Hole => {
                    let physical = self.physical_block_for_hole(tree, logical_block)?;
                    tree.insert_or_extend_initialized(logical_block, physical)?;
                    (physical, EncryptedBlockBase::ZeroedPlaintext)
                }
            };
            self.stage_encrypted_file_block_update(
                &contents_key,
                logical_block,
                physical,
                in_block,
                bytes.get(completed..end).ok_or(Error::DeviceRange)?,
                block_base,
            )?;
            completed = end;
        }
        Ok(())
    }

    /// Extends a regular file as a sparse range.
    ///
    /// # Errors
    /// Returns an error when `new_size` would shrink the file.
    pub fn extend_file(&mut self, file: TransactionFile, new_size: FileSize) -> Result<()> {
        let inode_index = self.ensure_inode_update(file.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        self.require_file_size_mutation(&inode)?;
        if new_size < inode.size() {
            return Err(Error::InvalidWriteRange);
        }
        self.require_inode_size_supported(new_size)?;
        raw_inode.set_size(new_size)?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Truncates a regular file and releases whole blocks beyond the new EOF.
    ///
    /// # Errors
    /// Returns an error when `new_size` would extend the file or root extent
    /// updates cannot fit in the inode.
    pub fn truncate_file(&mut self, file: TransactionFile, new_size: FileSize) -> Result<()> {
        let inode_index = self.ensure_inode_update(file.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        self.require_file_size_mutation(&inode)?;
        if new_size > inode.size() {
            return Err(Error::InvalidWriteRange);
        }
        self.require_inode_size_supported(new_size)?;
        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let mut tree = self.mutable_extent_tree(&inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let extents = tree.extents().to_vec();
        let keep_blocks = round_up_div(new_size.bytes(), block_size_u64)?;
        let mut updated = Vec::new();
        for extent in extents {
            let start = extent.logical_start().as_u64();
            let end = u64::from(extent.end_logical()?);
            if start >= keep_blocks {
                self.free_extent(extent, 0)?;
            } else if end > keep_blocks {
                let keep_len = u16::try_from(
                    keep_blocks
                        .checked_sub(start)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .map_err(|_| Error::ArithmeticOverflow)?;
                self.free_extent(extent, keep_len)?;
                updated.push(Extent::initialized(
                    extent.logical_start(),
                    ExtentLength::new(keep_len)?,
                    extent.physical_start(),
                ));
            } else {
                updated.push(extent);
            }
        }
        if new_size
            .bytes()
            .checked_rem(block_size_u64)
            .ok_or(Error::InvalidSuperblock)?
            != 0
        {
            if inode.protection().is_encrypted() {
                self.zero_encrypted_truncated_tail(
                    &inode,
                    updated.as_slice(),
                    new_size,
                    block_size_u64,
                )?;
            } else {
                self.zero_truncated_tail(updated.as_slice(), new_size, block_size_u64)?;
            }
        }
        tree.replace_extents(updated)?;
        raw_inode.set_size(new_size)?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_inode, tree)?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Enables fs-verity on a plain regular file by journal-staging ext4
    /// post-EOF metadata and setting `EXT4_VERITY_FL`.
    ///
    /// # Errors
    /// Returns an error when the inode is not a plain regular file, the file
    /// cannot be read into the verification domain, metadata allocation fails,
    /// or the extent tree cannot represent the post-EOF metadata.
    pub fn enable_verity(&mut self, file: TransactionFile, enable: &FsverityEnable) -> Result<()> {
        let inode_index = self.ensure_inode_update(file.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(&inode)?;
        }
        if inode.protection().is_verity() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let _payload = inode.file_payload_mutation()?;

        let mut plaintext = vec![0_u8; inode.size().to_usize()?];
        let read =
            self.volume
                .read_inode_plaintext_data(&inode, FileOffset::ZERO, &mut plaintext)?;
        if read.as_usize() != plaintext.len() {
            return Err(Error::InvalidVerityMetadata);
        }
        let merkle_tree = FsverityMerkleTree::build(
            &plaintext,
            enable.algorithm(),
            enable.block_size(),
            enable.salt(),
        )?;
        let descriptor = FsverityDescriptor::new(
            enable.algorithm(),
            enable.block_size(),
            inode.size().bytes(),
            merkle_tree.root_hash(),
            enable.salt().clone(),
        )?;
        let descriptor_fixed = descriptor.to_bytes()?;
        let descriptor_bytes = descriptor_byte_count(enable.signature().bytes())?;
        let layout = Ext4VerityMetadataLayout::new(
            inode.size(),
            self.volume.superblock.block_size(),
            u64::try_from(merkle_tree.blocks().len()).map_err(|_| Error::ArithmeticOverflow)?,
            descriptor_bytes,
        )?;
        let metadata = verity_metadata_image(
            layout,
            merkle_tree.blocks(),
            &descriptor_fixed,
            enable.signature().bytes(),
        )?;

        let mut tree = self.mutable_extent_tree(&inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        if inode.protection().is_encrypted() {
            self.stage_encrypted_inode_stream_write(
                &inode,
                &mut tree,
                layout.merkle_tree_offset(),
                &metadata,
            )?;
        } else {
            self.stage_inode_stream_write(&mut tree, layout.merkle_tree_offset(), &metadata)?;
        }
        raw_inode.mark_verity()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_inode, tree)?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Verifies file-data mutation policy with mount-scoped fscrypt keys.
    fn require_file_data_mutation(&self, inode: &Inode) -> Result<FilePayloadMutationCapability> {
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(inode)?;
            if inode.kind() != InodeKind::File || inode.protection().is_verity() {
                return Err(Error::UnsupportedEncryption);
            }
        }
        inode.file_payload_mutation()
    }

    /// Verifies file-size mutation policy with mount-scoped fscrypt keys.
    fn require_file_size_mutation(&self, inode: &Inode) -> Result<FileSizeMutationCapability> {
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(inode)?;
            if inode.kind() != InodeKind::File || inode.protection().is_verity() {
                return Err(Error::UnsupportedEncryption);
            }
        }
        inode.file_size_mutation()
    }

    /// Verifies directory-entry creation policy using the latest staged inode.
    fn require_directory_entry_create_mutation(
        &self,
        inode_id: InodeId,
    ) -> Result<DirectoryEntryMutationCapability> {
        let raw_inode = self.raw_inode_for_policy(inode_id)?;
        let inode = raw_inode.parse()?;
        self.require_directory_entry_create_mutation_for_inode(&inode)
    }

    /// Verifies directory-entry creation policy with mount-scoped fscrypt keys.
    fn require_directory_entry_create_mutation_for_inode(
        &self,
        inode: &Inode,
    ) -> Result<DirectoryEntryMutationCapability> {
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(inode)?;
        }
        inode.directory_entry_mutation()
    }

    /// Verifies directory-entry deletion policy with mount-scoped fscrypt keys.
    fn require_directory_entry_delete_mutation_for_inode(
        &self,
        inode: &Inode,
    ) -> Result<DirectoryEntryMutationCapability> {
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        inode.directory_entry_mutation()
    }

    /// Verifies directory-entry rename policy with mount-scoped fscrypt keys.
    fn require_directory_entry_rename_mutation_for_inode(
        &self,
        inode: &Inode,
    ) -> Result<DirectoryEntryMutationCapability> {
        self.require_directory_entry_create_mutation_for_inode(inode)
    }

    /// Verifies directory-entry replacement policy with mount-scoped fscrypt keys.
    fn require_directory_entry_replace_mutation_for_inode(
        &self,
        inode: &Inode,
    ) -> Result<DirectoryEntryMutationCapability> {
        self.require_directory_entry_create_mutation_for_inode(inode)
    }

    /// Builds the fscrypt context inherited by a new child of this directory.
    fn inherited_fscrypt_context(&mut self, parent: &Inode) -> Result<Option<FscryptContextV2>> {
        if !parent.protection().is_encrypted() {
            return Ok(None);
        }
        let (parent_context, _master_key) = self.volume.fscrypt_master_key_for_inode(parent)?;
        let nonce = self.volume.mount_context.next_fscrypt_file_nonce()?;
        Ok(Some(FscryptContextV2::new(parent_context.policy(), nonce)))
    }

    /// Stores an inherited fscrypt context on a newly-initialized live inode.
    fn apply_fscrypt_context(
        &mut self,
        raw_inode: &mut LiveInodeRecord,
        context: Option<FscryptContextV2>,
    ) -> Result<()> {
        let Some(context) = context else {
            return Ok(());
        };
        self.require_xattr_mutation()?;
        raw_inode.mark_encrypted()?;
        let mut set = self.xattr_set_for_raw_inode(raw_inode)?;
        set.set_encryption_context(XattrValue::new(&context.to_bytes())?);
        self.store_xattr_set(raw_inode, &set)
    }

    /// Returns the staged inode record when present, otherwise the device image.
    fn raw_inode_for_policy(&self, inode_id: InodeId) -> Result<LiveInodeRecord> {
        if let Some(raw_inode) = self
            .inode_updates
            .iter()
            .find(|raw_inode| raw_inode.id() == inode_id)
        {
            return raw_inode.clone_live();
        }
        self.volume.read_live_inode_record(inode_id)
    }

    /// Verifies that a directory does not already contain `name`.
    fn ensure_child_absent(&self, parent: InodeId, name: &Ext4Name) -> Result<()> {
        match self.find_child_entry(parent, name) {
            Ok(_) => Err(Error::NameAlreadyExists),
            Err(Error::DirectoryEntryNotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Finds a live directory entry by exact ext4 name.
    fn find_child_entry(&self, parent: InodeId, name: &Ext4Name) -> Result<RawDirectoryEntry> {
        let inode = self.volume.read_inode_record(parent)?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        let lookup_name = self.directory_lookup_name(&inode, name)?;
        if let Some(entry) = self.directory_layout(&inode)?.find(&lookup_name) {
            return Ok(entry);
        }
        Err(Error::DirectoryEntryNotFound)
    }

    /// Returns the on-disk name to use for a directory lookup inside this transaction.
    fn directory_lookup_name(&self, directory: &Inode, name: &Ext4Name) -> Result<Ext4Name> {
        match self.volume.encrypt_directory_child_name(directory, name) {
            Err(Error::MissingEncryptionKey) => Ok(
                MountedVolume::<D, JournaledMount<J>, N>::locked_directory_ciphertext_name(name)?
                    .unwrap_or_else(|| name.clone()),
            ),
            result => result,
        }
    }

    /// Adds a child entry to a mutable directory, extending it when supported.
    fn add_directory_entry(
        &mut self,
        parent: InodeId,
        name: &Ext4Name,
        child: InodeId,
        kind: DirectoryEntryKind,
    ) -> Result<()> {
        let inode_index = self.ensure_inode_update(parent)?;
        let mut raw_parent = self.staged_live_inode(inode_index)?;
        let parent_inode = raw_parent.parse()?;
        if parent_inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.require_directory_entry_create_mutation_for_inode(&parent_inode)?;
        let disk_name = self
            .volume
            .encrypt_directory_child_name(&parent_inode, name)?;
        if self
            .directory_layout(&parent_inode)?
            .find(&disk_name)
            .is_some()
        {
            return Err(Error::NameAlreadyExists);
        }
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            let mut entries = self.directory_layout(&parent_inode)?.entries();
            entries.push(RawDirectoryEntry::new(child, &disk_name, kind));
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(());
        }

        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if block.insert(child, &disk_name, kind)? {
                self.stage_directory_block(physical, block.into_bytes());
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                return Ok(());
            }
        }

        match self.volume.superblock.directory_indexing() {
            DirectoryIndexing::Enabled => {
                let mut entries = self.directory_layout(&parent_inode)?.entries();
                entries.push(RawDirectoryEntry::new(child, &disk_name, kind));
                self.stage_rebuilt_htree_directory(
                    inode_index,
                    raw_parent,
                    &parent_inode,
                    &entries,
                )?;
                return Ok(());
            }
            DirectoryIndexing::Disabled => {}
        }

        let block_size = self.volume.superblock.block_size();
        let block_size_u64 = u64::from(block_size.bytes());
        let new_physical = self.allocate_cluster()?;
        let mut tree = self.mutable_extent_tree(&parent_inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let logical_block =
            LogicalBlock::try_from(round_up_div(parent_inode.size().bytes(), block_size_u64)?)?;
        tree.insert_or_extend_initialized(logical_block, new_physical)?;

        let mut block = DirectoryBlock::empty(
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        );
        block.initialize_free_space()?;
        let inserted = block.insert(child, &disk_name, kind)?;
        if !inserted {
            return Err(Error::InvalidDirectoryEntry);
        }
        self.stage_directory_block(new_physical, block.into_bytes());
        let new_parent_size = FileSize::from_bytes(
            parent_inode
                .size()
                .bytes()
                .checked_add(block_size_u64)
                .ok_or(Error::ArithmeticOverflow)?,
        );
        self.require_inode_size_supported(new_parent_size)?;
        raw_parent.set_size(new_parent_size)?;
        raw_parent.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_parent, tree)?;
        self.replace_live_inode(inode_index, raw_parent)?;
        Ok(())
    }

    /// Removes a child entry from a mutable directory.
    fn remove_directory_entry(
        &mut self,
        parent: InodeId,
        name: &Ext4Name,
    ) -> Result<RawDirectoryEntry> {
        let inode_index = self.ensure_inode_update(parent)?;
        let mut raw_parent = self.staged_live_inode(inode_index)?;
        let parent_inode = raw_parent.parse()?;
        if parent_inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.require_directory_entry_delete_mutation_for_inode(&parent_inode)?;
        let disk_name = self.directory_lookup_name(&parent_inode, name)?;
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            let mut entries = self.directory_layout(&parent_inode)?.entries();
            let Some(position) = entries.iter().position(|entry| entry.name() == &disk_name) else {
                return Err(Error::DirectoryEntryNotFound);
            };
            let removed = entries.remove(position);
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(removed);
        }
        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if let Some(removed) = block.remove(&disk_name)? {
                self.stage_directory_block(physical, block.into_bytes());
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                return Ok(removed);
            }
        }
        Err(Error::DirectoryEntryNotFound)
    }

    /// Renames a child entry while preserving the expected child inode and kind.
    fn rename_directory_entry(
        &mut self,
        parent: InodeId,
        old_name: &Ext4Name,
        new_name: &Ext4Name,
        child: InodeId,
        kind: DirectoryEntryKind,
    ) -> Result<RawDirectoryEntry> {
        let inode_index = self.ensure_inode_update(parent)?;
        let mut raw_parent = self.staged_live_inode(inode_index)?;
        let parent_inode = raw_parent.parse()?;
        if parent_inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.require_directory_entry_rename_mutation_for_inode(&parent_inode)?;
        let old_disk_name = self
            .volume
            .encrypt_directory_child_name(&parent_inode, old_name)?;
        let new_disk_name = self
            .volume
            .encrypt_directory_child_name(&parent_inode, new_name)?;
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            let mut entries = self.directory_layout(&parent_inode)?.entries();
            if entries.iter().any(|entry| entry.name() == &new_disk_name) {
                return Err(Error::NameAlreadyExists);
            }
            let Some(position) = entries
                .iter()
                .position(|entry| entry.name() == &old_disk_name)
            else {
                return Err(Error::DirectoryEntryNotFound);
            };
            let renamed = entries
                .get(position)
                .ok_or(Error::InvalidDirectoryEntry)?
                .clone();
            if renamed.inode() != child {
                return Err(Error::InvalidDirectoryEntry);
            }
            *entries
                .get_mut(position)
                .ok_or(Error::InvalidDirectoryEntry)? =
                RawDirectoryEntry::new(child, &new_disk_name, kind);
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(renamed);
        }
        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if let Some(renamed) = block.rename(&old_disk_name, &new_disk_name)? {
                if renamed.inode() != child {
                    return Err(Error::InvalidDirectoryEntry);
                }
                let replacement = block.replace(&new_disk_name, child, kind)?;
                if replacement.is_none() {
                    return Err(Error::InvalidDirectoryEntry);
                }
                self.stage_directory_block(physical, block.into_bytes());
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                return Ok(renamed);
            }
        }
        Err(Error::DirectoryEntryNotFound)
    }

    /// Replaces the inode and kind stored for an existing directory name.
    fn replace_directory_entry(
        &mut self,
        parent: InodeId,
        name: &Ext4Name,
        child: InodeId,
        kind: DirectoryEntryKind,
    ) -> Result<RawDirectoryEntry> {
        let inode_index = self.ensure_inode_update(parent)?;
        let mut raw_parent = self.staged_live_inode(inode_index)?;
        let parent_inode = raw_parent.parse()?;
        if parent_inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.require_directory_entry_replace_mutation_for_inode(&parent_inode)?;
        let disk_name = self
            .volume
            .encrypt_directory_child_name(&parent_inode, name)?;
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            let mut entries = self.directory_layout(&parent_inode)?.entries();
            let Some(position) = entries.iter().position(|entry| entry.name() == &disk_name) else {
                return Err(Error::DirectoryEntryNotFound);
            };
            let replaced = entries
                .get(position)
                .ok_or(Error::InvalidDirectoryEntry)?
                .clone();
            *entries
                .get_mut(position)
                .ok_or(Error::InvalidDirectoryEntry)? =
                RawDirectoryEntry::new(child, &disk_name, kind);
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(replaced);
        }
        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if let Some(replaced) = block.replace(&disk_name, child, kind)? {
                self.stage_directory_block(physical, block.into_bytes());
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                return Ok(replaced);
            }
        }
        Err(Error::DirectoryEntryNotFound)
    }

    /// Rebuilds and stages one directory as a canonical HTree image.
    fn stage_rebuilt_htree_directory(
        &mut self,
        inode_index: StagedInodeIndex,
        mut raw_parent: LiveInodeRecord,
        parent_inode: &Inode,
        entries: &[RawDirectoryEntry],
    ) -> Result<()> {
        let dot = entries
            .iter()
            .find(|entry| entry.name().bytes() == b".")
            .ok_or(Error::InvalidDirectoryEntry)?;
        if dot.inode() != parent_inode.id() {
            return Err(Error::InvalidDirectoryEntry);
        }
        let dotdot = entries
            .iter()
            .find(|entry| entry.name().bytes() == b"..")
            .ok_or(Error::InvalidDirectoryEntry)?;
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let checksum = self.volume.directory_checksum(parent_inode);
        let image = build_htree_directory(
            parent_inode.id(),
            dotdot.inode(),
            entries,
            block_bytes,
            self.volume.superblock.directory_hash_seed(),
            self.volume.superblock.default_directory_hash_version(),
            checksum,
        )?;
        let existing_blocks =
            round_up_div(parent_inode.size().bytes(), u64::from(block_size.bytes()))?;
        let image_blocks =
            u64::try_from(image.block_count()).map_err(|_| Error::ArithmeticOverflow)?;
        let target_blocks = existing_blocks.max(image_blocks);
        let mut tree = self.mutable_extent_tree(parent_inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        for logical in 0..image_blocks {
            let logical_block = LogicalBlock::try_from(logical)?;
            let physical = match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => physical,
                BlockMapping::Uninitialized => return Err(Error::UnsupportedInodeMutation),
                BlockMapping::Hole => {
                    let physical = self.allocate_cluster()?;
                    tree.insert_or_extend_initialized(logical_block, physical)?;
                    physical
                }
            };
            let image_block = image
                .blocks()
                .get(usize::try_from(logical).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::InvalidDirectoryEntry)?
                .clone();
            self.stage_directory_block(physical, image_block);
        }
        raw_parent.mark_indexed_directory()?;
        let rebuilt_size = FileSize::from_bytes(
            target_blocks
                .checked_mul(u64::from(block_size.bytes()))
                .ok_or(Error::ArithmeticOverflow)?,
        );
        self.require_inode_size_supported(rebuilt_size)?;
        raw_parent.set_size(rebuilt_size)?;
        raw_parent.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_parent, tree)?;
        self.replace_live_inode(inode_index, raw_parent)
    }

    /// Stages the latest image for a mutated directory block.
    fn stage_directory_block(&mut self, block: BlockAddress, bytes: Vec<u8>) {
        if let Some(image) = self
            .directory_updates
            .iter_mut()
            .find(|image| image.block == block)
        {
            image.bytes = bytes;
        } else {
            self.directory_updates.push(BlockImage { block, bytes });
        }
    }

    /// Returns whether a directory contains only `.` and `..`.
    fn directory_is_empty(&self, inode: &Inode) -> Result<bool> {
        for entry in self.directory_layout(inode)?.entries() {
            let name = entry.name().bytes();
            if name != b"." && name != b".." {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Loads the staged-aware directory layout for mutation-time lookups.
    fn directory_layout(&self, inode: &Inode) -> Result<DirectoryLayout> {
        let storage = inode.directory_storage_kind()?;
        if matches!(storage, DirectoryStorageKind::HTree) {
            self.volume
                .superblock
                .directory_indexing()
                .require_supported()?;
        }
        let mut blocks = Vec::new();
        for (logical, _physical, block) in self.directory_blocks(inode)? {
            blocks.push(DirectoryBlockData::new(
                logical.as_u32(),
                block.into_bytes(),
            ));
        }
        DirectoryLayout::from_storage_kind(
            storage,
            blocks,
            self.volume.superblock.directory_hash_seed(),
            self.volume.superblock.default_directory_hash_version(),
            self.volume.directory_checksum(inode),
        )
    }

    /// Loads directory blocks, preferring staged images over device bytes.
    fn directory_blocks(
        &self,
        inode: &Inode,
    ) -> Result<Vec<(LogicalBlock, BlockAddress, DirectoryBlock)>> {
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let block_count = round_up_div(inode.size().bytes(), u64::from(block_size.bytes()))?;
        let tree = MutableExtentTree::load_inode_tree(
            inode.extent_root()?,
            block_size,
            &self.volume.device,
            self.volume.extent_tree_context(inode),
        )?;
        let mut blocks = Vec::new();
        for logical in 0..block_count {
            let logical = LogicalBlock::try_from(logical)?;
            let physical = match tree.map_logical(logical) {
                BlockMapping::Physical(physical) => physical,
                BlockMapping::Uninitialized | BlockMapping::Hole => {
                    return Err(Error::InvalidDirectoryEntry);
                }
            };
            let bytes = if let Some(staged) = self
                .directory_updates
                .iter()
                .find(|image| image.block == physical)
            {
                if staged.bytes.len() != block_bytes {
                    return Err(Error::InvalidDirectoryEntry);
                }
                staged.bytes.clone()
            } else {
                let mut bytes = vec![0_u8; block_bytes];
                self.volume
                    .device
                    .read_exact_at(block_size.offset_of(physical)?, &mut bytes)?;
                bytes
            };
            blocks.push((logical, physical, DirectoryBlock::new(bytes)));
        }
        Ok(blocks)
    }

    /// Loads a mutable extent tree for an inode selected by this transaction.
    fn mutable_extent_tree(&self, inode: &Inode) -> Result<MutableExtentTree> {
        MutableExtentTree::load_inode_tree(
            inode.extent_root()?,
            self.volume.superblock.block_size(),
            &self.volume.device,
            self.volume.extent_tree_context(inode),
        )
    }

    /// Stages an updated extent tree and adjusts its metadata block ownership.
    fn stage_extent_tree(
        &mut self,
        raw_inode: &mut LiveInodeRecord,
        mut tree: MutableExtentTree,
    ) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let required = tree.required_metadata_blocks(block_size)?;
        let mut metadata_blocks = tree.metadata_blocks().to_vec();
        while metadata_blocks.len() < required {
            metadata_blocks.push(self.allocate_cluster()?);
        }
        while metadata_blocks.len() > required {
            let block = metadata_blocks.pop().ok_or(Error::InvalidExtentTree)?;
            self.release_cluster_reference(block)?;
        }
        tree.set_metadata_blocks(metadata_blocks);

        let inode = raw_inode.parse()?;
        let serialized = tree.serialize(block_size, self.volume.extent_tree_context(&inode))?;
        self.stage_serialized_extent_tree(raw_inode, &serialized)?;
        let allocated_blocks = self.allocated_data_blocks(&tree)?;
        self.require_allocated_blocks_supported(allocated_blocks)?;
        raw_inode.set_allocated_blocks(allocated_blocks, u64::from(block_size.bytes()))
    }

    /// Counts physical blocks charged to an inode through allocation clusters.
    fn allocated_data_blocks(&self, tree: &MutableExtentTree) -> Result<u64> {
        let mut clusters = Vec::new();
        for extent in tree.extents().iter().copied() {
            for offset in 0..extent.len().as_u64() {
                let cluster = self.volume.superblock.cluster_of_block(BlockAddress::new(
                    extent
                        .physical_start()
                        .get()
                        .checked_add(offset)
                        .ok_or(Error::ArithmeticOverflow)?,
                ))?;
                if !clusters.contains(&cluster) {
                    clusters.push(cluster);
                }
            }
        }
        let mut blocks = 0_u64;
        for cluster in clusters {
            blocks = blocks
                .checked_add(u64::from(
                    self.volume.superblock.blocks_in_cluster(cluster)?,
                ))
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(blocks)
    }

    /// Copies a serialized extent tree into the inode and metadata block staging areas.
    fn stage_serialized_extent_tree(
        &mut self,
        raw_inode: &mut LiveInodeRecord,
        serialized: &SerializedExtentTree,
    ) -> Result<()> {
        raw_inode.set_extent_root_bytes(serialized.inode_root())?;
        for block in serialized.external_blocks() {
            self.extent_updates.push(BlockImage {
                block: block.block(),
                bytes: block.bytes().to_vec(),
            });
        }
        Ok(())
    }

    /// Increments a directory inode link count and updates timestamps.
    fn increment_directory_links(&mut self, inode_id: InodeId) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        raw_inode.increment_links_count()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Decrements a directory inode link count and updates timestamps.
    fn decrement_directory_links(&mut self, inode_id: InodeId) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let _links = raw_inode.decrement_links_count()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Aborts the transaction without writing staged data or metadata.
    pub fn abort(self) {}

    /// Returns the staged inode record index, loading it once when needed.
    fn ensure_inode_update(&mut self, inode_id: InodeId) -> Result<StagedInodeIndex> {
        if let Some(index) = self
            .inode_updates
            .iter()
            .position(|inode| inode.id() == inode_id)
        {
            return Ok(StagedInodeIndex::new(index));
        }
        let raw_inode = self.volume.read_live_inode_record(inode_id)?;
        self.inode_updates.push(raw_inode.into());
        Ok(StagedInodeIndex::new(
            self.inode_updates
                .len()
                .checked_sub(1)
                .ok_or(Error::ArithmeticOverflow)?,
        ))
    }

    /// Returns a staged live inode record by index.
    fn staged_live_inode(&self, index: StagedInodeIndex) -> Result<LiveInodeRecord> {
        self.inode_updates
            .get(index.get())
            .ok_or(Error::InvalidInode)?
            .clone_live()
    }

    /// Replaces a staged inode with its updated live state.
    fn replace_live_inode(
        &mut self,
        index: StagedInodeIndex,
        record: LiveInodeRecord,
    ) -> Result<()> {
        *self
            .inode_updates
            .get_mut(index.get())
            .ok_or(Error::InvalidInode)? = record.into();
        Ok(())
    }

    /// Replaces a staged inode with its deleted state.
    fn replace_deleted_inode(
        &mut self,
        index: StagedInodeIndex,
        record: DeletedInodeRecord,
    ) -> Result<()> {
        *self
            .inode_updates
            .get_mut(index.get())
            .ok_or(Error::InvalidInode)? = record.into();
        Ok(())
    }

    /// Allocates the first free allocation cluster visible in group bitmaps.
    fn allocate_cluster(&mut self) -> Result<BlockAddress> {
        let groups = self.volume.superblock.block_group_count()?;
        for group in 0..groups.as_u32() {
            let group = BlockGroupId::from_u32(group);
            let descriptor = BlockGroupDescriptor::read_from(
                &self.volume.device,
                &self.volume.superblock,
                group,
            )?;
            let bitmap_index = self.ensure_block_bitmap_update(descriptor.block_bitmap())?;
            let clusters_in_group = self.volume.superblock.clusters_in_group(group)?;
            for bit in 0..clusters_in_group {
                let position = ClusterBitmapPosition::new(group, bit);
                let cluster = ClusterAddress::new(
                    u64::from(group.as_u32())
                        .checked_mul(u64::from(
                            self.volume.superblock.clusters_per_group().as_u32(),
                        ))
                        .and_then(|start| start.checked_add(u64::from(bit)))
                        .ok_or(Error::ArithmeticOverflow)?,
                );
                let first_block = self.volume.superblock.first_block_of_cluster(cluster)?;
                if first_block.get() >= self.volume.superblock.block_count().as_u64() {
                    break;
                }
                if self.volume.superblock.blocks_in_cluster(cluster)?
                    != self.volume.superblock.blocks_per_cluster().as_u32()
                {
                    continue;
                }
                let occupied = {
                    let bitmap = self
                        .block_bitmap_updates
                        .get(bitmap_index)
                        .ok_or(Error::InvalidSuperblock)?;
                    cluster_bitmap_bit_state(bitmap.bytes.as_slice(), position)?
                };
                if occupied == BitmapBitState::Used {
                    continue;
                }
                if self.staged_cluster_reference_count(cluster)? != 0 {
                    return Err(Error::ClusterReferenceConflict);
                }
                let bitmap = self
                    .block_bitmap_updates
                    .get_mut(bitmap_index)
                    .ok_or(Error::InvalidSuperblock)?;
                set_cluster_bitmap_bit(
                    bitmap.bytes.as_mut_slice(),
                    position,
                    BitmapBitState::Used,
                )?;
                self.record_group_free_clusters_delta(group, FreeClusterDelta::from_i64(-1))?;
                self.free_clusters_delta = self.free_clusters_delta.checked_add(-1)?;
                self.record_cluster_reference_delta(cluster, 1)?;
                self.stage_cluster_zeroes(cluster)?;
                return Ok(first_block);
            }
        }
        Err(Error::NoSpace)
    }

    /// Stages zeroes for every block covered by a newly allocated cluster.
    fn stage_cluster_zeroes(&mut self, cluster: ClusterAddress) -> Result<()> {
        let first_block = self.volume.superblock.first_block_of_cluster(cluster)?;
        let blocks = self.volume.superblock.blocks_in_cluster(cluster)?;
        let bytes = usize::try_from(
            u64::from(blocks)
                .checked_mul(u64::from(self.volume.superblock.block_size().bytes()))
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .map_err(|_| Error::ArithmeticOverflow)?;
        self.data_writes.push(RangeWrite {
            offset: self.volume.superblock.block_size().offset_of(first_block)?,
            bytes: vec![0_u8; bytes],
        });
        Ok(())
    }

    /// Records one staged cluster-reference delta after checking underflow.
    fn record_cluster_reference_delta(
        &mut self,
        cluster: ClusterAddress,
        delta: i32,
    ) -> Result<()> {
        let updated = self
            .staged_cluster_reference_count(cluster)?
            .checked_add(delta)
            .ok_or(Error::ArithmeticOverflow)?;
        if updated < 0 {
            return Err(Error::ClusterReferenceConflict);
        }
        if let Some(entry) = self
            .cluster_deltas
            .iter_mut()
            .find(|entry| entry.cluster == cluster)
        {
            entry.delta = entry
                .delta
                .checked_add(delta)
                .ok_or(Error::ArithmeticOverflow)?;
        } else {
            self.cluster_deltas
                .push(ClusterReferenceDelta { cluster, delta });
        }
        Ok(())
    }

    /// Returns mounted plus staged references for one cluster.
    fn staged_cluster_reference_count(&self, cluster: ClusterAddress) -> Result<i32> {
        let mut count = i32::try_from(self.volume.state.clusters.count(cluster))
            .map_err(|_| Error::ArithmeticOverflow)?;
        for delta in self
            .cluster_deltas
            .iter()
            .filter(|delta| delta.cluster == cluster)
        {
            count = count
                .checked_add(delta.delta)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(count)
    }

    /// Releases a block-owned cluster reference and frees the cluster if no references remain.
    fn release_cluster_reference(&mut self, block: BlockAddress) -> Result<()> {
        let cluster = self.volume.superblock.cluster_of_block(block)?;
        self.record_cluster_reference_delta(cluster, -1)?;
        if self.staged_cluster_reference_count(cluster)? == 0 {
            self.free_cluster(cluster)?;
        }
        Ok(())
    }

    /// Clears one cluster bitmap bit and records the affected accounting deltas.
    fn free_cluster(&mut self, cluster: ClusterAddress) -> Result<()> {
        let position = ClusterBitmapPosition::from_cluster(&self.volume.superblock, cluster)?;
        let group = position.group();
        let descriptor =
            BlockGroupDescriptor::read_from(&self.volume.device, &self.volume.superblock, group)?;
        let bitmap_index = self.ensure_block_bitmap_update(descriptor.block_bitmap())?;
        let bitmap = self
            .block_bitmap_updates
            .get_mut(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        if cluster_bitmap_bit_state(bitmap.bytes.as_slice(), position)? == BitmapBitState::Used {
            set_cluster_bitmap_bit(bitmap.bytes.as_mut_slice(), position, BitmapBitState::Free)?;
            self.record_group_free_clusters_delta(group, FreeClusterDelta::from_i64(1))?;
            self.free_clusters_delta = self.free_clusters_delta.checked_add(1)?;
            Ok(())
        } else {
            Err(Error::ClusterReferenceConflict)
        }
    }

    /// Frees the suffix of an extent after `keep_len` blocks.
    fn free_extent(&mut self, extent: Extent, keep_len: u16) -> Result<()> {
        let start = u64::from(keep_len);
        let len = extent.len().as_u64();
        let physical_start = extent
            .physical_start()
            .get()
            .checked_add(start)
            .ok_or(Error::ArithmeticOverflow)?;
        for offset in start..len {
            let block = BlockAddress::new(
                extent
                    .physical_start()
                    .get()
                    .checked_add(offset)
                    .ok_or(Error::ArithmeticOverflow)?,
            );
            self.release_cluster_reference(block)?;
        }
        if physical_start > extent.physical_start().get() || keep_len == 0 {
            Ok(())
        } else {
            Err(Error::ArithmeticOverflow)
        }
    }

    /// Allocates the first non-reserved inode visible in inode bitmaps.
    fn allocate_inode(&mut self) -> Result<AllocatedInodeRecord> {
        let groups = self.volume.superblock.block_group_count()?;
        for group in 0..groups.as_u32() {
            let group = BlockGroupId::from_u32(group);
            let descriptor = BlockGroupDescriptor::read_from(
                &self.volume.device,
                &self.volume.superblock,
                group,
            )?;
            if descriptor.free_inodes_count() == 0 {
                continue;
            }
            let bitmap_index = self.ensure_inode_bitmap_update(descriptor.inode_bitmap())?;
            let inodes_in_group = self.inodes_in_group(group)?;
            for bit in 0..inodes_in_group {
                let position = InodeBitmapPosition::new(group, bit);
                let inode_id = position.inode_id(&self.volume.superblock)?;
                if inode_id.as_u32() < self.volume.superblock.first_inode().as_u32() {
                    continue;
                }
                let bitmap = self
                    .inode_bitmap_updates
                    .get_mut(bitmap_index)
                    .ok_or(Error::InvalidSuperblock)?;
                if inode_bitmap_bit_state(bitmap.bytes.as_slice(), position)?
                    == BitmapBitState::Free
                {
                    set_inode_bitmap_bit(
                        bitmap.bytes.as_mut_slice(),
                        position,
                        BitmapBitState::Used,
                    )?;
                    self.record_group_free_inodes_delta(group, -1)?;
                    return self.empty_allocated_inode_record(inode_id);
                }
            }
        }
        Err(Error::NoFreeInode)
    }

    /// Marks an inode free and records its group allocation delta.
    fn free_inode(&mut self, inode_id: InodeId) -> Result<()> {
        if inode_id == InodeId::ROOT {
            return Err(Error::CannotRemoveRoot);
        }
        let position = InodeBitmapPosition::from_inode(&self.volume.superblock, inode_id)?;
        let group = position.group();
        let descriptor =
            BlockGroupDescriptor::read_from(&self.volume.device, &self.volume.superblock, group)?;
        let bitmap_index = self.ensure_inode_bitmap_update(descriptor.inode_bitmap())?;
        let bitmap = self
            .inode_bitmap_updates
            .get_mut(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        if inode_bitmap_bit_state(bitmap.bytes.as_slice(), position)? == BitmapBitState::Used {
            set_inode_bitmap_bit(bitmap.bytes.as_mut_slice(), position, BitmapBitState::Free)?;
            self.record_group_free_inodes_delta(group, 1)?;
        }
        Ok(())
    }

    /// Stages zeroes for the remainder of a partially truncated data block.
    fn zero_truncated_tail(
        &mut self,
        extents: &[Extent],
        new_size: FileSize,
        block_size: u64,
    ) -> Result<()> {
        let logical_block = new_size
            .bytes()
            .checked_div(block_size)
            .ok_or(Error::InvalidSuperblock)?;
        let in_block = new_size
            .bytes()
            .checked_rem(block_size)
            .ok_or(Error::InvalidSuperblock)?;
        let BlockMapping::Physical(physical) =
            map_extents(extents, LogicalBlock::try_from(logical_block)?)
        else {
            return Ok(());
        };
        let zero_len = block_size
            .checked_sub(in_block)
            .ok_or(Error::ArithmeticOverflow)?;
        let offset = self
            .volume
            .superblock
            .block_size()
            .offset_of(physical)?
            .get()
            .checked_add(in_block)
            .ok_or(Error::ArithmeticOverflow)?;
        self.data_writes.push(RangeWrite {
            offset: ByteOffset::new(offset),
            bytes: vec![0_u8; usize::try_from(zero_len).map_err(|_| Error::ArithmeticOverflow)?],
        });
        Ok(())
    }

    /// Stages encrypted zeroes for the plaintext suffix of a truncated block.
    fn zero_encrypted_truncated_tail(
        &mut self,
        inode: &Inode,
        extents: &[Extent],
        new_size: FileSize,
        block_size: u64,
    ) -> Result<()> {
        let logical_block = new_size
            .bytes()
            .checked_div(block_size)
            .ok_or(Error::InvalidSuperblock)?;
        let in_block = new_size
            .bytes()
            .checked_rem(block_size)
            .ok_or(Error::InvalidSuperblock)?;
        let BlockMapping::Physical(physical) =
            map_extents(extents, LogicalBlock::try_from(logical_block)?)
        else {
            return Ok(());
        };
        let contents_key = self.volume.fscrypt_contents_key_for_inode(inode)?;
        let zero_len = usize::try_from(
            block_size
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .map_err(|_| Error::ArithmeticOverflow)?;
        let zeroes = vec![0_u8; zero_len];
        self.stage_encrypted_file_block_update(
            &contents_key,
            LogicalBlock::try_from(logical_block)?,
            physical,
            in_block,
            &zeroes,
            EncryptedBlockBase::ExistingPlaintext,
        )
    }

    /// Returns the staged block bitmap index, loading it once when needed.
    fn ensure_block_bitmap_update(&mut self, bitmap_block: BlockAddress) -> Result<usize> {
        if let Some(index) = self
            .block_bitmap_updates
            .iter()
            .position(|image| image.block == bitmap_block)
        {
            return Ok(index);
        }
        let mut bytes = vec![
            0_u8;
            usize::try_from(self.volume.superblock.block_size().bytes())
                .map_err(|_| Error::ArithmeticOverflow)?
        ];
        self.volume.device.read_exact_at(
            self.volume
                .superblock
                .block_size()
                .offset_of(bitmap_block)?,
            &mut bytes,
        )?;
        self.block_bitmap_updates.push(BlockImage {
            block: bitmap_block,
            bytes,
        });
        self.block_bitmap_updates
            .len()
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)
    }

    /// Returns the staged inode bitmap index, loading it once when needed.
    fn ensure_inode_bitmap_update(&mut self, bitmap_block: BlockAddress) -> Result<usize> {
        if let Some(index) = self
            .inode_bitmap_updates
            .iter()
            .position(|image| image.block == bitmap_block)
        {
            return Ok(index);
        }
        let mut bytes = vec![
            0_u8;
            usize::try_from(self.volume.superblock.block_size().bytes())
                .map_err(|_| Error::ArithmeticOverflow)?
        ];
        self.volume.device.read_exact_at(
            self.volume
                .superblock
                .block_size()
                .offset_of(bitmap_block)?,
            &mut bytes,
        )?;
        self.inode_bitmap_updates.push(BlockImage {
            block: bitmap_block,
            bytes,
        });
        self.inode_bitmap_updates
            .len()
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)
    }

    /// Returns the inode count actually present in a possibly partial group.
    fn inodes_in_group(&self, group: BlockGroupId) -> Result<u32> {
        let group_start = u64::from(group.as_u32())
            .checked_mul(u64::from(
                self.volume.superblock.inodes_per_group().as_u32(),
            ))
            .ok_or(Error::ArithmeticOverflow)?;
        let remaining = u64::from(self.volume.superblock.inode_count().as_u32())
            .checked_sub(group_start)
            .ok_or(Error::InvalidSuperblock)?;
        Ok(core::cmp::min(
            self.volume.superblock.inodes_per_group().as_u32(),
            u32::try_from(remaining).unwrap_or(u32::MAX),
        ))
    }

    /// Creates a zeroed inode record at the allocated inode's device offset.
    fn empty_allocated_inode_record(&self, inode_id: InodeId) -> Result<AllocatedInodeRecord> {
        Ok(RawInodeRecord {
            id: inode_id,
            offset: inode_offset_on_device(&self.volume.device, &self.volume.superblock, inode_id)?,
            bytes: vec![0_u8; usize::from(self.volume.superblock.inode_size().as_u16())],
        }
        .into_allocated())
    }

    /// Returns the mutable delta accumulator for a block group.
    fn group_delta_mut(&mut self, group: BlockGroupId) -> Result<&mut GroupDelta> {
        if let Some(index) = self
            .group_deltas
            .iter()
            .position(|entry| entry.group == group)
        {
            return self
                .group_deltas
                .get_mut(index)
                .ok_or(Error::InvalidSuperblock);
        }
        self.group_deltas.push(GroupDelta::new(group));
        self.group_deltas.last_mut().ok_or(Error::InvalidSuperblock)
    }

    /// Records a free-cluster count delta for one block group.
    fn record_group_free_clusters_delta(
        &mut self,
        group: BlockGroupId,
        delta: FreeClusterDelta,
    ) -> Result<()> {
        let entry = self.group_delta_mut(group)?;
        entry.free_clusters_delta = entry.free_clusters_delta.checked_add(delta.as_i64())?;
        Ok(())
    }

    /// Records a free-inode count delta for one block group and the superblock.
    fn record_group_free_inodes_delta(&mut self, group: BlockGroupId, delta: i64) -> Result<()> {
        let entry = self.group_delta_mut(group)?;
        entry.free_inodes_delta = entry
            .free_inodes_delta
            .checked_add(delta)
            .ok_or(Error::ArithmeticOverflow)?;
        self.free_inodes_delta = self
            .free_inodes_delta
            .checked_add(delta)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(())
    }

    /// Records a used-directory count delta for one block group.
    fn record_group_used_dirs_delta(&mut self, group: BlockGroupId, delta: i64) -> Result<()> {
        let entry = self.group_delta_mut(group)?;
        entry.used_dirs_delta = entry
            .used_dirs_delta
            .checked_add(delta)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(())
    }
}
