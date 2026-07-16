//! Journaled write transaction domain for mounted ext4 volumes.

use super::scope::*;

mod allocation;
mod commit;
mod file_data;
mod namespace;
mod staging;
mod xattr;

use commit::{
    descriptor_byte_count, directory_entry_kind, map_extents, reject_reserved_directory_name,
    verity_metadata_image,
};
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

/// How a rename handles an already existing target name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameTargetCollision {
    /// The target name must be absent.
    Reject,
    /// The target name may be replaced by the source entry.
    Replace,
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
pub struct JournalTransaction<'a, D: BlockStorage, N, J = InternalJournal> {
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

impl<'a, D: BlockStorage, N, J> JournalTransaction<'a, D, N, J> {
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
impl<D: BlockStorage, N: FscryptNonceGenerator, J> JournalTransaction<'_, D, N, J> {
    /// Verifies that the mounted profile admits xattr storage mutation.
    /// # Errors
    ///
    /// Returns an error when mounted xattr feature flags do not permit xattr storage mutation.
    fn require_xattr_mutation(&self) -> Result<()> {
        self.volume.superblock.xattr_mutation().require_supported()
    }

    /// Verifies that an inode size is representable by the mounted profile.
    /// # Errors
    ///
    /// Returns an error when `size` exceeds the active inode file-size encoding.
    fn require_inode_size_supported(&self, size: FileSize) -> Result<()> {
        self.volume
            .superblock
            .file_size_encoding()
            .require_supported(size.bytes(), LEGACY_FILE_SIZE_LIMIT)
    }

    /// Verifies that an inode block charge is representable by the mounted profile.
    /// # Errors
    ///
    /// Returns an error when `blocks` cannot be converted to sectors or exceeds the active
    /// `i_blocks` encoding.
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
    /// # Errors
    ///
    /// Returns an error when staged cluster deltas conflict or the superblock free-cluster delta
    /// cannot be applied.
    fn committed_cluster_state(&self) -> Result<(ClusterReferenceIndex, Superblock)> {
        let mut clusters = self.volume.state.clusters.try_clone()?;
        clusters.apply_deltas(self.cluster_deltas.as_slice())?;
        let mut superblock = self.volume.superblock;
        superblock.apply_free_cluster_delta(self.free_clusters_delta)?;
        Ok((clusters, superblock))
    }

    /// Verifies directory-entry creation policy using the latest staged inode.
    /// # Errors
    ///
    /// Returns an error when the parent inode cannot be loaded from staged/device state or does not
    /// permit directory-entry creation.
    fn require_directory_entry_create_mutation(
        &self,
        inode_id: InodeId,
    ) -> Result<DirectoryEntryMutationCapability> {
        let raw_inode = self.raw_inode_for_policy(inode_id)?;
        let inode = raw_inode.parse()?;
        self.require_directory_entry_create_mutation_for_inode(&inode)
    }

    /// Verifies directory-entry creation policy with mount-scoped fscrypt keys.
    /// # Errors
    ///
    /// Returns an error when `inode` is not a directory, lacks a required fscrypt key, or its
    /// storage policy rejects entry creation.
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
    /// # Errors
    ///
    /// Returns an error when `inode` is not a directory or its storage policy rejects entry
    /// deletion.
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
    /// # Errors
    ///
    /// Returns an error when the source directory cannot satisfy entry creation-style mutation
    /// requirements for rename staging.
    fn require_directory_entry_rename_mutation_for_inode(
        &self,
        inode: &Inode,
    ) -> Result<DirectoryEntryMutationCapability> {
        self.require_directory_entry_create_mutation_for_inode(inode)
    }

    /// Verifies directory-entry replacement policy with mount-scoped fscrypt keys.
    /// # Errors
    ///
    /// Returns an error when the target directory cannot satisfy entry creation-style mutation
    /// requirements for replacement staging.
    fn require_directory_entry_replace_mutation_for_inode(
        &self,
        inode: &Inode,
    ) -> Result<DirectoryEntryMutationCapability> {
        self.require_directory_entry_create_mutation_for_inode(inode)
    }

    /// Builds the fscrypt context inherited by a new child of this directory.
    /// # Errors
    ///
    /// Returns an error when the encrypted parent has no mounted master key or a new file nonce
    /// cannot be generated.
    fn inherited_fscrypt_context(&mut self, parent: &Inode) -> Result<Option<FscryptContextV2>> {
        if !parent.protection().is_encrypted() {
            return Ok(None);
        }
        let (parent_context, _master_key) = self.volume.fscrypt_master_key_for_inode(parent)?;
        let nonce = self.volume.mount_context.next_fscrypt_file_nonce()?;
        Ok(Some(FscryptContextV2::new(parent_context.policy(), nonce)))
    }

    /// Stores an inherited fscrypt context on a newly-initialized live inode.
    /// # Errors
    ///
    /// Returns an error when xattr mutation is unsupported, the encryption flag cannot be written,
    /// or the context cannot be stored in inode xattr storage.
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
    /// # Errors
    ///
    /// Returns an error when an existing staged record is deleted or the live inode cannot be read
    /// from the mounted device.
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

    /// Loads a mutable extent tree for an inode selected by this transaction.
    /// # Errors
    ///
    /// Returns an error when the inode does not expose a supported extent root or its extent tree
    /// cannot be loaded.
    fn mutable_extent_tree(&self, inode: &Inode) -> Result<MutableExtentTree> {
        MutableExtentTree::load_inode_tree(
            inode.extent_root()?,
            self.volume.superblock.block_size(),
            &self.volume.device,
            self.volume.extent_tree_context(inode),
        )
    }

    /// Stages an updated extent tree and adjusts its metadata block ownership.
    /// # Errors
    ///
    /// Returns an error when metadata block allocation or release fails, extent serialization fails,
    /// or the updated inode block charge cannot be represented.
    fn stage_extent_tree(
        &mut self,
        raw_inode: &mut LiveInodeRecord,
        mut tree: MutableExtentTree,
    ) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let required = tree.required_metadata_blocks(block_size)?;
        let mut metadata_blocks = memory::copied_slice(tree.metadata_blocks())?;
        while metadata_blocks.len() < required {
            metadata_blocks.try_push(self.allocate_cluster()?)?;
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
    /// # Errors
    ///
    /// Returns an error when extent block arithmetic overflows or a physical block cannot be mapped
    /// to mounted cluster geometry.
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
                    clusters.try_push(cluster)?;
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
    /// # Errors
    ///
    /// Returns an error when the serialized inode-root extent payload cannot be written.
    fn stage_serialized_extent_tree(
        &mut self,
        raw_inode: &mut LiveInodeRecord,
        serialized: &SerializedExtentTree,
    ) -> Result<()> {
        raw_inode.set_extent_root_bytes(serialized.inode_root())?;
        for block in serialized.external_blocks() {
            self.extent_updates.try_push(BlockImage {
                block: block.block(),
                bytes: memory::copied_slice(block.bytes())?,
            })?;
        }
        Ok(())
    }

    /// Increments a directory inode link count and updates timestamps.
    /// # Errors
    ///
    /// Returns an error when the directory inode cannot be staged, its link count is saturated, or
    /// timestamps cannot be written.
    fn increment_directory_links(&mut self, inode_id: InodeId) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        raw_inode.increment_links_count()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Decrements a directory inode link count and updates timestamps.
    /// # Errors
    ///
    /// Returns an error when the directory inode cannot be staged or the decremented link count and
    /// timestamps cannot be written.
    fn decrement_directory_links(&mut self, inode_id: InodeId) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let _links = raw_inode.decrement_links_count()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Returns the staged inode record index, loading it once when needed.
    /// # Errors
    ///
    /// Returns an error when `inode_id` cannot be read as a live inode or the staged index cannot be
    /// represented.
    fn ensure_inode_update(&mut self, inode_id: InodeId) -> Result<StagedInodeIndex> {
        if let Some(index) = self
            .inode_updates
            .iter()
            .position(|inode| inode.id() == inode_id)
        {
            return Ok(StagedInodeIndex::new(index));
        }
        let raw_inode = self.volume.read_live_inode_record(inode_id)?;
        self.inode_updates.try_push(raw_inode.into())?;
        Ok(StagedInodeIndex::new(
            self.inode_updates
                .len()
                .checked_sub(1)
                .ok_or(Error::ArithmeticOverflow)?,
        ))
    }

    /// Returns a staged live inode record by index.
    /// # Errors
    ///
    /// Returns an error when `index` is outside the staging vector or refers to a deleted inode.
    fn staged_live_inode(&self, index: StagedInodeIndex) -> Result<LiveInodeRecord> {
        self.inode_updates
            .get(index.get())
            .ok_or(Error::InvalidInode)?
            .clone_live()
    }

    /// Replaces a staged inode with its updated live state.
    /// # Errors
    ///
    /// Returns an error when `index` is outside the staged inode vector.
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
    /// # Errors
    ///
    /// Returns an error when `index` is outside the staged inode vector.
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
}
