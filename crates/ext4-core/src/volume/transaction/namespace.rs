//! Directory namespace mutation and directory-entry staging.

use super::*;

/// Existing target outcome for a replace-capable rename.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingRenameTarget {
    /// No target entry exists.
    Absent,
    /// A distinct target entry was removed from the namespace.
    Removed,
    /// The target entry already names the source inode.
    SameInode,
}

/// One staged-aware root or interior-node level on a mutation path.
#[derive(Debug, Eq, PartialEq)]
struct MutationHtreeLevel {
    /// Logical block containing this index (`0` for the root).
    logical: u32,
    /// Physical block receiving a rewritten image.
    physical: BlockAddress,
    /// Validated routing table at this level.
    index: DxIndex,
    /// Child selected for the mutation key.
    selected: usize,
}

/// Bounded root-to-leaf mutation route.
#[derive(Debug, Eq, PartialEq)]
struct MutationHtreePath {
    /// Resident root-to-leaf routing levels.
    levels: Vec<MutationHtreeLevel>,
}

impl MutationHtreePath {
    /// Returns the leaf logical block selected by the deepest route.
    /// # Errors
    ///
    /// Returns an error when the path is empty, the selected route is absent, or the selected leaf
    /// points back to a resident index block.
    fn leaf(&self) -> Result<u32> {
        let leaf = self
            .levels
            .last()
            .and_then(|level| level.index.entry(level.selected))
            .map(|entry| entry.block())
            .ok_or(Error::InvalidDirectoryEntry)?;
        if self.levels.iter().any(|level| level.logical == leaf) {
            return Err(Error::InvalidDirectoryEntry);
        }
        Ok(leaf)
    }

    /// Returns the effective boundary of the currently selected leaf route.
    /// # Errors
    ///
    /// Returns an error when the path is empty or the selected route is absent.
    fn boundary(&self) -> Result<u32> {
        if self.levels.is_empty() {
            return Err(Error::InvalidDirectoryEntry);
        }
        let mut boundary = 0;
        for level in &self.levels {
            boundary = level.index.route_boundary(level.selected, boundary)?;
        }
        Ok(boundary)
    }

    /// Reconstructs the primary-hash interval selected by this route.
    /// # Errors
    ///
    /// Returns an error when a selected route is absent or violates its parent interval.
    fn hash_range(&self) -> Result<HtreeHashRange> {
        let mut range = HtreeHashRange::root();
        for level in &self.levels {
            range = range.descend(&level.index, level.selected)?;
        }
        Ok(range)
    }
}

/// Root bytes, parsed root semantics, and selected mutation route.
struct HtreeMutationContext {
    /// Parsed root semantics and hash context.
    root: HtreeRoot,
    /// Mutable serialized root image staged only after routing changes succeed.
    root_bytes: Vec<u8>,
    /// Active staged-aware route selected for this mutation.
    path: MutationHtreePath,
}

/// One exact entry's staged-aware mutable leaf location.
struct DirectoryEntryLocation {
    /// Physical leaf block receiving the mutation.
    physical: BlockAddress,
    /// Parsed staged-aware leaf image.
    block: DirectoryBlock,
}

/// Selection mode for a staged-aware HTree route.
enum HtreePathTarget<'name> {
    /// Select the leaf routed by an exact raw name.
    Name(&'name Ext4Name),
    /// Select the first leaf in index order.
    First,
}

impl MutationResolvePass<'_, '_, '_> {
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
        self.inode_updates.try_push(raw_inode.into())?;
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

    /// Creates a hard link to a non-directory inode.
    ///
    /// # Errors
    /// Returns an error when the destination state has changed, replacement selects a directory,
    /// encryption policies differ, the source link count is saturated, or metadata cannot be
    /// staged.
    pub fn create_hard_link(
        &mut self,
        source: TransactionHardLinkSource,
        target_parent: TransactionDirectory,
        target_name: &Ext4Name,
        destination: HardLinkDestination<'_>,
    ) -> Result<()> {
        reject_reserved_directory_name(target_name)?;
        let source_inode_id = source.inode();
        let source_index = self.ensure_inode_update(source_inode_id)?;
        let mut raw_source = self.staged_live_inode(source_index)?;
        let source_inode = raw_source.parse()?;
        let _metadata = source_inode.metadata_mutation()?;
        let target_parent_inode = self.raw_inode_for_policy(target_parent.inode())?.parse()?;
        self.require_hard_link_encryption_policy(&source_inode, &target_parent_inode)?;

        let mut add_link = true;
        match destination {
            HardLinkDestination::Vacant => {
                self.ensure_child_absent(target_parent.inode(), target_name)?;
            }
            HardLinkDestination::Replace { existing_name } => {
                let existing = self.find_child_entry(target_parent.inode(), existing_name)?;
                if existing.inode() == source_inode_id {
                    add_link = false;
                    if existing_name != target_name {
                        let renamed = self.rename_directory_entry(
                            target_parent.inode(),
                            existing_name,
                            target_name,
                            source_inode_id,
                            source.entry_kind(),
                        )?;
                        if renamed.inode() != source_inode_id {
                            return Err(Error::InvalidDirectoryEntry);
                        }
                    }
                } else {
                    let existing_kind =
                        self.raw_inode_for_policy(existing.inode())?.parse()?.kind();
                    match existing_kind {
                        InodeKind::File => {
                            self.unlink_file(target_parent, existing_name)?;
                        }
                        InodeKind::Symlink => {
                            self.remove_symlink(target_parent, existing_name)?;
                        }
                        InodeKind::Directory => return Err(Error::WrongInodeKind),
                    }
                }
            }
        }

        if add_link {
            self.add_directory_entry(
                target_parent.inode(),
                target_name,
                source_inode_id,
                source.entry_kind(),
            )?;
            raw_source.increment_links_count()?;
        }
        raw_source.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(source_index, raw_source)?;
        Ok(())
    }

    /// Requires a hard-link source and destination directory to share one fscrypt policy.
    /// # Errors
    ///
    /// Returns an error when only one inode is encrypted, a context is missing, or policies differ.
    fn require_hard_link_encryption_policy(
        &mut self,
        source: &Inode,
        target_parent: &Inode,
    ) -> Result<()> {
        match (
            source.protection().is_encrypted(),
            target_parent.protection().is_encrypted(),
        ) {
            (false, false) => Ok(()),
            (true, true) => {
                let source_context = self
                    .volume
                    .read_inode_fscrypt_context(source.id())?
                    .ok_or(Error::InvalidEncryptionContext)?;
                let target_context = self
                    .volume
                    .read_inode_fscrypt_context(target_parent.id())?
                    .ok_or(Error::InvalidEncryptionContext)?;
                if source_context.policy() == target_context.policy() {
                    Ok(())
                } else {
                    Err(Error::UnsupportedEncryption)
                }
            }
            (true, false) | (false, true) => Err(Error::UnsupportedEncryption),
        }
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
        let allocation_size = FileAllocationSize::from_bytes(
            allocated_blocks
                .checked_mul(u64::from(block_size.bytes()))
                .ok_or(Error::ArithmeticOverflow)?,
        );
        let mut raw_inode = allocated_inode.initialize_directory(
            metadata,
            self.now,
            block_size,
            block,
            allocation_size,
            self.volume.superblock.inode_timestamp_encoding(),
        )?;
        self.apply_fscrypt_context(&mut raw_inode, inherited_context)?;
        let inode_id = raw_inode.id();
        let directory_checksum = self.volume.directory_checksum(&raw_inode.parse()?);

        let mut directory = DirectoryBlock::empty(
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
            directory_checksum,
        )?;
        directory.initialize_dot_entries(inode_id, parent.inode())?;
        self.stage_directory_block(block, directory.into_bytes())?;

        self.add_directory_entry(
            parent.inode(),
            name,
            inode_id,
            DirectoryEntryKind::Directory,
        )?;
        self.increment_directory_links(parent.inode())?;
        let group = InodeBitmapPosition::from_inode(&self.volume.superblock, inode_id)?.group();
        self.record_group_used_dirs_delta(group, 1)?;
        self.inode_updates.try_push(raw_inode.into())?;
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
            if block_bytes == 0 {
                return Err(Error::UnsupportedBlockSize);
            }
            let mut tree = MutableExtentTree::from_extents(Vec::new())?;
            let mut logical = 0_u64;
            let mut remaining = target.bytes();
            while !remaining.is_empty() {
                let chunk_len = core::cmp::min(block_bytes, remaining.len());
                let (chunk, remainder) = remaining
                    .split_at_checked(chunk_len)
                    .ok_or(Error::InvalidWriteRange)?;
                let block = self.allocate_cluster()?;
                let mut bytes = memory::repeated_vec(0_u8, block_bytes)?;
                memory::copy_exact(
                    bytes.get_mut(..chunk.len()).ok_or(Error::DeviceRange)?,
                    chunk,
                )?;
                self.data_writes.try_push(RangeWrite {
                    offset: block_size.offset_of(block)?,
                    bytes,
                })?;
                tree.insert_or_extend_initialized(LogicalBlock::try_from(logical)?, block)?;
                remaining = remainder;
                if !remaining.is_empty() {
                    logical = logical.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                }
            }
            self.stage_extent_tree(&mut raw_inode, tree)?;
            raw_inode
        };
        let inode_id = raw_inode.id();
        self.add_directory_entry(parent.inode(), name, inode_id, DirectoryEntryKind::Symlink)?;
        self.inode_updates.try_push(raw_inode.into())?;
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

    /// Renames or moves a child entry.
    ///
    /// # Errors
    /// Returns an error when the source entry is absent, the target collision mode rejects an
    /// existing target, either parent is outside the mutable directory domain, or a moved directory
    /// cannot have its parent link updated.
    pub fn rename_child(
        &mut self,
        source_parent: TransactionDirectory,
        source_name: &Ext4Name,
        target_parent: TransactionDirectory,
        target_name: &Ext4Name,
        target_collision: RenameTargetCollision,
    ) -> Result<()> {
        reject_reserved_directory_name(source_name)?;
        reject_reserved_directory_name(target_name)?;

        let source_parent = source_parent.inode();
        let target_parent = target_parent.inode();
        let source = self.find_child_entry(source_parent, source_name)?;
        if source_parent == target_parent && source_name == target_name {
            return Ok(());
        }
        if matches!(target_collision, RenameTargetCollision::Reject) {
            self.ensure_child_absent(target_parent, target_name)?;
        }

        let child_index = self.ensure_inode_update(source.inode())?;
        let mut child_raw = self.staged_live_inode(child_index)?;
        let child_inode = child_raw.parse()?;
        let _metadata = child_inode.metadata_mutation()?;
        if child_inode.kind() == InodeKind::Directory && source.inode() == InodeId::ROOT {
            return Err(Error::CannotRemoveRoot);
        }
        let kind = directory_entry_kind(child_inode.kind());
        if matches!(target_collision, RenameTargetCollision::Replace) {
            let existing_target = self.remove_existing_rename_target(
                target_parent,
                target_name,
                source.inode(),
                child_inode.kind(),
            )?;
            if matches!(existing_target, ExistingRenameTarget::SameInode) {
                return Ok(());
            }
        }

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

    /// Removes the existing target entry for a replace-capable rename.
    /// # Errors
    ///
    /// Returns an error when the target exists with a kind that cannot be replaced by the source
    /// kind or when the target's deletion policy rejects removal.
    fn remove_existing_rename_target(
        &mut self,
        target_parent: InodeId,
        target_name: &Ext4Name,
        source: InodeId,
        source_kind: InodeKind,
    ) -> Result<ExistingRenameTarget> {
        let target = match self.find_child_entry(target_parent, target_name) {
            Ok(target) => target,
            Err(Error::DirectoryEntryNotFound) => return Ok(ExistingRenameTarget::Absent),
            Err(error) => return Err(error),
        };
        if target.inode() == source {
            return Ok(ExistingRenameTarget::SameInode);
        }

        let target_kind = self.raw_inode_for_policy(target.inode())?.parse()?.kind();
        let target_parent = TransactionDirectory {
            id: DirectoryNodeId::new(target_parent),
        };
        match (source_kind, target_kind) {
            (InodeKind::Directory, InodeKind::Directory) => {
                self.remove_empty_directory(target_parent, target_name)?;
            }
            (InodeKind::Directory, InodeKind::File | InodeKind::Symlink)
            | (InodeKind::File | InodeKind::Symlink, InodeKind::Directory) => {
                return Err(Error::WrongInodeKind);
            }
            (InodeKind::File | InodeKind::Symlink, InodeKind::File) => {
                self.unlink_file(target_parent, target_name)?;
            }
            (InodeKind::File | InodeKind::Symlink, InodeKind::Symlink) => {
                self.remove_symlink(target_parent, target_name)?;
            }
        }
        Ok(ExistingRenameTarget::Removed)
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

    /// Verifies that a directory does not already contain `name`.
    /// # Errors
    ///
    /// Returns an error when `name` already exists in `parent` or the parent directory cannot be
    /// searched.
    fn ensure_child_absent(&mut self, parent: InodeId, name: &Ext4Name) -> Result<()> {
        match self.find_child_entry(parent, name) {
            Ok(_) => Err(Error::NameAlreadyExists),
            Err(Error::DirectoryEntryNotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Finds a live directory entry by exact ext4 name.
    /// # Errors
    ///
    /// Returns an error when `parent` is not a directory, its lookup name cannot be derived, or the
    /// requested entry is absent.
    fn find_child_entry(&mut self, parent: InodeId, name: &Ext4Name) -> Result<RawDirectoryEntry> {
        let inode = self.raw_inode_for_policy(parent)?.parse()?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        let lookup_name = self.directory_lookup_name(&inode, name)?;
        if let Some(location) = self.directory_entry_location(&inode, &lookup_name)? {
            return location
                .block
                .find(&lookup_name)?
                .ok_or(Error::InvalidDirectoryEntry);
        }
        Err(Error::DirectoryEntryNotFound)
    }

    /// Returns the on-disk name to use for a directory lookup inside this transaction.
    /// # Errors
    ///
    /// Returns an error when the encrypted lookup name cannot be derived and no locked-directory
    /// ciphertext fallback can represent `name`.
    fn directory_lookup_name(&mut self, directory: &Inode, name: &Ext4Name) -> Result<Ext4Name> {
        match self
            .volume
            .encrypt_directory_child_name(directory, name, self.crypto)
        {
            Err(Error::MissingEncryptionKey) => {
                if let Some(ciphertext) = EpochReadView::locked_directory_ciphertext_name(name)? {
                    Ok(ciphertext)
                } else {
                    Ext4Name::new(name.bytes())
                }
            }
            result => result,
        }
    }

    /// Adds a child entry to a mutable directory, extending it when supported.
    /// # Errors
    ///
    /// Returns an error when `parent` is not mutable, `name` already exists, encryption or local
    /// HTree routing/split fails, or a new directory block cannot be allocated and staged.
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
        let disk_name =
            self.volume
                .encrypt_directory_child_name(&parent_inode, name, self.crypto)?;
        if self
            .directory_entry_location(&parent_inode, &disk_name)?
            .is_some()
        {
            return Err(Error::NameAlreadyExists);
        }
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            return self.insert_htree_directory_entry(
                inode_index,
                raw_parent,
                &parent_inode,
                RawDirectoryEntry::new(child, &disk_name, kind)?,
            );
        }

        let mut tree = self.mutable_extent_tree(&parent_inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let block_size = self.volume.superblock.block_size();
        let block_size_u64 = u64::from(block_size.bytes());
        let block_count = round_up_div(parent_inode.size().bytes(), block_size_u64)?;
        for logical in 0..block_count {
            let (physical, mut block) = self.read_mutation_directory_block(
                &parent_inode,
                &tree,
                LogicalBlock::try_from(logical)?,
            )?;
            if block.insert(child, &disk_name, kind)? {
                self.stage_directory_block(physical, block.into_bytes())?;
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                return Ok(());
            }
        }

        if block_count == 1
            && !matches!(
                self.volume.superblock.directory_indexing(),
                DirectoryIndexing::Disabled
            )
        {
            return self.convert_linear_directory_to_htree(
                inode_index,
                raw_parent,
                &parent_inode,
                tree,
                RawDirectoryEntry::new(child, &disk_name, kind)?,
            );
        }

        let new_physical = self.allocate_cluster()?;
        let logical_block = LogicalBlock::try_from(block_count)?;
        tree.insert_or_extend_initialized(logical_block, new_physical)?;

        let mut block = DirectoryBlock::empty(
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
            self.volume.directory_checksum(&parent_inode),
        )?;
        block.initialize_free_space()?;
        let inserted = block.insert(child, &disk_name, kind)?;
        if !inserted {
            return Err(Error::InvalidDirectoryEntry);
        }
        self.stage_directory_block(new_physical, block.into_bytes())?;
        let new_parent_size = FileSize::from_bytes(
            parent_inode
                .size()
                .bytes()
                .checked_add(block_size_u64)
                .ok_or(Error::ArithmeticOverflow)?,
        );
        let encoded_size = self
            .volume
            .superblock
            .inode_data_encoding()
            .encode_directory_size(DirectorySize::from_bytes(new_parent_size.bytes()))?;
        raw_parent.set_encoded_size(encoded_size)?;
        raw_parent.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_parent, tree)?;
        self.replace_live_inode(inode_index, raw_parent)?;
        Ok(())
    }

    /// Removes a child entry from a mutable directory.
    /// # Errors
    ///
    /// Returns an error when `parent` is not mutable, `name` is absent, or the linear/HTree
    /// directory image cannot be rewritten.
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
        let Some(mut location) = self.directory_entry_location(&parent_inode, &disk_name)? else {
            return Err(Error::DirectoryEntryNotFound);
        };
        let removed = location
            .block
            .remove(&disk_name)?
            .ok_or(Error::DirectoryEntryNotFound)?;
        self.stage_directory_block(location.physical, location.block.into_bytes())?;
        raw_parent.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_parent)?;
        Ok(removed)
    }

    /// Renames a child entry while preserving the expected child inode and kind.
    /// # Errors
    ///
    /// Returns an error when the old entry is absent, the new name already exists, the existing
    /// entry does not match `child`, or the directory image cannot be rewritten.
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
        let old_disk_name =
            self.volume
                .encrypt_directory_child_name(&parent_inode, old_name, self.crypto)?;
        let new_disk_name =
            self.volume
                .encrypt_directory_child_name(&parent_inode, new_name, self.crypto)?;
        if self
            .directory_entry_location(&parent_inode, &new_disk_name)?
            .is_some()
        {
            return Err(Error::NameAlreadyExists);
        }
        let Some(mut source) = self.directory_entry_location(&parent_inode, &old_disk_name)? else {
            return Err(Error::DirectoryEntryNotFound);
        };
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            let tree = self.mutable_extent_tree(&parent_inode)?;
            let target_context = self.mutation_htree_context(
                &parent_inode,
                &tree,
                HtreePathTarget::Name(&new_disk_name),
            )?;
            let (target_physical, _target_block) = self.read_mutation_directory_block(
                &parent_inode,
                &tree,
                LogicalBlock::try_from(u64::from(target_context.path.leaf()?))?,
            )?;
            if target_physical == source.physical {
                let renamed = source
                    .block
                    .rename(&old_disk_name, &new_disk_name)?
                    .ok_or(Error::DirectoryEntryNotFound)?;
                if renamed.inode() != child {
                    return Err(Error::InvalidDirectoryEntry);
                }
                let replacement = source.block.replace(&new_disk_name, child, kind)?;
                if replacement.is_none() {
                    return Err(Error::InvalidDirectoryEntry);
                }
                self.stage_directory_block(source.physical, source.block.into_bytes())?;
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                return Ok(renamed);
            }
            let renamed = source
                .block
                .remove(&old_disk_name)?
                .ok_or(Error::DirectoryEntryNotFound)?;
            if renamed.inode() != child {
                return Err(Error::InvalidDirectoryEntry);
            }
            self.stage_directory_block(source.physical, source.block.into_bytes())?;
            self.insert_htree_directory_entry(
                inode_index,
                raw_parent,
                &parent_inode,
                RawDirectoryEntry::new(child, &new_disk_name, kind)?,
            )?;
            return Ok(renamed);
        }
        match source.block.rename(&old_disk_name, &new_disk_name) {
            Ok(Some(renamed)) => {
                if renamed.inode() != child {
                    return Err(Error::InvalidDirectoryEntry);
                }
                let replacement = source.block.replace(&new_disk_name, child, kind)?;
                if replacement.is_none() {
                    return Err(Error::InvalidDirectoryEntry);
                }
                self.stage_directory_block(source.physical, source.block.into_bytes())?;
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                Ok(renamed)
            }
            Ok(None) => Err(Error::DirectoryEntryNotFound),
            Err(Error::NoSpace) => {
                let renamed = source
                    .block
                    .remove(&old_disk_name)?
                    .ok_or(Error::DirectoryEntryNotFound)?;
                if renamed.inode() != child {
                    return Err(Error::InvalidDirectoryEntry);
                }
                self.stage_directory_block(source.physical, source.block.into_bytes())?;
                self.add_directory_entry(parent, new_name, child, kind)?;
                Ok(renamed)
            }
            Err(error) => Err(error),
        }
    }

    /// Replaces the inode and kind stored for an existing directory name.
    /// # Errors
    ///
    /// Returns an error when `name` is absent, `parent` is not mutable, or the replacement cannot be
    /// staged in the directory image.
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
        let disk_name =
            self.volume
                .encrypt_directory_child_name(&parent_inode, name, self.crypto)?;
        let Some(mut location) = self.directory_entry_location(&parent_inode, &disk_name)? else {
            return Err(Error::DirectoryEntryNotFound);
        };
        let replaced = location
            .block
            .replace(&disk_name, child, kind)?
            .ok_or(Error::DirectoryEntryNotFound)?;
        self.stage_directory_block(location.physical, location.block.into_bytes())?;
        raw_parent.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_parent)?;
        Ok(replaced)
    }

    /// Stages the latest image for a mutated directory block.
    /// # Errors
    ///
    /// Returns an error when recording a new staged block image cannot allocate.
    fn stage_directory_block(&mut self, block: BlockAddress, bytes: Vec<u8>) -> Result<()> {
        if let Some(image) = self
            .directory_updates
            .iter_mut()
            .find(|image| image.block == block)
        {
            image.bytes = bytes;
        } else {
            self.directory_updates
                .try_push(BlockImage { block, bytes })?;
        }
        Ok(())
    }

    /// Reads one logical directory block, preferring this transaction's newest staged image.
    /// # Errors
    ///
    /// Returns an error when the logical block is outside the semantic directory size, is not
    /// physically mapped, has an invalid staged length, or cannot be read or allocated.
    fn read_mutation_directory_block(
        &mut self,
        inode: &Inode,
        tree: &MutableExtentTree,
        logical: LogicalBlock,
    ) -> Result<(BlockAddress, DirectoryBlock)> {
        let block_count = round_up_div(
            inode.size().bytes(),
            u64::from(self.volume.superblock.block_size().bytes()),
        )?;
        if logical.as_u64() >= block_count {
            return Err(Error::InvalidDirectoryEntry);
        }
        let physical = match tree.map_logical(logical) {
            BlockMapping::Physical(physical) => physical,
            BlockMapping::Uninitialized | BlockMapping::Hole => {
                return Err(Error::InvalidDirectoryEntry);
            }
        };
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let bytes = if let Some(staged) = self
            .directory_updates
            .iter()
            .find(|image| image.block == physical)
        {
            if staged.bytes.len() != block_bytes {
                return Err(Error::InvalidDirectoryEntry);
            }
            memory::copied_slice(&staged.bytes)?
        } else {
            let mut bytes = memory::repeated_vec(0_u8, block_bytes)?;
            self.volume
                .device
                .read_exact_at(block_size.offset_of(physical)?, &mut bytes)?;
            bytes
        };
        Ok((
            physical,
            DirectoryBlock::new(bytes, self.volume.directory_checksum(inode)),
        ))
    }

    /// Builds one staged-aware HTree path for a primary hash.
    /// # Errors
    ///
    /// Returns an error when the root or an interior node is malformed, the configured depth is
    /// unsupported, a route cycles, or a selected block cannot be read.
    fn mutation_htree_context(
        &mut self,
        inode: &Inode,
        tree: &MutableExtentTree,
        target: HtreePathTarget<'_>,
    ) -> Result<HtreeMutationContext> {
        let checksum = self.volume.directory_checksum(inode);
        let (root_physical, root_block) =
            self.read_mutation_directory_block(inode, tree, LogicalBlock::try_from(0_u64)?)?;
        let root = HtreeRoot::parse(
            root_block.bytes(),
            inode.id(),
            self.volume.superblock.directory_hash_seed(),
            self.volume
                .superblock
                .directory_indexing()
                .require_supported()?,
            checksum,
        )?;
        let major = match target {
            HtreePathTarget::Name(name) => root.hash_scheme().hash(name).major,
            HtreePathTarget::First => 0,
        };
        let mut levels = Vec::new();
        levels.try_push(MutationHtreeLevel {
            logical: 0,
            physical: root_physical,
            selected: root.index().select(major),
            index: root.index().try_clone()?,
        })?;
        for _ in 0..root.indirect_levels() {
            let logical = levels
                .last()
                .and_then(|level| level.index.entry(level.selected))
                .map(|entry| entry.block())
                .ok_or(Error::InvalidDirectoryEntry)?;
            if levels.iter().any(|level| level.logical == logical) {
                return Err(Error::InvalidDirectoryEntry);
            }
            let (physical, block) = self.read_mutation_directory_block(
                inode,
                tree,
                LogicalBlock::try_from(u64::from(logical))?,
            )?;
            let index = DxIndex::parse_node(block.bytes(), checksum)?;
            levels.try_push(MutationHtreeLevel {
                logical,
                physical,
                selected: index.select(major),
                index,
            })?;
        }
        Ok(HtreeMutationContext {
            root,
            root_bytes: root_block.into_bytes(),
            path: MutationHtreePath { levels },
        })
    }

    /// Advances a mutation path to the next leaf while keeping only the active root-to-leaf route.
    /// # Errors
    ///
    /// Returns an error when the path is malformed, an interior route cycles, or a selected block
    /// cannot be read and validated.
    fn advance_mutation_htree_path(
        &mut self,
        inode: &Inode,
        tree: &MutableExtentTree,
        path: &mut MutationHtreePath,
        indirect_levels: u8,
    ) -> Result<bool> {
        let expected_levels = usize::from(indirect_levels)
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let Some(level_to_advance) = path.levels.iter().rposition(|level| {
            level
                .selected
                .checked_add(1)
                .is_some_and(|next| next < level.index.len())
        }) else {
            return Ok(false);
        };
        let level = path
            .levels
            .get_mut(level_to_advance)
            .ok_or(Error::InvalidDirectoryEntry)?;
        level.selected = level
            .selected
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        path.levels.truncate(
            level_to_advance
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?,
        );
        let checksum = self.volume.directory_checksum(inode);
        while path.levels.len() < expected_levels {
            let logical = path
                .levels
                .last()
                .and_then(|level| level.index.entry(level.selected))
                .map(|entry| entry.block())
                .ok_or(Error::InvalidDirectoryEntry)?;
            if path.levels.iter().any(|level| level.logical == logical) {
                return Err(Error::InvalidDirectoryEntry);
            }
            let (physical, block) = self.read_mutation_directory_block(
                inode,
                tree,
                LogicalBlock::try_from(u64::from(logical))?,
            )?;
            path.levels.try_push(MutationHtreeLevel {
                logical,
                physical,
                index: DxIndex::parse_node(block.bytes(), checksum)?,
                selected: 0,
            })?;
        }
        Ok(true)
    }

    /// Finds an exact entry and returns only its mutable leaf block.
    /// # Errors
    ///
    /// Returns an error when directory mapping, HTree routing, hash intervals, or a leaf dirent
    /// stream is invalid.
    fn directory_entry_location(
        &mut self,
        inode: &Inode,
        name: &Ext4Name,
    ) -> Result<Option<DirectoryEntryLocation>> {
        let tree = self.mutable_extent_tree(inode)?;
        match inode.directory_storage_kind()? {
            DirectoryStorageKind::Linear => {
                let block_count = round_up_div(
                    inode.size().bytes(),
                    u64::from(self.volume.superblock.block_size().bytes()),
                )?;
                for logical in 0..block_count {
                    let (physical, block) = self.read_mutation_directory_block(
                        inode,
                        &tree,
                        LogicalBlock::try_from(logical)?,
                    )?;
                    if block.find(name)?.is_some() {
                        return Ok(Some(DirectoryEntryLocation { physical, block }));
                    }
                }
                Ok(None)
            }
            DirectoryStorageKind::HTree => {
                if matches!(name.bytes(), b"." | b"..") {
                    return Err(Error::InvalidDirectoryEntry);
                }
                let mut context =
                    self.mutation_htree_context(inode, &tree, HtreePathTarget::Name(name))?;
                let hash = context.root.hash_scheme().hash(name);
                loop {
                    let (physical, block) = self.read_mutation_directory_block(
                        inode,
                        &tree,
                        LogicalBlock::try_from(u64::from(context.path.leaf()?))?,
                    )?;
                    let entries = block.entries()?;
                    context
                        .path
                        .hash_range()?
                        .validate_leaf(&entries, context.root.hash_scheme())?;
                    if entries.iter().any(|entry| entry.name() == name) {
                        return Ok(Some(DirectoryEntryLocation { physical, block }));
                    }
                    if !self.advance_mutation_htree_path(
                        inode,
                        &tree,
                        &mut context.path,
                        context.root.indirect_levels(),
                    )? || context.path.boundary()? & !1 != hash.major
                    {
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// Inserts one child through the selected HTree leaf and propagates only required splits.
    /// # Errors
    ///
    /// Returns an error when routing or leaf data is invalid, a split cannot be represented, the
    /// configured index depth is exhausted, allocation fails, or staging cannot complete.
    fn insert_htree_directory_entry(
        &mut self,
        inode_index: StagedInodeIndex,
        mut raw_parent: LiveInodeRecord,
        parent_inode: &Inode,
        entry: RawDirectoryEntry,
    ) -> Result<()> {
        let mut tree = self.mutable_extent_tree(parent_inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let checksum = self.volume.directory_checksum(parent_inode);
        let mut context =
            self.mutation_htree_context(parent_inode, &tree, HtreePathTarget::Name(entry.name()))?;
        let leaf_logical = context.path.leaf()?;
        let (leaf_physical, mut leaf) = self.read_mutation_directory_block(
            parent_inode,
            &tree,
            LogicalBlock::try_from(u64::from(leaf_logical))?,
        )?;
        context
            .path
            .hash_range()?
            .validate_leaf(&leaf.entries()?, context.root.hash_scheme())?;
        if leaf.insert(entry.inode(), entry.name(), entry.kind())? {
            self.stage_directory_block(leaf_physical, leaf.into_bytes())?;
            raw_parent
                .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
            return self.replace_live_inode(inode_index, raw_parent);
        }

        if context
            .path
            .levels
            .iter()
            .all(|level| level.index.is_full())
            && context.root.indirect_levels()
                >= self
                    .volume
                    .superblock
                    .directory_indexing()
                    .require_supported()?
        {
            return Err(Error::DirectoryIndexFull);
        }
        let hash = context.root.hash_scheme();
        let mut entries = leaf.entries()?;
        entries.try_push(entry)?;
        memory::heap_sort_by(&mut entries, |left, right| {
            let left_hash = hash.hash(left.name());
            let right_hash = hash.hash(right.name());
            left_hash
                .cmp(&right_hash)
                .then(left.name().bytes().cmp(right.name().bytes()))
        })?;
        let split_at = self.directory_leaf_split(&entries, checksum)?;
        let (left_entries, right_entries) = entries
            .split_at_checked(split_at)
            .ok_or(Error::InvalidDirectoryEntry)?;
        let left_last_hash = left_entries
            .last()
            .map(|entry| hash.hash(entry.name()).major)
            .ok_or(Error::InvalidDirectoryEntry)?;
        let right_first_hash = right_entries
            .first()
            .map(|entry| hash.hash(entry.name()).major)
            .ok_or(Error::InvalidDirectoryEntry)?;
        let boundary = right_first_hash | u32::from(left_last_hash == right_first_hash);
        let block_bytes = usize::try_from(self.volume.superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let left = DirectoryBlock::from_entries(block_bytes, checksum, left_entries)?;
        let right = DirectoryBlock::from_entries(block_bytes, checksum, right_entries)?;
        let mut next_logical = round_up_div(
            parent_inode.size().bytes(),
            u64::from(self.volume.superblock.block_size().bytes()),
        )?;
        let (right_logical, right_physical) =
            self.allocate_directory_block(&mut tree, &mut next_logical)?;
        self.stage_directory_block(leaf_physical, left.into_bytes())?;
        self.stage_directory_block(right_physical, right.into_bytes())?;
        self.propagate_htree_route(
            parent_inode,
            &mut tree,
            &mut next_logical,
            &mut context,
            DxEntry::new(boundary, right_logical)?,
        )?;
        self.finish_directory_growth(inode_index, raw_parent, tree, next_logical, false)
    }

    /// Selects the deterministic byte-balanced split that leaves both leaf halves representable.
    /// # Errors
    ///
    /// Returns an error when record lengths overflow or no split can fit both resulting leaves.
    fn directory_leaf_split(
        &self,
        entries: &[RawDirectoryEntry],
        checksum: DirectoryChecksum,
    ) -> Result<usize> {
        let usable = usize::try_from(self.volume.superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?
            .checked_sub(checksum.dirent_tail_bytes())
            .ok_or(Error::InvalidDirectoryEntry)?;
        let mut total = 0_usize;
        for entry in entries {
            total = total
                .checked_add(entry.encoded_len()?)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        let mut left = 0_usize;
        let mut selected = None;
        for split in 1..entries.len() {
            let prior = split.checked_sub(1).ok_or(Error::ArithmeticOverflow)?;
            left = left
                .checked_add(
                    entries
                        .get(prior)
                        .ok_or(Error::InvalidDirectoryEntry)?
                        .encoded_len()?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            let right = total.checked_sub(left).ok_or(Error::ArithmeticOverflow)?;
            if left > usable || right > usable {
                continue;
            }
            let difference = left.abs_diff(right);
            if selected
                .as_ref()
                .is_none_or(|(_, best_difference)| difference < *best_difference)
            {
                selected = Some((split, difference));
            }
        }
        selected
            .map(|(split, _)| split)
            .ok_or(Error::InvalidDirectoryEntry)
    }

    /// Propagates one new child route, splitting index nodes by median and growing the root.
    /// # Errors
    ///
    /// Returns an error when a path route is invalid, the permitted index depth is exhausted, a
    /// node image cannot be represented, allocation fails, or staging cannot complete.
    fn propagate_htree_route(
        &mut self,
        inode: &Inode,
        tree: &mut MutableExtentTree,
        next_logical: &mut u64,
        context: &mut HtreeMutationContext,
        mut route: DxEntry,
    ) -> Result<()> {
        let checksum = self.volume.directory_checksum(inode);
        let block_bytes = usize::try_from(self.volume.superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        for level_index in (0..context.path.levels.len()).rev() {
            let split = {
                let level = context
                    .path
                    .levels
                    .get_mut(level_index)
                    .ok_or(Error::InvalidDirectoryEntry)?;
                level.index.insert_after(level.selected, route)?
            };
            let level = context
                .path
                .levels
                .get_mut(level_index)
                .ok_or(Error::InvalidDirectoryEntry)?;
            let Some(split) = split else {
                if level_index == 0 {
                    write_htree_root_index(
                        &mut context.root_bytes,
                        context.root.indirect_levels(),
                        &level.index,
                        checksum,
                    )?;
                    self.stage_directory_block(
                        level.physical,
                        memory::copied_slice(&context.root_bytes)?,
                    )?;
                } else {
                    let mut bytes = memory::repeated_vec(0_u8, block_bytes)?;
                    write_htree_node(&mut bytes, &level.index, checksum)?;
                    self.stage_directory_block(level.physical, bytes)?;
                }
                return Ok(());
            };
            if level_index == 0 {
                let maximum = self
                    .volume
                    .superblock
                    .directory_indexing()
                    .require_supported()?;
                let new_depth = context
                    .root
                    .indirect_levels()
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow)?;
                if new_depth > maximum {
                    return Err(Error::DirectoryIndexFull);
                }
                let boundary = split.boundary();
                let right = split.into_right();
                let (left_logical, left_physical) =
                    self.allocate_directory_block(tree, next_logical)?;
                let (right_logical, right_physical) =
                    self.allocate_directory_block(tree, next_logical)?;
                let mut left_bytes = memory::repeated_vec(0_u8, block_bytes)?;
                write_htree_node(&mut left_bytes, &level.index, checksum)?;
                let mut right_bytes = memory::repeated_vec(0_u8, block_bytes)?;
                write_htree_node(&mut right_bytes, &right, checksum)?;
                let mut root_routes = Vec::new();
                root_routes.try_push(DxEntry::new(0, left_logical)?)?;
                root_routes.try_push(DxEntry::new(boundary, right_logical)?)?;
                let root_index = DxIndex::root(block_bytes, checksum, root_routes)?;
                write_htree_root_index(&mut context.root_bytes, new_depth, &root_index, checksum)?;
                self.stage_directory_block(left_physical, left_bytes)?;
                self.stage_directory_block(right_physical, right_bytes)?;
                self.stage_directory_block(
                    level.physical,
                    memory::copied_slice(&context.root_bytes)?,
                )?;
                return Ok(());
            }
            let boundary = split.boundary();
            let right = split.into_right();
            let mut left_bytes = memory::repeated_vec(0_u8, block_bytes)?;
            write_htree_node(&mut left_bytes, &level.index, checksum)?;
            self.stage_directory_block(level.physical, left_bytes)?;
            let (right_logical, right_physical) =
                self.allocate_directory_block(tree, next_logical)?;
            let mut right_bytes = memory::repeated_vec(0_u8, block_bytes)?;
            write_htree_node(&mut right_bytes, &right, checksum)?;
            self.stage_directory_block(right_physical, right_bytes)?;
            route = DxEntry::new(boundary, right_logical)?;
        }
        Err(Error::InvalidDirectoryEntry)
    }

    /// Converts a one-block linear directory into a root plus the minimum indexed leaf set.
    /// # Errors
    ///
    /// Returns an error when the linear block is malformed, the new leaf or root cannot be
    /// represented, allocation fails, or the staged directory growth cannot be published.
    fn convert_linear_directory_to_htree(
        &mut self,
        inode_index: StagedInodeIndex,
        raw_parent: LiveInodeRecord,
        parent_inode: &Inode,
        mut tree: MutableExtentTree,
        entry: RawDirectoryEntry,
    ) -> Result<()> {
        let checksum = self.volume.directory_checksum(parent_inode);
        let (root_physical, block) = self.read_mutation_directory_block(
            parent_inode,
            &tree,
            LogicalBlock::try_from(0_u64)?,
        )?;
        let entries = block.entries()?;
        let dot_inode = entries
            .iter()
            .find(|candidate| candidate.name().bytes() == b".")
            .map(RawDirectoryEntry::inode)
            .ok_or(Error::InvalidDirectoryEntry)?;
        let parent_inode_id = entries
            .iter()
            .find(|candidate| candidate.name().bytes() == b"..")
            .map(RawDirectoryEntry::inode)
            .ok_or(Error::InvalidDirectoryEntry)?;
        if dot_inode != parent_inode.id() {
            return Err(Error::InvalidDirectoryEntry);
        }
        let hash = DirectoryHashScheme::from_metadata(
            self.volume.superblock.directory_hash_seed(),
            self.volume.superblock.default_directory_hash_version(),
        );
        let mut children = Vec::new();
        for child in entries {
            if !matches!(child.name().bytes(), b"." | b"..") {
                children.try_push(child)?;
            }
        }
        children.try_push(entry)?;
        memory::heap_sort_by(&mut children, |left, right| {
            hash.hash(left.name())
                .cmp(&hash.hash(right.name()))
                .then(left.name().bytes().cmp(right.name().bytes()))
        })?;
        let block_bytes = usize::try_from(self.volume.superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let mut next_logical = 1_u64;
        let mut routes = Vec::new();
        match DirectoryBlock::from_entries(block_bytes, checksum, &children) {
            Ok(leaf) => {
                let (leaf_logical, leaf_physical) =
                    self.allocate_directory_block(&mut tree, &mut next_logical)?;
                routes.try_push(DxEntry::new(0, leaf_logical)?)?;
                self.stage_directory_block(leaf_physical, leaf.into_bytes())?;
            }
            Err(Error::NoSpace) => {
                let split_at = self.directory_leaf_split(&children, checksum)?;
                let (left_entries, right_entries) = children
                    .split_at_checked(split_at)
                    .ok_or(Error::InvalidDirectoryEntry)?;
                let left_last_hash = left_entries
                    .last()
                    .map(|child| hash.hash(child.name()).major)
                    .ok_or(Error::InvalidDirectoryEntry)?;
                let right_first_hash = right_entries
                    .first()
                    .map(|child| hash.hash(child.name()).major)
                    .ok_or(Error::InvalidDirectoryEntry)?;
                let boundary = right_first_hash | u32::from(left_last_hash == right_first_hash);
                let left = DirectoryBlock::from_entries(block_bytes, checksum, left_entries)?;
                let right = DirectoryBlock::from_entries(block_bytes, checksum, right_entries)?;
                let (left_logical, left_physical) =
                    self.allocate_directory_block(&mut tree, &mut next_logical)?;
                let (right_logical, right_physical) =
                    self.allocate_directory_block(&mut tree, &mut next_logical)?;
                routes.try_push(DxEntry::new(0, left_logical)?)?;
                routes.try_push(DxEntry::new(boundary, right_logical)?)?;
                self.stage_directory_block(left_physical, left.into_bytes())?;
                self.stage_directory_block(right_physical, right.into_bytes())?;
            }
            Err(error) => return Err(error),
        }
        let root_index = DxIndex::root(block_bytes, checksum, routes)?;
        let root = create_htree_root(
            block_bytes,
            parent_inode.id(),
            parent_inode_id,
            self.volume.superblock.default_directory_hash_version(),
            &root_index,
            checksum,
        )?;
        self.stage_directory_block(root_physical, root)?;
        self.finish_directory_growth(inode_index, raw_parent, tree, next_logical, true)
    }

    /// Allocates and maps the next directory logical block.
    /// # Errors
    ///
    /// Returns an error when the logical block is outside the HTree address domain, cluster
    /// allocation fails, or the extent mapping cannot be extended.
    fn allocate_directory_block(
        &mut self,
        tree: &mut MutableExtentTree,
        next_logical: &mut u64,
    ) -> Result<(u32, BlockAddress)> {
        let logical = u32::try_from(*next_logical).map_err(|_| Error::DirectoryIndexFull)?;
        DxEntry::new(0, logical)?;
        let physical = self.allocate_cluster()?;
        tree.insert_or_extend_initialized(LogicalBlock::try_from(*next_logical)?, physical)?;
        *next_logical = next_logical
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok((logical, physical))
    }

    /// Publishes directory size/extent/timestamp changes after local block staging succeeds.
    /// # Errors
    ///
    /// Returns an error when size encoding, timestamps, extent staging, or inode replacement
    /// cannot represent the completed growth.
    fn finish_directory_growth(
        &mut self,
        inode_index: StagedInodeIndex,
        mut raw_parent: LiveInodeRecord,
        tree: MutableExtentTree,
        block_count: u64,
        mark_indexed: bool,
    ) -> Result<()> {
        if mark_indexed {
            raw_parent.mark_indexed_directory()?;
        }
        let size = FileSize::from_bytes(
            block_count
                .checked_mul(u64::from(self.volume.superblock.block_size().bytes()))
                .ok_or(Error::ArithmeticOverflow)?,
        );
        let encoded = self
            .volume
            .superblock
            .inode_data_encoding()
            .encode_directory_size(DirectorySize::from_bytes(size.bytes()))?;
        raw_parent.set_encoded_size(encoded)?;
        raw_parent.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_parent, tree)?;
        self.replace_live_inode(inode_index, raw_parent)
    }

    /// Returns whether a directory contains only `.` and `..`.
    /// # Errors
    ///
    /// Returns an error when the directory layout cannot be loaded or parsed.
    fn directory_is_empty(&mut self, inode: &Inode) -> Result<bool> {
        let tree = self.mutable_extent_tree(inode)?;
        match inode.directory_storage_kind()? {
            DirectoryStorageKind::Linear => {
                let block_count = round_up_div(
                    inode.size().bytes(),
                    u64::from(self.volume.superblock.block_size().bytes()),
                )?;
                for logical in 0..block_count {
                    let (_physical, block) = self.read_mutation_directory_block(
                        inode,
                        &tree,
                        LogicalBlock::try_from(logical)?,
                    )?;
                    if block
                        .entries()?
                        .iter()
                        .any(|entry| !matches!(entry.name().bytes(), b"." | b".."))
                    {
                        return Ok(false);
                    }
                }
            }
            DirectoryStorageKind::HTree => {
                let mut context =
                    self.mutation_htree_context(inode, &tree, HtreePathTarget::First)?;
                loop {
                    let (_physical, block) = self.read_mutation_directory_block(
                        inode,
                        &tree,
                        LogicalBlock::try_from(u64::from(context.path.leaf()?))?,
                    )?;
                    let entries = block.entries()?;
                    context
                        .path
                        .hash_range()?
                        .validate_leaf(&entries, context.root.hash_scheme())?;
                    if !entries.is_empty() {
                        return Ok(false);
                    }
                    if !self.advance_mutation_htree_path(
                        inode,
                        &tree,
                        &mut context.path,
                        context.root.indirect_levels(),
                    )? {
                        break;
                    }
                }
            }
        }
        Ok(true)
    }
}
