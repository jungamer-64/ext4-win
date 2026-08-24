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
        let inode = self.volume.read_inode_record(parent)?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        let lookup_name = self.directory_lookup_name(&inode, name)?;
        if let Some(entry) = self.directory_layout(&inode)?.find(&lookup_name)? {
            return Ok(entry);
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
    /// Returns an error when `parent` is not mutable, `name` already exists, encryption or HTree
    /// rebuild fails, or a new directory block cannot be allocated and staged.
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
            .directory_layout(&parent_inode)?
            .find(&disk_name)?
            .is_some()
        {
            return Err(Error::NameAlreadyExists);
        }
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            let mut entries = self.directory_layout(&parent_inode)?.entries()?;
            entries.try_push(RawDirectoryEntry::new(child, &disk_name, kind)?)?;
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(());
        }

        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if block.insert(child, &disk_name, kind)? {
                self.stage_directory_block(physical, block.into_bytes())?;
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                return Ok(());
            }
        }

        match self.volume.superblock.directory_indexing() {
            DirectoryIndexing::Enabled => {
                let mut entries = self.directory_layout(&parent_inode)?.entries()?;
                entries.try_push(RawDirectoryEntry::new(child, &disk_name, kind)?)?;
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
            .encode_size(new_parent_size)?;
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
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            let mut entries = self.directory_layout(&parent_inode)?.entries()?;
            let Some(position) = entries.iter().position(|entry| entry.name() == &disk_name) else {
                return Err(Error::DirectoryEntryNotFound);
            };
            let removed = entries.try_remove_at(position)?;
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(removed);
        }
        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if let Some(removed) = block.remove(&disk_name)? {
                self.stage_directory_block(physical, block.into_bytes())?;
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                return Ok(removed);
            }
        }
        Err(Error::DirectoryEntryNotFound)
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
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            let mut entries = self.directory_layout(&parent_inode)?.entries()?;
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
                .try_clone()?;
            if renamed.inode() != child {
                return Err(Error::InvalidDirectoryEntry);
            }
            *entries
                .get_mut(position)
                .ok_or(Error::InvalidDirectoryEntry)? =
                RawDirectoryEntry::new(child, &new_disk_name, kind)?;
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
                self.stage_directory_block(physical, block.into_bytes())?;
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                return Ok(renamed);
            }
        }
        Err(Error::DirectoryEntryNotFound)
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
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            let mut entries = self.directory_layout(&parent_inode)?.entries()?;
            let Some(position) = entries.iter().position(|entry| entry.name() == &disk_name) else {
                return Err(Error::DirectoryEntryNotFound);
            };
            let replaced = entries
                .get(position)
                .ok_or(Error::InvalidDirectoryEntry)?
                .try_clone()?;
            *entries
                .get_mut(position)
                .ok_or(Error::InvalidDirectoryEntry)? =
                RawDirectoryEntry::new(child, &disk_name, kind)?;
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(replaced);
        }
        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if let Some(replaced) = block.replace(&disk_name, child, kind)? {
                self.stage_directory_block(physical, block.into_bytes())?;
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                self.replace_live_inode(inode_index, raw_parent)?;
                return Ok(replaced);
            }
        }
        Err(Error::DirectoryEntryNotFound)
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

    /// Returns whether a directory contains only `.` and `..`.
    /// # Errors
    ///
    /// Returns an error when the directory layout cannot be loaded or parsed.
    fn directory_is_empty(&mut self, inode: &Inode) -> Result<bool> {
        for entry in self.directory_layout(inode)?.entries()? {
            let name = entry.name().bytes();
            if name != b"." && name != b".." {
                return Ok(false);
            }
        }
        Ok(true)
    }

}
