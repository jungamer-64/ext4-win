//! Directory namespace mutation and directory-entry staging.

use super::*;

impl<D: BlockWriter, N: FscryptNonceGenerator, J> JournalTransaction<'_, D, N, J> {
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
    fn ensure_child_absent(&self, parent: InodeId, name: &Ext4Name) -> Result<()> {
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
    /// # Errors
    ///
    /// Returns an error when the encrypted lookup name cannot be derived and no locked-directory
    /// ciphertext fallback can represent `name`.
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
    /// # Errors
    ///
    /// Returns an error when dot entries are invalid, HTree construction fails, required blocks
    /// cannot be allocated, or the rebuilt extent tree/size cannot be staged.
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
    /// # Errors
    ///
    /// Returns an error when the directory layout cannot be loaded or parsed.
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
    /// # Errors
    ///
    /// Returns an error when directory storage is unsupported, indexed layout is disabled, or staged
    /// directory blocks cannot be parsed into a layout.
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
    /// # Errors
    ///
    /// Returns an error when the directory extent tree contains holes, a staged block has the wrong
    /// size, a device block cannot be read, or block-count arithmetic fails.
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
}
