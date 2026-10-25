//! Directory namespace mutation and directory-entry staging.

use super::*;

/// Existing target outcome for a replace-capable rename.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingRenameTarget {
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
    /// Exact entry selected by the query in this owned leaf image.
    entry: RawDirectoryEntry,
}

/// Selection mode for a staged-aware HTree route.
enum HtreePathTarget<'name> {
    /// Select the leaf routed by an exact raw name.
    Query(DirectoryLookup<'name>),
    /// Select the first leaf in index order.
    First,
}

impl MutationResolvePass<'_, '_, '_> {
    /// Selects Unicode comparison for an empty directory on a casefold-enabled filesystem.
    ///
    /// The transition shares the directory's mutation intent and journal publication, so it
    /// cannot race a child insertion. The filesystem's encoding and strictness are unchanged.
    /// # Errors
    /// Returns missing feature, nonempty directory, immutable policy, encryption or I/O failure.
    pub fn set_directory_casefold(
        &mut self,
        directory: TransactionDirectory,
        state: crate::DirectoryCasefold,
    ) -> Result<()> {
        self.edit(|pass| {
            pass.mutation.volume.superblock.require_casefold()?;
            let index = pass.mutation.ensure_inode_update(directory.inode())?;
            let mut raw = pass.mutation.staged_live_inode(index)?;
            let inode = raw.parse()?;
            if inode.kind() != InodeKind::Directory {
                return Err(Error::WrongInodeKind);
            }
            let _metadata = inode.metadata_mutation()?;
            let _entries = pass.require_directory_entry_rename_mutation_for_inode(&inode)?;
            if !pass.mutation.directory_is_empty(&inode)? {
                return Err(Error::DirectoryNotEmpty);
            }
            raw.set_casefold(state)?;
            pass.mutation
                .volume
                .superblock
                .name_semantics(&raw.parse()?)?;
            if inode.protection().is_encrypted()
                && inode.directory_storage_kind()? == DirectoryStorageKind::HTree
                && inode.flags().has_casefold() != raw.parse()?.flags().has_casefold()
            {
                let tree = pass.mutation.mutable_extent_tree(&inode)?;
                let checksum = pass.mutation.volume.directory_checksum(&inode);
                let (physical, block) = pass.mutation.read_mutation_directory_block(
                    &inode,
                    &tree,
                    LogicalBlock::from_u32(0),
                )?;
                let root = HtreeRoot::parse(
                    block.bytes(),
                    inode.id(),
                    pass.mutation.volume.superblock.directory_hash_seed(),
                    pass.mutation.volume.superblock.directory_hash_signedness(),
                    pass.mutation
                        .volume
                        .superblock
                        .directory_indexing()
                        .require_supported()?,
                    checksum,
                    DirectoryEntryEncoding::for_inode(&inode),
                )?;
                let hash = match state {
                    crate::DirectoryCasefold::Enabled => DirectoryIndexHash::StoredKeyed,
                    crate::DirectoryCasefold::Disabled => {
                        DirectoryIndexHash::Computed(DirectoryHashScheme::from_metadata(
                            pass.mutation.volume.superblock.directory_hash_seed(),
                            pass.mutation
                                .volume
                                .superblock
                                .default_directory_hash_version(),
                            pass.mutation.volume.superblock.directory_hash_signedness(),
                        ))
                    }
                };
                let mut bytes = block.into_bytes();
                write_htree_root_index(
                    &mut bytes,
                    hash,
                    root.indirect_levels(),
                    root.index(),
                    checksum,
                )?;
                pass.mutation.stage_directory_block(physical, bytes)?;
            }
            raw.touch_metadata(pass.now)?;
            pass.mutation.replace_live_inode(index, raw)
        })
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
        self.edit(|pass| {
            pass.ensure_child_absent(parent.inode(), name)?;
            pass.require_directory_entry_create_mutation(parent.inode())?;
            let parent_inode = pass
                .mutation
                .raw_inode_for_policy(parent.inode())?
                .parse()?;
            let inherited_context = pass.inherited_fscrypt_context(&parent_inode)?;
            let allocated_inode = pass.mutation.allocate_inode()?;
            let mut raw_inode = allocated_inode.initialize_file(
                metadata,
                parent_inode.flags(),
                pass.now,
                pass.mutation.volume.superblock.block_size(),
                pass.mutation.volume.superblock.inode_timestamp_encoding(),
            )?;
            pass.apply_fscrypt_context(&mut raw_inode, inherited_context)?;
            pass.mutation.inherit_acl(&parent_inode, &mut raw_inode)?;
            pass.mutation.initialize_inline_file(&mut raw_inode)?;
            let inode_id = raw_inode.id();
            pass.add_directory_entry(parent.inode(), name, inode_id, DirectoryEntryKind::File)?;
            pass.mutation.inode_updates.try_push(raw_inode.into())?;
            Ok(TransactionFile {
                id: FileNodeId::new(inode_id),
            })
        })
    }

    /// Removes a regular file directory entry and releases its inode when the
    /// final link is removed.
    ///
    /// # Errors
    /// Returns an error when the entry is absent, the child is not a mutable
    /// regular file, or metadata cannot be updated.
    pub fn unlink_file(&mut self, parent: TransactionDirectory, name: &Ext4Name) -> Result<()> {
        self.edit(|pass| {
            let removed = pass.remove_directory_entry(parent.inode(), name)?;
            let inode_index = pass.mutation.ensure_inode_update(removed.inode())?;
            let mut raw_inode = pass.mutation.staged_live_inode(inode_index)?;
            let inode = raw_inode.parse()?;
            if inode.kind() != InodeKind::File {
                return Err(Error::WrongInodeKind);
            }
            let _namespace = inode.namespace_mutation()?;
            match raw_inode.decrement_links_count()? {
                LinkCountAfterDecrement::StillLinked(_) => {
                    raw_inode.touch_metadata(pass.now)?;
                    pass.mutation.replace_live_inode(inode_index, raw_inode)?;
                }
                LinkCountAfterDecrement::Unlinked => {
                    pass.mutation.release_inode_data(&inode)?;
                    pass.mutation.reclaim_inode(raw_inode.raw())?;
                    let deleted =
                        raw_inode.delete(pass.now, pass.mutation.volume.superblock.block_size())?;
                    pass.mutation.replace_deleted_inode(inode_index, deleted)?;
                }
            }
            Ok(())
        })
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
        destination: NamespaceDestination<'_>,
    ) -> Result<()> {
        self.edit(|pass| {
            reject_reserved_directory_name(target_name)?;
            let source_inode_id = source.inode();
            let source_index = pass.mutation.ensure_inode_update(source_inode_id)?;
            let mut raw_source = pass.mutation.staged_live_inode(source_index)?;
            let source_inode = raw_source.parse()?;
            let _namespace = source_inode.namespace_mutation()?;
            let target_parent_inode = pass
                .mutation
                .raw_inode_for_policy(target_parent.inode())?
                .parse()?;
            pass.require_child_encryption_policy(&source_inode, &target_parent_inode)?;

            let mut add_link = true;
            match destination {
                NamespaceDestination::Vacant => {
                    pass.ensure_child_absent(target_parent.inode(), target_name)?;
                }
                NamespaceDestination::Replace { existing_name } => {
                    let existing = pass.find_child_entry(target_parent.inode(), existing_name)?;
                    if existing.inode() == source_inode_id {
                        add_link = false;
                        if existing_name != target_name {
                            let renamed = pass.rename_directory_entry(
                                target_parent.inode(),
                                &existing,
                                target_name,
                                source.entry_kind(),
                            )?;
                            if renamed.inode() != source_inode_id {
                                return Err(Error::InvalidDirectoryEntry);
                            }
                        }
                    } else {
                        let existing_kind = pass
                            .mutation
                            .raw_inode_for_policy(existing.inode())?
                            .parse()?
                            .kind();
                        match existing_kind {
                            InodeKind::File => {
                                pass.unlink_file(target_parent, existing_name)?;
                            }
                            InodeKind::Symlink => {
                                pass.remove_symlink(target_parent, existing_name)?;
                            }
                            InodeKind::Directory => return Err(Error::WrongInodeKind),
                        }
                    }
                }
            }

            if add_link {
                pass.add_directory_entry(
                    target_parent.inode(),
                    target_name,
                    source_inode_id,
                    source.entry_kind(),
                )?;
                raw_source.increment_links_count()?;
            }
            raw_source.touch_metadata(pass.now)?;
            pass.mutation.replace_live_inode(source_index, raw_source)?;
            Ok(())
        })
    }

    /// Requires children entering an encrypted directory to carry its fscrypt policy.
    /// # Errors
    ///
    /// Returns an error when an encrypted destination receives a plaintext inode, a context is
    /// missing, or policies differ. Unencrypted destinations impose no encryption policy.
    fn require_child_encryption_policy(
        &mut self,
        source: &Inode,
        target_parent: &Inode,
    ) -> Result<()> {
        match (
            source.protection().is_encrypted(),
            target_parent.protection().is_encrypted(),
        ) {
            (_, false) => Ok(()),
            (true, true) => {
                let source_context = self.mutation.fscrypt_context_for_inode(source)?;
                let target_context = self.mutation.fscrypt_context_for_inode(target_parent)?;
                if source_context.policy() == target_context.policy() {
                    Ok(())
                } else {
                    Err(Error::UnsupportedEncryption)
                }
            }
            (false, true) => Err(Error::UnsupportedEncryption),
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
        self.edit(|pass| {
            pass.ensure_child_absent(parent.inode(), name)?;
            pass.require_directory_entry_create_mutation(parent.inode())?;
            let parent_inode = pass
                .mutation
                .raw_inode_for_policy(parent.inode())?
                .parse()?;
            let inherited_context = pass.inherited_fscrypt_context(&parent_inode)?;
            let allocated_inode = pass.mutation.allocate_inode()?;
            let mut raw_inode = if pass.mutation.volume.superblock.supports_inline_data()
                && pass.mutation.volume.superblock.inode_size().as_u16() >= 256
                && inherited_context.is_none()
            {
                allocated_inode.initialize_inline_directory(
                    metadata,
                    parent.inode(),
                    parent_inode.flags(),
                    pass.now,
                    pass.mutation.volume.superblock.block_size(),
                    pass.mutation.volume.superblock.inode_timestamp_encoding(),
                )?
            } else {
                let block = pass.mutation.allocate_cluster()?;
                let block_size = pass.mutation.volume.superblock.block_size();
                let allocated_blocks =
                    u64::from(pass.mutation.volume.superblock.blocks_in_cluster(
                        pass.mutation.volume.superblock.cluster_of_block(block)?,
                    )?);
                let allocation_size = FileAllocationSize::from_bytes(
                    allocated_blocks
                        .checked_mul(u64::from(block_size.bytes()))
                        .ok_or(Error::ArithmeticOverflow)?,
                );
                let raw_inode = allocated_inode.initialize_directory(
                    metadata,
                    parent_inode.flags(),
                    pass.now,
                    block_size,
                    block,
                    allocation_size,
                    pass.mutation.volume.superblock.inode_timestamp_encoding(),
                )?;
                let inode_id = raw_inode.id();
                let directory_checksum =
                    pass.mutation.volume.directory_checksum(&raw_inode.parse()?);

                let mut directory = DirectoryBlock::empty(
                    usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
                    directory_checksum,
                    DirectoryEntryEncoding::Standard,
                )?;
                directory.initialize_dot_entries(inode_id, parent.inode())?;
                pass.mutation
                    .stage_directory_block(block, directory.into_bytes())?;

                raw_inode
            };
            pass.apply_fscrypt_context(&mut raw_inode, inherited_context)?;
            pass.mutation.inherit_acl(&parent_inode, &mut raw_inode)?;
            let inode_id = raw_inode.id();

            pass.add_directory_entry(
                parent.inode(),
                name,
                inode_id,
                DirectoryEntryKind::Directory,
            )?;
            pass.mutation
                .increment_directory_links(parent.inode(), pass.now)?;
            let group =
                InodeBitmapPosition::from_inode(&pass.mutation.volume.superblock, inode_id)?
                    .group();
            pass.mutation.record_group_used_dirs_delta(group, 1)?;
            pass.mutation.inode_updates.try_push(raw_inode.into())?;
            Ok(TransactionDirectory {
                id: DirectoryNodeId::new(inode_id),
            })
        })
    }

    /// Creates a symbolic link under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent is not mutable, the name exists, no inode or data block
    /// is free, or the target cannot fit below the filesystem block size, including its terminator.
    pub fn create_symlink(
        &mut self,
        parent: TransactionDirectory,
        name: &Ext4Name,
        target: &SymlinkTarget,
        metadata: NewSymlinkMetadata,
    ) -> Result<TransactionSymlink> {
        self.edit(|pass| {
            if target.bytes().len()
                >= usize::try_from(pass.mutation.volume.superblock.block_size().bytes())
                    .map_err(|_| Error::ArithmeticOverflow)?
            {
                return Err(Error::InvalidName);
            }
            pass.ensure_child_absent(parent.inode(), name)?;
            pass.require_directory_entry_create_mutation(parent.inode())?;
            let parent_inode = pass
                .mutation
                .raw_inode_for_policy(parent.inode())?
                .parse()?;
            if parent_inode.protection().is_encrypted() {
                return Err(Error::UnsupportedEncryption);
            }
            let allocated_inode = pass.mutation.allocate_inode()?;
            let raw_inode = if target.is_inline() {
                allocated_inode.initialize_inline_symlink(
                    metadata,
                    parent_inode.flags(),
                    pass.now,
                    target,
                    pass.mutation.volume.superblock.inode_timestamp_encoding(),
                )?
            } else {
                let block_size = pass.mutation.volume.superblock.block_size();
                let mut raw_inode = allocated_inode.initialize_extent_symlink(
                    metadata,
                    parent_inode.flags(),
                    pass.now,
                    block_size,
                    target,
                    pass.mutation.volume.superblock.inode_timestamp_encoding(),
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
                    let block = pass
                        .mutation
                        .allocate_extent_block(&tree, LogicalBlock::try_from(logical)?)?;
                    let mut bytes = memory::repeated_vec(0_u8, block_bytes)?;
                    memory::copy_exact(
                        bytes.get_mut(..chunk.len()).ok_or(Error::DeviceRange)?,
                        chunk,
                    )?;
                    pass.mutation.stage_file_write(
                        FileDataPersistence::Ordered,
                        RangeWrite {
                            offset: block_size.offset_of(block)?,
                            bytes,
                        },
                    )?;
                    tree.insert_or_extend_initialized(LogicalBlock::try_from(logical)?, block)?;
                    remaining = remainder;
                    if !remaining.is_empty() {
                        logical = logical.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                    }
                }
                pass.mutation.stage_extent_tree(&mut raw_inode, tree)?;
                raw_inode
            };
            let inode_id = raw_inode.id();
            pass.add_directory_entry(parent.inode(), name, inode_id, DirectoryEntryKind::Symlink)?;
            pass.mutation.inode_updates.try_push(raw_inode.into())?;
            Ok(TransactionSymlink {
                id: SymlinkNodeId::new(inode_id),
            })
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
        self.edit(|pass| {
            let removed = pass.find_child_entry(parent.inode(), name)?;
            if removed.inode() == InodeId::ROOT {
                return Err(Error::CannotRemoveRoot);
            }
            let inode_index = pass.mutation.ensure_inode_update(removed.inode())?;
            let raw_inode = pass.mutation.staged_live_inode(inode_index)?;
            let inode = raw_inode.parse()?;
            if inode.kind() != InodeKind::Directory {
                return Err(Error::WrongInodeKind);
            }
            let _namespace = inode.namespace_mutation()?;
            if !pass.mutation.directory_is_empty(&inode)? {
                return Err(Error::DirectoryNotEmpty);
            }
            let _removed = pass.remove_directory_entry(parent.inode(), name)?;
            pass.mutation.release_inode_data(&inode)?;
            pass.mutation.reclaim_inode(raw_inode.raw())?;
            let deleted =
                raw_inode.delete(pass.now, pass.mutation.volume.superblock.block_size())?;
            pass.mutation.replace_deleted_inode(inode_index, deleted)?;
            pass.mutation
                .decrement_directory_links(parent.inode(), pass.now)?;
            Ok(())
        })
    }

    /// Renames or moves a child entry.
    ///
    /// # Errors
    /// Returns an error when the source or selected replacement is absent, a vacant destination
    /// is occupied, either parent is outside the mutable directory domain, or a moved directory
    /// cannot have its parent link updated.
    pub fn rename_child(
        &mut self,
        source_parent: TransactionDirectory,
        source_name: &Ext4Name,
        target_parent: TransactionDirectory,
        target_name: &Ext4Name,
        destination: NamespaceDestination<'_>,
    ) -> Result<()> {
        self.edit(|pass| {
            reject_reserved_directory_name(source_name)?;
            reject_reserved_directory_name(target_name)?;

            let source_parent = source_parent.inode();
            let target_parent = target_parent.inode();
            let source = pass.find_child_entry(source_parent, source_name)?;
            if source_parent == target_parent && source_name == target_name {
                return Ok(());
            }
            let child_index = pass.mutation.ensure_inode_update(source.inode())?;
            let child_inode = pass.mutation.staged_live_inode(child_index)?.parse()?;
            let _namespace = child_inode.namespace_mutation()?;
            if child_inode.kind() == InodeKind::Directory && source.inode() == InodeId::ROOT {
                return Err(Error::CannotRemoveRoot);
            }
            if source_parent != target_parent {
                let destination_inode =
                    pass.mutation.raw_inode_for_policy(target_parent)?.parse()?;
                pass.require_child_encryption_policy(&child_inode, &destination_inode)?;
                if child_inode.kind() == InodeKind::Directory {
                    pass.require_acyclic_directory_move(source.inode(), target_parent)?;
                }
            }
            let kind = directory_entry_kind(child_inode.kind());
            let renames_source = if source_parent == target_parent {
                match pass.find_child_entry(target_parent, target_name) {
                    Ok(target) => target.name() == source.name(),
                    Err(Error::DirectoryEntryNotFound) => false,
                    Err(error) => return Err(error),
                }
            } else {
                false
            };
            match destination {
                NamespaceDestination::Vacant if !renames_source => {
                    pass.ensure_child_absent(target_parent, target_name)?;
                }
                NamespaceDestination::Replace { existing_name } => {
                    reject_reserved_directory_name(existing_name)?;
                    if existing_name != target_name && !renames_source {
                        pass.ensure_child_absent(target_parent, target_name)?;
                    }
                }
                NamespaceDestination::Vacant => {}
            }

            if let NamespaceDestination::Replace { existing_name } = destination {
                let existing_target = pass.remove_existing_rename_target(
                    target_parent,
                    existing_name,
                    source.inode(),
                    child_inode.kind(),
                )?;
                if matches!(existing_target, ExistingRenameTarget::SameInode) && !renames_source {
                    return Ok(());
                }
            }

            if source_parent == target_parent {
                let renamed =
                    pass.rename_directory_entry(source_parent, &source, target_name, kind)?;
                if renamed.inode() != source.inode() {
                    return Err(Error::InvalidDirectoryEntry);
                }
            } else {
                pass.add_directory_entry(target_parent, target_name, source.inode(), kind)?;
                let removed = pass.remove_directory_entry(source_parent, source_name)?;
                if removed.inode() != source.inode() {
                    return Err(Error::InvalidDirectoryEntry);
                }
                if child_inode.kind() == InodeKind::Directory {
                    let previous = pass.reparent_directory(source.inode(), target_parent)?;
                    if previous != source_parent {
                        return Err(Error::InvalidDirectoryEntry);
                    }
                    pass.mutation
                        .decrement_directory_links(source_parent, pass.now)?;
                    pass.mutation
                        .increment_directory_links(target_parent, pass.now)?;
                }
            }

            let mut child_raw = pass.mutation.staged_live_inode(child_index)?;
            child_raw.touch_metadata(pass.now)?;
            pass.mutation.replace_live_inode(child_index, child_raw)?;
            Ok(())
        })
    }

    /// Validates the staged destination ancestry and retains its inode intents until publication.
    /// # Errors
    /// Returns a rejected self/descendant move, malformed existing ancestry, I/O, or allocation
    /// failure. Parent relations are read from staged state so earlier moves in this pass count.
    fn require_acyclic_directory_move(&mut self, child: InodeId, parent: InodeId) -> Result<()> {
        let mut ancestors = Vec::new();
        let mut current = parent;
        loop {
            if current == child {
                return Err(Error::DirectoryCycle);
            }
            if ancestors.contains(&current) {
                return Err(Error::InvalidDirectoryEntry);
            }
            ancestors.try_push(current)?;
            if current == InodeId::ROOT {
                break;
            }
            current = self
                .find_child_entry(current, &Ext4Name::new(b"..")?)?
                .inode();
        }
        for ancestor in ancestors {
            if !self.mutation.namespace_ancestors.contains(&ancestor) {
                self.mutation.namespace_ancestors.try_push(ancestor)?;
            }
        }
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
            Err(Error::DirectoryEntryNotFound) => return Err(Error::DirectoryEntryNotFound),
            Err(error) => return Err(error),
        };
        if target.inode() == source {
            return Ok(ExistingRenameTarget::SameInode);
        }

        let target_kind = self
            .mutation
            .raw_inode_for_policy(target.inode())?
            .parse()?
            .kind();
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

    /// Removes one symbolic-link name, reclaiming its inode only after the final link.
    ///
    /// # Errors
    /// Returns an error when the entry is absent, not a symbolic link, or
    /// metadata cannot be updated.
    pub fn remove_symlink(&mut self, parent: TransactionDirectory, name: &Ext4Name) -> Result<()> {
        self.edit(|pass| {
            let removed = pass.remove_directory_entry(parent.inode(), name)?;
            let inode_index = pass.mutation.ensure_inode_update(removed.inode())?;
            let mut raw_inode = pass.mutation.staged_live_inode(inode_index)?;
            let inode = raw_inode.parse()?;
            if inode.kind() != InodeKind::Symlink {
                return Err(Error::WrongInodeKind);
            }
            let _namespace = inode.namespace_mutation()?;
            if matches!(
                raw_inode.decrement_links_count()?,
                LinkCountAfterDecrement::StillLinked(_)
            ) {
                raw_inode.touch_metadata(pass.now)?;
                pass.mutation.replace_live_inode(inode_index, raw_inode)?;
                return Ok(());
            }
            match inode.storage() {
                InodeStorage::Extents(_) => {
                    pass.mutation.release_inode_data(&inode)?;
                }
                InodeStorage::FastSymlink(_) | InodeStorage::InlineData(_) => {}
                InodeStorage::UnsupportedBlockMap => return Err(Error::UnsupportedBlockMap),
            }
            pass.mutation.reclaim_inode(raw_inode.raw())?;
            let deleted =
                raw_inode.delete(pass.now, pass.mutation.volume.superblock.block_size())?;
            pass.mutation.replace_deleted_inode(inode_index, deleted)?;
            Ok(())
        })
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
        let inode = self.mutation.raw_inode_for_policy(parent)?.parse()?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if inode.directory_storage_kind()? == DirectoryStorageKind::HTree
            && matches!(name.bytes(), b"." | b"..")
        {
            let tree = self.mutation.mutable_extent_tree(&inode)?;
            let (_physical, block) = self.mutation.read_mutation_directory_block(
                &inode,
                &tree,
                LogicalBlock::from_u32(0),
            )?;
            let root = HtreeRoot::parse(
                block.bytes(),
                inode.id(),
                self.mutation.volume.superblock.directory_hash_seed(),
                self.mutation.volume.superblock.directory_hash_signedness(),
                self.mutation
                    .volume
                    .superblock
                    .directory_indexing()
                    .require_supported()?,
                self.mutation.volume.directory_checksum(&inode),
                DirectoryEntryEncoding::for_inode(&inode),
            )?;
            return root
                .dot_entries()
                .iter()
                .find(|entry| entry.name() == name)
                .ok_or(Error::InvalidDirectoryEntry)?
                .try_clone();
        }
        let query = self
            .mutation
            .prepare_directory_lookup(&inode, name, self.crypto)?;
        if let InodeStorage::InlineData(data) = inode.storage() {
            return query
                .query()
                .find(
                    data.directory_entries(inode.id())?,
                    self.crypto,
                    self.mutation.volume.superblock.name_semantics(&inode)?,
                )?
                .ok_or(Error::DirectoryEntryNotFound);
        }
        if let Some(location) = self.directory_entry_location(&inode, query.query())? {
            return Ok(location.entry);
        }
        Err(Error::DirectoryEntryNotFound)
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
        let inode_index = self.mutation.ensure_inode_update(parent)?;
        let mut raw_parent = self.mutation.staged_live_inode(inode_index)?;
        let mut parent_inode = raw_parent.parse()?;
        if parent_inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.require_directory_entry_create_mutation_for_inode(&parent_inode)?;
        let entry =
            self.mutation
                .encode_directory_entry(&parent_inode, name, child, kind, self.crypto)?;
        let disk_name = entry.name();
        let names = self
            .mutation
            .volume
            .superblock
            .name_semantics(&parent_inode)?;
        if parent_inode.flags().has_inline_data() {
            if let Some(()) = self.mutation.edit_inline_directory(
                &mut raw_parent,
                |inline_parent, first, second| {
                    let _inline_parent = inline_parent;
                    for candidate in first.entries()?.into_iter().chain(second.entries()?) {
                        if names.equivalent(candidate.name(), disk_name)? {
                            return Err(Error::NameAlreadyExists);
                        }
                    }
                    if first.insert(&entry)?
                        || (!second.bytes().is_empty() && second.insert(&entry)?)
                    {
                        Ok(())
                    } else {
                        Err(Error::NoSpace)
                    }
                },
            )? {
                raw_parent.touch_contents(self.now)?;
                self.mutation.replace_live_inode(inode_index, raw_parent)?;
                return Ok(());
            }
            self.mutation.require_extent_storage(&mut raw_parent)?;
            parent_inode = raw_parent.parse()?;
        }
        let query = self
            .mutation
            .prepare_directory_lookup(&parent_inode, name, self.crypto)?;
        if self
            .directory_entry_location(&parent_inode, query.query())?
            .is_some()
        {
            return Err(Error::NameAlreadyExists);
        }
        self.mutation
            .insert_encoded_directory_entry(&mut raw_parent, entry)?;
        raw_parent.touch_contents(self.now)?;
        self.mutation.replace_live_inode(inode_index, raw_parent)
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
        let inode_index = self.mutation.ensure_inode_update(parent)?;
        let mut raw_parent = self.mutation.staged_live_inode(inode_index)?;
        let mut parent_inode = raw_parent.parse()?;
        if parent_inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.require_directory_entry_delete_mutation_for_inode(&parent_inode)?;
        let query = self
            .mutation
            .prepare_directory_lookup(&parent_inode, name, self.crypto)?;
        if let InodeStorage::InlineData(data) = parent_inode.storage() {
            let selected = query
                .query()
                .find(
                    data.directory_entries(parent_inode.id())?,
                    self.crypto,
                    self.mutation
                        .volume
                        .superblock
                        .name_semantics(&parent_inode)?,
                )?
                .ok_or(Error::DirectoryEntryNotFound)?;
            let disk_name = selected.name();
            if let Some(result) = self.mutation.edit_inline_directory(
                &mut raw_parent,
                |inline_parent, first, second| {
                    let _inline_parent = inline_parent;
                    if let Some(removed) = first.remove(disk_name)? {
                        return Ok(removed);
                    }
                    second
                        .remove(disk_name)?
                        .ok_or(Error::DirectoryEntryNotFound)
                },
            )? {
                raw_parent.touch_contents(self.now)?;
                self.mutation.replace_live_inode(inode_index, raw_parent)?;
                return Ok(result);
            }
            self.mutation.require_extent_storage(&mut raw_parent)?;
            parent_inode = raw_parent.parse()?;
        }
        let Some(mut location) = self.directory_entry_location(&parent_inode, query.query())?
        else {
            return Err(Error::DirectoryEntryNotFound);
        };
        let removed = location
            .block
            .remove(location.entry.name())?
            .ok_or(Error::DirectoryEntryNotFound)?;
        self.mutation
            .stage_directory_block(location.physical, location.block.into_bytes())?;
        raw_parent.touch_contents(self.now)?;
        self.mutation.replace_live_inode(inode_index, raw_parent)?;
        Ok(removed)
    }

    /// Replaces one observed source spelling using the destination's plaintext comparison contract.
    /// # Errors
    /// Returns changed source identity, duplicate target, policy, allocation or journal staging failure.
    fn rename_directory_entry(
        &mut self,
        parent: InodeId,
        source: &RawDirectoryEntry,
        new_name: &Ext4Name,
        kind: DirectoryEntryKind,
    ) -> Result<RawDirectoryEntry> {
        let inode_index = self.mutation.ensure_inode_update(parent)?;
        let mut raw_parent = self.mutation.staged_live_inode(inode_index)?;
        let mut parent_inode = raw_parent.parse()?;
        if parent_inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.require_directory_entry_rename_mutation_for_inode(&parent_inode)?;
        let child = source.inode();
        let replacement = self.mutation.encode_directory_entry(
            &parent_inode,
            new_name,
            child,
            kind,
            self.crypto,
        )?;
        match self.find_child_entry(parent, new_name) {
            Ok(target) if target.name() != source.name() => return Err(Error::NameAlreadyExists),
            Ok(_) | Err(Error::DirectoryEntryNotFound) => {}
            Err(error) => return Err(error),
        }
        if source.name() == replacement.name() && source.stored_hash() == replacement.stored_hash()
        {
            return source.try_clone();
        }
        if parent_inode.flags().has_inline_data() {
            if let Some(result) =
                self.mutation
                    .edit_inline_directory(&mut raw_parent, |_parent, first, second| {
                        let removed = match first.remove(source.name())? {
                            Some(entry) => entry,
                            None => second
                                .remove(source.name())?
                                .ok_or(Error::DirectoryEntryNotFound)?,
                        };
                        if removed.inode() != child {
                            return Err(Error::InvalidDirectoryEntry);
                        }
                        if first.insert(&replacement)?
                            || (!second.bytes().is_empty() && second.insert(&replacement)?)
                        {
                            Ok(removed)
                        } else {
                            Err(Error::NoSpace)
                        }
                    })?
            {
                raw_parent.touch_contents(self.now)?;
                self.mutation.replace_live_inode(inode_index, raw_parent)?;
                return Ok(result);
            }
            self.mutation.require_extent_storage(&mut raw_parent)?;
            parent_inode = raw_parent.parse()?;
        }
        let Some(mut location) =
            self.directory_entry_location(&parent_inode, DirectoryLookup::Stored(source))?
        else {
            return Err(Error::DirectoryEntryNotFound);
        };
        if location.entry.inode() != child {
            return Err(Error::InvalidDirectoryEntry);
        }
        if parent_inode.directory_storage_kind()? == DirectoryStorageKind::HTree {
            let removed = location
                .block
                .remove(source.name())?
                .ok_or(Error::DirectoryEntryNotFound)?;
            self.mutation
                .stage_directory_block(location.physical, location.block.into_bytes())?;
            self.mutation.insert_htree_directory_entry(
                &mut raw_parent,
                &parent_inode,
                replacement,
            )?;
            raw_parent.touch_contents(self.now)?;
            self.mutation.replace_live_inode(inode_index, raw_parent)?;
            return Ok(removed);
        }
        match location.block.rename(source.name(), &replacement) {
            Ok(Some(removed)) => {
                self.mutation
                    .stage_directory_block(location.physical, location.block.into_bytes())?;
                raw_parent.touch_contents(self.now)?;
                self.mutation.replace_live_inode(inode_index, raw_parent)?;
                Ok(removed)
            }
            Ok(None) => Err(Error::DirectoryEntryNotFound),
            Err(Error::NoSpace) => {
                let removed = location
                    .block
                    .remove(source.name())?
                    .ok_or(Error::DirectoryEntryNotFound)?;
                self.mutation
                    .stage_directory_block(location.physical, location.block.into_bytes())?;
                self.add_directory_entry(parent, new_name, child, kind)?;
                Ok(removed)
            }
            Err(error) => Err(error),
        }
    }

    /// Updates one moved directory's parent relation in its current storage representation.
    /// # Errors
    /// Returns policy, malformed special records, allocation or journal staging failure.
    fn reparent_directory(&mut self, directory: InodeId, parent: InodeId) -> Result<InodeId> {
        let index = self.mutation.ensure_inode_update(directory)?;
        let mut raw = self.mutation.staged_live_inode(index)?;
        let mut inode = raw.parse()?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.require_directory_entry_replace_mutation_for_inode(&inode)?;
        if inode.flags().has_inline_data() {
            if let Some(previous) =
                self.mutation
                    .edit_inline_directory(&mut raw, |current, _first, _second| {
                        let previous = *current;
                        *current = parent;
                        Ok(previous)
                    })?
            {
                raw.touch_contents(self.now)?;
                self.mutation.replace_live_inode(index, raw)?;
                return Ok(previous);
            }
            self.mutation.require_extent_storage(&mut raw)?;
            inode = raw.parse()?;
        }
        let tree = self.mutation.mutable_extent_tree(&inode)?;
        let (physical, mut block) = self.mutation.read_mutation_directory_block(
            &inode,
            &tree,
            LogicalBlock::from_u32(0),
        )?;
        let (previous, bytes) = match inode.directory_storage_kind()? {
            DirectoryStorageKind::Linear => {
                let previous = block.reparent(directory, parent)?;
                (previous, block.into_bytes())
            }
            DirectoryStorageKind::HTree => {
                let mut bytes = block.into_bytes();
                let previous = replace_htree_parent(
                    &mut bytes,
                    directory,
                    parent,
                    self.mutation.volume.directory_checksum(&inode),
                )?;
                (previous, bytes)
            }
        };
        self.mutation.stage_directory_block(physical, bytes)?;
        raw.touch_contents(self.now)?;
        self.mutation.replace_live_inode(index, raw)?;
        Ok(previous)
    }

    /// Finds an exact entry and returns only its mutable leaf block.
    /// # Errors
    ///
    /// Returns an error when directory mapping, HTree routing, hash intervals, or a leaf dirent
    /// stream is invalid.
    fn directory_entry_location(
        &mut self,
        inode: &Inode,
        query: DirectoryLookup<'_>,
    ) -> Result<Option<DirectoryEntryLocation>> {
        let tree = self.mutation.mutable_extent_tree(inode)?;
        match inode.directory_storage_kind()? {
            DirectoryStorageKind::Linear => {
                let block_count = round_up_div(
                    inode.size().bytes(),
                    u64::from(self.mutation.volume.superblock.block_size().bytes()),
                )?;
                for logical in 0..block_count {
                    let (physical, block) = self.mutation.read_mutation_directory_block(
                        inode,
                        &tree,
                        LogicalBlock::try_from(logical)?,
                    )?;
                    if let Some(entry) = query.find(
                        block.entries()?,
                        self.crypto,
                        self.mutation.volume.superblock.name_semantics(inode)?,
                    )? {
                        return Ok(Some(DirectoryEntryLocation {
                            physical,
                            block,
                            entry,
                        }));
                    }
                }
                Ok(None)
            }
            DirectoryStorageKind::HTree => {
                if query
                    .exact()
                    .is_some_and(|name| matches!(name.bytes(), b"." | b".."))
                {
                    return Err(Error::InvalidDirectoryEntry);
                }
                let mut context = self.mutation.mutation_htree_context(
                    inode,
                    &tree,
                    HtreePathTarget::Query(query),
                )?;
                let major = query.major(
                    context.root.hash_profile(),
                    self.mutation.volume.superblock.name_semantics(inode)?,
                )?;
                loop {
                    let (physical, block) = self.mutation.read_mutation_directory_block(
                        inode,
                        &tree,
                        LogicalBlock::try_from(u64::from(context.path.leaf()?))?,
                    )?;
                    let entries = block.entries()?;
                    context.path.hash_range()?.validate_leaf(
                        &entries,
                        context.root.hash_profile(),
                        self.mutation.volume.superblock.name_semantics(inode)?,
                    )?;
                    if let Some(entry) = query.find(
                        entries,
                        self.crypto,
                        self.mutation.volume.superblock.name_semantics(inode)?,
                    )? {
                        return Ok(Some(DirectoryEntryLocation {
                            physical,
                            block,
                            entry,
                        }));
                    }
                    if !self.mutation.advance_mutation_htree_path(
                        inode,
                        &tree,
                        &mut context.path,
                        context.root.indirect_levels(),
                    )? || context.path.boundary()? & !1 != major
                    {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

/// A logged binding supplies a postcondition; link-count arithmetic is not part of leaf editing.
enum LoggedBinding<'a> {
    /// The exact recorded spelling and inode must be present after replay.
    Present(RawDirectoryEntry),
    /// Only a binding to the recorded inode may be removed.
    AbsentIf {
        /// A replacement inode with the same name must remain untouched.
        inode: InodeId,
        /// Interpretation belongs to the admitted parent, not a global comparison policy.
        name: &'a Ext4Name,
    },
}
/// A prospective insertion is retained until every hash-collision leaf has been searched.
enum LoggedLeafResult {
    /// The existing binding already meets its postcondition or belongs to a different unlink target.
    FoundUnchanged,
    /// An observed binding was replaced or removed in this private block image.
    FoundChanged,
    /// A replacement removed the old binding but needs another leaf or layout growth.
    FoundRemoved,
    /// No equivalent name exists here; this private block can hold a future insertion.
    VacantInserted,
    /// This leaf lacks the binding and cannot supply an insertion image.
    Vacant,
}
impl LoggedBinding<'_> {
    /// Borrows the recorded component under the parent's actual plaintext comparison contract.
    fn name(&self) -> &Ext4Name {
        match self {
            Self::Present(entry) => entry.name(),
            Self::AbsentIf { name, .. } => name,
        }
    }
    /// Enforces an observed binding without changing any inode or accounting state.
    /// # Errors
    /// Rejects malformed directory data, normalization failure or an unrepresentable replacement.
    fn apply(
        &self,
        block: &mut DirectoryBlock,
        names: crate::disk_format::name::NameSemantics,
    ) -> Result<LoggedLeafResult> {
        for existing in block.entries()? {
            if !names.equivalent(existing.name(), self.name())? {
                continue;
            }
            match self {
                Self::Present(wanted) => {
                    if existing.inode() == wanted.inode()
                        && existing.name() == wanted.name()
                        && existing.kind() == wanted.kind()
                    {
                        return Ok(LoggedLeafResult::FoundUnchanged);
                    }
                    block
                        .remove(existing.name())?
                        .ok_or(Error::InvalidDirectoryEntry)?;
                    if !block.insert(wanted)? {
                        return Ok(LoggedLeafResult::FoundRemoved);
                    }
                }
                Self::AbsentIf { inode, .. } => {
                    if existing.inode() != *inode {
                        return Ok(LoggedLeafResult::FoundUnchanged);
                    }
                    block
                        .remove(existing.name())?
                        .ok_or(Error::InvalidDirectoryEntry)?;
                }
            }
            return Ok(LoggedLeafResult::FoundChanged);
        }
        match self {
            Self::Present(entry) if block.insert(entry)? => Ok(LoggedLeafResult::VacantInserted),
            _ => Ok(LoggedLeafResult::Vacant),
        }
    }
}

impl MetadataMutation<'_, '_> {
    /// Edits already encoded names; callers own access checks, cryptography, timestamps and inode publication.
    /// # Errors
    /// Returns malformed storage, unsupported indexing, allocation or serialization failure.
    fn insert_encoded_directory_entry(
        &mut self,
        raw_parent: &mut LiveInodeRecord,
        entry: RawDirectoryEntry,
    ) -> Result<()> {
        let parent_inode = raw_parent.parse()?;
        if matches!(
            parent_inode.directory_storage_kind()?,
            DirectoryStorageKind::HTree
        ) {
            return self.insert_htree_directory_entry(raw_parent, &parent_inode, entry);
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
            if block.insert(&entry)? {
                self.stage_directory_block(physical, block.into_bytes())?;
                return Ok(());
            }
        }

        if block_count == 1
            && !matches!(
                self.volume.superblock.directory_indexing(),
                DirectoryIndexing::Disabled
            )
        {
            return self.convert_linear_directory_to_htree(raw_parent, &parent_inode, tree, entry);
        }

        let logical_block = LogicalBlock::try_from(block_count)?;
        let new_physical = self.allocate_extent_block(&tree, logical_block)?;
        tree.insert_or_extend_initialized(logical_block, new_physical)?;

        let mut block = DirectoryBlock::empty(
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
            self.volume.directory_checksum(&parent_inode),
            DirectoryEntryEncoding::for_inode(&parent_inode),
        )?;
        block.initialize_free_space()?;
        let inserted = block.insert(&entry)?;
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
        self.stage_extent_tree(raw_parent, tree)?;
        Ok(())
    }

    /// Inserts one child through the selected HTree leaf and propagates only required splits.
    /// # Errors
    ///
    /// Returns an error when routing or leaf data is invalid, a split cannot be represented, the
    /// configured index depth is exhausted, allocation fails, or staging cannot complete.
    fn insert_htree_directory_entry(
        &mut self,
        raw_parent: &mut LiveInodeRecord,
        parent_inode: &Inode,
        entry: RawDirectoryEntry,
    ) -> Result<()> {
        let mut tree = self.mutable_extent_tree(parent_inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let checksum = self.volume.directory_checksum(parent_inode);
        let mut context = self.mutation_htree_context(
            parent_inode,
            &tree,
            HtreePathTarget::Query(DirectoryLookup::Stored(&entry)),
        )?;
        let leaf_logical = context.path.leaf()?;
        let (leaf_physical, mut leaf) = self.read_mutation_directory_block(
            parent_inode,
            &tree,
            LogicalBlock::try_from(u64::from(leaf_logical))?,
        )?;
        context.path.hash_range()?.validate_leaf(
            &leaf.entries()?,
            context.root.hash_profile(),
            self.volume.superblock.name_semantics(parent_inode)?,
        )?;
        if leaf.insert(&entry)? {
            self.stage_directory_block(leaf_physical, leaf.into_bytes())?;
            return Ok(());
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
        let hash = context.root.hash_profile();
        let mut entries = leaf.entries()?;
        entries.try_push(entry)?;
        let names = self.volume.superblock.name_semantics(parent_inode)?;
        let entries = ordered_directory_entries(entries, hash, names)?;
        let split_at = self.directory_leaf_split(&entries, checksum)?;
        let (left_entries, right_entries) = entries
            .split_at_checked(split_at)
            .ok_or(Error::InvalidDirectoryEntry)?;
        let left_last_hash = hash
            .entry_hash(
                left_entries.last().ok_or(Error::InvalidDirectoryEntry)?,
                names,
            )?
            .major;
        let right_first_hash = hash
            .entry_hash(
                right_entries.first().ok_or(Error::InvalidDirectoryEntry)?,
                names,
            )?
            .major;
        let boundary = right_first_hash | u32::from(left_last_hash == right_first_hash);
        let block_bytes = usize::try_from(self.volume.superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let left = DirectoryBlock::from_entries(
            block_bytes,
            checksum,
            left_entries,
            DirectoryEntryEncoding::for_inode(parent_inode),
        )?;
        let right = DirectoryBlock::from_entries(
            block_bytes,
            checksum,
            right_entries,
            DirectoryEntryEncoding::for_inode(parent_inode),
        )?;
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
        self.finish_directory_growth(raw_parent, tree, next_logical)
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
                        context.root.hash_profile(),
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
                write_htree_root_index(
                    &mut context.root_bytes,
                    context.root.hash_profile(),
                    new_depth,
                    &root_index,
                    checksum,
                )?;
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
        raw_parent: &mut LiveInodeRecord,
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
        let hash = if DirectoryEntryEncoding::for_inode(parent_inode)
            == DirectoryEntryEncoding::EncryptedCasefold
        {
            DirectoryIndexHash::StoredKeyed
        } else {
            DirectoryIndexHash::Computed(DirectoryHashScheme::from_metadata(
                self.volume.superblock.directory_hash_seed(),
                self.volume.superblock.default_directory_hash_version(),
                self.volume.superblock.directory_hash_signedness(),
            ))
        };
        let mut children = Vec::new();
        for child in entries {
            if !matches!(child.name().bytes(), b"." | b"..") {
                children.try_push(child)?;
            }
        }
        children.try_push(entry)?;
        let names = self.volume.superblock.name_semantics(parent_inode)?;
        let children = ordered_directory_entries(children, hash, names)?;
        let block_bytes = usize::try_from(self.volume.superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let mut next_logical = 1_u64;
        let mut routes = Vec::new();
        match DirectoryBlock::from_entries(
            block_bytes,
            checksum,
            &children,
            DirectoryEntryEncoding::for_inode(parent_inode),
        ) {
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
                let left_last_hash = hash
                    .entry_hash(
                        left_entries.last().ok_or(Error::InvalidDirectoryEntry)?,
                        names,
                    )?
                    .major;
                let right_first_hash = hash
                    .entry_hash(
                        right_entries.first().ok_or(Error::InvalidDirectoryEntry)?,
                        names,
                    )?
                    .major;
                let boundary = right_first_hash | u32::from(left_last_hash == right_first_hash);
                let left = DirectoryBlock::from_entries(
                    block_bytes,
                    checksum,
                    left_entries,
                    DirectoryEntryEncoding::for_inode(parent_inode),
                )?;
                let right = DirectoryBlock::from_entries(
                    block_bytes,
                    checksum,
                    right_entries,
                    DirectoryEntryEncoding::for_inode(parent_inode),
                )?;
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
            hash,
            &root_index,
            checksum,
        )?;
        self.stage_directory_block(root_physical, root)?;
        raw_parent.mark_indexed_directory()?;
        self.finish_directory_growth(raw_parent, tree, next_logical)
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
        let logical_block = LogicalBlock::try_from(*next_logical)?;
        let physical = self.allocate_extent_block(tree, logical_block)?;
        tree.insert_or_extend_initialized(logical_block, physical)?;
        *next_logical = next_logical
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok((logical, physical))
    }

    /// Derives directory size and allocation from the staged layout; the caller owns timestamps.
    /// # Errors
    ///
    /// Returns an error when size encoding or extent staging cannot represent the completed growth.
    fn finish_directory_growth(
        &mut self,
        raw_parent: &mut LiveInodeRecord,
        tree: MutableExtentTree,
        block_count: u64,
    ) -> Result<()> {
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
        self.stage_extent_tree(raw_parent, tree)
    }

    /// Replays plaintext bindings using staged leaves and final inode counts.
    /// # Errors
    /// Rejects encrypted/inline parents, directory hard links, or malformed routes and identities.
    pub(super) fn replay_directory_binding(
        &mut self,
        parent: InodeId,
        target: InodeId,
        name: &Ext4Name,
        change: crate::disk_format::journal::fast_commit::NamespaceChange,
    ) -> Result<()> {
        use crate::disk_format::journal::fast_commit::NamespaceChange;
        reject_reserved_directory_name(name)?;
        self.volume.superblock.require_namespace_inode(parent)?;
        self.volume.superblock.require_namespace_inode(target)?;
        if self.replay_inode_bit(parent)? == BitmapBitState::Free {
            return if change == NamespaceChange::Unlink {
                Ok(())
            } else {
                Err(Error::UnsupportedJournal)
            };
        }
        let parent = self.raw_inode_for_policy(parent)?.parse()?;
        if parent.kind() != InodeKind::Directory
            || parent.protection().is_encrypted()
            || parent.flags().has_inline_data()
        {
            return Err(Error::UnsupportedJournal);
        }
        let binding = match change {
            NamespaceChange::Create | NamespaceChange::Link => {
                let child = self.raw_inode_for_policy(target)?.parse()?;
                if child.kind() == InodeKind::Directory && change == NamespaceChange::Link {
                    return Err(Error::UnsupportedJournal);
                }
                LoggedBinding::Present(RawDirectoryEntry::new(
                    target,
                    name,
                    directory_entry_kind(child.kind()),
                )?)
            }
            NamespaceChange::Unlink => LoggedBinding::AbsentIf {
                inode: target,
                name,
            },
        };
        let names = self.volume.superblock.name_semantics(&parent)?;
        let tree = self.mutable_extent_tree(&parent)?;
        if tree.contains_uninitialized() {
            return Err(Error::InvalidDirectoryEntry);
        }
        let mut insertion = None;
        match parent.directory_storage_kind()? {
            DirectoryStorageKind::Linear => {
                let count = round_up_div(
                    parent.size().bytes(),
                    u64::from(self.volume.superblock.block_size().bytes()),
                )?;
                for logical in 0..count {
                    let (physical, mut block) = self.read_mutation_directory_block(
                        &parent,
                        &tree,
                        LogicalBlock::try_from(logical)?,
                    )?;
                    match binding.apply(&mut block, names)? {
                        LoggedLeafResult::FoundUnchanged => return Ok(()),
                        LoggedLeafResult::FoundChanged => {
                            return self.stage_directory_block(physical, block.into_bytes());
                        }
                        LoggedLeafResult::FoundRemoved => {
                            self.stage_directory_block(physical, block.into_bytes())?;
                            return self.finish_logged_binding(parent.id(), binding);
                        }
                        LoggedLeafResult::VacantInserted if insertion.is_none() => {
                            insertion = Some((physical, block))
                        }
                        LoggedLeafResult::Vacant | LoggedLeafResult::VacantInserted => {}
                    }
                }
            }
            DirectoryStorageKind::HTree => {
                let query = DirectoryLookup::Name(binding.name());
                let mut context =
                    self.mutation_htree_context(&parent, &tree, HtreePathTarget::Query(query))?;
                let major = query.major(context.root.hash_profile(), names)?;
                loop {
                    let logical = LogicalBlock::try_from(u64::from(context.path.leaf()?))?;
                    let (physical, mut block) =
                        self.read_mutation_directory_block(&parent, &tree, logical)?;
                    context.path.hash_range()?.validate_leaf(
                        &block.entries()?,
                        context.root.hash_profile(),
                        names,
                    )?;
                    match binding.apply(&mut block, names)? {
                        LoggedLeafResult::FoundUnchanged => return Ok(()),
                        LoggedLeafResult::FoundChanged => {
                            return self.stage_directory_block(physical, block.into_bytes());
                        }
                        LoggedLeafResult::FoundRemoved => {
                            self.stage_directory_block(physical, block.into_bytes())?;
                            return self.finish_logged_binding(parent.id(), binding);
                        }
                        LoggedLeafResult::VacantInserted if insertion.is_none() => {
                            insertion = Some((physical, block))
                        }
                        LoggedLeafResult::Vacant | LoggedLeafResult::VacantInserted => {}
                    }
                    if !self.advance_mutation_htree_path(
                        &parent,
                        &tree,
                        &mut context.path,
                        context.root.indirect_levels(),
                    )? || context.path.boundary()? & !1 != major
                    {
                        break;
                    }
                }
            }
        }
        if let Some((physical, block)) = insertion {
            self.stage_directory_block(physical, block.into_bytes())
        } else {
            self.finish_logged_binding(parent.id(), binding)
        }
    }

    /// Establishes mandatory directory entries before a fresh inode can enter namespace staging.
    /// # Errors
    /// Returns allocation, coordinate or directory checksum/serialization failure.
    pub(super) fn initialize_delta_directory(
        &mut self,
        raw: &mut LiveInodeRecord,
        tree: &mut MutableExtentTree,
        parent: InodeId,
    ) -> Result<()> {
        let logical = LogicalBlock::from_u32(0);
        let physical = self.allocate_extent_block(tree, logical)?;
        tree.insert_or_extend_initialized(logical, physical)?;
        let inode = raw.parse()?;
        let mut block = DirectoryBlock::empty(
            usize::try_from(self.volume.superblock.block_size().bytes())
                .map_err(|_| Error::ArithmeticOverflow)?,
            self.volume.directory_checksum(&inode),
            DirectoryEntryEncoding::for_inode(&inode),
        )?;
        block.initialize_dot_entries(raw.id(), parent)?;
        self.stage_directory_block(physical, block.into_bytes())
    }

    /// Visits the current staged directory view, stopping at the first completed observation.
    /// Hash routes are authenticated before the visitor observes a leaf; encoded names stay opaque.
    /// # Errors
    /// Returns malformed layout/routes, allocation, suspended reads or the visitor's failure.
    pub(super) fn visit_directory_entries(
        &mut self,
        inode: &Inode,
        mut visit: impl FnMut(&mut Self, Vec<RawDirectoryEntry>) -> Result<core::ops::ControlFlow<()>>,
    ) -> Result<core::ops::ControlFlow<()>> {
        use core::ops::ControlFlow;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if let InodeStorage::InlineData(data) = inode.storage() {
            return visit(self, data.directory_entries(inode.id())?);
        }
        let tree = self.mutable_extent_tree(inode)?;
        match inode.directory_storage_kind()? {
            DirectoryStorageKind::Linear => {
                let blocks = round_up_div(
                    inode.size().bytes(),
                    u64::from(self.volume.superblock.block_size().bytes()),
                )?;
                for logical in 0..blocks {
                    let (_, block) = self.read_mutation_directory_block(
                        inode,
                        &tree,
                        LogicalBlock::try_from(logical)?,
                    )?;
                    if visit(self, block.entries()?)?.is_break() {
                        return Ok(ControlFlow::Break(()));
                    }
                }
            }
            DirectoryStorageKind::HTree => {
                let mut context =
                    self.mutation_htree_context(inode, &tree, HtreePathTarget::First)?;
                loop {
                    let (_, block) = self.read_mutation_directory_block(
                        inode,
                        &tree,
                        LogicalBlock::try_from(u64::from(context.path.leaf()?))?,
                    )?;
                    let entries = block.entries()?;
                    context.path.hash_range()?.validate_leaf(
                        &entries,
                        context.root.hash_profile(),
                        self.volume.superblock.name_semantics(inode)?,
                    )?;
                    if visit(self, entries)?.is_break() {
                        return Ok(ControlFlow::Break(()));
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
        Ok(ControlFlow::Continue(()))
    }

    /// Empty-directory admission observes the same staged leaves as namespace recovery.
    /// # Errors
    /// Returns malformed directory storage, routes or source reads.
    pub(super) fn directory_is_empty(&mut self, inode: &Inode) -> Result<bool> {
        Ok(self
            .visit_directory_entries(inode, |_, entries| {
                Ok(
                    if entries
                        .iter()
                        .any(|entry| !matches!(entry.name().bytes(), b"." | b".."))
                    {
                        core::ops::ControlFlow::Break(())
                    } else {
                        core::ops::ControlFlow::Continue(())
                    },
                )
            })?
            .is_continue())
    }

    /// Directory link counts are structural postconditions, independent of replay attempt counts.
    /// # Errors
    /// Returns invalid children, malformed routes, source reads or count-field overflow.
    pub(super) fn recount_replayed_directory_links(
        &mut self,
        program: &crate::disk_format::journal::fast_commit::DeltaProgram,
    ) -> Result<()> {
        for offset in 0..self.inode_updates.len() {
            let is_directory = match self.inode_updates.get(offset).ok_or(Error::InvalidInode)? {
                StagedInodeRecord::Live(raw) => raw.parse()?.kind() == InodeKind::Directory,
                _ => false,
            };
            if !is_directory {
                continue;
            }
            let index = StagedInodeIndex::new(offset);
            let mut raw = self.staged_live_inode(index)?;
            let inode = raw.parse()?;
            let recorded = program.records().iter().any(|record| matches!(record, crate::disk_format::journal::fast_commit::ParsedDelta::Inode { inode: id, .. } if *id == inode.id()));
            let normalize_uncounted = inode.links_count().known_count().is_none()
                && !inode.flags().has_indexed_directory();
            if recorded && !normalize_uncounted {
                continue;
            }
            let mut structural_change = normalize_uncounted;
            for record in program.records() {
                if let crate::disk_format::journal::fast_commit::ParsedDelta::Namespace {
                    parent,
                    inode: child,
                    ..
                } = record
                    && *parent == inode.id()
                    && (self.replay_inode_bit(*child)? == BitmapBitState::Free
                        || self.raw_inode_for_policy(*child)?.parse()?.kind()
                            == InodeKind::Directory)
                {
                    structural_change = true;
                    break;
                }
            }
            if !structural_change {
                continue;
            }
            let mut links = Ext4LinkCount::TWO;
            let _complete = self.visit_directory_entries(&inode, |mutation, entries| {
                mutation.count_directory_children(entries, &inode, &mut links)?;
                Ok(core::ops::ControlFlow::Continue(()))
            })?;
            raw.replace_directory_links(links)?;
            self.replace_live_inode(index, raw)?;
        }
        Ok(())
    }

    /// Counts identities using validated inode kinds, including directories without dirent type hints.
    /// # Errors
    /// Returns invalid namespace identities, source I/O, allocation or directory-count overflow.
    fn count_directory_children(
        &mut self,
        entries: Vec<RawDirectoryEntry>,
        parent: &Inode,
        links: &mut Ext4LinkCount,
    ) -> Result<()> {
        for entry in entries {
            if matches!(entry.name().bytes(), b"." | b"..") {
                continue;
            }
            self.volume
                .superblock
                .require_namespace_inode(entry.inode())?;
            let inode = self.raw_inode_for_policy(entry.inode())?.parse()?;
            if inode.kind() == InodeKind::Directory {
                *links = links.directory_incremented(
                    self.volume
                        .superblock
                        .inode_data_encoding()
                        .directory_links(),
                    parent.flags().has_indexed_directory(),
                )?;
            }
        }
        Ok(())
    }

    /// A searched, absent name can require layout growth while preserving recorded inode timestamps.
    /// # Errors
    /// Returns allocation, layout or inode staging failure before persistence.
    fn finish_logged_binding(&mut self, parent: InodeId, binding: LoggedBinding<'_>) -> Result<()> {
        match binding {
            LoggedBinding::AbsentIf { .. } => Ok(()),
            LoggedBinding::Present(entry) => {
                let index = self.ensure_inode_update(parent)?;
                let mut raw = self.staged_live_inode(index)?;
                self.insert_encoded_directory_entry(&mut raw, entry)?;
                self.replace_live_inode(index, raw)
            }
        }
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
                .read_metadata_exact_at(block_size.offset_of(physical)?, &mut bytes)?;
            bytes
        };
        Ok((
            physical,
            DirectoryBlock::new(
                bytes,
                self.volume.directory_checksum(inode),
                DirectoryEntryEncoding::for_inode(inode),
            ),
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
            self.volume.superblock.directory_hash_signedness(),
            self.volume
                .superblock
                .directory_indexing()
                .require_supported()?,
            checksum,
            DirectoryEntryEncoding::for_inode(inode),
        )?;
        let major = match target {
            HtreePathTarget::Query(query) => query.major(
                root.hash_profile(),
                self.volume.superblock.name_semantics(inode)?,
            )?,
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
}

/// Sorts immutable entry/hash pairs so normalization and its fallible allocations precede sorting.
/// Bytewise directories retain their allocation-free comparator.
/// # Errors
/// Returns invalid encoding, normalization allocation or fallible sorting failures.
fn ordered_directory_entries(
    mut entries: Vec<RawDirectoryEntry>,
    hash: DirectoryIndexHash,
    names: crate::disk_format::name::NameSemantics,
) -> Result<Vec<RawDirectoryEntry>> {
    if let DirectoryIndexHash::Computed(scheme) = hash
        && names == crate::disk_format::name::NameSemantics::Bytewise
    {
        memory::heap_sort_by(&mut entries, |left, right| {
            scheme
                .hash(left.name().bytes())
                .cmp(&scheme.hash(right.name().bytes()))
                .then(left.name().bytes().cmp(right.name().bytes()))
        })?;
        return Ok(entries);
    }
    let mut keyed = Vec::new();
    keyed
        .try_reserve_exact(entries.len())
        .map_err(|_| Error::OutOfMemory)?;
    #[expect(
        clippy::disallowed_methods,
        reason = "the unbounded range is exactly the complete owned vector; its capacity is retained for reordered entries"
    )]
    for entry in entries.drain(..) {
        keyed.try_push((hash.entry_hash(&entry, names)?, entry))?;
    }
    memory::heap_sort_by(&mut keyed, |left, right| {
        left.0
            .cmp(&right.0)
            .then(left.1.name().bytes().cmp(right.1.name().bytes()))
    })?;
    for (_, entry) in keyed {
        entries.try_push(entry)?;
    }
    Ok(entries)
}
