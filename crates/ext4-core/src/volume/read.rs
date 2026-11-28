//! Read-only traversal and metadata projection for mounted volumes.

use core::num::NonZeroU64;

use super::htree::HtreePath;
use super::scope::*;

/// Establishes the same initialized-map contract for committed and transaction-overlay readers.
/// The caller independently excludes security.capability in its corresponding xattr view.
/// # Errors
/// Rejects protected/data-journaled payload, sparse or unwritten blocks and physical discontinuity.
pub(super) fn initialized_contiguous_storage(
    inode: &Inode,
    size: BlockSize,
    context: ExtentTreeContext,
    source: &mut impl crate::disk_format::extent::ExtentNodeReader,
    mount: super::session::MountIdentity,
    retained: Option<super::node::ContiguousFileStorage>,
) -> Result<Option<super::node::ContiguousFileStorage>> {
    inode.file_payload_mutation()?;
    if inode.protection() != crate::disk_format::inode::InodeProtection::Plain
        || inode.data_persistence() == crate::disk_format::inode::FileDataPersistence::Journaled
        || inode.security().permissions()
            != inode.security().permissions().without_file_privileges()
    {
        return Err(Error::UnsupportedInodeMutation);
    }
    let root = match inode.storage() {
        crate::disk_format::inode::InodeStorage::Extents(root) => root,
        crate::disk_format::inode::InodeStorage::InlineData(data)
            if inode.size().bytes() == 0 && data.file()?.is_empty() =>
        {
            return Ok(None);
        }
        _ => return Err(Error::UnsupportedInodeMutation),
    };
    let bytes = u64::from(size.bytes());
    let logical_size = inode.size();
    let mut mapping = ExtentMappingCursor::new(root, size, context)?;
    let allocated_blocks = mapping.allocation_end(source)?;
    let blocks = if let Some(retained) = retained {
        if retained.mount != mount
            || retained.inode != inode.id()
            || retained.generation != inode.generation()
            || !retained.initialized_length.bytes().is_multiple_of(bytes)
        {
            return Err(Error::InvalidWriteRange);
        }
        let blocks = retained
            .initialized_length
            .bytes()
            .checked_div(bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        if blocks > allocated_blocks {
            return Err(Error::InvalidWriteRange);
        }
        blocks
    } else {
        allocated_blocks
    };
    let initialized_length =
        FileSize::from_bytes(blocks.checked_mul(bytes).ok_or(Error::ArithmeticOverflow)?);
    if initialized_length.bytes() == 0 {
        return if logical_size.bytes() == 0 {
            Ok(None)
        } else {
            Err(Error::UnsupportedInodeMutation)
        };
    }
    if logical_size > initialized_length {
        return Err(Error::UnsupportedInodeMutation);
    }
    let mut cursor = 0_u64;
    let mut origin = None;
    while cursor < blocks {
        let run = mapping.map_run(
            LogicalBlock::try_from(cursor)?,
            NonZeroU64::new(
                blocks
                    .checked_sub(cursor)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::InvalidExtentTree)?,
            source,
        )?;
        let physical_start = match run {
            ExtentBlockRun::Initialized { physical_start, .. } => physical_start,
            ExtentBlockRun::Uninitialized { physical_start, .. }
                if retained.is_some()
                    && cursor.checked_mul(bytes).ok_or(Error::ArithmeticOverflow)?
                        >= logical_size.bytes() =>
            {
                physical_start
            }
            _ => return Err(Error::UnsupportedInodeMutation),
        };
        let physical = size.offset_of(physical_start)?.get();
        let base = *origin.get_or_insert(physical);
        if base.checked_add(cursor.checked_mul(bytes).ok_or(Error::ArithmeticOverflow)?)
            != Some(physical)
        {
            return Err(Error::UnsupportedInodeMutation);
        }
        cursor = cursor
            .checked_add(run.blocks().get())
            .ok_or(Error::ArithmeticOverflow)?;
    }
    Ok(Some(super::node::ContiguousFileStorage {
        mount,
        inode: inode.id(),
        generation: inode.generation(),
        physical: ByteOffset::new(origin.ok_or(Error::InvalidExtentTree)?),
        initialized_length,
        logical_size,
    }))
}

impl EpochReadView<'_, '_> {
    /// Allocation is read under block-group resource dependencies, so a suspended bitmap cannot
    /// be interpreted with a later allocation publication. Descriptor-selected metadata locations
    /// remain fixed for this mount; BLOCK_UNINIT uses their semantic bitmap, never raw disk bits.
    /// # Errors
    /// Returns geometry, bitmap integrity, allocation or lower-storage failures.
    pub(super) fn read_cluster_bitmap(
        &mut self,
        start: ClusterAddress,
        output: &mut [u8],
    ) -> Result<crate::ClusterCount> {
        let remaining = self
            .superblock
            .cluster_count()
            .as_u64()
            .checked_sub(start.get())
            .filter(|value| *value != 0)
            .ok_or(Error::DeviceRange)?;
        let capacity = u64::try_from(output.len())
            .map_err(|_| Error::ArithmeticOverflow)?
            .checked_mul(8)
            .ok_or(Error::ArithmeticOverflow)?;
        let count = crate::ClusterCount::new(capacity.min(remaining))?;
        output.fill(0);
        let mut cursor = 0_u64;
        let mut layouts = None;
        while cursor < count.as_u64() {
            let address = ClusterAddress::new(
                start
                    .get()
                    .checked_add(cursor)
                    .ok_or(Error::ArithmeticOverflow)?,
            );
            let group = self.superblock.cluster_group_of(address)?;
            self.observe_resource(MutationResource::block_group(group))?;
            let descriptor =
                BlockGroupDescriptor::read_from(&mut self.device, &self.superblock, group)?;
            let bitmap = match descriptor.block_bitmap_initialization() {
                AllocationBitmapInitialization::Initialized => descriptor.read_bitmap(
                    &mut self.device,
                    &self.superblock,
                    AllocationBitmapKind::Block,
                )?,
                AllocationBitmapInitialization::Uninitialized => {
                    if layouts.is_none() {
                        layouts = Some(super::block_group::read_group_metadata_layouts(
                            &mut self.device,
                            &self.superblock,
                        )?);
                    }
                    super::block_group::materialize_uninitialized_block_bitmap(
                        &self.superblock,
                        group,
                        layouts.as_deref().ok_or(Error::InvalidSuperblock)?,
                    )?
                }
            };
            let first = self.superblock.cluster_bit_in_group(address, group)?;
            let available = self
                .superblock
                .clusters_in_group(group)?
                .checked_sub(first)
                .ok_or(Error::InvalidClusterGeometry)?;
            let take = u64::from(available).min(
                count
                    .as_u64()
                    .checked_sub(cursor)
                    .ok_or(Error::ArithmeticOverflow)?,
            );
            if take == 0 {
                return Err(Error::InvalidClusterGeometry);
            }
            for bit in 0..take {
                let source = first
                    .checked_add(u32::try_from(bit).map_err(|_| Error::ArithmeticOverflow)?)
                    .ok_or(Error::ArithmeticOverflow)?;
                if cluster_bitmap_bit_state(&bitmap, ClusterBitmapPosition::new(group, source))?
                    == BitmapBitState::Used
                {
                    let target = cursor.checked_add(bit).ok_or(Error::ArithmeticOverflow)?;
                    let index =
                        usize::try_from(target / 8).map_err(|_| Error::ArithmeticOverflow)?;
                    let value = output.get_mut(index).ok_or(Error::DeviceRange)?;
                    *value |= 1_u8
                        .checked_shl(
                            u32::try_from(target % 8).map_err(|_| Error::ArithmeticOverflow)?,
                        )
                        .ok_or(Error::ArithmeticOverflow)?;
                }
            }
            cursor = cursor.checked_add(take).ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(count)
    }
}

/// Maximum bytes passed to one backing-device data read.
const MAX_READ_WINDOW_BYTES: usize = 65_536;

/// Fully validated protection and mapping state for one fs-verity range read.
struct VerityReadPlan {
    /// File payload and post-EOF metadata mapping.
    extent_tree: ExtentMappingCursor,
    /// Per-inode plaintext recovery key when fscrypt also protects this inode.
    contents_key: Option<FscryptContentsKey>,
    /// ext4 post-EOF placement of the serialized Merkle tree.
    metadata: Ext4VerityMetadataLayout,
    /// Descriptor-owned Merkle geometry and proof state factory.
    verifier: FsverityVerifier,
}

impl EpochReadView<'_, '_> {
    /// Loads one cohesive access policy, checking its agreement with inode fields.
    /// # Errors
    /// Returns inode-kind, xattr, ACL agreement, I/O or allocation failures.
    pub(super) fn load_access(&mut self, node: NodeId) -> Result<Ext4Access> {
        let raw = self.read_live_inode_record(node.inode())?;
        let inode = raw.parse()?;
        if !matches!(
            (node, inode.kind()),
            (NodeId::File(_), InodeKind::File)
                | (NodeId::Directory(_), InodeKind::Directory)
                | (NodeId::Symlink(_), InodeKind::Symlink)
        ) {
            return Err(Error::WrongInodeKind);
        }
        let xattrs = self.read_inode_xattrs_from_live(&raw)?;
        let acl = AclKind::Access.read(xattrs.public())?;
        if inode.kind() == InodeKind::Symlink && acl.is_some() {
            return Err(Error::InvalidAcl);
        }
        Ext4Access::new(inode.security(), acl)
    }

    /// Computes access before child creation from the parent's committed default ACL.
    /// # Errors
    /// Returns directory, default ACL, storage or allocation failures.
    pub(super) fn child_access(
        &mut self,
        parent: DirectoryNodeId,
        security: Ext4Security,
    ) -> Result<Ext4Access> {
        let raw = self.read_live_inode_record(parent.inode())?;
        if raw.parse()?.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        let xattrs = self.read_inode_xattrs_from_live(&raw)?;
        Ext4Access::inherit(security, AclKind::Default.read(xattrs.public())?)
    }

    /// Loads a regular file by previously validated file identity.
    /// # Errors
    ///
    /// Returns an error when the identity's inode cannot be loaded or is no longer a regular file.
    pub(super) fn load_file(&mut self, id: FileNodeId) -> Result<FileNode> {
        match self.load_validated_node(NodeId::File(id))? {
            LoadedNode::File(file) => Ok(file),
            LoadedNode::Directory(_) | LoadedNode::Symlink(_) => Err(Error::WrongInodeKind),
        }
    }

    /// Loads a directory by previously validated directory identity.
    /// # Errors
    ///
    /// Returns an error when the identity's inode cannot be loaded or is no longer a directory.
    pub(super) fn load_directory(&mut self, id: DirectoryNodeId) -> Result<DirectoryNode> {
        match self.load_validated_node(NodeId::Directory(id))? {
            LoadedNode::Directory(directory) => Ok(directory),
            LoadedNode::File(_) | LoadedNode::Symlink(_) => Err(Error::WrongInodeKind),
        }
    }

    /// Loads a symbolic link by previously validated symlink identity.
    /// # Errors
    ///
    /// Returns an error when the identity's inode cannot be loaded or is no longer a symbolic link.
    pub(super) fn load_symlink(&mut self, id: SymlinkNodeId) -> Result<SymlinkNode> {
        match self.load_validated_node(NodeId::Symlink(id))? {
            LoadedNode::Symlink(symlink) => Ok(symlink),
            LoadedNode::File(_) | LoadedNode::Directory(_) => Err(Error::WrongInodeKind),
        }
    }

    /// Reads all extended attributes attached to an inode.
    ///
    /// # Errors
    /// Returns an error when the inode or its external xattr block is malformed.
    pub(super) fn read_inode_xattrs(&mut self, inode_id: InodeId) -> Result<XattrSet> {
        let inode = self.read_live_inode_record(inode_id)?;
        Ok(self.read_inode_xattrs_from_live(&inode)?.into_public())
    }

    /// Reads one extended attribute value by name.
    ///
    /// # Errors
    /// Returns an error when the inode or its external xattr block is malformed.
    pub(super) fn read_inode_xattr(
        &mut self,
        inode_id: InodeId,
        name: &XattrName,
    ) -> Result<Option<XattrValue>> {
        self.read_inode_xattrs(inode_id)?
            .get(name)
            .map(XattrValue::try_clone)
            .transpose()
    }

    /// Resolves a context against the operation's key snapshot and records its freshness dependency.
    /// # Errors
    /// Returns resource-observation failure or a missing encryption key.
    pub(super) fn fscrypt_key(&mut self, context: FscryptContextV2) -> Result<FscryptInodeKey<'_>> {
        self.observe_resource(MutationResource::KEY_SET)?;
        self.fscrypt_keys.unlock(context)
    }

    /// Selects the committed inode's context before binding its mount key.
    /// # Errors
    /// Returns malformed inode/xattr/context, storage, allocation or missing-key failure.
    fn fscrypt_key_for_inode(&mut self, inode: &Inode) -> Result<FscryptInodeKey<'_>> {
        let raw = self.read_live_inode_record(inode.id())?;
        let xattrs = self.read_inode_xattrs_from_live(&raw)?;
        let value = xattrs
            .encryption_context()
            .ok_or(Error::InvalidEncryptionContext)?;
        self.fscrypt_key(FscryptContextV2::parse(value.bytes())?)
    }

    /// Prepares a query from committed directory context and the observed key snapshot.
    /// # Errors
    /// Returns context, encoding, allocation, crypto or missing-key display failure.
    fn prepare_directory_lookup<'name>(
        &mut self,
        parent: &Inode,
        name: &'name Ext4Name,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<PreparedDirectoryLookup<'name>> {
        let names = self.superblock.name_semantics(parent)?;
        if !parent.protection().is_encrypted() || matches!(name.bytes(), b"." | b"..") {
            return Ok(PreparedDirectoryLookup::Plain(name));
        }
        match self.fscrypt_key_for_inode(parent) {
            Ok(key) => PreparedDirectoryLookup::encrypted(name, names, key, crypto),
            Err(Error::MissingEncryptionKey) => Ok(PreparedDirectoryLookup::NoKey(
                FscryptNoKeyName::from_display(name.bytes())?.ok_or(Error::MissingEncryptionKey)?,
            )),
            Err(error) => Err(error),
        }
    }

    /// Converts an on-disk child name to plaintext for a directory.
    /// # Errors
    ///
    /// Returns an error when an encrypted parent lacks a filename key or the decrypted name is not a
    /// valid ext4 component.
    pub(super) fn decrypt_directory_child_name(
        &mut self,
        parent: &Inode,
        name: &Ext4Name,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<Ext4Name> {
        if !parent.protection().is_encrypted() || matches!(name.bytes(), b"." | b"..") {
            return Ext4Name::new(name.bytes());
        }
        self.fscrypt_key_for_inode(parent)?
            .decrypt_name(name, crypto)
    }

    /// Rejects protected plaintext data access until crypto and verification paths exist.
    /// # Errors
    ///
    /// Returns an error when the inode is encrypted or verity-protected, including the missing-key
    /// case for encrypted payloads.
    pub(super) fn reject_unsupported_protected_payload_access(
        &mut self,
        inode: &Inode,
    ) -> Result<()> {
        if inode.protection().is_encrypted() {
            let _key = self.fscrypt_key_for_inode(inode)?;
            return Err(Error::UnsupportedEncryption);
        }
        if inode.protection().is_verity() {
            return Err(Error::UnsupportedVerity);
        }
        Ok(())
    }

    /// Reads and classifies one inode as a typed node.
    ///
    /// # Errors
    /// Returns an error when the inode belongs to filesystem metadata, is outside the volume,
    /// or its record cannot be read and authenticated.
    pub(super) fn load_inode_node(&mut self, inode_id: InodeId) -> Result<LoadedNode> {
        self.superblock.require_namespace_inode(inode_id)?;
        Ok(LoadedNode::from_inode(self.read_inode_record(inode_id)?))
    }

    /// Reads complete metadata of one namespace inode whose node kind is not yet known.
    ///
    /// # Errors
    /// Returns an error when the inode belongs to filesystem metadata, is outside the volume,
    /// or its record cannot be read and authenticated.
    pub(super) fn load_inode_metadata(
        &mut self,
        inode_id: InodeId,
    ) -> Result<NodeMetadataSnapshot> {
        self.superblock.require_namespace_inode(inode_id)?;
        Ok(NodeMetadataSnapshot::from_inode(
            &self.read_inode_record(inode_id)?,
        ))
    }

    /// Loads an inode through a previously validated public identity.
    /// # Errors
    ///
    /// Returns an error when the inode cannot be loaded or its actual typed identity no longer
    /// matches `id`.
    pub(super) fn load_validated_node(&mut self, id: NodeId) -> Result<LoadedNode> {
        let node = self.load_inode_node(id.inode())?;
        if node.id() == id {
            Ok(node)
        } else {
            Err(Error::InvalidInode)
        }
    }

    /// Validates an initialized, contiguous regular-file payload for an external fixed-map owner.
    /// # Errors
    /// Rejects absent initialized allocation, resident data, sparse/unwritten or fragmented ranges,
    /// protected files and data-journaled payloads.
    pub(super) fn contiguous_file_storage(
        &mut self,
        id: FileNodeId,
    ) -> Result<super::node::ContiguousFileStorage> {
        let file = self.load_file(id)?;
        let inode = file.inode();
        if self
            .read_inode_xattrs(inode.id())?
            .entries()
            .any(|(name, _)| {
                name.namespace() == crate::XattrNamespace::Security && name.local() == b"capability"
            })
        {
            return Err(Error::UnsupportedInodeMutation);
        }
        let context = self.extent_tree_context(inode);
        let mount = self
            .published_epoch()
            .ok_or(Error::InvalidWriteRange)?
            .mount;
        initialized_contiguous_storage(
            inode,
            self.superblock.block_size(),
            context,
            &mut self.device,
            mount,
            None,
        )?
        .ok_or(Error::InvalidWriteRange)
    }

    /// Observes one payload allocation run without reading file contents or building a full tree.
    /// # Errors
    /// Returns invalid identity, unaligned/range, extent checksum/routing, or backing I/O failures.
    pub(super) fn node_data_allocation(
        &mut self,
        node: NodeId,
        offset: FileOffset,
    ) -> Result<Option<super::node::DataAllocationRun>> {
        let loaded = self.load_validated_node(node)?;
        let inode = match &loaded {
            LoadedNode::File(file) => file.inode(),
            LoadedNode::Directory(directory) => directory.inode(),
            LoadedNode::Symlink(symlink) => symlink.inode(),
        };
        let root = match inode.storage() {
            crate::disk_format::inode::InodeStorage::FastSymlink(_)
            | crate::disk_format::inode::InodeStorage::InlineData(_) => return Ok(None),
            crate::disk_format::inode::InodeStorage::Extents(root) => root,
            crate::disk_format::inode::InodeStorage::UnsupportedBlockMap => {
                return Err(Error::UnsupportedBlockMap);
            }
        };
        let size = self.superblock.block_size();
        let bytes = u64::from(size.bytes());
        if !offset.bytes().is_multiple_of(bytes) {
            return Err(Error::DeviceRange);
        }
        let context = self.extent_tree_context(inode);
        let mut mapping = ExtentMappingCursor::new(root, size, context)?;
        let eof = round_up_div(inode.size().bytes(), bytes)?;
        let end = if inode.protection().is_verity() {
            eof
        } else {
            eof.max(mapping.allocation_end(&mut self.device)?)
        };
        let logical = offset
            .bytes()
            .checked_div(bytes)
            .ok_or(Error::InvalidExtentTree)?;
        if logical >= end {
            return Ok(None);
        }
        let run = mapping.map_run(
            LogicalBlock::try_from(logical)?,
            NonZeroU64::new(end.checked_sub(logical).ok_or(Error::InvalidExtentTree)?)
                .ok_or(Error::InvalidExtentTree)?,
            &mut self.device,
        )?;
        let physical = match run {
            ExtentBlockRun::Initialized { physical_start, .. }
            | ExtentBlockRun::Uninitialized { physical_start, .. } => {
                Some(size.offset_of(physical_start)?)
            }
            ExtentBlockRun::Hole { .. } => None,
        };
        let end = offset
            .bytes()
            .checked_add(
                run.blocks()
                    .get()
                    .checked_mul(bytes)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Some(super::node::DataAllocationRun {
            start: offset,
            end: FileOffset::from_bytes(end),
            physical,
        }))
    }

    /// Reads file bytes from a typed regular file node.
    ///
    /// # Errors
    /// Returns an error when the file extent mapping cannot be traversed.
    pub(super) fn read_file(
        &mut self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<ReadBytes> {
        if file.protection().is_verity() {
            return self.read_verified_file(file, offset, out, crypto);
        }
        self.read_inode_plaintext_data(file.inode(), offset, out, crypto)
    }

    /// Reads a typed symlink target as bytes.
    ///
    /// # Errors
    /// Returns an error when the symlink target cannot be read.
    pub(super) fn read_symlink(&mut self, symlink: &SymlinkNode) -> Result<Vec<u8>> {
        self.reject_unsupported_protected_payload_access(symlink.inode())?;
        let len = symlink.size().to_usize()?;
        if let Ok(inline) = symlink.inode().fast_symlink() {
            return memory::copied_slice(inline.prefix(symlink.size())?);
        }
        let mut target = memory::repeated_vec(0_u8, len)?;
        let _bytes_read = self.read_inode_data(symlink.inode(), FileOffset::ZERO, &mut target)?;
        Ok(target)
    }

    /// Converts one raw on-disk dirent into its caller-visible validated entry.
    /// # Errors
    ///
    /// Returns an error when encrypted-name projection or referenced-inode validation fails.
    pub(super) fn project_directory_name(
        &mut self,
        directory: &DirectoryNode,
        raw: RawDirectoryEntry,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<Ext4Name> {
        if directory.protection().is_encrypted() {
            match self.decrypt_directory_child_name(directory.inode(), raw.name(), crypto) {
                Ok(name) => Ok(name),
                Err(Error::MissingEncryptionKey) => {
                    self.project_locked_directory_name(directory.inode(), &raw, crypto)
                }
                Err(error) => Err(error),
            }
        } else {
            raw.name().try_to_owned_name()
        }
    }

    /// Reads one mapped logical directory block.
    /// # Errors
    ///
    /// Returns an error when the logical block is outside the semantic directory size, unmapped,
    /// unreadable, or cannot be allocated.
    pub(super) fn read_directory_logical_block(
        &mut self,
        inode: &Inode,
        tree: &mut ExtentMappingCursor,
        logical: LogicalBlock,
    ) -> Result<DirectoryBlock> {
        let block_count = round_up_div(
            inode.size().bytes(),
            u64::from(self.superblock.block_size().bytes()),
        )?;
        if logical.as_u64() >= block_count {
            return Err(Error::InvalidDirectoryEntry);
        }
        let physical = match tree.map(logical, &mut self.device)? {
            BlockMapping::Physical(physical) => physical,
            BlockMapping::Uninitialized | BlockMapping::Hole => {
                return Err(Error::InvalidDirectoryEntry);
            }
        };
        let block_size = self.superblock.block_size();
        let mut bytes = memory::repeated_vec(
            0_u8,
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        self.device
            .read_metadata_exact_at(block_size.offset_of(physical)?, &mut bytes)?;
        Ok(DirectoryBlock::new(
            bytes,
            self.directory_checksum(inode),
            DirectoryEntryEncoding::for_inode(inode),
        ))
    }

    /// Loads only the interior nodes selected by the current validated route.
    /// # Errors
    /// Returns routing, parse, storage or allocation failure.
    fn complete_htree_descent(
        &mut self,
        inode: &Inode,
        tree: &mut ExtentMappingCursor,
        path: &mut HtreePath,
    ) -> Result<()> {
        let checksum = self.directory_checksum(inode);
        path.descend_with(|logical| {
            let block = self.read_directory_logical_block(inode, tree, logical)?;
            Ok((DxIndex::parse_node(block.bytes(), checksum)?, ()))
        })
    }

    /// Finds one exact on-disk name without materializing unrelated directory leaves.
    /// # Errors
    ///
    /// Returns an error when the directory storage, selected path, collision continuation, leaf
    /// hash interval, or exact entry is invalid.
    fn find_raw_directory_entry(
        &mut self,
        inode: &Inode,
        query: DirectoryLookup<'_>,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<Option<RawDirectoryEntry>> {
        let names = self.superblock.name_semantics(inode)?;
        if let InodeStorage::InlineData(data) = inode.storage() {
            return query.find(data.directory_entries(inode.id())?, crypto, names);
        }
        let mut tree = ExtentMappingCursor::new(
            inode.extent_root()?,
            self.superblock.block_size(),
            self.extent_tree_context(inode),
        )?;
        let block_size = self.superblock.block_size();
        match inode.directory_storage_kind()? {
            DirectoryStorageKind::Linear => {
                let block_count =
                    round_up_div(inode.size().bytes(), u64::from(block_size.bytes()))?;
                for logical in 0..block_count {
                    let block = self.read_directory_logical_block(
                        inode,
                        &mut tree,
                        LogicalBlock::try_from(logical)?,
                    )?;
                    if let Some(entry) = query.find(block.entries()?, crypto, names)? {
                        return Ok(Some(entry));
                    }
                }
                Ok(None)
            }
            DirectoryStorageKind::HTree => {
                let checksum = self.directory_checksum(inode);
                let root_block = self.read_directory_logical_block(
                    inode,
                    &mut tree,
                    LogicalBlock::try_from(0_u64)?,
                )?;
                let root = HtreeRoot::parse(
                    root_block.bytes(),
                    inode.id(),
                    self.superblock.directory_hash_seed(),
                    self.superblock.directory_hash_signedness(),
                    self.superblock.directory_indexing().require_supported()?,
                    checksum,
                    DirectoryEntryEncoding::for_inode(inode),
                )?;
                if let Some(entry) = root
                    .dot_entries()
                    .iter()
                    .find(|entry| query.exact() == Some(entry.name()))
                {
                    return Ok(Some(entry.try_clone()?));
                }
                let hash = root.hash_profile();
                let major = query.major(hash, names)?;
                let depth = root.indirect_levels();
                let mut path = HtreePath::new(root.into_index(), depth, major, ())?;
                self.complete_htree_descent(inode, &mut tree, &mut path)?;
                loop {
                    let leaf = self.read_directory_logical_block(inode, &mut tree, path.leaf()?)?;
                    let entries = leaf.entries()?;
                    path.hash_range()?.validate_leaf(&entries, hash, names)?;
                    if let Some(entry) = query.find(entries, crypto, names)? {
                        return Ok(Some(entry));
                    }
                    if !path.advance_route()? {
                        return Ok(None);
                    }
                    self.complete_htree_descent(inode, &mut tree, &mut path)?;
                    if path.boundary()? & !1 != major {
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// Reads only the requested fs-verity data blocks and authenticates each Merkle proof to the
    /// descriptor root before publishing bytes to `out`.
    /// # Errors
    ///
    /// Returns an error when metadata layout, encrypted plaintext recovery, proof traversal, or a
    /// data/Merkle digest is invalid.
    pub(super) fn read_verified_file(
        &mut self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<ReadBytes> {
        if out.is_empty() || offset.bytes() >= file.size().bytes() {
            return Ok(ReadBytes::from_usize(0));
        }
        let block_size = self.superblock.block_size();
        let extent_context = self.extent_tree_context(file.inode());
        let mut extent_tree =
            ExtentMappingCursor::new(file.inode().extent_root()?, block_size, extent_context)?;
        let contents_key = if file.protection().is_encrypted() {
            Some(
                self.fscrypt_key_for_inode(file.inode())?
                    .contents_key(crypto)?,
            )
        } else {
            None
        };
        let (metadata, descriptor) =
            self.read_verity_descriptor(file, &mut extent_tree, contents_key.as_ref(), crypto)?;
        if descriptor.block_size().bytes() > block_size.bytes() {
            return Err(Error::InvalidVerityMetadata);
        }
        let verifier = FsverityVerifier::new(descriptor)?;
        if verifier.tree_bytes() != metadata.merkle_tree_bytes() {
            return Err(Error::InvalidVerityMetadata);
        }
        let mut plan = VerityReadPlan {
            extent_tree,
            contents_key,
            metadata,
            verifier,
        };
        let readable = core::cmp::min(
            u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?,
            file.size().remaining_from(offset)?,
        );
        let request_end = offset
            .bytes()
            .checked_add(readable)
            .ok_or(Error::ArithmeticOverflow)?;
        let block_bytes = plan.verifier.block_size().to_usize()?;
        let block_bytes_u64 = u64::try_from(block_bytes).map_err(|_| Error::ArithmeticOverflow)?;
        let first_block = offset
            .bytes()
            .checked_div(block_bytes_u64)
            .ok_or(Error::InvalidVerityMetadata)?;
        let final_byte = request_end
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let final_block = final_byte
            .checked_div(block_bytes_u64)
            .ok_or(Error::InvalidVerityMetadata)?;
        let mut data_block = memory::repeated_vec(0_u8, block_bytes)?;
        let mut proof_block = memory::repeated_vec(0_u8, block_bytes)?;

        for data_block_index in first_block..=final_block {
            data_block.fill(0);
            let block_start = data_block_index
                .checked_mul(block_bytes_u64)
                .ok_or(Error::ArithmeticOverflow)?;
            let data_bytes = core::cmp::min(
                block_bytes_u64,
                plan.verifier
                    .data_size()
                    .checked_sub(block_start)
                    .ok_or(Error::InvalidVerityMetadata)?,
            );
            let data_bytes = usize::try_from(data_bytes).map_err(|_| Error::ArithmeticOverflow)?;
            self.read_prepared_plaintext_stream_range(
                plan.contents_key.as_ref(),
                &mut plan.extent_tree,
                block_start,
                data_block.get_mut(..data_bytes).ok_or(Error::DeviceRange)?,
                crypto,
            )?;
            self.verify_verity_data_block(
                &mut plan,
                data_block_index,
                &data_block,
                &mut proof_block,
                crypto,
            )?;

            let copy_start = core::cmp::max(offset.bytes(), block_start);
            let block_end = block_start
                .checked_add(block_bytes_u64)
                .ok_or(Error::ArithmeticOverflow)?;
            let copy_end = core::cmp::min(request_end, block_end);
            let source_start = usize::try_from(
                copy_start
                    .checked_sub(block_start)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let destination_start = usize::try_from(
                copy_start
                    .checked_sub(offset.bytes())
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let copy_bytes = usize::try_from(
                copy_end
                    .checked_sub(copy_start)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let source_end = source_start
                .checked_add(copy_bytes)
                .ok_or(Error::ArithmeticOverflow)?;
            let destination_end = destination_start
                .checked_add(copy_bytes)
                .ok_or(Error::ArithmeticOverflow)?;
            memory::copy_exact(
                out.get_mut(destination_start..destination_end)
                    .ok_or(Error::DeviceRange)?,
                data_block
                    .get(source_start..source_end)
                    .ok_or(Error::DeviceRange)?,
            )?;
        }
        Ok(ReadBytes::from_usize(
            usize::try_from(readable).map_err(|_| Error::ArithmeticOverflow)?,
        ))
    }

    /// Reads and validates the fixed fs-verity descriptor without loading the stored Merkle tree.
    /// # Errors
    ///
    /// Returns an error when the post-EOF tail, descriptor slot, or descriptor-derived layout is
    /// malformed.
    fn read_verity_descriptor(
        &mut self,
        file: &FileNode,
        extent_tree: &mut ExtentMappingCursor,
        contents_key: Option<&FscryptContentsKey>,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<(Ext4VerityMetadataLayout, FsverityDescriptor)> {
        let block_size = self.superblock.block_size();
        let metadata_end = extent_tree
            .allocation_end(&mut self.device)?
            .checked_mul(u64::from(block_size.bytes()))
            .ok_or(Error::ArithmeticOverflow)?;
        if metadata_end <= file.size().bytes() {
            return Err(Error::InvalidVerityMetadata);
        }
        let tail_offset = metadata_end
            .checked_sub(4)
            .ok_or(Error::InvalidVerityMetadata)?;
        let mut descriptor_size_tail = [0_u8; 4];
        self.read_prepared_plaintext_stream_range(
            contents_key,
            extent_tree,
            tail_offset,
            &mut descriptor_size_tail,
            crypto,
        )?;
        let descriptor_bytes = u32::from_le_bytes(descriptor_size_tail);
        let descriptor_offset = Ext4VerityMetadataLayout::descriptor_offset_from_metadata_end(
            block_size,
            metadata_end,
            descriptor_bytes,
        )?;
        let mut descriptor_image = memory::repeated_vec(
            0_u8,
            usize::try_from(descriptor_bytes).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        self.read_prepared_plaintext_stream_range(
            contents_key,
            extent_tree,
            descriptor_offset,
            &mut descriptor_image,
            crypto,
        )?;
        let descriptor = FsverityDescriptor::parse(&descriptor_image)?;
        let layout = Ext4VerityMetadataLayout::from_metadata_end(
            file.size(),
            block_size,
            metadata_end,
            descriptor_bytes,
            &descriptor,
        )?;
        Ok((layout, descriptor))
    }

    /// Authenticates one zero-padded data block through every stored Merkle level.
    /// # Errors
    ///
    /// Returns `VerityMismatch` for any data, proof-slot, proof-block, or root mismatch.
    fn verify_verity_data_block(
        &mut self,
        plan: &mut VerityReadPlan,
        data_block_index: u64,
        data_block: &[u8],
        proof_block: &mut [u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<()> {
        let mut verification =
            plan.verifier
                .begin_data_block(data_block_index, data_block, crypto)?;
        while let Some(location) = verification.next_merkle_block()? {
            let stream_offset = plan
                .metadata
                .merkle_tree_offset()
                .checked_add(location.tree_byte_offset())
                .ok_or(Error::ArithmeticOverflow)?;
            self.read_prepared_plaintext_stream_range(
                plan.contents_key.as_ref(),
                &mut plan.extent_tree,
                stream_offset,
                proof_block,
                crypto,
            )?;
            verification.verify_merkle_block(proof_block, crypto)?;
        }
        verification.finish()
    }

    /// Reads plaintext through a bounded extent path and optional pre-derived fscrypt contents key.
    /// # Errors
    ///
    /// Returns an error when extent traversal, device I/O, or block decryption fails.
    fn read_prepared_plaintext_stream_range(
        &mut self,
        contents_key: Option<&FscryptContentsKey>,
        extent_tree: &mut ExtentMappingCursor,
        offset: u64,
        out: &mut [u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<()> {
        match contents_key {
            Some(key) => {
                self.read_encrypted_inode_stream_range(key, extent_tree, offset, out, crypto)
            }
            None => self.read_inode_stream_range(extent_tree, offset, out),
        }
    }

    /// Enumerates the authoritative directory names of one hard-linkable inode.
    ///
    /// Traversal is iterative so the future cannot retain an unbounded async recursion chain. The
    /// completed scan is checked against the inode link count before it becomes a [`HardLinks`].
    ///
    /// # Errors
    /// Returns an error when the target is stale, a directory cannot be read, the directory graph
    /// contains a non-special cycle, allocation fails, or fewer reachable links exist than the
    /// inode advertises.
    pub(super) fn read_hard_links(
        &mut self,
        target: HardLinkNodeId,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<HardLinks> {
        let expected = match target {
            HardLinkNodeId::File(file) => {
                usize::from(self.load_file(file)?.links_count().on_disk_count())
            }
            HardLinkNodeId::Symlink(symlink) => {
                usize::from(self.load_symlink(symlink)?.links_count().on_disk_count())
            }
        };
        let target_node = NodeId::from(target);
        let mut pending = Vec::new();
        pending.try_push(DirectoryNodeId::ROOT)?;
        let mut visited = Vec::new();
        let mut links = Vec::new();
        links
            .try_reserve_exact(expected)
            .map_err(|_| Error::OutOfMemory)?;

        while let Some(directory_id) = pending.pop() {
            if visited.contains(&directory_id) {
                return Err(Error::InvalidDirectoryEntry);
            }
            visited.try_push(directory_id)?;
            let mut reader = DirectoryReader::new(directory_id, DirectoryScanCursor::start());
            while let Some(scanned) = self.next_directory_entry(&mut reader, crypto)? {
                let entry = scanned.into_entry();
                if matches!(entry.name().bytes(), b"." | b"..") {
                    continue;
                }
                match *entry.node() {
                    NodeId::Directory(child) => {
                        if visited.contains(&child) || pending.contains(&child) {
                            return Err(Error::InvalidDirectoryEntry);
                        }
                        pending.try_push(child)?;
                    }
                    node if node == target_node => {
                        links.try_push(HardLinkEntry::try_new(directory_id, entry.name())?)?;
                    }
                    NodeId::File(_) | NodeId::Symlink(_) => {}
                }
            }
        }

        HardLinks::try_from_entries(links, expected)
    }

    /// Projects a locked ciphertext identity together with its complete root-selected route.
    /// # Errors
    /// Returns directory validation, allocation or hash-provider failure.
    fn project_locked_directory_name(
        &mut self,
        inode: &Inode,
        entry: &RawDirectoryEntry,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<Ext4Name> {
        let name = entry.name();
        if matches!(name.bytes(), b"." | b"..") {
            return name.try_to_owned_name();
        }
        let hash = if let Some(hash) = entry.stored_hash() {
            hash
        } else if name.bytes().len() > 176
            && inode.directory_storage_kind()? == DirectoryStorageKind::HTree
        {
            let block_size = self.superblock.block_size();
            let mut tree = ExtentMappingCursor::new(
                inode.extent_root()?,
                block_size,
                self.extent_tree_context(inode),
            )?;
            let block = self.read_directory_logical_block(
                inode,
                &mut tree,
                LogicalBlock::try_from(0_u64)?,
            )?;
            HtreeRoot::parse(
                block.bytes(),
                inode.id(),
                self.superblock.directory_hash_seed(),
                self.superblock.directory_hash_signedness(),
                self.superblock.directory_indexing().require_supported()?,
                self.directory_checksum(inode),
                DirectoryEntryEncoding::for_inode(inode),
            )?
            .hash_profile()
            .entry_hash(entry, self.superblock.name_semantics(inode)?)?
        } else if name.bytes().len() > 176 {
            DirectoryHashScheme::from_metadata(
                self.superblock.directory_hash_seed(),
                self.superblock.default_directory_hash_version(),
                self.superblock.directory_hash_signedness(),
            )
            .hash(name.bytes())
        } else {
            DirectoryHash { major: 0, minor: 0 }
        };
        Ext4Name::new(
            &FscryptNoKeyName::from_ciphertext(name.bytes(), hash, crypto)?.display_bytes()?,
        )
    }

    /// Looks up an exact ext4 child name under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated.
    pub(super) fn lookup_child(
        &mut self,
        parent: &DirectoryNode,
        name: &Ext4Name,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<ChildLookup> {
        if parent.protection().is_verity() {
            return Err(Error::UnsupportedVerity);
        }
        let query = self.prepare_directory_lookup(parent.inode(), name, crypto)?;
        let exact_entry = self.find_raw_directory_entry(parent.inode(), query.query(), crypto)?;
        if let Some(raw) = exact_entry {
            let stored = if parent.inode().flags().has_casefold() {
                Some(self.project_directory_name(parent, raw.try_clone()?, crypto)?)
            } else {
                None
            };
            return Ok(ChildLookup::Found(
                self.validate_directory_entry(raw, stored.as_ref().unwrap_or(name))?
                    .into_child(parent.id()),
            ));
        }
        Ok(ChildLookup::NotFound)
    }

    /// Converts one raw directory entry into a public entry using an explicit visible name.
    /// # Errors
    ///
    /// Returns an error when `entry` references an inode that cannot be loaded and classified.
    pub(super) fn validate_directory_entry(
        &mut self,
        entry: RawDirectoryEntry,
        visible_name: &Ext4Name,
    ) -> Result<DirectoryEntry> {
        let node = self.load_inode_node(entry.inode())?.id();
        Ok(DirectoryEntry::new(
            visible_name.try_to_owned_name()?,
            node,
            entry.kind(),
        ))
    }

    /// Reads plaintext file data, decrypting fscrypt contents when needed.
    /// # Errors
    ///
    /// Returns an error when extent traversal fails, encrypted contents cannot be decrypted, or the
    /// requested output range cannot be represented.
    pub(super) fn read_inode_plaintext_data(
        &mut self,
        inode: &Inode,
        offset: FileOffset,
        out: &mut [u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<ReadBytes> {
        if !inode.protection().is_encrypted() {
            return self.read_inode_data(inode, offset, out);
        }
        if out.is_empty() || offset.bytes() >= inode.size().bytes() {
            return Ok(ReadBytes::from_usize(0));
        }

        let readable = core::cmp::min(
            u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?,
            inode.size().remaining_from(offset)?,
        );
        let context = self.extent_tree_context(inode);
        let mut extent_tree =
            ExtentMappingCursor::new(inode.extent_root()?, self.superblock.block_size(), context)?;
        let readable_len = usize::try_from(readable).map_err(|_| Error::ArithmeticOverflow)?;
        self.read_inode_plaintext_stream_range(
            inode,
            &mut extent_tree,
            offset.bytes(),
            out.get_mut(..readable_len).ok_or(Error::DeviceRange)?,
            crypto,
        )?;
        Ok(ReadBytes::from_usize(readable_len))
    }

    /// Reads file data through the inode extent tree, zero-filling sparse ranges.
    /// # Errors
    ///
    /// Returns an error when the extent tree cannot be loaded, read range arithmetic fails, or a
    /// mapped physical block cannot be read.
    pub(super) fn read_inode_data(
        &mut self,
        inode: &Inode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        if out.is_empty() || offset.bytes() >= inode.size().bytes() {
            return Ok(ReadBytes::from_usize(0));
        }

        let readable = core::cmp::min(
            u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?,
            inode.size().remaining_from(offset)?,
        );
        if let InodeStorage::InlineData(data) = inode.storage() {
            let start = usize::try_from(offset.bytes()).map_err(|_| Error::DeviceRange)?;
            let bytes = data.file()?.get(start..).ok_or(Error::DeviceRange)?;
            let count = core::cmp::min(out.len(), bytes.len());
            memory::copy_exact(
                out.get_mut(..count).ok_or(Error::DeviceRange)?,
                bytes.get(..count).ok_or(Error::DeviceRange)?,
            )?;
            return Ok(ReadBytes::from_usize(count));
        }
        let context = self.extent_tree_context(inode);
        let mut extent_tree =
            ExtentMappingCursor::new(inode.extent_root()?, self.superblock.block_size(), context)?;
        let readable_len = usize::try_from(readable).map_err(|_| Error::ArithmeticOverflow)?;
        self.read_inode_stream_range(
            &mut extent_tree,
            offset.bytes(),
            out.get_mut(..readable_len).ok_or(Error::DeviceRange)?,
        )?;
        Ok(ReadBytes::from_usize(readable_len))
    }

    /// Reads plaintext bytes from an inode extent stream without applying `i_size` limits.
    /// # Errors
    ///
    /// Returns an error when encrypted stream key lookup or the selected stream reader fails.
    pub(super) fn read_inode_plaintext_stream_range(
        &mut self,
        inode: &Inode,
        extent_tree: &mut ExtentMappingCursor,
        offset: u64,
        out: &mut [u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<()> {
        if inode.protection().is_encrypted() {
            let contents_key = self.fscrypt_key_for_inode(inode)?.contents_key(crypto)?;
            self.read_encrypted_inode_stream_range(&contents_key, extent_tree, offset, out, crypto)
        } else {
            self.read_inode_stream_range(extent_tree, offset, out)
        }
    }

    /// Reads and decrypts bytes from an fscrypt inode stream.
    /// # Errors
    ///
    /// Returns an error when stream range arithmetic fails, a mapped block cannot be read, or block
    /// decryption fails.
    pub(super) fn read_encrypted_inode_stream_range(
        &mut self,
        contents_key: &FscryptContentsKey,
        extent_tree: &mut ExtentMappingCursor,
        offset: u64,
        out: &mut [u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        let block_size = u64::from(self.superblock.block_size().bytes());
        let block_bytes = usize::try_from(self.superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let mut block = memory::repeated_vec(0_u8, block_bytes)?;
        let mut completed = 0_usize;

        while completed < out.len() {
            let position = offset
                .checked_add(u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let logical_block = position
                .checked_div(block_size)
                .ok_or(Error::InvalidSuperblock)?;
            let in_block = position
                .checked_rem(block_size)
                .ok_or(Error::InvalidSuperblock)?;
            let block_remaining = block_size
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            let total_remaining = u64::try_from(
                out.len()
                    .checked_sub(completed)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let chunk = usize::try_from(core::cmp::min(block_remaining, total_remaining))
                .map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            match extent_tree.map(LogicalBlock::try_from(logical_block)?, &mut self.device)? {
                BlockMapping::Physical(physical_block) => {
                    let target = out.get_mut(completed..end).ok_or(Error::DeviceRange)?;
                    if in_block == 0 && chunk == block_bytes {
                        self.device.read_exact_at(
                            self.superblock.block_size().offset_of(physical_block)?,
                            target,
                        )?;
                        contents_key.decrypt_block(logical_block, target, crypto)?;
                    } else {
                        self.device.read_exact_at(
                            self.superblock.block_size().offset_of(physical_block)?,
                            &mut block,
                        )?;
                        contents_key.decrypt_block(logical_block, &mut block, crypto)?;
                        let start =
                            usize::try_from(in_block).map_err(|_| Error::ArithmeticOverflow)?;
                        let block_end =
                            start.checked_add(chunk).ok_or(Error::ArithmeticOverflow)?;
                        memory::copy_exact(
                            target,
                            block.get(start..block_end).ok_or(Error::DeviceRange)?,
                        )?;
                    }
                }
                BlockMapping::Uninitialized | BlockMapping::Hole => {
                    out.get_mut(completed..end)
                        .ok_or(Error::DeviceRange)?
                        .fill(0);
                }
            }
            completed = end;
        }

        Ok(())
    }

    /// Reads bytes from an inode extent stream without applying `i_size` limits.
    /// # Errors
    ///
    /// Returns an error when stream range arithmetic fails or a mapped physical block cannot be
    /// read.
    pub(super) fn read_inode_stream_range(
        &mut self,
        extent_tree: &mut ExtentMappingCursor,
        offset: u64,
        out: &mut [u8],
    ) -> Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        let block_size = u64::from(self.superblock.block_size().bytes());
        let mut completed = 0_usize;

        while completed < out.len() {
            let position = offset
                .checked_add(u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let logical_block = position
                .checked_div(block_size)
                .ok_or(Error::InvalidSuperblock)?;
            let in_block = position
                .checked_rem(block_size)
                .ok_or(Error::InvalidSuperblock)?;
            let total_remaining = u64::try_from(
                out.len()
                    .checked_sub(completed)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let window = core::cmp::min(
                total_remaining,
                u64::try_from(MAX_READ_WINDOW_BYTES).map_err(|_| Error::ArithmeticOverflow)?,
            );
            let spanned = in_block
                .checked_add(window)
                .ok_or(Error::ArithmeticOverflow)?;
            let maximum_blocks = round_up_div(spanned, block_size)?;
            let maximum_blocks =
                NonZeroU64::new(maximum_blocks).ok_or(Error::ArithmeticOverflow)?;
            let run = extent_tree.map_run(
                LogicalBlock::try_from(logical_block)?,
                maximum_blocks,
                &mut self.device,
            )?;
            let run_bytes = run
                .blocks()
                .get()
                .checked_mul(block_size)
                .ok_or(Error::ArithmeticOverflow)?
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            let chunk_u64 = core::cmp::min(window, run_bytes);
            let chunk = usize::try_from(chunk_u64).map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            match run {
                ExtentBlockRun::Initialized { physical_start, .. } => {
                    let device_offset = self
                        .superblock
                        .block_size()
                        .offset_of(physical_start)?
                        .get()
                        .checked_add(in_block)
                        .ok_or(Error::ArithmeticOverflow)?;
                    self.device.read_exact_at(
                        ByteOffset::new(device_offset),
                        out.get_mut(completed..end).ok_or(Error::DeviceRange)?,
                    )?;
                }
                ExtentBlockRun::Uninitialized { .. } | ExtentBlockRun::Hole { .. } => {
                    out.get_mut(completed..end)
                        .ok_or(Error::DeviceRange)?
                        .fill(0);
                }
            }
            completed = end;
        }

        Ok(())
    }

    /// Reads an inode record together with its on-device offset.
    /// # Errors
    ///
    /// Returns an error when `inode_id` is outside the filesystem inode range, its table offset
    /// cannot be computed, or the record cannot be read or authenticated.
    pub(super) fn read_raw_inode_record(
        &mut self,
        inode_id: InodeId,
    ) -> Result<RawInodeRecord<Vec<u8>>> {
        self.observe_inode(inode_id)?;
        if inode_id.as_u32() > self.superblock.inode_count().as_u32() {
            return Err(Error::InvalidInode);
        }

        let inode_offset = inode_offset_on_device(&mut self.device, &self.superblock, inode_id)?;

        let mut bytes =
            memory::repeated_vec(0_u8, usize::from(self.superblock.inode_size().as_u16()))?;
        self.device
            .read_metadata_exact_at(inode_offset, &mut bytes)?;
        let record = RawInodeRecord {
            id: inode_id,
            offset: inode_offset,
            bytes,
            encoding: self.superblock.inode_data_encoding(),
        };
        record.verify_checksum(&self.superblock)?;
        Ok(record)
    }

    /// Reads and parses a typed inode record.
    /// # Errors
    ///
    /// Returns an error when the live inode record cannot be read or parsed as a supported inode.
    pub(super) fn read_inode_record(&mut self, inode_id: InodeId) -> Result<Inode> {
        self.read_live_inode_record(inode_id)?.parse()
    }

    /// Reads a live inode record for mutation or metadata interpretation.
    /// # Errors
    ///
    /// Returns an error when the raw inode record cannot be read or does not satisfy live-inode
    /// invariants.
    pub(super) fn read_live_inode_record(&mut self, inode_id: InodeId) -> Result<LiveInodeRecord> {
        self.read_raw_inode_record(inode_id)?.into_live()
    }

    /// Reads an opaque attribute through its separate inode/storage validation boundary.
    /// # Errors
    /// Propagates malformed value metadata, extent I/O, allocation and checksum failures.
    pub(super) fn read_attribute_value(
        &mut self,
        reference: xattr_storage::AttributeValueReference,
    ) -> Result<XattrValue> {
        let raw = self
            .read_raw_inode_record(reference.inode)?
            .into_attribute()?;
        let header = raw.parse()?;
        let data = header.data();
        if data.size().to_usize()? != reference.size {
            return Err(Error::InvalidXattr);
        }
        let InodeStorage::Extents(root) = data.storage() else {
            return Err(Error::InvalidXattr);
        };
        let mut mapping = ExtentMappingCursor::new(
            root,
            self.superblock.block_size(),
            crate::volume::orphan::extent_context(self.superblock, data),
        )?;
        let mut bytes = memory::repeated_vec(0, reference.size)?;
        self.read_inode_stream_range(&mut mapping, 0, &mut bytes)?;
        reference.admit_value(&header, &bytes, self.superblock.checksum_seed().as_u32())
    }
    /// Reads all xattr storage locations referenced by a live inode.
    /// # Errors
    ///
    /// Returns an error when inline xattrs, the external xattr pointer, external block I/O, or
    /// merged xattr namespaces are malformed.
    pub(super) fn read_inode_xattrs_from_live(
        &mut self,
        raw_inode: &LiveInodeRecord,
    ) -> Result<InodeXattrSet> {
        match self.superblock.xattr_mutation() {
            XattrMutationSupport::Disabled => return Ok(InodeXattrSet::empty()),
            XattrMutationSupport::Enabled => {}
        }
        let inline = xattr_storage::parse_inline_xattrs(raw_inode.inline_xattr_region()?)?
            .resolve(|reference| self.read_attribute_value(reference))?;
        let Some(block) = raw_inode.xattr_block()? else {
            return Ok(inline);
        };
        let mut bytes = memory::repeated_vec(
            0_u8,
            usize::try_from(self.superblock.block_size().bytes())
                .map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        self.device
            .read_metadata_exact_at(self.superblock.block_size().offset_of(block)?, &mut bytes)?;
        let external = xattr_storage::parse_external_xattr_block(&bytes, block, &self.superblock)?
            .resolve(|reference| self.read_attribute_value(reference))?;
        xattr_storage::merge_xattr_sets(inline, external)
    }

    /// Builds the checksum context required for this inode's extent tree.
    pub(super) fn extent_tree_context(&self, inode: &Inode) -> ExtentTreeContext {
        if self.superblock.metadata_checksum() == MetadataChecksum::Crc32c {
            ExtentTreeContext::metadata_csum(
                self.superblock.checksum_seed().as_u32(),
                inode.id(),
                inode.generation().as_u32(),
            )
        } else {
            ExtentTreeContext::none()
        }
    }

    /// Builds the checksum context required for directory metadata.
    pub(super) fn directory_checksum(&self, inode: &Inode) -> DirectoryChecksum {
        if self.superblock.metadata_checksum() == MetadataChecksum::Crc32c {
            DirectoryChecksum::metadata_csum(
                self.superblock.checksum_seed(),
                inode.id(),
                inode.generation().as_u32(),
            )
        } else {
            DirectoryChecksum::None
        }
    }
}
