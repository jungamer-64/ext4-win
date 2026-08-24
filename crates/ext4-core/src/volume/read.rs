//! Read-only traversal and metadata projection for mounted volumes.

use core::num::NonZeroU64;

use super::scope::*;

/// Maximum bytes passed to one backing-device data read.
const MAX_READ_WINDOW_BYTES: usize = 65_536;

/// Fully validated protection and mapping state for one fs-verity range read.
struct VerityReadPlan {
    /// File payload and post-EOF metadata mapping.
    extent_tree: ExtentTree,
    /// Per-inode plaintext recovery key when fscrypt also protects this inode.
    contents_key: Option<FscryptContentsKey>,
    /// ext4 post-EOF placement of the serialized Merkle tree.
    metadata: Ext4VerityMetadataLayout,
    /// Descriptor-owned Merkle geometry and proof state factory.
    verifier: FsverityVerifier,
}

impl EpochReadView<'_, '_> {
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
        self.read_inode_xattrs_from_live(&inode)?
            .public()
            .try_clone()
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

    /// Reads Windows overlay metadata isolated in `user.ext4win.*` xattrs.
    ///
    /// # Errors
    /// Returns an error when the overlay xattr payload is malformed.
    pub(super) fn read_inode_windows_overlay(
        &mut self,
        inode_id: InodeId,
    ) -> Result<Option<WindowsOverlay>> {
        let Some(value) =
            self.read_inode_xattr(inode_id, &WindowsOverlay::attributes_xattr_name()?)?
        else {
            return Ok(None);
        };
        Ok(Some(WindowsOverlay::parse(&value)?))
    }

    /// Reads Windows symbolic-link reparse metadata from its private xattr.
    ///
    /// # Errors
    /// Returns an error when the backing xattr or its payload is malformed.
    pub(super) fn read_inode_windows_symlink_reparse_point(
        &mut self,
        inode_id: InodeId,
    ) -> Result<Option<WindowsSymlinkReparsePoint>> {
        let Some(value) =
            self.read_inode_xattr(inode_id, &WindowsSymlinkReparsePoint::xattr_name()?)?
        else {
            return Ok(None);
        };
        Ok(Some(WindowsSymlinkReparsePoint::parse(&value)?))
    }

    /// Reads the fscrypt v2 context stored in ext4's private inode xattr slot.
    ///
    /// # Errors
    /// Returns an error when the inode's xattr storage is malformed or the
    /// stored fscrypt context is not in the supported v2 AES profile.
    pub(super) fn read_inode_fscrypt_context(
        &mut self,
        inode_id: InodeId,
    ) -> Result<Option<FscryptContextV2>> {
        let inode = self.read_live_inode_record(inode_id)?;
        let xattrs = self.read_inode_xattrs_from_live(&inode)?;
        let Some(value) = xattrs.encryption_context() else {
            return Ok(None);
        };
        Ok(Some(FscryptContextV2::parse(value.bytes())?))
    }

    /// Verifies that an encrypted inode has an available fscrypt master key.
    /// # Errors
    ///
    /// Returns an error when the inode is encrypted but its fscrypt context is malformed or no
    /// matching mounted master key exists.
    pub(super) fn require_encryption_key(&mut self, inode: &Inode) -> Result<()> {
        if !inode.protection().is_encrypted() {
            return Ok(());
        }
        let _key = self.fscrypt_master_key_for_inode(inode)?;
        Ok(())
    }

    /// Returns the mount key matching an encrypted inode's fscrypt context.
    /// # Errors
    ///
    /// Returns an error when the inode has no valid fscrypt context or the matching master key is
    /// absent from the mount context.
    pub(super) fn fscrypt_master_key_for_inode(
        &mut self,
        inode: &Inode,
    ) -> Result<(FscryptContextV2, &FscryptMasterKey)> {
        let Some(context) = self.read_inode_fscrypt_context(inode.id())? else {
            return Err(Error::InvalidEncryptionContext);
        };
        let Some(key) = self
            .fscrypt_keys
            .get(context.policy().master_key_identifier())
        else {
            return Err(Error::MissingEncryptionKey);
        };
        Ok((context, key))
    }

    /// Derives the per-file AES-XTS contents key for an encrypted inode.
    /// # Errors
    ///
    /// Returns an error when the inode's master key cannot be resolved or contents-key derivation
    /// rejects the policy parameters.
    pub(super) fn fscrypt_contents_key_for_inode(
        &mut self,
        inode: &Inode,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<FscryptContentsKey> {
        let (context, master_key) = self.fscrypt_master_key_for_inode(inode)?;
        master_key.derive_contents_key(context.nonce(), crypto)
    }

    /// Derives the per-directory filename key and padding policy.
    /// # Errors
    ///
    /// Returns an error when the inode's master key cannot be resolved or filename-key derivation
    /// rejects the policy parameters.
    pub(super) fn fscrypt_filenames_key_for_inode(
        &mut self,
        inode: &Inode,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<(FscryptFilenamesKey, FscryptFilenamePadding)> {
        let (context, master_key) = self.fscrypt_master_key_for_inode(inode)?;
        Ok((
            master_key.derive_filenames_key(context.nonce(), crypto)?,
            context.policy().filename_padding(),
        ))
    }

    /// Converts a plaintext child name to the on-disk name for a directory.
    /// # Errors
    ///
    /// Returns an error when an encrypted parent lacks a filename key or the encrypted name is not a
    /// valid ext4 component.
    pub(super) fn encrypt_directory_child_name(
        &mut self,
        parent: &Inode,
        name: &Ext4Name,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<Ext4Name> {
        if !parent.protection().is_encrypted() || matches!(name.bytes(), b"." | b"..") {
            return Ext4Name::new(name.bytes());
        }
        let (key, padding) = self.fscrypt_filenames_key_for_inode(parent, crypto)?;
        Ext4Name::from_disk(&key.encrypt_filename(name.bytes(), padding, crypto)?)
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
        let (key, _padding) = self.fscrypt_filenames_key_for_inode(parent, crypto)?;
        Ext4Name::new(&key.decrypt_filename(name.bytes(), crypto)?)
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
            self.require_encryption_key(inode)?;
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
    /// Returns an error when the inode number is outside the volume or the inode
    /// table cannot be read and parsed.
    pub(super) fn load_inode_node(&mut self, inode_id: InodeId) -> Result<LoadedNode> {
        Ok(LoadedNode::from_inode(self.read_inode_record(inode_id)?))
    }

    /// Loads and classifies one Windows-facing file index as a typed node identity.
    ///
    /// # Errors
    /// Returns an error when the file index cannot represent a live ext4 inode.
    pub(super) fn load_node_by_file_index(&mut self, file_index: u32) -> Result<NodeId> {
        let inode_id = InodeId::try_from(file_index)?;
        Ok(self.load_inode_node(inode_id)?.id())
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
        if let Ok(inline) = symlink.inode().inline_bytes() {
            return memory::copied_slice(inline.prefix(symlink.size())?);
        }
        let mut target = memory::repeated_vec(0_u8, len)?;
        let _bytes_read = self.read_inode_data(symlink.inode(), FileOffset::ZERO, &mut target)?;
        Ok(target)
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
        let extent_tree = ExtentTree::load_inode_tree(
            file.inode().extent_root()?,
            block_size,
            &mut self.device,
            extent_context,
        )?;
        let contents_key = if file.protection().is_encrypted() {
            Some(self.fscrypt_contents_key_for_inode(file.inode(), crypto)?)
        } else {
            None
        };
        let (metadata, descriptor) =
            self.read_verity_descriptor(file, &extent_tree, contents_key.as_ref(), crypto)?;
        if descriptor.block_size().bytes() > block_size.bytes() {
            return Err(Error::InvalidVerityMetadata);
        }
        let verifier = FsverityVerifier::new(descriptor)?;
        if verifier.tree_bytes() != metadata.merkle_tree_bytes() {
            return Err(Error::InvalidVerityMetadata);
        }
        let plan = VerityReadPlan {
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
                &plan.extent_tree,
                block_start,
                data_block.get_mut(..data_bytes).ok_or(Error::DeviceRange)?,
                crypto,
            )?;
            self.verify_verity_data_block(
                &plan,
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
        extent_tree: &ExtentTree,
        contents_key: Option<&FscryptContentsKey>,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<(Ext4VerityMetadataLayout, FsverityDescriptor)> {
        let block_size = self.superblock.block_size();
        let metadata_end = extent_payload_end_bytes(extent_tree, block_size)?;
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
        let mut descriptor_image = memory::repeated_vec(0_u8, FSVERITY_DESCRIPTOR_BYTES)?;
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
        plan: &VerityReadPlan,
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
                &plan.extent_tree,
                stream_offset,
                proof_block,
                crypto,
            )?;
            verification.verify_merkle_block(proof_block, crypto)?;
        }
        verification.finish()
    }

    /// Reads plaintext from a preloaded extent tree and optional pre-derived fscrypt contents key.
    /// # Errors
    ///
    /// Returns an error when extent traversal, device I/O, or block decryption fails.
    fn read_prepared_plaintext_stream_range(
        &mut self,
        contents_key: Option<&FscryptContentsKey>,
        extent_tree: &ExtentTree,
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
            HardLinkNodeId::File(file) => usize::from(self.load_file(file)?.links_count().get()),
            HardLinkNodeId::Symlink(symlink) => {
                usize::from(self.load_symlink(symlink)?.links_count().get())
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
            let directory = self.load_directory(directory_id)?;
            let entries = self.read_directory(&directory, crypto)?;
            for entry in entries {
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

    /// Projects one encrypted on-disk dirent name into a no-key display name.
    /// # Errors
    ///
    /// Returns an error when the ciphertext name cannot be represented as an ext4 no-key display
    /// name.
    pub(super) fn project_locked_directory_name(name: &Ext4Name) -> Result<Ext4Name> {
        if matches!(name.bytes(), b"." | b"..") {
            return Ext4Name::new(name.bytes());
        }
        let display = FscryptNoKeyName::from_ciphertext(name.bytes())?.display_bytes()?;
        Ext4Name::new(&display)
    }

    /// Decodes a no-key display name back into its encrypted on-disk name.
    /// # Errors
    ///
    /// Returns an error when `name` looks like a no-key display name but decodes to an invalid ext4
    /// ciphertext component.
    pub(super) fn locked_directory_ciphertext_name(name: &Ext4Name) -> Result<Option<Ext4Name>> {
        let Some(no_key_name) = FscryptNoKeyName::from_display(name.bytes())? else {
            return Ok(None);
        };
        Ok(Some(Ext4Name::from_disk(no_key_name.ciphertext_bytes())?))
    }

    /// Looks up an exact ext4 child name under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated.
    pub(super) fn lookup_child(
        &mut self,
        parent: &DirectoryNode,
        name: &Ext4Name,
    ) -> Result<ChildLookup> {
        if let Some(entry) = self.read_directory_layout(parent.inode())?.find(name)? {
            return Ok(ChildLookup::Found(self.directory_child(parent, entry)?));
        }
        Ok(ChildLookup::NotFound)
    }

    /// Looks up a Windows-visible child name, accepting case-insensitive matches only when unique.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated or the
    /// case-insensitive Windows projection is ambiguous.
    pub(super) fn lookup_windows_child(
        &mut self,
        parent: &DirectoryNode,
        requested: &WindowsName,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<ChildLookup> {
        match self.lookup_windows_child_entry(parent, requested, crypto)? {
            Some(entry) => Ok(ChildLookup::Found(entry.into_child(parent.id()))),
            None => Ok(ChildLookup::NotFound),
        }
    }

    /// Looks up a Windows-visible child name and returns the matched directory entry.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated or the
    /// case-insensitive Windows projection is ambiguous.
    pub(super) fn lookup_windows_child_entry(
        &mut self,
        parent: &DirectoryNode,
        requested: &WindowsName,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<Option<DirectoryEntry>> {
        if parent.protection().is_encrypted() {
            let visible_name = requested.to_ext4()?;
            let ciphertext =
                match self.encrypt_directory_child_name(parent.inode(), &visible_name, crypto) {
                    Ok(ciphertext) => ciphertext,
                    Err(Error::MissingEncryptionKey) => {
                        let Some(ciphertext) =
                            Self::locked_directory_ciphertext_name(&visible_name)?
                        else {
                            return Err(Error::MissingEncryptionKey);
                        };
                        ciphertext
                    }
                    Err(error) => return Err(error),
                };
            let entry = self
                .read_directory_layout(parent.inode())?
                .find(&ciphertext)?;
            return match entry {
                Some(entry) => Ok(Some(self.validate_directory_entry(entry, &visible_name)?)),
                None => Ok(None),
            };
        }
        if parent.protection().is_verity() {
            return Err(Error::UnsupportedVerity);
        }
        let mut folded = None;

        for entry in self.read_directory(parent, crypto)? {
            let Ok(name) = WindowsName::from_ext4(entry.name()) else {
                continue;
            };
            if name.equals(requested) {
                return Ok(Some(entry));
            }
            if name.equals_ascii_case_insensitive(requested) {
                if folded.is_some() {
                    return Err(Error::AmbiguousWindowsName);
                }
                folded = Some(entry);
            }
        }

        Ok(folded)
    }

    /// Converts a directory entry into a child whose inode kind is validated.
    /// # Errors
    ///
    /// Returns an error when the entry inode cannot be loaded and classified.
    pub(super) fn directory_child(
        &mut self,
        parent: &DirectoryNode,
        entry: RawDirectoryEntry,
    ) -> Result<DirectoryChild> {
        let (inode, name, _kind) = entry.into_parts();
        let node = self.load_inode_node(inode)?.id();
        Ok(DirectoryChild::new(parent.id(), name, node))
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
        let extent_tree = ExtentTree::load_inode_tree(
            inode.extent_root()?,
            self.superblock.block_size(),
            &mut self.device,
            context,
        )?;
        let readable_len = usize::try_from(readable).map_err(|_| Error::ArithmeticOverflow)?;
        self.read_inode_plaintext_stream_range(
            inode,
            &extent_tree,
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
        let context = self.extent_tree_context(inode);
        let extent_tree = ExtentTree::load_inode_tree(
            inode.extent_root()?,
            self.superblock.block_size(),
            &mut self.device,
            context,
        )?;
        let readable_len = usize::try_from(readable).map_err(|_| Error::ArithmeticOverflow)?;
        self.read_inode_stream_range(
            &extent_tree,
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
        extent_tree: &ExtentTree,
        offset: u64,
        out: &mut [u8],
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<()> {
        if inode.protection().is_encrypted() {
            let contents_key = self.fscrypt_contents_key_for_inode(inode, crypto)?;
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
        extent_tree: &ExtentTree,
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

            match extent_tree.map_logical(LogicalBlock::try_from(logical_block)?) {
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
        extent_tree: &ExtentTree,
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
            let run =
                extent_tree.map_run(LogicalBlock::try_from(logical_block)?, maximum_blocks)?;
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
    /// cannot be computed, or the record cannot be read.
    pub(super) fn read_raw_inode_record(&mut self, inode_id: InodeId) -> Result<RawInodeRecord> {
        if inode_id.as_u32() > self.superblock.inode_count().as_u32() {
            return Err(Error::InvalidInode);
        }

        let inode_offset = inode_offset_on_device(&mut self.device, &self.superblock, inode_id)?;

        let mut bytes =
            memory::repeated_vec(0_u8, usize::from(self.superblock.inode_size().as_u16()))?;
        self.device.read_exact_at(inode_offset, &mut bytes)?;
        Ok(RawInodeRecord {
            id: inode_id,
            offset: inode_offset,
            bytes,
            encoding: self.superblock.inode_data_encoding(),
        })
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
        let inline = xattr_storage::parse_inline_xattrs(raw_inode.inline_xattr_region()?)?;
        let Some(block) = raw_inode.xattr_block()? else {
            return Ok(inline);
        };
        let mut bytes = memory::repeated_vec(
            0_u8,
            usize::try_from(self.superblock.block_size().bytes())
                .map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        self.device
            .read_exact_at(self.superblock.block_size().offset_of(block)?, &mut bytes)?;
        let external = xattr_storage::parse_external_xattr_block(&bytes, block, &self.superblock)?;
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

/// Returns the exclusive byte end of the logical inode stream described by extents.
/// # Errors
///
/// Returns an error when extent end calculation or final block-to-byte multiplication overflows.
fn extent_payload_end_bytes(extent_tree: &ExtentTree, block_size: BlockSize) -> Result<u64> {
    let mut end_blocks = 0_u64;
    for extent in extent_tree.extents().iter().copied() {
        end_blocks = end_blocks.max(extent.end_logical());
    }
    end_blocks
        .checked_mul(u64::from(block_size.bytes()))
        .ok_or(Error::ArithmeticOverflow)
}
