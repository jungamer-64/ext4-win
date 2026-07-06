//! Read-only traversal and metadata projection for mounted volumes.

use super::scope::*;

#[cfg(test)]
impl<D, N> ReadOnlyVolume<D, N>
where
    D: BlockReader,
{
    /// Stable filesystem identity.
    #[must_use]
    pub(crate) const fn identity(&self) -> VolumeIdentity {
        self.volume.identity()
    }

    /// Mounted filesystem allocation geometry.
    #[must_use]
    pub(crate) const fn geometry(&self) -> VolumeGeometry {
        self.volume.geometry()
    }

    /// Loads a regular file by previously validated file identity.
    ///
    /// # Errors
    /// Returns an error when the inode cannot be read or no longer is a regular file.
    pub(crate) fn load_file(&self, id: FileNodeId) -> Result<FileNode> {
        self.volume.load_file(id)
    }

    /// Loads a directory by previously validated directory identity.
    ///
    /// # Errors
    /// Returns an error when the inode cannot be read or no longer is a directory.
    pub(crate) fn load_directory(&self, id: DirectoryNodeId) -> Result<DirectoryNode> {
        self.volume.load_directory(id)
    }

    /// Loads a symbolic link by previously validated symlink identity.
    ///
    /// # Errors
    /// Returns an error when the inode cannot be read or no longer is a symbolic link.
    pub(crate) fn load_symlink(&self, id: SymlinkNodeId) -> Result<SymlinkNode> {
        self.volume.load_symlink(id)
    }

    /// Reads all extended attributes attached to a typed node.
    ///
    /// # Errors
    /// Returns an error when the inode or its external xattr block is malformed.
    pub(crate) fn read_xattrs(&self, node: NodeId) -> Result<XattrSet> {
        self.volume.read_inode_xattrs(node.inode())
    }

    /// Reads one extended attribute value by name.
    ///
    /// # Errors
    /// Returns an error when the inode or its external xattr block is malformed.
    #[cfg(test)]
    pub(crate) fn read_xattr(&self, node: NodeId, name: &XattrName) -> Result<Option<XattrValue>> {
        self.volume.read_inode_xattr(node.inode(), name)
    }

    /// Reads a POSIX ACL from its ext4 xattr slot.
    ///
    /// # Errors
    /// Returns an error when the backing xattr or ACL payload is malformed.
    #[cfg(test)]
    pub(crate) fn read_posix_acl(
        &self,
        node: NodeId,
        kind: PosixAclKind,
    ) -> Result<Option<PosixAcl>> {
        self.volume.read_inode_posix_acl(node.inode(), kind)
    }

    /// Reads Windows overlay metadata isolated in user.ext4win.* xattrs.
    ///
    /// # Errors
    /// Returns an error when the overlay xattr payload is malformed.
    pub(crate) fn read_windows_overlay(&self, node: NodeId) -> Result<Option<WindowsOverlay>> {
        self.volume.read_inode_windows_overlay(node.inode())
    }

    /// Reads the fscrypt v2 context stored in ext4's private inode xattr slot.
    ///
    /// # Errors
    /// Returns an error when the inode's xattr storage is malformed or the stored fscrypt context
    /// is not in the supported v2 AES profile.
    #[cfg(test)]
    pub(crate) fn read_fscrypt_context(&self, node: NodeId) -> Result<Option<FscryptContextV2>> {
        self.volume.read_inode_fscrypt_context(node.inode())
    }

    /// Reads file bytes from a typed regular file node.
    ///
    /// # Errors
    /// Returns an error when the file extent mapping cannot be traversed.
    pub(crate) fn read_file(
        &self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        self.volume.read_file(file, offset, out)
    }

    /// Reads a typed symlink target as bytes.
    ///
    /// # Errors
    /// Returns an error when the symlink target cannot be read.
    pub(crate) fn read_symlink(&self, symlink: &SymlinkNode) -> Result<Vec<u8>> {
        self.volume.read_symlink(symlink)
    }

    /// Enumerates directory entries as validated node identities.
    ///
    /// # Errors
    /// Returns an error when the directory is too large for eager enumeration, contains malformed
    /// entries, or references an invalid inode.
    pub(crate) fn read_directory(&self, directory: &DirectoryNode) -> Result<Vec<DirectoryEntry>> {
        self.volume.read_directory(directory)
    }

    /// Looks up an exact ext4 child name under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated.
    #[cfg(test)]
    pub(crate) fn lookup_child(
        &self,
        parent: &DirectoryNode,
        name: &Ext4Name,
    ) -> Result<ChildLookup> {
        self.volume.lookup_child(parent, name)
    }

    /// Looks up a Windows-visible child name, accepting case-insensitive matches only when unique.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated or the case-insensitive Windows
    /// projection is ambiguous.
    pub(crate) fn lookup_windows_child(
        &self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> Result<ChildLookup> {
        self.volume.lookup_windows_child(parent, requested)
    }
}
impl<D, N, J> JournaledVolume<D, N, J>
where
    D: BlockReader,
{
    /// Stable filesystem identity.
    #[must_use]
    pub const fn identity(&self) -> VolumeIdentity {
        self.volume.identity()
    }

    /// Mounted filesystem allocation geometry.
    #[must_use]
    pub const fn geometry(&self) -> VolumeGeometry {
        self.volume.geometry()
    }

    /// Adds one fscrypt master key to this mounted volume.
    ///
    /// # Errors
    /// Returns an error when the key identifier is already present.
    pub fn add_fscrypt_key(&mut self, key: FscryptMasterKey) -> Result<()> {
        self.volume.add_fscrypt_key(key)
    }

    /// Removes one fscrypt master key from this mounted volume.
    #[must_use]
    pub fn remove_fscrypt_key(
        &mut self,
        identifier: FscryptKeyIdentifier,
    ) -> Option<FscryptMasterKey> {
        self.volume.remove_fscrypt_key(identifier)
    }

    /// Returns this mounted volume's fscrypt key presence for one identifier.
    #[must_use]
    pub fn fscrypt_key_presence(&self, identifier: FscryptKeyIdentifier) -> FscryptKeyPresence {
        self.volume.fscrypt_key_presence(identifier)
    }

    /// Loads a regular file by previously validated file identity.
    ///
    /// # Errors
    /// Returns an error when the inode cannot be read or no longer is a regular file.
    pub fn load_file(&self, id: FileNodeId) -> Result<FileNode> {
        self.volume.load_file(id)
    }

    /// Loads a directory by previously validated directory identity.
    ///
    /// # Errors
    /// Returns an error when the inode cannot be read or no longer is a directory.
    pub fn load_directory(&self, id: DirectoryNodeId) -> Result<DirectoryNode> {
        self.volume.load_directory(id)
    }

    /// Loads a symbolic link by previously validated symlink identity.
    ///
    /// # Errors
    /// Returns an error when the inode cannot be read or no longer is a symbolic link.
    pub fn load_symlink(&self, id: SymlinkNodeId) -> Result<SymlinkNode> {
        self.volume.load_symlink(id)
    }

    /// Loads and classifies one Windows-facing file index as a typed node identity.
    ///
    /// # Errors
    /// Returns an error when the file index cannot be mapped to a live inode.
    pub fn load_node_by_file_index(&self, file_index: u32) -> Result<NodeId> {
        self.volume.load_node_by_file_index(file_index)
    }

    /// Reads all extended attributes attached to a typed node.
    ///
    /// # Errors
    /// Returns an error when the inode or its external xattr block is malformed.
    pub fn read_xattrs(&self, node: NodeId) -> Result<XattrSet> {
        self.volume.read_inode_xattrs(node.inode())
    }

    /// Reads one extended attribute value by name.
    ///
    /// # Errors
    /// Returns an error when the inode or its external xattr block is malformed.
    #[cfg(test)]
    pub(crate) fn read_xattr(&self, node: NodeId, name: &XattrName) -> Result<Option<XattrValue>> {
        self.volume.read_inode_xattr(node.inode(), name)
    }

    /// Reads Windows overlay metadata isolated in user.ext4win.* xattrs.
    ///
    /// # Errors
    /// Returns an error when the overlay xattr payload is malformed.
    pub fn read_windows_overlay(&self, node: NodeId) -> Result<Option<WindowsOverlay>> {
        self.volume.read_inode_windows_overlay(node.inode())
    }

    /// Reads file bytes from a typed regular file node.
    ///
    /// # Errors
    /// Returns an error when the file extent mapping cannot be traversed.
    pub fn read_file(
        &self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        self.volume.read_file(file, offset, out)
    }

    /// Reads a typed symlink target as bytes.
    ///
    /// # Errors
    /// Returns an error when the symlink target cannot be read.
    pub fn read_symlink(&self, symlink: &SymlinkNode) -> Result<Vec<u8>> {
        self.volume.read_symlink(symlink)
    }

    /// Enumerates directory entries as validated node identities.
    ///
    /// # Errors
    /// Returns an error when the directory is too large for eager enumeration, contains malformed
    /// entries, or references an invalid inode.
    pub fn read_directory(&self, directory: &DirectoryNode) -> Result<Vec<DirectoryEntry>> {
        self.volume.read_directory(directory)
    }

    /// Looks up an exact ext4 child name under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated.
    #[cfg(test)]
    pub(crate) fn lookup_child(
        &self,
        parent: &DirectoryNode,
        name: &Ext4Name,
    ) -> Result<ChildLookup> {
        self.volume.lookup_child(parent, name)
    }

    /// Looks up a Windows-visible child name, accepting case-insensitive matches only when unique.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated or the case-insensitive Windows
    /// projection is ambiguous.
    pub fn lookup_windows_child(
        &self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> Result<ChildLookup> {
        self.volume.lookup_windows_child(parent, requested)
    }
}
impl<D: BlockReader, State, N> MountedVolume<D, State, N> {
    /// Stable filesystem identity.
    #[must_use]
    pub(super) const fn identity(&self) -> VolumeIdentity {
        VolumeIdentity {
            uuid: self.superblock.uuid(),
            label: self.superblock.volume_label(),
        }
    }

    /// Mounted filesystem allocation geometry.
    #[must_use]
    pub(super) const fn geometry(&self) -> VolumeGeometry {
        VolumeGeometry {
            block_size: self.superblock.block_size(),
            cluster_size: self.superblock.cluster_size(),
            cluster_count: self.superblock.cluster_count(),
            free_cluster_count: self.superblock.free_cluster_count(),
        }
    }

    /// Adds one fscrypt master key to this mounted volume.
    ///
    /// # Errors
    /// Returns an error when the key identifier is already present.
    pub(super) fn add_fscrypt_key(&mut self, key: FscryptMasterKey) -> Result<()> {
        self.mount_context.add_fscrypt_key(key)
    }

    /// Removes one fscrypt master key from this mounted volume.
    #[must_use]
    pub(super) fn remove_fscrypt_key(
        &mut self,
        identifier: FscryptKeyIdentifier,
    ) -> Option<FscryptMasterKey> {
        self.mount_context.remove_fscrypt_key(identifier)
    }

    /// Returns this mounted volume's fscrypt key presence for one identifier.
    #[must_use]
    pub(super) fn fscrypt_key_presence(
        &self,
        identifier: FscryptKeyIdentifier,
    ) -> FscryptKeyPresence {
        self.mount_context.fscrypt_key_presence(identifier)
    }

    /// Loads a regular file by previously validated file identity.
    /// # Errors
    ///
    /// Returns an error when the identity's inode cannot be loaded or is no longer a regular file.
    pub(super) fn load_file(&self, id: FileNodeId) -> Result<FileNode> {
        match self.load_validated_node(NodeId::File(id))? {
            LoadedNode::File(file) => Ok(file),
            LoadedNode::Directory(_) | LoadedNode::Symlink(_) => Err(Error::WrongInodeKind),
        }
    }

    /// Loads a directory by previously validated directory identity.
    /// # Errors
    ///
    /// Returns an error when the identity's inode cannot be loaded or is no longer a directory.
    pub(super) fn load_directory(&self, id: DirectoryNodeId) -> Result<DirectoryNode> {
        match self.load_validated_node(NodeId::Directory(id))? {
            LoadedNode::Directory(directory) => Ok(directory),
            LoadedNode::File(_) | LoadedNode::Symlink(_) => Err(Error::WrongInodeKind),
        }
    }

    /// Loads a symbolic link by previously validated symlink identity.
    /// # Errors
    ///
    /// Returns an error when the identity's inode cannot be loaded or is no longer a symbolic link.
    pub(super) fn load_symlink(&self, id: SymlinkNodeId) -> Result<SymlinkNode> {
        match self.load_validated_node(NodeId::Symlink(id))? {
            LoadedNode::Symlink(symlink) => Ok(symlink),
            LoadedNode::File(_) | LoadedNode::Directory(_) => Err(Error::WrongInodeKind),
        }
    }

    /// Reads all extended attributes attached to an inode.
    ///
    /// # Errors
    /// Returns an error when the inode or its external xattr block is malformed.
    pub(super) fn read_inode_xattrs(&self, inode_id: InodeId) -> Result<XattrSet> {
        self.read_inode_xattrs_from_live(&self.read_live_inode_record(inode_id)?)?
            .public()
            .try_clone()
    }

    /// Reads one extended attribute value by name.
    ///
    /// # Errors
    /// Returns an error when the inode or its external xattr block is malformed.
    pub(super) fn read_inode_xattr(
        &self,
        inode_id: InodeId,
        name: &XattrName,
    ) -> Result<Option<XattrValue>> {
        self.read_inode_xattrs(inode_id)?
            .get(name)
            .map(XattrValue::try_clone)
            .transpose()
    }

    /// Reads a POSIX ACL from its ext4 xattr slot.
    ///
    /// # Errors
    /// Returns an error when the backing xattr or ACL payload is malformed.
    #[cfg(test)]
    pub(super) fn read_inode_posix_acl(
        &self,
        inode_id: InodeId,
        kind: PosixAclKind,
    ) -> Result<Option<PosixAcl>> {
        let Some(value) = self.read_inode_xattr(inode_id, &PosixAcl::xattr_name(kind)?)? else {
            return Ok(None);
        };
        Ok(Some(PosixAcl::parse(&value)?))
    }

    /// Reads Windows overlay metadata isolated in `user.ext4win.*` xattrs.
    ///
    /// # Errors
    /// Returns an error when the overlay xattr payload is malformed.
    pub(super) fn read_inode_windows_overlay(
        &self,
        inode_id: InodeId,
    ) -> Result<Option<WindowsOverlay>> {
        let Some(value) =
            self.read_inode_xattr(inode_id, &WindowsOverlay::attributes_xattr_name()?)?
        else {
            return Ok(None);
        };
        Ok(Some(WindowsOverlay::parse(&value)?))
    }

    /// Reads the fscrypt v2 context stored in ext4's private inode xattr slot.
    ///
    /// # Errors
    /// Returns an error when the inode's xattr storage is malformed or the
    /// stored fscrypt context is not in the supported v2 AES profile.
    pub(super) fn read_inode_fscrypt_context(
        &self,
        inode_id: InodeId,
    ) -> Result<Option<FscryptContextV2>> {
        let xattrs = self.read_inode_xattrs_from_live(&self.read_live_inode_record(inode_id)?)?;
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
    pub(super) fn require_encryption_key(&self, inode: &Inode) -> Result<()> {
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
        &self,
        inode: &Inode,
    ) -> Result<(FscryptContextV2, &FscryptMasterKey)> {
        let Some(context) = self.read_inode_fscrypt_context(inode.id())? else {
            return Err(Error::InvalidEncryptionContext);
        };
        let Some(key) = self
            .mount_context
            .fscrypt_keys()
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
        &self,
        inode: &Inode,
    ) -> Result<FscryptContentsKey> {
        let (context, master_key) = self.fscrypt_master_key_for_inode(inode)?;
        master_key.derive_contents_key(context.nonce())
    }

    /// Derives the per-directory filename key and padding policy.
    /// # Errors
    ///
    /// Returns an error when the inode's master key cannot be resolved or filename-key derivation
    /// rejects the policy parameters.
    pub(super) fn fscrypt_filenames_key_for_inode(
        &self,
        inode: &Inode,
    ) -> Result<(FscryptFilenamesKey, FscryptFilenamePadding)> {
        let (context, master_key) = self.fscrypt_master_key_for_inode(inode)?;
        Ok((
            master_key.derive_filenames_key(context.nonce())?,
            context.policy().filename_padding(),
        ))
    }

    /// Converts a plaintext child name to the on-disk name for a directory.
    /// # Errors
    ///
    /// Returns an error when an encrypted parent lacks a filename key or the encrypted name is not a
    /// valid ext4 component.
    pub(super) fn encrypt_directory_child_name(
        &self,
        parent: &Inode,
        name: &Ext4Name,
    ) -> Result<Ext4Name> {
        if !parent.protection().is_encrypted() || matches!(name.bytes(), b"." | b"..") {
            return Ext4Name::new(name.bytes());
        }
        let (key, padding) = self.fscrypt_filenames_key_for_inode(parent)?;
        Ext4Name::from_disk(&key.encrypt_filename(name.bytes(), padding)?)
    }

    /// Converts an on-disk child name to plaintext for a directory.
    /// # Errors
    ///
    /// Returns an error when an encrypted parent lacks a filename key or the decrypted name is not a
    /// valid ext4 component.
    pub(super) fn decrypt_directory_child_name(
        &self,
        parent: &Inode,
        name: &Ext4Name,
    ) -> Result<Ext4Name> {
        if !parent.protection().is_encrypted() || matches!(name.bytes(), b"." | b"..") {
            return Ext4Name::new(name.bytes());
        }
        let (key, _padding) = self.fscrypt_filenames_key_for_inode(parent)?;
        Ext4Name::new(&key.decrypt_filename(name.bytes())?)
    }

    /// Rejects protected plaintext data access until crypto and verification paths exist.
    /// # Errors
    ///
    /// Returns an error when the inode is encrypted or verity-protected, including the missing-key
    /// case for encrypted payloads.
    pub(super) fn reject_unsupported_protected_payload_access(&self, inode: &Inode) -> Result<()> {
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
    pub(super) fn load_inode_node(&self, inode_id: InodeId) -> Result<LoadedNode> {
        Ok(LoadedNode::from_inode(self.read_inode_record(inode_id)?))
    }

    /// Loads and classifies one Windows-facing file index as a typed node identity.
    ///
    /// # Errors
    /// Returns an error when the file index cannot represent a live ext4 inode.
    pub(super) fn load_node_by_file_index(&self, file_index: u32) -> Result<NodeId> {
        let inode_id = InodeId::try_from(file_index)?;
        Ok(self.load_inode_node(inode_id)?.id())
    }

    /// Loads an inode through a previously validated public identity.
    /// # Errors
    ///
    /// Returns an error when the inode cannot be loaded or its actual typed identity no longer
    /// matches `id`.
    pub(super) fn load_validated_node(&self, id: NodeId) -> Result<LoadedNode> {
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
        &self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        if file.protection().is_verity() {
            return self.read_verified_file(file, offset, out);
        }
        self.read_inode_plaintext_data(file.inode(), offset, out)
    }

    /// Reads a typed symlink target as bytes.
    ///
    /// # Errors
    /// Returns an error when the symlink target cannot be read.
    pub(super) fn read_symlink(&self, symlink: &SymlinkNode) -> Result<Vec<u8>> {
        self.reject_unsupported_protected_payload_access(symlink.inode())?;
        let len = symlink.size().to_usize()?;
        if let Ok(inline) = symlink.inode().inline_bytes() {
            return memory::copied_slice(inline.prefix(symlink.size())?);
        }
        let mut target = memory::repeated_vec(0_u8, len)?;
        let _bytes_read = self.read_inode_data(symlink.inode(), FileOffset::ZERO, &mut target)?;
        Ok(target)
    }

    /// Reads a verity-protected regular file after verifying its full plaintext.
    /// # Errors
    ///
    /// Returns an error when verity metadata cannot be read, full-file plaintext cannot be read, the
    /// Merkle tree verification fails, or the requested output slice is out of range.
    pub(super) fn read_verified_file(
        &self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        if out.is_empty() || offset.bytes() >= file.size().bytes() {
            return Ok(ReadBytes::from_usize(0));
        }
        let metadata = self.read_verity_metadata(file)?;
        let mut plaintext = memory::repeated_vec(0_u8, file.size().to_usize()?)?;
        let read =
            self.read_inode_plaintext_data(file.inode(), FileOffset::ZERO, &mut plaintext)?;
        if read.as_usize() != plaintext.len() {
            return Err(Error::InvalidVerityMetadata);
        }
        metadata
            .merkle_tree()
            .verify_data(&plaintext, metadata.descriptor())?;

        let readable = core::cmp::min(
            u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?,
            file.size().remaining_from(offset)?,
        );
        let start = usize::try_from(offset.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let count = usize::try_from(readable).map_err(|_| Error::ArithmeticOverflow)?;
        let end = start.checked_add(count).ok_or(Error::ArithmeticOverflow)?;
        out.get_mut(..count)
            .ok_or(Error::DeviceRange)?
            .copy_from_slice(plaintext.get(start..end).ok_or(Error::DeviceRange)?);
        Ok(ReadBytes::from_usize(count))
    }

    /// Reads ext4 post-EOF fs-verity metadata from a regular file's extent stream.
    /// # Errors
    ///
    /// Returns an error when post-EOF metadata is absent, layout offsets are invalid, descriptor
    /// bytes are malformed, or metadata extents cannot be read.
    pub(super) fn read_verity_metadata(&self, file: &FileNode) -> Result<Ext4VerityMetadata> {
        let block_size = self.superblock.block_size();
        let extent_tree = ExtentTree::load_inode_tree(
            file.inode().extent_root()?,
            block_size,
            &self.device,
            self.extent_tree_context(file.inode()),
        )?;
        let metadata_end = extent_payload_end_bytes(&extent_tree, block_size)?;
        if metadata_end <= file.size().bytes() {
            return Err(Error::InvalidVerityMetadata);
        }
        let tail_offset = metadata_end
            .checked_sub(4)
            .ok_or(Error::InvalidVerityMetadata)?;
        let mut descriptor_size_tail = [0_u8; 4];
        self.read_inode_plaintext_stream_range(
            file.inode(),
            &extent_tree,
            tail_offset,
            &mut descriptor_size_tail,
        )?;
        let descriptor_bytes = u32::from_le_bytes(descriptor_size_tail);
        let descriptor_offset = Ext4VerityMetadataLayout::descriptor_offset_from_metadata_end(
            block_size,
            metadata_end,
            descriptor_bytes,
        )?;
        let descriptor_len =
            usize::try_from(descriptor_bytes).map_err(|_| Error::ArithmeticOverflow)?;
        let mut descriptor_image = memory::repeated_vec(0_u8, descriptor_len)?;
        self.read_inode_plaintext_stream_range(
            file.inode(),
            &extent_tree,
            descriptor_offset,
            &mut descriptor_image,
        )?;
        let descriptor = FsverityDescriptor::parse(
            descriptor_image
                .get(..FSVERITY_DESCRIPTOR_BYTES)
                .ok_or(Error::TruncatedStructure)?,
        )?;
        let layout = Ext4VerityMetadataLayout::from_metadata_end(
            file.size(),
            block_size,
            metadata_end,
            descriptor_bytes,
            &descriptor,
        )?;
        let merkle_tree_len =
            usize::try_from(layout.merkle_tree_bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let mut merkle_tree = memory::repeated_vec(0_u8, merkle_tree_len)?;
        self.read_inode_plaintext_stream_range(
            file.inode(),
            &extent_tree,
            layout.merkle_tree_offset(),
            &mut merkle_tree,
        )?;
        let signature = memory::copied_slice(
            descriptor_image
                .get(FSVERITY_DESCRIPTOR_BYTES..)
                .ok_or(Error::TruncatedStructure)?,
        )?;
        Ext4VerityMetadata::new(layout, descriptor, signature, merkle_tree)
    }

    /// Enumerates directory entries from a typed directory node.
    ///
    /// # Errors
    /// Returns an error when the directory is too large for eager
    /// enumeration, or contains malformed entries.
    pub(super) fn read_directory(&self, directory: &DirectoryNode) -> Result<Vec<DirectoryEntry>> {
        let entries = self.read_directory_layout(directory.inode())?.entries()?;
        let entries = if directory.protection().is_encrypted() {
            match self.decrypt_directory_entries(directory.inode(), &entries) {
                Err(Error::MissingEncryptionKey) => {
                    Self::project_locked_directory_entries(entries)?
                }
                result => result?,
            }
        } else {
            entries
        };
        self.validate_directory_entries(entries)
    }

    /// Decrypts directory-entry names for an unlocked encrypted directory.
    /// # Errors
    ///
    /// Returns an error when the directory filename key is unavailable or any decrypted entry name
    /// is not a valid ext4 component.
    pub(super) fn decrypt_directory_entries(
        &self,
        directory: &Inode,
        entries: &[RawDirectoryEntry],
    ) -> Result<Vec<RawDirectoryEntry>> {
        let mut decrypted = Vec::new();
        decrypted
            .try_reserve_exact(entries.len())
            .map_err(|_| Error::OutOfMemory)?;
        for entry in entries {
            let name = self.decrypt_directory_child_name(directory, entry.name())?;
            decrypted.try_push(RawDirectoryEntry::new(entry.inode(), &name, entry.kind())?)?;
        }
        Ok(decrypted)
    }

    /// Projects encrypted on-disk dirent names into reversible no-key names.
    /// # Errors
    ///
    /// Returns an error when an encrypted directory entry name cannot be encoded as a no-key display
    /// name.
    pub(super) fn project_locked_directory_entries(
        entries: Vec<RawDirectoryEntry>,
    ) -> Result<Vec<RawDirectoryEntry>> {
        let mut projected = Vec::new();
        projected
            .try_reserve_exact(entries.len())
            .map_err(|_| Error::OutOfMemory)?;
        for entry in entries {
            let name = Self::project_locked_directory_name(entry.name())?;
            projected.try_push(RawDirectoryEntry::new(entry.inode(), &name, entry.kind())?)?;
        }
        Ok(projected)
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
    #[cfg(test)]
    pub(super) fn lookup_child(
        &self,
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
        &self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> Result<ChildLookup> {
        match self.lookup_windows_child_entry(parent, requested)? {
            Some(entry) => Ok(ChildLookup::Found(DirectoryChild::new(
                parent.id(),
                entry.name(),
                *entry.node(),
            ))),
            None => Ok(ChildLookup::NotFound),
        }
    }

    /// Looks up a Windows-visible child name and returns the matched directory entry.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated or the
    /// case-insensitive Windows projection is ambiguous.
    pub(super) fn lookup_windows_child_entry(
        &self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> Result<Option<DirectoryEntry>> {
        if parent.protection().is_encrypted() {
            let visible_name = requested.to_ext4()?;
            let ciphertext = match self.encrypt_directory_child_name(parent.inode(), &visible_name)
            {
                Ok(ciphertext) => ciphertext,
                Err(Error::MissingEncryptionKey) => {
                    let Some(ciphertext) = Self::locked_directory_ciphertext_name(&visible_name)?
                    else {
                        return Err(Error::MissingEncryptionKey);
                    };
                    ciphertext
                }
                Err(error) => return Err(error),
            };
            return self
                .read_directory_layout(parent.inode())?
                .find(&ciphertext)?
                .map(|entry| self.validate_directory_entry(entry, &visible_name))
                .transpose();
        }
        if parent.protection().is_verity() {
            return Err(Error::UnsupportedVerity);
        }
        let mut folded = None;

        for entry in self.read_directory(parent)? {
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
    #[cfg(test)]
    pub(super) fn directory_child(
        &self,
        parent: &DirectoryNode,
        entry: RawDirectoryEntry,
    ) -> Result<DirectoryChild> {
        let node = self.load_inode_node(entry.inode())?.id();
        Ok(DirectoryChild::new(parent.id(), entry.name(), node))
    }

    /// Converts raw directory entries into public entries with validated node identity.
    /// # Errors
    ///
    /// Returns an error when any directory entry references an inode that cannot be loaded and
    /// classified.
    pub(super) fn validate_directory_entries(
        &self,
        entries: Vec<RawDirectoryEntry>,
    ) -> Result<Vec<DirectoryEntry>> {
        let mut validated = Vec::new();
        validated
            .try_reserve_exact(entries.len())
            .map_err(|_| Error::OutOfMemory)?;
        for entry in entries {
            let node = self.load_inode_node(entry.inode())?.id();
            validated.try_push(DirectoryEntry::new(entry.name(), node, entry.kind()))?;
        }
        Ok(validated)
    }

    /// Converts one raw directory entry into a public entry using an explicit visible name.
    /// # Errors
    ///
    /// Returns an error when `entry` references an inode that cannot be loaded and classified.
    pub(super) fn validate_directory_entry(
        &self,
        entry: RawDirectoryEntry,
        visible_name: &Ext4Name,
    ) -> Result<DirectoryEntry> {
        let node = self.load_inode_node(entry.inode())?.id();
        Ok(DirectoryEntry::new(visible_name, node, entry.kind()))
    }

    /// Loads and validates the directory layout selected by an inode.
    /// # Errors
    ///
    /// Returns an error when the directory exceeds eager-read limits, uses unsupported indexed
    /// storage, or its blocks cannot be parsed as the selected layout.
    pub(super) fn read_directory_layout(&self, inode: &Inode) -> Result<DirectoryLayout> {
        if inode.size().bytes() > MAX_EAGER_DIRECTORY_BYTES {
            return Err(Error::DirectoryTooLarge);
        }
        let storage = inode.directory_storage_kind()?;
        if matches!(storage, DirectoryStorageKind::HTree) {
            self.superblock.directory_indexing().require_supported()?;
        }
        DirectoryLayout::from_storage_kind(
            storage,
            self.read_directory_block_data(inode)?,
            self.superblock.directory_hash_seed(),
            self.superblock.default_directory_hash_version(),
            self.directory_checksum(inode),
        )
    }

    /// Reads directory file blocks through the inode extent tree.
    /// # Errors
    ///
    /// Returns an error when the directory extent tree contains holes or uninitialized extents,
    /// range arithmetic fails, or a directory block cannot be read.
    pub(super) fn read_directory_block_data(
        &self,
        inode: &Inode,
    ) -> Result<Vec<DirectoryBlockData>> {
        let block_size = self.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let block_count = round_up_div(inode.size().bytes(), u64::from(block_size.bytes()))?;
        let tree = MutableExtentTree::load_inode_tree(
            inode.extent_root()?,
            block_size,
            &self.device,
            self.extent_tree_context(inode),
        )?;
        let mut blocks = Vec::new();
        for logical in 0..block_count {
            let logical_block = LogicalBlock::try_from(logical)?;
            let physical = match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => physical,
                BlockMapping::Uninitialized | BlockMapping::Hole => {
                    return Err(Error::InvalidDirectoryEntry);
                }
            };
            let mut bytes = memory::repeated_vec(0_u8, block_bytes)?;
            self.device
                .read_exact_at(block_size.offset_of(physical)?, &mut bytes)?;
            blocks.try_push(DirectoryBlockData::new(logical_block.as_u32(), bytes))?;
        }
        Ok(blocks)
    }

    /// Reads plaintext file data, decrypting fscrypt contents when needed.
    /// # Errors
    ///
    /// Returns an error when extent traversal fails, encrypted contents cannot be decrypted, or the
    /// requested output range cannot be represented.
    pub(super) fn read_inode_plaintext_data(
        &self,
        inode: &Inode,
        offset: FileOffset,
        out: &mut [u8],
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
        let extent_tree = ExtentTree::load_inode_tree(
            inode.extent_root()?,
            self.superblock.block_size(),
            &self.device,
            self.extent_tree_context(inode),
        )?;
        let readable_len = usize::try_from(readable).map_err(|_| Error::ArithmeticOverflow)?;
        self.read_inode_plaintext_stream_range(
            inode,
            &extent_tree,
            offset.bytes(),
            out.get_mut(..readable_len).ok_or(Error::DeviceRange)?,
        )?;
        Ok(ReadBytes::from_usize(readable_len))
    }

    /// Reads file data through the inode extent tree, zero-filling sparse ranges.
    /// # Errors
    ///
    /// Returns an error when the extent tree cannot be loaded, read range arithmetic fails, or a
    /// mapped physical block cannot be read.
    pub(super) fn read_inode_data(
        &self,
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
        let extent_tree = ExtentTree::load_inode_tree(
            inode.extent_root()?,
            self.superblock.block_size(),
            &self.device,
            self.extent_tree_context(inode),
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
        &self,
        inode: &Inode,
        extent_tree: &ExtentTree,
        offset: u64,
        out: &mut [u8],
    ) -> Result<()> {
        if inode.protection().is_encrypted() {
            let contents_key = self.fscrypt_contents_key_for_inode(inode)?;
            self.read_encrypted_inode_stream_range(&contents_key, extent_tree, offset, out)
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
        &self,
        contents_key: &FscryptContentsKey,
        extent_tree: &ExtentTree,
        offset: u64,
        out: &mut [u8],
    ) -> Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        let block_size = u64::from(self.superblock.block_size().bytes());
        let block_bytes = usize::try_from(self.superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
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
                    let mut block = memory::repeated_vec(0_u8, block_bytes)?;
                    self.device.read_exact_at(
                        self.superblock.block_size().offset_of(physical_block)?,
                        &mut block,
                    )?;
                    contents_key.decrypt_block(logical_block, &mut block)?;
                    let start = usize::try_from(in_block).map_err(|_| Error::ArithmeticOverflow)?;
                    let block_end = start.checked_add(chunk).ok_or(Error::ArithmeticOverflow)?;
                    out.get_mut(completed..end)
                        .ok_or(Error::DeviceRange)?
                        .copy_from_slice(block.get(start..block_end).ok_or(Error::DeviceRange)?);
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
        &self,
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
            let block_remaining = block_size
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            let total_remaining = u64::try_from(
                out.len()
                    .checked_sub(completed)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let chunk_u64 = core::cmp::min(block_remaining, total_remaining);
            let chunk = usize::try_from(chunk_u64).map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            match extent_tree.map_logical(LogicalBlock::try_from(logical_block)?) {
                BlockMapping::Physical(physical_block) => {
                    let device_offset = self
                        .superblock
                        .block_size()
                        .offset_of(physical_block)?
                        .get()
                        .checked_add(in_block)
                        .ok_or(Error::ArithmeticOverflow)?;
                    self.device.read_exact_at(
                        ByteOffset::new(device_offset),
                        out.get_mut(completed..end).ok_or(Error::DeviceRange)?,
                    )?;
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

    /// Reads an inode record together with its on-device offset.
    /// # Errors
    ///
    /// Returns an error when `inode_id` is outside the filesystem inode range, its table offset
    /// cannot be computed, or the record cannot be read.
    pub(super) fn read_raw_inode_record(&self, inode_id: InodeId) -> Result<RawInodeRecord> {
        if inode_id.as_u32() > self.superblock.inode_count().as_u32() {
            return Err(Error::InvalidInode);
        }

        let inode_offset = inode_offset_on_device(&self.device, &self.superblock, inode_id)?;

        let mut bytes =
            memory::repeated_vec(0_u8, usize::from(self.superblock.inode_size().as_u16()))?;
        self.device.read_exact_at(inode_offset, &mut bytes)?;
        Ok(RawInodeRecord {
            id: inode_id,
            offset: inode_offset,
            bytes,
        })
    }

    /// Reads and parses a typed inode record.
    /// # Errors
    ///
    /// Returns an error when the live inode record cannot be read or parsed as a supported inode.
    pub(super) fn read_inode_record(&self, inode_id: InodeId) -> Result<Inode> {
        self.read_live_inode_record(inode_id)?.parse()
    }

    /// Reads a live inode record for mutation or metadata interpretation.
    /// # Errors
    ///
    /// Returns an error when the raw inode record cannot be read or does not satisfy live-inode
    /// invariants.
    pub(super) fn read_live_inode_record(&self, inode_id: InodeId) -> Result<LiveInodeRecord> {
        self.read_raw_inode_record(inode_id)?.into_live()
    }

    /// Reads all xattr storage locations referenced by a live inode.
    /// # Errors
    ///
    /// Returns an error when inline xattrs, the external xattr pointer, external block I/O, or
    /// merged xattr namespaces are malformed.
    pub(super) fn read_inode_xattrs_from_live(
        &self,
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
        end_blocks = end_blocks.max(u64::from(extent.end_logical()?));
    }
    end_blocks
        .checked_mul(u64::from(block_size.bytes()))
        .ok_or(Error::ArithmeticOverflow)
}
