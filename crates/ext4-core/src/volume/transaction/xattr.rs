//! Extended-attribute mutation and storage staging.

use super::*;

/// Rejects xattr reparse storage on a native ext4 symbolic link.
/// # Errors
///
/// Returns an error when the typed node is a symbolic link instead of a file or directory.
fn require_windows_reparse_storage_node(node: TransactionNode) -> Result<()> {
    match node.id() {
        NodeId::File(_) | NodeId::Directory(_) => Ok(()),
        NodeId::Symlink(_) => Err(Error::WrongInodeKind),
    }
}

impl<D: BlockStorage, N: FscryptNonceGenerator, J> JournalTransaction<'_, D, N, J> {
    /// Sets or replaces one ext4 extended attribute.
    ///
    /// # Errors
    /// Returns an error when the inode is not mutable or the xattr set cannot
    /// fit in supported in-inode or single-block external storage.
    pub fn set_xattr(
        &mut self,
        node: TransactionNode,
        name: XattrName,
        value: XattrValue,
    ) -> Result<()> {
        self.update_xattrs(node, |set| set.insert(name, value))
    }

    /// Removes one ext4 extended attribute.
    ///
    /// # Errors
    /// Returns an error when the inode or current xattr storage is malformed.
    pub fn remove_xattr(
        &mut self,
        node: TransactionNode,
        name: &XattrName,
    ) -> Result<Option<XattrValue>> {
        let mut removed = None;
        self.update_xattrs(node, |set| {
            removed = set.remove(name);
            Ok(())
        })?;
        Ok(removed)
    }

    /// Sets a POSIX ACL in the requested ACL xattr slot.
    ///
    /// # Errors
    /// Returns an error when the ACL cannot be serialized or stored.
    #[cfg(test)]
    pub(crate) fn set_posix_acl(
        &mut self,
        node: TransactionNode,
        kind: PosixAclKind,
        acl: PosixAcl,
    ) -> Result<()> {
        self.set_xattr(node, PosixAcl::xattr_name(kind)?, acl.to_xattr_value()?)
    }

    /// Sets Windows overlay metadata in `user.ext4win.*` xattrs.
    ///
    /// # Errors
    /// Returns an error when the overlay cannot be serialized or stored.
    pub fn set_windows_overlay(
        &mut self,
        node: TransactionNode,
        overlay: WindowsOverlay,
    ) -> Result<()> {
        self.set_xattr(
            node,
            WindowsOverlay::attributes_xattr_name()?,
            overlay.to_xattr_value()?,
        )
    }

    /// Sets Windows symbolic-link reparse metadata on a regular file or directory.
    ///
    /// # Errors
    /// Returns an error when the node is a native symbolic link or the reparse
    /// xattr cannot be serialized or stored.
    pub fn set_windows_symlink_reparse_point(
        &mut self,
        node: TransactionNode,
        reparse_point: WindowsSymlinkReparsePoint,
    ) -> Result<()> {
        require_windows_reparse_storage_node(node)?;
        self.set_xattr(
            node,
            WindowsSymlinkReparsePoint::xattr_name()?,
            reparse_point.to_xattr_value()?,
        )
    }

    /// Removes Windows symbolic-link reparse metadata from a regular file or directory.
    ///
    /// # Errors
    /// Returns an error when the node is a native symbolic link or the stored
    /// xattr payload is malformed.
    pub fn remove_windows_symlink_reparse_point(
        &mut self,
        node: TransactionNode,
    ) -> Result<Option<WindowsSymlinkReparsePoint>> {
        require_windows_reparse_storage_node(node)?;
        let Some(value) = self.remove_xattr(node, &WindowsSymlinkReparsePoint::xattr_name()?)?
        else {
            return Ok(None);
        };
        Ok(Some(WindowsSymlinkReparsePoint::parse(&value)?))
    }

    /// Stages the latest image for a mutated external xattr block.
    /// # Errors
    ///
    /// Returns an error when recording a new staged block image cannot allocate.
    fn stage_xattr_block(&mut self, block: BlockAddress, bytes: Vec<u8>) -> Result<()> {
        if let Some(image) = self
            .xattr_updates
            .iter_mut()
            .find(|image| image.block == block)
        {
            image.bytes = bytes;
        } else {
            self.xattr_updates.try_push(BlockImage { block, bytes })?;
        }
        Ok(())
    }

    /// Reads an external xattr block, preferring this transaction's staged image.
    /// # Errors
    ///
    /// Returns an error when `block` cannot be read from the mounted device or block-size arithmetic
    /// cannot be represented.
    fn xattr_block_bytes(&self, block: BlockAddress) -> Result<Vec<u8>> {
        if let Some(staged) = self
            .xattr_updates
            .iter()
            .rev()
            .find(|image| image.block == block)
        {
            return memory::copied_slice(&staged.bytes);
        }
        let block_size = self.volume.superblock.block_size();
        let mut bytes = memory::repeated_vec(
            0_u8,
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        self.volume
            .device
            .read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
        Ok(bytes)
    }

    /// Reads all xattrs referenced by a staged live inode.
    /// # Errors
    ///
    /// Returns an error when inline xattrs, the external block pointer, the external xattr block, or
    /// merged xattr namespaces are malformed.
    pub(super) fn xattr_set_for_raw_inode(
        &self,
        raw_inode: &LiveInodeRecord,
    ) -> Result<InodeXattrSet> {
        match self.volume.superblock.xattr_mutation() {
            XattrMutationSupport::Disabled => return Ok(InodeXattrSet::empty()),
            XattrMutationSupport::Enabled => {}
        }
        let inline = xattr_storage::parse_inline_xattrs(raw_inode.inline_xattr_region()?)?;
        let Some(block) = raw_inode.xattr_block()? else {
            return Ok(inline);
        };
        let bytes = self.xattr_block_bytes(block)?;
        let external =
            xattr_storage::parse_external_xattr_block(&bytes, block, &self.volume.superblock)?;
        xattr_storage::merge_xattr_sets(inline, external)
    }

    /// Applies a mutation to an inode's complete xattr set.
    /// # Errors
    ///
    /// Returns an error when xattr mutation is disabled, the inode cannot be staged, the existing
    /// set is malformed, `update` fails, or the updated set cannot be stored.
    fn update_xattrs(
        &mut self,
        node: TransactionNode,
        update: impl FnOnce(&mut XattrSet) -> Result<()>,
    ) -> Result<()> {
        self.require_xattr_mutation()?;
        let inode_index = self.ensure_inode_update(node.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        let _metadata = inode.metadata_mutation()?;

        let mut set = self.xattr_set_for_raw_inode(&raw_inode)?;
        update(set.public_mut())?;
        self.store_xattr_set(&mut raw_inode, &set)?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Stores a complete xattr set using inline storage when possible and one
    /// external xattr block otherwise.
    /// # Errors
    ///
    /// Returns an error when inline storage cannot be cleared or written, external xattr references
    /// cannot be released, or the set cannot fit supported xattr storage.
    pub(super) fn store_xattr_set(
        &mut self,
        raw_inode: &mut LiveInodeRecord,
        set: &InodeXattrSet,
    ) -> Result<()> {
        let old_block = raw_inode.xattr_block()?;
        if set.is_empty() {
            raw_inode.clear_inline_xattr_region()?;
            if let Some(block) = old_block {
                self.release_xattr_block_ref(block)?;
            }
            raw_inode.set_xattr_block(None)?;
            return Ok(());
        }

        let inline_capacity = raw_inode.writable_inline_xattr_region()?.len();
        match xattr_storage::serialize_inline_xattrs(set, inline_capacity) {
            Ok(bytes) => {
                raw_inode
                    .writable_inline_xattr_region()?
                    .copy_from_slice(&bytes);
                if let Some(block) = old_block {
                    self.release_xattr_block_ref(block)?;
                }
                raw_inode.set_xattr_block(None)
            }
            Err(Error::NoSpace) => self.store_external_xattr_set(raw_inode, set, old_block),
            Err(error) => Err(error),
        }
    }

    /// Stores a complete xattr set in a single external block.
    /// # Errors
    ///
    /// Returns an error when the set exceeds one external block, shared-block refcounts cannot be
    /// adjusted, a replacement block cannot be allocated, or serialization fails.
    fn store_external_xattr_set(
        &mut self,
        raw_inode: &mut LiveInodeRecord,
        set: &InodeXattrSet,
        old_block: Option<BlockAddress>,
    ) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        xattr_storage::ensure_external_xattrs_fit(set, block_bytes)?;

        let block = if let Some(block) = old_block {
            let bytes = self.xattr_block_bytes(block)?;
            let refcount = xattr_storage::external_xattr_refcount(&bytes)?;
            if refcount == 1 {
                block
            } else {
                let new_block = self.allocate_cluster()?;
                self.release_cluster_reference(block)?;
                self.decrement_xattr_block_ref(block, bytes, refcount)?;
                new_block
            }
        } else {
            self.allocate_cluster()?
        };
        let bytes = xattr_storage::serialize_external_xattr_block(
            set,
            block_bytes,
            block,
            &self.volume.superblock,
        )?;
        self.stage_xattr_block(block, bytes)?;
        raw_inode.clear_inline_xattr_region()?;
        raw_inode.set_xattr_block(Some(block))
    }

    /// Releases one inode reference to an external xattr block.
    /// # Errors
    ///
    /// Returns an error when the block image or refcount is malformed, or the backing cluster
    /// reference cannot be released.
    fn release_xattr_block_ref(&mut self, block: BlockAddress) -> Result<()> {
        let bytes = self.xattr_block_bytes(block)?;
        let refcount = xattr_storage::external_xattr_refcount(&bytes)?;
        self.release_cluster_reference(block)?;
        if refcount > 1 {
            self.decrement_xattr_block_ref(block, bytes, refcount)
        } else {
            Ok(())
        }
    }

    /// Decrements a shared external xattr block refcount.
    /// # Errors
    ///
    /// Returns an error when the current refcount is zero or the updated refcount checksum cannot be
    /// written.
    fn decrement_xattr_block_ref(
        &mut self,
        block: BlockAddress,
        mut bytes: Vec<u8>,
        refcount: u32,
    ) -> Result<()> {
        let updated = refcount.checked_sub(1).ok_or(Error::InvalidXattr)?;
        xattr_storage::set_external_xattr_refcount(
            &mut bytes,
            block,
            &self.volume.superblock,
            updated,
        )?;
        self.stage_xattr_block(block, bytes)?;
        Ok(())
    }
}
