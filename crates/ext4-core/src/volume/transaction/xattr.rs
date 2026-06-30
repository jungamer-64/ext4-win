//! Extended-attribute mutation and storage staging.

use super::*;

impl<D: BlockWriter, J, N: FscryptNonceGenerator> JournalTransaction<'_, D, J, N> {
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
        self.update_xattrs(node, |set| {
            set.insert(name, value);
            Ok(())
        })
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
    pub fn set_posix_acl(
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

    /// Stages the latest image for a mutated external xattr block.
    fn stage_xattr_block(&mut self, block: BlockAddress, bytes: Vec<u8>) {
        if let Some(image) = self
            .xattr_updates
            .iter_mut()
            .find(|image| image.block == block)
        {
            image.bytes = bytes;
        } else {
            self.xattr_updates.push(BlockImage { block, bytes });
        }
    }

    /// Reads an external xattr block, preferring this transaction's staged image.
    fn xattr_block_bytes(&self, block: BlockAddress) -> Result<Vec<u8>> {
        if let Some(staged) = self
            .xattr_updates
            .iter()
            .rev()
            .find(|image| image.block == block)
        {
            return Ok(staged.bytes.clone());
        }
        let block_size = self.volume.superblock.block_size();
        let mut bytes =
            vec![0_u8; usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?];
        self.volume
            .device
            .read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
        Ok(bytes)
    }

    /// Reads all xattrs referenced by a staged live inode.
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
        self.stage_xattr_block(block, bytes);
        raw_inode.clear_inline_xattr_region()?;
        raw_inode.set_xattr_block(Some(block))
    }

    /// Releases one inode reference to an external xattr block.
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
        self.stage_xattr_block(block, bytes);
        Ok(())
    }
}
