//! Extended-attribute mutation and storage staging.

use super::*;

impl MutationResolvePass<'_, '_, '_> {
    /// Sets or replaces one ext4 extended attribute.
    /// Access ACL values synchronize inode rwx; a header-only ACL removes either reserved ACL slot.
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
        self.edit(|pass| {
            pass.mutation.update_xattrs(node, pass.now, |set| {
                if AclKind::of(&name).is_some() && AclKind::is_absent_value(&value) {
                    set.remove(&name)?;
                    Ok(())
                } else {
                    set.insert(name, value)
                }
            })
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
        self.edit(|pass| {
            let mut removed = None;
            pass.mutation.update_xattrs(node, pass.now, |set| {
                removed = set.remove(name)?;
                Ok(())
            })?;
            Ok(removed)
        })
    }

}

impl MetadataMutation<'_, '_> {
    /// Establishes the child's access/default ACLs before its inode is published.
    /// # Errors
    /// Returns invalid parent policy, allocation or xattr serialization failures.
    pub(super) fn inherit_acl(
        &mut self,
        parent: &Inode,
        raw_inode: &mut LiveInodeRecord,
    ) -> Result<()> {
        let raw_parent = self.raw_inode_for_policy(parent.id())?;
        let parent_xattrs = self.xattr_set_for_raw_inode(&raw_parent)?;
        let Some(default) = AclKind::Default.read(parent_xattrs.public())? else {
            return Ok(());
        };
        let inode = raw_inode.parse()?;
        let directory_default = if inode.kind() == InodeKind::Directory {
            Some(default.try_clone()?)
        } else {
            None
        };
        let access = Ext4Access::inherit(inode.security(), Some(default))?;
        raw_inode.set_permissions(access.security().permissions())?;
        let mut set = self.xattr_set_for_raw_inode(raw_inode)?;
        if let Some(acl) = access.acl() {
            set.public_mut()
                .insert(AclKind::Access.name()?, acl.value()?)?;
        }
        if let Some(default) = directory_default {
            set.public_mut()
                .insert(AclKind::Default.name()?, default.value()?)?;
        }
        self.store_xattr_set(raw_inode, &set)
    }

    /// Retires execution privileges within the transaction changing contents or ownership.
    /// The core has no authority that permits retaining setid or file capabilities.
    /// # Errors
    /// Returns inode, xattr, allocation-accounting, or serialization failures before commit.
    pub(super) fn retire_file_privileges(&mut self, raw_inode: &mut LiveInodeRecord) -> Result<()> {
        let inode = raw_inode.parse()?;
        let permissions = inode.security().permissions().without_file_privileges();
        if permissions != inode.security().permissions() {
            raw_inode.set_permissions(permissions)?;
        }
        let mut xattrs = self.xattr_set_for_raw_inode(raw_inode)?;
        let capability = xattrs
            .public()
            .entries()
            .find(|(name, _)| {
                name.namespace() == crate::XattrNamespace::Security && name.local() == b"capability"
            })
            .map(|(name, _)| name.try_clone())
            .transpose()?;
        if let Some(capability) = capability {
            xattrs.public_mut().remove(&capability)?;
            self.store_xattr_set(raw_inode, &xattrs)?;
        }
        Ok(())
    }

    /// Builds the exact post-mutation metadata projection for one staged live inode.
    /// # Errors
    ///
    /// Returns an error when the inode, xattr storage, is invalid.
    pub(super) fn node_metadata_snapshot(
        &mut self,
        raw_inode: &LiveInodeRecord,
    ) -> Result<NodeMetadataSnapshot> {
        Ok(NodeMetadataSnapshot::from_inode(&raw_inode.parse()?))
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
    fn xattr_block_bytes(&mut self, block: BlockAddress) -> Result<Vec<u8>> {
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
            .read_metadata_exact_at(block_size.offset_of(block)?, &mut bytes)?;
        Ok(bytes)
    }

    /// Reads all xattrs referenced by a staged live inode.
    /// # Errors
    ///
    /// Returns an error when inline xattrs, the external block pointer, the external xattr block, or
    /// merged xattr namespaces are malformed.
    pub(super) fn xattr_set_for_raw_inode(
        &mut self,
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
        now: Ext4Timestamp,
        update: impl FnOnce(&mut XattrSet) -> Result<()>,
    ) -> Result<()> {
        self.require_xattr_mutation()?;
        let inode_index = self.ensure_inode_update(node.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        let _metadata = inode.metadata_mutation()?;

        let mut set = self.xattr_set_for_raw_inode(&raw_inode)?;
        update(set.public_mut())?;
        if let Some(acl) = AclKind::Access.read(set.public())? {
            if inode.kind() == InodeKind::Symlink {
                return Err(Error::InvalidAcl);
            }
            raw_inode.set_permissions(acl.mode(inode.security().permissions())?)?;
        }
        if AclKind::Default.read(set.public())?.is_some() && inode.kind() != InodeKind::Directory {
            return Err(Error::InvalidAcl);
        }
        self.store_xattr_set(&mut raw_inode, &set)?;
        raw_inode.touch_metadata(now)?;
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
        } else {
            let inline_capacity = raw_inode.writable_inline_xattr_region()?.len();
            match xattr_storage::serialize_inline_xattrs(set, inline_capacity) {
                Ok(bytes) => {
                    memory::copy_exact(raw_inode.writable_inline_xattr_region()?, &bytes)?;
                    if let Some(block) = old_block {
                        self.release_xattr_block_ref(block)?;
                    }
                    raw_inode.set_xattr_block(None)?;
                }
                Err(Error::NoSpace) => {
                    self.store_external_xattr_set(raw_inode, set, old_block)?;
                }
                Err(error) => return Err(error),
            }
        }

        let inode = raw_inode.parse()?;
        match inode.storage() {
            InodeStorage::Extents(_) => {
                let tree = self.mutable_extent_tree(&inode)?;
                self.set_inode_allocation_size(raw_inode, Some(&tree))
            }
            InodeStorage::InlineBytes(_) => self.set_inode_allocation_size(raw_inode, None),
            InodeStorage::UnsupportedBlockMap => Err(Error::UnsupportedBlockMap),
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
    pub(super) fn release_xattr_block_ref(&mut self, block: BlockAddress) -> Result<()> {
        let bytes = self.xattr_block_bytes(block)?;
        let _validated =
            xattr_storage::parse_external_xattr_block(&bytes, block, &self.volume.superblock)?;
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
