//! Extended-attribute mutation and storage staging.

use super::*;

impl MutationResolvePass<'_, '_, '_> {
    /// Checks layout capacity without allocating blocks, value inodes or staging writes.
    ///
    /// A positive result admits representation only; allocation and I/O can still fail when
    /// the caller subsequently stores the attribute in this mutation.
    /// # Errors
    /// Returns malformed existing attributes, inode policy or allocation failures.
    pub fn xattr_fits(
        &mut self,
        node: NodeId,
        name: XattrName,
        value: XattrValue,
    ) -> Result<bool> {
        self.edit(|pass| {
            if matches!(pass.mutation.volume.superblock.xattr_mutation(), XattrMutationSupport::Disabled) {
                return Ok(false);
            }
            let raw = pass.mutation.raw_inode_for_policy(node.inode())?;
            let mut set = pass.mutation.xattr_set_for_raw_inode(&raw)?;
            set.public_mut().insert(name, value)?;
            let width = usize::try_from(pass.mutation.volume.superblock.block_size().bytes())
                .map_err(|_| Error::ArithmeticOverflow)?;
            match xattr_storage::XattrStoragePlan::for_inode(
                &set,
                raw.inline_xattr_region()?.len(),
                width,
                pass.mutation.volume.superblock.attribute_value_storage(),
            ) {
                Ok(_) => Ok(true),
                Err(Error::NoSpace) => Ok(false),
                Err(error) => Err(error),
            }
        })
    }

    /// Sets or replaces one ext4 extended attribute.
    /// Access ACL values synchronize inode rwx; a header-only ACL removes either reserved ACL slot.
    ///
    /// # Errors
    /// Returns an error when the inode is not mutable or the xattr set cannot
    /// fit in the admitted attribute-entry and value-inode storage.
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
        self.store_xattr_set(raw_inode, set, None)
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
            self.store_xattr_set(raw_inode, xattrs, None)?;
        }
        Ok(())
    }

    /// Builds the exact post-mutation metadata projection for one staged live inode.
    /// # Errors
    ///
    /// Returns an error when the staged inode is malformed.
    pub(super) fn node_metadata_snapshot(
        &mut self,
        raw_inode: &LiveInodeRecord,
    ) -> Result<NodeMetadataSnapshot> {
        Ok(NodeMetadataSnapshot::from_inode(&raw_inode.parse()?))
    }

    /// Pairs the staged inode observation with its opaque attributes before commit.
    /// # Errors
    /// Returns malformed inode/xattr storage, backing-read or allocation failures.
    pub(super) fn node_metadata_update(
        &mut self,
        raw: &LiveInodeRecord,
    ) -> Result<NodeMetadataUpdate> {
        Ok(NodeMetadataUpdate::Live {
            metadata: self.node_metadata_snapshot(raw)?,
            xattrs: self.xattr_set_for_raw_inode(raw)?.into_public(),
        })
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

    /// Stages a complete distinct value inode; value sharing is never inferred from equal bytes.
    /// # Errors
    /// Propagates inode/block allocation, field encoding and payload staging failures.
    fn create_attribute_value(
        &mut self,
        value: &[u8],
    ) -> Result<xattr_storage::AttributeValueLocation> {
        if value.is_empty() || value.len() > XattrValue::MAX_BYTES {
            return Err(Error::InvalidXattr);
        }
        let block_size = self.volume.superblock.block_size();
        let width = usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let size = FileSize::from_bytes(
            u64::try_from(value.len()).map_err(|_| Error::ArithmeticOverflow)?,
        );
        let checksum = crate::disk::checksum::ext4_crc32c(
            self.volume.superblock.checksum_seed().as_u32(),
            value,
        );
        let mut raw = self.allocate_inode()?.initialize_attribute_value(
            size,
            checksum,
            block_size,
            self.volume.superblock.inode_timestamp_encoding(),
        )?;
        let mut tree = MutableExtentTree::from_extents(Vec::new())?;
        let mut start = 0_usize;
        let mut logical = 0_u64;
        while start < value.len() {
            let end = core::cmp::min(
                value.len(),
                start.checked_add(width).ok_or(Error::ArithmeticOverflow)?,
            );
            let logical_block = LogicalBlock::try_from(logical)?;
            let block = self.allocate_extent_block(&tree, logical_block)?;
            tree.insert_or_extend_initialized(logical_block, block)?;
            let mut bytes = memory::repeated_vec(0, width)?;
            let count = end.checked_sub(start).ok_or(Error::ArithmeticOverflow)?;
            memory::copy_exact(
                bytes.get_mut(..count).ok_or(Error::DeviceRange)?,
                value.get(start..end).ok_or(Error::DeviceRange)?,
            )?;
            self.stage_file_write(
                FileDataPersistence::Ordered,
                RangeWrite {
                    offset: block_size.offset_of(block)?,
                    bytes,
                },
            )?;
            start = end;
            logical = logical.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        }
        self.stage_extent_tree(&mut raw, tree)?;
        let location = xattr_storage::AttributeValueLocation {
            inode: raw.id(),
            size: value.len(),
            checksum,
        };
        self.stage_attribute_record(raw.into())?;
        Ok(location)
    }
    /// Publishes a private attribute-record successor within this transaction's sole inode index.
    /// # Errors
    /// Rejects namespace/deleted-role aliasing and physical allocation failure.
    fn stage_attribute_record(&mut self, record: StagedInodeRecord) -> Result<()> {
        if let Some(old) = self
            .inode_updates
            .iter_mut()
            .find(|old| old.id() == record.id())
        {
            if !matches!(old, StagedInodeRecord::Attribute(_)) {
                return Err(Error::InvalidXattr);
            }
            *old = record;
            Ok(())
        } else {
            self.inode_updates.try_push(record)
        }
    }
    /// Releases one physical entry reference, reclaiming storage only on the final reference.
    /// # Errors
    /// Rejects malformed header/reference relations and allocation-accounting failures.
    fn release_attribute_value(
        &mut self,
        reference: xattr_storage::AttributeValueReference,
    ) -> Result<()> {
        let mut raw = self.attribute_record(reference.inode)?;
        let header = raw.parse()?;
        if header.data().size().to_usize()? != reference.size {
            return Err(Error::InvalidXattr);
        }
        reference.verify_checksum(header.value_checksum())?;
        if let Some(remaining) = core::num::NonZeroU64::new(
            header
                .references()
                .checked_sub(1)
                .ok_or(Error::InvalidXattr)?,
        ) {
            raw.set_references(remaining)?;
            return self.stage_attribute_record(raw.into());
        }
        let data = header.data();
        let InodeStorage::Extents(root) = data.storage() else {
            return Err(Error::InvalidXattr);
        };
        let block_size = self.volume.superblock.block_size();
        let context = crate::volume::orphan::extent_context(self.volume.superblock, data);
        let mut source = TransactionExtentSource {
            device: &mut self.volume.device,
            staged: &self.extent_updates,
            block_size,
        };
        let tree = MutableExtentTree::load_inode_tree(root, block_size, &mut source, context)?;
        for extent in tree.extents().iter().copied() {
            self.free_extent(extent, 0)?;
        }
        for block in tree.metadata_blocks().iter().copied() {
            self.release_cluster_reference(block)?;
        }
        if ExtentInodeRecord::xattr_block(&raw)?.is_some() {
            return Err(Error::InvalidXattr);
        }
        self.free_inode(raw.id())?;
        self.stage_attribute_record(raw.retire(block_size)?.into())
    }
    /// Releases inode-body value entries; shared external-block entries have separate ownership.
    /// # Errors
    /// Propagates structural, reference-count and storage-release failures.
    pub(super) fn release_inline_attribute_values(
        &mut self,
        raw: &RawInodeRecord<Vec<u8>>,
    ) -> Result<()> {
        let mut references = Vec::new();
        for reference in
            xattr_storage::parse_inline_xattrs(raw.inline_xattr_region()?)?.attribute_references()
        {
            references.try_push(reference)?;
        }
        for reference in references {
            self.release_attribute_value(reference)?;
        }
        Ok(())
    }
    /// Acquires only attribute-value record ownership; namespace staging cannot alias it.
    /// # Errors
    /// Rejects another staged role or malformed/unallocated backing data.
    fn attribute_record(&mut self, id: InodeId) -> Result<AttributeInodeRecord> {
        match self.inode_updates.iter().find(|record| record.id() == id) {
            Some(StagedInodeRecord::Attribute(record)) => record.try_clone(),
            Some(_) => Err(Error::InvalidXattr),
            None => self.volume.read_raw_inode_record(id)?.into_attribute(),
        }
    }
    /// Reads a complete value through the transaction's inode, extent and payload overlays.
    /// # Errors
    /// Preserves metadata, physical allocation, checksum and suspended-I/O failures.
    fn read_attribute_value(
        &mut self,
        reference: xattr_storage::AttributeValueReference,
    ) -> Result<XattrValue> {
        let raw = self.attribute_record(reference.inode)?;
        let header = raw.parse()?;
        let data = header.data();
        if data.size().to_usize()? != reference.size {
            return Err(Error::InvalidXattr);
        }
        let InodeStorage::Extents(root) = data.storage() else {
            return Err(Error::InvalidXattr);
        };
        let block_size = self.volume.superblock.block_size();
        let context = crate::volume::orphan::extent_context(self.volume.superblock, data);
        let mut source = TransactionExtentSource {
            device: &mut self.volume.device,
            staged: &self.extent_updates,
            block_size,
        };
        let tree = MutableExtentTree::load_inode_tree(root, block_size, &mut source, context)?;
        let width = usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let mut bytes = memory::repeated_vec(0, reference.size)?;
        let mut start = 0_usize;
        let mut logical = 0_u64;
        while start < bytes.len() {
            let end = core::cmp::min(
                bytes.len(),
                start.checked_add(width).ok_or(Error::ArithmeticOverflow)?,
            );
            if let BlockMapping::Physical(block) =
                tree.map_logical(LogicalBlock::try_from(logical)?)
            {
                let payload = self.file_block_bytes(block)?;
                let count = end.checked_sub(start).ok_or(Error::ArithmeticOverflow)?;
                memory::copy_exact(
                    bytes.get_mut(start..end).ok_or(Error::DeviceRange)?,
                    payload.get(..count).ok_or(Error::DeviceRange)?,
                )?;
            }
            start = end;
            logical = logical.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        }
        reference.admit_value(
            &header,
            &bytes,
            self.volume.superblock.checksum_seed().as_u32(),
        )
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
        let inline = xattr_storage::parse_inline_xattrs(raw_inode.inline_xattr_region()?)?
            .resolve(|reference| self.read_attribute_value(reference))?;
        let Some(block) = raw_inode.xattr_block()? else {
            return Ok(inline);
        };
        let bytes = self.xattr_block_bytes(block)?;
        let external =
            xattr_storage::parse_external_xattr_block(&bytes, block, &self.volume.superblock)?
                .resolve(|reference| self.read_attribute_value(reference))?;
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
        self.store_xattr_set(&mut raw_inode, set, None)?;
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
        mut set: InodeXattrSet,
        inline: Option<InlinePayloadUpdate>,
    ) -> Result<()> {
        let old_block = raw_inode.xattr_block()?;
        let mut old_inline = Vec::new();
        for reference in xattr_storage::parse_inline_xattrs(raw_inode.inline_xattr_region()?)?
            .attribute_references()
        {
            old_inline.try_push(reference)?;
        }
        if set.is_empty() {
            for reference in old_inline {
                self.release_attribute_value(reference)?;
            }
            raw_inode.clear_inline_xattr_region()?;
            if let Some(block) = old_block {
                self.release_xattr_block_ref(block)?;
            }
            raw_inode.set_xattr_block(None)?;
        } else {
            let block_size = self.volume.superblock.block_size();
            let width =
                usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
            let values = self.volume.superblock.attribute_value_storage();
            let body_capacity = raw_inode.writable_inline_xattr_region()?.len();
            let plan = match xattr_storage::XattrStoragePlan::for_inode(
                &set,
                body_capacity,
                width,
                values,
            ) {
                Ok(plan) => plan,
                Err(Error::NoSpace)
                    if inline.is_none() && raw_inode.parse()?.flags().has_inline_data() =>
                {
                    self.convert_inline_data(raw_inode, &mut set)?;
                    xattr_storage::XattrStoragePlan::for_inode(&set, body_capacity, width, values)?
                }
                Err(error) => return Err(error),
            };
            let bound = plan.bind(|value| self.create_attribute_value(value))?;
            for reference in old_inline {
                self.release_attribute_value(reference)?;
            }
            match bound.placement() {
                xattr_storage::XattrValuePlacement::InInode => {
                    let bytes = bound.inline_bytes()?;
                    match inline {
                        Some(update) => raw_inode.replace_inline_payload(update, &bytes)?,
                        None => {
                            memory::copy_exact(raw_inode.writable_inline_xattr_region()?, &bytes)?
                        }
                    }
                    if let Some(block) = old_block {
                        self.release_xattr_block_ref(block)?;
                    }
                    raw_inode.set_xattr_block(None)?;
                }
                xattr_storage::XattrValuePlacement::ExternalBlock => {
                    let block = if let Some(block) = old_block {
                        let bytes = self.xattr_block_bytes(block)?;
                        let refcount = xattr_storage::external_xattr_refcount(&bytes)?;
                        if refcount == 1 {
                            let mut references = Vec::new();
                            for reference in xattr_storage::parse_external_xattr_block(
                                &bytes,
                                block,
                                &self.volume.superblock,
                            )?
                            .attribute_references()
                            {
                                references.try_push(reference)?;
                            }
                            for reference in references {
                                self.release_attribute_value(reference)?;
                            }
                            block
                        } else {
                            let next = self.allocate_cluster()?;
                            self.release_cluster_reference(block)?;
                            self.decrement_xattr_block_ref(block, bytes, refcount)?;
                            next
                        }
                    } else {
                        self.allocate_cluster()?
                    };
                    let bytes = bound.external_bytes(block, &self.volume.superblock)?;
                    self.stage_xattr_block(block, bytes)?;
                    raw_inode.clear_inline_xattr_region()?;
                    raw_inode.set_xattr_block(Some(block))?;
                }
            }
        }
        let inode = raw_inode.parse()?;
        match inode.storage() {
            InodeStorage::Extents(_) => {
                let tree = self.mutable_extent_tree(&inode)?;
                self.set_inode_allocation_size(raw_inode, Some(&tree))
            }
            InodeStorage::FastSymlink(_) | InodeStorage::InlineData(_) => {
                self.set_inode_allocation_size(raw_inode, None)
            }
            InodeStorage::UnsupportedBlockMap => Err(Error::UnsupportedBlockMap),
        }
    }

    /// Releases one inode reference to an external xattr block.
    /// # Errors
    ///
    /// Returns an error when the block image or refcount is malformed, or the backing cluster
    /// reference cannot be released.
    pub(super) fn release_xattr_block_ref(&mut self, block: BlockAddress) -> Result<()> {
        let bytes = self.xattr_block_bytes(block)?;
        let parsed =
            xattr_storage::parse_external_xattr_block(&bytes, block, &self.volume.superblock)?;
        let mut references = Vec::new();
        for reference in parsed.attribute_references() {
            references.try_push(reference)?;
        }
        let refcount = xattr_storage::external_xattr_refcount(&bytes)?;
        self.release_cluster_reference(block)?;
        if refcount > 1 {
            self.decrement_xattr_block_ref(block, bytes, refcount)
        } else {
            for reference in references {
                self.release_attribute_value(reference)?;
            }
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
