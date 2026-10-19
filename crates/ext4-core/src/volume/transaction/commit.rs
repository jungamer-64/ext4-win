//! Transaction commit serialization and journal handoff.

use super::*;

impl MetadataMutation<'_, '_> {
    /// Serializes all staged metadata mutations into byte-range writes.
    /// # Errors
    ///
    /// Returns an error when staged bitmap, directory, extent, xattr, group, superblock, or inode
    /// metadata cannot be serialized to device byte ranges.
    fn metadata_writes(&mut self) -> Result<Vec<RangeWrite>> {
        let mut writes = Vec::new();
        for bitmap in &self.block_bitmap_updates {
            writes.try_push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(bitmap.block)?,
                bytes: memory::copied_slice(&bitmap.bytes)?,
            })?;
        }
        for bitmap in &self.inode_bitmap_updates {
            writes.try_push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(bitmap.block)?,
                bytes: memory::copied_slice(&bitmap.bytes)?,
            })?;
        }
        for directory in &self.directory_updates {
            writes.try_push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(directory.block)?,
                bytes: memory::copied_slice(&directory.bytes)?,
            })?;
        }
        for extent in &self.extent_updates {
            writes.try_push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(extent.block)?,
                bytes: memory::copied_slice(&extent.bytes)?,
            })?;
        }
        for xattr in &self.xattr_updates {
            writes.try_push(RangeWrite {
                offset: self.volume.superblock.block_size().offset_of(xattr.block)?,
                bytes: memory::copied_slice(&xattr.bytes)?,
            })?;
        }
        for delta in &self.group_deltas {
            let mut descriptor = BlockGroupDescriptor::read_from(
                &mut self.volume.device,
                &self.volume.superblock,
                delta.group,
            )?;
            if !delta.free_clusters_delta.is_zero() {
                descriptor.apply_free_clusters_delta(
                    delta.free_clusters_delta,
                    &self.volume.superblock,
                    delta.group,
                )?;
            }
            if delta.free_inodes_delta != 0 {
                descriptor.apply_free_inodes_delta(
                    delta.free_inodes_delta,
                    &self.volume.superblock,
                    delta.group,
                )?;
            }
            if delta.used_dirs_delta != 0 {
                descriptor.apply_used_dirs_delta(
                    delta.used_dirs_delta,
                    &self.volume.superblock,
                    delta.group,
                )?;
            }
            if delta.block_bitmap_initialization == BitmapInitializationTransition::Initialize {
                descriptor.initialize_block_bitmap(&self.volume.superblock, delta.group)?;
            }
            if delta.inode_bitmap_initialization == BitmapInitializationTransition::Initialize {
                descriptor.initialize_inode_bitmap(&self.volume.superblock, delta.group)?;
            }
            if let Some(bitmap) = self
                .block_bitmap_updates
                .iter()
                .find(|bitmap| bitmap.block == descriptor.block_bitmap())
            {
                descriptor.refresh_block_bitmap_checksum(
                    &self.volume.superblock,
                    delta.group,
                    bitmap.bytes.as_slice(),
                )?;
            }
            if let Some(bitmap) = self
                .inode_bitmap_updates
                .iter()
                .find(|bitmap| bitmap.block == descriptor.inode_bitmap())
            {
                descriptor.refresh_inode_bitmap_metadata(
                    &self.volume.superblock,
                    delta.group,
                    bitmap.bytes.as_slice(),
                )?;
            }
            writes.try_push(RangeWrite {
                offset: descriptor.offset(),
                bytes: memory::copied_slice(descriptor.bytes())?,
            })?;
        }
        if !self.free_clusters_delta.is_zero()
            || self.free_inodes_delta != 0
            || self.volume_label_update.is_some()
        {
            writes.try_push(RangeWrite {
                offset: ByteOffset::new(SUPERBLOCK_OFFSET),
                bytes: self.updated_superblock_bytes()?,
            })?;
        }
        for inode in &self.inode_updates {
            let mut inode = inode.try_clone()?;
            inode.refresh_checksum(&self.volume.superblock)?;
            writes.try_push(RangeWrite {
                offset: inode.offset(),
                bytes: memory::copied_slice(inode.bytes())?,
            })?;
        }
        Ok(writes)
    }

    /// Coalesces metadata byte ranges into full blocks for journaling.
    /// # Errors
    ///
    /// Returns an error when a metadata write does not fit within one block or an original metadata
    /// block cannot be read before patching.
    pub(super) fn metadata_blocks(&mut self) -> Result<Vec<JournalBlock>> {
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let block_bytes_u64 = u64::from(block_size.bytes());
        let mut blocks = Vec::new();

        for write in self.metadata_writes()? {
            let block = BlockAddress::new(
                write
                    .offset
                    .get()
                    .checked_div(block_bytes_u64)
                    .ok_or(Error::InvalidSuperblock)?,
            );
            let in_block = usize::try_from(
                write
                    .offset
                    .get()
                    .checked_rem(block_bytes_u64)
                    .ok_or(Error::InvalidSuperblock)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let end = in_block
                .checked_add(write.bytes.len())
                .ok_or(Error::ArithmeticOverflow)?;
            if end > block_bytes {
                return Err(Error::InvalidWriteRange);
            }

            let index = if let Some(index) = blocks
                .iter()
                .position(|metadata: &JournalBlock| metadata.block() == block)
            {
                index
            } else {
                let mut bytes = memory::repeated_vec(0_u8, block_bytes)?;
                self.volume
                    .device
                    .read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
                blocks.try_push(JournalBlock::new(block, bytes))?;
                blocks
                    .len()
                    .checked_sub(1)
                    .ok_or(Error::ArithmeticOverflow)?
            };
            memory::copy_exact(
                blocks
                    .get_mut(index)
                    .ok_or(Error::InvalidSuperblock)?
                    .bytes_mut()
                    .get_mut(in_block..end)
                    .ok_or(Error::DeviceRange)?,
                &write.bytes,
            )?;
        }

        Ok(blocks)
    }

    /// Applies accumulated free-count deltas to a superblock image.
    /// # Errors
    ///
    /// Returns an error when the primary superblock cannot be read, free counters underflow or
    /// overflow, the label cannot be written, or the checksum cannot be refreshed.
    fn updated_superblock_bytes(&mut self) -> Result<Vec<u8>> {
        let mut bytes = memory::repeated_vec(0_u8, 1024)?;
        self.volume
            .device
            .read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut bytes)?;
        self.volume
            .superblock
            .apply_free_cluster_delta_to_raw(&mut bytes, self.free_clusters_delta)?;
        if self.free_inodes_delta != 0 {
            let current = u64::from(le_u32(&bytes, disk_offset(SUPERBLOCK_FREE_INODES_OFFSET))?);
            let raw_delta = self.free_inodes_delta;
            let updated = if raw_delta.is_negative() {
                current
                    .checked_sub(raw_delta.unsigned_abs())
                    .ok_or(Error::InvalidSuperblock)?
            } else {
                current
                    .checked_add(u64::try_from(raw_delta).map_err(|_| Error::ArithmeticOverflow)?)
                    .ok_or(Error::ArithmeticOverflow)?
            };
            put_le_u32(
                &mut bytes,
                disk_offset(SUPERBLOCK_FREE_INODES_OFFSET),
                u32::try_from(updated).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        if let Some(label) = self.volume_label_update {
            label.write_to(&mut bytes)?;
        }
        Superblock::refresh_checksum(&mut bytes)?;
        Ok(bytes)
    }
}

impl MetadataMutation<'_, '_> {
    /// Completes a storage-resolved mutation without issuing any lower write.
    /// # Errors
    ///
    /// Returns an error when metadata coalescing, staged allocation validation, resource discovery,
    /// or any pre-write allocation fails.
    pub fn resolve(
        mut self,
        ticket: u64,
        coordinator: &MutationCoordinatorState,
    ) -> Result<ResolvedMutation> {
        if self.volume.mount != Some(&coordinator.mount)
            || self.volume.epoch != Some(coordinator.published_epoch())
        {
            return Err(Error::ClusterReferenceConflict);
        }
        let mut journal_blocks = self.metadata_blocks()?;
        let mut data_writes = Vec::new();
        for write in core::mem::take(&mut self.file_writes) {
            match write.persistence {
                FileDataPersistence::Ordered => data_writes.try_push(write.write)?,
                FileDataPersistence::Journaled => {
                    journal_blocks.try_push(JournalBlock::new(write.block, write.write.bytes))?
                }
            }
        }
        let _validated_next_state = self.committed_cluster_state()?;
        let mut observed = ObservedResourceVersionSet::new(ticket, &coordinator.mount);
        let key_version = self
            .volume
            .key_dependency()
            .map(|resource| coordinator.resource_version(resource));
        // Journaling replaces whole blocks, including neighboring inode records. Their base
        // image must therefore be versioned even when the semantic inode intents are disjoint.
        for block in &journal_blocks {
            let resource = MutationResource::journal_block(block.block());
            observed.include(resource, coordinator.resource_version(resource))?;
        }
        let mut node_metadata_updates = Vec::new();
        node_metadata_updates
            .try_reserve_exact(self.inode_updates.len())
            .map_err(|_| Error::OutOfMemory)?;
        for index in 0..self.inode_updates.len() {
            let (inode_id, live) = {
                let inode = self.inode_updates.get(index).ok_or(Error::InvalidInode)?;
                (inode.id(), matches!(inode, StagedInodeRecord::Live(_)))
            };
            if live {
                let record = self.raw_inode_for_policy(inode_id)?;
                node_metadata_updates.try_push(self.node_metadata_snapshot(&record)?)?;
            }
            let resource = MutationResource::inode(inode_id);
            observed.include(resource, coordinator.resource_version(resource))?;
        }
        for delta in &self.group_deltas {
            let resource = MutationResource::block_group(delta.group);
            observed.include(resource, coordinator.resource_version(resource))?;
        }
        for ancestor in &self.namespace_ancestors {
            let resource = MutationResource::inode(*ancestor);
            observed.include(resource, coordinator.resource_version(resource))?;
        }
        if !self.free_clusters_delta.is_zero()
            || self.free_inodes_delta != 0
            || self.volume_label_update.is_some()
        {
            observed.include(
                MutationResource::VOLUME_METADATA,
                coordinator.resource_version(MutationResource::VOLUME_METADATA),
            )?;
        }
        Ok(ResolvedMutation {
            observed,
            key_version,
            node_metadata_updates,
            data_writes,
            journal_blocks,
            cluster_deltas: core::mem::take(&mut self.cluster_deltas),
            free_clusters_delta: self.free_clusters_delta,
            free_inodes_delta: self.free_inodes_delta,
            volume_label_update: self.volume_label_update,
        })
    }
}

impl ReservedMutation {
    /// Allocates the complete write plan, both epoch publications, and checkpoint before I/O.
    ///
    /// This must run only while the mutation's resource intents and global commit grant are held.
    /// # Errors
    ///
    /// Returns an error when versions changed, the journal is not clean, serialization fails, or
    /// any pre-publication allocation fails.
    pub fn prepare_commit(
        self,
        commit: super::super::CommitLease,
        coordinator: &mut MutationCoordinatorState,
        current_epoch: &CommittedEpoch,
        cache: &mut crate::MetadataCache,
    ) -> Result<CommitReadyMutation> {
        if commit.consume(&coordinator.mount)? != self.resolved.observed.ticket()
            || !self.resolved.is_current(coordinator)
        {
            return Err(Error::ClusterReferenceConflict);
        }
        let ticket = self.resolved.observed.ticket();
        let version_publication =
            coordinator.prepare_version_publication(&self.resolved.observed)?;
        let JournalCoordinatorState::Ready { journal, epoch } = &coordinator.journal else {
            return Err(Error::JournalCorrupt);
        };
        if coordinator.mount != current_epoch.mount
            || *epoch != (current_epoch.identity().uuid(), current_epoch.sequence())
        {
            return Err(Error::ClusterReferenceConflict);
        }

        let durable_clusters = current_epoch
            .clusters
            .with_deltas(&self.resolved.cluster_deltas)?;
        let checkpoint_clusters = durable_clusters.try_clone()?;
        let durable_keys = current_epoch.fscrypt_keys.try_clone()?;
        let checkpoint_keys = durable_keys.try_clone()?;
        let mut superblock = current_epoch.superblock;
        superblock.apply_free_cluster_delta(self.resolved.free_clusters_delta)?;
        superblock.apply_free_inode_delta(self.resolved.free_inodes_delta)?;
        if let Some(label) = self.resolved.volume_label_update {
            superblock.apply_volume_label(label);
        }

        let mut ordered_data_writes = Vec::new();
        ordered_data_writes
            .try_reserve_exact(self.resolved.data_writes.len())
            .map_err(|_| Error::OutOfMemory)?;
        for write in self.resolved.data_writes {
            ordered_data_writes.try_push(crate::StorageRequest::Write {
                target: crate::StorageTarget::Filesystem,
                offset: write.offset,
                buffer: write.bytes,
            })?;
        }

        let prepared = journal.prepare_commit(
            current_epoch.superblock.block_size(),
            self.resolved.journal_blocks,
        )?;
        let (
            planned_journal_writes,
            planned_commit_write,
            journal_target,
            durable_journal,
            overlay,
            checkpoint,
        ) = prepared.into_parts();
        let mut journal_writes = Vec::new();
        journal_writes
            .try_reserve_exact(planned_journal_writes.len())
            .map_err(|_| Error::OutOfMemory)?;
        for write in planned_journal_writes {
            journal_writes.try_push(write.into_request())?;
        }
        let commit_write = planned_commit_write.into_request();
        let (planned_home_writes, planned_clean_write, clean_journal) = checkpoint.into_parts();
        let mut home_writes = Vec::new();
        home_writes
            .try_reserve_exact(planned_home_writes.len())
            .map_err(|_| Error::OutOfMemory)?;
        for write in planned_home_writes {
            home_writes.try_push(write.into_request())?;
        }
        let durable_sequence = current_epoch.sequence().next()?;
        let checkpoint_sequence = durable_sequence.next()?;
        let durable_epoch = CommittedEpoch::prepared(
            current_epoch,
            durable_sequence,
            superblock,
            durable_keys,
            durable_clusters,
            overlay,
        );
        let checkpointed_epoch = CommittedEpoch::prepared(
            current_epoch,
            checkpoint_sequence,
            superblock,
            checkpoint_keys,
            checkpoint_clusters,
            Vec::new(),
        );
        let checkpoint = CheckpointOperation {
            home_writes,
            clean_write: planned_clean_write.into_request(),
            clean_journal,
            checkpointed_epoch,
        };
        cache.begin_mutation(
            ordered_data_writes
                .iter()
                .chain(journal_writes.iter())
                .chain(core::iter::once(&commit_write))
                .chain(checkpoint.home_writes.iter())
                .chain(core::iter::once(&checkpoint.clean_write)),
        )?;
        Ok(CommitReadyMutation {
            ticket,
            ordered_data_writes,
            journal_writes,
            commit_write,
            journal_target,
            durable_journal,
            durable_epoch,
            checkpoint,
            version_publication,
        })
    }
}

impl CommitReadyMutation {
    /// Starts ordered data I/O while sealing all later commit and publication states.
    #[must_use]
    pub fn start(self) -> StorageRequestSequence<OrderedDataDurability> {
        let durable = DurableMutation {
            ticket: self.ticket,
            durable_journal: self.durable_journal,
            durable_epoch: self.durable_epoch,
            checkpoint: self.checkpoint,
            version_publication: self.version_publication,
        };
        StorageRequestSequence::new(
            self.ordered_data_writes,
            OrderedDataDurability {
                journal_writes: self.journal_writes,
                next: JournalPayloadDurability {
                    journal_target: self.journal_target,
                    commit_write: self.commit_write,
                    durable,
                },
            },
        )
    }
}

impl DurableMutation {
    /// Publishes a durable commit using moves and fixed-table replacement only.
    ///
    /// Rejection retains the already durable mutation for publication with the correct grant.
    /// No storage I/O is repeated. This transition performs no allocation.
    /// # Errors
    /// Returns the error and reusable durable state when the grant or current epoch mismatches.
    #[expect(
        clippy::result_large_err,
        reason = "rejection must return owned durable state without allocating after commit"
    )]
    pub fn publish(
        self,
        visibility: super::super::VisibilityLease,
        coordinator: &mut MutationCoordinatorState,
    ) -> core::result::Result<PublishedMutation, (Error, Self)> {
        let valid = visibility.consume(&coordinator.mount) == Ok(self.ticket)
            && coordinator.mount == self.durable_epoch.mount
            && matches!(coordinator.journal, JournalCoordinatorState::Ready { .. })
            && coordinator.published_epoch().1.next() == Ok(self.durable_epoch.sequence());
        if !valid {
            return Err((Error::ClusterReferenceConflict, self));
        }
        let _durable_journal = self.durable_journal;
        coordinator.journal = JournalCoordinatorState::CheckpointPending {
            epoch: (
                self.durable_epoch.identity().uuid(),
                self.durable_epoch.sequence(),
            ),
        };
        coordinator.publish_versions(self.version_publication);
        Ok(PublishedMutation {
            epoch: self.durable_epoch,
            checkpoint: self.checkpoint,
        })
    }
}

impl CheckpointOperation {
    /// Starts checkpoint home-block I/O while sealing clean publication state.
    /// # Errors
    /// Returns the error and reusable checkpoint when its mount or visible epoch mismatches.
    #[expect(
        clippy::result_large_err,
        reason = "rejection preserves owned checkpoint authority without allocating after commit"
    )]
    pub fn start(
        self,
        checkpoint: super::super::CheckpointLease,
    ) -> core::result::Result<StorageRequestSequence<HomeBlockDurability>, (Error, Self)> {
        if checkpoint
            .consume(&self.checkpointed_epoch.mount)
            .and_then(|epoch| epoch.next())
            != Ok(self.checkpointed_epoch.sequence())
        {
            return Err((Error::ClusterReferenceConflict, self));
        }
        let journal_target = self.clean_write.target();
        Ok(StorageRequestSequence::new(
            self.home_writes,
            HomeBlockDurability {
                clean_write: self.clean_write,
                journal_target,
                clean_journal: self.clean_journal,
                checkpointed_epoch: self.checkpointed_epoch,
            },
        ))
    }
}

impl CheckpointPublication {
    /// Publishes prebuilt clean journal and overlay-free epoch after the final flush.
    ///
    /// This transition performs no allocation. Rejection retains the completed checkpoint proof.
    /// # Errors
    /// Returns the error and reusable publication when the coordinator is not its pending epoch.
    #[expect(
        clippy::result_large_err,
        reason = "rejection preserves completed checkpoint state without allocating after durability"
    )]
    pub fn publish(
        self,
        coordinator: &mut MutationCoordinatorState,
    ) -> core::result::Result<CommittedEpoch, (Error, Self)> {
        if coordinator.mount != self.checkpointed_epoch.mount
            || !matches!(
                coordinator.journal,
                JournalCoordinatorState::CheckpointPending { .. }
            )
            || coordinator.published_epoch().1.next() != Ok(self.checkpointed_epoch.sequence())
        {
            return Err((Error::ClusterReferenceConflict, self));
        }
        coordinator.journal = JournalCoordinatorState::Ready {
            journal: self.clean_journal,
            epoch: (
                self.checkpointed_epoch.identity().uuid(),
                self.checkpointed_epoch.sequence(),
            ),
        };
        Ok(self.checkpointed_epoch)
    }
}

/// Maps a logical block through an ordered extent list.
pub(super) fn map_extents(extents: &[Extent], logical_block: LogicalBlock) -> BlockMapping {
    for extent in extents {
        match extent.map_logical(logical_block) {
            BlockMapping::Physical(block) => return BlockMapping::Physical(block),
            BlockMapping::Uninitialized => return BlockMapping::Uninitialized,
            BlockMapping::Hole => {}
        }
    }
    BlockMapping::Hole
}

/// Builds the ext4 post-EOF verity metadata byte image.
/// # Errors
///
/// Returns an error when the verity layout offsets are inconsistent or any metadata slice falls
/// outside the allocated image.
pub(super) fn verity_metadata_image(
    layout: Ext4VerityMetadataLayout,
    merkle_tree: &[u8],
    descriptor: &[u8],
) -> Result<Vec<u8>> {
    let metadata_bytes = usize::try_from(
        layout
            .metadata_end()
            .checked_sub(layout.merkle_tree_offset())
            .ok_or(Error::InvalidVerityMetadata)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)?;
    let mut image = memory::repeated_vec(0_u8, metadata_bytes)?;
    let tree_end = merkle_tree.len();
    memory::copy_exact(
        image
            .get_mut(..tree_end)
            .ok_or(Error::InvalidVerityMetadata)?,
        merkle_tree,
    )?;
    let descriptor_offset = usize::try_from(
        layout
            .descriptor_offset()
            .checked_sub(layout.merkle_tree_offset())
            .ok_or(Error::InvalidVerityMetadata)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)?;
    let descriptor_end = descriptor_offset
        .checked_add(descriptor.len())
        .ok_or(Error::ArithmeticOverflow)?;
    memory::copy_exact(
        image
            .get_mut(descriptor_offset..descriptor_end)
            .ok_or(Error::InvalidVerityMetadata)?,
        descriptor,
    )?;
    let tail_offset = usize::try_from(
        layout
            .descriptor_size_offset()
            .checked_sub(layout.merkle_tree_offset())
            .ok_or(Error::InvalidVerityMetadata)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)?;
    put_le_u32(
        &mut image,
        disk_offset(tail_offset),
        u32::try_from(descriptor.len()).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    Ok(image)
}

/// Converts an inode kind into the directory entry file-type byte domain.
pub(super) const fn directory_entry_kind(kind: InodeKind) -> DirectoryEntryKind {
    match kind {
        InodeKind::File => DirectoryEntryKind::File,
        InodeKind::Directory => DirectoryEntryKind::Directory,
        InodeKind::Symlink => DirectoryEntryKind::Symlink,
    }
}

/// Rejects `.` and `..` as caller-supplied child names.
/// # Errors
///
/// Returns an error when `name` is `.` or `..`.
pub(super) fn reject_reserved_directory_name(name: &Ext4Name) -> Result<()> {
    if matches!(name.bytes(), b"." | b"..") {
        Err(Error::InvalidName)
    } else {
        Ok(())
    }
}

impl MutationResolvePass<'_, '_, '_> {
    /// Seals only staging whose public operations all completed successfully.
    /// # Errors
    /// Returns the first staging failure, incomplete-operation cancellation, or resolution failure.
    pub fn resolve(
        self,
        ticket: u64,
        coordinator: &MutationCoordinatorState,
    ) -> Result<ResolvedMutation> {
        match self.state {
            MutationState::Ready => self.mutation.resolve(ticket, coordinator),
            MutationState::Editing => Err(Error::OperationCancelled),
            MutationState::Rejected(error) => Err(error),
        }
    }
}
