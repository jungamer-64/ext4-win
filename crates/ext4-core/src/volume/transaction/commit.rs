//! Transaction commit serialization and journal handoff.

use super::*;

impl MetadataMutation<'_, '_> {
    /// Selects a complete inode operand only when every changed byte belongs to stable metadata.
    /// The full image remains authoritative; versions of its complete block are rechecked at commit.
    /// # Errors
    /// Propagates metadata read, coordinate or malformed inode failure before any write authority.
    fn commit_image(
        &mut self,
        blocks: Vec<JournalBlock>,
    ) -> Result<crate::disk_format::journal::JournalCommitImage> {
        use crate::disk_format::journal::JournalCommitImage;
        if !self
            .volume
            .superblock
            .features()
            .contains(crate::FilesystemFeature::FastCommit)
            || blocks.len() != 1
        {
            return Ok(JournalCommitImage::full(blocks));
        }
        let [StagedInodeRecord::Live(inode)] = self.inode_updates.as_slice() else {
            return Ok(JournalCommitImage::full(blocks));
        };
        let block = blocks.first().ok_or(Error::InvalidWriteRange)?;
        let size = self.volume.superblock.block_size();
        let block_start = size.offset_of(block.block())?;
        let mut base = match memory::repeated_vec(0, block.bytes().len()) {
            Ok(base) => base,
            Err(Error::OutOfMemory) => return Ok(JournalCommitImage::full(blocks)),
            Err(error) => return Err(error),
        };
        self.volume
            .device
            .read_metadata_exact_at(block_start, &mut base)?;
        let Some((offset, record_len)) =
            inode.metadata_delta_region(block_start, &base, block.bytes())?
        else {
            return Ok(JournalCommitImage::full(blocks));
        };
        JournalCommitImage::inode(blocks, size, inode.id(), offset, record_len)
    }

    /// Serializes all staged metadata mutations into byte-range writes.
    /// # Errors
    ///
    /// Returns an error when staged bitmap, directory, extent, xattr, group, superblock, or inode
    /// metadata cannot be serialized to device byte ranges.
    fn metadata_writes(&mut self, write_time: Option<Ext4Timestamp>) -> Result<Vec<RangeWrite>> {
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
            || self.mark_filesystem_error
        {
            writes.try_push(RangeWrite {
                offset: ByteOffset::new(SUPERBLOCK_OFFSET),
                bytes: self.updated_superblock_bytes(write_time)?,
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
    pub(super) fn metadata_images(
        &mut self,
        write_time: Option<Ext4Timestamp>,
    ) -> Result<super::super::metadata_image::MetadataImages> {
        let mut images =
            super::super::metadata_image::MetadataImages::new(self.volume.superblock.block_size());
        for write in self.metadata_writes(write_time)? {
            images.patch(&mut self.volume, write.offset, &write.bytes)?;
        }
        Ok(images)
    }

    /// Recovery has no precommit data writes: allocator zeroes and metadata share one full commit.
    /// # Errors
    /// Returns suspended source reads, serialization or pre-effect image allocation failure.
    pub(super) fn recovery_images(
        &mut self,
    ) -> Result<super::super::metadata_image::MetadataImages> {
        let mut images =
            super::super::metadata_image::MetadataImages::new(self.volume.superblock.block_size());
        for write in &self.file_writes {
            images.patch(&mut self.volume, write.write.offset, &write.write.bytes)?;
        }
        for write in self.metadata_writes(None)? {
            images.patch(&mut self.volume, write.offset, &write.bytes)?;
        }
        Ok(images)
    }

    /// Stamps ordinary superblock writes without adding a shared block to inode-only commits.
    /// Recovery preserves the replayed event clock instead of inventing a new write time.
    /// # Errors
    ///
    /// Returns an error when the primary superblock cannot be read, free counters underflow or
    /// overflow, the label cannot be written, or the checksum cannot be refreshed.
    fn updated_superblock_bytes(&mut self, write_time: Option<Ext4Timestamp>) -> Result<Vec<u8>> {
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
        if self.mark_filesystem_error {
            Superblock::mark_filesystem_error_in_raw(&mut bytes)?;
        }
        if let Some(now) = write_time {
            Superblock::update_write_time(&mut bytes, u64::try_from(now.seconds()).unwrap_or(0))?;
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
        now: Ext4Timestamp,
    ) -> Result<ResolvedMutation> {
        coordinator.require_session_authority()?;
        if self.volume.mount != Some(&coordinator.mount)
            || self.volume.epoch != Some(coordinator.published_epoch())
        {
            return Err(Error::ClusterReferenceConflict);
        }
        let mut journal_blocks = self.metadata_images(Some(now))?.into_blocks();
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
            let inode = self.inode_updates.get(index).ok_or(Error::InvalidInode)?;
            let inode_id = inode.id();
            match inode {
                StagedInodeRecord::Live(_) => {
                    let record = self.raw_inode_for_policy(inode_id)?;
                    node_metadata_updates.try_push(self.node_metadata_update(&record)?)?;
                }
                StagedInodeRecord::Deleted(_) => {
                    node_metadata_updates
                        .try_push(NodeMetadataUpdate::Retired { inode: inode_id })?;
                }
                StagedInodeRecord::Recovering(_) | StagedInodeRecord::Attribute(_) => {}
            }
            let resource = MutationResource::inode(inode_id);
            observed.include(resource, coordinator.resource_version(resource))?;
        }
        for delta in &self.group_deltas {
            let resource = MutationResource::block_group(delta.group);
            observed.include(resource, coordinator.resource_version(resource))?;
        }
        for ancestor in &self.directory_dependencies {
            let resource = MutationResource::inode(*ancestor);
            observed.include(resource, coordinator.resource_version(resource))?;
        }
        if !self.free_clusters_delta.is_zero()
            || self.free_inodes_delta != 0
            || self.volume_label_update.is_some()
            || self.mark_filesystem_error
        {
            observed.include(
                MutationResource::VOLUME_METADATA,
                coordinator.resource_version(MutationResource::VOLUME_METADATA),
            )?;
        }
        let mut data_writes = Vec::new();
        for write in core::mem::take(&mut self.file_writes) {
            match write.persistence {
                FileDataPersistence::Ordered => data_writes.try_push(write.write)?,
                FileDataPersistence::Journaled => {
                    journal_blocks.try_push(JournalBlock::new(write.block, write.write.bytes))?
                }
            }
        }
        Ok(ResolvedMutation {
            mark_filesystem_error: self.mark_filesystem_error,
            completion_durability: self.completion_durability,
            observed,
            key_version,
            node_metadata_updates,
            data_writes,
            image: self.commit_image(journal_blocks)?,
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
        coordinator.prepare_publication(
            commit,
            self.resolved.observed.ticket(),
            |coordinator, claim| {
                let result = self.prepare_under_claim(coordinator, current_epoch, cache, claim);
                if result.is_err() {
                    cache.abandon_mutation();
                }
                result
            },
        )
    }

    /// Serializes and fences a mutation under its already consumed commit acquisition.
    /// # Errors
    /// Returns stale resources, invalid journal state, serialization or allocation failure.
    fn prepare_under_claim(
        self,
        coordinator: &mut MutationCoordinatorState,
        current_epoch: &CommittedEpoch,
        cache: &mut crate::MetadataCache,
        claim: CommitClaim,
    ) -> Result<CommitReadyMutation> {
        if !self.resolved.is_current(coordinator) {
            return Err(Error::ClusterReferenceConflict);
        }
        let version_publication =
            coordinator.prepare_version_publication(&self.resolved.observed)?;
        let PublicationState::Ready {
            journal: Some(journal),
            epoch,
            ..
        } = &coordinator.journal
        else {
            return Err(Error::JournalCorrupt);
        };
        if coordinator.mount != current_epoch.mount
            || *epoch != (current_epoch.identity().uuid(), current_epoch.sequence())
        {
            return Err(Error::ClusterReferenceConflict);
        }

        let durable_clusters = current_epoch
            .clusters
            .as_ref()
            .ok_or(Error::ReadOnlyFilesystem)?
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
        if self.resolved.mark_filesystem_error {
            superblock.mark_filesystem_error();
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

        let prepared =
            journal.prepare_commit(current_epoch.superblock.block_size(), self.resolved.image)?;
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
            Some(durable_clusters),
            overlay,
        )?;
        let checkpointed_epoch = CommittedEpoch::prepared(
            current_epoch,
            checkpoint_sequence,
            superblock,
            checkpoint_keys,
            Some(checkpoint_clusters),
            Vec::new(),
        )?;
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
            claim,
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
    /// Consumes an unstarted write plan and releases its journal acquisition and cache fence.
    /// Dropping the plan alone retains the acquisition, so forgotten cleanup cannot admit a second commit.
    /// # Errors
    /// Returns the error and reusable plan for a foreign or mismatched coordinator.
    #[expect(
        clippy::result_large_err,
        reason = "rejected abort retains the owned write plan without allocating"
    )]
    pub fn abort(
        self,
        coordinator: &mut MutationCoordinatorState,
        cache: &mut crate::MetadataCache,
    ) -> core::result::Result<(), (Error, Self)> {
        if let Err(error) = coordinator.abort_prepared(self.durable_epoch.mount, self.claim) {
            return Err((error, self));
        }
        cache.abandon_mutation();
        Ok(())
    }

    /// Starts ordered data I/O while sealing all later commit and publication states.
    /// Transfer failure or abandoned continuation retains the acquisition: the mount owner must
    /// retire mutation admission and recover the journal before admitting another commit.
    #[must_use]
    pub fn start(self) -> StorageRequestSequence<OrderedDataDurability> {
        let durable = DurableMutation {
            claim: self.claim,
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
    /// Rejection consumes the supplied visibility lease and retains the durable mutation.
    /// Publication can be retried only if its matching acquisition still has unissued visibility
    /// authority; otherwise the mount owner must recover. No storage I/O is repeated, and this
    /// transition performs no allocation.
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
        if let Err(error) = coordinator.validate_visibility(visibility, self.claim) {
            return Err((error, self));
        }
        let valid = coordinator.mount == self.durable_epoch.mount
            && matches!(coordinator.journal, PublicationState::Ready { .. })
            && coordinator.published_epoch().1.next() == Ok(self.durable_epoch.sequence());
        if !valid {
            return Err((Error::ClusterReferenceConflict, self));
        }
        let _durable_journal = self.durable_journal;
        coordinator.journal = PublicationState::CheckpointPending {
            admission: CheckpointAdmission::Available,
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
    /// Consumes the supplied lease on either outcome. Rejection returns the checkpoint, which can
    /// start only if its matching acquisition still has unissued checkpoint authority; otherwise
    /// the mount owner must recover.
    #[expect(
        clippy::result_large_err,
        reason = "rejection preserves owned checkpoint authority without allocating after commit"
    )]
    pub fn start(
        self,
        checkpoint: super::super::CheckpointLease,
        coordinator: &MutationCoordinatorState,
    ) -> core::result::Result<StorageRequestSequence<HomeBlockDurability>, (Error, Self)> {
        if let Err(error) = coordinator.require_session_authority() {
            return Err((error, self));
        }
        if coordinator.mount != self.checkpointed_epoch.mount
            || coordinator.published_epoch().0 != self.checkpointed_epoch.identity().uuid()
            || coordinator.published_epoch().1.next() != Ok(self.checkpointed_epoch.sequence())
            || !matches!(
                coordinator.journal,
                PublicationState::CheckpointPending {
                    admission: CheckpointAdmission::Granted,
                    ..
                }
            )
            || checkpoint
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
        if let Err(error) = coordinator.require_session_authority() {
            return Err((error, self));
        }
        if coordinator.mount != self.checkpointed_epoch.mount
            || !matches!(
                coordinator.journal,
                PublicationState::CheckpointPending {
                    admission: CheckpointAdmission::Granted,
                    ..
                }
            )
            || coordinator.published_epoch().1.next() != Ok(self.checkpointed_epoch.sequence())
        {
            return Err((Error::ClusterReferenceConflict, self));
        }
        coordinator.journal = PublicationState::Ready {
            admission: CommitAdmission::Available,
            journal: Some(self.clean_journal),
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
            MutationState::Ready => self.mutation.resolve(ticket, coordinator, self.now),
            MutationState::Editing => Err(Error::OperationCancelled),
            MutationState::Rejected(error) => Err(error),
        }
    }
}
