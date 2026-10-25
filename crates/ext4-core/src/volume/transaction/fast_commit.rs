//! Reconstructs logical mapping postconditions before publishing any allocation or inode state.
use super::*;
use crate::disk_format::journal::fast_commit::{
    DeltaProgram, LogicalRange, NamespaceChange, ParsedDelta,
};
use crate::volume::fast_commit::ResolvedDeltaImages;

/// A changed inode owns its original tree until final data accounting is known for the whole log.
#[derive(Debug)]
enum ReplayInode {
    /// Existing storage or a file allocation already has a complete mapping interpretation.
    Live {
        /// Metadata and mapping identity remain private until final graph validation.
        raw: LiveInodeRecord,
        /// Resident symlinks/inline files own no extent-tree allocation.
        tree: Option<MutableExtentTree>,
    },
    /// Directory body initialization is mandatory before this inode can enter the staged live set.
    NewDirectory {
        /// Fresh metadata has no directory blocks or externally visible namespace authority.
        raw: LiveInodeRecord,
        /// The logged birth parent supplies the mandatory dot-dot postcondition.
        parent: InodeId,
    },
}
impl ReplayInode {
    /// Identity is independent of whether the storage initialization obligation has completed.
    fn id(&self) -> InodeId {
        match self {
            Self::Live { raw, .. } | Self::NewDirectory { raw, .. } => raw.id(),
        }
    }
}

/// Applies complete, ordered mapping assignments while deriving bitmap changes from final ownership.
/// # Errors
/// Rejects unsupported object creation/terminal unlink, invalid allocation, layout, capacity or source-I/O failure.
pub(in crate::volume) fn resolve_delta_postconditions(
    volume: EpochReadView<'_, '_>,
    program: &DeltaProgram,
) -> Result<ResolvedDeltaImages> {
    for record in program.records() {
        if let ParsedDelta::Namespace { inode, .. } = record
            && !program
                .records()
                .iter()
                .any(|record| matches!(record, ParsedDelta::Inode { inode: id, .. } if id == inode))
        {
            return Err(Error::UnsupportedJournal);
        }
    }
    validate_creation_ancestry(program)?;
    let allocation = AllocationExclusionSource::recovery(volume.superblock, program)?;
    let mut mutation = MetadataMutation::begin(volume, allocation);
    let mut inodes: Vec<ReplayInode> = Vec::new();
    for record in program.records() {
        match record {
            ParsedDelta::AddRange { inode, .. }
            | ParsedDelta::RemoveRange { inode, .. }
            | ParsedDelta::Inode { inode, .. } => {
                prepare_inode(&mut mutation, &mut inodes, program, *inode)?
            }
            ParsedDelta::Namespace { parent, inode, .. } => {
                prepare_inode(&mut mutation, &mut inodes, program, *parent)?;
                prepare_inode(&mut mutation, &mut inodes, program, *inode)?;
            }
        }
    }
    for inode in &mut inodes {
        let ReplayInode::Live {
            raw,
            tree: Some(tree),
        } = inode
        else {
            continue;
        };
        for record in program.records() {
            let (range, replacement) = match record {
                ParsedDelta::AddRange { inode: id, extent } if *id == raw.id() => {
                    (LogicalRange::from_extent(*extent)?, Some(*extent))
                }
                ParsedDelta::RemoveRange { inode: id, range } if *id == raw.id() => (*range, None),
                _ => continue,
            };
            for extent in tree.extents() {
                let first = extent.logical_start().as_u64().max(range.first().as_u64());
                let end = extent.end_logical().min(range.end());
                if first < end {
                    mutation.replay_reference_delta(slice_extent(*extent, first, end)?, -1)?;
                }
            }
            if let Some(extent) = replacement {
                mutation.replay_reference_delta(extent, 1)?;
            }
            replace_range(tree, range, replacement)?;
        }
    }
    let data_clusters = mutation.cluster_deltas.len();
    for index in 0..data_clusters {
        let cluster = mutation
            .cluster_deltas
            .get(index)
            .ok_or(Error::ClusterReferenceConflict)?
            .cluster;
        mutation.reconcile_replay_cluster(cluster)?;
    }
    for inode in inodes {
        let (mut raw, tree) = match inode {
            ReplayInode::Live { raw, tree } => (raw, tree),
            ReplayInode::NewDirectory { mut raw, parent } => {
                let mut tree = MutableExtentTree::from_extents(Vec::new())?;
                mutation.initialize_delta_directory(&mut raw, &mut tree, parent)?;
                (raw, Some(tree))
            }
        };
        if let Some(tree) = tree {
            if raw.parse()?.kind() == InodeKind::Directory {
                let blocks = tree
                    .extents()
                    .last()
                    .map_or(0, |extent| extent.end_logical());
                let size = blocks
                    .checked_mul(u64::from(mutation.volume.superblock.block_size().bytes()))
                    .ok_or(Error::ArithmeticOverflow)?;
                raw.set_encoded_size(
                    mutation
                        .volume
                        .superblock
                        .inode_data_encoding()
                        .encode_directory_size(DirectorySize::from_bytes(size))?,
                )?;
            }
            mutation.stage_extent_tree(&mut raw, tree)?;
        } else {
            mutation.set_inode_allocation_size(&mut raw, None)?;
        }
        mutation
            .inode_updates
            .try_push(StagedInodeRecord::Live(raw))?;
    }
    for record in program.records() {
        if let ParsedDelta::Namespace {
            change,
            parent,
            inode,
            name,
        } = record
        {
            mutation.replay_directory_binding(*parent, *inode, name, *change)?;
        }
    }
    mutation.recount_replayed_directory_links(program)?;
    let (_references, superblock) = mutation.committed_cluster_state()?;
    let images = mutation.recovery_images()?;
    Ok(ResolvedDeltaImages { superblock, images })
}

/// Shares final metadata admission across both operands of a namespace edit and range targets.
/// # Errors
/// Returns source reads, unsupported storage, invalid final metadata or allocation failure.
fn prepare_inode(
    mutation: &mut MetadataMutation<'_, '_>,
    inodes: &mut Vec<ReplayInode>,
    program: &DeltaProgram,
    id: InodeId,
) -> Result<()> {
    if inodes.iter().any(|inode| inode.id() == id) {
        return Ok(());
    }
    let encoded = program
        .records()
        .iter()
        .rev()
        .find_map(|record| match record {
            ParsedDelta::Inode { inode, encoded } if *inode == id => Some(encoded.as_slice()),
            _ => None,
        });
    if let Some(parent) = program.records().iter().find_map(|record| match record {
        ParsedDelta::Namespace {
            change: NamespaceChange::Create,
            parent,
            inode,
            ..
        } if *inode == id => Some(*parent),
        _ => None,
    }) {
        inodes.try_push(mutation.recover_created_inode(
            id,
            parent,
            encoded.ok_or(Error::UnsupportedJournal)?,
        )?)?;
    } else {
        let mut raw = mutation.volume.read_live_inode_record(id)?;
        if let Some(encoded) = encoded {
            raw = raw.restore_delta_metadata(encoded)?;
        }
        let inode = raw.parse()?;
        let tree = if matches!(inode.storage(), InodeStorage::Extents(_)) {
            Some(mutation.mutable_extent_tree(&inode)?)
        } else {
            None
        };
        inodes.try_push(ReplayInode::Live { raw, tree })?;
    }
    let planned = inodes.last().ok_or(Error::InvalidInode)?;
    let range = program.records().iter().any(|record| matches!(record, ParsedDelta::AddRange { inode, .. } | ParsedDelta::RemoveRange { inode, .. } if *inode == id));
    if range
        && !matches!(planned, ReplayInode::Live { raw, tree: Some(_) } if raw.parse()?.kind() != InodeKind::Directory)
    {
        return Err(Error::UnsupportedJournal);
    }
    Ok(())
}

/// Birth edges cannot introduce a cycle even before newly allocated directory bodies exist.
/// # Errors
/// Rejects cyclic creation parentage or pre-effect allocation failure.
fn validate_creation_ancestry(program: &DeltaProgram) -> Result<()> {
    for record in program.records() {
        let ParsedDelta::Namespace {
            change: NamespaceChange::Create,
            parent,
            inode,
            ..
        } = record
        else {
            continue;
        };
        let mut seen = Vec::new();
        seen.try_push(*inode)?;
        let mut cursor = *parent;
        loop {
            if seen.contains(&cursor) {
                return Err(Error::InvalidDirectoryEntry);
            }
            seen.try_push(cursor)?;
            let next = program.records().iter().find_map(|record| match record {
                ParsedDelta::Namespace {
                    change: NamespaceChange::Create,
                    parent,
                    inode,
                    ..
                } if *inode == cursor => Some(*parent),
                _ => None,
            });
            let Some(parent) = next else {
                break;
            };
            cursor = parent;
        }
    }
    Ok(())
}

/// Preserves extent initialization and checked coordinate origins while retaining one subinterval.
/// # Errors
/// Rejects empty, out-of-extent or unrepresentable logical/physical coordinates.
fn slice_extent(extent: Extent, first: u64, end: u64) -> Result<Extent> {
    if first < extent.logical_start().as_u64() || end > extent.end_logical() || first >= end {
        return Err(Error::InvalidExtentTree);
    }
    let offset = first
        .checked_sub(extent.logical_start().as_u64())
        .ok_or(Error::InvalidExtentTree)?;
    let physical = BlockAddress::new(
        extent
            .physical_start()
            .get()
            .checked_add(offset)
            .ok_or(Error::InvalidExtentTree)?,
    );
    let length = ExtentLength::new(
        u16::try_from(end.checked_sub(first).ok_or(Error::InvalidExtentTree)?)
            .map_err(|_| Error::InvalidExtentTree)?,
    )?;
    match extent.initialization() {
        ExtentInitialization::Initialized => Ok(Extent::initialized(
            LogicalBlock::try_from(first)?,
            length,
            physical,
        )),
        ExtentInitialization::Uninitialized => Ok(Extent::uninitialized(
            LogicalBlock::try_from(first)?,
            length,
            physical,
        )),
    }
}

/// One logical assignment supersedes earlier mappings only within its nonempty interval.
/// # Errors
/// Returns allocation, overlap, coordinate or extent-normalization failure without partial replacement.
fn replace_range(
    tree: &mut MutableExtentTree,
    range: LogicalRange,
    replacement: Option<Extent>,
) -> Result<()> {
    let first = range.first().as_u64();
    let mut extents = Vec::new();
    for old in tree.extents() {
        let start = old.logical_start().as_u64();
        let end = old.end_logical();
        if end <= first || start >= range.end() {
            extents.try_push(*old)?;
            continue;
        }
        if start < first {
            extents.try_push(slice_extent(*old, start, first)?)?;
        }
        if range.end() < end {
            extents.try_push(slice_extent(*old, range.end(), end)?)?;
        }
    }
    if let Some(extent) = replacement {
        if extent.logical_start() != range.first() || extent.end_logical() != range.end() {
            return Err(Error::InvalidExtentTree);
        }
        extents.try_push(extent)?;
    }
    tree.replace_extents(extents)
}

impl MetadataMutation<'_, '_> {
    /// A recorded object claims its exact ordinary inode slot without replacing another generation.
    /// # Errors
    /// Returns reserved identities, conflicting generations, unsupported metadata or bitmap/I/O failure.
    fn recover_created_inode(
        &mut self,
        id: InodeId,
        parent: InodeId,
        encoded: &[u8],
    ) -> Result<ReplayInode> {
        self.volume.superblock.require_namespace_inode(id)?;
        if id == InodeId::ROOT {
            return Err(Error::CannotRemoveRoot);
        }
        let position = InodeBitmapPosition::from_inode(&self.volume.superblock, id)?;
        let group = position.group();
        let descriptor = BlockGroupDescriptor::read_from(
            &mut self.volume.device,
            &self.volume.superblock,
            group,
        )?;
        let index = self.ensure_inode_bitmap_update(group, &descriptor)?;
        let bitmap = self
            .inode_bitmap_updates
            .get_mut(index)
            .ok_or(Error::InvalidInode)?;
        if inode_bitmap_bit_state(&bitmap.bytes, position)? == BitmapBitState::Used {
            let raw = self.volume.read_live_inode_record(id)?;
            if le_u32(raw.raw().bytes(), disk_offset(INODE_GENERATION_OFFSET))?
                != le_u32(encoded, disk_offset(INODE_GENERATION_OFFSET))?
            {
                return Err(Error::UnsupportedJournal);
            }
            let raw = raw.restore_delta_metadata(encoded)?;
            let tree = if matches!(raw.parse()?.storage(), InodeStorage::Extents(_)) {
                Some(self.mutable_extent_tree(&raw.parse()?)?)
            } else {
                None
            };
            if raw.parse()?.kind() == InodeKind::Directory
                && tree.as_ref().is_some_and(|tree| tree.extents().is_empty())
            {
                return Ok(ReplayInode::NewDirectory { raw, parent });
            }
            return Ok(ReplayInode::Live { raw, tree });
        }
        set_inode_bitmap_bit(&mut bitmap.bytes, position, BitmapBitState::Used)?;
        self.record_group_free_inodes_delta(group, -1)?;
        let block_size = self.volume.superblock.block_size();
        let raw = self
            .empty_allocated_inode_record(id)?
            .initialize_delta_inode(encoded, block_size)?;
        if raw.parse()?.kind() == InodeKind::Directory {
            self.record_group_used_dirs_delta(group, 1)?;
            Ok(ReplayInode::NewDirectory { raw, parent })
        } else {
            let tree = if matches!(raw.parse()?.storage(), InodeStorage::Extents(_)) {
                Some(self.mutable_extent_tree(&raw.parse()?)?)
            } else {
                None
            };
            Ok(ReplayInode::Live { raw, tree })
        }
    }

    /// Reference changes visit mapped allocation units only; sparse logical holes consume no work.
    /// # Errors
    /// Rejects invalid physical bounds, reference underflow, overflow or allocation failure.
    fn replay_reference_delta(&mut self, extent: Extent, sign: i32) -> Result<()> {
        let mut first = extent.physical_start().get();
        let end = first
            .checked_add(extent.len().as_u64())
            .ok_or(Error::InvalidExtentTree)?;
        if end > self.volume.superblock.block_count().as_u64() {
            return Err(Error::InvalidExtentTree);
        }
        while first < end {
            let cluster = self
                .volume
                .superblock
                .cluster_of_block(BlockAddress::new(first))?;
            let cluster_end = self
                .volume
                .superblock
                .first_block_of_cluster(cluster)?
                .get()
                .checked_add(u64::from(
                    self.volume.superblock.blocks_in_cluster(cluster)?,
                ))
                .ok_or(Error::ArithmeticOverflow)?;
            let last = end.min(cluster_end);
            let count = i32::try_from(last.checked_sub(first).ok_or(Error::InvalidExtentTree)?)
                .map_err(|_| Error::ArithmeticOverflow)?;
            self.record_cluster_reference_delta(
                cluster,
                count.checked_mul(sign).ok_or(Error::ArithmeticOverflow)?,
            )?;
            first = last;
        }
        Ok(())
    }

    /// Bitmap counts change only when the final reference postcondition changes one physical bit.
    /// # Errors
    /// Rejects malformed bitmaps, accounting overflow, missing ownership or suspended reads.
    fn reconcile_replay_cluster(&mut self, cluster: ClusterAddress) -> Result<()> {
        let wanted = if self.staged_cluster_reference_count(cluster)? == 0 {
            BitmapBitState::Free
        } else {
            BitmapBitState::Used
        };
        let position = ClusterBitmapPosition::from_cluster(&self.volume.superblock, cluster)?;
        let group = position.group();
        let descriptor = BlockGroupDescriptor::read_from(
            &mut self.volume.device,
            &self.volume.superblock,
            group,
        )?;
        let index = self.ensure_block_bitmap_update(group, &descriptor)?;
        let bitmap = self
            .block_bitmap_updates
            .get_mut(index)
            .ok_or(Error::InvalidSuperblock)?;
        let prior = cluster_bitmap_bit_state(&bitmap.bytes, position)?;
        if prior != wanted {
            set_cluster_bitmap_bit(&mut bitmap.bytes, position, wanted)?;
            let delta = if wanted == BitmapBitState::Free {
                1
            } else {
                -1
            };
            self.record_group_free_clusters_delta(group, FreeClusterDelta::from_i64(delta))?;
            self.free_clusters_delta = self.free_clusters_delta.checked_add(delta)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Fails if overlapping assignments lose surviving offsets or repeated replay changes poststates.
    #[test]
    fn range_assignments_preserve_fragments_initialization_and_idempotence() {
        let result = (|| -> Result<()> {
            let first = Extent::initialized(
                LogicalBlock::from_u32(2),
                ExtentLength::new(8)?,
                BlockAddress::new(100),
            );
            let second = Extent::uninitialized(
                LogicalBlock::from_u32(14),
                ExtentLength::new(4)?,
                BlockAddress::new(200),
            );
            let mut tree = MutableExtentTree::from_extents(vec![first, second])?;
            let replacement = Extent::uninitialized(
                LogicalBlock::from_u32(4),
                ExtentLength::new(12)?,
                BlockAddress::new(300),
            );
            let range = LogicalRange::new(4, 12)?;
            for _ in 0..2 {
                replace_range(&mut tree, range, Some(replacement))?;
                assert_eq!(
                    tree.extents(),
                    [
                        Extent::initialized(
                            LogicalBlock::from_u32(2),
                            ExtentLength::new(2)?,
                            BlockAddress::new(100)
                        ),
                        replacement,
                        Extent::uninitialized(
                            LogicalBlock::from_u32(16),
                            ExtentLength::new(2)?,
                            BlockAddress::new(202)
                        )
                    ]
                );
            }
            let range = LogicalRange::new(3, 14)?;
            for _ in 0..2 {
                replace_range(&mut tree, range, None)?;
                assert_eq!(
                    tree.extents(),
                    [
                        Extent::initialized(
                            LogicalBlock::from_u32(2),
                            ExtentLength::new(1)?,
                            BlockAddress::new(100)
                        ),
                        Extent::uninitialized(
                            LogicalBlock::from_u32(17),
                            ExtentLength::new(1)?,
                            BlockAddress::new(203)
                        )
                    ]
                );
            }
            replace_range(&mut tree, LogicalRange::new(0, u32::MAX)?, None)?;
            assert!(tree.extents().is_empty());
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }
}
