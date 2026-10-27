//! Bounded initialization of a physically contiguous, initialized file prefix.

use super::*;

/// Largest payload owned by one contiguous-initialization transaction.
const INITIALIZATION_BYTES: usize = 65_536;
/// Immutable zero source lives in the image, independently of the small kernel stack.
static INITIALIZATION_ZEROES: [u8; INITIALIZATION_BYTES] = [0; INITIALIZATION_BYTES];

impl MutationResolvePass<'_, '_, '_> {
    /// Appends zero-initialized blocks without changing the physical address of the old prefix.
    /// A call initializes at most 64 KiB and acknowledges only after its home checkpoint.
    /// Callers keep allocation exclusion across calls and resume from the returned length.
    ///
    /// # Errors
    /// Rejects non-block-aligned bounds, protected or noncontiguous prefixes, allocation failure,
    /// and a chosen tail that would make the complete file physically discontinuous. Failure
    /// rejects this entire resolve pass before any ordered write or metadata publication.
    pub fn initialize_contiguous_file_tail(
        &mut self,
        file: TransactionFile,
        target: FileSize,
    ) -> Result<super::super::node::ContiguousFileStorage> {
        self.edit(|pass| {
            let size = pass.mutation.volume.superblock.block_size();
            let raw = pass.mutation.raw_inode_for_policy(file.inode())?;
            let inode = raw.parse()?;
            let current = inode.size();
            let width = u64::from(size.bytes());
            if target.bytes() < current.bytes() || target.bytes() == 0
                || !target.bytes().is_multiple_of(width)
                || !current.bytes().is_multiple_of(width) {
                return Err(Error::InvalidWriteRange);
            }
            let previous = if current.bytes() == 0 { None }
                else { Some(pass.contiguous_file_storage(file.id())?) };
            let remaining = target.bytes().checked_sub(current.bytes()).ok_or(Error::ArithmeticOverflow)?;
            let count = usize::try_from(remaining.min(u64::try_from(INITIALIZATION_BYTES)
                .map_err(|_| Error::ArithmeticOverflow)?)).map_err(|_| Error::ArithmeticOverflow)?;
            if count != 0 {
                let index = pass.mutation.ensure_inode_update(file.inode())?;
                let mut raw = pass.mutation.staged_live_inode(index)?;
                pass.mutation.require_extent_storage(&mut raw)?;
                let mut tree = pass.mutation.mutable_extent_tree(&raw.parse()?)?;
                let origin = if let Some(previous) = previous {
                    // Admission above established whole-block coordinates for the old prefix.
                    BlockAddress::new(previous.physical().get().checked_div(width).ok_or(Error::InvalidClusterGeometry)?)
                } else {
                    if !tree.extents().is_empty() { return Err(Error::UnsupportedInodeMutation); }
                    let cluster_bytes = u64::from(pass.mutation.volume.superblock.cluster_size().bytes());
                    let clusters = crate::ClusterCount::new(round_up_div(target.bytes(), cluster_bytes)?)?;
                    let first = pass.mutation.find_free_cluster_run(clusters)?;
                    pass.mutation.volume.superblock.first_block_of_cluster(first)?
                };
                let first = current.bytes().checked_div(width).ok_or(Error::InvalidClusterGeometry)?;
                let end = current.bytes().checked_add(u64::try_from(count).map_err(|_| Error::ArithmeticOverflow)?)
                    .and_then(|end| end.checked_div(width)).ok_or(Error::ArithmeticOverflow)?;
                for logical in first..end {
                    let physical = BlockAddress::new(origin.get().checked_add(logical).ok_or(Error::ArithmeticOverflow)?);
                    let logical = LogicalBlock::try_from(logical)?;
                    match tree.allocated_block(logical)? {
                        Some(existing) if existing == physical => {}
                        Some(_) => return Err(Error::ClusterReferenceConflict),
                        None => {
                            pass.mutation.allocate_extent_block_at(&tree, logical, physical)?;
                            tree.insert_uninitialized(logical, physical)?;
                        }
                    }
                }
                pass.mutation.stage_extent_tree(&mut raw, tree)?;
                pass.mutation.replace_live_inode(index, raw)?;
                pass.write_file_range(file, FileOffset::from_bytes(current.bytes()),
                    INITIALIZATION_ZEROES.get(..count).ok_or(Error::InvalidWriteRange)?)?;
            } else {
                let index = pass.mutation.ensure_inode_update(file.inode())?;
                let mut raw = pass.mutation.staged_live_inode(index)?;
                raw.touch_metadata(pass.now)?;
                pass.mutation.replace_live_inode(index, raw)?;
            }
            let initialized = pass.contiguous_file_storage(file.id())?;
            if previous.is_some_and(|previous| previous.physical() != initialized.physical()) {
                return Err(Error::ClusterReferenceConflict);
            }
            pass.mutation.completion_durability = MutationCompletionDurability::HomeCheckpoint;
            Ok(initialized)
        })
    }
}
