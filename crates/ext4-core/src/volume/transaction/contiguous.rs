//! Bounded initialization of a physically contiguous, initialized file prefix.

use super::*;

/// Largest payload owned by one contiguous-initialization transaction.
const INITIALIZATION_BYTES: usize = 65_536;
/// Immutable zero source lives in the image, independently of the small kernel stack.
static INITIALIZATION_ZEROES: [u8; INITIALIZATION_BYTES] = [0; INITIALIZATION_BYTES];

impl MutationResolvePass<'_, '_, '_> {
    /// Appends zero-initialized blocks without changing the physical address of the old prefix.
    /// A call initializes at most 64 KiB and acknowledges only after its home checkpoint.
    /// Callers exclude changes to this file's mapping across calls and resume from the returned
    /// initialized length. Logical EOF is retained in the same transaction. Unclaimed tail space
    /// remains free and is revalidated by each transaction.
    ///
    /// # Errors
    /// Rejects non-block-aligned bounds, protected or noncontiguous prefixes, allocation failure,
    /// and a chosen tail that would make the complete file physically discontinuous. Failure
    /// rejects this entire resolve pass before any ordered write or metadata publication.
    pub fn initialize_contiguous_file_tail(
        &mut self,
        file: TransactionFile,
        target: FileSize,
        retained: Option<super::super::node::ContiguousFileStorage>,
    ) -> Result<super::super::node::ContiguousFileStorage> {
        self.edit(|pass| {
            let size = pass.mutation.volume.superblock.block_size();
            let raw = pass.mutation.raw_inode_for_policy(file.inode())?;
            let inode = raw.parse()?;
            let logical_size = inode.size();
            let previous = pass.contiguous_file_allocation(file.id(), retained)?;
            let mut initialized = previous;
            let current = previous.map_or(FileSize::from_bytes(0), |storage| {
                storage.initialized_length()
            });
            let width = u64::from(size.bytes());
            if target.bytes() < current.bytes()
                || target.bytes() == 0
                || !target.bytes().is_multiple_of(width)
                || !current.bytes().is_multiple_of(width)
            {
                return Err(Error::InvalidWriteRange);
            }
            let remaining = target
                .bytes()
                .checked_sub(current.bytes())
                .ok_or(Error::ArithmeticOverflow)?;
            let count =
                usize::try_from(remaining.min(
                    u64::try_from(INITIALIZATION_BYTES).map_err(|_| Error::ArithmeticOverflow)?,
                ))
                .map_err(|_| Error::ArithmeticOverflow)?;
            if count != 0 {
                let index = pass.mutation.ensure_inode_update(file.inode())?;
                let mut raw = pass.mutation.staged_live_inode(index)?;
                pass.mutation.require_extent_storage(&mut raw)?;
                let mut tree = pass.mutation.mutable_extent_tree(&raw.parse()?)?;
                let origin = if let Some(previous) = previous {
                    // Admission above established whole-block coordinates for the old prefix.
                    BlockAddress::new(
                        previous
                            .physical()
                            .get()
                            .checked_div(width)
                            .ok_or(Error::InvalidClusterGeometry)?,
                    )
                } else {
                    if !tree.extents().is_empty() {
                        return Err(Error::UnsupportedInodeMutation);
                    }
                    let cluster_bytes =
                        u64::from(pass.mutation.volume.superblock.cluster_size().bytes());
                    let clusters =
                        crate::ClusterCount::new(round_up_div(target.bytes(), cluster_bytes)?)?;
                    let first = pass.mutation.find_free_cluster_run(clusters)?;
                    pass.mutation
                        .volume
                        .superblock
                        .first_block_of_cluster(first)?
                };
                let first = current
                    .bytes()
                    .checked_div(width)
                    .ok_or(Error::InvalidClusterGeometry)?;
                let end = current
                    .bytes()
                    .checked_add(u64::try_from(count).map_err(|_| Error::ArithmeticOverflow)?)
                    .and_then(|end| end.checked_div(width))
                    .ok_or(Error::ArithmeticOverflow)?;
                for logical in first..end {
                    let physical = BlockAddress::new(
                        origin
                            .get()
                            .checked_add(logical)
                            .ok_or(Error::ArithmeticOverflow)?,
                    );
                    let logical = LogicalBlock::try_from(logical)?;
                    match tree.allocated_block(logical)? {
                        Some(existing) if existing == physical => {}
                        Some(_) => return Err(Error::ClusterReferenceConflict),
                        None => {
                            pass.mutation
                                .allocate_extent_block_at(&tree, logical, physical)?;
                            tree.insert_uninitialized(logical, physical)?;
                        }
                    }
                }
                pass.mutation.stage_extent_tree(&mut raw, tree)?;
                // The old physical prefix is already initialized. Advancing the provisional
                // EOF prevents generic write-gap zeroing from overwriting its retained bytes.
                raw.set_encoded_size(
                    pass.mutation
                        .volume
                        .superblock
                        .inode_data_encoding()
                        .encode_file_size(current)?,
                )?;
                pass.mutation.replace_live_inode(index, raw)?;
                pass.write_file_range(
                    file,
                    FileOffset::from_bytes(current.bytes()),
                    INITIALIZATION_ZEROES
                        .get(..count)
                        .ok_or(Error::InvalidWriteRange)?,
                )?;
                let mut raw = pass.mutation.staged_live_inode(index)?;
                let mut tree = pass.mutation.mutable_extent_tree(&raw.parse()?)?;
                tree.set_initialized_prefix(round_up_div(logical_size.bytes(), width)?)?;
                pass.mutation.stage_extent_tree(&mut raw, tree)?;
                raw.set_encoded_size(
                    pass.mutation
                        .volume
                        .superblock
                        .inode_data_encoding()
                        .encode_file_size(logical_size)?,
                )?;
                pass.mutation.replace_live_inode(index, raw)?;
                initialized = Some(super::super::node::ContiguousFileStorage {
                    mount: *pass.mutation.volume.mount.ok_or(Error::InvalidWriteRange)?,
                    inode: inode.id(),
                    generation: inode.generation(),
                    physical: size.offset_of(origin)?,
                    initialized_length: FileSize::from_bytes(
                        end.checked_mul(width).ok_or(Error::ArithmeticOverflow)?,
                    ),
                    logical_size,
                });
            } else {
                let index = pass.mutation.ensure_inode_update(file.inode())?;
                let mut raw = pass.mutation.staged_live_inode(index)?;
                raw.touch_metadata(pass.now)?;
                pass.mutation.replace_live_inode(index, raw)?;
            }
            let initialized = pass.retained_contiguous_file_storage(
                file.id(),
                initialized.ok_or(Error::InvalidWriteRange)?,
            )?;
            if previous.is_some_and(|previous| previous.physical() != initialized.physical()) {
                return Err(Error::ClusterReferenceConflict);
            }
            pass.mutation.completion_durability = MutationCompletionDurability::HomeCheckpoint;
            Ok(initialized)
        })
    }

    /// Changes logical EOF within a separately validated initialized physical allocation.
    /// Allocation and payload bytes remain unchanged. Extents past EOF are unwritten, preserving
    /// the independent raw initialization fact held by the fixed-map owner. That owner excludes
    /// allocation retirement, inode reuse and independent mapping/protection changes.
    /// # Errors
    /// Rejects a changed/non-initialized map, an excessive EOF, inode encoding or metadata failure.
    pub fn set_contiguous_file_eof(
        &mut self,
        file: TransactionFile,
        size: FileSize,
        initialized: super::super::node::ContiguousFileStorage,
    ) -> Result<super::super::node::ContiguousFileStorage> {
        self.edit(|pass| {
            let storage = pass.retained_contiguous_file_storage(file.id(), initialized)?;
            if size > storage.initialized_length() {
                return Err(Error::InvalidWriteRange);
            }
            let encoded = pass
                .mutation
                .volume
                .superblock
                .inode_data_encoding()
                .encode_file_size(size)?;
            let index = pass.mutation.ensure_inode_update(file.inode())?;
            let mut raw = pass.mutation.staged_live_inode(index)?;
            let mut tree = pass.mutation.mutable_extent_tree(&raw.parse()?)?;
            tree.set_initialized_prefix(round_up_div(
                size.bytes(),
                u64::from(pass.mutation.volume.superblock.block_size().bytes()),
            )?)?;
            pass.mutation.stage_extent_tree(&mut raw, tree)?;
            raw.set_encoded_size(encoded)?;
            raw.touch_contents(pass.now)?;
            pass.mutation.replace_live_inode(index, raw)?;
            pass.retained_contiguous_file_storage(file.id(), initialized)
        })
    }
}
