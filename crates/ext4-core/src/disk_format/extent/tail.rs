//! Depth-bounded allocation traversal and right-edge extent pruning.

use super::*;

/// An allocation-bearing extent-tree item, independent of payload initialization.
pub(crate) enum ExtentAllocation {
    /// Data allocation described by a leaf entry.
    Data(Extent),
    /// One external routing or leaf block.
    Metadata(BlockAddress),
}

/// One resident path node; external blocks remain owned until their parent entry is removed.
#[derive(Debug)]
struct PathNode {
    /// None identifies the inode-resident root.
    block: Option<BlockAddress>,
    /// Complete on-disk node image.
    bytes: Vec<u8>,
    /// Next entry for bounded depth-first traversal.
    next: usize,
}

impl PathNode {
    /// Checks entry capacity, local ordering, and depth before interpreting an entry.
    /// # Errors
    /// Returns an error for malformed node geometry, entries, or child pointers.
    fn validate(&self, expected: Option<u16>) -> Result<u16> {
        let mut extents = Vec::new();
        let depth = parse_node(&self.bytes, expected, &mut extents)?;
        let capacity = usize::from(le_u16(&self.bytes, disk_offset(4))?);
        let available = self
            .bytes
            .len()
            .checked_sub(EXTENT_HEADER_SIZE)
            .ok_or(Error::InvalidExtentTree)?;
        if capacity == 0 || capacity > available / EXTENT_ENTRY_SIZE {
            return Err(Error::InvalidExtentTree);
        }
        let entries = header_entries(&self.bytes)?;
        if depth > 0 && entries == 0 {
            return Err(Error::InvalidExtentTree);
        }
        let mut previous = None;
        for index in 0..entries {
            let key = le_u32(&self.bytes, disk_offset(entry_offset(index)?))?;
            if previous.is_some_and(|previous| key <= previous) {
                return Err(Error::InvalidExtentTree);
            }
            previous = Some(key);
        }
        Ok(depth)
    }

    /// Reads a validated index entry's external block address.
    /// # Errors
    /// Returns an error for an absent entry or zero pointer.
    fn child(&self, index: usize) -> Result<BlockAddress> {
        if index >= header_entries(&self.bytes)? {
            return Err(Error::InvalidExtentTree);
        }
        let offset = entry_offset(index)?;
        let low = u64::from(le_u32(
            &self.bytes,
            disk_offset(offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?),
        )?);
        let high = u64::from(le_u16(
            &self.bytes,
            disk_offset(offset.checked_add(8).ok_or(Error::ArithmeticOverflow)?),
        )?);
        let block = BlockAddress::new(low | high << 32);
        if block.get() == 0 {
            return Err(Error::InvalidExtentTree);
        }
        Ok(block)
    }
}

/// Loads one child while retaining at most one node per tree depth.
/// # Errors
/// Returns an error for a cycle, malformed node, failed checksum, allocation, or suspended read.
fn load_child(
    path: &[PathNode],
    block: BlockAddress,
    depth: u16,
    block_size: BlockSize,
    reader: &mut impl ExtentNodeReader,
    context: ExtentTreeContext,
) -> Result<PathNode> {
    if path.len() > usize::from(MAX_EXTENT_DEPTH)
        || path.iter().any(|node| node.block == Some(block))
    {
        return Err(Error::InvalidExtentTree);
    }
    let mut bytes = memory::repeated_vec(
        0,
        usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    reader.read_extent_bytes(block_size.offset_of(block)?, &mut bytes)?;
    verify_external_extent_block_checksum(context, &bytes)?;
    let node = PathNode {
        block: Some(block),
        bytes,
        next: 0,
    };
    node.validate(Some(depth))?;
    Ok(node)
}

/// Visits all allocation without retaining the complete extent tree.
/// # Errors
/// Returns an error for malformed or overlapping extents, failed reads/checksums, or visitor failure.
pub(crate) fn visit_allocations(
    root: &InodeExtentRoot,
    block_size: BlockSize,
    reader: &mut impl ExtentNodeReader,
    context: ExtentTreeContext,
    mut visit: impl FnMut(ExtentAllocation) -> Result<()>,
) -> Result<()> {
    let root = PathNode {
        block: None,
        bytes: memory::copied_slice(root.bytes())?,
        next: 0,
    };
    root.validate(None)?;
    let mut path = Vec::new();
    path.try_push(root)?;
    let mut previous_end = 0;
    while let Some(node) = path.last_mut() {
        if node.next == header_entries(&node.bytes)? {
            path.pop();
            continue;
        }
        let index = node.next;
        node.next = node.next.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        let depth = le_u16(&node.bytes, disk_offset(6))?;
        if depth == 0 {
            let extent = parse_extent(&node.bytes, entry_offset(index)?)?;
            if extent.logical_start().as_u64() < previous_end
                || extent.end_logical() > u64::from(u32::MAX).saturating_add(1)
            {
                return Err(Error::InvalidExtentTree);
            }
            previous_end = extent.end_logical();
            visit(ExtentAllocation::Data(extent))?;
        } else {
            let block = node.child(index)?;
            let child = load_child(
                &path,
                block,
                depth.checked_sub(1).ok_or(Error::InvalidExtentTree)?,
                block_size,
                reader,
                context,
            )?;
            visit(ExtentAllocation::Metadata(block))?;
            path.try_push(child)?;
        }
    }
    Ok(())
}

/// Validated rightmost path; pruning never rebuilds unrelated extent nodes.
#[derive(Debug)]
pub(crate) struct ExtentTail {
    /// Root through the rightmost leaf, bounded by MAX_EXTENT_DEPTH + 1.
    path: Vec<PathNode>,
    /// Checksum identity retained for modified external nodes.
    context: ExtentTreeContext,
}

impl ExtentTail {
    /// Loads only the path containing the final allocated logical block.
    /// # Errors
    /// Returns a validation, checksum, allocation, or read error.
    pub(crate) fn load(
        root: &InodeExtentRoot,
        block_size: BlockSize,
        reader: &mut impl ExtentNodeReader,
        context: ExtentTreeContext,
    ) -> Result<Self> {
        let root = PathNode {
            block: None,
            bytes: memory::copied_slice(root.bytes())?,
            next: 0,
        };
        let mut depth = root.validate(None)?;
        let mut path = Vec::new();
        path.try_push(root)?;
        while depth != 0 {
            let node = path.last().ok_or(Error::InvalidExtentTree)?;
            let last = header_entries(&node.bytes)?
                .checked_sub(1)
                .ok_or(Error::InvalidExtentTree)?;
            let block = node.child(last)?;
            depth = depth.checked_sub(1).ok_or(Error::InvalidExtentTree)?;
            let child = load_child(&path, block, depth, block_size, reader, context)?;
            path.try_push(child)?;
        }
        Ok(Self { path, context })
    }

    /// Final extent, or None for an empty inode root.
    /// # Errors
    /// Returns an error if the resident leaf is malformed.
    pub(crate) fn last(&self) -> Result<Option<Extent>> {
        let node = self.path.last().ok_or(Error::InvalidExtentTree)?;
        let Some(index) = header_entries(&node.bytes)?.checked_sub(1) else {
            return Ok(None);
        };
        Ok(Some(parse_extent(&node.bytes, entry_offset(index)?)?))
    }

    /// Trims one suffix and releases only nodes made empty by that removal.
    /// # Errors
    /// Returns an error if the suffix is empty/invalid or serialization/allocation fails.
    pub(crate) fn trim(mut self, keep: u16) -> Result<(SerializedExtentTree, Vec<BlockAddress>)> {
        let extent = self.last()?.ok_or(Error::InvalidExtentTree)?;
        if keep >= extent.len().as_u16() {
            return Err(Error::InvalidExtentTree);
        }
        let leaf = self.path.last_mut().ok_or(Error::InvalidExtentTree)?;
        let last = header_entries(&leaf.bytes)?
            .checked_sub(1)
            .ok_or(Error::InvalidExtentTree)?;
        if keep != 0 {
            let retained = Extent {
                len: ExtentLength::new(keep)?,
                ..extent
            };
            write_extent_entry(&mut leaf.bytes, entry_offset(last)?, retained)?;
        } else {
            remove_last_entry(leaf)?;
        }
        let mut released = Vec::new();
        let mut external_blocks = Vec::new();
        while self.path.len() > 1 {
            let mut node = self.path.pop().ok_or(Error::InvalidExtentTree)?;
            let block = node.block.ok_or(Error::InvalidExtentTree)?;
            if header_entries(&node.bytes)? == 0 {
                released.try_push(block)?;
                remove_last_entry(self.path.last_mut().ok_or(Error::InvalidExtentTree)?)?;
            } else {
                refresh_external_extent_block_checksum(self.context, &mut node.bytes)?;
                external_blocks.try_push(SerializedExtentBlock {
                    block,
                    bytes: node.bytes,
                })?;
                break;
            }
        }
        let root = self.path.first_mut().ok_or(Error::InvalidExtentTree)?;
        if header_entries(&root.bytes)? == 0 {
            write_header(&mut root.bytes, 0, 4, 0)?;
        }
        let mut inode_root = [0; 60];
        memory::copy_exact(&mut inode_root, &root.bytes)?;
        Ok((
            SerializedExtentTree {
                inode_root,
                external_blocks,
            },
            released,
        ))
    }
}

/// Drops the rightmost entry without exposing stale bytes as active routing.
/// # Errors
/// Returns an error for an empty or malformed node.
fn remove_last_entry(node: &mut PathNode) -> Result<()> {
    let count = header_entries(&node.bytes)?
        .checked_sub(1)
        .ok_or(Error::InvalidExtentTree)?;
    let offset = entry_offset(count)?;
    node.bytes
        .get_mut(
            offset
                ..offset
                    .checked_add(EXTENT_ENTRY_SIZE)
                    .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::InvalidExtentTree)?
        .fill(0);
    put_le_u16(
        &mut node.bytes,
        disk_offset(2),
        u16::try_from(count).map_err(|_| Error::ArithmeticOverflow)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact external-node images; reads are observed without granting mutation authority.
    struct NodeImages {
        /// Routing node followed by two leaf nodes.
        images: Vec<Vec<u8>>,
        /// Physical block identities read during the last path walk.
        reads: Vec<u64>,
    }

    impl ExtentNodeReader for NodeImages {
        fn read_extent_bytes(&mut self, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
            let block = offset
                .get()
                .checked_div(1024)
                .ok_or(Error::ArithmeticOverflow)?;
            self.reads.try_push(block)?;
            let index = usize::try_from(block.checked_sub(1).ok_or(Error::InvalidExtentTree)?)
                .map_err(|_| Error::ArithmeticOverflow)?;
            memory::copy_exact(out, self.images.get(index).ok_or(Error::InvalidExtentTree)?)
        }
    }

    /// # Panics
    /// Panics if right-edge pruning reads an unrelated leaf, loses retained data, or leaks a node.
    #[test]
    fn prune_right_edge_retains_left_subtree_and_collapses_empty_ancestors() {
        let result = (|| -> Result<()> {
            let mut root = [0; 60];
            write_header(&mut root, 1, 4, 2)?;
            put_le_u32(&mut root, disk_offset(16), 1)?;
            let mut images = Vec::new();
            for (depth, count) in [(1, 2), (0, 1), (0, 1)] {
                let mut bytes = memory::repeated_vec(0, 1024)?;
                write_header(&mut bytes, count, 84, depth)?;
                images.try_push(bytes)?;
            }
            let routing = images.get_mut(0).ok_or(Error::InvalidExtentTree)?;
            put_le_u32(routing, disk_offset(16), 2)?;
            put_le_u32(routing, disk_offset(24), 5)?;
            put_le_u32(routing, disk_offset(28), 3)?;
            for (index, logical, length, physical) in [(1, 0, 3, 100), (2, 5, 2, 200)] {
                let leaf = images.get_mut(index).ok_or(Error::InvalidExtentTree)?;
                put_le_u32(leaf, disk_offset(12), logical)?;
                put_le_u16(leaf, disk_offset(16), length)?;
                put_le_u32(leaf, disk_offset(20), physical)?;
            }
            let block_size = BlockSize::from_superblock_log(0)?;
            let mut reader = NodeImages {
                images,
                reads: Vec::new(),
            };
            for (keep, expected_reads, expected_released) in [
                (0, [1, 3], alloc::vec![BlockAddress::new(3)]),
                (1, [1, 2], alloc::vec![]),
                (
                    0,
                    [1, 2],
                    alloc::vec![BlockAddress::new(2), BlockAddress::new(1)],
                ),
            ] {
                reader.reads.clear();
                let tail = ExtentTail::load(
                    &InodeExtentRoot::from_bytes(root),
                    block_size,
                    &mut reader,
                    ExtentTreeContext::none(),
                )?;
                assert_eq!(reader.reads, expected_reads);
                let (changed, released) = tail.trim(keep)?;
                assert_eq!(released, expected_released);
                root = *changed.inode_root();
                for image in changed.external_blocks() {
                    let index = usize::try_from(
                        image
                            .block()
                            .get()
                            .checked_sub(1)
                            .ok_or(Error::InvalidExtentTree)?,
                    )
                    .map_err(|_| Error::ArithmeticOverflow)?;
                    memory::copy_exact(
                        reader
                            .images
                            .get_mut(index)
                            .ok_or(Error::InvalidExtentTree)?,
                        image.bytes(),
                    )?;
                }
            }
            assert_eq!(header_entries(&root)?, 0);
            assert_eq!(le_u16(&root, disk_offset(6))?, 0);
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }
}
