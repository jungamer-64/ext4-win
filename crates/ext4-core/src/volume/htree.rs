//! Bounded HTree routing shared by committed and staged directory access.

use alloc::vec::Vec;

use crate::disk_format::dir::{DxEntry, DxIndex, DxIndexSplit, HtreeHashRange};
use crate::disk_format::extent::LogicalBlock;
use crate::memory::FallibleVec;
use crate::{Error, Result};

/// A resident routing table and the selected child within its parent interval.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct HtreePathLevel<Location> {
    /// Logical node, with zero reserved for the root.
    logical: LogicalBlock,
    /// Write location for staged paths, or unit for readers.
    location: Location,
    /// Validated routing table.
    index: DxIndex,
    /// Child chosen within the table.
    selected: usize,
}

impl<Location: Copy> HtreePathLevel<Location> {
    /// Returns the associated location for an index rewrite.
    pub(super) const fn location(&self) -> Location {
        self.location
    }

    /// Borrows the routing table for serialization.
    pub(super) const fn index(&self) -> &DxIndex {
        &self.index
    }

    /// Inserts a split sibling after the child that was selected for update.
    /// # Errors
    /// Returns invalid index ordering, allocation or format capacity failures.
    pub(super) fn insert_after(&mut self, sibling: DxEntry) -> Result<Option<DxIndexSplit>> {
        self.index.insert_after(self.selected, sibling)
    }
}

/// One active route through authenticated tables, including a partially loaded descent.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct HtreePath<Location = ()> {
    /// Resident levels bounded by the validated root depth.
    levels: Vec<HtreePathLevel<Location>>,
    /// Number of interior tables expected below the root.
    depth: u8,
    /// Hash used to choose the next descendant during the active descent.
    descend_major: u32,
}

impl<Location: Copy> HtreePath<Location> {
    /// Begins a root-to-leaf route by selecting the initial root child.
    /// # Errors
    /// Returns an invalid logical root or fallible allocation error.
    pub(super) fn new(index: DxIndex, depth: u8, major: u32, location: Location) -> Result<Self> {
        let selected = index.select(major);
        let mut levels = Vec::new();
        levels.try_push(HtreePathLevel {
            logical: LogicalBlock::try_from(0_u64)?,
            location,
            index,
            selected,
        })?;
        Ok(Self {
            levels,
            depth,
            descend_major: major,
        })
    }

    /// Returns the root's validated interior depth.
    pub(super) const fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns the number of resident levels for bottom-up rewriting.
    pub(super) fn level_count(&self) -> usize {
        self.levels.len()
    }

    /// Whether extending this route requires growing the index root.
    pub(super) fn all_indexes_full(&self) -> bool {
        self.levels.iter().all(|level| level.index.is_full())
    }

    /// Supplies the one selected table for a staged index split.
    pub(super) fn level_mut(&mut self, level: usize) -> Option<&mut HtreePathLevel<Location>> {
        self.levels.get_mut(level)
    }

    /// Copies the bounded read route for collision-page rewind.
    /// # Errors
    /// Returns allocation failure while copying resident tables.
    pub(super) fn try_clone(&self) -> Result<Self> {
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(self.levels.len())
            .map_err(|_| Error::OutOfMemory)?;
        for level in &self.levels {
            levels.try_push(HtreePathLevel {
                logical: level.logical,
                location: level.location,
                index: level.index.try_clone()?,
                selected: level.selected,
            })?;
        }
        Ok(Self {
            levels,
            depth: self.depth,
            descend_major: self.descend_major,
        })
    }

    /// Selects the next child and rejects references back into resident index blocks.
    /// # Errors
    /// Returns a missing or cyclic route or invalid logical coordinate.
    fn child(&self) -> Result<LogicalBlock> {
        let block = self
            .levels
            .last()
            .and_then(|level| level.index.entry(level.selected))
            .ok_or(Error::InvalidDirectoryEntry)?
            .block();
        let logical = LogicalBlock::try_from(u64::from(block))?;
        if self.levels.iter().any(|level| level.logical == logical) {
            return Err(Error::InvalidDirectoryEntry);
        }
        Ok(logical)
    }

    /// Returns the one index block needed to resume this route.
    /// # Errors
    /// Returns a missing or cyclic route.
    pub(super) fn pending_index(&self) -> Result<Option<LogicalBlock>> {
        if self.levels.len() <= usize::from(self.depth) {
            Ok(Some(self.child()?))
        } else {
            Ok(None)
        }
    }

    /// Accepts only the currently selected interior table.
    /// # Errors
    /// Returns routing, depth or fallible allocation failure.
    pub(super) fn append_index(
        &mut self,
        logical: LogicalBlock,
        index: DxIndex,
        location: Location,
    ) -> Result<()> {
        if self.pending_index()? != Some(logical) {
            return Err(Error::InvalidDirectoryEntry);
        }
        let selected = index.select(self.descend_major);
        self.levels.try_push(HtreePathLevel {
            logical,
            location,
            index,
            selected,
        })
    }

    /// Completes a selected route using the caller's authority to read each interior table.
    /// # Errors
    /// Returns selected-route, read, validation or fallible allocation failure.
    pub(super) fn descend_with(
        &mut self,
        mut read: impl FnMut(LogicalBlock) -> Result<(DxIndex, Location)>,
    ) -> Result<()> {
        while let Some(logical) = self.pending_index()? {
            let (index, location) = read(logical)?;
            self.append_index(logical, index, location)?;
        }
        Ok(())
    }

    /// Returns the currently selected leaf of a completed route.
    /// # Errors
    /// Returns an incomplete, missing or cyclic route.
    pub(super) fn leaf(&self) -> Result<LogicalBlock> {
        if self.levels.len() <= usize::from(self.depth) {
            return Err(Error::InvalidDirectoryEntry);
        }
        self.child()
    }
    /// Returns the effective hash boundary for the currently selected leaf.
    /// # Errors
    ///
    /// Returns an error when the path is empty or its selected route is absent.
    pub(super) fn boundary(&self) -> Result<u32> {
        if self.levels.is_empty() {
            return Err(Error::InvalidDirectoryEntry);
        }
        let mut boundary = 0;
        for level in &self.levels {
            boundary = level.index.route_boundary(level.selected, boundary)?;
        }
        Ok(boundary)
    }

    /// Reconstructs the primary-hash interval selected by every resident path level.
    /// # Errors
    ///
    /// Returns an error when any selected route is absent or violates its parent interval.
    pub(super) fn hash_range(&self) -> Result<HtreeHashRange> {
        let mut range = HtreeHashRange::root();
        for level in &self.levels {
            range = range.descend(&level.index, level.selected)?;
        }
        Ok(range)
    }
    /// Next leaf boundary, derivable from resident ancestors without reading the next leaf.
    pub(super) fn next_boundary(&self) -> Option<u32> {
        self.levels.iter().rev().find_map(|level| {
            level
                .selected
                .checked_add(1)
                .and_then(|index| level.index.entry(index))
                .map(|entry| entry.hash())
        })
    }

    /// Selects the next subtree once; descendant reads are separate resumable stages.
    /// # Errors
    /// Returns invalid path or arithmetic errors.
    pub(super) fn advance_route(&mut self) -> Result<bool> {
        let Some(index) = self.levels.iter().rposition(|level| {
            level
                .selected
                .checked_add(1)
                .is_some_and(|next| next < level.index.len())
        }) else {
            return Ok(false);
        };
        let level = self
            .levels
            .get_mut(index)
            .ok_or(Error::InvalidDirectoryEntry)?;
        level.selected = level
            .selected
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        self.levels
            .truncate(index.checked_add(1).ok_or(Error::ArithmeticOverflow)?);
        self.descend_major = 0;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk_format::dir::DirectoryChecksum;

    /// # Errors
    /// Returns route fixture or valid traversal setup failures.
    /// # Panics
    /// Fails if descending a successor revisits an old table or follows a back-edge.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "compares selected logical blocks against a hand-built tree"
    )]
    fn advance_resumes_at_the_next_selected_subtree_and_rejects_back_edges() -> Result<()> {
        let root = DxIndex::root(
            1024,
            DirectoryChecksum::None,
            alloc::vec![DxEntry::new(0, 7)?, DxEntry::new(4, 8)?,],
        )?;
        let mut path = HtreePath::new(root, 1, 2, ())?;
        let seven = LogicalBlock::try_from(7_u64)?;
        let eight = LogicalBlock::try_from(8_u64)?;
        let leaf = LogicalBlock::try_from(19_u64)?;
        assert_eq!(path.pending_index()?, Some(seven));
        let first = DxIndex::root(
            1024,
            DirectoryChecksum::None,
            alloc::vec![DxEntry::new(0, 19)?],
        )?;
        path.append_index(seven, first, ())?;
        assert_eq!(path.leaf()?, leaf);
        assert!(path.advance_route()?);
        assert_eq!(path.pending_index()?, Some(eight));
        let cyclic = DxIndex::root(
            1024,
            DirectoryChecksum::None,
            alloc::vec![DxEntry::new(0, 8)?],
        )?;
        path.append_index(eight, cyclic, ())?;
        assert_eq!(path.leaf(), Err(Error::InvalidDirectoryEntry));
        Ok(())
    }
}
