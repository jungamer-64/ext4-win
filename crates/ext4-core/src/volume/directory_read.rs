//! Bounded directory walks with owned continuation across lower-I/O completions.

use super::read::{HtreePath, HtreePathLevel};
use super::scope::*;
use crate::disk::storage::{StorageTarget, StorageTranscript};
use crate::disk_format::dir::DirectoryRecord;

/// Maximum retained candidates in a cross-leaf hash collision run.
const COLLISION_CAPACITY: usize = 128;

/// Fixed read reuse budget, independent of directory cardinality.
const RECENT_DIRECTORY_READS: usize = 8;

/// One hashed dirent; the hash is shared by validation, ordering and continuation.
#[derive(Debug)]
struct Candidate {
    /// Validated on-disk record.
    raw: RawDirectoryEntry,
    /// Hash under the directory root's scheme.
    hash: DirectoryHash,
}

impl Candidate {
    /// Orders by the complete stable enumeration key.
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.hash
            .cmp(&other.hash)
            .then(self.raw.name().bytes().cmp(other.raw.name().bytes()))
    }

    /// Tests the caller's consumed-key boundary.
    fn follows(&self, after: Option<(DirectoryHash, DirectoryCursorName)>) -> bool {
        after.is_none_or(|(hash, name)| (self.hash, self.raw.name().bytes()) > (hash, name.bytes()))
    }
}

/// Result of one bounded internal stage. Progress owns all successfully decoded input.
enum WalkStep {
    /// The next stage may run after completed read buffers are retired.
    Progress,
    /// One raw entry ready for inode/name projection.
    Entry(RawDirectoryEntry, DirectoryScanPosition),
    /// Traversal observed the end.
    End,
}

/// One raw entry retained while its inode or encryption context is read.
#[derive(Debug)]
struct PendingEntry {
    /// Record whose validation has not completed.
    raw: RawDirectoryEntry,
    /// Name projection survives subsequent inode validation I/O.
    visible: Option<Ext4Name>,
    /// Position after this record.
    position: DirectoryScanPosition,
}

/// Physical-order linear directory traversal.
#[derive(Debug)]
struct LinearWalk {
    /// Logical block currently selected.
    logical: u64,
    /// Initial byte coordinate within that block.
    offset: u32,
    /// Parsed live records of the resident block.
    records: Option<alloc::vec::IntoIter<DirectoryRecord>>,
}

/// Cross-leaf collision selection with a fixed candidate budget.
#[derive(Debug)]
struct Collision {
    /// Route at the first leaf in the run, retained for another bounded selection pass.
    start: HtreePath,
    /// Primary hash shared by this run.
    major: u32,
    /// Smallest remaining candidates, descending so pop yields the next entry.
    candidates: Vec<Candidate>,
    /// More eligible entries existed than could be retained in this selection pass.
    overflow: bool,
}

/// Whether the current HTree path is serving ordinary entries or a collision merge.
#[derive(Debug)]
enum HashPhase {
    /// Emit the current leaf until a continued hash boundary is reached.
    Ordinary,
    /// Read every leaf of this collision run before emitting its smallest keys.
    Collect(Collision),
    /// Emit the bounded selection, then either resume the suffix or select the next page.
    Emit(Collision),
    /// No further leaf exists.
    End,
}

/// HTree traversal retains only paths, one leaf and a bounded collision selection.
#[derive(Debug)]
struct HashWalk {
    /// Root-selected name hashing contract.
    hash: DirectoryHashScheme,
    /// Number of interior levels below the root.
    depth: u8,
    /// Current root-to-leaf path, possibly awaiting descendants.
    path: HtreePath,
    /// Hash selecting descendants during an initial or resumed descent.
    descend_major: u32,
    /// Root-owned special entries not yet consumed.
    dots: alloc::vec::IntoIter<RawDirectoryEntry>,
    /// Validated candidates of one leaf, descending by semantic key.
    leaf: Option<Vec<Candidate>>,
    /// Last raw key consumed by the walk.
    after: Option<(DirectoryHash, DirectoryCursorName)>,
    /// Collision lifecycle.
    phase: HashPhase,
}

/// Storage representation selected after opening the directory inode.
#[derive(Debug)]
enum DirectoryLayout {
    /// The indexed root still requires a lower read.
    Root,
    /// Non-indexed physical traversal.
    Linear(LinearWalk),
    /// Indexed traversal in semantic-key order.
    Hash(alloc::boxed::Box<HashWalk>),
}

/// An opened directory and the bounded storage state interpreting it.
#[derive(Debug)]
struct DirectoryWalk {
    /// Validated directory inode from the retained read epoch.
    directory: DirectoryNode,
    /// Only the extent nodes mapping the currently requested block.
    mapping: ExtentMappingCursor,
    /// Directory-specific iteration state.
    layout: DirectoryLayout,
    /// Raw entry retained across projection I/O.
    pending: Option<PendingEntry>,
}

/// Opening, traversing and exhausted states of a single directory reader.
#[derive(Debug)]
enum ReaderState {
    /// The directory inode has not yet been loaded.
    Opening(DirectoryNodeId),
    /// An inode and its decoded walk are owned by this reader.
    Walking(alloc::boxed::Box<DirectoryWalk>),
    /// The end position has been observed.
    End,
    /// A non-suspension failure permanently ends this reader.
    Failed(Error),
}

/// Incremental directory traversal against one immutable committed read context.
///
/// A reader must remain attached to the same epoch throughout its lifetime. Only its opaque
/// cursor may be carried to a later epoch. A suspended call retains progress; other failures
/// terminate this reader and must not be retried. Use DirectoryReadOperation for owned I/O.
#[derive(Debug)]
pub struct DirectoryReader {
    /// Open/active/end protocol state.
    state: ReaderState,
    /// Last consumed coordinate and next raw ordinal.
    cursor: DirectoryScanCursor,
    /// Remaining live records for an explicit ordinal seek.
    skip: u64,
    /// Snapshot binding rejects accidental continuation on a replacement epoch.
    epoch: Option<(crate::FilesystemUuid, super::EpochSequence)>,
}

/// One decoded reader stage, before the owning operation retires the raw I/O transcript.
#[expect(
    clippy::large_enum_variant,
    reason = "yielding the inline publication cursor must not allocate for every directory entry"
)]
enum ReaderStep {
    /// Decoded progress retained by the reader.
    Progress,
    /// Fully validated caller-visible entry.
    Entry(ScannedDirectoryEntry),
    /// Directory end observed.
    End,
}

impl DirectoryReader {
    /// Starts a walk at an opaque continuation in the selected read context.
    #[must_use]
    pub const fn new(directory: DirectoryNodeId, cursor: DirectoryScanCursor) -> Self {
        let skip = match cursor.position {
            DirectoryScanPosition::Ordinal(target) => target,
            _ => 0,
        };
        Self {
            state: if matches!(cursor.position, DirectoryScanPosition::End) {
                ReaderState::End
            } else {
                ReaderState::Opening(directory)
            },
            cursor,
            skip,
            epoch: None,
        }
    }

    /// Last consumed position; publishing it is the caller's responsibility.
    #[must_use]
    pub const fn cursor(&self) -> &DirectoryScanCursor {
        &self.cursor
    }

    /// Advances exactly one owned stage, keeping successful work across suspension.
    /// # Errors
    /// Returns storage, allocation, malformed-directory or projection errors.
    fn step(
        &mut self,
        view: &mut EpochReadView<'_, '_>,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<ReaderStep> {
        if let ReaderState::Failed(error) = self.state {
            return Err(error);
        }
        let identity = view.epoch.ok_or(Error::DeviceIo)?;
        if self.epoch.is_some_and(|expected| expected != identity) {
            return Err(Error::DeviceIo);
        }
        self.epoch = Some(identity);
        if let ReaderState::Opening(id) = self.state {
            let directory = view.load_directory(id)?;
            if directory.protection().is_verity() {
                return Err(Error::UnsupportedVerity);
            }
            let inode = directory.inode();
            let mapping = ExtentMappingCursor::new(
                inode.extent_root()?,
                view.superblock.block_size(),
                view.extent_tree_context(inode),
            )?;
            let layout = match inode.directory_storage_kind()? {
                DirectoryStorageKind::HTree => DirectoryLayout::Root,
                DirectoryStorageKind::Linear => {
                    let (logical, offset) = match self.cursor.position {
                        DirectoryScanPosition::Linear { logical, offset } => {
                            (u64::from(logical), offset)
                        }
                        DirectoryScanPosition::Start | DirectoryScanPosition::Ordinal(_) => (0, 0),
                        _ => {
                            self.skip = self.cursor.ordinal;
                            (0, 0)
                        }
                    };
                    DirectoryLayout::Linear(LinearWalk {
                        logical,
                        offset,
                        records: None,
                    })
                }
            };
            if self.skip != 0 {
                self.cursor.ordinal = 0;
            }
            self.state = ReaderState::Walking(memory::try_box(DirectoryWalk {
                directory,
                mapping,
                layout,
                pending: None,
            })?);
            return Ok(ReaderStep::Progress);
        }
        let ReaderState::Walking(walk) = &mut self.state else {
            return Ok(ReaderStep::End);
        };
        if let Some(pending) = &mut walk.pending {
            let next = match pending.position {
                DirectoryScanPosition::HTree { major, minor } => {
                    DirectoryScanCursor::after_htree_entry(
                        major,
                        minor,
                        pending.raw.name(),
                        self.cursor.ordinal,
                    )?
                }
                position => DirectoryScanCursor::after_entry(position, self.cursor.ordinal)?,
            };
            if self.skip != 0 {
                self.skip = self.skip.checked_sub(1).ok_or(Error::ArithmeticOverflow)?;
                self.cursor = next;
                walk.pending = None;
                return Ok(ReaderStep::Progress);
            }
            let Some(visible) = &pending.visible else {
                pending.visible = Some(view.project_directory_name(
                    &walk.directory,
                    pending.raw.try_clone()?,
                    crypto,
                )?);
                return Ok(ReaderStep::Progress);
            };
            let entry = view.validate_directory_entry(pending.raw.try_clone()?, visible)?;
            let result = ScannedDirectoryEntry::new(entry, self.cursor.ordinal, next);
            self.cursor = next;
            walk.pending = None;
            return Ok(ReaderStep::Entry(result));
        }
        let step = match &mut walk.layout {
            DirectoryLayout::Root => {
                let inode = walk.directory.inode();
                let block = view.read_directory_logical_block(
                    inode,
                    &mut walk.mapping,
                    LogicalBlock::try_from(0_u64)?,
                )?;
                let root = HtreeRoot::parse(
                    block.bytes(),
                    inode.id(),
                    view.superblock.directory_hash_seed(),
                    view.superblock.directory_indexing().require_supported()?,
                    view.directory_checksum(inode),
                )?;
                let dot_start = match self.cursor.position {
                    DirectoryScanPosition::Start | DirectoryScanPosition::Ordinal(_) => 0,
                    DirectoryScanPosition::AfterDot => 1,
                    DirectoryScanPosition::Linear { .. } => {
                        self.skip = self.cursor.ordinal;
                        self.cursor.ordinal = 0;
                        0
                    }
                    _ => 2,
                };
                let after = match self.cursor.position {
                    DirectoryScanPosition::HTree { major, minor } => {
                        Some((DirectoryHash { major, minor }, self.cursor.htree_name))
                    }
                    _ => None,
                };
                let major = after.map_or(0, |key| key.0.major);
                let mut dots = Vec::new();
                for raw in root.dot_entries().iter().skip(dot_start) {
                    dots.try_push(raw.try_clone()?)?;
                }
                let index = root.index().try_clone()?;
                let selected = index.select(major);
                let mut levels = Vec::new();
                levels.try_push(HtreePathLevel {
                    logical: 0,
                    index,
                    selected,
                })?;
                walk.layout = DirectoryLayout::Hash(memory::try_box(HashWalk {
                    hash: root.hash_scheme(),
                    depth: root.indirect_levels(),
                    path: HtreePath { levels },
                    descend_major: major,
                    dots: dots.into_iter(),
                    leaf: None,
                    after,
                    phase: HashPhase::Ordinary,
                })?);
                WalkStep::Progress
            }
            DirectoryLayout::Linear(linear) => {
                linear.step(view, &walk.directory, &mut walk.mapping)?
            }
            DirectoryLayout::Hash(hash) => hash.step(view, &walk.directory, &mut walk.mapping)?,
        };
        match step {
            WalkStep::Progress => Ok(ReaderStep::Progress),
            WalkStep::Entry(raw, position) => {
                walk.pending = Some(PendingEntry {
                    raw,
                    visible: None,
                    position,
                });
                Ok(ReaderStep::Progress)
            }
            WalkStep::End => {
                self.cursor = DirectoryScanCursor::end(self.cursor.ordinal);
                self.state = ReaderState::End;
                Ok(ReaderStep::End)
            }
        }
    }
}

impl LinearWalk {
    /// Advances one physical block or resident dirent.
    /// # Errors
    /// Returns mapping, record, cursor or I/O errors.
    fn step(
        &mut self,
        view: &mut EpochReadView<'_, '_>,
        directory: &DirectoryNode,
        mapping: &mut ExtentMappingCursor,
    ) -> Result<WalkStep> {
        let count = round_up_div(
            directory.size().bytes(),
            u64::from(view.superblock.block_size().bytes()),
        )?;
        if self.logical >= count {
            return Ok(WalkStep::End);
        }
        let Some(records) = &mut self.records else {
            let block = view.read_directory_logical_block(
                directory.inode(),
                mapping,
                LogicalBlock::try_from(self.logical)?,
            )?;
            let records = block.records()?;
            self.records = Some(records.into_iter());
            return Ok(WalkStep::Progress);
        };
        for record in records.by_ref() {
            if record.offset() < self.offset {
                continue;
            }
            let position = if let Some(next) = records.as_slice().first() {
                DirectoryScanPosition::Linear {
                    logical: u32::try_from(self.logical).map_err(|_| Error::ArithmeticOverflow)?,
                    offset: next.offset(),
                }
            } else {
                DirectoryScanPosition::Linear {
                    logical: u32::try_from(
                        self.logical
                            .checked_add(1)
                            .ok_or(Error::ArithmeticOverflow)?,
                    )
                    .map_err(|_| Error::ArithmeticOverflow)?,
                    offset: 0,
                }
            };
            return Ok(WalkStep::Entry(record.entry().try_clone()?, position));
        }
        self.logical = self
            .logical
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        self.offset = 0;
        self.records = None;
        Ok(WalkStep::Progress)
    }
}

impl HtreePath {
    /// Next leaf boundary, derivable from resident ancestors without reading the next leaf.
    fn next_boundary(&self) -> Option<u32> {
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
    fn advance_route(&mut self) -> Result<bool> {
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
        Ok(true)
    }
}

impl HashWalk {
    /// Advances one route, leaf, collision selection, or yielded raw entry.
    /// # Errors
    /// Returns invalid routing, checksum, allocation or I/O errors.
    fn step(
        &mut self,
        view: &mut EpochReadView<'_, '_>,
        directory: &DirectoryNode,
        mapping: &mut ExtentMappingCursor,
    ) -> Result<WalkStep> {
        if let Some(dot) = self.dots.next() {
            let position = if dot.name().bytes() == b"." {
                DirectoryScanPosition::AfterDot
            } else {
                DirectoryScanPosition::AfterDotDot
            };
            return Ok(WalkStep::Entry(dot, position));
        }
        if matches!(self.phase, HashPhase::End) {
            return Ok(WalkStep::End);
        }
        let expected = usize::from(self.depth)
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        if self.path.levels.len() < expected {
            let logical = self.path.leaf()?;
            let block = view.read_directory_logical_block(
                directory.inode(),
                mapping,
                LogicalBlock::try_from(u64::from(logical))?,
            )?;
            let index =
                DxIndex::parse_node(block.bytes(), view.directory_checksum(directory.inode()))?;
            let selected = index.select(self.descend_major);
            self.path.levels.try_push(HtreePathLevel {
                logical,
                index,
                selected,
            })?;
            self.path.hash_range()?;
            return Ok(WalkStep::Progress);
        }
        if self.leaf.is_none() {
            let block = view.read_directory_logical_block(
                directory.inode(),
                mapping,
                LogicalBlock::try_from(u64::from(self.path.leaf()?))?,
            )?;
            let range = self.path.hash_range()?;
            let mut candidates = Vec::new();
            for raw in block.entries()? {
                if matches!(raw.name().bytes(), b"." | b"..") {
                    return Err(Error::InvalidDirectoryEntry);
                }
                let hash = self.hash.hash(raw.name());
                range.validate_hash(hash.major)?;
                let candidate = Candidate { raw, hash };
                if candidate.follows(self.after) {
                    candidates.try_push(candidate)?;
                }
            }
            memory::heap_sort_by(&mut candidates, |left, right| right.cmp(left))?;
            self.leaf = Some(candidates);
            return Ok(WalkStep::Progress);
        }
        self.consume_leaf()
    }

    /// Advances ordering and collision selection using the resident validated leaf.
    /// # Errors
    /// Returns allocation, malformed-path, or cursor encoding failures.
    fn consume_leaf(&mut self) -> Result<WalkStep> {
        match &mut self.phase {
            HashPhase::Ordinary => {
                let boundary = self
                    .path
                    .next_boundary()
                    .filter(|boundary| boundary & 1 != 0)
                    .map(|boundary| boundary & !1);
                let leaf = self.leaf.as_mut().ok_or(Error::InvalidDirectoryEntry)?;
                if let Some(major) = boundary
                    && leaf.last().is_none_or(|entry| entry.hash.major >= major)
                {
                    self.phase = HashPhase::Collect(Collision {
                        start: self.path.try_clone()?,
                        major,
                        candidates: Vec::new(),
                        overflow: false,
                    });
                    return Ok(WalkStep::Progress);
                }
                if let Some(candidate) = leaf.pop() {
                    return self.yield_candidate(candidate);
                }
                self.next_leaf()?;
            }
            HashPhase::Collect(collision) => {
                let leaf = self.leaf.as_mut().ok_or(Error::InvalidDirectoryEntry)?;
                while leaf
                    .last()
                    .is_some_and(|candidate| candidate.hash.major <= collision.major)
                {
                    let candidate = leaf.pop().ok_or(Error::InvalidDirectoryEntry)?;
                    if candidate.hash.major != collision.major || !candidate.follows(self.after) {
                        continue;
                    }
                    collision.retain(candidate)?;
                }
                if self.path.next_boundary() == Some(collision.major | 1) {
                    self.next_leaf()?;
                } else {
                    let HashPhase::Collect(collision) =
                        core::mem::replace(&mut self.phase, HashPhase::Ordinary)
                    else {
                        return Err(Error::InvalidDirectoryEntry);
                    };
                    self.phase = HashPhase::Emit(collision);
                }
            }
            HashPhase::Emit(collision) => {
                if let Some(candidate) = collision.candidates.pop() {
                    return self.yield_candidate(candidate);
                }
                let HashPhase::Emit(mut collision) =
                    core::mem::replace(&mut self.phase, HashPhase::Ordinary)
                else {
                    return Err(Error::InvalidDirectoryEntry);
                };
                if collision.overflow {
                    self.path = collision.start.try_clone()?;
                    self.leaf = None;
                    self.descend_major = collision.major;
                    collision.overflow = false;
                    self.phase = HashPhase::Collect(collision);
                }
            }
            HashPhase::End => return Ok(WalkStep::End),
        }
        Ok(WalkStep::Progress)
    }

    /// Consumes a candidate into the stable raw-key continuation.
    /// # Errors
    /// Returns inline-name representation errors.
    fn yield_candidate(&mut self, candidate: Candidate) -> Result<WalkStep> {
        self.after = Some((
            candidate.hash,
            DirectoryCursorName::from_name(candidate.raw.name())?,
        ));
        Ok(WalkStep::Entry(
            candidate.raw,
            DirectoryScanPosition::HTree {
                major: candidate.hash.major,
                minor: candidate.hash.minor,
            },
        ))
    }

    /// Moves to a subsequent leaf without repeating an ancestor transition on suspension.
    /// # Errors
    /// Returns path/arithmetic errors.
    fn next_leaf(&mut self) -> Result<()> {
        if !self.path.advance_route()? {
            self.phase = HashPhase::End;
        }
        self.leaf = None;
        self.descend_major = 0;
        Ok(())
    }
}

impl EpochReadView<'_, '_> {
    /// Executes the same incremental engine inside an ephemeral synchronous read pass.
    /// # Errors
    /// Returns read/validation failures; suspension preserves the supplied reader.
    pub(super) fn next_directory_entry(
        &mut self,
        reader: &mut DirectoryReader,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<Option<ScannedDirectoryEntry>> {
        loop {
            let step = reader.step(self, crypto).inspect_err(|error| {
                if *error != Error::OperationSuspended {
                    reader.state = ReaderState::Failed(*error);
                }
            })?;
            match step {
                ReaderStep::Progress => {}
                ReaderStep::Entry(entry) => return Ok(Some(entry)),
                ReaderStep::End => return Ok(None),
            }
        }
    }
}

/// One consuming transition of an owned directory read.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "consuming transitions move one inline cursor and continuation without per-entry heap allocation"
)]
pub enum DirectoryReadTransition {
    /// Submit the sole pending transfer and resume only with its matching completion.
    SubmitLower {
        /// Lower request ownership.
        request: crate::StorageRequest,
        /// Decoded progress awaiting the transfer.
        suspended: DirectoryReadOperation,
    },
    /// Exactly one validated entry; the continuation is ready for the next advance.
    Entry {
        /// Caller-visible name, identity and publication cursor.
        entry: ScannedDirectoryEntry,
        /// Remaining walk in the same immutable epoch.
        continuation: DirectoryReadOperation,
    },
    /// End of directory or a terminal failure.
    Complete(Result<DirectoryScanCursor>),
}

/// Completion-driven enumeration with depth/leaf-bounded retained storage.
///
/// The caller retains the immutable epoch lease until completion. Entries are yielded once;
/// only cursors, never decoded nodes, may cross from one request epoch to another.
#[derive(Debug)]
pub struct DirectoryReadOperation {
    /// Single directory's decoded progress.
    reader: DirectoryReader,
    /// Unfinished decoding reads plus a fixed recent-read reuse budget.
    storage: StorageTranscript,
}

impl DirectoryReadOperation {
    /// Creates a read at a caller's committed cursor.
    #[must_use]
    pub const fn new(
        profile: &MountedProfile,
        directory: DirectoryNodeId,
        cursor: DirectoryScanCursor,
    ) -> Self {
        Self {
            reader: DirectoryReader::new(directory, cursor),
            storage: StorageTranscript::new(StorageTarget::Filesystem, profile.filesystem_length()),
        }
    }

    /// Consumes one event and runs until an entry, lower read, or terminal outcome is ready.
    #[must_use]
    pub fn advance(
        mut self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        crypto: &mut dyn CryptographicOperation,
    ) -> DirectoryReadTransition {
        match event {
            super::OperationEvent::Admitted => {}
            super::OperationEvent::StorageCompleted(completion) => {
                if let Err(error) = self.storage.complete(completion) {
                    return DirectoryReadTransition::Complete(Err(error));
                }
            }
            super::OperationEvent::CancelRequested => {
                return DirectoryReadTransition::Complete(Err(Error::OperationCancelled));
            }
            _ => return DirectoryReadTransition::Complete(Err(Error::DeviceIo)),
        }
        loop {
            let step = {
                let device = OperationDevice::with_overlay(&mut self.storage, epoch);
                let mut view = EpochReadView::committed(device, epoch);
                self.reader.step(&mut view, crypto)
            };
            match step {
                Err(Error::OperationSuspended) => {
                    return match self.storage.take_pending_request() {
                        Ok(request) => DirectoryReadTransition::SubmitLower {
                            request,
                            suspended: self,
                        },
                        Err(error) => DirectoryReadTransition::Complete(Err(error)),
                    };
                }
                Err(error) => return DirectoryReadTransition::Complete(Err(error)),
                Ok(ReaderStep::End) => {
                    return DirectoryReadTransition::Complete(Ok(self.reader.cursor));
                }
                Ok(ReaderStep::Progress) => {
                    if let Err(error) = self.storage.retire_decoded_stage(RECENT_DIRECTORY_READS) {
                        return DirectoryReadTransition::Complete(Err(error));
                    }
                }
                Ok(ReaderStep::Entry(entry)) => {
                    if let Err(error) = self.storage.retire_decoded_stage(RECENT_DIRECTORY_READS) {
                        return DirectoryReadTransition::Complete(Err(error));
                    }
                    return DirectoryReadTransition::Entry {
                        entry,
                        continuation: self,
                    };
                }
            }
        }
    }
}

impl Collision {
    /// Retains the smallest remaining semantic keys without growing the candidate budget.
    /// # Errors
    /// Returns allocation or arithmetic failures before emitting any selected candidate.
    fn retain(&mut self, candidate: Candidate) -> Result<()> {
        let at = self
            .candidates
            .partition_point(|other| other.cmp(&candidate).is_gt());
        if self.candidates.len() == COLLISION_CAPACITY {
            self.overflow = true;
            if at == 0 {
                return Ok(());
            }
            let _discarded = self.candidates.try_remove_at(0)?;
            self.candidates.try_insert(
                at.checked_sub(1).ok_or(Error::ArithmeticOverflow)?,
                candidate,
            )?;
        } else {
            self.candidates.try_insert(at, candidate)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns name, record or allocation failures during fixture construction.
    /// # Panics
    /// Fails if multiple bounded passes reorder, repeat, or omit colliding names.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "the test uses Result for fallible fixture construction and assertions for semantic comparisons"
    )]
    fn collision_selection_preserves_minor_hash_and_name_across_pages() -> Result<()> {
        let mut after = None;
        let mut actual = Vec::new();
        for _page in 0..3 {
            let mut collision = Collision {
                start: HtreePath { levels: Vec::new() },
                major: 2,
                candidates: Vec::new(),
                overflow: false,
            };
            // A permutation supplies 300 equal-major keys in leaf-independent order.
            for input in 0..300_u32 {
                let index = input * 173 % 300;
                let name = Ext4Name::new(alloc::format!("n-{index:03}").as_bytes())?;
                let candidate = Candidate {
                    raw: RawDirectoryEntry::new(InodeId::ROOT, &name, DirectoryEntryKind::File)?,
                    hash: DirectoryHash {
                        major: 2,
                        minor: index % 3,
                    },
                };
                if candidate.follows(after) {
                    collision.retain(candidate)?;
                }
                assert!(collision.candidates.len() <= COLLISION_CAPACITY);
            }
            while let Some(candidate) = collision.candidates.pop() {
                after = Some((
                    candidate.hash,
                    DirectoryCursorName::from_name(candidate.raw.name())?,
                ));
                actual.try_push((
                    candidate.hash.minor,
                    candidate.raw.name().try_to_owned_name()?,
                ))?;
            }
        }
        let mut expected = Vec::new();
        for minor in 0..3 {
            for index in 0..300 {
                if index % 3 == minor {
                    expected.try_push((
                        minor,
                        Ext4Name::new(alloc::format!("n-{index:03}").as_bytes())?,
                    ))?;
                }
            }
        }
        assert_eq!(actual, expected);
        Ok(())
    }
    /// # Errors
    /// Returns fixture construction or collision traversal errors.
    /// # Panics
    /// Fails if collision leaves, repeated selection passes, or the following suffix lose ordering.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixtures use Result; assertions compare independently ordered names"
    )]
    fn cross_leaf_collision_walk_emits_all_pages_then_suffix() -> Result<()> {
        use crate::disk_format::superblock::{DirectoryHashSeed, DirectoryHashVersion};
        let routes = alloc::vec![
            DxEntry::new(0, 1)?,
            DxEntry::new(3, 2)?,
            DxEntry::new(3, 3)?,
            DxEntry::new(4, 4)?
        ];
        let mut walk = HashWalk {
            hash: DirectoryHashScheme::from_metadata(
                DirectoryHashSeed::from_words([0; 4]),
                DirectoryHashVersion::Legacy,
            ),
            depth: 0,
            path: HtreePath {
                levels: alloc::vec![HtreePathLevel {
                    logical: 0,
                    index: DxIndex::root(1024, DirectoryChecksum::None, routes)?,
                    selected: 0
                }],
            },
            descend_major: 0,
            dots: Vec::new().into_iter(),
            leaf: None,
            after: None,
            phase: HashPhase::Ordinary,
        };
        let mut actual = Vec::new();
        for _stage in 0..1000 {
            if matches!(walk.phase, HashPhase::End) {
                break;
            }
            if walk.leaf.is_none() {
                let leaf = walk.path.leaf()?;
                let mut candidates = Vec::new();
                for input in 0..301_u32 {
                    let index = input * 173 % 301;
                    let route = if index == 300 { 4 } else { index % 3 + 1 };
                    if route != leaf {
                        continue;
                    }
                    let name = Ext4Name::new(alloc::format!("n-{index:03}").as_bytes())?;
                    let candidate = Candidate {
                        raw: RawDirectoryEntry::new(
                            InodeId::ROOT,
                            &name,
                            DirectoryEntryKind::File,
                        )?,
                        hash: DirectoryHash {
                            major: if index == 300 { 4 } else { 2 },
                            minor: index % 7,
                        },
                    };
                    if candidate.follows(walk.after) {
                        candidates.try_push(candidate)?;
                    }
                }
                memory::heap_sort_by(&mut candidates, |left, right| right.cmp(left))?;
                walk.leaf = Some(candidates);
            }
            if let WalkStep::Entry(raw, _) = walk.consume_leaf()? {
                actual.try_push(raw.name().try_to_owned_name()?)?;
            }
            if let HashPhase::Collect(collision) | HashPhase::Emit(collision) = &walk.phase {
                assert!(collision.candidates.len() <= COLLISION_CAPACITY);
            }
        }
        assert!(matches!(walk.phase, HashPhase::End));
        let mut expected = Vec::new();
        for minor in 0..7 {
            for index in 0..300 {
                if index % 7 == minor {
                    expected.try_push(Ext4Name::new(alloc::format!("n-{index:03}").as_bytes())?)?;
                }
            }
        }
        expected.try_push(Ext4Name::new(b"n-300")?)?;
        assert_eq!(actual, expected);
        Ok(())
    }
}
