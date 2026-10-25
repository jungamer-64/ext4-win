//! Private delta recovery resolves and validates postimages before consuming journal authority.
use super::scope::*;
use super::block_group::AllocationIndexBuild;
use super::metadata_image::MetadataImages;
use super::orphan::ValidatedOrphanInventory;
use super::transaction::StorageRequestSequence;
use crate::disk::storage::{StorageTranscript, StorageTarget};
use crate::disk_format::journal::{DeltaRecoverySeed, fast_commit::ParsedDelta};

/// Effect-free postimages carry no journal or mount-publication authority.
#[derive(Debug)]
pub(super) struct ResolvedDeltaImages {
    /// Checked accounting successor represented by the corresponding primary postimage.
    pub(super) superblock: Superblock,
    /// Unique, immutable candidate metadata read by allocation validation.
    pub(super) images: MetadataImages,
}

/// Each phase owns its snapshot and its unique recovery continuation across lower reads.
#[derive(Debug)]
enum DeltaReplayPhase {
    /// Classify dependencies and resolve metadata-only programs without an allocation snapshot.
    Inspect { superblock: Superblock, seed: DeltaRecoverySeed },
    /// The original allocation graph must be valid before it grants allocation accounting.
    IndexBase { superblock: Superblock, seed: DeltaRecoverySeed, orphans: ValidatedOrphanInventory, index: alloc::boxed::Box<AllocationIndexBuild> },
    /// Reconstruct complete range and metadata postconditions under the original ownership graph.
    Resolve { superblock: Superblock, seed: DeltaRecoverySeed, clusters: ClusterReferenceIndex },
    /// Validate tracking in the prospective images, before any persistence operation.
    CandidateOrphans { seed: DeltaRecoverySeed, candidate: ResolvedDeltaImages },
    /// Detect physical overlap and bitmap disagreement in the complete prospective graph.
    IndexCandidate { seed: DeltaRecoverySeed, candidate: ResolvedDeltaImages, orphans: ValidatedOrphanInventory, index: alloc::boxed::Box<AllocationIndexBuild> },
    /// A replacement full commit and checkpoint are completely allocated but have not been sent.
    Ready(StorageRequestSequence<Journal<CleanJournal>>),
    /// Errors consume the preparation; only an unfinished lower read can resume a live phase.
    Failed,
}

/// Owns the original delta log until validated postimages become a complete full-commit sequence.
#[derive(Debug)]
pub(super) struct DeltaReplayOperation {
    /// This private transcript never sees mutable candidates from another phase or mount.
    transcript: StorageTranscript,
    /// Sole recovery state; candidate validity is established only by its consuming transition.
    phase: DeltaReplayPhase,
}
impl DeltaReplayOperation {
    /// Binds the program to freshly revalidated physical filesystem identity before reading operands.
    /// # Errors
    /// Rejects journal/filesystem identity or physical geometry substitution.
    pub(super) fn new(length: DeviceLength, superblock: Superblock, seed: DeltaRecoverySeed) -> Result<Self> {
        seed.require_filesystem(&superblock)?;
        Ok(Self { transcript: StorageTranscript::new(StorageTarget::Filesystem, length), phase: DeltaReplayPhase::Inspect { superblock, seed } })
    }

    /// Routes reads only to the private preparation phase that issued them.
    /// # Errors
    /// Rejects mismatched or failed transfers, short reads and invalid overlay coordinates.
    pub(super) fn complete(&mut self, completion: crate::StorageCompletion) -> Result<()> {
        let completion = match &self.phase {
            DeltaReplayPhase::CandidateOrphans { candidate, .. } | DeltaReplayPhase::IndexCandidate { candidate, .. } => completion.apply_overlay(&candidate.images)?,
            DeltaReplayPhase::Inspect { .. } | DeltaReplayPhase::IndexBase { .. } | DeltaReplayPhase::Resolve { .. } => completion,
            DeltaReplayPhase::Ready(_) | DeltaReplayPhase::Failed => return Err(Error::DeviceIo),
        };
        self.transcript.complete(completion)
    }

    /// Advances preparation; no returned request writes or flushes backing storage.
    /// # Errors
    /// Returns metadata, ownership, resource, or journal-capacity failure without replay effects.
    pub(super) fn next_request(&mut self, keys: &FscryptKeySet) -> Result<Option<crate::StorageRequest>> {
        loop {
            let phase = core::mem::replace(&mut self.phase, DeltaReplayPhase::Failed);
            let result = match phase {
                DeltaReplayPhase::Inspect { superblock, seed } => {
                    let mut view = EpochReadView::mounting(OperationDevice::new(&mut self.transcript), superblock, keys);
                    if seed.program().records().iter().all(|record| matches!(record, ParsedDelta::Inode { .. })) {
                        match resolve_metadata(&mut view, &seed) {
                            Ok(candidate) => { self.transcript = StorageTranscript::new(StorageTarget::Filesystem, self.transcript.len()); self.phase = DeltaReplayPhase::CandidateOrphans { seed, candidate }; Ok(()) }
                            Err(error) => { self.phase = DeltaReplayPhase::Inspect { superblock, seed }; Err(error) }
                        }
                    } else {
                        match ValidatedOrphanInventory::load(&mut view) {
                            Ok(orphans) => { self.phase = DeltaReplayPhase::IndexBase { superblock, seed, orphans, index: memory::try_box(AllocationIndexBuild::new())? }; Ok(()) }
                            Err(error) => { self.phase = DeltaReplayPhase::Inspect { superblock, seed }; Err(error) }
                        }
                    }
                }
                DeltaReplayPhase::IndexBase { superblock, seed, orphans, mut index } => match index.advance(&mut self.transcript, &superblock, &orphans) {
                    Ok(clusters) => { self.phase = DeltaReplayPhase::Resolve { superblock, seed, clusters }; Ok(()) }
                    Err(error) => { self.phase = DeltaReplayPhase::IndexBase { superblock, seed, orphans, index }; Err(error) }
                },
                DeltaReplayPhase::Resolve { superblock, seed, clusters } => {
                    let view = EpochReadView::recovering(OperationDevice::new(&mut self.transcript), superblock, keys, &clusters);
                    match super::transaction::resolve_delta_ranges(view, seed.program()) {
                        Ok(candidate) => { self.transcript = StorageTranscript::new(StorageTarget::Filesystem, self.transcript.len()); self.phase = DeltaReplayPhase::CandidateOrphans { seed, candidate }; Ok(()) }
                        Err(error) => { self.phase = DeltaReplayPhase::Resolve { superblock, seed, clusters }; Err(error) }
                    }
                }
                DeltaReplayPhase::CandidateOrphans { seed, candidate } => {
                    let device = OperationDevice::with_overlay(&mut self.transcript, &candidate.images, None);
                    let mut view = EpochReadView::mounting(device, candidate.superblock, keys);
                    match ValidatedOrphanInventory::load(&mut view) {
                        Ok(orphans) => { self.phase = DeltaReplayPhase::IndexCandidate { seed, candidate, orphans, index: memory::try_box(AllocationIndexBuild::new())? }; Ok(()) }
                        Err(error) => { self.phase = DeltaReplayPhase::CandidateOrphans { seed, candidate }; Err(error) }
                    }
                }
                DeltaReplayPhase::IndexCandidate { seed, candidate, orphans, mut index } => match index.advance(&mut self.transcript, &candidate.superblock, &orphans) {
                    Ok(_validated) => {
                        let prepared = seed.prepare_commit(candidate.superblock.block_size(), candidate.images.into_blocks())?;
                        self.phase = DeltaReplayPhase::Ready(StorageRequestSequence::checkpoint(prepared, |journal| journal)?);
                        Ok(())
                    }
                    Err(error) => { self.phase = DeltaReplayPhase::IndexCandidate { seed, candidate, orphans, index }; Err(error) }
                },
                DeltaReplayPhase::Ready(sequence) => { self.phase = DeltaReplayPhase::Ready(sequence); return Ok(None); }
                DeltaReplayPhase::Failed => return Err(Error::DeviceIo),
            };
            match result {
                Ok(()) => {}
                Err(Error::OperationSuspended) => return self.transcript.take_pending_request().map(Some),
                Err(error) => { self.phase = DeltaReplayPhase::Failed; return Err(error); }
            }
        }
    }

    /// The complete replacement is revealed only after candidate validation and preallocation.
    /// # Errors
    /// Rejects unfinished or failed preparation instead of discarding its recovery obligation.
    pub(super) fn into_sequence(self) -> Result<StorageRequestSequence<Journal<CleanJournal>>> {
        match self.phase { DeltaReplayPhase::Ready(sequence) => Ok(sequence), _ => Err(Error::DeviceIo) }
    }
}

/// Metadata-only records retain their original storage identity and attribute body.
/// # Errors
/// Returns suspended I/O, allocation, layout or unsupported semantic replay failure.
fn resolve_metadata(volume: &mut EpochReadView<'_, '_>, seed: &DeltaRecoverySeed) -> Result<ResolvedDeltaImages> {
    let mut images = MetadataImages::new(volume.superblock.block_size());
    let records = seed.program().records();
    for (index, record) in records.iter().enumerate() {
        let ParsedDelta::Inode { inode, encoded } = record else { return Err(Error::UnsupportedJournal); };
        if records.get(index.checked_add(1).ok_or(Error::ArithmeticOverflow)?..).ok_or(Error::JournalCorrupt)?.iter().any(|later| matches!(later, ParsedDelta::Inode { inode: other, .. } if other == inode)) { continue; }
        let live = volume.read_live_inode_record(*inode)?.apply_metadata_delta(encoded)?;
        let mut staged = StagedInodeRecord::Live(live);
        staged.refresh_checksum(&volume.superblock)?;
        images.patch(volume, staged.offset(), staged.bytes())?;
    }
    Ok(ResolvedDeltaImages { superblock: volume.superblock, images })
}
