//! Private delta recovery resolves and validates postimages before consuming journal authority.
use super::block_group::AllocationIndexBuild;
use super::metadata_image::MetadataImages;
use super::orphan::ValidatedOrphanInventory;
use super::scope::*;
use super::transaction::StorageRequestSequence;
use crate::disk::storage::{StorageTarget, StorageTranscript};
use crate::disk_format::journal::DeltaRecoverySeed;

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
    /// Admit the original orphan inventory before interpreting prospective metadata.
    ReadOrphans {
        /// Descriptor and inode decoding stay bound to freshly revalidated checkpoint geometry.
        superblock: Superblock,
        /// The original durable log remains authoritative while preparation can fail.
        seed: DeltaRecoverySeed,
    },
    /// The original allocation graph must be valid before it grants allocation accounting.
    IndexBase {
        /// No prospective accounting edit has been applied to this source snapshot.
        superblock: Superblock,
        /// Operands cannot be separated from their eventual full-commit conversion authority.
        seed: DeltaRecoverySeed,
        /// Only these registered zero-link allocations may enter the original ownership scan.
        orphans: ValidatedOrphanInventory,
        /// Decoded progress survives suspension but cannot authorize a partially built index.
        index: alloc::boxed::Box<AllocationIndexBuild>,
    },
    /// Reconstruct complete range and metadata postconditions under the original ownership graph.
    Resolve {
        /// The accounting baseline is unchanged throughout all provisional resolution passes.
        superblock: Superblock,
        /// Its immutable ADD operands reserve future data before any metadata allocation.
        seed: DeltaRecoverySeed,
        /// Completed source ownership permits deltas but does not establish candidate validity.
        clusters: ClusterReferenceIndex,
    },
    /// Validate tracking in the prospective images, before any persistence operation.
    CandidateOrphans {
        /// Conversion remains unavailable until the prospective allocation graph is checked.
        seed: DeltaRecoverySeed,
        /// These exact immutable bytes must feed both validation and subsequent persistence.
        candidate: ResolvedDeltaImages,
    },
    /// Detect physical overlap and bitmap disagreement in the complete prospective graph.
    IndexCandidate {
        /// Retained delta authority is consumed only after this complete scan succeeds.
        seed: DeltaRecoverySeed,
        /// No mutable alias can change a validated block before full-commit serialization.
        candidate: ResolvedDeltaImages,
        /// Prospective trackers admit zero-link records in the same immutable image set.
        orphans: ValidatedOrphanInventory,
        /// This fresh scan validates postimages independently of provisional reference arithmetic.
        index: alloc::boxed::Box<AllocationIndexBuild>,
    },
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
    pub(super) fn new(
        length: DeviceLength,
        superblock: Superblock,
        seed: DeltaRecoverySeed,
    ) -> Result<Self> {
        seed.require_filesystem(&superblock)?;
        Ok(Self {
            transcript: StorageTranscript::new(StorageTarget::Filesystem, length),
            phase: DeltaReplayPhase::ReadOrphans { superblock, seed },
        })
    }

    /// Routes reads only to the private preparation phase that issued them.
    /// # Errors
    /// Rejects mismatched or failed transfers, short reads and invalid overlay coordinates.
    pub(super) fn complete(&mut self, completion: crate::StorageCompletion) -> Result<()> {
        let completion = match &self.phase {
            DeltaReplayPhase::CandidateOrphans { candidate, .. }
            | DeltaReplayPhase::IndexCandidate { candidate, .. } => {
                completion.apply_overlay(&candidate.images)?
            }
            DeltaReplayPhase::ReadOrphans { .. }
            | DeltaReplayPhase::IndexBase { .. }
            | DeltaReplayPhase::Resolve { .. } => completion,
            DeltaReplayPhase::Ready(_) | DeltaReplayPhase::Failed => return Err(Error::DeviceIo),
        };
        self.transcript.complete(completion)
    }

    /// Advances preparation; no returned request writes or flushes backing storage.
    /// # Errors
    /// Returns metadata, ownership, resource, or journal-capacity failure without replay effects.
    pub(super) fn next_request(
        &mut self,
        keys: &FscryptKeySet,
    ) -> Result<Option<crate::StorageRequest>> {
        loop {
            let phase = core::mem::replace(&mut self.phase, DeltaReplayPhase::Failed);
            let result = match phase {
                DeltaReplayPhase::ReadOrphans { superblock, seed } => {
                    let mut view = EpochReadView::mounting(
                        OperationDevice::new(&mut self.transcript),
                        superblock,
                        keys,
                    );
                    match ValidatedOrphanInventory::load(&mut view) {
                        Ok(orphans) => {
                            self.phase = DeltaReplayPhase::IndexBase {
                                superblock,
                                seed,
                                orphans,
                                index: memory::try_box(AllocationIndexBuild::new())?,
                            };
                            Ok(())
                        }
                        Err(error) => {
                            self.phase = DeltaReplayPhase::ReadOrphans { superblock, seed };
                            Err(error)
                        }
                    }
                }

                DeltaReplayPhase::IndexBase {
                    superblock,
                    seed,
                    orphans,
                    mut index,
                } => match index.advance(&mut self.transcript, &superblock, &orphans) {
                    Ok(clusters) => {
                        self.phase = DeltaReplayPhase::Resolve {
                            superblock,
                            seed,
                            clusters,
                        };
                        Ok(())
                    }
                    Err(error) => {
                        self.phase = DeltaReplayPhase::IndexBase {
                            superblock,
                            seed,
                            orphans,
                            index,
                        };
                        Err(error)
                    }
                },
                DeltaReplayPhase::Resolve {
                    superblock,
                    seed,
                    clusters,
                } => {
                    let view = EpochReadView::recovering(
                        OperationDevice::new(&mut self.transcript),
                        superblock,
                        keys,
                        &clusters,
                    );
                    match super::transaction::resolve_delta_postconditions(view, seed.program()) {
                        Ok(candidate) => {
                            self.transcript = StorageTranscript::new(
                                StorageTarget::Filesystem,
                                self.transcript.len(),
                            );
                            self.phase = DeltaReplayPhase::CandidateOrphans { seed, candidate };
                            Ok(())
                        }
                        Err(error) => {
                            self.phase = DeltaReplayPhase::Resolve {
                                superblock,
                                seed,
                                clusters,
                            };
                            Err(error)
                        }
                    }
                }
                DeltaReplayPhase::CandidateOrphans { seed, candidate } => {
                    let device = OperationDevice::with_overlay(
                        &mut self.transcript,
                        &candidate.images,
                        None,
                    );
                    let mut view = EpochReadView::mounting(device, candidate.superblock, keys);
                    match ValidatedOrphanInventory::load(&mut view) {
                        Ok(orphans) => {
                            self.phase = DeltaReplayPhase::IndexCandidate {
                                seed,
                                candidate,
                                orphans,
                                index: memory::try_box(AllocationIndexBuild::new())?,
                            };
                            Ok(())
                        }
                        Err(error) => {
                            self.phase = DeltaReplayPhase::CandidateOrphans { seed, candidate };
                            Err(error)
                        }
                    }
                }
                DeltaReplayPhase::IndexCandidate {
                    seed,
                    candidate,
                    orphans,
                    mut index,
                } => match index.advance(&mut self.transcript, &candidate.superblock, &orphans) {
                    Ok(_validated) => {
                        let prepared = seed.prepare_commit(
                            candidate.superblock.block_size(),
                            candidate.images.into_blocks(),
                        )?;
                        self.phase = DeltaReplayPhase::Ready(StorageRequestSequence::checkpoint(
                            prepared,
                            |journal| journal,
                        )?);
                        Ok(())
                    }
                    Err(error) => {
                        self.phase = DeltaReplayPhase::IndexCandidate {
                            seed,
                            candidate,
                            orphans,
                            index,
                        };
                        Err(error)
                    }
                },
                DeltaReplayPhase::Ready(sequence) => {
                    self.phase = DeltaReplayPhase::Ready(sequence);
                    return Ok(None);
                }
                DeltaReplayPhase::Failed => return Err(Error::DeviceIo),
            };
            match result {
                Ok(()) => {}
                Err(Error::OperationSuspended) => {
                    return self.transcript.take_pending_request().map(Some);
                }
                Err(error) => {
                    self.phase = DeltaReplayPhase::Failed;
                    return Err(error);
                }
            }
        }
    }

    /// The complete replacement is revealed only after candidate validation and preallocation.
    /// # Errors
    /// Rejects unfinished or failed preparation instead of discarding its recovery obligation.
    pub(super) fn into_sequence(self) -> Result<StorageRequestSequence<Journal<CleanJournal>>> {
        match self.phase {
            DeltaReplayPhase::Ready(sequence) => Ok(sequence),
            _ => Err(Error::DeviceIo),
        }
    }
}
