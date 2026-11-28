//! Session close after the host drains all journal users.

use alloc::boxed::Box;

use super::session::{MountIdentity, MountedProfile, MutationCoordinatorState};
use super::session_marker::prepare_session_checkpoint;
use super::transaction::{StorageRequestSequence, StorageRequestSequenceStep};
use crate::disk::block::BlockSize;
use crate::disk::storage::{OperationDevice, StorageTarget, StorageTranscript};
use crate::disk_format::inode::Ext4Timestamp;
use crate::disk_format::journal::{CleanJournal, Journal, PreparedCleanJournal};
use crate::disk_format::superblock::{Superblock, WriteSessionState};
use crate::{Error, Result};

/// Proof that this session's media-change obligations completed after its operations drained.
/// Read-only sessions leave the medium's existing recovery markers unchanged.
#[derive(Debug)]
pub struct CleanCloseDurability {
    /// Completion belongs to one admitted session even when UUIDs and device lengths match.
    pub(super) mount: MountIdentity,
}

/// One consuming transition of the clean-close durability protocol.
#[derive(Debug)]
pub enum CleanCloseTransition {
    /// Submit one prepared source read or journal/checkpoint transfer.
    SubmitLower {
        /// Owned lower-storage request.
        request: crate::StorageRequest,
        /// Operation resumed only by the matching completion.
        suspended: Box<CleanCloseOperation>,
    },
    /// This session has no remaining media-change obligation, or closing failed.
    Complete(Result<CleanCloseDurability>),
}

/// Allocation-before-effects clean shutdown/dismount operation.
#[derive(Debug)]
pub struct CleanCloseOperation {
    /// Exact mount whose drained journal may authorize finalization.
    mount: MountIdentity,
    /// Read-only sessions have no media effects, including flushes.
    access: super::MediaAccess,
    /// Transcript retained until every source byte has been read before effects.
    filesystem: StorageTranscript,
    /// Validated primary block width.
    block_size: BlockSize,
    /// Independent journal device, when present, must be flushed before close publication.
    journal_target: Option<StorageTarget>,
    /// Owns exactly one preparation or lower-transfer continuation.
    phase: CleanClosePhase,
}

/// Frozen after native writeback and every journal user has drained.
#[derive(Debug)]
struct CleanClosePreparation {
    /// Exact drained cursor; no later mutation may advance it during close.
    journal: Journal<CleanJournal>,
    /// One close event clock, retained unchanged across suspended source reads.
    unix_seconds: u64,
}

/// Source preparation and effect submission cannot share a live continuation.
#[derive(Debug)]
enum CleanClosePhase {
    /// Admission and native writeback have not yet drained.
    Ready,
    /// Latest drained journal cursor and close clock, sampled before any close effect.
    Preparing(CleanClosePreparation),
    /// Source read must complete before preparation resumes.
    ReadPending(CleanClosePreparation),
    /// Fully prepared flush, log, checkpoint and clean-journal requests.
    Writing(StorageRequestSequence<PreparedCleanJournal>),
    /// Matching completion alone can reveal the remaining sequence.
    Pending(crate::PendingStorageTransfer<StorageRequestSequence<PreparedCleanJournal>>),
    /// Completion consumed this operation's close authority.
    Complete,
}

impl CleanCloseOperation {
    /// Allocates no journal snapshot until the host seals admission and drains native writeback,
    /// mutations, checkpoints and discard. That exclusion must last through finalization.
    #[must_use]
    pub const fn new(profile: &MountedProfile) -> Self {
        Self {
            mount: profile.mount,
            access: profile.access(),
            filesystem: StorageTranscript::new(
                StorageTarget::Filesystem,
                profile.filesystem_length(),
            ),
            block_size: profile.block_size(),
            journal_target: profile.journal_target(),
            phase: CleanClosePhase::Ready,
        }
    }

    /// Starts finalization using the latest drained journal cursor and current wall clock.
    /// A failure after submission can leave a committed close for subsequent mount recovery;
    /// the host must retain exclusion and must not retry an uncertain close.
    #[must_use]
    pub fn start(
        mut self: Box<Self>,
        coordinator: &MutationCoordinatorState,
        now: Ext4Timestamp,
    ) -> CleanCloseTransition {
        if !matches!(self.phase, CleanClosePhase::Ready) || self.mount != coordinator.mount() {
            return CleanCloseTransition::Complete(Err(Error::ClusterReferenceConflict));
        }
        if matches!(self.access, super::MediaAccess::ReadOnly) {
            return CleanCloseTransition::Complete(Ok(CleanCloseDurability { mount: self.mount }));
        }
        let journal = match coordinator.drained_journal() {
            Ok(journal) => journal,
            Err(error) => return CleanCloseTransition::Complete(Err(error)),
        };
        // Unsigned superblock clocks clamp dates before the Unix epoch to zero.
        self.phase = CleanClosePhase::Preparing(CleanClosePreparation {
            journal,
            unix_seconds: u64::try_from(now.seconds()).unwrap_or(0),
        });
        self.drive()
    }

    /// Completes one exact transfer. The host retains cancellation until durability completes.
    #[must_use]
    pub fn advance(mut self: Box<Self>, event: super::OperationEvent) -> CleanCloseTransition {
        let super::OperationEvent::StorageCompleted(completion) = event else {
            return CleanCloseTransition::Complete(Err(Error::DeviceIo));
        };
        let result = match core::mem::replace(&mut self.phase, CleanClosePhase::Complete) {
            CleanClosePhase::ReadPending(preparation) => self
                .filesystem
                .complete(completion)
                .map(|()| CleanClosePhase::Preparing(preparation)),
            CleanClosePhase::Pending(pending) => {
                pending.complete(completion).map(CleanClosePhase::Writing)
            }
            _ => Err(Error::DeviceIo),
        };
        match result {
            Ok(phase) => {
                self.phase = phase;
                self.drive()
            }
            Err(error) => CleanCloseTransition::Complete(Err(error)),
        }
    }

    /// Reads every source and prepares every request before issuing the initial durability barrier.
    fn drive(mut self: Box<Self>) -> CleanCloseTransition {
        loop {
            match core::mem::replace(&mut self.phase, CleanClosePhase::Complete) {
                CleanClosePhase::Preparing(preparation) => {
                    let result = (|| {
                        let mut device = OperationDevice::new(&mut self.filesystem);
                        let raw = Superblock::prepare_write_session(
                            &mut device,
                            WriteSessionState::Closed,
                            preparation.unix_seconds,
                        )?;
                        let flushes = [StorageTarget::Filesystem, StorageTarget::ExternalJournal];
                        let flush_before =
                            if self.journal_target == Some(StorageTarget::ExternalJournal) {
                                &flushes[..]
                            } else {
                                &flushes[..1]
                            };
                        prepare_session_checkpoint(
                            &mut device,
                            &raw,
                            self.block_size,
                            &preparation.journal,
                            flush_before,
                        )
                    })();
                    match result {
                        Ok(sequence) => self.phase = CleanClosePhase::Writing(sequence),
                        Err(Error::OperationSuspended) => {
                            let request = match self.filesystem.take_pending_request() {
                                Ok(request) => request,
                                Err(error) => return CleanCloseTransition::Complete(Err(error)),
                            };
                            self.phase = CleanClosePhase::ReadPending(preparation);
                            return CleanCloseTransition::SubmitLower {
                                request,
                                suspended: self,
                            };
                        }
                        Err(error) => return CleanCloseTransition::Complete(Err(error)),
                    }
                }
                CleanClosePhase::Writing(sequence) => match sequence.advance() {
                    StorageRequestSequenceStep::Submit { request, suspended } => {
                        self.phase = CleanClosePhase::Pending(suspended);
                        return CleanCloseTransition::SubmitLower {
                            request,
                            suspended: self,
                        };
                    }
                    StorageRequestSequenceStep::Finished(_journal) => {
                        return CleanCloseTransition::Complete(Ok(CleanCloseDurability {
                            mount: self.mount,
                        }));
                    }
                },
                _ => return CleanCloseTransition::Complete(Err(Error::DeviceIo)),
            }
        }
    }
}
