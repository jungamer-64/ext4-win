//! Pointer-free device-local operation scheduling model.
//!
//! This module owns only bounded identities and scheduling facts. Kernel objects, IRPs, lower
//! completion envelopes, callbacks, and mounted-volume authority remain in the reactor shell.

use ext4_core::{EpochSequence, MutationResource};

use crate::memory::DriverVec;

/// Hard bound shared by pending and active filesystem operations on one device.
pub(crate) const MAX_OPERATIONS: usize = 64;

/// Scheduler-local identity for the per-handle CLEANUP terminal barrier.
pub(crate) const CLEANUP_HANDLE_BARRIER: u64 = 2;
/// Scheduler-local identity for the terminal CLOSE drain.
pub(crate) const CLOSE_HANDLE_BARRIER: u64 = 3;

/// Generation-checked identity of one bounded scheduler slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SlotId {
    /// Fixed slot index used by shell-owned envelopes.
    index: usize,
    /// Monotonic reuse generation at that index.
    generation: u64,
}

impl SlotId {
    /// Reconstructs a callback-carried identity for generation validation.
    pub(crate) const fn from_parts(index: usize, generation: u64) -> Self {
        Self { index, generation }
    }

    /// Fixed bounded index.
    pub(crate) const fn index(self) -> usize {
        self.index
    }

    /// Reuse generation captured with this identity.
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

/// Pointer-free identity of one FILE_OBJECT serialization lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HandleId(usize);

impl HandleId {
    /// Builds an opaque identity from a shell-owned address value.
    pub(crate) const fn from_address(address: usize) -> Self {
        Self(address)
    }
}

/// Requests whose FILE_OBJECT lifetime legally continues after CLEANUP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PostCleanupRequest {
    /// Paging read captured from `IRP_PAGING_IO`.
    PagingRead,
    /// Paging write captured from `IRP_PAGING_IO`.
    PagingWrite,
    /// Explicit device flush that accesses no user-visible handle authority.
    FlushBuffers,
    /// Terminal context release after every earlier post-cleanup request drains.
    Close,
}

/// Exact per-handle scheduler lane selected at operation admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleOperationLane {
    /// Normal request admitted only while the handle is open.
    Ordinary,
    /// Terminal cleanup barrier that closes ordinary admission.
    Cleanup,
    /// Explicitly legal post-cleanup request.
    PostCleanup(PostCleanupRequest),
}

/// Pointer-free operation admission classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Admission {
    /// Device-wide request with no handle serialization requirement.
    Device,
    /// Request serialized in one stable handle lane.
    Handle {
        /// Opaque handle identity.
        handle: HandleId,
        /// Typed lifecycle lane.
        lane: HandleOperationLane,
    },
}

impl Admission {
    /// Returns the per-handle identity, if any.
    const fn handle(self) -> Option<HandleId> {
        match self {
            Self::Device => None,
            Self::Handle { handle, .. } => Some(handle),
        }
    }

    /// Returns whether CLEANUP may cancel this active operation.
    const fn is_ordinary_handle(self) -> bool {
        matches!(
            self,
            Self::Handle {
                lane: HandleOperationLane::Ordinary,
                ..
            }
        )
    }

    /// Returns whether cancellation must not preempt this terminal operation.
    pub(crate) const fn is_terminal_barrier(self) -> bool {
        matches!(
            self,
            Self::Handle {
                lane: HandleOperationLane::Cleanup
                    | HandleOperationLane::PostCleanup(PostCleanupRequest::Close),
                ..
            }
        )
    }
}

/// Resource-intent request prepared before mutation reservation.
#[derive(Debug)]
pub(crate) struct IntentRequest {
    /// Stable FIFO mutation ticket.
    ticket: u64,
    /// Complete resource set acquired atomically or not at all.
    resources: DriverVec<MutationResource>,
}

impl IntentRequest {
    /// Builds an intent request before any lower write exists.
    pub(crate) const fn new(ticket: u64, resources: DriverVec<MutationResource>) -> Self {
        Self { ticket, resources }
    }

    /// Stable FIFO ticket.
    pub(crate) const fn ticket(&self) -> u64 {
        self.ticket
    }

    /// Complete opaque resource set.
    pub(crate) fn resources(&self) -> &[MutationResource] {
        self.resources.as_slice()
    }
}

/// Reason an operation is suspended without a lower transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitCondition {
    /// Durable values are waiting for the epoch visibility gate.
    Visibility {
        /// Mutation ticket whose durable overlay is awaiting publication.
        ticket: u64,
    },
    /// Published overlay work is waiting for the checkpoint slot.
    Checkpoint {
        /// Visible epoch whose home-block checkpoint is awaiting publication.
        epoch: EpochSequence,
    },
    /// Flush waits for every queued or granted commit to become durable.
    VolumeDurability,
    /// Clean close waits until journal space is clean.
    JournalClean,
    /// Per-handle terminal or durability barrier.
    Barrier {
        /// Typed barrier identity expected by the suspended operation.
        identity: u64,
    },
}

/// Scheduler phase independent from shell-owned operation payloads.
#[derive(Debug)]
pub(crate) enum Phase {
    /// Slot is available.
    Vacant,
    /// Sole actor temporarily owns the payload while selecting the next phase.
    Actor,
    /// One concrete event is ready for delivery.
    Ready,
    /// Admission waits for the exact earlier handle predecessor.
    HandleTurn,
    /// Resource intent is queued under FIFO arbitration.
    Intent(IntentRequest),
    /// Journal commit grant is queued.
    Commit {
        /// Mutation ticket queued for the serialized commit lane.
        ticket: u64,
    },
    /// Non-I/O gate wait.
    Waiting(WaitCondition),
    /// One retry timer is armed.
    Retry,
    /// Lower IRP registration/call is executing.
    Registering,
    /// A completion envelope owns the lower lifetime.
    Lower,
}

/// Resource ownership retained after an intent grant.
#[derive(Debug)]
struct HeldIntent {
    /// Stable FIFO ticket.
    ticket: u64,
    /// Complete atomically acquired resource set.
    resources: DriverVec<MutationResource>,
}

/// Serialized commit ownership retained until publication or abandonment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeldCommit {
    /// Stable FIFO ticket.
    ticket: u64,
}

/// One pointer-free bounded operation slot.
#[derive(Debug)]
struct Slot {
    /// Monotonic reuse generation.
    generation: u64,
    /// Resource set held through durable visibility publication.
    intent: Option<HeldIntent>,
    /// Commit grant held through durable publication.
    commit: Option<HeldCommit>,
    /// Published cancellation not yet consumed.
    cancel_pending: bool,
    /// Cancellation remains legal before the effect boundary.
    cancel_enabled: bool,
    /// Device or handle lane.
    admission: Option<Admission>,
    /// Exact earlier same-handle slot.
    predecessor: Option<SlotId>,
    /// Current scheduling phase.
    phase: Phase,
}

impl Slot {
    /// Creates one vacant slot.
    const fn vacant() -> Self {
        Self {
            generation: 0,
            intent: None,
            commit: None,
            cancel_pending: false,
            cancel_enabled: false,
            admission: None,
            predecessor: None,
            phase: Phase::Vacant,
        }
    }
}

/// Result of installing a newly decoded operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionStart {
    /// Cancellation was already published and must be delivered first.
    Cancelled,
    /// Exact same-handle predecessor must terminate first.
    HandleTurn,
    /// Admission may be delivered immediately.
    Admitted,
}

/// Result of requesting cancellation for one phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancelDisposition {
    /// Cancellation is disabled or already retired.
    Ignored,
    /// Shell must recover the suspended operation and deliver cancellation.
    ResumeOperation,
    /// Shell must propagate cancellation to the active lower request.
    CancelLower,
    /// Retry remains armed; timer delivery will observe cancellation.
    AwaitRetry,
    /// Registration cannot be interrupted; its result will observe cancellation.
    AwaitRegistration,
}

/// Result of requesting an intent from an operation that may already retain the same set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntentDisposition {
    /// The exact grant remains held across re-resolution.
    Retained,
    /// Request was queued and must await FIFO arbitration.
    Queued,
}

/// Pointer-free scheduler for one device-local reactor.
#[derive(Debug)]
pub(crate) struct Scheduler {
    /// Fixed bounded slot registry.
    slots: [Slot; MAX_OPERATIONS],
    /// Terminal drain closes further model admission.
    draining: bool,
}

impl Scheduler {
    /// Creates an empty running scheduler.
    pub(crate) fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| Slot::vacant()),
            draining: false,
        }
    }

    /// Closes model admission while allowing active slots to drain.
    pub(crate) fn begin_drain(&mut self) {
        self.draining = true;
    }

    /// Returns active slots whose legal cancellation has not yet been requested.
    pub(crate) fn drain_cancel_mask(&self) -> u64 {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| {
                !matches!(slot.phase, Phase::Vacant) && slot.cancel_enabled && !slot.cancel_pending
            })
            .fold(0_u64, |mask, (index, _)| mask | (1_u64 << index))
    }

    /// Reserves one vacant slot with a fresh generation.
    pub(crate) fn reserve(&mut self) -> Option<SlotId> {
        if self.draining {
            return None;
        }
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| matches!(slot.phase, Phase::Vacant))?;
        slot.generation = slot.generation.checked_add(1)?;
        slot.cancel_pending = false;
        slot.cancel_enabled = true;
        slot.admission = None;
        slot.predecessor = None;
        slot.phase = Phase::Actor;
        Some(SlotId {
            index,
            generation: slot.generation,
        })
    }

    /// Returns the current identity at a fixed index.
    pub(crate) fn identity(&self, index: usize) -> Option<SlotId> {
        let slot = self.slots.get(index)?;
        (!matches!(slot.phase, Phase::Vacant)).then_some(SlotId {
            index,
            generation: slot.generation,
        })
    }

    /// Verifies a callback-provided generation and enters actor ownership.
    pub(crate) fn enter_retry(&mut self, identity: SlotId) -> bool {
        let Some(slot) = self.slot_mut(identity) else {
            return false;
        };
        if !matches!(slot.phase, Phase::Retry) {
            return false;
        }
        slot.phase = Phase::Actor;
        true
    }

    /// Installs scheduler admission for one actor-owned reservation.
    pub(crate) fn install(
        &mut self,
        identity: SlotId,
        admission: Admission,
        cancelled: bool,
    ) -> Option<AdmissionStart> {
        let predecessor = admission
            .handle()
            .and_then(|handle| self.latest_handle_predecessor(identity.index, handle));
        let slot = self.slot_mut(identity)?;
        if !matches!(slot.phase, Phase::Actor)
            || slot.intent.is_some()
            || slot.commit.is_some()
            || slot.admission.is_some()
        {
            return None;
        }
        let terminal = admission.is_terminal_barrier();
        slot.cancel_enabled = !terminal;
        slot.cancel_pending = cancelled && !terminal;
        slot.admission = Some(admission);
        slot.predecessor = predecessor;
        let start = if slot.cancel_pending {
            AdmissionStart::Cancelled
        } else if predecessor.is_some() {
            AdmissionStart::HandleTurn
        } else {
            AdmissionStart::Admitted
        };
        slot.phase = match start {
            AdmissionStart::Cancelled | AdmissionStart::Admitted => Phase::Ready,
            AdmissionStart::HandleTurn => Phase::HandleTurn,
        };
        Some(start)
    }

    /// Moves one ready slot to sole-actor ownership.
    pub(crate) fn take_ready(&mut self) -> Option<SlotId> {
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| matches!(slot.phase, Phase::Ready))?;
        slot.phase = Phase::Actor;
        Some(SlotId {
            index,
            generation: slot.generation,
        })
    }

    /// Sets an actor-owned slot to a new phase.
    pub(crate) fn set_phase(&mut self, identity: SlotId, phase: Phase) -> bool {
        let Some(slot) = self.slot_mut(identity) else {
            return false;
        };
        if !matches!(slot.phase, Phase::Actor) {
            return false;
        }
        slot.phase = phase;
        true
    }

    /// Moves a phase selected by the shell into actor ownership.
    pub(crate) fn enter_phase(
        &mut self,
        index: usize,
        predicate: impl FnOnce(&Phase) -> bool,
    ) -> Option<SlotId> {
        let slot = self.slots.get_mut(index)?;
        if !predicate(&slot.phase) {
            return None;
        }
        slot.phase = Phase::Actor;
        Some(SlotId {
            index,
            generation: slot.generation,
        })
    }

    /// Completes and vacates one actor-owned slot.
    pub(crate) fn complete(&mut self, identity: SlotId) -> bool {
        let Some(slot) = self.slot_mut(identity) else {
            return false;
        };
        if !matches!(slot.phase, Phase::Actor) || slot.intent.is_some() || slot.commit.is_some() {
            return false;
        }
        slot.admission = None;
        slot.predecessor = None;
        slot.cancel_pending = false;
        slot.cancel_enabled = false;
        slot.phase = Phase::Vacant;
        true
    }

    /// Returns whether any slot retains active scheduling state.
    pub(crate) fn has_active(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| !matches!(slot.phase, Phase::Vacant))
    }

    /// Detaches a handle lane while post-publication work continues.
    pub(crate) fn release_handle_lane(&mut self, identity: SlotId) -> bool {
        let Some(slot) = self.slot_mut(identity) else {
            return false;
        };
        slot.admission = None;
        slot.predecessor = None;
        true
    }

    /// Returns active ordinary-handle slots preceding one cleanup operation.
    pub(crate) fn ordinary_handle_mask(&self, excluded: usize, handle: HandleId) -> u64 {
        self.slots
            .iter()
            .enumerate()
            .filter(|(index, slot)| {
                *index != excluded
                    && slot.admission.is_some_and(|admission| {
                        admission.handle() == Some(handle) && admission.is_ordinary_handle()
                    })
            })
            .fold(0_u64, |mask, (index, _)| mask | (1_u64 << index))
    }

    /// Marks cancellation as retired for one live slot.
    pub(crate) fn retire_cancel(&mut self, index: usize) -> bool {
        let Some(slot) = self.slots.get_mut(index) else {
            return false;
        };
        slot.cancel_pending = false;
        slot.cancel_enabled = false;
        true
    }

    /// Folds one callback publication into cancellation state.
    pub(crate) fn cancellation_is_pending(&mut self, index: usize, published: bool) -> bool {
        let Some(slot) = self.slots.get_mut(index) else {
            return false;
        };
        if !slot.cancel_enabled {
            slot.cancel_pending = false;
            return false;
        }
        slot.cancel_pending |= published;
        slot.cancel_pending
    }

    /// Atomically consumes cancellation before the first effect-bearing operation.
    pub(crate) fn consume_cancel_before_effect(&mut self, index: usize, published: bool) -> bool {
        let Some(slot) = self.slots.get_mut(index) else {
            return false;
        };
        if !slot.cancel_enabled {
            slot.cancel_pending = false;
            return false;
        }
        slot.cancel_pending |= published;
        if slot.cancel_pending {
            true
        } else {
            slot.cancel_enabled = false;
            false
        }
    }

    /// Applies cancellation to the current scheduler phase.
    pub(crate) fn request_cancel(&mut self, index: usize) -> CancelDisposition {
        let Some(slot) = self.slots.get_mut(index) else {
            return CancelDisposition::Ignored;
        };
        if !slot.cancel_enabled {
            slot.cancel_pending = false;
            return CancelDisposition::Ignored;
        }
        slot.cancel_pending = true;
        match slot.phase {
            Phase::Ready
            | Phase::HandleTurn
            | Phase::Intent(_)
            | Phase::Commit { .. }
            | Phase::Waiting(_) => {
                slot.phase = Phase::Ready;
                CancelDisposition::ResumeOperation
            }
            Phase::Lower => CancelDisposition::CancelLower,
            Phase::Retry => CancelDisposition::AwaitRetry,
            Phase::Registering | Phase::Actor => CancelDisposition::AwaitRegistration,
            Phase::Vacant => CancelDisposition::Ignored,
        }
    }

    /// Queues an intent or retains an exact previously granted set.
    pub(crate) fn request_intent(
        &mut self,
        identity: SlotId,
        request: IntentRequest,
    ) -> Option<IntentDisposition> {
        let slot = self.slot_mut(identity)?;
        if !matches!(slot.phase, Phase::Actor) {
            return None;
        }
        if slot
            .intent
            .as_ref()
            .is_some_and(|held| held_intent_matches_request(held, &request))
        {
            slot.phase = Phase::Ready;
            return Some(IntentDisposition::Retained);
        }
        slot.intent = None;
        slot.phase = Phase::Intent(request);
        Some(IntentDisposition::Queued)
    }

    /// Selects and grants the next conflict-free FIFO intent.
    pub(crate) fn grant_next_intent(&mut self) -> Option<(SlotId, u64)> {
        let candidate = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let Phase::Intent(request) = &slot.phase else {
                    return None;
                };
                if intent_conflicts_with_held(&self.slots, request)
                    || earlier_queued_intent_conflicts(&self.slots, request)
                {
                    return None;
                }
                Some((request.ticket(), index))
            })
            .min_by_key(|candidate| *candidate)?;
        let (ticket, index) = candidate;
        let slot = self.slots.get_mut(index)?;
        let phase = core::mem::replace(&mut slot.phase, Phase::Actor);
        let Phase::Intent(request) = phase else {
            return None;
        };
        slot.intent = Some(HeldIntent {
            ticket,
            resources: request.resources,
        });
        Some((
            SlotId {
                index,
                generation: slot.generation,
            },
            ticket,
        ))
    }

    /// Releases any held intent from a live slot.
    pub(crate) fn release_intent(&mut self, identity: SlotId) -> bool {
        let Some(slot) = self.slot_mut(identity) else {
            return false;
        };
        slot.intent = None;
        true
    }

    /// Queues one commit request from actor ownership.
    pub(crate) fn request_commit(&mut self, identity: SlotId, ticket: u64) -> bool {
        self.set_phase(identity, Phase::Commit { ticket })
    }

    /// Returns the earliest unattempted queued commit.
    pub(crate) fn next_commit_candidate(
        &self,
        attempted: &[bool; MAX_OPERATIONS],
    ) -> Option<(SlotId, u64)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let attempted = attempted.get(index).copied()?;
                if attempted {
                    return None;
                }
                let Phase::Commit { ticket } = slot.phase else {
                    return None;
                };
                Some((
                    SlotId {
                        index,
                        generation: slot.generation,
                    },
                    ticket,
                ))
            })
            .min_by_key(|(_, ticket)| *ticket)
    }

    /// Records a runtime-granted commit and enters actor ownership.
    pub(crate) fn grant_commit(&mut self, identity: SlotId, ticket: u64) -> bool {
        let Some(slot) = self.slot_mut(identity) else {
            return false;
        };
        if !matches!(slot.phase, Phase::Commit { ticket: queued } if queued == ticket)
            || slot.commit.is_some()
        {
            return false;
        }
        slot.commit = Some(HeldCommit { ticket });
        slot.phase = Phase::Actor;
        true
    }

    /// Returns an ungranted commit to actor ownership for its terminal volume-failure event.
    /// No commit capability is fabricated, and existing resource intents remain until completion.
    pub(crate) fn reject_commit(&mut self, identity: SlotId, ticket: u64) -> bool {
        let Some(slot) = self.slot_mut(identity) else {
            return false;
        };
        if !matches!(slot.phase, Phase::Commit { ticket: queued } if queued == ticket)
            || slot.commit.is_some()
        {
            return false;
        }
        slot.phase = Phase::Actor;
        true
    }

    /// Removes a pre-write commit grant for return to the runtime.
    pub(crate) fn abandon_commit(&mut self, identity: SlotId) -> Option<u64> {
        self.slot_mut(identity)?
            .commit
            .take()
            .map(|commit| commit.ticket)
    }

    /// Returns whether any queued or held commit remains.
    pub(crate) fn has_commit_work(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.commit.is_some() || matches!(slot.phase, Phase::Commit { .. }))
    }

    /// Installs one wait condition from actor ownership.
    pub(crate) fn request_wait(&mut self, identity: SlotId, condition: WaitCondition) -> bool {
        self.set_phase(identity, Phase::Waiting(condition))
    }

    /// Enters a one-way closing wait and revokes top-level cancellation permanently.
    ///
    /// The lifecycle transition to `Closing` is already published before this call. A callback
    /// racing with actor execution therefore cannot restore the pre-closing state or abandon the
    /// durability outcome.
    pub(crate) fn request_closing_wait(
        &mut self,
        identity: SlotId,
        condition: WaitCondition,
    ) -> bool {
        let Some(slot) = self.slot_mut(identity) else {
            return false;
        };
        if !matches!(slot.phase, Phase::Actor) {
            return false;
        }
        slot.cancel_pending = false;
        slot.cancel_enabled = false;
        slot.phase = Phase::Waiting(condition);
        true
    }

    /// Returns one fixed slot's current wait condition.
    pub(crate) fn wait_condition(&self, index: usize) -> Option<WaitCondition> {
        let Phase::Waiting(condition) = self.slots.get(index)?.phase else {
            return None;
        };
        Some(condition)
    }

    /// Grants one waiting slot and enters actor ownership.
    pub(crate) fn grant_wait(&mut self, index: usize) -> Option<SlotId> {
        self.enter_phase(index, |phase| matches!(phase, Phase::Waiting(_)))
    }

    /// Returns handle-turn slots whose exact predecessor has terminated.
    pub(crate) fn ready_handle_turns(&self) -> u64 {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| {
                matches!(slot.phase, Phase::HandleTurn)
                    && slot
                        .predecessor
                        .is_none_or(|predecessor| !self.predecessor_is_live(predecessor))
            })
            .fold(0_u64, |mask, (index, _)| mask | (1_u64 << index))
    }

    /// Grants one handle turn and enters actor ownership.
    pub(crate) fn grant_handle_turn(&mut self, index: usize) -> Option<SlotId> {
        let identity = self.enter_phase(index, |phase| matches!(phase, Phase::HandleTurn))?;
        self.slot_mut(identity)?.predecessor = None;
        Some(identity)
    }

    /// Checks whether a barrier is currently releasable.
    pub(crate) fn terminal_barrier_is_releasable(&self, index: usize, identity: u64) -> bool {
        let Some(slot) = self.slots.get(index) else {
            return false;
        };
        if slot.predecessor.is_some() {
            return false;
        }
        matches!(
            (slot.admission, identity),
            (
                Some(Admission::Handle {
                    lane: HandleOperationLane::Cleanup,
                    ..
                }),
                CLEANUP_HANDLE_BARRIER
            ) | (
                Some(Admission::Handle {
                    lane: HandleOperationLane::PostCleanup(PostCleanupRequest::Close),
                    ..
                }),
                CLOSE_HANDLE_BARRIER
            )
        )
    }

    /// Consumes grants required by durable publication.
    pub(crate) fn consume_durable_authority(&mut self, identity: SlotId, ticket: u64) -> bool {
        let Some(slot) = self.slot_mut(identity) else {
            return false;
        };
        let intent = slot.intent.take();
        let commit = slot.commit.take();
        matches!(intent, Some(HeldIntent { ticket: held, .. }) if held == ticket)
            && commit == Some(HeldCommit { ticket })
    }

    /// Verifies that checkpoint publication owns no mutation grants.
    pub(crate) fn checkpoint_authority_is_clear(&self, identity: SlotId) -> bool {
        self.slot(identity)
            .is_some_and(|slot| slot.intent.is_none() && slot.commit.is_none())
    }

    /// Returns the live slot matching an exact index-generation identity.
    fn slot(&self, identity: SlotId) -> Option<&Slot> {
        self.slots
            .get(identity.index)
            .filter(|slot| slot.generation == identity.generation)
    }

    /// Returns the uniquely borrowed live slot matching an exact identity.
    fn slot_mut(&mut self, identity: SlotId) -> Option<&mut Slot> {
        self.slots
            .get_mut(identity.index)
            .filter(|slot| slot.generation == identity.generation)
    }

    /// Reports whether an exact predecessor generation still owns work.
    fn predecessor_is_live(&self, predecessor: SlotId) -> bool {
        self.slot(predecessor)
            .is_some_and(|slot| !matches!(slot.phase, Phase::Vacant))
    }

    /// Finds the unique tail of one handle lane before installing a reserved slot.
    fn latest_handle_predecessor(&self, reserved_index: usize, handle: HandleId) -> Option<SlotId> {
        let mut tail = None;
        for (index, slot) in self.slots.iter().enumerate() {
            if index == reserved_index
                || matches!(slot.phase, Phase::Vacant | Phase::Actor)
                || slot.admission.and_then(Admission::handle) != Some(handle)
            {
                continue;
            }
            let identity = SlotId {
                index,
                generation: slot.generation,
            };
            let has_successor =
                self.slots
                    .iter()
                    .enumerate()
                    .any(|(successor_index, successor)| {
                        successor_index != reserved_index
                            && !matches!(successor.phase, Phase::Vacant)
                            && successor.admission.and_then(Admission::handle) == Some(handle)
                            && successor.predecessor == Some(identity)
                    });
            if !has_successor && tail.replace(identity).is_some() {
                return None;
            }
        }
        tail
    }
}

/// Whether two complete resource sets overlap.
fn resource_sets_overlap(left: &[MutationResource], right: &[MutationResource]) -> bool {
    left.iter().any(|resource| right.contains(resource))
}

/// Tests a queued request against every currently held set.
fn intent_conflicts_with_held(slots: &[Slot; MAX_OPERATIONS], request: &IntentRequest) -> bool {
    slots.iter().any(|slot| {
        slot.intent.as_ref().is_some_and(|held| {
            resource_sets_overlap(held.resources.as_slice(), request.resources())
        })
    })
}

/// Returns whether a re-resolved mutation requests the exact resource set it already owns.
fn held_intent_matches_request(held: &HeldIntent, request: &IntentRequest) -> bool {
    held.ticket == request.ticket()
        && mutation_resource_sets_equal(held.resources.as_slice(), request.resources())
}

/// Compares mutation resource sets without relying on discovery order.
fn mutation_resource_sets_equal(left: &[MutationResource], right: &[MutationResource]) -> bool {
    left.len() == right.len()
        && left.iter().all(|resource| right.contains(resource))
        && right.iter().all(|resource| left.contains(resource))
}

/// Prevents a later ticket from bypassing an earlier overlapping request.
fn earlier_queued_intent_conflicts(
    slots: &[Slot; MAX_OPERATIONS],
    request: &IntentRequest,
) -> bool {
    slots.iter().any(|slot| {
        let Phase::Intent(earlier) = &slot.phase else {
            return false;
        };
        earlier.ticket() < request.ticket()
            && resource_sets_overlap(earlier.resources(), request.resources())
    })
}

#[cfg(test)]
mod tests {
    use ext4_core::MutationResource;

    use crate::memory::DriverVec;

    use super::{
        Admission, AdmissionStart, CLEANUP_HANDLE_BARRIER, CancelDisposition, HandleId,
        HandleOperationLane, IntentRequest, MAX_OPERATIONS, Phase, PostCleanupRequest, Scheduler,
        SlotId, WaitCondition,
    };

    /// Extracts required fixture state while preserving assertion-based test failure.
    macro_rules! require_some {
        ($candidate:expr) => {{
            let candidate = $candidate;
            assert!(candidate.is_some());
            let Some(value) = candidate else {
                return;
            };
            value
        }};
    }

    /// Builds one bounded resource set, returning `None` on fixture allocation failure.
    fn resources(values: &[MutationResource]) -> Option<DriverVec<MutationResource>> {
        let mut resources = DriverVec::new();
        for value in values {
            if resources.try_push(*value).is_err() {
                return None;
            }
        }
        Some(resources)
    }

    /// Verifies bounded admission and generation-safe slot reuse.
    /// # Panics
    ///
    /// Panics when the scheduler violates its bounded slot identity contract.
    #[test]
    fn slot_bound_and_generation_reuse_are_exact() {
        let mut scheduler = Scheduler::new();
        let mut slots = [None; MAX_OPERATIONS];
        for slot in &mut slots {
            *slot = scheduler.reserve();
            assert!(slot.is_some());
        }
        assert!(scheduler.reserve().is_none());
        let first = require_some!(slots.first().copied().flatten());
        assert!(scheduler.complete(first));
        let reused = require_some!(scheduler.reserve());
        assert_eq!(reused.index(), first.index());
        assert_eq!(reused.generation(), first.generation() + 1);
    }

    /// Verifies conflict-aware FIFO intent admission without head-of-line blocking.
    /// # Panics
    ///
    /// Panics when intent arbitration violates overlap or ticket ordering.
    #[test]
    fn conflicting_intents_are_fifo_while_disjoint_intents_progress() {
        let mut scheduler = Scheduler::new();
        let first = require_some!(scheduler.reserve());
        let second = require_some!(scheduler.reserve());
        let disjoint = require_some!(scheduler.reserve());
        let first_resources = require_some!(resources(&[MutationResource::VOLUME_METADATA]));
        let second_resources = require_some!(resources(&[MutationResource::VOLUME_METADATA]));
        let disjoint_resources = require_some!(resources(&[MutationResource::KEY_SET]));
        assert_eq!(
            scheduler.request_intent(second, IntentRequest::new(2, second_resources),),
            Some(super::IntentDisposition::Queued)
        );
        assert_eq!(
            scheduler.request_intent(first, IntentRequest::new(1, first_resources),),
            Some(super::IntentDisposition::Queued)
        );
        assert_eq!(
            scheduler.request_intent(disjoint, IntentRequest::new(3, disjoint_resources),),
            Some(super::IntentDisposition::Queued)
        );
        assert_eq!(scheduler.grant_next_intent(), Some((first, 1)));
        assert_eq!(scheduler.grant_next_intent(), Some((disjoint, 3)));
        assert_eq!(scheduler.grant_next_intent(), None);
    }

    /// Verifies serialized commit selection by mutation ticket.
    /// # Panics
    ///
    /// Panics when commit selection or held-commit accounting is inconsistent.
    #[test]
    fn commit_queue_is_serialized_by_ticket() {
        let mut scheduler = Scheduler::new();
        let later = require_some!(scheduler.reserve());
        let earlier = require_some!(scheduler.reserve());
        assert!(scheduler.request_commit(later, 20));
        assert!(scheduler.request_commit(earlier, 10));
        let mut attempted = [false; MAX_OPERATIONS];
        assert_eq!(
            scheduler.next_commit_candidate(&attempted),
            Some((earlier, 10))
        );
        let attempted_earlier = require_some!(attempted.get_mut(earlier.index()));
        *attempted_earlier = true;
        assert_eq!(
            scheduler.next_commit_candidate(&attempted),
            Some((later, 20))
        );
        assert!(scheduler.grant_commit(earlier, 10));
        assert!(scheduler.has_commit_work());
        assert!(!scheduler.reject_commit(later, 10));
        assert!(scheduler.reject_commit(later, 20));
        assert_eq!(scheduler.abandon_commit(later), None);
        assert!(scheduler.has_commit_work());
        assert!(!scheduler.reject_commit(earlier, 10));
        assert_eq!(scheduler.abandon_commit(earlier), Some(10));
        assert!(!scheduler.has_commit_work());
    }

    /// Verifies cancellation behavior at every suspending scheduler phase.
    /// # Panics
    ///
    /// Panics when cancellation loses work or bypasses a non-interruptible phase.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn cancellation_covers_wait_retry_registering_and_lower_phases() {
        let mut scheduler = Scheduler::new();
        for (phase, expected) in [
            (Phase::Ready, CancelDisposition::ResumeOperation),
            (Phase::HandleTurn, CancelDisposition::ResumeOperation),
            (
                Phase::Commit { ticket: 1 },
                CancelDisposition::ResumeOperation,
            ),
            (Phase::Retry, CancelDisposition::AwaitRetry),
            (Phase::Registering, CancelDisposition::AwaitRegistration),
            (Phase::Lower, CancelDisposition::CancelLower),
        ] {
            let slot = require_some!(scheduler.reserve());
            assert!(scheduler.set_phase(slot, phase));
            assert_eq!(scheduler.request_cancel(slot.index()), expected);
            if expected == CancelDisposition::AwaitRegistration {
                let registered = require_some!(scheduler.enter_phase(slot.index(), |current| {
                    matches!(current, Phase::Registering)
                }));
                assert!(scheduler.set_phase(registered, Phase::Lower));
                assert_eq!(
                    scheduler.request_cancel(slot.index()),
                    CancelDisposition::CancelLower
                );
            }
            let live = require_some!(scheduler.identity(slot.index()));
            assert!(scheduler.release_intent(live));
            let _abandoned_commit: Option<u64> = scheduler.abandon_commit(live);
            let _entered_phase: Option<SlotId> = scheduler.enter_phase(slot.index(), |_| true);
            let identity = require_some!(scheduler.identity(slot.index()));
            assert!(scheduler.complete(identity));
        }

        let intent = require_some!(scheduler.reserve());
        let intent_resources = require_some!(resources(&[MutationResource::VOLUME_METADATA]));
        assert_eq!(
            scheduler.request_intent(intent, IntentRequest::new(9, intent_resources),),
            Some(super::IntentDisposition::Queued)
        );
        assert_eq!(
            scheduler.request_cancel(intent.index()),
            CancelDisposition::ResumeOperation
        );
        let intent = require_some!(scheduler.take_ready());
        assert!(scheduler.complete(intent));

        for condition in [
            WaitCondition::Visibility { ticket: 11 },
            WaitCondition::Checkpoint {
                epoch: unsafe {
                    // SAFETY: EpochSequence is an opaque u64 sequence whose documented initial
                    // value is zero; this local fixture never crosses the scheduler boundary.
                    core::mem::MaybeUninit::zeroed().assume_init()
                },
            },
            WaitCondition::VolumeDurability,
            WaitCondition::JournalClean,
            WaitCondition::Barrier { identity: 13 },
        ] {
            let waiting = require_some!(scheduler.reserve());
            assert!(scheduler.request_wait(waiting, condition));
            assert_eq!(
                scheduler.request_cancel(waiting.index()),
                CancelDisposition::ResumeOperation
            );
            let waiting = require_some!(scheduler.take_ready());
            assert!(scheduler.complete(waiting));
        }
    }

    /// # Panics
    ///
    /// Panics if one-way closing retains or later recovers top-level cancellation authority.
    #[test]
    fn closing_wait_revokes_cancellation_before_durability_drain() {
        let mut scheduler = Scheduler::new();
        let slot = require_some!(scheduler.reserve());
        assert_eq!(
            scheduler.install(slot, Admission::Device, false),
            Some(AdmissionStart::Admitted)
        );
        assert_eq!(scheduler.take_ready(), Some(slot));
        assert_eq!(
            scheduler.request_cancel(slot.index()),
            CancelDisposition::AwaitRegistration
        );
        let condition = WaitCondition::JournalClean;
        assert!(scheduler.request_closing_wait(slot, condition));
        assert_eq!(scheduler.wait_condition(slot.index()), Some(condition));
        assert!(!scheduler.cancellation_is_pending(slot.index(), true));
        assert_eq!(
            scheduler.request_cancel(slot.index()),
            CancelDisposition::Ignored
        );
    }

    /// Verifies pre-commit cancellation resumes without entering lower I/O and leaves no grant.
    /// # Panics
    ///
    /// Panics when intent/commit waiting cancellation retains authority or enters a lower phase.
    #[test]
    fn precommit_cancellation_releases_scheduler_authority() {
        let mut scheduler = Scheduler::new();

        let intent_waiter = require_some!(scheduler.reserve());
        let intent_resources = require_some!(resources(&[MutationResource::VOLUME_METADATA]));
        assert_eq!(
            scheduler.request_intent(intent_waiter, IntentRequest::new(1, intent_resources),),
            Some(super::IntentDisposition::Queued)
        );
        assert_eq!(
            scheduler.request_cancel(intent_waiter.index()),
            CancelDisposition::ResumeOperation
        );
        let resumed_intent = require_some!(scheduler.take_ready());
        assert_eq!(resumed_intent, intent_waiter);
        assert!(scheduler.checkpoint_authority_is_clear(resumed_intent));
        assert!(scheduler.complete(resumed_intent));

        let commit_waiter = require_some!(scheduler.reserve());
        let commit_resources = require_some!(resources(&[MutationResource::VOLUME_METADATA]));
        assert_eq!(
            scheduler.request_intent(commit_waiter, IntentRequest::new(2, commit_resources),),
            Some(super::IntentDisposition::Queued)
        );
        assert_eq!(scheduler.grant_next_intent(), Some((commit_waiter, 2)));
        assert!(scheduler.request_commit(commit_waiter, 2));
        assert_eq!(
            scheduler.request_cancel(commit_waiter.index()),
            CancelDisposition::ResumeOperation
        );
        let resumed_commit = require_some!(scheduler.take_ready());
        assert_eq!(resumed_commit, commit_waiter);
        assert!(!scheduler.checkpoint_authority_is_clear(resumed_commit));
        assert!(scheduler.release_intent(resumed_commit));
        assert_eq!(scheduler.abandon_commit(resumed_commit), None);
        assert!(scheduler.checkpoint_authority_is_clear(resumed_commit));
        assert!(!scheduler.has_commit_work());
        assert!(scheduler.complete(resumed_commit));
    }

    /// Verifies drain cancellation selects interruptible work and preserves terminal work.
    /// # Panics
    ///
    /// Panics when drain admits new work, repeats cancellation, or cancels a terminal barrier.
    #[test]
    fn drain_rejects_admission_and_selects_interruptible_work() {
        let mut scheduler = Scheduler::new();
        let slot = require_some!(scheduler.reserve());
        let lower = require_some!(scheduler.reserve());
        assert!(scheduler.set_phase(lower, Phase::Lower));
        let terminal = require_some!(scheduler.reserve());
        let handle = HandleId::from_address(17);
        assert_eq!(
            scheduler.install(
                slot,
                Admission::Handle {
                    handle,
                    lane: HandleOperationLane::Ordinary,
                },
                false,
            ),
            Some(AdmissionStart::Admitted)
        );
        assert_eq!(
            scheduler.install(
                terminal,
                Admission::Handle {
                    handle: HandleId::from_address(23),
                    lane: HandleOperationLane::Cleanup,
                },
                false,
            ),
            Some(AdmissionStart::Admitted)
        );
        scheduler.begin_drain();
        assert!(scheduler.reserve().is_none());
        assert_eq!(
            scheduler.drain_cancel_mask(),
            (1_u64 << slot.index()) | (1_u64 << lower.index())
        );
        assert_eq!(
            scheduler.request_cancel(slot.index()),
            CancelDisposition::ResumeOperation
        );
        assert_eq!(
            scheduler.request_cancel(lower.index()),
            CancelDisposition::CancelLower
        );
        assert_eq!(scheduler.drain_cancel_mask(), 0);
        let actor = require_some!(scheduler.take_ready());
        assert!(scheduler.complete(actor));
        let lower_actor = require_some!(
            scheduler.enter_phase(lower.index(), |phase| matches!(phase, Phase::Lower))
        );
        assert!(scheduler.complete(lower_actor));
        let terminal_actor = require_some!(scheduler.take_ready());
        assert_eq!(terminal_actor, terminal);
        assert!(scheduler.complete(terminal_actor));
        assert!(!scheduler.has_active());
    }

    /// Verifies per-handle FIFO lanes, terminal barriers, and cleanup cancellation selection.
    /// # Panics
    ///
    /// Panics when operations on one handle escape their ordered lane.
    #[test]
    fn handle_fifo_barrier_and_ordinary_cancel_mask_are_model_owned() {
        let mut scheduler = Scheduler::new();
        let handle = HandleId::from_address(17);
        let other = HandleId::from_address(23);
        let first = require_some!(scheduler.reserve());
        assert_eq!(
            scheduler.install(
                first,
                Admission::Handle {
                    handle,
                    lane: HandleOperationLane::Ordinary,
                },
                false,
            ),
            Some(AdmissionStart::Admitted)
        );
        let cleanup = require_some!(scheduler.reserve());
        assert_eq!(
            scheduler.install(
                cleanup,
                Admission::Handle {
                    handle,
                    lane: HandleOperationLane::Cleanup,
                },
                false,
            ),
            Some(AdmissionStart::HandleTurn)
        );
        let independent = require_some!(scheduler.reserve());
        assert_eq!(
            scheduler.install(
                independent,
                Admission::Handle {
                    handle: other,
                    lane: HandleOperationLane::PostCleanup(PostCleanupRequest::PagingRead),
                },
                false,
            ),
            Some(AdmissionStart::Admitted)
        );
        assert_eq!(
            scheduler.ordinary_handle_mask(cleanup.index(), handle),
            1_u64 << first.index()
        );
        assert!(!scheduler.terminal_barrier_is_releasable(cleanup.index(), CLEANUP_HANDLE_BARRIER));
        let first_actor = require_some!(scheduler.take_ready());
        assert_eq!(first_actor, first);
        assert!(scheduler.complete(first_actor));
        assert_eq!(scheduler.ready_handle_turns(), 1_u64 << cleanup.index());
        let cleanup_actor = require_some!(scheduler.grant_handle_turn(cleanup.index()));
        assert_eq!(cleanup_actor, cleanup);
        assert!(scheduler.request_wait(
            cleanup_actor,
            WaitCondition::Barrier {
                identity: CLEANUP_HANDLE_BARRIER,
            },
        ));
        assert!(scheduler.terminal_barrier_is_releasable(cleanup.index(), CLEANUP_HANDLE_BARRIER));
        assert_eq!(
            scheduler.wait_condition(cleanup.index()),
            Some(WaitCondition::Barrier {
                identity: CLEANUP_HANDLE_BARRIER,
            })
        );
        assert_eq!(scheduler.grant_wait(cleanup.index()), Some(cleanup));
    }

    /// Verifies retry events cannot target a recycled slot generation.
    /// # Panics
    ///
    /// Panics when retry or cancellation authority survives slot reuse.
    #[test]
    fn retry_generation_and_effect_cancellation_are_stale_safe() {
        let mut scheduler = Scheduler::new();
        let first = require_some!(scheduler.reserve());
        assert!(!scheduler.consume_cancel_before_effect(first.index(), false));
        assert!(scheduler.set_phase(first, Phase::Retry));
        assert!(scheduler.enter_retry(first));
        assert!(scheduler.complete(first));
        let reused = require_some!(scheduler.reserve());
        assert_eq!(reused.index(), first.index());
        assert!(!scheduler.enter_retry(SlotId::from_parts(first.index(), first.generation())));
        assert!(scheduler.set_phase(reused, Phase::Retry));
        assert!(scheduler.enter_retry(reused));
        assert!(scheduler.complete(reused));
    }

    /// Verifies lower completion and cancellation converge in either arrival order.
    /// # Panics
    ///
    /// Panics when a race leaves stale cancellation or slot ownership behind.
    #[test]
    fn cancel_and_lower_completion_orders_converge_without_stale_reuse() {
        let mut scheduler = Scheduler::new();
        let cancel_first = require_some!(scheduler.reserve());
        assert!(scheduler.set_phase(cancel_first, Phase::Lower));
        assert_eq!(
            scheduler.request_cancel(cancel_first.index()),
            CancelDisposition::CancelLower
        );
        let completed = require_some!(
            scheduler.enter_phase(cancel_first.index(), |phase| matches!(phase, Phase::Lower))
        );
        assert!(scheduler.complete(completed));

        let completion_first = require_some!(scheduler.reserve());
        assert!(scheduler.set_phase(completion_first, Phase::Lower));
        let completed = require_some!(scheduler.enter_phase(completion_first.index(), |phase| {
            matches!(phase, Phase::Lower)
        }));
        assert!(scheduler.complete(completed));
        assert_eq!(
            scheduler.request_cancel(completion_first.index()),
            CancelDisposition::Ignored
        );
    }

    /// Verifies durable publication consumes exact mutation grants and no device-operation grants.
    /// # Panics
    ///
    /// Panics when publication authority can be duplicated, mismatched, or retained.
    #[test]
    fn durable_publication_consumes_exact_intent_and_commit_authority() {
        let mut scheduler = Scheduler::new();
        let mutation = require_some!(scheduler.reserve());
        let mutation_resources = require_some!(resources(&[MutationResource::VOLUME_METADATA]));
        assert_eq!(
            scheduler.request_intent(mutation, IntentRequest::new(7, mutation_resources),),
            Some(super::IntentDisposition::Queued)
        );
        assert_eq!(scheduler.grant_next_intent(), Some((mutation, 7)));
        assert!(scheduler.request_commit(mutation, 7));
        assert_eq!(
            scheduler.next_commit_candidate(&[false; MAX_OPERATIONS]),
            Some((mutation, 7))
        );
        assert!(scheduler.grant_commit(mutation, 7));
        assert!(scheduler.consume_durable_authority(mutation, 7));
        assert!(scheduler.checkpoint_authority_is_clear(mutation));
        assert!(scheduler.complete(mutation));

        let device = require_some!(scheduler.reserve());
        assert_eq!(
            scheduler.install(device, Admission::Device, false),
            Some(AdmissionStart::Admitted)
        );
        let device = require_some!(scheduler.take_ready());
        assert!(scheduler.checkpoint_authority_is_clear(device));
    }
}
