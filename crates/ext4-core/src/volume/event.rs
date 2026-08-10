//! Concrete scheduler events and single-use grant capabilities.

use crate::StorageCompletion;

/// Identity assigned to one admitted scheduler operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationId(u64);

impl OperationId {
    /// Builds an identity from one bounded scheduler slot generation.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the scheduler-local representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One timer firing bound to a particular retry attempt.
///
/// This type deliberately implements neither `Clone` nor `Copy`. Advancing an operation consumes
/// the only permit issued for that timer firing.
#[derive(Debug)]
pub struct RetryPermit {
    /// Operation whose retry timer fired.
    operation: OperationId,
    /// One-based lower-I/O attempt authorized by this firing.
    attempt: u8,
}

impl RetryPermit {
    /// Issues one timer permit after the scheduler removed the matching armed timer.
    #[must_use]
    pub const fn issued(operation: OperationId, attempt: u8) -> Self {
        Self { operation, attempt }
    }

    /// Consumes the permit into the identity and authorized attempt.
    #[must_use]
    pub const fn into_parts(self) -> (OperationId, u8) {
        (self.operation, self.attempt)
    }
}

/// Exclusive ownership of every resource intent requested by one resolved mutation.
#[derive(Debug)]
pub struct MutationLease {
    /// FIFO mutation ticket retained across stale-plan re-resolution.
    ticket: u64,
}

impl MutationLease {
    /// Issues the lease after the scheduler atomically acquired the complete resource set.
    #[must_use]
    pub const fn granted(ticket: u64) -> Self {
        Self { ticket }
    }

    /// Observes the scheduler ticket without duplicating the one-shot lease.
    #[must_use]
    pub const fn ticket(&self) -> u64 {
        self.ticket
    }

    /// Consumes the lease into its stable FIFO ticket.
    #[must_use]
    pub const fn into_ticket(self) -> u64 {
        self.ticket
    }
}

/// Exclusive authority to occupy the current journal commit slot.
#[derive(Debug)]
pub struct CommitLease {
    /// FIFO mutation ticket selected by commit arbitration.
    ticket: u64,
}

impl CommitLease {
    /// Issues the lease after journal-space and checkpoint constraints are satisfied.
    #[must_use]
    pub const fn granted(ticket: u64) -> Self {
        Self { ticket }
    }

    /// Observes the scheduler ticket without duplicating the one-shot lease.
    #[must_use]
    pub const fn ticket(&self) -> u64 {
        self.ticket
    }

    /// Consumes the lease into its FIFO mutation ticket.
    #[must_use]
    pub const fn into_ticket(self) -> u64 {
        self.ticket
    }
}

/// Short exclusive authority to swap one durable epoch into reader visibility.
#[derive(Debug)]
pub struct VisibilityLease {
    /// FIFO mutation ticket whose durable values may be published.
    ticket: u64,
}

impl VisibilityLease {
    /// Issues the lease after the visibility gate becomes exclusively available.
    #[must_use]
    pub const fn granted(ticket: u64) -> Self {
        Self { ticket }
    }

    /// Observes the scheduler ticket without duplicating the one-shot lease.
    #[must_use]
    pub const fn ticket(&self) -> u64 {
        self.ticket
    }

    /// Consumes the lease into its FIFO mutation ticket.
    #[must_use]
    pub const fn into_ticket(self) -> u64 {
        self.ticket
    }
}

/// Exclusive authority to use the journal checkpoint slot independently of visibility.
#[derive(Debug)]
pub struct CheckpointLease {
    /// Sequence of the visible epoch whose overlay is being checkpointed.
    epoch: super::EpochSequence,
}

impl CheckpointLease {
    /// Issues the lease for one published overlay epoch.
    #[must_use]
    pub const fn granted(epoch: super::EpochSequence) -> Self {
        Self { epoch }
    }

    /// Consumes the lease into the checkpointed epoch sequence.
    #[must_use]
    pub const fn into_epoch(self) -> super::EpochSequence {
        self.epoch
    }
}

/// One terminal-barrier release bound to an operation waiting behind earlier requests.
#[derive(Debug)]
pub struct BarrierPermit {
    /// Scheduler-local barrier identity.
    barrier: u64,
}

impl BarrierPermit {
    /// Issues the permit after every operation preceding the barrier has terminated.
    #[must_use]
    pub const fn released(barrier: u64) -> Self {
        Self { barrier }
    }

    /// Consumes the permit into its scheduler-local identity.
    #[must_use]
    pub const fn into_identity(self) -> u64 {
        self.barrier
    }
}

/// The only stimuli capable of advancing a completion-driven filesystem operation.
///
/// An executor never probes operations for readiness. It moves exactly one event into exactly one
/// suspended operation, which then consumes itself into its next transition.
#[derive(Debug)]
pub enum OperationEvent {
    /// First admission into a scheduler lane.
    Admitted,
    /// One lower-storage transfer whose IRP and buffer are no longer used by the lower stack.
    StorageCompleted(StorageCompletion),
    /// Top-level cancellation observed by the active-operation lane.
    CancelRequested,
    /// One operation-specific retry timer fired.
    RetryElapsed(RetryPermit),
    /// The complete mutation resource set was acquired atomically.
    IntentGranted(MutationLease),
    /// The journal commit slot was granted.
    CommitGranted(CommitLease),
    /// The short durable-epoch visibility gate was granted.
    VisibilityGranted(VisibilityLease),
    /// The checkpoint slot was granted independently of visibility.
    CheckpointGranted(CheckpointLease),
    /// A per-handle or durability barrier released this operation.
    BarrierReleased(BarrierPermit),
}
