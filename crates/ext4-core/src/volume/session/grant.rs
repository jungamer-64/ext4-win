//! Single-use capabilities issued by the mounted session coordinator.

use super::{EpochSequence, MountIdentity};

/// Exclusive ownership of every resource intent requested by one resolved mutation.
#[derive(Debug)]
pub struct MutationLease {
    /// Mount whose coordinator issued this authority.
    mount: MountIdentity,
    /// FIFO mutation ticket retained across stale-plan re-resolution.
    ticket: u64,
}

impl MutationLease {
    /// Constructed only by the owning coordinator after external gate arbitration.
    pub(super) fn new(mount: MountIdentity, ticket: u64) -> Self {
        Self { mount, ticket }
    }
    /// Checks the issuing session; either outcome consumes this lease.
    /// # Errors
    /// Returns a conflict if the grant belongs to another mount.
    pub(super) fn consume(self, mount: &MountIdentity) -> crate::Result<u64> {
        if &self.mount != mount {
            return Err(crate::Error::ClusterReferenceConflict);
        }
        Ok(self.ticket)
    }

    /// Observes the scheduler ticket without duplicating the one-shot lease.
    #[must_use]
    pub const fn ticket(&self) -> u64 {
        self.ticket
    }
}

/// Identity of one coordinator acquisition, distinct from a reusable scheduler ticket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::volume) struct CommitClaim {
    /// Scheduler operation retaining the reservation.
    pub(super) ticket: u64,
    /// Acquisition generation; revocation never makes an older claim current again.
    pub(super) generation: u64,
}

/// Exclusive authority to occupy the current journal commit slot.
#[derive(Debug)]
pub struct CommitLease {
    /// Mount whose coordinator issued this authority.
    mount: MountIdentity,
    /// FIFO mutation ticket selected by commit arbitration.
    claim: CommitClaim,
}

impl CommitLease {
    /// Constructed only by the coordinator after reserving the matching state transition.
    pub(super) fn new(mount: MountIdentity, claim: CommitClaim) -> Self {
        Self { mount, claim }
    }
    /// Checks the issuing session; either outcome consumes this lease.
    /// # Errors
    /// Returns a conflict if the grant belongs to another mount.
    pub(super) fn consume(self, mount: &MountIdentity) -> crate::Result<CommitClaim> {
        if &self.mount != mount {
            return Err(crate::Error::ClusterReferenceConflict);
        }
        Ok(self.claim)
    }

    /// Observes the scheduler ticket without duplicating the one-shot lease.
    #[must_use]
    pub const fn ticket(&self) -> u64 {
        self.claim.ticket
    }
}

/// Short exclusive authority to swap one durable epoch into reader visibility.
#[derive(Debug)]
pub struct VisibilityLease {
    /// Mount whose coordinator issued this authority.
    mount: MountIdentity,
    /// FIFO mutation ticket whose durable values may be published.
    claim: CommitClaim,
}

impl VisibilityLease {
    /// Constructed only by the coordinator after reserving the matching state transition.
    pub(super) fn new(mount: MountIdentity, claim: CommitClaim) -> Self {
        Self { mount, claim }
    }
    /// Checks the issuing session; either outcome consumes this lease.
    /// # Errors
    /// Returns a conflict if the grant belongs to another mount.
    pub(super) fn consume(self, mount: &MountIdentity) -> crate::Result<CommitClaim> {
        if &self.mount != mount {
            return Err(crate::Error::ClusterReferenceConflict);
        }
        Ok(self.claim)
    }

    /// Observes the scheduler ticket without duplicating the one-shot lease.
    #[must_use]
    pub const fn ticket(&self) -> u64 {
        self.claim.ticket
    }
}

/// Exclusive authority to use the journal checkpoint slot independently of visibility.
#[derive(Debug)]
pub struct CheckpointLease {
    /// Mount whose coordinator issued this authority.
    mount: MountIdentity,
    /// Sequence of the visible epoch whose overlay is being checkpointed.
    epoch: EpochSequence,
}

impl CheckpointLease {
    /// Constructed only after the coordinator acquires its pending checkpoint.
    pub(super) fn new(mount: MountIdentity, epoch: EpochSequence) -> Self {
        Self { mount, epoch }
    }
    /// Checks the issuing session; either outcome consumes this lease.
    /// # Errors
    /// Returns a conflict if the grant belongs to another mount.
    pub(super) fn consume(self, mount: &MountIdentity) -> crate::Result<EpochSequence> {
        if &self.mount != mount {
            return Err(crate::Error::ClusterReferenceConflict);
        }
        Ok(self.epoch)
    }
}
