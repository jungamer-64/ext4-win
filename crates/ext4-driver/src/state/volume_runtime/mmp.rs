//! Actor-owned record authority and final filesystem-close handoff.
use ext4_core::{
    CleanCloseDurability, Error, MmpCompletion, MmpDeadline, MmpLease, MmpOperation,
    MmpRenewingLease, MmpTime, Result,
};

use crate::kernel::status::{DriverError, DriverResult};

/// Exclusive ownership steps preserve the last acknowledged I/O window during asynchronous renewal.
#[derive(Debug)]
enum LiveOwnership {
    /// Only this value can start another record update or release.
    Held(MmpLease),
    /// A completion-owned operation holds update authority; this value retains only bounded I/O.
    Renewing(MmpRenewingLease),
}

/// Media authority is independent of I/O reliability and cannot be reconstructed after retirement.
#[derive(Debug)]
enum OwnershipPhase {
    /// The mounted format requires no MMP claim.
    Unprotected,
    /// Ordinary I/O and periodic renewal remain admitted within the acknowledged window.
    Active(LiveOwnership),
    /// No filesystem writes remain; an in-flight renewal must finish before final release.
    Closing {
        /// The same ownership chain persists while completion transfers are outstanding.
        authority: LiveOwnership,
        /// The filesystem's completed durability protocol authorizes requesting a clean MMP marker.
        durability: CleanCloseDurability,
    },
    /// The completion-owned operation is releasing; the prior deadline remains observable.
    Releasing {
        /// No observation may extend the release operation's previously acknowledged window.
        deadline: MmpDeadline,
    },
    /// Both filesystem close and any required record release completed, awaiting the native close.
    Released(CleanCloseDurability),
    /// Final close consumed its unique acknowledgment; no media authority remains.
    Closed,
    /// A new mount and recovery are required; late completions cannot resurrect the session.
    Revoked(Error),
}
/// A single private state machine owns admission, renewal and final release transitions.
#[derive(Debug)]
pub(super) struct MediaOwnership(OwnershipPhase);

impl LiveOwnership {
    /// Observes only the current acknowledgement while a child owns record-update authority.
    const fn deadline(&self) -> MmpDeadline {
        match self {
            Self::Held(lease) => lease.deadline(),
            Self::Renewing(pending) => pending.deadline(),
        }
    }
    /// A pending update needs a deadline watchdog; an idle owner needs its earlier heartbeat.
    fn wakeup(&self) -> MmpDeadline {
        match self {
            Self::Held(lease) => lease.next_update(),
            Self::Renewing(pending) => pending.deadline(),
        }
    }
}

impl MediaOwnership {
    /// Binds only the optional lease returned by a successfully completed core mount.
    pub(super) fn from_mount(lease: Option<MmpLease>) -> Self {
        Self(match lease {
            Some(lease) => OwnershipPhase::Active(LiveOwnership::Held(lease)),
            None => OwnershipPhase::Unprotected,
        })
    }
    /// One observation combines physical freshness with independent one-way retirement.
    pub(super) fn deadline(&self) -> Option<MmpDeadline> {
        match &self.0 {
            OwnershipPhase::Active(authority) | OwnershipPhase::Closing { authority, .. } => {
                Some(authority.deadline())
            }
            OwnershipPhase::Releasing { deadline, .. } => Some(*deadline),
            OwnershipPhase::Unprotected
            | OwnershipPhase::Released(_)
            | OwnershipPhase::Closed
            | OwnershipPhase::Revoked(_) => None,
        }
    }
    /// Permission and deadline are published together; retirement always denies native callbacks.
    pub(super) const fn permits_io(&self) -> bool {
        matches!(
            self.0,
            OwnershipPhase::Unprotected
                | OwnershipPhase::Active(_)
                | OwnershipPhase::Closing { .. }
                | OwnershipPhase::Releasing { .. }
        )
    }
    /// The actor's next timer represents either a due heartbeat or an outstanding update's expiry.
    pub(super) fn wakeup(&self) -> Option<MmpDeadline> {
        match &self.0 {
            OwnershipPhase::Active(authority) | OwnershipPhase::Closing { authority, .. } => {
                Some(authority.wakeup())
            }
            OwnershipPhase::Releasing { deadline, .. } => Some(*deadline),
            OwnershipPhase::Unprotected
            | OwnershipPhase::Released(_)
            | OwnershipPhase::Closed
            | OwnershipPhase::Revoked(_) => None,
        }
    }
    /// Checks the retained acknowledgement independently of record-update ownership.
    /// # Errors
    /// Revocation, retirement or expiration cannot be repaired by observing a later completion.
    pub(super) fn authorize(&self, now: MmpTime) -> DriverResult<()> {
        match self.0 {
            OwnershipPhase::Revoked(_) => return Err(Error::MmpOwnershipLost.into()),
            OwnershipPhase::Released(_) | OwnershipPhase::Closed => {
                return Err(DriverError::FileClosed);
            }
            _ => {}
        }
        if self
            .deadline()
            .is_some_and(|deadline| deadline.remaining_millis(now) == 0)
        {
            return Err(Error::MmpOwnershipLost.into());
        }
        Ok(())
    }
    /// Starts a due renewal or a close-authorized release exactly once.
    /// # Errors
    /// Expiration consumes the ownership chain; no update operation is returned.
    pub(super) fn next_action(&mut self, now: MmpTime) -> Result<Option<MmpOperation>> {
        let ready = match &self.0 {
            OwnershipPhase::Active(LiveOwnership::Held(lease)) => {
                lease.next_update().remaining_millis(now) == 0
            }
            OwnershipPhase::Closing {
                authority: LiveOwnership::Held(_),
                ..
            } => true,
            _ => false,
        };
        if !ready {
            return Ok(None);
        }
        let phase = core::mem::replace(
            &mut self.0,
            OwnershipPhase::Revoked(Error::MmpOwnershipLost),
        );
        match phase {
            OwnershipPhase::Active(LiveOwnership::Held(lease)) => {
                let (pending, operation) = lease.renew(now)?;
                self.0 = OwnershipPhase::Active(LiveOwnership::Renewing(pending));
                Ok(Some(operation))
            }
            OwnershipPhase::Closing {
                authority: LiveOwnership::Held(lease),
                durability,
            } => {
                lease.authorize(now)?;
                let deadline = lease.deadline();
                let operation = lease
                    .release(durability)
                    .map_err(|(error, _lease, _durability)| error)?;
                self.0 = OwnershipPhase::Releasing { deadline };
                Ok(Some(operation))
            }
            _ => Err(Error::ClusterReferenceConflict),
        }
    }
    /// Accepts the unique matching child postcondition; no completion reconstructs revoked authority.
    /// # Errors
    /// Rejects foreign, late, or phase-inconsistent durable completions and consumes their proof.
    pub(super) fn complete(&mut self, completion: MmpCompletion, now: MmpTime) -> Result<()> {
        if let OwnershipPhase::Revoked(_) = self.0 {
            return Err(Error::MmpOwnershipLost);
        }
        let phase = core::mem::replace(
            &mut self.0,
            OwnershipPhase::Revoked(Error::MmpOwnershipLost),
        );
        self.0 = match (phase, completion) {
            (
                OwnershipPhase::Active(LiveOwnership::Renewing(pending)),
                MmpCompletion::Renewed(proof),
            ) => {
                let lease = pending
                    .complete(proof, now)
                    .map_err(|(error, _proof)| error)?;
                OwnershipPhase::Active(LiveOwnership::Held(lease))
            }
            (
                OwnershipPhase::Closing {
                    authority: LiveOwnership::Renewing(pending),
                    durability,
                },
                MmpCompletion::Renewed(proof),
            ) => {
                let lease = pending
                    .complete(proof, now)
                    .map_err(|(error, _proof)| error)?;
                OwnershipPhase::Closing {
                    authority: LiveOwnership::Held(lease),
                    durability,
                }
            }
            (OwnershipPhase::Releasing { deadline }, MmpCompletion::Released(durability)) => {
                if deadline.remaining_millis(now) == 0 {
                    return Err(Error::MmpOwnershipLost);
                }
                OwnershipPhase::Released(durability)
            }
            _ => return Err(Error::ClusterReferenceConflict),
        };
        Ok(())
    }
    /// Transfers the filesystem completion into release ownership only after its last write.
    /// # Errors
    /// Returns the close proof unchanged for duplicate or phase-inconsistent close requests.
    pub(super) fn request_close(
        &mut self,
        durability: CleanCloseDurability,
    ) -> core::result::Result<(), (DriverError, CleanCloseDurability)> {
        if !matches!(
            self.0,
            OwnershipPhase::Unprotected | OwnershipPhase::Active(_)
        ) {
            let reason = match self.0 {
                OwnershipPhase::Revoked(reason) => DriverError::from(reason),
                _ => DriverError::FileClosed,
            };
            return Err((reason, durability));
        }
        self.0 = match core::mem::replace(
            &mut self.0,
            OwnershipPhase::Revoked(Error::MmpOwnershipLost),
        ) {
            OwnershipPhase::Unprotected => OwnershipPhase::Released(durability),
            OwnershipPhase::Active(authority) => OwnershipPhase::Closing {
                authority,
                durability,
            },
            _ => return Err((Error::ClusterReferenceConflict.into(), durability)),
        };
        Ok(())
    }
    /// Readiness retains failure separately from an outstanding physical release.
    /// # Errors
    /// Returns the terminal ownership failure while an upper close acknowledgment is pending.
    pub(super) fn close_ready(&self) -> DriverResult<bool> {
        match self.0 {
            OwnershipPhase::Released(_) => Ok(true),
            OwnershipPhase::Revoked(reason) => Err(reason.into()),
            OwnershipPhase::Closed => Err(DriverError::FileClosed),
            _ => Ok(false),
        }
    }
    /// Transfers the final close acknowledgment once, after both durability domains completed.
    /// # Errors
    /// Rejects a premature, duplicate or failed close without consuming a live ownership chain.
    pub(super) fn finish_close(&mut self) -> DriverResult<CleanCloseDurability> {
        if !self.close_ready()? {
            return Err(Error::ClusterReferenceConflict.into());
        }
        let OwnershipPhase::Released(durability) =
            core::mem::replace(&mut self.0, OwnershipPhase::Closed)
        else {
            return Err(Error::ClusterReferenceConflict.into());
        };
        Ok(durability)
    }
    /// Retires this ownership chain without a clean write, preserving its first terminal reason.
    pub(super) fn revoke(&mut self, reason: Error) {
        if !matches!(self.0, OwnershipPhase::Revoked(_)) {
            self.0 = OwnershipPhase::Revoked(reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Panics
    /// Fails if retirement loses its cause, admits I/O, or lets a late completion restore authority.
    #[test]
    fn revocation_is_independent_of_reliability_and_rejects_late_completions() {
        let mut ownership = MediaOwnership::from_mount(None);
        let now = MmpTime::new(1000, 0);
        assert_eq!(ownership.authorize(now), Ok(()));
        assert!(matches!(ownership.next_action(now), Ok(None)));
        assert_eq!(ownership.wakeup(), None);
        ownership.revoke(Error::MmpCorrupt);
        assert!(!ownership.permits_io());
        assert_eq!(
            ownership.authorize(now),
            Err(Error::MmpOwnershipLost.into())
        );
        assert_eq!(ownership.close_ready(), Err(Error::MmpCorrupt.into()));
        assert_eq!(
            ownership.complete(MmpCompletion::ReadOnly, now),
            Err(Error::MmpOwnershipLost)
        );
        ownership.revoke(Error::DeviceIo);
        assert_eq!(ownership.close_ready(), Err(Error::MmpCorrupt.into()));
        assert!(matches!(ownership.next_action(now), Ok(None)));
        assert_eq!(ownership.wakeup(), None);
    }
}
