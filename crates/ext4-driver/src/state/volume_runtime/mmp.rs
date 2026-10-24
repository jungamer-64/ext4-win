//! Actor-owned record authority and final filesystem-close handoff.
use ext4_core::{CleanCloseDurability, Error, MmpDeadline, MmpLease, MmpRenewingLease};

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
        /// Upper close acknowledgment waits for the independent ownership-release result.
        durability: CleanCloseDurability,
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

impl MediaOwnership {
    /// Binds only the optional lease returned by a successfully completed core mount.
    pub(super) fn from_mount(lease: Option<MmpLease>) -> Self {
        Self(match lease { Some(lease) => OwnershipPhase::Active(LiveOwnership::Held(lease)), None => OwnershipPhase::Unprotected })
    }
}
