//! Completion events delivered by a filesystem operation executor.

use super::{CheckpointLease, CommitLease, MutationLease, VisibilityLease};
use crate::StorageCompletion;

/// The only stimuli capable of advancing a completion-driven filesystem operation.
///
/// An executor never probes operations for readiness. It moves exactly one event into exactly one
/// suspended operation, which then consumes itself into its next transition.
#[derive(Debug)]
pub enum OperationEvent {
    /// A complete operation-owned monotonic delay elapsed.
    TimerElapsed,
    /// First admission into a scheduler lane.
    Admitted,
    /// One lower-storage transfer whose IRP and buffer are no longer used by the lower stack.
    StorageCompleted(StorageCompletion),
    /// Mount-time lower device-length query completed through its private IRP envelope.
    DeviceLengthCompleted(crate::Result<crate::DeviceLength>),
    /// Physical write availability queried independently of filesystem mount policy.
    DeviceWriteAccessCompleted(crate::Result<crate::DeviceWriteAccess>),
    /// Top-level cancellation observed by the active-operation lane.
    CancelRequested,
    /// The complete mutation resource set was acquired atomically.
    IntentGranted(MutationLease),
    /// The journal commit slot was granted.
    CommitGranted(CommitLease),
    /// The short durable-epoch visibility gate was granted.
    VisibilityGranted(VisibilityLease),
    /// The checkpoint slot was granted independently of visibility.
    CheckpointGranted(CheckpointLease),
}
