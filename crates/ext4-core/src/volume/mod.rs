//! Mounted ext4 volume state and journaled write transactions.

mod access;
pub use access::{MediaAccess, MountAccess, RecoveryMemoryLimit};
mod block_group;
mod directory;
mod directory_read;
pub use directory_read::{DirectoryReadOperation, DirectoryReadTransition, DirectoryReader};
mod event;
mod inode_record;
mod keys;
pub use keys::{PreparedKeyChange, ReservedKeyChange, ResolvedKeyChange};
mod metadata_cache;
mod mmp;
mod mount;
pub(crate) use metadata_cache::CacheReadStamp;
pub use metadata_cache::{MetadataCache, MetadataCacheAccess};
pub use mmp::{
    MmpChange, MmpCompletion, MmpDeadline, MmpEffect, MmpEvent, MmpFailure, MmpLease, MmpOperation,
    MmpOwner, MmpRenewal, MmpRenewingLease, MmpTime, MmpTransition,
};
mod node;
mod operation;
mod orphan;
mod read;
mod recovery;
mod scope;
mod transaction;
mod trim;
pub use trim::{
    PendingTrim, PreparedTrim, TRIM_BATCH_BYTES, TRIM_BATCH_RANGES, TrimAdmission, TrimAlignment,
    TrimBatchResult, TrimCompletion, TrimCompletionMismatch, TrimCursor, TrimFailure,
    TrimIoOutcome, TrimRange, TrimRequest, TrimScanOperation, TrimScanTransition, TrimSelection,
};

pub use directory::{DirectoryScanCursor, ScannedDirectoryEntry};
pub use event::{CheckpointLease, CommitLease, MutationLease, OperationEvent, VisibilityLease};
pub use mount::{
    CleanCloseDurability, CleanCloseOperation, CleanCloseTransition, CommittedEpoch,
    CommittedReadContext, CompletedMount, EpochSequence, ExternalJournalProbeOperation,
    ExternalJournalProbeOutcome, ExternalJournalProbeTransition, ExternalJournalRequirement,
    MountOperation, MountProbeOperation, MountProbeTransition, MountTransition, MountedProfile,
    MutationCoordinatorState, MutationResolveContext, MutationResource, ObservedResourceVersionSet,
    ProbedMount, ResourceVersion, ValidatedExternalJournal, VolumeGeometry, VolumeIdentity,
};
pub use node::{
    ChildLookup, DataAllocationRun, DirectoryChild, DirectoryEntry, DirectoryNode, DirectoryNodeId,
    FileNode, FileNodeId, HardLinkEntry, HardLinkNodeId, HardLinks, NodeDataPolicy, NodeId,
    NodeMetadataSnapshot, NodeMetadataUpdate, SymlinkNode, SymlinkNodeId,
};
pub use operation::{
    CommittedReadPass, EpochReadOperation, EpochReadPass, MutationResolveOperation,
    MutationResolveReady, MutationResolveTransition, ReadTransition,
};
pub use transaction::{
    CheckpointOperation, CheckpointPublication, CleanJournalDurability, CleanJournalRecordPhase,
    CommitDurability, CommitReadyMutation, CommitRecordPhase, DurableMutation, HomeBlockDurability,
    JournalPayloadDurability, MutationResolvePass, NamespaceDestination, OrderedDataDurability,
    PublishedMutation, ReservedMutation, ResolvedMutation, StorageRequestSequence,
    StorageRequestSequenceStep, TransactionDirectory, TransactionFile, TransactionHardLinkSource,
    TransactionNode, TransactionSymlink,
};
