//! Mounted ext4 volume state and journaled write transactions.

mod block_group;
mod inode_record;
mod mount;
mod node;
mod read;
mod scope;
mod transaction;

pub use mount::{
    ExternalJournal, InternalJournal, JournaledVolume, MountContext, ReadOnlyVolume,
    VolumeGeometry, VolumeIdentity,
};
pub use node::{
    ChildLookup, DirectoryChild, DirectoryEntry, DirectoryNode, DirectoryNodeId, FileNode,
    FileNodeId, LoadedNode, NodeId, SymlinkNode, SymlinkNodeId,
};
pub(crate) use transaction::MetadataBlock;
pub use transaction::{
    JournalTransaction, TransactionDirectory, TransactionFile, TransactionNode, TransactionSymlink,
};
