//! Completion-driven reads with current metadata and revalidated inode dependencies.

use super::scope::*;
use super::transaction::{MutationResolvePass, ResolvedMutation};
use crate::disk::storage::{StorageTarget, StorageTranscript};

/// One consuming transition of a committed-epoch read operation.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "owned transcripts and read provenance travel by value across I/O suspension without adding a heap allocation to each completion"
)]
pub enum ReadTransition<T> {
    /// Submit one owned lower request and suspend only this operation.
    SubmitLower {
        /// Request moved into the lower completion envelope.
        request: crate::StorageRequest,
        /// Read transcript resumed only by the matching completion.
        suspended: EpochReadOperation,
    },
    /// Read operation terminated with a value or normal domain error.
    Complete(Result<T>),
}

/// Read surface shared by committed read passes and mutation resolve passes.
///
/// These are the two concrete restart-local contexts that may inspect committed state. Neither
/// implementation can survive suspension: all storage and continuation ownership remains in its
/// enclosing operation.
pub trait CommittedReadPass {
    /// Loads validated inode ownership, mode and the complete access ACL.
    /// # Errors
    /// Returns storage, ACL decoding or inode/ACL disagreement failures.
    fn load_access(&mut self, node: NodeId) -> Result<Ext4Access>;
    /// Computes child access from the directory's default ACL and requested inode fields.
    /// # Errors
    /// Returns storage, default ACL or allocation failures.
    fn child_access(
        &mut self,
        parent: DirectoryNodeId,
        security: Ext4Security,
    ) -> Result<Ext4Access>;

    /// Reads complete inode metadata from the pass's coherent ext4 view.
    /// # Errors
    /// Returns an inode-kind mismatch, storage failure or malformed inode.
    fn load_node_metadata(&mut self, node: NodeId) -> Result<super::NodeMetadataSnapshot> {
        let snapshot = match node {
            NodeId::File(id) => super::NodeMetadataSnapshot::from_inode(self.load_file(id)?.inode()),
            NodeId::Directory(id) => super::NodeMetadataSnapshot::from_inode(self.load_directory(id)?.inode()),
            NodeId::Symlink(id) => super::NodeMetadataSnapshot::from_inode(self.load_symlink(id)?.inode()),
        };
        Ok(snapshot)
    }

    /// Loads a regular file by validated identity.
    /// # Errors
    ///
    /// Returns an error when the inode cannot be read or does not describe the requested file.
    fn load_file(&mut self, id: FileNodeId) -> Result<FileNode>;
    /// Loads a directory by validated identity.
    /// # Errors
    ///
    /// Returns an error when the inode cannot be read or does not describe a directory.
    fn load_directory(&mut self, id: DirectoryNodeId) -> Result<DirectoryNode>;
    /// Loads a symbolic link by validated identity.
    /// # Errors
    ///
    /// Returns an error when the inode cannot be read or does not describe a symbolic link.
    fn load_symlink(&mut self, id: SymlinkNodeId) -> Result<SymlinkNode>;
    /// Loads and classifies one Windows-facing file index.
    /// # Errors
    ///
    /// Returns an error when the index is invalid or its inode cannot be loaded and classified.
    fn load_node_by_file_index(&mut self, file_index: u32) -> Result<NodeId>;
    /// Reads every extended attribute attached to a typed node.
    /// # Errors
    ///
    /// Returns an error when the inode or external attribute block is invalid or unavailable.
    fn read_xattrs(&mut self, node: NodeId) -> Result<XattrSet>;
    /// Reads one extended attribute attached to a typed node.
    /// # Errors
    ///
    /// Returns an error when attributes cannot be read or the selected value cannot be copied.
    fn read_xattr(&mut self, node: NodeId, name: &XattrName) -> Result<Option<XattrValue>>;
    /// Reads regular-file bytes into an exact caller-owned range.
    /// # Errors
    ///
    /// Returns an error when the range, extent mapping, encryption, verity proof, or storage read
    /// cannot be completed.
    fn read_file(
        &mut self,
        file: FileNodeId,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes>;
    /// Reads one symbolic-link target into an owned byte vector.
    /// # Errors
    ///
    /// Returns an error when the target is malformed, cannot be read, or cannot be allocated.
    fn read_symlink(&mut self, symlink: SymlinkNodeId) -> Result<Vec<u8>>;
    /// Advances one entry in an owned directory reader; suspension retains its progress.
    /// # Errors
    ///
    /// Returns an error when the directory/index/dirent representation is invalid, entry names
    /// cannot be projected, referenced inodes are invalid, or bounded result allocation fails.
    fn next_directory_entry(
        &mut self,
        reader: &mut DirectoryReader,
    ) -> Result<Option<ScannedDirectoryEntry>>;
    /// Enumerates every reachable hard link to a non-directory inode.
    /// # Errors
    ///
    /// Returns an error when directory traversal or result allocation fails.
    fn read_hard_links(&mut self, target: HardLinkNodeId) -> Result<HardLinks>;
    /// Looks up one exact ext4 child name.
    /// # Errors
    ///
    /// Returns an error when the directory is invalid or its storage cannot be searched.
    fn lookup_child(&mut self, parent: DirectoryNodeId, name: &Ext4Name) -> Result<ChildLookup>;
}

/// Ephemeral synchronous read pass reconstructed from one operation transcript and epoch.
///
/// The pass may be borrowed only while one concrete event is being advanced. It cannot be stored
/// in a completion context, and an incomplete storage access returns
/// [`Error::OperationSuspended`] so the owning [`EpochReadOperation`] can move the resulting owned
/// request into lower-I/O ownership.
pub struct EpochReadPass<'pass, 'storage, 'epoch> {
    /// Internal committed-epoch view used only for this restartable pass.
    view: &'pass mut EpochReadView<'storage, 'epoch>,
    /// Mutable provider objects owned by the enclosing top-level operation.
    crypto: &'pass mut dyn CryptographicOperation,
}

impl core::fmt::Debug for EpochReadPass<'_, '_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EpochReadPass")
            .finish_non_exhaustive()
    }
}

impl EpochReadPass<'_, '_, '_> {
    /// Observes the payload allocation beginning at one block-aligned file coordinate.
    /// No result means resident data or the end of the visible allocation span. This grants no
    /// raw-I/O or mutation authority; the result belongs to the pass's immutable epoch.
    /// # Errors
    /// Returns invalid identity/range, malformed extent/checksum, allocation, or storage failures.
    pub fn node_data_allocation(
        &mut self,
        node: NodeId,
        offset: FileOffset,
    ) -> Result<Option<super::node::DataAllocationRun>> {
        self.view.node_data_allocation(node, offset)
    }

    /// Loads a regular file by validated identity.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the inode is not a regular file.
    pub fn load_file(&mut self, id: FileNodeId) -> Result<FileNode> {
        self.view.load_file(id)
    }

    /// Loads a directory by validated identity.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the inode is not a directory.
    pub fn load_directory(&mut self, id: DirectoryNodeId) -> Result<DirectoryNode> {
        self.view.load_directory(id)
    }

    /// Loads a symbolic link by validated identity.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the inode is not a symbolic link.
    pub fn load_symlink(&mut self, id: SymlinkNodeId) -> Result<SymlinkNode> {
        self.view.load_symlink(id)
    }

    /// Loads and classifies one Windows-facing file index.
    /// # Errors
    ///
    /// Returns an error when the index does not identify a live inode.
    pub fn load_node_by_file_index(&mut self, file_index: u32) -> Result<NodeId> {
        self.view.load_node_by_file_index(file_index)
    }

    /// Reads every extended attribute attached to one typed node.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the xattr representation is invalid.
    pub fn read_xattrs(&mut self, node: NodeId) -> Result<XattrSet> {
        self.view.read_inode_xattrs(node.inode())
    }

    /// Reads one extended attribute attached to one typed node.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the xattr representation is invalid.
    pub fn read_xattr(&mut self, node: NodeId, name: &XattrName) -> Result<Option<XattrValue>> {
        self.view.read_inode_xattr(node.inode(), name)
    }

    /// Reads regular-file bytes into an exact caller-owned range.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the file mapping is invalid.
    pub fn read_file(
        &mut self,
        file: FileNodeId,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        let file = self.view.load_file(file)?;
        self.view.read_file(&file, offset, out, self.crypto)
    }

    /// Reads one symbolic-link target into an owned byte vector.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the target is invalid.
    pub fn read_symlink(&mut self, symlink: SymlinkNodeId) -> Result<Vec<u8>> {
        let symlink = self.view.load_symlink(symlink)?;
        self.view.read_symlink(&symlink)
    }

    /// Reads one bounded live-directory page.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or directory traversal/projection fails.
    pub fn next_directory_entry(
        &mut self,
        reader: &mut DirectoryReader,
    ) -> Result<Option<ScannedDirectoryEntry>> {
        self.view.next_directory_entry(reader, self.crypto)
    }

    /// Enumerates every reachable hard link to a non-directory inode.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or namespace invariants fail.
    pub fn read_hard_links(&mut self, target: HardLinkNodeId) -> Result<HardLinks> {
        self.view.read_hard_links(target, self.crypto)
    }

    /// Looks up one exact ext4 child name.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the directory is invalid.
    pub fn lookup_child(
        &mut self,
        parent: DirectoryNodeId,
        name: &Ext4Name,
    ) -> Result<ChildLookup> {
        let parent = self.view.load_directory(parent)?;
        self.view.lookup_child(&parent, name, self.crypto)
    }
}

impl CommittedReadPass for EpochReadPass<'_, '_, '_> {
    fn load_access(&mut self, node: NodeId) -> Result<Ext4Access> {
        self.view.load_access(node)
    }
    fn child_access(
        &mut self,
        parent: DirectoryNodeId,
        security: Ext4Security,
    ) -> Result<Ext4Access> {
        self.view.child_access(parent, security)
    }

    fn load_file(&mut self, id: FileNodeId) -> Result<FileNode> {
        self.load_file(id)
    }

    fn load_directory(&mut self, id: DirectoryNodeId) -> Result<DirectoryNode> {
        self.load_directory(id)
    }

    fn load_symlink(&mut self, id: SymlinkNodeId) -> Result<SymlinkNode> {
        self.load_symlink(id)
    }

    fn load_node_by_file_index(&mut self, file_index: u32) -> Result<NodeId> {
        self.load_node_by_file_index(file_index)
    }

    fn read_xattrs(&mut self, node: NodeId) -> Result<XattrSet> {
        self.read_xattrs(node)
    }

    fn read_xattr(&mut self, node: NodeId, name: &XattrName) -> Result<Option<XattrValue>> {
        self.read_xattr(node, name)
    }

    fn read_file(
        &mut self,
        file: FileNodeId,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        self.read_file(file, offset, out)
    }

    fn read_symlink(&mut self, symlink: SymlinkNodeId) -> Result<Vec<u8>> {
        self.read_symlink(symlink)
    }

    fn next_directory_entry(
        &mut self,
        reader: &mut DirectoryReader,
    ) -> Result<Option<ScannedDirectoryEntry>> {
        self.next_directory_entry(reader)
    }

    fn read_hard_links(&mut self, target: HardLinkNodeId) -> Result<HardLinks> {
        self.read_hard_links(target)
    }

    fn lookup_child(&mut self, parent: DirectoryNodeId, name: &Ext4Name) -> Result<ChildLookup> {
        self.lookup_child(parent, name)
    }
}

/// Operation-owned transcript and dependency versions for one logical read.
///
/// Each pass requires a current coordinator context. A changed inode or key dependency terminates
/// the operation with [`Error::ReadConflict`] before interpreting a lower completion; a new read
/// requires fresh admission. Unrelated publications preserve owned buffers across suspension.
#[derive(Debug)]
pub struct EpochReadOperation {
    /// Mount session that owns every retained read buffer.
    mount: MountIdentity,
    /// Completed and in-flight reads for the filesystem device.
    filesystem: StorageTranscript,
    /// Inode and key versions establishing the interpretation of retained storage bytes.
    observed: ReadObservations,
    /// Provenance against which this reader last retired raw whole-block metadata.
    metadata_stamp: Option<super::CacheReadStamp>,
}

impl EpochReadOperation {
    /// Opens an entry projection with the dependencies of the traversal that identified it.
    pub(super) fn entry(profile: &MountedProfile, observed: ReadObservations) -> Self {
        Self {
            mount: profile.mount,
            filesystem: StorageTranscript::new(
                StorageTarget::Filesystem,
                profile.filesystem_length(),
            ),
            observed,
            metadata_stamp: None,
        }
    }
    /// Creates an empty read transcript for one mounted filesystem device.
    #[must_use]
    pub fn new(profile: &MountedProfile) -> Self {
        Self {
            mount: profile.mount,
            observed: ReadObservations::new(),
            metadata_stamp: None,
            filesystem: StorageTranscript::new(
                StorageTarget::Filesystem,
                profile.filesystem_length(),
            ),
        }
    }

    /// Runs one arbitrary restartable read pass after consuming the supplied concrete event.
    ///
    /// The closure is invoked at most once for this event and receives only an ephemeral pass. A
    /// lower-storage miss suspends the owning operation by value; unrelated operations are never
    /// probed. A read conflict consumes the operation and cannot resume its transcript.
    #[must_use]
    pub fn run<T>(
        mut self,
        event: super::OperationEvent,
        context: super::CommittedReadContext<'_>,
        crypto: &mut dyn CryptographicOperation,
        resolve: impl FnOnce(&mut EpochReadPass<'_, '_, '_>) -> Result<T>,
    ) -> ReadTransition<T> {
        let cache = context.cache;
        let epoch = cache.epoch();
        if self.mount != epoch.mount {
            return ReadTransition::Complete(Err(Error::ReadConflict));
        }
        match event {
            super::OperationEvent::Admitted => {}
            super::OperationEvent::StorageCompleted(completion) => {
                if let Err(error) = self.filesystem.complete(completion) {
                    return ReadTransition::Complete(Err(error));
                }
            }
            super::OperationEvent::CancelRequested => {
                return ReadTransition::Complete(Err(Error::OperationCancelled));
            }
            super::OperationEvent::RetryElapsed(_)
            | super::OperationEvent::DeviceLengthCompleted(_)
            | super::OperationEvent::IntentGranted(_)
            | super::OperationEvent::CommitGranted(_)
            | super::OperationEvent::VisibilityGranted(_)
            | super::OperationEvent::CheckpointGranted(_)
            | super::OperationEvent::BarrierReleased(_) => {
                return ReadTransition::Complete(Err(Error::DeviceIo));
            }
        }
        if !context.versions.revalidate_read(&self.observed) {
            return ReadTransition::Complete(Err(Error::ReadConflict));
        }
        if self.metadata_stamp != Some(cache.stamp()) {
            self.filesystem.refresh_metadata(cache.stamp());
            self.metadata_stamp = Some(cache.stamp());
        }
        let result = {
            let device = OperationDevice::with_overlay(&mut self.filesystem, epoch, Some(cache));
            let mut view =
                EpochReadView::observing(device, epoch, context.versions, &mut self.observed);
            let mut pass = EpochReadPass {
                view: &mut view,
                crypto,
            };
            resolve(&mut pass)
        };
        match result {
            Err(Error::OperationSuspended) => match self.filesystem.take_pending_request() {
                Ok(request) => ReadTransition::SubmitLower {
                    request,
                    suspended: self,
                },
                Err(error) => ReadTransition::Complete(Err(error)),
            },
            result => ReadTransition::Complete(result),
        }
    }
}

/// Owned mutation resolver after its event has been integrated and before one synchronous pass.
#[derive(Debug)]
pub struct MutationResolveReady {
    /// Immutable epoch selected for the entire resolve transcript.
    epoch: Option<super::EpochSequence>,
    /// Mount session that owns every retained read buffer.
    mount: MountIdentity,
    /// Operation-owned filesystem transcript.
    filesystem: StorageTranscript,
}

/// Owned mutation resolver suspended only on concrete storage completions.
#[derive(Debug)]
pub struct MutationResolveOperation {
    /// Immutable epoch selected for the entire resolve transcript.
    epoch: Option<super::EpochSequence>,
    /// Mount session that owns every retained read buffer.
    mount: MountIdentity,
    /// Operation-owned filesystem transcript.
    filesystem: StorageTranscript,
}

/// Terminal or lower-submit transition after one mutation resolve pass.
#[derive(Debug)]
pub enum MutationResolveTransition {
    /// Submit the pass's sole owned read and suspend all resolver state by value.
    SubmitLower {
        /// Request moved into the lower completion envelope.
        request: crate::StorageRequest,
        /// Resolver resumed only by the matching completion.
        suspended: MutationResolveOperation,
    },
    /// Resolution terminated before any lower write was issued.
    Complete(Result<ResolvedMutation>),
}

impl MutationResolveOperation {
    /// Creates an empty mutation read transcript.
    #[must_use]
    pub fn new(profile: &MountedProfile) -> Self {
        Self {
            mount: profile.mount,
            epoch: None,
            filesystem: StorageTranscript::new(
                StorageTarget::Filesystem,
                profile.filesystem_length(),
            ),
        }
    }

    /// Integrates admission or one matching read completion.
    /// # Errors
    ///
    /// Returns an error for a failed, short, duplicate, or mismatched completion.
    pub fn accept(mut self, event: super::OperationEvent) -> Result<MutationResolveReady> {
        match event {
            super::OperationEvent::Admitted => {}
            super::OperationEvent::StorageCompleted(completion) => {
                self.filesystem.complete(completion)?;
            }
            super::OperationEvent::CancelRequested => return Err(Error::OperationCancelled),
            super::OperationEvent::RetryElapsed(_)
            | super::OperationEvent::DeviceLengthCompleted(_)
            | super::OperationEvent::IntentGranted(_)
            | super::OperationEvent::CommitGranted(_)
            | super::OperationEvent::VisibilityGranted(_)
            | super::OperationEvent::CheckpointGranted(_)
            | super::OperationEvent::BarrierReleased(_) => return Err(Error::DeviceIo),
        }
        Ok(MutationResolveReady {
            mount: self.mount,
            epoch: self.epoch,
            filesystem: self.filesystem,
        })
    }
}

impl MutationResolveReady {
    /// Borrows an ephemeral synchronous resolve pass.
    ///
    /// The returned pass cannot enter a completion envelope. It must be consumed by
    /// [`MutationResolvePass::resolve`] before [`Self::finish`] moves this owned resolver.
    /// # Errors
    /// Rejects a different mount or epoch before interpreting retained lower buffers.
    pub fn begin_pass<'pass>(
        &'pass mut self,
        cache: crate::MetadataCacheAccess<'pass>,
        now: Ext4Timestamp,
        crypto: &'pass mut dyn CryptographicOperation,
    ) -> Result<MutationResolvePass<'pass, 'pass, 'pass>> {
        let epoch = cache.epoch();
        if self.mount != epoch.mount
            || self
                .epoch
                .is_some_and(|sequence| sequence != epoch.sequence())
        {
            return Err(Error::StaleReadContext);
        }
        self.epoch = Some(epoch.sequence());
        let device = OperationDevice::with_overlay(&mut self.filesystem, epoch, Some(cache));
        Ok(MutationResolvePass::begin(
            EpochReadView::committed(device, epoch),
            now,
            crypto,
        ))
    }

    /// Converts one consumed pass result into a lower submit or terminal resolved mutation.
    #[must_use]
    pub fn finish(mut self, result: Result<ResolvedMutation>) -> MutationResolveTransition {
        if matches!(result, Err(Error::OperationSuspended)) {
            return match self.filesystem.take_pending_request() {
                Ok(request) => MutationResolveTransition::SubmitLower {
                    request,
                    suspended: MutationResolveOperation {
                        mount: self.mount,
                        epoch: self.epoch,
                        filesystem: self.filesystem,
                    },
                },
                Err(error) => MutationResolveTransition::Complete(Err(error)),
            };
        }
        MutationResolveTransition::Complete(result)
    }
}
