//! Completion-driven read operation sessions over immutable committed epochs.

use super::scope::*;
use super::transaction::{MutationResolvePass, ResolvedMutation};
use crate::disk::storage::{StorageTarget, StorageTranscript};

/// One consuming transition of a committed-epoch read operation.
#[derive(Debug)]
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

/// Read surface shared by immutable read passes and mutation resolve passes.
///
/// These are the two concrete restart-local contexts that may inspect committed state. Neither
/// implementation can survive suspension: all storage and continuation ownership remains in its
/// enclosing operation.
pub trait CommittedReadPass {
    /// Loads a regular file by validated identity.
    fn load_file(&mut self, id: FileNodeId) -> Result<FileNode>;
    /// Loads a directory by validated identity.
    fn load_directory(&mut self, id: DirectoryNodeId) -> Result<DirectoryNode>;
    /// Loads a symbolic link by validated identity.
    fn load_symlink(&mut self, id: SymlinkNodeId) -> Result<SymlinkNode>;
    /// Loads and classifies one Windows-facing file index.
    fn load_node_by_file_index(&mut self, file_index: u32) -> Result<NodeId>;
    /// Reads every extended attribute attached to a typed node.
    fn read_xattrs(&mut self, node: NodeId) -> Result<XattrSet>;
    /// Reads one extended attribute attached to a typed node.
    fn read_xattr(&mut self, node: NodeId, name: &XattrName) -> Result<Option<XattrValue>>;
    /// Reads Windows overlay metadata.
    fn read_windows_overlay(&mut self, node: NodeId) -> Result<Option<WindowsOverlay>>;
    /// Reads Windows symbolic-link reparse metadata.
    fn read_windows_symlink_reparse_point(
        &mut self,
        node: NodeId,
    ) -> Result<Option<WindowsSymlinkReparsePoint>>;
    /// Reads regular-file bytes into an exact caller-owned range.
    fn read_file(
        &mut self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes>;
    /// Reads one symbolic-link target into an owned byte vector.
    fn read_symlink(&mut self, symlink: &SymlinkNode) -> Result<Vec<u8>>;
    /// Enumerates validated directory entries.
    fn read_directory(&mut self, directory: &DirectoryNode) -> Result<Vec<DirectoryEntry>>;
    /// Enumerates every reachable hard link to a non-directory inode.
    fn read_hard_links(&mut self, target: HardLinkNodeId) -> Result<HardLinks>;
    /// Looks up one exact ext4 child name.
    fn lookup_child(&mut self, parent: &DirectoryNode, name: &Ext4Name) -> Result<ChildLookup>;
    /// Looks up one unambiguous Windows-visible child name.
    fn lookup_windows_child(
        &mut self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> Result<ChildLookup>;
}

/// Ephemeral synchronous read pass reconstructed from one operation transcript and epoch.
///
/// The pass may be borrowed only while one concrete event is being advanced. It cannot be stored
/// in a completion context, and an incomplete storage access returns
/// [`Error::OperationSuspended`] so the owning [`EpochReadOperation`] can move the resulting owned
/// request into lower-I/O ownership.
#[derive(Debug)]
pub struct EpochReadPass<'pass, 'storage, 'epoch> {
    /// Internal committed-epoch view used only for this restartable pass.
    view: &'pass mut EpochReadView<'storage, 'epoch>,
}

impl EpochReadPass<'_, '_, '_> {
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

    /// Reads Windows overlay metadata from the ext4 xattr boundary.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the overlay is invalid.
    pub fn read_windows_overlay(&mut self, node: NodeId) -> Result<Option<WindowsOverlay>> {
        self.view.read_inode_windows_overlay(node.inode())
    }

    /// Reads Windows symbolic-link reparse metadata from the ext4 xattr boundary.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the payload is invalid.
    pub fn read_windows_symlink_reparse_point(
        &mut self,
        node: NodeId,
    ) -> Result<Option<WindowsSymlinkReparsePoint>> {
        self.view
            .read_inode_windows_symlink_reparse_point(node.inode())
    }

    /// Reads regular-file bytes into an exact caller-owned range.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the file mapping is invalid.
    pub fn read_file(
        &mut self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        self.view.read_file(file, offset, out)
    }

    /// Reads one symbolic-link target into an owned byte vector.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the target is invalid.
    pub fn read_symlink(&mut self, symlink: &SymlinkNode) -> Result<Vec<u8>> {
        self.view.read_symlink(symlink)
    }

    /// Enumerates validated directory entries.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the directory is invalid.
    pub fn read_directory(&mut self, directory: &DirectoryNode) -> Result<Vec<DirectoryEntry>> {
        self.view.read_directory(directory)
    }

    /// Enumerates every reachable hard link to a non-directory inode.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or namespace invariants fail.
    pub fn read_hard_links(&mut self, target: HardLinkNodeId) -> Result<HardLinks> {
        self.view.read_hard_links(target)
    }

    /// Looks up one exact ext4 child name.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete or the directory is invalid.
    pub fn lookup_child(&mut self, parent: &DirectoryNode, name: &Ext4Name) -> Result<ChildLookup> {
        self.view.lookup_child(parent, name)
    }

    /// Looks up one unambiguous Windows-visible child name.
    /// # Errors
    ///
    /// Returns an error when storage is incomplete, the directory is invalid, or the projected
    /// name is ambiguous.
    pub fn lookup_windows_child(
        &mut self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> Result<ChildLookup> {
        self.view.lookup_windows_child(parent, requested)
    }
}

impl CommittedReadPass for EpochReadPass<'_, '_, '_> {
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

    fn read_windows_overlay(&mut self, node: NodeId) -> Result<Option<WindowsOverlay>> {
        self.read_windows_overlay(node)
    }

    fn read_windows_symlink_reparse_point(
        &mut self,
        node: NodeId,
    ) -> Result<Option<WindowsSymlinkReparsePoint>> {
        self.read_windows_symlink_reparse_point(node)
    }

    fn read_file(
        &mut self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        self.read_file(file, offset, out)
    }

    fn read_symlink(&mut self, symlink: &SymlinkNode) -> Result<Vec<u8>> {
        self.read_symlink(symlink)
    }

    fn read_directory(&mut self, directory: &DirectoryNode) -> Result<Vec<DirectoryEntry>> {
        self.read_directory(directory)
    }

    fn read_hard_links(&mut self, target: HardLinkNodeId) -> Result<HardLinks> {
        self.read_hard_links(target)
    }

    fn lookup_child(&mut self, parent: &DirectoryNode, name: &Ext4Name) -> Result<ChildLookup> {
        self.lookup_child(parent, name)
    }

    fn lookup_windows_child(
        &mut self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> Result<ChildLookup> {
        self.lookup_windows_child(parent, requested)
    }
}

/// Operation-owned transcript for one logical read against an immutable epoch.
///
/// The caller retains the immutable epoch lease and logical request arguments. This value retains
/// only owned lower-read buffers and therefore remains address-independent while suspended.
#[derive(Debug)]
pub struct EpochReadOperation {
    /// Completed and in-flight reads for the filesystem device.
    filesystem: StorageTranscript,
}

impl EpochReadOperation {
    /// Creates an empty read transcript for one mounted filesystem device.
    #[must_use]
    pub const fn new(profile: &MountedProfile) -> Self {
        Self {
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
    /// probed.
    #[must_use]
    pub fn run<T>(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        resolve: impl FnOnce(&mut EpochReadPass<'_, '_, '_>) -> Result<T>,
    ) -> ReadTransition<T> {
        self.resolve(event, epoch, |view| {
            let mut pass = EpochReadPass { view };
            resolve(&mut pass)
        })
    }

    /// Loads a regular file identity from the selected immutable epoch.
    #[must_use]
    pub fn load_file(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        id: FileNodeId,
    ) -> ReadTransition<FileNode> {
        self.resolve(event, epoch, |volume| volume.load_file(id))
    }

    /// Loads a directory identity from the selected immutable epoch.
    #[must_use]
    pub fn load_directory(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        id: DirectoryNodeId,
    ) -> ReadTransition<DirectoryNode> {
        self.resolve(event, epoch, |volume| volume.load_directory(id))
    }

    /// Loads a symbolic-link identity from the selected immutable epoch.
    #[must_use]
    pub fn load_symlink(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        id: SymlinkNodeId,
    ) -> ReadTransition<SymlinkNode> {
        self.resolve(event, epoch, |volume| volume.load_symlink(id))
    }

    /// Loads and classifies one Windows-facing file index.
    #[must_use]
    pub fn load_node_by_file_index(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        file_index: u32,
    ) -> ReadTransition<NodeId> {
        self.resolve(event, epoch, |volume| {
            volume.load_node_by_file_index(file_index)
        })
    }

    /// Reads every public extended attribute attached to a typed node.
    #[must_use]
    pub fn read_xattrs(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        node: NodeId,
    ) -> ReadTransition<XattrSet> {
        self.resolve(event, epoch, |volume| {
            volume.read_inode_xattrs(node.inode())
        })
    }

    /// Reads one public extended attribute by name.
    #[must_use]
    pub fn read_xattr(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        node: NodeId,
        name: &XattrName,
    ) -> ReadTransition<Option<XattrValue>> {
        self.resolve(event, epoch, |volume| {
            volume.read_inode_xattr(node.inode(), name)
        })
    }

    /// Reads Windows overlay metadata isolated in the ext4 xattr boundary.
    #[must_use]
    pub fn read_windows_overlay(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        node: NodeId,
    ) -> ReadTransition<Option<WindowsOverlay>> {
        self.resolve(event, epoch, |volume| {
            volume.read_inode_windows_overlay(node.inode())
        })
    }

    /// Reads a Windows symbolic-link reparse payload from the ext4 xattr boundary.
    #[must_use]
    pub fn read_windows_symlink_reparse_point(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        node: NodeId,
    ) -> ReadTransition<Option<WindowsSymlinkReparsePoint>> {
        self.resolve(event, epoch, |volume| {
            volume.read_inode_windows_symlink_reparse_point(node.inode())
        })
    }

    /// Reads a bounded regular-file range into the caller-owned top-level buffer.
    #[must_use]
    pub fn read_file(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> ReadTransition<ReadBytes> {
        self.resolve(event, epoch, |volume| volume.read_file(file, offset, out))
    }

    /// Reads a symbolic-link target into a fallibly allocated owned byte vector.
    #[must_use]
    pub fn read_symlink(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        symlink: &SymlinkNode,
    ) -> ReadTransition<Vec<u8>> {
        self.resolve(event, epoch, |volume| volume.read_symlink(symlink))
    }

    /// Enumerates validated directory entries.
    #[must_use]
    pub fn read_directory(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        directory: &DirectoryNode,
    ) -> ReadTransition<Vec<DirectoryEntry>> {
        self.resolve(event, epoch, |volume| volume.read_directory(directory))
    }

    /// Enumerates every reachable namespace link to one non-directory inode.
    #[must_use]
    pub fn read_hard_links(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        target: HardLinkNodeId,
    ) -> ReadTransition<HardLinks> {
        self.resolve(event, epoch, |volume| volume.read_hard_links(target))
    }

    /// Looks up one exact ext4 child name.
    #[must_use]
    pub fn lookup_child(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        parent: &DirectoryNode,
        name: &Ext4Name,
    ) -> ReadTransition<ChildLookup> {
        self.resolve(event, epoch, |volume| volume.lookup_child(parent, name))
    }

    /// Looks up one Windows-visible child name with ambiguity rejection.
    #[must_use]
    pub fn lookup_windows_child(
        self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> ReadTransition<ChildLookup> {
        self.resolve(event, epoch, |volume| {
            volume.lookup_windows_child(parent, requested)
        })
    }

    /// Integrates an event and executes one restartable synchronous resolve pass.
    fn resolve<T>(
        mut self,
        event: super::OperationEvent,
        epoch: &CommittedEpoch,
        resolve: impl FnOnce(&mut EpochReadView<'_, '_>) -> Result<T>,
    ) -> ReadTransition<T> {
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
        let result = {
            let device = OperationDevice::with_overlay(&mut self.filesystem, epoch);
            let mut volume = EpochReadView::committed(device, epoch);
            resolve(&mut volume)
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
pub struct MutationResolveReady<N> {
    /// Operation-owned filesystem transcript.
    filesystem: StorageTranscript,
    /// Operation-owned nonce object; it never enters committed epoch state.
    nonce_generator: N,
}

/// Owned mutation resolver suspended only on concrete storage completions.
#[derive(Debug)]
pub struct MutationResolveOperation<N> {
    /// Operation-owned filesystem transcript.
    filesystem: StorageTranscript,
    /// Operation-owned nonce object.
    nonce_generator: N,
}

/// Terminal or lower-submit transition after one mutation resolve pass.
#[derive(Debug)]
pub enum MutationResolveTransition<N> {
    /// Submit the pass's sole owned read and suspend all resolver state by value.
    SubmitLower {
        /// Request moved into the lower completion envelope.
        request: crate::StorageRequest,
        /// Resolver resumed only by the matching completion.
        suspended: MutationResolveOperation<N>,
    },
    /// Resolution terminated before any lower write was issued.
    Complete(Result<ResolvedMutation>),
}

impl<N> MutationResolveOperation<N> {
    /// Creates an empty mutation read transcript and takes ownership of its nonce object.
    #[must_use]
    pub const fn new(profile: &MountedProfile, nonce_generator: N) -> Self {
        Self {
            filesystem: StorageTranscript::new(
                StorageTarget::Filesystem,
                profile.filesystem_length(),
            ),
            nonce_generator,
        }
    }

    /// Integrates admission or one matching read completion.
    /// # Errors
    ///
    /// Returns an error for a failed, short, duplicate, or mismatched completion.
    pub fn accept(mut self, event: super::OperationEvent) -> Result<MutationResolveReady<N>> {
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
            filesystem: self.filesystem,
            nonce_generator: self.nonce_generator,
        })
    }
}

impl<N: FscryptNonceGenerator> MutationResolveReady<N> {
    /// Borrows an ephemeral synchronous resolve pass.
    ///
    /// The returned pass cannot enter a completion envelope. It must be consumed by
    /// [`MutationResolvePass::resolve`] before [`Self::finish`] moves this owned resolver.
    #[must_use]
    pub fn begin_pass<'pass>(
        &'pass mut self,
        epoch: &'pass CommittedEpoch,
        now: Ext4Timestamp,
    ) -> MutationResolvePass<'pass, 'pass, 'pass, N> {
        let device = OperationDevice::with_overlay(&mut self.filesystem, epoch);
        MutationResolvePass::begin(
            EpochReadView::committed(device, epoch),
            now,
            &mut self.nonce_generator,
        )
    }

    /// Converts one consumed pass result into a lower submit or terminal resolved mutation.
    #[must_use]
    pub fn finish(mut self, result: Result<ResolvedMutation>) -> MutationResolveTransition<N> {
        if matches!(result, Err(Error::OperationSuspended)) {
            return match self.filesystem.take_pending_request() {
                Ok(request) => MutationResolveTransition::SubmitLower {
                    request,
                    suspended: MutationResolveOperation {
                        filesystem: self.filesystem,
                        nonce_generator: self.nonce_generator,
                    },
                },
                Err(error) => MutationResolveTransition::Complete(Err(error)),
            };
        }
        MutationResolveTransition::Complete(result)
    }
}
