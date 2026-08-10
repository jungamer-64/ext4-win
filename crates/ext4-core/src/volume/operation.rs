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
