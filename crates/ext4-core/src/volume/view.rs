//! Pass-local metadata views for recovery and mounted operations.

use super::block_group::ClusterReferenceIndex;
use super::session::{
    CommittedEpoch, MutationResource, PublishedEpochId, ReadObservations, ResourceVersion,
    ResourceVersionTable,
};
use crate::disk::storage::OperationDevice;
use crate::disk_format::inode::InodeId;
use crate::disk_format::superblock::Superblock;
use crate::protection::fscrypt::FscryptKeySet;
use crate::{Error, Result};

/// A pass-local read dependency recorder; no mutation or publication authority is exposed.
#[derive(Debug)]
struct ReadObservation<'pass, 'state> {
    /// Dependencies owned by the suspended read operation.
    observed: &'pass mut ReadObservations,
    /// Current committed versions for this pass.
    versions: &'state ResourceVersionTable,
}

/// Whether a pass has consumed mount-key authority while building its result.
#[derive(Clone, Copy, Debug)]
enum KeySetDependency {
    /// No operation in this pass has depended on a master key.
    Independent,
    /// Mutation reservation and serialized commit preparation must revalidate the key version.
    Required,
}

/// Ephemeral read facade reconstructed for each completion-driven resolve pass.
///
/// It borrows immutable epoch state and an operation-owned storage transcript; it is never stored
/// in a lower completion context.
#[derive(Debug)]
pub(super) struct EpochReadView<'storage, 'epoch> {
    /// Retains key usage across the remainder of mutation resolution, including plaintext staging.
    key_dependency: KeySetDependency,
    /// Read dependencies; mount and mutation resolution have separate admission protocols.
    observation: Option<ReadObservation<'storage, 'epoch>>,
    /// Concrete operation storage view.
    pub(super) device: OperationDevice<'storage>,
    /// Current validated superblock snapshot.
    pub(super) superblock: Superblock,
    /// Immutable key snapshot selected by the epoch lease.
    pub(super) fscrypt_keys: &'epoch FscryptKeySet,
    /// Publication provenance, present only for a committed view.
    publication: Option<PublishedEpochId>,
    /// Allocation ownership snapshot used only by mutation resolution.
    clusters: Option<&'epoch ClusterReferenceIndex>,
}

impl<'storage, 'epoch> EpochReadView<'storage, 'epoch> {
    /// Builds a view of an already committed epoch.
    pub(super) const fn committed(
        device: OperationDevice<'storage>,
        epoch: &'epoch CommittedEpoch,
    ) -> Self {
        Self {
            key_dependency: KeySetDependency::Independent,
            observation: None,
            device,
            superblock: epoch.superblock,
            fscrypt_keys: &epoch.fscrypt_keys,
            clusters: epoch.clusters.as_ref(),
            publication: Some(epoch.publication_id()),
        }
    }

    /// Borrows validated mount-private metadata before the first live epoch exists.
    pub(super) const fn recovery(
        device: OperationDevice<'storage>,
        superblock: Superblock,
        fscrypt_keys: &'epoch FscryptKeySet,
        clusters: Option<&'epoch ClusterReferenceIndex>,
    ) -> Self {
        Self {
            key_dependency: KeySetDependency::Independent,
            observation: None,
            device,
            superblock,
            fscrypt_keys,
            clusters,
            publication: None,
        }
    }

    /// Returns the publication that authorized this view, when already mounted.
    pub(super) const fn published_epoch(&self) -> Option<PublishedEpochId> {
        self.publication
    }

    /// Constructs a read view whose lower bytes are checked against committed inode versions.
    pub(super) fn observing(
        device: OperationDevice<'storage>,
        epoch: &'epoch CommittedEpoch,
        versions: &'epoch ResourceVersionTable,
        observed: &'storage mut ReadObservations,
    ) -> Self {
        let mut view = Self::committed(device, epoch);
        view.observation = Some(ReadObservation { observed, versions });
        view
    }

    /// Records an inode dependency before mapping or reading its disk representation.
    /// # Errors
    /// Returns allocation failure before issuing an inode-dependent lower read.
    pub(super) fn observe_inode(&mut self, inode: InodeId) -> Result<()> {
        self.observe_resource(MutationResource::inode(inode))
    }

    /// Records a dependency on the current key set before deriving plaintext.
    /// # Errors
    /// Returns allocation failure before consuming key-dependent bytes.
    pub(super) fn observe_resource(&mut self, resource: MutationResource) -> Result<()> {
        if let Some(observation) = &mut self.observation {
            observation
                .observed
                .include(resource, observation.versions.version(resource))?;
        }
        if resource == MutationResource::KEY_SET {
            self.key_dependency = KeySetDependency::Required;
        }
        Ok(())
    }

    /// Key snapshot dependency checked before a mutation enters its serialized commit.
    pub(super) const fn key_dependency(&self) -> Option<MutationResource> {
        match self.key_dependency {
            KeySetDependency::Independent => None,
            KeySetDependency::Required => Some(MutationResource::KEY_SET),
        }
    }

    /// Current inode version for decoded directory progress, absent during mount or resolution.
    pub(super) fn inode_version(&self, inode: InodeId) -> Option<ResourceVersion> {
        self.observation
            .as_ref()
            .map(|observation| observation.versions.version(MutationResource::inode(inode)))
    }

    /// Returns the committed allocation ownership required by mutation resolution.
    /// # Errors
    ///
    /// Returns [`Error::ClusterReferenceConflict`] when called from a mount-time view that has no
    /// committed allocation index.
    pub(super) fn committed_clusters(&self) -> Result<&ClusterReferenceIndex> {
        self.clusters.ok_or(Error::ClusterReferenceConflict)
    }
}
