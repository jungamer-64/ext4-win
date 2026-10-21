//! Mount-local key publication, serialized with filesystem commits but issuing no storage I/O.

use super::scope::*;
use super::{CommitLease, MutationLease, VisibilityLease};

/// Replacement key snapshot resolved against one committed key-set version.
///
/// Key material is mount-local. Publishing this change does not journal or persist it, and
/// unmounting discards it. Removing an absent identifier succeeds without granting data access.
#[derive(Debug)]
pub struct ResolvedKeyChange {
    /// Exclusive intent and freshness requirements for the key snapshot.
    observed: ObservedResourceVersionSet,
    /// Complete successor, erased if preparation is abandoned.
    keys: FscryptKeySet,
}

impl ResolvedKeyChange {
    /// Resolves insertion of an already validated master key.
    /// # Errors
    /// Returns stale epoch, duplicate identifier, or allocation failures before publication.
    pub fn add(
        epoch: &CommittedEpoch,
        coordinator: &MutationCoordinatorState,
        ticket: u64,
        key: FscryptMasterKey,
    ) -> Result<Self> {
        let mut change = Self::snapshot(epoch, coordinator, ticket)?;
        change.keys.insert(key)?;
        Ok(change)
    }

    /// Resolves removal of one identifier, including an identifier already absent.
    /// # Errors
    /// Returns stale epoch or allocation failures before publication.
    pub fn remove(
        epoch: &CommittedEpoch,
        coordinator: &MutationCoordinatorState,
        ticket: u64,
        identifier: FscryptKeyIdentifier,
    ) -> Result<Self> {
        let mut change = Self::snapshot(epoch, coordinator, ticket)?;
        drop(change.keys.remove(identifier)?);
        Ok(change)
    }

    /// Captures the sole authoritative key snapshot and its resource version together.
    /// # Errors
    /// Returns a stale epoch or allocation failure.
    fn snapshot(
        epoch: &CommittedEpoch,
        coordinator: &MutationCoordinatorState,
        ticket: u64,
    ) -> Result<Self> {
        if coordinator.mount != epoch.mount
            || coordinator.published_epoch() != (epoch.identity().uuid(), epoch.sequence())
        {
            return Err(Error::StaleReadContext);
        }
        let mut observed = ObservedResourceVersionSet::new(ticket, &coordinator.mount);
        observed.include(
            MutationResource::KEY_SET,
            coordinator.resource_version(MutationResource::KEY_SET),
        )?;
        Ok(Self {
            observed,
            keys: epoch.fscrypt_keys.try_clone()?,
        })
    }

    /// Resource/version snapshot used to acquire the exclusive key-set intent.
    #[must_use]
    pub const fn observed_resources(&self) -> &ObservedResourceVersionSet {
        &self.observed
    }

    /// Consumes a matching key-set intent after revalidating its observed version.
    /// # Errors
    /// Returns a mismatched ticket or a changed key set before reserving publication authority.
    pub fn reserve(
        self,
        intent: MutationLease,
        coordinator: &MutationCoordinatorState,
    ) -> Result<ReservedKeyChange> {
        if intent.consume(&coordinator.mount)? != self.observed.ticket()
            || !coordinator.revalidate(&self.observed)
        {
            return Err(Error::ClusterReferenceConflict);
        }
        Ok(ReservedKeyChange { resolved: self })
    }
}

/// Key successor protected by its exclusive key-set resource intent.
#[derive(Debug)]
pub struct ReservedKeyChange {
    /// Version-revalidated successor owned until commit preparation or abandonment.
    resolved: ResolvedKeyChange,
}

impl ReservedKeyChange {
    /// Preallocates one successor epoch under the matching serialized commit grant.
    ///
    /// The serialized commit lane keeps checkpoint completion from replacing this successor.
    /// It grants ordering authority only; a key change does not make a journal transaction.
    /// # Errors
    /// Returns mismatched grants, stale keys/epoch, a pending checkpoint, or allocation failure.
    pub fn prepare(
        self,
        commit: CommitLease,
        coordinator: &mut MutationCoordinatorState,
        current: &CommittedEpoch,
    ) -> Result<PreparedKeyChange> {
        coordinator.prepare_publication(
            commit,
            self.resolved.observed.ticket(),
            |coordinator, claim| self.prepare_under_claim(coordinator, current, claim),
        )
    }

    /// Prepares an allocation-free key publication under the consumed acquisition.
    /// # Errors
    /// Returns stale keys/epochs or allocation failures before publication.
    fn prepare_under_claim(
        self,
        coordinator: &mut MutationCoordinatorState,
        current: &CommittedEpoch,
        claim: CommitClaim,
    ) -> Result<PreparedKeyChange> {
        if !coordinator.revalidate(&self.resolved.observed) {
            return Err(Error::ClusterReferenceConflict);
        }
        if coordinator.mount != current.mount {
            return Err(Error::StaleReadContext);
        }
        let expected_epoch = (current.identity().uuid(), current.sequence());
        match &coordinator.journal {
            JournalCoordinatorState::Ready { epoch, .. } if *epoch == expected_epoch => {}
            _ => return Err(Error::StaleReadContext),
        }
        let versions = coordinator.prepare_version_publication(&self.resolved.observed)?;
        let epoch = CommittedEpoch::prepared(
            current,
            current.sequence().next()?,
            current.superblock,
            self.resolved.keys,
            current.clusters.try_clone()?,
            Vec::new(),
        );
        Ok(PreparedKeyChange {
            claim,
            expected_epoch,
            epoch,
            versions,
        })
    }
}

/// Fully prepared mount-key publication; dropping it leaves keys unchanged and retains the
/// acquisition. Explicit abort consumes the successor before another operation can be admitted.
#[derive(Debug)]
pub struct PreparedKeyChange {
    /// Mutation whose exclusive grants protect this publication.
    claim: CommitClaim,
    /// Published epoch that must still be current at the consuming transition.
    expected_epoch: (crate::FilesystemUuid, super::EpochSequence),
    /// Complete successor requiring no allocation during the swap.
    epoch: CommittedEpoch,
    /// Key-resource freshness publication, prepared under commit serialization.
    versions: ResourceVersionPublication,
}

impl PreparedKeyChange {
    /// Consumes an unpublished key successor and revokes its preparation and visibility authority.
    /// # Errors
    /// Returns the error and reusable successor for a foreign or superseded coordinator.
    #[expect(
        clippy::result_large_err,
        reason = "rejected abort retains secret-owned preparation without allocating"
    )]
    pub fn abort(
        self,
        coordinator: &mut MutationCoordinatorState,
    ) -> core::result::Result<(), (Error, Self)> {
        if let Err(error) = coordinator.abort_prepared(self.epoch.mount, self.claim) {
            return Err((error, self));
        }
        Ok(())
    }

    /// Publishes keys and their dependency version without allocation or storage I/O.
    /// # Errors
    /// Consumes the visibility grant on either outcome. Rejection returns the unpublished key
    /// successor, which can be explicitly aborted against its owning coordinator.
    #[expect(
        clippy::result_large_err,
        reason = "publication rejection returns the secret-owned successor without allocating"
    )]
    pub fn publish(
        self,
        visibility: VisibilityLease,
        coordinator: &mut MutationCoordinatorState,
    ) -> core::result::Result<CommittedEpoch, (Error, Self)> {
        if !coordinator.accepts_visibility(visibility, self.claim)
            || coordinator.mount != self.epoch.mount
        {
            return Err((Error::ClusterReferenceConflict, self));
        }
        let JournalCoordinatorState::Ready {
            epoch, admission, ..
        } = &mut coordinator.journal
        else {
            return Err((Error::StaleReadContext, self));
        };
        if *epoch != self.expected_epoch {
            return Err((Error::StaleReadContext, self));
        }
        *epoch = (self.epoch.identity().uuid(), self.epoch.sequence());
        *admission = CommitAdmission::Available;
        coordinator.publish_versions(self.versions);
        Ok(self.epoch)
    }
}
