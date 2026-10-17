//! Shared identity of opened namespace links, independent of per-handle access and cursors.
//!
//! Each inode's ledger interns its live locations. The volume reactor alone observes or changes
//! their contents; native callbacks and passive workers never access them. Rename prepares its
//! successor before commit and replaces the shared value only after durability. `RefCell` guards
//! cannot cross that publication boundary; a conflicting borrow is a terminal reactor defect.

use super::{DriverError, DriverResult, DriverVec, KernelWideInconsistency, OpenedLocation};
use crate::memory::{DriverShared, DriverSharedLease};
use core::cell::{Ref, RefCell};

/// Ledger-owned location identities for one inode, retaining only identities with live leases.
pub(super) struct OpenedLocations {
    /// Owning allocations; their current contents are also the lookup key.
    entries: DriverVec<DriverShared<RefCell<OpenedLocation>>>,
}

impl OpenedLocations {
    /// Starts without any selected namespace link.
    pub(super) const fn new() -> Self {
        Self {
            entries: DriverVec::new(),
        }
    }

    /// Shares a current location and reclaims identities whose final lease has retired.
    /// # Errors
    /// Returns allocation or finite reference exhaustion before a handle is published.
    pub(super) fn acquire(
        &mut self,
        location: OpenedLocation,
    ) -> DriverResult<OpenedLocationLease> {
        for index in (0..self.entries.len()).rev() {
            let entry = self
                .entries
                .as_slice()
                .get(index)
                .ok_or(DriverError::InternalInvariantViolation)?;
            if !entry.has_leases() {
                let _retired = self.entries.swap_remove(index);
            }
        }
        for entry in self.entries.iter() {
            if *borrow(entry.get()) == location {
                return Ok(OpenedLocationLease {
                    inner: entry.try_acquire()?,
                });
            }
        }
        let entry = DriverShared::try_new(RefCell::new(location))?;
        let lease = OpenedLocationLease {
            inner: entry.try_acquire()?,
        };
        self.entries
            .try_push_owned(entry)
            .map_err(|failure| failure.into_parts().0)?;
        Ok(lease)
    }

    /// Prepares a spelling change of an already-open hard-link destination.
    /// # Errors
    /// Returns finite reference exhaustion without modifying any location.
    pub(super) fn prepare_rename(
        &self,
        source: &OpenedLocation,
        destination: OpenedLocation,
    ) -> DriverResult<Option<PreparedLinkRename>> {
        for entry in self.entries.iter() {
            if entry.has_leases() && *borrow(entry.get()) == *source {
                return Ok(Some(PreparedLinkRename {
                    inner: entry.try_acquire()?,
                    destination,
                }));
            }
        }
        Ok(None)
    }
}

/// Namespace identity selected by a handle; independent hard links retain different allocations.
#[derive(Debug)]
pub(crate) struct OpenedLocationLease {
    /// Keeps the selected link alive through cleanup, close, and pending publication.
    inner: DriverSharedLease<RefCell<OpenedLocation>>,
}

impl OpenedLocationLease {
    /// Borrows the current link position during one non-suspending reactor step.
    pub(crate) fn location(&self) -> Ref<'_, OpenedLocation> {
        borrow(self.inner.get())
    }

    /// Retains this exact link and preallocates its successor before any irreversible write.
    /// # Errors
    /// Returns reference exhaustion before publication authority exists.
    pub(crate) fn prepare_rename(
        &self,
        destination: OpenedLocation,
    ) -> DriverResult<PreparedLinkRename> {
        Ok(PreparedLinkRename {
            inner: self.inner.try_acquire()?,
            destination,
        })
    }
}

/// Unique post-commit publication authority for one selected namespace link.
#[derive(Debug)]
pub(crate) struct PreparedLinkRename {
    /// Independently retains the link through commit; no CCB pointer or handle enumeration is needed.
    inner: DriverSharedLease<RefCell<OpenedLocation>>,
    /// Fully owned successor moved into the shared allocation without allocation.
    destination: OpenedLocation,
}

impl PreparedLinkRename {
    /// Publishes the committed successor to every handle that selected this exact link.
    pub(crate) fn publish(self) {
        let mut location = self.inner.get().try_borrow_mut().unwrap_or_else(|_| {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
        });
        *location = self.destination;
    }
}

/// Borrows only during an actor step; overlapping mutable access is an internal protocol defect.
fn borrow(location: &RefCell<OpenedLocation>) -> Ref<'_, OpenedLocation> {
    location
        .try_borrow()
        .unwrap_or_else(|_| KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ext4_core::{DirectoryNodeId, Ext4Name};

    /// Creates a selected-link position without requiring an on-disk fixture.
    /// # Errors
    /// Returns name or allocation failure.
    fn location(name: &[u8]) -> DriverResult<OpenedLocation> {
        OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &Ext4Name::new(name)?)
    }

    /// # Errors
    /// Returns fixture name, allocation or lease exhaustion.
    /// # Panics
    /// Fails if chained rename leaves another open stale or changes a different hard link.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture construction propagates; assertions check shared link semantics"
    )]
    fn handles_follow_the_same_link_through_chained_renames() -> DriverResult<()> {
        let mut registry = OpenedLocations::new();
        let first = registry.acquire(location(b"a")?)?;
        let second = registry.acquire(location(b"a")?)?;
        let other_link = registry.acquire(location(b"other")?)?;
        let aborted = first.prepare_rename(location(b"uncommitted")?)?;
        drop(aborted);
        assert_eq!(*second.location(), location(b"a")?);
        first.prepare_rename(location(b"b")?)?.publish();
        assert_eq!(*first.location(), location(b"b")?);
        assert_eq!(*second.location(), location(b"b")?);
        let reopened = registry.acquire(location(b"b")?)?;
        let reused_old_name = registry.acquire(location(b"a")?)?;
        second.prepare_rename(location(b"c")?)?.publish();
        assert_eq!(*first.location(), location(b"c")?);
        assert_eq!(*reopened.location(), location(b"c")?);
        assert_eq!(*other_link.location(), location(b"other")?);
        assert_eq!(*reused_old_name.location(), location(b"a")?);
        let deletion =
            super::super::PendingFileDeletion::try_from_disposition(&reopened.location())?;
        assert_eq!(deletion.target_ref().name().bytes(), b"c");
        drop((first, second, reopened));
        let fresh = registry.acquire(location(b"c")?)?;
        fresh.prepare_rename(location(b"d")?)?.publish();
        assert_eq!(*fresh.location(), location(b"d")?);
        assert_eq!(*other_link.location(), location(b"other")?);
        Ok(())
    }

    /// # Errors
    /// Returns fixture name, allocation or reference exhaustion.
    /// # Panics
    /// Fails if hard-link spelling replacement updates an unrelated selected link.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible setup propagates; assertions check destination identity selection"
    )]
    fn replacement_changes_only_the_selected_destination_link() -> DriverResult<()> {
        let mut registry = OpenedLocations::new();
        let source = registry.acquire(location(b"source")?)?;
        let destination = registry.acquire(location(b"target")?)?;
        let publication = registry.prepare_rename(&location(b"target")?, location(b"TARGET")?)?;
        assert!(publication.is_some());
        if let Some(publication) = publication {
            publication.publish();
        }
        assert_eq!(*source.location(), location(b"source")?);
        assert_eq!(*destination.location(), location(b"TARGET")?);
        assert!(
            registry
                .prepare_rename(&location(b"absent")?, location(b"unused")?)?
                .is_none()
        );
        Ok(())
    }
}
