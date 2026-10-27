//! Reactor-owned namespace links. Location, deletion and active opens have one authority.
//!
//! Stable slots retain handles and commit publications. Coalescence redirects a source slot
//! to the surviving link, including existing handles. Native callbacks never access this table.
//! Pending removal survives zero handle references until cleanup establishes its outcome.

use super::{
    DriverError, DriverResult, DriverVec, FileCleanupDisposition, FileDeleteTarget,
    KernelWideInconsistency, OpenedLocation, PendingFileDeletion,
};
use crate::memory::{DriverShared, DriverSharedLease};
use core::{
    cell::{Cell, Ref, RefCell, RefMut},
    ptr::NonNull,
};

/// One inode's selected links, allocated on its first namespace handle.
pub(super) struct OpenedLocations {
    /// Slot ownership survives its final handle while deletion is still pending.
    table: Option<DriverShared<RefCell<LinkTable>>>,
}
/// Slots are reused only after references and deletion obligations retire.
#[derive(Debug)]
struct LinkTable {
    /// Redirects own one reference to their destination.
    slots: DriverVec<Option<LinkSlot>>,
}
/// Zero references are retained only while an accepted deletion still needs an outcome.
#[derive(Debug)]
struct LinkSlot {
    /// Handles, publications and incoming redirects retaining this slot.
    references: u32,
    /// A namespace authority or its surviving destination.
    identity: LinkIdentity,
}
/// Namespace authority survives coalescence through a retained acyclic redirect.
#[derive(Debug)]
enum LinkIdentity {
    /// Sole authority for one current namespace link.
    Link(OpenedLink),
    /// A coalesced source retains its surviving slot.
    Redirect(usize),
}
/// Active handles and deletion share the same committed namespace identity.
#[derive(Debug)]
struct OpenedLink {
    /// Committed parent and spelling.
    location: OpenedLocation,
    /// Handle opens not yet consumed by cleanup or rollback.
    active_handles: u32,
    /// Admission and removal ownership for this link.
    deletion: LinkDeletion,
}
/// Removing grants one cleanup exclusive finalization; a failed result does not imply rollback.
#[derive(Debug)]
enum LinkDeletion {
    /// May admit another handle.
    Live,
    /// Validated removal waits for the last link handle.
    Pending(PendingFileDeletion),
    /// One cleanup owns the stable target through its external outcome.
    Removing(PendingFileDeletion),
    /// Removal committed; cleaned handles retain only the removed identity.
    Deleted,
}
/// Completion policy for an exclusively claimed link deletion.
pub(super) enum LinkDeletionOutcome {
    /// The selected namespace entry was durably removed.
    Removed,
    /// A known pre-effect failure restores the link.
    Aborted,
    /// Another inode handle prevents final-link reclamation.
    Deferred,
}
impl LinkDeletion {
    /// Removed identities still report deletion through retained cleaned handles.
    fn is_pending(&self) -> bool {
        !matches!(self, Self::Live)
    }
    /// A committed removal no longer subtracts from the inode's remaining link count.
    fn counts_as_pending_link(&self) -> bool {
        matches!(self, Self::Pending(_) | Self::Removing(_))
    }
}
impl LinkTable {
    /// Only retained references may select occupied slots; absence is terminal corruption.
    fn slot(&self, index: usize) -> &LinkSlot {
        self.slots
            .as_slice()
            .get(index)
            .and_then(Option::as_ref)
            .unwrap_or_else(corruption)
    }
    /// Mutation remains within the reactor's exclusive table borrow.
    fn slot_mut(&mut self, index: usize) -> &mut LinkSlot {
        self.slots
            .as_mut_slice()
            .get_mut(index)
            .and_then(Option::as_mut)
            .unwrap_or_else(corruption)
    }
    /// Joining distinct roots preserves an acyclic redirect graph.
    fn root(&self, mut index: usize) -> usize {
        for _ in 0..self.slots.len() {
            match &self.slot(index).identity {
                LinkIdentity::Link(_) => return index,
                LinkIdentity::Redirect(target) => index = *target,
            }
        }
        corruption()
    }
    /// Resolves a retained identity without changing its original slot ownership.
    fn link(&self, index: usize) -> &OpenedLink {
        match &self.slot(self.root(index)).identity {
            LinkIdentity::Link(link) => link,
            LinkIdentity::Redirect(_) => corruption(),
        }
    }
    /// Writes only the root authority, so aliases cannot diverge from surviving handles.
    fn link_mut(&mut self, index: usize) -> &mut OpenedLink {
        let root = self.root(index);
        match &mut self.slot_mut(root).identity {
            LinkIdentity::Link(link) => link,
            LinkIdentity::Redirect(_) => corruption(),
        }
    }
    /// Removed identities cannot capture a new entry with the same spelling.
    fn find(&self, location: &OpenedLocation) -> Option<usize> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            let LinkIdentity::Link(link) = &slot.as_ref()?.identity else {
                return None;
            };
            (link.location == *location && !matches!(link.deletion, LinkDeletion::Deleted))
                .then_some(index)
        })
    }
    /// # Errors
    /// Returns reference exhaustion without changing ownership.
    fn retain(&mut self, index: usize) -> DriverResult<()> {
        let slot = self.slot_mut(index);
        slot.references = slot
            .references
            .checked_add(1)
            .ok_or(DriverError::InsufficientResources)?;
        Ok(())
    }
    /// Consumes one handle obligation independently of its retained Close reference.
    fn deactivate(&mut self, index: usize) {
        let link = self.link_mut(index);
        link.active_handles = link
            .active_handles
            .checked_sub(1)
            .unwrap_or_else(corruption);
    }
    /// Releases redirects iteratively; pending zero-reference links retain their cleanup obligation.
    fn release(&mut self, mut index: usize) {
        loop {
            let slot = self.slot_mut(index);
            slot.references = slot.references.checked_sub(1).unwrap_or_else(corruption);
            if slot.references != 0 {
                return;
            }
            let redirect = match &slot.identity {
                LinkIdentity::Redirect(target) => Some(*target),
                LinkIdentity::Link(link) if link.deletion.counts_as_pending_link() => return,
                LinkIdentity::Link(_) => None,
            };
            *self
                .slots
                .as_mut_slice()
                .get_mut(index)
                .unwrap_or_else(corruption) = None;
            match redirect {
                Some(target) => index = target,
                None => return,
            }
        }
    }
    /// # Errors
    /// Returns deletion, allocation or counter exhaustion before admitting a handle.
    fn open(&mut self, location: OpenedLocation) -> DriverResult<usize> {
        if let Some(index) = self.find(&location) {
            let link = self.link(index);
            if link.deletion.is_pending() {
                return Err(DriverError::DeletePending);
            }
            let next = link
                .active_handles
                .checked_add(1)
                .ok_or(DriverError::InsufficientResources)?;
            self.retain(index)?;
            self.link_mut(index).active_handles = next;
            return Ok(index);
        }
        let slot = Some(LinkSlot {
            references: 1,
            identity: LinkIdentity::Link(OpenedLink {
                location,
                active_handles: 1,
                deletion: LinkDeletion::Live,
            }),
        });
        if let Some(index) = self.slots.iter().position(Option::is_none) {
            *self
                .slots
                .as_mut_slice()
                .get_mut(index)
                .unwrap_or_else(corruption) = slot;
            Ok(index)
        } else {
            let index = self.slots.len();
            self.slots
                .try_push_owned(slot)
                .map_err(|failure| failure.into_parts().0)?;
            Ok(index)
        }
    }
    /// Publication binds the prevalidated parent/name to its live link authority.
    fn target(&self, target: &FileDeleteTarget) -> usize {
        self.slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| {
                let LinkIdentity::Link(link) = &slot.as_ref()?.identity else {
                    return None;
                };
                if matches!(link.deletion, LinkDeletion::Deleted) {
                    return None;
                }
                match &link.location {
                    OpenedLocation::DirectoryEntry { parent, name }
                        if *parent == target.parent() && name == target.name() =>
                    {
                        Some(index)
                    }
                    _ => None,
                }
            })
            .unwrap_or_else(corruption)
    }
    /// Moves a preallocated removal into link-wide admission only when its owner publishes it.
    fn set_pending(&mut self, pending: PendingFileDeletion) {
        let index = self.target(pending.target_ref());
        let link = self.link_mut(index);
        if matches!(&link.deletion, LinkDeletion::Pending(existing) if existing.cause() == super::FileDeletionCause::DeleteOnClose)
        {
            return;
        }
        if !matches!(link.deletion, LinkDeletion::Live | LinkDeletion::Pending(_)) {
            corruption::<()>();
        }
        link.deletion = LinkDeletion::Pending(pending);
    }
    /// Finalization must match the exact claimed allocation, rather than a reusable name.
    fn removing(&self, target: NonNull<FileDeleteTarget>) -> usize {
        self.slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| {
                let LinkIdentity::Link(link) = &slot.as_ref()?.identity else {
                    return None;
                };
                match &link.deletion {
                    LinkDeletion::Removing(pending) if pending.target() == target => Some(index),
                    _ => None,
                }
            })
            .unwrap_or_else(corruption)
    }
}
impl OpenedLocations {
    /// Leaves namespace storage unallocated until a create claim acquires its first link.
    pub(super) const fn new() -> Self {
        Self { table: None }
    }
    /// # Errors
    /// Returns deletion, allocation or reference exhaustion before handle publication.
    pub(super) fn acquire(
        &mut self,
        location: OpenedLocation,
    ) -> DriverResult<OpenedLocationLease> {
        if self.table.is_none() {
            self.table = Some(DriverShared::try_new(RefCell::new(LinkTable {
                slots: DriverVec::new(),
            }))?);
        }
        let table = self
            .table
            .as_ref()
            .unwrap_or_else(corruption)
            .try_acquire()?;
        let index = borrow_mut(table.get()).open(location)?;
        Ok(OpenedLocationLease {
            identity: LinkLease {
                table,
                reference: SlotReference::Retained(index),
            },
            active: Cell::new(true),
            paging_cleanup: RefCell::new(None),
        })
    }
    /// # Errors
    /// Returns reference exhaustion before staging a spelling change or coalescence.
    pub(super) fn prepare_rename(
        &self,
        source: &OpenedLocation,
        destination: OpenedLocation,
    ) -> DriverResult<Option<PreparedLinkRename>> {
        let Some(table) = &self.table else {
            return Ok(None);
        };
        let Some(index) = borrow(table.get()).find(source) else {
            return Ok(None);
        };
        LinkLease::retain(table.try_acquire()?, index)?
            .prepare_rename(destination, None)
            .map(Some)
    }
    /// # Errors
    /// Rejects only the selected link; node-only checks apply to uniquely linked directories.
    pub(super) fn ensure_openable(&self, location: Option<&OpenedLocation>) -> DriverResult<()> {
        let Some(table) = &self.table else {
            return Ok(());
        };
        let table = borrow(table.get());
        let pending = match location {
            Some(location) => table.find(location).is_some_and(|index| table.link(index).deletion.is_pending()),
            None => table.slots.iter().flatten().any(|slot| matches!(&slot.identity, LinkIdentity::Link(link) if link.deletion.is_pending())),
        };
        if pending {
            Err(DriverError::DeletePending)
        } else {
            Ok(())
        }
    }
    /// Mandatory on-close deletion cannot be displaced by a mutable disposition.
    pub(super) fn set_pending(&self, pending: PendingFileDeletion) {
        borrow_mut(self.table.as_ref().unwrap_or_else(corruption).get()).set_pending(pending);
    }
    /// Any finalizing inode handle can claim a deferred link, but each target has one cleanup owner.
    pub(super) fn claim_deletion(&self) -> FileCleanupDisposition {
        let Some(table) = &self.table else {
            return FileCleanupDisposition::Retained;
        };
        let mut table = borrow_mut(table.get());
        for slot in table.slots.as_mut_slice().iter_mut().flatten() {
            let LinkIdentity::Link(link) = &mut slot.identity else {
                continue;
            };
            if link.active_handles != 0 || !matches!(link.deletion, LinkDeletion::Pending(_)) {
                continue;
            }
            let LinkDeletion::Pending(pending) =
                core::mem::replace(&mut link.deletion, LinkDeletion::Live)
            else {
                corruption()
            };
            let target = pending.target();
            link.deletion = LinkDeletion::Removing(pending);
            return FileCleanupDisposition::Delete(target);
        }
        FileCleanupDisposition::Retained
    }
    /// Completes the exact claimed target without allocating or repeating an uncertain effect.
    pub(super) fn finish_deletion(
        &self,
        target: NonNull<FileDeleteTarget>,
        outcome: LinkDeletionOutcome,
    ) {
        let mut table = borrow_mut(self.table.as_ref().unwrap_or_else(corruption).get());
        let index = table.removing(target);
        let link = table.link_mut(index);
        let LinkDeletion::Removing(pending) =
            core::mem::replace(&mut link.deletion, LinkDeletion::Live)
        else {
            corruption()
        };
        link.deletion = match outcome {
            LinkDeletionOutcome::Removed => LinkDeletion::Deleted,
            LinkDeletionOutcome::Aborted => LinkDeletion::Live,
            LinkDeletionOutcome::Deferred => LinkDeletion::Pending(pending),
        };
        if table.slot(index).references == 0 && !table.link(index).deletion.counts_as_pending_link()
        {
            *table
                .slots
                .as_mut_slice()
                .get_mut(index)
                .unwrap_or_else(corruption) = None;
        }
    }
    /// Fast metadata queries defer to the reactor whenever retained links have deletion state.
    pub(super) fn requires_query_fallback(&self) -> bool {
        self.table.as_ref().is_some_and(|table| {
            borrow(table.get()).slots.iter().flatten().any(|slot| {
            matches!(&slot.identity, LinkIdentity::Link(link) if link.deletion.is_pending())
        })
        })
    }
    /// Unremoved links whose deletion has been accepted.
    pub(super) fn pending_links(&self) -> u32 {
        self.table.as_ref().map_or(0, |table| {
            u32::try_from(borrow(table.get()).slots.iter().flatten().filter(|slot| matches!(&slot.identity, LinkIdentity::Link(link) if link.deletion.counts_as_pending_link())).count()).unwrap_or_else(|_| corruption())
        })
    }
}
/// Stable slot reference, independent of handle cleanup authority.
#[derive(Debug)]
struct LinkLease {
    /// Registry allocation retained through this slot's final reference.
    table: DriverSharedLease<RefCell<LinkTable>>,
    /// Private, stable slot index.
    reference: SlotReference,
}
/// Slot ownership can transfer to a redirect without increasing its reference count.
#[derive(Debug)]
enum SlotReference {
    /// This lease must release the retained slot.
    Retained(usize),
    /// A published redirect owns the slot reference.
    Transferred,
}
impl LinkLease {
    /// Transferred ownership cannot be reused as a preparation lease.
    fn index(&self) -> usize {
        match self.reference {
            SlotReference::Retained(index) => index,
            SlotReference::Transferred => corruption(),
        }
    }
    /// Transfers the already reserved reference to a redirect before the preparation lease drops.
    fn transfer(&mut self) -> usize {
        match core::mem::replace(&mut self.reference, SlotReference::Transferred) {
            SlotReference::Retained(index) => index,
            SlotReference::Transferred => corruption(),
        }
    }
    /// # Errors
    /// Returns reference exhaustion without changing ownership.
    fn retain(table: DriverSharedLease<RefCell<LinkTable>>, index: usize) -> DriverResult<Self> {
        borrow_mut(table.get()).retain(index)?;
        Ok(Self {
            table,
            reference: SlotReference::Retained(index),
        })
    }
    /// # Errors
    /// Returns reference exhaustion before namespace mutation.
    fn prepare_rename(
        self,
        destination: OpenedLocation,
        merge: Option<&OpenedLocation>,
    ) -> DriverResult<PreparedLinkRename> {
        let target = borrow(self.table.get()).find(merge.unwrap_or(&destination));
        let target = target
            .map(|index| Self::retain(self.table.try_acquire()?, index))
            .transpose()?;
        Ok(PreparedLinkRename {
            source: self,
            target,
            destination,
        })
    }
}
impl Drop for LinkLease {
    fn drop(&mut self) {
        if let SlotReference::Retained(index) = self.reference {
            borrow_mut(self.table.get()).release(index);
        }
    }
}
/// Selected link and the unique active-open obligation of one handle.
#[derive(Debug)]
pub(crate) struct OpenedLocationLease {
    /// Survives cleanup so query and Close retain the same namespace identity.
    identity: LinkLease,
    /// Cleanup consumes this obligation; Drop handles cancelled-create rollback.
    active: Cell<bool>,
    /// Only the kernel paging owner retains this mandatory cleanup target. The live link remains
    /// reopenable until that owner's cleanup; another control handle cannot consume this value.
    paging_cleanup: RefCell<Option<PendingFileDeletion>>,
}
impl OpenedLocationLease {
    /// Binds a preallocated target to this retained link and its unique handle-cleanup obligation.
    pub(super) fn arm_paging_cleanup(&self, pending: PendingFileDeletion) {
        if pending.cause() != super::FileDeletionCause::DeleteOnClose
            || !self.active.get()
            || borrow(self.identity.table.get()).target(pending.target_ref())
                != self.identity.index()
            || borrow_mut(&self.paging_cleanup).replace(pending).is_some()
        {
            corruption::<()>();
        }
    }
    /// The returned guard must retire before any namespace publication or suspension.
    pub(crate) fn location(&self) -> Ref<'_, OpenedLocation> {
        Ref::map(borrow(self.identity.table.get()), |table| {
            &table.link(self.identity.index()).location
        })
    }
    /// Reads only this selected link; unrelated hard links retain ordinary admission.
    pub(crate) fn delete_pending(&self) -> bool {
        borrow(self.identity.table.get())
            .link(self.identity.index())
            .deletion
            .is_pending()
    }
    /// Consumes the link-open obligation while leaving its Close reference intact.
    pub(super) fn cleanup(&self) {
        if !self.active.replace(false) {
            corruption::<()>();
        }
        let mut table = borrow_mut(self.identity.table.get());
        if let Some(pending) = borrow_mut(&self.paging_cleanup).take() {
            table.set_pending(pending);
        }
        table.deactivate(self.identity.index());
    }
    /// Normal disposition cancellation cannot revoke mandatory delete-on-close.
    pub(super) fn clear_pending(&self) {
        let mut table = borrow_mut(self.identity.table.get());
        let link = table.link_mut(self.identity.index());
        if matches!(&link.deletion, LinkDeletion::Pending(pending) if pending.cause() == super::FileDeletionCause::DeleteOnClose)
        {
            return;
        }
        if !matches!(link.deletion, LinkDeletion::Live | LinkDeletion::Pending(_)) {
            corruption::<()>();
        }
        link.deletion = LinkDeletion::Live;
    }
    /// # Errors
    /// Returns reference exhaustion before a namespace write.
    pub(crate) fn prepare_rename(
        &self,
        destination: OpenedLocation,
    ) -> DriverResult<PreparedLinkRename> {
        LinkLease::retain(self.identity.table.try_acquire()?, self.identity.index())?
            .prepare_rename(destination, None)
    }
    /// # Errors
    /// Returns reference exhaustion while binding a surviving link and its final spelling.
    pub(crate) fn prepare_merge(
        &self,
        target: &OpenedLocation,
        destination: OpenedLocation,
    ) -> DriverResult<PreparedLinkRename> {
        LinkLease::retain(self.identity.table.try_acquire()?, self.identity.index())?
            .prepare_rename(destination, Some(target))
    }
}
impl Drop for OpenedLocationLease {
    fn drop(&mut self) {
        if self.active.get() {
            borrow_mut(self.identity.table.get()).deactivate(self.identity.index());
        }
    }
}
/// Allocation-free publication of a committed movement or link coalescence.
#[derive(Debug)]
pub(crate) struct PreparedLinkRename {
    /// Retains every source handle's selected identity.
    source: LinkLease,
    /// Existing destination of a coalescence.
    target: Option<LinkLease>,
    /// Final committed spelling.
    destination: OpenedLocation,
}
impl PreparedLinkRename {
    /// Transfers prepared references and handle counts without allocation after durable commit.
    pub(crate) fn publish(mut self) {
        let mut table = borrow_mut(self.source.table.get());
        let source = table.root(self.source.index());
        if let Some(target) = &mut self.target {
            let root = table.root(target.index());
            if source != root {
                let handles = table
                    .link(source)
                    .active_handles
                    .checked_add(table.link(root).active_handles)
                    .unwrap_or_else(corruption);
                let redirect = target.transfer();
                table.link_mut(root).active_handles = handles;
                table.slot_mut(source).identity = LinkIdentity::Redirect(redirect);
            }
        }
        table.link_mut(source).location = self.destination;
    }
}
/// A missing retained slot or cyclic redirect is a terminal reactor defect.
fn corruption<T>() -> T {
    KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
}

/// The sole reactor cannot overlap a table mutation with an outstanding location observation.
fn borrow(table: &RefCell<LinkTable>) -> Ref<'_, LinkTable> {
    table.try_borrow().unwrap_or_else(|_| corruption())
}
/// Every mutation finishes within one actor step before publication or deferred execution.
fn borrow_mut<T>(table: &RefCell<T>) -> RefMut<'_, T> {
    table.try_borrow_mut().unwrap_or_else(|_| corruption())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ext4_core::{DirectoryNodeId, Ext4Name};

    /// # Errors
    /// Returns name validation or fixture allocation failure.
    fn location(name: &[u8]) -> DriverResult<OpenedLocation> {
        OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &Ext4Name::new(name)?)
    }

    /// # Errors
    /// Returns fixture allocation or finite reference exhaustion.
    /// # Panics
    /// Fails if one hard link affects another link's opens, cancellation or cleanup target.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible setup propagates; assertions check independent link lifecycles"
    )]
    fn independent_links_keep_both_deletions_and_wait_only_for_their_own_handles()
    -> DriverResult<()> {
        let mut links = OpenedLocations::new();
        let a = links.acquire(location(b"a")?)?;
        let same_a = links.acquire(location(b"a")?)?;
        let b = links.acquire(location(b"b")?)?;
        let first = PendingFileDeletion::try_from_disposition(&a.location())?;
        let first_target = first.target();
        links.set_pending(first);
        assert!(a.delete_pending());
        assert!(same_a.delete_pending());
        assert!(!b.delete_pending());
        assert!(matches!(
            links.acquire(location(b"a")?),
            Err(DriverError::DeletePending)
        ));
        let other_b = links.acquire(location(b"b")?)?;
        let pending = PendingFileDeletion::try_from_disposition(&b.location())?;
        links.set_pending(pending);
        b.clear_pending();
        assert!(a.delete_pending());
        assert!(!b.delete_pending());
        let second = PendingFileDeletion::try_from_disposition(&b.location())?;
        let second_target = second.target();
        links.set_pending(second);
        assert_eq!(links.pending_links(), 2);
        a.cleanup();
        assert_eq!(links.claim_deletion(), FileCleanupDisposition::Retained);
        same_a.cleanup();
        assert_eq!(
            links.claim_deletion(),
            FileCleanupDisposition::Delete(first_target)
        );
        links.finish_deletion(first_target, LinkDeletionOutcome::Removed);
        b.cleanup();
        assert_eq!(links.claim_deletion(), FileCleanupDisposition::Retained);
        other_b.cleanup();
        assert_eq!(
            links.claim_deletion(),
            FileCleanupDisposition::Delete(second_target)
        );
        links.finish_deletion(second_target, LinkDeletionOutcome::Removed);
        assert_eq!(links.pending_links(), 0);
        // A later entry with the same spelling must have a fresh live identity.
        let fresh_a = links.acquire(location(b"a")?)?;
        assert!(!fresh_a.delete_pending());
        assert!(a.delete_pending());
        let pending = PendingFileDeletion::try_from_disposition(&fresh_a.location())?;
        let target = pending.target();
        links.set_pending(pending);
        fresh_a.cleanup();
        assert_eq!(
            links.claim_deletion(),
            FileCleanupDisposition::Delete(target)
        );
        links.finish_deletion(target, LinkDeletionOutcome::Removed);
        Ok(())
    }

    /// # Errors
    /// Returns fixture allocation or finite reference exhaustion.
    /// # Panics
    /// Fails if deferred final-link deletion loses its target or mandatory deletion can be cancelled.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check finalization ownership after fallible fixture setup"
    )]
    fn mandatory_deletion_retains_its_target_through_defer_and_pre_effect_abort() -> DriverResult<()>
    {
        let mut links = OpenedLocations::new();
        let a = links.acquire(location(b"a")?)?;
        let pending = PendingFileDeletion::try_from_delete_on_close(&a.location())?;
        let target = pending.target();
        links.set_pending(pending);
        a.clear_pending();
        let replacement = PendingFileDeletion::try_from_disposition(&a.location())?;
        links.set_pending(replacement);
        a.cleanup();
        assert_eq!(
            links.claim_deletion(),
            FileCleanupDisposition::Delete(target)
        );
        assert_eq!(links.claim_deletion(), FileCleanupDisposition::Retained);
        links.finish_deletion(target, LinkDeletionOutcome::Deferred);
        drop(a);
        assert_eq!(links.pending_links(), 1);
        assert_eq!(
            links.claim_deletion(),
            FileCleanupDisposition::Delete(target)
        );
        links.finish_deletion(target, LinkDeletionOutcome::Aborted);
        assert!(links.acquire(location(b"a")?).is_ok());
        Ok(())
    }

    /// # Errors
    /// Propagates link or preallocated deletion-target failures.
    /// # Panics
    /// Fails if a shared control handle consumes the paging owner's deletion or prevents a later
    /// control reopen before owner cleanup, or if cleanup can unlink a still-active control link.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions observe paging-owner cleanup through ordinary live-link admission and final-link deletion"
    )]
    fn paging_owner_deletion_waits_for_its_cleanup_and_remaining_control_handles()
    -> DriverResult<()> {
        let mut links = OpenedLocations::new();
        let owner = links.acquire(location(b"paging")?)?;
        let deletion = PendingFileDeletion::try_from_delete_on_close(&owner.location())?;
        let target = deletion.target();
        owner.arm_paging_cleanup(deletion);
        let control = links.acquire(location(b"paging")?)?;
        assert_eq!(links.ensure_openable(Some(&location(b"paging")?)), Ok(()));
        assert!(!owner.delete_pending());
        control.cleanup();
        assert_eq!(links.claim_deletion(), FileCleanupDisposition::Retained);
        let remaining = links.acquire(location(b"paging")?)?;
        owner.cleanup();
        assert_eq!(
            links.ensure_openable(Some(&location(b"paging")?)),
            Err(DriverError::DeletePending)
        );
        assert_eq!(links.claim_deletion(), FileCleanupDisposition::Retained);
        remaining.cleanup();
        assert_eq!(
            links.claim_deletion(),
            FileCleanupDisposition::Delete(target)
        );
        links.finish_deletion(target, LinkDeletionOutcome::Removed);
        Ok(())
    }

    /// # Errors
    /// Returns fixture allocation or finite reference exhaustion.
    /// # Panics
    /// Fails if closing named handles loses deferred links before the file-id handle cleans up.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible setup propagates; assertions check retained cleanup obligations"
    )]
    fn deferred_links_survive_named_handle_close_until_the_inode_cleanup_collects_them()
    -> DriverResult<()> {
        let mut links = OpenedLocations::new();
        let inode = links.acquire(OpenedLocation::FileReference)?;
        let handles = [
            links.acquire(location(b"a")?)?,
            links.acquire(location(b"b")?)?,
        ];
        for handle in &handles {
            let pending = PendingFileDeletion::try_from_disposition(&handle.location())?;
            links.set_pending(pending);
            handle.cleanup();
        }
        let FileCleanupDisposition::Delete(first) = links.claim_deletion() else {
            return Err(DriverError::InternalInvariantViolation);
        };
        let FileCleanupDisposition::Delete(second) = links.claim_deletion() else {
            return Err(DriverError::InternalInvariantViolation);
        };
        links.finish_deletion(first, LinkDeletionOutcome::Deferred);
        links.finish_deletion(second, LinkDeletionOutcome::Deferred);
        drop(handles);
        assert_eq!(links.pending_links(), 2);
        inode.cleanup();
        let FileCleanupDisposition::Delete(first) = links.claim_deletion() else {
            return Err(DriverError::InternalInvariantViolation);
        };
        let FileCleanupDisposition::Delete(second) = links.claim_deletion() else {
            return Err(DriverError::InternalInvariantViolation);
        };
        assert_ne!(first, second);
        assert_eq!(links.claim_deletion(), FileCleanupDisposition::Retained);
        links.finish_deletion(first, LinkDeletionOutcome::Removed);
        links.finish_deletion(second, LinkDeletionOutcome::Removed);
        assert_eq!(links.pending_links(), 0);
        Ok(())
    }

    /// # Errors
    /// Returns fixture allocation or finite reference exhaustion.
    /// # Panics
    /// Fails if coalesced handles split location, deletion or active-handle authority.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible setup propagates; assertions check coalesced link behavior"
    )]
    fn coalesced_handles_follow_chained_renames_and_share_one_deletion() -> DriverResult<()> {
        let mut links = OpenedLocations::new();
        let a = links.acquire(location(b"a")?)?;
        let same_a = links.acquire(location(b"a")?)?;
        let b = links.acquire(location(b"b")?)?;
        let c = links.acquire(location(b"c")?)?;
        let b_location = b.location().try_to_owned_location()?;
        let aborted = a.prepare_merge(&b_location, location(b"b")?)?;
        drop(aborted);
        assert_eq!(*a.location(), location(b"a")?);
        a.prepare_merge(&b_location, location(b"b")?)?.publish();
        b.prepare_rename(location(b"renamed")?)?.publish();
        assert_eq!(*same_a.location(), location(b"renamed")?);
        let c_location = c.location().try_to_owned_location()?;
        b.prepare_merge(&c_location, location(b"c")?)?.publish();
        assert_eq!(*a.location(), location(b"c")?);
        let reopened = links.acquire(location(b"c")?)?;
        let reused_a = links.acquire(location(b"a")?)?;
        let pending = PendingFileDeletion::try_from_disposition(&a.location())?;
        let target = pending.target();
        links.set_pending(pending);
        assert!(c.delete_pending());
        assert!(reopened.delete_pending());
        assert!(!reused_a.delete_pending());
        for handle in [&a, &same_a, &b, &c] {
            handle.cleanup();
            assert_eq!(links.claim_deletion(), FileCleanupDisposition::Retained);
        }
        reopened.cleanup();
        assert_eq!(
            links.claim_deletion(),
            FileCleanupDisposition::Delete(target)
        );
        links.finish_deletion(target, LinkDeletionOutcome::Removed);
        drop((a, same_a, b, c, reopened, reused_a));
        // Retired aliases release their destination references; slots remain reusable.
        for _ in 0..128 {
            drop(links.acquire(location(b"fresh")?)?);
        }
        assert!(
            borrow(links.table.as_ref().unwrap_or_else(corruption).get())
                .slots
                .len()
                <= 4
        );
        Ok(())
    }
}
