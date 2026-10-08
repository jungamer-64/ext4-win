//! UUID-scoped immutable identity publication; metadata requests pin one snapshot at admission.
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::{DriverShared, DriverSharedLease, DriverVec};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use ext4_core::FilesystemUuid;
use ext4_security::{IdentityMap, MappingReply, MappingSnapshot, PublicationOutcome, Replacement};
mod registry;
use registry::{READ_CAPACITY, RegistryStore, key_text};

/// Operation-owned table; acquired access remains independent of later slot publication.
pub(crate) type IdentitySnapshot = DriverSharedLease<MappingSnapshot>;
/// Mount-owned access to exactly one filesystem's identity slot.
pub(crate) type IdentityBinding = DriverSharedLease<IdentitySlot>;

/// Effective creator identity captured once even when the create ultimately opens an existing inode.
#[derive(Clone, Copy, Debug)]
pub(crate) enum CreationIdentity {
    /// Both token principals are explicitly mapped.
    Mapped(ext4_core::Ext4Owner),
    /// Existing-object opens remain possible, but inode creation is forbidden.
    Unmapped,
}
impl CreationIdentity {
    /// Requires explicit identity before a child inode can be constructed.
    /// # Errors
    /// Returns access denied for either unmapped token principal.
    pub(crate) const fn require(self) -> DriverResult<ext4_core::Ext4Owner> {
        match self {
            Self::Mapped(owner) => Ok(owner),
            Self::Unmapped => Err(DriverError::AccessDenied),
        }
    }
}

/// Identity inputs pinned together for one logical create, including restartable resolution.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreationContext<'a> {
    /// The same immutable table used by every descriptor and creator conversion.
    pub(crate) mapping: &'a ext4_security::IdentityMap,
    /// Effective token principals captured at operation admission.
    pub(crate) creator: CreationIdentity,
}

/// Mutable publication facts protected by the slot's short native lock.
#[derive(Debug)]
struct SlotState {
    /// One authoritative current table owner.
    active: DriverShared<MappingSnapshot>,
    /// Known durable generation, independent of applied generation.
    saved: u64,
    /// Persistence/publication phase retained after acknowledgement loss.
    outcome: PublicationOutcome,
    /// Last native failure, or zero.
    status: i32,
    /// One retained worker owns reconciliation or replacement admission.
    busy: bool,
}

/// Shared UUID slot whose critical sections never allocate or perform registry I/O.
#[derive(Debug)]
pub(crate) struct IdentitySlot {
    /// Lock protects ownership acquisition and replacement, preventing reference/free races.
    #[cfg(not(test))]
    lock: UnsafeCell<wdk_sys::KSPIN_LOCK>,
    /// Deterministic short-lock equivalent in the user-mode test process.
    #[cfg(test)]
    lock: core::sync::atomic::AtomicBool,
    /// Published immutable table and commit facts.
    state: UnsafeCell<SlotState>,
}
impl IdentitySlot {
    /// Allocates all snapshot storage before a mount or replacement can publish it.
    /// # Errors
    /// Returns a recoverable pool allocation failure.
    fn new(snapshot: MappingSnapshot) -> DriverResult<Self> {
        let saved = snapshot.generation;
        Ok(Self {
            #[cfg(not(test))]
            lock: UnsafeCell::new(0),
            #[cfg(test)]
            lock: core::sync::atomic::AtomicBool::new(false),
            state: UnsafeCell::new(SlotState {
                active: DriverShared::try_new(snapshot)?,
                saved,
                outcome: PublicationOutcome::Applied,
                status: 0,
                busy: false,
            }),
        })
    }
    /// Lends publication state only inside a bounded, allocation-free critical section.
    #[expect(
        unsafe_code,
        reason = "the native lock serializes every access to slot ownership and scalar commit facts"
    )]
    fn locked<R>(&self, operation: impl FnOnce(&mut SlotState) -> R) -> R {
        #[cfg(not(test))]
        let irql = unsafe {
            // SAFETY: An unlocked KSPIN_LOCK has value zero; slot storage outlives this call.
            crate::kernel::ffi::KeAcquireSpinLockRaiseToDpc(self.lock.get())
        };
        #[cfg(test)]
        while self
            .lock
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::Acquire,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            core::hint::spin_loop();
        }
        let result = operation(unsafe {
            // SAFETY: Every state access holds this same exclusive lock; no borrow escapes it.
            &mut *self.state.get()
        });
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Balances the immediately preceding acquisition on this thread.
            crate::kernel::ffi::KeReleaseSpinLock(self.lock.get(), irql);
        }
        #[cfg(test)]
        self.lock
            .store(false, core::sync::atomic::Ordering::Release);
        result
    }
    /// Pins the snapshot once for an open/traverse/query/set operation.
    /// # Errors
    /// Returns finite reference-budget exhaustion.
    pub(crate) fn capture(&self) -> DriverResult<IdentitySnapshot> {
        self.locked(|state| state.active.try_acquire())
    }
    /// Captures independent persistence and application facts together with immutable ownership.
    /// # Errors
    /// Returns finite reference-budget exhaustion.
    fn observe(&self) -> DriverResult<IdentityObservation> {
        self.locked(|state| {
            Ok(IdentityObservation {
                active: state.active.try_acquire()?,
                saved: state.saved,
                outcome: state.outcome,
                status: state.status,
            })
        })
    }
    /// Publishes a preallocated durable successor; old owners drop outside the critical section.
    fn publish(&self, next: DriverShared<MappingSnapshot>) {
        let old = self.locked(|state| {
            state.saved = next.get().generation;
            state.outcome = PublicationOutcome::Applied;
            state.status = 0;
            core::mem::replace(&mut state.active, next)
        });
        drop(old);
    }
    /// Retains a failed effect phase for reconciliation through the control endpoint.
    fn record_failure(&self, outcome: PublicationOutcome, status: i32) {
        self.locked(|state| {
            state.outcome = outcome;
            state.status = status;
        });
    }
}
#[expect(
    unsafe_code,
    reason = "all interior ownership transitions hold the native spin lock and borrowed snapshots are immutable"
)]
// SAFETY: The short lock protects SlotState; the only escaping state is a counted immutable lease.
unsafe impl Send for IdentitySlot {}
#[expect(
    unsafe_code,
    reason = "all interior ownership transitions hold the native spin lock and borrowed snapshots are immutable"
)]
// SAFETY: All shared state access is serialized and every snapshot remains retained independently.
unsafe impl Sync for IdentitySlot {}

/// Consistent query observation, owned independently of subsequent publication.
#[derive(Debug)]
pub(crate) struct IdentityObservation {
    /// Applied snapshot.
    pub(crate) active: IdentitySnapshot,
    /// Known saved generation.
    pub(crate) saved: u64,
    /// Last effect phase.
    pub(crate) outcome: PublicationOutcome,
    /// Native status retained for administrator reconciliation.
    pub(crate) status: i32,
}

/// One UUID's catalog owner; mounts obtain only a lease to this slot.
#[derive(Debug)]
struct CatalogEntry {
    /// Core UUID, independent of Windows volume-path identity.
    uuid: FilesystemUuid,
    /// Shared publication slot retained through mounted-device and worker drain.
    slot: DriverShared<IdentitySlot>,
}
/// UUID slot registration authority; mounts can acquire snapshots without registry or replacement authority.
#[derive(Debug)]
pub(crate) struct IdentityDirectory {
    /// Control-actor-owned unique membership.
    entries: DriverVec<CatalogEntry>,
}
/// Administrator control authority owns persistence independently of mount registration.
#[derive(Debug)]
pub(crate) struct IdentityCatalog {
    /// Registration can be borrowed without exposing the service's registry authority.
    directory: IdentityDirectory,
    /// Narrow service registry authority retained by catalog and submitted workers.
    registry: Option<DriverShared<RegistryStore>>,
}
impl IdentityCatalog {
    /// Constructs the unpublished empty catalog.
    pub(crate) const fn empty() -> Self {
        Self {
            directory: IdentityDirectory {
                entries: DriverVec::new(),
            },
            registry: None,
        }
    }
    /// Narrows a control actor borrow to UUID registration alone.
    pub(crate) const fn directory_mut(&mut self) -> &mut IdentityDirectory {
        &mut self.directory
    }
}
impl IdentityDirectory {
    /// Installs a validated startup record before any mount can observe it.
    /// # Errors
    /// Rejects duplicate UUIDs and physical allocation failure.
    fn restore(&mut self, snapshot: MappingSnapshot) -> DriverResult<()> {
        if self.entries.iter().any(|entry| entry.uuid == snapshot.uuid) {
            return Err(DriverError::InvalidParameter);
        }
        let uuid = snapshot.uuid;
        let slot = DriverShared::try_new(IdentitySlot::new(snapshot)?)?;
        self.entries
            .try_push_owned(CatalogEntry { uuid, slot })
            .map_err(|error| error.into_parts().0)
    }
    /// Acquires a UUID-specific mount/control capability, creating an unconfigured slot if absent.
    /// # Errors
    /// Returns allocation or reference-budget failure before publication.
    pub(crate) fn binding(&mut self, uuid: FilesystemUuid) -> DriverResult<IdentityBinding> {
        if let Some(entry) = self.entries.iter().find(|entry| entry.uuid == uuid) {
            return entry.slot.try_acquire();
        }
        self.restore(MappingSnapshot {
            uuid,
            generation: 0,
            map: IdentityMap::empty(),
        })?;
        self.entries
            .iter()
            .find(|entry| entry.uuid == uuid)
            .ok_or(DriverError::InternalInvariantViolation)?
            .slot
            .try_acquire()
    }
}

/// Captured control command; Consumed is the terminal state after moving its owned table.
#[derive(Debug)]
pub(crate) enum IdentityCommand {
    /// Observes state and reconciles an uncertain persistence effect.
    Query(FilesystemUuid),
    /// Replaces the entire validated table with a CAS successor.
    Replace(Replacement),
    /// The operation now owns this request's command.
    Consumed,
}
impl IdentityCommand {
    /// Returns the sole UUID the command authorizes.
    /// # Errors
    /// Rejects an already consumed command.
    pub(crate) fn uuid(&self) -> DriverResult<FilesystemUuid> {
        match self {
            Self::Query(uuid) => Ok(*uuid),
            Self::Replace(replacement) => Ok(replacement.next().uuid),
            Self::Consumed => Err(DriverError::InternalInvariantViolation),
        }
    }
}
impl IdentityCatalog {
    /// Restores validated durable tables before the first mount or administrative request.
    /// # Safety
    /// The counted loader service path is valid through this synchronous initialization.
    /// # Errors
    /// Returns registry, malformed persisted value, allocation or duplicate UUID failure.
    #[expect(
        unsafe_code,
        reason = "the service path is consumed only by the synchronous registry constructor"
    )]
    pub(crate) unsafe fn load(path: wdk_sys::PCUNICODE_STRING) -> DriverResult<Self> {
        let registry = unsafe {
            // SAFETY: The caller retains the loader-owned path throughout initialization.
            RegistryStore::open(path)
        }?;
        let mut catalog = Self::empty();
        let mut buffer = DriverVec::try_repeated_copy(0, READ_CAPACITY)?;
        let mut index = 0_u32;
        while let Some(uuid) = registry.enumerate(index)? {
            let key = key_text(uuid);
            if let Some(length) = registry.read(&key, &mut buffer)? {
                let snapshot = MappingSnapshot::decode(
                    buffer
                        .as_slice()
                        .get(..length)
                        .ok_or(DriverError::InvalidBufferSize)?,
                )?;
                if snapshot.uuid != uuid || snapshot.generation == 0 {
                    return Err(DriverError::InvalidParameter);
                }
                catalog.directory.restore(snapshot)?;
            }
            index = index.checked_add(1).ok_or(DriverError::InvalidBufferSize)?;
        }
        catalog.registry = Some(DriverShared::try_new(registry)?);
        Ok(catalog)
    }
    /// Prepares every allocation and reply before a persistence worker can accept an effect.
    /// # Errors
    /// Returns resource failure or a short output buffer before any write; conflicts are encoded replies.
    pub(crate) fn prepare(
        &mut self,
        command: IdentityCommand,
        capacity: usize,
    ) -> DriverResult<PreparedIdentityAction> {
        let uuid = command.uuid()?;
        let binding = self.directory.binding(uuid)?;
        let reservation = match UpdateReservation::acquire(binding) {
            Ok(reservation) => reservation,
            Err(DriverError::DeviceBusy) if matches!(command, IdentityCommand::Query(_)) => {
                let observation = self.directory.binding(uuid)?.get().observe()?;
                let reply = MappingReply::prepare(observation.active.get())?;
                if capacity < reply.required_length() {
                    return Err(DriverError::BufferTooSmall);
                }
                return Ok(PreparedIdentityAction::Reply(reply.complete(
                    observation.outcome,
                    observation.status,
                    observation.saved,
                )));
            }
            Err(error) => return Err(error),
        };
        let observation = reservation.binding.get().observe()?;
        let old_reply = MappingReply::prepare(observation.active.get())?;
        if capacity < old_reply.required_length() {
            return Err(DriverError::BufferTooSmall);
        }
        match command {
            IdentityCommand::Query(_) if observation.outcome != PublicationOutcome::Unknown => {
                Ok(PreparedIdentityAction::Reply(old_reply.complete(
                    observation.outcome,
                    observation.status,
                    observation.saved,
                )))
            }
            IdentityCommand::Replace(replacement)
                if replacement.expected_generation() != observation.active.get().generation
                    || observation.outcome == PublicationOutcome::Unknown =>
            {
                Ok(PreparedIdentityAction::Reply(old_reply.complete(
                    PublicationOutcome::Conflict,
                    DriverError::DeviceBusy.ntstatus(),
                    observation.saved,
                )))
            }
            IdentityCommand::Replace(replacement) => {
                let record = replacement.encode()?;
                if capacity
                    < record
                        .len()
                        .checked_add(ext4_security::CONTROL_REPLY_BYTES)
                        .ok_or(DriverError::InvalidBufferSize)?
                {
                    return Err(DriverError::BufferTooSmall);
                }
                let next_reply = MappingReply::prepare(replacement.next())?;
                let next = DriverShared::try_new(replacement.into_next())?;
                let registry = self
                    .registry
                    .as_ref()
                    .ok_or(DriverError::NotSupported)?
                    .try_acquire()?;
                Ok(PreparedIdentityAction::Work(crate::memory::boxed_try_with(
                    || {
                        Ok(IdentityWork {
                            registry,
                            reservation,
                            key: key_text(next.get().uuid),
                            kind: IdentityWorkKind::Replace {
                                next,
                                record,
                                old_reply,
                                next_reply,
                                saved: observation.saved,
                            },
                        })
                    },
                )?))
            }
            IdentityCommand::Query(uuid) => {
                // Reconciliation may discover the larger unacknowledged successor.
                if capacity < ext4_security::MAX_MAPPING_BYTES + ext4_security::CONTROL_REPLY_BYTES
                {
                    return Err(DriverError::BufferTooSmall);
                }
                let buffer = DriverVec::try_repeated_copy(0, READ_CAPACITY)?;
                let registry = self
                    .registry
                    .as_ref()
                    .ok_or(DriverError::NotSupported)?
                    .try_acquire()?;
                Ok(PreparedIdentityAction::Work(crate::memory::boxed_try_with(
                    || {
                        Ok(IdentityWork {
                            registry,
                            reservation,
                            key: key_text(uuid),
                            kind: IdentityWorkKind::Reconcile {
                                buffer,
                                old_reply,
                                saved: observation.saved,
                                generation: observation.active.get().generation,
                                uuid,
                            },
                        })
                    },
                )?))
            }
            IdentityCommand::Consumed => Err(DriverError::InternalInvariantViolation),
        }
    }
}
/// Exactly one pre-effect reply or retained worker is produced at control admission.
#[derive(Debug)]
pub(crate) enum PreparedIdentityAction {
    /// No registry operation is required.
    Reply(Vec<u8>),
    /// A fully prepared owned operation enters the existing passive worker protocol.
    Work(alloc::boxed::Box<IdentityWork>),
}
/// Unique UUID mutation admission, released when prepared work fails or its effect completes.
#[derive(Debug)]
struct UpdateReservation {
    /// Keeps the same slot alive through completion and acknowledgement loss.
    binding: IdentityBinding,
}
impl UpdateReservation {
    /// Acquires one worker's authority without holding a spin lock across I/O.
    /// # Errors
    /// Rejects concurrent replacement or reconciliation on this UUID.
    fn acquire(binding: IdentityBinding) -> DriverResult<Self> {
        binding.get().locked(|state| {
            if state.busy {
                return Err(DriverError::DeviceBusy);
            }
            state.busy = true;
            Ok(())
        })?;
        Ok(Self { binding })
    }
}
impl Drop for UpdateReservation {
    fn drop(&mut self) {
        self.binding.get().locked(|state| state.busy = false);
    }
}
/// Different effects retain precisely the prepared values needed for their completion.
#[derive(Debug)]
enum IdentityWorkKind {
    /// Save and flush one complete validated successor.
    Replace {
        /// Infallible publication owner prepared before persistence.
        next: DriverShared<MappingSnapshot>,
        /// One complete registry value.
        record: Vec<u8>,
        /// Active-table reply for pre-effect or uncertain failure.
        old_reply: MappingReply,
        /// Successor reply prepared before persistence.
        next_reply: MappingReply,
        /// Previously known durable generation.
        saved: u64,
    },
    /// Read and flush authoritative storage after an uncertain write.
    Reconcile {
        /// Entire native query buffer allocated before worker submission.
        buffer: DriverVec<u8>,
        /// Active-table reply if uncertainty remains.
        old_reply: MappingReply,
        /// Prior durable generation.
        saved: u64,
        /// Prior applied generation bounds the possible successor.
        generation: u64,
        /// Ext4 UUID must match the stored whole-table record.
        uuid: FilesystemUuid,
    },
}
/// Worker-owned registry and UUID admission. Cancellation cannot release either before completion.
#[derive(Debug)]
pub(crate) struct IdentityWork {
    /// Root authority outlives the native call even during control-device drain.
    registry: DriverSharedLease<RegistryStore>,
    /// Unique update/reconciliation authority.
    reservation: UpdateReservation,
    /// Fixed native subkey name prepared before persistence.
    key: [u16; 36],
    /// Fully captured effect and acknowledgement storage.
    kind: IdentityWorkKind,
}
impl IdentityWork {
    /// Executes at PASSIVE_LEVEL; after successful flush publication and reply completion cannot fail.
    pub(crate) fn execute(self) -> Vec<u8> {
        let slot = self.reservation.binding.get();
        match self.kind {
            IdentityWorkKind::Replace {
                next,
                record,
                old_reply,
                next_reply,
                saved,
            } => {
                slot.record_failure(PublicationOutcome::Unknown, wdk_sys::STATUS_PENDING);
                let (phase, status) = self.registry.get().save(&self.key, &record);
                if phase == PublicationOutcome::SavedNotApplied && status >= 0 {
                    let generation = next.get().generation;
                    slot.locked(|state| {
                        state.saved = generation;
                        state.outcome = PublicationOutcome::SavedNotApplied;
                        state.status = 0;
                    });
                    slot.publish(next);
                    next_reply.complete(PublicationOutcome::Applied, 0, generation)
                } else {
                    slot.record_failure(phase, status);
                    old_reply.complete(phase, status, saved)
                }
            }
            IdentityWorkKind::Reconcile {
                mut buffer,
                old_reply,
                saved,
                generation,
                uuid,
            } => {
                let result = (|| {
                    let Some(length) = self.registry.get().read(&self.key, &mut buffer)? else {
                        return if saved == 0 {
                            Ok(None)
                        } else {
                            Err(DriverError::InvalidParameter)
                        };
                    };
                    let snapshot = MappingSnapshot::decode(
                        buffer
                            .as_slice()
                            .get(..length)
                            .ok_or(DriverError::InvalidBufferSize)?,
                    )?;
                    if snapshot.uuid != uuid
                        || snapshot.generation < generation
                        || snapshot.generation > generation.saturating_add(1)
                    {
                        return Err(DriverError::InvalidParameter);
                    }
                    let reply = MappingReply::prepare(&snapshot)?;
                    let next = DriverShared::try_new(snapshot)?;
                    self.registry.get().flush(&self.key)?;
                    Ok(Some((next, reply)))
                })();
                match result {
                    Ok(Some((next, reply))) => {
                        let generation = next.get().generation;
                        slot.publish(next);
                        reply.complete(PublicationOutcome::Applied, 0, generation)
                    }
                    Ok(None) => {
                        slot.record_failure(PublicationOutcome::NotSaved, 0);
                        old_reply.complete(PublicationOutcome::NotSaved, 0, saved)
                    }
                    Err(error) => {
                        let status = error.ntstatus();
                        slot.record_failure(PublicationOutcome::Unknown, status);
                        old_reply.complete(PublicationOutcome::Unknown, status, saved)
                    }
                }
            }
        }
    }
    /// Worker queue failure occurs before an effect; uncertainty from a prior attempt is preserved.
    pub(crate) fn failed(self, error: DriverError) -> Vec<u8> {
        let (reply, saved, outcome) = match self.kind {
            IdentityWorkKind::Replace {
                old_reply, saved, ..
            } => (old_reply, saved, PublicationOutcome::NotSaved),
            IdentityWorkKind::Reconcile {
                old_reply, saved, ..
            } => (old_reply, saved, PublicationOutcome::Unknown),
        };
        self.reservation
            .binding
            .get()
            .record_failure(outcome, error.ntstatus());
        reply.complete(outcome, error.ntstatus(), saved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Errors
    /// Returns pool or shared-record allocation failure.
    /// # Panics
    /// Panics if replacement changes a pinned snapshot or loses failure facts.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check publication behavior while fixture setup propagates allocation failures"
    )]
    #[test]
    fn publication_pins_old_generations_and_preserves_commit_facts() -> DriverResult<()> {
        let uuid = FilesystemUuid::from_bytes([7; 16]);
        let mut catalog = IdentityCatalog::empty();
        let binding = catalog.directory.binding(uuid)?;
        let old = binding.get().capture()?;
        let reservation = UpdateReservation::acquire(binding)?;
        assert!(matches!(
            UpdateReservation::acquire(catalog.directory.binding(uuid)?),
            Err(DriverError::DeviceBusy)
        ));
        let next = DriverShared::try_new(MappingSnapshot {
            uuid,
            generation: 1,
            map: IdentityMap::empty(),
        })?;
        reservation.binding.get().publish(next);
        assert_eq!(old.get().generation, 0);
        assert_eq!(
            catalog
                .directory
                .binding(uuid)?
                .get()
                .capture()?
                .get()
                .generation,
            1
        );
        drop(reservation);
        let binding = catalog.directory.binding(uuid)?;
        binding.get().record_failure(
            PublicationOutcome::Unknown,
            DriverError::RegistryFailure(-123).ntstatus(),
        );
        let observed = binding.get().observe()?;
        assert_eq!(observed.saved, 1);
        assert_eq!(observed.active.get().generation, 1);
        assert_eq!(observed.outcome, PublicationOutcome::Unknown);
        assert_eq!(observed.status, -123);
        let command = IdentityCommand::Replace(Replacement::new(
            1,
            MappingSnapshot {
                uuid,
                generation: 2,
                map: IdentityMap::empty(),
            },
        )?);
        let PreparedIdentityAction::Reply(bytes) = catalog.prepare(command, 65568)? else {
            return Err(DriverError::InternalInvariantViolation);
        };
        assert_eq!(
            ext4_security::MappingState::decode(&bytes)?.outcome,
            PublicationOutcome::Conflict
        );
        Ok(())
    }
    /// # Errors
    /// Returns owned fixture allocation or control-codec failure.
    /// # Panics
    /// Panics if short-buffer, queue failure or cancellation publishes a successor.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions verify effect admission while resource setup propagates allocation failures"
    )]
    #[test]
    fn pre_effect_failure_and_cancellation_keep_the_active_table() -> DriverResult<()> {
        let mut catalog = IdentityCatalog::empty();
        catalog.registry = Some(DriverShared::try_new(RegistryStore {})?);
        let uuid = FilesystemUuid::from_bytes([9; 16]);
        assert!(matches!(
            catalog.prepare(IdentityCommand::Query(uuid), 1),
            Err(DriverError::BufferTooSmall)
        ));
        let replace = || {
            Replacement::new(
                0,
                MappingSnapshot {
                    uuid,
                    generation: 1,
                    map: IdentityMap::empty(),
                },
            )
        };
        let PreparedIdentityAction::Work(work) =
            catalog.prepare(IdentityCommand::Replace(replace()?), 65568)?
        else {
            return Err(DriverError::InternalInvariantViolation);
        };
        let reply =
            ext4_security::MappingState::decode(&work.failed(DriverError::InsufficientResources))?;
        assert_eq!(reply.outcome, PublicationOutcome::NotSaved);
        assert_eq!(reply.active.generation, 0);
        assert_eq!(reply.saved_generation, 0);
        let PreparedIdentityAction::Work(work) =
            catalog.prepare(IdentityCommand::Replace(replace()?), 65568)?
        else {
            return Err(DriverError::InternalInvariantViolation);
        };
        drop(work);
        let binding = catalog.directory.binding(uuid)?;
        let reservation = UpdateReservation::acquire(binding)?;
        assert_eq!(reservation.binding.get().capture()?.get().generation, 0);
        reservation.binding.get().locked(|state| {
            state.saved = 1;
            state.outcome = PublicationOutcome::SavedNotApplied;
        });
        let PreparedIdentityAction::Reply(bytes) =
            catalog.prepare(IdentityCommand::Query(uuid), 65568)?
        else {
            return Err(DriverError::InternalInvariantViolation);
        };
        let observed = ext4_security::MappingState::decode(&bytes)?;
        assert_eq!(observed.outcome, PublicationOutcome::SavedNotApplied);
        assert_eq!(observed.saved_generation, 1);
        assert_eq!(observed.active.generation, 0);
        Ok(())
    }
}
