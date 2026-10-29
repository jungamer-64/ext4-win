//! Durable UUID-scoped future-mount policy; existing sessions retain their selected value.

use crate::kernel::configuration_registry::{
    ConfigurationDomain, QUERY_HEADER_BYTES, RegistryStore, SaveOutcome, key_text,
};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::{DriverVec, ShortLock};
use ext4_control::{
    POLICY_RECORD_BYTES, POLICY_REPLY_BYTES, PolicyOutcome, PolicyReplacement, PolicySnapshot,
    PolicyState,
};
use ext4_core::FilesystemUuid;
use ext4_shared::Shared;

/// Consistent persistence facts and exclusive worker admission for one UUID.
#[derive(Debug)]
struct SlotState {
    /// Only known durable policy can be selected for a mount.
    observation: PolicyState,
    /// A retained passive worker owns replacement or reconciliation.
    busy: bool,
}
/// Shared publication scope, independent of any mounted volume's lifetime.
#[derive(Debug)]
struct PolicySlot(ShortLock<SlotState>);
/// One UUID's retained slot owner.
#[derive(Debug)]
struct Entry {
    /// Membership identity.
    uuid: FilesystemUuid,
    /// Retained through all passive work.
    slot: Shared<PolicySlot>,
}
/// Mount selection can read known durable policies but cannot persist replacements.
#[derive(Debug)]
pub(crate) struct PolicyDirectory {
    /// Control-actor-owned unique UUID membership.
    entries: DriverVec<Entry>,
}
impl PolicyDirectory {
    /// Captures exactly one known policy for a new session before recovery starts.
    /// # Errors
    /// Rejects uncertain persistent state until administrator query reconciliation.
    pub(crate) fn select(&self, uuid: FilesystemUuid) -> DriverResult<PolicySnapshot> {
        let Some(entry) = self.entries.iter().find(|entry| entry.uuid == uuid) else {
            return Ok(PolicySnapshot::defaults(uuid));
        };
        let observation = entry.slot.get().0.with(|state| state.observation);
        if observation.outcome == PolicyOutcome::Unknown {
            return Err(DriverError::DeviceBusy);
        }
        Ok(observation.selected)
    }
    /// Registers validated startup data or unsaved defaults before any worker can observe it.
    /// # Errors
    /// Rejects duplicate membership and allocation failure.
    fn restore(&mut self, snapshot: PolicySnapshot) -> DriverResult<()> {
        if self.entries.iter().any(|entry| entry.uuid == snapshot.uuid) {
            return Err(DriverError::InvalidParameter);
        }
        let slot = Shared::try_new(PolicySlot(ShortLock::new(SlotState {
            observation: PolicyState {
                outcome: if snapshot.generation == 0 {
                    PolicyOutcome::NotSaved
                } else {
                    PolicyOutcome::Saved
                },
                status: 0,
                selected: snapshot,
            },
            busy: false,
        })))?;
        self.entries
            .try_push_owned(Entry {
                uuid: snapshot.uuid,
                slot,
            })
            .map_err(|error| error.into_parts().0)
    }
    /// Acquires a narrow UUID capability, creating defaults if this UUID has not been configured.
    /// # Errors
    /// Returns pool or reference-budget failure.
    fn binding(&mut self, uuid: FilesystemUuid) -> DriverResult<Shared<PolicySlot>> {
        if !self.entries.iter().any(|entry| entry.uuid == uuid) {
            self.restore(PolicySnapshot::defaults(uuid))?;
        }
        self.entries
            .iter()
            .find(|entry| entry.uuid == uuid)
            .ok_or(DriverError::InternalInvariantViolation)?
            .slot
            .try_acquire()
            .map_err(Into::into)
    }
}
/// Control-device persistence authority; mounts only borrow its selection directory.
#[derive(Debug)]
pub(crate) struct PolicyCatalog {
    /// Selection and unique membership authority.
    directory: PolicyDirectory,
    /// Retained kernel-only registry root.
    registry: Option<Shared<RegistryStore>>,
}
/// Captured policy command owning its validated input.
#[derive(Debug)]
pub(crate) enum PolicyCommand {
    /// Observe or reconcile a whole record.
    Query(FilesystemUuid),
    /// Save a complete immediate successor.
    Replace(PolicyReplacement),
}
impl PolicyCommand {
    /// Sole UUID authorized by this command.
    pub(crate) fn uuid(&self) -> FilesystemUuid {
        match self {
            Self::Query(uuid) => *uuid,
            Self::Replace(next) => next.next().uuid,
        }
    }
}
/// An output-only observation or a fully prepared persistent operation.
#[derive(Debug)]
pub(crate) enum PreparedPolicyAction {
    /// No persistent call required.
    Reply([u8; POLICY_REPLY_BYTES]),
    /// Retained until passive completion even when the administrator cancels.
    Work(alloc::boxed::Box<PolicyWork>),
}
impl PolicyCatalog {
    /// Empty unpublished catalog with no registry authority.
    pub(crate) const fn empty() -> Self {
        Self {
            directory: PolicyDirectory {
                entries: DriverVec::new(),
            },
            registry: None,
        }
    }
    /// Narrows mount access to selection only.
    pub(crate) const fn directory(&self) -> &PolicyDirectory {
        &self.directory
    }
    /// Restores all validated records before control-device publication.
    /// # Safety
    /// The loader retains the counted service path through initialization.
    /// # Errors
    /// Preserves registry failures; malformed or mismatched records reject initialization.
    #[expect(
        unsafe_code,
        reason = "the loader-owned path is borrowed only during synchronous root construction"
    )]
    pub(crate) unsafe fn load(path: wdk_sys::PCUNICODE_STRING) -> DriverResult<Self> {
        let registry = unsafe {
            // SAFETY: Caller retains the loader service path during this synchronous call.
            RegistryStore::open(path, ConfigurationDomain::MountPolicy)
        }?;
        let mut catalog = Self::empty();
        let mut buffer = DriverVec::try_repeated_copy(0, POLICY_RECORD_BYTES + QUERY_HEADER_BYTES)?;
        let mut index = 0_u32;
        while let Some(uuid) = registry.enumerate(index)? {
            if let Some(length) = registry.read(&key_text(uuid), &mut buffer)? {
                let snapshot = PolicySnapshot::decode(
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
        catalog.registry = Some(Shared::try_new(registry)?);
        Ok(catalog)
    }
    /// Completes all allocation, output admission and CAS checks before a persistence effect.
    /// # Errors
    /// Returns short-buffer, resource, busy or malformed-command failures before effects.
    pub(crate) fn prepare(
        &mut self,
        command: PolicyCommand,
        capacity: usize,
    ) -> DriverResult<PreparedPolicyAction> {
        if capacity < POLICY_REPLY_BYTES {
            return Err(DriverError::BufferTooSmall);
        }
        let uuid = command.uuid();
        let binding = self.directory.binding(uuid)?;
        let admitted = binding.get().0.with(|state| {
            let old = state.observation;
            if state.busy {
                return Err((DriverError::DeviceBusy, old));
            }
            state.busy = true;
            Ok(old)
        });
        let old = match admitted {
            Ok(old) => old,
            Err((_, old)) if matches!(command, PolicyCommand::Query(_)) => {
                return Ok(PreparedPolicyAction::Reply(old.encode()));
            }
            Err((error, _)) => return Err(error),
        };
        let reservation = Reservation { binding };
        let kind = match command {
            PolicyCommand::Query(_) if old.outcome != PolicyOutcome::Unknown => {
                return Ok(PreparedPolicyAction::Reply(old.encode()));
            }
            PolicyCommand::Replace(next)
                if old.outcome == PolicyOutcome::Unknown
                    || next.expected_generation() != old.selected.generation =>
            {
                return Ok(PreparedPolicyAction::Reply(
                    PolicyState {
                        outcome: PolicyOutcome::Conflict,
                        status: DriverError::DeviceBusy.ntstatus(),
                        ..old
                    }
                    .encode(),
                ));
            }
            PolicyCommand::Replace(next) => WorkKind::Replace(next.next()),
            PolicyCommand::Query(_) => WorkKind::Reconcile(DriverVec::try_repeated_copy(
                0,
                POLICY_RECORD_BYTES + QUERY_HEADER_BYTES,
            )?),
        };
        let registry = self
            .registry
            .as_ref()
            .ok_or(DriverError::NotSupported)?
            .try_acquire()?;
        Ok(PreparedPolicyAction::Work(crate::memory::boxed_try_with(
            || {
                Ok(PolicyWork {
                    registry,
                    reservation,
                    old,
                    key: key_text(uuid),
                    kind,
                })
            },
        )?))
    }
}
/// Worker reservation drops only when queue admission fails or passive execution has finished.
#[derive(Debug)]
struct Reservation {
    /// Scope is exactly one UUID and one worker lifetime.
    binding: Shared<PolicySlot>,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.binding.get().0.with(|state| state.busy = false);
    }
}
/// Captured persistent operation with all required storage reserved.
#[derive(Debug)]
enum WorkKind {
    /// Save one complete positive-generation successor.
    Replace(PolicySnapshot),
    /// Read an uncertain record into preallocated native query storage.
    Reconcile(DriverVec<u8>),
}
/// Passive effect owner, independent of mount and requesting handle lifetimes.
#[derive(Debug)]
pub(crate) struct PolicyWork {
    /// Root retained through native completion.
    registry: Shared<RegistryStore>,
    /// Exclusive UUID update authority.
    reservation: Reservation,
    /// Known state before the effect; retained for failed or uncertain acknowledgement.
    old: PolicyState,
    /// Fixed registry key prepared before submission.
    key: [u16; 36],
    /// Preallocated operation input.
    kind: WorkKind,
}
impl PolicyWork {
    /// Performs one effect; publication and response encoding after durability cannot fail.
    pub(crate) fn execute(mut self) -> [u8; POLICY_REPLY_BYTES] {
        let observation = match &mut self.kind {
            WorkKind::Replace(next) => {
                self.reservation.binding.get().0.with(|state| {
                    state.observation = PolicyState {
                        outcome: PolicyOutcome::Unknown,
                        status: wdk_sys::STATUS_PENDING,
                        ..self.old
                    }
                });
                let (effect, status) = self.registry.get().save(&self.key, &next.encode());
                match effect {
                    SaveOutcome::Durable if status >= 0 => PolicyState {
                        outcome: PolicyOutcome::Saved,
                        status: 0,
                        selected: *next,
                    },
                    SaveOutcome::NotSaved => PolicyState {
                        outcome: PolicyOutcome::NotSaved,
                        status,
                        ..self.old
                    },
                    SaveOutcome::Unknown | SaveOutcome::Durable => PolicyState {
                        outcome: PolicyOutcome::Unknown,
                        status,
                        ..self.old
                    },
                }
            }
            WorkKind::Reconcile(buffer) => {
                let result = (|| {
                    let Some(length) = self.registry.get().read(&self.key, buffer)? else {
                        return if self.old.selected.generation == 0 {
                            Ok(self.old.selected)
                        } else {
                            Err(DriverError::InvalidParameter)
                        };
                    };
                    let snapshot = PolicySnapshot::decode(
                        buffer
                            .as_slice()
                            .get(..length)
                            .ok_or(DriverError::InvalidBufferSize)?,
                    )?;
                    if snapshot.uuid != self.old.selected.uuid
                        || snapshot.generation < self.old.selected.generation
                        || snapshot.generation == 0
                        || snapshot.generation > self.old.selected.generation.saturating_add(1)
                    {
                        return Err(DriverError::InvalidParameter);
                    }
                    self.registry.get().flush(&self.key)?;
                    Ok(snapshot)
                })();
                match result {
                    Ok(selected) => PolicyState {
                        outcome: if selected.generation == 0 {
                            PolicyOutcome::NotSaved
                        } else {
                            PolicyOutcome::Saved
                        },
                        status: 0,
                        selected,
                    },
                    Err(error) => PolicyState {
                        outcome: PolicyOutcome::Unknown,
                        status: error.ntstatus(),
                        ..self.old
                    },
                }
            }
        };
        self.reservation
            .binding
            .get()
            .0
            .with(|state| state.observation = observation);
        observation.encode()
    }
    /// Queue failure is pre-effect; previous uncertainty remains authoritative.
    pub(crate) fn failed(self, error: DriverError) -> [u8; POLICY_REPLY_BYTES] {
        let observation = PolicyState {
            status: error.ntstatus(),
            ..self.old
        };
        self.reservation
            .binding
            .get()
            .0
            .with(|state| state.observation = observation);
        observation.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ext4_core::{MountAccess, ReadOnlyRecovery};

    /// # Errors
    /// Propagates physical resource or policy codec failure.
    /// # Panics
    /// Panics if policy changes retroactively widen selected session authority.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture setup propagates errors; assertions check immutable selection and uncertainty"
    )]
    #[test]
    fn selection_is_fixed_and_uncertainty_blocks_new_sessions() -> DriverResult<()> {
        let uuid = FilesystemUuid::from_bytes([5; 16]);
        let mut catalog = PolicyCatalog::empty();
        catalog.registry = Some(Shared::try_new(RegistryStore {})?);
        let selected = catalog.directory.select(uuid)?;
        let binding = catalog.directory.binding(uuid)?;
        let readonly = PolicySnapshot {
            uuid,
            generation: 1,
            policy: MountAccess::ReadOnly {
                recovery: ReadOnlyRecovery::Replay,
            },
        };
        binding.get().0.with(|state| {
            state.observation = PolicyState {
                outcome: PolicyOutcome::Saved,
                status: 0,
                selected: readonly,
            }
        });
        assert_eq!(selected.policy, MountAccess::ReadWrite);
        assert_eq!(catalog.directory.select(uuid)?, readonly);
        binding
            .get()
            .0
            .with(|state| state.observation.outcome = PolicyOutcome::Unknown);
        assert!(matches!(
            catalog.directory.select(uuid),
            Err(DriverError::DeviceBusy)
        ));
        let replacement = PolicyReplacement::new(1, uuid, MountAccess::ReadWrite)?;
        let PreparedPolicyAction::Reply(bytes) =
            catalog.prepare(PolicyCommand::Replace(replacement), POLICY_REPLY_BYTES)?
        else {
            return Err(DriverError::InternalInvariantViolation);
        };
        assert_eq!(
            PolicyState::decode(&bytes)?.outcome,
            PolicyOutcome::Conflict
        );
        let PreparedPolicyAction::Work(work) =
            catalog.prepare(PolicyCommand::Query(uuid), POLICY_REPLY_BYTES)?
        else {
            return Err(DriverError::InternalInvariantViolation);
        };
        let bytes = work.failed(DriverError::InsufficientResources);
        assert_eq!(PolicyState::decode(&bytes)?.outcome, PolicyOutcome::Unknown);
        assert!(matches!(
            catalog.directory.select(uuid),
            Err(DriverError::DeviceBusy)
        ));
        Ok(())
    }
    /// # Errors
    /// Propagates physical resource and codec failures.
    /// # Panics
    /// Panics if pre-effect failure publishes a successor or retains exclusive admission.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check the pre-effect contract while allocation failures propagate"
    )]
    #[test]
    fn output_admission_and_worker_failure_preserve_durable_selection() -> DriverResult<()> {
        let uuid = FilesystemUuid::from_bytes([8; 16]);
        let mut catalog = PolicyCatalog::empty();
        catalog.registry = Some(Shared::try_new(RegistryStore {})?);
        let replacement = PolicyReplacement::new(
            0,
            uuid,
            MountAccess::ReadOnly {
                recovery: ReadOnlyRecovery::Replay,
            },
        )?;
        assert!(matches!(
            catalog.prepare(
                PolicyCommand::Replace(replacement),
                POLICY_REPLY_BYTES.saturating_sub(1)
            ),
            Err(DriverError::BufferTooSmall)
        ));
        let PreparedPolicyAction::Work(work) =
            catalog.prepare(PolicyCommand::Replace(replacement), POLICY_REPLY_BYTES)?
        else {
            return Err(DriverError::InternalInvariantViolation);
        };
        assert!(matches!(
            catalog.prepare(PolicyCommand::Replace(replacement), POLICY_REPLY_BYTES),
            Err(DriverError::DeviceBusy)
        ));
        let bytes = work.failed(DriverError::InsufficientResources);
        assert_eq!(PolicyState::decode(&bytes)?.selected.generation, 0);
        assert_eq!(
            catalog.directory.select(uuid)?.policy,
            MountAccess::ReadWrite
        );
        let PreparedPolicyAction::Work(work) =
            catalog.prepare(PolicyCommand::Replace(replacement), POLICY_REPLY_BYTES)?
        else {
            return Err(DriverError::InternalInvariantViolation);
        };
        let bytes = work.execute();
        assert_eq!(
            PolicyState::decode(&bytes)?.outcome,
            PolicyOutcome::NotSaved
        );
        assert_eq!(catalog.directory.select(uuid)?.generation, 0);
        Ok(())
    }
}
