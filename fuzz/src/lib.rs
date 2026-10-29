//! Bounded deterministic storage harnesses for ext4 mount and journal recovery fuzzing.

#![feature(allocator_ext)]

use ext4_core::{
    CompletedStorageTransfer, DeviceLength, Error, ExternalJournalProbeOperation,
    ExternalJournalProbeOutcome, ExternalJournalProbeTransition, FscryptKeySet, MountTransition,
    OperationEvent, StorageCompletion, StorageRequest, StorageTarget,
};
use std::boxed::Box;

#[path = "../limits.rs"]
mod limits;
pub use limits::MAX_INPUT_BYTES;

/// Largest individual lower-storage transfer accepted by the harness.
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// Maximum completion-driven transitions before the harness rejects one input.
const MAX_STEPS: usize = 4096;

/// Stable terminal classification used to detect nondeterministic execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountOutcome {
    /// Mount and recovery reached the production terminal success state.
    Mounted,
    /// The core or bounded storage boundary rejected the image.
    Rejected,
    /// The filesystem requested an external journal but none was supplied.
    ExternalJournalUnavailable,
    /// The explicit transition budget was exhausted.
    StepBudgetExhausted,
}

/// Runs both media-access modes twice and checks deterministic, bounded recovery.
pub fn assert_deterministic_mount(filesystem: &[u8], external_journal: Option<&[u8]>) {
    if filesystem.len() > MAX_INPUT_BYTES
        || external_journal.is_some_and(|journal| journal.len() > MAX_INPUT_BYTES)
    {
        return;
    }
    for access in [
        ext4_core::MountAccess::ReadWrite,
        ext4_core::MountAccess::ReadOnly {
            recovery: ext4_core::ReadOnlyRecovery::Memory {
                limit: ext4_core::RecoveryMemoryLimit::DEFAULT,
            },
        },
    ] {
        let first = run_mount(filesystem, external_journal, access);
        let second = run_mount(filesystem, external_journal, access);
        assert_eq!(first, second, "mount/recovery result must be deterministic");
        assert_ne!(
            first,
            MountOutcome::StepBudgetExhausted,
            "mount/recovery must terminate within the explicit transition budget"
        );
    }
}

/// Bounded external-journal validation result before mount continuation attachment.
enum ExternalValidation {
    /// The selected journal matched and is ready to attach.
    Match(Box<ext4_core::ValidatedExternalJournal>),
    /// The selected bytes were rejected by the production validator.
    Rejected,
    /// The validator failed to terminate within its explicit budget.
    StepBudgetExhausted,
}

/// Owns the mutable images seen by one completion-driven execution.
#[derive(Debug)]
struct Devices {
    /// Primary ext4 image.
    filesystem: Vec<u8>,
    /// Optional external JBD2 image.
    external_journal: Option<Vec<u8>>,
}

impl Devices {
    /// Returns the selected immutable image.
    fn target(&self, target: StorageTarget) -> Option<&[u8]> {
        match target {
            StorageTarget::Filesystem => Some(&self.filesystem),
            StorageTarget::ExternalJournal => self.external_journal.as_deref(),
        }
    }

    /// Returns the selected mutable image.
    fn target_mut(&mut self, target: StorageTarget) -> Option<&mut [u8]> {
        match target {
            StorageTarget::Filesystem => Some(&mut self.filesystem),
            StorageTarget::ExternalJournal => self.external_journal.as_deref_mut(),
        }
    }

    /// Completes one bounded lower request while retaining its exact owned transfer.
    fn complete(&mut self, request: StorageRequest) -> StorageCompletion {
        if request.byte_count() > MAX_REQUEST_BYTES {
            return StorageCompletion::failure(
                CompletedStorageTransfer::from_request(request),
                Error::DeviceRange,
            );
        }
        match request {
            StorageRequest::Read {
                target,
                offset,
                mut buffer,
            } => {
                let copied = usize::try_from(offset.get())
                    .ok()
                    .and_then(|start| start.checked_add(buffer.len()).map(|end| (start, end)))
                    .and_then(|(start, end)| self.target(target)?.get(start..end))
                    .is_some_and(|source| copy_exact(&mut buffer, source));
                let transfer = CompletedStorageTransfer::Read {
                    target,
                    offset,
                    buffer,
                };
                if copied {
                    let information = transfer.byte_count();
                    StorageCompletion::success(transfer, information)
                } else {
                    StorageCompletion::failure(transfer, Error::DeviceRange)
                }
            }
            StorageRequest::Write {
                target,
                offset,
                buffer,
            } => {
                let copied = usize::try_from(offset.get())
                    .ok()
                    .and_then(|start| start.checked_add(buffer.len()).map(|end| (start, end)))
                    .and_then(|(start, end)| self.target_mut(target)?.get_mut(start..end))
                    .is_some_and(|destination| copy_exact(destination, &buffer));
                let transfer = CompletedStorageTransfer::Write {
                    target,
                    offset,
                    buffer,
                };
                if copied {
                    let information = transfer.byte_count();
                    StorageCompletion::success(transfer, information)
                } else {
                    StorageCompletion::failure(transfer, Error::DeviceRange)
                }
            }
            StorageRequest::Flush { target } => {
                let transfer = CompletedStorageTransfer::Flush { target };
                if self.target(target).is_some() {
                    StorageCompletion::success(transfer, 0)
                } else {
                    StorageCompletion::failure(transfer, Error::DeviceRange)
                }
            }
        }
    }
}

/// Copies one fuzz-device range only when both checked slices have the same length.
fn copy_exact(destination: &mut [u8], source: &[u8]) -> bool {
    if destination.len() != source.len() {
        return false;
    }
    for (destination, source) in destination.iter_mut().zip(source) {
        *destination = *source;
    }
    true
}

/// Advances the concrete production mount operation within the explicit step budget.
fn run_mount(
    filesystem: &[u8],
    external_journal: Option<&[u8]>,
    access: ext4_core::MountAccess,
) -> MountOutcome {
    let mut devices = Devices {
        filesystem: filesystem.to_vec(),
        external_journal: external_journal.map(<[u8]>::to_vec),
    };
    let Ok(probe) = Box::try_new(ext4_core::MountProbeOperation::new(
        DeviceLength::from_bytes(u64::try_from(filesystem.len()).unwrap_or(u64::MAX)),
    )) else {
        return MountOutcome::Rejected;
    };
    let mut probe = probe.advance(OperationEvent::Admitted);
    let mut prepared = None;
    for _ in 0..MAX_STEPS {
        probe = match probe {
            ext4_core::MountProbeTransition::SubmitLower { request, suspended } => {
                let completion = devices.complete(request);
                suspended.advance(OperationEvent::StorageCompleted(completion))
            }
            ext4_core::MountProbeTransition::Complete(result) => {
                match result {
                    Ok(value) => prepared = Some(value),
                    Err(_) => return MountOutcome::Rejected,
                }
                break;
            }
        };
    }
    let Some(prepared) = prepared else {
        return MountOutcome::StepBudgetExhausted;
    };
    let mut millis = 0_u64;
    let now = ext4_core::MmpTime::new(millis, 0);
    let Ok(owner) = ext4_core::MmpOwner::new([0x35; 16]) else {
        return MountOutcome::Rejected;
    };
    let Ok(operation) = prepared.start(
        FscryptKeySet::empty(),
        access,
        ext4_core::DeviceWriteAccess::Writable,
        owner,
        now,
    ) else {
        return MountOutcome::Rejected;
    };
    let Ok(operation) = Box::try_new(operation) else {
        return MountOutcome::Rejected;
    };
    let mut transition = operation.advance(OperationEvent::Admitted, now);
    for _step in 0..MAX_STEPS {
        match transition {
            MountTransition::SubmitLower { request, suspended }
            | MountTransition::SubmitOwnership { request, suspended } => {
                if access.media_access() == ext4_core::MediaAccess::ReadOnly {
                    assert!(
                        matches!(&request, StorageRequest::Read { .. }),
                        "read-only mounting must not submit media effects"
                    );
                }
                transition = suspended.advance(
                    OperationEvent::StorageCompleted(devices.complete(request)),
                    ext4_core::MmpTime::new(millis, 0),
                );
            }
            MountTransition::DiscoverExternalJournal {
                requirement,
                suspended,
            } => {
                let Some(journal) = devices.external_journal.as_ref() else {
                    return MountOutcome::ExternalJournalUnavailable;
                };
                let journal_length =
                    DeviceLength::from_bytes(u64::try_from(journal.len()).unwrap_or(u64::MAX));
                let validated =
                    match validate_external_journal(&mut devices, requirement, journal_length) {
                        ExternalValidation::Match(validated) => validated,
                        ExternalValidation::Rejected => return MountOutcome::Rejected,
                        ExternalValidation::StepBudgetExhausted => {
                            return MountOutcome::StepBudgetExhausted;
                        }
                    };
                transition = suspended.attach_external_journal(
                    validated,
                    ext4_core::DeviceWriteAccess::Writable,
                    ext4_core::MmpTime::new(millis, 0),
                );
            }
            MountTransition::WaitForTimer { seconds, suspended } => {
                millis = millis.saturating_add(u64::from(seconds).saturating_mul(1000));
                transition = suspended.advance(
                    OperationEvent::TimerElapsed,
                    ext4_core::MmpTime::new(millis, 0),
                );
            }
            MountTransition::Complete(result) => {
                return if result.is_ok() {
                    MountOutcome::Mounted
                } else {
                    MountOutcome::Rejected
                };
            }
        }
    }
    MountOutcome::StepBudgetExhausted
}

/// Runs the production external-journal validator within the same finite budget.
fn validate_external_journal(
    devices: &mut Devices,
    requirement: ext4_core::ExternalJournalRequirement,
    length: DeviceLength,
) -> ExternalValidation {
    let Ok(operation) = Box::try_new(ExternalJournalProbeOperation::new(requirement, length))
    else {
        return ExternalValidation::Rejected;
    };
    let mut transition = operation.advance(OperationEvent::Admitted);
    for _step in 0..MAX_STEPS {
        match transition {
            ExternalJournalProbeTransition::SubmitLower { request, suspended } => {
                transition =
                    suspended.advance(OperationEvent::StorageCompleted(devices.complete(request)));
            }
            ExternalJournalProbeTransition::Complete(Ok(ExternalJournalProbeOutcome::Match(
                validated,
            ))) => return ExternalValidation::Match(validated),
            ExternalJournalProbeTransition::Complete(
                Ok(ExternalJournalProbeOutcome::Mismatch) | Err(_),
            ) => return ExternalValidation::Rejected,
        }
    }
    ExternalValidation::StepBudgetExhausted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    #[test]
    fn independent_seed_reaches_external_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../tools/xtask/fixtures/journal");
        let filesystem = fs::read(fixtures.join("external-4k-v3-64.filesystem.img"))?;
        let journal = fs::read(fixtures.join("external-4k-v3-64.journal.img"))?;
        assert!(filesystem.len() + journal.len() + 4 <= MAX_INPUT_BYTES);
        for access in [
            ext4_core::MountAccess::ReadWrite,
            ext4_core::MountAccess::ReadOnly {
                recovery: ext4_core::ReadOnlyRecovery::Memory {
                    limit: ext4_core::RecoveryMemoryLimit::DEFAULT,
                },
            },
        ] {
            assert_eq!(
                run_mount(&filesystem, Some(&journal), access),
                MountOutcome::Mounted
            );
            assert_eq!(
                run_mount(&filesystem, None, access),
                MountOutcome::ExternalJournalUnavailable
            );
        }
        Ok(())
    }
}
