//! Bounded deterministic storage harnesses for ext4 mount and journal recovery fuzzing.

#![feature(allocator_api)]

use ext4_core::{
    CompletedStorageTransfer, DeviceLength, Error, ExternalJournalProbeOperation,
    ExternalJournalProbeOutcome, ExternalJournalProbeTransition, FscryptKeySet, MountOperation,
    MountTransition, OperationEvent, StorageCompletion, StorageRequest, StorageTarget,
};
use std::boxed::Box;

/// Largest complete input retained by either fuzz target.
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;

/// Largest individual lower-storage transfer accepted by the harness.
const MAX_REQUEST_BYTES: usize = 128 * 1024;

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

/// Runs the mount/recovery protocol twice and asserts an identical terminal classification.
pub fn assert_deterministic_mount(filesystem: &[u8], external_journal: Option<&[u8]>) {
    if filesystem.len() > MAX_INPUT_BYTES
        || external_journal.is_some_and(|journal| journal.len() > MAX_INPUT_BYTES)
    {
        return;
    }
    let first = run_mount(filesystem, external_journal);
    let second = run_mount(filesystem, external_journal);
    assert_eq!(first, second, "mount/recovery result must be deterministic");
    assert_ne!(
        first,
        MountOutcome::StepBudgetExhausted,
        "mount/recovery must terminate within the explicit transition budget"
    );
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
fn run_mount(filesystem: &[u8], external_journal: Option<&[u8]>) -> MountOutcome {
    let Ok(operation) = Box::try_new(MountOperation::new(
        DeviceLength::from_bytes(u64::try_from(filesystem.len()).unwrap_or(u64::MAX)),
        FscryptKeySet::empty(),
    )) else {
        return MountOutcome::Rejected;
    };
    let mut devices = Devices {
        filesystem: filesystem.to_vec(),
        external_journal: external_journal.map(<[u8]>::to_vec),
    };
    let mut transition = operation.advance(OperationEvent::Admitted);
    for _step in 0..MAX_STEPS {
        match transition {
            MountTransition::SubmitLower { request, suspended } => {
                transition =
                    suspended.advance(OperationEvent::StorageCompleted(devices.complete(request)));
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
                transition = suspended.attach_external_journal(validated);
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
