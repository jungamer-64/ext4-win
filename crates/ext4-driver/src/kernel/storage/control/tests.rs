//! Independent native DSM bytes and returned physical ownership through the typed event boundary.
use super::*;
use alloc::{boxed::Box, vec::Vec};
use ext4_core::{CompletedStorageTransfer, MutationCoordinatorState, PendingTrim};

/// # Errors
/// Returns buffer admission failure before any native request.
/// # Panics
/// Fails if protection is confused with an unsuccessful physical availability query.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check native completion semantics while allocation is fallible"
)]
fn write_availability_preserves_status_and_continuation() -> DriverResult<()> {
    for (status, expected) in [
        (
            wdk_sys::STATUS_SUCCESS,
            Ok(ext4_core::DeviceWriteAccess::Writable),
        ),
        (
            wdk_sys::STATUS_MEDIA_WRITE_PROTECTED,
            Ok(ext4_core::DeviceWriteAccess::ReadOnly),
        ),
        (
            wdk_sys::STATUS_IO_DEVICE_ERROR,
            Err(DriverError::from(Error::DeviceIo)),
        ),
    ] {
        let completed = CompletedLowerIrp {
            suspended: DeviceControlCommand::WriteAccess { suspended: 73 },
            transfer: AlignedTransferBuffer::try_zeroed(0, 8)?,
            status,
            information: 0,
        }
        .finish_control();
        let DeviceControlCompletion::WriteAccess { suspended, result } = completed else {
            return Err(DriverError::InternalInvariantViolation);
        };
        assert_eq!(suspended, 73);
        assert_eq!(result, expected);
    }
    Ok(())
}

/// Completes a portable core transfer against the independently generated journal fixture.
/// # Errors
/// Returns a malformed range, mismatched buffer or conversion failure.
fn transfer(
    mut request: StorageRequest,
    filesystem: &mut [u8],
    journal: &mut [u8],
) -> DriverResult<StorageCompletion> {
    let image = match request.target() {
        StorageTarget::Filesystem => filesystem,
        StorageTarget::ExternalJournal => journal,
    };
    match &mut request {
        StorageRequest::Read { offset, buffer, .. }
        | StorageRequest::Write { offset, buffer, .. } => {
            let start = usize::try_from(offset.get()).map_err(|_| DriverError::InvalidParameter)?;
            let end = start
                .checked_add(buffer.len())
                .ok_or(DriverError::InvalidParameter)?;
            let range = image
                .get_mut(start..end)
                .ok_or(DriverError::InvalidParameter)?;
            match &mut request {
                StorageRequest::Read { buffer, .. } => memory::copy_exact(buffer, range)?,
                StorageRequest::Write { buffer, .. } => memory::copy_exact(range, buffer)?,
                StorageRequest::Flush { .. } => {
                    return Err(DriverError::InternalInvariantViolation);
                }
            }
        }
        StorageRequest::Flush { .. } => {}
    }
    let count = request.byte_count();
    Ok(StorageCompletion::success(
        CompletedStorageTransfer::from_request(request),
        count,
    ))
}

/// Obtains an unforgeable discard request from the actual core mount, scan and reservation path.
/// # Errors
/// Propagates fixture input, mount, metadata authentication or admission failure.
fn admitted_request() -> DriverResult<(TrimRequest, PendingTrim, MutationCoordinatorState)> {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/xtask/fixtures/journal");
    let mut filesystem = std::fs::read(root.join("external-4k-v3-64.filesystem.img"))
        .map_err(|_| DriverError::InvalidParameter)?;
    let mut journal = std::fs::read(root.join("external-4k-v3-64.journal.img"))
        .map_err(|_| DriverError::InvalidParameter)?;
    let length = DeviceLength::from_bytes(
        u64::try_from(filesystem.len()).map_err(|_| DriverError::InvalidParameter)?,
    );
    let mut probe = Box::try_new(ext4_core::MountProbeOperation::new(length))
        .map_err(|_| DriverError::InsufficientResources)?
        .advance(ext4_core::OperationEvent::Admitted);
    let prepared = loop {
        probe = match probe {
            ext4_core::MountProbeTransition::SubmitLower { request, suspended } => suspended
                .advance(ext4_core::OperationEvent::StorageCompleted(transfer(
                    request,
                    &mut filesystem,
                    &mut journal,
                )?)),
            ext4_core::MountProbeTransition::Complete(result) => break result?,
        };
    };
    let now = ext4_core::MmpTime::new(0, 0);
    let mut step = Box::try_new(prepared.start(
        ext4_core::FscryptKeySet::empty(),
        ext4_core::MountAccess::ReadWrite,
        ext4_core::DeviceWriteAccess::Writable,
        ext4_core::MmpOwner::new([0x35; 16])?,
        now,
    )?)
    .map_err(|_| DriverError::InsufficientResources)?
    .advance(ext4_core::OperationEvent::Admitted, now);
    let mounted = loop {
        step = match step {
            ext4_core::MountTransition::SubmitLower { request, suspended }
            | ext4_core::MountTransition::SubmitOwnership { request, suspended } => suspended
                .advance(
                    ext4_core::OperationEvent::StorageCompleted(transfer(
                        request,
                        &mut filesystem,
                        &mut journal,
                    )?),
                    now,
                ),
            ext4_core::MountTransition::DiscoverExternalJournal {
                requirement,
                suspended,
            } => {
                let length = DeviceLength::from_bytes(
                    u64::try_from(journal.len()).map_err(|_| DriverError::InvalidParameter)?,
                );
                let mut probe = Box::try_new(ext4_core::ExternalJournalProbeOperation::new(
                    requirement,
                    length,
                ))
                .map_err(|_| DriverError::InsufficientResources)?
                .advance(ext4_core::OperationEvent::Admitted);
                let validated = loop {
                    probe = match probe {
                        ext4_core::ExternalJournalProbeTransition::SubmitLower {
                            request,
                            suspended,
                        } => suspended.advance(ext4_core::OperationEvent::StorageCompleted(
                            transfer(request, &mut filesystem, &mut journal)?,
                        )),
                        ext4_core::ExternalJournalProbeTransition::Complete(result) => {
                            match result? {
                                ext4_core::ExternalJournalProbeOutcome::Match(validated) => {
                                    break validated;
                                }
                                ext4_core::ExternalJournalProbeOutcome::Mismatch => {
                                    return Err(DriverError::InvalidParameter);
                                }
                            }
                        }
                    };
                };
                suspended.attach_external_journal(
                    validated,
                    ext4_core::DeviceWriteAccess::Writable,
                    now,
                )
            }
            ext4_core::MountTransition::Complete(result) => break result?,
            ext4_core::MountTransition::WaitForTimer { .. } => {
                return Err(DriverError::InvalidParameter);
            }
        };
    };
    let (profile, epoch, mut coordinator, _mmp) = mounted.into_parts();
    let mut cache = ext4_core::MetadataCache::default();
    let mut operation = ext4_core::TrimScanOperation::new(
        &profile,
        ext4_core::TrimCursor::start(),
        ext4_core::TrimAlignment::new(512)?,
    );
    let mut event = ext4_core::OperationEvent::Admitted;
    let selection = loop {
        match operation.advance(event, coordinator.read_context(cache.access(&epoch))?) {
            ext4_core::TrimScanTransition::SubmitLower { request, suspended } => {
                event = ext4_core::OperationEvent::StorageCompleted(transfer(
                    request,
                    &mut filesystem,
                    &mut journal,
                )?);
                operation = suspended;
            }
            ext4_core::TrimScanTransition::Complete(result) => break result?,
        }
    };
    let ext4_core::TrimAdmission::Prepared(batch) = selection.reserve(&mut coordinator, &epoch)?
    else {
        return Err(DriverError::InternalInvariantViolation);
    };
    let (request, pending) = batch.submit();
    Ok((request, pending, coordinator))
}

/// # Panics
/// Fails if the DSM header, aligned range placement or signed/unsigned scalar encoding differs.
#[test]
fn independent_dsm_input_vector_and_device_boundaries() {
    let result = (|| -> DriverResult<()> {
        let sector = TransferSectorSize::from_bytes(512)?;
        let bytes = encode_trim(
            DeviceLength::from_bytes(16384),
            sector,
            [(ByteOffset::new(4096), 8192)].into_iter(),
        )?;
        assert_eq!(
            bytes.as_slice(),
            &[
                28, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 16, 0,
                0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0,
            ]
        );
        for ranges in [
            Vec::new(),
            alloc::vec![(ByteOffset::new(1), 512)],
            alloc::vec![(ByteOffset::new(4096), 16384)],
            alloc::vec![(ByteOffset::new(4096), 0)],
        ] {
            assert!(matches!(
                encode_trim(DeviceLength::from_bytes(16384), sector, ranges.into_iter()),
                Err(DriverError::InvalidParameter)
            ));
        }
        assert!(matches!(
            encode_trim(
                DeviceLength::from_bytes(u64::MAX),
                sector,
                [(ByteOffset::new(1_u64 << 63), 512)].into_iter()
            ),
            Err(DriverError::InvalidParameter)
        ));
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if uncertain lower effects are mistaken for unsubmitted commands or lose their owner.
#[test]
fn native_discard_outcomes_return_the_exact_physical_owner() {
    let result = (|| -> DriverResult<()> {
        for (status, information, expected) in [
            (wdk_sys::STATUS_SUCCESS, 0, TrimIoOutcome::Acknowledged),
            (
                wdk_sys::STATUS_NOT_SUPPORTED,
                0,
                TrimIoOutcome::Uncertain(TrimFailure::Unsupported),
            ),
            (
                wdk_sys::STATUS_CANCELLED,
                0,
                TrimIoOutcome::Uncertain(TrimFailure::Cancelled),
            ),
            (
                wdk_sys::STATUS_SUCCESS,
                1,
                TrimIoOutcome::Uncertain(TrimFailure::Failed(Error::DeviceIo)),
            ),
        ] {
            let (request, pending, mut coordinator) = admitted_request()?;
            let requested_bytes = request.byte_count();
            let transfer = encode_trim(
                DeviceLength::from_bytes(16 * 1024 * 1024),
                TransferSectorSize::from_bytes(512)?,
                request
                    .ranges()
                    .map(|range| (range.offset(), range.length_bytes())),
            )?;
            let completed = CompletedLowerIrp {
                suspended: DeviceControlCommand::Trim {
                    request,
                    suspended: 77,
                },
                transfer,
                status,
                information,
            }
            .finish_control();
            let DeviceControlCompletion::Trim {
                suspended,
                completion,
                status,
            } = completed
            else {
                return Err(DriverError::InternalInvariantViolation);
            };
            assert_eq!(suspended, 77);
            let event = crate::irp::reactor::CompletionEvent::TrimCompleted { completion, status };
            let crate::irp::reactor::CompletionEvent::TrimCompleted { completion, status } = event
            else {
                return Err(DriverError::InternalInvariantViolation);
            };
            assert_eq!(
                status >= wdk_sys::STATUS_SUCCESS,
                expected == TrimIoOutcome::Acknowledged
            );
            let result = pending
                .complete(&mut coordinator, completion)
                .map_err(|mismatch| DriverError::Core(mismatch.reason))?;
            assert_eq!(result.outcome, expected);
            assert_eq!(result.requested_bytes, requested_bytes);
            assert!(!coordinator.has_pending_trim());
        }
        let (request, pending, mut coordinator) = admitted_request()?;
        let completed = DeviceControlCommand::Trim {
            request,
            suspended: 78,
        }
        .unsubmitted(DriverError::Core(Error::OperationCancelled));
        let DeviceControlCompletion::Trim {
            suspended,
            completion,
            ..
        } = completed
        else {
            return Err(DriverError::InternalInvariantViolation);
        };
        assert_eq!(suspended, 78);
        let result = pending
            .complete(&mut coordinator, completion)
            .map_err(|mismatch| DriverError::Core(mismatch.reason))?;
        assert_eq!(
            result.outcome,
            TrimIoOutcome::Unsubmitted(TrimFailure::Cancelled)
        );
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}
