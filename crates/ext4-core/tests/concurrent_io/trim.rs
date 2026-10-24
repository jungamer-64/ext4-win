//! Physical discard authority is independent of allocation ownership and journal publication.
use super::*;

/// Drives only production metadata reads to select one bounded segment of free space.
/// # Errors
/// Propagates context, storage or authenticated allocation metadata failure.
fn select(fixture: &mut Fixture) -> Result<TrimSelection> {
    select_at(fixture, TrimCursor::start())
}

/// Drives a fresh metadata scan from the previous batch's physical continuation.
/// # Errors
/// Propagates current-epoch admission, storage or allocation metadata failure.
fn select_at(fixture: &mut Fixture, cursor: TrimCursor) -> Result<TrimSelection> {
    let mut operation = TrimScanOperation::new(&fixture.profile, cursor, TrimAlignment::new(4096)?);
    let mut event = OperationEvent::Admitted;
    loop {
        match operation.advance(
            event,
            fixture
                .coordinator
                .read_context(fixture.cache.access(&fixture.epoch))?,
        ) {
            TrimScanTransition::SubmitLower { request, suspended } => {
                if !matches!(request, StorageRequest::Read { .. }) {
                    return Err(Error::DeviceIo);
                }
                event = OperationEvent::StorageCompleted(fixture.disk.complete(request)?);
                operation = suspended;
            }
            TrimScanTransition::Complete(result) => return result,
        }
    }
}

/// # Errors
/// Propagates independent fixture, fragmented file allocation, truncate, scan or completion failure.
/// # Panics
/// Fails if range exhaustion skips free space, repeats an interval, or retains allocation exclusion
/// after exact completion.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify bounded physical progress over independently fragmented allocation metadata"
)]
fn fragmented_free_space_resumes_after_range_budget_without_repeating_intervals() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let files = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let metadata = NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?);
        let mut files = Vec::new();
        files
            .try_reserve_exact(130)
            .map_err(|_| Error::OutOfMemory)?;
        for index in 0..130 {
            let name = Ext4Name::new(format!("trim-fragment-{index:03}").as_bytes())?;
            let file = pass.create_file(root, &name, metadata)?;
            pass.write_file_range(file, FileOffset::ZERO, &[0xa5; 4096])?;
            files.push(file.id());
        }
        Ok(files)
    })?;
    fixture.mutate(|pass| {
        for (index, file) in files.iter().enumerate() {
            if index.is_multiple_of(2) {
                let file = pass.file(*file)?;
                pass.truncate_file(file, FileSize::from_bytes(0))?;
            }
        }
        Ok(())
    })?;
    let mut cursor = TrimCursor::start();
    let mut previous_end = 0;
    let mut physical_batches = 0;
    for _segment in 0..8 {
        if cursor.is_complete() {
            break;
        }
        match select_at(&mut fixture, cursor)?.reserve(&mut fixture.coordinator, &fixture.epoch)? {
            TrimAdmission::Prepared(batch) => {
                let (request, pending) = batch.submit();
                if physical_batches == 0 {
                    assert_eq!(request.ranges().len(), TRIM_BATCH_RANGES);
                }
                for range in request.ranges() {
                    assert!(range.offset().get() >= previous_end);
                    previous_end = range
                        .offset()
                        .get()
                        .checked_add(range.length_bytes())
                        .ok_or(Error::DeviceRange)?;
                    for block in range.offset().get() / 4096..previous_end / 4096 {
                        let bit = u8::try_from(block % 8).map_err(|_| Error::DeviceRange)?;
                        let index = 12_288_usize
                            .checked_add(
                                usize::try_from(block / 8).map_err(|_| Error::DeviceRange)?,
                            )
                            .ok_or(Error::DeviceRange)?;
                        assert_eq!(
                            fixture
                                .disk
                                .filesystem
                                .get(index)
                                .ok_or(Error::DeviceRange)?
                                & (1 << bit),
                            0
                        );
                    }
                }
                let completion = request.completed(TrimIoOutcome::Acknowledged);
                let result = pending
                    .complete(&mut fixture.coordinator, completion)
                    .map_err(|mismatch| mismatch.reason)?;
                assert!(!fixture.coordinator.has_pending_trim());
                cursor = result.next;
                physical_batches += 1;
            }
            TrimAdmission::Advanced(next) => cursor = next,
            TrimAdmission::Waiting(_) => return Err(Error::ClusterReferenceConflict),
        }
    }
    assert!(cursor.is_complete());
    assert!(physical_batches >= 2);
    Ok(())
}

/// Admits the nonempty fixture selection through the production coordinator.
/// # Errors
/// Returns selection failure or unexpected initial contention.
fn submit(fixture: &mut Fixture) -> Result<(TrimRequest, PendingTrim)> {
    match select(fixture)?.reserve(&mut fixture.coordinator, &fixture.epoch)? {
        TrimAdmission::Prepared(batch) => Ok(batch.submit()),
        _ => Err(Error::ClusterReferenceConflict),
    }
}

/// # Errors
/// Propagates fixture, reservation, ordinary metadata commit or completion mismatch failure.
/// # Panics
/// Fails if a live discard can erase an allocated block or stall unrelated in-place writes.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare independent bitmap ownership and physical completion boundaries"
)]
fn discard_reserves_free_clusters_until_exact_completion_and_allows_existing_data_writes()
-> Result<()> {
    let mut fixture = Fixture::new()?;
    let effects = fixture.disk.storage_effects;
    let (request, pending) = submit(&mut fixture)?;
    assert_eq!(fixture.disk.storage_effects, effects);
    assert!(request.ranges().len() <= TRIM_BATCH_RANGES);
    assert!(request.byte_count() > 0 && request.byte_count() <= TRIM_BATCH_BYTES);
    // Independent raw fixture bitmap: group zero, four-KiB blocks, block bitmap at block three.
    for range in request.ranges() {
        assert!(range.offset().get().is_multiple_of(4096));
        assert!(range.length_bytes().is_multiple_of(4096));
        let first = range.offset().get() / 4096;
        let end = first
            .checked_add(range.length_bytes() / 4096)
            .ok_or(Error::DeviceRange)?;
        for block in first..end {
            let bit = u8::try_from(block % 8).map_err(|_| Error::DeviceRange)?;
            let index = 12_288_usize
                .checked_add(usize::try_from(block / 8).map_err(|_| Error::DeviceRange)?)
                .ok_or(Error::DeviceRange)?;
            assert_eq!(
                fixture
                    .disk
                    .filesystem
                    .get(index)
                    .ok_or(Error::DeviceRange)?
                    & (1 << bit),
                0
            );
        }
    }
    let a = fixture.a;
    fixture.mutate(|pass| {
        let file = pass.file(a)?;
        pass.write_file_range(file, FileOffset::ZERO, b"c")
    })?;
    assert_eq!(
        fixture.mutate(|pass| {
            let file = pass.file(a)?;
            pass.write_file_range(file, FileOffset::from_bytes(8192), b"new")
        }),
        Err(Error::NoSpace)
    );
    let bytes = request.byte_count();
    let result = pending
        .complete(
            &mut fixture.coordinator,
            request.completed(TrimIoOutcome::Acknowledged),
        )
        .map_err(|mismatch| mismatch.reason)?;
    assert_eq!(result.requested_bytes, bytes);
    assert_eq!(result.outcome, TrimIoOutcome::Acknowledged);
    assert!(result.next.is_complete());
    fixture.mutate(|pass| {
        let file = pass.file(a)?;
        pass.write_file_range(file, FileOffset::from_bytes(8192), b"new")
    })?;
    Ok(())
}

/// # Errors
/// Propagates actual mutation staging, selection or completion failure.
/// # Panics
/// Fails if allocation chosen before discard admission reaches physical writes afterward.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe commit admission before any new home-write effect"
)]
fn already_resolved_allocation_rechecks_the_current_discard_reservation() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let a = fixture.a;
    let (resolved, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket,
        &mut PlainCrypto,
        |pass| {
            let file = pass.file(a)?;
            pass.write_file_range(file, FileOffset::from_bytes(8192), b"new")
        },
    )?;
    let reserved = resolved.reserve(
        fixture.coordinator.grant_intent(ticket),
        &fixture.coordinator,
    )?;
    let (request, pending) = submit(&mut fixture)?;
    let effects = fixture.disk.storage_effects;
    let commit = fixture
        .coordinator
        .acquire_commit(ticket)?
        .ok_or(Error::ClusterReferenceConflict)?;
    assert!(matches!(
        reserved.prepare_commit(
            commit,
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    assert_eq!(fixture.disk.storage_effects, effects);
    pending
        .complete(
            &mut fixture.coordinator,
            request.completed(TrimIoOutcome::Unsubmitted(TrimFailure::Cancelled)),
        )
        .map_err(|mismatch| mismatch.reason)?;
    Ok(())
}

/// # Errors
/// Propagates independent mount, reservation or retained completion mismatch failure.
/// # Panics
/// Fails if a foreign completion releases ranges, or revocation hides uncertain physical progress.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions exercise scoped completion ownership and uncertain effects"
)]
fn foreign_completion_retains_both_owners_and_revoked_completion_preserves_progress() -> Result<()>
{
    let mut first = Fixture::new()?;
    let mut second = Fixture::new()?;
    let (first_request, first_pending) = submit(&mut first)?;
    let (second_request, second_pending) = submit(&mut second)?;
    let bytes = first_request.byte_count();
    let mismatch = match first_pending.complete(
        &mut first.coordinator,
        second_request.completed(TrimIoOutcome::Acknowledged),
    ) {
        Err(mismatch) => mismatch,
        Ok(_) => return Err(Error::DeviceIo),
    };
    assert_eq!(mismatch.reason, Error::ClusterReferenceConflict);
    second_pending
        .complete(&mut second.coordinator, mismatch.completion)
        .map_err(|mismatch| mismatch.reason)?;
    first.coordinator.revoke_media_ownership();
    let result = mismatch
        .pending
        .complete(
            &mut first.coordinator,
            first_request.completed(TrimIoOutcome::Uncertain(TrimFailure::Cancelled)),
        )
        .map_err(|mismatch| mismatch.reason)?;
    assert_eq!(result.requested_bytes, bytes);
    assert_eq!(
        result.outcome,
        TrimIoOutcome::Uncertain(TrimFailure::Cancelled)
    );
    assert!(matches!(
        first
            .coordinator
            .read_context(first.cache.access(&first.epoch)),
        Err(Error::MmpOwnershipLost)
    ));
    Ok(())
}
