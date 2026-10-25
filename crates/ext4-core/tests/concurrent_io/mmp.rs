//! Independent on-disk MMP vectors exercised through complete filesystem mount and close.
use super::*;

/// Independent block reserved in the fixture's otherwise free block bitmap.
const OWNERSHIP_BLOCK: usize = 1000;
/// Physical fixture byte coordinate.
const OWNERSHIP_OFFSET: usize = OWNERSHIP_BLOCK * 4096;

/// Writes independent wire bytes without a production encoder.
/// # Errors
/// Returns a truncated field or overflowing range.
fn put(image: &mut [u8], offset: usize, bytes: &[u8]) -> Result<()> {
    let end = offset.checked_add(bytes.len()).ok_or(Error::DeviceRange)?;
    let destination = image.get_mut(offset..end).ok_or(Error::DeviceRange)?;
    for (destination, source) in destination.iter_mut().zip(bytes) {
        *destination = *source;
    }
    Ok(())
}

/// Encodes feature, allocated block and dependent checksums from independent format fields.
/// # Errors
/// Returns malformed fixture geometry, occupied placement or arithmetic failure.
fn ownership_disk(sequence: u32) -> Result<Disk> {
    let mut disk = Disk::fixture();
    let image = &mut disk.filesystem;
    let flags = fixture_u32(image, 1120)? | 0x100;
    put(image, 1120, &flags.to_le_bytes())?;
    put(image, 1024 + 0x166, &1_u16.to_le_bytes())?;
    put(image, 1024 + 0x168, &1000_u64.to_le_bytes())?;
    let seed = fixture_crc32c(u32::MAX, image.get(1128..1144).ok_or(Error::DeviceRange)?);
    let bitmap = usize::try_from(fixture_u32(image, 4096)?)
        .map_err(|_| Error::DeviceRange)?
        .checked_mul(4096)
        .ok_or(Error::DeviceRange)?;
    let byte = image
        .get_mut(
            bitmap
                .checked_add(OWNERSHIP_BLOCK / 8)
                .ok_or(Error::DeviceRange)?,
        )
        .ok_or(Error::DeviceRange)?;
    if *byte & 1 != 0 {
        return Err(Error::InvalidSuperblock);
    }
    *byte |= 1;
    let bitmap_crc = fixture_crc32c(
        seed,
        image
            .get(bitmap..bitmap.checked_add(4096).ok_or(Error::DeviceRange)?)
            .ok_or(Error::DeviceRange)?,
    )
    .to_le_bytes();
    put(
        image,
        4096 + 24,
        bitmap_crc.get(..2).ok_or(Error::DeviceRange)?,
    )?;
    put(
        image,
        4096 + 56,
        bitmap_crc.get(2..).ok_or(Error::DeviceRange)?,
    )?;
    let free = u16::from_le_bytes(
        image
            .get(4108..4110)
            .ok_or(Error::DeviceRange)?
            .try_into()
            .map_err(|_| Error::DeviceRange)?,
    );
    put(
        image,
        4108,
        &free.checked_sub(1).ok_or(Error::DeviceRange)?.to_le_bytes(),
    )?;
    put(image, 4126, &[0, 0])?;
    let group_crc = fixture_crc32c(
        fixture_crc32c(seed, &0_u32.to_le_bytes()),
        image.get(4096..4160).ok_or(Error::DeviceRange)?,
    )
    .to_le_bytes();
    put(image, 4126, group_crc.get(..2).ok_or(Error::DeviceRange)?)?;
    let free = fixture_u32(image, 1036)?
        .checked_sub(1)
        .ok_or(Error::DeviceRange)?;
    put(image, 1036, &free.to_le_bytes())?;
    let crc = fixture_crc32c(u32::MAX, image.get(1024..2044).ok_or(Error::DeviceRange)?);
    put(image, 2044, &crc.to_le_bytes())?;
    let record = image
        .get_mut(OWNERSHIP_OFFSET..OWNERSHIP_OFFSET + 4096)
        .ok_or(Error::DeviceRange)?;
    record.fill(0);
    put(record, 0, &0x004d_4d50_u32.to_le_bytes())?;
    put(record, 4, &sequence.to_le_bytes())?;
    put(record, 112, &5_u16.to_le_bytes())?;
    let crc = fixture_crc32c(seed, record.get(..1020).ok_or(Error::DeviceRange)?);
    put(record, 1020, &crc.to_le_bytes())?;
    record.get_mut(1024..).ok_or(Error::DeviceRange)?.fill(0xa5);
    Ok(disk)
}

/// Runs an ownership action after its required acquisition waits ended.
/// # Errors
/// Preserves effect/observation failure without retrying a request.
fn ownership_action(
    disk: &mut Disk,
    operation: MmpOperation,
    now: MmpTime,
) -> Result<MmpCompletion> {
    let mut step = Box::try_new(operation)
        .map_err(|_| Error::OutOfMemory)?
        .advance(MmpEvent::Start, now);
    loop {
        step = match step {
            MmpTransition::SubmitLower { request, suspended } => {
                suspended.advance(MmpEvent::StorageCompleted(disk.complete(request)?), now)
            }
            MmpTransition::Complete(result) => return result.map_err(|failure| failure.reason),
            MmpTransition::Wait { .. } => return Err(Error::DeviceIo),
        };
    }
}

/// # Errors
/// Returns independent fixture construction, ownership or journal-recovery failure.
/// # Panics
/// Fails if a torn session image authorizes physical recovery before its MMP claim.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe journal-authenticated MMP admission and physical write ordering"
)]
fn torn_session_primary_is_authenticated_before_physical_ownership() -> Result<()> {
    let mut disk = ownership_disk(0xff4d_4d50)?;
    let mut logged_primary = None;
    let result = disk.mount_at(MountAccess::ReadWrite, 200, |disk, boundary, _| {
        if let MountBoundary::Lower(StorageRequest::Write {
            target: StorageTarget::ExternalJournal,
            offset,
            buffer,
        }) = boundary
            && buffer.get(1080..1082) == Some([0x53, 0xef].as_slice())
        {
            logged_primary = Some(usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?);
        }
        if let MountBoundary::Lower(StorageRequest::Write {
            target: StorageTarget::Filesystem,
            offset,
            buffer,
        }) = boundary
            && offset.get() == 0
            && buffer.len() == 4096
        {
            put(
                &mut disk.filesystem,
                0,
                buffer.get(..1536).ok_or(Error::DeviceRange)?,
            )?;
            return Err(Error::DeviceIo);
        }
        Ok(())
    });
    assert!(matches!(result, Err(Error::DeviceIo)));
    // Independent owner-release evidence makes this copied crash fixture available to a new host.
    put(
        &mut disk.filesystem,
        OWNERSHIP_OFFSET + 4,
        &0xff4d_4d50_u32.to_le_bytes(),
    )?;
    let seed = fixture_crc32c(
        u32::MAX,
        disk.filesystem.get(1128..1144).ok_or(Error::DeviceRange)?,
    );
    let crc = fixture_crc32c(
        seed,
        disk.filesystem
            .get(OWNERSHIP_OFFSET..OWNERSHIP_OFFSET + 1020)
            .ok_or(Error::DeviceRange)?,
    );
    put(
        &mut disk.filesystem,
        OWNERSHIP_OFFSET + 1020,
        &crc.to_le_bytes(),
    )?;
    disk.storage_effects = 0;
    let mut invalid = Disk {
        filesystem: disk.filesystem.clone(),
        journal: disk.journal.clone(),
        storage_effects: 0,
    };
    let payload = logged_primary
        .ok_or(Error::DeviceRange)?
        .checked_add(1024)
        .ok_or(Error::DeviceRange)?;
    *invalid.journal.get_mut(payload).ok_or(Error::DeviceRange)? ^= 1;
    assert!(invalid.mount(MountAccess::ReadWrite).is_err());
    assert_eq!(invalid.storage_effects, 0);
    let mut claimed = false;
    let _mounted = disk.mount_at(MountAccess::ReadWrite, 300, |_, boundary, _| {
        if let MountBoundary::Lower(StorageRequest::Write {
            target: StorageTarget::Filesystem,
            offset,
            ..
        }) = boundary
        {
            if offset.get() == u64::try_from(OWNERSHIP_OFFSET).map_err(|_| Error::DeviceRange)? {
                claimed = true;
            } else if offset.get() == 0 {
                assert!(claimed);
            }
        }
        Ok(())
    })?;
    assert!(claimed);
    Ok(())
}

/// # Errors
/// Propagates independently encoded mount, journal, ownership and close failures.
/// # Panics
/// Fails if discovery consumes ownership time or release precedes filesystem completion.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe mount and physical durability boundaries"
)]
fn delayed_external_discovery_precedes_claim_and_complete_close_releases_it() -> Result<()> {
    let mut disk = ownership_disk(0xff4d_4d50)?;
    let mounted = disk.mount_observing(MountAccess::ReadWrite, |disk, boundary, millis| {
        if !matches!(boundary, MountBoundary::JournalValidated) {
            return Ok(());
        }
        assert_eq!(disk.storage_effects, 0);
        *millis = millis.saturating_add(60_000);
        Ok(())
    })?;
    let (profile, _epoch, coordinator, lease) = mounted.into_parts();
    let lease = lease.ok_or(Error::MmpOwnershipLost)?;
    let now = MmpTime::new(71_000, 0);
    lease.authorize(now)?;
    assert_eq!(lease.deadline().monotonic_millis(), 76_000);
    assert_ne!(
        fixture_u32(&disk.filesystem, OWNERSHIP_OFFSET + 4)?,
        0xff4d_4d50
    );
    let (pending, operation) = lease.renew(now)?;
    let MmpCompletion::Renewed(proof) = ownership_action(&mut disk, operation, now)? else {
        return Err(Error::DeviceIo);
    };
    let lease = pending
        .complete(proof, now)
        .map_err(|(error, _proof)| error)?;
    let mut close = Box::try_new(CleanCloseOperation::new(&profile))
        .map_err(|_| Error::OutOfMemory)?
        .start(&coordinator, Ext4Timestamp::from_seconds(900));
    let durability = loop {
        close = match close {
            CleanCloseTransition::SubmitLower { request, suspended } => {
                suspended.advance(OperationEvent::StorageCompleted(disk.complete(request)?))
            }
            CleanCloseTransition::Complete(result) => break result?,
        };
    };
    assert_ne!(
        fixture_u32(&disk.filesystem, OWNERSHIP_OFFSET + 4)?,
        0xff4d_4d50
    );
    let operation = lease
        .release(durability)
        .map_err(|(error, _lease, _proof)| error)?;
    assert!(matches!(
        ownership_action(&mut disk, operation, now)?,
        MmpCompletion::Released(_)
    ));
    assert_eq!(
        fixture_u32(&disk.filesystem, OWNERSHIP_OFFSET + 4)?,
        0xff4d_4d50
    );
    assert!(
        disk.filesystem
            .get(OWNERSHIP_OFFSET + 1024..OWNERSHIP_OFFSET + 4096)
            .ok_or(Error::DeviceRange)?
            .iter()
            .all(|byte| *byte == 0xa5)
    );
    Ok(())
}

/// # Errors
/// Propagates fixture preparation or read-only mount failure.
/// # Panics
/// Fails if observation, active-owner rejection or corrupt-owner rejection writes media.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare complete device images and exact admission failures"
)]
fn readonly_and_rejected_owners_leave_both_devices_unchanged() -> Result<()> {
    for (sequence, reason) in [
        (0xff4d_4d50, None),
        (0xe24d_4d50, Some(Error::MmpOwnerActive)),
    ] {
        for access in [
            MountAccess::ReadWrite,
            MountAccess::ReadOnly {
                recovery_memory: RecoveryMemoryLimit::DEFAULT,
            },
        ] {
            if reason.is_none() && access == MountAccess::ReadWrite {
                continue;
            }
            let mut disk = ownership_disk(sequence)?;
            let filesystem = disk.filesystem.clone();
            let journal = disk.journal.clone();
            let result = disk.mount(access);
            if let Some(reason) = reason {
                assert!(matches!(result, Err(error) if error == reason));
            } else {
                assert!(result.is_ok());
            }
            assert_eq!(disk.storage_effects, 0);
            assert_eq!(disk.filesystem, filesystem);
            assert_eq!(disk.journal, journal);
        }
    }
    let mut disk = ownership_disk(0xff4d_4d50)?;
    *disk
        .filesystem
        .get_mut(OWNERSHIP_OFFSET + 1020)
        .ok_or(Error::DeviceRange)? ^= 1;
    assert!(matches!(
        disk.mount(MountAccess::ReadWrite),
        Err(Error::MmpCorrupt)
    ));
    assert_eq!(disk.storage_effects, 0);
    Ok(())
}

/// # Errors
/// Propagates fixture encoding or field access failure.
/// # Panics
/// Fails if a discovery token carries an obsolete journal cursor into replay.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish identity validation from a fresh cursor read"
)]
fn journal_cursor_is_read_again_after_exclusive_discovery() -> Result<()> {
    let mut disk = ownership_disk(0xff4d_4d50)?;
    let result = disk.mount_observing(MountAccess::ReadWrite, |disk, boundary, millis| {
        if !matches!(boundary, MountBoundary::JournalValidated) {
            return Ok(());
        }
        assert_eq!(disk.storage_effects, 0);
        *millis = millis.saturating_add(60_000);
        *disk.journal.get_mut(4096).ok_or(Error::DeviceRange)? ^= 1;
        Ok(())
    });
    assert_eq!(result.err(), Some(Error::JournalCorrupt));
    assert_eq!(disk.storage_effects, 0);
    Ok(())
}

/// # Errors
/// Propagates fixture preparation and exact physical boundary access failures.
/// # Panics
/// Fails if recovery uses a cursor read before the durable ownership claim.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe physical claim effects before replay admission"
)]
fn journal_cursor_is_read_again_under_the_acknowledged_claim() -> Result<()> {
    let mut disk = ownership_disk(0xff4d_4d50)?;
    let mut changed = false;
    let result = disk.mount_observing(MountAccess::ReadWrite, |disk, boundary, _millis| {
        if disk.storage_effects == 4
            && matches!(boundary, MountBoundary::Lower(StorageRequest::Read { offset, .. }) if offset.get() == 4_096_000)
        {
            *disk.journal.get_mut(4096).ok_or(Error::DeviceRange)? ^= 1;
            changed = true;
        }
        Ok(())
    });
    assert!(changed);
    assert_eq!(result.err(), Some(Error::JournalCorrupt));
    assert_eq!(disk.storage_effects, 4);
    Ok(())
}
