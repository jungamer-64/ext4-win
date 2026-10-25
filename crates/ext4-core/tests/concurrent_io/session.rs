//! Session clocks are checked against independent ext4 byte offsets and crash boundaries.

use super::*;

/// Reads the unsigned extended superblock timestamp independently of the production encoder.
/// # Errors
/// Returns a truncated fixture field.
fn disk_time(disk: &Disk, low: usize, high: usize) -> Result<u64> {
    let low = 1024_usize.checked_add(low).ok_or(Error::DeviceRange)?;
    let high = 1024_usize.checked_add(high).ok_or(Error::DeviceRange)?;
    Ok(u64::from(fixture_u32(&disk.filesystem, low)?)
        | (u64::from(*disk.filesystem.get(high).ok_or(Error::DeviceRange)?) << 32))
}

/// Reads the little-endian mount counter independently of the production parser.
/// # Errors
/// Returns a truncated fixture field.
fn mount_count(disk: &Disk) -> Result<u16> {
    let bytes = disk.filesystem.get(1076..1078).ok_or(Error::DeviceRange)?;
    Ok(u16::from_le_bytes(
        bytes.try_into().map_err(|_| Error::DeviceRange)?,
    ))
}

/// Seeds an independently encoded mount-count boundary and refreshes the fixture's CRC32C.
/// # Errors
/// Returns a truncated fixture field.
fn seed_count(disk: &mut Disk, count: u16) -> Result<()> {
    for (byte, source) in disk
        .filesystem
        .get_mut(1076..1078)
        .ok_or(Error::DeviceRange)?
        .iter_mut()
        .zip(count.to_le_bytes())
    {
        *byte = source;
    }
    let crc = fixture_crc32c(
        u32::MAX,
        disk.filesystem.get(1024..2044).ok_or(Error::DeviceRange)?,
    );
    for (byte, source) in disk
        .filesystem
        .get_mut(2044..2048)
        .ok_or(Error::DeviceRange)?
        .iter_mut()
        .zip(crc.to_le_bytes())
    {
        *byte = source;
    }
    Ok(())
}

/// Drives exact lower completions and can reject one write/flush without acknowledging close.
/// # Errors
/// Returns the actual finalization or storage failure, without retrying uncertain effects.
fn close(
    disk: &mut Disk,
    profile: &MountedProfile,
    coordinator: &MutationCoordinatorState,
    now: Ext4Timestamp,
    fail_effect: Option<usize>,
) -> Result<usize> {
    let mut step = Box::try_new(CleanCloseOperation::new(profile))
        .map_err(|_| Error::OutOfMemory)?
        .start(coordinator, now);
    let mut effects = 0_usize;
    loop {
        step = match step {
            CleanCloseTransition::SubmitLower { request, suspended } => {
                let completion = if matches!(request, StorageRequest::Read { .. }) {
                    disk.complete(request)?
                } else {
                    effects = effects.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                    if fail_effect == Some(effects) {
                        StorageCompletion::failure(
                            CompletedStorageTransfer::from_request(request),
                            Error::DeviceIo,
                        )
                    } else {
                        disk.complete(request)?
                    }
                };
                suspended.advance(OperationEvent::StorageCompleted(completion))
            }
            CleanCloseTransition::Complete(result) => {
                let _durability = result?;
                return Ok(effects);
            }
        }
    }
}

/// # Errors
/// Returns fixture, mount, mutation or finalization failure.
/// # Panics
/// Fails if counts, unsigned timestamp extensions or clean-close preservation disagree with disk fields.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare production effects with independently decoded ext4 fields"
)]
fn writable_mount_and_close_persist_session_clocks() -> Result<()> {
    let mut fixture = Fixture::new()?;
    seed_count(&mut fixture.disk, u16::MAX)?;
    let mount_time = 0x01_2345_6789;
    let (profile, epoch, coordinator, _mmp) = fixture
        .disk
        .mount_at(MountAccess::ReadWrite, mount_time, |_, _, _| Ok(()))?
        .into_parts();
    assert_eq!(mount_count(&fixture.disk)?, 0);
    assert_eq!(disk_time(&fixture.disk, 0x2c, 0x275)?, mount_time);
    assert_eq!(disk_time(&fixture.disk, 0x30, 0x274)?, mount_time);
    fixture.profile = profile;
    fixture.cache = MetadataCache::try_new(&epoch)?;
    fixture.epoch = epoch;
    fixture.coordinator = coordinator;
    fixture.mutate(|pass| pass.set_volume_label(Ext4VolumeLabel::new(b"clock")?))?;
    assert_eq!(disk_time(&fixture.disk, 0x30, 0x274)?, 2);
    assert_eq!(disk_time(&fixture.disk, 0x2c, 0x275)?, mount_time);
    let close_time = Ext4Timestamp::new(0x02_3456_789a, 999)?;
    let effects = close(
        &mut fixture.disk,
        &fixture.profile,
        &fixture.coordinator,
        close_time,
        None,
    )?;
    assert!(effects > 4);
    assert_eq!(mount_count(&fixture.disk)?, 0);
    assert_eq!(disk_time(&fixture.disk, 0x2c, 0x275)?, mount_time);
    assert_eq!(disk_time(&fixture.disk, 0x30, 0x274)?, 0x02_3456_789a);
    let flags = fixture_u32(&fixture.disk.filesystem, 1120)?;
    assert_eq!(flags & 4, 0);
    for effect in 1..=effects {
        let mut failed = Fixture::new()?;
        assert!(matches!(
            close(
                &mut failed.disk,
                &failed.profile,
                &failed.coordinator,
                Ext4Timestamp::from_seconds(900),
                Some(effect)
            ),
            Err(Error::DeviceIo)
        ));
        let _recovered = failed.disk.mount(MountAccess::ReadOnly {
            recovery: ext4_core::ReadOnlyRecovery::Memory {
                limit: RecoveryMemoryLimit::DEFAULT,
            },
        })?;
    }
    Ok(())
}

/// # Errors
/// Returns fixture, mount or finalization failure.
/// # Panics
/// Fails if a read-only session changes any media byte or issues a write/flush.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe read-only storage and clock invariance"
)]
fn read_only_mount_and_close_preserve_all_session_fields() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let before = fixture.disk.filesystem.clone();
    let journal = fixture.disk.journal.clone();
    fixture.disk.storage_effects = 0;
    let (profile, _epoch, coordinator, _mmp) = fixture
        .disk
        .mount_at(
            MountAccess::ReadOnly {
                recovery: ext4_core::ReadOnlyRecovery::Memory {
                    limit: RecoveryMemoryLimit::DEFAULT,
                },
            },
            0x12_3456_789a,
            |_, _, _| Ok(()),
        )?
        .into_parts();
    assert_eq!(
        close(
            &mut fixture.disk,
            &profile,
            &coordinator,
            Ext4Timestamp::from_seconds(900),
            None
        )?,
        0
    );
    assert_eq!(fixture.disk.filesystem, before);
    assert_eq!(fixture.disk.journal, journal);
    assert_eq!(fixture.disk.storage_effects, 0);
    Ok(())
}

/// # Errors
/// Returns fixture setup, journal replay or independent byte-decoding failure.
/// # Panics
/// Fails if a torn home image loses a committed mount or makes its checksum unrecoverable.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions inspect committed session recovery after a sector-prefix home write"
)]
fn journal_recovers_mount_clocks_after_torn_primary_checkpoint() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let initial_count = mount_count(&fixture.disk)?;
    let mut torn = false;
    let result = fixture.disk.mount_at(
        MountAccess::ReadWrite,
        0x12_3456_789a,
        |disk, boundary, _| {
            if let MountBoundary::Lower(StorageRequest::Write {
                target: StorageTarget::Filesystem,
                offset,
                buffer,
            }) = boundary
                && offset.get() == 0
                && buffer.len() == 4096
            {
                for (byte, source) in disk
                    .filesystem
                    .get_mut(..1536)
                    .ok_or(Error::DeviceRange)?
                    .iter_mut()
                    .zip(buffer.iter())
                {
                    *byte = *source;
                }
                torn = true;
                return Err(Error::DeviceIo);
            }
            Ok(())
        },
    );
    assert!(matches!(result, Err(Error::DeviceIo)));
    assert!(torn);
    let _mounted = fixture
        .disk
        .mount_at(MountAccess::ReadWrite, 1234, |_, _, _| Ok(()))?;
    assert_eq!(mount_count(&fixture.disk)?, initial_count.wrapping_add(2));
    assert_eq!(disk_time(&fixture.disk, 0x2c, 0x275)?, 1234);
    assert_eq!(disk_time(&fixture.disk, 0x30, 0x274)?, 1234);
    Ok(())
}

/// # Errors
/// Returns fixture setup, close checkpoint or journal recovery failure.
/// # Panics
/// Fails if clearing RECOVER before retiring the log hides a torn timestamp without metadata CRCs.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe recovery authority independently of the filesystem checksum feature"
)]
fn journal_recovers_close_clock_without_superblock_checksums() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let flags = fixture_u32(&fixture.disk.filesystem, 1124)? & !0x400;
    for (byte, source) in fixture
        .disk
        .filesystem
        .get_mut(1124..1128)
        .ok_or(Error::DeviceRange)?
        .iter_mut()
        .zip(flags.to_le_bytes())
    {
        *byte = source;
    }
    let (profile, _epoch, coordinator, _mmp) = fixture
        .disk
        .mount_at(MountAccess::ReadWrite, 0x01_ffff_ffff, |_, _, _| Ok(()))?
        .into_parts();
    let mut step = Box::try_new(CleanCloseOperation::new(&profile))
        .map_err(|_| Error::OutOfMemory)?
        .start(&coordinator, Ext4Timestamp::new(0x02_0000_0001, 0)?);
    loop {
        step = match step {
            CleanCloseTransition::SubmitLower { request, suspended } => {
                if let StorageRequest::Write {
                    target: StorageTarget::Filesystem,
                    offset,
                    buffer,
                } = &request
                    && offset.get() == 0
                    && buffer.len() == 4096
                {
                    for (byte, source) in fixture
                        .disk
                        .filesystem
                        .get_mut(..1536)
                        .ok_or(Error::DeviceRange)?
                        .iter_mut()
                        .zip(buffer.iter())
                    {
                        *byte = *source;
                    }
                    let result = suspended.advance(OperationEvent::StorageCompleted(
                        StorageCompletion::failure(
                            CompletedStorageTransfer::from_request(request),
                            Error::DeviceIo,
                        ),
                    ));
                    assert!(matches!(
                        result,
                        CleanCloseTransition::Complete(Err(Error::DeviceIo))
                    ));
                    break;
                }
                suspended.advance(OperationEvent::StorageCompleted(
                    fixture.disk.complete(request)?,
                ))
            }
            CleanCloseTransition::Complete(_) => return Err(Error::DeviceIo),
        };
    }
    assert_eq!(fixture_u32(&fixture.disk.filesystem, 1120)? & 4, 0);
    assert_eq!(disk_time(&fixture.disk, 0x30, 0x274)?, 0x01_0000_0001);
    let mut replayed = false;
    let _mount = fixture
        .disk
        .mount_at(MountAccess::ReadWrite, 1234, |_, boundary, _| {
            if let MountBoundary::Lower(StorageRequest::Write {
                target: StorageTarget::Filesystem,
                offset,
                buffer,
            }) = boundary
                && offset.get() == 0
                && buffer.len() == 4096
                && fixture_u32(buffer, 1024 + 0x30)? == 1
                && buffer.get(1024 + 0x274) == Some(&2)
            {
                replayed = true;
            }
            Ok(())
        })?;
    assert!(replayed);
    Ok(())
}

/// # Errors
/// Returns mount or close failure.
/// # Panics
/// Fails if unsigned superblock clocks wrap outside their domain or encode pre-epoch dates.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare clock-domain boundaries with independent on-disk values"
)]
fn session_clocks_clamp_to_the_unsigned_40_bit_domain() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let (profile, _epoch, coordinator, _mmp) = fixture
        .disk
        .mount_at(MountAccess::ReadWrite, u64::MAX, |_, _, _| Ok(()))?
        .into_parts();
    assert_eq!(disk_time(&fixture.disk, 0x2c, 0x275)?, 0xff_ffff_ffff);
    assert_eq!(disk_time(&fixture.disk, 0x30, 0x274)?, 0xff_ffff_ffff);
    close(
        &mut fixture.disk,
        &profile,
        &coordinator,
        Ext4Timestamp::from_seconds(-1),
        None,
    )?;
    assert_eq!(disk_time(&fixture.disk, 0x2c, 0x275)?, 0xff_ffff_ffff);
    assert_eq!(disk_time(&fixture.disk, 0x30, 0x274)?, 0);
    Ok(())
}
