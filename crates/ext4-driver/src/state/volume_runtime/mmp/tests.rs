//! The actor controller consumes real mount, renewal and filesystem-close completions.
use super::*;
use alloc::{boxed::Box, vec::Vec};
use ext4_core::{
    CleanCloseOperation, CleanCloseTransition, CompletedMount, CompletedStorageTransfer,
    DeviceLength, ExternalJournalProbeOperation, ExternalJournalProbeOutcome,
    ExternalJournalProbeTransition, FscryptKeySet, MmpEvent, MmpOwner, MmpTransition, MountAccess,
    MountProbeOperation, MountProbeTransition, MountTransition, MountedProfile, OperationEvent,
    StorageCompletion, StorageRequest, StorageTarget,
};

/// Simulated devices retain effects across core mount and actor ownership continuations.
struct Device {
    /// Filesystem image includes the independent MMP record.
    filesystem: Vec<u8>,
    /// External journal kept separately from the home-block authority.
    journal: Vec<u8>,
    /// Monotonic clock shared by every ownership event.
    millis: u64,
}
impl Device {
    /// Loads independently generated input images without installing or invoking the driver.
    /// # Errors
    /// Returns fixture I/O failure.
    fn fixture() -> Result<Self> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/xtask/fixtures/journal");
        Ok(Self {
            filesystem: std::fs::read(root.join("external-4k-v3-64.filesystem.img"))
                .map_err(|_| Error::DeviceIo)?,
            journal: std::fs::read(root.join("external-4k-v3-64.journal.img"))
                .map_err(|_| Error::DeviceIo)?,
            millis: 0,
        })
    }
    /// Completes one exact owned transfer; no storage operation is retried.
    /// # Errors
    /// Returns a malformed simulated range.
    fn complete(&mut self, mut request: StorageRequest) -> Result<StorageCompletion> {
        let image = match request.target() {
            StorageTarget::Filesystem => &mut self.filesystem,
            StorageTarget::ExternalJournal => &mut self.journal,
        };
        match &mut request {
            StorageRequest::Read { offset, buffer, .. }
            | StorageRequest::Write { offset, buffer, .. } => {
                let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
                let end = start.checked_add(buffer.len()).ok_or(Error::DeviceRange)?;
                let range = image.get_mut(start..end).ok_or(Error::DeviceRange)?;
                match &mut request {
                    StorageRequest::Read { buffer, .. } => {
                        for (destination, source) in buffer.iter_mut().zip(range.iter()) {
                            *destination = *source;
                        }
                    }
                    StorageRequest::Write { buffer, .. } => {
                        for (destination, source) in range.iter_mut().zip(buffer.iter()) {
                            *destination = *source;
                        }
                    }
                    StorageRequest::Flush { .. } => return Err(Error::DeviceIo),
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
    /// Samples one consistent clock domain for mount and actor operations.
    const fn now(&self) -> MmpTime {
        MmpTime::new(self.millis, 0)
    }
    /// Drives the public mount boundary through its actual external-journal and MMP protocols.
    /// # Errors
    /// Preserves admission, validation or lower completion failure.
    fn mount(&mut self) -> Result<CompletedMount> {
        let length = DeviceLength::from_bytes(
            u64::try_from(self.filesystem.len()).map_err(|_| Error::DeviceRange)?,
        );
        let mut probe = Box::try_new(MountProbeOperation::new(length))
            .map_err(|_| Error::OutOfMemory)?
            .advance(OperationEvent::Admitted);
        let prepared = loop {
            probe = match probe {
                MountProbeTransition::SubmitLower { request, suspended } => {
                    suspended.advance(OperationEvent::StorageCompleted(self.complete(request)?))
                }
                MountProbeTransition::Complete(result) => break result?,
            };
        };
        let mut step = Box::try_new(prepared.start(
            FscryptKeySet::empty(),
            MountAccess::ReadWrite,
            ext4_core::DeviceWriteAccess::Writable,
            MmpOwner::new([0x56; 16])?,
            self.now(),
        )?)
        .map_err(|_| Error::OutOfMemory)?
        .advance(OperationEvent::Admitted, self.now());
        loop {
            step = match step {
                MountTransition::SubmitLower { request, suspended }
                | MountTransition::SubmitOwnership { request, suspended } => suspended.advance(
                    OperationEvent::StorageCompleted(self.complete(request)?),
                    self.now(),
                ),
                MountTransition::WaitForTimer { seconds, suspended } => {
                    self.millis = self
                        .millis
                        .saturating_add(u64::from(seconds).saturating_mul(1000));
                    suspended.advance(OperationEvent::TimerElapsed, self.now())
                }
                MountTransition::DiscoverExternalJournal {
                    requirement,
                    suspended,
                } => {
                    let length = DeviceLength::from_bytes(
                        u64::try_from(self.journal.len()).map_err(|_| Error::DeviceRange)?,
                    );
                    let mut probe =
                        Box::try_new(ExternalJournalProbeOperation::new(requirement, length))
                            .map_err(|_| Error::OutOfMemory)?
                            .advance(OperationEvent::Admitted);
                    let validated = loop {
                        probe = match probe {
                            ExternalJournalProbeTransition::SubmitLower { request, suspended } => {
                                suspended.advance(OperationEvent::StorageCompleted(
                                    self.complete(request)?,
                                ))
                            }
                            ExternalJournalProbeTransition::Complete(result) => match result? {
                                ExternalJournalProbeOutcome::Match(validated) => break validated,
                                ExternalJournalProbeOutcome::Mismatch => {
                                    return Err(Error::UnsupportedJournal);
                                }
                            },
                        };
                    };
                    suspended.attach_external_journal(
                        validated,
                        ext4_core::DeviceWriteAccess::Writable,
                        self.now(),
                    )
                }
                MountTransition::Complete(result) => {
                    return result
                        .map(|mounted| *mounted)
                        .map_err(|failure| failure.reason);
                }
            };
        }
    }
    /// Completes actual filesystem finalization before release admission.
    /// # Errors
    /// Preserves read/write/flush failure.
    fn close(
        &mut self,
        profile: &MountedProfile,
        coordinator: &ext4_core::MutationCoordinatorState,
    ) -> Result<CleanCloseDurability> {
        let mut step = Box::try_new(CleanCloseOperation::new(profile))
            .map_err(|_| Error::OutOfMemory)?
            .start(coordinator, ext4_core::Ext4Timestamp::from_seconds(900));
        loop {
            step = match step {
                CleanCloseTransition::SubmitLower { request, suspended } => {
                    suspended.advance(OperationEvent::StorageCompleted(self.complete(request)?))
                }
                CleanCloseTransition::Complete(result) => return result,
            };
        }
    }
    /// Returns only acknowledged core completion evidence to the controller.
    /// # Errors
    /// Propagates the exact ownership protocol failure without retry or clean compensation.
    fn ownership(&mut self, operation: MmpOperation) -> Result<MmpCompletion> {
        let mut step = Box::try_new(operation)
            .map_err(|_| Error::OutOfMemory)?
            .advance(MmpEvent::Start, self.now());
        loop {
            step = match step {
                MmpTransition::SubmitLower { request, suspended } => suspended.advance(
                    MmpEvent::StorageCompleted(self.complete(request)?),
                    self.now(),
                ),
                MmpTransition::Complete(result) => return result.map_err(|failure| failure.reason),
                MmpTransition::Wait { .. } => return Err(Error::DeviceIo),
            };
        }
    }
}

/// Decodes independent format fields in the test image.
/// # Errors
/// Returns truncated input.
fn fixture_u32(image: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::DeviceRange)?;
    Ok(u32::from_le_bytes(
        image
            .get(offset..end)
            .ok_or(Error::DeviceRange)?
            .try_into()
            .map_err(|_| Error::DeviceRange)?,
    ))
}
/// Independent reflected CRC32C used solely to encode disk vectors.
fn fixture_crc32c(mut state: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        state ^= u32::from(*byte);
        for _ in 0..8 {
            state = (state >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(state & 1));
        }
    }
    state
}

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
fn ownership_disk(sequence: u32) -> Result<Device> {
    let mut disk = Device::fixture()?;
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

/// # Panics
/// Fails if a close races renewal, the watchdog disappears, or normal close becomes revocation.
#[test]
fn close_waits_for_the_pending_renewal_before_physical_release() {
    let result = (|| -> Result<()> {
        let mut device = ownership_disk(0xff4d_4d50)?;
        let (profile, _epoch, coordinator, lease) = device.mount()?.into_parts();
        let lease = lease.ok_or(Error::MmpOwnershipLost)?;
        device.millis = lease.next_update().monotonic_millis();
        let old_deadline = lease.deadline();
        let mut owner = MediaOwnership::from_mount(Some(lease));
        let operation = owner.next_action(device.now())?.ok_or(Error::DeviceIo)?;
        assert_eq!(owner.wakeup(), Some(old_deadline));
        assert_eq!(owner.authorize(device.now()), Ok(()));
        let close = device.close(&profile, &coordinator)?;
        owner
            .request_close(close)
            .map_err(|(_error, _close)| Error::DeviceIo)?;
        assert_eq!(owner.close_ready(), Ok(false));
        assert!(matches!(owner.next_action(device.now()), Ok(None)));
        let completion = device.ownership(operation)?;
        owner.complete(completion, device.now())?;
        let release = owner.next_action(device.now())?.ok_or(Error::DeviceIo)?;
        assert_eq!(owner.close_ready(), Ok(false));
        let completion = device.ownership(release)?;
        owner.complete(completion, device.now())?;
        assert_eq!(owner.close_ready(), Ok(true));
        assert_eq!(owner.authorize(device.now()), Err(DriverError::FileClosed));
        assert_eq!(
            fixture_u32(&device.filesystem, OWNERSHIP_OFFSET + 4)?,
            0xff4d_4d50
        );
        owner.finish_close().map_err(|_error| Error::DeviceIo)?;
        assert_eq!(owner.close_ready(), Err(DriverError::FileClosed));
        assert_eq!(owner.wakeup(), None);
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if a durable but late renewal can admit I/O or write a clean marker after revocation.
#[test]
fn a_late_actor_renewal_cannot_restore_admission_or_clean_release() {
    let result = (|| -> Result<()> {
        let mut device = ownership_disk(0xff4d_4d50)?;
        let (_profile, _epoch, _coordinator, lease) = device.mount()?.into_parts();
        let lease = lease.ok_or(Error::MmpOwnershipLost)?;
        device.millis = lease.next_update().monotonic_millis();
        let old_deadline = lease.deadline();
        let mut owner = MediaOwnership::from_mount(Some(lease));
        let operation = owner.next_action(device.now())?.ok_or(Error::DeviceIo)?;
        let completion = device.ownership(operation)?;
        device.millis = old_deadline.monotonic_millis();
        assert_eq!(
            owner.authorize(device.now()),
            Err(Error::MmpOwnershipLost.into())
        );
        owner.revoke(Error::MmpOwnershipLost);
        assert_eq!(
            owner.complete(completion, device.now()),
            Err(Error::MmpOwnershipLost)
        );
        assert!(matches!(owner.next_action(device.now()), Ok(None)));
        assert_ne!(
            fixture_u32(&device.filesystem, OWNERSHIP_OFFSET + 4)?,
            0xff4d_4d50
        );
        assert_eq!(owner.wakeup(), None);
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if retirement loses its cause, admits I/O, or lets a late completion restore authority.
#[test]
fn revocation_is_independent_of_reliability_and_rejects_late_completions() {
    let mut ownership = MediaOwnership::from_mount(None);
    let now = MmpTime::new(1000, 0);
    assert_eq!(ownership.authorize(now), Ok(()));
    assert!(matches!(ownership.next_action(now), Ok(None)));
    assert_eq!(ownership.wakeup(), None);
    ownership.revoke(Error::MmpCorrupt);
    assert!(!ownership.permits_io());
    assert_eq!(
        ownership.authorize(now),
        Err(Error::MmpOwnershipLost.into())
    );
    assert_eq!(ownership.close_ready(), Err(Error::MmpCorrupt.into()));
    assert!(matches!(
        ext4_core::MmpOwner::new([0; 16])
            .map(MmpCompletion::Observed)
            .map(|completion| ownership.complete(completion, now)),
        Ok(Err(Error::MmpOwnershipLost))
    ));
    ownership.revoke(Error::DeviceIo);
    assert_eq!(ownership.close_ready(), Err(Error::MmpCorrupt.into()));
    assert!(matches!(ownership.next_action(now), Ok(None)));
    assert_eq!(ownership.wakeup(), None);
}
