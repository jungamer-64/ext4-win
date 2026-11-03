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

/// # Errors
/// Returns fixture mount, native geometry or runtime allocation failure.
#[expect(
    unsafe_code,
    reason = "the caller retains the native device until the binding is dropped"
)]
fn binding(
    disk: &mut Device,
    native: &mut wdk_sys::DEVICE_OBJECT,
) -> crate::kernel::status::DriverResult<crate::state::MountedVolumeBinding> {
    use crate::kernel::storage::{LowerStorageDevice, MountedStorage};
    // SAFETY: The caller retains this native fixture until all mounted state is released.
    let device = unsafe { crate::state::KernelDevice::from_raw(core::ptr::from_mut(native)) }
        .ok_or(DriverError::InvalidParameter)?;
    let lower = LowerStorageDevice::from_device(
        device,
        DeviceLength::from_bytes(
            u64::try_from(disk.filesystem.len()).map_err(|_| DriverError::InvalidParameter)?,
        ),
    )?;
    let mut catalog = crate::identity::IdentityCatalog::empty();
    crate::state::MountedVolumeBinding::from_completed_mount(
        disk.mount()?,
        MountedStorage::primary(device, lower),
        crate::kernel::operational_trace::OperationalTrace::host_test(),
        catalog.directory_mut(),
    )
}

/// # Errors
/// Returns independent mount-fixture or close-preparation failure.
/// # Panics
/// Fails if a real writeback failure reopens the session or preserves paging admission.
#[test]
#[expect(
    unsafe_code,
    reason = "the local FILE_OBJECT outlives its mounted close preparation"
)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fallible setup precedes terminal writeback assertions"
)]
fn unreliable_writeback_terminates_close_preparation() -> crate::kernel::status::DriverResult<()> {
    let mut disk = Device::fixture()?;
    let mut native = wdk_sys::DEVICE_OBJECT {
        SectorSize: 512,
        Flags: wdk_sys::DO_DIRECT_IO,
        ..wdk_sys::DEVICE_OBJECT::default()
    };
    let mut binding = binding(&mut disk, &mut native)?;
    let mut file = wdk_sys::FILE_OBJECT::default();
    // SAFETY: The local FILE_OBJECT remains live until the preparation is consumed.
    let owner = unsafe { crate::state::KernelFileObject::from_raw(&raw mut file) }
        .ok_or(DriverError::InvalidParameter)?;
    binding.with_access(|access| {
        let preparation =
            access.prepare_volume_close(crate::state::VolumeCloseTarget::Dismount(owner))?;
        access.record_cache_writeback_failure(wdk_sys::STATUS_IO_DEVICE_ERROR);
        let transition = access
            .abort_or_seal_close(preparation)
            .ok_or(DriverError::InternalInvariantViolation)?;
        access.abandon_session();
        assert!(access.session_work_drained());
        drop(access.finish_abandoned_session());
        access.fail_volume_state_transition(
            transition,
            DriverError::CacheManagerFailure(wdk_sys::STATUS_IO_DEVICE_ERROR),
        );
        assert_eq!(access.ensure_mounted(), Err(DriverError::VolumeDismounted));
        assert_eq!(
            access.storage_access().authorize_paging(),
            Err(DriverError::VolumeDismounted)
        );
        Ok(())
    })
}

/// Decodes the same direct-volume identity that an original IRP retains through submission.
/// # Errors
/// Returns invalid fixture contexts or native IRP decoding failure.
#[expect(
    unsafe_code,
    reason = "the test retains its binding, FILE_OBJECT and CCB until every captured identity is consumed"
)]
fn raw_target(
    binding: &mut crate::state::MountedVolumeBinding,
    file: &mut wdk_sys::FILE_OBJECT,
    handle: &mut crate::state::OpenedVolumeHandle,
) -> crate::kernel::status::DriverResult<crate::state::RawVolumeTarget> {
    let volume = binding.with_access(|access| access.file_object_owner());
    // SAFETY: The binding retains its pinned VCB throughout this fixture.
    let stream = unsafe { &volume.as_ref().stream_context };
    file.FsContext = stream.header().as_ptr();
    file.FsContext2 = core::ptr::from_mut(handle).cast();
    file.SectionObjectPointer = stream.section_objects()?.as_ptr();
    file.Flags |= wdk_sys::FO_VOLUME_OPEN;
    let mut device = wdk_sys::DEVICE_OBJECT::default();
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        FileObject: core::ptr::from_mut(file),
        ..wdk_sys::IO_STACK_LOCATION::default()
    };
    let mut irp = wdk_sys::IRP::default();
    irp.Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation = &raw mut stack;
    let mut received = unsafe {
        // SAFETY: All IRP and stack storage outlives this synchronous decode.
        crate::irp::ReceivedIrp::decode(&raw mut device, &raw mut irp)
    }?;
    received.with_active(|active| {
        Ok(
            crate::state::OpenedVolume::decode(active.current_stack()?.file_object()?)?
                .raw_target(),
        )
    })
}

/// # Errors
/// Returns independent fixture, close-protocol or raw-submission failure.
/// # Panics
/// Fails if ended ext4 ownership blocks a retained raw owner, or unlock preserves its authority.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fallible fixture and protocol execution surround authority assertions"
)]
fn dismount_retains_raw_submissions_without_restoring_filesystem_ownership()
-> crate::kernel::status::DriverResult<()> {
    use crate::state::{
        MountedVolumeState, OpenedVolumeHandle, RawVolumeAccess, RawVolumeOperationKind,
        StorageSubmissionSource, VolumeFlushScope,
    };
    for first_raw_write in [false, true] {
        let mut disk = Device::fixture()?;
        let mut native = wdk_sys::DEVICE_OBJECT {
            SectorSize: 512,
            Flags: wdk_sys::DO_DIRECT_IO,
            ..wdk_sys::DEVICE_OBJECT::default()
        };
        let mut binding = binding(&mut disk, &mut native)?;
        let mut file = wdk_sys::FILE_OBJECT::default();
        let mut handle = OpenedVolumeHandle::new(RawVolumeAccess::ReadWrite);
        let target = raw_target(&mut binding, &mut file, &mut handle)?;
        // This fixture begins with the exclusive raw lock already held.
        binding.actor.volume_control.state = MountedVolumeState::Locked {
            owner: target.owner(),
        };
        let close_target = if first_raw_write {
            crate::state::VolumeCloseTarget::RawWrite(target.owner())
        } else {
            crate::state::VolumeCloseTarget::Dismount(target.owner())
        };
        let (transition, mut close) = binding.with_access(|access| {
            let preparation = access.prepare_volume_close(close_target)?;
            assert!(access.abort_or_seal_close(preparation).is_none());
            assert_eq!(access.authorize_handle(target.owner()), Ok(()));
            let preparation = access.prepare_volume_close(close_target)?;
            assert!(access.prepare_close_writeback(&preparation)?.is_empty());
            let transition = access.seal_volume_close(preparation)?;
            let close = Box::try_new(CleanCloseOperation::new(access.mounted_profile()))
                .map_err(|_| DriverError::InsufficientResources)?;
            Ok::<_, DriverError>((
                transition,
                access.start_clean_close(close, ext4_core::Ext4Timestamp::from_seconds(900)),
            ))
        })?;
        let durability = loop {
            close = match close {
                CleanCloseTransition::SubmitLower { request, suspended } => {
                    drop(binding.with_access(|access| {
                        access.authorize_storage_submission(StorageSubmissionSource::Filesystem)
                    })?);
                    suspended.advance(OperationEvent::StorageCompleted(disk.complete(request)?))
                }
                CleanCloseTransition::Complete(result) => break result?,
            };
        };
        binding.with_access(|access| access.request_mmp_close(durability))?;
        binding.with_access(|access| {
            let _durability = access.finish_mmp_close()?;
            access.publish_volume_state_transition(transition)?;
            assert!(matches!(
                access.authorize_storage_submission(StorageSubmissionSource::Filesystem),
                Err(DriverError::FileClosed)
            ));
            for kind in [RawVolumeOperationKind::Read, RawVolumeOperationKind::Write] {
                drop(
                    access.authorize_storage_submission(StorageSubmissionSource::RawVolume {
                        target,
                        kind,
                    })?,
                );
            }
            assert!(matches!(
                access.volume_flush_scope(target)?,
                VolumeFlushScope::RawDevice(_)
            ));
            if first_raw_write {
                assert!(access.raw_locked_by(target.owner()));
                access.dismount_raw_session(target.owner());
            }
            access.unlock_volume(target.owner())?;
            assert!(matches!(
                access.authorize_storage_submission(StorageSubmissionSource::RawVolume {
                    target,
                    kind: RawVolumeOperationKind::Write,
                }),
                Err(DriverError::AccessDenied)
            ));
            Ok::<_, DriverError>(())
        })?;
    }
    Ok(())
}

/// # Errors
/// Returns fixture or lifecycle preparation failure.
/// # Panics
/// Fails if unhealthy media cannot terminate, physical work is mistaken for clean state,
/// or abandonment permits a recovery/MMP write before retirement.
#[test]
#[expect(
    unsafe_code,
    reason = "the local direct-volume identity outlives its close transition"
)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fallible mount setup surrounds lifecycle and submission assertions"
)]
fn unhealthy_sessions_drain_and_retire_without_clean_publication()
-> crate::kernel::status::DriverResult<()> {
    use crate::state::{StorageSubmissionSource, VolumeCloseTarget, VolumeRetirement};
    for lost_ownership in [false, true] {
        let mut disk = Device::fixture()?;
        let mut native = wdk_sys::DEVICE_OBJECT {
            SectorSize: 512,
            Flags: wdk_sys::DO_DIRECT_IO,
            ..wdk_sys::DEVICE_OBJECT::default()
        };
        let mut binding = binding(&mut disk, &mut native)?;
        let mut file = wdk_sys::FILE_OBJECT::default();
        // SAFETY: The stack FILE_OBJECT remains live until the binding finishes its transition.
        let owner = unsafe { crate::state::KernelFileObject::from_raw(&raw mut file) }
            .ok_or(DriverError::InvalidParameter)?;
        let activity = binding.with_access(|access| access.admit_mutation())?.1;
        binding.with_access(|access| {
            if lost_ownership {
                access.fail_mmp(Error::MmpOwnershipLost);
            } else {
                access.record_durability_unknown();
            }
            assert!(access.authorize_durability().is_err());
            let preparation = access.prepare_volume_close(VolumeCloseTarget::Dismount(owner))?;
            let transition = access.seal_volume_close(preparation)?;
            access.abandon_session();
            assert!(!access.session_work_drained());
            drop(activity);
            assert!(access.session_work_drained());
            assert!(access.finish_abandoned_session().is_none());
            access.fail_volume_state_transition(transition, DriverError::VolumeDismounted);
            assert_eq!(access.ensure_mounted(), Err(DriverError::VolumeDismounted));
            assert!(
                access
                    .authorize_storage_submission(StorageSubmissionSource::Filesystem)
                    .is_err()
            );
            assert_eq!(access.close_node_file_object(), VolumeRetirement::Start);
            Ok::<_, DriverError>(())
        })?;
    }
    Ok(())
}

/// # Panics
/// Fails if a physically completed renewal resurrects abandoned media authority or
/// authorizes a clean MMP release without filesystem-close durability.
#[test]
fn abandonment_joins_renewal_without_releasing_a_clean_record() {
    let result = (|| -> Result<()> {
        let mut device = ownership_disk(0xff4d_4d50)?;
        let (_, _, _, lease) = device.mount()?.into_parts();
        let lease = lease.ok_or(Error::MmpOwnershipLost)?;
        device.millis = lease.next_update().monotonic_millis();
        let mut owner = MediaOwnership::from_mount(Some(lease));
        let operation = owner.next_action(device.now())?.ok_or(Error::DeviceIo)?;
        let completion = device.ownership(operation)?;
        owner.abandon();
        assert_eq!(owner.authorize(device.now()), Err(DriverError::FileClosed));
        assert!(owner.complete(completion, device.now()).is_err());
        assert!(!owner.permits_io());
        assert!(owner.next_action(device.now())?.is_none());
        assert_ne!(
            fixture_u32(&device.filesystem, OWNERSHIP_OFFSET + 4)?,
            0xff4d_4d50
        );
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}
