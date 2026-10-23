//! Independent record vectors and effect-level ownership protocol tests.
use super::*;
use crate::disk::block::{BlockAddress, BlockSize};
use crate::disk::endian::{DiskOffset, put_fixed, put_le_u16, put_le_u32};
use crate::memory::FallibleVec;

/// One owned simulated device, including independently observable durable state.
struct Device {
    /// A full block with non-record bytes that all updates must preserve.
    bytes: Vec<u8>,
    /// Flush publishes the complete physical block to this durable image.
    durable: Vec<u8>,
    /// Counts writes and flushes separately from reads.
    effects: Vec<&'static str>,
    /// Host monotonic clock, advanced only by complete waits or explicit injected latency.
    millis: u64,
}
impl Device {
    /// Prepares one format-valid block without using the production record encoder.
    /// # Errors
    /// Returns fixture allocation or bounds failure.
    fn new(sequence: u32) -> Result<Self> {
        let mut bytes = memory::repeated_vec(0xa5, 4096)?;
        let record = bytes.get_mut(..1024).ok_or(Error::MmpCorrupt)?;
        record.fill(0);
        put_le_u32(record, DiskOffset::new(0), 0x004d_4d50)?;
        put_le_u32(record, DiskOffset::new(4), sequence)?;
        put_le_u16(record, DiskOffset::new(112), 5)?;
        Ok(Self {
            durable: memory::copied_slice(&bytes)?,
            bytes,
            effects: Vec::new(),
            millis: 0,
        })
    }
    /// Common physical format profile; record encoding tests authenticate checksum separately.
    /// # Errors
    /// Returns invalid fixture block geometry.
    fn parameters() -> Result<MmpParameters> {
        Ok(MmpParameters {
            block: BlockAddress::new(10),
            bytes: BlockSize::from_superblock_log(2)?,
            seed: None,
            update_seconds: 1,
        })
    }
    /// Begins an acquisition with one fresh instance identity.
    /// # Errors
    /// Returns fixture geometry or operation allocation failure.
    fn acquire(&mut self, access: MediaAccess) -> Result<MmpTransition> {
        let operation = memory::try_box(MmpOperation {
            effect: MmpEffect::None,
            parameters: Self::parameters()?,
            owner: MmpOwner::new([0x35; 16]),
            action: Action::Acquire(access),
            state: State::Start,
        })?;
        Ok(operation.advance(MmpEvent::Start, self.now()))
    }
    /// Uses separate monotonic and diagnostic wall-clock domains.
    fn now(&self) -> MmpTime {
        MmpTime::new(self.millis, 1_000_000)
    }
    /// Completes a real transfer, returning its complete owned buffer to the operation.
    /// # Errors
    /// Returns fixture bounds or trace allocation failure.
    fn complete(&mut self, mut request: StorageRequest) -> Result<StorageCompletion> {
        match &mut request {
            StorageRequest::Read { buffer, .. } => memory::copy_exact(buffer, &self.bytes)?,
            StorageRequest::Write { buffer, .. } => {
                self.effects.try_push("write")?;
                memory::copy_exact(&mut self.bytes, buffer)?;
            }
            StorageRequest::Flush { .. } => {
                self.effects.try_push("flush")?;
                memory::copy_exact(&mut self.durable, &self.bytes)?;
            }
        }
        let length = request.byte_count();
        Ok(StorageCompletion::success(
            CompletedStorageTransfer::from_request(request),
            length,
        ))
    }
    /// Drives actual request/flush/wait transitions; injection acts at an external effect boundary.
    /// # Errors
    /// Preserves the terminal protocol failure or fixture failure.
    fn run(
        &mut self,
        mut transition: MmpTransition,
        mut inject: impl FnMut(&mut Self, usize) -> Result<()>,
    ) -> Result<Option<MmpLease>> {
        let mut step = 0_usize;
        loop {
            inject(self, step)?;
            step = step.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
            transition = match transition {
                MmpTransition::SubmitLower { request, suspended } => {
                    let completion = self.complete(request)?;
                    suspended.advance(MmpEvent::StorageCompleted(completion), self.now())
                }
                MmpTransition::Wait { seconds, suspended } => {
                    self.millis = self
                        .millis
                        .saturating_add(u64::from(seconds).saturating_mul(1000));
                    suspended.advance(MmpEvent::Elapsed, self.now())
                }
                MmpTransition::Complete(result) => return result.map_err(|failure| failure.reason),
            };
        }
    }
    /// Completes one whole acquire operation with no injected peer activity.
    /// # Errors
    /// Returns the actual protocol outcome, including ownership competition.
    fn acquired(&mut self) -> Result<MmpLease> {
        let transition = self.acquire(MediaAccess::ReadWrite)?;
        self.run(transition, |_device, _step| Ok(()))?
            .ok_or(Error::MmpOwnershipLost)
    }
}

/// # Panics
/// Fails when a format vector, checksum domain or full-block preservation contract differs.
#[test]
fn independent_record_vector_and_checksum_domain() {
    let result = (|| -> Result<()> {
        let mut device = Device::new(42)?;
        put_fixed(
            &mut device.bytes,
            DiskOffset::new(8),
            &123_456_789_u64.to_le_bytes(),
        )?;
        put_fixed(&mut device.bytes, DiskOffset::new(16), b"node")?;
        put_fixed(&mut device.bytes, DiskOffset::new(80), b"dev")?;
        // CRC32C known answer produced with a separate table-driven encoder and explicit seed.
        put_le_u32(&mut device.bytes, DiskOffset::new(1020), 0xa55c_ae5d)?;
        let record = MmpRecord::parse(&device.bytes, Some(0x1234_5678))?;
        assert_eq!(record.sequence, 42);
        assert_eq!(record.interval, 5);
        put_le_u32(&mut device.bytes, DiskOffset::new(8), 1)?;
        assert_eq!(
            MmpRecord::parse(&device.bytes, Some(0x1234_5678)),
            Err(Error::MmpCorrupt)
        );
        assert!(MmpRecord::parse(&device.bytes, None).is_ok());
        for sequence in [0xe24d_4d51, 0xffff_ffff] {
            put_le_u32(&mut device.bytes, DiskOffset::new(4), sequence)?;
            assert_eq!(
                MmpRecord::parse(&device.bytes, None),
                Err(Error::MmpCorrupt)
            );
        }
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if ownership is granted before delayed readback and a fresh durable update.
#[test]
fn acquire_renew_release_preserve_physical_block_and_durability() {
    let result = (|| -> Result<()> {
        let mut device = Device::new(mmp::CLEAN)?;
        let lease = device.acquired()?;
        assert_eq!(device.effects, ["write", "flush", "write", "flush"]);
        assert_eq!(device.millis, 11_000);
        assert_eq!(device.bytes, device.durable);
        assert!(
            device
                .bytes
                .get(1024..)
                .ok_or(Error::MmpCorrupt)?
                .iter()
                .all(|byte| *byte == 0xa5)
        );
        lease.authorize(device.now())?;
        let operation = memory::try_box(lease.renew())?;
        let transition = operation.advance(MmpEvent::Start, device.now());
        let lease = device
            .run(transition, |_device, _step| Ok(()))?
            .ok_or(Error::MmpOwnershipLost)?;
        let operation = memory::try_box(lease.release())?;
        let transition = operation.advance(MmpEvent::Start, device.now());
        assert!(device.run(transition, |_device, _step| Ok(()))?.is_none());
        assert_eq!(
            MmpRecord::parse(&device.durable, None)?.sequence,
            mmp::CLEAN
        );
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if a reader changes storage or accepts an independently changing owner.
#[test]
fn readonly_observation_is_write_free_and_rejects_active_owners() {
    let result = (|| -> Result<()> {
        for sequence in [mmp::CLEAN, 1] {
            let mut device = Device::new(sequence)?;
            let before = memory::copied_slice(&device.bytes)?;
            let transition = device.acquire(MediaAccess::ReadOnly)?;
            assert!(device.run(transition, |_device, _step| Ok(()))?.is_none());
            assert!(device.effects.is_empty());
            assert_eq!(device.bytes, before);
        }
        for access in [MediaAccess::ReadOnly, MediaAccess::ReadWrite] {
            let mut device = Device::new(1)?;
            let transition = device.acquire(access)?;
            let outcome = device.run(transition, |device, step| {
                if step == 2 {
                    put_le_u32(&mut device.bytes, DiskOffset::new(4), 2)?;
                }
                Ok(())
            });
            assert!(matches!(outcome, Err(Error::MmpOwnerActive)));
            assert!(device.effects.is_empty());
            let mut checker = Device::new(mmp::CHECKER)?;
            let transition = checker.acquire(access)?;
            assert!(matches!(
                checker.run(transition, |_device, _step| Ok(())),
                Err(Error::MmpOwnerActive)
            ));
            assert!(checker.effects.is_empty());
        }
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if lost or expired ownership can perform another update or clean release.
#[test]
fn revocation_and_latency_consume_authority() {
    let result = (|| -> Result<()> {
        for release in [false, true] {
            let mut device = Device::new(mmp::CLEAN)?;
            let lease = device.acquired()?;
            device.effects.clear();
            put_le_u32(&mut device.bytes, DiskOffset::new(4), 99)?;
            let operation = memory::try_box(if release {
                lease.release()
            } else {
                lease.renew()
            })?;
            let transition = operation.advance(MmpEvent::Start, device.now());
            assert!(matches!(
                device.run(transition, |_device, _step| Ok(())),
                Err(Error::MmpOwnershipLost)
            ));
            assert!(device.effects.is_empty());
        }
        let mut device = Device::new(mmp::CLEAN)?;
        let lease = device.acquired()?;
        device.effects.clear();
        device.millis = device.millis.saturating_add(5000);
        assert_eq!(lease.authorize(device.now()), Err(Error::MmpOwnershipLost));
        let operation = memory::try_box(lease.renew())?;
        let transition = operation.advance(MmpEvent::Start, device.now());
        assert!(matches!(
            transition,
            MmpTransition::Complete(Err(MmpFailure {
                reason: Error::MmpOwnershipLost,
                effect: MmpEffect::None
            }))
        ));
        assert!(device.effects.is_empty());
        let mut device = Device::new(mmp::CLEAN)?;
        let transition = device.acquire(MediaAccess::ReadWrite)?;
        let outcome = device.run(transition, |device, step| {
            if step == 7 {
                device.millis = device.millis.saturating_add(5000);
            }
            Ok(())
        });
        assert!(matches!(outcome, Err(Error::MmpOwnershipLost)));
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if a failed or short ownership write is interpreted as zero effect or a reusable lease.
#[test]
fn write_and_flush_failures_have_uncertain_effects() {
    let result = (|| -> Result<()> {
        for fail_flush in [false, true] {
            let mut device = Device::new(mmp::CLEAN)?;
            let transition = device.acquire(MediaAccess::ReadWrite)?;
            let MmpTransition::SubmitLower { request, suspended } = transition else {
                return Err(Error::DeviceIo);
            };
            let completion = device.complete(request)?;
            let transition =
                suspended.advance(MmpEvent::StorageCompleted(completion), device.now());
            let MmpTransition::SubmitLower { request, suspended } = transition else {
                return Err(Error::DeviceIo);
            };
            let transition = if fail_flush {
                let completion = device.complete(request)?;
                suspended.advance(MmpEvent::StorageCompleted(completion), device.now())
            } else {
                let completion = StorageCompletion::success(
                    CompletedStorageTransfer::from_request(request),
                    512,
                );
                suspended.advance(MmpEvent::StorageCompleted(completion), device.now())
            };
            let outcome = if fail_flush {
                let MmpTransition::SubmitLower { request, suspended } = transition else {
                    return Err(Error::DeviceIo);
                };
                suspended.advance(
                    MmpEvent::StorageCompleted(StorageCompletion::failure(
                        CompletedStorageTransfer::from_request(request),
                        Error::DeviceIo,
                    )),
                    device.now(),
                )
            } else {
                transition
            };
            assert!(matches!(
                outcome,
                MmpTransition::Complete(Err(MmpFailure {
                    reason: Error::DeviceIo,
                    effect: MmpEffect::Submitted(MmpChange::Claim)
                }))
            ));
        }
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if an early timer event admits peer observation or cancellation hides a durable claim.
#[test]
fn early_observation_and_cancel_preserve_effect_classification() {
    let result = (|| -> Result<()> {
        let mut device = Device::new(1)?;
        let transition = device.acquire(MediaAccess::ReadOnly)?;
        let MmpTransition::SubmitLower { request, suspended } = transition else {
            return Err(Error::DeviceIo);
        };
        let completion = device.complete(request)?;
        let transition = suspended.advance(MmpEvent::StorageCompleted(completion), device.now());
        let MmpTransition::Wait { suspended, .. } = transition else {
            return Err(Error::DeviceIo);
        };
        assert!(matches!(
            suspended.advance(MmpEvent::Elapsed, device.now()),
            MmpTransition::Complete(Err(MmpFailure {
                reason: Error::InvalidTimestamp,
                effect: MmpEffect::None
            }))
        ));
        let mut device = Device::new(mmp::CLEAN)?;
        let mut transition = device.acquire(MediaAccess::ReadWrite)?;
        loop {
            transition = match transition {
                MmpTransition::SubmitLower { request, suspended } => {
                    let completion = device.complete(request)?;
                    suspended.advance(MmpEvent::StorageCompleted(completion), device.now())
                }
                MmpTransition::Wait { suspended, .. } => {
                    assert!(matches!(
                        suspended.advance(MmpEvent::Cancel, device.now()),
                        MmpTransition::Complete(Err(MmpFailure {
                            reason: Error::OperationCancelled,
                            effect: MmpEffect::Durable(MmpChange::Claim)
                        }))
                    ));
                    break;
                }
                MmpTransition::Complete(_) => return Err(Error::MmpOwnershipLost),
            }
        }
        assert_ne!(
            MmpRecord::parse(&device.durable, None)?.sequence,
            mmp::CLEAN
        );
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if an extreme preference eliminates renewal slack or ignores the peer's advertised wait.
#[test]
fn interval_boundaries_retain_completion_slack() {
    let result = (|| -> Result<()> {
        for seconds in [0, 1, 2, 149, 150, 151, 299, 300, u16::MAX] {
            let parameters = MmpParameters {
                update_seconds: seconds,
                ..Device::parameters()?
            };
            let heartbeat = parameters.heartbeat_seconds();
            assert!(heartbeat > 0);
            assert!(parameters.check_seconds() >= heartbeat.saturating_mul(2));
            assert!(parameters.check_seconds() <= 300);
            assert_eq!(parameters.observation_seconds(u16::MAX), 65_595);
        }
        assert_eq!(
            MmpParameters {
                update_seconds: 0,
                ..Device::parameters()?
            }
            .heartbeat_seconds(),
            5
        );
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}

/// # Panics
/// Fails if a different owner with the same sequence can receive this mount's lease.
#[test]
fn delayed_claim_verification_compares_the_instance_identity() {
    let result = (|| -> Result<()> {
        let mut device = Device::new(mmp::CLEAN)?;
        let mut transition = device.acquire(MediaAccess::ReadWrite)?;
        loop {
            transition = match transition {
                MmpTransition::SubmitLower { request, suspended } => {
                    let completion = device.complete(request)?;
                    suspended.advance(MmpEvent::StorageCompleted(completion), device.now())
                }
                MmpTransition::Wait { seconds, suspended } => {
                    put_fixed(&mut device.bytes, DiskOffset::new(16), b"foreign-owner")?;
                    device.millis = device
                        .millis
                        .saturating_add(u64::from(seconds).saturating_mul(1000));
                    suspended.advance(MmpEvent::Elapsed, device.now())
                }
                MmpTransition::Complete(outcome) => {
                    assert!(matches!(
                        outcome,
                        Err(MmpFailure {
                            reason: Error::MmpOwnershipLost,
                            effect: MmpEffect::Durable(MmpChange::Claim)
                        })
                    ));
                    break;
                }
            }
        }
        assert_eq!(device.effects, ["write", "flush"]);
        Ok(())
    })();
    assert_eq!(result, Ok(()));
}
