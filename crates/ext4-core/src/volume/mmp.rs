//! Device-visible ownership operations, independent of journal durability and cached metadata.

use super::MediaAccess;
use crate::disk_format::mmp::{self, MmpParameters, MmpRecord};
use crate::memory;
use crate::{
    ByteOffset, CompletedStorageTransfer, Error, Result, StorageCompletion, StorageRequest,
    StorageRequestIdentity, StorageTarget,
};
use alloc::{boxed::Box, vec::Vec};

/// A bounded advertised window leaves at least one heartbeat period for completion latency.
const MAX_ADVERTISED_SECONDS: u16 = 300;
/// A zero superblock preference selects this host's ordinary five-second heartbeat.
const DEFAULT_UPDATE_SECONDS: u16 = 5;

impl MmpParameters {
    /// The only conversion from physical block coordinates to lower byte coordinates.
    /// # Errors
    /// Rejects overflowing placement before any lower transfer.
    fn offset(self) -> Result<ByteOffset> {
        self.bytes
            .offset_of(self.block)
            .map_err(|_error| Error::MmpCorrupt)
    }
    /// Bound observed waiting by the greater local and peer interval.
    fn observation_seconds(self, peer: u16) -> u32 {
        let interval = u32::from(self.heartbeat_seconds().max(peer).max(mmp::MIN_INTERVAL));
        interval
            .saturating_mul(2)
            .saturating_add(1)
            .min(interval.saturating_add(60))
    }
    /// Advertise enough time for two ordinary heartbeat periods.
    fn check_seconds(self) -> u16 {
        self.heartbeat_seconds()
            .saturating_mul(2)
            .max(mmp::MIN_INTERVAL)
    }
    /// Select a period that always fits twice inside the bounded advertised window.
    fn heartbeat_seconds(self) -> u16 {
        let desired = if self.update_seconds == 0 {
            DEFAULT_UPDATE_SECONDS
        } else {
            self.update_seconds
        };
        desired.min(MAX_ADVERTISED_SECONDS / 2)
    }
}

#[cfg(test)]
mod tests;

/// Fresh mount identity supplied by the host before any ownership write.
///
/// `entropy` must come from the host's cryptographic random source for each acquisition. The
/// resulting node identity is an instance identifier, not a claim about a machine hostname.
#[derive(Debug)]
pub struct MmpOwner {
    /// Independent mount instance identity, encoded within the fixed nodename field.
    node: [u8; 64],
    /// Initial non-reserved sequence selected independently of other mounts.
    sequence: u32,
}
impl MmpOwner {
    /// Binds fresh cryptographic entropy to one acquisition.
    pub fn new(entropy: [u8; 16]) -> Self {
        let mut node = [0; 64];
        for (target, source) in node.iter_mut().zip(b"ext4-win:") {
            *target = *source;
        }
        for (target, byte) in node
            .iter_mut()
            .skip(9)
            .zip(entropy.iter().flat_map(|byte| [byte >> 4, byte & 15]))
        {
            *target = match byte {
                0..=9 => b'0'.wrapping_add(byte),
                _ => b'a'.wrapping_add(byte.wrapping_sub(10)),
            };
        }
        let [a, b, c, d, ..] = entropy;
        let raw = u32::from_le_bytes([a, b, c, d]);
        Self {
            node,
            sequence: (raw & 0x7fff_ffff).max(1),
        }
    }
}

/// Sole authority obtained after a durable ownership claim and an independent delayed readback.
/// Dropping this value never writes a clean marker: only an explicitly completed release may do so.
#[derive(Debug)]
pub struct MmpLease {
    /// Physical record and immutable checksum domain.
    parameters: MmpParameters,
    /// Exact instance identity and last acknowledged sequence.
    owner: MmpOwner,
    /// Deadline established at the acknowledged update's submission, never at a late callback.
    valid_until_millis: u64,
}
impl MmpLease {
    /// Maximum interval before the host must drive another ownership check.
    pub fn update_seconds(&self) -> u16 {
        self.parameters.heartbeat_seconds()
    }
    /// Checks freshness before admitting a media mutation or publishing its result.
    /// # Errors
    /// Returns ownership loss at or after the monotonic deadline; wall-clock changes do not extend it.
    pub fn authorize(&self, now: MmpTime) -> Result<()> {
        if now.monotonic_millis >= self.valid_until_millis {
            return Err(Error::MmpOwnershipLost);
        }
        Ok(())
    }
    /// Schedules renewal early enough to include write, flush and independent read latency.
    pub(crate) fn renewal_due(&self, now: MmpTime) -> bool {
        let window = u64::from(self.parameters.check_seconds()).saturating_mul(1000);
        let since = self.valid_until_millis.saturating_sub(window);
        now.monotonic_millis
            >= since.saturating_add(u64::from(self.update_seconds()).saturating_mul(1000))
    }
    /// Consumes the lease until fresh media observation, update, flush and readback all complete.
    /// The host must revoke mutation/publication admission while no acknowledged lease is held.
    pub fn renew(self) -> MmpOperation {
        MmpOperation {
            effect: MmpEffect::None,
            parameters: self.parameters,
            owner: self.owner,
            action: Action::Renew(self.valid_until_millis),
            state: State::Start,
        }
    }
    /// Consumes ownership for release after the host has finished all filesystem writes.
    /// Failure leaves ownership unreleased; it never authorizes a second unverified clean write.
    pub fn release(self) -> MmpOperation {
        MmpOperation {
            effect: MmpEffect::None,
            parameters: self.parameters,
            owner: self.owner,
            action: Action::Release(self.valid_until_millis),
            state: State::Start,
        }
    }
}

/// Clock domains supplied together at a host completion boundary.
#[derive(Clone, Copy, Debug)]
pub struct MmpTime {
    /// Monotonic milliseconds from a stable host origin for this mount's entire lifetime.
    monotonic_millis: u64,
    /// UTC seconds are written only for diagnostics.
    unix_seconds: u64,
}
impl MmpTime {
    /// Keeps clock domains distinct throughout ownership admission and record encoding.
    pub const fn new(monotonic_millis: u64, unix_seconds: u64) -> Self {
        Self {
            monotonic_millis,
            unix_seconds,
        }
    }
}

/// Stimulus delivered only to the continuation that owns the corresponding lower request or timer.
#[derive(Debug)]
pub enum MmpEvent {
    /// First invocation of the operation.
    Start,
    /// Exact owned lower request completed; no cached bytes may satisfy it.
    StorageCompleted(StorageCompletion),
    /// The full requested monotonic delay elapsed; early wakeups must not produce this event.
    Elapsed,
    /// Cancel before another submission. A previously written claim is not implicitly released.
    Cancel,
}
/// One external effect or a fully acknowledged result of an ownership operation.
#[derive(Debug)]
pub enum MmpTransition {
    /// Submit exactly once; storage retry policy must not blindly repeat a failed ownership write.
    SubmitLower {
        /// Direct filesystem-device transfer, bypassing metadata/recovery caches.
        request: StorageRequest,
        /// Unique completion owner.
        suspended: Box<MmpOperation>,
    },
    /// Wait without occupying a worker or holding a journal/visibility gate.
    Wait {
        /// Complete monotonic observation delay.
        seconds: u32,
        /// Unique timer continuation.
        suspended: Box<MmpOperation>,
    },
    /// An acknowledged lease, or no write authority after read-only observation or clean release.
    Complete(core::result::Result<Option<MmpLease>, MmpFailure>),
}
/// Ownership change submitted to the physical device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmpChange {
    /// Fresh ownership claim; a failed mount can leave this record for subsequent observation.
    Claim,
    /// Renewal of this mount's existing ownership.
    Update,
    /// Clean release after filesystem finalization.
    Release,
}
/// Machine-readable external progress, independent of a caller success acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmpEffect {
    /// This operation submitted no ownership write.
    None,
    /// The write may have reached storage; no durability acknowledgement was received.
    Submitted(MmpChange),
    /// The write and filesystem-device flush completed; subsequent observation failed.
    Durable(MmpChange),
}
/// A consumed acquisition or lease operation with its failure and external progress intact.
#[derive(Debug, Eq, PartialEq)]
pub struct MmpFailure {
    /// Programmatic reason, independent of whether an effect was accepted.
    pub reason: Error,
    /// Last externally submitted ownership change and its durability acknowledgement.
    pub effect: MmpEffect,
}
/// Completion-driven acquisition, renewal or final release of one physical ownership record.
#[derive(Debug)]
pub struct MmpOperation {
    /// Authoritative external progress; it survives phase changes and post-write read failure.
    effect: MmpEffect,
    /// Mounted physical and authentication domain.
    parameters: MmpParameters,
    /// Sole expected owner identity.
    owner: MmpOwner,
    /// Determines allowed effects and completion authority.
    action: Action,
    /// Exactly one external event can advance this phase.
    state: State,
}
/// Each action has a distinct ownership postcondition.
#[derive(Clone, Copy, Debug)]
enum Action {
    /// Observe without writes, or claim before mounting with write authority.
    Acquire(MediaAccess),
    /// Refresh an existing lease before its monotonic deadline.
    Renew(u64),
    /// Release only the currently held and unexpired lease.
    Release(u64),
}
/// Meaning of the next independent read.
#[derive(Clone, Copy, Debug)]
enum ReadPurpose {
    /// Decode the initial record before choosing any effect.
    Initial,
    /// Detect a changing peer across the complete advertised observation interval.
    Observe(MmpRecord),
    /// Verify the initial random claim after delayed observation, then establish a fresh update.
    VerifyClaim,
    /// Verify the durable update before its deadline can authorize normal filesystem writes.
    VerifyLease(u64),
}
/// Completed writes determine the remaining durability and observation protocol.
#[derive(Clone, Copy, Debug)]
enum AfterWrite {
    /// The new random claim requires this complete observation delay.
    Claim(u32),
    /// The updated record must be independently observed before this monotonic deadline.
    Renewal(u64),
    /// A clean marker can acknowledge release only after flush.
    Release,
}
impl AfterWrite {
    /// The ownership effect persists independently of the next continuation phase.
    const fn change(self) -> MmpChange {
        match self {
            Self::Claim(_) => MmpChange::Claim,
            Self::Renewal(_) => MmpChange::Update,
            Self::Release => MmpChange::Release,
        }
    }
}
/// External operations own their matching identity and continuation state together.
#[derive(Debug)]
enum State {
    /// No request has been submitted.
    Start,
    /// Only this lower completion can advance the read.
    Reading {
        /// Only the matching concrete lower completion can advance this phase.
        expected: StorageRequestIdentity,
        /// Interpretation of authenticated bytes returned by this read.
        purpose: ReadPurpose,
    },
    /// Only completion of this monotonic delay admits the next read.
    Waiting {
        /// The delayed observation retains its meaning across the host timer boundary.
        purpose: ReadPurpose,
        /// Early timer callbacks cannot establish the required observation interval.
        not_before_millis: u64,
    },
    /// An ownership write may have reached media.
    Writing {
        /// Only the matching concrete lower completion can advance this phase.
        expected: StorageRequestIdentity,
        /// Durable outcome and observation required after this effect.
        after: AfterWrite,
    },
    /// Ownership bytes require filesystem-device durability acknowledgement.
    Flushing {
        /// Only the matching concrete lower completion can advance this phase.
        expected: StorageRequestIdentity,
        /// Durable outcome and observation required after this effect.
        after: AfterWrite,
    },
}
impl MmpOperation {
    /// Starts protection for the physical record selected by primary mount admission.
    /// # Errors
    /// Rejects overflowing placement before constructing any lower transfer.
    pub(super) fn acquire(
        parameters: MmpParameters,
        owner: MmpOwner,
        access: MediaAccess,
    ) -> Result<Self> {
        parameters.offset()?;
        Ok(Self {
            effect: MmpEffect::None,
            parameters,
            owner,
            action: Action::Acquire(access),
            state: State::Start,
        })
    }
    /// Consumes one owned event. Any failed renewal consumes its lease; the host must fence
    /// mutation and reconcile in-flight writes before further publication or clean release.
    #[must_use]
    pub fn advance(mut self: Box<Self>, event: MmpEvent, now: MmpTime) -> MmpTransition {
        if matches!(event, MmpEvent::Cancel) {
            return self.failed(Error::OperationCancelled);
        }
        if matches!(
            self.state,
            State::Start
                | State::Reading {
                    purpose: ReadPurpose::Initial,
                    ..
                }
        ) && matches!(self.action, Action::Renew(deadline) | Action::Release(deadline) if now.monotonic_millis >= deadline)
        {
            return self.failed(Error::MmpOwnershipLost);
        }
        let outcome = match (core::mem::replace(&mut self.state, State::Start), event) {
            (State::Start, MmpEvent::Start) => return self.read(ReadPurpose::Initial),
            (
                State::Waiting {
                    purpose,
                    not_before_millis,
                },
                MmpEvent::Elapsed,
            ) => {
                if now.monotonic_millis < not_before_millis {
                    return self.failed(Error::InvalidTimestamp);
                }
                return self.read(purpose);
            }
            (State::Reading { expected, purpose }, MmpEvent::StorageCompleted(completion)) => {
                expected.complete_transfer(completion).and_then(|transfer| {
                    let CompletedStorageTransfer::Read { buffer, .. } = transfer else {
                        return Err(Error::DeviceIo);
                    };
                    let record = MmpRecord::parse(&buffer, self.parameters.seed)?;
                    Ok((purpose, record, buffer))
                })
            }
            (State::Writing { expected, after }, MmpEvent::StorageCompleted(completion)) => {
                if let Err(error) = expected.complete(completion) {
                    return self.failed(error);
                }
                let request = StorageRequest::Flush {
                    target: StorageTarget::Filesystem,
                };
                self.state = State::Flushing {
                    expected: StorageRequestIdentity::from_request(&request),
                    after,
                };
                return MmpTransition::SubmitLower {
                    request,
                    suspended: self,
                };
            }
            (State::Flushing { expected, after }, MmpEvent::StorageCompleted(completion)) => {
                if let Err(error) = expected.complete(completion) {
                    return self.failed(error);
                }
                self.effect = MmpEffect::Durable(after.change());
                return match after {
                    AfterWrite::Release => MmpTransition::Complete(Ok(None)),
                    AfterWrite::Claim(seconds) => self.wait(ReadPurpose::VerifyClaim, seconds, now),
                    AfterWrite::Renewal(deadline) => self.read(ReadPurpose::VerifyLease(deadline)),
                };
            }
            _ => Err(Error::DeviceIo),
        };
        match outcome {
            Ok((purpose, record, buffer)) => self.observed(purpose, record, buffer, now),
            Err(error) => self.failed(error),
        }
    }
    /// Reports external progress without treating failure as evidence of zero effect.
    fn failed(self: Box<Self>, reason: Error) -> MmpTransition {
        MmpTransition::Complete(Err(MmpFailure {
            reason,
            effect: self.effect,
        }))
    }
    /// Requests uncached, full-block bytes with an owned destination.
    fn read(mut self: Box<Self>, purpose: ReadPurpose) -> MmpTransition {
        let request = (|| {
            Ok(StorageRequest::Read {
                target: StorageTarget::Filesystem,
                offset: self.parameters.offset()?,
                buffer: memory::repeated_vec(
                    0,
                    usize::try_from(self.parameters.bytes.bytes())
                        .map_err(|_error| Error::MmpCorrupt)?,
                )?,
            })
        })();
        match request {
            Ok(request) => {
                self.state = State::Reading {
                    expected: StorageRequestIdentity::from_request(&request),
                    purpose,
                };
                MmpTransition::SubmitLower {
                    request,
                    suspended: self,
                }
            }
            Err(error) => self.failed(error),
        }
    }
    /// Transfers the sole continuation to the host's monotonic timer owner.
    fn wait(
        mut self: Box<Self>,
        purpose: ReadPurpose,
        seconds: u32,
        now: MmpTime,
    ) -> MmpTransition {
        self.state = State::Waiting {
            purpose,
            not_before_millis: now
                .monotonic_millis
                .saturating_add(u64::from(seconds).saturating_mul(1000)),
        };
        MmpTransition::Wait {
            seconds,
            suspended: self,
        }
    }
    /// Interprets one authenticated, independent media observation.
    fn observed(
        self: Box<Self>,
        purpose: ReadPurpose,
        record: MmpRecord,
        buffer: Vec<u8>,
        now: MmpTime,
    ) -> MmpTransition {
        match purpose {
            ReadPurpose::VerifyLease(deadline) => {
                if !self.owns(record) || now.monotonic_millis >= deadline {
                    return self.failed(Error::MmpOwnershipLost);
                }
                return MmpTransition::Complete(Ok(Some(MmpLease {
                    parameters: self.parameters,
                    owner: self.owner,
                    valid_until_millis: deadline,
                })));
            }
            ReadPurpose::VerifyClaim => {
                if !self.owns(record) {
                    return self.failed(Error::MmpOwnershipLost);
                }
                return self.refresh(buffer, now);
            }
            ReadPurpose::Observe(previous) if record != previous => {
                return self.failed(Error::MmpOwnerActive);
            }
            ReadPurpose::Initial => match self.action {
                Action::Acquire(_) => {
                    if record.sequence == mmp::CHECKER {
                        return self.failed(Error::MmpOwnerActive);
                    }
                    if record.sequence != mmp::CLEAN {
                        let seconds = self.parameters.observation_seconds(record.interval);
                        return self.wait(ReadPurpose::Observe(record), seconds, now);
                    }
                }
                Action::Renew(_) | Action::Release(_) => {
                    if !self.owns(record) {
                        return self.failed(Error::MmpOwnershipLost);
                    }
                }
            },
            ReadPurpose::Observe(_) => {}
        }
        let (sequence, after) = match self.action {
            Action::Acquire(MediaAccess::ReadOnly) => return MmpTransition::Complete(Ok(None)),
            Action::Acquire(MediaAccess::ReadWrite) => (
                self.owner.sequence,
                AfterWrite::Claim(self.parameters.observation_seconds(record.interval)),
            ),
            Action::Renew(_) => return self.refresh(buffer, now),
            Action::Release(_) => (mmp::CLEAN, AfterWrite::Release),
        };
        self.write(buffer, sequence, after, now)
    }
    /// Establishes a new deadline from submission time, including lower write/flush/read latency.
    fn refresh(mut self: Box<Self>, buffer: Vec<u8>, now: MmpTime) -> MmpTransition {
        self.owner.sequence = if self.owner.sequence == mmp::LAST_SEQUENCE {
            1
        } else {
            self.owner.sequence.saturating_add(1)
        };
        let deadline = now
            .monotonic_millis
            .saturating_add(u64::from(self.parameters.check_seconds()).saturating_mul(1000));
        let sequence = self.owner.sequence;
        self.write(buffer, sequence, AfterWrite::Renewal(deadline), now)
    }
    /// Full sequence and instance identity are required; wall-clock time grants no ownership.
    fn owns(&self, record: MmpRecord) -> bool {
        record.sequence == self.owner.sequence && record.node == self.owner.node
    }
    /// Prepares the complete image before submitting the irreversible record change.
    fn write(
        mut self: Box<Self>,
        mut buffer: Vec<u8>,
        sequence: u32,
        after: AfterWrite,
        now: MmpTime,
    ) -> MmpTransition {
        let request = (|| {
            MmpRecord::write(
                &mut buffer,
                self.parameters.seed,
                sequence,
                now.unix_seconds,
                &self.owner.node,
                self.parameters.check_seconds(),
            )?;
            Ok(StorageRequest::Write {
                target: StorageTarget::Filesystem,
                offset: self.parameters.offset()?,
                buffer,
            })
        })();
        match request {
            Ok(request) => {
                self.effect = MmpEffect::Submitted(after.change());
                self.state = State::Writing {
                    expected: StorageRequestIdentity::from_request(&request),
                    after,
                };
                MmpTransition::SubmitLower {
                    request,
                    suspended: self,
                }
            }
            Err(error) => self.failed(error),
        }
    }
}
