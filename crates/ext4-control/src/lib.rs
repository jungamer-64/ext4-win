//! Mount-policy and directory-comparison controls shared by the driver and administrator tools.
//!
//! A saved policy selects future mounts. Existing sessions retain the authority fixed before
//! recovery; a successful save never changes the media authority of an existing session.
#![no_std]
#![forbid(unsafe_code)]
use ext4_core::{FilesystemUuid, MountAccess, RecoveryMemoryLimit};

/// Directory comparison query on a retained directory handle, using buffered I/O.
pub const QUERY_DIRECTORY_CASEFOLD_FSCTL: u32 = 0x0009_2414;
/// Empty-directory comparison transition; the driver requires retained attribute-write access.
pub const SET_DIRECTORY_CASEFOLD_FSCTL: u32 = 0x0009_2418;
/// Complete directory comparison query reply or transition input.
pub const CASEFOLD_STATE_BYTES: usize = 4;

/// Buffered mounted-volume discard requiring a writable volume handle and management privilege.
pub const TRIM_VOLUME_FSCTL: u32 = 0x0009_a420;
/// Complete progress observation, including a stopped or uncertain physical batch.
pub const TRIM_REPLY_BYTES: usize = 64;

/// Terminal reason is separate from acknowledged or uncertain physical byte counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrimOutcome {
    /// The scan reached the filesystem end; device acknowledgment does not imply zero-read behavior.
    Complete,
    /// Discard is not supported by the lower stack.
    Unsupported,
    /// Cancellation stopped this scan, possibly after acknowledged or uncertain batches.
    Cancelled,
    /// A native, metadata, ownership or resource failure stopped the scan.
    Failed,
}
/// Physical progress remains observable even when an administrative operation stops with failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrimReport {
    /// Mounted filesystem identity in ext4 byte order.
    pub uuid: FilesystemUuid,
    /// Terminal reason; it never implies zero progress by itself.
    pub outcome: TrimOutcome,
    /// Native or protocol failure status, zero after a completed scan.
    pub status: i32,
    /// Prefix of physical bytes acknowledged by completed lower commands.
    pub acknowledged_bytes: u64,
    /// Last batch whose lower execution ended without a reliable acknowledgment.
    pub uncertain_bytes: u64,
}
impl TrimReport {
    /// Preallocated fixed reply; an effect-bearing operation needs no final allocation.
    pub fn encode(self) -> [u8; TRIM_REPLY_BYTES] {
        let mut bytes = [0; TRIM_REPLY_BYTES];
        let outcome: u32 = match self.outcome {
            TrimOutcome::Complete => 0,
            TrimOutcome::Unsupported => 1,
            TrimOutcome::Cancelled => 2,
            TrimOutcome::Failed => 3,
        };
        let fields = b"E4TR\x01\0\0\0"
            .iter()
            .copied()
            .chain(self.uuid.bytes())
            .chain(outcome.to_le_bytes())
            .chain(self.status.to_le_bytes())
            .chain(self.acknowledged_bytes.to_le_bytes())
            .chain(self.uncertain_bytes.to_le_bytes());
        for (destination, source) in bytes.iter_mut().zip(fields) {
            *destination = source;
        }
        bytes
    }
    /// Validates a complete reply before exposing progress or deciding whether to start another scan.
    /// # Errors
    /// Rejects unknown tags, invalid reserved fields, impossible successful uncertainty and overflow.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != TRIM_REPLY_BYTES
            || bytes.get(..8) != Some(b"E4TR\x01\0\0\0")
            || bytes
                .get(48..)
                .is_none_or(|reserved| reserved.iter().any(|byte| *byte != 0))
        {
            return Err(Error::MalformedEncoding);
        }
        let outcome = match u32::from_le_bytes(field(bytes, 24)?) {
            0 => TrimOutcome::Complete,
            1 => TrimOutcome::Unsupported,
            2 => TrimOutcome::Cancelled,
            3 => TrimOutcome::Failed,
            _ => return Err(Error::MalformedEncoding),
        };
        let status = i32::from_le_bytes(field(bytes, 28)?);
        let acknowledged_bytes = u64::from_le_bytes(field(bytes, 32)?);
        let uncertain_bytes = u64::from_le_bytes(field(bytes, 40)?);
        if (outcome == TrimOutcome::Complete && (status != 0 || uncertain_bytes != 0))
            || acknowledged_bytes.checked_add(uncertain_bytes).is_none()
        {
            return Err(Error::MalformedEncoding);
        }
        Ok(Self {
            uuid: FilesystemUuid::from_bytes(field(bytes, 8)?),
            outcome,
            status,
            acknowledged_bytes,
            uncertain_bytes,
        })
    }
}

/// Encodes a directory comparison selection independently of native structure layout.
pub const fn encode_casefold(state: ext4_core::DirectoryCasefold) -> [u8; CASEFOLD_STATE_BYTES] {
    match state {
        ext4_core::DirectoryCasefold::Disabled => 0_u32.to_le_bytes(),
        ext4_core::DirectoryCasefold::Enabled => 1_u32.to_le_bytes(),
    }
}
/// Decodes exactly one supported comparison selection before mutation admission.
/// # Errors
/// Rejects truncated, extended or unknown state tags.
pub fn decode_casefold(bytes: &[u8]) -> Result<ext4_core::DirectoryCasefold, Error> {
    let tag = u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_error| Error::MalformedEncoding)?,
    );
    match tag {
        0 => Ok(ext4_core::DirectoryCasefold::Disabled),
        1 => Ok(ext4_core::DirectoryCasefold::Enabled),
        _ => Err(Error::MalformedEncoding),
    }
}

/// Buffered query requiring readable administrator control access.
pub const QUERY_POLICY_IOCTL: u32 = 0x0008_6014;
/// Buffered generation-checked save requiring writable administrator control access.
pub const REPLACE_POLICY_IOCTL: u32 = 0x0008_a018;
/// Complete persistent record size.
pub const POLICY_RECORD_BYTES: usize = 56;
/// Complete persistence observation size.
pub const POLICY_REPLY_BYTES: usize = 72;

/// Validation failure before persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Malformed encoding, unsupported tag or nonzero reserved field.
    MalformedEncoding,
    /// A successor cannot have a zero or exhausted generation.
    InvalidGeneration,
    /// Recovery budget is zero or cannot be represented on the target.
    RecoveryBudget,
}
/// Media authority selected for a future mount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessMode {
    /// Journaled writes after successful admission.
    ReadWrite,
    /// Private recovery with no lower write or flush.
    ReadOnly,
}
/// Background free-space discard admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomaticTrim {
    /// Discard is scheduled only by an explicit request.
    Disabled,
    /// The mounted owner schedules bounded batches every sixty seconds.
    EveryMinute,
}
/// Allocation-free validated policy value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountPolicy {
    /// Fixed media authority for the next session.
    pub access: AccessMode,
    /// Logical private-recovery budget independent of physical allocation failure.
    pub recovery_memory: RecoveryMemoryLimit,
    /// Background discard selection.
    pub automatic_trim: AutomaticTrim,
}
impl MountPolicy {
    /// Writable defaults with bounded recovery and automatic discard disabled.
    pub const DEFAULT: Self = Self {
        access: AccessMode::ReadWrite,
        recovery_memory: RecoveryMemoryLimit::DEFAULT,
        automatic_trim: AutomaticTrim::Disabled,
    };
    /// Fixes core media authority at the mount selection boundary.
    pub const fn mount_access(self) -> MountAccess {
        match self.access {
            AccessMode::ReadWrite => MountAccess::ReadWrite,
            AccessMode::ReadOnly => MountAccess::ReadOnly {
                recovery_memory: self.recovery_memory,
            },
        }
    }
}
/// Authoritative policy and durable-selection generation for one ext4 UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicySnapshot {
    /// UUID in ext4 byte order.
    pub uuid: FilesystemUuid,
    /// Zero denotes unsaved defaults; persisted records have positive generations.
    pub generation: u64,
    /// Policy copied into each admitted session.
    pub policy: MountPolicy,
}
impl PolicySnapshot {
    /// Unsaved defaults for one filesystem identity.
    pub const fn defaults(uuid: FilesystemUuid) -> Self {
        Self {
            uuid,
            generation: 0,
            policy: MountPolicy::DEFAULT,
        }
    }
    /// Encodes the entire persistent value without allocation or native-layout dependence.
    pub fn encode(self) -> [u8; POLICY_RECORD_BYTES] {
        let mut bytes = [0; POLICY_RECORD_BYTES];
        let access: u32 = match self.policy.access {
            AccessMode::ReadWrite => 0,
            AccessMode::ReadOnly => 1,
        };
        let trim: u32 = match self.policy.automatic_trim {
            AutomaticTrim::Disabled => 0,
            AutomaticTrim::EveryMinute => 1,
        };
        let budget = u64::try_from(self.policy.recovery_memory.bytes()).unwrap_or(u64::MAX);
        let fields = b"E4MP\x01\0\0\0"
            .iter()
            .copied()
            .chain(self.uuid.bytes())
            .chain(self.generation.to_le_bytes())
            .chain(access.to_le_bytes())
            .chain(trim.to_le_bytes())
            .chain(budget.to_le_bytes());
        for (target, value) in bytes.iter_mut().zip(fields) {
            *target = value;
        }
        bytes
    }
    /// Decodes an exact complete record and establishes policy invariants.
    /// # Errors
    /// Rejects unsupported versions, reserved fields, unknown tags and invalid budgets.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != POLICY_RECORD_BYTES
            || bytes.get(..8) != Some(b"E4MP\x01\0\0\0")
            || bytes
                .get(48..)
                .is_none_or(|reserved| reserved.iter().any(|v| *v != 0))
        {
            return Err(Error::MalformedEncoding);
        }
        let access = match u32::from_le_bytes(field(bytes, 32)?) {
            0 => AccessMode::ReadWrite,
            1 => AccessMode::ReadOnly,
            _ => return Err(Error::MalformedEncoding),
        };
        let automatic_trim = match u32::from_le_bytes(field(bytes, 36)?) {
            0 => AutomaticTrim::Disabled,
            1 => AutomaticTrim::EveryMinute,
            _ => return Err(Error::MalformedEncoding),
        };
        let budget = usize::try_from(u64::from_le_bytes(field(bytes, 40)?))
            .map_err(|_| Error::RecoveryBudget)?;
        let recovery_memory =
            RecoveryMemoryLimit::new(budget).map_err(|_| Error::RecoveryBudget)?;
        Ok(Self {
            uuid: FilesystemUuid::from_bytes(field(bytes, 8)?),
            generation: u64::from_le_bytes(field(bytes, 24)?),
            policy: MountPolicy {
                access,
                recovery_memory,
                automatic_trim,
            },
        })
    }
}
/// Save result independent of transport acknowledgement and existing session authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyOutcome {
    /// No record effect was accepted.
    NotSaved,
    /// The reported snapshot is durable and selectable by subsequent mounts.
    Saved,
    /// A persistent effect may exist; mount selection requires reconciliation.
    Unknown,
    /// The expected predecessor no longer holds.
    Conflict,
}
/// Complete observed persistence facts; mounted sessions remain independent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyState {
    /// Last authoritative outcome.
    pub outcome: PolicyOutcome,
    /// Native failure status or zero.
    pub status: i32,
    /// Last known durable snapshot, or unsaved defaults.
    pub selected: PolicySnapshot,
}
impl PolicyState {
    /// Completes a fixed-size reply without post-effect allocation.
    pub fn encode(self) -> [u8; POLICY_REPLY_BYTES] {
        let mut bytes = [0; POLICY_REPLY_BYTES];
        let outcome: u32 = match self.outcome {
            PolicyOutcome::NotSaved => 0,
            PolicyOutcome::Saved => 1,
            PolicyOutcome::Unknown => 2,
            PolicyOutcome::Conflict => 3,
        };
        let fields = b"E4PS\x01\0\0\0"
            .iter()
            .copied()
            .chain(outcome.to_le_bytes())
            .chain(self.status.to_le_bytes())
            .chain(self.selected.encode());
        for (target, value) in bytes.iter_mut().zip(fields) {
            *target = value;
        }
        bytes
    }
    /// Decodes a complete observation.
    /// # Errors
    /// Rejects malformed headers, outcome tags or policy records.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != POLICY_REPLY_BYTES || bytes.get(..8) != Some(b"E4PS\x01\0\0\0") {
            return Err(Error::MalformedEncoding);
        }
        let outcome = match u32::from_le_bytes(field(bytes, 8)?) {
            0 => PolicyOutcome::NotSaved,
            1 => PolicyOutcome::Saved,
            2 => PolicyOutcome::Unknown,
            3 => PolicyOutcome::Conflict,
            _ => return Err(Error::MalformedEncoding),
        };
        Ok(Self {
            outcome,
            status: i32::from_le_bytes(field(bytes, 12)?),
            selected: PolicySnapshot::decode(bytes.get(16..).ok_or(Error::MalformedEncoding)?)?,
        })
    }
}
/// Validated CAS successor; the encoded generation uniquely defines its predecessor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyReplacement {
    /// Positive generation established before admission.
    next: PolicySnapshot,
}
impl PolicyReplacement {
    /// Prepares a whole replacement before any persistent effect.
    /// # Errors
    /// Rejects generation exhaustion.
    pub fn new(previous: u64, uuid: FilesystemUuid, policy: MountPolicy) -> Result<Self, Error> {
        Ok(Self {
            next: PolicySnapshot {
                uuid,
                generation: previous.checked_add(1).ok_or(Error::InvalidGeneration)?,
                policy,
            },
        })
    }
    /// Expected predecessor checked under exclusive UUID update admission.
    pub const fn expected_generation(self) -> u64 {
        self.next.generation.saturating_sub(1)
    }
    /// Complete validated successor.
    pub const fn next(self) -> PolicySnapshot {
        self.next
    }
    /// Encodes a whole-record replacement.
    pub fn encode(self) -> [u8; POLICY_RECORD_BYTES] {
        self.next.encode()
    }
    /// Establishes an immediate predecessor for a decoded successor.
    /// # Errors
    /// Rejects malformed records and generation zero.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let next = PolicySnapshot::decode(bytes)?;
        if next.generation == 0 {
            return Err(Error::InvalidGeneration);
        }
        Ok(Self { next })
    }
}
/// Copies a checked fixed-width wire field.
/// # Errors
/// Rejects truncation and invalid offsets.
fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset.checked_add(N).ok_or(Error::MalformedEncoding)?;
    bytes
        .get(offset..end)
        .ok_or(Error::MalformedEncoding)?
        .try_into()
        .map_err(|_| Error::MalformedEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Panics
    /// Fails if physical progress is encoded inconsistently or impossible success is admitted.
    #[test]
    fn trim_progress_wire_contract() {
        let report = TrimReport {
            uuid: FilesystemUuid::from_bytes([7; 16]),
            outcome: TrimOutcome::Cancelled,
            status: -1,
            acknowledged_bytes: 4096,
            uncertain_bytes: 512,
        };
        let mut vector = [0; TRIM_REPLY_BYTES];
        for (destination, source) in vector.iter_mut().zip(b"E4TR\x01\0\0\0") {
            *destination = *source;
        }
        vector[8..24].fill(7);
        vector[24] = 2;
        vector[28..32].fill(0xff);
        vector[33] = 0x10;
        vector[41] = 2;
        assert_eq!(report.encode(), vector);
        assert_eq!(TrimReport::decode(&vector), Ok(report));
        for bytes in [&vector[..63], &[0; 65][..]] {
            assert_eq!(TrimReport::decode(bytes), Err(Error::MalformedEncoding));
        }
        for position in [0, 4, 24, 48] {
            let mut invalid = vector;
            if let Some(value) = invalid.get_mut(position) {
                *value = 9;
            }
            assert_eq!(TrimReport::decode(&invalid), Err(Error::MalformedEncoding));
        }
        let mut invalid = vector;
        invalid[24] = 0;
        assert_eq!(TrimReport::decode(&invalid), Err(Error::MalformedEncoding));
        invalid[28..32].fill(0);
        assert_eq!(TrimReport::decode(&invalid), Err(Error::MalformedEncoding));
        invalid[40..48].fill(0);
        assert!(TrimReport::decode(&invalid).is_ok());
        invalid = vector;
        invalid[32..40].fill(0xff);
        assert_eq!(TrimReport::decode(&invalid), Err(Error::MalformedEncoding));
    }
    /// # Panics
    /// Fails if a directory control admits unknown tags or changes its independent wire vector.
    #[test]
    fn directory_casefold_wire_contract() {
        assert_eq!(
            encode_casefold(ext4_core::DirectoryCasefold::Enabled),
            [1, 0, 0, 0]
        );
        assert_eq!(
            decode_casefold(&[0; 4]),
            Ok(ext4_core::DirectoryCasefold::Disabled)
        );
        for bytes in [&[2, 0, 0, 0][..], &[1, 0, 0][..], &[1, 0, 0, 0, 0][..]] {
            assert_eq!(decode_casefold(bytes), Err(Error::MalformedEncoding));
        }
    }

    /// # Panics
    /// Panics if wire facts change or an invalid boundary is admitted.
    #[test]
    fn known_answer_and_invalid_boundaries() {
        let snapshot = PolicySnapshot::defaults(FilesystemUuid::from_bytes([7; 16]));
        let bytes = snapshot.encode();
        assert_eq!(
            bytes.get(24..48),
            Some(
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0
                ]
                .as_slice()
            )
        );
        assert_eq!(PolicySnapshot::decode(&bytes), Ok(snapshot));
        let state = PolicyState {
            outcome: PolicyOutcome::Unknown,
            status: -123,
            selected: snapshot,
        };
        assert_eq!(PolicyState::decode(&state.encode()), Ok(state));
        for length in 0..POLICY_RECORD_BYTES {
            assert!(PolicySnapshot::decode(bytes.get(..length).unwrap_or_default()).is_err());
        }
        let mut reserved = bytes;
        if let Some(value) = reserved.get_mut(48) {
            *value = 1;
        }
        assert_eq!(
            PolicySnapshot::decode(&reserved),
            Err(Error::MalformedEncoding)
        );
        assert_eq!(
            PolicyReplacement::decode(&bytes),
            Err(Error::InvalidGeneration)
        );
        assert_eq!(
            PolicyReplacement::new(u64::MAX, snapshot.uuid, snapshot.policy),
            Err(Error::InvalidGeneration)
        );
    }
}
