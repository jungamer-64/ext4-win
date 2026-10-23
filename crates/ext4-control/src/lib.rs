//! UUID-scoped administration contracts for the driver and administrator tools.
//!
//! A saved policy selects future mounts. Existing sessions retain the authority fixed before
//! recovery; a successful save never changes the media authority of an existing session.
#![no_std]
#![forbid(unsafe_code)]
use ext4_core::{FilesystemUuid, MountAccess, RecoveryMemoryLimit};

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
