//! Bounded control replies distinguish persistence from live publication and acknowledgement.
use crate::{Error, MappingSnapshot, reserve};
use alloc::vec::Vec;

/// Fixed versioned status header preceding the complete active table.
pub const CONTROL_REPLY_BYTES: usize = 32;

/// Authoritative commit phase observed by the driver; callers reconcile rather than blindly retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PublicationOutcome {
    /// No persistence effect was accepted.
    NotSaved = 0,
    /// The saved table is durable but not yet published to new operations.
    SavedNotApplied = 1,
    /// The durable table is the live snapshot for newly admitted operations.
    Applied = 2,
    /// The persistence effect cannot be determined from the failed operation.
    Unknown = 3,
    /// The expected generation does not match current authority.
    Conflict = 4,
}
impl PublicationOutcome {
    /// Stable wire tag independent of native representation.
    pub const fn tag(self) -> u32 {
        match self {
            Self::NotSaved => 0,
            Self::SavedNotApplied => 1,
            Self::Applied => 2,
            Self::Unknown => 3,
            Self::Conflict => 4,
        }
    }
}

/// Complete observed state returned by query and replacement, including native failure status.
#[derive(Debug, Eq, PartialEq)]
pub struct MappingState {
    /// Commit phase; independent of communication success.
    pub outcome: PublicationOutcome,
    /// Native persistence/publication failure, or zero.
    pub status: i32,
    /// Last generation known durably saved.
    pub saved_generation: u64,
    /// Active immutable table and its applied generation.
    pub active: MappingSnapshot,
}
impl MappingState {
    /// Serializes one query/replacement result.
    /// # Errors
    /// Propagates bounded allocation and table encoding failures.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(MappingReply::prepare(&self.active)?.complete(
            self.outcome,
            self.status,
            self.saved_generation,
        ))
    }
    /// Decodes a complete observed state without collapsing commit phases into an error string.
    /// # Errors
    /// Rejects malformed headers, phases or inconsistent applied generations.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        decode_state(bytes)
    }
}

/// Reply storage prepared before persistence; completion only changes fixed status fields.
#[derive(Debug)]
pub struct MappingReply {
    /// Complete wire record with reserved status header.
    bytes: Vec<u8>,
}
impl MappingReply {
    /// Captures the immutable active table and allocates the entire reply before an effect.
    /// # Errors
    /// Returns allocation or record-size failure.
    pub fn prepare(active: &MappingSnapshot) -> Result<Self, Error> {
        let record = active.encode()?;
        let mut bytes = Vec::new();
        reserve(
            &mut bytes,
            CONTROL_REPLY_BYTES
                .checked_add(record.len())
                .ok_or(Error::RecordTooLarge)?,
        )?;
        bytes.extend_from_slice(b"E4IS\x01\0\0\0");
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&active.generation.to_le_bytes());
        bytes.extend_from_slice(&record);
        Ok(Self { bytes })
    }
    /// Exact native output admission charge for this prepared table.
    pub fn required_length(&self) -> usize {
        self.bytes.len()
    }
    /// Completes a preallocated reply without allocation or fallible encoding after persistence.
    pub fn complete(mut self, outcome: PublicationOutcome, status: i32, saved: u64) -> Vec<u8> {
        let fields = outcome
            .tag()
            .to_le_bytes()
            .into_iter()
            .chain(status.to_le_bytes())
            .chain(saved.to_le_bytes());
        for (target, value) in self.bytes.iter_mut().skip(8).zip(fields) {
            *target = value;
        }
        self.bytes
    }
}
/// Parses one complete control observation.
/// # Errors
/// Rejects malformed headers, phases or inconsistent applied generations.
fn decode_state(bytes: &[u8]) -> Result<MappingState, Error> {
    if bytes.get(..8) != Some(b"E4IS\x01\0\0\0") {
        return Err(Error::InvalidEncoding);
    }
    let outcome = match crate::u32_at(bytes, 8)? {
        0 => PublicationOutcome::NotSaved,
        1 => PublicationOutcome::SavedNotApplied,
        2 => PublicationOutcome::Applied,
        3 => PublicationOutcome::Unknown,
        4 => PublicationOutcome::Conflict,
        _ => return Err(Error::InvalidEncoding),
    };
    let status = i32::from_le_bytes(
        bytes
            .get(12..16)
            .ok_or(Error::InvalidEncoding)?
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    );
    let saved_generation = scalar64(bytes, 16)?;
    let generation = scalar64(bytes, 24)?;
    let active = MappingSnapshot::decode(
        bytes
            .get(CONTROL_REPLY_BYTES..)
            .ok_or(Error::InvalidEncoding)?,
    )?;
    if active.generation != generation
        || saved_generation < generation
        || (outcome == PublicationOutcome::Applied && saved_generation != generation)
        || (outcome == PublicationOutcome::SavedNotApplied && saved_generation == generation)
    {
        return Err(Error::InvalidEncoding);
    }
    Ok(MappingState {
        outcome,
        status,
        saved_generation,
        active,
    })
}

/// Prepared full-table replacement; expected generation is a compare-and-swap requirement.
#[derive(Debug, Eq, PartialEq)]
pub struct Replacement {
    /// Observed active generation the administrator intends to replace.
    expected_generation: u64,
    /// Complete validated successor with generation exactly expected + 1.
    next: MappingSnapshot,
}
impl Replacement {
    /// Establishes monotonic generation before any persistent effect.
    /// # Errors
    /// Rejects exhausted or non-successor generations.
    pub fn new(expected_generation: u64, next: MappingSnapshot) -> Result<Self, Error> {
        if expected_generation.checked_add(1) != Some(next.generation) {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self {
            expected_generation,
            next,
        })
    }
    /// Generation whose authority must still hold when the driver reserves this UUID.
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
    /// Borrows the validated immutable successor for pre-effect reply construction.
    pub const fn next(&self) -> &MappingSnapshot {
        &self.next
    }
    /// Consumes replacement preparation into its sole successor publication owner.
    pub fn into_next(self) -> MappingSnapshot {
        self.next
    }
    /// Encodes the successor record; its generation also encodes the CAS expectation.
    /// # Errors
    /// Propagates record encoding failure.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.next.encode()
    }
    /// Validates the replacement and derives its required predecessor.
    /// # Errors
    /// Rejects malformed tables and zero-generation replacements.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let next = MappingSnapshot::decode(bytes)?;
        Self::new(
            next.generation
                .checked_sub(1)
                .ok_or(Error::InvalidEncoding)?,
            next,
        )
    }
}
/// Reads a bounded 64-bit control field.
/// # Errors
/// Rejects truncated headers.
fn scalar64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let end = offset.checked_add(8).ok_or(Error::InvalidEncoding)?;
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(Error::InvalidEncoding)?
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    ))
}
