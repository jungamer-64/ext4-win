//! Portable Windows identity, access-right and security-descriptor contracts.
//!
//! Inode ownership and mode remain authoritative. Identity tables only interpret those facts at
//! the Windows boundary. A table belongs to one filesystem UUID and one publication generation.
#![no_std]
#![feature(vec_push_within_capacity)]
#![forbid(unsafe_code)]

extern crate alloc;

mod control;
mod creation;
mod descriptor;
mod identity;
mod rights;
pub use control::{
    CONTROL_REPLY_BYTES, MappingReply, MappingState, PublicationOutcome, Replacement,
};
pub use creation::{ChildKind, child_security};
pub use descriptor::{Components, Descriptor, MAX_DESCRIPTOR_BYTES};
pub use identity::{
    GroupMapping, IdentityMap, MappingSnapshot, Sid, UserMapping, parse_uuid, uuid_text,
};
pub use rights::{
    AccessDecision, BASE_RIGHTS, CONTROLLED_RIGHTS, EXECUTE_RIGHTS, MAXIMUM_ALLOWED,
    MAXIMUM_CANDIDATES, READ_RIGHTS, WRITE_RIGHTS, evaluate_access, mode_rights, rights_mode,
};

/// Maximum complete identity record accepted by the control and persistent boundaries.
pub const MAX_MAPPING_BYTES: usize = 65_536;
/// Buffered administrator control query; requires a readable control-device handle.
pub const QUERY_IDENTITY_IOCTL: u32 = 0x0008_6004;
/// Buffered administrator table replacement; requires a writable control-device handle.
pub const REPLACE_IDENTITY_IOCTL: u32 = 0x0008_a008;
/// Buffered mounted-volume query returning the core-validated filesystem UUID.
pub const QUERY_VOLUME_IDENTITY_FSCTL: u32 = 0x0009_2410;

/// Machine-readable failure of the portable identity and descriptor boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid encoding, unsupported version, invalid SID or invalid component selection.
    InvalidEncoding,
    /// A SID or numeric identity is repeated within one identity domain.
    DuplicateIdentity,
    /// Logical record size exceeds the control boundary's explicit byte budget.
    RecordTooLarge,
    /// Physical memory could not be reserved.
    AllocationFailed,
    /// The descriptor cannot represent the inode owner/mode contract.
    UnrepresentableDescriptor,
    /// An effective user or primary group has no configured numeric identity.
    UnmappedIdentity,
}

/// Fallibly reserves additional storage without hiding allocation failure.
/// # Errors
/// Returns an error for an out-of-bounds encoding or allocation failure.
pub(crate) fn reserve<T>(values: &mut alloc::vec::Vec<T>, count: usize) -> Result<(), Error> {
    values
        .try_reserve(count)
        .map_err(|_| Error::AllocationFailed)
}

/// Reads one checked little-endian scalar from boundary bytes.
/// # Errors
/// Returns an error for an out-of-bounds encoding or allocation failure.
pub(crate) fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::InvalidEncoding)?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(Error::InvalidEncoding)?
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    ))
}
