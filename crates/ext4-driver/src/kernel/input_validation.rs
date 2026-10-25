//! Native format admission of immutable, kernel-owned request snapshots at PASSIVE_LEVEL.
//! A successful check applies only to those exact bytes through subsequent interpretation.
use super::status::{DriverError, DriverResult};

/// Validates FILE_FULL_EA_INFORMATION without interpreting names or mutating the filesystem.
/// # Errors
/// Preserves the I/O Manager's invalid-entry offset for IRP completion.
#[expect(
    unsafe_code,
    reason = "the immutable initialized snapshot outlives native validation"
)]
pub(crate) fn full_ea(bytes: &[u8]) -> DriverResult<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| DriverError::InvalidBufferSize)?;
    let mut offset = 0;
    let status = unsafe {
        // SAFETY: the snapshot is readable for length, independent of requestor mutation;
        // offset is uniquely writable and validation retains neither pointer.
        validate_full_ea(bytes.as_ptr(), length, &mut offset)
    };
    if status < 0 {
        return Err(DriverError::InvalidEaBuffer { offset });
    }
    Ok(())
}

/// Validates a complete buffered reparse representation before interpreting its tag.
/// # Errors
/// Returns the exact FsRtl status; malformed input has caused no filesystem effect.
#[expect(
    unsafe_code,
    reason = "FsRtl borrows one bounded immutable kernel-owned snapshot"
)]
pub(crate) fn reparse(bytes: &[u8]) -> DriverResult<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| DriverError::InvalidBufferSize)?;
    let status = unsafe {
        // SAFETY: buffered input is initialized and immutable for this synchronous call.
        validate_reparse(bytes.as_ptr(), length)
    };
    if status < 0 {
        return Err(DriverError::ReparseValidationFailed(status));
    }
    Ok(())
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the C boundary retains the native validation ABI and IRQL contract"
)]
unsafe extern "system" {
    #[link_name = "ext4win_validate_full_ea"]
    fn validate_full_ea(bytes: *const u8, length: u32, offset: *mut u32) -> i32;
    #[link_name = "ext4win_validate_reparse"]
    fn validate_reparse(bytes: *const u8, length: u32) -> i32;
}

/// # Safety
/// Retains the production ABI; host fixtures must decode prepared semantic inputs directly.
/// # Panics
/// Host processes cannot execute I/O Manager kernel validation.
#[cfg(test)]
#[expect(
    unsafe_code,
    clippy::panic,
    clippy::disallowed_macros,
    reason = "host tests must not simulate kernel structural admission"
)]
unsafe fn validate_full_ea(_bytes: *const u8, _length: u32, _offset: *mut u32) -> i32 {
    panic!("EA format admission requires the I/O Manager")
}

/// # Safety
/// Retains the production ABI; host fixtures must decode prepared semantic inputs directly.
/// # Panics
/// Host processes cannot execute FsRtl kernel validation.
#[cfg(test)]
#[expect(
    unsafe_code,
    clippy::panic,
    clippy::disallowed_macros,
    reason = "host tests must not simulate FsRtl structural admission"
)]
unsafe fn validate_reparse(_bytes: *const u8, _length: u32) -> i32 {
    panic!("reparse format admission requires FsRtl")
}
