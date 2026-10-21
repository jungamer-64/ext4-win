//! Cached transfer range selection and request-local Cache Manager backpressure.

use super::status::{DriverError, DriverResult};
use crate::irp::{MdlTransfer, MdlTransferRequest};

/// Selects the current transfer length while stream resource ownership excludes size publication.
/// # Errors
/// Returns EOF for a read starting at EOF, and invalid parameter for a write beyond EOF.
pub(super) fn bounded_length(request: MdlTransferRequest, eof: i64) -> DriverResult<u32> {
    if request.length() == 0 {
        return Ok(0);
    }
    let start =
        i64::try_from(request.start().bytes()).map_err(|_| DriverError::InvalidParameter)?;
    let remaining = eof.checked_sub(start).filter(|remaining| *remaining > 0);
    match (request.action(), remaining) {
        (MdlTransfer::Read, Some(remaining)) => Ok(request
            .length()
            .min(u32::try_from(remaining).unwrap_or(u32::MAX))),
        (MdlTransfer::Read, None) => Err(DriverError::CacheManagerFailure(
            wdk_sys::STATUS_END_OF_FILE,
        )),
        (MdlTransfer::Write, Some(remaining)) if i64::from(request.length()) <= remaining => {
            Ok(request.length())
        }
        (MdlTransfer::Write, _) => Err(DriverError::InvalidParameter),
    }
}

/// Validates a preplanned copy against the current committed EOF under MainResource.
/// # Errors
/// Returns invalid parameter for negative offsets and retry when the planned epoch's range no longer fits.
pub(super) fn validate_copy_range(offset: i64, length: u32, eof: i64) -> DriverResult<()> {
    if offset < 0 {
        return Err(DriverError::InvalidParameter);
    }
    if offset
        .checked_add(i64::from(length))
        .is_some_and(|end| end <= eof)
    {
        Ok(())
    } else {
        Err(DriverError::CacheManagerFailure(
            super::status::STATUS_RETRY,
        ))
    }
}

/// Cache checks and callback posting have independent retry observations.
#[derive(Clone, Copy)]
enum WriteAttempt {
    /// No cache check has occurred.
    First,
    /// A prior nonblocking cache check denied admission.
    Checked,
}

/// Request-local state for nonblocking Cache Manager admission.
pub(super) struct WriteAdmission {
    /// Distinguishes the first check from later admission attempts.
    attempt: WriteAttempt,
}
impl WriteAdmission {
    /// Carries whether an earlier attempt denied this write request.
    pub(super) const fn new(retrying: bool) -> Self {
        Self {
            attempt: if retrying {
                WriteAttempt::Checked
            } else {
                WriteAttempt::First
            },
        }
    }

    /// Records the first/repeated check independently of whether Cc accepts it.
    fn checking(&mut self) -> bool {
        let retrying = !matches!(self.attempt, WriteAttempt::First);
        if !retrying {
            self.attempt = WriteAttempt::Checked;
        }
        retrying
    }

    /// Checks admission and records whether Cc has already seen this request.
    /// # Safety
    /// The work owner retains `file` for this <= APC_LEVEL native call.
    #[expect(
        unsafe_code,
        reason = "only the retained native FILE_OBJECT and scalar write count cross this call"
    )]
    #[cfg(not(test))]
    pub(super) unsafe fn accepted(
        &mut self,
        file: wdk_sys::PFILE_OBJECT,
        length: u32,
        wait: bool,
    ) -> bool {
        let accepted = unsafe {
            // SAFETY: The work owner retains file; no requestor memory is accessed.
            wdk_sys::ntddk::CcCanIWrite(file, length, u8::from(wait), u8::from(self.checking()))
        };
        accepted != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ext4_core::FileOffset;

    /// # Panics
    /// Fails if repeated checks are mistaken for repeated callback posting.
    #[test]
    fn repeated_cache_checks_preserve_retry_state() {
        let mut admission = WriteAdmission::new(false);
        assert!(!admission.checking());
        assert!(admission.checking());
        assert!(admission.checking());
        assert!(WriteAdmission::new(true).checking());
    }

    /// # Panics
    /// Fails if a stale current-EOF plan proceeds to a cache copy or overflow is accepted.
    #[test]
    fn cache_copy_revalidates_the_committed_range() {
        assert_eq!(validate_copy_range(80, 40, 120), Ok(()));
        assert_eq!(
            validate_copy_range(80, 40, 100),
            Err(DriverError::CacheManagerFailure(
                super::super::status::STATUS_RETRY
            ))
        );
        assert_eq!(
            validate_copy_range(i64::MAX, 1, i64::MAX),
            Err(DriverError::CacheManagerFailure(
                super::super::status::STATUS_RETRY
            ))
        );
        assert_eq!(
            validate_copy_range(-1, 1, 100),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Errors
    /// Returns an invalid fixed request fixture.
    /// # Panics
    /// Fails if current EOF selection changes read shortening or write rejection.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture conversion errors return Result while known answers use assertions"
    )]
    fn mdl_ranges_use_current_eof() -> DriverResult<()> {
        let read = MdlTransferRequest::try_new(MdlTransfer::Read, FileOffset::from_bytes(80), 40)?;
        assert_eq!(bounded_length(read, 100), Ok(20));
        assert_eq!(bounded_length(read, 120), Ok(40));
        assert_eq!(
            bounded_length(read, 80),
            Err(DriverError::CacheManagerFailure(
                wdk_sys::STATUS_END_OF_FILE
            ))
        );
        let write =
            MdlTransferRequest::try_new(MdlTransfer::Write, FileOffset::from_bytes(80), 40)?;
        assert_eq!(bounded_length(write, 120), Ok(40));
        assert_eq!(
            bounded_length(write, 100),
            Err(DriverError::InvalidParameter)
        );
        let empty =
            MdlTransferRequest::try_new(MdlTransfer::Write, FileOffset::from_bytes(100), 0)?;
        assert_eq!(bounded_length(empty, 100), Ok(0));
        assert!(
            MdlTransferRequest::try_new(MdlTransfer::Read, FileOffset::from_bytes(u64::MAX), 1)
                .is_err()
        );
        Ok(())
    }
}
