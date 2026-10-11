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
    /// Neither a cache check nor deferred posting has occurred.
    First,
    /// Cache checks have occurred but no deferred callback has been posted.
    Checked,
    /// Both subsequent checks and deferred postings must carry their retry flags.
    Deferred,
}

/// Request-local backpressure state; no filesystem resource is held while waiting for Cc.
pub(super) struct WriteAdmission {
    /// Distinguishes first check, repeated check and repeated deferred posting.
    attempt: WriteAttempt,
}
impl WriteAdmission {
    /// No check or deferred callback has occurred for this write request.
    pub(super) const fn new() -> Self {
        Self {
            attempt: WriteAttempt::First,
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

    /// Records deferred posting independently of check retries.
    fn deferring(&mut self) -> bool {
        let retrying = matches!(self.attempt, WriteAttempt::Deferred);
        self.attempt = WriteAttempt::Deferred;
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

    /// Joins each deferred callback before returning or releasing its stack-resident event.
    /// # Safety
    /// The PASSIVE_LEVEL worker retains file and holds no filesystem resource through this call.
    #[expect(
        unsafe_code,
        reason = "the nonalertable native wait retains callback storage and the work envelope retains file"
    )]
    #[cfg(not(test))]
    pub(super) unsafe fn wait(&mut self, file: wdk_sys::PFILE_OBJECT, length: u32) {
        while !unsafe {
            // SAFETY: The caller retains file and permits blocking outside filesystem resources.
            self.accepted(file, length, true)
        } {
            let ready = core::cell::UnsafeCell::new(wdk_sys::KEVENT::default());
            unsafe {
                // SAFETY: The local event has a stable address until the joined callback completes.
                super::ffi::KeInitializeEvent(
                    ready.get(),
                    wdk_sys::_EVENT_TYPE::NotificationEvent,
                    0,
                );
            }
            unsafe {
                // SAFETY: Both non-null contexts remain retained through the nonalertable wait;
                // immediate callback delivery is preserved by the notification event.
                wdk_sys::ntddk::CcDeferWrite(
                    file,
                    Some(write_ready),
                    ready.get().cast(),
                    file.cast(),
                    length,
                    u8::from(self.deferring()),
                );
            }
            unsafe {
                // SAFETY: No cancellation or timeout can release event storage while Cc owns the callback.
                let _wait_status = super::ffi::KeWaitForSingleObject(
                    ready.get().cast(),
                    wdk_sys::_KWAIT_REASON::Executive,
                    0,
                    0,
                    core::ptr::null_mut(),
                );
            }
        }
    }
}

/// Completes the sole native use of request-local write notification storage.
/// # Safety
/// Cc supplies the retained event context registered by WriteAdmission::wait.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the worker's nonalertable wait retains this event until callback signaling"
)]
unsafe extern "C" fn write_ready(context: *mut core::ffi::c_void, _file: *mut core::ffi::c_void) {
    unsafe {
        // SAFETY: The originating work owner retains this event through the nonalertable wait.
        super::ffi::KeSetEvent(context.cast(), 0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ext4_core::FileOffset;

    /// # Panics
    /// Fails if repeated checks are mistaken for repeated callback posting.
    #[test]
    fn checks_and_deferred_postings_have_independent_retry_state() {
        let mut admission = WriteAdmission::new();
        assert!(!admission.checking());
        assert!(admission.checking());
        assert!(!admission.deferring());
        assert!(admission.checking());
        assert!(admission.deferring());
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
