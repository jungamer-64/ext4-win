//! Kernel time conversion for ext4 mutation timestamps.

use ext4_core::Ext4Timestamp;

use crate::kernel::status::DriverError;

/// Converts the bounded ext4 time domain to Windows ticks, truncating below 100 ns.
pub(crate) fn windows_timestamp(timestamp: Ext4Timestamp) -> i64 {
    timestamp
        .seconds()
        .wrapping_mul(10_000_000)
        .wrapping_add(116_444_736_000_000_000)
        .wrapping_add(i64::from(timestamp.nanoseconds() / 100))
}

/// Converts Windows ticks to signed Unix seconds and fractional time.
/// # Errors
/// Returns invalid parameter outside the ext4 representable time range.
pub(crate) fn ext4_timestamp(ticks: i64) -> Result<Ext4Timestamp, DriverError> {
    let unix = ticks
        .checked_sub(116_444_736_000_000_000)
        .ok_or(DriverError::InvalidParameter)?;
    let nanoseconds = u32::try_from(unix.rem_euclid(10_000_000))
        .map_err(|_| DriverError::InvalidParameter)?
        .checked_mul(100)
        .ok_or(DriverError::InvalidParameter)?;
    Ext4Timestamp::new(unix.div_euclid(10_000_000), nanoseconds)
        .map_err(|_| DriverError::InvalidParameter)
}

/// Returns the current system time as an ext4 inode timestamp.
/// # Errors
///
/// Returns an error when the system time cannot be represented as an ext4 timestamp.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
pub(crate) fn current_ext4_timestamp() -> Result<Ext4Timestamp, DriverError> {
    let mut time = wdk_sys::LARGE_INTEGER { QuadPart: 0 };
    unsafe {
        // SAFETY: `time` points to writable stack storage for the kernel to
        // receive the current system time.
        crate::kernel::ffi::KeQuerySystemTimePrecise(core::ptr::addr_of_mut!(time));
    }
    let ticks = unsafe {
        // SAFETY: KeQuerySystemTimePrecise initialized the LARGE_INTEGER value.
        time.QuadPart
    };
    ext4_timestamp(ticks)
}

/// Monotonic milliseconds shared by MMP events and native permission expiration.
/// This clock is sampled at the callback boundary and never depends on diagnostic UTC time.
#[expect(
    unsafe_code,
    reason = "the synchronous kernel clock call writes only its exact stack output"
)]
pub(crate) fn monotonic_millis() -> u64 {
    let mut counter = 0_u64;
    let ticks = unsafe {
        // SAFETY: `counter` is writable for the complete native output and outlives this call.
        crate::kernel::ffi::KeQueryInterruptTimePrecise(core::ptr::addr_of_mut!(counter))
    };
    ticks / 10_000
}

/// Samples the kernel's boot-relative monotonic clock separately from diagnostic UTC seconds.
/// # Errors
/// Returns an invalid or unrepresentable wall-clock timestamp.
pub(crate) fn mmp_time() -> Result<ext4_core::MmpTime, DriverError> {
    let millis = monotonic_millis();
    let seconds = u64::try_from(current_ext4_timestamp()?.seconds())
        .map_err(|_error| DriverError::InvalidParameter)?;
    Ok(ext4_core::MmpTime::new(millis, seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Fails if epoch conversion or the maximum ext4 timestamp loses ticks.
    /// # Errors
    /// Returns an error if a known-answer timestamp cannot be represented.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "known-answer assertions report test failures while fallible timestamp construction propagates errors"
    )]
    fn windows_time_known_answers() -> Result<(), DriverError> {
        assert_eq!(
            windows_timestamp(Ext4Timestamp::from_seconds(0)),
            116_444_736_000_000_000
        );
        assert_eq!(
            windows_timestamp(Ext4Timestamp::from_seconds(1)),
            116_444_736_010_000_000
        );
        assert_eq!(
            windows_timestamp(Ext4Timestamp::new(i64::from(u32::MAX), 0)?),
            159_394_408_950_000_000
        );
        for (seconds, nanos) in [
            (-1, 999_999_900),
            (2_147_483_648, 100),
            (4_294_967_297, 123_456_700),
            (15_032_385_535, 999_999_900),
        ] {
            let time = Ext4Timestamp::new(seconds, nanos)?;
            assert_eq!(ext4_timestamp(windows_timestamp(time))?, time);
        }
        assert_eq!(
            windows_timestamp(Ext4Timestamp::new(0, 99)?),
            116_444_736_000_000_000
        );
        assert_eq!(ext4_timestamp(i64::MIN), Err(DriverError::InvalidParameter));
        assert_eq!(ext4_timestamp(i64::MAX), Err(DriverError::InvalidParameter));
        Ok(())
    }
}
