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

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Fails if epoch conversion or the maximum ext4 timestamp loses ticks.
    #[test]
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
        Ok(())
    }
}
