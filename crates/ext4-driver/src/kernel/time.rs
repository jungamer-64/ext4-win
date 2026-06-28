//! Kernel time conversion for ext4 mutation timestamps.

use ext4_core::Ext4Timestamp;

use crate::kernel::status::DriverError;

/// Returns the current system time as an ext4 inode timestamp.
pub(crate) fn current_ext4_timestamp() -> Result<Ext4Timestamp, DriverError> {
    let mut time = wdk_sys::LARGE_INTEGER { QuadPart: 0 };
    unsafe {
        // SAFETY: `time` points to writable stack storage for the kernel to
        // receive the current system time.
        crate::kernel::ffi::KeQuerySystemTimePrecise(core::ptr::addr_of_mut!(time));
    }
    let mut seconds: wdk_sys::ULONG = 0;
    let converted = unsafe {
        // SAFETY: Both pointers reference writable stack storage valid for the
        // duration of the conversion call.
        crate::kernel::ffi::RtlTimeToSecondsSince1970(
            core::ptr::addr_of_mut!(time),
            core::ptr::addr_of_mut!(seconds),
        )
    };
    if converted == 0 {
        return Err(DriverError::InvalidParameter);
    }
    Ok(Ext4Timestamp::from_unix_seconds(seconds))
}
