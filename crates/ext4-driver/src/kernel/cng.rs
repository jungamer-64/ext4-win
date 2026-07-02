//! Kernel CNG boundary used by fscrypt mount state.

use core::ffi::c_void;

use ext4_core::{Error, FscryptFileNonce, FscryptNonceGenerator, Result as Ext4Result};
use wdk_sys::{NT_SUCCESS, NTSTATUS};

/// Ask CNG to use the system-preferred RNG without opening an algorithm handle.
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

#[link(name = "Cng")]
unsafe extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut c_void,
        buffer: *mut u8,
        buffer_len: u32,
        flags: u32,
    ) -> NTSTATUS;
}

/// fscrypt nonce generator backed by kernel CNG.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CngFscryptNonceGenerator;

impl FscryptNonceGenerator for CngFscryptNonceGenerator {
    fn next_file_nonce(&mut self) -> Ext4Result<FscryptFileNonce> {
        let mut nonce = [0_u8; 16];
        fill_random(&mut nonce)?;
        Ok(FscryptFileNonce::new(nonce))
    }
}

/// Fills a kernel buffer from CNG's system-preferred RNG.
/// # Errors
///
/// Returns an error when `out.len()` exceeds CNG's `u32` buffer length or `BCryptGenRandom` fails.
fn fill_random(out: &mut [u8]) -> Ext4Result<()> {
    let buffer_len = u32::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?;
    let status = unsafe {
        // SAFETY: A null algorithm handle is required with
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG. `out` is a live writable buffer for
        // exactly `buffer_len` bytes during the call.
        BCryptGenRandom(
            core::ptr::null_mut(),
            out.as_mut_ptr(),
            buffer_len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    cng_status_to_core(status)
}

/// Converts CNG NTSTATUS values into the ext4-core failure domain.
/// # Errors
///
/// Returns an error when `status` is not a successful CNG NTSTATUS value.
fn cng_status_to_core(status: NTSTATUS) -> Ext4Result<()> {
    if NT_SUCCESS(status) {
        Ok(())
    } else {
        Err(Error::DeviceIo)
    }
}

#[cfg(test)]
mod tests {
    use ext4_core::Error;
    use wdk_sys::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

    use super::cng_status_to_core;

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn cng_status_mapping_preserves_success_and_io_failure() {
        assert_eq!(cng_status_to_core(STATUS_SUCCESS), Ok(()));
        assert_eq!(
            cng_status_to_core(STATUS_UNSUCCESSFUL),
            Err(Error::DeviceIo)
        );
    }
}
