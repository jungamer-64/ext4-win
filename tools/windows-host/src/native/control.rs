//! Secured administrator transport and independent effect/acknowledgement outcomes.
use super::FileHandle;
use core::ptr;
use ext4_core::FilesystemUuid;
use std::{io, path::Path};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// Transport outcome retaining any authoritative reply or unacknowledged persistent effect.
#[derive(Debug)]
pub enum ControlError<S> {
    /// Failure before request submission.
    Preparation(io::Error),
    /// Query did not return an authoritative observation.
    Query(io::Error),
    /// Replacement was submitted; reconcile before considering a retry.
    Unacknowledged {
        /// Exact configuration identity requiring reconciliation.
        uuid: FilesystemUuid,
        /// Supplied predecessor generation.
        expected_generation: u64,
        /// Native transport or reply validation failure.
        source: io::Error,
    },
    /// Authoritative reply arrived before native handle release failed.
    Release {
        /// The reply remains authoritative despite release failure.
        state: S,
        /// Native release diagnostic.
        source: io::Error,
    },
}
impl<S> core::fmt::Display for ControlError<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Preparation(error) => write!(f, "request was not submitted: {error}"),
            Self::Query(error) => write!(f, "query failed: {error}"),
            Self::Unacknowledged {
                expected_generation,
                source,
                ..
            } => write!(
                f,
                "replacement outcome unknown (expected generation {expected_generation}); query before retrying: {source}"
            ),
            Self::Release { source, .. } => write!(
                f,
                "authoritative reply received, then handle release failed: {source}"
            ),
        }
    }
}
impl<S: core::fmt::Debug> core::error::Error for ControlError<S> {}
/// Submission effect classification fixed before calling the native boundary.
#[derive(Clone, Copy, Debug)]
pub(super) enum Submission {
    /// An observation can reconcile but cannot save a new successor.
    Query,
    /// Whole-record replacement may persist despite communication failure.
    Replacement {
        /// Record's filesystem identity.
        uuid: FilesystemUuid,
        /// Compared predecessor.
        expected_generation: u64,
    },
}
/// Sends one bounded synchronous control; input and output never overlap in Rust.
/// # Errors
/// Returns native submission or reply-bound errors.
pub(super) fn exchange(
    file: &FileHandle,
    code: u32,
    input: &[u8],
    output: &mut [u8],
) -> io::Result<usize> {
    let input_length = u32::try_from(input.len()).map_err(io::Error::other)?;
    let output_length = u32::try_from(output.len()).map_err(io::Error::other)?;
    let mut returned = 0;
    let success = unsafe {
        // SAFETY: The retained handle and disjoint initialized buffers remain valid for this synchronous call.
        DeviceIoControl(
            file.raw()?,
            code,
            input.as_ptr().cast(),
            input_length,
            output.as_mut_ptr().cast(),
            output_length,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    let count = usize::try_from(returned).map_err(io::Error::other)?;
    if count > output.len() {
        return Err(io::Error::other("control returned an excessive length"));
    }
    Ok(count)
}
/// Reads the device name from the driver's authoritative lifecycle contract.
/// # Errors
/// Rejects an incomplete build-time device identity contract.
fn control_path() -> io::Result<&'static str> {
    include_str!("../../../../crates/ext4-driver/lifecycle-control-v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix("win32_device_path="))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other("driver control device identity is missing"))
}

/// Submits one bounded command and retains commit uncertainty separately from native release.
/// # Errors
/// Preserves preparation, query, unacknowledged replacement and post-reply release failure.
pub(super) fn request<S>(
    code: u32,
    input: &[u8],
    output: &mut [u8],
    submission: Submission,
    decode: impl FnOnce(&[u8]) -> io::Result<S>,
) -> Result<S, ControlError<S>> {
    let access = match submission {
        Submission::Query => 0x8000_0000,
        Submission::Replacement { .. } => 0xc000_0000,
    };
    let file = FileHandle::open(
        Path::new(control_path().map_err(ControlError::Preparation)?),
        access,
        0,
    )
    .map_err(ControlError::Preparation)?;
    let result = exchange(&file, code, input, output).and_then(|length| {
        decode(
            output
                .get(..length)
                .ok_or_else(|| io::Error::other("invalid reply length"))?,
        )
    });
    let close = file.close();
    let state = result.map_err(|source| match submission {
        Submission::Query => ControlError::Query(source),
        Submission::Replacement {
            uuid,
            expected_generation,
        } => ControlError::Unacknowledged {
            uuid,
            expected_generation,
            source,
        },
    })?;
    match close {
        Ok(()) => Ok(state),
        Err(source) => Err(ControlError::Release { state, source }),
    }
}
