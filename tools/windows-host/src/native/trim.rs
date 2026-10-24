//! Manual discard preserves physical progress independently of transport and native release.
use super::{FileHandle, control, identity, volume_at_mount};
use ext4_control::TrimReport;
use std::{io, path::Path};
use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA;

/// Observable effect classification survives failures of transport or explicit native cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrimSubmission {
    /// No discard request was submitted.
    NotSubmitted,
    /// A request may have executed, but no trustworthy progress reply arrived; do not retry it.
    Unacknowledged,
    /// The driver's physical progress remains authoritative despite a subsequent release failure.
    Acknowledged(TrimReport),
}

/// Administrative failure retains effect knowledge and independent cleanup failures.
#[derive(Debug)]
pub struct TrimError {
    /// Physical outcome knowledge, independent of the native error.
    pub submission: TrimSubmission,
    /// Primary transport, admission or release diagnostic.
    pub source: io::Error,
    /// Additional handle release failure after the primary error.
    pub handle_release: Option<io::Error>,
    /// Additional impersonation reversion failure after the primary error.
    pub privilege_release: Option<io::Error>,
}
impl TrimError {
    /// Establishes a primary failure without discarding any effect classification.
    fn new(submission: TrimSubmission, source: io::Error) -> Self {
        Self {
            submission,
            source,
            handle_release: None,
            privilege_release: None,
        }
    }
}
impl core::fmt::Display for TrimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let outcome = match self.submission {
            TrimSubmission::NotSubmitted => "TRIM was not submitted",
            TrimSubmission::Unacknowledged => "TRIM outcome is unknown; do not retry automatically",
            TrimSubmission::Acknowledged(_) => "TRIM progress acknowledged before cleanup failed",
        };
        write!(f, "{outcome}: {}", self.source)?;
        if let Some(error) = &self.handle_release {
            write!(f, "; handle release also failed: {error}")?;
        }
        if let Some(error) = &self.privilege_release {
            write!(f, "; privilege reversion also failed: {error}")?;
        }
        Ok(())
    }
}
impl core::error::Error for TrimError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Submits once through a writable volume handle and observes its explicit release.
/// # Errors
/// Retains acknowledged progress or unacknowledged submission if transport or release fails.
fn request(volume: &str) -> Result<TrimReport, TrimError> {
    let root = format!("{}\\", volume.trim_end_matches('\\'));
    let device = volume_at_mount(Path::new(&root))
        .map_err(|error| TrimError::new(TrimSubmission::NotSubmitted, error))?;
    let file = FileHandle::open(Path::new(device.trim_end_matches('\\')), FILE_WRITE_DATA, 0)
        .map_err(|error| TrimError::new(TrimSubmission::NotSubmitted, error))?;
    let mut output = [0; ext4_control::TRIM_REPLY_BYTES];
    let result = control::exchange(&file, ext4_control::TRIM_VOLUME_FSCTL, &[], &mut output)
        .and_then(|length| {
            TrimReport::decode(
                output
                    .get(..length)
                    .ok_or_else(|| io::Error::other("invalid TRIM reply length"))?,
            )
            .map_err(|error| io::Error::other(format!("invalid TRIM reply: {error:?}")))
        });
    let close = file.close();
    match result {
        Ok(report) => close
            .map(|()| report)
            .map_err(|error| TrimError::new(TrimSubmission::Acknowledged(report), error)),
        Err(source) => Err(TrimError {
            handle_release: close.err(),
            ..TrimError::new(TrimSubmission::Unacknowledged, source)
        }),
    }
}

/// Discards mounted ext4 free space with private SeManageVolumePrivilege admission and no retry.
/// The path must identify a drive root, mounted folder or volume GUID. Stopped scans return their
/// progress report; transport success does not imply that every batch succeeded.
/// # Errors
/// Preserves no-submission, unknown outcome and acknowledged progress after release failure.
pub fn trim_volume(volume: &str) -> Result<TrimReport, TrimError> {
    let (result, reversion) =
        identity::with_volume_management(|| request(volume)).map_err(|error| match error {
            identity::ManagementFailure::Preparation(source) => {
                TrimError::new(TrimSubmission::NotSubmitted, source)
            }
            identity::ManagementFailure::Unacknowledged(source) => {
                TrimError::new(TrimSubmission::Unacknowledged, source)
            }
        })?;
    match reversion {
        Ok(()) => result,
        Err(source) => Err(match result {
            Ok(report) => TrimError::new(TrimSubmission::Acknowledged(report), source),
            Err(mut error) => {
                error.privilege_release = Some(source);
                error
            }
        }),
    }
}
