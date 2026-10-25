//! Requested discard preserves physical progress independently of transport and native release.
use super::{FileHandle, control, identity, volume_at_mount};
use ext4_control::TrimReport;
use ext4_core::FilesystemUuid;
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

/// Resolves a filesystem identity without choosing between mounted copies of the same UUID.
/// # Errors
/// Returns not-found for an unmounted UUID and ambiguity for multiple mounted copies.
fn select_volume(
    uuid: FilesystemUuid,
    volumes: Vec<(String, FilesystemUuid)>,
) -> io::Result<String> {
    let mut matching = volumes
        .into_iter()
        .filter(|(_, identity)| *identity == uuid);
    let (volume, _) = matching.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "ext4 filesystem UUID is not mounted",
        )
    })?;
    if matching.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "multiple mounted volumes have this ext4 UUID; select a volume path",
        ));
    }
    Ok(volume)
}

/// Establishes the requested filesystem identity before acquiring discard authority.
/// # Errors
/// Returns path/UUID discovery failures without submitting discard.
fn resolve_target(target: &str) -> io::Result<(String, FilesystemUuid)> {
    match ext4_security::parse_uuid(target) {
        Ok(uuid) => Ok((select_volume(uuid, identity::identity_volumes()?)?, uuid)),
        Err(_) => {
            let uuid = identity::volume_identity(target)?;
            let root = format!("{}\\", target.trim_end_matches('\\'));
            Ok((volume_at_mount(Path::new(&root))?, uuid))
        }
    }
}

/// Submits once through a writable volume handle bound to the requested filesystem identity.
/// # Errors
/// Discovery or same-handle UUID verification fails before submission. Transport/release failure
/// retains acknowledged progress or an unacknowledged submission independently of native cleanup.
fn request(target: &str) -> Result<TrimReport, TrimError> {
    let (device, expected) = resolve_target(target)
        .map_err(|error| TrimError::new(TrimSubmission::NotSubmitted, error))?;
    let file = FileHandle::open(Path::new(device.trim_end_matches('\\')), FILE_WRITE_DATA, 0)
        .map_err(|error| TrimError::new(TrimSubmission::NotSubmitted, error))?;
    let mut bytes = [0; 16];
    let verified = file
        .control(ext4_security::QUERY_VOLUME_IDENTITY_FSCTL, &mut bytes)
        .and_then(|length| {
            if length == bytes.len() && FilesystemUuid::from_bytes(bytes) == expected {
                Ok(())
            } else {
                Err(io::Error::other(
                    "opened volume does not match the requested ext4 UUID",
                ))
            }
        });
    if let Err(source) = verified {
        return Err(TrimError {
            handle_release: file.close().err(),
            ..TrimError::new(TrimSubmission::NotSubmitted, source)
        });
    }
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
/// The target is an ext4 UUID or a drive root, mounted folder or Windows volume GUID. A UUID must
/// name exactly one mounted filesystem. The writable handle is checked against that UUID before
/// submission. Stopped scans return progress; transport success does not imply every batch succeeded.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Fails if UUID selection chooses another filesystem, an absent target, or an ambiguous copy.
    #[test]
    fn filesystem_uuid_selects_exactly_one_mounted_volume() {
        let target = FilesystemUuid::from_bytes([1; 16]);
        let other = FilesystemUuid::from_bytes([2; 16]);
        assert_eq!(
            select_volume(
                target,
                vec![("other".into(), other), ("target".into(), target)]
            )
            .map_err(|error| error.kind()),
            Ok("target".to_owned())
        );
        assert_eq!(
            select_volume(target, vec![("other".into(), other)]).map_err(|e| e.kind()),
            Err(io::ErrorKind::NotFound)
        );
        assert_eq!(
            select_volume(
                target,
                vec![("first".into(), target), ("copy".into(), target)]
            )
            .map_err(|e| e.kind()),
            Err(io::ErrorKind::AlreadyExists)
        );
    }
}
