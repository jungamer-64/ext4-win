//! Directory-bound comparison controls with explicit transport and release outcomes.
use super::{FileHandle, control};
use ext4_core::DirectoryCasefold;
use std::{io, path::Path};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES,
};

/// Directory control failures retain whether a journaled transition may have completed.
#[derive(Debug)]
pub enum DirectoryCasefoldError {
    /// No request was submitted.
    Preparation(io::Error),
    /// No authoritative observation arrived; release failure is retained independently.
    Query {
        /// Transport or reply validation failure.
        source: io::Error,
        /// Native release failure after the failed observation.
        release: Option<io::Error>,
    },
    /// A submitted transition may have committed; observe the directory before retrying.
    Unacknowledged {
        /// Requested comparison state.
        requested: DirectoryCasefold,
        /// Transport failure after submission.
        source: io::Error,
        /// Native release failure after the unacknowledged submission.
        release: Option<io::Error>,
    },
    /// A successful observation or durable transition preceded release failure.
    Release {
        /// Authoritative acknowledged state.
        state: DirectoryCasefold,
        /// Native release diagnostic; it does not revoke the acknowledgement.
        source: io::Error,
    },
}
impl core::fmt::Display for DirectoryCasefoldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Preparation(source) => write!(f, "directory control was not submitted: {source}"),
            Self::Query { source, release } => {
                write!(f, "directory comparison query failed: {source}")?;
                if let Some(release) = release {
                    write!(f, "; handle release also failed: {release}")?;
                }
                Ok(())
            }
            Self::Unacknowledged {
                source, release, ..
            } => {
                write!(
                    f,
                    "directory comparison outcome unknown; use casefold show before retrying: {source}"
                )?;
                if let Some(release) = release {
                    write!(f, "; handle release also failed: {release}")?;
                }
                Ok(())
            }
            Self::Release { source, .. } => write!(
                f,
                "directory state acknowledged, then handle release failed: {source}"
            ),
        }
    }
}
impl core::error::Error for DirectoryCasefoldError {}

/// Selects access and effect classification before any native submission.
#[derive(Clone, Copy, Debug)]
enum DirectoryControl {
    /// Read current committed metadata.
    Query,
    /// Set an empty directory's comparison state through a journaled transition.
    Set(DirectoryCasefold),
}

/// Runs one synchronous directory-bound control and explicitly observes native handle release.
/// # Errors
/// Retains preparation, observation, uncertain effect and acknowledged-state release failures.
fn request(
    path: &Path,
    action: DirectoryControl,
) -> Result<DirectoryCasefold, DirectoryCasefoldError> {
    let access = match action {
        DirectoryControl::Query => FILE_READ_ATTRIBUTES,
        DirectoryControl::Set(_) => FILE_WRITE_ATTRIBUTES,
    };
    let file = FileHandle::open(path, access, FILE_FLAG_BACKUP_SEMANTICS)
        .map_err(DirectoryCasefoldError::Preparation)?;
    let result = match action {
        DirectoryControl::Query => {
            let mut output = [0; ext4_control::CASEFOLD_STATE_BYTES];
            control::exchange(
                &file,
                ext4_control::QUERY_DIRECTORY_CASEFOLD_FSCTL,
                &[],
                &mut output,
            )
            .and_then(|length| {
                ext4_control::decode_casefold(
                    output
                        .get(..length)
                        .ok_or_else(|| io::Error::other("invalid comparison reply length"))?,
                )
                .map_err(|error| io::Error::other(format!("invalid comparison reply: {error:?}")))
            })
        }
        DirectoryControl::Set(state) => control::exchange(
            &file,
            ext4_control::SET_DIRECTORY_CASEFOLD_FSCTL,
            &ext4_control::encode_casefold(state),
            &mut [],
        )
        .map(|_length| state),
    };
    let close = file.close();
    match result {
        Ok(state) => match close {
            Ok(()) => Ok(state),
            Err(source) => Err(DirectoryCasefoldError::Release { state, source }),
        },
        Err(source) => Err(match action {
            DirectoryControl::Query => DirectoryCasefoldError::Query {
                source,
                release: close.err(),
            },
            DirectoryControl::Set(requested) => DirectoryCasefoldError::Unacknowledged {
                requested,
                source,
                release: close.err(),
            },
        }),
    }
}

/// Observes the committed comparison state of the directory selected by `path`.
/// # Errors
/// Retains query failure or an acknowledged state followed by release failure.
pub fn query_directory_casefold(path: &Path) -> Result<DirectoryCasefold, DirectoryCasefoldError> {
    request(path, DirectoryControl::Query)
}
/// Changes comparison state through a retained attribute-write handle; no automatic retry occurs.
/// The filesystem must declare casefold and the directory must be empty at commit preparation.
/// # Errors
/// Retains pre-submission failure, unacknowledged effect or acknowledged-state release failure.
pub fn set_directory_casefold(
    path: &Path,
    state: DirectoryCasefold,
) -> Result<DirectoryCasefold, DirectoryCasefoldError> {
    request(path, DirectoryControl::Set(state))
}
