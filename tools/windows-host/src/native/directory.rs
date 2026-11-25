//! Directory-bound comparison controls with explicit transport and release outcomes.
use super::{FileHandle, control};
use crate::DirectoryCaseSensitivity;
use ext4_core::DirectoryCasefold;
use std::{io, path::Path};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_CASE_SENSITIVE_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
    FILE_WRITE_ATTRIBUTES, FileCaseSensitiveInfo, GetFileInformationByHandleEx,
    SetFileInformationByHandle,
};

/// Windows `FILE_CS_FLAG_CASE_SENSITIVE_DIR`.
const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 0x0000_0001;

/// Directory state controlled through one directory handle.
pub trait DirectoryControlState: Copy + core::fmt::Debug {
    /// `ext4ctl` command that observes this state before a retry.
    const OBSERVE_COMMAND: &'static str;
}

impl DirectoryControlState for DirectoryCasefold {
    const OBSERVE_COMMAND: &'static str = "casefold show";
}

impl DirectoryControlState for DirectoryCaseSensitivity {
    const OBSERVE_COMMAND: &'static str = "case-sensitive show";
}

/// Directory control failures retain whether a journaled transition may have completed.
#[derive(Debug)]
pub enum DirectoryControlError<S> {
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
        /// Requested state.
        requested: S,
        /// Transport failure after submission.
        source: io::Error,
        /// Native release failure after the unacknowledged submission.
        release: Option<io::Error>,
    },
    /// A successful observation or durable transition preceded release failure.
    Release {
        /// Authoritative acknowledged state.
        state: S,
        /// Native release diagnostic; it does not revoke the acknowledgement.
        source: io::Error,
    },
}
impl<S: DirectoryControlState> core::fmt::Display for DirectoryControlError<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Preparation(source) => write!(f, "directory control was not submitted: {source}"),
            Self::Query { source, release } => {
                write!(f, "directory state query failed: {source}")?;
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
                    "directory state outcome unknown; use {} before retrying: {source}",
                    S::OBSERVE_COMMAND
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
impl<S: DirectoryControlState> core::error::Error for DirectoryControlError<S> {}

/// Selects access and effect classification before any native submission.
#[derive(Clone, Copy, Debug)]
enum DirectoryControl<S> {
    /// Read current committed metadata.
    Query,
    /// Change the directory state through a journaled transition.
    Set(S),
}

/// Runs one synchronous directory-bound control and explicitly observes native handle release.
/// # Errors
/// Retains preparation, observation, uncertain effect and acknowledged-state release failures.
fn request<S: DirectoryControlState>(
    path: &Path,
    action: DirectoryControl<S>,
    exchange: impl FnOnce(&FileHandle, DirectoryControl<S>) -> io::Result<S>,
) -> Result<S, DirectoryControlError<S>> {
    let access = match action {
        DirectoryControl::Query => FILE_READ_ATTRIBUTES,
        DirectoryControl::Set(_) => FILE_WRITE_ATTRIBUTES,
    };
    let file = FileHandle::open(path, access, FILE_FLAG_BACKUP_SEMANTICS)
        .map_err(DirectoryControlError::Preparation)?;
    let result = exchange(&file, action);
    let close = file.close();
    match result {
        Ok(state) => match close {
            Ok(()) => Ok(state),
            Err(source) => Err(DirectoryControlError::Release { state, source }),
        },
        Err(source) => Err(match action {
            DirectoryControl::Query => DirectoryControlError::Query {
                source,
                release: close.err(),
            },
            DirectoryControl::Set(requested) => DirectoryControlError::Unacknowledged {
                requested,
                source,
                release: close.err(),
            },
        }),
    }
}

/// Exchanges ext4 casefold state through the driver's directory controls.
/// # Errors
/// Returns transport or reply validation failures.
fn casefold_exchange(
    file: &FileHandle,
    action: DirectoryControl<DirectoryCasefold>,
) -> io::Result<DirectoryCasefold> {
    match action {
        DirectoryControl::Query => {
            let mut output = [0; ext4_control::CASEFOLD_STATE_BYTES];
            let length = control::exchange(
                file,
                ext4_control::QUERY_DIRECTORY_CASEFOLD_FSCTL,
                &[],
                &mut output,
            )?;
            ext4_control::decode_casefold(
                output
                    .get(..length)
                    .ok_or_else(|| io::Error::other("invalid comparison reply length"))?,
            )
            .map_err(|error| io::Error::other(format!("invalid comparison reply: {error:?}")))
        }
        DirectoryControl::Set(state) => control::exchange(
            file,
            ext4_control::SET_DIRECTORY_CASEFOLD_FSCTL,
            &ext4_control::encode_casefold(state),
            &mut [],
        )
        .map(|_length| state),
    }
}

/// Exchanges Windows case sensitivity through `FileCaseSensitiveInfo`.
/// # Errors
/// Returns native failures or a reply carrying undefined flags.
fn case_sensitivity_exchange(
    file: &FileHandle,
    action: DirectoryControl<DirectoryCaseSensitivity>,
) -> io::Result<DirectoryCaseSensitivity> {
    let handle = file.raw()?;
    let size = u32::try_from(size_of::<FILE_CASE_SENSITIVE_INFO>()).map_err(io::Error::other)?;
    match action {
        DirectoryControl::Query => {
            let mut info = FILE_CASE_SENSITIVE_INFO::default();
            let success = unsafe {
                // SAFETY: The retained handle and the initialized record outlive this
                // synchronous call, and `size` is the record's exact byte length.
                GetFileInformationByHandleEx(
                    handle,
                    FileCaseSensitiveInfo,
                    (&raw mut info).cast(),
                    size,
                )
            };
            if success == 0 {
                return Err(io::Error::last_os_error());
            }
            match info.Flags {
                0 => Ok(DirectoryCaseSensitivity::Disabled),
                FILE_CS_FLAG_CASE_SENSITIVE_DIR => Ok(DirectoryCaseSensitivity::Enabled),
                flags => Err(io::Error::other(format!(
                    "invalid case-sensitivity reply flags {flags:#x}"
                ))),
            }
        }
        DirectoryControl::Set(state) => {
            let info = FILE_CASE_SENSITIVE_INFO {
                Flags: match state {
                    DirectoryCaseSensitivity::Disabled => 0,
                    DirectoryCaseSensitivity::Enabled => FILE_CS_FLAG_CASE_SENSITIVE_DIR,
                },
            };
            let success = unsafe {
                // SAFETY: The retained handle and the initialized record outlive this
                // synchronous call, and `size` is the record's exact byte length.
                SetFileInformationByHandle(
                    handle,
                    FileCaseSensitiveInfo,
                    (&raw const info).cast(),
                    size,
                )
            };
            if success == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(state)
        }
    }
}

/// Observes the committed comparison state of the directory selected by `path`.
/// # Errors
/// Retains query failure or an acknowledged state followed by release failure.
pub fn query_directory_casefold(
    path: &Path,
) -> Result<DirectoryCasefold, DirectoryControlError<DirectoryCasefold>> {
    request(path, DirectoryControl::Query, casefold_exchange)
}
/// Changes comparison state through a retained attribute-write handle; no automatic retry occurs.
/// The filesystem must declare casefold and the directory must be empty at commit preparation.
/// # Errors
/// Retains pre-submission failure, unacknowledged effect or acknowledged-state release failure.
pub fn set_directory_casefold(
    path: &Path,
    state: DirectoryCasefold,
) -> Result<DirectoryCasefold, DirectoryControlError<DirectoryCasefold>> {
    request(path, DirectoryControl::Set(state), casefold_exchange)
}

/// Observes the Windows case sensitivity of the directory selected by `path`.
/// # Errors
/// Retains query failure or an acknowledged state followed by release failure.
pub fn query_directory_case_sensitivity(
    path: &Path,
) -> Result<DirectoryCaseSensitivity, DirectoryControlError<DirectoryCaseSensitivity>> {
    request(path, DirectoryControl::Query, case_sensitivity_exchange)
}
/// Changes Windows case sensitivity through a retained attribute-write handle; no automatic retry
/// occurs. The directory must be empty unless it already has the requested state.
/// # Errors
/// Retains pre-submission failure, unacknowledged effect or acknowledged-state release failure.
pub fn set_directory_case_sensitivity(
    path: &Path,
    state: DirectoryCaseSensitivity,
) -> Result<DirectoryCaseSensitivity, DirectoryControlError<DirectoryCaseSensitivity>> {
    request(
        path,
        DirectoryControl::Set(state),
        case_sensitivity_exchange,
    )
}
