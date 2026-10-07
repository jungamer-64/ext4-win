//! Windows account resolution and bounded identity-control requests.
use super::{FileHandle, completed, volume_names, wide};
use core::ptr;
use ext4_core::FilesystemUuid;
use ext4_security::{
    CONTROL_REPLY_BYTES, MAX_MAPPING_BYTES, MappingState, QUERY_IDENTITY_IOCTL,
    QUERY_VOLUME_IDENTITY_FSCTL, REPLACE_IDENTITY_IOCTL, Replacement, Sid,
};
use std::{
    ffi::OsStr,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
};
use windows_sys::Win32::{
    Security::*,
    System::{
        IO::DeviceIoControl,
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    },
};

/// Effective token principals used for new inode UID/GID assignment.
#[derive(Clone, Copy, Debug)]
pub struct EffectiveIdentity {
    /// Effective token's user, including thread impersonation.
    pub user: Sid,
    /// Effective token's primary group.
    pub primary_group: Sid,
}
/// Transport failures retain whether an identity replacement may already have committed.
#[derive(Debug)]
pub enum IdentityControlError {
    /// Validation, allocation or handle opening failed before submission.
    Preparation(io::Error),
    /// A query failed without an authoritative state reply.
    Query(io::Error),
    /// Replacement was submitted and requires query reconciliation before any retry.
    Unacknowledged {
        /// Filesystem whose saved/applied generations must be queried.
        uuid: FilesystemUuid,
        /// Generation supplied by the failed request.
        expected_generation: u64,
        /// Native transport or reply decoding failure.
        source: io::Error,
    },
    /// An authoritative reply arrived before release of the native handle failed.
    Release {
        /// Commit facts remain authoritative despite the release failure.
        state: MappingState,
        /// Native handle release diagnostic.
        source: io::Error,
    },
}
impl core::fmt::Display for IdentityControlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Preparation(error) => write!(f, "identity request was not submitted: {error}"),
            Self::Query(error) => write!(f, "identity query failed: {error}"),
            Self::Unacknowledged {
                expected_generation,
                source,
                ..
            } => write!(
                f,
                "replacement outcome unknown (expected generation {expected_generation}); query saved/applied generations before retrying: {source}"
            ),
            Self::Release { state, source } => write!(
                f,
                "identity reply received ({:?}, saved {}, applied {}), then handle release failed: {source}",
                state.outcome, state.saved_generation, state.active.generation
            ),
        }
    }
}
impl core::error::Error for IdentityControlError {}

/// Converts portable validation failures only at the host presentation boundary.
fn invalid(error: ext4_security::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}"))
}
/// Opens the effective token, preserving impersonation and native query errors.
/// # Errors
/// Returns native token-open failures.
fn effective_token() -> io::Result<OwnedHandle> {
    let mut token = ptr::null_mut();
    let thread = unsafe {
        // SAFETY: GetCurrentThread returns a borrowed pseudo handle requiring no release.
        GetCurrentThread()
    };
    let opened = unsafe {
        // SAFETY: Pseudo thread handle is borrowed; native output is initialized writable storage.
        OpenThreadToken(thread, TOKEN_QUERY, 1, &mut token)
    };
    if opened == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(1008) {
            return Err(error);
        }
        let process = unsafe {
            // SAFETY: GetCurrentProcess returns a borrowed pseudo handle requiring no release.
            GetCurrentProcess()
        };
        let opened = unsafe {
            // SAFETY: No thread token exists; the process pseudo handle is borrowed synchronously.
            OpenProcessToken(process, TOKEN_QUERY, &mut token)
        };
        if opened == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if token.is_null() {
        return Err(io::Error::other("native token open returned no handle"));
    }
    Ok(unsafe {
        // SAFETY: Successful native open transfers exactly one live handle to this unique owner.
        OwnedHandle::from_raw_handle(token)
    })
}
/// Copies the selected user/primary-group SID from aligned token-information storage.
/// # Errors
/// Preserves native query failure and rejects malformed returned pointers or SID lengths.
fn token_sid(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Sid> {
    let mut storage = [0_u64; 16];
    let mut length = 0;
    let success = unsafe {
        // SAFETY: Storage is aligned and writable for 128 bytes; the token remains retained.
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            storage.as_mut_ptr().cast(),
            128,
            &mut length,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    if class != TokenUser && class != TokenPrimaryGroup {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported token principal",
        ));
    }
    let sid = unsafe {
        // SAFETY: TOKEN_USER and TOKEN_PRIMARY_GROUP both start with an aligned PSID field.
        // The initialized local storage owns the copied field and the returned SID bytes.
        ptr::read(storage.as_ptr().cast::<PSID>())
    };
    let offset = (sid.addr())
        .checked_sub(storage.as_ptr().addr())
        .ok_or_else(|| io::Error::other("SID precedes token buffer"))?;
    let returned = usize::try_from(length).map_err(io::Error::other)?;
    if returned > 128 || offset.checked_add(8).is_none_or(|end| end > returned) {
        return Err(io::Error::other("SID outside token buffer"));
    }
    let bytes = unsafe {
        // SAFETY: The native output is fully initialized within this stack buffer; no native call overlaps.
        core::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned)
    };
    let remaining = bytes
        .get(offset..)
        .ok_or_else(|| io::Error::other("invalid SID offset"))?;
    let count = usize::from(
        *remaining
            .get(1)
            .ok_or_else(|| io::Error::other("truncated SID"))?,
    );
    let length = count
        .checked_mul(4)
        .and_then(|v| v.checked_add(8))
        .ok_or_else(|| io::Error::other("invalid SID length"))?;
    Sid::parse(
        remaining
            .get(..length)
            .ok_or_else(|| io::Error::other("truncated token SID"))?,
    )
    .map_err(invalid)
}
/// Returns effective user and primary group, suitable for explicit administrator mappings.
/// # Errors
/// Returns native token or SID-validation failures.
pub fn effective_identity() -> io::Result<EffectiveIdentity> {
    let token = effective_token()?;
    Ok(EffectiveIdentity {
        user: token_sid(&token, TokenUser)?,
        primary_group: token_sid(&token, TokenPrimaryGroup)?,
    })
}
/// Resolves account names in user mode; textual SIDs require no account lookup.
/// # Errors
/// Preserves account lookup errors and rejects invalid SID syntax/length.
pub fn resolve_identity(account: &str) -> io::Result<Sid> {
    if account.starts_with("S-") {
        return account.parse().map_err(invalid);
    }
    let account = wide(OsStr::new(account))?;
    let mut sid_len = 0;
    let mut domain_len = 0;
    let mut kind = 0;
    unsafe {
        // SAFETY: Null output buffers request required sizes; account is retained and terminated.
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &mut sid_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        );
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(122) {
        return Err(error);
    }
    if !(8..=68).contains(&sid_len) {
        return Err(io::Error::other("account returned invalid SID length"));
    }
    let mut sid = [0_u32; 17];
    let mut domain = Vec::new();
    let count = usize::try_from(domain_len).map_err(io::Error::other)?;
    domain.try_reserve_exact(count).map_err(io::Error::other)?;
    domain.resize(count, 0_u16);
    let success = unsafe {
        // SAFETY: Aligned SID and domain storage are exclusive and sized by the native size query.
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(sid_len).map_err(io::Error::other)?;
    if length > 68 {
        return Err(io::Error::other("account SID exceeded supplied buffer"));
    }
    let bytes = unsafe {
        // SAFETY: Native output was written into this aligned initialized array and is bounded above.
        core::slice::from_raw_parts(sid.as_ptr().cast::<u8>(), length)
    };
    Sid::parse(bytes).map_err(invalid)
}

/// Queries a mounted ext4 filesystem's core UUID using a direct volume handle.
/// # Errors
/// Returns native mount/control errors or an invalid UUID payload.
pub fn volume_identity(path: &str) -> io::Result<FilesystemUuid> {
    let trimmed = path.trim_end_matches('\\');
    let path = if trimmed.len() == 2 && trimmed.ends_with(':') {
        format!("\\\\.\\{trimmed}")
    } else {
        trimmed.to_owned()
    };
    let file = FileHandle::open(Path::new(&path), 0x80, 0)?;
    let mut bytes = [0_u8; 16];
    let result = file
        .control(QUERY_VOLUME_IDENTITY_FSCTL, &mut bytes)
        .and_then(|length| {
            if length == 16 {
                Ok(FilesystemUuid::from_bytes(bytes))
            } else {
                Err(io::Error::other("invalid filesystem UUID reply"))
            }
        });
    completed(result, file.close())
}
/// Lists mounted ext4 UUIDs with their Windows volume names.
/// # Errors
/// Returns volume enumeration errors; non-ext4 and unavailable volumes are omitted.
pub fn identity_volumes() -> io::Result<Vec<(String, FilesystemUuid)>> {
    let mut volumes = Vec::new();
    for name in volume_names()? {
        if let Ok(uuid) = volume_identity(&name) {
            volumes.push((name, uuid));
        }
    }
    Ok(volumes)
}
/// Sends one bounded synchronous control; input and output never overlap in Rust.
/// # Errors
/// Returns native submission or reply-bound errors.
fn exchange(file: &FileHandle, code: u32, input: &[u8], output: &mut [u8]) -> io::Result<usize> {
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
        return Err(io::Error::other(
            "identity control returned an excessive length",
        ));
    }
    Ok(count)
}
/// Allocates the maximum complete control reply before any replacement submission.
/// # Errors
/// Returns physical allocation failure.
fn reply_buffer() -> io::Result<Vec<u8>> {
    let length = MAX_MAPPING_BYTES
        .checked_add(CONTROL_REPLY_BYTES)
        .ok_or_else(|| io::Error::other("identity reply bound overflow"))?;
    let mut output = Vec::new();
    output.try_reserve_exact(length).map_err(io::Error::other)?;
    output.resize(length, 0);
    Ok(output)
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

/// Queries saved and applied generations without inferring a failed replacement's outcome.
/// # Errors
/// Preserves preparation, query and post-reply native release failures.
pub fn query_identity(uuid: FilesystemUuid) -> Result<MappingState, IdentityControlError> {
    let mut output = reply_buffer().map_err(IdentityControlError::Preparation)?;
    let file = FileHandle::open(
        Path::new(control_path().map_err(IdentityControlError::Preparation)?),
        0x8000_0000,
        0,
    )
    .map_err(IdentityControlError::Preparation)?;
    let result =
        exchange(&file, QUERY_IDENTITY_IOCTL, &uuid.bytes(), &mut output).and_then(|length| {
            MappingState::decode(
                output
                    .get(..length)
                    .ok_or_else(|| io::Error::other("invalid reply length"))?,
            )
            .map_err(invalid)
        });
    let close = file.close();
    let state = result.map_err(IdentityControlError::Query)?;
    match close {
        Ok(()) => Ok(state),
        Err(source) => Err(IdentityControlError::Release { state, source }),
    }
}
/// Replaces the complete table using a generation CAS; no automatic retry is performed.
/// # Errors
/// Submission failures preserve an uncertain effect; callers query before deciding on a retry.
pub fn replace_identity(replacement: Replacement) -> Result<MappingState, IdentityControlError> {
    let bytes = replacement
        .encode()
        .map_err(|error| IdentityControlError::Preparation(invalid(error)))?;
    let mut output = reply_buffer().map_err(IdentityControlError::Preparation)?;
    let file = FileHandle::open(
        Path::new(control_path().map_err(IdentityControlError::Preparation)?),
        0xc000_0000,
        0,
    )
    .map_err(IdentityControlError::Preparation)?;
    let result = exchange(&file, REPLACE_IDENTITY_IOCTL, &bytes, &mut output).and_then(|length| {
        MappingState::decode(
            output
                .get(..length)
                .ok_or_else(|| io::Error::other("invalid reply length"))?,
        )
        .map_err(invalid)
    });
    let close = file.close();
    let state = result.map_err(|source| IdentityControlError::Unacknowledged {
        uuid: replacement.next.uuid,
        expected_generation: replacement.expected_generation,
        source,
    })?;
    match close {
        Ok(()) => Ok(state),
        Err(source) => Err(IdentityControlError::Release { state, source }),
    }
}
