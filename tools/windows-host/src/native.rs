//! Exclusive owner of user-mode Windows ABI calls, checked buffers and native release.
use core::ptr;
use std::{
    ffi::{OsStr, OsString},
    io,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, IntoRawHandle},
    },
    path::{Path, PathBuf},
    time::Instant,
};
use windows_sys::{
    Wdk::Storage::FileSystem::{
        NtQueryDirectoryFile, NtQueryInformationFile, NtQueryVolumeInformationFile,
    },
    Win32::{
        Devices::DeviceAndDriverInstallation::SetupGetInfDriverStoreLocationW,
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, UNICODE_STRING},
        Security::{CheckTokenMembership, CreateWellKnownSid, WinBuiltinAdministratorsSid},
        Storage::FileSystem::*,
        System::{
            IO::{DeviceIoControl, IO_STATUS_BLOCK},
            Registry::*,
            Services::*,
        },
    },
};

/// Observes bytes available on a borrowed child-output pipe without blocking for EOF.
///
/// Closing a requester need not close pipe handles inherited by another process. Callers can
/// therefore drain currently available diagnostics and finalize without waiting on descendants.
/// # Errors
/// Returns native observation failures; a broken pipe has no remaining available bytes.
pub fn pipe_bytes_available(pipe: &impl AsRawHandle) -> io::Result<u32> {
    let mut available = 0;
    let success = unsafe {
        // SAFETY: the handle is borrowed for the synchronous call; only the initialized
        // scalar output is supplied, and no buffer or pointer is retained.
        windows_sys::Win32::System::Pipes::PeekNamedPipe(
            pipe.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut available,
            ptr::null_mut(),
        )
    };
    if success != 0 {
        Ok(available)
    } else {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(109) {
            Ok(0)
        } else {
            Err(error)
        }
    }
}

/// Encodes one NUL-terminated Windows boundary string, rejecting embedded NULs.
/// # Errors
/// Returns invalid input when the string contains an embedded NUL.
pub(crate) fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "embedded NUL in Windows path",
        ));
    }
    value.push(0);
    Ok(value)
}
/// Decodes the initialized prefix of a NUL-terminated Windows output buffer.
pub(crate) fn decode(value: &[u16]) -> OsString {
    OsString::from_wide(
        &value
            .iter()
            .copied()
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>(),
    )
}
/// Preserves a Win32 error code in the OS error representation.
/// # Errors
/// Returns the native error for a nonzero status.
pub(crate) fn win32(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code.cast_signed()))
    }
}
/// Validates a fixed output record field.
/// # Errors
/// Returns truncated or overflowing native output errors.
fn field<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| io::Error::other("native field overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| io::Error::other("truncated native output"))?
        .try_into()
        .map_err(io::Error::other)
}

/// An exclusively owned synchronous file/device handle; no raw handle escapes this crate.
#[derive(Debug)]
struct FileHandle {
    /// Native handle not yet consumed by explicit close.
    raw: Option<HANDLE>,
}
impl FileHandle {
    /// Opens exactly the requested access domain with shared read/write/delete.
    /// # Errors
    /// Returns invalid path or Windows open errors.
    fn open(path: &Path, access: u32, flags: u32) -> io::Result<Self> {
        let path = wide(path.as_os_str())?;
        let raw = unsafe {
            // SAFETY: path is NUL-terminated and alive for this synchronous call; no borrowed
            // security, template, or overlapped storage is supplied.
            CreateFileW(
                path.as_ptr(),
                access,
                7,
                ptr::null(),
                OPEN_EXISTING,
                flags,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { raw: Some(raw) })
        }
    }
    /// Borrows the live native handle for a synchronous call in this module.
    /// # Errors
    /// Returns an error after close has consumed the handle.
    fn raw(&self) -> io::Result<HANDLE> {
        self.raw
            .ok_or_else(|| io::Error::other("file handle already closed"))
    }
    /// Observes native release failure at the operation's explicit completion boundary.
    /// # Errors
    /// Returns a close failure; the old authority has been consumed even on failure.
    fn close(mut self) -> io::Result<()> {
        if let Some(raw) = self.raw.take() {
            let success = unsafe {
                // SAFETY: this owner uniquely consumes a live CreateFile handle.
                CloseHandle(raw)
            };
            if success == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    /// Executes a payload-free or bounded-output synchronous device control operation.
    /// # Errors
    /// Returns Windows control failure, length overflow, or invalid returned length.
    fn control(&self, code: u32, output: &mut [u8]) -> io::Result<usize> {
        let length = u32::try_from(output.len()).map_err(io::Error::other)?;
        let raw = self.raw()?;
        let mut returned = 0;
        let buffer = if output.is_empty() {
            ptr::null_mut()
        } else {
            output.as_mut_ptr().cast()
        };
        let success = unsafe {
            // SAFETY: the exclusively borrowed output is valid for length bytes, the handle
            // remains alive, and this synchronous request retains no pointers after return.
            DeviceIoControl(
                raw,
                code,
                ptr::null(),
                0,
                buffer,
                length,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if success == 0 {
            return Err(io::Error::last_os_error());
        }
        let returned = usize::try_from(returned).map_err(io::Error::other)?;
        if returned > output.len() {
            return Err(io::Error::other(
                "native control returned an excessive length",
            ));
        }
        Ok(returned)
    }
}
impl Drop for FileHandle {
    /// Releases an abandoned handle; normal operation observes close through the explicit method.
    fn drop(&mut self) {
        if let Some(raw) = self.raw.take() {
            let success = unsafe {
                // SAFETY: take consumes this owner's only live handle.
                CloseHandle(raw)
            };
            if success == 0 {
                eprintln!(
                    "fallback handle close failed: {}",
                    io::Error::last_os_error()
                );
            }
        }
    }
}
/// Combines a native operation with its required handle release.
/// # Errors
/// Preserves both failures if the operation and close fail.
fn completed<T>(result: io::Result<T>, close: io::Result<()>) -> io::Result<T> {
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(close)) => Err(io::Error::other(format!(
            "operation: {operation}; close: {close}"
        ))),
    }
}

/// One read-only native volume information result, including failure status and exact bytes.
#[derive(Debug)]
pub struct VolumeQuery {
    /// File-system information class name.
    pub name: &'static str,
    /// Native information class value.
    pub number: i32,
    /// Native status; a failed class does not erase successful preceding classes.
    pub status: i32,
    /// Initialized bytes returned by Windows.
    pub data: Vec<u8>,
    /// Synchronous call latency; there is no kernel-operation cancellation claim.
    pub milliseconds: f64,
}
/// Reads native volume identity, allocation and sector classes through an attribute-only handle.
/// # Errors
/// Returns open, malformed length, or explicit handle-release failures.
pub fn volume_information(path: &Path) -> io::Result<Vec<VolumeQuery>> {
    let file = FileHandle::open(path, 0x80, FILE_FLAG_BACKUP_SEMANTICS)?;
    let result = (|| {
        let mut records = Vec::new();
        for (name, number) in [
            ("volume", 1),
            ("size", 3),
            ("device", 4),
            ("attributes", 5),
            ("full-size", 7),
            ("sector-size", 11),
        ] {
            let mut data = vec![0_u8; 4096];
            let mut status_block = IO_STATUS_BLOCK::default();
            let raw = file.raw()?;
            let start = Instant::now();
            let status = unsafe {
                // SAFETY: the synchronous attribute handle and both output buffers outlive the
                // query; ntdll writes at most the supplied 4096 bytes.
                NtQueryVolumeInformationFile(
                    raw,
                    &mut status_block,
                    data.as_mut_ptr().cast(),
                    4096,
                    number,
                )
            };
            if status_block.Information > data.len() {
                return Err(io::Error::other("native volume length exceeds buffer"));
            }
            data.truncate(status_block.Information);
            records.push(VolumeQuery {
                name,
                number,
                status,
                data,
                milliseconds: start.elapsed().as_secs_f64() * 1000.0,
            });
        }
        Ok(records)
    })();
    completed(result, file.close())
}

/// Configured service facts; these identify the image on disk, not kernel memory.
#[derive(Debug)]
pub struct ServiceConfiguration {
    /// Service type from the registry.
    pub kind: u32,
    /// Configured start policy.
    pub start: u32,
    /// Raw explicit ImagePath, retained for identity comparison.
    pub image: String,
}
/// Reads one service registry field with native type checking and without environment expansion.
/// # Errors
/// Returns registry lookup, data type, or output-boundary errors.
fn registry(key: &[u16], name: &str, flags: u32) -> io::Result<Vec<u8>> {
    let name = wide(OsStr::new(name))?;
    let mut size = 0;
    let status = unsafe {
        // SAFETY: key/name remain terminated and valid; null output requests size only.
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            flags | RRF_NOEXPAND,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        )
    };
    win32(status)?;
    let mut bytes = vec![0_u8; usize::try_from(size).map_err(io::Error::other)?];
    let status = unsafe {
        // SAFETY: output storage has the queried size and exclusive mutation authority.
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            flags | RRF_NOEXPAND,
            ptr::null_mut(),
            bytes.as_mut_ptr().cast(),
            &mut size,
        )
    };
    win32(status)?;
    if usize::try_from(size).map_err(io::Error::other)? > bytes.len() {
        return Err(io::Error::other("registry length exceeded allocation"));
    }
    bytes.truncate(usize::try_from(size).map_err(io::Error::other)?);
    Ok(bytes)
}
/// Reads an explicit, type-checked service ImagePath and policy.
/// # Errors
/// Returns malformed names, absent services, registry errors or invalid UTF-16.
pub fn service_configuration(name: &str) -> io::Result<ServiceConfiguration> {
    let key = service_key(name)?;
    let kind = u32::from_le_bytes(field(&registry(&key, "Type", RRF_RT_REG_DWORD)?, 0)?);
    let start = u32::from_le_bytes(field(&registry(&key, "Start", RRF_RT_REG_DWORD)?, 0)?);
    let bytes = registry(&key, "ImagePath", RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ)?;
    if bytes.len() % 2 != 0 {
        return Err(io::Error::other("malformed registry UTF-16"));
    }
    let units: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let image = decode(&units)
        .into_string()
        .map_err(|_| io::Error::other("service ImagePath is not valid Unicode"))?;
    if image.is_empty() {
        return Err(io::Error::other("driver has no explicit ImagePath"));
    }
    Ok(ServiceConfiguration { kind, start, image })
}

/// Establishes one service-key name without permitting arbitrary registry traversal.
/// # Errors
/// Returns empty, malformed or NUL-containing service names.
fn service_key(name: &str) -> io::Result<Vec<u16>> {
    if name.is_empty()
        || !name
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, '_' | '.' | '-'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected one service name",
        ));
    }
    wide(OsStr::new(&format!(
        "SYSTEM\\CurrentControlSet\\Services\\{name}"
    )))
}

/// Distinguishes registry-key absence from an incomplete service or a failed observation.
/// # Errors
/// Returns access, native open or close failures; only key-not-found establishes absence.
pub fn service_registered(name: &str) -> io::Result<bool> {
    let key = service_key(name)?;
    let mut handle = ptr::null_mut();
    let status = unsafe {
        // SAFETY: the key is terminated and valid for the synchronous call and output
        // handle storage is exclusively borrowed. No callback or data is retained.
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut handle,
        )
    };
    if matches!(status, 2 | 3) {
        return Ok(false);
    }
    win32(status)?;
    let status = unsafe {
        // SAFETY: this function uniquely consumes the successful RegOpenKeyExW handle.
        RegCloseKey(handle)
    };
    win32(status)?;
    Ok(true)
}

/// Resolves the explicit native/system-root service spelling into an absolute Windows path.
/// # Errors
/// Returns missing variables, ambiguous relative paths, or invalid input.
pub fn driver_path(raw: &str) -> io::Result<PathBuf> {
    let mut expanded = String::new();
    let mut remaining = raw.trim().trim_matches('"');
    while let Some((before, tail)) = remaining.split_once('%') {
        expanded.push_str(before);
        let (variable, rest) = tail
            .split_once('%')
            .ok_or_else(|| io::Error::other("unclosed ImagePath environment variable"))?;
        expanded.push_str(&std::env::var(variable).map_err(io::Error::other)?);
        remaining = rest;
    }
    expanded.push_str(remaining);
    let root =
        std::env::var_os("SystemRoot").ok_or_else(|| io::Error::other("SystemRoot absent"))?;
    let path = if expanded.to_ascii_lowercase().starts_with("\\systemroot\\") {
        PathBuf::from(root).join(
            expanded
                .get(12..)
                .ok_or_else(|| io::Error::other("invalid SystemRoot path"))?,
        )
    } else if let Some(value) = expanded.strip_prefix("\\??\\") {
        PathBuf::from(value)
    } else if expanded.to_ascii_lowercase().starts_with("system32\\") {
        PathBuf::from(root).join(expanded)
    } else {
        PathBuf::from(expanded)
    };
    if !path.is_absolute() {
        return Err(io::Error::other(
            "driver ImagePath must resolve to an absolute path",
        ));
    }
    Ok(path)
}

/// Queries SCM state; absence is distinct from a failed query.
/// # Errors
/// Returns native manager, service-query, or handle-release failures.
pub fn service_state(name: &str) -> io::Result<Option<u32>> {
    let name = wide(OsStr::new(name))?;
    let manager = unsafe {
        // SAFETY: null local-machine/database selectors need no storage, query-only access.
        OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT)
    };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = unsafe {
        // SAFETY: manager remains live and the terminated service name outlives the call.
        OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS)
    };
    let open_error = if service.is_null() {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    let closed = unsafe {
        // SAFETY: this function exclusively owns and consumes the manager handle.
        CloseServiceHandle(manager)
    };
    if service.is_null() {
        if closed == 0 {
            return Err(io::Error::last_os_error());
        }
        return match open_error {
            Some(error) if error.raw_os_error() == Some(1060) => Ok(None),
            Some(error) => Err(error),
            None => Err(io::Error::other("missing SCM outcome")),
        };
    }
    let mut status = SERVICE_STATUS::default();
    let queried = unsafe {
        // SAFETY: service is live, query-only, and status is fully writable native layout.
        QueryServiceStatus(service, &mut status)
    };
    let result = if queried == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Some(status.dwCurrentState))
    };
    let closed_service = unsafe {
        // SAFETY: this function exclusively owns and consumes the service handle.
        CloseServiceHandle(service)
    };
    let close = if closed_service == 0 {
        Err(io::Error::last_os_error())
    } else if closed == 0 {
        Err(io::Error::other("SCM manager close failed"))
    } else {
        Ok(())
    };
    completed(result, close)
}

/// Confirms effective administrator membership before lifecycle or storage mutation.
/// # Errors
/// Returns native membership failure or permission denial.
pub fn require_administrator() -> io::Result<()> {
    let mut sid = [0_u64; 16];
    let mut size = 128;
    let created = unsafe {
        // SAFETY: aligned writable SID storage has the supplied size; no domain SID is used.
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut member = 0;
    let checked = unsafe {
        // SAFETY: a complete well-known SID was constructed; null token selects the current token.
        CheckTokenMembership(ptr::null_mut(), sid.as_ptr().cast_mut().cast(), &mut member)
    };
    if checked == 0 {
        return Err(io::Error::last_os_error());
    }
    if member == 0 {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "an elevated administrator process is required",
        ))
    } else {
        Ok(())
    }
}

/// Publishes a previously flushed phase file with the Windows write-through move boundary.
/// # Errors
/// Returns a publication failure. Recovery must inspect committed phase files; an error alone
/// does not establish that the filename was never published.
pub fn publish_phase(staged: &Path, final_path: &Path) -> io::Result<()> {
    let staged = wide(staged.as_os_str())?;
    let final_path = wide(final_path.as_os_str())?;
    let moved = unsafe {
        // SAFETY: both independent terminated paths outlive the synchronous call; no replacement is requested.
        MoveFileExW(staged.as_ptr(), final_path.as_ptr(), MOVEFILE_WRITE_THROUGH)
    };
    if moved == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Resolves an OEM INF to its authoritative DriverStore directory through SetupAPI.
/// # Errors
/// Returns malformed OEM names or native mapping failures.
pub fn driver_store_image(oem: &str) -> io::Result<PathBuf> {
    let number = oem
        .strip_prefix("oem")
        .and_then(|value| value.strip_suffix(".inf"))
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| io::Error::other("invalid OEM INF name"))?;
    let _validated_number = number;
    let root =
        std::env::var_os("SystemRoot").ok_or_else(|| io::Error::other("SystemRoot absent"))?;
    let inf = wide(PathBuf::from(root).join("INF").join(oem).as_os_str())?;
    let mut output = vec![0_u16; 32768];
    let mut required = 0;
    let success = unsafe {
        // SAFETY: terminated INF and exclusive UTF-16 output remain live; no optional platform pointers are supplied.
        SetupGetInfDriverStoreLocationW(
            inf.as_ptr(),
            ptr::null(),
            ptr::null(),
            output.as_mut_ptr(),
            32768,
            &mut required,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    let path = PathBuf::from(decode(&output));
    if !path
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("ext4win.inf"))
    {
        return Err(io::Error::other(
            "OEM INF resolves to a different original INF",
        ));
    }
    Ok(path
        .parent()
        .ok_or_else(|| io::Error::other("DriverStore INF has no directory"))?
        .join("ext4win.sys"))
}

/// Observable control-retirement acknowledgement; absence requires separate SCM reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retirement {
    /// The control request completed and the alias was withdrawn.
    Retired,
    /// A prior request may have retired the endpoint; this does not prove driver unload.
    EndpointAbsent,
}
/// Consumes the secured control endpoint's payload-free prepare-unload request.
/// # Errors
/// Returns native request/release or alias-withdrawal errors. The request may already have
/// committed when an error is observed; callers reconcile through SCM before retry or removal.
pub fn prepare_unload(path: &Path, code: u32) -> io::Result<Retirement> {
    let file = match FileHandle::open(path, 0x4000_0000, FILE_ATTRIBUTE_NORMAL) {
        Ok(file) => file,
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => {
            return Ok(Retirement::EndpointAbsent);
        }
        Err(error) => return Err(error),
    };
    let result = file.control(code, &mut []).and_then(|returned| {
        if returned == 0 {
            Ok(())
        } else {
            Err(io::Error::other("control retirement returned a payload"))
        }
    });
    completed(result, file.close())?;
    let path = path
        .as_os_str()
        .to_str()
        .and_then(|path| path.strip_prefix("\\\\.\\"))
        .ok_or_else(|| io::Error::other("invalid control device path"))?;
    let path = wide(OsStr::new(path))?;
    let mut buffer = vec![0_u16; 32768];
    let length = unsafe {
        // SAFETY: input and writable output have the supplied native lifetime and capacity.
        QueryDosDeviceW(path.as_ptr(), buffer.as_mut_ptr(), 32768)
    };
    if length != 0 {
        return Err(io::Error::other(
            "prepare-unload left the control alias published",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(2) {
        return Err(error);
    }
    Ok(Retirement::Retired)
}

/// Independent GPT identity and byte extent used to constrain volume discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionIdentity {
    /// Current Windows disk number, revalidated against the disk unique ID by the owner.
    pub disk: u32,
    /// Byte offset of the session partition.
    pub offset: u64,
    /// Byte length of the session partition.
    pub length: u64,
    /// Native-layout GUID bytes of the independently recorded GPT partition ID.
    pub guid: [u8; 16],
}
/// Parses a canonical GUID into Windows native field byte order.
/// # Errors
/// Returns invalid GUID syntax or overflowing fields.
pub fn guid_bytes(value: &str) -> io::Result<[u8; 16]> {
    let value = value.trim_matches(['{', '}']);
    let components: Vec<_> = value.split('-').collect();
    let [a, b, c, d, e] = components.as_slice() else {
        return Err(io::Error::other("invalid GUID"));
    };
    if [a.len(), b.len(), c.len(), d.len(), e.len()] != [8, 4, 4, 4, 12] {
        return Err(io::Error::other("invalid GUID"));
    }
    let mut result = Vec::new();
    result.extend(
        u32::from_str_radix(a, 16)
            .map_err(io::Error::other)?
            .to_le_bytes(),
    );
    result.extend(
        u16::from_str_radix(b, 16)
            .map_err(io::Error::other)?
            .to_le_bytes(),
    );
    result.extend(
        u16::from_str_radix(c, 16)
            .map_err(io::Error::other)?
            .to_le_bytes(),
    );
    let tail = format!("{d}{e}");
    for pair in tail.as_bytes().as_chunks::<2>().0 {
        result.push(
            u8::from_str_radix(core::str::from_utf8(pair).map_err(io::Error::other)?, 16)
                .map_err(io::Error::other)?,
        );
    }
    result
        .try_into()
        .map_err(|_| io::Error::other("invalid GUID byte length"))
}

/// Mount state observed independently during interrupted-session recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountState {
    /// Device path has retired.
    Absent,
    /// Identifiable device rejects mounted access.
    Dismounted,
    /// Filesystem is currently mounted.
    Mounted,
}
/// Maps only the native states establishing absence or logical dismount.
/// # Errors
/// Returns all other native failures unchanged.
fn mount_error(error: io::Error) -> io::Result<MountState> {
    match error.raw_os_error() {
        Some(2 | 3) => Ok(MountState::Absent),
        Some(21 | 1005) => Ok(MountState::Dismounted),
        _ => Err(error),
    }
}
/// Queries mounted state rather than assuming a failed repeated dismount means success.
/// # Errors
/// Returns unmodeled native states, invalid control output, or close failures.
pub fn mount_state(volume: &str) -> io::Result<MountState> {
    let file = match FileHandle::open(Path::new(volume.trim_end_matches('\\')), 0x8000_0000, 0) {
        Ok(file) => file,
        Err(error) => return mount_error(error),
    };
    let state = match file.control(0x0009_0028, &mut []) {
        Ok(0) => Ok(MountState::Mounted),
        Ok(_) => Err(io::Error::other("mounted-state control returned a payload")),
        Err(error) => mount_error(error),
    };
    completed(state, file.close())
}

/// Enumerates volume names while owning the native enumeration handle through explicit finish.
/// # Errors
/// Returns native enumeration or release errors.
pub fn volume_names() -> io::Result<Vec<String>> {
    let mut buffer = vec![0_u16; 1024];
    let search = unsafe {
        // SAFETY: the output buffer is exclusive and has 1024 initialized UTF-16 units.
        FindFirstVolumeW(buffer.as_mut_ptr(), 1024)
    };
    if search == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut names = Vec::new();
        loop {
            names.push(
                decode(&buffer)
                    .into_string()
                    .map_err(|_| io::Error::other("invalid volume name"))?,
            );
            let more = unsafe {
                // SAFETY: the live search handle and exclusive buffer retain the enumeration contract.
                FindNextVolumeW(search, buffer.as_mut_ptr(), 1024)
            };
            if more == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(18) {
                    return Err(error);
                }
                return Ok(names);
            }
        }
    })();
    let closed = unsafe {
        // SAFETY: enumeration has ended and this function uniquely consumes the search handle.
        FindVolumeClose(search)
    };
    completed(
        result,
        if closed == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        },
    )
}
/// Finds a unique volume by its exact disk extent and GPT identity without mounting it.
///
/// Volumes whose identity controls cannot be queried are not admitted. `None` means no fully
/// checked candidate was observed; it does not establish device absence or authorize detachment.
/// # Errors
/// Returns enumeration, conflicting identity, or native release errors.
pub fn find_volume(identity: &PartitionIdentity) -> io::Result<Option<String>> {
    let mut found = None;
    for name in volume_names()? {
        let file = match FileHandle::open(Path::new(name.trim_end_matches('\\')), 0, 0) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let matched = (|| {
            let mut extents = [0_u8; 32];
            if file.control(0x0056_0000, &mut extents).ok() != Some(32) {
                return Ok(false);
            }
            if u32::from_le_bytes(field(&extents, 0)?) != 1
                || u32::from_le_bytes(field(&extents, 8)?) != identity.disk
                || u64::from_le_bytes(field(&extents, 16)?) != identity.offset
                || u64::from_le_bytes(field(&extents, 24)?) != identity.length
            {
                return Ok(false);
            }
            let mut partition = [0_u8; 144];
            if file.control(0x0007_0048, &mut partition).ok() != Some(144) {
                return Ok(false);
            }
            Ok(u32::from_le_bytes(field(&partition, 0)?) == 1
                && field::<16>(&partition, 48)? == identity.guid)
        })();
        if completed(matched, file.close())? {
            if found.is_some() {
                return Err(io::Error::other(
                    "multiple volume names match the session partition",
                ));
            }
            found = Some(name);
        }
    }
    Ok(found)
}

/// Reads the exact Mount Manager target of one generated directory mount point.
/// # Errors
/// Returns Windows lookup or invalid output errors.
pub fn volume_at_mount(path: &Path) -> io::Result<String> {
    let path = wide(path.as_os_str())?;
    let mut buffer = vec![0_u16; 1024];
    let success = unsafe {
        // SAFETY: the terminated mount path and exclusive output remain live synchronously.
        GetVolumeNameForVolumeMountPointW(path.as_ptr(), buffer.as_mut_ptr(), 1024)
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    decode(&buffer)
        .into_string()
        .map_err(|_| io::Error::other("invalid volume name"))
}

/// Verifies allocation reservation without EOF growth, release, and allocation below written EOF.
/// The supplied fixture must be an empty regular file.
/// # Errors
/// Returns native allocation/write/query/flush failures, contract disagreement, or close failure.
pub fn verify_allocation_control(path: &Path) -> io::Result<()> {
    let file = FileHandle::open(path, 0x4000_0080, 0)?;
    let result = (|| {
        for bound in [32_768, 0] {
            set_file_allocation(&file, bound)?;
            let standard = file_information_query(&file, 5, 24, 0)?;
            let allocation = i64::from_le_bytes(field(&standard, 0)?);
            let eof = i64::from_le_bytes(field(&standard, 8)?);
            if eof != 0 || allocation < bound || (bound == 0 && allocation != 0) {
                return Err(io::Error::other(
                    "allocation reservation changed EOF or failed to resize",
                ));
            }
        }
        write_and_flush_byte(&file)?;
        set_file_allocation(&file, 0)?;
        let standard = file_information_query(&file, 5, 24, 0)?;
        if i64::from_le_bytes(field(&standard, 0)?) != 0
            || i64::from_le_bytes(field(&standard, 8)?) != 0
        {
            return Err(io::Error::other(
                "allocation below EOF did not truncate and release storage",
            ));
        }
        Ok(())
    })();
    completed(result, file.close())
}

/// Sets the requested signed Windows byte allocation on one retained synchronous handle.
/// # Errors
/// Returns native set-information failures.
fn set_file_allocation(file: &FileHandle, bound: i64) -> io::Result<()> {
    let raw = file.raw()?;
    let info = FILE_ALLOCATION_INFO {
        AllocationSize: bound,
    };
    let size =
        u32::try_from(core::mem::size_of::<FILE_ALLOCATION_INFO>()).map_err(io::Error::other)?;
    let success = unsafe {
        // SAFETY: The retained synchronous handle and fully initialized record remain live until
        // Windows copies the allocation request; no pointer or callback is retained.
        SetFileInformationByHandle(
            raw,
            FileAllocationInfo,
            core::ptr::from_ref(&info).cast(),
            size,
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Exercises explicit basic times, handle-local suppression, independent handles, and resumption.
/// # Errors
/// Returns native set/write/query/flush failures, timestamp disagreement, or explicit close failure.
pub fn verify_timestamp_suppression(path: &Path) -> io::Result<()> {
    const FIXED_TIME: i64 = 125_911_584_000_000_000;
    let file = FileHandle::open(path, 0x4000_0080, 0)?;
    let result = (|| {
        let explicit = FILE_BASIC_INFO {
            CreationTime: FIXED_TIME,
            LastAccessTime: FIXED_TIME,
            LastWriteTime: FIXED_TIME,
            ChangeTime: FIXED_TIME,
            FileAttributes: 0,
        };
        set_basic_information(&file, &explicit)?;
        let suppressed = FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: -1,
            LastWriteTime: -1,
            ChangeTime: -1,
            FileAttributes: 0,
        };
        set_basic_information(&file, &suppressed)?;
        write_and_flush_byte(&file)?;
        let retained = file_information_query(&file, 4, 40, 0)?;
        for offset in [8, 16, 24] {
            if i64::from_le_bytes(field(&retained, offset)?) != FIXED_TIME {
                return Err(io::Error::other("suppressed handle changed a timestamp"));
            }
        }
        let other = FileHandle::open(path, 0x4000_0080, 0)?;
        let changed = (|| {
            write_and_flush_byte(&other)?;
            let observed = file_information_query(&other, 4, 40, 0)?;
            if i64::from_le_bytes(field(&observed, 16)?) == FIXED_TIME {
                return Err(io::Error::other(
                    "suppression leaked to an independent handle",
                ));
            }
            Ok(())
        })();
        completed(changed, other.close())?;
        set_basic_information(&file, &explicit)?;
        let resumed = FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: -2,
            LastWriteTime: -2,
            ChangeTime: -2,
            FileAttributes: 0,
        };
        set_basic_information(&file, &resumed)?;
        write_and_flush_byte(&file)?;
        let observed = file_information_query(&file, 4, 40, 0)?;
        if i64::from_le_bytes(field(&observed, 16)?) == FIXED_TIME {
            return Err(io::Error::other(
                "resumed handle did not update its write timestamp",
            ));
        }
        Ok(())
    })();
    completed(result, file.close())
}

/// Sets one fixed basic-information record on a retained synchronous handle.
/// # Errors
/// Returns native set-information failures.
fn set_basic_information(file: &FileHandle, info: &FILE_BASIC_INFO) -> io::Result<()> {
    let raw = file.raw()?;
    let size = u32::try_from(core::mem::size_of::<FILE_BASIC_INFO>()).map_err(io::Error::other)?;
    let success = unsafe {
        // SAFETY: The handle and fully initialized fixed record remain live throughout this
        // synchronous call; Windows copies the input without retaining it.
        SetFileInformationByHandle(raw, FileBasicInfo, core::ptr::from_ref(info).cast(), size)
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Writes one byte at the handle cursor and observes durable cached-write completion.
/// # Errors
/// Returns short-write, native write or flush failures.
fn write_and_flush_byte(file: &FileHandle) -> io::Result<()> {
    let raw = file.raw()?;
    let byte = [0xAC_u8];
    let mut written = 0;
    let success = unsafe {
        // SAFETY: This synchronous handle retains the one-byte input and fixed output until
        // WriteFile completes; no overlapped operation or deferred pointer is supplied.
        WriteFile(raw, byte.as_ptr(), 1, &mut written, ptr::null_mut())
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    if written != 1 {
        return Err(io::Error::other("native timestamp fixture short write"));
    }
    let flushed = unsafe {
        // SAFETY: This borrowed handle remains live through synchronous flush completion.
        FlushFileBuffers(raw)
    };
    if flushed == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Exercises metadata-only, zero-access and data handle lifetimes, aggregate information, and
/// complete and truncated root-relative name records against the supplied fixture facts.
/// # Errors
/// Returns opening, native metadata, identity or explicit release failures.
pub fn verify_metadata(path: &Path, relative_name: &str, eof: u64) -> io::Result<()> {
    let first = FileHandle::open(path, 0x80, 0)?;
    let result = (|| {
        let second = FileHandle::open(path, 0, 0)?;
        let mut label = [0_u16; 261];
        let mut filesystem = [0_u16; 261];
        let mut serial = 0;
        let mut maximum = 0;
        let mut flags = 0;
        let raw = second.raw()?;
        let queried = unsafe {
            // SAFETY: both native string buffers and scalar outputs are writable for the advertised capacities.
            GetVolumeInformationByHandleW(
                raw,
                label.as_mut_ptr(),
                261,
                &mut serial,
                &mut maximum,
                &mut flags,
                filesystem.as_mut_ptr(),
                261,
            )
        };
        let result = if queried == 0 {
            Err(io::Error::last_os_error())
        } else if decode(&filesystem) != "EXT4" || maximum != 255 {
            Err(io::Error::other(
                "volume identity from metadata handle differs",
            ))
        } else {
            Ok(())
        };
        completed(result, second.close())?;
        let [logical, _, _, effective, ..] = sector_information(&first)?;
        if logical != effective {
            return Err(io::Error::other(
                "filesystem effective sector differs from its transfer unit",
            ));
        }
        let data = FileHandle::open(path, 0x8000_0000, 0)?;
        completed(
            verify_file_information(&data, relative_name, eof),
            data.close(),
        )
    })();
    completed(result, first.close())
}

/// Queries one native volume class and preserves exact status and returned length.
/// # Errors
/// Returns an unexpected native status or a returned length outside the owned buffer.
fn volume_information_query(
    file: &FileHandle,
    class: i32,
    capacity: u32,
    expected: u32,
) -> io::Result<Vec<u8>> {
    let mut output = vec![0xA5; usize::try_from(capacity).map_err(io::Error::other)?];
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        // SAFETY: The synchronous handle and owned output/status buffers remain live until the
        // native query returns. The native routine receives their actual buffer capacity.
        NtQueryVolumeInformationFile(
            file.raw()?,
            &mut io_status,
            output.as_mut_ptr().cast(),
            capacity,
            class,
        )
    };
    if status.cast_unsigned() != expected || io_status.Information > output.len() {
        return Err(io::Error::other(format!(
            "volume information class {class}: status {:08X}, expected {expected:08X}, returned {}",
            status.cast_unsigned(),
            io_status.Information
        )));
    }
    output.truncate(io_status.Information);
    Ok(output)
}

/// Observes sector information and checks its agreement with independent allocation queries.
/// # Errors
/// Returns native failures, incorrect fixed-record lengths or inconsistent sector units.
fn sector_information(file: &FileHandle) -> io::Result<[u32; 7]> {
    let bytes = volume_information_query(file, 11, 28, 0)?;
    if bytes.len() != 28 || !volume_information_query(file, 11, 27, 0xC000_0004)?.is_empty() {
        return Err(io::Error::other(
            "sector information length contract differs",
        ));
    }
    let mut sector = [0_u32; 7];
    for (value, bytes) in sector.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *value = u32::from_le_bytes(*bytes);
    }
    let [logical, atomic, performance, effective, ..] = sector;
    if !logical.is_power_of_two()
        || atomic < logical
        || performance < logical
        || effective < logical
    {
        return Err(io::Error::other("invalid native sector geometry"));
    }
    for (class, length, sectors_offset, bytes_offset) in [(3, 24, 16, 20), (7, 32, 24, 28)] {
        let allocation = volume_information_query(file, class, length, 0)?;
        if allocation.len() != usize::try_from(length).map_err(io::Error::other)?
            || u32::from_le_bytes(field(&allocation, bytes_offset)?) != logical
            || u32::from_le_bytes(field(&allocation, sectors_offset)?) == 0
        {
            return Err(io::Error::other(
                "allocation and sector information disagree",
            ));
        }
    }
    Ok(sector)
}

/// Queries one native information class with an exact expected status and bounded output.
/// # Errors
/// Returns native failures, unexpected status, or an out-of-range returned byte count.
fn file_information_query(
    file: &FileHandle,
    class: i32,
    capacity: usize,
    expected: u32,
) -> io::Result<Vec<u8>> {
    let mut output = vec![0xA5_u8; capacity];
    let mut io_status = IO_STATUS_BLOCK::default();
    let raw = file.raw()?;
    let capacity = u32::try_from(capacity).map_err(io::Error::other)?;
    let status = unsafe {
        // SAFETY: The synchronous file handle and exclusive status/output buffers remain live
        // until the query returns. No callback or overlapped lifetime is established.
        NtQueryInformationFile(
            raw,
            &mut io_status,
            output.as_mut_ptr().cast(),
            capacity,
            class,
        )
    };
    if status.cast_unsigned() != expected || io_status.Information > output.len() {
        return Err(io::Error::other(format!(
            "file information class {class}: status {:08X}, expected {expected:08X}, returned {}",
            status.cast_unsigned(),
            io_status.Information,
        )));
    }
    output.truncate(io_status.Information);
    Ok(output)
}

/// Checks a specification-defined name record against independently supplied UTF-16 units.
/// # Errors
/// Returns a header, payload, or initialized-prefix length mismatch.
fn file_name_record(
    output: &[u8],
    offset: usize,
    expected: &[u16],
    returned_units: usize,
) -> io::Result<()> {
    let record = output
        .get(offset..)
        .ok_or_else(|| io::Error::other("missing file name record"))?;
    let expected_bytes = expected
        .len()
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("file name length overflow"))?;
    if usize::try_from(u32::from_le_bytes(field(record, 0)?)).map_err(io::Error::other)?
        != expected_bytes
    {
        return Err(io::Error::other("file name required length differs"));
    }
    let payload = record
        .get(4..)
        .ok_or_else(|| io::Error::other("missing file name payload"))?;
    let expected = expected
        .get(..returned_units)
        .ok_or_else(|| io::Error::other("invalid expected name prefix"))?;
    let (pairs, remainder) = payload.as_chunks::<2>();
    if !remainder.is_empty()
        || pairs.len() != expected.len()
        || !pairs
            .iter()
            .zip(expected)
            .all(|(bytes, expected)| u16::from_le_bytes(*bytes) == *expected)
    {
        return Err(io::Error::other("file name payload differs"));
    }
    Ok(())
}

/// Verifies the aggregate layout using separate information classes and fixture EOF/name facts.
/// # Errors
/// Returns native query or observable information-contract mismatches.
fn verify_file_information(file: &FileHandle, relative_name: &str, eof: u64) -> io::Result<()> {
    let expected: Vec<_> = relative_name.encode_utf16().collect();
    if expected.len() < 3 || expected.first() != Some(&0x005C) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fixture requires a root-relative name longer than two WCHARs",
        ));
    }
    for class in [9, 48] {
        let complete = file_information_query(file, class, 4096, 0)?;
        file_name_record(&complete, 0, &expected, expected.len())?;
        let prefix = file_information_query(file, class, 9, 0x8000_0005)?;
        file_name_record(&prefix, 0, &expected, 2)?;
        if !file_information_query(file, class, 7, 0xC000_0004)?.is_empty() {
            return Err(io::Error::other("short name query returned bytes"));
        }
    }
    let all = file_information_query(file, 18, 4096, 0)?;
    file_name_record(&all, 96, &expected, expected.len())?;
    if u64::from_le_bytes(field(&all, 48)?) != eof {
        return Err(io::Error::other(
            "aggregate EOF differs from fixture content",
        ));
    }
    for (class, offset, size) in [
        (4, 0_usize, 40_usize),
        (5, 40, 24),
        (6, 64, 8),
        (7, 72, 4),
        (8, 76, 4),
        (14, 80, 8),
        (16, 88, 4),
        (17, 92, 4),
    ] {
        let separate = file_information_query(file, class, size, 0)?;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| io::Error::other("aggregate field overflow"))?;
        if all.get(offset..end) != Some(separate.as_slice()) {
            return Err(io::Error::other(format!(
                "aggregate field for class {class} differs from separate query"
            )));
        }
    }
    let partial = file_information_query(file, 18, 105, 0x8000_0005)?;
    file_name_record(&partial, 96, &expected, 2)?;
    if partial.get(..100) != all.get(..100) {
        return Err(io::Error::other("truncated aggregate lost fixed metadata"));
    }
    if !file_information_query(file, 18, 103, 0xC000_0004)?.is_empty() {
        return Err(io::Error::other("short aggregate query returned bytes"));
    }
    Ok(())
}

/// Consumes a Rust file at a live operation's explicit native close boundary.
/// # Errors
/// Returns CloseHandle failure after consuming ownership; callers must not retry the old handle.
pub fn close_file(file: std::fs::File) -> io::Result<()> {
    FileHandle {
        raw: Some(file.into_raw_handle()),
    }
    .close()
}

/// Enumerates files using the native pattern-bearing query path, without filtering a broader scan.
/// # Errors
/// Returns native enumeration, output or explicit search-release failures.
pub fn pattern_files(pattern: &Path) -> io::Result<Vec<OsString>> {
    let pattern = wide(pattern.as_os_str())?;
    let mut data = WIN32_FIND_DATAW::default();
    let search = unsafe {
        // SAFETY: terminated input and writable native record remain alive through this synchronous call.
        FindFirstFileW(pattern.as_ptr(), &mut data)
    };
    if search == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut names = Vec::new();
        loop {
            names.push(decode(&data.cFileName));
            let next = unsafe {
                // SAFETY: search is live and data is an exclusively writable native record.
                FindNextFileW(search, &mut data)
            };
            if next == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(18) {
                    return Err(error);
                }
                return Ok(names);
            }
        }
    })();
    let closed = unsafe {
        // SAFETY: this function uniquely consumes its completed native file search.
        FindClose(search)
    };
    completed(
        result,
        if closed == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        },
    )
}

/// Queries the native directory cursor with precisely controlled buffer and pattern semantics.
/// # Errors
/// Returns unexpected native status, invalid length, or malformed input.
fn directory_query(
    file: &FileHandle,
    pattern: Option<&str>,
    capacity: usize,
    single: bool,
    restart: bool,
    expected: u32,
) -> io::Result<Vec<u8>> {
    let mut expression = pattern.map(|value| wide(OsStr::new(value))).transpose()?;
    let unicode = expression
        .as_mut()
        .map(|value| {
            let length = value
                .len()
                .checked_sub(1)
                .and_then(|size| size.checked_mul(2))
                .and_then(|size| u16::try_from(size).ok())
                .ok_or_else(|| io::Error::other("directory pattern exceeds native length"))?;
            Ok::<_, io::Error>(UNICODE_STRING {
                Length: length,
                MaximumLength: length
                    .checked_add(2)
                    .ok_or_else(|| io::Error::other("directory pattern length overflow"))?,
                Buffer: value.as_mut_ptr(),
            })
        })
        .transpose()?;
    let pattern_pointer = unicode.as_ref().map_or(ptr::null(), ptr::from_ref);
    let mut bytes = vec![0_u8; capacity];
    let mut io_status = IO_STATUS_BLOCK::default();
    let raw = file.raw()?;
    let capacity = u32::try_from(capacity).map_err(io::Error::other)?;
    let status = unsafe {
        // SAFETY: synchronous directory handle, optional Unicode expression and both exclusive
        // output buffers outlive the call; no callback or overlapped lifetime is established.
        NtQueryDirectoryFile(
            raw,
            ptr::null_mut(),
            None,
            ptr::null(),
            &mut io_status,
            bytes.as_mut_ptr().cast(),
            capacity,
            12,
            single,
            pattern_pointer,
            restart,
        )
    };
    if status.cast_unsigned() != expected || io_status.Information > bytes.len() {
        return Err(io::Error::other(format!(
            "directory status {:08X}, expected {expected:08X}, returned {}",
            status.cast_unsigned(),
            io_status.Information
        )));
    }
    bytes.truncate(io_status.Information);
    Ok(bytes)
}
/// Requires exactly one complete native file-name record.
/// # Errors
/// Returns a record-layout or name mismatch.
fn single_name(bytes: &[u8], expected: &str) -> io::Result<()> {
    let name_bytes = u32::from_le_bytes(field(bytes, 8)?);
    let payload = bytes
        .get(12..)
        .ok_or_else(|| io::Error::other("truncated name record"))?;
    if payload.len() % 2 != 0 {
        return Err(io::Error::other("odd native name length"));
    }
    let units: Vec<_> = payload
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| field(pair, 0).map(u16::from_le_bytes))
        .collect::<io::Result<_>>()?;
    if u32::from_le_bytes(field(bytes, 0)?) != 0
        || usize::try_from(name_bytes).map_err(io::Error::other)? != payload.len()
        || decode(&units) != expected
    {
        return Err(io::Error::other(
            "single FILE_NAMES_INFORMATION record mismatch",
        ));
    }
    Ok(())
}
/// Exercises FILE_NAMES_INFORMATION retry, pattern capture, restart and alignment on a fixture.
/// # Errors
/// Returns native query, record, cursor semantics or explicit release failures.
pub fn verify_directory(directory: &Path) -> io::Result<()> {
    let file = FileHandle::open(directory, 0x0010_0001, FILE_FLAG_BACKUP_SEMANTICS)?;
    let result = (|| {
        let prefix = directory_query(&file, Some("entry-000000"), 16, true, false, 0x8000_0005)?;
        if prefix.len() != 16 || u32::from_le_bytes(field(&prefix, 8)?) != 24 {
            return Err(io::Error::other("initial overflow prefix mismatch"));
        }
        single_name(
            &directory_query(&file, Some("ignored-later-expression"), 256, true, false, 0)?,
            "entry-000000",
        )?;
        directory_query(&file, None, 256, true, false, 0x8000_0006)?;
        single_name(
            &directory_query(&file, None, 256, true, true, 0)?,
            "entry-000000",
        )
    })();
    completed(result, file.close())?;
    let file = FileHandle::open(directory, 0x0010_0001, FILE_FLAG_BACKUP_SEMANTICS)?;
    let result = (|| {
        directory_query(&file, Some("no-such-entry"), 256, true, false, 0xc000_000f)?;
        directory_query(&file, None, 256, true, false, 0x8000_0006)?;
        Ok(())
    })();
    completed(result, file.close())?;
    let file = FileHandle::open(directory, 0x0010_0001, FILE_FLAG_BACKUP_SEMANTICS)?;
    let result = (|| {
        let bytes = directory_query(&file, Some("entry-*"), 76, false, false, 0)?;
        if bytes.len() != 76
            || u32::from_le_bytes(field(&bytes, 0)?) != 40
            || u32::from_le_bytes(field(&bytes, 40)?) != 0
            || u32::from_le_bytes(field(&bytes, 8)?) != 24
            || u32::from_le_bytes(field(&bytes, 48)?) != 24
        {
            return Err(io::Error::other(
                "small-buffer record alignment or final link mismatch",
            ));
        }
        if !directory_query(&file, None, 16, true, false, 0)?.is_empty() {
            return Err(io::Error::other("later short buffer consumed a name"));
        }
        if directory_query(&file, None, 256, true, false, 0)?.len() != 36 {
            return Err(io::Error::other("retry did not return one complete name"));
        }
        Ok(())
    })();
    completed(result, file.close())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Panics
    /// Panics when the real Windows I/O Manager supplies aggregate handle fields that differ
    /// from their independently queried values.
    #[test]
    fn aggregate_handle_fields_match_native_queries() {
        let result = (|| {
            let file = FileHandle::open(&std::env::current_exe()?, 0x8000_0000, 0)?;
            let observed = (|| {
                let all = file_information_query(&file, 18, 4096, 0)?;
                for (class, offset) in [(8, 76_usize), (16, 88), (17, 92)] {
                    let separate = file_information_query(&file, class, 4, 0)?;
                    let end = offset
                        .checked_add(4)
                        .ok_or_else(|| io::Error::other("field overflow"))?;
                    if all.get(offset..end) != Some(separate.as_slice()) {
                        return Err(io::Error::other(format!(
                            "native aggregate class {class} field differs"
                        )));
                    }
                }
                Ok(())
            })();
            completed(observed, file.close())
        })();
        assert!(result.is_ok(), "{result:?}");
    }
    /// # Panics
    /// Panics if independent Windows timestamp observations disagree with the handle contract.
    #[test]
    fn native_file_allocation_and_timestamp_contracts() {
        let result = (|| {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("ext4win-times-{}-{nonce}.bin", std::process::id()));
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            close_file(file)?;
            let result = (|| {
                verify_allocation_control(&path)?;
                verify_timestamp_suppression(&path)
            })();
            completed(result, std::fs::remove_file(&path))
        })();
        assert!(result.is_ok(), "{result:?}");
    }

    /// Checks real attribute-only volume queries, exact service absence and native GUID encoding.
    /// # Errors
    /// Returns host observation or field decoding failures.
    /// # Panics
    /// Panics if native observation boundaries are not preserved.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions intentionally fail native host contracts after fallible observation"
    )]
    fn host_observation_contract() -> io::Result<()> {
        let path = std::env::temp_dir();
        let queries = volume_information(&path)?;
        assert_eq!(queries.len(), 6);
        assert!(queries.iter().all(|query| query.data.len() <= 4096));
        let file = FileHandle::open(&path, 0x80, FILE_FLAG_BACKUP_SEMANTICS)?;
        let sector = completed(sector_information(&file), file.close())?;
        assert!(sector.first().is_some_and(|logical| *logical >= 512));
        let name = format!("ext4win-absent-{}", std::process::id());
        assert!(!service_registered(&name)?);
        assert!(service_state(&name)?.is_none());
        assert!(service_configuration(&name).is_err());
        assert!(service_registered("EventLog")?);
        assert!(!service_configuration("EventLog")?.image.is_empty());
        assert_eq!(
            guid_bytes("0fc63daf-8483-4772-8e79-3d69d8477de4")?,
            [
                0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47,
                0x7d, 0xe4
            ]
        );
        assert!(guid_bytes("0fc63daf-8483-4772-8e79-3d69d8477de").is_err());
        assert!(driver_path("C:relative.sys").is_err());
        Ok(())
    }
}

/// ETW consumer ownership and typed fixed-scalar event records.
mod trace;
pub use trace::{TraceEvent, TraceSession};

/// Effective token identity and UUID-scoped administrator control.
mod identity;
pub use identity::*;
