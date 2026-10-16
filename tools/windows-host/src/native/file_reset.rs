//! Observes Windows create dispositions separately from Rust's open-and-truncate behavior.
use super::{FileHandle, close_file, completed, wide};
use core::ptr;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        TRUNCATE_EXISTING,
    },
};

/// Existing attributes that CREATE_ALWAYS must explicitly acknowledge.
const PROTECTED_ATTRIBUTES: u32 = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;

/// Creates a new fixture and checks protected attributes, refused resets, and successful EOF resets.
/// Rust create-and-truncate opens and TRUNCATE_EXISTING retain existing attributes;
/// CREATE_ALWAYS requires both protected attributes in the request.
/// The caller owns the fixture path and its cleanup, including after failure.
/// # Errors
/// Returns file I/O, native create or explicit close failures, or observable contract disagreement.
pub fn verify_existing_file_reset(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .attributes(PROTECTED_ATTRIBUTES)
        .open(path)?;
    close_file(file)?;
    verify_empty_reset(path)?;
    let native_path = wide(path.as_os_str())?;
    for (disposition, attributes) in [
        (TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL),
        (CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL),
        (CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN),
        (CREATE_ALWAYS, FILE_ATTRIBUTE_SYSTEM),
        (CREATE_ALWAYS, PROTECTED_ATTRIBUTES),
    ] {
        seed_payload(path)?;
        let raw = unsafe {
            // SAFETY: The terminated path lives through this synchronous call. No security,
            // template or asynchronous storage is supplied; a successful handle is owned below.
            CreateFileW(
                native_path.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                disposition,
                attributes,
                ptr::null_mut(),
            )
        };
        let refusal_required = disposition == CREATE_ALWAYS && attributes != PROTECTED_ATTRIBUTES;
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            let error = io::Error::last_os_error();
            if !refusal_required || error.raw_os_error() != Some(ERROR_ACCESS_DENIED.cast_signed())
            {
                return Err(error);
            }
            if fs::read(path)? != b"existing payload" {
                return Err(io::Error::other(
                    "refused reset changed the existing payload",
                ));
            }
        } else {
            let file = FileHandle { raw: Some(raw) };
            let result = if refusal_required {
                Err(io::Error::other(
                    "CREATE_ALWAYS ignored protected attributes",
                ))
            } else {
                verify_empty_reset(path)
            };
            completed(result, file.close())?;
        }
    }
    for create_if_missing in [false, true] {
        seed_payload(path)?;
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(create_if_missing)
            .open(path)?;
        completed(verify_empty_reset(path), close_file(file))?;
    }
    Ok(())
}

/// Seeds a nonempty payload without requesting a create disposition or attribute change.
/// # Errors
/// Returns open, write or explicit close failure.
fn seed_payload(path: &Path) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let result = file.write_all(b"existing payload");
    completed(result, close_file(file))
}

/// Checks EOF and attribute retention after a successful reset or initial fixture creation.
/// # Errors
/// Returns metadata failure or disagreement with the empty protected-file contract.
fn verify_empty_reset(path: &Path) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.len() != 0
        || metadata.file_attributes() & PROTECTED_ATTRIBUTES != PROTECTED_ATTRIBUTES
    {
        return Err(io::Error::other(
            "file reset changed protected attributes or retained EOF",
        ));
    }
    Ok(())
}
