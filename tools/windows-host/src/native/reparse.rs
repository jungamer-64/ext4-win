//! Reparse point and extended attribute observations on a disposable volume.

use super::{FileHandle, completed};
use core::ptr;
use std::{fs::File, io, path::Path};
use windows_sys::{
    Wdk::Storage::FileSystem::{NtFsControlFile, NtQueryEaFile, NtSetEaFile},
    Win32::{
        Foundation::{
            NTSTATUS, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_EAS_NOT_SUPPORTED,
            STATUS_NOT_A_REPARSE_POINT, STATUS_SUCCESS,
        },
        Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_EA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA,
            SYNCHRONIZE,
        },
        System::{
            IO::IO_STATUS_BLOCK,
            Ioctl::{FSCTL_DELETE_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT},
            SystemServices::IO_REPARSE_TAG_SYMLINK,
        },
    },
};

/// Creates one empty probe file and checks the actual Windows FSCTL and EA contracts.
/// The probe belongs to the caller's disposable volume.
/// # Errors
/// Returns native status, output, attribute-state, or handle finalization failures.
pub fn verify_reparse_point_lifecycle(path: &Path) -> io::Result<()> {
    super::close_file(File::create_new(path)?)?;
    let file = FileHandle::open(
        path,
        FILE_READ_EA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    completed(lifecycle(&file), file.close())
}

/// Checks both orders of the EA/reparse exclusion and the GET output boundaries.
/// # Errors
/// Returns an unexpected native status or an observation that differs from the fixture.
fn lifecycle(file: &FileHandle) -> io::Result<()> {
    // Relative symlink to alpha.bin. Both names share an 18-byte UTF-16 path region.
    let symlink = [
        0x0C, 0, 0, 0xA0, 30, 0, 0, 0, 0, 0, 18, 0, 0, 0, 18, 0, 1, 0, 0, 0, b'a', 0, b'l', 0,
        b'p', 0, b'h', 0, b'a', 0, b'.', 0, b'b', 0, b'i', 0, b'n', 0,
    ];
    // FILE_FULL_EA_INFORMATION with one name ("PROBE") and one value byte.
    let ea = [
        0, 0, 0, 0, 0, 5, 1, 0, b'P', b'R', b'O', b'B', b'E', 0, 0x51,
    ];
    let delete_ea = [0, 0, 0, 0, 0, 5, 0, 0, b'P', b'R', b'O', b'B', b'E', 0];
    let [tag0, tag1, tag2, tag3] = IO_REPARSE_TAG_SYMLINK.to_le_bytes();
    let delete_reparse = [tag0, tag1, tag2, tag3, 0, 0, 0, 0];

    set_ea(file, &ea, STATUS_SUCCESS)?;
    fsctl(
        file,
        FSCTL_SET_REPARSE_POINT,
        &symlink,
        &mut [],
        STATUS_EAS_NOT_SUPPORTED,
    )?;
    fsctl(
        file,
        FSCTL_GET_REPARSE_POINT,
        &[],
        &mut [0xA5; 38],
        STATUS_NOT_A_REPARSE_POINT,
    )?;
    require_ea(file, &ea)?;
    set_ea(file, &delete_ea, STATUS_SUCCESS)?;
    fsctl(
        file,
        FSCTL_SET_REPARSE_POINT,
        &symlink,
        &mut [],
        STATUS_SUCCESS,
    )?;
    set_ea(file, &ea, STATUS_EAS_NOT_SUPPORTED)?;

    let mut short = [0xA5; 27];
    fsctl(
        file,
        FSCTL_GET_REPARSE_POINT,
        &[],
        &mut short,
        STATUS_BUFFER_TOO_SMALL,
    )?;
    if short != [0xA5; 27] {
        return Err(io::Error::other(
            "reparse GET wrote data on STATUS_BUFFER_TOO_SMALL",
        ));
    }
    let mut prefix = [0xA5; 28];
    let written = fsctl(
        file,
        FSCTL_GET_REPARSE_POINT,
        &[],
        &mut prefix,
        STATUS_BUFFER_OVERFLOW,
    )?;
    if written != Some(prefix.len()) || Some(prefix.as_slice()) != symlink.get(..prefix.len()) {
        return Err(io::Error::other(
            "reparse GET did not return the expected prefix and byte count",
        ));
    }
    let mut output = [0xA5; 38];
    let written = fsctl(
        file,
        FSCTL_GET_REPARSE_POINT,
        &[],
        &mut output,
        STATUS_SUCCESS,
    )?;
    if written != Some(symlink.len()) || output != symlink {
        return Err(io::Error::other(
            "reparse GET did not return the complete expected record",
        ));
    }

    fsctl(
        file,
        FSCTL_DELETE_REPARSE_POINT,
        &delete_reparse,
        &mut [],
        STATUS_SUCCESS,
    )?;
    fsctl(
        file,
        FSCTL_GET_REPARSE_POINT,
        &[],
        &mut output,
        STATUS_NOT_A_REPARSE_POINT,
    )?;
    set_ea(file, &ea, STATUS_SUCCESS)?;
    require_ea(file, &ea)
}

/// Returns the information published to user mode with the exact expected status.
/// # Errors
/// Returns argument conversion, native handle, or unexpected completion errors.
fn fsctl(
    file: &FileHandle,
    code: u32,
    input: &[u8],
    output: &mut [u8],
    expected: NTSTATUS,
) -> io::Result<Option<usize>> {
    let mut iosb = IO_STATUS_BLOCK {
        Information: usize::MAX,
        ..IO_STATUS_BLOCK::default()
    };
    let input_bytes = u32::try_from(input.len()).map_err(io::Error::other)?;
    let output_bytes = u32::try_from(output.len()).map_err(io::Error::other)?;
    let input = if input.is_empty() {
        ptr::null()
    } else {
        input.as_ptr().cast()
    };
    let output = if output.is_empty() {
        ptr::null_mut()
    } else {
        output.as_mut_ptr().cast()
    };
    let raw = file.raw()?;
    let status = unsafe {
        // SAFETY: The file was opened synchronously. The status block and supplied buffers
        // remain valid for the call, each with its exact length, and there is no APC.
        NtFsControlFile(
            raw,
            ptr::null_mut(),
            None,
            ptr::null(),
            &mut iosb,
            code,
            input,
            input_bytes,
            output,
            output_bytes,
        )
    };
    if status != expected {
        return Err(io::Error::other(format!(
            "reparse FSCTL {code:#x}: NTSTATUS {status:#010x}, expected {expected:#010x}"
        )));
    }
    // Windows may leave the user-mode status block untouched for error-severity results.
    Ok((iosb.Information != usize::MAX).then_some(iosb.Information))
}

/// Sets or removes one EA via the native handle and preserves the returned status.
/// # Errors
/// Returns argument conversion, handle, or unexpected completion errors.
fn set_ea(file: &FileHandle, input: &[u8], expected: NTSTATUS) -> io::Result<()> {
    let raw = file.raw()?;
    let bytes = u32::try_from(input.len()).map_err(io::Error::other)?;
    let mut iosb = IO_STATUS_BLOCK::default();
    let status = unsafe {
        // SAFETY: The synchronous handle, initialized EA input and exclusive status block
        // remain live until the call completes.
        NtSetEaFile(raw, &mut iosb, input.as_ptr().cast(), bytes)
    };
    if status != expected {
        return Err(io::Error::other(format!(
            "NtSetEaFile: NTSTATUS {status:#010x}, expected {expected:#010x}"
        )));
    }
    Ok(())
}

/// Checks the complete EA record in a newly started native query.
/// # Errors
/// Returns handle, native query, or record mismatch failures.
fn require_ea(file: &FileHandle, expected: &[u8]) -> io::Result<()> {
    let mut output = [0xA5_u8; 64];
    let mut iosb = IO_STATUS_BLOCK::default();
    let raw = file.raw()?;
    let status = unsafe {
        // SAFETY: The synchronous handle and both exclusive output buffers remain live.
        // A null list and index request a fresh unfiltered scan.
        NtQueryEaFile(
            raw,
            &mut iosb,
            output.as_mut_ptr().cast(),
            64,
            false,
            ptr::null(),
            0,
            ptr::null(),
            true,
        )
    };
    if status != STATUS_SUCCESS || output.get(..iosb.Information) != Some(expected) {
        return Err(io::Error::other(format!(
            "NtQueryEaFile: unexpected record, NTSTATUS {status:#010x}, length {}",
            iosb.Information
        )));
    }
    Ok(())
}
