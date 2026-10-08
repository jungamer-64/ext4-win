//! Aligned Win32 descriptor transfer; native APIs own access and request validation.
use super::*;

/// Queries owner/group/DACL with a zero-length size probe and a bounded native buffer.
/// # Errors
/// Returns native query, invalid required-size or allocation failure.
pub fn file_security(path: &Path) -> io::Result<Vec<u8>> {
    let path = wide(path.as_os_str())?;
    let selection =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut required = 0;
    let probed = unsafe {
        // SAFETY: The path is terminated, output is null with zero capacity, and required is writable.
        GetFileSecurityW(path.as_ptr(), selection, ptr::null_mut(), 0, &mut required)
    };
    if probed != 0 || io::Error::last_os_error().raw_os_error() != Some(122) {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(required).map_err(io::Error::other)?;
    if !(20..=ext4_security::MAX_DESCRIPTOR_BYTES).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor size exceeds the inode projection contract",
        ));
    }
    let mut words = [0_u32; 122];
    let queried = unsafe {
        // SAFETY: Aligned initialized storage covers the independently observed required length.
        GetFileSecurityW(
            path.as_ptr(),
            selection,
            words.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    if queried == 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(required).map_err(io::Error::other)? != length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor length changed during query",
        ));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    bytes.extend(words.into_iter().flat_map(u32::to_le_bytes).take(length));
    Ok(bytes)
}
/// Writes a complete native DACL using WRITE_DAC authority obtained by Windows.
/// A failed acknowledgement is not proof that metadata stayed unchanged; query before retrying.
/// # Errors
/// Returns invalid descriptor size, native authorization or metadata failure.
pub fn set_file_dacl(path: &Path, descriptor: &[u8]) -> io::Result<()> {
    if !(20..=ext4_security::MAX_DESCRIPTOR_BYTES).contains(&descriptor.len())
        || !descriptor.len().is_multiple_of(4)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid inode descriptor extent",
        ));
    }
    let path = wide(path.as_os_str())?;
    let mut words = [0_u32; 122];
    for (word, bytes) in words.iter_mut().zip(descriptor.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    let success = unsafe {
        // SAFETY: The native API validates the complete aligned image; path and descriptor remain retained.
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            words.as_ptr().cast_mut().cast(),
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
