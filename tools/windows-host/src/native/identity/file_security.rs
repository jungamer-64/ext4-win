//! Complete aligned descriptor ownership and bounded native validation before publication.
use super::*;
use windows_sys::Wdk::System::SystemServices::RtlValidRelativeSecurityDescriptor;

/// Reserves initialized DWORD-aligned storage covering every requested descriptor byte.
/// # Errors
/// Returns capacity or allocation failure before any native call can use the storage.
fn descriptor_words(length: usize) -> io::Result<Vec<u32>> {
    let count = length.div_ceil(size_of::<u32>());
    let mut words = Vec::new();
    words.try_reserve_exact(count).map_err(io::Error::other)?;
    words.resize(count, 0);
    Ok(words)
}

/// Immutable self-relative image whose components fit its owned aligned allocation.
/// Pointer-only native setters may inspect it only after length-aware RTL validation.
struct RelativeSecurityDescriptor {
    /// Sole backing allocation; no mutation or reallocation follows validation.
    words: Vec<u32>,
}

impl RelativeSecurityDescriptor {
    /// Copies the complete byte image and validates its referenced components before publication.
    /// # Errors
    /// Rejects invalid size, absolute descriptors or invalid component extents; propagates allocation failure.
    fn capture(bytes: &[u8]) -> io::Result<Self> {
        if !(size_of::<SECURITY_DESCRIPTOR_RELATIVE>()..=ext4_security::MAX_DESCRIPTOR_BYTES)
            .contains(&bytes.len())
            || u16::from_le_bytes(super::super::field(bytes, 2)?) & SE_SELF_RELATIVE == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid self-relative security descriptor extent",
            ));
        }
        let mut words = descriptor_words(bytes.len())?;
        let mut input = bytes.iter().copied();
        for word in &mut words {
            *word = u32::from_le_bytes(core::array::from_fn(|_| input.next().unwrap_or(0)));
        }
        let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
        let valid = unsafe {
            // SAFETY: The complete initialized self-relative header and image are DWORD-aligned,
            // immutable and readable for exactly length bytes. This length-aware validator checks
            // component offsets and extents before a pointer-only API may inspect the image.
            RtlValidRelativeSecurityDescriptor(
                words.as_ptr().cast_mut().cast(),
                length,
                DACL_SECURITY_INFORMATION,
            )
        };
        if !valid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid self-relative security descriptor components",
            ));
        }
        Ok(Self { words })
    }

    /// Borrows the validated complete image for one synchronous native setter.
    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.words.as_ptr().cast_mut().cast()
    }
}

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
    if !(size_of::<SECURITY_DESCRIPTOR_RELATIVE>()..=ext4_security::MAX_DESCRIPTOR_BYTES)
        .contains(&length)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor size exceeds the inode projection contract",
        ));
    }
    let mut words = descriptor_words(length)?;
    let queried = unsafe {
        // SAFETY: The initialized DWORD allocation covers the advertised required byte count,
        // including a partial final word. Both output slots remain live through this synchronous call.
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
/// Returns invalid self-relative descriptor size/components, allocation, native authorization or metadata failure.
pub fn set_file_dacl(path: &Path, descriptor: &[u8]) -> io::Result<()> {
    let descriptor = RelativeSecurityDescriptor::capture(descriptor)?;
    let path = wide(path.as_os_str())?;
    let success = unsafe {
        // SAFETY: Length-aware validation established that every referenced component is inside
        // the immutable aligned image. The terminated path and complete descriptor outlive this call.
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{completed, field};
    use super::*;

    /// Self-relative descriptor with a present null DACL, encoded independently of the host adapter.
    const NULL_DACL: [u8; 20] = [1, 0, 4, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    /// Writes a fixture field without relying on production descriptor parsing or encoding.
    /// # Errors
    /// Returns a fixture offset outside the owned image.
    fn put(bytes: &mut [u8], offset: usize, value: &[u8]) -> io::Result<()> {
        let end = offset
            .checked_add(value.len())
            .ok_or_else(|| io::Error::other("fixture overflow"))?;
        let target = bytes
            .get_mut(offset..end)
            .ok_or_else(|| io::Error::other("fixture field outside image"))?;
        for (target, value) in target.iter_mut().zip(value) {
            *target = *value;
        }
        Ok(())
    }

    /// Encodes plain ACCESS_ALLOWED_ACE records, including access needed to remove the test file.
    /// # Errors
    /// Returns token-query, SID-encoding or native field-size conversion failure.
    fn large_descriptor() -> io::Result<Vec<u8>> {
        let user = super::super::effective_identity()?.user;
        let mut principals = vec![(user, 0x001f_01ff_u32)];
        for rid in 1000..1064 {
            let sid = format!("S-1-5-21-1-2-3-{rid}")
                .parse::<Sid>()
                .map_err(invalid)?;
            principals.push((sid, 0x0012_0089_u32));
        }
        let mut acl = vec![2, 0, 0, 0, 65, 0, 0, 0];
        for (sid, mask) in principals {
            let ace_length = sid
                .bytes()
                .len()
                .checked_add(8)
                .ok_or_else(|| io::Error::other("fixture ACE overflow"))?;
            acl.extend_from_slice(&[0, 0]);
            acl.extend_from_slice(
                &u16::try_from(ace_length)
                    .map_err(io::Error::other)?
                    .to_le_bytes(),
            );
            acl.extend_from_slice(&mask.to_le_bytes());
            acl.extend_from_slice(sid.bytes());
        }
        let acl_length = u16::try_from(acl.len()).map_err(io::Error::other)?;
        put(&mut acl, 2, &acl_length.to_le_bytes())?;
        let mut image = NULL_DACL.to_vec();
        put(&mut image, 16, &20_u32.to_le_bytes())?;
        image.extend_from_slice(&acl);
        Ok(image)
    }

    /// # Errors
    /// Returns native token, file I/O, descriptor transfer or cleanup failure.
    /// # Panics
    /// Fails if native round-trip truncates the independently encoded ACL or changes an ACE.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "native setup and cleanup errors propagate while assertions compare complete ACL bytes"
    )]
    fn native_large_dacl_round_trip_preserves_every_ace() -> io::Result<()> {
        let expected = large_descriptor()?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ext4win-security-{}-{nonce}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        let result = (|| {
            super::super::super::close_file(file)?;
            // The source need not be DWORD-aligned; capture must establish native alignment.
            let mut source = vec![0];
            source.extend_from_slice(&expected);
            set_file_dacl(
                &path,
                source
                    .get(1..)
                    .ok_or_else(|| io::Error::other("missing fixture image"))?,
            )?;
            let queried = file_security(&path)?;
            // Exercise publication of a complete image returned by the query boundary as well.
            set_file_dacl(&path, &queried)?;
            file_security(&path)
        })();
        let queried = completed(result, std::fs::remove_file(&path))?;
        let offset =
            usize::try_from(u32::from_le_bytes(field(&queried, 16)?)).map_err(io::Error::other)?;
        assert!(queried.len() > 488);
        assert_eq!(queried.get(offset..), expected.get(20..));
        Ok(())
    }

    /// # Errors
    /// Returns fixture construction failure.
    /// # Panics
    /// Fails if untrusted size, representation or component extents reach filesystem publication.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture errors propagate while assertions verify invalid-input classification"
    )]
    fn rejects_unbounded_components_before_file_access() -> io::Result<()> {
        let path = Path::new("ext4win-invalid-descriptor-must-not-reach-file-access");
        let mut cases = vec![
            Vec::new(),
            vec![0; 19],
            vec![0; ext4_security::MAX_DESCRIPTOR_BYTES + 1],
            vec![0; 40],
        ];
        for offset in [4, 8, 12, 16] {
            let mut image = NULL_DACL.to_vec();
            put(
                &mut image,
                2,
                &(SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT).to_le_bytes(),
            )?;
            put(&mut image, offset, &0xffff_fffc_u32.to_le_bytes())?;
            cases.push(image);
        }
        let mut acl = NULL_DACL.to_vec();
        put(&mut acl, 16, &20_u32.to_le_bytes())?;
        acl.extend_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
        // Only seven ACL bytes are present, even though DWORD rounding reserves eight.
        cases.push(
            acl.get(..27)
                .ok_or_else(|| io::Error::other("missing ACL fixture"))?
                .to_vec(),
        );
        put(&mut acl, 22, &u16::MAX.to_le_bytes())?;
        cases.push(acl);
        let mut sid = NULL_DACL.to_vec();
        put(&mut sid, 4, &20_u32.to_le_bytes())?;
        sid.extend_from_slice(&[1, 15, 0, 0, 0, 0, 0, 5]);
        cases.push(sid);
        for image in cases {
            let result = set_file_dacl(path, &image);
            assert_eq!(
                result.err().map(|error| error.kind()),
                Some(io::ErrorKind::InvalidInput)
            );
        }
        Ok(())
    }

    /// # Panics
    /// Fails if a valid null DACL or byte-count boundary is replaced by a word-alignment restriction.
    #[test]
    fn accepts_self_relative_null_dacl_through_the_byte_limit() {
        assert!(RelativeSecurityDescriptor::capture(&NULL_DACL).is_ok());
        let mut image = NULL_DACL.to_vec();
        image.resize(ext4_security::MAX_DESCRIPTOR_BYTES, 0);
        assert!(RelativeSecurityDescriptor::capture(&image).is_ok());
    }
}
