use ext4_core::{
    Ext4Gid, Ext4LinkCount, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp,
    Ext4Uid, FileAllocationSize, FileSize,
};

pub(super) fn test_metadata(kind: super::FileMetadataKind) -> Option<super::FileMetadata> {
    test_metadata_with_permissions(kind, 0o644, 0)
}

pub(super) fn test_metadata_with_permissions(
    kind: super::FileMetadataKind,
    permissions: u16,
    overlay_attributes: u32,
) -> Option<super::FileMetadata> {
    let timestamp = Ext4Timestamp::from_unix_seconds(1);
    Some(super::FileMetadata {
        file_index: 1,
        kind,
        size: FileSize::from_bytes(0),
        allocation_size: FileAllocationSize::from_bytes(0),
        security: Ext4Security::new(
            Ext4Owner::new(Ext4Uid::from_u32(0), Ext4Gid::from_u32(0)),
            Ext4Permissions::new(permissions).ok()?,
        ),
        times: Ext4Times::new(timestamp, timestamp, timestamp, timestamp),
        links_count: Ext4LinkCount::ONE,
        overlay_attributes,
        reparse_point: match kind {
            super::FileMetadataKind::File | super::FileMetadataKind::Directory => {
                super::FileMetadataReparsePoint::None
            }
            super::FileMetadataKind::Symlink => super::FileMetadataReparsePoint::SymbolicLink,
        },
    })
}

/// Builds one variable-length namespace information buffer.
pub(super) fn le_u32(buffer: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(core::mem::size_of::<u32>())?;
    let bytes = buffer.get(offset..end)?;
    let bytes = <[u8; 4]>::try_from(bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Reads one little-endian u64 from a test output buffer.
pub(super) fn le_u64(buffer: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(core::mem::size_of::<u64>())?;
    let bytes = buffer.get(offset..end)?;
    let bytes = <[u8; 8]>::try_from(bytes).ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Builds a Windows hard-link set through the same fallible ownership boundary as production.
pub(super) fn byte_at(buffer: &[u8], offset: usize) -> Option<u8> {
    buffer.get(offset).copied()
}

/// Reads one little-endian i64 from a test output buffer.
pub(super) fn le_i64(buffer: &[u8], offset: usize) -> Option<i64> {
    let end = offset.checked_add(core::mem::size_of::<i64>())?;
    let bytes = buffer.get(offset..end)?;
    let bytes = <[u8; 8]>::try_from(bytes).ok()?;
    Some(i64::from_le_bytes(bytes))
}

/// Writes one little-endian u32 into a test input buffer.
pub(super) fn put_le_u32(buffer: &mut [u8], offset: usize, value: u32) -> bool {
    let Some(end) = offset.checked_add(core::mem::size_of::<u32>()) else {
        return false;
    };
    let Some(target) = buffer.get_mut(offset..end) else {
        return false;
    };
    crate::memory::copy_exact(target, &value.to_le_bytes()).is_ok()
}

/// Writes one little-endian i64 into a test input buffer.
pub(super) fn put_le_i64(buffer: &mut [u8], offset: usize, value: i64) -> bool {
    let Some(end) = offset.checked_add(core::mem::size_of::<i64>()) else {
        return false;
    };
    let Some(target) = buffer.get_mut(offset..end) else {
        return false;
    };
    crate::memory::copy_exact(target, &value.to_le_bytes()).is_ok()
}

/// Asserts that every byte not owned by an encoded scalar field was cleared.
/// # Panics
///
/// Panics when an ABI padding byte is nonzero.
pub(super) fn assert_padding_zero(record: &[u8], fields: &[(usize, usize)]) {
    for (offset, byte) in record.iter().copied().enumerate() {
        let is_field = fields.iter().any(|(start, length)| {
            start
                .checked_add(*length)
                .is_some_and(|end| *start <= offset && offset < end)
        });
        if !is_field {
            assert_eq!(byte, 0, "padding byte {offset} retained stale storage");
        }
    }
}
