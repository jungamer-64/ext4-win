use super::*;
use crate::request::file_info::test_support::*;

/// Builds a sparse-size snapshot with a distinct inode projection and native stream authority.
fn snapshot() -> Option<super::AllFileInformation> {
    let metadata = test_metadata(super::FileMetadataKind::File)?;
    Some(super::AllFileInformation {
        metadata,
        delete_pending: false,
        stream_sizes: crate::kernel::stream::StreamSizes::try_from_ext4(
            FileSize::from_bytes(8_193),
            FileAllocationSize::from_bytes(4_096),
            ext4_core::ClusterSize::new(4_096).ok()?,
        )
        .ok()?,
        position: 0x0102_0304_0506_0708,
        ea_size: 37,
    })
}

/// # Panics
/// Panics when aggregate fields violate the Windows layout, lose stream authority, or overwrite
/// upstream-owned fields or bytes beyond the initialized prefix.
#[test]
fn all_information_packs_windows_layout_and_stream_authority() {
    let snapshot = snapshot();
    assert!(snapshot.is_some());
    let Some(snapshot) = snapshot else {
        return;
    };
    let name = [0x005C, 0x0064, 0x005C, 0x0066];
    let mut output = [0xA5; 112];
    assert_eq!(
        super::pack_all_information(&mut output, &snapshot, &name)
            .and_then(|packed| packed.completion()),
        IrpCompletion::from_usize(108)
    );
    assert_eq!(le_i64(&output, 40), Some(4_096));
    assert_eq!(le_i64(&output, 48), Some(8_193));
    assert_eq!(le_u32(&output, 56), Some(1));
    assert_eq!(output.get(60..64), Some([0, 0, 0, 0].as_slice()));
    assert_eq!(le_i64(&output, 64), Some(1));
    assert_eq!(le_u32(&output, 72), Some(37));
    assert_eq!(output.get(76..80), Some([0xA5; 4].as_slice()));
    assert_eq!(le_i64(&output, 80), Some(0x0102_0304_0506_0708));
    assert_eq!(output.get(88..96), Some([0xA5; 8].as_slice()));
    assert_eq!(le_u32(&output, 96), Some(8));
    assert_eq!(
        output.get(100..108),
        Some([0x5C, 0, b'd', 0, 0x5C, 0, b'f', 0].as_slice())
    );
    assert_eq!(output.get(108..), Some([0xA5; 4].as_slice()));
}

/// # Panics
/// Panics when a truncated aggregate loses fixed fields, rounds partial UTF-16 incorrectly, or
/// accepts a buffer below the Windows minimum.
#[test]
fn all_information_preserves_partial_progress_and_minimum_size() {
    let snapshot = snapshot();
    assert!(snapshot.is_some());
    let Some(snapshot) = snapshot else {
        return;
    };
    let name = [0x005C, 0x0064, 0x005C, 0x0066];
    let mut partial = [0xA5; 105];
    assert_eq!(
        super::pack_all_information(&mut partial, &snapshot, &name)
            .and_then(|packed| packed.completion()),
        IrpCompletion::buffer_overflow(104)
    );
    assert_eq!(le_u32(&partial, 96), Some(8));
    assert_eq!(
        partial.get(100..),
        Some([0x5C, 0, b'd', 0, 0xA5].as_slice())
    );
    assert_eq!(le_u32(&partial, 72), Some(37));
    let mut short = [0xA5; 103];
    assert_eq!(
        super::pack_all_information(&mut short, &snapshot, &name),
        Err(DriverError::InfoLengthMismatch)
    );
    assert!(short.iter().all(|byte| *byte == 0xA5));
}
