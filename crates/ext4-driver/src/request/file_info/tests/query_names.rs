use super::*;
use crate::request::file_info::test_support::*;

/// # Panics
/// Panics when a root-relative path loses separators, stored casing, or Unicode components.
#[test]
fn relative_names_preserve_namespace_spelling() {
    let empty = super::assemble_relative_name(&[]);
    assert!(empty.is_ok());
    if let Ok(root) = empty {
        assert_eq!(root.as_slice(), &[0x005C]);
    }
    let components = ["表😀", "Parent", "Top"]
        .iter()
        .map(|name| WindowsName::from_ext4(&Ext4Name::new(name.as_bytes()).ok()?).ok())
        .collect::<Option<alloc::vec::Vec<_>>>();
    assert!(components.is_some());
    let Some(components) = components else {
        return;
    };
    let result = super::assemble_relative_name(&components);
    assert!(result.is_ok());
    if let Ok(result) = result {
        let expected = "\\Top\\Parent\\表😀"
            .encode_utf16()
            .collect::<alloc::vec::Vec<_>>();
        assert_eq!(result.as_slice(), expected.as_slice());
    }
}

/// # Panics
/// Panics when name information fails to report the full byte length and exact initialized prefix.
#[test]
fn name_information_packs_specification_vectors() {
    let name = [0x005C, 0x8868, 0xD83D, 0xDE00];
    let mut output = [0xA5; 16];
    assert_eq!(
        super::pack_name_information(&mut output, &name).and_then(|packed| packed.completion()),
        IrpCompletion::from_usize(12)
    );
    assert_eq!(
        output,
        [
            8, 0, 0, 0, 0x5C, 0, 0x68, 0x88, 0x3D, 0xD8, 0, 0xDE, 0xA5, 0xA5, 0xA5, 0xA5
        ]
    );

    let mut partial = [0xA5; 9];
    assert_eq!(
        super::pack_name_information(&mut partial, &name).and_then(|packed| packed.completion()),
        IrpCompletion::buffer_overflow(8)
    );
    assert_eq!(partial, [8, 0, 0, 0, 0x5C, 0, 0x68, 0x88, 0xA5]);
    assert_eq!(le_u32(&partial, 0), Some(8));

    let mut split_surrogate = [0xA5; 10];
    assert_eq!(
        super::pack_name_information(&mut split_surrogate, &name)
            .and_then(|packed| packed.completion()),
        IrpCompletion::buffer_overflow(10)
    );
    // The protocol truncates on WCHAR boundaries, including between surrogate code units.
    assert_eq!(
        split_surrogate,
        [8, 0, 0, 0, 0x5C, 0, 0x68, 0x88, 0x3D, 0xD8]
    );
}

/// # Panics
/// Panics when a subminimum query writes output, or root output adds a terminator to Information.
#[test]
fn name_information_enforces_minimum_and_root_length() {
    for length in 0..8 {
        let mut output = alloc::vec![0xA5; length];
        assert_eq!(
            super::pack_name_information(&mut output, &[0x005C])
                .and_then(|packed| packed.completion()),
            Err(DriverError::InfoLengthMismatch)
        );
        assert!(output.iter().all(|byte| *byte == 0xA5));
    }
    let mut root = [0xA5; 8];
    assert_eq!(
        super::pack_name_information(&mut root, &[0x005C]).and_then(|packed| packed.completion()),
        IrpCompletion::from_usize(6)
    );
    assert_eq!(root, [2, 0, 0, 0, 0x5C, 0, 0xA5, 0xA5]);
}
