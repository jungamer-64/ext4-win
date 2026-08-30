use super::*;
use crate::irp::ReceivedIrp;
use crate::request::file_info::test_support::*;
use alloc::vec;

fn namespace_information_input(units: &[u16]) -> Option<alloc::vec::Vec<u8>> {
    let name_bytes = units.len().checked_mul(core::mem::size_of::<u16>())?;
    let payload = super::FILE_NAMESPACE_NAME_OFFSET.checked_add(name_bytes)?;
    let total = core::cmp::max(
        payload,
        core::mem::size_of::<wdk_sys::FILE_LINK_INFORMATION>(),
    );
    let mut input = vec![0_u8; total];
    if !put_le_u32(
        &mut input,
        super::FILE_NAMESPACE_NAME_LENGTH_OFFSET,
        u32::try_from(name_bytes).ok()?,
    ) {
        return None;
    }
    let name = input.get_mut(super::FILE_NAMESPACE_NAME_OFFSET..total)?;
    let (outputs, remainder) = name.as_chunks_mut::<2>();
    if !remainder.is_empty() {
        return None;
    }
    for (output, unit) in outputs.iter_mut().zip(units.iter().copied()) {
        crate::memory::copy_exact(output, &unit.to_le_bytes()).ok()?;
    }
    Some(input)
}

/// # Panics
///
/// Panics when rename-ex flags select the wrong collision policy or admit unsupported behavior.
#[test]
fn rename_ex_flags_decode_collision_and_reject_unsupported_semantics() {
    let mut input = [0_u8; super::FILE_NAMESPACE_NAME_OFFSET + 2];
    assert!(put_le_u32(
        &mut input,
        super::FILE_NAMESPACE_FLAGS_OFFSET,
        wdk_sys::FILE_RENAME_IGNORE_READONLY_ATTRIBUTE,
    ));
    assert_eq!(
        super::RenameInformationFormat::Flags.target_collision(&input),
        Ok(ext4_core::RenameTargetCollision::Reject)
    );

    assert!(put_le_u32(
        &mut input,
        super::FILE_NAMESPACE_FLAGS_OFFSET,
        wdk_sys::FILE_RENAME_REPLACE_IF_EXISTS,
    ));
    assert_eq!(
        super::RenameInformationFormat::Flags.target_collision(&input),
        Ok(ext4_core::RenameTargetCollision::Replace)
    );

    assert!(put_le_u32(
        &mut input,
        super::FILE_NAMESPACE_FLAGS_OFFSET,
        wdk_sys::FILE_RENAME_POSIX_SEMANTICS,
    ));
    assert_eq!(
        super::RenameInformationFormat::Flags.target_collision(&input),
        Err(DriverError::NotSupported)
    );
}

/// # Panics
///
/// Panics when hard-link legacy/extended collision semantics drift.
#[test]
fn hard_link_flags_decode_collision_and_reject_unimplemented_semantics() {
    let mut input = [0_u8; super::FILE_NAMESPACE_NAME_OFFSET + 2];
    assert_eq!(
        super::HardLinkInformationFormat::ReplaceIfExistsByte.target_collision(&input),
        Ok(super::HardLinkTargetCollision::Reject)
    );
    let Some(replace) = input.get_mut(super::FILE_NAMESPACE_REPLACE_IF_EXISTS_OFFSET) else {
        return;
    };
    *replace = 1;
    assert_eq!(
        super::HardLinkInformationFormat::ReplaceIfExistsByte.target_collision(&input),
        Ok(super::HardLinkTargetCollision::Replace)
    );

    assert!(put_le_u32(
        &mut input,
        super::FILE_NAMESPACE_FLAGS_OFFSET,
        wdk_sys::FILE_LINK_REPLACE_IF_EXISTS,
    ));
    assert_eq!(
        super::HardLinkInformationFormat::Flags.target_collision(&input),
        Ok(super::HardLinkTargetCollision::Replace)
    );
    for unsupported in [
        wdk_sys::FILE_LINK_POSIX_SEMANTICS,
        wdk_sys::FILE_LINK_IGNORE_READONLY_ATTRIBUTE,
    ] {
        assert!(put_le_u32(
            &mut input,
            super::FILE_NAMESPACE_FLAGS_OFFSET,
            unsupported,
        ));
        assert_eq!(
            super::HardLinkInformationFormat::Flags.target_collision(&input),
            Err(DriverError::NotSupported)
        );
    }
}

/// # Panics
///
/// Panics when the Windows hard-link limit or archive transition drifts.
#[test]
fn hard_link_count_and_archive_boundaries_are_explicit() {
    let below_limit = Ext4LinkCount::new(1023);
    let at_limit = Ext4LinkCount::new(1024);
    assert!(below_limit.is_ok());
    assert!(at_limit.is_ok());
    if let (Ok(below_limit), Ok(at_limit)) = (below_limit, at_limit) {
        assert_eq!(
            super::HardLinkCountEffect::Increase.validate(below_limit),
            Ok(())
        );
        assert_eq!(
            super::HardLinkCountEffect::Increase.validate(at_limit),
            Err(DriverError::from(ext4_core::Error::TooManyLinks))
        );
        assert_eq!(
            super::HardLinkCountEffect::Preserve.validate(at_limit),
            Ok(())
        );
    }

    let overlay = super::hard_link_archive_overlay(0);
    assert!(overlay.is_ok());
    if let Ok(Some(overlay)) = overlay {
        assert_eq!(
            overlay.attributes().bits(),
            ext4_core::Ext4WindowsAttributes::ARCHIVE
        );
    }
    assert_eq!(
        super::hard_link_archive_overlay(ext4_core::Ext4WindowsAttributes::ARCHIVE),
        Ok(None)
    );
}

/// # Panics
///
/// Panics when vacant and replacement destinations select the wrong parent effect.
#[test]
fn hard_link_destinations_preserve_parent_oplock_effects() {
    let vacant = super::PreparedHardLinkDestination::Vacant;
    assert_eq!(vacant.oplock_effect(), NamespaceParentOplockEffect::Change);
    let name = Ext4Name::new(b"target");
    assert!(name.is_ok());
    if let Ok(name) = name {
        let replaced = super::PreparedHardLinkDestination::Replace {
            existing_name: name,
        };
        assert_eq!(
            replaced.oplock_effect(),
            NamespaceParentOplockEffect::Removal
        );
    }
}

/// # Panics
///
/// Panics when namespace path bases or relative-path rejection drift.
#[test]
fn namespace_target_distinguishes_opened_parent_from_volume_root() {
    let truncated = [0_u8; core::mem::size_of::<wdk_sys::FILE_LINK_INFORMATION>() - 1];
    assert_eq!(
        super::NamespaceTargetPath::decode(&truncated, DirectoryNodeId::ROOT),
        Err(DriverError::InfoLengthMismatch)
    );

    let relative = namespace_information_input(&[u16::from(b'a')]);
    assert!(relative.is_some());
    if let Some(relative) = relative {
        let decoded = super::NamespaceTargetPath::decode(&relative, DirectoryNodeId::ROOT);
        assert!(decoded.is_ok());
        if let Ok(decoded) = decoded {
            assert_eq!(
                decoded.base(),
                super::NamespaceTargetBase::OpenedParent(DirectoryNodeId::ROOT)
            );
            assert!(decoded.parents().is_empty());
        }
    }

    let absolute = namespace_information_input(&[
        super::UTF16_BACKSLASH,
        u16::from(b'd'),
        u16::from(b'i'),
        u16::from(b'r'),
        super::UTF16_BACKSLASH,
        u16::from(b'a'),
    ]);
    assert!(absolute.is_some());
    if let Some(absolute) = absolute {
        let decoded = super::NamespaceTargetPath::decode(&absolute, DirectoryNodeId::ROOT);
        assert!(decoded.is_ok());
        if let Ok(decoded) = decoded {
            assert_eq!(decoded.base(), super::NamespaceTargetBase::VolumeRoot);
            assert_eq!(decoded.parents().len(), 1);
        }
    }

    let relative_path =
        namespace_information_input(&[u16::from(b'd'), super::UTF16_BACKSLASH, u16::from(b'a')]);
    assert!(relative_path.is_some());
    if let Some(relative_path) = relative_path {
        assert_eq!(
            super::NamespaceTargetPath::decode(&relative_path, DirectoryNodeId::ROOT),
            Err(DriverError::InvalidParameter)
        );
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn rename_root_directory_field_is_not_supported() {
    let mut input = [0_u8; super::FILE_NAMESPACE_ROOT_DIRECTORY_OFFSET + 8];
    let Some(root_directory) = input.get_mut(
        super::FILE_NAMESPACE_ROOT_DIRECTORY_OFFSET
            ..super::FILE_NAMESPACE_ROOT_DIRECTORY_OFFSET + core::mem::size_of::<wdk_sys::HANDLE>(),
    ) else {
        return;
    };
    let Some(first_byte) = root_directory.get_mut(0) else {
        return;
    };
    *first_byte = 1;

    assert_eq!(
        super::reject_root_directory(&input),
        Err(DriverError::NotSupported)
    );
}
/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
#[expect(
    unsafe_code,
    reason = "the live stack fixtures satisfy ReceivedIrp's raw dispatch-pair contract"
)]
fn rename_replace_flag_decode_boundary_selects_replace_collision() {
    let mut input = [0_u8; core::mem::size_of::<wdk_sys::FILE_RENAME_INFORMATION>()];
    let Some(replace_flag) = input.get_mut(super::FILE_NAMESPACE_REPLACE_IF_EXISTS_OFFSET) else {
        return;
    };
    *replace_flag = 1;
    let name_length = input.get_mut(
        super::FILE_NAMESPACE_NAME_LENGTH_OFFSET
            ..super::FILE_NAMESPACE_NAME_LENGTH_OFFSET + core::mem::size_of::<u32>(),
    );
    assert!(
        name_length.is_some(),
        "test rename buffer contains the name length field"
    );
    let Some(name_length) = name_length else {
        return;
    };
    assert_eq!(
        crate::memory::copy_exact(name_length, &2_u32.to_le_bytes()),
        Ok(())
    );
    let name =
        input.get_mut(super::FILE_NAMESPACE_NAME_OFFSET..super::FILE_NAMESPACE_NAME_OFFSET + 2);
    assert!(
        name.is_some(),
        "test rename buffer contains the first UTF-16 code unit"
    );
    let Some(name) = name else {
        return;
    };
    assert_eq!(
        crate::memory::copy_exact(name, &u16::from(b'a').to_le_bytes()),
        Ok(())
    );

    let mut file_object = wdk_sys::FILE_OBJECT::default();
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        FileObject: core::ptr::addr_of_mut!(file_object),
        ..wdk_sys::IO_STACK_LOCATION::default()
    };
    stack.Parameters.SetFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10 {
        Length: u32::try_from(input.len()).unwrap_or(u32::MAX),
        __bindgen_padding_0: 0,
        FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformation,
        FileObject: core::ptr::null_mut(),
        __bindgen_anon_1:
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10__bindgen_ty_1::default(),
    };

    let mut irp = wdk_sys::IRP::default();
    irp.AssociatedIrp.SystemBuffer = input.as_mut_ptr().cast();
    irp.Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation = core::ptr::addr_of_mut!(stack);

    let mut device = wdk_sys::DEVICE_OBJECT::default();
    let mut target = unsafe {
        // SAFETY: Both stack-local fixtures remain live through the active decode operation.
        ReceivedIrp::decode(
            core::ptr::addr_of_mut!(device),
            core::ptr::addr_of_mut!(irp),
        )
    };
    assert!(target.is_ok());
    if let Ok(target) = target.as_mut() {
        let parsed = target.with_active(|active| {
            let stack = active.current_stack()?.set_file()?;
            super::NamespaceTargetPath::decode(
                active.buffered_input(stack.length())?.as_slice(),
                ext4_core::DirectoryNodeId::ROOT,
            )
        });
        assert!(parsed.is_ok());
        if let Ok(parsed) = parsed {
            assert_eq!(
                super::RenameInformationFormat::ReplaceIfExistsByte.target_collision(&input),
                Ok(ext4_core::RenameTargetCollision::Replace)
            );
            assert_eq!(
                parsed.base(),
                super::NamespaceTargetBase::OpenedParent(ext4_core::DirectoryNodeId::ROOT,)
            );
        }
    }
}
