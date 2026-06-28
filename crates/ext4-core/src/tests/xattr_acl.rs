use super::*;

#[test]
fn in_inode_xattr_round_trips_through_inode_body() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let name = must(XattrName::new(XattrNamespace::User, b"small"));
    let value = must(XattrValue::new(b"value"));

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let node_id = node_id(&volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, node_id);
        must(transaction.set_xattr(node, name.clone(), value.clone()));
        must(transaction.commit());
    }

    let inode_offset = modern_inode_offset(3);
    assert_eq!(get_u32(&image, inode_offset + 104), 0);
    assert_eq!(get_u32(&image, inode_offset + 160), 0xEA02_0000);

    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    assert_eq!(must(volume.read_xattr(inode(3), &name)), Some(value));
    assert_eq!(must(volume.read_xattrs(inode(3))).entries().len(), 1);
}

#[test]
fn external_xattr_block_is_allocated_and_removed() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let name = must(XattrName::new(XattrNamespace::User, b"large"));
    let payload = vec![0xAB; 700];
    let value = must(XattrValue::new(&payload));

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let node_id = node_id(&volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, node_id);
        must(transaction.set_xattr(node, name.clone(), value.clone()));
        must(transaction.commit());
    }

    let inode_offset = modern_inode_offset(3);
    let xattr_block = get_u32(&image, inode_offset + 104);
    assert_ne!(xattr_block, 0);
    let xattr_block_offset = block_offset(xattr_block);
    assert_eq!(get_u32(&image, xattr_block_offset), 0xEA02_0000);
    assert_eq!(get_u32(&image, xattr_block_offset + 4), 1);
    assert_eq!(get_u32(&image, xattr_block_offset + 8), 1);
    assert_ne!(get_u32(&image, xattr_block_offset + 16), 0);

    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    assert_eq!(must(volume.read_xattr(inode(3), &name)), Some(value));

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let node_id = node_id(&volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, node_id);
        assert_eq!(
            must(transaction.remove_xattr(node, &name)),
            Some(must(XattrValue::new(&payload)))
        );
        must(transaction.commit());
    }

    assert_eq!(get_u32(&image, inode_offset + 104), 0);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    assert_eq!(must(volume.read_xattr(inode(3), &name)), None);
}

#[test]
fn posix_acl_uses_typed_acl_boundary() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let acl = must(PosixAcl::new(vec![
        PosixAclEntry::UserObj(must(Ext4Permissions::new(0o700))),
        PosixAclEntry::GroupObj(must(Ext4Permissions::new(0o050))),
        PosixAclEntry::Other(must(Ext4Permissions::new(0o005))),
    ]));
    let acl_value = must(acl.to_xattr_value());

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let node_id = node_id(&volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, node_id);
        must(transaction.set_posix_acl(node, PosixAclKind::Access, acl.clone()));
        must(transaction.commit());
    }

    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    assert_eq!(
        must(volume.read_posix_acl(inode(3), PosixAclKind::Access)),
        Some(acl)
    );
    assert_eq!(
        must(volume.read_xattr(inode(3), &must(PosixAcl::access_xattr_name()))),
        Some(acl_value)
    );
}

#[test]
fn windows_overlay_is_stored_in_user_ext4win_xattr() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let overlay = WindowsOverlay::new(must(Ext4WindowsAttributes::new(
        Ext4WindowsAttributes::HIDDEN | Ext4WindowsAttributes::ARCHIVE,
    )));

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let node_id = node_id(&volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, node_id);
        must(transaction.set_windows_overlay(node, overlay));
        must(transaction.commit());
    }

    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    assert_eq!(must(volume.read_windows_overlay(inode(3))), Some(overlay));
    assert_eq!(
        must(volume.read_xattr(inode(3), &must(WindowsOverlay::attributes_xattr_name()))),
        Some(must(overlay.to_xattr_value()))
    );
}

#[test]
fn minimal_profile_mounts_without_ext_attr_but_rejects_xattr_mutations() {
    let mut image = minimal_write_fixture_image();
    let overlay = WindowsOverlay::new(must(Ext4WindowsAttributes::new(
        Ext4WindowsAttributes::HIDDEN | Ext4WindowsAttributes::ARCHIVE,
    )));
    let acl = must(PosixAcl::new(vec![
        PosixAclEntry::UserObj(must(Ext4Permissions::new(0o700))),
        PosixAclEntry::GroupObj(must(Ext4Permissions::new(0o500))),
        PosixAclEntry::Other(must(Ext4Permissions::new(0o000))),
    ]));

    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    assert_eq!(
        must(volume.read_xattr(
            inode(3),
            &must(XattrName::new(XattrNamespace::User, b"name"))
        )),
        None
    );
    assert_eq!(must(volume.read_windows_overlay(inode(3))), None);

    let node_id = node_id(&volume, inode(3));
    let mut xattr = volume.begin_transaction(NOW);
    let node = transaction_node(&xattr, node_id);
    let result = xattr.set_xattr(
        node,
        must(XattrName::new(XattrNamespace::User, b"name")),
        must(XattrValue::new(b"value")),
    );
    assert_eq!(result, Err(Error::UnsupportedWriteFeature));

    let mut posix_acl = volume.begin_transaction(NOW);
    let node = transaction_node(&posix_acl, node_id);
    let result = posix_acl.set_posix_acl(node, PosixAclKind::Access, acl);
    assert_eq!(result, Err(Error::UnsupportedWriteFeature));

    let mut windows = volume.begin_transaction(NOW);
    let node = transaction_node(&windows, node_id);
    let result = windows.set_windows_overlay(node, overlay);
    assert_eq!(result, Err(Error::UnsupportedWriteFeature));
}
