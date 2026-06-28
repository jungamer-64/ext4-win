use super::*;

#[test]
fn write_mount_accepts_bigalloc() {
    let mut image = bigalloc_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));

    assert_eq!(volume.superblock().cluster_size().bytes(), 4096);
    assert_eq!(volume.superblock().blocks_per_cluster().as_u32(), 4);
    assert_eq!(volume.superblock().clusters_per_group().as_u32(), 2048);
    assert_eq!(volume.superblock().cluster_count().as_u64(), 16);
    assert_eq!(volume.superblock().free_cluster_count().as_u64(), 9);
}

#[test]
fn bigalloc_geometry_rejections_are_targeted() {
    let mut image = bigalloc_fixture_image();
    put_u32(&mut image, 1024 + 28, 0);
    assert_eq!(
        Superblock::parse_read_write(&image[1024..2048]),
        Err(Error::InvalidClusterGeometry)
    );

    let mut image = bigalloc_fixture_image();
    put_u32(&mut image, 1024 + 36, 8192);
    assert_eq!(
        Superblock::parse_read_write(&image[1024..2048]),
        Err(Error::InvalidClusterGeometry)
    );

    let mut image = bigalloc_fixture_image();
    put_u32(&mut image, 1024 + 96, INCOMPAT_MODERN & !0x0040);
    assert_eq!(
        Superblock::parse_read_write(&image[1024..2048]),
        Err(Error::UnsupportedWriteFeature)
    );

    let mut image = variable_block_fixture_image(4096);
    put_u32(&mut image, 1024 + 28, 0);
    assert_eq!(
        Superblock::parse(&image[1024..2048]),
        Err(Error::InvalidClusterGeometry)
    );
}

#[test]
fn bigalloc_hole_write_reuses_logical_cluster() {
    let mut image = bigalloc_fixture_image();
    let initial_free = get_u32(&image, 1024 + 12);
    let file_cluster = bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        overwrite_file(&mut transaction, file_id, 1024, b"hole");
        must(transaction.commit());

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free)
        );
        let mut output = [0_u8; 4];
        assert_eq!(read_file(&volume, 3, 1024, &mut output), 4);
        assert_eq!(&output, b"hole");
    }

    assert_eq!(get_u32(&image, 1024 + 12), initial_free);
    assert!(bigalloc_cluster_is_used(&image, file_cluster));
    assert_eq!(
        &image[block_offset(MODERN_FILE_DATA_BLOCK + 1)
            ..block_offset(MODERN_FILE_DATA_BLOCK + 1) + 4],
        b"hole"
    );
}

#[test]
fn bigalloc_sparse_extension_allocates_one_cluster() {
    let mut image = bigalloc_fixture_image();
    let initial_free = get_u32(&image, 1024 + 12);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE * 5).unwrap_or(u64::MAX),
        );
        overwrite_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE * 4).unwrap_or(u64::MAX),
            b"next",
        );
        must(transaction.commit());

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free - 1)
        );
        let mut output = [0_u8; 4];
        assert_eq!(
            read_file(
                &volume,
                3,
                u64::try_from(BLOCK_SIZE * 4).unwrap_or(u64::MAX),
                &mut output,
            ),
            4
        );
        assert_eq!(&output, b"next");
    }

    assert_eq!(get_u32(&image, 1024 + 12), initial_free - 1);
}

#[test]
fn bigalloc_partial_truncate_preserves_referenced_cluster() {
    let mut image = bigalloc_fixture_image();
    let inode_base = modern_inode_offset(3);
    write_extent_root(&mut image, inode_base + 40, 0, 2, MODERN_FILE_DATA_BLOCK);
    image[block_offset(MODERN_FILE_DATA_BLOCK + 1)..block_offset(MODERN_FILE_DATA_BLOCK + 1) + 4]
        .copy_from_slice(b"tail");
    let initial_free = get_u32(&image, 1024 + 12);
    let file_cluster = bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        truncate_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX),
        );
        must(transaction.commit());

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free)
        );
    }

    assert_eq!(get_u32(&image, 1024 + 12), initial_free);
    assert!(bigalloc_cluster_is_used(&image, file_cluster));
}

#[test]
fn bigalloc_full_truncate_frees_last_cluster_reference() {
    let mut image = bigalloc_fixture_image();
    let initial_free = get_u32(&image, 1024 + 12);
    let file_cluster = bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        truncate_file(&mut transaction, file_id, 0);
        must(transaction.commit());

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free + 1)
        );
    }

    assert_eq!(get_u32(&image, 1024 + 12), initial_free + 1);
    assert!(!bigalloc_cluster_is_used(&image, file_cluster));
}

#[test]
fn bigalloc_unlink_file_frees_last_cluster_reference() {
    let mut image = bigalloc_fixture_image_with_journal_blocks(16);
    put_u16(&mut image, modern_inode_offset(3) + 26, 1);
    let initial_free = get_u32(&image, 1024 + 12);
    let file_cluster = bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, crate::DirectoryNodeId::ROOT);
        must(transaction.unlink_file(root, &must(Ext4Name::new(b"file"))));
        must(transaction.commit());

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free + 1)
        );
    }

    assert_eq!(get_u32(&image, 1024 + 12), initial_free + 1);
    assert!(!bigalloc_cluster_is_used(&image, file_cluster));
}

#[test]
fn bigalloc_two_extents_in_same_physical_cluster_are_indexed() {
    let mut image = bigalloc_fixture_image();
    let inode_base = modern_inode_offset(3);
    put_u32(
        &mut image,
        inode_base + 4,
        u32::try_from(BLOCK_SIZE * 3).unwrap_or(u32::MAX),
    );
    write_two_extent_root(
        &mut image,
        inode_base + 40,
        0,
        1,
        MODERN_FILE_DATA_BLOCK,
        2,
        1,
        MODERN_FILE_DATA_BLOCK + 2,
    );
    let initial_free = get_u32(&image, 1024 + 12);
    let file_cluster = bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        truncate_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX),
        );
        must(transaction.commit());

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free)
        );
    }

    assert!(bigalloc_cluster_is_used(&image, file_cluster));
}

#[test]
fn bigalloc_duplicate_physical_block_reference_is_rejected() {
    let mut image = bigalloc_fixture_image();
    let inode_base = modern_inode_offset(3);
    put_u32(
        &mut image,
        inode_base + 4,
        u32::try_from(BLOCK_SIZE * 2).unwrap_or(u32::MAX),
    );
    write_two_extent_root(
        &mut image,
        inode_base + 40,
        0,
        1,
        MODERN_FILE_DATA_BLOCK,
        1,
        1,
        MODERN_FILE_DATA_BLOCK,
    );
    let device = SliceBlockDeviceMut::new(&mut image);
    let result = Volume::<_, ReadWrite>::mount_read_write(device, test_mount_context());

    assert_eq!(result.map(|_| ()), Err(Error::ClusterReferenceConflict));
}

#[test]
fn bigalloc_mount_rejects_references_into_free_clusters() {
    let mut image = bigalloc_fixture_image();
    set_bigalloc_cluster_used(
        &mut image,
        bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK),
        false,
    );
    let device = SliceBlockDeviceMut::new(&mut image);
    let result = Volume::<_, ReadWrite>::mount_read_write(device, test_mount_context());

    assert_eq!(result.map(|_| ()), Err(Error::ClusterReferenceConflict));
}

#[test]
fn bigalloc_allocated_unreferenced_cluster_remains_unavailable() {
    let mut image = bigalloc_fixture_image();
    let reserved_cluster = 7_u32;
    set_bigalloc_cluster_used(&mut image, reserved_cluster, true);
    let initial_free = get_u32(&image, 1024 + 12) - 1;
    let free_inodes = get_u32(&image, 1024 + 16);
    put_u32(&mut image, 1024 + 12, initial_free);
    write_modern_block_group_descriptor(&mut image, initial_free, free_inodes);
    refresh_primary_block_group_descriptor_checksum(&mut image);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE * 5).unwrap_or(u64::MAX),
        );
        overwrite_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE * 4).unwrap_or(u64::MAX),
            b"next",
        );
        must(transaction.commit());
    }

    assert!(bigalloc_cluster_is_used(&image, reserved_cluster));
    assert!(bigalloc_cluster_is_used(&image, reserved_cluster + 1));
    assert_eq!(&image[block_offset(33)..block_offset(33) + 4], b"next");
}

#[test]
fn bigalloc_directory_create_remove_returns_cluster_count() {
    let mut image = bigalloc_fixture_image_with_journal_blocks(16);
    let initial_free = get_u32(&image, 1024 + 12);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, crate::DirectoryNodeId::ROOT);
        let child = must(transaction.create_directory(
            root,
            &must(Ext4Name::new(b"child")),
            test_directory_metadata(),
        ));
        must(transaction.remove_empty_directory(root, &must(Ext4Name::new(b"child"))));
        assert_eq!(child.id().inode().as_u32(), 11);
        must(transaction.commit());

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free)
        );
    }

    assert_eq!(get_u32(&image, 1024 + 12), initial_free);
}

#[test]
fn bigalloc_extent_metadata_allocation_uses_cluster_accounting() {
    let mut image = bigalloc_fixture_image_with_journal_blocks(16);
    let initial_free = get_u32(&image, 1024 + 12);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE * 10).unwrap_or(u64::MAX),
        );
        for logical in [0_u64, 2, 4, 6, 8] {
            overwrite_file(
                &mut transaction,
                file_id,
                logical.saturating_mul(u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX)),
                b"x",
            );
        }
        must(transaction.commit());

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free - 3)
        );
    }

    let inode_base = modern_inode_offset(3);
    assert_eq!(get_u16(&image, inode_base + 46), 1);
    let extent_block = get_u32(&image, inode_base + 56);
    assert_ne!(extent_block, 0);
    assert!(bigalloc_cluster_is_used(
        &image,
        bigalloc_cluster_for_block(extent_block)
    ));
    assert_eq!(get_u16(&image, block_offset(extent_block)), 0xF30A);
}

#[test]
fn bigalloc_external_xattr_allocation_uses_cluster_accounting() {
    let mut image = bigalloc_fixture_image_with_journal_blocks(16);
    let initial_free = get_u32(&image, 1024 + 12);
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

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free - 1)
        );
    }
    let xattr_block = get_u32(&image, modern_inode_offset(3) + 104);
    assert_ne!(xattr_block, 0);
    assert!(bigalloc_cluster_is_used(
        &image,
        bigalloc_cluster_for_block(xattr_block)
    ));

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let node_id = node_id(&volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, node_id);
        assert_eq!(must(transaction.remove_xattr(node, &name)), Some(value));
        must(transaction.commit());

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free)
        );
    }

    assert_eq!(get_u32(&image, 1024 + 12), initial_free);
    assert!(!bigalloc_cluster_is_used(
        &image,
        bigalloc_cluster_for_block(xattr_block)
    ));
}
