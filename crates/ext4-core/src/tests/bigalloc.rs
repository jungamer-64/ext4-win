use super::*;

fn superblock_free_blocks(image: &[u8]) -> u32 {
    get_u32(image, 1024 + 12)
}

fn bigalloc_free_clusters(image: &[u8]) -> u32 {
    superblock_free_blocks(image) / BIGALLOC_BLOCKS_PER_CLUSTER
}

fn primary_group_free_clusters(image: &[u8]) -> u32 {
    let descriptor = block_offset(2);
    u32::from(get_u16(image, descriptor + 12)) | (u32::from(get_u16(image, descriptor + 44)) << 16)
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn write_mount_accepts_bigalloc() {
    let mut image = bigalloc_fixture_image();
    let superblock = must(Superblock::parse_read_write(&image[1024..2048]));
    let device = MemoryBlockStorage::new(&mut image);
    let volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    assert_eq!(volume.geometry().cluster_size().bytes(), 4096);
    assert_eq!(superblock.blocks_per_cluster().as_u32(), 4);
    assert_eq!(superblock.clusters_per_group().as_u32(), 2048);
    assert_eq!(volume.geometry().cluster_count().as_u64(), 16);
    assert_eq!(volume.geometry().free_cluster_count().as_u64(), 9);
    assert_eq!(superblock_free_blocks(&image), 36);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
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
    put_u32(&mut image, 1024 + 12, 35);
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

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bigalloc_hole_write_reuses_logical_cluster() {
    let mut image = bigalloc_fixture_image();
    let initial_free_blocks = superblock_free_blocks(&image);
    let initial_free_clusters = bigalloc_free_clusters(&image);
    let file_cluster = bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&mut volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        write_file(&mut transaction, file_id, 1024, b"hole");
        must_run(transaction.commit());

        assert_eq!(
            volume.geometry().free_cluster_count().as_u64(),
            u64::from(initial_free_clusters)
        );
        assert_eq!(
            file_node(&mut volume, 3).allocation_size().bytes(),
            u64::from(BIGALLOC_BLOCKS_PER_CLUSTER) * BLOCK_SIZE_U64
        );
        let mut output = [0_u8; 4];
        assert_eq!(read_file(&mut volume, 3, 1024, &mut output), 4);
        assert_eq!(&output, b"hole");
    }

    assert_eq!(superblock_free_blocks(&image), initial_free_blocks);
    assert!(bigalloc_cluster_is_used(&image, file_cluster));
    assert_eq!(
        &image[block_offset(MODERN_FILE_DATA_BLOCK + 1)
            ..block_offset(MODERN_FILE_DATA_BLOCK + 1) + 4],
        b"hole"
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bigalloc_sparse_extension_allocates_one_cluster() {
    let mut image = bigalloc_fixture_image();
    let initial_free_blocks = superblock_free_blocks(&image);
    let initial_free_clusters = bigalloc_free_clusters(&image);
    let initial_group_free_clusters = primary_group_free_clusters(&image);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&mut volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE * 5).unwrap_or(u64::MAX),
        );
        write_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE * 4).unwrap_or(u64::MAX),
            b"next",
        );
        must_run(transaction.commit());

        assert_eq!(
            volume.geometry().free_cluster_count().as_u64(),
            u64::from(initial_free_clusters - 1)
        );
        assert_eq!(
            file_node(&mut volume, 3).allocation_size().bytes(),
            2 * u64::from(BIGALLOC_BLOCKS_PER_CLUSTER) * BLOCK_SIZE_U64
        );
        let mut output = [0_u8; 4];
        assert_eq!(
            read_file(
                &mut volume,
                3,
                u64::try_from(BLOCK_SIZE * 4).unwrap_or(u64::MAX),
                &mut output,
            ),
            4
        );
        assert_eq!(&output, b"next");
    }

    assert_eq!(
        superblock_free_blocks(&image),
        initial_free_blocks - BIGALLOC_BLOCKS_PER_CLUSTER
    );
    assert_eq!(
        primary_group_free_clusters(&image),
        initial_group_free_clusters - 1
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bigalloc_partial_truncate_preserves_referenced_cluster() {
    let mut image = bigalloc_fixture_image();
    let inode_base = modern_inode_offset(3);
    write_extent_root(&mut image, inode_base + 40, 0, 2, MODERN_FILE_DATA_BLOCK);
    image[block_offset(MODERN_FILE_DATA_BLOCK + 1)..block_offset(MODERN_FILE_DATA_BLOCK + 1) + 4]
        .copy_from_slice(b"tail");
    let initial_free_blocks = superblock_free_blocks(&image);
    let initial_free_clusters = bigalloc_free_clusters(&image);
    let file_cluster = bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&mut volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        truncate_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX),
        );
        must_run(transaction.commit());

        assert_eq!(
            volume.geometry().free_cluster_count().as_u64(),
            u64::from(initial_free_clusters)
        );
        assert_eq!(
            file_node(&mut volume, 3).allocation_size().bytes(),
            u64::from(BIGALLOC_BLOCKS_PER_CLUSTER) * BLOCK_SIZE_U64
        );
    }

    assert_eq!(superblock_free_blocks(&image), initial_free_blocks);
    assert!(bigalloc_cluster_is_used(&image, file_cluster));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bigalloc_full_truncate_frees_last_cluster_reference() {
    let mut image = bigalloc_fixture_image();
    let initial_free_blocks = superblock_free_blocks(&image);
    let initial_free_clusters = bigalloc_free_clusters(&image);
    let file_cluster = bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&mut volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        truncate_file(&mut transaction, file_id, 0);
        must_run(transaction.commit());

        assert_eq!(
            volume.geometry().free_cluster_count().as_u64(),
            u64::from(initial_free_clusters + 1)
        );
    }

    assert_eq!(
        superblock_free_blocks(&image),
        initial_free_blocks + BIGALLOC_BLOCKS_PER_CLUSTER
    );
    assert!(!bigalloc_cluster_is_used(&image, file_cluster));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bigalloc_unlink_file_frees_last_cluster_reference() {
    let mut image = bigalloc_fixture_image_with_journal_blocks(16);
    put_u16(&mut image, modern_inode_offset(3) + 26, 1);
    let initial_free_blocks = superblock_free_blocks(&image);
    let initial_free_clusters = bigalloc_free_clusters(&image);
    let file_cluster = bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
        must_run(transaction.unlink_file(root, &must(Ext4Name::new(b"file"))));
        must_run(transaction.commit());

        assert_eq!(
            volume.geometry().free_cluster_count().as_u64(),
            u64::from(initial_free_clusters + 1)
        );
    }

    assert_eq!(
        superblock_free_blocks(&image),
        initial_free_blocks + BIGALLOC_BLOCKS_PER_CLUSTER
    );
    assert!(!bigalloc_cluster_is_used(&image, file_cluster));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
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
    let initial_free_clusters = bigalloc_free_clusters(&image);
    let file_cluster = bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&mut volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        truncate_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX),
        );
        must_run(transaction.commit());

        assert_eq!(
            volume.geometry().free_cluster_count().as_u64(),
            u64::from(initial_free_clusters)
        );
    }

    assert!(bigalloc_cluster_is_used(&image, file_cluster));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
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
    let device = MemoryBlockStorage::new(&mut image);
    let result = run(JournaledVolume::mount(device, test_mount_context()));

    assert_eq!(result.map(|_| ()), Err(Error::ClusterReferenceConflict));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bigalloc_mount_rejects_references_into_free_clusters() {
    let mut image = bigalloc_fixture_image();
    set_bigalloc_cluster_used(
        &mut image,
        bigalloc_cluster_for_block(MODERN_FILE_DATA_BLOCK),
        false,
    );
    let device = MemoryBlockStorage::new(&mut image);
    let result = run(JournaledVolume::mount(device, test_mount_context()));

    assert_eq!(result.map(|_| ()), Err(Error::ClusterReferenceConflict));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bigalloc_allocated_unreferenced_cluster_remains_unavailable() {
    let mut image = bigalloc_fixture_image();
    let reserved_cluster = 7_u32;
    set_bigalloc_cluster_used(&mut image, reserved_cluster, true);
    let free_blocks = superblock_free_blocks(&image) - BIGALLOC_BLOCKS_PER_CLUSTER;
    let free_clusters = bigalloc_free_clusters(&image) - 1;
    let free_inodes = get_u32(&image, 1024 + 16);
    put_u32(&mut image, 1024 + 12, free_blocks);
    write_modern_block_group_descriptor(&mut image, free_clusters, free_inodes);
    refresh_primary_block_group_descriptor_checksum(&mut image);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&mut volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE * 5).unwrap_or(u64::MAX),
        );
        write_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE * 4).unwrap_or(u64::MAX),
            b"next",
        );
        must_run(transaction.commit());
    }

    assert!(bigalloc_cluster_is_used(&image, reserved_cluster));
    assert!(bigalloc_cluster_is_used(&image, reserved_cluster + 1));
    assert_eq!(&image[block_offset(33)..block_offset(33) + 4], b"next");
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bigalloc_directory_create_remove_returns_cluster_count() {
    let mut image = bigalloc_fixture_image_with_journal_blocks(16);
    let initial_free_blocks = superblock_free_blocks(&image);
    let initial_free_clusters = bigalloc_free_clusters(&image);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
        let child = must_run(transaction.create_directory(
            root,
            &must(Ext4Name::new(b"child")),
            test_directory_metadata(),
        ));
        must_run(transaction.remove_empty_directory(root, &must(Ext4Name::new(b"child"))));
        assert_eq!(child.id().inode().as_u32(), 11);
        must_run(transaction.commit());

        assert_eq!(
            volume.geometry().free_cluster_count().as_u64(),
            u64::from(initial_free_clusters)
        );
    }

    assert_eq!(superblock_free_blocks(&image), initial_free_blocks);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bigalloc_extent_metadata_allocation_uses_cluster_accounting() {
    let mut image = bigalloc_fixture_image_with_journal_blocks(16);
    let initial_free_clusters = bigalloc_free_clusters(&image);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&mut volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            file_id,
            u64::try_from(BLOCK_SIZE * 10).unwrap_or(u64::MAX),
        );
        for logical in [0_u64, 2, 4, 6, 8] {
            write_file(
                &mut transaction,
                file_id,
                logical.saturating_mul(u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX)),
                b"x",
            );
        }
        must_run(transaction.commit());

        assert_eq!(
            volume.geometry().free_cluster_count().as_u64(),
            u64::from(initial_free_clusters - 3)
        );
        assert_eq!(
            file_node(&mut volume, 3).allocation_size().bytes(),
            4 * u64::from(BIGALLOC_BLOCKS_PER_CLUSTER) * BLOCK_SIZE_U64
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

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bigalloc_external_xattr_allocation_uses_cluster_accounting() {
    let mut image = bigalloc_fixture_image_with_journal_blocks(16);
    let initial_free_blocks = superblock_free_blocks(&image);
    let initial_free_clusters = bigalloc_free_clusters(&image);
    let name = must(XattrName::new(XattrNamespace::User, b"large"));
    let payload = vec![0xAB; 700];
    let value = must(XattrValue::new(&payload));

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let node_id = node_id(&mut volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&mut transaction, node_id);
        must_run(transaction.set_xattr(node, name.clone(), value.clone()));
        must_run(transaction.commit());

        assert_eq!(
            volume.geometry().free_cluster_count().as_u64(),
            u64::from(initial_free_clusters - 1)
        );
    }
    let xattr_block = get_u32(&image, modern_inode_offset(3) + 104);
    assert_ne!(xattr_block, 0);
    assert!(bigalloc_cluster_is_used(
        &image,
        bigalloc_cluster_for_block(xattr_block)
    ));

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let node_id = node_id(&mut volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&mut transaction, node_id);
        assert_eq!(must_run(transaction.remove_xattr(node, &name)), Some(value));
        must_run(transaction.commit());

        assert_eq!(
            volume.geometry().free_cluster_count().as_u64(),
            u64::from(initial_free_clusters)
        );
    }

    assert_eq!(superblock_free_blocks(&image), initial_free_blocks);
    assert!(!bigalloc_cluster_is_used(
        &image,
        bigalloc_cluster_for_block(xattr_block)
    ));
}
