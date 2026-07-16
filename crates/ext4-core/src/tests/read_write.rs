use super::*;

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn sparse_file_reads_zeroes_for_holes() {
    let image = fixture_image();
    let volume = must(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let mut output = vec![0xAA; 1030];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 1030);
    assert!(output[..1024].iter().all(|byte| *byte == 0));
    assert_eq!(&output[1024..1029], b"hello");
    assert_eq!(output[1029], 0);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn uninitialized_extent_reads_as_zeroes() {
    let mut image = fixture_image();
    put_u16(&mut image, inode_offset(3) + 56, 0x8001);
    let volume = must(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let mut output = [0xAA; 5];
    let read = read_file(&volume, 3, 1024, &mut output);

    assert_eq!(read, 5);
    assert_eq!(output, [0, 0, 0, 0, 0]);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn extent_hole_mapping_is_explicit() {
    let mut raw = [0_u8; 60];
    write_extent_root(&mut raw, 0, 1, 1, FILE_DATA_BLOCK);
    let root = crate::disk_format::inode::InodeExtentRoot::from_bytes(raw);
    let tree = must(ExtentTree::load_inode_tree(
        &root,
        must(BlockSize::from_superblock_log(0)),
        &MemoryBlockSource::new(&[]),
        ExtentTreeContext::none(),
    ));

    assert_eq!(
        tree.map_logical(LogicalBlock::from_u32(0)),
        BlockMapping::Hole
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn sparse_hole_write_allocates_block() {
    let mut image = modern_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));

    let file_id = file_node_id(&volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    write_file(&mut transaction, file_id, 1024, b"hole");
    must(transaction.commit());

    let mut output = [0_u8; 4];
    let read = read_file(&volume, 3, 1024, &mut output);
    assert_eq!(read, 4);
    assert_eq!(&output, b"hole");
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn write_extends_created_empty_file() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));

    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&transaction, crate::DirectoryNodeId::ROOT);
    let name = must(Ext4Name::new(b"written"));
    let file = must(transaction.create_file(root, &name, test_file_metadata()));
    must(transaction.write_file_range(file, FileOffset::ZERO, b"created"));
    must(transaction.commit());

    assert_eq!(
        lookup_ext4_inode(&volume, InodeId::ROOT, b"written"),
        Some(inode(11))
    );
    let file = file_node(&volume, 11);
    assert_eq!(file.size().bytes(), 7);
    let mut output = [0_u8; 7];
    assert_eq!(read_file(&volume, 11, 0, &mut output), 7);
    assert_eq!(&output, b"created");
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn extending_write_zeroes_visible_gap_inside_allocated_block() {
    let mut image = modern_fixture_image();
    put_u32(&mut image, modern_inode_offset(3) + 4, 5);
    let data_offset = block_offset(MODERN_FILE_DATA_BLOCK);
    image[data_offset + 5..data_offset + 9].fill(0xA5);
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));

    let file_id = file_node_id(&volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    write_file(&mut transaction, file_id, 9, b"tail");
    must(transaction.commit());

    let file = file_node(&volume, 3);
    assert_eq!(file.size().bytes(), 13);
    let mut output = [0xAA; 13];
    assert_eq!(read_file(&volume, 3, 0, &mut output), 13);
    assert_eq!(&output[..5], b"hello");
    assert_eq!(&output[5..9], &[0, 0, 0, 0]);
    assert_eq!(&output[9..13], b"tail");
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn write_allocates_external_extent_leaf_after_root_capacity() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&volume, 3);
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
        must(transaction.commit());

        let mut output = [0_u8; 1];
        assert_eq!(read_file(&volume, 3, 0, &mut output), 1);
        assert_eq!(output, [b'x']);
        assert_eq!(
            read_file(
                &volume,
                3,
                u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX),
                &mut output
            ),
            1
        );
        assert_eq!(output, [0]);
    }

    let inode_base = modern_inode_offset(3);
    assert_eq!(get_u16(&image, inode_base + 46), 1);
    let extent_block = get_u32(&image, inode_base + 56);
    assert_ne!(extent_block, 0);
    assert_eq!(get_u16(&image, block_offset(extent_block)), 0xF30A);

    let volume = must(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let mut output = [0_u8; 1];
    assert_eq!(
        read_file(
            &volume,
            3,
            8_u64.saturating_mul(u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX)),
            &mut output
        ),
        1
    );
    assert_eq!(output, [b'x']);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn mutable_extent_tree_serializes_depth_two_indexes() {
    let block_size = must(BlockSize::from_superblock_log(0));
    let mut extents = Vec::new();
    for index in 0..337_u32 {
        extents.push(Extent::initialized(
            LogicalBlock::from_u32(index.saturating_mul(2)),
            must(ExtentLength::new(1)),
            BlockAddress::new(1_000 + u64::from(index)),
        ));
    }
    let mut tree = must(MutableExtentTree::from_extents(extents));
    let metadata_blocks = (1..=6).map(BlockAddress::new).collect::<Vec<_>>();
    tree.set_metadata_blocks(metadata_blocks);
    let serialized = must(tree.serialize(block_size, ExtentTreeContext::none()));

    let mut image = vec![0_u8; BLOCK_SIZE * 8];
    for block in serialized.external_blocks() {
        let offset = block_offset(u32::try_from(block.block().get()).unwrap_or(u32::MAX));
        image[offset..offset + BLOCK_SIZE].copy_from_slice(block.bytes());
    }
    let loaded = must(MutableExtentTree::load_inode_tree(
        &InodeExtentRoot::from_bytes(*serialized.inode_root()),
        block_size,
        &MemoryBlockSource::new(&image),
        ExtentTreeContext::none(),
    ));

    assert_eq!(loaded.extents().len(), 337);
    assert_eq!(
        loaded.map_logical(LogicalBlock::from_u32(672)),
        BlockMapping::Physical(BlockAddress::new(1_336))
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn external_extent_block_checksum_mismatch_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&volume, 3);
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
        must(transaction.commit());
    }

    let extent_block = get_u32(&image, modern_inode_offset(3) + 56);
    let checksum_offset = block_offset(extent_block) + BLOCK_SIZE - 4;
    image[checksum_offset] ^= 0x80;

    let volume = must(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let file = file_node(&volume, 3);
    let mut output = [0_u8; 1];
    let result = volume.read_file(&file, FileOffset::ZERO, &mut output);

    assert_eq!(result, Err(Error::ChecksumMismatch));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn uninitialized_extent_write_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u16(&mut image, modern_inode_offset(3) + 56, 0x8001);
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
    let file_id = file_node_id(&volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    let file = transaction_file(&transaction, file_id);
    let result = transaction.write_file_range(file, FileOffset::ZERO, b"x");

    assert_eq!(result, Err(Error::UnsupportedInodeMutation));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn inode_protection_flags_are_typed_before_mutation_policy() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let context_bytes = fscrypt_v2_context_bytes();
    install_inline_fscrypt_context(&mut image, 3, &context_bytes);
    let file_flags = get_u32(&image, modern_inode_offset(3) + 32) | EXT4_VERITY_FL;
    put_u32(&mut image, modern_inode_offset(3) + 32, file_flags);
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));

    let file = file_node(&volume, 3);
    assert_eq!(file.protection(), InodeProtection::EncryptedVerity);
    let file_id = file.id();

    let mut transaction = volume.begin_transaction(NOW);
    let file = transaction_file(&transaction, file_id);
    let result = transaction.write_file_range(file, FileOffset::ZERO, b"x");

    assert_eq!(result, Err(Error::MissingEncryptionKey));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn extend_file_creates_sparse_range() {
    let mut image = modern_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));

    let file_id = file_node_id(&volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    extend_file(&mut transaction, file_id, 3072);
    must(transaction.commit());

    let file = file_node(&volume, 3);
    let mut output = [0xAA; 4];
    let read = read_file(&volume, 3, 2048, &mut output);
    assert_eq!(file.size().bytes(), 3072);
    assert_eq!(read, 4);
    assert_eq!(output, [0, 0, 0, 0]);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn minimal_profile_rejects_file_size_beyond_large_file_boundary() {
    let mut image = minimal_write_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
    let file_id = file_node_id(&volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    let file = transaction_file(&transaction, file_id);
    let result = transaction.extend_file(file, FileSize::from_bytes(0x8000_0000));

    assert_eq!(result, Err(Error::UnsupportedInodeMutation));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn minimal_profile_rejects_extending_write_beyond_large_file_boundary() {
    let mut image = minimal_write_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
    let file_id = file_node_id(&volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    let file = transaction_file(&transaction, file_id);
    let result = transaction.write_file_range(file, FileOffset::from_bytes(0x7FFF_FFFF), b"x");

    assert_eq!(result, Err(Error::UnsupportedInodeMutation));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn truncate_file_releases_blocks() {
    let mut image = modern_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));

    let file_id = file_node_id(&volume, 3);
    let mut write = volume.begin_transaction(NOW);
    write_file(&mut write, file_id, 1024, b"hole");
    must(write.commit());
    let mut truncate = volume.begin_transaction(NOW);
    truncate_file(&mut truncate, file_id, 0);
    must(truncate.commit());

    let file = file_node(&volume, 3);
    assert_eq!(file.size().bytes(), 0);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn transaction_too_large_is_rejected_before_writes() {
    let mut image = modern_fixture_image_with_journal_blocks(3);
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
    let file_id = file_node_id(&volume, 3);
    let mut transaction = volume.begin_transaction(NOW);

    write_file(&mut transaction, file_id, 1024, b"hole");
    let result = transaction.commit();

    assert!(matches!(result, Err(Error::TransactionTooLarge)));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn inode_security_is_parsed_from_owner_and_mode() {
    let image = modern_fixture_image();
    let device = MemoryBlockSource::new(&image);
    let volume = must(ReadOnlyVolume::mount(device, test_mount_context()));

    let file = file_node(&volume, 3);
    assert_eq!(file.security().owner().uid().as_u32(), 0);
    assert_eq!(file.security().owner().gid().as_u32(), 0);
    assert_eq!(file.security().permissions().as_u16(), 0o444);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn inode_times_are_parsed_from_inode_fields() {
    let mut image = modern_fixture_image();
    let offset = modern_inode_offset(3);
    put_u32(&mut image, offset + 8, 11);
    put_u32(&mut image, offset + 12, 22);
    put_u32(&mut image, offset + 16, 33);
    put_u32(&mut image, offset + 144, 44);

    let device = MemoryBlockSource::new(&image);
    let volume = must(ReadOnlyVolume::mount(device, test_mount_context()));
    let file = file_node(&volume, 3);

    assert_eq!(
        file.times(),
        Ext4Times::new(
            Ext4Timestamp::from_unix_seconds(11),
            Ext4Timestamp::from_unix_seconds(33),
            Ext4Timestamp::from_unix_seconds(22),
            Ext4Timestamp::from_unix_seconds(44),
        )
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn set_posix_security_updates_owner_and_permissions() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let security = Ext4Security::new(
            Ext4Owner::new(
                Ext4Uid::from_u32(0x0002_0001),
                Ext4Gid::from_u32(0x0004_0003),
            ),
            must(Ext4Permissions::new(0o6750)),
        );
        let node_id = node_id(&volume, inode(3));

        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, node_id);
        must(transaction.set_posix_security(node, security));
        must(transaction.commit());

        let file = file_node(&volume, 3);
        assert_eq!(file.security(), security);
    }

    let inode_offset = modern_inode_offset(3);
    assert_eq!(get_u16(&image, inode_offset) & 0o7777, 0o6750);
    assert_eq!(get_u16(&image, inode_offset + 2), 1);
    assert_eq!(get_u16(&image, inode_offset + 24), 3);
    assert_eq!(get_u16(&image, inode_offset + 120), 2);
    assert_eq!(get_u16(&image, inode_offset + 122), 4);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn set_times_updates_inode_timestamp_fields() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let times = Ext4Times::new(
        Ext4Timestamp::from_unix_seconds(11),
        Ext4Timestamp::from_unix_seconds(22),
        Ext4Timestamp::from_unix_seconds(33),
        Ext4Timestamp::from_unix_seconds(44),
    );

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let node_id = node_id(&volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, node_id);
        must(transaction.set_times(node, times));
        must(transaction.commit());
    }

    let inode_offset = modern_inode_offset(3);
    assert_eq!(get_u32(&image, inode_offset + 8), 11);
    assert_eq!(get_u32(&image, inode_offset + 16), 22);
    assert_eq!(get_u32(&image, inode_offset + 12), 33);
    assert_eq!(get_u32(&image, inode_offset + 144), 44);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn minimal_profile_does_not_write_extra_inode_timestamp_fields() {
    let mut image = minimal_write_fixture_image();
    let times = Ext4Times::new(
        Ext4Timestamp::from_unix_seconds(11),
        Ext4Timestamp::from_unix_seconds(22),
        Ext4Timestamp::from_unix_seconds(33),
        Ext4Timestamp::from_unix_seconds(44),
    );

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let node_id = node_id(&volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, node_id);
        must(transaction.set_times(node, times));
        must(transaction.commit());
    }

    let inode_offset = modern_inode_offset(3);
    assert_eq!(get_u32(&image, inode_offset + 8), 11);
    assert_eq!(get_u32(&image, inode_offset + 16), 22);
    assert_eq!(get_u32(&image, inode_offset + 12), 33);
    assert_eq!(get_u16(&image, inode_offset + 128), 0);
    assert_eq!(get_u32(&image, inode_offset + 144), 0);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn volume_label_round_trips_through_superblock() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let label = must(Ext4VolumeLabel::new(b"EXT4WIN"));

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        transaction.set_volume_label(label);
        must(transaction.commit());
    }

    assert_eq!(&image[1024 + 120..1024 + 127], b"EXT4WIN");
    assert_eq!(&image[1024 + 127..1024 + 136], &[0_u8; 9]);

    let volume = must(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    assert_eq!(volume.identity().label(), label);
    assert_eq!(volume.identity().label().bytes(), b"EXT4WIN");
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn volume_label_rejects_unrepresentable_bytes() {
    assert_eq!(
        Ext4VolumeLabel::new(b"12345678901234567"),
        Err(Error::InvalidName)
    );
    assert_eq!(Ext4VolumeLabel::new(b"bad\0label"), Err(Error::InvalidName));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn bad_tag_checksum_transaction_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 9, 1);
    write_jbd2_data(&mut image, 2, b"BAD!!");
    write_jbd2_descriptor_with_checksum(&mut image, 1, 9, MODERN_FILE_DATA_BLOCK, 0xDEAD_BEEF);
    write_jbd2_commit(&mut image, 3, 9);

    let device = MemoryBlockStorage::new(&mut image);
    let result = JournaledVolume::mount(device, test_mount_context());

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
    assert_eq!(get_be_u32(&image, journal_log_offset(0) + 0x1C), 1);
    assert_ne!(get_u32(&image, 1024 + 96) & INCOMPAT_RECOVER, 0);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn extent_depth_traversal_reads_index_block() {
    let mut image = modern_fixture_image();
    write_indexed_file_inode(&mut image);
    let volume = must(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}
