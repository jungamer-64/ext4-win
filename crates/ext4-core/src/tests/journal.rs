use super::*;

#[test]
fn dirty_volume_is_rejected() {
    let mut image = fixture_image();
    put_u16(&mut image, 1024 + 58, 0);
    let result = ReadOnlyVolume::mount(SliceBlockDevice::new(&image), test_mount_context());

    assert!(matches!(result, Err(Error::DirtyVolume)));
}

#[test]
fn metadata_descriptor_checksum_is_verified() {
    let image = modern_fixture_image();
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));

    assert_eq!(read_directory(&volume, InodeId::ROOT).len(), 3);
}

#[test]
fn bad_metadata_descriptor_checksum_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    corrupt_primary_block_group_descriptor_checksum(&mut image);
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let result = volume.root_directory();

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

#[test]
fn gdt_descriptor_checksum_is_verified() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 100, 0x0001 | 0x0002 | RO_COMPAT_GDT_CSUM);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));

    assert_eq!(read_directory(&volume, InodeId::ROOT).len(), 4);
}

#[test]
fn bad_gdt_descriptor_checksum_is_rejected() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 100, 0x0001 | 0x0002 | RO_COMPAT_GDT_CSUM);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    corrupt_primary_block_group_descriptor_checksum(&mut image);
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let result = volume.root_directory();

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

#[test]
fn jbd2_header_is_big_endian() {
    let mut block = [0_u8; 12];
    must(crate::disk_format::journal::Jbd2Header::descriptor(7).encode(&mut block));
    let header = must(crate::disk_format::journal::Jbd2Header::parse(&block));

    assert_eq!(header.block_type(), 1);
    assert_eq!(header.sequence(), 7);
}

#[test]
fn write_mount_accepts_minimal_journaled_profile() {
    let mut image = minimal_write_fixture_image();
    let superblock = must(Superblock::parse_read_write(&image[1024..2048]));
    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));

    assert_eq!(superblock.journal_mode(), JournalMode::Internal(inode(8)));
    let mut output = [0_u8; 5];
    assert_eq!(read_file(&volume, 3, 0, &mut output), 5);
    assert_eq!(&output, b"hello");
}

#[test]
fn gdt_csum_minimal_profile_refreshes_descriptor_checksum_after_write() {
    let mut image = minimal_write_fixture_image_with_gdt_csum();
    let checksum_offset = block_offset(2) + 30;
    let before = get_u16(&image, checksum_offset);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, crate::DirectoryNodeId::ROOT);
        must(transaction.create_file(root, &must(Ext4Name::new(b"new")), test_file_metadata()));
        must(transaction.commit());
    }

    assert_ne!(get_u16(&image, checksum_offset), before);
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    assert_eq!(
        lookup_ext4_inode(&volume, InodeId::ROOT, b"new"),
        Some(inode(11))
    );
}

#[test]
fn overwrite_existing_file_range_commits() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));

    let file_id = file_node_id(&volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    overwrite_file(&mut transaction, file_id, 0, b"HELLO");
    must(transaction.commit());

    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);
    assert_eq!(read, 5);
    assert_eq!(&output, b"HELLO");
}

#[test]
fn committed_dirty_journal_transaction_is_replayed() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 7, 1);
    write_jbd2_data(&mut image, 2, b"REPLAY");
    write_jbd2_descriptor(&mut image, 1, 7, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, 7);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let volume = must(JournaledVolume::mount(device, test_mount_context()));
        let mut output = [0_u8; 6];
        let read = read_file(&volume, 3, 0, &mut output);
        assert_eq!(read, 6);
        assert_eq!(&output, b"REPLAY");
    }

    assert_eq!(get_be_u32(&image, journal_log_offset(0) + 0x1C), 0);
    assert_eq!(get_u32(&image, 1024 + 96) & INCOMPAT_RECOVER, 0);
}

#[test]
fn descriptor_without_commit_is_ignored() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 8, 1);
    write_jbd2_data(&mut image, 2, b"IGNORE");
    write_jbd2_descriptor(&mut image, 1, 8, MODERN_FILE_DATA_BLOCK, 0);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}

#[test]
fn later_revoke_prevents_stale_metadata_replay() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 10, 1);
    write_jbd2_data(&mut image, 2, b"STALE");
    write_jbd2_descriptor(&mut image, 1, 10, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, 10);
    write_jbd2_revoke(&mut image, 4, 11, MODERN_FILE_DATA_BLOCK);
    write_jbd2_commit(&mut image, 5, 11);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}

#[test]
fn circular_journal_wraparound_is_replayed() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 12, 6);
    write_jbd2_data(&mut image, 7, b"WRAP!");
    write_jbd2_descriptor(&mut image, 6, 12, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 1, 12);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"WRAP!");
}

#[test]
fn escaped_journal_data_block_is_unescaped_on_replay() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 13, 1);
    write_jbd2_data(&mut image, 2, &[0, 0, 0, 0, b'E']);
    write_jbd2_descriptor(
        &mut image,
        1,
        13,
        MODERN_FILE_DATA_BLOCK,
        JBD2_TAG_FLAG_ESCAPE,
    );
    write_jbd2_commit(&mut image, 3, 13);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output[..4], &JBD2_MAGIC.to_be_bytes());
    assert_eq!(output[4], b'E');
}

#[test]
fn checkpointed_dirty_journal_replay_is_idempotent() {
    let mut image = modern_fixture_image();
    let home = block_offset(MODERN_FILE_DATA_BLOCK);
    image[home..home + 5].copy_from_slice(b"DONE!");
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 14, 1);
    write_jbd2_data(&mut image, 2, b"DONE!");
    write_jbd2_descriptor(&mut image, 1, 14, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, 14);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"DONE!");
}

#[test]
fn external_journal_uuid_mismatch_is_rejected() {
    let mut image = modern_fixture_image();
    make_external_journal_filesystem(&mut image, [1; 16]);
    let mut journal = vec![0_u8; BLOCK_SIZE * 16];
    write_jbd2_superblock_at(
        &mut journal,
        EXTERNAL_JOURNAL_SUPERBLOCK_OFFSET,
        8,
        [2; 16],
        1,
        0,
        default_journal_incompat(),
    );

    let result: crate::Result<JournaledVolume<_, ExternalJournal<_>>> =
        JournaledVolume::mount_with_external_journal(
            SliceBlockDeviceMut::new(&mut image),
            SliceBlockDeviceMut::new(&mut journal),
            test_mount_context(),
        );

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn fast_commit_journal_feature_is_rejected() {
    let mut image = modern_fixture_image();
    write_jbd2_superblock_at(
        &mut image,
        journal_log_offset(0),
        8,
        [0; 16],
        1,
        0,
        default_journal_incompat() | JBD2_FEATURE_INCOMPAT_FAST_COMMIT,
    );
    let device = SliceBlockDeviceMut::new(&mut image);
    let result = JournaledVolume::mount(device, test_mount_context());

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn write_transaction_emits_descriptor_data_and_commit_records() {
    let mut image = modern_fixture_image();
    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        overwrite_file(&mut transaction, file_id, 0, b"HELLO");
        must(transaction.commit());
    }

    assert_eq!(get_be_u32(&image, journal_log_offset(1)), JBD2_MAGIC);
    assert_eq!(
        get_be_u32(&image, journal_log_offset(1) + 4),
        JBD2_DESCRIPTOR_BLOCK
    );
    assert_eq!(get_be_u32(&image, journal_log_offset(3)), JBD2_MAGIC);
    assert_eq!(
        get_be_u32(&image, journal_log_offset(3) + 4),
        JBD2_COMMIT_BLOCK
    );
}

#[test]
fn emitted_committed_records_are_replayable_after_checkpoint_loss() {
    let mut image = modern_fixture_image();
    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(&mut transaction, file_id, 3072);
        must(transaction.commit());
    }

    put_u32(&mut image, modern_inode_offset(3) + 4, 2048);
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 1, 1);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let file = file_node(&volume, 3);

    assert_eq!(file.size().bytes(), 3072);
}

#[test]
fn legacy_32bit_descriptor_tag_is_replayed() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_jbd2_superblock_at(&mut image, journal_log_offset(0), 8, [0; 16], 15, 1, 0);
    write_jbd2_descriptor_32bit(&mut image, 1, 15, MODERN_FILE_DATA_BLOCK);
    write_jbd2_data(&mut image, 2, b"32BIT");
    write_jbd2_commit(&mut image, 3, 15);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"32BIT");
}

#[test]
fn csum_v2_descriptor_tail_and_commit_checksum_are_verified() {
    let mut image = modern_fixture_image();
    let uuid = [3; 16];
    mark_filesystem_needs_recovery(&mut image);
    write_jbd2_superblock_at(
        &mut image,
        journal_log_offset(0),
        8,
        uuid,
        16,
        1,
        JBD2_FEATURE_INCOMPAT_CSUM_V2,
    );
    write_jbd2_data(&mut image, 2, b"V2OK!");
    write_jbd2_descriptor_csum_v2(&mut image, 1, 16, MODERN_FILE_DATA_BLOCK, uuid);
    write_jbd2_commit_with_checksum(&mut image, 3, 16, uuid);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"V2OK!");
}

#[test]
fn zero_tag_checksum_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 17, 1);
    write_jbd2_data(&mut image, 2, b"ZERO!");
    write_jbd2_descriptor_with_checksum(&mut image, 1, 17, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, 17);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

#[test]
fn zero_descriptor_tail_checksum_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 18, 1);
    write_jbd2_data(&mut image, 2, b"TAIL!");
    write_jbd2_descriptor(&mut image, 1, 18, MODERN_FILE_DATA_BLOCK, 0);
    put_be_u32(&mut image, journal_log_offset(1) + BLOCK_SIZE - 4, 0);
    write_jbd2_commit(&mut image, 3, 18);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

#[test]
fn invalid_commit_checksum_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 19, 1);
    write_jbd2_data(&mut image, 2, b"COMIT");
    write_jbd2_descriptor(&mut image, 1, 19, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, 19);
    put_be_u32(&mut image, journal_log_offset(3) + 0x10, 0xDEAD_BEEF);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

#[test]
fn invalid_revoke_tail_checksum_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 20, 1);
    write_jbd2_revoke(&mut image, 1, 20, MODERN_FILE_DATA_BLOCK);
    put_be_u32(
        &mut image,
        journal_log_offset(1) + BLOCK_SIZE - 4,
        0xDEAD_BEEF,
    );
    write_jbd2_commit(&mut image, 2, 20);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

#[test]
fn journal_superblock_fields_and_checksum_are_preserved_when_cleaned() {
    let mut image = modern_fixture_image();
    let base = journal_log_offset(0);
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 21, 1);
    put_be_u32(&mut image, base + 0x58, 0x1122_3344);
    refresh_jbd2_superblock_checksum(&mut image, base);
    write_jbd2_data(&mut image, 2, b"KEEP!");
    write_jbd2_descriptor(&mut image, 1, 21, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, 21);

    let device = SliceBlockDeviceMut::new(&mut image);
    let _volume = must(JournaledVolume::mount(device, test_mount_context()));

    assert_eq!(get_be_u32(&image, base + 0x18), 22);
    assert_eq!(get_be_u32(&image, base + 0x1C), 0);
    assert_eq!(get_be_u32(&image, base + 0x58), 0x1122_3344);
    assert_eq!(
        get_be_u32(&image, base + 0xFC),
        jbd2_superblock_checksum(&image, base)
    );
}

#[test]
fn journal_sequence_wraps_after_max_transaction() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, u32::MAX, 1);
    write_jbd2_data(&mut image, 2, b"WRAP0");
    write_jbd2_descriptor(&mut image, 1, u32::MAX, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, u32::MAX);

    let device = SliceBlockDeviceMut::new(&mut image);
    let _volume = must(JournaledVolume::mount(device, test_mount_context()));

    assert_eq!(get_be_u32(&image, journal_log_offset(0) + 0x18), 0);
    assert_eq!(get_be_u32(&image, journal_log_offset(0) + 0x1C), 0);
}

#[test]
fn nonzero_journal_ro_compat_is_rejected() {
    let mut image = modern_fixture_image();
    put_be_u32(&mut image, journal_log_offset(0) + 0x2C, 1);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn recovery_required_with_zero_journal_start_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::JournalCorrupt)));
    assert_ne!(get_u32(&image, 1024 + 96) & INCOMPAT_RECOVER, 0);
}

#[test]
fn replay_target_outside_filesystem_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 22, 1);
    write_jbd2_data(&mut image, 2, b"OUT!!");
    write_jbd2_descriptor(
        &mut image,
        1,
        22,
        u32::try_from(MODERN_IMAGE_BLOCKS).unwrap_or(u32::MAX),
        0,
    );
    write_jbd2_commit(&mut image, 3, 22);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::JournalCorrupt)));
}

#[test]
fn replay_target_inside_internal_journal_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 23, 1);
    write_jbd2_data(&mut image, 2, b"SELF!");
    write_jbd2_descriptor(&mut image, 1, 23, MODERN_JOURNAL_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, 23);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::JournalCorrupt)));
}

#[test]
fn emitted_journal_data_escapes_jbd2_magic_prefix() {
    let mut image = modern_fixture_image();
    put_be_u32(
        &mut image,
        block_offset(MODERN_INODE_TABLE_BLOCK),
        JBD2_MAGIC,
    );
    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        overwrite_file(&mut transaction, file_id, 0, b"MAGIC");
        must(transaction.commit());
    }

    let descriptor = journal_log_offset(1);
    let mut tag = descriptor + 12;
    let mut data_logical = 2;
    let mut found = false;
    while tag < descriptor + BLOCK_SIZE - 4 {
        let block = get_be_u32(&image, tag);
        let flags = get_be_u32(&image, tag + 4);
        if block == MODERN_INODE_TABLE_BLOCK {
            found = true;
            assert_ne!(flags & JBD2_TAG_FLAG_ESCAPE, 0);
            assert_eq!(get_be_u32(&image, journal_log_offset(data_logical)), 0);
            break;
        }
        if flags & JBD2_TAG_FLAG_LAST_TAG != 0 {
            break;
        }
        tag += 16;
        data_logical += 1;
    }
    assert!(found);
}

#[test]
fn descriptor_tag_uuid_mismatch_is_rejected() {
    let mut image = modern_fixture_image();
    let journal_uuid = [7; 16];
    mark_filesystem_needs_recovery(&mut image);
    write_jbd2_superblock_at(
        &mut image,
        journal_log_offset(0),
        8,
        journal_uuid,
        24,
        1,
        default_journal_incompat(),
    );
    write_jbd2_data(&mut image, 2, b"UUID!");
    write_jbd2_descriptor_with_uuid(
        &mut image,
        1,
        24,
        MODERN_FILE_DATA_BLOCK,
        [8; 16],
        journal_uuid,
    );
    write_jbd2_commit_with_checksum(&mut image, 3, 24, journal_uuid);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::JournalCorrupt)));
}

#[test]
fn descriptor_tag_uuid_match_is_replayed() {
    let mut image = modern_fixture_image();
    let journal_uuid = [9; 16];
    mark_filesystem_needs_recovery(&mut image);
    write_jbd2_superblock_at(
        &mut image,
        journal_log_offset(0),
        8,
        journal_uuid,
        25,
        1,
        default_journal_incompat(),
    );
    write_jbd2_data(&mut image, 2, b"UUID?");
    write_jbd2_descriptor_with_uuid(
        &mut image,
        1,
        25,
        MODERN_FILE_DATA_BLOCK,
        journal_uuid,
        journal_uuid,
    );
    write_jbd2_commit_with_checksum(&mut image, 3, 25, journal_uuid);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"UUID?");
}

#[test]
fn descriptor_without_last_tag_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 26, 1);
    write_jbd2_data(&mut image, 2, b"NLAST");
    write_jbd2_descriptor(&mut image, 1, 26, MODERN_FILE_DATA_BLOCK, 0);
    put_be_u32(
        &mut image,
        journal_log_offset(1) + 16,
        JBD2_TAG_FLAG_SAME_UUID,
    );
    write_jbd2_block_tail_checksum(&mut image, 1, [0; 16]);
    write_jbd2_commit(&mut image, 3, 26);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::JournalCorrupt)));
}

#[test]
fn empty_descriptor_commit_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 27, 1);
    let descriptor = journal_log_offset(1);
    image[descriptor..descriptor + BLOCK_SIZE].fill(0);
    write_jbd2_header(&mut image, descriptor, JBD2_DESCRIPTOR_BLOCK, 27);
    write_jbd2_block_tail_checksum(&mut image, 1, [0; 16]);
    write_jbd2_commit(&mut image, 2, 27);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::JournalCorrupt)));
}

#[test]
fn duplicate_home_block_in_transaction_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 28, 1);
    write_jbd2_data(&mut image, 2, b"DUPA!");
    write_jbd2_data(&mut image, 3, b"DUPB!");
    write_jbd2_two_tag_descriptor(
        &mut image,
        1,
        28,
        MODERN_FILE_DATA_BLOCK,
        MODERN_FILE_DATA_BLOCK,
        [0; 16],
    );
    write_jbd2_commit(&mut image, 4, 28);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::JournalCorrupt)));
}

#[test]
fn second_descriptor_block_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 29, 1);
    write_jbd2_data(&mut image, 2, b"ONE!!");
    write_jbd2_descriptor(&mut image, 1, 29, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_data(&mut image, 4, b"TWO!!");
    write_jbd2_descriptor(&mut image, 3, 29, MODERN_ROOT_DIR_BLOCK, 0);
    write_jbd2_commit(&mut image, 5, 29);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn commit_sequence_mismatch_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 30, 1);
    write_jbd2_data(&mut image, 2, b"CSEQ!");
    write_jbd2_descriptor(&mut image, 1, 30, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, 31);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::JournalCorrupt)));
    assert_ne!(get_u32(&image, 1024 + 96) & INCOMPAT_RECOVER, 0);
}

#[test]
fn same_transaction_later_revoke_prevents_replay() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 31, 1);
    write_jbd2_data(&mut image, 2, b"NOPE!");
    write_jbd2_descriptor(&mut image, 1, 31, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_revoke(&mut image, 3, 31, MODERN_FILE_DATA_BLOCK);
    write_jbd2_commit(&mut image, 4, 31);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}

#[test]
fn malformed_revoke_remainder_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 32, 1);
    write_jbd2_revoke(&mut image, 1, 32, MODERN_FILE_DATA_BLOCK);
    put_be_u32(&mut image, journal_log_offset(1) + 12, 29);
    write_jbd2_block_tail_checksum(&mut image, 1, [0; 16]);
    write_jbd2_commit(&mut image, 2, 32);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::JournalCorrupt)));
}

#[test]
fn wrapped_later_revoke_prevents_old_sequence_replay() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, u32::MAX, 1);
    write_jbd2_data(&mut image, 2, b"OLD!!");
    write_jbd2_descriptor(&mut image, 1, u32::MAX, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, u32::MAX);
    write_jbd2_revoke(&mut image, 4, 0, MODERN_FILE_DATA_BLOCK);
    write_jbd2_commit(&mut image, 5, 0);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}

#[test]
fn nonzero_journal_compat_is_rejected() {
    let mut image = modern_fixture_image();
    put_be_u32(&mut image, journal_log_offset(0) + 0x24, 1);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn journal_first_block_must_be_one() {
    let mut image = modern_fixture_image();
    put_be_u32(&mut image, journal_log_offset(0) + 0x14, 2);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn journal_maxlen_beyond_inode_capacity_is_rejected() {
    let mut image = modern_fixture_image();
    put_be_u32(&mut image, journal_log_offset(0) + 0x10, 9);

    let result = JournaledVolume::mount(SliceBlockDeviceMut::new(&mut image), test_mount_context());

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn external_journal_short_device_is_rejected() {
    let mut image = modern_fixture_image();
    let uuid = [4; 16];
    make_external_journal_filesystem(&mut image, uuid);
    let mut journal = vec![0_u8; EXTERNAL_JOURNAL_SUPERBLOCK_OFFSET + BLOCK_SIZE * 4];
    write_jbd2_superblock_at(
        &mut journal,
        EXTERNAL_JOURNAL_SUPERBLOCK_OFFSET,
        8,
        uuid,
        1,
        0,
        default_journal_incompat(),
    );

    let result: crate::Result<JournaledVolume<_, ExternalJournal<_>>> =
        JournaledVolume::mount_with_external_journal(
            SliceBlockDeviceMut::new(&mut image),
            SliceBlockDeviceMut::new(&mut journal),
            test_mount_context(),
        );

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn fragmented_internal_journal_is_mapped_on_demand() {
    let mut image = modern_fixture_image();
    write_fragmented_journal_inode(&mut image);
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 33, 4);
    write_jbd2_data(&mut image, 5, b"FRAG!");
    write_jbd2_descriptor(&mut image, 4, 33, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 6, 33);
    move_journal_block(&mut image, 4, 28);
    move_journal_block(&mut image, 5, 29);
    move_journal_block(&mut image, 6, 30);

    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"FRAG!");

    let file_id = file_node_id(&volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    overwrite_file(&mut transaction, file_id, 1024, b"hole");
    must(transaction.commit());
    let mut committed = [0_u8; 4];
    let read = read_file(&volume, 3, 1024, &mut committed);

    assert_eq!(read, 4);
    assert_eq!(&committed, b"hole");
}

#[test]
fn checkpoint_failure_leaves_replayable_dirty_journal() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 34, 1);
    write_jbd2_data(&mut image, 2, b"AGAIN");
    write_jbd2_descriptor(&mut image, 1, 34, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_commit(&mut image, 3, 34);
    {
        let fail_offset = ByteOffset::new(
            u64::try_from(block_offset(MODERN_FILE_DATA_BLOCK)).unwrap_or(u64::MAX),
        );
        let device = FailOneWriteAt::new(&mut image, fail_offset);
        let result = JournaledVolume::mount(device, test_mount_context());
        assert!(matches!(result, Err(Error::DeviceRange)));
    }
    assert_eq!(get_be_u32(&image, journal_log_offset(0) + 0x1C), 1);
    assert_ne!(get_u32(&image, 1024 + 96) & INCOMPAT_RECOVER, 0);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"AGAIN");
}
