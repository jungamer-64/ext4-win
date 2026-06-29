use super::*;

#[test]
fn clean_superblock_mounts() {
    let image = fixture_image();
    let device = SliceBlockDevice::new(&image);
    let volume = must(ReadOnlyVolume::mount(device, test_mount_context()));
    let superblock = must(Superblock::parse(&image[1024..2048]));

    assert_eq!(volume.geometry().block_size().bytes(), 1024);
    assert_eq!(superblock.inode_count().as_u32(), 16);
}

#[test]
fn invalid_magic_is_rejected() {
    let mut image = fixture_image();
    put_u16(&mut image, 1024 + 56, 0);
    let result = Superblock::parse(&image[1024..2048]);

    assert_eq!(result, Err(Error::InvalidMagic));
}

#[test]
fn unsupported_incompat_feature_is_rejected() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 96, 0x0010 | 0x0040);
    let result = ReadOnlyVolume::mount(SliceBlockDevice::new(&image), test_mount_context());

    assert!(matches!(result, Err(Error::UnsupportedIncompatFeature)));
}

#[test]
fn inode_zero_is_not_constructible() {
    assert_eq!(InodeId::try_from(0), Err(Error::InvalidInode));
}

#[test]
fn file_offset_addition_rejects_overflow() {
    let result = FileOffset::from_bytes(u64::MAX).checked_add_len(1);

    assert_eq!(result, Err(Error::ArithmeticOverflow));
}

#[test]
fn crc32c_known_vector_matches_castagnoli() {
    assert_eq!(crate::disk::checksum::crc32c(0, b"123456789"), 0xE306_9283);
}

#[test]
fn metadata_checksum_mismatch_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u32(&mut image, 1024 + 1020, 1);
    let result = Superblock::parse(&image[1024..2048]);

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

#[test]
fn larger_block_sizes_mount_and_read_file() {
    for block_size in [8192_usize, 16_384, 65_536] {
        let image = variable_block_fixture_image(block_size);
        let volume = must(ReadOnlyVolume::mount(
            SliceBlockDevice::new(&image),
            test_mount_context(),
        ));
        let mut output = [0_u8; 5];
        let read = read_file(&volume, 3, 0, &mut output);

        assert_eq!(
            volume.geometry().block_size().bytes(),
            u32::try_from(block_size).unwrap_or(u32::MAX)
        );
        assert_eq!(read, 5);
        assert_eq!(&output, b"hello");
    }
}

#[test]
fn block_count_uses_64bit_superblock_high_field() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u32(&mut image, 1024 + 4, 1);
    put_u32(&mut image, 1024 + 336, 1);
    let superblock = must(Superblock::parse(&image[1024..2048]));

    assert_eq!(superblock.block_count().as_u64(), 0x1_0000_0001);
}

#[test]
fn metadata_csum_seed_is_accepted_with_metadata_csum() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u32(&mut image, 1024 + 96, INCOMPAT_MODERN | INCOMPAT_CSUM_SEED);
    put_u32(&mut image, 1024 + 624, 0x1234_5678);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    let superblock = must(Superblock::parse(&image[1024..2048]));
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));

    assert_eq!(superblock.checksum_seed().as_u32(), 0x1234_5678);
    assert_eq!(read_directory(&volume, InodeId::ROOT).len(), 3);
}

#[test]
fn write_mount_accepts_metadata_csum_seed() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u32(&mut image, 1024 + 96, INCOMPAT_MODERN | INCOMPAT_CSUM_SEED);
    put_u32(&mut image, 1024 + 624, 0x1234_5678);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    let superblock = must(Superblock::parse_read_write(&image[1024..2048]));
    let device = SliceBlockDeviceMut::new(&mut image);
    let _volume = must(JournaledVolume::mount(device, test_mount_context()));

    assert_eq!(superblock.checksum_seed().as_u32(), 0x1234_5678);
}

#[test]
fn metadata_csum_seed_without_metadata_csum_is_rejected() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 96, 0x0002 | 0x0040 | INCOMPAT_CSUM_SEED);
    let result = Superblock::parse(&image[1024..2048]);

    assert!(matches!(result, Err(Error::UnsupportedIncompatFeature)));
}

#[test]
fn read_only_mount_accepts_quota_and_clean_orphan_file() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 92, COMPAT_ORPHAN_FILE);
    put_u32(&mut image, 1024 + 100, 0x0001 | 0x0002 | RO_COMPAT_QUOTA);
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));

    assert_eq!(read_directory(&volume, InodeId::ROOT).len(), 4);
}

#[test]
fn read_only_mount_rejects_layout_changing_features() {
    for incompat in [
        INCOMPAT_META_BG,
        INCOMPAT_LARGEDIR,
        INCOMPAT_INLINE_DATA,
        INCOMPAT_CASEFOLD,
    ] {
        let mut image = fixture_image();
        put_u32(&mut image, 1024 + 96, 0x0002 | 0x0040 | incompat);
        let result = Superblock::parse(&image[1024..2048]);

        assert!(matches!(result, Err(Error::UnsupportedIncompatFeature)));
    }

    {
        let read_only_compat = RO_COMPAT_ORPHAN_PRESENT;
        let mut image = fixture_image();
        put_u32(&mut image, 1024 + 100, 0x0001 | 0x0002 | read_only_compat);
        let result = Superblock::parse(&image[1024..2048]);

        assert!(matches!(result, Err(Error::UnsupportedReadOnlyFeature)));
    }
}

#[test]
fn write_mount_accepts_modern_baseline() {
    let mut image = modern_fixture_image();
    let superblock = must(Superblock::parse_read_write(&image[1024..2048]));
    let device = SliceBlockDeviceMut::new(&mut image);
    let _volume = must(JournaledVolume::mount(device, test_mount_context()));

    assert_eq!(superblock.journal_mode(), JournalMode::Internal(inode(8)));
}

#[test]
fn write_mount_rejects_recovery_accounting_feature_profiles() {
    for compat in [COMPAT_FAST_COMMIT, COMPAT_ORPHAN_FILE] {
        let mut image = minimal_write_fixture_image();
        put_u32(&mut image, 1024 + 92, COMPAT_HAS_JOURNAL | compat);
        let result = Superblock::parse_read_write(&image[1024..2048]);

        assert_eq!(result, Err(Error::UnsupportedWriteFeature));
    }

    for read_only_compat in [
        RO_COMPAT_READONLY,
        RO_COMPAT_QUOTA,
        RO_COMPAT_PROJECT,
        RO_COMPAT_ORPHAN_PRESENT,
    ] {
        let mut image = minimal_write_fixture_image();
        put_u32(&mut image, 1024 + 100, read_only_compat);
        let result = Superblock::parse_read_write(&image[1024..2048]);

        assert_eq!(result, Err(Error::UnsupportedWriteFeature));
    }
}
