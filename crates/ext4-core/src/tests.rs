#![expect(
    clippy::arithmetic_side_effects,
    reason = "fixture builder writes fixed ext4 structure offsets"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "fixture builder asserts exact in-memory image layout"
)]
#![expect(
    clippy::panic,
    reason = "unit tests fail through panic on unexpected errors"
)]

use alloc::{vec, vec::Vec};

use crate::{
    DirectoryEntryKind, Error, Ext4Timestamp, ExternalJournal, InodeId, ReadOnly, ReadWrite,
    SliceBlockDevice, SliceBlockDeviceMut, Superblock, Volume, WindowsName,
};

const BLOCK_SIZE: usize = 1024;
const IMAGE_BLOCKS: usize = 16;
const INODE_TABLE_BLOCK: u32 = 5;
const ROOT_DIR_BLOCK: u32 = 8;
const FILE_DATA_BLOCK: u32 = 9;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const MODERN_IMAGE_BLOCKS: usize = 64;
const MODERN_INODE_SIZE: usize = 256;
const MODERN_BLOCK_BITMAP_BLOCK: u32 = 3;
const MODERN_INODE_BITMAP_BLOCK: u32 = 4;
const MODERN_INODE_TABLE_BLOCK: u32 = 5;
const MODERN_ROOT_DIR_BLOCK: u32 = 12;
const MODERN_FILE_DATA_BLOCK: u32 = 13;
const MODERN_EXTENT_INDEX_BLOCK: u32 = 14;
const MODERN_JOURNAL_BLOCK: u32 = 20;
const COMPAT_MODERN: u32 = 0x0004 | 0x0008 | 0x0010 | 0x0020;
const INCOMPAT_MODERN: u32 = 0x0002 | 0x0040 | 0x0080 | 0x0200;
const RO_COMPAT_MODERN: u32 = 0x0001 | 0x0002 | 0x0008 | 0x0020 | 0x0040 | 0x0400;
const NOW: Ext4Timestamp = Ext4Timestamp::from_unix_seconds(1_700_000_000);
const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
const JBD2_COMMIT_BLOCK: u32 = 2;
const JBD2_SUPERBLOCK_V2: u32 = 4;
const JBD2_REVOKE_BLOCK: u32 = 5;
const JBD2_FEATURE_INCOMPAT_REVOKE: u32 = 0x0001;
const JBD2_FEATURE_INCOMPAT_64BIT: u32 = 0x0002;
const JBD2_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x0008;
const JBD2_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x0010;
const JBD2_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0020;
const JBD2_TAG_FLAG_ESCAPE: u32 = 0x0001;
const JBD2_TAG_FLAG_SAME_UUID: u32 = 0x0002;
const JBD2_TAG_FLAG_LAST_TAG: u32 = 0x0008;
const JBD2_CHECKSUM_CRC32C: u8 = 4;
const INCOMPAT_RECOVER: u32 = 0x0004;
const INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const EXTERNAL_JOURNAL_SUPERBLOCK_OFFSET: usize = 2048;

#[test]
fn clean_superblock_mounts() {
    let image = fixture_image();
    let device = SliceBlockDevice::new(&image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(device));

    assert_eq!(volume.superblock().block_size().bytes(), 1024);
    assert_eq!(volume.superblock().inode_count(), 16);
}

#[test]
fn invalid_magic_is_rejected() {
    let mut image = fixture_image();
    put_u16(&mut image, 1024 + 56, 0);
    let result = Superblock::parse(&image[1024..2048]);

    assert_eq!(result, Err(Error::InvalidMagic));
}

#[test]
fn dirty_volume_is_rejected() {
    let mut image = fixture_image();
    put_u16(&mut image, 1024 + 58, 0);
    let result = Volume::<_, ReadOnly>::mount_read_only(SliceBlockDevice::new(&image));

    assert!(matches!(result, Err(Error::DirtyVolume)));
}

#[test]
fn unsupported_incompat_feature_is_rejected() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 96, 0x0010 | 0x0040);
    let result = Volume::<_, ReadOnly>::mount_read_only(SliceBlockDevice::new(&image));

    assert!(matches!(result, Err(Error::UnsupportedIncompatFeature)));
}

#[test]
fn directory_entries_are_parsed_from_root_inode() {
    let image = fixture_image();
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
    ));
    let entries = must(volume.read_directory(InodeId::ROOT));

    assert_eq!(entries.len(), 4);
    assert_eq!(entries[2].name().bytes(), b"file");
    assert_eq!(entries[2].kind(), DirectoryEntryKind::File);
    assert_eq!(entries[3].name().bytes(), b"link");
    assert_eq!(entries[3].kind(), DirectoryEntryKind::Symlink);
}

#[test]
fn sparse_file_reads_zeroes_for_holes() {
    let image = fixture_image();
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
    ));
    let mut output = vec![0xAA; 1030];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

    assert_eq!(read, 1030);
    assert!(output[..1024].iter().all(|byte| *byte == 0));
    assert_eq!(&output[1024..1029], b"hello");
    assert_eq!(output[1029], 0);
}

#[test]
fn symlink_inline_target_is_read_without_extents() {
    let image = fixture_image();
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
    ));
    let target = must(volume.read_symlink(InodeId::new(4)));

    assert_eq!(target, b"file");
}

#[test]
fn exact_ext4_lookup_uses_raw_bytes() {
    let image = fixture_image();
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
    ));
    let child = must(volume.lookup_child(InodeId::ROOT, b"file"));

    assert_eq!(child, Some(InodeId::new(3)));
}

#[test]
fn windows_name_projection_rejects_reserved_separator() {
    let ext4_name = must(crate::Ext4Name::new(b"a:b"));
    let result = WindowsName::from_ext4(&ext4_name);

    assert!(matches!(result, Err(Error::InvalidName)));
}

#[test]
fn windows_lookup_accepts_unique_ascii_case_fold() {
    let image = fixture_image();
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
    ));
    let child = must(volume.lookup_windows_child(InodeId::ROOT, &[0x0046, 0x0049, 0x004C, 0x0045]));

    assert_eq!(child, Some(InodeId::new(3)));
}

#[test]
fn crc32c_known_vector_matches_castagnoli() {
    assert_eq!(crate::checksum::crc32c(0, b"123456789"), 0xE306_9283);
}

#[test]
fn metadata_checksum_mismatch_is_rejected() {
    let mut image = modern_fixture_image();
    put_u32(&mut image, 1024 + 1020, 1);
    let result = Superblock::parse(&image[1024..2048]);

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

#[test]
fn block_count_uses_64bit_superblock_high_field() {
    let mut image = modern_fixture_image();
    put_u32(&mut image, 1024 + 4, 1);
    put_u32(&mut image, 1024 + 336, 1);
    let superblock = must(Superblock::parse(&image[1024..2048]));

    assert_eq!(superblock.block_count(), 0x1_0000_0001);
}

#[test]
fn jbd2_header_is_big_endian() {
    let mut block = [0_u8; 12];
    must(crate::journal::Jbd2Header::descriptor(7).encode(&mut block));
    let header = must(crate::journal::Jbd2Header::parse(&block));

    assert_eq!(header.block_type(), 1);
    assert_eq!(header.sequence(), 7);
}

#[test]
fn write_mount_accepts_modern_baseline() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));

    assert_eq!(volume.superblock().journal_inode(), 8);
}

#[test]
fn write_mount_rejects_bigalloc() {
    let mut image = modern_fixture_image();
    put_u32(&mut image, 1024 + 100, RO_COMPAT_MODERN | 0x0200);
    let device = SliceBlockDeviceMut::new(&mut image);
    let result = Volume::<_, ReadWrite>::mount_read_write(device);

    assert!(matches!(result, Err(Error::UnsupportedWriteFeature)));
}

#[test]
fn overwrite_existing_file_range_commits() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(device));

    let mut transaction = volume.begin_transaction(NOW);
    must(transaction.overwrite_file_range(InodeId::new(3), 0, b"HELLO"));
    must(transaction.commit());

    let mut output = [0_u8; 5];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));
    assert_eq!(read, 5);
    assert_eq!(&output, b"HELLO");
}

#[test]
fn sparse_hole_write_allocates_block() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(device));

    let mut transaction = volume.begin_transaction(NOW);
    must(transaction.overwrite_file_range(InodeId::new(3), 1024, b"hole"));
    must(transaction.commit());

    let mut output = [0_u8; 4];
    let read = must(volume.read_file(InodeId::new(3), 1024, &mut output));
    assert_eq!(read, 4);
    assert_eq!(&output, b"hole");
}

#[test]
fn extend_file_creates_sparse_range() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(device));

    let mut transaction = volume.begin_transaction(NOW);
    must(transaction.extend_file(InodeId::new(3), 3072));
    must(transaction.commit());

    let inode = must(volume.read_inode(InodeId::new(3)));
    let mut output = [0xAA; 4];
    let read = must(volume.read_file(InodeId::new(3), 2048, &mut output));
    assert_eq!(inode.size(), 3072);
    assert_eq!(read, 4);
    assert_eq!(output, [0, 0, 0, 0]);
}

#[test]
fn truncate_file_releases_blocks() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(device));

    let mut write = volume.begin_transaction(NOW);
    must(write.overwrite_file_range(InodeId::new(3), 1024, b"hole"));
    must(write.commit());
    let mut truncate = volume.begin_transaction(NOW);
    must(truncate.truncate_file(InodeId::new(3), 0));
    must(truncate.commit());

    let inode = must(volume.read_inode(InodeId::new(3)));
    assert_eq!(inode.size(), 0);
}

#[test]
fn transaction_too_large_is_rejected_before_writes() {
    let mut image = modern_fixture_image_with_journal_blocks(3);
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
    let mut transaction = volume.begin_transaction(NOW);

    must(transaction.overwrite_file_range(InodeId::new(3), 1024, b"hole"));
    let result = transaction.commit();

    assert!(matches!(result, Err(Error::TransactionTooLarge)));
}

#[test]
fn committed_dirty_journal_transaction_is_replayed() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 7, 1);
    write_jbd2_descriptor(&mut image, 1, 7, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_data(&mut image, 2, b"REPLAY");
    write_jbd2_commit(&mut image, 3, 7);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
        let mut output = [0_u8; 6];
        let read = must(volume.read_file(InodeId::new(3), 0, &mut output));
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
    write_jbd2_descriptor(&mut image, 1, 8, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_data(&mut image, 2, b"IGNORE");

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
    let mut output = [0_u8; 5];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}

#[test]
fn bad_tag_checksum_transaction_is_ignored() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 9, 1);
    write_jbd2_descriptor_with_checksum(&mut image, 1, 9, MODERN_FILE_DATA_BLOCK, 0xDEAD_BEEF);
    write_jbd2_data(&mut image, 2, b"BAD!!");
    write_jbd2_commit(&mut image, 3, 9);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
    let mut output = [0_u8; 5];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}

#[test]
fn later_revoke_prevents_stale_metadata_replay() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 10, 1);
    write_jbd2_descriptor(&mut image, 1, 10, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_data(&mut image, 2, b"STALE");
    write_jbd2_commit(&mut image, 3, 10);
    write_jbd2_revoke(&mut image, 4, 11, MODERN_FILE_DATA_BLOCK);
    write_jbd2_commit(&mut image, 5, 11);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
    let mut output = [0_u8; 5];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}

#[test]
fn circular_journal_wraparound_is_replayed() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 12, 6);
    write_jbd2_descriptor(&mut image, 6, 12, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_data(&mut image, 7, b"WRAP!");
    write_jbd2_commit(&mut image, 1, 12);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
    let mut output = [0_u8; 5];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

    assert_eq!(read, 5);
    assert_eq!(&output, b"WRAP!");
}

#[test]
fn escaped_journal_data_block_is_unescaped_on_replay() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 13, 1);
    write_jbd2_descriptor(
        &mut image,
        1,
        13,
        MODERN_FILE_DATA_BLOCK,
        JBD2_TAG_FLAG_ESCAPE,
    );
    write_jbd2_data(&mut image, 2, &[0, 0, 0, 0, b'E']);
    write_jbd2_commit(&mut image, 3, 13);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
    let mut output = [0_u8; 5];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

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
    write_jbd2_descriptor(&mut image, 1, 14, MODERN_FILE_DATA_BLOCK, 0);
    write_jbd2_data(&mut image, 2, b"DONE!");
    write_jbd2_commit(&mut image, 3, 14);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
    let mut output = [0_u8; 5];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

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

    let result: crate::Result<Volume<_, ReadWrite<ExternalJournal<_>>>> =
        Volume::mount_read_write_with_external_journal(
            SliceBlockDeviceMut::new(&mut image),
            SliceBlockDeviceMut::new(&mut journal),
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
    let result = Volume::<_, ReadWrite>::mount_read_write(device);

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn write_transaction_emits_descriptor_data_and_commit_records() {
    let mut image = modern_fixture_image();
    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
        let mut transaction = volume.begin_transaction(NOW);
        must(transaction.overwrite_file_range(InodeId::new(3), 0, b"HELLO"));
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
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
        let mut transaction = volume.begin_transaction(NOW);
        must(transaction.extend_file(InodeId::new(3), 3072));
        must(transaction.commit());
    }

    put_u32(&mut image, modern_inode_offset(3) + 4, 2048);
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 1, 1);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
    let inode = must(volume.read_inode(InodeId::new(3)));

    assert_eq!(inode.size(), 3072);
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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
    let mut output = [0_u8; 5];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(device));
    let mut output = [0_u8; 5];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

    assert_eq!(read, 5);
    assert_eq!(&output, b"V2OK!");
}

#[test]
fn extent_depth_traversal_reads_index_block() {
    let mut image = modern_fixture_image();
    write_indexed_file_inode(&mut image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
    ));
    let mut output = [0_u8; 5];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}

fn fixture_image() -> Vec<u8> {
    let mut image = vec![0_u8; BLOCK_SIZE * IMAGE_BLOCKS];
    write_superblock(&mut image);
    write_block_group_descriptor(&mut image);
    write_root_inode(&mut image);
    write_file_inode(&mut image);
    write_symlink_inode(&mut image);
    write_root_directory(&mut image);
    let file_data_offset = block_offset(FILE_DATA_BLOCK);
    image[file_data_offset..file_data_offset + 5].copy_from_slice(b"hello");
    image
}

fn modern_fixture_image() -> Vec<u8> {
    modern_fixture_image_with_journal_blocks(8)
}

fn modern_fixture_image_with_journal_blocks(journal_blocks: u16) -> Vec<u8> {
    let mut image = vec![0_u8; BLOCK_SIZE * MODERN_IMAGE_BLOCKS];
    let free_blocks = write_modern_block_bitmap(&mut image, journal_blocks);
    write_modern_superblock(&mut image, free_blocks, journal_blocks);
    write_modern_block_group_descriptor(&mut image, free_blocks);
    write_modern_root_inode(&mut image);
    write_modern_file_inode(&mut image);
    write_modern_journal_inode(&mut image, journal_blocks);
    write_modern_root_directory(&mut image);
    let file_data_offset = block_offset(MODERN_FILE_DATA_BLOCK);
    image[file_data_offset..file_data_offset + 5].copy_from_slice(b"hello");
    image
}

fn write_superblock(image: &mut [u8]) {
    let base = 1024;
    put_u32(image, base, 16);
    put_u32(
        image,
        base + 4,
        u32::try_from(IMAGE_BLOCKS).unwrap_or(u32::MAX),
    );
    put_u32(image, base + 20, 1);
    put_u32(image, base + 24, 0);
    put_u32(image, base + 32, 8192);
    put_u32(image, base + 40, 16);
    put_u16(image, base + 56, 0xEF53);
    put_u16(image, base + 58, 1);
    put_u32(image, base + 76, 1);
    put_u32(image, base + 84, 11);
    put_u16(image, base + 88, 128);
    put_u32(image, base + 96, 0x0002 | 0x0040);
    put_u32(image, base + 100, 0x0001 | 0x0002);
}

fn write_modern_superblock(image: &mut [u8], free_blocks: u32, journal_blocks: u16) {
    let base = 1024;
    put_u32(image, base, 16);
    put_u32(
        image,
        base + 4,
        u32::try_from(MODERN_IMAGE_BLOCKS).unwrap_or(u32::MAX),
    );
    put_u32(image, base + 12, free_blocks);
    put_u32(image, base + 20, 1);
    put_u32(image, base + 24, 0);
    put_u32(image, base + 32, 8192);
    put_u32(image, base + 40, 16);
    put_u16(image, base + 56, 0xEF53);
    put_u16(image, base + 58, 1);
    put_u32(image, base + 76, 1);
    put_u32(image, base + 84, 11);
    put_u16(
        image,
        base + 88,
        u16::try_from(MODERN_INODE_SIZE).unwrap_or(u16::MAX),
    );
    put_u32(image, base + 92, COMPAT_MODERN);
    put_u32(image, base + 96, INCOMPAT_MODERN);
    put_u32(image, base + 100, RO_COMPAT_MODERN);
    put_u32(image, base + 224, 8);
    put_u16(image, base + 254, 64);
    put_u32(image, base + 336, 0);
    put_u32(image, base + 344, 0);
    put_u32(image, base + 268, u32::from(journal_blocks));
}

fn write_block_group_descriptor(image: &mut [u8]) {
    put_u32(image, block_offset(2) + 8, INODE_TABLE_BLOCK);
}

fn write_modern_block_group_descriptor(image: &mut [u8], free_blocks: u32) {
    let base = block_offset(2);
    put_u32(image, base, MODERN_BLOCK_BITMAP_BLOCK);
    put_u32(image, base + 4, MODERN_INODE_BITMAP_BLOCK);
    put_u32(image, base + 8, MODERN_INODE_TABLE_BLOCK);
    put_u16(
        image,
        base + 12,
        u16::try_from(free_blocks & u32::from(u16::MAX)).unwrap_or(u16::MAX),
    );
    put_u16(
        image,
        base + 44,
        u16::try_from(free_blocks >> 16).unwrap_or(u16::MAX),
    );
}

fn write_modern_block_bitmap(image: &mut [u8], journal_blocks: u16) -> u32 {
    let used_blocks = [
        1_u32,
        2,
        MODERN_BLOCK_BITMAP_BLOCK,
        MODERN_INODE_BITMAP_BLOCK,
        MODERN_INODE_TABLE_BLOCK,
        MODERN_INODE_TABLE_BLOCK + 1,
        MODERN_INODE_TABLE_BLOCK + 2,
        MODERN_INODE_TABLE_BLOCK + 3,
        MODERN_ROOT_DIR_BLOCK,
        MODERN_FILE_DATA_BLOCK,
    ];
    for block in used_blocks {
        set_modern_block_used(image, block, true);
    }
    for offset in 0..journal_blocks {
        set_modern_block_used(image, MODERN_JOURNAL_BLOCK + u32::from(offset), true);
    }
    let used = u32::try_from(used_blocks.len()).unwrap_or(u32::MAX) + u32::from(journal_blocks);
    u32::try_from(MODERN_IMAGE_BLOCKS - 1).unwrap_or(u32::MAX) - used
}

fn write_root_inode(image: &mut [u8]) {
    let offset = inode_offset(2);
    put_u16(image, offset, 0x4000 | 0o755);
    put_u32(
        image,
        offset + 4,
        u32::try_from(BLOCK_SIZE).unwrap_or(u32::MAX),
    );
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    write_extent_root(image, offset + 40, 0, 1, ROOT_DIR_BLOCK);
}

fn write_modern_root_inode(image: &mut [u8]) {
    let offset = modern_inode_offset(2);
    put_u16(image, offset, 0x4000 | 0o755);
    put_u32(
        image,
        offset + 4,
        u32::try_from(BLOCK_SIZE).unwrap_or(u32::MAX),
    );
    put_u32(image, offset + 28, 2);
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    write_extent_root(image, offset + 40, 0, 1, MODERN_ROOT_DIR_BLOCK);
}

fn write_file_inode(image: &mut [u8]) {
    let offset = inode_offset(3);
    put_u16(image, offset, 0x8000 | 0o444);
    put_u32(image, offset + 4, 2048);
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    write_extent_root(image, offset + 40, 1, 1, FILE_DATA_BLOCK);
}

fn write_modern_file_inode(image: &mut [u8]) {
    let offset = modern_inode_offset(3);
    put_u16(image, offset, 0x8000 | 0o444);
    put_u32(image, offset + 4, 2048);
    put_u32(image, offset + 28, 2);
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    write_extent_root(image, offset + 40, 0, 1, MODERN_FILE_DATA_BLOCK);
}

fn write_indexed_file_inode(image: &mut [u8]) {
    let offset = modern_inode_offset(3);
    put_u16(image, offset, 0x8000 | 0o444);
    put_u32(image, offset + 4, 1024);
    put_u32(image, offset + 28, 2);
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    image[offset + 40..offset + 100].fill(0);
    put_u16(image, offset + 40, 0xF30A);
    put_u16(image, offset + 42, 1);
    put_u16(image, offset + 44, 4);
    put_u16(image, offset + 46, 1);
    put_u32(image, offset + 52, 0);
    put_u32(image, offset + 56, MODERN_EXTENT_INDEX_BLOCK);
    let leaf = block_offset(MODERN_EXTENT_INDEX_BLOCK);
    put_u16(image, leaf, 0xF30A);
    put_u16(image, leaf + 2, 1);
    put_u16(image, leaf + 4, 84);
    put_u16(image, leaf + 6, 0);
    put_u32(image, leaf + 12, 0);
    put_u16(image, leaf + 16, 1);
    put_u16(image, leaf + 18, 0);
    put_u32(image, leaf + 20, MODERN_FILE_DATA_BLOCK);
}

fn write_modern_journal_inode(image: &mut [u8], journal_blocks: u16) {
    let offset = modern_inode_offset(8);
    put_u16(image, offset, 0x8000 | 0o600);
    put_u32(
        image,
        offset + 4,
        u32::from(journal_blocks) * u32::try_from(BLOCK_SIZE).unwrap_or(u32::MAX),
    );
    put_u32(image, offset + 28, u32::from(journal_blocks) * 2);
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    write_extent_root(image, offset + 40, 0, journal_blocks, MODERN_JOURNAL_BLOCK);
    write_jbd2_superblock(image, journal_blocks);
}

fn write_jbd2_superblock(image: &mut [u8], journal_blocks: u16) {
    write_jbd2_superblock_at(
        image,
        journal_log_offset(0),
        u32::from(journal_blocks),
        [0; 16],
        1,
        0,
        default_journal_incompat(),
    );
}

fn write_jbd2_superblock_at(
    image: &mut [u8],
    base: usize,
    journal_blocks: u32,
    uuid: [u8; 16],
    sequence: u32,
    start: u32,
    incompat: u32,
) {
    image[base..base + BLOCK_SIZE].fill(0);
    put_be_u32(image, base, JBD2_MAGIC);
    put_be_u32(image, base + 4, JBD2_SUPERBLOCK_V2);
    put_be_u32(image, base + 8, 0);
    put_be_u32(
        image,
        base + 0x0C,
        u32::try_from(BLOCK_SIZE).unwrap_or(u32::MAX),
    );
    put_be_u32(image, base + 0x10, journal_blocks);
    put_be_u32(image, base + 0x14, 1);
    put_be_u32(image, base + 0x18, sequence);
    put_be_u32(image, base + 0x1C, start);
    put_be_u32(image, base + 0x28, incompat);
    image[base + 0x30..base + 0x40].copy_from_slice(&uuid);
    image[base + 0x50] = JBD2_CHECKSUM_CRC32C;
}

fn default_journal_incompat() -> u32 {
    JBD2_FEATURE_INCOMPAT_REVOKE | JBD2_FEATURE_INCOMPAT_64BIT | JBD2_FEATURE_INCOMPAT_CSUM_V3
}

fn write_dirty_journal_superblock(image: &mut [u8], sequence: u32, start: u32) {
    write_jbd2_superblock_at(
        image,
        journal_log_offset(0),
        8,
        [0; 16],
        sequence,
        start,
        default_journal_incompat(),
    );
}

fn write_jbd2_descriptor(
    image: &mut [u8],
    logical: u32,
    sequence: u32,
    home_block: u32,
    extra_flags: u32,
) {
    write_jbd2_descriptor_with_checksum(image, logical, sequence, home_block, 0);
    let flags_offset = journal_log_offset(logical) + 16;
    put_be_u32(
        image,
        flags_offset,
        JBD2_TAG_FLAG_SAME_UUID | JBD2_TAG_FLAG_LAST_TAG | extra_flags,
    );
}

fn write_jbd2_descriptor_with_checksum(
    image: &mut [u8],
    logical: u32,
    sequence: u32,
    home_block: u32,
    checksum: u32,
) {
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    write_jbd2_header(image, base, JBD2_DESCRIPTOR_BLOCK, sequence);
    put_be_u32(image, base + 12, home_block);
    put_be_u32(
        image,
        base + 16,
        JBD2_TAG_FLAG_SAME_UUID | JBD2_TAG_FLAG_LAST_TAG,
    );
    put_be_u32(image, base + 20, 0);
    put_be_u32(image, base + 24, checksum);
}

fn write_jbd2_descriptor_32bit(image: &mut [u8], logical: u32, sequence: u32, home_block: u32) {
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    write_jbd2_header(image, base, JBD2_DESCRIPTOR_BLOCK, sequence);
    put_be_u32(image, base + 12, home_block);
    put_be_u16(
        image,
        base + 18,
        u16::try_from(JBD2_TAG_FLAG_SAME_UUID | JBD2_TAG_FLAG_LAST_TAG).unwrap_or(u16::MAX),
    );
}

fn write_jbd2_descriptor_csum_v2(
    image: &mut [u8],
    logical: u32,
    sequence: u32,
    home_block: u32,
    uuid: [u8; 16],
) {
    let base = journal_log_offset(logical);
    let data = image[journal_log_offset(logical + 1)..journal_log_offset(logical + 1) + BLOCK_SIZE]
        .to_vec();
    let tag_checksum = jbd2_tag_checksum(sequence, &data, uuid);
    image[base..base + BLOCK_SIZE].fill(0);
    write_jbd2_header(image, base, JBD2_DESCRIPTOR_BLOCK, sequence);
    put_be_u32(image, base + 12, home_block);
    put_be_u16(
        image,
        base + 16,
        u16::try_from(tag_checksum & u32::from(u16::MAX)).unwrap_or(u16::MAX),
    );
    put_be_u16(
        image,
        base + 18,
        u16::try_from(JBD2_TAG_FLAG_SAME_UUID | JBD2_TAG_FLAG_LAST_TAG).unwrap_or(u16::MAX),
    );
    write_jbd2_block_tail_checksum(image, logical, uuid);
}

fn write_jbd2_data(image: &mut [u8], logical: u32, prefix: &[u8]) {
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    image[base..base + prefix.len()].copy_from_slice(prefix);
}

fn write_jbd2_commit(image: &mut [u8], logical: u32, sequence: u32) {
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    write_jbd2_header(image, base, JBD2_COMMIT_BLOCK, sequence);
}

fn write_jbd2_commit_with_checksum(image: &mut [u8], logical: u32, sequence: u32, uuid: [u8; 16]) {
    write_jbd2_commit(image, logical, sequence);
    let base = journal_log_offset(logical);
    image[base + 0x0C] = JBD2_CHECKSUM_CRC32C;
    image[base + 0x0D] = 4;
    let checksum = jbd2_block_checksum(image, logical, 0x10, uuid);
    put_be_u32(image, base + 0x10, checksum);
}

fn write_jbd2_revoke(image: &mut [u8], logical: u32, sequence: u32, block: u32) {
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    write_jbd2_header(image, base, JBD2_REVOKE_BLOCK, sequence);
    put_be_u32(image, base + 12, 28);
    put_be_u32(image, base + 16, 0);
    put_be_u32(image, base + 20, block);
}

fn write_jbd2_header(image: &mut [u8], base: usize, block_type: u32, sequence: u32) {
    put_be_u32(image, base, JBD2_MAGIC);
    put_be_u32(image, base + 4, block_type);
    put_be_u32(image, base + 8, sequence);
}

fn write_jbd2_block_tail_checksum(image: &mut [u8], logical: u32, uuid: [u8; 16]) {
    let tail = journal_log_offset(logical) + BLOCK_SIZE - 4;
    put_be_u32(image, tail, 0);
    let checksum = jbd2_block_checksum(image, logical, BLOCK_SIZE - 4, uuid);
    put_be_u32(image, tail, checksum);
}

fn jbd2_block_checksum(image: &[u8], logical: u32, checksum_offset: usize, uuid: [u8; 16]) -> u32 {
    let base = journal_log_offset(logical);
    let mut block = image[base..base + BLOCK_SIZE].to_vec();
    block[checksum_offset..checksum_offset + 4].fill(0);
    crate::checksum::crc32c(crate::checksum::crc32c(0, &uuid), &block)
}

fn jbd2_tag_checksum(sequence: u32, data: &[u8], uuid: [u8; 16]) -> u32 {
    let seed = crate::checksum::crc32c(0, &uuid);
    let seed = crate::checksum::crc32c(seed, &sequence.to_be_bytes());
    crate::checksum::crc32c(seed, data)
}

fn journal_log_offset(logical: u32) -> usize {
    block_offset(MODERN_JOURNAL_BLOCK + logical)
}

fn mark_filesystem_needs_recovery(image: &mut [u8]) {
    put_u32(image, 1024 + 96, INCOMPAT_MODERN | INCOMPAT_RECOVER);
}

fn make_external_journal_filesystem(image: &mut [u8], uuid: [u8; 16]) {
    put_u32(image, 1024 + 96, INCOMPAT_MODERN | INCOMPAT_JOURNAL_DEV);
    image[1024 + 208..1024 + 224].copy_from_slice(&uuid);
    put_u32(image, 1024 + 224, 0);
}

fn write_symlink_inode(image: &mut [u8]) {
    let offset = inode_offset(4);
    put_u16(image, offset, 0xA000 | 0o777);
    put_u32(image, offset + 4, 4);
    image[offset + 40..offset + 44].copy_from_slice(b"file");
}

fn write_root_directory(image: &mut [u8]) {
    let base = block_offset(ROOT_DIR_BLOCK);
    write_dirent(image, base, 2, 12, b".", 2);
    write_dirent(image, base + 12, 2, 12, b"..", 2);
    write_dirent(image, base + 24, 3, 16, b"file", 1);
    write_dirent(image, base + 40, 4, 984, b"link", 7);
}

fn write_modern_root_directory(image: &mut [u8]) {
    let base = block_offset(MODERN_ROOT_DIR_BLOCK);
    write_dirent(image, base, 2, 12, b".", 2);
    write_dirent(image, base + 12, 2, 12, b"..", 2);
    write_dirent(image, base + 24, 3, 1000, b"file", 1);
}

fn write_extent_root(
    image: &mut [u8],
    offset: usize,
    logical_start: u32,
    len: u16,
    physical_start: u32,
) {
    put_u16(image, offset, 0xF30A);
    put_u16(image, offset + 2, 1);
    put_u16(image, offset + 4, 4);
    put_u16(image, offset + 6, 0);
    put_u32(image, offset + 12, logical_start);
    put_u16(image, offset + 16, len);
    put_u16(image, offset + 18, 0);
    put_u32(image, offset + 20, physical_start);
}

fn write_dirent(
    image: &mut [u8],
    offset: usize,
    inode: u32,
    rec_len: u16,
    name: &[u8],
    file_type: u8,
) {
    put_u32(image, offset, inode);
    put_u16(image, offset + 4, rec_len);
    image[offset + 6] = u8::try_from(name.len()).unwrap_or(u8::MAX);
    image[offset + 7] = file_type;
    image[offset + 8..offset + 8 + name.len()].copy_from_slice(name);
}

fn inode_offset(inode: u32) -> usize {
    block_offset(INODE_TABLE_BLOCK) + usize::try_from(inode - 1).unwrap_or(usize::MAX) * 128
}

fn modern_inode_offset(inode: u32) -> usize {
    block_offset(MODERN_INODE_TABLE_BLOCK)
        + usize::try_from(inode - 1).unwrap_or(usize::MAX) * MODERN_INODE_SIZE
}

fn block_offset(block: u32) -> usize {
    usize::try_from(block).unwrap_or(usize::MAX) * BLOCK_SIZE
}

fn set_modern_block_used(image: &mut [u8], block: u32, used: bool) {
    let bit = block - 1;
    let byte =
        block_offset(MODERN_BLOCK_BITMAP_BLOCK) + usize::try_from(bit / 8).unwrap_or(usize::MAX);
    let mask = 1_u8 << (bit % 8);
    if used {
        image[byte] |= mask;
    } else {
        image[byte] &= !mask;
    }
}

fn put_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_be_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_be_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn get_u32(image: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        image[offset],
        image[offset + 1],
        image[offset + 2],
        image[offset + 3],
    ])
}

fn get_be_u32(image: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        image[offset],
        image[offset + 1],
        image[offset + 2],
        image[offset + 3],
    ])
}

fn must<T>(result: crate::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected ext4-core error: {error:?}"),
    }
}
