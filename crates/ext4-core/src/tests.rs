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
    BlockAddress, BlockGroupId, BlockMapping, BlockReader, BlockSize, BlockWriter, ByteOffset,
    DeviceLength, DirectoryEntry, DirectoryEntryKind, DirectoryNode, Error, Ext4Gid, Ext4Name,
    Ext4Owner, Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp, Ext4Uid, Ext4VolumeLabel,
    Ext4WindowsAttributes, Extent, ExtentLength, ExtentTree, ExtentTreeContext, ExternalJournal,
    FileNode, FileOffset, FileSize, InodeExtentRoot, InodeId, JournalMode, LogicalBlock,
    LookupResult, MountContext, MutableExtentTree, NewDirectoryMetadata, NewFileMetadata,
    NewSymlinkMetadata, Node, PosixAcl, PosixAclEntry, PosixAclKind, ReadOnly, ReadWrite,
    SliceBlockDevice, SliceBlockDeviceMut, Superblock, SymlinkNode, SymlinkTarget,
    TransactionDirectory, TransactionFile, Volume, WindowsName, WindowsOverlay, XattrName,
    XattrNamespace, XattrValue,
};

const BLOCK_SIZE: usize = 1024;
const IMAGE_BLOCKS: usize = 16;
const INODE_TABLE_BLOCK: u32 = 5;
const ROOT_DIR_BLOCK: u32 = 8;
const FILE_DATA_BLOCK: u32 = 9;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const EXT4_INDEX_FL: u32 = 0x0000_1000;
const MODERN_IMAGE_BLOCKS: usize = 64;
const MODERN_INODE_SIZE: usize = 256;
const MODERN_BLOCK_BITMAP_BLOCK: u32 = 3;
const MODERN_INODE_BITMAP_BLOCK: u32 = 4;
const MODERN_INODE_TABLE_BLOCK: u32 = 5;
const MODERN_ROOT_DIR_BLOCK: u32 = 12;
const MODERN_FILE_DATA_BLOCK: u32 = 13;
const MODERN_EXTENT_INDEX_BLOCK: u32 = 14;
const MODERN_JOURNAL_BLOCK: u32 = 20;
const BIGALLOC_BLOCKS_PER_CLUSTER: u32 = 4;
const BIGALLOC_LOG_CLUSTER_SIZE: u32 = 2;
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
const COMPAT_ORPHAN_FILE: u32 = 0x1000;
const INCOMPAT_RECOVER: u32 = 0x0004;
const INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const INCOMPAT_META_BG: u32 = 0x0010;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INCOMPAT_ENCRYPT: u32 = 0x0001_0000;
const INCOMPAT_CASEFOLD: u32 = 0x0002_0000;
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
const RO_COMPAT_QUOTA: u32 = 0x0100;
const RO_COMPAT_BIGALLOC: u32 = 0x0200;
const RO_COMPAT_VERITY: u32 = 0x8000;
const RO_COMPAT_ORPHAN_PRESENT: u32 = 0x0001_0000;
const EXTERNAL_JOURNAL_SUPERBLOCK_OFFSET: usize = 2048;

fn inode(value: u32) -> InodeId {
    must(InodeId::try_from(value))
}

fn file_node<D: BlockReader, State>(volume: &Volume<D, State>, inode_id: u32) -> FileNode {
    match must(volume.read_node(inode(inode_id))) {
        Node::File(file) => file,
        Node::Directory(_) | Node::Symlink(_) => panic!("expected file node"),
    }
}

fn directory_node<D: BlockReader, State>(
    volume: &Volume<D, State>,
    inode_id: InodeId,
) -> DirectoryNode {
    match must(volume.read_node(inode_id)) {
        Node::Directory(directory) => directory,
        Node::File(_) | Node::Symlink(_) => panic!("expected directory node"),
    }
}

fn symlink_node<D: BlockReader, State>(volume: &Volume<D, State>, inode_id: u32) -> SymlinkNode {
    match must(volume.read_node(inode(inode_id))) {
        Node::Symlink(symlink) => symlink,
        Node::File(_) | Node::Directory(_) => panic!("expected symlink node"),
    }
}

fn read_file<D: BlockReader, State>(
    volume: &Volume<D, State>,
    inode_id: u32,
    offset: u64,
    out: &mut [u8],
) -> usize {
    let file = file_node(volume, inode_id);
    must(volume.read_file(&file, FileOffset::from_bytes(offset), out)).as_usize()
}

fn read_directory<D: BlockReader, State>(
    volume: &Volume<D, State>,
    inode_id: InodeId,
) -> Vec<DirectoryEntry> {
    let directory = directory_node(volume, inode_id);
    must(volume.read_directory(&directory))
}

fn read_symlink<D: BlockReader, State>(volume: &Volume<D, State>, inode_id: u32) -> Vec<u8> {
    let symlink = symlink_node(volume, inode_id);
    must(volume.read_symlink(&symlink))
}

fn lookup_ext4<D: BlockReader, State>(
    volume: &Volume<D, State>,
    parent: InodeId,
    name: &[u8],
) -> LookupResult {
    let directory = directory_node(volume, parent);
    let name = must(Ext4Name::new(name));
    must(volume.lookup_child(&directory, &name))
}

fn lookup_windows<D: BlockReader, State>(
    volume: &Volume<D, State>,
    parent: InodeId,
    name: &[u16],
) -> LookupResult {
    let directory = directory_node(volume, parent);
    let name = must(WindowsName::from_utf16(name));
    must(volume.lookup_windows_child(&directory, &name))
}

fn transaction_file<D: BlockWriter, J>(
    transaction: &crate::WriteTransaction<'_, D, J>,
    inode_id: u32,
) -> TransactionFile {
    must(transaction.file(inode(inode_id)))
}

fn transaction_directory<D: BlockWriter, J>(
    transaction: &crate::WriteTransaction<'_, D, J>,
    inode_id: InodeId,
) -> TransactionDirectory {
    must(transaction.directory(inode_id))
}

fn transaction_node<D: BlockWriter, J>(
    transaction: &crate::WriteTransaction<'_, D, J>,
    inode_id: InodeId,
) -> crate::TransactionNode {
    must(transaction.node(inode_id))
}

fn test_owner() -> Ext4Owner {
    Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(1000))
}

fn test_file_metadata() -> NewFileMetadata {
    NewFileMetadata::new(test_owner(), must(Ext4Permissions::new(0o644)))
}

fn test_directory_metadata() -> NewDirectoryMetadata {
    NewDirectoryMetadata::new(test_owner(), must(Ext4Permissions::new(0o755)))
}

fn test_symlink_metadata() -> NewSymlinkMetadata {
    NewSymlinkMetadata::new(test_owner(), must(Ext4Permissions::new(0o777)))
}

fn test_mount_context() -> MountContext {
    MountContext::without_encryption_keys()
}

fn overwrite_file<D: BlockWriter, J>(
    transaction: &mut crate::WriteTransaction<'_, D, J>,
    inode_id: u32,
    offset: u64,
    bytes: &[u8],
) {
    let file = transaction_file(transaction, inode_id);
    must(transaction.overwrite_file_range(file, FileOffset::from_bytes(offset), bytes));
}

fn extend_file<D: BlockWriter, J>(
    transaction: &mut crate::WriteTransaction<'_, D, J>,
    inode_id: u32,
    new_size: u64,
) {
    let file = transaction_file(transaction, inode_id);
    must(transaction.extend_file(file, FileSize::from_bytes(new_size)));
}

fn truncate_file<D: BlockWriter, J>(
    transaction: &mut crate::WriteTransaction<'_, D, J>,
    inode_id: u32,
    new_size: u64,
) {
    let file = transaction_file(transaction, inode_id);
    must(transaction.truncate_file(file, FileSize::from_bytes(new_size)));
}

#[test]
fn clean_superblock_mounts() {
    let image = fixture_image();
    let device = SliceBlockDevice::new(&image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        device,
        test_mount_context(),
    ));

    assert_eq!(volume.superblock().block_size().bytes(), 1024);
    assert_eq!(volume.superblock().inode_count().as_u32(), 16);
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
    let result =
        Volume::<_, ReadOnly>::mount_read_only(SliceBlockDevice::new(&image), test_mount_context());

    assert!(matches!(result, Err(Error::DirtyVolume)));
}

#[test]
fn unsupported_incompat_feature_is_rejected() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 96, 0x0010 | 0x0040);
    let result =
        Volume::<_, ReadOnly>::mount_read_only(SliceBlockDevice::new(&image), test_mount_context());

    assert!(matches!(result, Err(Error::UnsupportedIncompatFeature)));
}

#[test]
fn directory_entries_are_parsed_from_root_inode() {
    let image = fixture_image();
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let entries = read_directory(&volume, InodeId::ROOT);

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
        test_mount_context(),
    ));
    let mut output = vec![0xAA; 1030];
    let read = read_file(&volume, 3, 0, &mut output);

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
        test_mount_context(),
    ));
    let target = read_symlink(&volume, 4);

    assert_eq!(target, b"file");
}

#[test]
fn uninitialized_extent_reads_as_zeroes() {
    let mut image = fixture_image();
    put_u16(&mut image, inode_offset(3) + 56, 0x8001);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let mut output = [0xAA; 5];
    let read = read_file(&volume, 3, 1024, &mut output);

    assert_eq!(read, 5);
    assert_eq!(output, [0, 0, 0, 0, 0]);
}

#[test]
fn exact_ext4_lookup_uses_raw_bytes() {
    let image = fixture_image();
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let child = lookup_ext4(&volume, InodeId::ROOT, b"file");

    assert_eq!(child, LookupResult::Found(inode(3)));
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
        test_mount_context(),
    ));
    let child = lookup_windows(&volume, InodeId::ROOT, &[0x0046, 0x0049, 0x004C, 0x0045]);

    assert_eq!(child, LookupResult::Found(inode(3)));
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
fn lookup_reports_not_found_without_option() {
    let image = fixture_image();
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));

    assert_eq!(
        lookup_ext4(&volume, InodeId::ROOT, b"missing"),
        LookupResult::NotFound
    );
}

#[test]
fn windows_lookup_rejects_ambiguous_case_fold() {
    let mut image = fixture_image();
    write_dirent(
        &mut image,
        block_offset(ROOT_DIR_BLOCK) + 40,
        4,
        984,
        b"FILE",
        1,
    );
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let root = directory_node(&volume, InodeId::ROOT);
    let requested = must(WindowsName::from_utf16(&[0x0046, 0x0069, 0x004C, 0x0065]));
    let result = volume.lookup_windows_child(&root, &requested);

    assert_eq!(result, Err(Error::AmbiguousWindowsName));
}

#[test]
fn extent_hole_mapping_is_explicit() {
    let mut raw = [0_u8; 60];
    write_extent_root(&mut raw, 0, 1, 1, FILE_DATA_BLOCK);
    let root = crate::inode::InodeExtentRoot::from_bytes(raw);
    let tree = must(ExtentTree::parse_inode_root(&root));

    assert_eq!(
        tree.map_logical(LogicalBlock::from_u32(0)),
        BlockMapping::Hole
    );
}

#[test]
fn crc32c_known_vector_matches_castagnoli() {
    assert_eq!(crate::checksum::crc32c(0, b"123456789"), 0xE306_9283);
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
        let volume = must(Volume::<_, ReadOnly>::mount_read_only(
            SliceBlockDevice::new(&image),
            test_mount_context(),
        ));
        let mut output = [0_u8; 5];
        let read = read_file(&volume, 3, 0, &mut output);

        assert_eq!(
            volume.superblock().block_size().bytes(),
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
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));

    assert_eq!(volume.superblock().checksum_seed().as_u32(), 0x1234_5678);
    assert_eq!(read_directory(&volume, InodeId::ROOT).len(), 3);
}

#[test]
fn write_mount_accepts_metadata_csum_seed() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u32(&mut image, 1024 + 96, INCOMPAT_MODERN | INCOMPAT_CSUM_SEED);
    put_u32(&mut image, 1024 + 624, 0x1234_5678);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));

    assert_eq!(volume.superblock().checksum_seed().as_u32(), 0x1234_5678);
}

#[test]
fn metadata_csum_seed_without_metadata_csum_is_rejected() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 96, 0x0002 | 0x0040 | INCOMPAT_CSUM_SEED);
    let result = Superblock::parse(&image[1024..2048]);

    assert!(matches!(result, Err(Error::UnsupportedIncompatFeature)));
}

#[test]
fn metadata_descriptor_checksum_is_verified() {
    let image = modern_fixture_image();
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));

    assert_eq!(read_directory(&volume, InodeId::ROOT).len(), 3);
}

#[test]
fn bad_metadata_descriptor_checksum_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    corrupt_primary_block_group_descriptor_checksum(&mut image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let result = volume.read_node(InodeId::ROOT);

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

#[test]
fn gdt_descriptor_checksum_is_verified() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 100, 0x0001 | 0x0002 | RO_COMPAT_GDT_CSUM);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
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
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let result = volume.read_node(InodeId::ROOT);

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

#[test]
fn read_only_mount_accepts_quota_and_clean_orphan_file() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 92, COMPAT_ORPHAN_FILE);
    put_u32(&mut image, 1024 + 100, 0x0001 | 0x0002 | RO_COMPAT_QUOTA);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));

    assert_eq!(read_directory(&volume, InodeId::ROOT).len(), 4);
}

#[test]
fn read_only_mount_accepts_encryption_and_verity_feature_bits() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 96, 0x0002 | 0x0040 | INCOMPAT_ENCRYPT);
    put_u32(&mut image, 1024 + 100, 0x0001 | 0x0002 | RO_COMPAT_VERITY);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
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

    for read_only_compat in [RO_COMPAT_ORPHAN_PRESENT] {
        let mut image = fixture_image();
        put_u32(&mut image, 1024 + 100, 0x0001 | 0x0002 | read_only_compat);
        let result = Superblock::parse(&image[1024..2048]);

        assert!(matches!(result, Err(Error::UnsupportedReadOnlyFeature)));
    }
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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));

    assert_eq!(
        volume.superblock().journal_mode(),
        JournalMode::Internal(inode(8))
    );
}

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
fn overwrite_existing_file_range_commits() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));

    let mut transaction = volume.begin_transaction(NOW);
    overwrite_file(&mut transaction, 3, 0, b"HELLO");
    must(transaction.commit());

    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);
    assert_eq!(read, 5);
    assert_eq!(&output, b"HELLO");
}

#[test]
fn sparse_hole_write_allocates_block() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));

    let mut transaction = volume.begin_transaction(NOW);
    overwrite_file(&mut transaction, 3, 1024, b"hole");
    must(transaction.commit());

    let mut output = [0_u8; 4];
    let read = read_file(&volume, 3, 1024, &mut output);
    assert_eq!(read, 4);
    assert_eq!(&output, b"hole");
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
        let mut transaction = volume.begin_transaction(NOW);
        overwrite_file(&mut transaction, 3, 1024, b"hole");
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
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            3,
            u64::try_from(BLOCK_SIZE * 5).unwrap_or(u64::MAX),
        );
        overwrite_file(
            &mut transaction,
            3,
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
        let mut transaction = volume.begin_transaction(NOW);
        truncate_file(
            &mut transaction,
            3,
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
        let mut transaction = volume.begin_transaction(NOW);
        truncate_file(&mut transaction, 3, 0);
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
        let root = transaction_directory(&transaction, InodeId::ROOT);
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
        let mut transaction = volume.begin_transaction(NOW);
        truncate_file(
            &mut transaction,
            3,
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
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            3,
            u64::try_from(BLOCK_SIZE * 5).unwrap_or(u64::MAX),
        );
        overwrite_file(
            &mut transaction,
            3,
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
        let root = transaction_directory(&transaction, InodeId::ROOT);
        let child = must(transaction.create_directory(
            root,
            &must(Ext4Name::new(b"child")),
            test_directory_metadata(),
        ));
        must(transaction.remove_empty_directory(root, &must(Ext4Name::new(b"child"))));
        assert_eq!(child.inode_id().as_u32(), 11);
        must(transaction.commit());

        assert_eq!(
            volume.superblock().free_cluster_count().as_u64(),
            u64::from(initial_free)
        );
    }

    assert_eq!(get_u32(&image, 1024 + 12), initial_free);
}

#[test]
fn overwrite_allocates_external_extent_leaf_after_root_capacity() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            3,
            u64::try_from(BLOCK_SIZE * 10).unwrap_or(u64::MAX),
        );
        for logical in [0_u64, 2, 4, 6, 8] {
            overwrite_file(
                &mut transaction,
                3,
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

    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
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
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            3,
            u64::try_from(BLOCK_SIZE * 10).unwrap_or(u64::MAX),
        );
        for logical in [0_u64, 2, 4, 6, 8] {
            overwrite_file(
                &mut transaction,
                3,
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
        &SliceBlockDevice::new(&image),
        ExtentTreeContext::none(),
    ));

    assert_eq!(loaded.extents().len(), 337);
    assert_eq!(
        loaded.map_logical(LogicalBlock::from_u32(672)),
        BlockMapping::Physical(BlockAddress::new(1_336))
    );
}

#[test]
fn external_extent_block_checksum_mismatch_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(
            &mut transaction,
            3,
            u64::try_from(BLOCK_SIZE * 10).unwrap_or(u64::MAX),
        );
        for logical in [0_u64, 2, 4, 6, 8] {
            overwrite_file(
                &mut transaction,
                3,
                logical.saturating_mul(u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX)),
                b"x",
            );
        }
        must(transaction.commit());
    }

    let extent_block = get_u32(&image, modern_inode_offset(3) + 56);
    let checksum_offset = block_offset(extent_block) + BLOCK_SIZE - 4;
    image[checksum_offset] ^= 0x80;

    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let file = file_node(&volume, 3);
    let mut output = [0_u8; 1];
    let result = volume.read_file(&file, FileOffset::ZERO, &mut output);

    assert_eq!(result, Err(Error::ChecksumMismatch));
}

#[test]
fn uninitialized_extent_write_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u16(&mut image, modern_inode_offset(3) + 56, 0x8001);
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let mut transaction = volume.begin_transaction(NOW);
    let file = transaction_file(&transaction, 3);
    let result = transaction.overwrite_file_range(file, FileOffset::ZERO, b"x");

    assert_eq!(result, Err(Error::UnsupportedInodeMutation));
}

#[test]
fn extend_file_creates_sparse_range() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));

    let mut transaction = volume.begin_transaction(NOW);
    extend_file(&mut transaction, 3, 3072);
    must(transaction.commit());

    let file = file_node(&volume, 3);
    let mut output = [0xAA; 4];
    let read = read_file(&volume, 3, 2048, &mut output);
    assert_eq!(file.size().bytes(), 3072);
    assert_eq!(read, 4);
    assert_eq!(output, [0, 0, 0, 0]);
}

#[test]
fn truncate_file_releases_blocks() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));

    let mut write = volume.begin_transaction(NOW);
    overwrite_file(&mut write, 3, 1024, b"hole");
    must(write.commit());
    let mut truncate = volume.begin_transaction(NOW);
    truncate_file(&mut truncate, 3, 0);
    must(truncate.commit());

    let file = file_node(&volume, 3);
    assert_eq!(file.size().bytes(), 0);
}

#[test]
fn transaction_too_large_is_rejected_before_writes() {
    let mut image = modern_fixture_image_with_journal_blocks(3);
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let mut transaction = volume.begin_transaction(NOW);

    overwrite_file(&mut transaction, 3, 1024, b"hole");
    let result = transaction.commit();

    assert!(matches!(result, Err(Error::TransactionTooLarge)));
}

#[test]
fn create_file_adds_directory_entry_and_inode() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, InodeId::ROOT);
        let name = must(Ext4Name::new(b"new"));
        let file = must(transaction.create_file(root, &name, test_file_metadata()));
        assert_eq!(file.inode_id(), inode(11));
        must(transaction.commit());

        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"new"),
            LookupResult::Found(inode(11))
        );
        let file = file_node(&volume, 11);
        assert_eq!(file.size().bytes(), 0);
    }

    assert_eq!(get_u32(&image, 1024 + 16), 5);
}

#[test]
fn create_file_rejects_duplicate_name() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&transaction, InodeId::ROOT);
    let name = must(Ext4Name::new(b"file"));
    let result = transaction.create_file(root, &name, test_file_metadata());

    assert_eq!(result, Err(Error::NameAlreadyExists));
}

#[test]
fn inode_security_is_parsed_from_owner_and_mode() {
    let image = modern_fixture_image();
    let device = SliceBlockDevice::new(&image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        device,
        test_mount_context(),
    ));

    let file = file_node(&volume, 3);
    assert_eq!(file.security().owner().uid().as_u32(), 0);
    assert_eq!(file.security().owner().gid().as_u32(), 0);
    assert_eq!(file.security().permissions().as_u16(), 0o444);
}

#[test]
fn inode_times_are_parsed_from_inode_fields() {
    let mut image = modern_fixture_image();
    let offset = modern_inode_offset(3);
    put_u32(&mut image, offset + 8, 11);
    put_u32(&mut image, offset + 12, 22);
    put_u32(&mut image, offset + 16, 33);
    put_u32(&mut image, offset + 144, 44);

    let device = SliceBlockDevice::new(&image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        device,
        test_mount_context(),
    ));
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

#[test]
fn set_posix_security_updates_owner_and_permissions() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let security = Ext4Security::new(
            Ext4Owner::new(
                Ext4Uid::from_u32(0x0002_0001),
                Ext4Gid::from_u32(0x0004_0003),
            ),
            must(Ext4Permissions::new(0o6750)),
        );

        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, inode(3));
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
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, inode(3));
        must(transaction.set_times(node, times));
        must(transaction.commit());
    }

    let inode_offset = modern_inode_offset(3);
    assert_eq!(get_u32(&image, inode_offset + 8), 11);
    assert_eq!(get_u32(&image, inode_offset + 16), 22);
    assert_eq!(get_u32(&image, inode_offset + 12), 33);
    assert_eq!(get_u32(&image, inode_offset + 144), 44);
}

#[test]
fn volume_label_round_trips_through_superblock() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let label = must(Ext4VolumeLabel::new(b"EXT4WIN"));

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        transaction.set_volume_label(label);
        must(transaction.commit());
    }

    assert_eq!(&image[1024 + 120..1024 + 127], b"EXT4WIN");
    assert_eq!(&image[1024 + 127..1024 + 136], &[0_u8; 9]);

    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    assert_eq!(volume.volume_label(), label);
    assert_eq!(volume.volume_label().bytes(), b"EXT4WIN");
}

#[test]
fn volume_label_rejects_unrepresentable_bytes() {
    assert_eq!(
        Ext4VolumeLabel::new(b"12345678901234567"),
        Err(Error::InvalidName)
    );
    assert_eq!(Ext4VolumeLabel::new(b"bad\0label"), Err(Error::InvalidName));
}

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
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, inode(3));
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
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, inode(3));
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
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, inode(3));
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
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, inode(3));
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
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, inode(3));
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
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, inode(3));
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
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, inode(3));
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
fn unlink_file_removes_directory_entry_and_frees_inode() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let name = must(Ext4Name::new(b"new"));

        let mut create = volume.begin_transaction(NOW);
        let root = transaction_directory(&create, InodeId::ROOT);
        let _file = must(create.create_file(root, &name, test_file_metadata()));
        must(create.commit());

        let mut unlink = volume.begin_transaction(NOW);
        let root = transaction_directory(&unlink, InodeId::ROOT);
        must(unlink.unlink_file(root, &name));
        must(unlink.commit());

        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"new"),
            LookupResult::NotFound
        );
    }

    assert_eq!(get_u32(&image, 1024 + 16), 6);
}

#[test]
fn unlink_file_reports_missing_entry() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&transaction, InodeId::ROOT);
    let name = must(Ext4Name::new(b"missing"));
    let result = transaction.unlink_file(root, &name);

    assert_eq!(result, Err(Error::DirectoryEntryNotFound));
}

#[test]
fn rename_file_updates_staged_directory_entry() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, InodeId::ROOT);
        let old_name = must(Ext4Name::new(b"old"));
        let new_name = must(Ext4Name::new(b"new"));
        let file = must(transaction.create_file(root, &old_name, test_file_metadata()));
        must(transaction.rename_child(root, &old_name, root, &new_name));
        assert_eq!(file.inode_id(), inode(11));
        must(transaction.commit());

        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"old"),
            LookupResult::NotFound
        );
        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"new"),
            LookupResult::Found(inode(11))
        );
    }

    assert_eq!(get_u32(&image, 1024 + 16), 5);
}

#[test]
fn rename_rejects_existing_target() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&transaction, InodeId::ROOT);
    let source = must(Ext4Name::new(b"file"));
    let target = must(Ext4Name::new(b"target"));
    let _target_file = must(transaction.create_file(root, &target, test_file_metadata()));
    let result = transaction.rename_child(root, &source, root, &target);

    assert_eq!(result, Err(Error::NameAlreadyExists));
}

#[test]
fn create_and_remove_empty_directory_updates_namespace() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let name = must(Ext4Name::new(b"dir"));

        let mut create = volume.begin_transaction(NOW);
        let root = transaction_directory(&create, InodeId::ROOT);
        let directory = must(create.create_directory(root, &name, test_directory_metadata()));
        assert_eq!(directory.inode_id(), inode(11));
        must(create.commit());

        let entries = read_directory(&volume, inode(11));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name().bytes(), b".");
        assert_eq!(entries[1].name().bytes(), b"..");

        let mut remove = volume.begin_transaction(NOW);
        let root = transaction_directory(&remove, InodeId::ROOT);
        must(remove.remove_empty_directory(root, &name));
        must(remove.commit());

        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"dir"),
            LookupResult::NotFound
        );
    }

    assert_eq!(get_u32(&image, 1024 + 16), 6);
}

#[test]
fn create_inline_symlink_adds_directory_entry_and_inode() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, InodeId::ROOT);
        let name = must(Ext4Name::new(b"inline-link"));
        let target = must(SymlinkTarget::new(b"file"));
        let symlink =
            must(transaction.create_symlink(root, &name, &target, test_symlink_metadata()));
        assert_eq!(symlink.inode_id(), inode(11));
        must(transaction.commit());

        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"inline-link"),
            LookupResult::Found(inode(11))
        );
        let symlink = symlink_node(&volume, 11);
        assert_eq!(must(volume.read_symlink(&symlink)), b"file");
    }
}

#[test]
fn create_extent_symlink_writes_target_blocks() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let target_bytes = [b't'; 96];

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, InodeId::ROOT);
        let name = must(Ext4Name::new(b"extent-link"));
        let target = must(SymlinkTarget::new(&target_bytes));
        let symlink =
            must(transaction.create_symlink(root, &name, &target, test_symlink_metadata()));
        assert_eq!(symlink.inode_id(), inode(11));
        must(transaction.commit());

        let symlink = symlink_node(&volume, 11);
        assert_eq!(must(volume.read_symlink(&symlink)), target_bytes);
    }
}

#[test]
fn remove_symlink_removes_directory_entry_and_frees_inode() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let name = must(Ext4Name::new(b"delete-link"));
        let target = must(SymlinkTarget::new(b"file"));

        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, InodeId::ROOT);
        must(transaction.create_symlink(root, &name, &target, test_symlink_metadata()));
        must(transaction.commit());

        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, InodeId::ROOT);
        must(transaction.remove_symlink(root, &name));
        must(transaction.commit());

        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"delete-link"),
            LookupResult::NotFound
        );
    }
}

#[test]
fn rename_directory_across_parents_updates_dotdot() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let source_name = must(Ext4Name::new(b"a"));
        let target_parent_name = must(Ext4Name::new(b"b"));
        let moved_name = must(Ext4Name::new(b"moved"));

        let mut create_source = volume.begin_transaction(NOW);
        let root = transaction_directory(&create_source, InodeId::ROOT);
        let source =
            must(create_source.create_directory(root, &source_name, test_directory_metadata()));
        assert_eq!(source.inode_id(), inode(11));
        must(create_source.commit());

        let mut create_target = volume.begin_transaction(NOW);
        let root = transaction_directory(&create_target, InodeId::ROOT);
        let target_parent = must(create_target.create_directory(
            root,
            &target_parent_name,
            test_directory_metadata(),
        ));
        assert_eq!(target_parent.inode_id(), inode(12));
        must(create_target.commit());

        let mut rename = volume.begin_transaction(NOW);
        let root = transaction_directory(&rename, InodeId::ROOT);
        let target_parent = transaction_directory(&rename, inode(12));
        must(rename.rename_child(root, &source_name, target_parent, &moved_name));
        must(rename.commit());

        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"a"),
            LookupResult::NotFound
        );
        assert_eq!(
            lookup_ext4(&volume, inode(12), b"moved"),
            LookupResult::Found(inode(11))
        );
        let moved_entries = read_directory(&volume, inode(11));
        let dotdot = moved_entries
            .iter()
            .find(|entry| entry.name().bytes() == b"..");
        assert!(dotdot.is_some());
        if let Some(dotdot) = dotdot {
            assert_eq!(dotdot.inode(), inode(12));
        }
    }

    assert_eq!(get_u32(&image, 1024 + 16), 4);
}

#[test]
fn remove_directory_rejects_non_empty_child() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let dir_name = must(Ext4Name::new(b"dir"));
    let file_name = must(Ext4Name::new(b"child"));

    let mut create_dir = volume.begin_transaction(NOW);
    let root = transaction_directory(&create_dir, InodeId::ROOT);
    let directory = must(create_dir.create_directory(root, &dir_name, test_directory_metadata()));
    must(create_dir.commit());

    let mut create_file = volume.begin_transaction(NOW);
    let child_parent = transaction_directory(&create_file, directory.inode_id());
    let _file = must(create_file.create_file(child_parent, &file_name, test_file_metadata()));
    must(create_file.commit());

    let mut remove = volume.begin_transaction(NOW);
    let root = transaction_directory(&remove, InodeId::ROOT);
    let result = remove.remove_empty_directory(root, &dir_name);

    assert_eq!(result, Err(Error::DirectoryNotEmpty));
}

#[test]
fn remove_directory_rejects_root_entry() {
    let mut image = modern_fixture_image();
    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&transaction, InodeId::ROOT);
    let dot = must(Ext4Name::new(b"."));
    let result = transaction.remove_empty_directory(root, &dot);

    assert_eq!(result, Err(Error::CannotRemoveRoot));
}

#[test]
fn indexed_directory_create_rebuilds_real_htree() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    make_indexed_root_directory(&mut image);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, InodeId::ROOT);
        let name = must(Ext4Name::new(b"idx"));
        let file = must(transaction.create_file(root, &name, test_file_metadata()));
        assert_eq!(file.inode_id(), inode(11));
        must(transaction.commit());

        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"idx"),
            LookupResult::Found(inode(11))
        );
    }

    let root_block = block_offset(MODERN_ROOT_DIR_BLOCK);
    assert_eq!(get_u32(&image, root_block), 2);
    assert_eq!(image[root_block + 29], 8);
    assert_eq!(image[root_block + 30], 0);
    assert_eq!(get_u16(&image, root_block + 34), 1);
    assert_eq!(get_u32(&image, root_block + 36), 1);
    assert_eq!(get_u32(&image, block_offset(MODERN_EXTENT_INDEX_BLOCK)), 3);
}

#[test]
fn htree_directory_read_lookup_and_windows_lookup_use_real_index() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    make_indexed_root_directory(&mut image);
    let device = SliceBlockDevice::new(&image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        device,
        test_mount_context(),
    ));

    let entries = read_directory(&volume, InodeId::ROOT);

    assert!(entries.iter().any(|entry| entry.name().bytes() == b"."));
    assert!(entries.iter().any(|entry| entry.name().bytes() == b".."));
    assert!(entries.iter().any(|entry| entry.name().bytes() == b"file"));
    assert_eq!(
        lookup_ext4(&volume, InodeId::ROOT, b"file"),
        LookupResult::Found(inode(3))
    );
    assert_eq!(
        lookup_windows(
            &volume,
            InodeId::ROOT,
            &[
                u16::from(b'F'),
                u16::from(b'I'),
                u16::from(b'L'),
                u16::from(b'E'),
            ],
        ),
        LookupResult::Found(inode(3))
    );
}

#[test]
fn htree_dx_tail_checksum_mismatch_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    make_indexed_root_directory(&mut image);
    image[block_offset(MODERN_ROOT_DIR_BLOCK) + 36] ^= 1;
    let device = SliceBlockDevice::new(&image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        device,
        test_mount_context(),
    ));
    let root = directory_node(&volume, InodeId::ROOT);

    assert_eq!(volume.read_directory(&root), Err(Error::ChecksumMismatch));
}

#[test]
fn htree_leaf_tail_checksum_mismatch_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    make_indexed_root_directory(&mut image);
    image[block_offset(MODERN_EXTENT_INDEX_BLOCK) + 8] ^= 1;
    let device = SliceBlockDevice::new(&image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        device,
        test_mount_context(),
    ));
    let root = directory_node(&volume, InodeId::ROOT);

    assert_eq!(volume.read_directory(&root), Err(Error::ChecksumMismatch));
}

#[test]
fn linear_directory_converts_to_htree_when_full() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        for index in 0..4_u8 {
            let mut bytes = vec![b'a' + index; 240];
            bytes.push(b'0' + index);
            let name = must(Ext4Name::new(&bytes));
            let mut transaction = volume.begin_transaction(NOW);
            let root = transaction_directory(&transaction, InodeId::ROOT);
            let _file = must(transaction.create_file(root, &name, test_file_metadata()));
            must(transaction.commit());
        }

        let root = directory_node(&volume, InodeId::ROOT);
        let entries = must(volume.read_directory(&root));
        assert!(
            entries
                .iter()
                .any(|entry| entry.name().bytes().len() == 241)
        );
    }

    let root_inode = modern_inode_offset(2);
    assert_ne!(get_u32(&image, root_inode + 32) & EXT4_INDEX_FL, 0);
    assert!(get_u32(&image, root_inode + 4) >= u32::try_from(BLOCK_SIZE * 2).unwrap_or(u32::MAX));
}

#[test]
fn indexed_directory_rename_and_unlink_rebuild_htree_consistently() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    make_indexed_root_directory(&mut image);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let old_name = must(Ext4Name::new(b"temp"));
        let renamed_name = must(Ext4Name::new(b"renamed"));

        let mut create = volume.begin_transaction(NOW);
        let root = transaction_directory(&create, InodeId::ROOT);
        let file = must(create.create_file(root, &old_name, test_file_metadata()));
        must(create.commit());

        let mut rename = volume.begin_transaction(NOW);
        let root = transaction_directory(&rename, InodeId::ROOT);
        must(rename.rename_child(root, &old_name, root, &renamed_name));
        must(rename.commit());

        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"temp"),
            LookupResult::NotFound
        );
        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"renamed"),
            LookupResult::Found(file.inode_id())
        );

        let mut unlink = volume.begin_transaction(NOW);
        let root = transaction_directory(&unlink, InodeId::ROOT);
        must(unlink.unlink_file(root, &renamed_name));
        must(unlink.commit());

        assert_eq!(
            lookup_ext4(&volume, InodeId::ROOT, b"renamed"),
            LookupResult::NotFound
        );
    }
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
        let volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}

#[test]
fn bad_tag_checksum_transaction_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 9, 1);
    write_jbd2_data(&mut image, 2, b"BAD!!");
    write_jbd2_descriptor_with_checksum(&mut image, 1, 9, MODERN_FILE_DATA_BLOCK, 0xDEAD_BEEF);
    write_jbd2_commit(&mut image, 3, 9);

    let device = SliceBlockDeviceMut::new(&mut image);
    let result = Volume::<_, ReadWrite>::mount_read_write(device, test_mount_context());

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
    assert_eq!(get_be_u32(&image, journal_log_offset(0) + 0x1C), 1);
    assert_ne!(get_u32(&image, 1024 + 96) & INCOMPAT_RECOVER, 0);
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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
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

    let result: crate::Result<Volume<_, ReadWrite<ExternalJournal<_>>>> =
        Volume::mount_read_write_with_external_journal(
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
    let result = Volume::<_, ReadWrite>::mount_read_write(device, test_mount_context());

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn write_transaction_emits_descriptor_data_and_commit_records() {
    let mut image = modern_fixture_image();
    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        overwrite_file(&mut transaction, 3, 0, b"HELLO");
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
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        extend_file(&mut transaction, 3, 3072);
        must(transaction.commit());
    }

    put_u32(&mut image, modern_inode_offset(3) + 4, 2048);
    mark_filesystem_needs_recovery(&mut image);
    write_dirty_journal_superblock(&mut image, 1, 1);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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
    let _volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));

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
    let _volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));

    assert_eq!(get_be_u32(&image, journal_log_offset(0) + 0x18), 0);
    assert_eq!(get_be_u32(&image, journal_log_offset(0) + 0x1C), 0);
}

#[test]
fn nonzero_journal_ro_compat_is_rejected() {
    let mut image = modern_fixture_image();
    put_be_u32(&mut image, journal_log_offset(0) + 0x2C, 1);

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn recovery_required_with_zero_journal_start_is_rejected() {
    let mut image = modern_fixture_image();
    mark_filesystem_needs_recovery(&mut image);

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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
        let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
            device,
            test_mount_context(),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        overwrite_file(&mut transaction, 3, 0, b"MAGIC");
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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
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

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}

#[test]
fn nonzero_journal_compat_is_rejected() {
    let mut image = modern_fixture_image();
    put_be_u32(&mut image, journal_log_offset(0) + 0x24, 1);

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn journal_first_block_must_be_one() {
    let mut image = modern_fixture_image();
    put_be_u32(&mut image, journal_log_offset(0) + 0x14, 2);

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

    assert!(matches!(result, Err(Error::UnsupportedJournal)));
}

#[test]
fn journal_maxlen_beyond_inode_capacity_is_rejected() {
    let mut image = modern_fixture_image();
    put_be_u32(&mut image, journal_log_offset(0) + 0x10, 9);

    let result = Volume::<_, ReadWrite>::mount_read_write(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context(),
    );

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

    let result: crate::Result<Volume<_, ReadWrite<ExternalJournal<_>>>> =
        Volume::mount_read_write_with_external_journal(
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
    let mut volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"FRAG!");

    let mut transaction = volume.begin_transaction(NOW);
    overwrite_file(&mut transaction, 3, 1024, b"hole");
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
        let result = Volume::<_, ReadWrite>::mount_read_write(device, test_mount_context());
        assert!(matches!(result, Err(Error::DeviceRange)));
    }
    assert_eq!(get_be_u32(&image, journal_log_offset(0) + 0x1C), 1);
    assert_ne!(get_u32(&image, 1024 + 96) & INCOMPAT_RECOVER, 0);

    let device = SliceBlockDeviceMut::new(&mut image);
    let volume = must(Volume::<_, ReadWrite>::mount_read_write(
        device,
        test_mount_context(),
    ));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"AGAIN");
}

#[test]
fn extent_depth_traversal_reads_index_block() {
    let mut image = modern_fixture_image();
    write_indexed_file_inode(&mut image);
    let volume = must(Volume::<_, ReadOnly>::mount_read_only(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let mut output = [0_u8; 5];
    let read = read_file(&volume, 3, 0, &mut output);

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

fn bigalloc_fixture_image() -> Vec<u8> {
    bigalloc_fixture_image_with_journal_blocks(8)
}

fn bigalloc_fixture_image_with_journal_blocks(journal_blocks: u16) -> Vec<u8> {
    let mut image = vec![0_u8; BLOCK_SIZE * MODERN_IMAGE_BLOCKS];
    let free_clusters = write_bigalloc_block_bitmap(&mut image, journal_blocks);
    let free_inodes = write_modern_inode_bitmap(&mut image);
    write_modern_superblock(&mut image, free_clusters, free_inodes, journal_blocks);
    put_u32(&mut image, 1024 + 28, BIGALLOC_LOG_CLUSTER_SIZE);
    put_u32(&mut image, 1024 + 36, 8192 / BIGALLOC_BLOCKS_PER_CLUSTER);
    put_u32(
        &mut image,
        1024 + 100,
        RO_COMPAT_MODERN | RO_COMPAT_BIGALLOC,
    );
    write_modern_block_group_descriptor(&mut image, free_clusters, free_inodes);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    write_modern_root_inode(&mut image);
    write_modern_file_inode(&mut image);
    write_modern_journal_inode(&mut image, journal_blocks);
    write_modern_root_directory(&mut image);
    let file_data_offset = block_offset(MODERN_FILE_DATA_BLOCK);
    image[file_data_offset..file_data_offset + 5].copy_from_slice(b"hello");
    image
}

fn modern_fixture_image_with_journal_blocks(journal_blocks: u16) -> Vec<u8> {
    let mut image = vec![0_u8; BLOCK_SIZE * MODERN_IMAGE_BLOCKS];
    let free_clusters = write_modern_block_bitmap(&mut image, journal_blocks);
    let free_inodes = write_modern_inode_bitmap(&mut image);
    write_modern_superblock(&mut image, free_clusters, free_inodes, journal_blocks);
    write_modern_block_group_descriptor(&mut image, free_clusters, free_inodes);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    write_modern_root_inode(&mut image);
    write_modern_file_inode(&mut image);
    write_modern_journal_inode(&mut image, journal_blocks);
    write_modern_root_directory(&mut image);
    let file_data_offset = block_offset(MODERN_FILE_DATA_BLOCK);
    image[file_data_offset..file_data_offset + 5].copy_from_slice(b"hello");
    image
}

fn variable_block_fixture_image(block_size: usize) -> Vec<u8> {
    let image_blocks = 8_usize;
    let inode_table_block = 3_u32;
    let root_dir_block = 5_u32;
    let file_data_block = 6_u32;
    let mut image = vec![0_u8; block_size * image_blocks];
    let base = 1024;
    let log_block_size = block_size.trailing_zeros() - 10;

    put_u32(&mut image, base, 16);
    put_u32(
        &mut image,
        base + 4,
        u32::try_from(image_blocks).unwrap_or(u32::MAX),
    );
    put_u32(&mut image, base + 20, 0);
    put_u32(&mut image, base + 24, log_block_size);
    put_u32(&mut image, base + 28, log_block_size);
    put_u32(
        &mut image,
        base + 32,
        u32::try_from(block_size * 8).unwrap_or(u32::MAX),
    );
    put_u32(
        &mut image,
        base + 36,
        u32::try_from(block_size * 8).unwrap_or(u32::MAX),
    );
    put_u32(&mut image, base + 40, 16);
    put_u16(&mut image, base + 56, 0xEF53);
    put_u16(&mut image, base + 58, 1);
    put_u32(&mut image, base + 76, 1);
    put_u32(&mut image, base + 84, 11);
    put_u16(&mut image, base + 88, 128);
    put_u32(&mut image, base + 96, 0x0002 | 0x0040);
    put_u32(&mut image, base + 100, 0x0001 | 0x0002);

    put_u32(
        &mut image,
        variable_block_offset(1, block_size) + 8,
        inode_table_block,
    );

    let root_inode = variable_inode_offset(inode_table_block, 2, block_size);
    put_u16(&mut image, root_inode, 0x4000 | 0o755);
    put_u32(
        &mut image,
        root_inode + 4,
        u32::try_from(block_size).unwrap_or(u32::MAX),
    );
    put_u32(&mut image, root_inode + 32, EXT4_EXTENTS_FL);
    write_extent_root(&mut image, root_inode + 40, 0, 1, root_dir_block);

    let file_inode = variable_inode_offset(inode_table_block, 3, block_size);
    put_u16(&mut image, file_inode, 0x8000 | 0o444);
    put_u32(&mut image, file_inode + 4, 5);
    put_u32(&mut image, file_inode + 32, EXT4_EXTENTS_FL);
    write_extent_root(&mut image, file_inode + 40, 0, 1, file_data_block);

    let root_dir = variable_block_offset(root_dir_block, block_size);
    write_dirent(&mut image, root_dir, 2, 12, b".", 2);
    write_dirent(&mut image, root_dir + 12, 2, 12, b"..", 2);
    write_dirent(
        &mut image,
        root_dir + 24,
        3,
        u16::try_from(block_size - 24).unwrap_or(u16::MAX),
        b"file",
        1,
    );

    let file_data_offset = variable_block_offset(file_data_block, block_size);
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
    put_u32(image, base + 28, 0);
    put_u32(image, base + 32, 8192);
    put_u32(image, base + 36, 8192);
    put_u32(image, base + 40, 16);
    put_u16(image, base + 56, 0xEF53);
    put_u16(image, base + 58, 1);
    put_u32(image, base + 76, 1);
    put_u32(image, base + 84, 11);
    put_u16(image, base + 88, 128);
    put_u32(image, base + 96, 0x0002 | 0x0040);
    put_u32(image, base + 100, 0x0001 | 0x0002);
}

fn write_modern_superblock(
    image: &mut [u8],
    free_clusters: u32,
    free_inodes: u32,
    journal_blocks: u16,
) {
    let base = 1024;
    put_u32(image, base, 16);
    put_u32(
        image,
        base + 4,
        u32::try_from(MODERN_IMAGE_BLOCKS).unwrap_or(u32::MAX),
    );
    put_u32(image, base + 12, free_clusters);
    put_u32(image, base + 16, free_inodes);
    put_u32(image, base + 20, 1);
    put_u32(image, base + 24, 0);
    put_u32(image, base + 28, 0);
    put_u32(image, base + 32, 8192);
    put_u32(image, base + 36, 8192);
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

fn write_modern_block_group_descriptor(image: &mut [u8], free_clusters: u32, free_inodes: u32) {
    let base = block_offset(2);
    put_u32(image, base, MODERN_BLOCK_BITMAP_BLOCK);
    put_u32(image, base + 4, MODERN_INODE_BITMAP_BLOCK);
    put_u32(image, base + 8, MODERN_INODE_TABLE_BLOCK);
    put_u16(
        image,
        base + 12,
        u16::try_from(free_clusters & u32::from(u16::MAX)).unwrap_or(u16::MAX),
    );
    put_u16(
        image,
        base + 44,
        u16::try_from(free_clusters >> 16).unwrap_or(u16::MAX),
    );
    put_u16(
        image,
        base + 14,
        u16::try_from(free_inodes & u32::from(u16::MAX)).unwrap_or(u16::MAX),
    );
    put_u16(image, base + 16, 1);
    put_u16(
        image,
        base + 46,
        u16::try_from(free_inodes >> 16).unwrap_or(u16::MAX),
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

fn write_bigalloc_block_bitmap(image: &mut [u8], journal_blocks: u16) -> u32 {
    let bitmap = block_offset(MODERN_BLOCK_BITMAP_BLOCK);
    image[bitmap..bitmap + BLOCK_SIZE].fill(0);
    let mut used_clusters = [false; 16];
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
        mark_bigalloc_cluster_for_block(image, &mut used_clusters, block);
    }
    for offset in 0..journal_blocks {
        mark_bigalloc_cluster_for_block(
            image,
            &mut used_clusters,
            MODERN_JOURNAL_BLOCK + u32::from(offset),
        );
    }
    let used = used_clusters.iter().filter(|used| **used).count();
    u32::try_from(used_clusters.len() - used).unwrap_or(u32::MAX)
}

fn mark_bigalloc_cluster_for_block(image: &mut [u8], used_clusters: &mut [bool; 16], block: u32) {
    let cluster = usize::try_from((block - 1) / BIGALLOC_BLOCKS_PER_CLUSTER).unwrap_or(usize::MAX);
    used_clusters[cluster] = true;
    set_bigalloc_cluster_used(image, u32::try_from(cluster).unwrap_or(u32::MAX), true);
}

fn set_bigalloc_cluster_used(image: &mut [u8], cluster: u32, used: bool) {
    let byte = block_offset(MODERN_BLOCK_BITMAP_BLOCK)
        + usize::try_from(cluster / 8).unwrap_or(usize::MAX);
    let mask = 1_u8 << (cluster % 8);
    if used {
        image[byte] |= mask;
    } else {
        image[byte] &= !mask;
    }
}

fn bigalloc_cluster_is_used(image: &[u8], cluster: u32) -> bool {
    let byte = block_offset(MODERN_BLOCK_BITMAP_BLOCK)
        + usize::try_from(cluster / 8).unwrap_or(usize::MAX);
    let mask = 1_u8 << (cluster % 8);
    image[byte] & mask != 0
}

fn bigalloc_cluster_for_block(block: u32) -> u32 {
    (block - 1) / BIGALLOC_BLOCKS_PER_CLUSTER
}

fn write_modern_inode_bitmap(image: &mut [u8]) -> u32 {
    for inode in 1..=10 {
        set_modern_inode_used(image, inode, true);
    }
    6
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
    refresh_extent_block_checksum(image, 3, MODERN_EXTENT_INDEX_BLOCK);
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
    let data = image[journal_log_offset(logical + 1)..journal_log_offset(logical + 1) + BLOCK_SIZE]
        .to_vec();
    let checksum = jbd2_tag_checksum(sequence, &data, [0; 16]);
    write_jbd2_descriptor_with_checksum(image, logical, sequence, home_block, checksum);
    let flags_offset = journal_log_offset(logical) + 16;
    put_be_u32(
        image,
        flags_offset,
        JBD2_TAG_FLAG_SAME_UUID | JBD2_TAG_FLAG_LAST_TAG | extra_flags,
    );
    write_jbd2_block_tail_checksum(image, logical, [0; 16]);
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
    write_jbd2_block_tail_checksum(image, logical, [0; 16]);
}

fn write_jbd2_descriptor_with_uuid(
    image: &mut [u8],
    logical: u32,
    sequence: u32,
    home_block: u32,
    tag_uuid: [u8; 16],
    journal_uuid: [u8; 16],
) {
    let data = image[journal_log_offset(logical + 1)..journal_log_offset(logical + 1) + BLOCK_SIZE]
        .to_vec();
    let checksum = jbd2_tag_checksum(sequence, &data, journal_uuid);
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    write_jbd2_header(image, base, JBD2_DESCRIPTOR_BLOCK, sequence);
    put_be_u32(image, base + 12, home_block);
    put_be_u32(image, base + 16, JBD2_TAG_FLAG_LAST_TAG);
    put_be_u32(image, base + 20, 0);
    put_be_u32(image, base + 24, checksum);
    image[base + 28..base + 44].copy_from_slice(&tag_uuid);
    write_jbd2_block_tail_checksum(image, logical, journal_uuid);
}

fn write_jbd2_two_tag_descriptor(
    image: &mut [u8],
    logical: u32,
    sequence: u32,
    first_home_block: u32,
    second_home_block: u32,
    uuid: [u8; 16],
) {
    let first_data = image
        [journal_log_offset(logical + 1)..journal_log_offset(logical + 1) + BLOCK_SIZE]
        .to_vec();
    let second_data = image
        [journal_log_offset(logical + 2)..journal_log_offset(logical + 2) + BLOCK_SIZE]
        .to_vec();
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    write_jbd2_header(image, base, JBD2_DESCRIPTOR_BLOCK, sequence);

    put_be_u32(image, base + 12, first_home_block);
    put_be_u32(image, base + 16, JBD2_TAG_FLAG_SAME_UUID);
    put_be_u32(image, base + 20, 0);
    put_be_u32(
        image,
        base + 24,
        jbd2_tag_checksum(sequence, &first_data, uuid),
    );

    put_be_u32(image, base + 28, second_home_block);
    put_be_u32(
        image,
        base + 32,
        JBD2_TAG_FLAG_SAME_UUID | JBD2_TAG_FLAG_LAST_TAG,
    );
    put_be_u32(image, base + 36, 0);
    put_be_u32(
        image,
        base + 40,
        jbd2_tag_checksum(sequence, &second_data, uuid),
    );

    write_jbd2_block_tail_checksum(image, logical, uuid);
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
    write_jbd2_commit_with_checksum(image, logical, sequence, [0; 16]);
}

fn write_jbd2_commit_with_checksum(image: &mut [u8], logical: u32, sequence: u32, uuid: [u8; 16]) {
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    write_jbd2_header(image, base, JBD2_COMMIT_BLOCK, sequence);
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
    write_jbd2_block_tail_checksum(image, logical, [0; 16]);
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

fn refresh_jbd2_superblock_checksum(image: &mut [u8], base: usize) {
    put_be_u32(image, base + 0xFC, 0);
    let checksum = jbd2_superblock_checksum(image, base);
    put_be_u32(image, base + 0xFC, checksum);
}

fn jbd2_superblock_checksum(image: &[u8], base: usize) -> u32 {
    let mut block = image[base..base + 1024].to_vec();
    block[0xFC..0x100].fill(0);
    crate::checksum::crc32c(0, &block)
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

fn write_fragmented_journal_inode(image: &mut [u8]) {
    let offset = modern_inode_offset(8);
    put_u16(image, offset, 0x8000 | 0o600);
    put_u32(
        image,
        offset + 4,
        8 * u32::try_from(BLOCK_SIZE).unwrap_or(u32::MAX),
    );
    put_u32(image, offset + 28, 16);
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    write_two_extent_root(image, offset + 40, 0, 4, MODERN_JOURNAL_BLOCK, 4, 4, 28);
    for block in 24..28 {
        set_modern_block_used(image, block, false);
    }
    for block in 28..32 {
        set_modern_block_used(image, block, true);
    }
}

fn move_journal_block(image: &mut [u8], logical: u32, physical_block: u32) {
    let source = journal_log_offset(logical);
    let target = block_offset(physical_block);
    let block = image[source..source + BLOCK_SIZE].to_vec();
    image[target..target + BLOCK_SIZE].copy_from_slice(&block);
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

fn make_indexed_root_directory(image: &mut [u8]) {
    set_modern_block_used(image, MODERN_EXTENT_INDEX_BLOCK, true);
    let free_clusters = get_u32(image, 1024 + 12) - 1;
    put_u32(image, 1024 + 12, free_clusters);
    let descriptor = block_offset(2);
    put_u16(
        image,
        descriptor + 12,
        u16::try_from(free_clusters & u32::from(u16::MAX)).unwrap_or(u16::MAX),
    );
    put_u16(
        image,
        descriptor + 44,
        u16::try_from(free_clusters >> 16).unwrap_or(u16::MAX),
    );

    let root_inode = modern_inode_offset(2);
    put_u32(
        image,
        root_inode + 4,
        u32::try_from(BLOCK_SIZE * 2).unwrap_or(u32::MAX),
    );
    put_u32(image, root_inode + 28, 4);
    put_u32(image, root_inode + 32, EXT4_EXTENTS_FL | EXT4_INDEX_FL);
    write_two_extent_root(
        image,
        root_inode + 40,
        0,
        1,
        MODERN_ROOT_DIR_BLOCK,
        1,
        1,
        MODERN_EXTENT_INDEX_BLOCK,
    );
    let superblock = must(Superblock::parse(&image[1024..2048]));
    let checksum = crate::dir::DirectoryChecksum::metadata_csum(
        superblock.checksum_seed(),
        inode(2),
        get_u32(image, root_inode + 100),
    );
    let file_name = must(Ext4Name::new(b"file"));
    let entries = vec![DirectoryEntry::new(
        inode(3),
        &file_name,
        DirectoryEntryKind::File,
    )];
    let htree = must(crate::dir::build_htree_directory(
        inode(2),
        inode(2),
        &entries,
        BLOCK_SIZE,
        superblock.directory_hash_seed(),
        superblock.default_directory_hash_version(),
        checksum,
    ));
    image[block_offset(MODERN_ROOT_DIR_BLOCK)..block_offset(MODERN_ROOT_DIR_BLOCK) + BLOCK_SIZE]
        .copy_from_slice(&htree.blocks()[0]);
    image[block_offset(MODERN_EXTENT_INDEX_BLOCK)
        ..block_offset(MODERN_EXTENT_INDEX_BLOCK) + BLOCK_SIZE]
        .copy_from_slice(&htree.blocks()[1]);
    refresh_primary_block_group_descriptor_checksum(image);
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

#[expect(
    clippy::too_many_arguments,
    reason = "ext4 extent entries are fixed on-disk fields"
)]
fn write_two_extent_root(
    image: &mut [u8],
    offset: usize,
    first_logical_start: u32,
    first_len: u16,
    first_physical_start: u32,
    second_logical_start: u32,
    second_len: u16,
    second_physical_start: u32,
) {
    image[offset..offset + 60].fill(0);
    put_u16(image, offset, 0xF30A);
    put_u16(image, offset + 2, 2);
    put_u16(image, offset + 4, 4);
    put_u16(image, offset + 6, 0);
    put_u32(image, offset + 12, first_logical_start);
    put_u16(image, offset + 16, first_len);
    put_u16(image, offset + 18, 0);
    put_u32(image, offset + 20, first_physical_start);
    put_u32(image, offset + 24, second_logical_start);
    put_u16(image, offset + 28, second_len);
    put_u16(image, offset + 30, 0);
    put_u32(image, offset + 32, second_physical_start);
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

fn variable_inode_offset(inode_table_block: u32, inode: u32, block_size: usize) -> usize {
    variable_block_offset(inode_table_block, block_size)
        + usize::try_from(inode - 1).unwrap_or(usize::MAX) * 128
}

fn block_offset(block: u32) -> usize {
    usize::try_from(block).unwrap_or(usize::MAX) * BLOCK_SIZE
}

fn variable_block_offset(block: u32, block_size: usize) -> usize {
    usize::try_from(block).unwrap_or(usize::MAX) * block_size
}

fn primary_block_group_descriptor_offset(image: &[u8]) -> usize {
    let superblock = must(Superblock::parse(&image[1024..2048]));
    let block_size = usize::try_from(superblock.block_size().bytes()).unwrap_or(usize::MAX);
    if block_size == 1024 {
        variable_block_offset(2, block_size)
    } else {
        variable_block_offset(1, block_size)
    }
}

fn refresh_primary_block_group_descriptor_checksum(image: &mut [u8]) {
    let superblock = must(Superblock::parse(&image[1024..2048]));
    let descriptor_size = usize::from(superblock.descriptor_size().as_u16());
    let base = primary_block_group_descriptor_offset(image);
    must(crate::group::write_block_group_descriptor_checksum(
        &superblock,
        BlockGroupId::from_u32(0),
        &mut image[base..base + descriptor_size],
    ));
}

fn refresh_extent_block_checksum(image: &mut [u8], inode: u32, block: u32) {
    let superblock = must(Superblock::parse(&image[1024..2048]));
    let base = block_offset(block);
    put_u32(image, base + BLOCK_SIZE - 4, 0);
    let inode_offset = modern_inode_offset(inode);
    let generation = get_u32(image, inode_offset + 100);
    let mut checksum =
        crate::checksum::crc32c(superblock.checksum_seed().as_u32(), &inode.to_le_bytes());
    checksum = crate::checksum::crc32c(checksum, &generation.to_le_bytes());
    checksum = crate::checksum::crc32c(checksum, &image[base..base + BLOCK_SIZE]);
    put_u32(image, base + BLOCK_SIZE - 4, checksum);
}

fn corrupt_primary_block_group_descriptor_checksum(image: &mut [u8]) {
    let base = primary_block_group_descriptor_offset(image);
    let checksum_offset = base + 30;
    put_u16(
        image,
        checksum_offset,
        get_u16(image, checksum_offset) ^ u16::MAX,
    );
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

fn set_modern_inode_used(image: &mut [u8], inode: u32, used: bool) {
    let bit = inode - 1;
    let byte =
        block_offset(MODERN_INODE_BITMAP_BLOCK) + usize::try_from(bit / 8).unwrap_or(usize::MAX);
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

fn get_u16(image: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([image[offset], image[offset + 1]])
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

#[derive(Debug)]
struct FailOneWriteAt<'a> {
    bytes: &'a mut [u8],
    fail_offset: ByteOffset,
    failed: bool,
}

impl<'a> FailOneWriteAt<'a> {
    fn new(bytes: &'a mut [u8], fail_offset: ByteOffset) -> Self {
        Self {
            bytes,
            fail_offset,
            failed: false,
        }
    }
}

impl BlockReader for FailOneWriteAt<'_> {
    fn len(&self) -> DeviceLength {
        DeviceLength::from_bytes(u64::try_from(self.bytes.len()).unwrap_or(u64::MAX))
    }

    fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> crate::Result<()> {
        let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
        let end = start.checked_add(out.len()).ok_or(Error::DeviceRange)?;
        let source = self.bytes.get(start..end).ok_or(Error::DeviceRange)?;
        out.copy_from_slice(source);
        Ok(())
    }
}

impl BlockWriter for FailOneWriteAt<'_> {
    fn write_exact_at(&mut self, offset: ByteOffset, bytes: &[u8]) -> crate::Result<()> {
        if offset == self.fail_offset && !self.failed {
            self.failed = true;
            return Err(Error::DeviceRange);
        }
        let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
        let end = start.checked_add(bytes.len()).ok_or(Error::DeviceRange)?;
        let target = self.bytes.get_mut(start..end).ok_or(Error::DeviceRange)?;
        target.copy_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

fn must<T>(result: crate::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected ext4-core error: {error:?}"),
    }
}
