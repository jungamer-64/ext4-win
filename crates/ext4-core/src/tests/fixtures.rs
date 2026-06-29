use super::*;

pub(super) fn fixture_image() -> Vec<u8> {
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

pub(super) fn modern_fixture_image() -> Vec<u8> {
    modern_fixture_image_with_journal_blocks(8)
}

pub(super) fn minimal_write_fixture_image() -> Vec<u8> {
    minimal_write_fixture_image_with_journal_blocks(16)
}

pub(super) fn minimal_write_fixture_image_with_journal_blocks(journal_blocks: u16) -> Vec<u8> {
    let mut image = modern_fixture_image_with_journal_blocks(journal_blocks);
    put_u32(&mut image, 1024 + 92, COMPAT_HAS_JOURNAL);
    put_u32(&mut image, 1024 + 96, INCOMPAT_FILETYPE | INCOMPAT_EXTENTS);
    put_u32(&mut image, 1024 + 100, 0);
    put_u16(&mut image, 1024 + 254, 0);
    image
}

pub(super) fn minimal_write_fixture_image_with_gdt_csum() -> Vec<u8> {
    let mut image = minimal_write_fixture_image();
    put_u32(&mut image, 1024 + 100, RO_COMPAT_GDT_CSUM);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    image
}

pub(super) fn bigalloc_fixture_image() -> Vec<u8> {
    bigalloc_fixture_image_with_journal_blocks(8)
}

pub(super) fn bigalloc_fixture_image_with_journal_blocks(journal_blocks: u16) -> Vec<u8> {
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

pub(super) fn modern_fixture_image_with_journal_blocks(journal_blocks: u16) -> Vec<u8> {
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

pub(super) fn verity_fixture_image() -> Vec<u8> {
    const VERITY_IMAGE_BLOCKS: usize = 80;
    const VERITY_METADATA_BLOCK: u32 = 64;
    const VERITY_METADATA_BLOCKS: u16 = 2;

    let mut image = modern_fixture_image();
    image.resize(BLOCK_SIZE * VERITY_IMAGE_BLOCKS, 0);
    put_u32(
        &mut image,
        1024 + 4,
        u32::try_from(VERITY_IMAGE_BLOCKS).unwrap_or(u32::MAX),
    );
    let free_clusters = get_u32(&image, 1024 + 12) + 14;
    put_u32(&mut image, 1024 + 12, free_clusters);
    let descriptor = block_offset(2);
    put_u16(
        &mut image,
        descriptor + 12,
        u16::try_from(free_clusters & u32::from(u16::MAX)).unwrap_or(u16::MAX),
    );
    put_u16(
        &mut image,
        descriptor + 44,
        u16::try_from(free_clusters >> 16).unwrap_or(u16::MAX),
    );
    for block in VERITY_METADATA_BLOCK..VERITY_METADATA_BLOCK + u32::from(VERITY_METADATA_BLOCKS) {
        set_modern_block_used(&mut image, block, true);
    }

    let inode_offset = modern_inode_offset(3);
    let read_only_compat = get_u32(&image, 1024 + 100) | RO_COMPAT_VERITY;
    let inode_flags = get_u32(&image, inode_offset + 32) | EXT4_VERITY_FL;
    put_u32(&mut image, 1024 + 100, read_only_compat);
    put_u32(&mut image, inode_offset + 32, inode_flags);
    put_u32(&mut image, inode_offset + 28, 6);
    write_two_extent_root(
        &mut image,
        inode_offset + 40,
        0,
        1,
        MODERN_FILE_DATA_BLOCK,
        VERITY_METADATA_BLOCK,
        VERITY_METADATA_BLOCKS,
        VERITY_METADATA_BLOCK,
    );

    let mut plaintext = vec![0_u8; 2048];
    plaintext[..5].copy_from_slice(b"hello");
    let verity_block_size = must(FsverityBlockSize::new(
        u32::try_from(BLOCK_SIZE).unwrap_or(u32::MAX),
    ));
    let salt = FsveritySalt::empty();
    let merkle_tree = must(FsverityMerkleTree::build(
        &plaintext,
        FsverityHashAlgorithm::Sha256,
        verity_block_size,
        &salt,
    ));
    let descriptor = must(FsverityDescriptor::new(
        FsverityHashAlgorithm::Sha256,
        verity_block_size,
        u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
        merkle_tree.root_hash(),
        salt,
    ));
    let descriptor_bytes = must(descriptor.to_bytes());
    let layout = must(Ext4VerityMetadataLayout::new(
        FileSize::from_bytes(u64::try_from(plaintext.len()).unwrap_or(u64::MAX)),
        must(BlockSize::from_superblock_log(0)),
        u64::try_from(merkle_tree.blocks().len()).unwrap_or(u64::MAX),
        u32::try_from(FSVERITY_DESCRIPTOR_BYTES).unwrap_or(u32::MAX),
    ));
    let tree_offset = usize::try_from(layout.merkle_tree_offset()).unwrap_or(usize::MAX);
    image[tree_offset..tree_offset + merkle_tree.blocks().len()]
        .copy_from_slice(merkle_tree.blocks());
    let descriptor_offset = usize::try_from(layout.descriptor_offset()).unwrap_or(usize::MAX);
    image[descriptor_offset..descriptor_offset + descriptor_bytes.len()]
        .copy_from_slice(&descriptor_bytes);
    put_u32(
        &mut image,
        usize::try_from(layout.descriptor_size_offset()).unwrap_or(usize::MAX),
        u32::try_from(FSVERITY_DESCRIPTOR_BYTES).unwrap_or(u32::MAX),
    );
    refresh_primary_block_group_descriptor_checksum(&mut image);
    image
}

pub(super) fn variable_block_fixture_image(block_size: usize) -> Vec<u8> {
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

pub(super) fn write_superblock(image: &mut [u8]) {
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

pub(super) fn write_modern_superblock(
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

pub(super) fn write_block_group_descriptor(image: &mut [u8]) {
    put_u32(image, block_offset(2) + 8, INODE_TABLE_BLOCK);
}

pub(super) fn write_modern_block_group_descriptor(
    image: &mut [u8],
    free_clusters: u32,
    free_inodes: u32,
) {
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

pub(super) fn write_modern_block_bitmap(image: &mut [u8], journal_blocks: u16) -> u32 {
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

pub(super) fn write_bigalloc_block_bitmap(image: &mut [u8], journal_blocks: u16) -> u32 {
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

pub(super) fn mark_bigalloc_cluster_for_block(
    image: &mut [u8],
    used_clusters: &mut [bool; 16],
    block: u32,
) {
    let cluster = usize::try_from((block - 1) / BIGALLOC_BLOCKS_PER_CLUSTER).unwrap_or(usize::MAX);
    used_clusters[cluster] = true;
    set_bigalloc_cluster_used(image, u32::try_from(cluster).unwrap_or(u32::MAX), true);
}

pub(super) fn set_bigalloc_cluster_used(image: &mut [u8], cluster: u32, used: bool) {
    let byte = block_offset(MODERN_BLOCK_BITMAP_BLOCK)
        + usize::try_from(cluster / 8).unwrap_or(usize::MAX);
    let mask = 1_u8 << (cluster % 8);
    if used {
        image[byte] |= mask;
    } else {
        image[byte] &= !mask;
    }
}

pub(super) fn bigalloc_cluster_is_used(image: &[u8], cluster: u32) -> bool {
    let byte = block_offset(MODERN_BLOCK_BITMAP_BLOCK)
        + usize::try_from(cluster / 8).unwrap_or(usize::MAX);
    let mask = 1_u8 << (cluster % 8);
    image[byte] & mask != 0
}

pub(super) fn bigalloc_cluster_for_block(block: u32) -> u32 {
    (block - 1) / BIGALLOC_BLOCKS_PER_CLUSTER
}

pub(super) fn write_modern_inode_bitmap(image: &mut [u8]) -> u32 {
    for inode in 1..=10 {
        set_modern_inode_used(image, inode, true);
    }
    6
}

pub(super) fn write_root_inode(image: &mut [u8]) {
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

pub(super) fn write_modern_root_inode(image: &mut [u8]) {
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

pub(super) fn write_file_inode(image: &mut [u8]) {
    let offset = inode_offset(3);
    put_u16(image, offset, 0x8000 | 0o444);
    put_u32(image, offset + 4, 2048);
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    write_extent_root(image, offset + 40, 1, 1, FILE_DATA_BLOCK);
}

pub(super) fn write_modern_file_inode(image: &mut [u8]) {
    let offset = modern_inode_offset(3);
    put_u16(image, offset, 0x8000 | 0o444);
    put_u32(image, offset + 4, 2048);
    put_u32(image, offset + 28, 2);
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    write_extent_root(image, offset + 40, 0, 1, MODERN_FILE_DATA_BLOCK);
}

pub(super) fn write_indexed_file_inode(image: &mut [u8]) {
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

pub(super) fn write_modern_journal_inode(image: &mut [u8], journal_blocks: u16) {
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

pub(super) fn write_jbd2_superblock(image: &mut [u8], journal_blocks: u16) {
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

pub(super) fn write_jbd2_superblock_at(
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

pub(super) fn default_journal_incompat() -> u32 {
    JBD2_FEATURE_INCOMPAT_REVOKE | JBD2_FEATURE_INCOMPAT_64BIT | JBD2_FEATURE_INCOMPAT_CSUM_V3
}

pub(super) fn write_dirty_journal_superblock(image: &mut [u8], sequence: u32, start: u32) {
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

pub(super) fn write_jbd2_descriptor(
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

pub(super) fn write_jbd2_descriptor_with_checksum(
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

pub(super) fn write_jbd2_descriptor_with_uuid(
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

pub(super) fn write_jbd2_two_tag_descriptor(
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

pub(super) fn write_jbd2_descriptor_32bit(
    image: &mut [u8],
    logical: u32,
    sequence: u32,
    home_block: u32,
) {
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

pub(super) fn write_jbd2_descriptor_csum_v2(
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

pub(super) fn write_jbd2_data(image: &mut [u8], logical: u32, prefix: &[u8]) {
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    image[base..base + prefix.len()].copy_from_slice(prefix);
}

pub(super) fn write_jbd2_commit(image: &mut [u8], logical: u32, sequence: u32) {
    write_jbd2_commit_with_checksum(image, logical, sequence, [0; 16]);
}

pub(super) fn write_jbd2_commit_with_checksum(
    image: &mut [u8],
    logical: u32,
    sequence: u32,
    uuid: [u8; 16],
) {
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    write_jbd2_header(image, base, JBD2_COMMIT_BLOCK, sequence);
    image[base + 0x0C] = JBD2_CHECKSUM_CRC32C;
    image[base + 0x0D] = 4;
    let checksum = jbd2_block_checksum(image, logical, 0x10, uuid);
    put_be_u32(image, base + 0x10, checksum);
}

pub(super) fn write_jbd2_revoke(image: &mut [u8], logical: u32, sequence: u32, block: u32) {
    let base = journal_log_offset(logical);
    image[base..base + BLOCK_SIZE].fill(0);
    write_jbd2_header(image, base, JBD2_REVOKE_BLOCK, sequence);
    put_be_u32(image, base + 12, 28);
    put_be_u32(image, base + 16, 0);
    put_be_u32(image, base + 20, block);
    write_jbd2_block_tail_checksum(image, logical, [0; 16]);
}

pub(super) fn write_jbd2_header(image: &mut [u8], base: usize, block_type: u32, sequence: u32) {
    put_be_u32(image, base, JBD2_MAGIC);
    put_be_u32(image, base + 4, block_type);
    put_be_u32(image, base + 8, sequence);
}

pub(super) fn write_jbd2_block_tail_checksum(image: &mut [u8], logical: u32, uuid: [u8; 16]) {
    let tail = journal_log_offset(logical) + BLOCK_SIZE - 4;
    put_be_u32(image, tail, 0);
    let checksum = jbd2_block_checksum(image, logical, BLOCK_SIZE - 4, uuid);
    put_be_u32(image, tail, checksum);
}

pub(super) fn refresh_jbd2_superblock_checksum(image: &mut [u8], base: usize) {
    put_be_u32(image, base + 0xFC, 0);
    let checksum = jbd2_superblock_checksum(image, base);
    put_be_u32(image, base + 0xFC, checksum);
}

pub(super) fn jbd2_superblock_checksum(image: &[u8], base: usize) -> u32 {
    let mut block = image[base..base + 1024].to_vec();
    block[0xFC..0x100].fill(0);
    crate::disk::checksum::crc32c(0, &block)
}

pub(super) fn jbd2_block_checksum(
    image: &[u8],
    logical: u32,
    checksum_offset: usize,
    uuid: [u8; 16],
) -> u32 {
    let base = journal_log_offset(logical);
    let mut block = image[base..base + BLOCK_SIZE].to_vec();
    block[checksum_offset..checksum_offset + 4].fill(0);
    crate::disk::checksum::crc32c(crate::disk::checksum::crc32c(0, &uuid), &block)
}

pub(super) fn jbd2_tag_checksum(sequence: u32, data: &[u8], uuid: [u8; 16]) -> u32 {
    let seed = crate::disk::checksum::crc32c(0, &uuid);
    let seed = crate::disk::checksum::crc32c(seed, &sequence.to_be_bytes());
    crate::disk::checksum::crc32c(seed, data)
}

pub(super) fn journal_log_offset(logical: u32) -> usize {
    block_offset(MODERN_JOURNAL_BLOCK + logical)
}

pub(super) fn mark_filesystem_needs_recovery(image: &mut [u8]) {
    put_u32(image, 1024 + 96, INCOMPAT_MODERN | INCOMPAT_RECOVER);
}

pub(super) fn make_external_journal_filesystem(image: &mut [u8], uuid: [u8; 16]) {
    put_u32(image, 1024 + 96, INCOMPAT_MODERN | INCOMPAT_JOURNAL_DEV);
    image[1024 + 208..1024 + 224].copy_from_slice(&uuid);
    put_u32(image, 1024 + 224, 0);
}

pub(super) fn write_fragmented_journal_inode(image: &mut [u8]) {
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

pub(super) fn move_journal_block(image: &mut [u8], logical: u32, physical_block: u32) {
    let source = journal_log_offset(logical);
    let target = block_offset(physical_block);
    let block = image[source..source + BLOCK_SIZE].to_vec();
    image[target..target + BLOCK_SIZE].copy_from_slice(&block);
}

pub(super) fn write_symlink_inode(image: &mut [u8]) {
    let offset = inode_offset(4);
    put_u16(image, offset, 0xA000 | 0o777);
    put_u32(image, offset + 4, 4);
    image[offset + 40..offset + 44].copy_from_slice(b"file");
}

pub(super) fn write_root_directory(image: &mut [u8]) {
    let base = block_offset(ROOT_DIR_BLOCK);
    write_dirent(image, base, 2, 12, b".", 2);
    write_dirent(image, base + 12, 2, 12, b"..", 2);
    write_dirent(image, base + 24, 3, 16, b"file", 1);
    write_dirent(image, base + 40, 4, 984, b"link", 7);
}

pub(super) fn write_modern_root_directory(image: &mut [u8]) {
    let base = block_offset(MODERN_ROOT_DIR_BLOCK);
    write_dirent(image, base, 2, 12, b".", 2);
    write_dirent(image, base + 12, 2, 12, b"..", 2);
    write_dirent(image, base + 24, 3, 1000, b"file", 1);
}

pub(super) fn make_indexed_root_directory(image: &mut [u8]) {
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
    let checksum = crate::disk_format::dir::DirectoryChecksum::metadata_csum(
        superblock.checksum_seed(),
        inode(2),
        get_u32(image, root_inode + 100),
    );
    let file_name = must(Ext4Name::new(b"file"));
    let entries = vec![RawDirectoryEntry::new(
        inode(3),
        &file_name,
        DirectoryEntryKind::File,
    )];
    let htree = must(crate::disk_format::dir::build_htree_directory(
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

pub(super) fn write_extent_root(
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
pub(super) fn write_two_extent_root(
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

pub(super) fn write_dirent(
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

pub(super) fn inode_offset(inode: u32) -> usize {
    block_offset(INODE_TABLE_BLOCK) + usize::try_from(inode - 1).unwrap_or(usize::MAX) * 128
}

pub(super) fn modern_inode_offset(inode: u32) -> usize {
    block_offset(MODERN_INODE_TABLE_BLOCK)
        + usize::try_from(inode - 1).unwrap_or(usize::MAX) * MODERN_INODE_SIZE
}

pub(super) fn variable_inode_offset(
    inode_table_block: u32,
    inode: u32,
    block_size: usize,
) -> usize {
    variable_block_offset(inode_table_block, block_size)
        + usize::try_from(inode - 1).unwrap_or(usize::MAX) * 128
}

pub(super) fn block_offset(block: u32) -> usize {
    usize::try_from(block).unwrap_or(usize::MAX) * BLOCK_SIZE
}

pub(super) fn variable_block_offset(block: u32, block_size: usize) -> usize {
    usize::try_from(block).unwrap_or(usize::MAX) * block_size
}

pub(super) fn primary_block_group_descriptor_offset(image: &[u8]) -> usize {
    let superblock = must(Superblock::parse(&image[1024..2048]));
    let block_size = usize::try_from(superblock.block_size().bytes()).unwrap_or(usize::MAX);
    if block_size == 1024 {
        variable_block_offset(2, block_size)
    } else {
        variable_block_offset(1, block_size)
    }
}

pub(super) fn refresh_primary_block_group_descriptor_checksum(image: &mut [u8]) {
    let superblock = must(Superblock::parse(&image[1024..2048]));
    let descriptor_size = usize::from(superblock.descriptor_size().as_u16());
    let base = primary_block_group_descriptor_offset(image);
    must(
        crate::disk_format::group::write_block_group_descriptor_checksum(
            &superblock,
            BlockGroupId::from_u32(0),
            &mut image[base..base + descriptor_size],
        ),
    );
}

pub(super) fn refresh_extent_block_checksum(image: &mut [u8], inode: u32, block: u32) {
    let superblock = must(Superblock::parse(&image[1024..2048]));
    let base = block_offset(block);
    put_u32(image, base + BLOCK_SIZE - 4, 0);
    let inode_offset = modern_inode_offset(inode);
    let generation = get_u32(image, inode_offset + 100);
    let mut checksum =
        crate::disk::checksum::crc32c(superblock.checksum_seed().as_u32(), &inode.to_le_bytes());
    checksum = crate::disk::checksum::crc32c(checksum, &generation.to_le_bytes());
    checksum = crate::disk::checksum::crc32c(checksum, &image[base..base + BLOCK_SIZE]);
    put_u32(image, base + BLOCK_SIZE - 4, checksum);
}

pub(super) fn corrupt_primary_block_group_descriptor_checksum(image: &mut [u8]) {
    let base = primary_block_group_descriptor_offset(image);
    let checksum_offset = base + 30;
    put_u16(
        image,
        checksum_offset,
        get_u16(image, checksum_offset) ^ u16::MAX,
    );
}

pub(super) fn set_modern_block_used(image: &mut [u8], block: u32, used: bool) {
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

pub(super) fn set_modern_inode_used(image: &mut [u8], inode: u32, used: bool) {
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

pub(super) fn put_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn put_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn put_be_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

pub(super) fn put_be_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

pub(super) fn get_u16(image: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([image[offset], image[offset + 1]])
}

pub(super) fn get_u32(image: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        image[offset],
        image[offset + 1],
        image[offset + 2],
        image[offset + 3],
    ])
}

pub(super) fn get_be_u32(image: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        image[offset],
        image[offset + 1],
        image[offset + 2],
        image[offset + 3],
    ])
}

#[derive(Debug)]
pub(super) struct FailOneWriteAt<'a> {
    bytes: &'a mut [u8],
    fail_offset: ByteOffset,
    failed: bool,
}

impl<'a> FailOneWriteAt<'a> {
    pub(super) fn new(bytes: &'a mut [u8], fail_offset: ByteOffset) -> Self {
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

pub(super) fn must<T>(result: crate::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected ext4-core error: {error:?}"),
    }
}
