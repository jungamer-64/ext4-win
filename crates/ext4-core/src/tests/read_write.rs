use super::*;
use alloc::rc::Rc;
use core::{cell::Cell, num::NonZeroU64};

/// Read-only test source retaining maximum backing-read size outside the mounted volume.
#[derive(Clone, Debug)]
struct ObservedBlockSource<'a> {
    bytes: &'a [u8],
    maximum_read: Rc<Cell<usize>>,
}

impl BlockSource for ObservedBlockSource<'_> {
    fn len(&self) -> DeviceLength {
        DeviceLength::from_bytes(u64::try_from(self.bytes.len()).unwrap_or(u64::MAX))
    }

    async fn read_exact_at(&mut self, offset: ByteOffset, out: &mut [u8]) -> crate::Result<()> {
        self.maximum_read
            .set(self.maximum_read.get().max(out.len()));
        let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
        let end = start.checked_add(out.len()).ok_or(Error::DeviceRange)?;
        let source = self.bytes.get(start..end).ok_or(Error::DeviceRange)?;
        out.copy_from_slice(source);
        Ok(())
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn sparse_file_reads_zeroes_for_holes() {
    let image = fixture_image();
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let mut output = vec![0xAA; 1030];
    let read = read_file(&mut volume, 3, 0, &mut output);

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
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let mut output = [0xAA; 5];
    let read = read_file(&mut volume, 3, 1024, &mut output);

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
    let mut device = MemoryBlockSource::new(&[]);
    let tree = must_run(ExtentTree::load_inode_tree(
        &root,
        must(BlockSize::from_superblock_log(0)),
        &mut device,
        ExtentTreeContext::none(),
    ));

    assert_eq!(
        tree.map_logical(LogicalBlock::from_u32(0)),
        BlockMapping::Hole
    );
}

/// # Panics
///
/// Panics when typed extent runs do not preserve hole, physical, and unwritten boundaries.
#[test]
fn extent_run_mapping_stops_at_typed_boundaries() {
    let mut raw = [0_u8; 60];
    write_two_extent_root(&mut raw, 0, 2, 3, 10, 7, 2, 20);
    put_u16(&mut raw, 28, 0x8002);
    let root = InodeExtentRoot::from_bytes(raw);
    let mut device = MemoryBlockSource::new(&[]);
    let tree = must_run(ExtentTree::load_inode_tree(
        &root,
        must(BlockSize::from_superblock_log(0)),
        &mut device,
        ExtentTreeContext::none(),
    ));
    let maximum = NonZeroU64::new(10).unwrap_or(NonZeroU64::MIN);

    assert_eq!(
        must(tree.map_run(LogicalBlock::from_u32(0), maximum)),
        crate::disk_format::extent::ExtentBlockRun::Hole {
            blocks: NonZeroU64::new(2).unwrap_or(NonZeroU64::MIN),
        }
    );
    assert_eq!(
        must(tree.map_run(LogicalBlock::from_u32(3), maximum)),
        crate::disk_format::extent::ExtentBlockRun::Initialized {
            physical_start: BlockAddress::new(11),
            blocks: NonZeroU64::new(2).unwrap_or(NonZeroU64::MIN),
        }
    );
    assert_eq!(
        must(tree.map_run(LogicalBlock::from_u32(5), maximum)),
        crate::disk_format::extent::ExtentBlockRun::Hole {
            blocks: NonZeroU64::new(2).unwrap_or(NonZeroU64::MIN),
        }
    );
    assert_eq!(
        must(tree.map_run(LogicalBlock::from_u32(7), maximum)),
        crate::disk_format::extent::ExtentBlockRun::Uninitialized {
            blocks: NonZeroU64::new(2).unwrap_or(NonZeroU64::MIN),
        }
    );
}

/// # Panics
///
/// Panics when a multi-megabyte request reaches the backing source in a window over 64 KiB.
#[test]
fn large_plain_read_bounds_each_backing_io_window() {
    const DATA_BLOCKS: usize = 4096;
    const DATA_START_BLOCK: u32 = 64;
    let file_bytes = DATA_BLOCKS * BLOCK_SIZE;
    let image_blocks = usize::try_from(DATA_START_BLOCK).unwrap_or(usize::MAX) + DATA_BLOCKS;
    let mut image = modern_fixture_image();
    image.resize(image_blocks * BLOCK_SIZE, 0);
    put_u32(
        &mut image,
        1024 + 4,
        u32::try_from(image_blocks).unwrap_or(u32::MAX),
    );
    let inode = modern_inode_offset(3);
    put_u32(
        &mut image,
        inode + 4,
        u32::try_from(file_bytes).unwrap_or(u32::MAX),
    );
    put_u32(
        &mut image,
        inode + 28,
        u32::try_from(file_bytes / 512).unwrap_or(u32::MAX),
    );
    write_extent_root(
        &mut image,
        inode + 40,
        0,
        u16::try_from(DATA_BLOCKS).unwrap_or(u16::MAX),
        DATA_START_BLOCK,
    );
    let data_start = block_offset(DATA_START_BLOCK);
    for (index, byte) in image[data_start..data_start + file_bytes]
        .iter_mut()
        .enumerate()
    {
        *byte = u8::try_from(index % 251).unwrap_or(0);
    }

    let maximum_read = Rc::new(Cell::new(0));
    let source = ObservedBlockSource {
        bytes: &image,
        maximum_read: Rc::clone(&maximum_read),
    };
    let mut volume = must_run(ReadOnlyVolume::mount(source, test_mount_context()));
    let file = file_node(&mut volume, 3);
    maximum_read.set(0);
    let mut output = vec![0_u8; file_bytes];

    assert_eq!(
        must_run(volume.read_file(&file, FileOffset::ZERO, &mut output)).as_usize(),
        file_bytes
    );
    assert_eq!(maximum_read.get(), 64 * 1024);
    assert_eq!(&output[..251], &image[data_start..data_start + 251]);
    assert_eq!(
        &output[file_bytes - 251..],
        &image[data_start + file_bytes - 251..data_start + file_bytes]
    );
}

/// # Panics
///
/// Panics when the extent domain rejects the final logical block or accepts blocks beyond it.
#[test]
fn extent_logical_boundary_allows_only_one_final_block() {
    let final_extent = Extent::initialized(
        LogicalBlock::from_u32(u32::MAX),
        must(ExtentLength::new(1)),
        BlockAddress::new(1),
    );
    let tree = MutableExtentTree::from_extents(vec![final_extent]);
    assert!(tree.is_ok());
    let Ok(tree) = tree else {
        return;
    };
    assert_eq!(tree.extents()[0].end_logical(), u64::from(u32::MAX) + 1);

    assert_eq!(
        MutableExtentTree::from_extents(vec![Extent::initialized(
            LogicalBlock::from_u32(u32::MAX),
            must(ExtentLength::new(2)),
            BlockAddress::new(1),
        )]),
        Err(Error::InvalidExtentTree)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn sparse_hole_write_allocates_block() {
    let mut image = modern_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    let file_id = file_node_id(&mut volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    write_file(&mut transaction, file_id, 1024, b"hole");
    must_run(transaction.commit());

    let mut output = [0_u8; 4];
    let read = read_file(&mut volume, 3, 1024, &mut output);
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
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
    let name = must(Ext4Name::new(b"written"));
    let file = must_run(transaction.create_file(root, &name, test_file_metadata()));
    must_run(transaction.write_file_range(file, FileOffset::ZERO, b"created"));
    must_run(transaction.commit());

    assert_eq!(
        lookup_ext4_inode(&mut volume, InodeId::ROOT, b"written"),
        Some(inode(11))
    );
    let file = file_node(&mut volume, 11);
    assert_eq!(file.size().bytes(), 7);
    let mut output = [0_u8; 7];
    assert_eq!(read_file(&mut volume, 11, 0, &mut output), 7);
    assert_eq!(&output, b"created");
}

/// # Panics
///
/// Panics when adjacent write windows in one transaction fail to compose across a shared block.
#[test]
fn adjacent_write_windows_compose_inside_one_transaction() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    let prefix = vec![0x41_u8; BLOCK_SIZE + 17];
    let suffix = b"tail";
    let gap = 7_usize;
    let suffix_offset = gap.saturating_add(prefix.len());
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
    let name = must(Ext4Name::new(b"windowed"));
    let file = must_run(transaction.create_file(root, &name, test_file_metadata()));
    must_run(transaction.write_file_range(
        file,
        FileOffset::from_bytes(u64::try_from(gap).unwrap_or(u64::MAX)),
        &prefix,
    ));
    must_run(transaction.write_file_range(
        file,
        FileOffset::from_bytes(u64::try_from(suffix_offset).unwrap_or(u64::MAX)),
        suffix,
    ));
    must_run(transaction.commit());

    let output_length = suffix_offset.saturating_add(suffix.len());
    let mut output = vec![0xAA_u8; output_length];
    assert_eq!(read_file(&mut volume, 11, 0, &mut output), output_length);
    assert_eq!(&output[..gap], &[0_u8; 7]);
    assert_eq!(&output[gap..suffix_offset], prefix.as_slice());
    assert_eq!(&output[suffix_offset..], suffix);
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
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    let file_id = file_node_id(&mut volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    write_file(&mut transaction, file_id, 9, b"tail");
    must_run(transaction.commit());

    let file = file_node(&mut volume, 3);
    assert_eq!(file.size().bytes(), 13);
    let mut output = [0xAA; 13];
    assert_eq!(read_file(&mut volume, 3, 0, &mut output), 13);
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

        let mut output = [0_u8; 1];
        assert_eq!(read_file(&mut volume, 3, 0, &mut output), 1);
        assert_eq!(output, [b'x']);
        assert_eq!(
            read_file(
                &mut volume,
                3,
                u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX),
                &mut output
            ),
            1
        );
        assert_eq!(output, [0]);
        assert_eq!(
            file_node(&mut volume, 3).allocation_size().bytes(),
            6 * BLOCK_SIZE_U64
        );
    }

    let inode_base = modern_inode_offset(3);
    assert_eq!(get_u16(&image, inode_base + 46), 1);
    let extent_block = get_u32(&image, inode_base + 56);
    assert_ne!(extent_block, 0);
    assert_eq!(get_u16(&image, block_offset(extent_block)), 0xF30A);

    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let mut output = [0_u8; 1];
    assert_eq!(
        read_file(
            &mut volume,
            3,
            8_u64.saturating_mul(u64::try_from(BLOCK_SIZE).unwrap_or(u64::MAX)),
            &mut output
        ),
        1
    );
    assert_eq!(output, [b'x']);
    assert_eq!(
        file_node(&mut volume, 3).allocation_size().bytes(),
        6 * BLOCK_SIZE_U64
    );
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
    let mut device = MemoryBlockSource::new(&image);
    let loaded = must_run(MutableExtentTree::load_inode_tree(
        &InodeExtentRoot::from_bytes(*serialized.inode_root()),
        block_size,
        &mut device,
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
    }

    let extent_block = get_u32(&image, modern_inode_offset(3) + 56);
    let checksum_offset = block_offset(extent_block) + BLOCK_SIZE - 4;
    image[checksum_offset] ^= 0x80;

    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let file = file_node(&mut volume, 3);
    let mut output = [0_u8; 1];
    let result = run(volume.read_file(&file, FileOffset::ZERO, &mut output));

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
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let file_id = file_node_id(&mut volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    let file = transaction_file(&mut transaction, file_id);
    let result = run(transaction.write_file_range(file, FileOffset::ZERO, b"x"));

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
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    let file = file_node(&mut volume, 3);
    assert_eq!(file.protection(), InodeProtection::EncryptedVerity);
    let file_id = file.id();

    let mut transaction = volume.begin_transaction(NOW);
    let file = transaction_file(&mut transaction, file_id);
    let result = run(transaction.write_file_range(file, FileOffset::ZERO, b"x"));

    assert_eq!(result, Err(Error::MissingEncryptionKey));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn extend_file_creates_sparse_range() {
    let mut image = modern_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    let file_id = file_node_id(&mut volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    extend_file(&mut transaction, file_id, 3072);
    must_run(transaction.commit());

    let file = file_node(&mut volume, 3);
    let mut output = [0xAA; 4];
    let read = read_file(&mut volume, 3, 2048, &mut output);
    assert_eq!(file.size().bytes(), 3072);
    assert_eq!(read, 4);
    assert_eq!(output, [0, 0, 0, 0]);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn large_file_write_round_trips_size_and_sparse_allocation() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let write_offset = (1_u64 << 32) + 37;

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&mut volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        write_file(&mut transaction, file_id, write_offset, b"large");
        must_run(transaction.commit());

        let file = file_node(&mut volume, 3);
        assert_eq!(file.size().bytes(), write_offset + 5);
        assert_eq!(file.allocation_size().bytes(), 2 * BLOCK_SIZE_U64);
        let mut output = [0xAA; 7];
        assert_eq!(
            read_file(&mut volume, 3, write_offset - 2, &mut output),
            output.len()
        );
        assert_eq!(&output, b"\0\0large");
    }

    let inode_base = modern_inode_offset(3);
    assert_eq!(get_u32(&image, inode_base + 4), 42);
    assert_eq!(get_u32(&image, inode_base + 108), 1);

    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let file = file_node(&mut volume, 3);
    assert_eq!(file.size().bytes(), write_offset + 5);
    assert_eq!(file.allocation_size().bytes(), 2 * BLOCK_SIZE_U64);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn final_logical_block_accepts_exact_maximum_eof() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let maximum_size = (u64::from(u32::MAX) + 1) * BLOCK_SIZE_U64;

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&mut volume, 3);

        let mut extension = volume.begin_transaction(NOW);
        extend_file(&mut extension, file_id, maximum_size);
        must_run(extension.commit());
        assert_eq!(file_node(&mut volume, 3).size().bytes(), maximum_size);

        let mut rejected = volume.begin_transaction(NOW);
        let file = transaction_file(&mut rejected, file_id);
        assert_eq!(
            run(rejected.extend_file(file, FileSize::from_bytes(maximum_size + 1))),
            Err(Error::InvalidWriteRange)
        );
        drop(rejected);
        assert_eq!(file_node(&mut volume, 3).size().bytes(), maximum_size);

        let mut last_block_write = volume.begin_transaction(NOW);
        write_file(&mut last_block_write, file_id, maximum_size - 1, b"z");
        must_run(last_block_write.commit());
        let file = file_node(&mut volume, 3);
        assert_eq!(file.size().bytes(), maximum_size);
        assert_eq!(file.allocation_size().bytes(), 2 * BLOCK_SIZE_U64);
        let mut output = [0xAA; 2];
        assert_eq!(
            read_file(&mut volume, 3, maximum_size - 2, &mut output),
            output.len()
        );
        assert_eq!(output, [0, b'z']);

        let mut truncate = volume.begin_transaction(NOW);
        truncate_file(&mut truncate, file_id, 5);
        must_run(truncate.commit());
        let file = file_node(&mut volume, 3);
        assert_eq!(file.size().bytes(), 5);
        assert_eq!(file.allocation_size().bytes(), BLOCK_SIZE_U64);
    }

    let inode_base = modern_inode_offset(3);
    assert_eq!(get_u32(&image, inode_base + 4), 5);
    assert_eq!(get_u32(&image, inode_base + 108), 0);
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let file = file_node(&mut volume, 3);
    assert_eq!(file.size().bytes(), 5);
    assert_eq!(file.allocation_size().bytes(), BLOCK_SIZE_U64);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn minimal_profile_rejects_file_size_beyond_large_file_boundary() {
    let mut image = minimal_write_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let file_id = file_node_id(&mut volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    let file = transaction_file(&mut transaction, file_id);
    let result = run(transaction.extend_file(file, FileSize::from_bytes(0x8000_0000)));

    assert_eq!(result, Err(Error::UnsupportedInodeMutation));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn minimal_profile_rejects_extending_write_beyond_large_file_boundary() {
    let mut image = minimal_write_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let file_id = file_node_id(&mut volume, 3);
    let mut transaction = volume.begin_transaction(NOW);
    let file = transaction_file(&mut transaction, file_id);
    let result = run(transaction.write_file_range(file, FileOffset::from_bytes(0x7FFF_FFFF), b"x"));

    assert_eq!(result, Err(Error::UnsupportedInodeMutation));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn truncate_file_releases_blocks() {
    let mut image = modern_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    let file_id = file_node_id(&mut volume, 3);
    let mut write = volume.begin_transaction(NOW);
    write_file(&mut write, file_id, 1024, b"hole");
    must_run(write.commit());
    let mut truncate = volume.begin_transaction(NOW);
    truncate_file(&mut truncate, file_id, 0);
    must_run(truncate.commit());

    let file = file_node(&mut volume, 3);
    assert_eq!(file.size().bytes(), 0);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn transaction_too_large_is_rejected_before_writes() {
    let mut image = modern_fixture_image_with_journal_blocks(3);
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let file_id = file_node_id(&mut volume, 3);
    let mut transaction = volume.begin_transaction(NOW);

    write_file(&mut transaction, file_id, 1024, b"hole");
    let result = run(transaction.commit());

    assert!(matches!(result, Err(Error::TransactionTooLarge)));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn inode_security_is_parsed_from_owner_and_mode() {
    let image = modern_fixture_image();
    let device = MemoryBlockSource::new(&image);
    let mut volume = must_run(ReadOnlyVolume::mount(device, test_mount_context()));

    let file = file_node(&mut volume, 3);
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
    let mut volume = must_run(ReadOnlyVolume::mount(device, test_mount_context()));
    let file = file_node(&mut volume, 3);

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
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let security = Ext4Security::new(
            Ext4Owner::new(
                Ext4Uid::from_u32(0x0002_0001),
                Ext4Gid::from_u32(0x0004_0003),
            ),
            must(Ext4Permissions::new(0o6750)),
        );
        let node_id = node_id(&mut volume, inode(3));

        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&mut transaction, node_id);
        must_run(transaction.set_posix_security(node, security));
        must_run(transaction.commit());

        let file = file_node(&mut volume, 3);
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
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let node_id = node_id(&mut volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&mut transaction, node_id);
        must_run(transaction.set_times(node, times));
        must_run(transaction.commit());
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
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let node_id = node_id(&mut volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&mut transaction, node_id);
        must_run(transaction.set_times(node, times));
        must_run(transaction.commit());
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
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        transaction.set_volume_label(label);
        must_run(transaction.commit());
    }

    assert_eq!(&image[1024 + 120..1024 + 127], b"EXT4WIN");
    assert_eq!(&image[1024 + 127..1024 + 136], &[0_u8; 9]);

    let volume = must_run(ReadOnlyVolume::mount(
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
    let result = run(JournaledVolume::mount(device, test_mount_context()));

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
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let mut output = [0_u8; 5];
    let read = read_file(&mut volume, 3, 0, &mut output);

    assert_eq!(read, 5);
    assert_eq!(&output, b"hello");
}
