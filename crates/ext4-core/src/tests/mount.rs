use super::*;

#[derive(Debug)]
struct ObservedFlushDevice<'a> {
    bytes: &'a mut [u8],
    flushes: &'a core::sync::atomic::AtomicU32,
    fail_next_flush: &'a core::sync::atomic::AtomicBool,
}

impl<'a> ObservedFlushDevice<'a> {
    const fn new(
        bytes: &'a mut [u8],
        flushes: &'a core::sync::atomic::AtomicU32,
        fail_next_flush: &'a core::sync::atomic::AtomicBool,
    ) -> Self {
        Self {
            bytes,
            flushes,
            fail_next_flush,
        }
    }
}

impl BlockSource for ObservedFlushDevice<'_> {
    fn len(&self) -> DeviceLength {
        DeviceLength::from_bytes(u64::try_from(self.bytes.len()).unwrap_or(u64::MAX))
    }

    async fn read_exact_at(&mut self, offset: ByteOffset, out: &mut [u8]) -> crate::Result<()> {
        let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
        let end = start.checked_add(out.len()).ok_or(Error::DeviceRange)?;
        let source = self.bytes.get(start..end).ok_or(Error::DeviceRange)?;
        out.copy_from_slice(source);
        Ok(())
    }
}

impl BlockStorage for ObservedFlushDevice<'_> {
    async fn write_exact_at(&mut self, offset: ByteOffset, bytes: &[u8]) -> crate::Result<()> {
        let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
        let end = start.checked_add(bytes.len()).ok_or(Error::DeviceRange)?;
        let target = self.bytes.get_mut(start..end).ok_or(Error::DeviceRange)?;
        target.copy_from_slice(bytes);
        Ok(())
    }

    async fn flush(&mut self) -> crate::Result<()> {
        self.flushes
            .try_update(
                core::sync::atomic::Ordering::Relaxed,
                core::sync::atomic::Ordering::Relaxed,
                |value| value.checked_add(1),
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
        if self
            .fail_next_flush
            .swap(false, core::sync::atomic::Ordering::Relaxed)
        {
            return Err(Error::DeviceIo);
        }
        Ok(())
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn clean_superblock_mounts() {
    let image = fixture_image();
    let device = MemoryBlockSource::new(&image);
    let volume = must_run(ReadOnlyVolume::mount(device, test_mount_context()));
    let superblock = must(Superblock::parse(&image[1024..2048]));

    assert_eq!(volume.geometry().block_size().bytes(), 1024);
    assert_eq!(superblock.inode_count().as_u32(), 16);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn journaled_volume_flush_reaches_filesystem_device() {
    let mut image = modern_fixture_image();
    let flushes = core::sync::atomic::AtomicU32::new(0);
    let fail_next_flush = core::sync::atomic::AtomicBool::new(false);
    let device = ObservedFlushDevice::new(&mut image, &flushes, &fail_next_flush);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let before = flushes.load(core::sync::atomic::Ordering::Relaxed);

    assert_eq!(run(volume.flush()), Ok(()));
    let expected = before.checked_add(1);
    assert!(expected.is_some());
    if let Some(expected) = expected {
        assert_eq!(
            flushes.load(core::sync::atomic::Ordering::Relaxed),
            expected
        );
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn journaled_volume_flush_returns_device_error() {
    let mut image = modern_fixture_image();
    let flushes = core::sync::atomic::AtomicU32::new(0);
    let fail_next_flush = core::sync::atomic::AtomicBool::new(false);
    let device = ObservedFlushDevice::new(&mut image, &flushes, &fail_next_flush);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let before = flushes.load(core::sync::atomic::Ordering::Relaxed);
    fail_next_flush.store(true, core::sync::atomic::Ordering::Relaxed);

    assert_eq!(run(volume.flush()), Err(Error::DeviceIo));
    let expected = before.checked_add(1);
    assert!(expected.is_some());
    if let Some(expected) = expected {
        assert_eq!(
            flushes.load(core::sync::atomic::Ordering::Relaxed),
            expected
        );
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn invalid_magic_is_rejected() {
    let mut image = fixture_image();
    put_u16(&mut image, 1024 + 56, 0);
    let result = Superblock::parse(&image[1024..2048]);

    assert_eq!(result, Err(Error::InvalidMagic));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn unsupported_incompat_feature_is_rejected() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 96, 0x0010 | 0x0040);
    let result = run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));

    assert!(matches!(result, Err(Error::UnsupportedIncompatFeature)));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn inode_zero_is_not_constructible() {
    assert_eq!(InodeId::try_from(0), Err(Error::InvalidInode));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn file_offset_addition_rejects_overflow() {
    let result = FileOffset::from_bytes(u64::MAX).checked_add_len(1);

    assert_eq!(result, Err(Error::ArithmeticOverflow));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn crc32c_known_vector_matches_castagnoli() {
    assert_eq!(crate::disk::checksum::crc32c(0, b"123456789"), 0xE306_9283);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn metadata_checksum_mismatch_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u32(&mut image, 1024 + 1020, 1);
    let result = Superblock::parse(&image[1024..2048]);

    assert!(matches!(result, Err(Error::ChecksumMismatch)));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn larger_block_sizes_mount_and_read_file() {
    for block_size in [8192_usize, 16_384, 65_536] {
        let image = variable_block_fixture_image(block_size);
        let mut volume = must_run(ReadOnlyVolume::mount(
            MemoryBlockSource::new(&image),
            test_mount_context(),
        ));
        let mut output = [0_u8; 5];
        let read = read_file(&mut volume, 3, 0, &mut output);

        assert_eq!(
            volume.geometry().block_size().bytes(),
            u32::try_from(block_size).unwrap_or(u32::MAX)
        );
        assert_eq!(read, 5);
        assert_eq!(&output, b"hello");
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn block_count_uses_64bit_superblock_high_field() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u32(&mut image, 1024 + 4, 1);
    put_u32(&mut image, 1024 + 336, 1);
    let superblock = must(Superblock::parse(&image[1024..2048]));

    assert_eq!(superblock.block_count().as_u64(), 0x1_0000_0001);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn metadata_csum_seed_is_accepted_with_metadata_csum() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u32(&mut image, 1024 + 96, INCOMPAT_MODERN | INCOMPAT_CSUM_SEED);
    put_u32(&mut image, 1024 + 624, 0x1234_5678);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    let superblock = must(Superblock::parse(&image[1024..2048]));
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));

    assert_eq!(superblock.checksum_seed().as_u32(), 0x1234_5678);
    assert_eq!(read_directory(&mut volume, InodeId::ROOT).len(), 3);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn write_mount_accepts_metadata_csum_seed() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    put_u32(&mut image, 1024 + 96, INCOMPAT_MODERN | INCOMPAT_CSUM_SEED);
    put_u32(&mut image, 1024 + 624, 0x1234_5678);
    refresh_primary_block_group_descriptor_checksum(&mut image);
    let superblock = must(Superblock::parse_read_write(&image[1024..2048]));
    let device = MemoryBlockStorage::new(&mut image);
    let _volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    assert_eq!(superblock.checksum_seed().as_u32(), 0x1234_5678);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn metadata_csum_seed_without_metadata_csum_is_rejected() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 96, 0x0002 | 0x0040 | INCOMPAT_CSUM_SEED);
    let result = Superblock::parse(&image[1024..2048]);

    assert!(matches!(result, Err(Error::UnsupportedIncompatFeature)));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn read_only_mount_accepts_quota_and_clean_orphan_file() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 92, COMPAT_ORPHAN_FILE);
    put_u32(&mut image, 1024 + 100, 0x0001 | 0x0002 | RO_COMPAT_QUOTA);
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));

    assert_eq!(read_directory(&mut volume, InodeId::ROOT).len(), 4);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
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

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn write_mount_accepts_modern_baseline() {
    let mut image = modern_fixture_image();
    let superblock = must(Superblock::parse_read_write(&image[1024..2048]));
    let device = MemoryBlockStorage::new(&mut image);
    let _volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    assert_eq!(superblock.journal_mode(), JournalMode::Internal(inode(8)));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
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
