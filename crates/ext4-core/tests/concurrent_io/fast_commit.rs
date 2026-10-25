//! Independent delta-log records driven through production mount and storage continuations.
use super::*;

/// The independently generated fixture has a 4 KiB external journal superblock at block one.
const JOURNAL_SUPER: usize = 4096;

/// Writes explicit vector bytes without using a production encoder.
/// # Errors
/// Returns an overflowing or truncated fixture field.
fn put(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<()> {
    let end = offset.checked_add(value.len()).ok_or(Error::DeviceRange)?;
    for (to, from) in bytes
        .get_mut(offset..end)
        .ok_or(Error::DeviceRange)?
        .iter_mut()
        .zip(value)
    {
        *to = *from;
    }
    Ok(())
}
/// Reads a big-endian journal field independently of the production parser.
/// # Errors
/// Returns a malformed fixture coordinate or scalar.
fn be32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::DeviceRange)?;
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..end)
            .ok_or(Error::DeviceRange)?
            .try_into()
            .map_err(|_| Error::DeviceRange)?,
    ))
}
/// Encodes one complete TLV with its independently chosen wire opcode and field lengths.
/// # Errors
/// Returns field-width overflow or a record crossing this vector's block.
fn record(block: &mut [u8], at: &mut usize, tag: u16, value: &[u8]) -> Result<()> {
    put(block, *at, &tag.to_le_bytes())?;
    put(
        block,
        at.checked_add(2).ok_or(Error::DeviceRange)?,
        &u16::try_from(value.len())
            .map_err(|_| Error::DeviceRange)?
            .to_le_bytes(),
    )?;
    let start = at.checked_add(4).ok_or(Error::DeviceRange)?;
    put(block, start, value)?;
    *at = start.checked_add(value.len()).ok_or(Error::DeviceRange)?;
    Ok(())
}

/// Selects only the independent JBD2 reserved-area profile, retaining ext4's declared feature masks.
/// The inode root in INODE is deliberately unrelated; ADD owns the replacement mapping.
/// # Errors
/// Returns fixture geometry, checksum, TLV or data-range construction failure.
fn inject_range(fixture: &mut Fixture, physical: u32) -> Result<u32> {
    let inode = NodeId::File(fixture.a).file_index();
    let offset = fixture_inode_offset(&fixture.disk, NodeId::File(fixture.a))?;
    let end = offset.checked_add(256).ok_or(Error::DeviceRange)?;
    let mut raw = fixture
        .disk
        .filesystem
        .get(offset..end)
        .ok_or(Error::DeviceRange)?
        .to_vec();
    let prior = fixture_u32(&raw, 60)?;
    put(&mut raw, 0, &(0x8000_u16 | 0o660).to_le_bytes())?;
    put(&mut raw, 4, &8_u32.to_le_bytes())?;
    put(&mut raw, 108, &0_u32.to_le_bytes())?;
    raw.get_mut(28..32).ok_or(Error::DeviceRange)?.fill(0xff);
    raw.get_mut(40..100).ok_or(Error::DeviceRange)?.fill(0xa5);
    raw.get_mut(116..118).ok_or(Error::DeviceRange)?.fill(0xff);
    let extra = usize::from(u16::from_le_bytes(
        raw.get(128..130)
            .ok_or(Error::DeviceRange)?
            .try_into()
            .map_err(|_| Error::DeviceRange)?,
    ));
    let prefix = 128_usize.checked_add(extra).ok_or(Error::DeviceRange)?;
    let journal = &mut fixture.disk.journal;
    let raw_sb = journal
        .get_mut(JOURNAL_SUPER..JOURNAL_SUPER + 4096)
        .ok_or(Error::DeviceRange)?;
    let tid = be32(raw_sb, 0x18)?;
    let end = be32(raw_sb, 0x10)?;
    let flags = be32(raw_sb, 0x28)? | 0x20;
    put(raw_sb, 0x28, &flags.to_be_bytes())?;
    put(raw_sb, 0x54, &16_u32.to_be_bytes())?;
    put(raw_sb, 0xfc, &[0; 4])?;
    let crc = fixture_crc32c(u32::MAX, raw_sb.get(..1024).ok_or(Error::DeviceRange)?);
    put(raw_sb, 0xfc, &crc.to_be_bytes())?;
    let first = usize::try_from(end.checked_sub(15).ok_or(Error::DeviceRange)?)
        .map_err(|_| Error::DeviceRange)?
        .checked_mul(4096)
        .ok_or(Error::DeviceRange)?;
    journal.get_mut(first..).ok_or(Error::DeviceRange)?.fill(0);
    let mut block = [0; 4096];
    let mut at = 0_usize;
    let mut head = [0; 8];
    put(&mut head, 4, &tid.to_le_bytes())?;
    record(&mut block, &mut at, 9, &head)?;
    let mut add = [0; 16];
    put(&mut add, 0, &inode.to_le_bytes())?;
    put(&mut add, 8, &1_u16.to_le_bytes())?;
    put(&mut add, 12, &physical.to_le_bytes())?;
    record(&mut block, &mut at, 1, &add)?;
    // A deletion spanning sparse logical space must visit mapped extents, not every logical block.
    let mut del = [0; 12];
    put(&mut del, 0, &inode.to_le_bytes())?;
    put(&mut del, 4, &1_u32.to_le_bytes())?;
    put(&mut del, 8, &u32::MAX.to_le_bytes())?;
    record(&mut block, &mut at, 2, &del)?;
    let mut image = Vec::new();
    image
        .try_reserve_exact(prefix.checked_add(4).ok_or(Error::DeviceRange)?)
        .map_err(|_| Error::OutOfMemory)?;
    image.extend_from_slice(&inode.to_le_bytes());
    image.extend_from_slice(raw.get(..prefix).ok_or(Error::DeviceRange)?);
    record(&mut block, &mut at, 6, &image)?;
    put(&mut block, at, &8_u16.to_le_bytes())?;
    let length = 4096_usize
        .checked_sub(at)
        .and_then(|size| size.checked_sub(4))
        .ok_or(Error::DeviceRange)?;
    put(
        &mut block,
        at.checked_add(2).ok_or(Error::DeviceRange)?,
        &u16::try_from(length)
            .map_err(|_| Error::DeviceRange)?
            .to_le_bytes(),
    )?;
    put(
        &mut block,
        at.checked_add(4).ok_or(Error::DeviceRange)?,
        &tid.to_le_bytes(),
    )?;
    let crc_end = at.checked_add(8).ok_or(Error::DeviceRange)?;
    let crc = fixture_crc32c(0, block.get(..crc_end).ok_or(Error::DeviceRange)?);
    put(&mut block, crc_end, &crc.to_le_bytes())?;
    put(journal, first, &block)?;
    Ok(prior)
}

/// Reads the independently encoded group-zero block bitmap.
/// # Errors
/// Returns malformed bitmap geometry or a truncated byte.
fn allocated(disk: &Disk, block: u32) -> Result<bool> {
    let bitmap = usize::try_from(fixture_u32(&disk.filesystem, 4096)?)
        .map_err(|_| Error::DeviceRange)?
        .checked_mul(4096)
        .ok_or(Error::DeviceRange)?;
    let byte = bitmap
        .checked_add(usize::try_from(block / 8).map_err(|_| Error::DeviceRange)?)
        .ok_or(Error::DeviceRange)?;
    Ok(*disk.filesystem.get(byte).ok_or(Error::DeviceRange)? & (1_u8 << (block % 8)) != 0)
}

/// # Errors
/// Propagates fixture preparation, mount and recovered file-read failures.
/// # Panics
/// Fails if read-only replay touches either backing device or fails to expose the final mapping.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare recovered data and unchanged physical device images"
)]
fn read_only_mapping_replay_has_zero_backing_effects() -> Result<()> {
    let mut fixture = Fixture::new()?;
    assert!(!allocated(&fixture.disk, 1000)?);
    put(&mut fixture.disk.filesystem, 1000 * 4096, b"replayed")?;
    inject_range(&mut fixture, 1000)?;
    let filesystem = fixture.disk.filesystem.clone();
    let journal = fixture.disk.journal.clone();
    fixture.disk.storage_effects = 0;
    let (profile, epoch, coordinator, _lease) = fixture
        .disk
        .mount(MountAccess::ReadOnly {
            recovery_memory: RecoveryMemoryLimit::DEFAULT,
        })?
        .into_parts();
    fixture.cache = MetadataCache::try_new(&epoch)?;
    fixture.profile = profile;
    fixture.epoch = epoch;
    fixture.coordinator = coordinator;
    let file = fixture.a;
    let mut bytes = [0; 8];
    assert_eq!(
        fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?,
        ReadBytes::from_usize(8)
    );
    assert_eq!(&bytes, b"replayed");
    assert_eq!(
        fixture.read(|pass| Ok(pass.load_file(file)?.security().permissions().as_u16()))?,
        0o660
    );
    assert_eq!(fixture.disk.storage_effects, 0);
    assert_eq!(fixture.disk.filesystem, filesystem);
    assert_eq!(fixture.disk.journal, journal);
    Ok(())
}

/// # Errors
/// Propagates fixture preparation, independent encoding or mount failure.
/// # Panics
/// Fails if an interrupted home checkpoint cannot roll forward from the replacement full commit.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe failure before a checkpoint finishes and recovered allocation bits"
)]
fn interrupted_mapping_checkpoint_replays_the_complete_replacement() -> Result<()> {
    let mut fixture = Fixture::new()?;
    assert!(!allocated(&fixture.disk, 1000)?);
    put(&mut fixture.disk.filesystem, 1000 * 4096, b"replayed")?;
    let prior = inject_range(&mut fixture, 1000)?;
    let mut homes = 0_usize;
    let failed = fixture
        .disk
        .mount_observing(MountAccess::ReadWrite, |_disk, boundary, _time| {
            if matches!(
                boundary,
                MountBoundary::Lower(StorageRequest::Write {
                    target: StorageTarget::Filesystem,
                    ..
                })
            ) {
                homes = homes.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                if homes == 2 {
                    return Err(Error::DeviceIo);
                }
            }
            Ok(())
        });
    assert!(matches!(failed, Err(Error::DeviceIo)));
    assert_eq!(homes, 2);
    fixture.remount()?;
    let file = fixture.a;
    let mut bytes = [0; 8];
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?;
    assert_eq!(&bytes, b"replayed");
    assert!(allocated(&fixture.disk, 1000)?);
    assert!(!allocated(&fixture.disk, prior)?);
    let free = fixture_u32(&fixture.disk.filesystem, 1036)?;
    inject_range(&mut fixture, 1000)?;
    fixture.remount()?;
    assert_eq!(fixture_u32(&fixture.disk.filesystem, 1036)?, free);
    assert!(allocated(&fixture.disk, 1000)?);
    Ok(())
}

/// # Errors
/// Propagates fixture geometry, inode lookup and independent record construction failures.
/// # Panics
/// Fails if a second inode can steal a physical block or candidate rejection follows any write.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check the full prospective ownership graph before persistence"
)]
fn conflicting_mapping_is_rejected_before_any_recovery_write() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let other = fixture_inode_offset(&fixture.disk, NodeId::File(fixture.b))?;
    let physical = fixture_u32(
        &fixture.disk.filesystem,
        other.checked_add(60).ok_or(Error::DeviceRange)?,
    )?;
    inject_range(&mut fixture, physical)?;
    fixture.disk.storage_effects = 0;
    assert!(matches!(
        fixture.disk.mount(MountAccess::ReadWrite),
        Err(Error::ClusterReferenceConflict)
    ));
    assert_eq!(fixture.disk.storage_effects, 0);
    Ok(())
}
