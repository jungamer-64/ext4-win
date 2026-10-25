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
    let mut add = [0; 16];
    put(&mut add, 0, &inode.to_le_bytes())?;
    put(&mut add, 8, &1_u16.to_le_bytes())?;
    put(&mut add, 12, &physical.to_le_bytes())?;
    // A deletion spanning sparse logical space must visit mapped extents, not every logical block.
    let mut del = [0; 12];
    put(&mut del, 0, &inode.to_le_bytes())?;
    put(&mut del, 4, &1_u32.to_le_bytes())?;
    put(&mut del, 8, &u32::MAX.to_le_bytes())?;
    let mut image = Vec::new();
    image
        .try_reserve_exact(prefix.checked_add(4).ok_or(Error::DeviceRange)?)
        .map_err(|_| Error::OutOfMemory)?;
    image.extend_from_slice(&inode.to_le_bytes());
    image.extend_from_slice(raw.get(..prefix).ok_or(Error::DeviceRange)?);
    install_delta(fixture, &[(1, &add), (2, &del), (6, &image)])?;
    Ok(prior)
}

/// Installs a complete reserved-area wire vector without a production journal encoder.
/// # Errors
/// Returns fixture geometry, record width or independent checksum construction failure.
fn install_delta(fixture: &mut Fixture, records: &[(u16, &[u8])]) -> Result<()> {
    let journal = &mut fixture.disk.journal;
    let raw_sb = journal
        .get_mut(JOURNAL_SUPER..JOURNAL_SUPER + 4096)
        .ok_or(Error::DeviceRange)?;
    if be32(raw_sb, 0x1c)? != 0 {
        return Err(Error::JournalCorrupt);
    }
    // A clean journal persists the last committed sequence; its running transaction is the successor.
    let tid = be32(raw_sb, 0x18)?.wrapping_add(1);
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
    for (tag, value) in records {
        record(&mut block, &mut at, *tag, value)?;
    }
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
    Ok(())
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

/// Records an existing inode's final count and a name transition as independent TLV postconditions.
/// # Errors
/// Returns inode geometry, metadata width, record bounds or checksum construction failure.
fn inject_binding(
    fixture: &mut Fixture,
    parent: DirectoryNodeId,
    target: FileNodeId,
    from: &[u8],
    to: &[u8],
) -> Result<()> {
    let inode = NodeId::File(target).file_index();
    let offset = fixture_inode_offset(&fixture.disk, NodeId::File(target))?;
    let raw = fixture
        .disk
        .filesystem
        .get(offset..offset.checked_add(256).ok_or(Error::DeviceRange)?)
        .ok_or(Error::DeviceRange)?;
    let prefix = 128_usize
        .checked_add(usize::from(u16::from_le_bytes(
            raw.get(128..130)
                .ok_or(Error::DeviceRange)?
                .try_into()
                .map_err(|_| Error::DeviceRange)?,
        )))
        .ok_or(Error::DeviceRange)?;
    let mut image = inode.to_le_bytes().to_vec();
    image.extend_from_slice(raw.get(..prefix).ok_or(Error::DeviceRange)?);
    let binding = |name: &[u8]| -> Vec<u8> {
        let mut value = NodeId::Directory(parent)
            .file_index()
            .to_le_bytes()
            .to_vec();
        value.extend_from_slice(&inode.to_le_bytes());
        value.extend_from_slice(name);
        value
    };
    let link = binding(to);
    let unlink = binding(from);
    install_delta(fixture, &[(4, &link), (5, &unlink), (6, &image)])
}

/// # Errors
/// Propagates ordinary HTree construction, independent log injection and mount failures.
/// # Panics
/// Fails if namespace replay changes final link counts or routes an indexed entry incorrectly.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare final name bindings and independent inode link-count fields"
)]
fn namespace_postconditions_preserve_final_counts_in_linear_and_indexed_directories() -> Result<()>
{
    for indexed in [false, true] {
        let mut fixture = Fixture::new()?;
        if indexed {
            fixture.mutate(|pass| {
                let root = pass.directory(DirectoryNodeId::ROOT)?;
                for index in 0_u8..24 {
                    let mut name = [b'x'; 240];
                    *name.get_mut(0).ok_or(Error::InvalidName)? =
                        b'a'.checked_add(index).ok_or(Error::InvalidName)?;
                    pass.create_file(
                        root,
                        &Ext4Name::new(&name)?,
                        NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
                    )?;
                }
                Ok(())
            })?;
            let root =
                fixture_inode_offset(&fixture.disk, NodeId::Directory(DirectoryNodeId::ROOT))?;
            assert_ne!(
                fixture_u32(
                    &fixture.disk.filesystem,
                    root.checked_add(32).ok_or(Error::DeviceRange)?
                )? & 0x1000,
                0
            );
        }
        let file = fixture.a;
        for _ in 0..2 {
            inject_binding(
                &mut fixture,
                DirectoryNodeId::ROOT,
                file,
                b"concurrent-a",
                b"delta-renamed",
            )?;
            fixture.remount()?;
            assert!(matches!(
                fixture.read(|pass| pass
                    .lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"concurrent-a")?))?,
                ChildLookup::NotFound
            ));
            assert!(
                matches!(fixture.read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"delta-renamed")?))?, ChildLookup::Found(child) if *child.node() == NodeId::File(file))
            );
            let offset = fixture_inode_offset(&fixture.disk, NodeId::File(file))?
                .checked_add(26)
                .ok_or(Error::DeviceRange)?;
            let end = offset.checked_add(2).ok_or(Error::DeviceRange)?;
            let links = u16::from_le_bytes(
                fixture
                    .disk
                    .filesystem
                    .get(offset..end)
                    .ok_or(Error::DeviceRange)?
                    .try_into()
                    .map_err(|_| Error::DeviceRange)?,
            );
            assert_eq!(links, 1);
        }
    }
    Ok(())
}

/// # Errors
/// Propagates casefold admission, child creation, independent log injection and mount failures.
/// # Panics
/// Fails if logged plaintext names lose their parent's comparison rules or recorded spelling.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare recovered spelling and Unicode lookup equivalence"
)]
fn namespace_postconditions_use_the_admitted_parent_comparison() -> Result<()> {
    let mut fixture = casefold_fixture(0, 1)?;
    let (parent, file) = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let directory = pass.create_directory(
            root,
            &Ext4Name::new(b"delta-folded")?,
            NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
        )?;
        pass.set_directory_casefold(directory, DirectoryCasefold::Enabled)?;
        let file = pass.create_file(
            directory,
            &Ext4Name::new(b"original")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )?;
        Ok((directory.id(), file.id()))
    })?;
    inject_binding(&mut fixture, parent, file, b"original", "Straße".as_bytes())?;
    fixture.remount()?;
    assert!(
        matches!(fixture.read(|pass| pass.lookup_child(parent, &Ext4Name::new(b"STRASSE")?))?, ChildLookup::Found(child) if child.name().bytes() == "Straße".as_bytes() && *child.node() == NodeId::File(file))
    );
    Ok(())
}

/// # Errors
/// Propagates independent records and production mount recovery failures.
/// # Panics
/// Fails if replay removes a replacement binding owned by a different inode.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify conditional unlink through the final namespace"
)]
fn conditional_unlink_preserves_a_different_inode_at_the_same_name() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let b = fixture.b;
    inject_binding(
        &mut fixture,
        DirectoryNodeId::ROOT,
        b,
        b"concurrent-a",
        b"concurrent-b",
    )?;
    fixture.remount()?;
    for (name, target) in [
        (b"concurrent-a".as_slice(), a),
        (b"concurrent-b".as_slice(), b),
    ] {
        assert!(
            matches!(fixture.read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(name)?))?, ChildLookup::Found(child) if *child.node() == NodeId::File(target))
        );
    }
    Ok(())
}

/// Builds a fresh file's recorded identity without copying a production allocation algorithm.
/// # Errors
/// Returns malformed fixture metadata, record layout or independent checksum construction failure.
fn inject_creation(fixture: &mut Fixture, inode: u32) -> Result<()> {
    let offset = fixture_inode_offset(&fixture.disk, NodeId::File(fixture.a))?;
    let mut raw = fixture
        .disk
        .filesystem
        .get(offset..offset.checked_add(256).ok_or(Error::DeviceRange)?)
        .ok_or(Error::DeviceRange)?
        .to_vec();
    put(&mut raw, 0, &(0x8000_u16 | 0o640).to_le_bytes())?;
    put(&mut raw, 4, &8_u32.to_le_bytes())?;
    put(&mut raw, 100, &0x1234_abcd_u32.to_le_bytes())?;
    put(&mut raw, 108, &0_u32.to_le_bytes())?;
    raw.get_mut(40..100).ok_or(Error::DeviceRange)?.fill(0xa5);
    let prefix = 128_usize
        .checked_add(usize::from(u16::from_le_bytes(
            raw.get(128..130)
                .ok_or(Error::DeviceRange)?
                .try_into()
                .map_err(|_| Error::DeviceRange)?,
        )))
        .ok_or(Error::DeviceRange)?;
    let mut image = inode.to_le_bytes().to_vec();
    image.extend_from_slice(raw.get(..prefix).ok_or(Error::DeviceRange)?);
    let mut binding = 2_u32.to_le_bytes().to_vec();
    binding.extend_from_slice(&inode.to_le_bytes());
    binding.extend_from_slice(b"delta-created");
    let mut add = [0; 16];
    put(&mut add, 0, &inode.to_le_bytes())?;
    put(&mut add, 8, &1_u16.to_le_bytes())?;
    put(&mut add, 12, &1000_u32.to_le_bytes())?;
    install_delta(fixture, &[(3, &binding), (1, &add), (6, &image)])
}

/// # Errors
/// Propagates independent create records, production recovery and new file-read failures.
/// # Panics
/// Fails if exact inode allocation, reconstructed generation or repeated accounting differs.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare new namespace identity, data and allocation counters"
)]
fn new_file_creation_claims_the_logged_inode_once() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
    let free_blocks = fixture_u32(&fixture.disk.filesystem, 1036)?;
    assert!(!allocated(&fixture.disk, 1000)?);
    put(&mut fixture.disk.filesystem, 1000 * 4096, b"replayed")?;
    for _ in 0..2 {
        inject_creation(&mut fixture, 64)?;
        fixture.remount()?;
        let ChildLookup::Found(child) = fixture.read(|pass| {
            pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"delta-created")?)
        })?
        else {
            return Err(Error::DirectoryEntryNotFound);
        };
        assert_eq!(child.node().file_index(), 64);
        let NodeId::File(file) = *child.node() else {
            return Err(Error::WrongInodeKind);
        };
        let mut bytes = [0; 8];
        fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?;
        assert_eq!(&bytes, b"replayed");
        assert_eq!(
            fixture.read(|pass| Ok(pass.load_file(file)?.security().permissions().as_u16()))?,
            0o640
        );
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1040)?,
            free_inodes.checked_sub(1).ok_or(Error::InvalidSuperblock)?
        );
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1036)?,
            free_blocks.checked_sub(1).ok_or(Error::InvalidSuperblock)?
        );
        let offset = fixture_inode_offset(&fixture.disk, NodeId::File(file))?;
        assert_eq!(
            fixture_u32(
                &fixture.disk.filesystem,
                offset.checked_add(100).ok_or(Error::DeviceRange)?
            )?,
            0x1234_abcd
        );
    }
    Ok(())
}

/// # Errors
/// Propagates fixture construction, independent records or production admission failures.
/// # Panics
/// Fails if creation replaces root or an occupied generation without any retirement postcondition.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe preserved root and occupied identity ownership before writes"
)]
fn creation_rejects_root_and_unretired_occupied_generations() -> Result<()> {
    for root in [true, false] {
        let mut fixture = Fixture::new()?;
        let id = if root {
            2
        } else {
            NodeId::File(fixture.a).file_index()
        };
        inject_creation(&mut fixture, id)?;
        fixture.disk.storage_effects = 0;
        let expected = if root {
            Error::CannotRemoveRoot
        } else {
            Error::UnsupportedJournal
        };
        assert_eq!(
            fixture.disk.mount(MountAccess::ReadWrite).map(|_| ()),
            Err(expected)
        );
        assert_eq!(fixture.disk.storage_effects, 0);
    }
    Ok(())
}

/// Encodes the fixture's inode prefix independently of production inode serialization.
/// # Errors
/// Returns a malformed table coordinate, metadata width or vector allocation failure.
fn inode_operand(disk: &Disk, node: NodeId) -> Result<Vec<u8>> {
    let offset = fixture_inode_offset(disk, node)?;
    let raw = disk
        .filesystem
        .get(offset..offset.checked_add(256).ok_or(Error::DeviceRange)?)
        .ok_or(Error::DeviceRange)?;
    let prefix = 128_usize
        .checked_add(usize::from(u16::from_le_bytes(
            raw.get(128..130)
                .ok_or(Error::DeviceRange)?
                .try_into()
                .map_err(|_| Error::DeviceRange)?,
        )))
        .ok_or(Error::DeviceRange)?;
    let prefix = if fixture_u32(raw, 32)? & 0x1000_0000 != 0 {
        raw.len()
    } else {
        prefix
    };
    let mut value = node.file_index().to_le_bytes().to_vec();
    value.extend_from_slice(raw.get(..prefix).ok_or(Error::DeviceRange)?);
    Ok(value)
}

/// Encodes one raw namespace component without performing an ordinary mutation.
fn namespace_operand(parent: DirectoryNodeId, child: NodeId, name: &[u8]) -> Vec<u8> {
    let mut value = NodeId::Directory(parent)
        .file_index()
        .to_le_bytes()
        .to_vec();
    value.extend_from_slice(&child.file_index().to_le_bytes());
    value.extend_from_slice(name);
    value
}

/// # Errors
/// Propagates base-directory construction, independent vector construction or mount recovery failure.
/// # Panics
/// Fails if replay reads a source-only layout, omits HTree growth or allocates twice on reapplication.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe rebuilt directory routing, stable allocation and recovered bindings"
)]
fn namespace_replay_derives_growth_before_using_recorded_parent_layout() -> Result<()> {
    let mut fixture = Fixture::new()?;
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        for index in 0_u8..16 {
            let mut name = [b'x'; 240];
            *name.get_mut(0).ok_or(Error::InvalidName)? =
                b'a'.checked_add(index).ok_or(Error::InvalidName)?;
            pass.create_file(
                root,
                &Ext4Name::new(&name)?,
                NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
            )?;
        }
        Ok(())
    })?;
    let root_offset =
        fixture_inode_offset(&fixture.disk, NodeId::Directory(DirectoryNodeId::ROOT))?;
    let flags = fixture_u32(
        &fixture.disk.filesystem,
        root_offset.checked_add(32).ok_or(Error::DeviceRange)?,
    )?;
    assert_eq!(flags & 0x1000, 0);
    let mut parent = inode_operand(&fixture.disk, NodeId::Directory(DirectoryNodeId::ROOT))?;
    put(&mut parent, 36, &(flags | 0x1000).to_le_bytes())?;
    put(&mut parent, 8, &12288_u32.to_le_bytes())?;
    let file = fixture.a;
    let child = NodeId::File(file);
    let image = inode_operand(&fixture.disk, child)?;
    let name = [b'z'; 250];
    let link = namespace_operand(DirectoryNodeId::ROOT, child, &name);
    let unlink = namespace_operand(DirectoryNodeId::ROOT, child, b"concurrent-a");
    let records = [
        (4, link.as_slice()),
        (5, unlink.as_slice()),
        (6, image.as_slice()),
        (6, parent.as_slice()),
    ];
    install_delta(&mut fixture, &records)?;
    fixture.remount()?;
    let free = fixture_u32(&fixture.disk.filesystem, 1036)?;
    assert_ne!(
        fixture_u32(
            &fixture.disk.filesystem,
            root_offset.checked_add(32).ok_or(Error::DeviceRange)?
        )? & 0x1000,
        0
    );
    assert!(
        fixture_u32(
            &fixture.disk.filesystem,
            root_offset.checked_add(4).ok_or(Error::DeviceRange)?
        )? >= 8192
    );
    install_delta(&mut fixture, &records)?;
    fixture.remount()?;
    assert_eq!(fixture_u32(&fixture.disk.filesystem, 1036)?, free);
    assert!(
        matches!(fixture.read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(&name)?))?, ChildLookup::Found(entry) if *entry.node() == child)
    );
    let mut bytes = [0; 1];
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?;
    assert_eq!(&bytes, b"a");
    Ok(())
}

/// Constructs namespace identities that do not exist until the replayed allocation succeeds.
fn birth_binding(parent: u32, inode: u32, name: &[u8]) -> Vec<u8> {
    let mut value = parent.to_le_bytes().to_vec();
    value.extend_from_slice(&inode.to_le_bytes());
    value.extend_from_slice(name);
    value
}

/// Independent mode/size vectors for namespace object births.
#[derive(Clone, Copy, Eq, PartialEq)]
enum BirthKind {
    /// Mode type 0x8000 with one externally supplied payload block.
    File,
    /// Mode type 0x4000 with a body reconstructed from namespace records.
    Directory,
    /// Mode type 0xa000 with a short target stored in the inode prefix.
    Symlink,
}

/// Explicit raw inode operands retain only the independent format-vector fields they declare.
/// # Errors
/// Returns malformed template coordinates or field bounds.
fn birth_inode(fixture: &Fixture, inode: u32, kind: BirthKind, links: u16) -> Result<Vec<u8>> {
    let mut value = inode_operand(&fixture.disk, NodeId::File(fixture.a))?;
    put(&mut value, 0, &inode.to_le_bytes())?;
    let (mode, flags, size) = match kind {
        BirthKind::File => (0x8000_u16 | 0o640, 0x80000_u32, 8_u32),
        BirthKind::Directory => (0x4000_u16 | 0o755, 0x80000_u32, 4096_u32),
        BirthKind::Symlink => (0xa000_u16 | 0o777, 0_u32, 11_u32),
    };
    put(&mut value, 4, &mode.to_le_bytes())?;
    put(&mut value, 8, &size.to_le_bytes())?;
    put(&mut value, 30, &links.to_le_bytes())?;
    put(&mut value, 36, &flags.to_le_bytes())?;
    put(&mut value, 104, &(0x1234_0000_u32 | inode).to_le_bytes())?;
    put(&mut value, 112, &0_u32.to_le_bytes())?;
    value.get_mut(44..104).ok_or(Error::DeviceRange)?.fill(0);
    if kind == BirthKind::Symlink {
        put(&mut value, 44, b"target/path")?;
    }
    Ok(value)
}

/// # Errors
/// Propagates independently constructed directory/file/symlink records and production recovery.
/// # Panics
/// Fails if dot entries, structural counts, nested namespace or repeated allocation differ.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe initialized directory bodies and stable recovered allocation"
)]
fn nested_directory_creation_initializes_parentage_and_fast_symlinks_once() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let root = fixture_inode_offset(&fixture.disk, NodeId::Directory(DirectoryNodeId::ROOT))?;
    let root_links_offset = root.checked_add(26).ok_or(Error::DeviceRange)?;
    let root_links = u16::from_le_bytes(
        fixture
            .disk
            .filesystem
            .get(root_links_offset..root_links_offset.checked_add(2).ok_or(Error::DeviceRange)?)
            .ok_or(Error::DeviceRange)?
            .try_into()
            .map_err(|_| Error::DeviceRange)?,
    );
    let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
    let free_blocks = fixture_u32(&fixture.disk.filesystem, 1036)?;
    put(&mut fixture.disk.filesystem, 1000 * 4096, b"replayed")?;
    let a = birth_binding(2, 64, b"delta-tree");
    let b = birth_binding(64, 65, b"nested");
    let c = birth_binding(65, 66, b"payload");
    let d = birth_binding(65, 67, b"link");
    let i64 = birth_inode(&fixture, 64, BirthKind::Directory, 3)?;
    let i65 = birth_inode(&fixture, 65, BirthKind::Directory, 2)?;
    let i66 = birth_inode(&fixture, 66, BirthKind::File, 1)?;
    let i67 = birth_inode(&fixture, 67, BirthKind::Symlink, 1)?;
    let mut add = [0; 16];
    put(&mut add, 0, &66_u32.to_le_bytes())?;
    put(&mut add, 8, &1_u16.to_le_bytes())?;
    put(&mut add, 12, &1000_u32.to_le_bytes())?;
    let records = [
        (3, a.as_slice()),
        (3, b.as_slice()),
        (3, c.as_slice()),
        (3, d.as_slice()),
        (1, add.as_slice()),
        (6, i64.as_slice()),
        (6, i65.as_slice()),
        (6, i66.as_slice()),
        (6, i67.as_slice()),
    ];
    for _ in 0..2 {
        install_delta(&mut fixture, &records)?;
        fixture.remount()?;
        let ChildLookup::Found(top) = fixture.read(|pass| {
            pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"delta-tree")?)
        })?
        else {
            return Err(Error::DirectoryEntryNotFound);
        };
        let NodeId::Directory(top) = *top.node() else {
            return Err(Error::WrongInodeKind);
        };
        let ChildLookup::Found(nested) =
            fixture.read(|pass| pass.lookup_child(top, &Ext4Name::new(b"nested")?))?
        else {
            return Err(Error::DirectoryEntryNotFound);
        };
        let NodeId::Directory(nested) = *nested.node() else {
            return Err(Error::WrongInodeKind);
        };
        assert!(
            matches!(fixture.read(|pass| pass.lookup_child(top, &Ext4Name::new(b"..")?))?, ChildLookup::Found(parent) if *parent.node() == NodeId::Directory(DirectoryNodeId::ROOT))
        );
        assert!(
            matches!(fixture.read(|pass| pass.lookup_child(nested, &Ext4Name::new(b"..")?))?, ChildLookup::Found(parent) if *parent.node() == NodeId::Directory(top))
        );
        let ChildLookup::Found(payload) =
            fixture.read(|pass| pass.lookup_child(nested, &Ext4Name::new(b"payload")?))?
        else {
            return Err(Error::DirectoryEntryNotFound);
        };
        let NodeId::File(file) = *payload.node() else {
            return Err(Error::WrongInodeKind);
        };
        let mut bytes = [0; 8];
        fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?;
        assert_eq!(&bytes, b"replayed");
        let ChildLookup::Found(link) =
            fixture.read(|pass| pass.lookup_child(nested, &Ext4Name::new(b"link")?))?
        else {
            return Err(Error::DirectoryEntryNotFound);
        };
        let NodeId::Symlink(link) = *link.node() else {
            return Err(Error::WrongInodeKind);
        };
        assert_eq!(
            fixture.read(|pass| pass.read_symlink(link))?,
            b"target/path"
        );
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1040)?,
            free_inodes.checked_sub(4).ok_or(Error::InvalidSuperblock)?
        );
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1036)?,
            free_blocks.checked_sub(3).ok_or(Error::InvalidSuperblock)?
        );
        let actual_root_links = u16::from_le_bytes(
            fixture
                .disk
                .filesystem
                .get(
                    root_links_offset
                        ..root_links_offset.checked_add(2).ok_or(Error::DeviceRange)?,
                )
                .ok_or(Error::DeviceRange)?
                .try_into()
                .map_err(|_| Error::DeviceRange)?,
        );
        assert_eq!(
            actual_root_links,
            root_links.checked_add(1).ok_or(Error::InvalidInode)?
        );
    }
    Ok(())
}

/// # Errors
/// Propagates independent cyclic operands or production recovery admission errors.
/// # Panics
/// Fails if a directory birth cycle reaches any persistent write or flush.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify acyclic creation parentage before effects"
)]
fn cyclic_directory_births_are_rejected_before_allocation_publication() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = birth_binding(65, 64, b"a");
    let b = birth_binding(64, 65, b"b");
    let i64 = birth_inode(&fixture, 64, BirthKind::Directory, 3)?;
    let i65 = birth_inode(&fixture, 65, BirthKind::Directory, 3)?;
    install_delta(&mut fixture, &[(3, &a), (3, &b), (6, &i64), (6, &i65)])?;
    fixture.disk.storage_effects = 0;
    assert!(matches!(
        fixture.disk.mount(MountAccess::ReadWrite),
        Err(Error::InvalidDirectoryEntry)
    ));
    assert_eq!(fixture.disk.storage_effects, 0);
    Ok(())
}

/// Reads an inode's group-zero allocation bit independently of the mount implementation.
/// # Errors
/// Returns invalid fixture bitmap geometry or a truncated byte.
fn inode_allocated(disk: &Disk, inode: u32) -> Result<bool> {
    let bit = inode.checked_sub(1).ok_or(Error::InvalidInode)?;
    let bitmap = usize::try_from(fixture_u32(&disk.filesystem, 4100)?)
        .map_err(|_| Error::DeviceRange)?
        .checked_mul(4096)
        .ok_or(Error::DeviceRange)?;
    let byte = bitmap
        .checked_add(usize::try_from(bit / 8).map_err(|_| Error::DeviceRange)?)
        .ok_or(Error::DeviceRange)?;
    Ok(*disk.filesystem.get(byte).ok_or(Error::DeviceRange)? & (1_u8 << (bit % 8)) != 0)
}

/// # Errors
/// Propagates independent unlink operands and production recovery failures.
/// # Panics
/// Fails if terminal replay leaks allocation, frees another file or repeats a counter transition.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe terminal ownership and repeatable counter postconditions"
)]
fn terminal_unlink_without_inode_metadata_retires_allocation_once() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let id = NodeId::File(fixture.a).file_index();
    let inode = fixture_inode_offset(&fixture.disk, NodeId::File(fixture.a))?;
    let block = fixture_u32(
        &fixture.disk.filesystem,
        inode.checked_add(60).ok_or(Error::DeviceRange)?,
    )?;
    let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
    let free_blocks = fixture_u32(&fixture.disk.filesystem, 1036)?;
    let unlink = namespace_operand(
        DirectoryNodeId::ROOT,
        NodeId::File(fixture.a),
        b"concurrent-a",
    );
    for _ in 0..2 {
        install_delta(&mut fixture, &[(5, &unlink)])?;
        fixture.remount()?;
        assert!(matches!(
            fixture
                .read(|pass| pass
                    .lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"concurrent-a")?))?,
            ChildLookup::NotFound
        ));
        assert!(!inode_allocated(&fixture.disk, id)?);
        assert!(!allocated(&fixture.disk, block)?);
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1040)?,
            free_inodes.checked_add(1).ok_or(Error::InvalidSuperblock)?
        );
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1036)?,
            free_blocks.checked_add(1).ok_or(Error::InvalidSuperblock)?
        );
        let mut bytes = [0; 1];
        let retained = fixture.b;
        fixture.read(|pass| pass.read_file(retained, FileOffset::ZERO, &mut bytes))?;
        assert_eq!(&bytes, b"b");
    }
    Ok(())
}

/// # Errors
/// Propagates ordinary cross-directory hard-link creation and production delta recovery.
/// # Panics
/// Fails if missing inode metadata implies deletion despite a remaining binding in another directory.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe the complete final namespace rather than procedural link arithmetic"
)]
fn unlink_census_preserves_a_hard_link_in_an_unchanged_parent() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    let parent = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let parent = pass.create_directory(
            root,
            &Ext4Name::new(b"retained-parent")?,
            NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
        )?;
        let source = pass.hard_link_source(HardLinkNodeId::File(file))?;
        pass.create_hard_link(
            source,
            parent,
            &Ext4Name::new(b"retained")?,
            NamespaceDestination::Vacant,
        )?;
        Ok(parent.id())
    })?;
    let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
    let free_blocks = fixture_u32(&fixture.disk.filesystem, 1036)?;
    let unlink = namespace_operand(DirectoryNodeId::ROOT, NodeId::File(file), b"concurrent-a");
    for _ in 0..2 {
        install_delta(&mut fixture, &[(5, &unlink)])?;
        fixture.remount()?;
        assert_eq!(
            fixture.read(|pass| Ok(pass.load_file(file)?.links_count()))?,
            Ext4LinkCount::ONE
        );
        assert!(
            matches!(fixture.read(|pass| pass.lookup_child(parent, &Ext4Name::new(b"retained")?))?, ChildLookup::Found(entry) if *entry.node() == NodeId::File(file))
        );
        assert_eq!(fixture_u32(&fixture.disk.filesystem, 1040)?, free_inodes);
        assert_eq!(fixture_u32(&fixture.disk.filesystem, 1036)?, free_blocks);
        assert!(inode_allocated(
            &fixture.disk,
            NodeId::File(file).file_index()
        )?);
    }
    Ok(())
}

/// # Errors
/// Propagates ordinary nested-directory creation and independent unlink record construction.
/// # Panics
/// Fails if nested terminal replay needs live table bodies after their bitmap slots are free.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe directory retirement and stable repeated namespace absence"
)]
fn nested_directory_unlinks_release_bodies_and_parent_counts_once() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let (outer, inner, file) = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let metadata = NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?);
        let outer = pass.create_directory(root, &Ext4Name::new(b"retired-tree")?, metadata)?;
        let inner = pass.create_directory(outer, &Ext4Name::new(b"inner")?, metadata)?;
        let file = pass.create_file(
            inner,
            &Ext4Name::new(b"file")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )?;
        Ok((outer.id(), inner.id(), file.id()))
    })?;
    let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
    let free_blocks = fixture_u32(&fixture.disk.filesystem, 1036)?;
    let root_links =
        fixture.read(|pass| Ok(pass.load_directory(DirectoryNodeId::ROOT)?.links_count()))?;
    let a = namespace_operand(
        DirectoryNodeId::ROOT,
        NodeId::Directory(outer),
        b"retired-tree",
    );
    let b = namespace_operand(outer, NodeId::Directory(inner), b"inner");
    let c = namespace_operand(inner, NodeId::File(file), b"file");
    for _ in 0..2 {
        install_delta(&mut fixture, &[(5, &a), (5, &b), (5, &c)])?;
        fixture.remount()?;
        assert!(matches!(
            fixture
                .read(|pass| pass
                    .lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"retired-tree")?))?,
            ChildLookup::NotFound
        ));
        for node in [
            NodeId::Directory(outer),
            NodeId::Directory(inner),
            NodeId::File(file),
        ] {
            assert!(!inode_allocated(&fixture.disk, node.file_index())?);
        }
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1040)?,
            free_inodes.checked_add(3).ok_or(Error::InvalidSuperblock)?
        );
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1036)?,
            free_blocks.checked_add(2).ok_or(Error::InvalidSuperblock)?
        );
        assert_eq!(
            fixture.read(|pass| Ok(pass
                .load_directory(DirectoryNodeId::ROOT)?
                .links_count()
                .on_disk_count()))?,
            root_links
                .on_disk_count()
                .checked_sub(1)
                .ok_or(Error::InvalidInode)?
        );
    }
    Ok(())
}

/// # Errors
/// Propagates fixture namespace creation and independent deletion operands.
/// # Panics
/// Fails if unlinking a nonempty directory publishes partial namespace or storage reclamation.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe rejection before journal or home effects"
)]
fn terminal_directory_replay_requires_final_namespace_emptiness() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let directory = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let directory = pass.create_directory(
            root,
            &Ext4Name::new(b"nonempty")?,
            NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
        )?;
        pass.create_file(
            directory,
            &Ext4Name::new(b"retained")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )?;
        Ok(directory.id())
    })?;
    let unlink = namespace_operand(
        DirectoryNodeId::ROOT,
        NodeId::Directory(directory),
        b"nonempty",
    );
    install_delta(&mut fixture, &[(5, &unlink)])?;
    fixture.disk.storage_effects = 0;
    assert!(matches!(
        fixture.disk.mount(MountAccess::ReadWrite),
        Err(Error::DirectoryNotEmpty)
    ));
    assert_eq!(fixture.disk.storage_effects, 0);
    Ok(())
}

/// # Errors
/// Propagates an independently recorded earlier inode image and terminal namespace operand.
/// # Panics
/// Fails if an earlier positive count resurrects storage after a later unlink or on repeated replay.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare final namespace ownership with an earlier metadata image"
)]
fn later_unlink_supersedes_an_earlier_positive_inode_count() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = NodeId::File(fixture.a);
    let image = inode_operand(&fixture.disk, file)?;
    let unlink = namespace_operand(DirectoryNodeId::ROOT, file, b"concurrent-a");
    let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
    for _ in 0..2 {
        install_delta(&mut fixture, &[(6, &image), (5, &unlink)])?;
        fixture.remount()?;
        assert!(!inode_allocated(&fixture.disk, file.file_index())?);
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1040)?,
            free_inodes.checked_add(1).ok_or(Error::InvalidSuperblock)?
        );
    }
    Ok(())
}

/// # Errors
/// Propagates attribute-inode construction, namespace recovery and surviving attribute reads.
/// # Panics
/// Fails if terminal unlink leaks attribute storage or retires another inode's value ownership.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe complete terminal data and attribute reclamation"
)]
fn terminal_replay_releases_attributes_and_preserves_another_value_owner() -> Result<()> {
    let mut fixture = fixture_with_incompatible_features(0x400)?;
    let retained = fixture.b;
    let victim = fixture.a;
    let value = [0x73; 16_384];
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(retained))?;
        pass.set_xattr(
            node,
            XattrName::new(XattrNamespace::User, b"large")?,
            XattrValue::new(&value)?,
        )
    })?;
    let free_blocks = fixture_u32(&fixture.disk.filesystem, 1036)?;
    let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(victim))?;
        pass.set_xattr(
            node,
            XattrName::new(XattrNamespace::User, b"large")?,
            XattrValue::new(&value)?,
        )
    })?;
    let unlink = namespace_operand(DirectoryNodeId::ROOT, NodeId::File(victim), b"concurrent-a");
    for _ in 0..2 {
        install_delta(&mut fixture, &[(5, &unlink)])?;
        fixture.remount()?;
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1036)?,
            free_blocks.checked_add(1).ok_or(Error::InvalidSuperblock)?
        );
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1040)?,
            free_inodes.checked_add(1).ok_or(Error::InvalidSuperblock)?
        );
        let observed = fixture
            .read(|pass| {
                pass.read_xattr(
                    NodeId::File(retained),
                    &XattrName::new(XattrNamespace::User, b"large")?,
                )
            })?
            .ok_or(Error::InvalidXattr)?;
        assert_eq!(observed.bytes(), value);
    }
    Ok(())
}

/// # Errors
/// Propagates a sparse range assignment followed by a terminal unlink without an inode operand.
/// # Panics
/// Fails if superseded mappings survive retirement or unused ADD storage stays allocated.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe final ownership after ordered range and namespace operands"
)]
fn terminal_unlink_consumes_range_assignments_without_a_final_inode_image() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = NodeId::File(fixture.a);
    let free_blocks = fixture_u32(&fixture.disk.filesystem, 1036)?;
    let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
    let unlink = namespace_operand(DirectoryNodeId::ROOT, file, b"concurrent-a");
    let mut add = [0; 16];
    put(&mut add, 0, &file.file_index().to_le_bytes())?;
    put(&mut add, 8, &1_u16.to_le_bytes())?;
    put(&mut add, 12, &1000_u32.to_le_bytes())?;
    let mut del = [0; 12];
    put(&mut del, 0, &file.file_index().to_le_bytes())?;
    put(&mut del, 4, &1_u32.to_le_bytes())?;
    put(&mut del, 8, &u32::MAX.to_le_bytes())?;
    for _ in 0..2 {
        install_delta(&mut fixture, &[(1, &add), (2, &del), (5, &unlink)])?;
        fixture.remount()?;
        assert!(!inode_allocated(&fixture.disk, file.file_index())?);
        assert!(!allocated(&fixture.disk, 1000)?);
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1036)?,
            free_blocks.checked_add(1).ok_or(Error::InvalidSuperblock)?
        );
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1040)?,
            free_inodes.checked_add(1).ok_or(Error::InvalidSuperblock)?
        );
    }
    Ok(())
}

/// # Errors
/// Propagates terminal deletion, injected home-write interruption and production remount recovery.
/// # Panics
/// Fails if a partially checkpointed deletion loses the full transaction's retirement postcondition.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe roll-forward of namespace, inode and allocation together"
)]
fn interrupted_terminal_checkpoint_recovers_one_complete_retirement() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = NodeId::File(fixture.a);
    let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
    let unlink = namespace_operand(DirectoryNodeId::ROOT, file, b"concurrent-a");
    install_delta(&mut fixture, &[(5, &unlink)])?;
    let mut homes = 0_usize;
    let outcome = fixture
        .disk
        .mount_observing(MountAccess::ReadWrite, |_, boundary, _| {
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
    assert_eq!(outcome.map(|_| ()), Err(Error::DeviceIo));
    assert_eq!(homes, 2);
    fixture.remount()?;
    assert!(!inode_allocated(&fixture.disk, file.file_index())?);
    assert!(matches!(
        fixture.read(
            |pass| pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"concurrent-a")?)
        )?,
        ChildLookup::NotFound
    ));
    assert_eq!(
        fixture_u32(&fixture.disk.filesystem, 1040)?,
        free_inodes.checked_add(1).ok_or(Error::InvalidSuperblock)?
    );
    let replacement = namespace_operand(DirectoryNodeId::ROOT, file, b"concurrent-b");
    install_delta(&mut fixture, &[(5, &replacement)])?;
    fixture.remount()?;
    let retained = fixture.b;
    assert!(
        matches!(fixture.read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"concurrent-b")?))?, ChildLookup::Found(entry) if *entry.node() == NodeId::File(retained))
    );
    assert_eq!(
        fixture_u32(&fixture.disk.filesystem, 1040)?,
        free_inodes.checked_add(1).ok_or(Error::InvalidSuperblock)?
    );
    Ok(())
}

/// # Errors
/// Propagates delta installation and production read-only recovery.
/// # Panics
/// Fails if virtual terminal reclamation touches backing storage or leaves the deleted binding visible.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare the recovered namespace with unchanged backing images"
)]
fn read_only_terminal_replay_has_zero_backing_effects() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let unlink = namespace_operand(
        DirectoryNodeId::ROOT,
        NodeId::File(fixture.a),
        b"concurrent-a",
    );
    install_delta(&mut fixture, &[(5, &unlink)])?;
    let filesystem = fixture.disk.filesystem.clone();
    let journal = fixture.disk.journal.clone();
    fixture.disk.storage_effects = 0;
    let (profile, epoch, coordinator, _) = fixture
        .disk
        .mount(MountAccess::ReadOnly {
            recovery_memory: RecoveryMemoryLimit::DEFAULT,
        })?
        .into_parts();
    fixture.profile = profile;
    fixture.cache = MetadataCache::try_new(&epoch)?;
    fixture.epoch = epoch;
    fixture.coordinator = coordinator;
    assert!(matches!(
        fixture.read(
            |pass| pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"concurrent-a")?)
        )?,
        ChildLookup::NotFound
    ));
    let retained = fixture.b;
    let mut bytes = [0; 1];
    fixture.read(|pass| pass.read_file(retained, FileOffset::ZERO, &mut bytes))?;
    assert_eq!(&bytes, b"b");
    assert_eq!(fixture.disk.storage_effects, 0);
    assert_eq!(fixture.disk.filesystem, filesystem);
    assert_eq!(fixture.disk.journal, journal);
    Ok(())
}

/// Independent complete inode and xattr vectors use an unsorted physical attribute-entry order.
/// # Errors
/// Returns template bounds or insufficient space in this fixture's 256-byte record.
fn inline_file_operand(
    fixture: &Fixture,
    inode: u32,
    payload: &[u8],
    public_value: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut value = inode_operand(&fixture.disk, NodeId::File(fixture.a))?;
    if value.len() != 260 {
        return Err(Error::InvalidInode);
    }
    put(&mut value, 0, &inode.to_le_bytes())?;
    put(
        &mut value,
        8,
        &u32::try_from(payload.len())
            .map_err(|_| Error::DeviceRange)?
            .to_le_bytes(),
    )?;
    put(&mut value, 112, &0_u32.to_le_bytes())?;
    value.get_mut(44..104).ok_or(Error::DeviceRange)?.fill(0);
    let first = payload.len().min(60);
    put(
        &mut value,
        44,
        payload.get(..first).ok_or(Error::DeviceRange)?,
    )?;
    let extra = u16::from_le_bytes(
        value
            .get(132..134)
            .ok_or(Error::DeviceRange)?
            .try_into()
            .map_err(|_| Error::DeviceRange)?,
    );
    let body_start = 132_usize
        .checked_add(usize::from(extra))
        .ok_or(Error::DeviceRange)?;
    let body = value.get_mut(body_start..).ok_or(Error::DeviceRange)?;
    body.fill(0);
    put(body, 0, &0xea02_0000_u32.to_le_bytes())?;
    let mut cursor = 4_usize;
    let mut end = body.len();
    for (index, name, bytes) in [
        (
            7_u8,
            b"data".as_slice(),
            payload.get(60..).unwrap_or_default(),
        ),
        (1_u8, b"keep".as_slice(), public_value.unwrap_or_default()),
    ] {
        if index == 1 && public_value.is_none() {
            continue;
        }
        let aligned = bytes.len().checked_add(3).ok_or(Error::DeviceRange)? & !3;
        end = end.checked_sub(aligned).ok_or(Error::DeviceRange)?;
        if cursor.checked_add(24).ok_or(Error::DeviceRange)? > end {
            return Err(Error::NoSpace);
        }
        put(body, cursor, &[4, index])?;
        put(
            body,
            cursor.checked_add(2).ok_or(Error::DeviceRange)?,
            &u16::try_from(end.checked_sub(4).ok_or(Error::DeviceRange)?)
                .map_err(|_| Error::DeviceRange)?
                .to_le_bytes(),
        )?;
        put(
            body,
            cursor.checked_add(8).ok_or(Error::DeviceRange)?,
            &u32::try_from(bytes.len())
                .map_err(|_| Error::DeviceRange)?
                .to_le_bytes(),
        )?;
        put(
            body,
            cursor.checked_add(16).ok_or(Error::DeviceRange)?,
            name,
        )?;
        put(body, end, bytes)?;
        cursor = cursor.checked_add(20).ok_or(Error::DeviceRange)?;
    }
    Ok(value)
}

/// # Errors
/// Propagates independent inline record construction, recovery, payload and attribute reads.
/// # Panics
/// Fails if full resident bytes, semantic attributes, repeated replay or read-only isolation differ.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare independent complete inline vectors with recovered data and ownership"
)]
fn inline_records_restore_full_payload_and_preserve_attribute_bindings() -> Result<()> {
    for access in [
        MountAccess::ReadWrite,
        MountAccess::ReadOnly {
            recovery_memory: RecoveryMemoryLimit::DEFAULT,
        },
    ] {
        let mut fixture = inline_fixture()?;
        let file = fixture.a;
        fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(file))?;
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::User, b"keep")?,
                XattrValue::new(b"kept")?,
            )
        })?;
        let payload = [0x59; 80];
        let image = inline_file_operand(
            &fixture,
            NodeId::File(file).file_index(),
            &payload,
            Some(b"kept"),
        )?;
        let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
        let free_blocks = fixture_u32(&fixture.disk.filesystem, 1036)?;
        for _ in 0..2 {
            install_delta(&mut fixture, &[(6, &image)])?;
            let original_fs = fixture.disk.filesystem.clone();
            let original_journal = fixture.disk.journal.clone();
            fixture.disk.storage_effects = 0;
            let (profile, epoch, coordinator, _) = fixture.disk.mount(access)?.into_parts();
            fixture.profile = profile;
            fixture.cache = MetadataCache::try_new(&epoch)?;
            fixture.epoch = epoch;
            fixture.coordinator = coordinator;
            let mut bytes = [0; 80];
            assert_eq!(
                fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?,
                ReadBytes::from_usize(80)
            );
            assert_eq!(bytes, payload);
            let keep = fixture
                .read(|pass| {
                    pass.read_xattr(
                        NodeId::File(file),
                        &XattrName::new(XattrNamespace::User, b"keep")?,
                    )
                })?
                .ok_or(Error::InvalidXattr)?;
            assert_eq!(keep.bytes(), b"kept");
            assert_eq!(fixture_u32(&fixture.disk.filesystem, 1040)?, free_inodes);
            assert_eq!(fixture_u32(&fixture.disk.filesystem, 1036)?, free_blocks);
            if matches!(access, MountAccess::ReadOnly { .. }) {
                assert_eq!(fixture.disk.storage_effects, 0);
                assert_eq!(fixture.disk.filesystem, original_fs);
                assert_eq!(fixture.disk.journal, original_journal);
            }
        }
    }
    Ok(())
}

/// # Errors
/// Propagates fixture attributes and independent malformed inline operands.
/// # Panics
/// Fails if inline payload replay can rebind other attributes or admit an omitted body before effects.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe complete resident admission before persistent writes"
)]
fn inline_records_reject_changed_attributes_and_missing_bodies_before_effects() -> Result<()> {
    for variant in 0..3 {
        let mut fixture = inline_fixture()?;
        let file = fixture.a;
        fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(file))?;
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::User, b"keep")?,
                XattrValue::new(b"kept")?,
            )
        })?;
        let mut image = inline_file_operand(
            &fixture,
            NodeId::File(file).file_index(),
            &[0x59; 80],
            Some(if variant == 0 { b"evil" } else { b"kept" }),
        )?;
        let expected = if variant == 0 {
            Error::UnsupportedJournal
        } else {
            Error::InvalidInode
        };
        if variant == 1 {
            image.truncate(164);
        } else if variant == 2 {
            image.get_mut(164..).ok_or(Error::DeviceRange)?.fill(0);
        }
        install_delta(&mut fixture, &[(6, &image)])?;
        fixture.disk.storage_effects = 0;
        assert_eq!(
            fixture.disk.mount(MountAccess::ReadWrite).map(|_| ()),
            Err(expected)
        );
        assert_eq!(fixture.disk.storage_effects, 0);
    }
    Ok(())
}

/// # Errors
/// Propagates complete inline file/directory operands, production creation and namespace reads.
/// # Panics
/// Fails if full inline creation loses payload, dot parentage, or consumes ordinary data blocks.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe complete resident births and stable allocation"
)]
fn inline_creation_recovers_complete_bodies_without_data_allocation() -> Result<()> {
    let mut fixture = inline_fixture()?;
    let file = inline_file_operand(&fixture, 64, &[0x51; 80], None)?;
    let mut directory = inline_file_operand(&fixture, 65, &[0; 60], None)?;
    put(&mut directory, 4, &(0x4000_u16 | 0o755).to_le_bytes())?;
    put(&mut directory, 30, &2_u16.to_le_bytes())?;
    put(&mut directory, 44, &2_u32.to_le_bytes())?;
    put(&mut directory, 52, &56_u16.to_le_bytes())?;
    let file_name = birth_binding(2, 64, b"inline-born");
    let directory_name = birth_binding(2, 65, b"inline-dir-born");
    let free_blocks = fixture_u32(&fixture.disk.filesystem, 1036)?;
    let free_inodes = fixture_u32(&fixture.disk.filesystem, 1040)?;
    for _ in 0..2 {
        install_delta(
            &mut fixture,
            &[
                (6, &file),
                (3, &file_name),
                (6, &directory),
                (3, &directory_name),
            ],
        )?;
        fixture.remount()?;
        let ChildLookup::Found(entry) = fixture.read(|pass| {
            pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"inline-born")?)
        })?
        else {
            return Err(Error::DirectoryEntryNotFound);
        };
        let NodeId::File(id) = *entry.node() else {
            return Err(Error::WrongInodeKind);
        };
        let mut bytes = [0; 80];
        fixture.read(|pass| pass.read_file(id, FileOffset::ZERO, &mut bytes))?;
        assert_eq!(bytes, [0x51; 80]);
        let ChildLookup::Found(entry) = fixture.read(|pass| {
            pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"inline-dir-born")?)
        })?
        else {
            return Err(Error::DirectoryEntryNotFound);
        };
        let NodeId::Directory(id) = *entry.node() else {
            return Err(Error::WrongInodeKind);
        };
        assert!(
            matches!(fixture.read(|pass| pass.lookup_child(id, &Ext4Name::new(b"..")?))?, ChildLookup::Found(entry) if *entry.node() == NodeId::Directory(DirectoryNodeId::ROOT))
        );
        assert_eq!(fixture_u32(&fixture.disk.filesystem, 1036)?, free_blocks);
        assert_eq!(
            fixture_u32(&fixture.disk.filesystem, 1040)?,
            free_inodes.checked_sub(2).ok_or(Error::InvalidSuperblock)?
        );
    }
    Ok(())
}
