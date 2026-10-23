//! Concurrent read and mutation contracts over independently generated ext4 journal fixtures.

#![feature(allocator_api)]

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use ext4_core::*;
use sha2::Digest as _;

/// Selects the on-disk inline-data feature using format constants and an independent CRC.
/// # Errors
/// Returns an invalid fixture field or failed production mount.
fn inline_fixture() -> Result<Fixture> {
    fixture_with_incompatible_features(0x8000)
}

/// Declares an explicit format-vector feature profile without changing tracked image inputs.
/// # Errors
/// Propagates malformed fixture fields and production mount rejection.
#[expect(
    clippy::disallowed_methods,
    reason = "checked fixture fields receive exact little-endian values"
)]
fn fixture_with_incompatible_features(features: u32) -> Result<Fixture> {
    let mut disk = Disk::fixture();
    let flags = fixture_u32(&disk.filesystem, 1120)? | features;
    disk.filesystem
        .get_mut(1120..1124)
        .ok_or(Error::DeviceRange)?
        .copy_from_slice(&flags.to_le_bytes());
    let checksum = fixture_crc32c(
        u32::MAX,
        disk.filesystem.get(1024..2044).ok_or(Error::DeviceRange)?,
    );
    disk.filesystem
        .get_mut(2044..2048)
        .ok_or(Error::DeviceRange)?
        .copy_from_slice(&checksum.to_le_bytes());
    Fixture::from_disk(disk)
}

/// Constructs a filesystem encoding from independent on-disk constants.
/// # Errors
/// Returns truncated fixture fields or production mount rejection.
#[expect(
    clippy::disallowed_methods,
    reason = "exact fixture fields receive independently specified little-endian format values"
)]
fn casefold_fixture(features: u32, encoding_flags: u16) -> Result<Fixture> {
    let mut disk = Disk::fixture();
    let flags = fixture_u32(&disk.filesystem, 1120)? | 0x0002_0000 | features;
    disk.filesystem
        .get_mut(1120..1124)
        .ok_or(Error::DeviceRange)?
        .copy_from_slice(&flags.to_le_bytes());
    disk.filesystem
        .get_mut(1660..1662)
        .ok_or(Error::DeviceRange)?
        .copy_from_slice(&1_u16.to_le_bytes());
    disk.filesystem
        .get_mut(1662..1664)
        .ok_or(Error::DeviceRange)?
        .copy_from_slice(&encoding_flags.to_le_bytes());
    let checksum = fixture_crc32c(
        u32::MAX,
        disk.filesystem.get(1024..2044).ok_or(Error::DeviceRange)?,
    );
    disk.filesystem
        .get_mut(2044..2048)
        .ok_or(Error::DeviceRange)?
        .copy_from_slice(&checksum.to_le_bytes());
    Fixture::from_disk(disk)
}

/// # Errors
/// Propagates mount, namespace transition, journal, remount or directory read failure.
/// # Panics
/// Fails if aliases change identity, duplicate names are admitted, or stored spelling is lost.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe namespace identities, stored spellings and transition failures"
)]
fn casefold_namespace_mutations_preserve_spelling_and_inheritance() -> Result<()> {
    for features in [0, 0x8000] {
        let mut fixture = casefold_fixture(features, 1)?;
        let directory = fixture.mutate(|pass| {
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            let directory = pass.create_directory(
                root,
                &Ext4Name::new(b"folded")?,
                NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
            )?;
            pass.set_directory_casefold(directory, DirectoryCasefold::Enabled)?;
            Ok(directory.id())
        })?;
        let stored = Ext4Name::new("Straße".as_bytes())?;
        let alias = Ext4Name::new(b"strasse")?;
        let upper = Ext4Name::new(b"STRASSE")?;
        let file = fixture.mutate(|pass| {
            let directory = pass.directory(directory)?;
            pass.create_file(
                directory,
                &stored,
                NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
            )
            .map(|file| file.id())
        })?;
        fixture.remount()?;
        let found = fixture.read(|pass| pass.lookup_child(directory, &alias))?;
        assert!(
            matches!(found, ChildLookup::Found(ref child) if child.name() == &stored && *child.node() == NodeId::File(file))
        );
        assert_eq!(
            fixture.mutate(|pass| {
                let directory = pass.directory(directory)?;
                pass.create_file(
                    directory,
                    &upper,
                    NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
                )
                .map(|_file| ())
            }),
            Err(Error::NameAlreadyExists)
        );
        assert_eq!(
            fixture.mutate(|pass| {
                let directory = pass.directory(directory)?;
                pass.set_directory_casefold(directory, DirectoryCasefold::Disabled)
            }),
            Err(Error::DirectoryNotEmpty)
        );
        fixture.mutate(|pass| {
            let directory = pass.directory(directory)?;
            pass.rename_child(
                directory,
                &alias,
                directory,
                &upper,
                NamespaceDestination::Vacant,
            )
        })?;
        fixture.remount()?;
        assert!(
            matches!(fixture.read(|pass| pass.lookup_child(directory, &stored))?,
            ChildLookup::Found(child) if child.name() == &upper && *child.node() == NodeId::File(file))
        );
        fixture.mutate(|pass| {
            let directory = pass.directory(directory)?;
            pass.rename_child(
                directory,
                &stored,
                directory,
                &alias,
                NamespaceDestination::Replace {
                    existing_name: &upper,
                },
            )?;
            pass.unlink_file(directory, &upper)
        })?;
        fixture.mutate(|pass| {
            let directory = pass.directory(directory)?;
            pass.set_directory_casefold(directory, DirectoryCasefold::Disabled)?;
            for name in [&stored, &upper] {
                pass.create_file(
                    directory,
                    name,
                    NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
                )?;
            }
            pass.unlink_file(directory, &stored)?;
            pass.unlink_file(directory, &upper)?;
            pass.set_directory_casefold(directory, DirectoryCasefold::Enabled)
        })?;
        let child = fixture.mutate(|pass| {
            let parent = pass.directory(directory)?;
            let child = pass.create_directory(
                parent,
                &Ext4Name::new(b"Child")?,
                NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
            )?;
            pass.create_file(
                child,
                &stored,
                NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
            )?;
            Ok(child.id())
        })?;
        fixture.remount()?;
        assert!(matches!(
            fixture.read(|pass| pass.lookup_child(child, &alias))?,
            ChildLookup::Found(_)
        ));
        fixture.mutate(|pass| {
            let child = pass.directory(child)?;
            pass.unlink_file(child, &upper)?;
            let parent = pass.directory(directory)?;
            pass.remove_empty_directory(parent, &Ext4Name::new(b"CHILD")?)
        })?;
        fixture.remount()?;
    }
    let mut fixture = Fixture::new()?;
    assert_eq!(
        fixture.mutate(|pass| {
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            pass.set_directory_casefold(root, DirectoryCasefold::Enabled)
        }),
        Err(Error::UnsupportedWriteFeature)
    );
    Ok(())
}

/// # Errors
/// Propagates encoded fixture, allocation, index split, journal or read failure.
/// # Panics
/// Fails if folded index routes, case-only renames, invalid-byte policy or enumeration disagree.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe indexed namespace behavior through committed passes"
)]
fn casefold_htree_routes_aliases_and_preserves_invalid_encoding_policy() -> Result<()> {
    let mut fixture = casefold_fixture(0x8000, 0)?;
    let directory = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let directory = pass.create_directory(
            root,
            &Ext4Name::new(b"indexed-folded")?,
            NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
        )?;
        pass.set_directory_casefold(directory, DirectoryCasefold::Enabled)?;
        Ok(directory.id())
    })?;
    for index in 0..40 {
        let name = format!("É-{index:02}-{}", "x".repeat(180));
        fixture.mutate(|pass| {
            let directory = pass.directory(directory)?;
            pass.create_file(
                directory,
                &Ext4Name::new(name.as_bytes())?,
                NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
            )
            .map(|_file| ())
        })?;
    }
    fixture.remount()?;
    let offset = fixture_inode_offset(&fixture.disk, NodeId::Directory(directory))?;
    assert_eq!(
        fixture_u32(
            &fixture.disk.filesystem,
            offset.checked_add(32).ok_or(Error::ArithmeticOverflow)?
        )? & 0x1000,
        0x1000
    );
    for index in 0..40 {
        let alias = format!("é-{index:02}-{}", "X".repeat(180));
        assert!(matches!(
            fixture.read(|pass| pass.lookup_child(directory, &Ext4Name::new(alias.as_bytes())?))?,
            ChildLookup::Found(_)
        ));
    }
    let old = Ext4Name::new(format!("é-00-{}", "X".repeat(180)).as_bytes())?;
    let new = Ext4Name::new(format!("É-00-{}", "X".repeat(180)).as_bytes())?;
    fixture.mutate(|pass| {
        let directory = pass.directory(directory)?;
        pass.rename_child(
            directory,
            &old,
            directory,
            &new,
            NamespaceDestination::Vacant,
        )
    })?;
    let mut reader = DirectoryReader::new(directory, DirectoryScanCursor::start());
    let mut seen = 0;
    while let Some(entry) = fixture.read(|pass| pass.next_directory_entry(&mut reader))? {
        if !matches!(entry.entry().name().bytes(), b"." | b"..") {
            seen += 1;
        }
    }
    assert_eq!(seen, 40);
    let invalid = Ext4Name::new(b"Mixed\xff")?;
    fixture.mutate(|pass| {
        let directory = pass.directory(directory)?;
        pass.create_file(
            directory,
            &invalid,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )
        .map(|_file| ())
    })?;
    assert!(matches!(
        fixture.read(|pass| pass.lookup_child(directory, &invalid))?,
        ChildLookup::Found(_)
    ));
    assert!(matches!(
        fixture.read(|pass| pass.lookup_child(directory, &Ext4Name::new(b"mixed\xff")?))?,
        ChildLookup::NotFound
    ));
    fixture.mutate(|pass| {
        let directory = pass.directory(directory)?;
        pass.unlink_file(directory, &invalid)?;
        for index in 0..40 {
            let alias = format!("é-{index:02}-{}", "X".repeat(180));
            pass.unlink_file(directory, &Ext4Name::new(alias.as_bytes())?)?;
        }
        pass.set_directory_casefold(directory, DirectoryCasefold::Disabled)
    })?;
    fixture.remount()?;
    let mut strict = casefold_fixture(0, 1)?;
    let directory = strict.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let directory = pass.create_directory(
            root,
            &Ext4Name::new(b"strict")?,
            NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
        )?;
        pass.set_directory_casefold(directory, DirectoryCasefold::Enabled)?;
        Ok(directory.id())
    })?;
    let effects = strict.disk.storage_effects;
    assert_eq!(
        strict.mutate(|pass| {
            let directory = pass.directory(directory)?;
            pass.create_file(
                directory,
                &invalid,
                NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
            )
            .map(|_file| ())
        }),
        Err(Error::InvalidName)
    );
    assert_eq!(strict.disk.storage_effects, effects);
    Ok(())
}

/// # Errors
/// Propagates value preparation, commit, read, replacement, release and remount failures.
/// # Panics
/// Fails if large values change bytes, expose value inodes as namespace, or leak allocation.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe opaque values, hidden inode roles and allocation recovery"
)]
fn attribute_value_inodes_replace_delete_and_preserve_inline_payload() -> Result<()> {
    for features in [0x400, 0x8400] {
        let mut fixture = fixture_with_incompatible_features(features)?;
        let file = fixture.a;
        let before = fixture.epoch.geometry().free_cluster_count();
        fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(file))?;
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::User, b"large")?,
                XattrValue::new(&[0x71; 16_384])?,
            )?;
            assert!(
                pass.staged_xattrs(NodeId::File(file))?
                    .entries()
                    .any(|(_, value)| value.bytes() == [0x71; 16_384])
            );
            Ok(())
        })?;
        fixture.remount()?;
        let value = fixture
            .read(|pass| {
                pass.read_xattr(
                    NodeId::File(file),
                    &XattrName::new(XattrNamespace::User, b"large")?,
                )
            })?
            .ok_or(Error::InvalidXattr)?;
        assert_eq!(value.bytes(), &[0x71; 16_384]);
        let offset = fixture_inode_offset(&fixture.disk, NodeId::File(file))?;
        let value_inode = fixture_u32(
            &fixture.disk.filesystem,
            offset.checked_add(168).ok_or(Error::ArithmeticOverflow)?,
        )?;
        assert_ne!(value_inode, 0);
        assert_eq!(
            fixture
                .read(|pass| pass.load_node_by_file_index(value_inode))
                .err(),
            Some(Error::InvalidInode)
        );
        fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(file))?;
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::User, b"large")?,
                XattrValue::new(&[0x42; 8192])?,
            )?;
            let file = pass.file(file)?;
            pass.write_file_range(file, FileOffset::from_bytes(1), b"b")
        })?;
        fixture.remount()?;
        let mut payload = [0; 2];
        assert_eq!(
            fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut payload))?,
            ReadBytes::from_usize(2)
        );
        assert_eq!(payload, *b"ab");
        let value = fixture
            .read(|pass| {
                pass.read_xattr(
                    NodeId::File(file),
                    &XattrName::new(XattrNamespace::User, b"large")?,
                )
            })?
            .ok_or(Error::InvalidXattr)?;
        assert_eq!(value.bytes(), &[0x42; 8192]);
        fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(file))?;
            pass.remove_xattr(node, &XattrName::new(XattrNamespace::User, b"large")?)?;
            Ok(())
        })?;
        fixture.remount()?;
        assert_eq!(fixture.epoch.geometry().free_cluster_count(), before);
    }
    Ok(())
}

/// # Errors
/// Propagates independently encoded reference construction, read, release and remount failures.
/// # Panics
/// Fails if shared value storage is freed early or an authenticated wrong count grants a mount.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    clippy::disallowed_methods,
    reason = "checked disk vectors and assertions observe physical-entry ownership independently"
)]
fn attribute_value_shared_references_and_corruption() -> Result<()> {
    let mut fixture = fixture_with_incompatible_features(0x400)?;
    let a = fixture.a;
    let b = fixture.b;
    let before = fixture.epoch.geometry().free_cluster_count();
    let payload = alloc::vec![0x6d; 65_536];
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(a))?;
        pass.set_xattr(
            node,
            XattrName::new(XattrNamespace::User, b"large")?,
            XattrValue::new(&payload)?,
        )
    })?;
    let a_offset = fixture_inode_offset(&fixture.disk, NodeId::File(a))?;
    let b_offset = fixture_inode_offset(&fixture.disk, NodeId::File(b))?;
    let value_number = fixture_u32(&fixture.disk.filesystem, a_offset + 168)?;
    let table = usize::try_from(fixture_u32(&fixture.disk.filesystem, 4104)?)
        .map_err(|_| Error::ArithmeticOverflow)?;
    let value_offset = table * 4096
        + usize::try_from(value_number - 1).map_err(|_| Error::ArithmeticOverflow)? * 256;
    let body = fixture
        .disk
        .filesystem
        .get(a_offset + 160..a_offset + 256)
        .ok_or(Error::DeviceRange)?
        .to_vec();
    fixture
        .disk
        .filesystem
        .get_mut(b_offset + 160..b_offset + 256)
        .ok_or(Error::DeviceRange)?
        .copy_from_slice(&body);
    let b_flags = fixture_u32(&fixture.disk.filesystem, b_offset + 32)?;
    fixture.disk.encode_inode(NodeId::File(b), b_flags, None)?;
    let value_flags = fixture_u32(&fixture.disk.filesystem, value_offset + 32)?;
    // There are two physical inode-body entries. The authenticated count of one must fail.
    fixture.disk.storage_effects = 0;
    assert_eq!(
        fixture.disk.mount(MountAccess::ReadWrite).err(),
        Some(Error::InvalidXattr)
    );
    assert_eq!(fixture.disk.storage_effects, 0);
    fixture
        .disk
        .filesystem
        .get_mut(value_offset + 36..value_offset + 40)
        .ok_or(Error::DeviceRange)?
        .copy_from_slice(&2_u32.to_le_bytes());
    fixture
        .disk
        .encode_inode_number(value_number, value_flags, None)?;
    fixture.remount()?;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(a))?;
        pass.remove_xattr(node, &XattrName::new(XattrNamespace::User, b"large")?)?;
        Ok(())
    })?;
    fixture.remount()?;
    let value = fixture
        .read(|pass| {
            pass.read_xattr(
                NodeId::File(b),
                &XattrName::new(XattrNamespace::User, b"large")?,
            )
        })?
        .ok_or(Error::InvalidXattr)?;
    assert_eq!(value.bytes(), payload);
    let payload_block = usize::try_from(fixture_u32(&fixture.disk.filesystem, value_offset + 60)?)
        .map_err(|_| Error::ArithmeticOverflow)?;
    let byte = fixture
        .disk
        .filesystem
        .get_mut(payload_block * 4096)
        .ok_or(Error::DeviceRange)?;
    *byte ^= 1;
    fixture.remount()?;
    assert_eq!(
        fixture
            .read(|pass| pass.read_xattr(
                NodeId::File(b),
                &XattrName::new(XattrNamespace::User, b"large")?
            ))
            .err(),
        Some(Error::ChecksumMismatch)
    );
    *fixture
        .disk
        .filesystem
        .get_mut(payload_block * 4096)
        .ok_or(Error::DeviceRange)? ^= 1;
    fixture.remount()?;
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.unlink_file(root, &Ext4Name::new(b"concurrent-b")?)
    })?;
    fixture.remount()?;
    // Removing b also releases its original one-byte data block.
    assert_eq!(
        fixture.epoch.geometry().free_cluster_count().as_u64(),
        before.as_u64() + 1
    );
    Ok(())
}

/// # Errors
/// Propagates fixture, private mount, content growth and reclamation failures.
/// # Panics
/// Fails if inline read-only access changes storage or growth loses its old prefix.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe lower effects, growth contents and final allocation accounting"
)]
fn inline_growth_and_read_only_mount_preserve_storage_contracts() -> Result<()> {
    let mut fixture = inline_fixture()?;
    let file = fixture.a;
    let filesystem = fixture.disk.filesystem.clone();
    let journal = fixture.disk.journal.clone();
    fixture.disk.storage_effects = 0;
    let (profile, epoch, coordinator) = fixture
        .disk
        .mount(MountAccess::ReadOnly {
            recovery_memory: RecoveryMemoryLimit::DEFAULT,
        })?
        .into_parts();
    fixture.profile = profile;
    fixture.epoch = epoch;
    fixture.coordinator = coordinator;
    fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
    let mut byte = [0];
    assert_eq!(
        fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut byte))?,
        ReadBytes::from_usize(1)
    );
    assert_eq!(byte, *b"a");
    assert_eq!(fixture.disk.storage_effects, 0);
    assert_eq!(fixture.disk.filesystem, filesystem);
    assert_eq!(fixture.disk.journal, journal);
    fixture.remount()?;
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.write_file_range(file, FileOffset::from_bytes(200), b"tail")
    })?;
    fixture.remount()?;
    let mut bytes = [0; 204];
    assert_eq!(
        fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?,
        ReadBytes::from_usize(204)
    );
    assert_eq!(bytes.first(), Some(&b'a'));
    assert!(
        bytes
            .get(1..200)
            .ok_or(Error::DeviceRange)?
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(bytes.get(200..), Some(b"tail".as_slice()));
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.unlink_file(root, &Ext4Name::new(b"concurrent-a")?)
    })?;
    fixture.remount()?;
    Ok(())
}

/// # Errors
/// Propagates independent field/checksum encoding failures.
/// # Panics
/// Fails if an authenticated but missing or undersized body can grant mount authority.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check corruption rejection before lower storage effects"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "checked format-vector fields have exact encoded widths"
)]
fn inline_inode_admission_requires_its_complete_private_body() -> Result<()> {
    for missing_body in [true, false] {
        let mut fixture = inline_fixture()?;
        let node = NodeId::File(fixture.a);
        let offset = fixture_inode_offset(&fixture.disk, node)?;
        if missing_body {
            let start = offset.checked_add(160).ok_or(Error::ArithmeticOverflow)?;
            let end = offset.checked_add(256).ok_or(Error::ArithmeticOverflow)?;
            fixture
                .disk
                .filesystem
                .get_mut(start..end)
                .ok_or(Error::DeviceRange)?
                .fill(0);
        } else {
            let start = offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?;
            let end = start.checked_add(4).ok_or(Error::ArithmeticOverflow)?;
            fixture
                .disk
                .filesystem
                .get_mut(start..end)
                .ok_or(Error::DeviceRange)?
                .copy_from_slice(&200_u32.to_le_bytes());
        }
        fixture.disk.encode_inode(node, 0x1000_0000, None)?;
        fixture.disk.storage_effects = 0;
        assert_eq!(
            fixture.disk.mount(MountAccess::ReadWrite).err(),
            Some(Error::InvalidInode)
        );
        assert_eq!(fixture.disk.storage_effects, 0);
    }
    Ok(())
}

/// # Errors
/// Propagates mount, content, xattr, conversion and remount failures.
/// # Panics
/// Fails if inode-body data leaks, gaps retain bytes, or conversion loses content or ownership.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions directly observe content, allocation and opaque-attribute contracts"
)]
fn inline_file_updates_and_xattr_conversion_preserve_content() -> Result<()> {
    let mut fixture = inline_fixture()?;
    let file = fixture.a;
    let offset = fixture_inode_offset(&fixture.disk, NodeId::File(file))?;
    assert_eq!(
        fixture_u32(
            &fixture.disk.filesystem,
            offset.checked_add(32).ok_or(Error::ArithmeticOverflow)?
        )? & 0x1008_0000,
        0x1000_0000
    );
    assert_eq!(
        fixture_u32(
            &fixture.disk.filesystem,
            offset.checked_add(28).ok_or(Error::ArithmeticOverflow)?
        )?,
        0
    );
    assert!(
        fixture
            .read(|pass| pass.read_xattrs(NodeId::File(file)))?
            .is_empty()
    );
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.write_file_range(file, FileOffset::from_bytes(40), &[b'z'; 61])?;
        pass.truncate_file(file, FileSize::from_bytes(65))?;
        pass.extend_file(file, FileSize::from_bytes(100))
    })?;
    fixture.remount()?;
    let mut expected = [0; 100];
    if let Some(first) = expected.first_mut() {
        *first = b'a';
    }
    expected
        .get_mut(40..65)
        .ok_or(Error::DeviceRange)?
        .fill(b'z');
    let mut actual = [0; 100];
    assert_eq!(
        fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut actual))?,
        ReadBytes::from_usize(100)
    );
    assert_eq!(actual, expected);
    assert_eq!(
        fixture_u32(
            &fixture.disk.filesystem,
            offset.checked_add(32).ok_or(Error::ArithmeticOverflow)?
        )? & 0x1008_0000,
        0x1000_0000
    );
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(file))?;
        pass.set_xattr(
            node,
            XattrName::new(XattrNamespace::User, b"opaque")?,
            XattrValue::new(&[0x73; 512])?,
        )
    })?;
    fixture.remount()?;
    assert_eq!(
        fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut actual))?,
        ReadBytes::from_usize(100)
    );
    assert_eq!(actual, expected);
    assert_eq!(
        fixture_u32(
            &fixture.disk.filesystem,
            offset.checked_add(32).ok_or(Error::ArithmeticOverflow)?
        )? & 0x1008_0000,
        0x0008_0000
    );
    fixture.mutate(|pass| {
        let selected = pass.file(file)?;
        pass.truncate_file(selected, FileSize::from_bytes(1))
    })?;
    fixture.remount()?;
    assert_eq!(
        fixture_u32(
            &fixture.disk.filesystem,
            offset.checked_add(32).ok_or(Error::ArithmeticOverflow)?
        )? & 0x1008_0000,
        0x0008_0000
    );
    Ok(())
}

/// # Errors
/// Propagates directory, namespace, conversion and remount failures.
/// # Panics
/// Fails if two-region traversal, parent updates, growth or deletion loses namespace semantics.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe namespace and storage transitions across remount"
)]
fn inline_directories_enumerate_move_grow_and_delete() -> Result<()> {
    let mut fixture = inline_fixture()?;
    let owner = Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(1000));
    let (directory, other) = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let directory = pass.create_directory(
            root,
            &Ext4Name::new(b"inline-dir")?,
            NewDirectoryMetadata::new(owner, Ext4Permissions::new(0o755)?),
        )?;
        pass.create_file(
            directory,
            &Ext4Name::new(b"first")?,
            NewFileMetadata::new(owner, Ext4Permissions::new(0o644)?),
        )?;
        let other = pass.create_directory(
            root,
            &Ext4Name::new(b"other-inline-dir")?,
            NewDirectoryMetadata::new(owner, Ext4Permissions::new(0o755)?),
        )?;
        Ok((directory.id(), other.id()))
    })?;
    fixture.remount()?;
    let offset = fixture_inode_offset(&fixture.disk, NodeId::Directory(directory))?;
    assert_eq!(
        fixture_u32(
            &fixture.disk.filesystem,
            offset.checked_add(32).ok_or(Error::ArithmeticOverflow)?
        )? & 0x1008_0000,
        0x1000_0000
    );
    let mut reader = DirectoryReader::new(directory, DirectoryScanCursor::start());
    let mut names = Vec::new();
    while let Some(entry) = fixture.read(|pass| pass.next_directory_entry(&mut reader))? {
        names.push(entry.entry().name().bytes().to_vec());
    }
    assert_eq!(names, [b".".to_vec(), b"..".to_vec(), b"first".to_vec()]);
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let other = pass.directory(other)?;
        pass.rename_child(
            root,
            &Ext4Name::new(b"inline-dir")?,
            other,
            &Ext4Name::new(b"moved-inline-dir")?,
            NamespaceDestination::Vacant,
        )
    })?;
    fixture.remount()?;
    assert_eq!(
        fixture_u32(
            &fixture.disk.filesystem,
            offset.checked_add(40).ok_or(Error::ArithmeticOverflow)?
        )?,
        NodeId::Directory(other).file_index()
    );
    fixture.mutate(|pass| {
        let directory = pass.directory(directory)?;
        pass.unlink_file(directory, &Ext4Name::new(b"first")?)?;
        for index in 0..12 {
            let name = format!("entry-{index:02}-large-component");
            pass.create_file(
                directory,
                &Ext4Name::new(name.as_bytes())?,
                NewFileMetadata::new(owner, Ext4Permissions::new(0o644)?),
            )?;
        }
        Ok(())
    })?;
    fixture.remount()?;
    assert_eq!(
        fixture_u32(
            &fixture.disk.filesystem,
            offset.checked_add(32).ok_or(Error::ArithmeticOverflow)?
        )? & 0x1008_0000,
        0x0008_0000
    );
    for index in 0..12 {
        let name = format!("entry-{index:02}-large-component");
        assert!(matches!(
            fixture.read(|pass| pass.lookup_child(directory, &Ext4Name::new(name.as_bytes())?))?,
            ChildLookup::Found(_)
        ));
    }
    fixture.mutate(|pass| {
        let selected = pass.directory(directory)?;
        for index in 0..12 {
            let name = format!("entry-{index:02}-large-component");
            pass.unlink_file(selected, &Ext4Name::new(name.as_bytes())?)?;
        }
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let other = pass.directory(other)?;
        pass.remove_empty_directory(other, &Ext4Name::new(b"moved-inline-dir")?)?;
        pass.remove_empty_directory(root, &Ext4Name::new(b"other-inline-dir")?)
    })?;
    fixture.remount()?;
    Ok(())
}

/// # Errors
/// Returns fixture setup, journal commit, private replay or read failures.
/// # Panics
/// Fails if private replay changes media, loses committed bytes, or grants media mutation.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions directly observe write-free replay through production I/O boundaries"
)]
fn read_only_recovery_preserves_media_and_mount_local_keys() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let (resolved, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket,
        &mut PlainCrypto,
        |pass| {
            let file = pass.file(fixture.a)?;
            pass.write_file_range(file, FileOffset::from_bytes(0), b"private-replay")
        },
    )?;
    let prepared = resolved
        .reserve(
            fixture.coordinator.grant_intent(ticket),
            &fixture.coordinator,
        )?
        .prepare_commit(
            fixture
                .coordinator
                .acquire_commit(ticket)?
                .ok_or(Error::ClusterReferenceConflict)?,
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
        )?;
    let ordered = fixture.disk.sequence(prepared.start())?;
    let payloads = fixture.disk.transfer(ordered.submit())?;
    let payload = fixture.disk.sequence(payloads)?;
    let commit = fixture.disk.transfer(payload.submit())?;
    let durability = fixture.disk.transfer(commit.submit())?;
    drop(fixture.disk.transfer(durability.submit())?);
    let filesystem = fixture.disk.filesystem.clone();
    let journal = fixture.disk.journal.clone();
    fixture.disk.storage_effects = 0;
    assert!(matches!(
        fixture.disk.mount(MountAccess::ReadOnly {
            recovery_memory: RecoveryMemoryLimit::new(1)?
        }),
        Err(Error::RecoveryMemoryLimitExceeded)
    ));
    assert_eq!(fixture.disk.storage_effects, 0);
    assert_eq!(fixture.disk.filesystem, filesystem);
    assert_eq!(fixture.disk.journal, journal);
    let access = MountAccess::ReadOnly {
        recovery_memory: RecoveryMemoryLimit::DEFAULT,
    };
    let (profile, epoch, coordinator) = fixture.disk.mount(access)?.into_parts();
    fixture.profile = profile;
    fixture.epoch = epoch;
    fixture.coordinator = coordinator;
    fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
    let file = fixture.a;
    let read = |pass: &mut EpochReadPass<'_, '_, '_>| {
        let mut bytes = [0; 14];
        let _read = pass.read_file(file, FileOffset::from_bytes(0), &mut bytes)?;
        Ok(bytes)
    };
    assert_eq!(fixture.read(read)?, *b"private-replay");
    let ticket = fixture.coordinator.admit_mutation()?;
    let key = FscryptMasterKey::from_raw(&[7; 32], &mut PlainCrypto)?;
    let change = ResolvedKeyChange::add(&fixture.epoch, &fixture.coordinator, ticket, key)?;
    fixture.publish_keys(change)?;
    assert_eq!(fixture.read(read)?, *b"private-replay");
    assert!(matches!(
        fixture.mutate(|pass| pass.set_volume_label(Ext4VolumeLabel::new(b"denied")?)),
        Err(Error::ReadOnlyFilesystem)
    ));
    let close = Box::try_new(CleanCloseOperation::new(&fixture.profile))
        .map_err(|_| Error::OutOfMemory)?
        .advance(OperationEvent::Admitted);
    assert!(matches!(close, CleanCloseTransition::Complete(Ok(_))));
    assert_eq!(fixture.disk.storage_effects, 0);
    assert_eq!(fixture.disk.filesystem, filesystem);
    assert_eq!(fixture.disk.journal, journal);
    Ok(())
}

/// # Errors
/// Returns fixture construction or mutation resolution failures.
/// # Panics
/// Fails if equal disk UUIDs and local counters let one mount consume another mount's state.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe session isolation through production boundaries"
)]
fn mount_sessions_isolate_plans_grants_and_read_provenance() -> Result<()> {
    let mut origin = Fixture::new()?;
    let mut other = Fixture::new()?;
    assert_eq!(
        origin.epoch.identity().uuid(),
        other.epoch.identity().uuid()
    );
    assert_eq!(origin.epoch.sequence(), other.epoch.sequence());
    assert!(matches!(
        other
            .coordinator
            .read_context(other.cache.access(&origin.epoch)),
        Err(Error::StaleReadContext)
    ));
    let ticket = origin.coordinator.admit_mutation()?;
    let resolve = |fixture: &mut Fixture| {
        fixture
            .disk
            .resolve(
                &fixture.profile,
                &fixture.epoch,
                &fixture.coordinator,
                ticket,
                &mut PlainCrypto,
                |pass| pass.set_volume_label(Ext4VolumeLabel::new(b"scoped")?),
            )
            .map(|(resolved, ())| resolved)
    };
    let resolved = resolve(&mut origin)?;
    assert!(matches!(
        resolved.reserve(other.coordinator.grant_intent(ticket), &other.coordinator),
        Err(Error::ClusterReferenceConflict)
    ));
    let resolved = resolve(&mut origin)?;
    assert!(matches!(
        resolved.reserve(other.coordinator.grant_intent(ticket), &origin.coordinator),
        Err(Error::ClusterReferenceConflict)
    ));
    let reserved = resolve(&mut origin)?
        .reserve(origin.coordinator.grant_intent(ticket), &origin.coordinator)?;
    assert!(matches!(
        reserved.prepare_commit(
            other
                .coordinator
                .acquire_commit(ticket)?
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut origin.coordinator,
            &origin.epoch,
            &mut origin.cache
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    let old_read = EpochReadOperation::new(&origin.profile);
    let old_directory = DirectoryReadOperation::new(
        &origin.profile,
        DirectoryNodeId::ROOT,
        DirectoryScanCursor::start(),
    );
    let old_resolver = MutationResolveOperation::new(&origin.profile);
    let stale_plan = resolve(&mut origin)?;
    origin.remount()?;
    assert!(matches!(
        stale_plan.reserve(origin.coordinator.grant_intent(ticket), &origin.coordinator),
        Err(Error::ClusterReferenceConflict)
    ));
    assert!(matches!(
        old_read.run(
            OperationEvent::Admitted,
            origin
                .coordinator
                .read_context(origin.cache.access(&origin.epoch))?,
            &mut PlainCrypto,
            |_| Ok(())
        ),
        ReadTransition::Complete(Err(Error::ReadConflict))
    ));
    assert!(matches!(
        old_directory.advance(
            OperationEvent::Admitted,
            origin
                .coordinator
                .read_context(origin.cache.access(&origin.epoch))?,
            &mut PlainCrypto
        ),
        DirectoryReadTransition::Complete(Err(Error::ReadConflict))
    ));
    let mut ready = old_resolver.accept(OperationEvent::Admitted)?;
    assert!(matches!(
        ready.begin_pass(
            origin.cache.access(&origin.epoch),
            Ext4Timestamp::from_seconds(2),
            &mut PlainCrypto
        ),
        Err(Error::StaleReadContext)
    ));
    Ok(())
}

/// # Errors
/// Returns fixture, storage, or journal transition failures.
/// # Panics
/// Fails if rejected publication loses the durable mutation or accepts another mount or ticket.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify durable-state retention and publication through real storage"
)]
fn durable_publications_retain_state_after_mismatched_authority() -> Result<()> {
    let mut origin = Fixture::new()?;
    let mut other = Fixture::new()?;
    let ticket = origin.coordinator.admit_mutation()?;
    let (resolved, ()) = origin.disk.resolve(
        &origin.profile,
        &origin.epoch,
        &origin.coordinator,
        ticket,
        &mut PlainCrypto,
        |pass| pass.set_volume_label(Ext4VolumeLabel::new(b"scoped")?),
    )?;
    let prepared = resolved
        .reserve(origin.coordinator.grant_intent(ticket), &origin.coordinator)?
        .prepare_commit(
            origin
                .coordinator
                .acquire_commit(ticket)?
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut origin.coordinator,
            &origin.epoch,
            &mut origin.cache,
        )?;
    let ordered = origin.disk.sequence(prepared.start())?;
    let sequence = origin.disk.transfer(ordered.submit())?;
    let payload = origin.disk.sequence(sequence)?;
    let record = origin.disk.transfer(payload.submit())?;
    let barrier = origin.disk.transfer(record.submit())?;
    let durable = origin.disk.transfer(barrier.submit())?;
    let other_ticket = other.coordinator.admit_mutation()?;
    let (other_resolved, ()) = other.disk.resolve(
        &other.profile,
        &other.epoch,
        &other.coordinator,
        other_ticket,
        &mut PlainCrypto,
        |pass| pass.set_volume_label(Ext4VolumeLabel::new(b"other")?),
    )?;
    let other_prepared = other_resolved
        .reserve(
            other.coordinator.grant_intent(other_ticket),
            &other.coordinator,
        )?
        .prepare_commit(
            other
                .coordinator
                .acquire_commit(other_ticket)?
                .ok_or(Error::ClusterReferenceConflict)?,
            &mut other.coordinator,
            &other.epoch,
            &mut other.cache,
        )?;
    let effects = origin.disk.storage_effects;
    let (error, durable) = durable
        .publish(
            other
                .coordinator
                .acquire_visibility(other_ticket)
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut other.coordinator,
        )
        .err()
        .ok_or(Error::DeviceIo)?;
    assert_eq!(error, Error::ClusterReferenceConflict);
    other_prepared
        .abort(&mut other.coordinator, &mut other.cache)
        .map_err(|(error, _prepared)| error)?;
    let wrong_ticket = origin.coordinator.admit_mutation()?;
    assert!(
        origin
            .coordinator
            .acquire_visibility(wrong_ticket)
            .is_none()
    );
    let (epoch, checkpoint) = durable
        .publish(
            origin
                .coordinator
                .acquire_visibility(ticket)
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut origin.coordinator,
        )
        .map_err(|(error, _durable)| error)?
        .into_parts();
    assert_eq!(origin.disk.storage_effects, effects);
    assert_eq!(epoch.identity().label(), Ext4VolumeLabel::new(b"scoped")?);
    assert!(
        other
            .coordinator
            .acquire_checkpoint(epoch.sequence())
            .is_none()
    );
    assert!(origin.coordinator.acquire_commit(wrong_ticket)?.is_none());
    let sequence = checkpoint
        .start(
            origin
                .coordinator
                .acquire_checkpoint(epoch.sequence())
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
        )
        .map_err(|(error, _checkpoint)| error)?;
    let home = origin.disk.sequence(sequence)?;
    let record = origin.disk.transfer(home.submit())?;
    let barrier = origin.disk.transfer(record.submit())?;
    let publication = origin.disk.transfer(barrier.submit())?;
    let effects = origin.disk.storage_effects;
    let (error, publication) = publication
        .publish(&mut other.coordinator)
        .err()
        .ok_or(Error::DeviceIo)?;
    assert_eq!(error, Error::ClusterReferenceConflict);
    origin.epoch = publication
        .publish(&mut origin.coordinator)
        .map_err(|(error, _publication)| error)?;
    assert_eq!(origin.disk.storage_effects, effects);
    origin.remount()?;
    assert_eq!(
        origin.epoch.identity().label(),
        Ext4VolumeLabel::new(b"scoped")?
    );
    Ok(())
}

/// Independent hashing and HKDF oracle; plaintext fixtures must never invoke a cipher.
#[derive(Debug)]
struct PlainCrypto;

/// # Errors
/// Returns fixture, namespace mutation or read failures.
/// # Panics
/// Fails if exact spelling does not distinguish distinct ext4 byte names.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe ext4 namespace spelling through production passes"
)]
fn exact_namespace_lookup_preserves_distinct_spellings() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let lower = Ext4Name::new("é".as_bytes())?;
    let upper = Ext4Name::new("É".as_bytes())?;
    let file = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.create_file(
            root,
            &lower,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )
        .map(|file| file.id())
    })?;
    assert!(matches!(
        fixture.read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &upper))?,
        ChildLookup::NotFound
    ));
    assert!(
        matches!(fixture.read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &lower))?, ChildLookup::Found(child) if *child.node() == NodeId::File(file))
    );
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.rename_child(root, &lower, root, &upper, NamespaceDestination::Vacant)
    })?;
    assert!(
        matches!(fixture.read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &upper))?, ChildLookup::Found(child) if *child.node() == NodeId::File(file))
    );
    Ok(())
}

/// # Errors
/// Returns fixture, explicit timestamp, namespace, metadata or content mutation failures.
/// # Panics
/// Fails if metadata changes imply file access/content changes, or writes imply reads.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare each timestamp meaning with independent event inputs"
)]
fn inode_timestamps_distinguish_metadata_contents_and_access() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let accessed = Ext4Timestamp::new(100, 10)?;
    let modified = Ext4Timestamp::new(200, 20)?;
    let created = Ext4Timestamp::new(50, 5)?;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(a))?;
        pass.set_times(
            node,
            Ext4Times::new(
                accessed,
                modified,
                Ext4Timestamp::from_seconds(300),
                Some(created),
            ),
        )
    })?;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(a))?;
        pass.set_posix_security(
            node,
            Ext4Security::new(namespace_owner(), Ext4Permissions::new(0o600)?),
        )?;
        pass.set_xattr(
            node,
            XattrName::new(XattrNamespace::User, b"times")?,
            XattrValue::new(b"metadata")?,
        )?;
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let source = pass.hard_link_source(HardLinkNodeId::File(a))?;
        let alias = Ext4Name::new(b"time-alias")?;
        let renamed = Ext4Name::new(b"renamed-alias")?;
        pass.create_hard_link(source, root, &alias, NamespaceDestination::Vacant)?;
        pass.rename_child(root, &alias, root, &renamed, NamespaceDestination::Vacant)?;
        pass.unlink_file(root, &renamed)
    })?;
    let times = fixture.read(|pass| Ok(pass.load_file(a)?.times()))?;
    assert_eq!(times.accessed(), accessed);
    assert_eq!(times.modified(), modified);
    assert_eq!(times.changed(), Ext4Timestamp::from_seconds(2));
    assert_eq!(times.created(), Some(created));
    fixture.mutate(|pass| {
        let a = pass.file(a)?;
        pass.write_file_range(a, FileOffset::ZERO, b"Z")
    })?;
    let times = fixture.read(|pass| Ok(pass.load_file(a)?.times()))?;
    assert_eq!(times.accessed(), accessed);
    assert_eq!(times.modified(), Ext4Timestamp::from_seconds(2));
    assert_eq!(times.changed(), Ext4Timestamp::from_seconds(2));
    assert_eq!(times.created(), Some(created));
    Ok(())
}

/// # Errors
/// Returns fixture, explicit timestamp, namespace or metadata-read failures.
/// # Panics
/// Fails if directory mutation changes access time or new inode timestamps are incomplete.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare directory and creation events with their supplied timestamps"
)]
fn directory_entry_changes_preserve_access_and_initialize_child_times() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let accessed = Ext4Timestamp::new(100, 10)?;
    fixture.mutate(|pass| {
        let root = pass.node(NodeId::Directory(DirectoryNodeId::ROOT))?;
        pass.set_times(
            root,
            Ext4Times::new(
                accessed,
                Ext4Timestamp::from_seconds(300),
                Ext4Timestamp::from_seconds(200),
                None,
            ),
        )
    })?;
    let child = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.create_file(
            root,
            &Ext4Name::new(b"time-child")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )
        .map(|child| child.id())
    })?;
    let times = fixture.read(|pass| Ok(pass.load_directory(DirectoryNodeId::ROOT)?.times()))?;
    assert_eq!(times.accessed(), accessed);
    assert_eq!(times.modified(), Ext4Timestamp::from_seconds(2));
    assert_eq!(times.changed(), Ext4Timestamp::from_seconds(2));
    let times = fixture.read(|pass| Ok(pass.load_file(child)?.times()))?;
    let now = Ext4Timestamp::from_seconds(2);
    assert_eq!(times, Ext4Times::new(now, now, now, Some(now)));
    Ok(())
}

/// # Errors
/// Returns fixture setup, remount, namespace lookup or the independent successor mutation failure.
/// # Panics
/// Fails if a handled failure can publish partial namespace changes or recover staging authority.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe rejected commit authority and unchanged physical storage"
)]
fn handled_staging_failure_revokes_resolution_without_storage_effects() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    fixture
        .disk
        .encode_inode(NodeId::File(a), 0x0008_0010, None)?;
    fixture.remount()?;
    let before = (
        fixture_crc32c(u32::MAX, &fixture.disk.filesystem),
        fixture_crc32c(u32::MAX, &fixture.disk.journal),
    );
    let result = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        match pass.unlink_file(root, &Ext4Name::new(b"concurrent-a")?) {
            Err(Error::OperationSuspended) => return Err(Error::OperationSuspended),
            result => assert_eq!(result, Err(Error::UnsupportedInodeMutation)),
        }
        assert_eq!(
            pass.set_volume_label(Ext4VolumeLabel::new(b"rejected")?),
            Err(Error::UnsupportedInodeMutation),
        );
        Ok(())
    });
    assert_eq!(result, Err(Error::UnsupportedInodeMutation));
    assert_eq!(
        before,
        (
            fixture_crc32c(u32::MAX, &fixture.disk.filesystem),
            fixture_crc32c(u32::MAX, &fixture.disk.journal),
        )
    );
    let found = fixture
        .read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"concurrent-a")?))?;
    assert!(matches!(found, ChildLookup::Found(_)));
    let b = fixture.b;
    fixture.mutate(|pass| {
        let b = pass.file(b)?;
        pass.write_file_range(b, FileOffset::ZERO, b"B")
    })?;
    Ok(())
}

/// # Errors
/// Returns fixture, mutation, durability or payload-read failures.
/// # Panics
/// Fails if released journal images overwrite a successor owner's bytes after checkpoint.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare committed payloads with independent write inputs"
)]
fn block_release_retires_staged_images_across_persistence_policies() -> Result<()> {
    for offset in [FileOffset::ZERO, FileOffset::from_bytes(4096)] {
        let mut fixture = Fixture::new()?;
        let a = fixture.a;
        let b = fixture.b;
        fixture
            .disk
            .encode_inode(NodeId::File(a), 0x0008_4000, None)?;
        fixture.remount()?;
        fixture.mutate(|pass| {
            let a = pass.file(a)?;
            let b = pass.file(b)?;
            pass.write_file_range(a, offset, b"J")?;
            pass.truncate_file(a, FileSize::from_bytes(0))?;
            pass.truncate_file(b, FileSize::from_bytes(0))?;
            pass.write_file_range(b, FileOffset::ZERO, b"NEW")
        })?;
        let mut output = [0; 3];
        fixture.read(|pass| pass.read_file(b, FileOffset::ZERO, &mut output))?;
        assert_eq!(&output, b"NEW");
        fixture.remount()?;
        fixture.read(|pass| pass.read_file(b, FileOffset::ZERO, &mut output))?;
        assert_eq!(&output, b"NEW");
    }
    Ok(())
}

/// # Errors
/// Returns fixture, write-plan, storage-flush, remount or payload-read failures.
/// # Panics
/// Fails if allocation overwrites a committed owner before its retirement is committed.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe the old filesystem after an interrupted commit"
)]
fn allocation_preserves_committed_owners_until_the_retirement_commit() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let b = fixture.b;
    fixture
        .disk
        .encode_inode(NodeId::File(a), 0x0008_4000, None)?;
    fixture.remount()?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let (resolved, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket,
        &mut PlainCrypto,
        |pass| {
            let a = pass.file(a)?;
            let b = pass.file(b)?;
            pass.write_file_range(a, FileOffset::ZERO, b"J")?;
            pass.truncate_file(a, FileSize::from_bytes(0))?;
            pass.truncate_file(b, FileSize::from_bytes(0))?;
            pass.write_file_range(b, FileOffset::ZERO, b"NEW")
        },
    )?;
    let prepared = resolved
        .reserve(
            fixture.coordinator.grant_intent(ticket),
            &fixture.coordinator,
        )?
        .prepare_commit(
            fixture
                .coordinator
                .acquire_commit(ticket)?
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
        )?;
    let ordered = fixture.disk.sequence(prepared.start())?;
    let payload_sequence = fixture.disk.transfer(ordered.submit())?;
    drop(payload_sequence);
    fixture.remount()?;
    for (file, expected) in [(a, b'a'), (b, b'b')] {
        let mut output = [0; 1];
        fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut output))?;
        assert_eq!(output, [expected]);
    }
    Ok(())
}

/// # Errors
/// Returns fixture preparation, parameter construction or read failures.
/// # Panics
/// Fails if an undeclared filesystem feature can publish a verity inode or any storage effect.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe feature admission and unchanged physical storage"
)]
fn verity_requires_filesystem_feature_before_mutation() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    let enable = FsverityEnable::new(
        FsverityHashAlgorithm::Sha256,
        FsverityBlockSize::new(4096)?,
        FsveritySalt::empty(),
        FsveritySignature::empty(),
    );
    let before = (
        fixture_crc32c(u32::MAX, &fixture.disk.filesystem),
        fixture_crc32c(u32::MAX, &fixture.disk.journal),
    );
    assert_eq!(
        fixture.mutate(|pass| {
            let target = pass.file(file)?;
            pass.enable_verity(target, &enable)
        }),
        Err(Error::UnsupportedVerity)
    );
    assert_eq!(
        (
            fixture_crc32c(u32::MAX, &fixture.disk.filesystem),
            fixture_crc32c(u32::MAX, &fixture.disk.journal)
        ),
        before
    );
    Ok(())
}

/// # Errors
/// Returns feature fixture, transaction, Merkle generation or verified read failures.
/// # Panics
/// Fails if verity hashes a prior disk image, loses staged writes, or rejects its signed layout.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare published verified bytes with independent write inputs"
)]
fn verity_covers_staged_ordered_and_journaled_file_images() -> Result<()> {
    for flags in [0x0008_0000, 0x0008_4000] {
        let mut disk = Disk::fixture();
        disk.enable_verity_feature()?;
        let mut fixture = Fixture::from_disk(disk)?;
        let file = fixture.a;
        fixture.disk.encode_inode(NodeId::File(file), flags, None)?;
        fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
        let enable = FsverityEnable::new(
            FsverityHashAlgorithm::Sha256,
            FsverityBlockSize::new(4096)?,
            FsveritySalt::empty(),
            FsveritySignature::new(&[0x30, 2, 5, 0])?,
        );
        let created = fixture.mutate(|pass| {
            let target = pass.file(file)?;
            pass.write_file_range(target, FileOffset::ZERO, b"old")?;
            pass.write_file_range(target, FileOffset::from_bytes(1), b"XYZ")?;
            pass.reserve_file_allocation(target, FileAllocationSize::from_bytes(12_288))?;
            pass.enable_verity(target, &enable)?;
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            let created = pass.create_file(
                root,
                &Ext4Name::new(b"verified")?,
                NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
            )?;
            pass.reserve_file_allocation(created, FileAllocationSize::from_bytes(12_288))?;
            pass.write_file_range(created, FileOffset::from_bytes(8192), b"created")?;
            pass.extend_file(created, FileSize::from_bytes(16_384))?;
            pass.enable_verity(created, &enable)?;
            Ok(created.id())
        })?;
        let mut output = [0; 4];
        assert_eq!(
            fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut output))?,
            ReadBytes::from_usize(4)
        );
        assert_eq!(&output, b"oXYZ");
        let mut output = [0; 7];
        assert_eq!(
            fixture.read(|pass| pass.read_file(
                created,
                FileOffset::from_bytes(8192),
                &mut output
            ))?,
            ReadBytes::from_usize(7)
        );
        assert_eq!(&output, b"created");
        let mut zeroes = [0xff; 8];
        for offset in [0, 4096, 12_288] {
            fixture.read(|pass| {
                pass.read_file(created, FileOffset::from_bytes(offset), &mut zeroes)
            })?;
            assert_eq!(zeroes, [0; 8]);
        }
    }
    Ok(())
}

/// # Errors
/// Returns fixture, independent DAX flag encoding, remount or read failures.
/// # Panics
/// Fails if fs-verity enablement publishes a DAX/verity inode or issues any storage effect.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify the incompatible feature transition and unchanged durable storage"
)]
fn verity_rejects_dax_without_storage_effects() -> Result<()> {
    let mut disk = Disk::fixture();
    disk.enable_verity_feature()?;
    let mut fixture = Fixture::from_disk(disk)?;
    let file = fixture.a;
    fixture
        .disk
        .encode_inode(NodeId::File(file), 0x0208_0000, None)?;
    fixture.remount()?;
    fixture.mutate(|pass| {
        let target = pass.file(file)?;
        pass.write_file_range(target, FileOffset::ZERO, b"DAX")
    })?;
    let before = (
        fixture_crc32c(u32::MAX, &fixture.disk.filesystem),
        fixture_crc32c(u32::MAX, &fixture.disk.journal),
        fixture.disk.storage_effects,
    );
    let enable = FsverityEnable::new(
        FsverityHashAlgorithm::Sha256,
        FsverityBlockSize::new(4096)?,
        FsveritySalt::empty(),
        FsveritySignature::empty(),
    );
    assert_eq!(
        fixture.mutate(|pass| {
            let target = pass.file(file)?;
            pass.enable_verity(target, &enable)
        }),
        Err(Error::UnsupportedInodeMutation)
    );
    assert_eq!(
        (
            fixture_crc32c(u32::MAX, &fixture.disk.filesystem),
            fixture_crc32c(u32::MAX, &fixture.disk.journal),
            fixture.disk.storage_effects,
        ),
        before
    );
    let mut output = [0; 3];
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut output))?;
    assert_eq!(&output, b"DAX");
    Ok(())
}

/// # Errors
/// Returns mount, write, durability or read failures while recovering an interrupted extension.
/// # Panics
/// Fails if data flushed without an EOF commit becomes visible through sparse extension.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe bytes after an independently interrupted persistence boundary"
)]
fn sparse_extension_zeroes_initialized_storage_after_interrupted_write() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    let ticket = fixture.coordinator.admit_mutation()?;
    let (resolved, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket,
        &mut PlainCrypto,
        |pass| {
            let target = pass.file(file)?;
            pass.write_file_range(target, FileOffset::from_bytes(1), b"SECRET")
        },
    )?;
    let prepared = resolved
        .reserve(
            fixture.coordinator.grant_intent(ticket),
            &fixture.coordinator,
        )?
        .prepare_commit(
            fixture
                .coordinator
                .acquire_commit(ticket)?
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
        )?;
    {
        let ordered = fixture.disk.sequence(prepared.start())?;
        let _payload_sequence = fixture.disk.transfer(ordered.submit())?;
        // A crash loses preparation and publication state after data reaches its home block.
    }
    let (profile, epoch, coordinator) = fixture.disk.mount(MountAccess::ReadWrite)?.into_parts();
    fixture.profile = profile;
    fixture.cache = MetadataCache::try_new(&epoch)?;
    fixture.epoch = epoch;
    fixture.coordinator = coordinator;
    assert_eq!(
        fixture.read(|pass| Ok(pass.load_file(file)?.size()))?,
        FileSize::from_bytes(1)
    );
    fixture.mutate(|pass| {
        let target = pass.file(file)?;
        pass.extend_file(target, FileSize::from_bytes(7))
    })?;
    let mut bytes = [0xff; 7];
    assert_eq!(
        fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?,
        ReadBytes::from_usize(7)
    );
    assert_eq!(bytes, [b'a', 0, 0, 0, 0, 0, 0]);
    Ok(())
}

/// # Errors
/// Returns storage, journal, or read failure while exercising the production commit protocol.
/// # Panics
/// Fails if journaled bytes reach home early or are absent from the published epoch overlay.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe physical storage and published reads across the commit boundary"
)]
fn journaled_file_data_publishes_before_home_checkpoint() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    fixture
        .disk
        .encode_inode(NodeId::File(file), 0x0008_4000, None)?;
    fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
    let mut byte = [0];
    let (_read, request) = fixture.suspend_payload(file, &mut byte)?;
    let home = usize::try_from(request.offset().ok_or(Error::DeviceRange)?.get())
        .map_err(|_| Error::DeviceRange)?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let (resolved, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket,
        &mut PlainCrypto,
        |pass| {
            let target = pass.file(file)?;
            pass.write_file_range(target, FileOffset::ZERO, b"J")?;
            pass.write_file_range(target, FileOffset::ZERO, b"K")
        },
    )?;
    let ready = resolved
        .reserve(
            fixture.coordinator.grant_intent(ticket),
            &fixture.coordinator,
        )?
        .prepare_commit(
            fixture
                .coordinator
                .acquire_commit(ticket)?
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
        )?;
    let StorageRequestSequenceStep::Finished(ordered) = ready.start().advance() else {
        return Err(Error::InvalidWriteRange);
    };
    let payload_sequence = fixture.disk.transfer(ordered.submit())?;
    let payload = fixture.disk.sequence(payload_sequence)?;
    let commit_record = fixture.disk.transfer(payload.submit())?;
    let durability = fixture.disk.transfer(commit_record.submit())?;
    let durable = fixture.disk.transfer(durability.submit())?;
    assert_eq!(fixture.disk.filesystem.get(home), Some(&b'a'));
    let (epoch, checkpoint) = durable
        .publish(
            fixture
                .coordinator
                .acquire_visibility(ticket)
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut fixture.coordinator,
        )
        .map_err(|(error, _durable)| error)?
        .into_parts();
    fixture.epoch = epoch;
    fixture.cache.publish(&fixture.epoch);
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut byte))?;
    assert_eq!(byte, *b"K");
    assert_eq!(fixture.disk.filesystem.get(home), Some(&b'a'));
    let home_writes = fixture.disk.sequence(
        checkpoint
            .start(
                fixture
                    .coordinator
                    .acquire_checkpoint(fixture.epoch.sequence())
                    .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            )
            .map_err(|(error, _checkpoint)| error)?,
    )?;
    let clean_record = fixture.disk.transfer(home_writes.submit())?;
    let clean_durability = fixture.disk.transfer(clean_record.submit())?;
    let clean = fixture.disk.transfer(clean_durability.submit())?;
    fixture.epoch = clean
        .publish(&mut fixture.coordinator)
        .map_err(|(error, _publication)| error)?;
    assert_eq!(fixture.disk.filesystem.get(home), Some(&b'K'));
    Ok(())
}

impl CryptographicOperation for PlainCrypto {
    fn fill_random(&mut self, _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn hkdf_sha512(&mut self, key: &[u8], info: &[u8], output: &mut [u8]) -> Result<()> {
        hkdf::Hkdf::<sha2::Sha512>::new(None, key)
            .expand(info, output)
            .map_err(|_| Error::CryptographicFailure)
    }
    fn encrypt_aes_256_xts(&mut self, _: &[u8; 64], _: u64, _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn decrypt_aes_256_xts(&mut self, _: &[u8; 64], _: u64, _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn encrypt_aes_256_cbc_cs3(&mut self, _: &[u8; 32], _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn decrypt_aes_256_cbc_cs3(&mut self, _: &[u8; 32], _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn sha256(&mut self, bytes: &[u8]) -> Result<[u8; 32]> {
        Ok(sha2::Sha256::digest(bytes).into())
    }
    fn sha512(&mut self, bytes: &[u8]) -> Result<[u8; 64]> {
        Ok(sha2::Sha512::digest(bytes).into())
    }
}

/// Reversible cipher stand-in for inode-context routing, not a cryptographic conformance oracle.
/// Its key- and data-unit-dependent bytes expose a stale nonce or incorrect key selection.
#[derive(Debug)]
struct ContextCrypto {
    /// Distinct deterministic nonce supplied to each attempted inode construction.
    nonce: u8,
}

impl CryptographicOperation for ContextCrypto {
    fn fill_random(&mut self, bytes: &mut [u8]) -> Result<()> {
        self.nonce = self.nonce.wrapping_add(1);
        bytes.fill(self.nonce);
        Ok(())
    }
    fn hkdf_sha512(&mut self, key: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        PlainCrypto.hkdf_sha512(key, info, out)
    }
    fn encrypt_aes_256_xts(&mut self, key: &[u8; 64], unit: u64, bytes: &mut [u8]) -> Result<()> {
        context_cipher(key, unit, bytes)
    }
    fn decrypt_aes_256_xts(&mut self, key: &[u8; 64], unit: u64, bytes: &mut [u8]) -> Result<()> {
        context_cipher(key, unit, bytes)
    }
    fn encrypt_aes_256_cbc_cs3(&mut self, key: &[u8; 32], bytes: &mut [u8]) -> Result<()> {
        context_cipher(key, 0, bytes)
    }
    fn decrypt_aes_256_cbc_cs3(&mut self, key: &[u8; 32], bytes: &mut [u8]) -> Result<()> {
        context_cipher(key, 0, bytes)
    }
    fn sha256(&mut self, bytes: &[u8]) -> Result<[u8; 32]> {
        PlainCrypto.sha256(bytes)
    }
    fn sha512(&mut self, bytes: &[u8]) -> Result<[u8; 64]> {
        PlainCrypto.sha512(bytes)
    }
}

/// Applies the test provider's reversible transform with independent key and unit coordinates.
/// # Errors
/// Returns an invalid provider key or arithmetic failure.
fn context_cipher(key: &[u8], unit: u64, bytes: &mut [u8]) -> Result<()> {
    let unit = unit.to_le_bytes();
    for (position, byte) in bytes.iter_mut().enumerate() {
        let key_position = position
            .checked_rem(key.len())
            .ok_or(Error::CryptographicFailure)?;
        let unit_position = position
            .checked_rem(unit.len())
            .ok_or(Error::CryptographicFailure)?;
        *byte ^= *key.get(key_position).ok_or(Error::CryptographicFailure)?
            ^ *unit.get(unit_position).ok_or(Error::CryptographicFailure)?;
    }
    Ok(())
}

/// Only these private in-memory copies are mutated; tracked fixture images remain inputs.
#[derive(Debug)]
struct Disk {
    filesystem: Vec<u8>,
    journal: Vec<u8>,
    /// Submitted writes and flushes, including requests made before mount publication.
    storage_effects: usize,
}

impl Disk {
    /// Declares verity support using independent raw superblock fields before mounting.
    /// # Errors
    /// Returns an error when the fixture does not contain the declared superblock fields.
    #[expect(
        clippy::disallowed_methods,
        reason = "checked four-byte fixture fields receive exactly four independently encoded bytes"
    )]
    fn enable_verity_feature(&mut self) -> Result<()> {
        let features = u32::from_le_bytes(
            self.filesystem
                .get(1124..1128)
                .ok_or(Error::InvalidSuperblock)?
                .try_into()
                .map_err(|_| Error::InvalidSuperblock)?,
        );
        self.filesystem
            .get_mut(1124..1128)
            .ok_or(Error::InvalidSuperblock)?
            .copy_from_slice(&(features | 0x8000).to_le_bytes());
        let checksum = fixture_crc32c(
            u32::MAX,
            self.filesystem
                .get(1024..2044)
                .ok_or(Error::InvalidSuperblock)?,
        );
        self.filesystem
            .get_mut(2044..2048)
            .ok_or(Error::InvalidSuperblock)?
            .copy_from_slice(&checksum.to_le_bytes());
        Ok(())
    }

    /// Encodes flags and a private encryption xattr in the independent 4 KiB/256-byte fixture.
    /// Its inode-table address and CRC32C computation come from the disk format, not core encoders.
    /// # Errors
    /// Returns an invalid fixture layout or an out-of-range encoded field.
    fn encode_inode(&mut self, node: NodeId, flags: u32, context: Option<&[u8; 40]>) -> Result<()> {
        self.encode_inode_number(node.file_index(), flags, context)
    }

    /// Seals independently edited namespace or attribute inode fields.
    /// # Errors
    /// Propagates fixture bounds and checksum-field failures.
    #[expect(
        clippy::disallowed_methods,
        reason = "checked fixture field copies have equal lengths"
    )]
    fn encode_inode_number(
        &mut self,
        number: u32,
        flags: u32,
        context: Option<&[u8; 40]>,
    ) -> Result<()> {
        let index = usize::try_from(number.checked_sub(1).ok_or(Error::InvalidInode)?)
            .map_err(|_| Error::ArithmeticOverflow)?;
        let start = index
            .checked_mul(256)
            .and_then(|offset| offset.checked_add(35 * 4096))
            .ok_or(Error::ArithmeticOverflow)?;
        let end = start.checked_add(256).ok_or(Error::ArithmeticOverflow)?;
        let uuid = self
            .filesystem
            .get(1128..1144)
            .ok_or(Error::InvalidSuperblock)?
            .to_vec();
        let record = self
            .filesystem
            .get_mut(start..end)
            .ok_or(Error::InvalidInode)?;
        record
            .get_mut(32..36)
            .ok_or(Error::InvalidInode)?
            .copy_from_slice(&flags.to_le_bytes());
        if let Some(context) = context {
            record
                .get_mut(128..130)
                .ok_or(Error::InvalidInode)?
                .copy_from_slice(&32_u16.to_le_bytes());
            record.get_mut(160..).ok_or(Error::InvalidInode)?.fill(0);
            record
                .get_mut(160..164)
                .ok_or(Error::InvalidInode)?
                .copy_from_slice(&0xea02_0000_u32.to_le_bytes());
            *record.get_mut(164).ok_or(Error::InvalidInode)? = 1;
            *record.get_mut(165).ok_or(Error::InvalidInode)? = 9;
            record
                .get_mut(166..168)
                .ok_or(Error::InvalidInode)?
                .copy_from_slice(&52_u16.to_le_bytes());
            record
                .get_mut(172..176)
                .ok_or(Error::InvalidInode)?
                .copy_from_slice(&40_u32.to_le_bytes());
            *record.get_mut(180).ok_or(Error::InvalidInode)? = b'c';
            record
                .get_mut(216..256)
                .ok_or(Error::InvalidInode)?
                .copy_from_slice(context);
        }
        let generation = record.get(100..104).ok_or(Error::InvalidInode)?.to_vec();
        record.get_mut(124..126).ok_or(Error::InvalidInode)?.fill(0);
        record.get_mut(130..132).ok_or(Error::InvalidInode)?.fill(0);
        let crc = fixture_crc32c(
            fixture_crc32c(
                fixture_crc32c(fixture_crc32c(u32::MAX, &uuid), &number.to_le_bytes()),
                &generation,
            ),
            record,
        );
        let checksum = crc.to_le_bytes();
        record
            .get_mut(124..126)
            .ok_or(Error::InvalidInode)?
            .copy_from_slice(checksum.get(..2).ok_or(Error::InvalidInode)?);
        record
            .get_mut(130..132)
            .ok_or(Error::InvalidInode)?
            .copy_from_slice(checksum.get(2..).ok_or(Error::InvalidInode)?);
        if context.is_some() {
            let mut features = [0_u8; 4];
            features.copy_from_slice(
                self.filesystem
                    .get(1120..1124)
                    .ok_or(Error::InvalidSuperblock)?,
            );
            self.filesystem
                .get_mut(1120..1124)
                .ok_or(Error::InvalidSuperblock)?
                .copy_from_slice(&(u32::from_le_bytes(features) | 0x0001_0000).to_le_bytes());
            let crc = fixture_crc32c(
                u32::MAX,
                self.filesystem
                    .get(1024..2044)
                    .ok_or(Error::InvalidSuperblock)?,
            );
            self.filesystem
                .get_mut(2044..2048)
                .ok_or(Error::InvalidSuperblock)?
                .copy_from_slice(&crc.to_le_bytes());
        }
        Ok(())
    }

    fn fixture() -> Self {
        Self {
            filesystem: include_bytes!(
                "../../../tools/xtask/fixtures/journal/external-4k-v3-64.filesystem.img"
            )
            .to_vec(),
            journal: include_bytes!(
                "../../../tools/xtask/fixtures/journal/external-4k-v3-64.journal.img"
            )
            .to_vec(),
            storage_effects: 0,
        }
    }

    /// # Errors
    /// Returns an invalid device range before copying a malformed transfer.
    fn complete(&mut self, mut request: StorageRequest) -> Result<StorageCompletion> {
        if !matches!(request, StorageRequest::Read { .. }) {
            self.storage_effects = self
                .storage_effects
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        let image = match request.target() {
            StorageTarget::Filesystem => &mut self.filesystem,
            StorageTarget::ExternalJournal => &mut self.journal,
        };
        match &mut request {
            StorageRequest::Read { offset, buffer, .. }
            | StorageRequest::Write { offset, buffer, .. } => {
                let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
                let end = start.checked_add(buffer.len()).ok_or(Error::DeviceRange)?;
                let range = image.get_mut(start..end).ok_or(Error::DeviceRange)?;
                #[expect(
                    clippy::disallowed_methods,
                    reason = "the checked image range is constructed with the exact request buffer length before either copy"
                )]
                match &mut request {
                    StorageRequest::Read { buffer, .. } => buffer.copy_from_slice(range),
                    StorageRequest::Write { buffer, .. } => range.copy_from_slice(buffer),
                    StorageRequest::Flush { .. } => return Err(Error::DeviceIo),
                }
            }
            StorageRequest::Flush { .. } => {}
        }
        let length = request.byte_count();
        Ok(StorageCompletion::success(
            CompletedStorageTransfer::from_request(request),
            length,
        ))
    }

    /// # Errors
    /// Returns a mount, external-journal discovery, or storage failure.
    fn mount(&mut self, access: MountAccess) -> Result<CompletedMount> {
        let length = u64::try_from(self.filesystem.len()).map_err(|_| Error::DeviceRange)?;
        let mut probe = Box::try_new(ext4_core::MountProbeOperation::new(
            DeviceLength::from_bytes(length),
        ))
        .map_err(|_| Error::OutOfMemory)?
        .advance(OperationEvent::Admitted);
        let prepared = loop {
            probe = match probe {
                ext4_core::MountProbeTransition::SubmitLower { request, suspended } => {
                    suspended.advance(OperationEvent::StorageCompleted(self.complete(request)?))
                }
                ext4_core::MountProbeTransition::Complete(result) => break result?,
            };
        };
        let mut step = Box::try_new(prepared.start(FscryptKeySet::empty(), access))
            .map_err(|_| Error::OutOfMemory)?
            .advance(OperationEvent::Admitted);
        loop {
            step = match step {
                MountTransition::SubmitLower { request, suspended } => {
                    suspended.advance(OperationEvent::StorageCompleted(self.complete(request)?))
                }
                MountTransition::Complete(result) => return result.map(|mounted| *mounted),
                MountTransition::DiscoverExternalJournal {
                    requirement,
                    suspended,
                } => {
                    let length =
                        u64::try_from(self.journal.len()).map_err(|_| Error::DeviceRange)?;
                    let mut probe = Box::try_new(ExternalJournalProbeOperation::new(
                        requirement,
                        DeviceLength::from_bytes(length),
                    ))
                    .map_err(|_| Error::OutOfMemory)?
                    .advance(OperationEvent::Admitted);
                    let journal = loop {
                        probe = match probe {
                            ExternalJournalProbeTransition::SubmitLower { request, suspended } => {
                                suspended.advance(OperationEvent::StorageCompleted(
                                    self.complete(request)?,
                                ))
                            }
                            ExternalJournalProbeTransition::Complete(result) => match result? {
                                ExternalJournalProbeOutcome::Match(journal) => break journal,
                                ExternalJournalProbeOutcome::Mismatch => {
                                    return Err(Error::UnsupportedJournal);
                                }
                            },
                        };
                    };
                    suspended.attach_external_journal(journal)
                }
            };
        }
    }

    /// # Errors
    /// Returns a transfer validation failure without hiding I/O progress.
    fn transfer<N>(
        &mut self,
        (request, pending): (StorageRequest, PendingStorageTransfer<N>),
    ) -> Result<N> {
        pending.complete(self.complete(request)?)
    }

    /// # Errors
    /// Returns the first failed transfer in the production sequence.
    fn sequence<N>(&mut self, mut sequence: StorageRequestSequence<N>) -> Result<N> {
        loop {
            match sequence.advance() {
                StorageRequestSequenceStep::Submit { request, suspended } => {
                    sequence = suspended.complete(self.complete(request)?)?;
                }
                StorageRequestSequenceStep::Finished(next) => return Ok(next),
            }
        }
    }

    /// # Errors
    /// Returns any commit/checkpoint failure; these tests never retry a partially effected commit.
    fn commit(
        &mut self,
        coordinator: &mut MutationCoordinatorState,
        cache: &mut MetadataCache,
        ticket: u64,
        prepared: CommitReadyMutation,
    ) -> Result<CommittedEpoch> {
        let ordered = self.sequence(prepared.start())?;
        let payload_sequence = self.transfer(ordered.submit())?;
        let payload = self.sequence(payload_sequence)?;
        let commit_record = self.transfer(payload.submit())?;
        let durability = self.transfer(commit_record.submit())?;
        let durable = self.transfer(durability.submit())?;
        let (epoch, checkpoint) = durable
            .publish(
                coordinator
                    .acquire_visibility(ticket)
                    .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
                coordinator,
            )
            .map_err(|(error, _durable)| error)?
            .into_parts();
        cache.publish(&epoch);
        let home = self.sequence(
            checkpoint
                .start(
                    coordinator
                        .acquire_checkpoint(epoch.sequence())
                        .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
                )
                .map_err(|(error, _checkpoint)| error)?,
        )?;
        let clean_record = self.transfer(home.submit())?;
        let clean_durability = self.transfer(clean_record.submit())?;
        let clean = self.transfer(clean_durability.submit())?;
        let epoch = clean
            .publish(coordinator)
            .map_err(|(error, _publication)| error)?;
        cache.publish(&epoch);
        Ok(epoch)
    }

    /// # Errors
    /// Returns read/resolve failure before constructing a mutation with matching epoch versions.
    fn resolve<F, R>(
        &mut self,
        profile: &MountedProfile,
        epoch: &CommittedEpoch,
        coordinator: &MutationCoordinatorState,
        ticket: u64,
        crypto: &mut dyn CryptographicOperation,
        mut mutate: F,
    ) -> Result<(ResolvedMutation, R)>
    where
        F: for<'storage, 'epoch, 'crypto> FnMut(
            &mut MutationResolvePass<'storage, 'epoch, 'crypto>,
        ) -> Result<R>,
    {
        let mut operation = MutationResolveOperation::new(profile);
        let mut event = OperationEvent::Admitted;
        let mut cache = MetadataCache::default();
        loop {
            let mut ready = operation.accept(event)?;
            let mut output = None;
            let result = {
                let mut pass = ready.begin_pass(
                    cache.access(epoch),
                    Ext4Timestamp::from_seconds(2),
                    crypto,
                )?;
                mutate(&mut pass).and_then(|value| {
                    output = Some(value);
                    pass.resolve(ticket, coordinator)
                })
            };
            match ready.finish(result) {
                MutationResolveTransition::SubmitLower { request, suspended } => {
                    event = OperationEvent::StorageCompleted(self.complete(request)?);
                    operation = suspended;
                }
                MutationResolveTransition::Complete(result) => {
                    return Ok((result?, output.ok_or(Error::DeviceIo)?));
                }
            }
        }
    }
}

/// One mount owns current publication, coordinator, and storage independently.
struct Fixture {
    disk: Disk,
    profile: MountedProfile,
    epoch: CommittedEpoch,
    coordinator: MutationCoordinatorState,
    cache: MetadataCache,
    /// Operation-owned provider; plaintext tests reject unexpected cipher execution.
    crypto: Box<dyn CryptographicOperation>,
    a: FileNodeId,
    b: FileNodeId,
}

impl Fixture {
    /// Replaces mount-local state with independently recovered storage state.
    /// # Errors
    /// Returns mount recovery or cache allocation failure.
    fn remount(&mut self) -> Result<()> {
        let (profile, epoch, coordinator) = self.disk.mount(MountAccess::ReadWrite)?.into_parts();
        self.profile = profile;
        self.cache = MetadataCache::try_new(&epoch)?;
        self.epoch = epoch;
        self.coordinator = coordinator;
        Ok(())
    }
    /// Publishes mount-local key state without passing any request to the disk executor.
    /// # Errors
    /// Returns stale authority or allocation failure before publication.
    fn publish_keys(&mut self, change: ResolvedKeyChange) -> Result<()> {
        let ticket = change.observed_resources().ticket();
        let prepared = change
            .reserve(self.coordinator.grant_intent(ticket), &self.coordinator)?
            .prepare(
                self.coordinator
                    .acquire_commit(ticket)?
                    .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
                &mut self.coordinator,
                &self.epoch,
            )?;
        self.epoch = prepared
            .publish(
                self.coordinator
                    .acquire_visibility(ticket)
                    .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
                &mut self.coordinator,
            )
            .map_err(|(error, _prepared)| error)?;
        self.cache.publish(&self.epoch);
        Ok(())
    }

    /// Reads through the production completion-driven boundary without staging a mutation.
    /// # Errors
    /// Returns read admission, storage, or requested-domain failures.
    fn read<F, R>(&mut self, mut read: F) -> Result<R>
    where
        F: for<'pass, 'storage, 'epoch> FnMut(
            &mut EpochReadPass<'pass, 'storage, 'epoch>,
        ) -> Result<R>,
    {
        let mut operation = EpochReadOperation::new(&self.profile);
        let mut event = OperationEvent::Admitted;
        loop {
            match operation.run(
                event,
                self.coordinator
                    .read_context(self.cache.access(&self.epoch))?,
                self.crypto.as_mut(),
                |pass| read(pass),
            ) {
                ReadTransition::SubmitLower { request, suspended } => {
                    event = OperationEvent::StorageCompleted(self.disk.complete(request)?);
                    operation = suspended;
                }
                ReadTransition::Complete(result) => return result,
            }
        }
    }

    /// # Errors
    /// Returns fixture mount, allocation, create, write, or commit failure.
    fn new() -> Result<Self> {
        Self::from_disk(Disk::fixture())
    }

    /// Mounts and populates an independently selected disk image.
    /// # Errors
    /// Returns fixture mount, namespace, payload or commit failure.
    fn from_disk(mut disk: Disk) -> Result<Self> {
        let (profile, epoch, mut coordinator) = disk.mount(MountAccess::ReadWrite)?.into_parts();
        let ticket = coordinator.admit_mutation()?;
        let (resolved, (a, b)) = disk.resolve(
            &profile,
            &epoch,
            &coordinator,
            ticket,
            &mut PlainCrypto,
            |pass| {
                let root = pass.directory(DirectoryNodeId::ROOT)?;
                let metadata = NewFileMetadata::new(
                    Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(1000)),
                    Ext4Permissions::new(0o644)?,
                );
                let a = pass.create_file(root, &Ext4Name::new(b"concurrent-a")?, metadata)?;
                let b = pass.create_file(root, &Ext4Name::new(b"concurrent-b")?, metadata)?;
                pass.write_file_range(a, FileOffset::ZERO, b"a")?;
                pass.write_file_range(b, FileOffset::ZERO, b"b")?;
                Ok((a.id(), b.id()))
            },
        )?;
        let mut cache = MetadataCache::try_new(&epoch)?;
        let ready = resolved
            .reserve(coordinator.grant_intent(ticket), &coordinator)?
            .prepare_commit(
                coordinator
                    .acquire_commit(ticket)?
                    .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
                &mut coordinator,
                &epoch,
                &mut cache,
            )?;
        let epoch = disk.commit(&mut coordinator, &mut cache, ticket, ready)?;
        Ok(Self {
            disk,
            profile,
            epoch,
            coordinator,
            cache,
            crypto: Box::try_new(PlainCrypto).map_err(|_| Error::OutOfMemory)?,
            a,
            b,
        })
    }

    /// # Errors
    /// Returns a pre-write mutation failure or a commit failure without automatically retrying it.
    fn mutate<F, R>(&mut self, mutate: F) -> Result<R>
    where
        F: for<'storage, 'epoch, 'crypto> FnMut(
            &mut MutationResolvePass<'storage, 'epoch, 'crypto>,
        ) -> Result<R>,
    {
        let ticket = self.coordinator.admit_mutation()?;
        let (resolved, output) = self.disk.resolve(
            &self.profile,
            &self.epoch,
            &self.coordinator,
            ticket,
            self.crypto.as_mut(),
            mutate,
        )?;
        let ready = resolved
            .reserve(self.coordinator.grant_intent(ticket), &self.coordinator)?
            .prepare_commit(
                self.coordinator
                    .acquire_commit(ticket)?
                    .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
                &mut self.coordinator,
                &self.epoch,
                &mut self.cache,
            )?;
        self.epoch = self
            .disk
            .commit(&mut self.coordinator, &mut self.cache, ticket, ready)?;
        Ok(output)
    }

    /// # Errors
    /// Returns read failure or unexpected completion before the fixture's one-byte payload I/O.
    fn suspend_payload(
        &mut self,
        file: FileNodeId,
        output: &mut [u8; 1],
    ) -> Result<(EpochReadOperation, StorageRequest)> {
        let mut read = EpochReadOperation::new(&self.profile);
        let mut event = OperationEvent::Admitted;
        loop {
            match read.run(
                event,
                self.coordinator
                    .read_context(self.cache.access(&self.epoch))?,
                self.crypto.as_mut(),
                |pass| pass.read_file(file, FileOffset::ZERO, output),
            ) {
                ReadTransition::SubmitLower { request, suspended } if request.byte_count() == 1 => {
                    return Ok((suspended, request));
                }
                ReadTransition::SubmitLower { request, suspended } => {
                    event = OperationEvent::StorageCompleted(self.disk.complete(request)?);
                    read = suspended;
                }
                ReadTransition::Complete(result) => {
                    result?;
                    return Err(Error::DeviceIo);
                }
            }
        }
    }
}

/// # Errors
/// Returns a fixture, resolve, or commit failure.
/// # Panics
/// Fails when a neighboring inode update erases a previously committed file size.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fallible setup is separate from concurrent publication assertions"
)]
fn shared_metadata_images_revalidate_before_overwriting_neighbors() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let b = fixture.b;
    let ticket_a = fixture.coordinator.admit_mutation()?;
    let ticket_b = fixture.coordinator.admit_mutation()?;
    let (a_update, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket_a,
        &mut PlainCrypto,
        |pass| {
            let file = pass.file(a)?;
            pass.write_file_range(file, FileOffset::from_bytes(1), b"AAA")
        },
    )?;
    let (b_update, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket_b,
        &mut PlainCrypto,
        |pass| {
            let file = pass.file(b)?;
            pass.write_file_range(file, FileOffset::from_bytes(1), b"BBB")
        },
    )?;
    let a_resources = a_update
        .observed_resources()
        .resources()
        .collect::<Vec<_>>();
    assert!(
        b_update
            .observed_resources()
            .resources()
            .any(|resource| a_resources.contains(&resource))
    );
    let ready = a_update
        .reserve(
            fixture.coordinator.grant_intent(ticket_a),
            &fixture.coordinator,
        )?
        .prepare_commit(
            fixture
                .coordinator
                .acquire_commit(ticket_a)?
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
        )?;
    fixture.epoch = fixture.disk.commit(
        &mut fixture.coordinator,
        &mut fixture.cache,
        ticket_a,
        ready,
    )?;
    assert!(matches!(
        b_update.reserve(
            fixture.coordinator.grant_intent(ticket_b),
            &fixture.coordinator
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    fixture.mutate(|pass| {
        let file = pass.file(b)?;
        pass.write_file_range(file, FileOffset::from_bytes(1), b"BBB")
    })?;
    let mut operation = EpochReadOperation::new(&fixture.profile);
    let mut event = OperationEvent::Admitted;
    let mut a_bytes = [0_u8; 4];
    let mut b_bytes = [0_u8; 4];
    loop {
        match operation.run(
            event,
            fixture
                .coordinator
                .read_context(fixture.cache.access(&fixture.epoch))?,
            &mut PlainCrypto,
            |pass| {
                pass.read_file(a, FileOffset::ZERO, &mut a_bytes)?;
                pass.read_file(b, FileOffset::ZERO, &mut b_bytes)?;
                Ok((pass.load_file(a)?.size(), pass.load_file(b)?.size()))
            },
        ) {
            ReadTransition::SubmitLower { request, suspended } => {
                event = OperationEvent::StorageCompleted(fixture.disk.complete(request)?);
                operation = suspended;
            }
            ReadTransition::Complete(result) => {
                assert_eq!(result?, (FileSize::from_bytes(4), FileSize::from_bytes(4)));
                assert_eq!(a_bytes, *b"aAAA");
                assert_eq!(b_bytes, *b"bBBB");
                return Ok(());
            }
        }
    }
}

/// # Errors
/// Returns fixture or mutation failure.
/// # Panics
/// Fails when a suspended reader interprets bytes after its inode releases their physical block.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture mutation is separate from read isolation assertions"
)]
fn block_reuse_revokes_the_suspended_read_before_copying_data() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut output = [0_u8; 1];
    let a = fixture.a;
    let (read, request) = fixture.suspend_payload(a, &mut output)?;
    fixture.mutate(|pass| {
        let file = pass.file(a)?;
        pass.truncate_file(file, FileSize::from_bytes(0))
    })?;
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let metadata = NewFileMetadata::new(
            Ext4Owner::new(Ext4Uid::from_u32(2000), Ext4Gid::from_u32(2000)),
            Ext4Permissions::new(0o600)?,
        );
        let file = pass.create_file(root, &Ext4Name::new(b"concurrent-c")?, metadata)?;
        pass.write_file_range(file, FileOffset::ZERO, b"C")
    })?;
    let completion = fixture.disk.complete(request)?;
    match read.run(
        OperationEvent::StorageCompleted(completion),
        fixture
            .coordinator
            .read_context(fixture.cache.access(&fixture.epoch))?,
        &mut PlainCrypto,
        |pass| pass.read_file(a, FileOffset::ZERO, &mut output),
    ) {
        ReadTransition::Complete(result) => assert_eq!(result, Err(Error::ReadConflict)),
        ReadTransition::SubmitLower { .. } => return Err(Error::DeviceIo),
    }
    assert_eq!(output, [0]);
    Ok(())
}

/// # Errors
/// Returns fixture or mutation failure.
/// # Panics
/// Fails when publication on another inode invalidates an otherwise unchanged payload read.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture mutation is separate from disjoint read progress assertions"
)]
fn unrelated_inode_publication_preserves_the_pending_payload_read() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let b = fixture.b;
    let mut output = [0_u8; 1];
    let (read, request) = fixture.suspend_payload(a, &mut output)?;
    fixture.mutate(|pass| {
        let file = pass.file(b)?;
        pass.write_file_range(file, FileOffset::ZERO, b"B")
    })?;
    let completion = fixture.disk.complete(request)?;
    match read.run(
        OperationEvent::StorageCompleted(completion),
        fixture
            .coordinator
            .read_context(fixture.cache.access(&fixture.epoch))?,
        &mut PlainCrypto,
        |pass| pass.read_file(a, FileOffset::ZERO, &mut output),
    ) {
        ReadTransition::Complete(result) => assert_eq!(result?.as_usize(), 1),
        ReadTransition::SubmitLower { .. } => return Err(Error::DeviceIo),
    }
    assert_eq!(output, [b'a']);
    Ok(())
}

/// # Errors
/// Returns fixture, mutation, or read failure.
/// # Panics
/// Fails when a retained whole metadata block supplies a newly observed neighbor's old record.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture storage and cache admission are separate from metadata freshness assertions"
)]
fn cache_replacement_keeps_new_inode_observations_current() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let b = fixture.b;
    fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
    let mut output = [0_u8; 1];
    let (mut read, request) = fixture.suspend_payload(a, &mut output)?;
    fixture.mutate(|pass| {
        let file = pass.file(b)?;
        pass.write_file_range(file, FileOffset::from_bytes(1), b"BBB")
    })?;
    fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
    let mut event = OperationEvent::StorageCompleted(fixture.disk.complete(request)?);
    loop {
        match read.run(
            event,
            fixture
                .coordinator
                .read_context(fixture.cache.access(&fixture.epoch))?,
            &mut PlainCrypto,
            |pass| {
                pass.read_file(a, FileOffset::ZERO, &mut output)?;
                Ok(pass.load_file(b)?.size())
            },
        ) {
            ReadTransition::SubmitLower { request, suspended } => {
                event = OperationEvent::StorageCompleted(fixture.disk.complete(request)?);
                read = suspended;
            }
            ReadTransition::Complete(result) => {
                assert_eq!(result?, FileSize::from_bytes(4));
                assert_eq!(output, [b'a']);
                return Ok(());
            }
        }
    }
}

/// # Errors
/// Returns fixture, traversal, or mutation failure.
/// # Panics
/// Fails when entry metadata loses the inode version established by directory traversal.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture traversal is separate from entry projection consistency assertions"
)]
fn directory_entry_projection_retains_its_inode_dependency() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut walk = DirectoryReadOperation::new(
        &fixture.profile,
        DirectoryNodeId::ROOT,
        DirectoryScanCursor::start(),
    );
    let mut event = OperationEvent::Admitted;
    let node = NodeId::File(fixture.a);
    let read = loop {
        match walk.advance(
            event,
            fixture
                .coordinator
                .read_context(fixture.cache.access(&fixture.epoch))?,
            &mut PlainCrypto,
        ) {
            DirectoryReadTransition::SubmitLower { request, suspended } => {
                event = OperationEvent::StorageCompleted(fixture.disk.complete(request)?);
                walk = suspended;
            }
            DirectoryReadTransition::Entry {
                entry,
                continuation,
            } => {
                if *entry.entry().node() == node {
                    break continuation.entry_read(&fixture.profile, node)?;
                }
                event = OperationEvent::Admitted;
                walk = continuation;
            }
            DirectoryReadTransition::Complete(result) => {
                result?;
                return Err(Error::DirectoryEntryNotFound);
            }
        }
    };
    let a = fixture.a;
    fixture.mutate(|pass| {
        let file = pass.file(a)?;
        pass.truncate_file(file, FileSize::from_bytes(0))
    })?;
    match read.run(
        OperationEvent::Admitted,
        fixture
            .coordinator
            .read_context(fixture.cache.access(&fixture.epoch))?,
        &mut PlainCrypto,
        |pass| pass.load_node_metadata(node),
    ) {
        ReadTransition::Complete(result) => assert_eq!(result, Err(Error::ReadConflict)),
        ReadTransition::SubmitLower { .. } => return Err(Error::DeviceIo),
    }
    Ok(())
}

/// # Errors
/// Returns fixture, resolve, or commit failure.
/// # Panics
/// Fails when metadata from an earlier publication is paired with current resource versions.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture commit is separate from current-context admission assertions"
)]
fn current_versions_reject_an_earlier_epoch_at_admission() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let ticket = fixture.coordinator.admit_mutation()?;
    let (resolved, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket,
        &mut PlainCrypto,
        |pass| {
            let file = pass.file(a)?;
            pass.write_file_range(file, FileOffset::ZERO, b"A")
        },
    )?;
    let ready = resolved
        .reserve(
            fixture.coordinator.grant_intent(ticket),
            &fixture.coordinator,
        )?
        .prepare_commit(
            fixture
                .coordinator
                .acquire_commit(ticket)?
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
        )?;
    let current =
        fixture
            .disk
            .commit(&mut fixture.coordinator, &mut fixture.cache, ticket, ready)?;
    assert!(matches!(
        fixture
            .coordinator
            .read_context(fixture.cache.access(&fixture.epoch)),
        Err(Error::StaleReadContext)
    ));
    let ticket = fixture.coordinator.admit_mutation()?;
    assert!(matches!(
        fixture.disk.resolve(
            &fixture.profile,
            &fixture.epoch,
            &fixture.coordinator,
            ticket,
            &mut PlainCrypto,
            |pass| {
                let file = pass.file(a)?;
                pass.write_file_range(file, FileOffset::ZERO, b"a")
            }
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    fixture.epoch = current;
    Ok(())
}

/// # Errors
/// Returns fixture, directory resolution, or namespace mutation failure.
/// # Panics
/// Fails when decoded directory progress is reused by resolution against another epoch.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture setup is separate from directory resolution lifetime assertions"
)]
fn retained_directory_resolution_rejects_a_replacement_epoch() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut reader = DirectoryReader::new(DirectoryNodeId::ROOT, DirectoryScanCursor::start());
    let ticket = fixture.coordinator.admit_mutation()?;
    let (_resolved, _entry) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket,
        &mut PlainCrypto,
        |pass| pass.next_directory_entry(&mut reader),
    )?;
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let metadata = NewFileMetadata::new(
            Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(1000)),
            Ext4Permissions::new(0o644)?,
        );
        pass.create_file(root, &Ext4Name::new(b"reader-admission")?, metadata)?;
        Ok(())
    })?;
    let ticket = fixture.coordinator.admit_mutation()?;
    assert!(matches!(
        fixture.disk.resolve(
            &fixture.profile,
            &fixture.epoch,
            &fixture.coordinator,
            ticket,
            &mut PlainCrypto,
            |pass| pass.next_directory_entry(&mut reader),
        ),
        Err(Error::ReadConflict)
    ));
    Ok(())
}

/// Independent owner shared by namespace fixtures.
fn namespace_owner() -> Ext4Owner {
    Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(1000))
}

/// Independent reflected CRC32C for fixture field encoding.
fn fixture_crc32c(mut state: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        state ^= u32::from(*byte);
        for _ in 0..8 {
            state = (state >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(state & 1));
        }
    }
    state
}

/// Supported v2 policy plus an independently chosen key identifier and file nonce.
fn namespace_context(identifier: u8) -> [u8; 40] {
    let mut bytes = [identifier; 40];
    for (destination, source) in bytes.iter_mut().zip([2, 1, 4, 0, 0, 0, 0, 0]) {
        *destination = source;
    }
    bytes
}

/// Selects the routing provider and installs a matching key for an independently encoded parent.
/// # Errors
/// Returns fixture, mount, context encoding, or key publication failure.
#[expect(
    clippy::disallowed_methods,
    reason = "the checked identifier field has the exact 16-byte source width"
)]
fn encrypted_namespace_fixture() -> Result<(Fixture, DirectoryNodeId)> {
    let mut fixture = Fixture::new()?;
    let parent = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.create_directory(
            root,
            &Ext4Name::new(b"encrypted")?,
            NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
        )
        .map(|directory| directory.id())
    })?;
    let key = FscryptMasterKey::from_raw(&[7; 32], &mut PlainCrypto)?;
    let mut context = namespace_context(0x31);
    context
        .get_mut(8..24)
        .ok_or(Error::InvalidEncryptionContext)?
        .copy_from_slice(&key.identifier().bytes());
    fixture
        .disk
        .encode_inode(NodeId::Directory(parent), 0x80800, Some(&context))?;
    fixture.disk.enable_verity_feature()?;
    fixture.remount()?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let change = ResolvedKeyChange::add(&fixture.epoch, &fixture.coordinator, ticket, key)?;
    fixture.publish_keys(change)?;
    fixture.crypto = Box::try_new(ContextCrypto { nonce: 0x50 }).map_err(|_| Error::OutOfMemory)?;
    Ok((fixture, parent))
}

/// # Errors
/// Returns fixture, namespace, allocation, encryption, commit, or read failure.
/// # Panics
/// Fails if staged contexts cannot support child creation, external-xattr movement, or data reads.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare committed names and plaintext after staged-context mutations"
)]
fn encrypted_creation_uses_staged_contexts_for_names_links_and_contents() -> Result<()> {
    let (mut fixture, parent) = encrypted_namespace_fixture()?;
    let (directory, file) = fixture.mutate(|pass| {
        let parent = pass.directory(parent)?;
        let directory = pass.create_directory(
            parent,
            &Ext4Name::new(b"sub")?,
            NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
        )?;
        let file = pass.create_file(
            directory,
            &Ext4Name::new(b"payload")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )?;
        pass.create_file(
            directory,
            &Ext4Name::new(b"a:b")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )?;
        pass.reserve_file_allocation(file, FileAllocationSize::from_bytes(8192))?;
        let node = pass.node(NodeId::File(file.id()))?;
        pass.set_xattr(
            node,
            XattrName::new(XattrNamespace::User, b"large")?,
            XattrValue::new(&[b'X'; 512])?,
        )?;
        pass.write_file_range(file, FileOffset::from_bytes(5), b"secret")?;
        let source = pass.hard_link_source(HardLinkNodeId::File(file.id()))?;
        pass.create_hard_link(
            source,
            directory,
            &Ext4Name::new(b"link")?,
            NamespaceDestination::Vacant,
        )?;
        pass.rename_child(
            directory,
            &Ext4Name::new(b"payload")?,
            directory,
            &Ext4Name::new(b"renamed")?,
            NamespaceDestination::Vacant,
        )?;
        Ok((directory.id(), file.id()))
    })?;
    // Remount discards keys. The new snapshot must reacquire the same master key explicitly.
    fixture.remount()?;
    let key = FscryptMasterKey::from_raw(&[7; 32], &mut PlainCrypto)?;
    let ticket = fixture.coordinator.admit_mutation()?;
    fixture.publish_keys(ResolvedKeyChange::add(
        &fixture.epoch,
        &fixture.coordinator,
        ticket,
        key,
    )?)?;
    for name in [b"renamed".as_slice(), b"link".as_slice()] {
        let name = Ext4Name::new(name)?;
        let found = fixture.read(|pass| pass.lookup_child(directory, &name))?;
        assert!(matches!(found, ChildLookup::Found(child) if *child.node() == NodeId::File(file)));
    }
    assert!(matches!(
        fixture.read(|pass| pass.lookup_child(directory, &Ext4Name::new(b"a:b")?))?,
        ChildLookup::Found(_)
    ));
    let mut bytes = [0xff; 11];
    assert_eq!(
        fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?,
        ReadBytes::from_usize(11)
    );
    assert_eq!(&bytes, b"\0\0\0\0\0secret");
    Ok(())
}

/// # Errors
/// Returns fixture, context selection, verity preparation, commit or verified-read failure.
/// # Panics
/// Fails if new encrypted inode contexts cannot cover staged data and post-EOF verity metadata.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare verified plaintext after same-transaction creation and verity enablement"
)]
fn new_encrypted_inode_can_enable_verity_in_its_creation_transaction() -> Result<()> {
    let (mut fixture, parent) = encrypted_namespace_fixture()?;
    let enable = FsverityEnable::new(
        FsverityHashAlgorithm::Sha256,
        FsverityBlockSize::new(1024)?,
        FsveritySalt::empty(),
        FsveritySignature::empty(),
    );
    let file = fixture.mutate(|pass| {
        let parent = pass.directory(parent)?;
        let file = pass.create_file(
            parent,
            &Ext4Name::new(b"verified")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )?;
        pass.write_file_range(file, FileOffset::from_bytes(8192), b"verified")?;
        pass.enable_verity(file, &enable)?;
        Ok(file.id())
    })?;
    let mut bytes = [0; 8];
    assert_eq!(
        fixture.read(|pass| pass.read_file(file, FileOffset::from_bytes(8192), &mut bytes))?,
        ReadBytes::from_usize(8)
    );
    assert_eq!(&bytes, b"verified");
    Ok(())
}

/// # Errors
/// Returns fixture, derivation, or pre-publication failure.
/// # Panics
/// Fails if key-only publication touches storage or abandoned preparation changes presence.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare publication and persistence boundaries"
)]
fn mount_keys_publish_without_storage_and_disappear_on_remount() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let before = (
        fixture_crc32c(u32::MAX, &fixture.disk.filesystem),
        fixture_crc32c(u32::MAX, &fixture.disk.journal),
    );
    let key = FscryptMasterKey::from_raw(&[7; 32], &mut PlainCrypto)?;
    let identifier = key.identifier();
    assert_eq!(
        identifier.bytes(),
        [
            0x11, 0x01, 0x42, 0x0d, 0x49, 0x92, 0x90, 0xb0, 0x05, 0xfc, 0x68, 0x15, 0x27, 0x25,
            0x71, 0x59
        ]
    );
    let ticket = fixture.coordinator.admit_mutation()?;
    let change = ResolvedKeyChange::add(&fixture.epoch, &fixture.coordinator, ticket, key)?;
    fixture.publish_keys(change)?;
    assert_eq!(
        fixture.epoch.fscrypt_key_presence(identifier),
        FscryptKeyPresence::Present
    );
    let published = fixture.epoch.sequence();

    let ticket = fixture.coordinator.admit_mutation()?;
    let abandoned =
        ResolvedKeyChange::remove(&fixture.epoch, &fixture.coordinator, ticket, identifier)?
            .reserve(
                fixture.coordinator.grant_intent(ticket),
                &fixture.coordinator,
            )?
            .prepare(
                fixture
                    .coordinator
                    .acquire_commit(ticket)?
                    .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
                &mut fixture.coordinator,
                &fixture.epoch,
            )?;
    abandoned
        .abort(&mut fixture.coordinator)
        .map_err(|(error, _prepared)| error)?;
    assert_eq!(fixture.epoch.sequence(), published);
    assert_eq!(
        fixture.epoch.fscrypt_key_presence(identifier),
        FscryptKeyPresence::Present
    );

    let ticket = fixture.coordinator.admit_mutation()?;
    let removal =
        ResolvedKeyChange::remove(&fixture.epoch, &fixture.coordinator, ticket, identifier)?;
    fixture.publish_keys(removal)?;
    assert_eq!(
        fixture.epoch.fscrypt_key_presence(identifier),
        FscryptKeyPresence::Absent
    );
    let ticket = fixture.coordinator.admit_mutation()?;
    let absent =
        ResolvedKeyChange::remove(&fixture.epoch, &fixture.coordinator, ticket, identifier)?;
    fixture.publish_keys(absent)?;

    let key = FscryptMasterKey::from_raw(&[7; 32], &mut PlainCrypto)?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let addition = ResolvedKeyChange::add(&fixture.epoch, &fixture.coordinator, ticket, key)?;
    fixture.publish_keys(addition)?;
    assert_eq!(
        before,
        (
            fixture_crc32c(u32::MAX, &fixture.disk.filesystem),
            fixture_crc32c(u32::MAX, &fixture.disk.journal),
        )
    );
    let (_, remounted, _) = fixture.disk.mount(MountAccess::ReadWrite)?.into_parts();
    assert_eq!(
        remounted.fscrypt_key_presence(identifier),
        FscryptKeyPresence::Absent
    );
    Ok(())
}

/// # Errors
/// Returns fixture, derivation, or publication failure.
/// # Panics
/// Fails if a stale key snapshot overwrites a newer one or key publication reverts file metadata.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish key-resource conflicts from independent file progress"
)]
fn key_publication_revalidates_keys_and_retains_independent_file_commits() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let first = FscryptMasterKey::from_raw(&[1; 32], &mut PlainCrypto)?;
    let first_id = first.identifier();
    let ticket = fixture.coordinator.admit_mutation()?;
    let first = ResolvedKeyChange::add(&fixture.epoch, &fixture.coordinator, ticket, first)?;
    let second = FscryptMasterKey::from_raw(&[2; 32], &mut PlainCrypto)?;
    let second_id = second.identifier();
    let stale_ticket = fixture.coordinator.admit_mutation()?;
    let stale = ResolvedKeyChange::add(&fixture.epoch, &fixture.coordinator, stale_ticket, second)?;
    fixture.publish_keys(first)?;
    assert!(matches!(
        stale.reserve(
            fixture.coordinator.grant_intent(stale_ticket),
            &fixture.coordinator
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    let ticket = fixture.coordinator.admit_mutation()?;
    let second = FscryptMasterKey::from_raw(&[2; 32], &mut PlainCrypto)?;
    let pending = ResolvedKeyChange::add(&fixture.epoch, &fixture.coordinator, ticket, second)?;
    let b = fixture.b;
    fixture.mutate(|pass| {
        let file = pass.file(b)?;
        pass.write_file_range(file, FileOffset::ZERO, &[b'B'; 8192])
    })?;
    let a = fixture.a;
    let mut pending_data = [0; 1];
    let (pending_read, request) = fixture.suspend_payload(a, &mut pending_data)?;
    fixture.publish_keys(pending)?;
    let completion = fixture.disk.complete(request)?;
    match pending_read.run(
        OperationEvent::StorageCompleted(completion),
        fixture
            .coordinator
            .read_context(fixture.cache.access(&fixture.epoch))?,
        &mut PlainCrypto,
        |pass| pass.read_file(a, FileOffset::ZERO, &mut pending_data),
    ) {
        ReadTransition::Complete(result) => assert_eq!(result?, ReadBytes::from_usize(1)),
        ReadTransition::SubmitLower { .. } => return Err(Error::DeviceIo),
    }
    assert_eq!(pending_data, [b'a']);
    assert_eq!(
        fixture.epoch.fscrypt_key_presence(first_id),
        FscryptKeyPresence::Present
    );
    assert_eq!(
        fixture.epoch.fscrypt_key_presence(second_id),
        FscryptKeyPresence::Present
    );
    let mut data = [0; 8192];
    assert_eq!(
        fixture.read(|pass| pass.read_file(b, FileOffset::ZERO, &mut data))?,
        ReadBytes::from_usize(data.len())
    );
    assert_eq!(data, [b'B'; 8192]);
    // Exercise the allocation ownership retained by the key epoch in a subsequent disk mutation.
    fixture.mutate(|pass| {
        let file = pass.file(b)?;
        pass.truncate_file(file, FileSize::from_bytes(0))
    })?;
    Ok(())
}

/// # Errors
/// Returns fixture, independent inode encoding, read admission, or key publication failures.
/// # Panics
/// Fails if a read consumes encrypted bytes after its master key is removed.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe revocation before cipher execution and output copy"
)]
fn key_removal_revokes_encrypted_reads_and_resolved_mutations() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let key = FscryptMasterKey::from_raw(&[7; 32], &mut PlainCrypto)?;
    let identifier = key.identifier();
    let mut context = namespace_context(0x55);
    for (byte, identifier_byte) in context.iter_mut().skip(8).zip(identifier.bytes()) {
        *byte = identifier_byte;
    }
    fixture
        .disk
        .encode_inode(NodeId::File(a), 0x0008_0800, Some(&context))?;
    let b = fixture.b;
    fixture
        .disk
        .encode_inode(NodeId::File(b), 0x0008_0800, Some(&context))?;
    let (profile, epoch, coordinator) = fixture.disk.mount(MountAccess::ReadWrite)?.into_parts();
    fixture.profile = profile;
    fixture.epoch = epoch;
    fixture.coordinator = coordinator;
    fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let addition = ResolvedKeyChange::add(&fixture.epoch, &fixture.coordinator, ticket, key)?;
    fixture.publish_keys(addition)?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let other_key = FscryptMasterKey::from_raw(&[9; 32], &mut PlainCrypto)?;
    let pending_keys =
        ResolvedKeyChange::add(&fixture.epoch, &fixture.coordinator, ticket, other_key)?;
    fixture.mutate(|pass| {
        let file = pass.file(b)?;
        pass.truncate_file(file, FileSize::from_bytes(0))
    })?;
    fixture.publish_keys(pending_keys)?;
    let payload = fixture
        .read(|pass| pass.node_data_allocation(NodeId::File(a), FileOffset::ZERO))?
        .and_then(DataAllocationRun::physical)
        .ok_or(Error::InvalidExtentTree)?;
    let mut output = [0; 1];
    let mut read = EpochReadOperation::new(&fixture.profile);
    let mut event = OperationEvent::Admitted;
    let (read, request) = loop {
        match read.run(
            event,
            fixture
                .coordinator
                .read_context(fixture.cache.access(&fixture.epoch))?,
            &mut PlainCrypto,
            |pass| pass.read_file(a, FileOffset::ZERO, &mut output),
        ) {
            ReadTransition::SubmitLower { request, suspended } if matches!(&request, StorageRequest::Read { offset, .. } if *offset == payload) =>
            {
                break (suspended, request);
            }
            ReadTransition::SubmitLower { request, suspended } => {
                event = OperationEvent::StorageCompleted(fixture.disk.complete(request)?);
                read = suspended;
            }
            ReadTransition::Complete(result) => {
                result?;
                return Err(Error::DeviceIo);
            }
        }
    };
    let pending_ticket = fixture.coordinator.admit_mutation()?;
    let (pending, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        pending_ticket,
        &mut PlainCrypto,
        |pass| {
            let file = pass.file(a)?;
            pass.truncate_file(file, FileSize::from_bytes(0))
        },
    )?;
    let reserved_ticket = fixture.coordinator.admit_mutation()?;
    let (reserved, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        reserved_ticket,
        &mut PlainCrypto,
        |pass| {
            let file = pass.file(a)?;
            pass.truncate_file(file, FileSize::from_bytes(0))
        },
    )?;
    let reserved = reserved.reserve(
        fixture.coordinator.grant_intent(reserved_ticket),
        &fixture.coordinator,
    )?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let removal =
        ResolvedKeyChange::remove(&fixture.epoch, &fixture.coordinator, ticket, identifier)?;
    fixture.publish_keys(removal)?;
    assert!(matches!(
        pending.reserve(
            fixture.coordinator.grant_intent(pending_ticket),
            &fixture.coordinator
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    assert!(matches!(
        reserved.prepare_commit(
            fixture
                .coordinator
                .acquire_commit(reserved_ticket)?
                .ok_or(ext4_core::Error::ClusterReferenceConflict)?,
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    let completion = fixture.disk.complete(request)?;
    match read.run(
        OperationEvent::StorageCompleted(completion),
        fixture
            .coordinator
            .read_context(fixture.cache.access(&fixture.epoch))?,
        &mut PlainCrypto,
        |pass| pass.read_file(a, FileOffset::ZERO, &mut output),
    ) {
        ReadTransition::Complete(result) => assert_eq!(result, Err(Error::ReadConflict)),
        ReadTransition::SubmitLower { .. } => return Err(Error::DeviceIo),
    }
    assert_eq!(output, [0]);
    Ok(())
}

/// # Errors
/// Returns fixture, independent encoding, or read failures.
/// # Panics
/// Fails if namespace operations bypass an inode's append-only flag.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "namespace admission assertions follow fallible fixture setup"
)]
fn append_only_inode_retains_its_names_and_link_count() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    fixture
        .disk
        .encode_inode(NodeId::File(file), 0x0008_0020, None)?;
    fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
    assert!(matches!(
        fixture.mutate(|pass| {
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            pass.unlink_file(root, &Ext4Name::new(b"concurrent-a")?)
        }),
        Err(Error::UnsupportedInodeMutation)
    ));
    assert!(matches!(
        fixture.mutate(|pass| {
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            pass.rename_child(
                root,
                &Ext4Name::new(b"concurrent-a")?,
                root,
                &Ext4Name::new(b"renamed")?,
                NamespaceDestination::Vacant,
            )
        }),
        Err(Error::UnsupportedInodeMutation)
    ));
    assert!(matches!(
        fixture.mutate(|pass| pass.hard_link_source(HardLinkNodeId::File(file))),
        Err(Error::UnsupportedInodeMutation)
    ));
    assert_eq!(
        fixture.read(|pass| Ok(pass.load_file(file)?.links_count()))?,
        Ext4LinkCount::ONE
    );
    assert!(matches!(
        fixture.read(
            |pass| pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"concurrent-a")?)
        )?,
        ChildLookup::Found(_)
    ));
    Ok(())
}

/// # Errors
/// Returns fixture, independent encryption-context encoding, or read failures.
/// # Panics
/// Fails if rename inserts a plaintext or foreign-policy child into an encrypted directory.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "encryption policy assertions follow fallible fixture setup"
)]
fn rename_requires_the_encrypted_destination_policy() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let destination = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        Ok(pass
            .create_directory(
                root,
                &Ext4Name::new(b"encrypted")?,
                NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
            )?
            .id())
    })?;
    fixture.disk.encode_inode(
        NodeId::Directory(destination),
        0x0008_0800,
        Some(&namespace_context(0x11)),
    )?;
    for encrypted_source in [false, true] {
        if encrypted_source {
            fixture.disk.encode_inode(
                NodeId::File(fixture.a),
                0x0008_0800,
                Some(&namespace_context(0x22)),
            )?;
        }
        fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
        assert!(matches!(
            fixture.mutate(|pass| {
                let root = pass.directory(DirectoryNodeId::ROOT)?;
                let target = pass.directory(destination)?;
                pass.rename_child(
                    root,
                    &Ext4Name::new(b"concurrent-a")?,
                    target,
                    &Ext4Name::new(b"moved")?,
                    NamespaceDestination::Vacant,
                )
            }),
            Err(Error::UnsupportedEncryption)
        ));
        assert!(matches!(
            fixture
                .read(|pass| pass
                    .lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(b"concurrent-a")?))?,
            ChildLookup::Found(_)
        ));
    }
    Ok(())
}

/// # Errors
/// Returns fixture, namespace, or payload failures.
/// # Panics
/// Fails if unlink invalidates a surviving name or inline storage includes the terminator byte.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "observable namespace assertions follow fallible fixture setup"
)]
fn symlink_names_share_storage_until_the_final_unlink() -> Result<()> {
    for length in [59, 60, 61, 4095] {
        let mut fixture = Fixture::new()?;
        let free_before = fixture.epoch.geometry().free_cluster_count();
        let target = SymlinkTarget::new(&vec![b'x'; length])?;
        let first = Ext4Name::new(b"link-first")?;
        let second = Ext4Name::new(b"link-second")?;
        let link = fixture.mutate(|pass| {
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            Ok(pass
                .create_symlink(
                    root,
                    &first,
                    &target,
                    NewSymlinkMetadata::new(namespace_owner(), Ext4Permissions::new(0o777)?),
                )?
                .id())
        })?;
        let allocation =
            fixture.read(|pass| Ok(pass.load_symlink(link)?.allocation_size().bytes()))?;
        assert_eq!(allocation, if length < 60 { 0 } else { 4096 });
        fixture.mutate(|pass| {
            let source = pass.hard_link_source(HardLinkNodeId::Symlink(link))?;
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            pass.create_hard_link(source, root, &second, NamespaceDestination::Vacant)
        })?;
        fixture.mutate(|pass| {
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            pass.remove_symlink(root, &first)
        })?;
        assert_eq!(
            fixture.read(|pass| pass.read_symlink(link))?,
            target.bytes()
        );
        assert_eq!(
            fixture.read(|pass| Ok(pass.load_symlink(link)?.links_count()))?,
            Ext4LinkCount::ONE
        );
        fixture.mutate(|pass| {
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            pass.remove_symlink(root, &second)
        })?;
        assert!(matches!(
            fixture.read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &second))?,
            ChildLookup::NotFound
        ));
        assert_eq!(fixture.epoch.geometry().free_cluster_count(), free_before);
    }
    Ok(())
}

/// # Errors
/// Returns fixture or lookup failures.
/// # Panics
/// Fails if native target admission creates a name for an unrepresentable target.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "native symlink admission assertions follow fallible setup"
)]
fn native_symlink_target_reserves_its_terminator_inside_one_block() -> Result<()> {
    let mut fixture = Fixture::new()?;
    for length in [4096, 4097] {
        let name = Ext4Name::new(b"oversized-link")?;
        let target = SymlinkTarget::new(&vec![b'x'; length])?;
        assert!(matches!(
            fixture.mutate(|pass| {
                let root = pass.directory(DirectoryNodeId::ROOT)?;
                pass.create_symlink(
                    root,
                    &name,
                    &target,
                    NewSymlinkMetadata::new(namespace_owner(), Ext4Permissions::new(0o777)?),
                )
            }),
            Err(Error::InvalidName)
        ));
        assert!(matches!(
            fixture.read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &name))?,
            ChildLookup::NotFound
        ));
    }
    Ok(())
}

/// # Errors
/// Returns fixture, directory, resolve, or commit failures.
/// # Panics
/// Fails if a directory can enter its descendants or a stale ancestry proof can be committed.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "ancestry and conflict assertions follow fallible setup"
)]
fn directory_moves_revalidate_destination_ancestry() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a_name = Ext4Name::new(b"tree-a")?;
    let b_name = Ext4Name::new(b"tree-b")?;
    let c_name = Ext4Name::new(b"tree-c")?;
    let moved = Ext4Name::new(b"moved")?;
    let (a, b, c) = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let metadata = NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?);
        let a = pass.create_directory(root, &a_name, metadata)?;
        let b = pass.create_directory(a, &b_name, metadata)?;
        let c = pass.create_directory(root, &c_name, metadata)?;
        Ok((a.id(), b.id(), c.id()))
    })?;
    for destination in [a, b] {
        assert!(matches!(
            fixture.mutate(|pass| {
                let root = pass.directory(DirectoryNodeId::ROOT)?;
                let destination = pass.directory(destination)?;
                pass.rename_child(
                    root,
                    &a_name,
                    destination,
                    &moved,
                    NamespaceDestination::Vacant,
                )
            }),
            Err(Error::DirectoryCycle)
        ));
    }
    let ticket = fixture.coordinator.admit_mutation()?;
    let (resolved, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket,
        &mut PlainCrypto,
        |pass| {
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            let destination = pass.directory(c)?;
            pass.rename_child(
                root,
                &a_name,
                destination,
                &moved,
                NamespaceDestination::Vacant,
            )
        },
    )?;
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let destination = pass.directory(b)?;
        pass.rename_child(
            root,
            &c_name,
            destination,
            &moved,
            NamespaceDestination::Vacant,
        )
    })?;
    assert!(matches!(
        resolved.reserve(
            fixture.coordinator.grant_intent(ticket),
            &fixture.coordinator
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    assert!(matches!(
        fixture.mutate(|pass| {
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            let destination = pass.directory(c)?;
            pass.rename_child(
                root,
                &a_name,
                destination,
                &moved,
                NamespaceDestination::Vacant,
            )
        }),
        Err(Error::DirectoryCycle)
    ));
    Ok(())
}

/// # Errors
/// Returns fixture, privilege staging, data mutation, or remount failures.
/// # Panics
/// Fails if content mutation preserves execution authority or changes non-executable setgid.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare durable privilege state with independent modification inputs"
)]
fn content_mutation_retires_execution_privileges() -> Result<()> {
    for operation in 0..3 {
        let mut fixture = Fixture::new()?;
        let file = fixture.a;
        fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(file))?;
            pass.set_posix_security(
                node,
                Ext4Security::new(namespace_owner(), Ext4Permissions::new(0o6777)?),
            )?;
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::Security, b"capability")?,
                XattrValue::new(&[1, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])?,
            )
        })?;
        fixture.mutate(|pass| {
            let file = pass.file(file)?;
            match operation {
                0 => pass.write_file_range(file, FileOffset::ZERO, b"changed"),
                1 => pass.truncate_file(file, FileSize::from_bytes(0)),
                _ => pass.extend_file(file, FileSize::from_bytes(8192)),
            }
        })?;
        fixture.remount()?;
        assert_eq!(
            fixture.read(|pass| Ok(pass.load_file(file)?.security().permissions().as_u16()))?,
            0o777
        );
        assert!(
            fixture
                .read(|pass| pass.read_xattr(
                    NodeId::File(file),
                    &XattrName::new(XattrNamespace::Security, b"capability")?
                ))?
                .is_none()
        );
    }
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(file))?;
        pass.set_posix_security(
            node,
            Ext4Security::new(namespace_owner(), Ext4Permissions::new(0o2640)?),
        )
    })?;
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.write_file_range(file, FileOffset::ZERO, b"Z")
    })?;
    assert_eq!(
        fixture.read(|pass| Ok(pass.load_file(file)?.security().permissions().as_u16()))?,
        0o2640
    );
    Ok(())
}

/// # Errors
/// Returns fixture, security mutation, xattr or remount failures.
/// # Panics
/// Fails if ownership changes retain execution privileges or discard access policy or mode semantics.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare durable ownership, setid and capability state with independent transition inputs"
)]
fn ownership_mutation_retires_execution_privileges() -> Result<()> {
    let uid_changed = Ext4Owner::new(Ext4Uid::from_u32(0), Ext4Gid::from_u32(1000));
    let gid_changed = Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(0));
    for (before, owner, requested, expected, keeps_capability) in [
        (0o6777, uid_changed, 0o6777, 0o777, false),
        (0o6777, gid_changed, 0o6777, 0o777, false),
        (0o6640, uid_changed, 0o6640, 0o2640, false),
        (0o6777, namespace_owner(), 0o6755, 0o6755, true),
    ] {
        let mut fixture = Fixture::new()?;
        let file = fixture.a;
        let capability = XattrName::new(XattrNamespace::Security, b"capability")?;
        fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(file))?;
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::System, b"posix_acl_access")?,
                XattrValue::new(&NAMED_ACL)?,
            )?;
            pass.set_posix_security(
                node,
                Ext4Security::new(namespace_owner(), Ext4Permissions::new(before)?),
            )?;
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::Security, b"capability")?,
                XattrValue::new(&[1, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])?,
            )
        })?;
        fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(file))?;
            pass.set_posix_security(
                node,
                Ext4Security::new(owner, Ext4Permissions::new(requested)?),
            )
        })?;
        fixture.remount()?;
        let access = fixture.read(|pass| pass.load_access(NodeId::File(file)))?;
        assert_eq!(access.security().owner(), owner);
        assert_eq!(access.security().permissions().as_u16(), expected);
        assert_eq!(access.acl().map(|acl| acl.users().len()), Some(1));
        assert_eq!(
            fixture
                .read(|pass| pass.read_xattr(NodeId::File(file), &capability))?
                .is_some(),
            keeps_capability
        );
    }
    let mut fixture = Fixture::new()?;
    let directory = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.create_directory(
            root,
            &Ext4Name::new(b"setgid-directory")?,
            NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o2755)?),
        )
        .map(|directory| directory.id())
    })?;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::Directory(directory))?;
        pass.set_posix_security(
            node,
            Ext4Security::new(uid_changed, Ext4Permissions::new(0o2755)?),
        )
    })?;
    fixture.remount()?;
    assert_eq!(
        fixture.read(|pass| Ok(pass.load_directory(directory)?.security()))?,
        Ext4Security::new(uid_changed, Ext4Permissions::new(0o2755)?)
    );
    Ok(())
}

/// # Errors
/// Returns fixture, flag encoding, metadata access or remount failures.
/// # Panics
/// Fails if retained node identities bypass append-only policy or a rejected edit reaches storage.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify mutation rejection and the unchanged persistent metadata endpoint"
)]
fn append_only_metadata_changes_are_rejected() -> Result<()> {
    for operation in 0..3 {
        let mut fixture = Fixture::new()?;
        let file = fixture.a;
        let name = XattrName::new(XattrNamespace::User, b"protected")?;
        let node = fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(file))?;
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::User, b"protected")?,
                XattrValue::new(b"original")?,
            )?;
            Ok(node)
        })?;
        fixture
            .disk
            .encode_inode(NodeId::File(file), 0x0008_0020, None)?;
        fixture.remount()?;
        let before = fixture.read(|pass| {
            let file = pass.load_file(file)?;
            Ok((file.security(), file.times()))
        })?;
        assert_eq!(
            fixture.mutate(|pass| match operation {
                0 => pass.set_posix_security(
                    node,
                    Ext4Security::new(namespace_owner(), Ext4Permissions::new(0o777)?),
                ),
                1 => pass.set_xattr(
                    node,
                    XattrName::new(XattrNamespace::User, b"protected")?,
                    XattrValue::new(b"changed")?,
                ),
                _ => pass.set_times(
                    node,
                    Ext4Times::new(
                        Ext4Timestamp::from_seconds(9),
                        Ext4Timestamp::from_seconds(9),
                        Ext4Timestamp::from_seconds(9),
                        None,
                    ),
                ),
            }),
            Err(Error::UnsupportedInodeMutation)
        );
        fixture.remount()?;
        assert_eq!(
            fixture.read(|pass| {
                let file = pass.load_file(file)?;
                Ok((file.security(), file.times()))
            })?,
            before
        );
        assert_eq!(
            fixture.read(|pass| pass.read_xattr(NodeId::File(file), &name))?,
            Some(XattrValue::new(b"original")?)
        );
    }
    Ok(())
}

/// # Errors
/// Returns fixture, enumeration, exact lookup, unlink or recovery failures.
/// # Panics
/// Fails if any supported ciphertext length loses its keyless namespace identity.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare enumeration and lookup against independently encoded ciphertext names"
)]
fn locked_long_names_support_lookup_and_unlink() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let (directory, files) = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let directory = pass.create_directory(
            root,
            &Ext4Name::new(b"locked-long")?,
            NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
        )?;
        let mut files = Vec::new();
        for length in [184, 192, 255] {
            let file = pass.create_file(
                directory,
                &Ext4Name::new(&vec![b'x'; length])?,
                NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
            )?;
            files.push(file.id());
        }
        Ok((directory.id(), files))
    })?;
    fixture.disk.encode_inode(
        NodeId::Directory(directory),
        0x0008_0800,
        Some(&namespace_context(0x11)),
    )?;
    for file in files {
        fixture.disk.encode_inode(
            NodeId::File(file),
            0x0008_0800,
            Some(&namespace_context(0x11)),
        )?;
    }
    fixture.remount()?;
    let mut reader = DirectoryReader::new(directory, DirectoryScanCursor::start());
    let mut names = Vec::new();
    while let Some(scanned) = fixture.read(|pass| pass.next_directory_entry(&mut reader))? {
        let entry = scanned.into_entry();
        if matches!(entry.name().bytes(), b"." | b"..") {
            continue;
        }
        assert!(entry.name().bytes().len() <= 255);
        let visible = entry.name();
        let found = fixture.read(|pass| pass.lookup_child(directory, visible))?;
        assert!(matches!(found, ChildLookup::Found(child) if child.node() == entry.node()));
        names.push(entry.name().try_to_owned_name()?);
    }
    assert_eq!(names.len(), 3);
    for name in names {
        fixture.mutate(|pass| {
            let directory = pass.directory(directory)?;
            pass.unlink_file(directory, &name)
        })?;
    }
    fixture.remount()?;
    let mut reader = DirectoryReader::new(directory, DirectoryScanCursor::start());
    let mut remaining = 0;
    while fixture
        .read(|pass| pass.next_directory_entry(&mut reader))?
        .is_some()
    {
        remaining += 1;
    }
    assert_eq!(remaining, 2);
    Ok(())
}

/// Independent reduced-width ext4 ACL with one named user and a group-class mask.
const NAMED_ACL: [u8; 28] = [
    1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 6, 0, 233, 3, 0, 0, 4, 0, 6, 0, 16, 0, 6, 0, 32, 0, 0, 0,
];

/// # Errors
/// Returns fixture, ACL or mutation failure.
/// # Panics
/// Panics when ACL mode synchronization or directory inheritance differs from the disk contract.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare independent ACL byte and permission vectors"
)]
fn posix_acl_mode_and_inheritance() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(a))?;
        pass.set_xattr(
            node,
            XattrName::new(XattrNamespace::System, b"posix_acl_access")?,
            XattrValue::new(&NAMED_ACL)?,
        )
    })?;
    assert_eq!(
        fixture.read(|pass| Ok(pass
            .load_access(NodeId::File(a))?
            .security()
            .permissions()
            .as_u16()))?,
        0o660
    );
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(a))?;
        pass.set_posix_security(
            node,
            Ext4Security::new(namespace_owner(), Ext4Permissions::new(0o640)?),
        )
    })?;
    fixture.remount()?;
    fixture.read(|pass| {
        let access = pass.load_access(NodeId::File(a))?;
        assert_eq!(access.security().permissions().as_u16(), 0o640);
        let acl = access.acl().ok_or(Error::InvalidAcl)?;
        assert_eq!(acl.mask().ok_or(Error::InvalidAcl)?.bits(), 4);
        assert_eq!(
            acl.users()
                .first()
                .ok_or(Error::InvalidAcl)?
                .permissions()
                .bits(),
            6
        );
        Ok(())
    })?;
    let (file, directory, nested, symlink) = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let parent_node = pass.node(NodeId::Directory(DirectoryNodeId::ROOT))?;
        pass.set_xattr(
            parent_node,
            XattrName::new(XattrNamespace::System, b"posix_acl_default")?,
            XattrValue::new(&NAMED_ACL)?,
        )?;
        let file = pass.create_file(
            root,
            &Ext4Name::new(b"acl-child")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )?;
        let directory = pass.create_directory(
            root,
            &Ext4Name::new(b"acl-dir")?,
            NewDirectoryMetadata::new(namespace_owner(), Ext4Permissions::new(0o755)?),
        )?;
        let nested = pass.create_file(
            directory,
            &Ext4Name::new(b"nested")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )?;
        let symlink = pass.create_symlink(
            root,
            &Ext4Name::new(b"acl-link")?,
            &SymlinkTarget::new(b"acl-child")?,
            NewSymlinkMetadata::new(namespace_owner(), Ext4Permissions::new(0o777)?),
        )?;
        Ok((file.id(), directory.id(), nested.id(), symlink.id()))
    })?;
    fixture.remount()?;
    for (node, mode) in [
        (NodeId::File(file), 0o640),
        (NodeId::Directory(directory), 0o640),
        (NodeId::File(nested), 0o640),
    ] {
        fixture.read(|pass| {
            let access = pass.load_access(node)?;
            assert_eq!(access.security().permissions().as_u16(), mode);
            assert!(access.acl().is_some());
            Ok(())
        })?;
    }
    assert!(fixture.read(|pass| Ok(pass.load_access(NodeId::Symlink(symlink))?.acl().is_none()))?);
    Ok(())
}

/// # Errors
/// Returns fixture or xattr setup failure.
/// # Panics
/// Panics when malformed ACLs or illegal inode-kind policies are accepted.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify ACL rejection at the persistent mutation boundary"
)]
fn malformed_acl_mutations_leave_committed_policy_unchanged() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let before = fixture.read(|pass| Ok(pass.load_file(a)?.security()))?;
    for bad in [vec![], {
        let mut bad = NAMED_ACL.to_vec();
        *bad.get_mut(6).ok_or(Error::InvalidAcl)? = 8;
        bad
    }] {
        assert_eq!(
            fixture.mutate(|pass| {
                let node = pass.node(NodeId::File(a))?;
                pass.set_xattr(
                    node,
                    XattrName::new(XattrNamespace::System, b"posix_acl_access")?,
                    XattrValue::new(&bad)?,
                )
            }),
            Err(Error::InvalidAcl)
        );
    }
    assert_eq!(
        fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(a))?;
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::System, b"posix_acl_default")?,
                XattrValue::new(&NAMED_ACL)?,
            )
        }),
        Err(Error::InvalidAcl)
    );
    fixture.remount()?;
    assert_eq!(
        fixture.read(|pass| Ok(pass.load_file(a)?.security()))?,
        before
    );
    Ok(())
}

/// # Errors
/// Returns fixture, xattr mutation or remount failure.
/// # Panics
/// Panics if an empty ACL remains stored or changes the remaining inode permissions.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify persistent absence as the empty ACL contract"
)]
fn empty_acl_values_remove_the_reserved_slot() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(a))?;
        pass.set_xattr(
            node,
            XattrName::new(XattrNamespace::System, b"posix_acl_access")?,
            XattrValue::new(&NAMED_ACL)?,
        )?;
        for local in [
            b"posix_acl_access".as_slice(),
            b"posix_acl_default".as_slice(),
        ] {
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::System, local)?,
                XattrValue::new(&1_u32.to_le_bytes())?,
            )?;
        }
        Ok(())
    })?;
    fixture.remount()?;
    fixture.read(|pass| {
        let access = pass.load_access(NodeId::File(a))?;
        assert!(access.acl().is_none());
        assert_eq!(access.security().permissions().as_u16(), 0o660);
        let attrs = pass.read_xattrs(NodeId::File(a))?;
        for local in [
            b"posix_acl_access".as_slice(),
            b"posix_acl_default".as_slice(),
        ] {
            assert!(
                attrs
                    .get(&XattrName::new(XattrNamespace::System, local)?)
                    .is_none()
            );
        }
        Ok(())
    })
}

/// Reads a little-endian fixture field independently of the production parser.
/// # Errors
/// Returns a malformed fixture range or field width.
fn fixture_u32(image: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::ArithmeticOverflow)?;
    Ok(u32::from_le_bytes(
        image
            .get(offset..end)
            .ok_or(Error::DeviceRange)?
            .try_into()
            .map_err(|_| Error::TruncatedStructure)?,
    ))
}

/// Locates a group-zero inode in the independently generated 4 KiB/256-byte fixture.
/// # Errors
/// Returns malformed geometry or an out-of-range inode coordinate.
fn fixture_inode_offset(disk: &Disk, node: NodeId) -> Result<usize> {
    let table = usize::try_from(fixture_u32(&disk.filesystem, 4104)?)
        .map_err(|_| Error::ArithmeticOverflow)?;
    let slot = usize::try_from(
        node.file_index()
            .checked_sub(1)
            .ok_or(Error::InvalidInode)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)?;
    table
        .checked_mul(4096)
        .and_then(|base| {
            slot.checked_mul(256)
                .and_then(|delta| base.checked_add(delta))
        })
        .ok_or(Error::ArithmeticOverflow)
}

/// # Errors
/// Returns fixture, inode allocation, namespace, commit, remount or payload-read failure.
/// # Panics
/// Fails if retiring committed or newly created inodes prevents an atomic replacement.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe the replacement namespace and contents after commit and remount"
)]
fn transaction_inode_retirement_preserves_replacement_and_next_transaction_allocation() -> Result<()>
{
    let mut fixture = Fixture::new()?;
    let replacement = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.unlink_file(root, &Ext4Name::new(b"concurrent-a")?)?;
        let metadata = NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?);
        let transient = pass.create_file(root, &Ext4Name::new(b"transient")?, metadata)?;
        pass.write_file_range(transient, FileOffset::ZERO, b"temporary")?;
        pass.unlink_file(root, &Ext4Name::new(b"transient")?)?;
        let replacement = pass.create_file(root, &Ext4Name::new(b"replacement")?, metadata)?;
        pass.write_file_range(replacement, FileOffset::ZERO, b"replacement")?;
        Ok(replacement.id())
    })?;
    fixture.remount()?;
    let mut bytes = [0; 11];
    assert_eq!(
        fixture.read(|pass| pass.read_file(replacement, FileOffset::ZERO, &mut bytes))?,
        ReadBytes::from_usize(11)
    );
    assert_eq!(&bytes, b"replacement");
    for name in [b"concurrent-a".as_slice(), b"transient".as_slice()] {
        assert!(matches!(
            fixture.read(|pass| pass.lookup_child(DirectoryNodeId::ROOT, &Ext4Name::new(name)?))?,
            ChildLookup::NotFound
        ));
    }
    let next = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let next = pass.create_file(
            root,
            &Ext4Name::new(b"next")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )?;
        pass.write_file_range(next, FileOffset::ZERO, b"next")?;
        Ok(next.id())
    })?;
    fixture.remount()?;
    let mut bytes = [0; 4];
    fixture.read(|pass| pass.read_file(next, FileOffset::ZERO, &mut bytes))?;
    assert_eq!(&bytes, b"next");
    Ok(())
}

/// # Errors
/// Returns fixture, hard-link, resolution, commit or inode-reuse failures.
/// # Panics
/// Fails if a surviving link retires its allocation or final unlink omits its retirement.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe resolved lifecycle publications and committed namespace behavior"
)]
fn final_unlink_publishes_retirement_before_inode_reuse() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let source = pass.hard_link_source(HardLinkNodeId::File(file))?;
        pass.create_hard_link(
            source,
            root,
            &Ext4Name::new(b"retained-alias")?,
            NamespaceDestination::Vacant,
        )
    })?;
    for (name, final_link) in [
        (b"retained-alias".as_slice(), false),
        (b"concurrent-a".as_slice(), true),
    ] {
        let ticket = fixture.coordinator.admit_mutation()?;
        let (resolved, ()) = fixture.disk.resolve(
            &fixture.profile,
            &fixture.epoch,
            &fixture.coordinator,
            ticket,
            &mut PlainCrypto,
            |pass| {
                let root = pass.directory(DirectoryNodeId::ROOT)?;
                pass.unlink_file(root, &Ext4Name::new(name)?)
            },
        )?;
        let reserved = resolved.reserve(
            fixture.coordinator.grant_intent(ticket),
            &fixture.coordinator,
        )?;
        let updates = reserved.node_metadata_updates();
        assert_eq!(
            updates.iter().any(|update| matches!(update,
                NodeMetadataUpdate::Retired { inode } if *inode == NodeId::File(file).inode()
            )),
            final_link
        );
        assert_eq!(
            updates.iter().any(|update| matches!(update,
                NodeMetadataUpdate::Live { metadata, .. } if metadata.node() == NodeId::File(file)
            )),
            !final_link
        );
        let ready = reserved.prepare_commit(
            fixture
                .coordinator
                .acquire_commit(ticket)?
                .ok_or(Error::ClusterReferenceConflict)?,
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
        )?;
        fixture.epoch =
            fixture
                .disk
                .commit(&mut fixture.coordinator, &mut fixture.cache, ticket, ready)?;
    }
    let replacement = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let replacement = pass.create_file(
            root,
            &Ext4Name::new(b"concurrent-a")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o644)?),
        )?;
        pass.write_file_range(replacement, FileOffset::ZERO, b"replacement")?;
        Ok(replacement.id())
    })?;
    // This fixture's first-free allocator must exercise the retired number, not a fresh slot.
    assert_eq!(replacement, file);
    fixture.remount()?;
    let mut bytes = [0; 11];
    fixture.read(|pass| pass.read_file(replacement, FileOffset::ZERO, &mut bytes))?;
    assert_eq!(&bytes, b"replacement");
    Ok(())
}

/// Shares one independently encoded external attribute block between two fixture inodes.
/// Header and inode checksums authenticate the requested count, even when it disagrees with owners.
/// # Errors
/// Returns malformed fixture geometry, missing external storage, or field bounds.
fn shared_xattr_fixture(refcount: u32) -> Result<Fixture> {
    shared_xattr_fixture_values(refcount, 0, 1, 512)
}

/// Constructs a shared block with a chosen set of format-level value references.
/// # Errors
/// Propagates allocation, mutation, field and independent checksum construction failures.
#[expect(
    clippy::disallowed_methods,
    reason = "checked fixture field copies use matching slice lengths"
)]
fn shared_xattr_fixture_values(
    refcount: u32,
    features: u32,
    count: u8,
    size: usize,
) -> Result<Fixture> {
    let mut fixture = fixture_with_incompatible_features(features)?;
    let a = fixture.a;
    let b = fixture.b;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(a))?;
        for index in 0..count {
            let name = if index == 0 {
                b"shared".to_vec()
            } else {
                alloc::vec![b'a'.checked_add(index).ok_or(Error::ArithmeticOverflow)?]
            };
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::User, &name)?,
                XattrValue::new(&alloc::vec![b'A'; size])?,
            )?;
        }
        Ok(())
    })?;
    let a_offset = fixture_inode_offset(&fixture.disk, NodeId::File(a))?;
    let b_offset = fixture_inode_offset(&fixture.disk, NodeId::File(b))?;
    let field = |base: usize, offset: usize, width: usize| -> Result<core::ops::Range<usize>> {
        let start = base.checked_add(offset).ok_or(Error::ArithmeticOverflow)?;
        Ok(start..start.checked_add(width).ok_or(Error::ArithmeticOverflow)?)
    };
    for (offset, width) in [(28, 4), (104, 4), (118, 2)] {
        let bytes = fixture
            .disk
            .filesystem
            .get(field(a_offset, offset, width)?)
            .ok_or(Error::DeviceRange)?
            .to_vec();
        fixture
            .disk
            .filesystem
            .get_mut(field(b_offset, offset, width)?)
            .ok_or(Error::DeviceRange)?
            .copy_from_slice(&bytes);
    }
    let flags = fixture_u32(
        &fixture.disk.filesystem,
        b_offset.checked_add(32).ok_or(Error::ArithmeticOverflow)?,
    )?;
    fixture.disk.encode_inode(NodeId::File(b), flags, None)?;
    let block = u64::from(fixture_u32(
        &fixture.disk.filesystem,
        a_offset.checked_add(104).ok_or(Error::ArithmeticOverflow)?,
    )?);
    if block == 0 {
        return Err(Error::InvalidXattr);
    }
    let base = usize::try_from(block.checked_mul(4096).ok_or(Error::ArithmeticOverflow)?)
        .map_err(|_| Error::DeviceRange)?;
    fixture
        .disk
        .filesystem
        .get_mut(field(base, 4, 4)?)
        .ok_or(Error::DeviceRange)?
        .copy_from_slice(&refcount.to_le_bytes());
    fixture
        .disk
        .filesystem
        .get_mut(field(base, 16, 4)?)
        .ok_or(Error::DeviceRange)?
        .fill(0);
    let seed = fixture_crc32c(
        u32::MAX,
        fixture
            .disk
            .filesystem
            .get(1128..1144)
            .ok_or(Error::DeviceRange)?,
    );
    let checksum = fixture_crc32c(
        fixture_crc32c(seed, &block.to_le_bytes()),
        fixture
            .disk
            .filesystem
            .get(field(base, 0, 4096)?)
            .ok_or(Error::DeviceRange)?,
    );
    fixture
        .disk
        .filesystem
        .get_mut(field(base, 16, 4)?)
        .ok_or(Error::DeviceRange)?
        .copy_from_slice(&checksum.to_le_bytes());
    fixture.disk.storage_effects = 0;
    Ok(fixture)
}

/// # Errors
/// Propagates shared format-vector construction, reference release, read and remount failures.
/// # Panics
/// Fails if shared-block owners are mistaken for extra physical value entries.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe external value retention after removing a shared block owner"
)]
fn attribute_value_entries_in_shared_blocks_have_one_reference() -> Result<()> {
    let mut fixture = shared_xattr_fixture_values(2, 0x400, 5, 8192)?;
    fixture.remount()?;
    let a = fixture.a;
    let b = fixture.b;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(a))?;
        pass.set_xattr(
            node,
            XattrName::new(XattrNamespace::User, b"shared")?,
            XattrValue::new(b"replacement")?,
        )
    })?;
    fixture.remount()?;
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.unlink_file(root, &Ext4Name::new(b"concurrent-a")?)
    })?;
    fixture.remount()?;
    let value = fixture
        .read(|pass| {
            pass.read_xattr(
                NodeId::File(b),
                &XattrName::new(XattrNamespace::User, b"shared")?,
            )
        })?
        .ok_or(Error::InvalidXattr)?;
    assert_eq!(value.bytes(), &[b'A'; 8192]);
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.unlink_file(root, &Ext4Name::new(b"concurrent-b")?)
    })?;
    fixture.remount()?;
    Ok(())
}

/// # Errors
/// Returns independent fixture construction failures.
/// # Panics
/// Fails if authenticated but inconsistent xattr ownership can grant mount or write authority.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check mount rejection and absence of storage effects"
)]
fn external_xattr_counts_match_exact_inode_ownership_before_mount() -> Result<()> {
    for count in [0, 1, 3] {
        let mut fixture = shared_xattr_fixture(count)?;
        assert_eq!(
            fixture.disk.mount(MountAccess::ReadWrite).err(),
            Some(Error::InvalidXattr),
            "count={count}"
        );
        assert_eq!(fixture.disk.storage_effects, 0, "count={count}");
    }
    Ok(())
}

/// # Errors
/// Returns mount, mutation, read, or fixture construction failures.
/// # Panics
/// Fails if a valid shared block update alters another inode or leaves invalid ownership.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare independently encoded shared values after remount"
)]
fn shared_xattr_copy_on_write_and_release_preserve_other_owners() -> Result<()> {
    let mut fixture = shared_xattr_fixture(2)?;
    fixture.remount()?;
    let a = fixture.a;
    let b = fixture.b;
    fixture.mutate(|pass| {
        let node = pass.node(NodeId::File(a))?;
        pass.set_xattr(
            node,
            XattrName::new(XattrNamespace::User, b"shared")?,
            XattrValue::new(&[b'B'; 512])?,
        )
    })?;
    fixture.remount()?;
    for (file, expected) in [(a, b'B'), (b, b'A')] {
        let value = fixture
            .read(|pass| {
                pass.read_xattr(
                    NodeId::File(file),
                    &XattrName::new(XattrNamespace::User, b"shared")?,
                )
            })?
            .ok_or(Error::InvalidXattr)?;
        assert!(value.bytes().iter().all(|byte| *byte == expected));
    }
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        pass.unlink_file(root, &Ext4Name::new(b"concurrent-a")?)?;
        pass.unlink_file(root, &Ext4Name::new(b"concurrent-b")?)
    })?;
    fixture.remount()?;
    Ok(())
}

/// # Errors
/// Returns fixture construction or geometry failures.
/// # Panics
/// Fails if corrupted ownership or allocation can reach mount publication or a storage effect.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify rejection before any mount write or flush"
)]
fn persisted_metadata_checksums_precede_mount_authority() -> Result<()> {
    let fixture = Fixture::new()?;
    let inode = fixture_inode_offset(&fixture.disk, NodeId::File(fixture.a))?;
    let block_bitmap = usize::try_from(fixture_u32(&fixture.disk.filesystem, 4096)?)
        .map_err(|_| Error::ArithmeticOverflow)?
        .checked_mul(4096)
        .ok_or(Error::ArithmeticOverflow)?;
    let inode_bitmap = usize::try_from(fixture_u32(&fixture.disk.filesystem, 4100)?)
        .map_err(|_| Error::ArithmeticOverflow)?
        .checked_mul(4096)
        .ok_or(Error::ArithmeticOverflow)?;
    let slot = usize::try_from(
        NodeId::File(fixture.a)
            .file_index()
            .checked_sub(1)
            .ok_or(Error::InvalidInode)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)?;
    for (offset, mask) in [
        (inode.checked_add(2).ok_or(Error::ArithmeticOverflow)?, 1_u8),
        (inode.checked_add(124).ok_or(Error::ArithmeticOverflow)?, 1),
        (block_bitmap, 1),
        (
            inode_bitmap
                .checked_add(slot / 8)
                .ok_or(Error::ArithmeticOverflow)?,
            1_u8.checked_shl(u32::try_from(slot % 8).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?,
        ),
    ] {
        let mut disk = Disk {
            filesystem: fixture.disk.filesystem.to_vec(),
            journal: fixture.disk.journal.to_vec(),
            storage_effects: 0,
        };
        *disk.filesystem.get_mut(offset).ok_or(Error::DeviceRange)? ^= mask;
        assert_eq!(
            disk.mount(MountAccess::ReadWrite).err(),
            Some(Error::ChecksumMismatch),
            "offset={offset}"
        );
        assert_eq!(disk.storage_effects, 0, "offset={offset}");
    }
    Ok(())
}

/// # Errors
/// Returns fixture construction, geometry or cache allocation failures.
/// # Panics
/// Fails if a disk inode can confer read or mutation authority without its checksum.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions exercise ordinary read and mutation boundaries after a corrupt storage read"
)]
fn persisted_inode_checksums_precede_access_and_mutation() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let offset = fixture_inode_offset(&fixture.disk, NodeId::File(a))?
        .checked_add(2)
        .ok_or(Error::ArithmeticOverflow)?;
    *fixture
        .disk
        .filesystem
        .get_mut(offset)
        .ok_or(Error::DeviceRange)? ^= 1;
    fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
    assert_eq!(
        fixture.read(|pass| pass.load_access(NodeId::File(a))).err(),
        Some(Error::ChecksumMismatch)
    );
    let effects = fixture.disk.storage_effects;
    assert_eq!(
        fixture
            .mutate(|pass| {
                let file = pass.file(a)?;
                pass.write_file_range(file, FileOffset::ZERO, b"replacement")
            })
            .err(),
        Some(Error::ChecksumMismatch)
    );
    assert_eq!(fixture.disk.storage_effects, effects);
    Ok(())
}

/// # Errors
/// Returns fixture construction or wire-field range failures.
/// # Panics
/// Fails if clearing a required JBD2 CRC permits recovery or any storage effect.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions exercise the external journal probe and mount protocol on an independently generated journal"
)]
fn journal_checksum_zero_does_not_disable_authentication() -> Result<()> {
    let mut disk = Disk::fixture();
    disk.journal
        .get_mut(4348..4352)
        .ok_or(Error::DeviceRange)?
        .fill(0);
    assert_eq!(
        disk.mount(MountAccess::ReadWrite).err(),
        Some(Error::ChecksumMismatch)
    );
    assert_eq!(disk.storage_effects, 0);
    Ok(())
}

/// # Errors
/// Returns fixture encoding failures.
/// # Panics
/// Fails if an unsupported format selector reaches journal replay or mount writes.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check mount rejection and absence of external storage effects"
)]
fn mount_rejects_unsupported_format_selectors_before_storage_effects() -> Result<()> {
    for (offset, bytes) in [(1100, [2, 0, 0, 0].as_slice()), (1397, [2].as_slice())] {
        let mut disk = Disk::fixture();
        for (target, byte) in disk.filesystem.iter_mut().skip(offset).zip(bytes) {
            *target = *byte;
        }
        let checksum = fixture_crc32c(
            u32::MAX,
            disk.filesystem.get(1024..2044).ok_or(Error::DeviceRange)?,
        );
        for (target, byte) in disk
            .filesystem
            .iter_mut()
            .skip(2044)
            .zip(checksum.to_le_bytes())
        {
            *target = byte;
        }
        assert_eq!(
            disk.mount(MountAccess::ReadWrite).err(),
            Some(Error::UnsupportedWriteFeature)
        );
        assert_eq!(disk.storage_effects, 0);
    }
    Ok(())
}

/// # Errors
/// Returns ext4 fixture, mutation, storage or allocation failures.
/// # Panics
/// Fails if opaque user values change inode-read or payload-write eligibility.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe opaque ext4 attributes and committed file contents"
)]
fn user_xattr_values_remain_opaque_through_metadata_and_content_mutation() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    for name in [
        b"arbitrary".as_slice(),
        b"ext4win.attributes",
        b"ext4win.reparse.symlink",
    ] {
        fixture.mutate(|pass| {
            let node = pass.node(NodeId::File(file))?;
            pass.set_xattr(
                node,
                XattrName::new(XattrNamespace::User, name)?,
                XattrValue::new(b"opaque")?,
            )
        })?;
    }
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.write_file_range(file, FileOffset::ZERO, b"Z")
    })?;
    fixture.remount()?;
    let snapshot = fixture.read(|pass| pass.load_node_metadata(NodeId::File(file)))?;
    assert_eq!(snapshot.size(), FileSize::from_bytes(1));
    for name in [b"ext4win.attributes".as_slice(), b"ext4win.reparse.symlink"] {
        let value = fixture.read(|pass| {
            pass.read_xattr(
                NodeId::File(file),
                &XattrName::new(XattrNamespace::User, name)?,
            )
        })?;
        assert_eq!(
            value.as_ref().map(XattrValue::bytes),
            Some(b"opaque".as_slice())
        );
    }
    let mut bytes = [0; 1];
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?;
    assert_eq!(&bytes, b"Z");
    Ok(())
}

/// # Errors
/// Returns fixture, acquisition, mutation-resolution or preparation failures.
/// # Panics
/// Fails if revocation revalidates an older lease or an owned preparation admits another commit.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify journal ownership through real resolve and prepare boundaries"
)]
fn journal_acquisition_revocation_and_preparation_are_exclusive() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let resolve = |fixture: &mut Fixture| -> Result<ReservedMutation> {
        let (resolved, ()) = fixture.disk.resolve(
            &fixture.profile,
            &fixture.epoch,
            &fixture.coordinator,
            ticket,
            &mut PlainCrypto,
            |pass| pass.set_volume_label(Ext4VolumeLabel::new(b"exclusive")?),
        )?;
        resolved.reserve(
            fixture.coordinator.grant_intent(ticket),
            &fixture.coordinator,
        )
    };
    let old = fixture
        .coordinator
        .acquire_commit(ticket)?
        .ok_or(Error::DeviceIo)?;
    assert!(fixture.coordinator.acquire_commit(ticket)?.is_none());
    fixture.coordinator.revoke_unprepared_commit(ticket);
    let current = fixture
        .coordinator
        .acquire_commit(ticket)?
        .ok_or(Error::DeviceIo)?;
    assert!(matches!(
        resolve(&mut fixture)?.prepare_commit(
            old,
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    let prepared = resolve(&mut fixture)?.prepare_commit(
        current,
        &mut fixture.coordinator,
        &fixture.epoch,
        &mut fixture.cache,
    )?;
    fixture.coordinator.revoke_unprepared_commit(ticket);
    assert!(fixture.coordinator.acquire_commit(ticket)?.is_none());
    prepared
        .abort(&mut fixture.coordinator, &mut fixture.cache)
        .map_err(|(error, _prepared)| error)?;
    assert!(fixture.coordinator.journal_is_clean());
    let foreign = Fixture::new()?;
    let reserved = resolve(&mut fixture)?;
    let grant = fixture
        .coordinator
        .acquire_commit(ticket)?
        .ok_or(Error::DeviceIo)?;
    assert!(matches!(
        reserved.prepare_commit(
            grant,
            &mut fixture.coordinator,
            &foreign.epoch,
            &mut fixture.cache
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    assert!(fixture.coordinator.journal_is_clean());
    fixture.mutate(|pass| pass.set_volume_label(Ext4VolumeLabel::new(b"after-abort")?))?;
    assert_eq!(
        fixture.epoch.identity().label(),
        Ext4VolumeLabel::new(b"after-abort")?
    );
    Ok(())
}
