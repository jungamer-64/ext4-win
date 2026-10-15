//! Concurrent read and mutation contracts over independently generated ext4 journal fixtures.

#![feature(allocator_api)]

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use ext4_core::*;
use sha2::Digest as _;

/// Independent hashing and HKDF oracle; plaintext fixtures must never invoke a cipher.
#[derive(Debug)]
struct PlainCrypto;

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
        .reserve(&fixture.coordinator, MutationLease::granted(ticket))?
        .prepare_commit(
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
            CommitLease::granted(ticket),
        )?;
    let ordered = fixture.disk.sequence(prepared.start())?;
    fixture.disk.checked(ordered.flush_request())?;
    drop(ordered);
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
        |pass| {
            let target = pass.file(file)?;
            pass.write_file_range(target, FileOffset::from_bytes(1), b"SECRET")
        },
    )?;
    let prepared = resolved
        .reserve(&fixture.coordinator, MutationLease::granted(ticket))?
        .prepare_commit(
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
            CommitLease::granted(ticket),
        )?;
    {
        let ordered = fixture.disk.sequence(prepared.start())?;
        fixture.disk.checked(ordered.flush_request())?;
        // A crash loses preparation and publication state after data reaches its home block.
    }
    let (profile, epoch, coordinator) = fixture.disk.mount()?.into_parts();
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
        |pass| {
            let target = pass.file(file)?;
            pass.write_file_range(target, FileOffset::ZERO, b"J")?;
            pass.write_file_range(target, FileOffset::ZERO, b"K")
        },
    )?;
    let ready = resolved
        .reserve(&fixture.coordinator, MutationLease::granted(ticket))?
        .prepare_commit(
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
            CommitLease::granted(ticket),
        )?;
    let StorageRequestSequenceStep::Finished(ordered) = ready.start().advance() else {
        return Err(Error::InvalidWriteRange);
    };
    fixture.disk.checked(ordered.flush_request())?;
    let payload = fixture.disk.sequence(ordered.completed())?;
    fixture.disk.checked(payload.flush_request())?;
    let (request, durable) = payload.completed().submit();
    fixture.disk.checked(request)?;
    fixture.disk.checked(durable.flush_request())?;
    assert_eq!(fixture.disk.filesystem.get(home), Some(&b'a'));
    let (epoch, checkpoint) = durable
        .completed()
        .publish(&mut fixture.coordinator, VisibilityLease::granted(ticket))
        .into_parts();
    fixture.epoch = epoch;
    fixture.cache.publish(&fixture.epoch);
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut byte))?;
    assert_eq!(byte, *b"K");
    assert_eq!(fixture.disk.filesystem.get(home), Some(&b'a'));
    let home_writes = fixture
        .disk
        .sequence(checkpoint.start(CheckpointLease::granted(fixture.epoch.sequence())))?;
    fixture.disk.checked(home_writes.flush_request())?;
    let (request, clean) = home_writes.completed().submit();
    fixture.disk.checked(request)?;
    fixture.disk.checked(clean.flush_request())?;
    fixture.epoch = clean.completed(&mut fixture.coordinator);
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

/// Only these private in-memory copies are mutated; tracked fixture images remain inputs.
#[derive(Debug)]
struct Disk {
    filesystem: Vec<u8>,
    journal: Vec<u8>,
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
    #[expect(
        clippy::disallowed_methods,
        reason = "each fixture copy uses a checked range with the exact encoded field width"
    )]
    fn encode_inode(&mut self, node: NodeId, flags: u32, context: Option<&[u8; 40]>) -> Result<()> {
        let number = node.file_index();
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
        }
    }

    /// # Errors
    /// Returns an invalid device range before copying a malformed transfer.
    fn complete(&mut self, mut request: StorageRequest) -> Result<StorageCompletion> {
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
    fn mount(&mut self) -> Result<CompletedMount> {
        let length = u64::try_from(self.filesystem.len()).map_err(|_| Error::DeviceRange)?;
        let mut step = Box::try_new(MountOperation::new(
            DeviceLength::from_bytes(length),
            FscryptKeySet::empty(),
        ))
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
    fn checked(&mut self, request: StorageRequest) -> Result<()> {
        StorageRequestIdentity::from_request(&request).complete(self.complete(request)?)
    }

    /// # Errors
    /// Returns the first failed transfer in the production sequence.
    fn sequence<N>(&mut self, mut sequence: StorageRequestSequence<N>) -> Result<N> {
        loop {
            match sequence.advance() {
                StorageRequestSequenceStep::Submit { request, suspended } => {
                    self.checked(request)?;
                    sequence = suspended;
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
        self.checked(ordered.flush_request())?;
        let payload = self.sequence(ordered.completed())?;
        self.checked(payload.flush_request())?;
        let (request, durable) = payload.completed().submit();
        self.checked(request)?;
        self.checked(durable.flush_request())?;
        let (epoch, checkpoint) = durable
            .completed()
            .publish(coordinator, VisibilityLease::granted(ticket))
            .into_parts();
        cache.publish(&epoch);
        let home = self.sequence(checkpoint.start(CheckpointLease::granted(epoch.sequence())))?;
        self.checked(home.flush_request())?;
        let (request, clean) = home.completed().submit();
        self.checked(request)?;
        self.checked(clean.flush_request())?;
        let epoch = clean.completed(coordinator);
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
            let mut crypto = PlainCrypto;
            let result = {
                let mut pass = ready.begin_pass(
                    cache.access(epoch),
                    Ext4Timestamp::from_seconds(2),
                    &mut crypto,
                );
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
#[derive(Debug)]
struct Fixture {
    disk: Disk,
    profile: MountedProfile,
    epoch: CommittedEpoch,
    coordinator: MutationCoordinatorState,
    cache: MetadataCache,
    a: FileNodeId,
    b: FileNodeId,
}

impl Fixture {
    /// Replaces mount-local state with independently recovered storage state.
    /// # Errors
    /// Returns mount recovery or cache allocation failure.
    fn remount(&mut self) -> Result<()> {
        let (profile, epoch, coordinator) = self.disk.mount()?.into_parts();
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
            .reserve(&self.coordinator, MutationLease::granted(ticket))?
            .prepare(
                &mut self.coordinator,
                &self.epoch,
                CommitLease::granted(ticket),
            )?;
        self.epoch = prepared.publish(&mut self.coordinator, VisibilityLease::granted(ticket))?;
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
                &mut PlainCrypto,
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
        let (profile, epoch, mut coordinator) = disk.mount()?.into_parts();
        let ticket = coordinator.admit_mutation()?;
        let (resolved, (a, b)) = disk.resolve(&profile, &epoch, &coordinator, ticket, |pass| {
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
        })?;
        let mut cache = MetadataCache::try_new(&epoch)?;
        let ready = resolved
            .reserve(&coordinator, MutationLease::granted(ticket))?
            .prepare_commit(
                &mut coordinator,
                &epoch,
                &mut cache,
                CommitLease::granted(ticket),
            )?;
        let epoch = disk.commit(&mut coordinator, &mut cache, ticket, ready)?;
        Ok(Self {
            disk,
            profile,
            epoch,
            coordinator,
            cache,
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
            mutate,
        )?;
        let ready = resolved
            .reserve(&self.coordinator, MutationLease::granted(ticket))?
            .prepare_commit(
                &mut self.coordinator,
                &self.epoch,
                &mut self.cache,
                CommitLease::granted(ticket),
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
                &mut PlainCrypto,
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
        .reserve(&fixture.coordinator, MutationLease::granted(ticket_a))?
        .prepare_commit(
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
            CommitLease::granted(ticket_a),
        )?;
    fixture.epoch = fixture.disk.commit(
        &mut fixture.coordinator,
        &mut fixture.cache,
        ticket_a,
        ready,
    )?;
    assert!(matches!(
        b_update.reserve(&fixture.coordinator, MutationLease::granted(ticket_b)),
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
        |pass| {
            let file = pass.file(a)?;
            pass.write_file_range(file, FileOffset::ZERO, b"A")
        },
    )?;
    let ready = resolved
        .reserve(&fixture.coordinator, MutationLease::granted(ticket))?
        .prepare_commit(
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
            CommitLease::granted(ticket),
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
            .reserve(&fixture.coordinator, MutationLease::granted(ticket))?
            .prepare(
                &mut fixture.coordinator,
                &fixture.epoch,
                CommitLease::granted(ticket),
            )?;
    drop(abandoned);
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
    let (_, remounted, _) = fixture.disk.mount()?.into_parts();
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
        stale.reserve(&fixture.coordinator, MutationLease::granted(stale_ticket)),
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
    let (profile, epoch, coordinator) = fixture.disk.mount()?.into_parts();
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
        |pass| {
            let file = pass.file(a)?;
            pass.truncate_file(file, FileSize::from_bytes(0))
        },
    )?;
    let reserved = reserved.reserve(
        &fixture.coordinator,
        MutationLease::granted(reserved_ticket),
    )?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let removal =
        ResolvedKeyChange::remove(&fixture.epoch, &fixture.coordinator, ticket, identifier)?;
    fixture.publish_keys(removal)?;
    assert!(matches!(
        pending.reserve(&fixture.coordinator, MutationLease::granted(pending_ticket)),
        Err(Error::ClusterReferenceConflict)
    ));
    assert!(matches!(
        reserved.prepare_commit(
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
            CommitLease::granted(reserved_ticket)
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
        resolved.reserve(&fixture.coordinator, MutationLease::granted(ticket)),
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
        let visible = WindowsName::from_ext4(entry.name())?;
        let found = fixture
            .read(|pass| pass.lookup_windows_child(directory, &visible, WindowsNameMatch::Exact))?;
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
