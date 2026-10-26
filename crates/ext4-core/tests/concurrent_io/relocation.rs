//! Allocation movement and physical retirement observed independently at device offsets.

use super::*;

/// Finds test space from the externally observable allocation bitmap.
/// # Errors
/// Returns fixture read, coordinate or free-space exhaustion failures.
fn destination(fixture: &mut Fixture) -> Result<ClusterAddress> {
    destination_run(fixture, 1)
}

/// Selects a contiguous free test destination without changing allocation authority.
/// # Errors
/// Returns bitmap reads, coordinate or free-space exhaustion failures.
fn destination_run(fixture: &mut Fixture, count: u64) -> Result<ClusterAddress> {
    let mut bitmap = [0; 128];
    fixture.read(|pass| pass.read_cluster_bitmap(ClusterAddress::new(0), &mut bitmap))?;
    for cluster in 0..fixture.epoch.geometry().cluster_count().as_u64().min(1024) {
        let byte = usize::try_from(cluster / 8).map_err(|_| Error::ArithmeticOverflow)?;
        let end = cluster.checked_add(count).ok_or(Error::ArithmeticOverflow)?;
        if end > fixture.epoch.geometry().cluster_count().as_u64().min(1024) { break; }
        let mut free = bitmap.get(byte).ok_or(Error::DeviceRange)? & (1 << (cluster % 8)) == 0;
        for next in cluster..end {
            let byte = usize::try_from(next / 8).map_err(|_| Error::ArithmeticOverflow)?;
            free &= bitmap.get(byte).ok_or(Error::DeviceRange)? & (1 << (next % 8)) == 0;
        }
        if free {
            return Ok(ClusterAddress::new(cluster));
        }
    }
    Err(Error::NoSpace)
}

/// # Errors
/// Returns fixture, inode flag encoding, mount or physical relocation resolution failure.
/// # Panics
/// Fails if journaled relocation can acknowledge before its destination payload reaches home.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "assertions observe the completion contract derived from exact staged relocation effects")]
fn relocation_requires_home_checkpoint_for_physical_destination_readers() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    fixture.disk.encode_inode(NodeId::File(file), 0x0008_4000, None)?;
    fixture.remount()?;
    let target = destination(&mut fixture)?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let (resolved, ()) = fixture.disk.resolve(&fixture.profile, &fixture.epoch, &fixture.coordinator,
        ticket, &mut PlainCrypto, |pass| {
            let file = pass.file(file)?;
            pass.move_file_clusters(file, FileOffset::ZERO, target, ClusterCount::new(1)?)
        })?;
    assert_eq!(resolved.completion_durability(), MutationCompletionDurability::HomeCheckpoint);
    Ok(())
}

/// # Errors
/// Returns fixture, sparse extension, movement, bitmap or payload read failure.
/// # Panics
/// Fails if moving virtual clusters allocates a sparse hole or changes zero-read contents.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "assertions compare sparse file contents and independent destination bitmap bits")]
fn relocation_preserves_sparse_virtual_clusters() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.write_file_range(file, FileOffset::from_bytes(8192), b"Z")
    })?;
    let target = destination_run(&mut fixture, 3)?;
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.move_file_clusters(file, FileOffset::ZERO, target, ClusterCount::new(3)?)
    })?;
    let mut content = vec![0xff; 8193];
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut content))?;
    assert_eq!(content.first(), Some(&b'a'));
    assert_eq!(content.last(), Some(&b'Z'));
    assert!(content.get(1..8192).ok_or(Error::DeviceRange)?.iter().all(|byte| *byte == 0));
    let mut bitmap = [0; 1];
    fixture.read(|pass| pass.read_cluster_bitmap(target, &mut bitmap))?;
    assert_eq!(bitmap.first().ok_or(Error::DeviceRange)? & 7, 5);
    let rejected = fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.move_file_clusters(file, FileOffset::ZERO, target, ClusterCount::new(4)?)
    });
    assert!(matches!(rejected, Err(Error::InvalidWriteRange)));
    Ok(())
}

/// # Errors
/// Returns fixture, policy, resolution, commit preparation or remount failure.
/// # Panics
/// Fails if uncommitted zero images destroy the old file or its physical home data.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "assertions observe independent physical bytes before commit and after recovery")]
fn zero_retirement_does_not_modify_the_old_file_before_commit() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.set_zero_on_deallocation(file)
    })?;
    let mut byte = [0];
    let (_read, request) = fixture.suspend_payload(file, &mut byte)?;
    let home = usize::try_from(request.offset().ok_or(Error::DeviceRange)?.get()).map_err(|_| Error::ArithmeticOverflow)?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let (resolved, ()) = fixture.disk.resolve(&fixture.profile, &fixture.epoch, &fixture.coordinator,
        ticket, &mut PlainCrypto, |pass| {
            let file = pass.file(file)?;
            pass.truncate_file(file, FileSize::from_bytes(0))
        })?;
    assert_eq!(resolved.completion_durability(), MutationCompletionDurability::HomeCheckpoint);
    let prepared = resolved.reserve(fixture.coordinator.grant_intent(ticket), &fixture.coordinator)?
        .prepare_commit(fixture.coordinator.acquire_commit(ticket)?.ok_or(Error::ClusterReferenceConflict)?,
            &mut fixture.coordinator, &fixture.epoch, &mut fixture.cache)?;
    let ordered = fixture.disk.sequence(prepared.start())?;
    let payload_sequence = fixture.disk.transfer(ordered.submit())?;
    let payload = fixture.disk.sequence(payload_sequence)?;
    assert_eq!(fixture.disk.filesystem.get(home), Some(&b'a'));
    drop(payload);
    fixture.remount()?;
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut byte))?;
    assert_eq!(byte, [b'a']);
    assert_eq!(fixture.disk.filesystem.get(home), Some(&b'a'));
    Ok(())
}

/// # Errors
/// Returns fixture, relocation, storage or remount failure.
/// # Panics
/// Fails if exact destination selection loses content, changes allocation charge or accepts reuse.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "assertions compare independent input and physical destination bytes")]
fn relocation_preserves_payload_and_rejects_occupied_destination() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    let target = destination(&mut fixture)?;
    let geometry = fixture.epoch.geometry();
    let destination_byte = geometry.allocation_start()?.get()
        .checked_add(target.get().checked_mul(u64::from(geometry.cluster_size().bytes())).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::ArithmeticOverflow)?;
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.move_file_clusters(file, FileOffset::ZERO, target, ClusterCount::new(1)?)
    })?;
    let mut byte = [0];
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut byte))?;
    assert_eq!(byte, [b'a']);
    assert_eq!(fixture.disk.filesystem.get(usize::try_from(destination_byte).map_err(|_| Error::ArithmeticOverflow)?), Some(&b'a'));
    let occupied = fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.move_file_clusters(file, FileOffset::ZERO, target, ClusterCount::new(1)?)
    });
    assert!(matches!(occupied, Err(Error::NoSpace)));
    fixture.remount()?;
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut byte))?;
    assert_eq!(byte, [b'a']);
    Ok(())
}

/// # Errors
/// Returns fixture, policy selection, truncation or remount failure.
/// # Panics
/// Fails if retired physical storage retains any original payload after checkpoint.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "assertions observe full original physical blocks after retirement")]
fn zero_deallocation_persists_policy_and_erases_retired_home_storage() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    let mut byte = [0];
    let (_read, request) = fixture.suspend_payload(file, &mut byte)?;
    let home = usize::try_from(request.offset().ok_or(Error::DeviceRange)?.get()).map_err(|_| Error::ArithmeticOverflow)?;
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.set_zero_on_deallocation(file)
    })?;
    fixture.remount()?;
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.truncate_file(file, FileSize::from_bytes(0))
    })?;
    assert!(fixture.disk.filesystem.get(home..home + 4096).ok_or(Error::DeviceRange)?.iter().all(|byte| *byte == 0));
    fixture.remount()?;
    assert!(fixture.disk.filesystem.get(home..home + 4096).ok_or(Error::DeviceRange)?.iter().all(|byte| *byte == 0));
    Ok(())
}

/// # Errors
/// Returns inline fixture, namespace, conversion, truncation or physical read failures.
/// # Panics
/// Fails if zero retirement can retain resident payload or lose contents during extent conversion.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "assertions observe payload preservation, allocation and physical retirement")]
fn zero_policy_converts_inline_file_before_accepting_retirement() -> Result<()> {
    let mut fixture = inline_fixture()?;
    let file = fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let file = pass.create_file(root, &Ext4Name::new(b"zero-inline")?,
            NewFileMetadata::new(namespace_owner(), Ext4Permissions::new(0o600)?))?;
        pass.write_file_range(file, FileOffset::ZERO, b"resident-secret")?;
        Ok(file.id())
    })?;
    assert_eq!(fixture.read(|pass| Ok(pass.load_file(file)?.allocation_size().bytes()))?, 0);
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.set_zero_on_deallocation(file)
    })?;
    assert!(fixture.read(|pass| Ok(pass.load_file(file)?.allocation_size().bytes()))? > 0);
    let mut bytes = [0; 15];
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?;
    assert_eq!(&bytes, b"resident-secret");
    let mut byte = [0];
    let (_read, request) = fixture.suspend_payload(file, &mut byte)?;
    let home = usize::try_from(request.offset().ok_or(Error::DeviceRange)?.get()).map_err(|_| Error::ArithmeticOverflow)?;
    fixture.mutate(|pass| {
        let file = pass.file(file)?;
        pass.truncate_file(file, FileSize::from_bytes(0))
    })?;
    assert!(fixture.disk.filesystem.get(home..home + 4096).ok_or(Error::DeviceRange)?.iter().all(|byte| *byte == 0));
    Ok(())
}
