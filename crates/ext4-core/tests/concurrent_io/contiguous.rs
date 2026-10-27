//! Contiguous initialization observed through durable inode fields and physical payload bytes.

use super::*;

/// # Errors
/// Propagates fixture, initialization, independent inode decoding or recovery failure.
/// # Panics
/// Fails if one transaction exceeds 64 KiB, chooses a small free hole, exposes stale bytes or
/// changes the physical address or data of a prefix already acknowledged to a physical reader.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "assertions compare checkpointed payload against independently addressed disk bytes and inode fields")]
fn contiguous_initialization_bounds_progress_and_preserves_physical_prefix() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    // This leaves a small earlier free hole beside the independently allocated second file.
    fixture.mutate(|pass| { let file = pass.file(file)?; pass.truncate_file(file, FileSize::from_bytes(0)) })?;
    let target = FileSize::from_bytes(135_168);
    let mut origin = None;
    for expected in [65_536, 131_072, 135_168] {
        let storage = fixture.mutate(|pass| { let file = pass.file(file)?; pass.initialize_contiguous_file_tail(file, target) })?;
        assert_eq!(storage.length().bytes(), expected);
        assert_eq!(*origin.get_or_insert(storage.physical()), storage.physical());
        let inode = fixture_inode_offset(&fixture.disk, NodeId::File(file))?;
        assert_eq!(u64::from(fixture_u32(&fixture.disk.filesystem, inode + 4)?), expected);
        let physical = u64::from(fixture_u32(&fixture.disk.filesystem, inode + 60)?);
        assert_eq!(physical.checked_mul(4096), Some(storage.physical().get()));
        let start = usize::try_from(storage.physical().get()).map_err(|_| Error::ArithmeticOverflow)?;
        let end = start.checked_add(usize::try_from(expected).map_err(|_| Error::ArithmeticOverflow)?).ok_or(Error::ArithmeticOverflow)?;
        assert!(fixture.disk.filesystem.get(start..end).ok_or(Error::DeviceRange)?.iter().all(|byte| *byte == 0));
        fixture.remount()?;
        assert_eq!(fixture.read(|pass| pass.contiguous_file_storage(file))?, storage);
    }
    let origin = origin.ok_or(Error::DeviceRange)?;
    let start = usize::try_from(origin.get()).map_err(|_| Error::ArithmeticOverflow)?;
    fixture.disk.filesystem.get_mut(start..start.checked_add(4096).ok_or(Error::ArithmeticOverflow)?).ok_or(Error::DeviceRange)?.fill(0x5a);
    let extended = fixture.mutate(|pass| { let file = pass.file(file)?; pass.initialize_contiguous_file_tail(file, FileSize::from_bytes(139_264)) })?;
    assert_eq!(extended.physical(), origin);
    assert_eq!(extended.length().bytes(), 139_264);
    assert!(fixture.disk.filesystem.get(start..start.checked_add(4096).ok_or(Error::ArithmeticOverflow)?).ok_or(Error::DeviceRange)?.iter().all(|byte| *byte == 0x5a));
    Ok(())
}

/// # Errors
/// Propagates fixture, bounded setup, competing physical allocation or committed read failures.
/// # Panics
/// Fails if a later occupied tail can move the old map or submit any failed-pass media effect.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "assertions compare a rejected exact-tail claim with independent media effects and the last committed prefix")]
fn contiguous_tail_collision_retains_last_durable_prefix_without_effects() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    fixture.mutate(|pass| { let file = pass.file(file)?; pass.truncate_file(file, FileSize::from_bytes(0)) })?;
    let target = FileSize::from_bytes(131_072);
    let prefix = fixture.mutate(|pass| { let file = pass.file(file)?; pass.initialize_contiguous_file_tail(file, target) })?;
    assert_eq!(fixture.epoch.geometry().cluster_size().bytes(), 4096);
    let occupied = ClusterAddress::new(prefix.physical().get().checked_add(65_536).ok_or(Error::ArithmeticOverflow)? / 4096);
    let other = fixture.b;
    fixture.mutate(|pass| { let other = pass.file(other)?; pass.move_file_clusters(other, FileOffset::ZERO, occupied, ClusterCount::new(1)?) })?;
    let effects = fixture.disk.storage_effects;
    let rejected = fixture.mutate(|pass| { let file = pass.file(file)?; pass.initialize_contiguous_file_tail(file, target) });
    assert_eq!(rejected, Err(Error::NoSpace));
    assert_eq!(fixture.disk.storage_effects, effects);
    assert_eq!(fixture.read(|pass| pass.contiguous_file_storage(file))?, prefix);
    let mut other_byte = [0];
    fixture.read(|pass| pass.read_file(other, FileOffset::ZERO, &mut other_byte))?;
    assert_eq!(other_byte, [b'b']);
    Ok(())
}

/// # Errors
/// Propagates fixture or bounded initialization resolution failure.
/// # Panics
/// Fails if physical-map setup may acknowledge before the transaction's home checkpoint.
#[test]
#[expect(clippy::panic_in_result_fn, reason = "assertions observe the resolved transaction's actual durability contract")]
fn contiguous_initialization_requires_home_checkpoint() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let file = fixture.a;
    fixture.mutate(|pass| { let file = pass.file(file)?; pass.truncate_file(file, FileSize::from_bytes(0)) })?;
    let ticket = fixture.coordinator.admit_mutation()?;
    let (resolved, prefix) = fixture.disk.resolve(&fixture.profile, &fixture.epoch, &fixture.coordinator,
        ticket, &mut PlainCrypto, |pass| { let file = pass.file(file)?; pass.initialize_contiguous_file_tail(file, FileSize::from_bytes(131_072)) })?;
    assert_eq!(prefix.length().bytes(), 65_536);
    assert_eq!(resolved.completion_durability(), MutationCompletionDurability::HomeCheckpoint);
    Ok(())
}
