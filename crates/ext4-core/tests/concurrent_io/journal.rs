//! JBD2 recovery against independently encoded records and selected crash persistence.

use super::fast_commit::{allocated, inject_range};
use super::*;

/// Block size and superblock offset for the tracked 4 KiB external journal fixture.
pub(super) const JOURNAL_SUPER: usize = 4096;
/// Filesystem block size for the external-journal fixture.
const BLOCK_BYTES: usize = 4096;
/// An otherwise unreferenced home block used to observe a replayed payload.
const PAYLOAD_HOME: u32 = 1001;

/// Overwrites a checked part of an independently encoded image.
/// # Errors
/// Returns an overflowing or truncated fixture field.
pub(super) fn put(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<()> {
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
pub(super) fn be32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::DeviceRange)?;
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..end)
            .ok_or(Error::DeviceRange)?
            .try_into()
            .map_err(|_| Error::DeviceRange)?,
    ))
}

/// Converts a fixture block number into its byte offset.
/// # Errors
/// Rejects unrepresentable offsets.
fn block_offset(block: u32) -> Result<usize> {
    usize::try_from(block)
        .ok()
        .and_then(|block| block.checked_mul(BLOCK_BYTES))
        .ok_or(Error::DeviceRange)
}

/// Sets the selected tail and refreshes the checksum over the JBD2 superblock payload.
/// # Errors
/// Returns a truncated fixture header.
fn set_tail(journal: &mut [u8], start: u32, sequence: u32) -> Result<()> {
    let superblock = journal
        .get_mut(JOURNAL_SUPER..JOURNAL_SUPER + 1024)
        .ok_or(Error::DeviceRange)?;
    put(superblock, 0x18, &sequence.to_be_bytes())?;
    put(superblock, 0x1c, &start.to_be_bytes())?;
    put(superblock, 0xfc, &[0; 4])?;
    let checksum = fixture_crc32c(u32::MAX, superblock);
    put(superblock, 0xfc, &checksum.to_be_bytes())
}

/// Reads the UUID-derived checksum seed used by the fixture's v3 descriptor and commit records.
/// # Errors
/// Returns a truncated journal UUID.
fn journal_checksum_seed(journal: &[u8]) -> Result<u32> {
    let uuid = journal
        .get(JOURNAL_SUPER + 0x30..JOURNAL_SUPER + 0x40)
        .ok_or(Error::DeviceRange)?;
    Ok(fixture_crc32c(u32::MAX, uuid))
}

/// Encodes the common record header in a zeroed fixture block.
/// # Errors
/// Returns a truncated header field.
fn control_block(kind: u32, sequence: u32) -> Result<[u8; BLOCK_BYTES]> {
    let mut block = [0; BLOCK_BYTES];
    put(&mut block, 0, &0xc03b_3998_u32.to_be_bytes())?;
    put(&mut block, 4, &kind.to_be_bytes())?;
    put(&mut block, 8, &sequence.to_be_bytes())?;
    Ok(block)
}

/// Writes a v3 commit block at the specified logical position.
/// # Errors
/// Returns fixture range or checksum-field failure.
fn write_commit(journal: &mut [u8], logical: u32, sequence: u32) -> Result<()> {
    let mut block = control_block(2, sequence)?;
    let checksum = fixture_crc32c(journal_checksum_seed(journal)?, &block);
    put(&mut block, 16, &checksum.to_be_bytes())?;
    put(journal, block_offset(logical)?, &block)
}

/// Writes a contiguous descriptor, payload and commit. The tag explicitly carries its journal UUID.
/// # Errors
/// Returns an unrepresentable or truncated fixture range.
fn write_single_payload_transaction(
    journal: &mut [u8],
    start: u32,
    sequence: u32,
    payload: &[u8; BLOCK_BYTES],
) -> Result<()> {
    let seed = journal_checksum_seed(journal)?;
    let uuid = journal
        .get(JOURNAL_SUPER + 0x30..JOURNAL_SUPER + 0x40)
        .ok_or(Error::DeviceRange)?;
    let mut descriptor = control_block(1, sequence)?;
    put(&mut descriptor, 12, &PAYLOAD_HOME.to_be_bytes())?;
    put(&mut descriptor, 16, &8_u32.to_be_bytes())?;
    let checksum = fixture_crc32c(fixture_crc32c(seed, &sequence.to_be_bytes()), payload);
    put(&mut descriptor, 24, &checksum.to_be_bytes())?;
    put(&mut descriptor, 28, uuid)?;
    let tail = fixture_crc32c(seed, &descriptor);
    put(&mut descriptor, BLOCK_BYTES - 4, &tail.to_be_bytes())?;
    put(journal, block_offset(start)?, &descriptor)?;
    let data = start.checked_add(1).ok_or(Error::DeviceRange)?;
    put(journal, block_offset(data)?, payload)?;
    write_commit(
        journal,
        data.checked_add(1).ok_or(Error::DeviceRange)?,
        sequence,
    )
}

/// # Errors
/// Propagates fixture encoding, crash injection, remount and file read failures.
/// # Panics
/// Fails if pre-commit ring reuse makes a durable fast commit undiscoverable.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions observe the crash point and subsequent allocation and file content"
)]
fn wrapped_conversion_keeps_fast_commit_discoverable_after_reordered_persistence() -> Result<()> {
    let mut fixture = Fixture::new()?;
    put(
        &mut fixture.disk.filesystem,
        1000 * BLOCK_BYTES,
        b"replayed",
    )?;
    let old_block = inject_range(&mut fixture, 1000)?;
    let journal = &mut fixture.disk.journal;
    let superblock = journal.get(JOURNAL_SUPER..).ok_or(Error::DeviceRange)?;
    let first = be32(superblock, 0x14)?;
    let fast_tid = be32(superblock, 0x18)?;
    let ring_end = be32(superblock, 0x10)?
        .checked_sub(be32(superblock, 0x54)?)
        .ok_or(Error::DeviceRange)?;
    let transaction_count = ring_end
        .checked_sub(first)
        .and_then(|count| count.checked_sub(1))
        .ok_or(Error::DeviceRange)?
        / 3;
    let oldest_tid = fast_tid.wrapping_sub(transaction_count);
    // Fill the old prefix with byte-identical home images so the test can isolate journal persistence.
    let payload = fixture
        .disk
        .filesystem
        .get(block_offset(PAYLOAD_HOME)?..block_offset(PAYLOAD_HOME + 1)?)
        .ok_or(Error::DeviceRange)?
        .try_into()
        .map_err(|_| Error::DeviceRange)?;
    let mut start = first;
    for index in 0..transaction_count {
        write_single_payload_transaction(journal, start, oldest_tid.wrapping_add(index), payload)?;
        start = start.checked_add(3).ok_or(Error::DeviceRange)?;
    }
    set_tail(journal, first, oldest_tid)?;

    let mut crash_journal = journal.clone();
    let mut wrapped = false;
    let oldest_record = block_offset(first)?;
    let result = fixture
        .disk
        .mount_observing(MountAccess::ReadWrite, |disk, boundary, _| {
            match boundary {
                MountBoundary::Lower(StorageRequest::Flush {
                    target: StorageTarget::ExternalJournal,
                }) => {
                    crash_journal.clone_from(&disk.journal);
                }
                MountBoundary::Lower(StorageRequest::Write {
                    target: StorageTarget::ExternalJournal,
                    offset,
                    buffer,
                }) if usize::try_from(offset.get()) == Ok(oldest_record) => {
                    // Only this pending write survives. Earlier writes survive only up to the last
                    // successful journal flush.
                    put(&mut crash_journal, oldest_record, buffer)?;
                    wrapped = true;
                    return Err(Error::DeviceIo);
                }
                _ => {}
            }
            Ok(())
        });
    assert!(matches!(result, Err(Error::DeviceIo)));
    assert!(wrapped);
    fixture.disk.journal = crash_journal;
    fixture.remount()?;
    assert!(allocated(&fixture.disk, 1000)?);
    assert!(!allocated(&fixture.disk, old_block)?);
    let file = fixture.a;
    let mut bytes = [0; 8];
    fixture.read(|pass| pass.read_file(file, FileOffset::ZERO, &mut bytes))?;
    assert_eq!(&bytes, b"replayed");
    Ok(())
}
