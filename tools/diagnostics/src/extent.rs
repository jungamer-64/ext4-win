//! Independent ext4 checksum diagnostic; it deliberately does not call the production core.
use crate::{artifact::field, invalid};
use serde_json::{Value, json};
use std::io;

/// Calculates the reflected CRC32C recurrence without a production checksum dependency.
fn crc(mut seed: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        seed ^= u32::from(*byte);
        for _ in 0..8 {
            seed = (seed >> 1) ^ if seed & 1 == 1 { 0x82f6_3b78 } else { 0 };
        }
    }
    seed
}

/// Verifies one external extent block; this does not validate filesystem consistency.
/// # Errors
/// Returns malformed superblock, inode, geometry, header, or checksum-tail errors.
pub(crate) fn check(
    superblock: &[u8],
    inode: u64,
    generation: u64,
    block: &[u8],
) -> io::Result<Value> {
    if superblock.len() != 1024 || u16::from_le_bytes(field(superblock, 56)?) != 0xef53 {
        return Err(invalid("expected a 1024-byte ext superblock"));
    }
    let incompat = u32::from_le_bytes(field(superblock, 96)?);
    if u32::from_le_bytes(field(superblock, 100)?) & 0x400 == 0 || superblock.get(0x175) != Some(&1)
    {
        return Err(invalid(
            "superblock does not declare CRC32C metadata checksums",
        ));
    }
    let log = u32::from_le_bytes(field(superblock, 24)?);
    if log > 6 || 1024_usize.checked_shl(log) != Some(block.len()) {
        return Err(invalid(
            "extent block length disagrees with superblock geometry",
        ));
    }
    let inode = u32::try_from(inode).map_err(|_| invalid("inode outside on-disk range"))?;
    let generation =
        u32::try_from(generation).map_err(|_| invalid("generation outside on-disk range"))?;
    if inode == 0 {
        return Err(invalid("inode outside on-disk range"));
    }
    let entries = u16::from_le_bytes(field(block, 2)?);
    let maximum = u16::from_le_bytes(field(block, 4)?);
    let depth = u16::from_le_bytes(field(block, 6)?);
    let tail = usize::from(maximum)
        .checked_mul(12)
        .and_then(|size| size.checked_add(12))
        .ok_or_else(|| invalid("extent checksum tail overflow"))?;
    if u16::from_le_bytes(field(block, 0)?) != 0xf30a
        || maximum == 0
        || entries > maximum
        || depth > 5
    {
        return Err(invalid("invalid external extent header or checksum tail"));
    }
    let expected = u32::from_le_bytes(
        field(block, tail).map_err(|_| invalid("invalid extent checksum tail"))?,
    );
    let uuid: [u8; 16] = field(superblock, 104)?;
    let seed = if incompat & 0x2000 != 0 {
        u32::from_le_bytes(field(superblock, 0x270)?)
    } else {
        crc(u32::MAX, &uuid)
    };
    let seed = crc(crc(seed, &inode.to_le_bytes()), &generation.to_le_bytes());
    let actual = crc(
        seed,
        block
            .get(..tail)
            .ok_or_else(|| invalid("invalid extent checksum tail"))?,
    );
    Ok(
        json!({"success": actual == expected, "matches": actual == expected, "inode": inode, "generation": generation,
        "stored_crc32c": format!("{expected:08x}"), "computed_crc32c": format!("{actual:08x}"), "tail_byte_offset": tail,
        "entries": entries, "maximum": maximum, "depth": depth}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Known answers cover block geometries, UUID seeding, capacity-tail semantics and mismatch.
    /// # Errors
    /// Returns unexpected input-boundary failures.
    /// # Panics
    /// Panics if a spec-derived checksum or mismatch result changes.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "known-answer assertions fail this test; input preparation remains fallible"
    )]
    fn known_answers() -> io::Result<()> {
        assert_eq!(crc(u32::MAX, b"123456789") ^ u32::MAX, 0xe306_9283);
        for (log, maximum, answer) in [
            (0, 84_u16, 0x992a_6622_u32),
            (1, 169, 0x0de5_c751),
            (2, 340, 0x7a50_ae35),
            (2, 1, 0xb6cf_3f8e),
        ] {
            let mut superblock = [0_u8; 1024];
            let mut block = vec![
                0;
                1024_usize
                    .checked_shl(log)
                    .ok_or_else(|| invalid("fixture size"))?
            ];
            for (offset, bytes) in [
                (24, log.to_le_bytes().to_vec()),
                (56, 0xef53_u16.to_le_bytes().to_vec()),
                (96, 0x2000_u32.to_le_bytes().to_vec()),
                (100, 0x400_u32.to_le_bytes().to_vec()),
                (0x270, 0x1234_5678_u32.to_le_bytes().to_vec()),
                (0x175, vec![1]),
            ] {
                write(&mut superblock, offset, &bytes)?;
            }
            let tail = usize::from(maximum)
                .checked_mul(12)
                .and_then(|size| size.checked_add(12))
                .ok_or_else(|| invalid("fixture tail"))?;
            for (offset, bytes) in [
                (0, 0xf30a_u16.to_le_bytes().to_vec()),
                (2, 1_u16.to_le_bytes().to_vec()),
                (4, maximum.to_le_bytes().to_vec()),
                (16, 3_u16.to_le_bytes().to_vec()),
                (20, 0x10203_u32.to_le_bytes().to_vec()),
                (tail, answer.to_le_bytes().to_vec()),
            ] {
                write(&mut block, offset, &bytes)?;
            }
            assert_eq!(
                check(&superblock, 0x1234, 0x0102_0304, &block)?.get("matches"),
                Some(&json!(true))
            );
            if maximum == 1 {
                let byte = block.last_mut().ok_or_else(|| invalid("fixture padding"))?;
                *byte = 42;
                assert_eq!(
                    check(&superblock, 0x1234, 0x0102_0304, &block)?.get("matches"),
                    Some(&json!(true))
                );
            }
            if log == 2 && maximum == 340 {
                write(&mut superblock, 96, &0_u32.to_le_bytes())?;
                write(&mut block, tail, &0xfb54_1659_u32.to_le_bytes())?;
                assert_eq!(
                    check(&superblock, 0x1234, 0x0102_0304, &block)?.get("matches"),
                    Some(&json!(true))
                );
                write(&mut superblock, 96, &0x2000_u32.to_le_bytes())?;
                write(&mut block, tail, &answer.to_le_bytes())?;
            }
            if let Some(byte) = block.get_mut(12) {
                *byte ^= 1;
            }
            assert_eq!(
                check(&superblock, 0x1234, 0x0102_0304, &block)?.get("matches"),
                Some(&json!(false))
            );
            assert!(check(&superblock, 0, 0, &block).is_err());
        }
        Ok(())
    }
    /// Writes a synthetic wire field without unchecked fixture indexing.
    /// # Errors
    /// Returns an error when the fixture buffer cannot hold the field.
    fn write(bytes: &mut [u8], offset: usize, data: &[u8]) -> io::Result<()> {
        let end = offset
            .checked_add(data.len())
            .ok_or_else(|| invalid("fixture overflow"))?;
        let destination = bytes
            .get_mut(offset..end)
            .ok_or_else(|| invalid("fixture range"))?;
        for (destination, source) in destination.iter_mut().zip(data) {
            *destination = *source;
        }
        Ok(())
    }
}
