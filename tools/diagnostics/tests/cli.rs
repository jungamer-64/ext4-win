//! Process-boundary contracts: explicit paths, JSON evidence and nonzero checksum outcomes.
#![forbid(unsafe_code)]
extern crate alloc;
use core::error::Error;
use serde_json::{Value, json};
use std::{
    fs, io,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

/// Writes independent known-answer wire fields without unchecked fixture indexing.
/// # Errors
/// Returns overflowing or out-of-range fixture fields.
fn put(bytes: &mut [u8], offset: usize, data: &[u8]) -> io::Result<()> {
    let end = offset
        .checked_add(data.len())
        .ok_or_else(|| io::Error::other("fixture offset overflow"))?;
    let destination = bytes
        .get_mut(offset..end)
        .ok_or_else(|| io::Error::other("fixture range"))?;
    for (destination, source) in destination.iter_mut().zip(data) {
        *destination = *source;
    }
    Ok(())
}

/// Checksum success and mismatch remain distinguishable after crossing the executable boundary.
/// # Errors
/// Returns fixture I/O, process, JSON or generated-directory cleanup failures.
/// # Panics
/// Panics if exit codes or emitted JSON lose the requested checksum result.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions intentionally fail executable contract tests after fallible setup"
)]
fn checksum_exit_contract() -> Result<(), Box<dyn Error>> {
    let instant = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("ext4win-cli-{}-{instant}", std::process::id()));
    fs::create_dir(&root)?;
    let operation = (|| -> Result<(), Box<dyn Error>> {
        let mut superblock = [0_u8; 1024];
        for (offset, bytes) in [
            (24, 2_u32.to_le_bytes().to_vec()),
            (56, 0xef53_u16.to_le_bytes().to_vec()),
            (96, 0x2000_u32.to_le_bytes().to_vec()),
            (100, 0x400_u32.to_le_bytes().to_vec()),
            (0x175, vec![1]),
            (0x270, 0x1234_5678_u32.to_le_bytes().to_vec()),
        ] {
            put(&mut superblock, offset, &bytes)?;
        }
        let mut block = vec![0_u8; 4096];
        for (offset, bytes) in [
            (0, 0xf30a_u16.to_le_bytes().to_vec()),
            (2, 1_u16.to_le_bytes().to_vec()),
            (4, 1_u16.to_le_bytes().to_vec()),
            (16, 3_u16.to_le_bytes().to_vec()),
            (20, 0x0001_0203_u32.to_le_bytes().to_vec()),
            (24, 0xb6cf_3f8e_u32.to_le_bytes().to_vec()),
        ] {
            put(&mut block, offset, &bytes)?;
        }
        fs::write(root.join("superblock.bin"), superblock)?;
        for expected in [true, false] {
            if !expected {
                put(&mut block, 12, &[1])?;
            }
            fs::write(root.join("extent.bin"), &block)?;
            let output = Command::new(env!("CARGO_BIN_EXE_ext4-diagnostics"))
                .current_dir(&root)
                .args([
                    "extent",
                    "--superblock",
                    "superblock.bin",
                    "--block",
                    "extent.bin",
                    "--inode",
                    "0x1234",
                    "--generation",
                    "0x01020304",
                ])
                .output()?;
            assert_eq!(output.status.success(), expected);
            assert_eq!(
                serde_json::from_slice::<Value>(&output.stdout)?.get("matches"),
                Some(&json!(expected))
            );
            assert!(output.stderr.is_empty());
        }
        Ok(())
    })();
    let cleanup = (|| -> io::Result<()> {
        for entry in fs::read_dir(&root)? {
            fs::remove_file(entry?.path())?;
        }
        fs::remove_dir(&root)
    })();
    match (operation, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error.into()),
        (Err(error), Err(cleanup)) => {
            Err(io::Error::other(format!("{error}; CLI fixture cleanup: {cleanup}")).into())
        }
    }
}
