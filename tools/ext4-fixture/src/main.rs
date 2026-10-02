//! Native Linux fixture operations using filesystem syscalls and independent e2fsprogs output.
#![forbid(unsafe_code)]
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
    process::{Command, ExitCode},
    time::{SystemTime, UNIX_EPOCH},
};

/// Executes one explicit fixture operation and reports its terminal outcome.
fn main() -> ExitCode {
    match execute(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fixture operation failed: {error}");
            ExitCode::FAILURE
        }
    }
}
/// Dispatches supported Linux-local fixture capabilities.
/// # Errors
/// Returns malformed arguments, I/O, oracle, or mutation failures.
fn execute(arguments: Vec<String>) -> io::Result<()> {
    match arguments.as_slice() {
        [command, root, count, width] if command == "populate-mounted" => populate(
            Path::new(root),
            count.parse().map_err(io::Error::other)?,
            width.parse().map_err(io::Error::other)?,
        ),
        [command, image] if command == "encryption-namespace" => namespace(Path::new(image)),
        [command, image] if command == "live-directory" => live(Path::new(image)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ext4-fixture <populate-mounted ROOT COUNT NAME_BYTES|encryption-namespace IMAGE|live-directory IMAGE>",
        )),
    }
}
/// Creates a mounted directory through Linux native hard-link operations, preserving kernel HTree construction.
/// Width is a minimum byte length; zero keeps generated names without padding.
/// # Errors
/// Returns invalid profile geometry or filesystem mutation failures.
fn populate(root: &Path, count: usize, width: usize) -> io::Result<()> {
    if count == 0 || width > 255 {
        return Err(io::Error::other("invalid directory profile geometry"));
    }
    let directory = root.join("depth2");
    fs::create_dir(&directory)?;
    let mut target = root.join("target-0");
    for index in 0..count {
        if index % 50000 == 0 {
            target = root.join(format!("target-{index}"));
            File::create(&target)?;
        }
        let mut name = format!("depth-{index:05}-");
        name.extend(core::iter::repeat_n('x', width.saturating_sub(name.len())));
        fs::hard_link(&target, directory.join(name))?;
    }
    Ok(())
}

/// Encodes only the ext4 encryption namespace byte that debugfs cannot spell.
/// # Errors
/// Returns oracle parsing, unexpected inline attribute, or image-write failures.
fn namespace(image: &Path) -> io::Result<()> {
    for name in [
        "/locked",
        "/locked/abcdefghijklmnop",
        "/locked/ponmlkjihgfedcba",
    ] {
        let output = Command::new("debugfs")
            .args(["-R", &format!("imap {name}")])
            .arg(image)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        let text = String::from_utf8(output.stdout).map_err(io::Error::other)?;
        let (_, location) = text
            .split_once("located at block ")
            .ok_or_else(|| io::Error::other("imap omitted inode location"))?;
        let (block, offset) = location
            .split_once(", offset ")
            .ok_or_else(|| io::Error::other("imap omitted byte offset"))?;
        let block: u64 = block.parse().map_err(io::Error::other)?;
        let offset = offset
            .split_whitespace()
            .next()
            .and_then(|value| value.strip_prefix("0x"))
            .ok_or_else(|| io::Error::other("invalid imap byte offset"))?;
        let offset = u64::from_str_radix(offset, 16).map_err(io::Error::other)?;
        let base = block
            .checked_mul(4096)
            .and_then(|base| base.checked_add(offset))
            .and_then(|base| base.checked_add(128))
            .ok_or_else(|| io::Error::other("inode byte offset overflow"))?;
        let mut disk = OpenOptions::new().read(true).write(true).open(image)?;
        disk.seek(SeekFrom::Start(base))?;
        let mut extra = [0_u8; 2];
        disk.read_exact(&mut extra)?;
        let attribute = base
            .checked_add(u64::from(u16::from_le_bytes(extra)))
            .ok_or_else(|| io::Error::other("attribute offset overflow"))?;
        disk.seek(SeekFrom::Start(attribute))?;
        let mut header = [0_u8; 24];
        disk.read_exact(&mut header)?;
        if header.get(..6) != Some(&[0, 0, 2, 234, 1, 0]) || header.get(20) != Some(&b'c') {
            return Err(io::Error::other(
                "unexpected oracle inline attribute layout",
            ));
        }
        disk.seek(SeekFrom::Start(
            attribute
                .checked_add(5)
                .ok_or_else(|| io::Error::other("namespace offset overflow"))?,
        ))?;
        disk.write_all(&[9])?;
        disk.sync_all()?;
    }
    Ok(())
}

/// Streams the independent live fixture's hard-link workload into a debugfs request file.
/// # Errors
/// Returns writer errors.
fn live_commands(mut output: impl Write) -> io::Result<()> {
    writeln!(output, "mkdir /live-ci/large-directory")?;
    for group in 0_usize..2 {
        let target = format!("/live-ci/large-target-{group}");
        writeln!(output, "write /dev/null {target}")?;
        let begin = group
            .checked_mul(50000)
            .ok_or_else(|| io::Error::other("fixture count overflow"))?;
        let end = begin
            .checked_add(50000)
            .ok_or_else(|| io::Error::other("fixture count overflow"))?;
        for index in begin..end {
            if index != 0 && index % 200 == 0 {
                writeln!(output, "expand_dir /live-ci/large-directory")?;
            }
            writeln!(
                output,
                "ln {target} /live-ci/large-directory/entry-{index:06}"
            )?;
        }
        writeln!(output, "set_inode_field {target} links_count 50001")?;
    }
    Ok(())
}
/// Generates and optimizes the disposable live directory through the independent filesystem oracle.
/// # Errors
/// Returns request-file, debugfs diagnostics, e2fsck, or mandatory cleanup failures.
fn live(image: &Path) -> io::Result<()> {
    let instant = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let requests = env::temp_dir().join(format!(
        "ext4win-live-{}-{instant}.debugfs",
        std::process::id()
    ));
    let result = (|| {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&requests)?;
        let mut writer = io::BufWriter::new(file);
        live_commands(&mut writer)?;
        writer.flush()?;
        drop(writer);
        let output = Command::new("debugfs")
            .args(["-w", "-f"])
            .arg(&requests)
            .arg(image)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        let diagnostics = String::from_utf8(output.stderr).map_err(io::Error::other)?;
        if diagnostics
            .lines()
            .any(|line| !line.is_empty() && !line.starts_with("debugfs "))
        {
            return Err(io::Error::other(diagnostics));
        }
        let status = Command::new("e2fsck").arg("-fyD").arg(image).status()?;
        if !matches!(status.code(), Some(0 | 1)) {
            return Err(io::Error::other(format!(
                "fixture optimization failed: {status}"
            )));
        }
        Ok(())
    })();
    let cleanup = if requests.exists() {
        fs::remove_file(&requests)
    } else {
        Ok(())
    };
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(io::Error::other(format!(
            "fixture: {operation}; cleanup: {cleanup}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The workload has a fixed independently known namespace count and bounded inode link count.
    /// # Errors
    /// Returns request serialization or UTF-8 errors.
    /// # Panics
    /// Panics when the fixture does not describe all 100000 names.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture assertions intentionally fail the test; fallible preparation retains its diagnostics"
    )]
    fn live_namespace_contract() -> io::Result<()> {
        let mut bytes = Vec::new();
        live_commands(&mut bytes)?;
        let text = String::from_utf8(bytes).map_err(io::Error::other)?;
        assert_eq!(
            text.lines().filter(|line| line.starts_with("ln ")).count(),
            100000
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.ends_with("links_count 50001"))
                .count(),
            2
        );
        assert!(text.contains("entry-000000"));
        assert!(text.contains("entry-099999"));
        Ok(())
    }

    /// Mounted profiles preserve native generated names and independently requested padding.
    /// # Errors
    /// Returns filesystem or generated-directory cleanup failures.
    /// # Panics
    /// Panics if native and padded profiles expose different names or hard-link content.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "filesystem assertions intentionally fail fixture contract tests after fallible setup"
    )]
    fn mounted_name_profiles() -> io::Result<()> {
        let instant = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let root =
            env::temp_dir().join(format!("ext4win-populate-{}-{instant}", std::process::id()));
        fs::create_dir(&root)?;
        let operation = (|| -> io::Result<()> {
            for width in [0, 255] {
                let directory = root.join(format!("profile-{width}"));
                fs::create_dir(&directory)?;
                populate(&directory, 2, width)?;
                let mut name = "depth-00000-".to_owned();
                name.extend(core::iter::repeat_n('x', width.saturating_sub(name.len())));
                fs::write(directory.join("target-0"), b"independent link content")?;
                assert_eq!(
                    fs::read(directory.join("depth2").join(name))?,
                    b"independent link content"
                );
                assert_eq!(
                    fs::read_dir(directory.join("depth2"))?
                        .collect::<io::Result<Vec<_>>>()?
                        .len(),
                    2
                );
            }
            Ok(())
        })();
        let cleanup = (|| -> io::Result<()> {
            for entry in fs::read_dir(&root)? {
                let directory = entry?.path();
                let children = directory.join("depth2");
                for child in fs::read_dir(&children)? {
                    fs::remove_file(child?.path())?;
                }
                fs::remove_dir(&children)?;
                fs::remove_file(directory.join("target-0"))?;
                fs::remove_dir(&directory)?;
            }
            fs::remove_dir(&root)
        })();
        match (operation, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(io::Error::other(format!(
                "{error}; fixture cleanup: {cleanup}"
            ))),
        }
    }
}
