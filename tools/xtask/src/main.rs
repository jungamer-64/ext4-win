//! Host-side development and production verification workflows for ext4-win.

extern crate alloc;

use alloc::collections::BTreeSet;
use core::{error::Error, fmt::Write as _};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::{self, Command, ExitCode},
    time::{SystemTime, UNIX_EPOCH},
};

/// Dynamically dispatched error returned by one host workflow.
type TaskResult<T> = Result<T, Box<dyn Error>>;

/// Fixed marker prefix embedded in all identity-bound production artifacts.
const ARTIFACT_ID_MARKER: &str = "EXT4WIN_ARTIFACT_ID=";

/// Sentinel reserved for ordinary builds that did not pass the production workflow.
const UNVERIFIED_ARTIFACT_ID: &str = "00000000000000000000000000000000";

/// Cargo encoded-rustflags field separator.
const ENCODED_RUSTFLAGS_SEPARATOR: &str = "\u{1f}";

/// One supported host workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Task {
    /// Runs the complete host-independent development gate.
    VerifyPortable,
    /// Builds and verifies one signed, identity-bound Windows driver bundle.
    VerifyProductionDriver,
}

impl Task {
    /// Parses one exact task name.
    fn parse(argument: &OsStr) -> Option<Self> {
        if argument == "verify-portable" {
            Some(Self::VerifyPortable)
        } else if argument == "verify-production-driver" {
            Some(Self::VerifyProductionDriver)
        } else {
            None
        }
    }
}

/// Non-sentinel identity shared by one production build's IR, link map, and image.
#[derive(Debug, Eq, PartialEq)]
struct ArtifactIdentity(String);

impl ArtifactIdentity {
    /// Creates a process- and instant-bound 128-bit identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the system clock predates the Unix epoch, string formatting fails,
    /// or the generated value equals the reserved all-zero sentinel.
    fn create(repository_root: &Path) -> TaskResult<Self> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let mut hasher = Sha256::new();
        hasher.update(elapsed.as_nanos().to_le_bytes());
        hasher.update(process::id().to_le_bytes());
        hasher.update(repository_root.as_os_str().to_string_lossy().as_bytes());

        let mut value = String::with_capacity(UNVERIFIED_ARTIFACT_ID.len());
        for byte in hasher.finalize().iter().take(16) {
            write!(&mut value, "{byte:02x}")?;
        }
        if value == UNVERIFIED_ARTIFACT_ID {
            return Err(io::Error::other("generated the reserved artifact identity").into());
        }
        Ok(Self(value))
    }

    /// Returns the raw 32-digit identity.
    fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the complete marker embedded in generated artifacts.
    fn marker(&self) -> String {
        format!("{ARTIFACT_ID_MARKER}{}", self.0)
    }
}

/// Digest of all version-controlled and untracked source inputs to a production build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceSnapshot([u8; 32]);

/// Exact output paths belonging to one production build.
#[derive(Debug)]
struct ProductionArtifacts {
    /// Release LLVM IR emitted by rustc.
    ir: PathBuf,
    /// Final-image link map copied into the cargo-wdk package.
    link_map: PathBuf,
    /// Signed driver image copied into the cargo-wdk package.
    driver: PathBuf,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Parses and executes exactly one requested workflow.
///
/// # Errors
///
/// Returns an error for an invalid command line or any failed child workflow operation.
fn run() -> TaskResult<()> {
    let mut arguments = env::args_os();
    let _binary = arguments.next();
    let task = arguments
        .next()
        .as_deref()
        .and_then(Task::parse)
        .ok_or_else(usage_error)?;
    if arguments.next().is_some() {
        return Err(usage_error().into());
    }

    let repository_root = repository_root()?;
    match task {
        Task::VerifyPortable => verify_portable(&repository_root),
        Task::VerifyProductionDriver => verify_production_driver(&repository_root),
    }
}

/// Returns the stable command-line contract.
fn usage_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: cargo xtask <verify-portable|verify-production-driver>",
    )
}

/// Resolves the workspace root from the xtask package location.
///
/// # Errors
///
/// Returns an error when the compiled package location is not nested two levels below a root.
fn repository_root() -> Result<PathBuf, io::Error> {
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_directory
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("xtask is not nested below the workspace root"))
}

/// Runs formatting, checking, tests, and Clippy without selecting the WDK crate.
///
/// # Errors
///
/// Returns an error when a portable Cargo gate cannot start or exits unsuccessfully.
fn verify_portable(repository_root: &Path) -> TaskResult<()> {
    run_checked(
        cargo_command(repository_root, &["fmt", "--all", "--", "--check"]),
        "portable formatting gate",
    )?;
    run_checked(
        cargo_command(repository_root, &["check", "--locked", "--all-targets"]),
        "portable check gate",
    )?;
    run_checked(
        cargo_command(repository_root, &["test", "--locked"]),
        "portable test gate",
    )?;
    run_checked(
        cargo_command(repository_root, &["clippy", "--locked", "--all-targets"]),
        "portable Clippy gate",
    )?;
    println!("portable development gates: PASS");
    Ok(())
}

/// Builds and verifies one exact signed production driver bundle.
///
/// # Errors
///
/// Returns an error on non-Windows hosts, failed build or analysis commands, missing or invalid
/// artifacts, source drift, or artifact hashing failure.
fn verify_production_driver(repository_root: &Path) -> TaskResult<()> {
    if !cfg!(target_os = "windows") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "production driver verification requires a Windows host with MSVC and the WDK",
        )
        .into());
    }

    let source_before = source_snapshot(repository_root)?;
    let identity = ArtifactIdentity::create(repository_root)?;
    build_production_driver(repository_root, &identity)?;
    let artifacts = locate_production_artifacts(repository_root, &identity)?;
    run_production_reachability(repository_root, &artifacts)?;
    let source_after = source_snapshot(repository_root)?;
    if source_before != source_after {
        return Err(io::Error::other(
            "source inputs changed while the production artifact gate was running",
        )
        .into());
    }

    let ir_hash = sha256_file(&artifacts.ir)?;
    let map_hash = sha256_file(&artifacts.link_map)?;
    let driver_hash = sha256_file(&artifacts.driver)?;
    println!("production artifact bundle: PASS");
    println!("identity: {}", identity.as_str());
    println!("LLVM IR: {} ({ir_hash})", artifacts.ir.display());
    println!("link map: {} ({map_hash})", artifacts.link_map.display());
    println!(
        "signed driver: {} ({driver_hash})",
        artifacts.driver.display()
    );
    Ok(())
}

/// Invokes cargo-wdk from the sole driver package with child-local build identity and flags.
///
/// # Errors
///
/// Returns an error when cargo-wdk cannot start or exits unsuccessfully.
fn build_production_driver(repository_root: &Path, identity: &ArtifactIdentity) -> TaskResult<()> {
    let driver_root = repository_root.join("crates").join("ext4-driver");
    let encoded_rustflags = ["-C", "target-feature=+crt-static", "--emit=llvm-ir,link"]
        .join(ENCODED_RUSTFLAGS_SEPARATOR);
    let mut command = cargo_command(
        &driver_root,
        &[
            "wdk",
            "build",
            "--profile",
            "release",
            "--locked",
            "--verify-signature",
        ],
    );
    command
        .env("EXT4WIN_ARTIFACT_ID", identity.as_str())
        .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags)
        .env_remove("RUSTFLAGS");
    run_checked(command, "signed production driver build")?;
    Ok(())
}

/// Finds the fixed package outputs and the only LLVM IR carrying this build's identity.
///
/// # Errors
///
/// Returns an error when a fixed artifact is missing, traversal fails, or the identity does not
/// select exactly one LLVM IR file.
fn locate_production_artifacts(
    repository_root: &Path,
    identity: &ArtifactIdentity,
) -> TaskResult<ProductionArtifacts> {
    let release_root = repository_root.join("target").join("release");
    let package_root = release_root.join("ext4win_package");
    let link_map = package_root.join("ext4win.map");
    let driver = package_root.join("ext4win.sys");
    require_file(&link_map, "cargo-wdk package link map")?;
    require_file(&driver, "cargo-wdk signed package driver")?;

    let marker = identity.marker();
    let mut matching_ir = Vec::new();
    collect_identity_ir(&release_root, &marker, &mut matching_ir)?;
    if matching_ir.len() != 1 {
        return Err(io::Error::other(format!(
            "expected exactly one release ext4win.ll with identity {}; found {}",
            identity.as_str(),
            matching_ir.len()
        ))
        .into());
    }
    let ir = matching_ir
        .pop()
        .ok_or_else(|| io::Error::other("identity-bearing LLVM IR disappeared"))?;
    Ok(ProductionArtifacts {
        ir,
        link_map,
        driver,
    })
}

/// Recursively collects exact-name LLVM IR files containing one artifact marker.
///
/// # Errors
///
/// Returns an error when a directory entry or candidate LLVM IR file cannot be read.
fn collect_identity_ir(
    directory: &Path,
    marker: &str,
    matching: &mut Vec<PathBuf>,
) -> Result<(), io::Error> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_identity_ir(&entry.path(), marker, matching)?;
        } else if file_type.is_file() && entry.file_name() == "ext4win.ll" {
            let contents = fs::read_to_string(entry.path())?;
            if contents.contains(marker) {
                matching.push(entry.path());
            }
        }
    }
    Ok(())
}

/// Rejects a missing or non-file artifact path.
///
/// # Errors
///
/// Returns `NotFound` when `path` is not a regular file.
fn require_file(path: &Path, description: &str) -> Result<(), io::Error> {
    if path.is_file() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{description} was not produced: {}", path.display()),
        ))
    }
}

/// Runs the reachability analyzer against the exact production artifact bundle.
///
/// # Errors
///
/// Returns an error when the analyzer cannot start or exits unsuccessfully.
fn run_production_reachability(
    repository_root: &Path,
    artifacts: &ProductionArtifacts,
) -> TaskResult<()> {
    let mut command = cargo_command(
        repository_root,
        &[
            "run",
            "--locked",
            "-p",
            "production-reachability",
            "--release",
            "--",
        ],
    );
    command
        .arg(&artifacts.ir)
        .arg(&artifacts.link_map)
        .arg(&artifacts.driver);
    run_checked(command, "production reachability gate")?;
    Ok(())
}

/// Captures one stable digest of all source inputs selected by Git.
///
/// # Errors
///
/// Returns an error when Git fails, emits a non-UTF-8 path, or a selected file cannot be read.
fn source_snapshot(repository_root: &Path) -> TaskResult<SourceSnapshot> {
    let mut command = Command::new("git");
    command.arg("-C").arg(repository_root).args([
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        "crates",
        "tools",
        ".cargo",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
    ]);
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("git ls-files failed with {}", output.status)).into());
    }

    let relative_paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| String::from_utf8(bytes.to_vec()))
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut hasher = Sha256::new();
    for relative_path in relative_paths {
        let absolute_path = repository_root.join(Path::new(&relative_path));
        let contents = if absolute_path.is_file() {
            Some(fs::read(&absolute_path)?)
        } else {
            None
        };
        hash_source_record(&mut hasher, &relative_path, contents.as_deref());
    }
    Ok(SourceSnapshot(hasher.finalize().into()))
}

/// Adds one unambiguous path and file-state record to a source snapshot.
fn hash_source_record(hasher: &mut Sha256, relative_path: &str, contents: Option<&[u8]>) {
    hasher.update(relative_path.len().to_le_bytes());
    hasher.update(relative_path.as_bytes());
    match contents {
        Some(bytes) => {
            hasher.update([1]);
            hasher.update(bytes.len().to_le_bytes());
            hasher.update(Sha256::digest(bytes));
        }
        None => hasher.update([0]),
    }
}

/// Computes an uppercase SHA-256 digest for one artifact file.
///
/// # Errors
///
/// Returns an error when the file cannot be read or digest formatting fails.
fn sha256_file(path: &Path) -> TaskResult<String> {
    let digest = Sha256::digest(fs::read(path)?);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02X}")?;
    }
    Ok(output)
}

/// Creates one cargo child command rooted at an explicit package or workspace directory.
fn cargo_command(working_directory: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new("cargo");
    command.current_dir(working_directory).args(arguments);
    command
}

/// Executes one child process and reports a nonzero status as a workflow error.
///
/// # Errors
///
/// Returns an error when the child cannot start or exits unsuccessfully.
fn run_checked(mut command: Command, description: &str) -> TaskResult<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{description} failed with {status}")).into())
    }
}

#[cfg(test)]
mod tests {
    use super::{ArtifactIdentity, Sha256, Task, UNVERIFIED_ARTIFACT_ID, hash_source_record};
    use sha2::Digest as _;
    use std::{ffi::OsStr, path::Path};

    /// Artifact identities satisfy the build-script boundary without using the sentinel.
    ///
    /// # Panics
    ///
    /// Panics if identity generation fails or violates the exact build-script contract.
    #[test]
    fn artifact_identity_has_exact_boundary_shape() {
        let generated = ArtifactIdentity::create(Path::new("repository"));
        assert!(
            generated.is_ok(),
            "artifact identity generation must succeed"
        );
        let Some(identity) = generated.ok() else {
            return;
        };
        assert_eq!(identity.as_str().len(), UNVERIFIED_ARTIFACT_ID.len());
        assert_ne!(identity.as_str(), UNVERIFIED_ARTIFACT_ID);
        assert!(
            identity
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }

    /// Only the two documented, semantically distinct workflows are accepted.
    ///
    /// # Panics
    ///
    /// Panics if the parser accepts an ambiguous name or rejects a documented name.
    #[test]
    fn task_parser_rejects_ambiguous_commands() {
        assert_eq!(
            Task::parse(OsStr::new("verify-portable")),
            Some(Task::VerifyPortable)
        );
        assert_eq!(
            Task::parse(OsStr::new("verify-production-driver")),
            Some(Task::VerifyProductionDriver)
        );
        assert_eq!(Task::parse(OsStr::new("verify")), None);
    }

    /// Snapshot records distinguish content changes, missing files, and path changes.
    ///
    /// # Panics
    ///
    /// Panics if two semantically different source records produce the same digest.
    #[test]
    fn source_records_bind_path_state_and_content() {
        let baseline = record_digest("crates/a.rs", Some(b"one"));
        assert_ne!(baseline, record_digest("crates/a.rs", Some(b"two")));
        assert_ne!(baseline, record_digest("crates/b.rs", Some(b"one")));
        assert_ne!(baseline, record_digest("crates/a.rs", None));
    }

    /// Returns the digest of one normalized source record.
    fn record_digest(path: &str, contents: Option<&[u8]>) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hash_source_record(&mut hasher, path, contents);
        hasher.finalize().into()
    }
}
