//! Host-side development and production verification workflows for ext4-win.

#![feature(allocator_api)]

extern crate alloc;

use alloc::collections::BTreeSet;
use core::{error::Error, fmt::Write as _, mem::size_of};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Seek as _, Write as _},
    path::{Path, PathBuf},
    process::{self, Command, ExitCode, Output},
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
    Portable,
    /// Checks, tests, lints, and documents the Windows driver crate.
    Driver,
    /// Generates Linux JBD2 transactions and verifies core recovery in both directions.
    JournalInterop,
    /// Reproduces tracked external-journal fixtures under the pinned Linux toolchain.
    JournalFixtureProvenance,
    /// Builds and verifies one signed, identity-bound Windows driver bundle.
    ProductionDriver,
}

impl Task {
    /// Parses one exact task name.
    fn parse(argument: &OsStr) -> Option<Self> {
        if argument == "verify-portable" {
            Some(Self::Portable)
        } else if argument == "verify-driver" {
            Some(Self::Driver)
        } else if argument == "verify-journal-interop" {
            Some(Self::JournalInterop)
        } else if argument == "verify-journal-fixture-provenance" {
            Some(Self::JournalFixtureProvenance)
        } else if argument == "verify-production-driver" {
            Some(Self::ProductionDriver)
        } else {
            None
        }
    }
}

/// Non-sentinel identity shared by one production build's IR, link map, and image.
#[derive(Debug, Eq, PartialEq)]
struct ArtifactIdentity(String);

/// Four-component Windows SDK/WDK directory version used to order installed toolsets.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct WindowsKitVersion([u32; 4]);

impl WindowsKitVersion {
    /// Parses the exact numeric directory form used below `Windows Kits\\10\\bin`.
    fn parse(value: &str) -> Option<Self> {
        let mut components = value.split('.');
        let mut parsed = [0_u32; 4];
        for component in &mut parsed {
            *component = components.next()?.parse().ok()?;
        }
        if components.next().is_some() {
            return None;
        }
        Some(Self(parsed))
    }
}

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

impl SourceSnapshot {
    /// Formats the exact source digest recorded in a production manifest.
    ///
    /// # Errors
    ///
    /// Returns an error only when hexadecimal formatting fails.
    fn hex_digest(&self) -> TaskResult<String> {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            write!(&mut output, "{byte:02X}")?;
        }
        Ok(output)
    }
}

/// Exact output paths belonging to one production build.
#[derive(Debug)]
struct ProductionArtifacts {
    /// Release LLVM IR emitted by rustc.
    ir: PathBuf,
    /// Final-image link map copied into the cargo-wdk package.
    link_map: PathBuf,
    /// Signed driver image copied into the cargo-wdk package.
    driver: PathBuf,
    /// Signed catalog copied into the cargo-wdk package.
    catalog: PathBuf,
    /// Installation metadata copied into the cargo-wdk package.
    inf: PathBuf,
}

/// Immutable analyzer inputs copied from one cryptographically re-verified production bundle.
#[derive(Debug)]
struct SealedProductionArtifacts {
    /// Private copies consumed by the reachability analyzer.
    artifacts: ProductionArtifacts,
    /// SHA-256 of the LLVM IR copy before analyzer execution.
    ir_hash: String,
    /// SHA-256 of the map copy before analyzer execution.
    map_hash: String,
    /// SHA-256 of the signed driver copy before analyzer execution.
    driver_hash: String,
    /// SHA-256 of the signed catalog copy before analyzer execution.
    catalog_hash: String,
    /// SHA-256 of the installation metadata copy before analyzer execution.
    inf_hash: String,
}

impl SealedProductionArtifacts {
    /// Rejects analyzer input mutation after the exact snapshot was sealed.
    ///
    /// # Errors
    ///
    /// Returns an error when any file read by the analyzer differs from its sealed hash.
    fn verify_unchanged(&self) -> TaskResult<()> {
        verify_sha256(&self.artifacts.ir, &self.ir_hash, "sealed LLVM IR")?;
        verify_sha256(&self.artifacts.link_map, &self.map_hash, "sealed link map")?;
        verify_sha256(
            &self.artifacts.driver,
            &self.driver_hash,
            "sealed signed driver",
        )?;
        verify_sha256(
            &self.artifacts.catalog,
            &self.catalog_hash,
            "sealed signed catalog",
        )?;
        verify_sha256(
            &self.artifacts.inf,
            &self.inf_hash,
            "sealed driver installation metadata",
        )
    }
}

/// Native Linux tools or the same tools reached through one installed WSL distribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxEnvironment {
    /// Host commands execute directly.
    Native,
    /// Host commands execute through `wsl.exe --exec`.
    Wsl,
}

impl LinuxEnvironment {
    /// Discovers and verifies every mandatory e2fsprogs executable.
    ///
    /// # Errors
    ///
    /// Returns an error instead of skipping when Linux, WSL, or any required executable is absent.
    fn require() -> TaskResult<Self> {
        let environment = if cfg!(target_os = "linux") {
            Self::Native
        } else if cfg!(target_os = "windows") {
            Self::Wsl
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "journal interoperability requires Linux or an installed WSL distribution",
            )
            .into());
        };
        for tool in ["mke2fs", "debugfs", "e2fsck"] {
            let mut command = environment.command(tool);
            command.arg("-V");
            run_checked(command, &format!("required {tool} availability"))?;
        }
        Ok(environment)
    }

    /// Builds one direct or WSL-routed child command.
    fn command(self, program: &str) -> Command {
        match self {
            Self::Native => Command::new(program),
            Self::Wsl => {
                let mut command = Command::new("wsl.exe");
                command.args(["--exec", program]);
                command
            }
        }
    }

    /// Builds one Linux command with an environment variable visible in the Linux process.
    ///
    /// A Windows environment override on `wsl.exe` is not forwarded into the distribution unless
    /// `WSLENV` is configured. Routing through `env` keeps fixture generation independent of the
    /// caller's global WSL configuration while avoiding shell interpretation.
    fn command_with_environment(self, program: &str, key: &str, value: &str) -> Command {
        match self {
            Self::Native => {
                let mut command = Command::new(program);
                command.env(key, value);
                command
            }
            Self::Wsl => {
                let mut command = Command::new("wsl.exe");
                command
                    .args(["--exec", "env"])
                    .arg(format!("{key}={value}"))
                    .arg(program);
                command
            }
        }
    }

    /// Converts one host path into the namespace used by the selected Linux tools.
    ///
    /// # Errors
    ///
    /// Returns an error for non-UTF-8 native paths or failed/empty WSL conversion output.
    fn tool_path(self, path: &Path) -> TaskResult<String> {
        match self {
            Self::Native => path
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other("journal gate path is not UTF-8").into()),
            Self::Wsl => {
                let mut command = Command::new("wsl.exe");
                command.args(["--exec", "wslpath", "-a"]).arg(path);
                let output = run_checked_output(command, "WSL path conversion")?;
                let converted = String::from_utf8(output.stdout)?;
                let converted = converted.trim();
                if converted.is_empty() {
                    Err(io::Error::other("WSL returned an empty converted path").into())
                } else {
                    Ok(converted.to_owned())
                }
            }
        }
    }

    /// Returns the exact mke2fs release token used as the e2fsprogs authority.
    ///
    /// # Errors
    ///
    /// Returns an error when mke2fs fails, emits non-UTF-8 diagnostics, or omits its version token.
    fn e2fsprogs_version(self) -> TaskResult<String> {
        let mut command = self.command("mke2fs");
        command.arg("-V");
        let output = run_checked_output(command, "e2fsprogs version query")?;
        let mut bytes = output.stdout;
        bytes.extend_from_slice(&output.stderr);
        let version_output = String::from_utf8(bytes)?;
        version_output
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("mke2fs ")
                    .and_then(|suffix| suffix.split_ascii_whitespace().next())
            })
            .map(ToOwned::to_owned)
            .ok_or_else(|| io::Error::other("mke2fs omitted its version token").into())
    }

    /// Requires root authority and usable loop-device tooling for provenance reproduction.
    ///
    /// # Errors
    ///
    /// Returns an error when `id`, `losetup`, or loop-device allocation is unavailable, or the
    /// selected Linux environment does not run as root.
    fn require_loop_device_authority(self) -> TaskResult<()> {
        let mut identity = self.command("id");
        identity.arg("-u");
        let output = run_checked_output(identity, "Linux effective-user query")?;
        if String::from_utf8(output.stdout)?.trim() != "0" {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "external journal fixture provenance requires Linux root authority",
            )
            .into());
        }
        let mut version = self.command("losetup");
        version.arg("--version");
        run_checked(version, "required loop-device tooling")?;
        let mut free = self.command("losetup");
        free.arg("--find");
        run_checked_output(free, "free loop-device query")?;
        Ok(())
    }
}

/// One generated internal-journal interoperability profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalInteropCase {
    /// Filesystem and journal block size.
    block_size: u32,
    /// Debugfs JBD2 checksum version.
    checksum_version: u8,
    /// Whether ext4 and JBD2 carry 64-bit block addresses.
    block_numbers_64bit: bool,
    /// Whether the JBD2 profile admits revoke control blocks.
    revokes: bool,
}

/// Physical placement used while canonicalizing debugfs-produced JBD2 descriptors.
#[derive(Clone, Copy, Debug)]
enum JournalImageLayout<'a> {
    /// Logical journal blocks are mapped through the internal journal inode.
    Internal(&'a [u64]),
    /// Dedicated journal blocks use their logical block number as the device block number.
    ExternalIdentity {
        /// Number of complete blocks in the dedicated journal device.
        capacity_blocks: u32,
        /// Device block containing the JBD2 superblock after the ext-family device header.
        superblock_block: u32,
    },
}

impl JournalImageLayout<'_> {
    /// Returns the device block containing the JBD2 superblock.
    ///
    /// # Errors
    ///
    /// Returns an error when an internal journal has no logical block zero.
    fn superblock_physical(self) -> TaskResult<u64> {
        match self {
            Self::Internal(logical_to_physical) => logical_to_physical
                .first()
                .copied()
                .ok_or_else(|| io::Error::other("internal journal mapping is empty").into()),
            Self::ExternalIdentity {
                superblock_block, ..
            } => Ok(u64::from(superblock_block)),
        }
    }

    /// Returns the number of logical blocks backed by this image layout.
    ///
    /// # Errors
    ///
    /// Returns an error when an internal mapping cannot be represented by the JBD2 wire width.
    fn capacity_blocks(self) -> TaskResult<u32> {
        match self {
            Self::Internal(logical_to_physical) => Ok(u32::try_from(logical_to_physical.len())?),
            Self::ExternalIdentity {
                capacity_blocks, ..
            } => Ok(capacity_blocks),
        }
    }

    /// Maps one validated logical JBD2 block into the containing raw image.
    ///
    /// # Errors
    ///
    /// Returns an error when the logical block is outside the selected journal device.
    fn physical_block(self, logical: u32) -> TaskResult<u64> {
        match self {
            Self::Internal(logical_to_physical) => logical_to_physical
                .get(usize::try_from(logical)?)
                .copied()
                .ok_or_else(|| {
                    io::Error::other("internal logical journal block is unmapped").into()
                }),
            Self::ExternalIdentity {
                capacity_blocks, ..
            } if logical < capacity_blocks => Ok(u64::from(logical)),
            Self::ExternalIdentity { .. } => {
                Err(io::Error::other("external logical journal block exceeds the device").into())
            }
        }
    }
}

/// Evidence collected while canonicalizing one active debugfs journal stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DebugfsJournalEvidence {
    /// Descriptor count belonging to the first committed transaction.
    first_committed_descriptors: Option<usize>,
    /// Descriptor count in the uncommitted tail after the last commit.
    pending_descriptors: usize,
    /// Revoke control blocks encountered in the active stream.
    revoke_blocks: usize,
    /// Descriptors changed from a precisely recognized debugfs encoding defect.
    normalized_descriptors: usize,
}

/// Commit timestamp treatment for one debugfs journal normalization pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DebugfsCommitTimestamp {
    /// Retain the independent timestamp in dynamically generated interoperability images.
    Preserve,
    /// Publish one deterministic timestamp in a tracked fixture commit block.
    Canonical(u64),
}

/// One tracked filesystem/external-journal pair and its independent provenance.
#[derive(Debug, Eq, PartialEq)]
struct ExternalJournalFixture {
    /// Stable fixture stem and diagnostics identity.
    name: String,
    /// Filesystem and journal block size.
    block_size: u32,
    /// Debugfs JBD2 checksum version.
    checksum_version: u8,
    /// Whether ext4 and JBD2 carry 64-bit block addresses.
    block_numbers_64bit: bool,
    /// Free primary block overwritten by the committed fixture transaction.
    replay_block: u64,
    /// Fixed primary-filesystem UUID.
    filesystem_uuid: String,
    /// Fixed external-journal UUID.
    journal_uuid: String,
    /// Tracked filesystem image name relative to the manifest.
    filesystem_file: String,
    /// SHA-256 of the expanded raw filesystem image.
    filesystem_sha256: String,
    /// Tracked external-journal image name relative to the manifest.
    journal_file: String,
    /// SHA-256 of the expanded raw external-journal image.
    journal_sha256: String,
}

/// Parsed authority for deterministic external-journal fixture reproduction.
#[derive(Debug, Eq, PartialEq)]
struct JournalFixtureManifest {
    /// Exact e2fsprogs release required for byte-for-byte provenance.
    e2fsprogs_version: String,
    /// Stable fake Unix timestamp supplied to every mutating e2fsprogs process.
    fake_time: u64,
    /// The three supported external-journal profiles.
    fixtures: Vec<ExternalJournalFixture>,
}

/// Two explicitly finalized loop-device leases used by fixture reproduction.
#[derive(Debug)]
struct FixtureLoopDevices {
    /// Loop device presenting the external journal as a block device.
    journal: String,
    /// Loop device presenting the primary filesystem as a block device.
    filesystem: String,
}

impl FixtureLoopDevices {
    /// Attaches the journal first and filesystem second, rolling back the first attachment if the
    /// second cannot be established.
    ///
    /// # Errors
    ///
    /// Returns an error when either loop device cannot be attached or rollback cannot detach the
    /// already attached journal device.
    fn attach(
        linux: LinuxEnvironment,
        journal_image: &str,
        filesystem_image: &str,
    ) -> TaskResult<Self> {
        let journal = attach_loop_device(linux, journal_image)?;
        match attach_loop_device(linux, filesystem_image) {
            Ok(filesystem) => Ok(Self {
                journal,
                filesystem,
            }),
            Err(attach_error) => {
                let detach = detach_loop_device(linux, &journal);
                match detach {
                    Ok(()) => Err(attach_error),
                    Err(detach_error) => Err(io::Error::other(format!(
                        "filesystem loop attach failed ({attach_error}); journal rollback also failed ({detach_error})"
                    ))
                    .into()),
                }
            }
        }
    }

    /// Explicitly detaches both block-device leases while preserving both failure diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an error when either `losetup --detach` operation fails.
    fn detach(self, linux: LinuxEnvironment) -> TaskResult<()> {
        let filesystem = detach_loop_device(linux, &self.filesystem);
        let journal = detach_loop_device(linux, &self.journal);
        combine_verification_and_cleanup(filesystem, journal)
    }
}

/// Host-file implementation of the production storage target boundary.
#[derive(Debug)]
struct FileStorageAdapter {
    /// Primary filesystem image.
    filesystem: File,
    /// External journal image when the mounted profile requires one.
    external_journal: Option<File>,
}

/// Progress of one production workflow stopped only after a complete write or flush effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectBoundaryRun {
    /// Number of write/flush requests completed by this execution.
    completed_effects: usize,
    /// Whether the workflow reached its semantic terminal state instead of simulating a crash.
    completed: bool,
}

/// Counts production durability effects and withholds the completion that crosses a selected
/// crash boundary.
#[derive(Debug)]
struct EffectBoundaryController {
    /// One-based write/flush completion at which the in-memory operation is abandoned.
    stop_after: Option<usize>,
    /// Write/flush completions already applied to the host image.
    completed_effects: usize,
}

impl EffectBoundaryController {
    /// Creates one full execution or a crash execution stopped after an exact effect count.
    ///
    /// # Errors
    ///
    /// Returns an error when zero is supplied even though effect boundaries are one-based.
    fn new(stop_after: Option<usize>) -> TaskResult<Self> {
        if stop_after == Some(0) {
            return Err(io::Error::other("effect boundary zero is invalid").into());
        }
        Ok(Self {
            stop_after,
            completed_effects: 0,
        })
    }

    /// Executes one request and returns no completion when its durable effect is the selected
    /// simulated-crash boundary.
    ///
    /// A final `sync_all` models the maximal persistence permitted at that boundary. The remount
    /// must therefore accept both the old and new semantic state without relying on volatile
    /// operation state.
    ///
    /// # Errors
    ///
    /// Returns an error for request I/O, effect-count overflow, or host durability failure.
    fn complete(
        &mut self,
        storage: &mut FileStorageAdapter,
        request: ext4_core::StorageRequest,
    ) -> TaskResult<Option<ext4_core::StorageCompletion>> {
        let has_effect = matches!(
            request,
            ext4_core::StorageRequest::Write { .. } | ext4_core::StorageRequest::Flush { .. }
        );
        let completion = complete_file_request(storage, request)?;
        if has_effect {
            self.completed_effects = self
                .completed_effects
                .checked_add(1)
                .ok_or_else(|| io::Error::other("effect boundary count overflow"))?;
            if self.stop_after == Some(self.completed_effects) {
                storage.sync_all()?;
                return Ok(None);
            }
        }
        Ok(Some(completion))
    }

    /// Reports a simulated crash after the selected completion.
    const fn stopped(self) -> EffectBoundaryRun {
        EffectBoundaryRun {
            completed_effects: self.completed_effects,
            completed: false,
        }
    }

    /// Reports normal completion of the production workflow.
    const fn completed(self) -> EffectBoundaryRun {
        EffectBoundaryRun {
            completed_effects: self.completed_effects,
            completed: true,
        }
    }
}

/// Result of consuming a preallocated request sequence through one crash-boundary controller.
#[derive(Debug)]
enum BoundarySequence<Next> {
    /// The operation state was deliberately abandoned after an applied storage effect.
    Stopped,
    /// Every request completed and the production continuation is available.
    Finished(Next),
}

impl FileStorageAdapter {
    /// Opens one internal-journal filesystem for production state-machine execution.
    ///
    /// # Errors
    ///
    /// Returns an error when the image cannot be opened read/write.
    fn open_internal(filesystem: &Path) -> TaskResult<Self> {
        Ok(Self {
            filesystem: OpenOptions::new().read(true).write(true).open(filesystem)?,
            external_journal: None,
        })
    }

    /// Opens a primary filesystem and its external journal as two distinct storage targets.
    ///
    /// # Errors
    ///
    /// Returns an error when either image cannot be opened read/write.
    fn open_external(filesystem: &Path, external_journal: &Path) -> TaskResult<Self> {
        Ok(Self {
            filesystem: OpenOptions::new().read(true).write(true).open(filesystem)?,
            external_journal: Some(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(external_journal)?,
            ),
        })
    }

    /// Returns one routed host file or rejects an unavailable external target.
    ///
    /// # Errors
    ///
    /// Returns an error when an internal-only adapter receives an external-journal request.
    fn target_mut(&mut self, target: ext4_core::StorageTarget) -> TaskResult<&mut File> {
        match target {
            ext4_core::StorageTarget::Filesystem => Ok(&mut self.filesystem),
            ext4_core::StorageTarget::ExternalJournal => self
                .external_journal
                .as_mut()
                .ok_or_else(|| io::Error::other("unexpected external-journal request").into()),
        }
    }

    /// Flushes both host files after a deliberately interrupted core commit.
    ///
    /// # Errors
    ///
    /// Returns the first host durability failure.
    fn sync_all(&self) -> TaskResult<()> {
        self.filesystem.sync_all()?;
        if let Some(external) = &self.external_journal {
            external.sync_all()?;
        }
        Ok(())
    }
}

impl JournalInteropCase {
    /// Stable directory/file stem for gate diagnostics.
    fn name(self) -> String {
        format!(
            "internal-{}k-v{}-{}bit",
            self.block_size / 1024,
            self.checksum_version,
            if self.block_numbers_64bit { 64 } else { 32 }
        )
    }
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
        Task::Portable => verify_portable(&repository_root),
        Task::Driver => verify_driver(&repository_root),
        Task::JournalInterop => verify_journal_interop(&repository_root),
        Task::JournalFixtureProvenance => verify_journal_fixture_provenance(&repository_root),
        Task::ProductionDriver => verify_production_driver(&repository_root),
    }
}

/// Returns the stable command-line contract.
fn usage_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: cargo xtask <verify-portable|verify-driver|verify-journal-interop|verify-journal-fixture-provenance|verify-production-driver>",
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

/// Checks, tests, lints, and documents the Windows kernel driver crate.
///
/// # Errors
///
/// Returns an error when any driver Cargo gate cannot start or exits unsuccessfully.
fn verify_driver(repository_root: &Path) -> TaskResult<()> {
    run_checked(
        cargo_command(repository_root, &["check", "-p", "ext4win", "--locked"]),
        "driver check gate",
    )?;
    run_checked(
        cargo_command(repository_root, &["test", "-p", "ext4win", "--locked"]),
        "driver unit-test gate",
    )?;
    run_checked(
        cargo_command(
            repository_root,
            &["clippy", "-p", "ext4win", "--all-targets", "--locked"],
        ),
        "driver Clippy gate",
    )?;
    run_checked(
        cargo_command(
            repository_root,
            &["doc", "-p", "ext4win", "--no-deps", "--locked"],
        ),
        "driver rustdoc gate",
    )?;
    println!("driver development gates: PASS");
    Ok(())
}

/// Generates JBD2 records with e2fsprogs, replays them through the production core state machine,
/// clean-closes the image, and asks e2fsck to independently validate the result.
///
/// # Errors
///
/// Returns an error when Linux/e2fsprogs is unavailable, fixture generation fails, the core mount
/// or close protocol rejects an image, replay differs from the expected latest committed payload,
/// e2fsck reports damage, or temporary artifact cleanup fails.
fn verify_journal_interop(repository_root: &Path) -> TaskResult<()> {
    let linux = LinuxEnvironment::require()?;
    let temporary_root = create_task_directory(repository_root, "journal-interop")?;
    let cases = [
        JournalInteropCase {
            block_size: 1024,
            checksum_version: 2,
            block_numbers_64bit: false,
            revokes: true,
        },
        JournalInteropCase {
            block_size: 1024,
            checksum_version: 3,
            block_numbers_64bit: true,
            revokes: true,
        },
        JournalInteropCase {
            block_size: 2048,
            checksum_version: 2,
            block_numbers_64bit: true,
            revokes: true,
        },
        JournalInteropCase {
            block_size: 2048,
            checksum_version: 3,
            block_numbers_64bit: false,
            revokes: true,
        },
        JournalInteropCase {
            block_size: 4096,
            checksum_version: 2,
            block_numbers_64bit: false,
            revokes: true,
        },
        JournalInteropCase {
            block_size: 4096,
            checksum_version: 3,
            block_numbers_64bit: true,
            revokes: true,
        },
    ];
    let verification = (|| -> TaskResult<()> {
        for case in cases {
            verify_linux_generated_journal_case(linux, &temporary_root, case)?;
        }
        let fixture_directory = journal_fixture_directory(repository_root);
        let manifest =
            parse_journal_fixture_manifest(&fixture_directory.join("provenance.manifest"))?;
        for fixture in &manifest.fixtures {
            verify_external_journal_fixture(linux, &fixture_directory, &temporary_root, fixture)?;
        }
        Ok(())
    })();
    let cleanup = remove_task_directory(repository_root, &temporary_root, "journal-interop");
    combine_verification_and_cleanup(verification, cleanup)?;
    println!("JBD2 Linux -> core recovery and clean-close interoperability: PASS");
    Ok(())
}

/// Expands one tracked raw pair, drives core external recovery/close, and asks e2fsck to validate
/// the clean result with the ordinary-file journal path.
///
/// # Errors
///
/// Returns an error for missing or drifted tracked input, copy/file I/O, core validation/recovery,
/// payload mismatch, or e2fsck failure.
fn verify_external_journal_fixture(
    linux: LinuxEnvironment,
    fixture_directory: &Path,
    temporary_root: &Path,
    fixture: &ExternalJournalFixture,
) -> TaskResult<()> {
    let tracked_filesystem = fixture_directory.join(&fixture.filesystem_file);
    let tracked_journal = fixture_directory.join(&fixture.journal_file);
    require_fixture_digest(
        &tracked_filesystem,
        &fixture.filesystem_sha256,
        &format!("{} filesystem", fixture.name),
    )?;
    require_fixture_digest(
        &tracked_journal,
        &fixture.journal_sha256,
        &format!("{} external journal", fixture.name),
    )?;

    let case_root = temporary_root.join(&fixture.name);
    fs::create_dir(&case_root)?;
    let filesystem = case_root.join("filesystem.img");
    let journal = case_root.join("external-journal.img");
    fs::copy(&tracked_filesystem, &filesystem)?;
    fs::copy(&tracked_journal, &journal)?;
    if fixture.name == "external-1k-v2-32" {
        verify_external_journal_fault_matrix(linux, &case_root, &filesystem, &journal, fixture)?;
    }
    drive_external_core_mount_and_clean_close(&filesystem, &journal)?;
    verify_pattern_block(&filesystem, fixture.block_size, fixture.replay_block, 0xD4)?;

    let filesystem_path = linux.tool_path(&filesystem)?;
    let journal_path = linux.tool_path(&journal)?;
    let mut e2fsck = linux.command("e2fsck");
    e2fsck.args(["-f", "-n", "-j", &journal_path, &filesystem_path]);
    run_checked(
        e2fsck,
        &format!("external-journal e2fsck for {}", fixture.name),
    )?;
    Ok(())
}

/// Generates one committed/revoked/multi-descriptor transaction stream and validates core replay.
///
/// # Errors
///
/// Returns an error for child-tool, parsing, image I/O, core protocol, replay, or e2fsck failure.
fn verify_linux_generated_journal_case(
    linux: LinuxEnvironment,
    temporary_root: &Path,
    case: JournalInteropCase,
) -> TaskResult<()> {
    const IMAGE_BYTES: u64 = 128 * 1024 * 1024;

    let case_root = temporary_root.join(case.name());
    fs::create_dir(&case_root)?;
    let image = case_root.join("filesystem.img");
    File::create(&image)?.set_len(IMAGE_BYTES)?;
    let image_tool_path = linux.tool_path(&image)?;
    let features = if case.block_numbers_64bit {
        "metadata_csum,64bit,^metadata_csum_seed,^orphan_file"
    } else {
        "metadata_csum,^64bit,^metadata_csum_seed,^orphan_file"
    };
    let mut mke2fs = linux.command("mke2fs");
    mke2fs.args([
        "-q",
        "-F",
        "-t",
        "ext4",
        "-b",
        &case.block_size.to_string(),
        "-O",
        features,
        "-E",
        "lazy_itable_init=0,lazy_journal_init=0",
        "-J",
        "size=8",
        &image_tool_path,
    ]);
    run_checked(mke2fs, &format!("mke2fs for {}", case.name()))?;

    let journal_block_sequence = debugfs_block_sequence(linux, &image_tool_path, "blocks <8>")?;
    let journal_blocks = journal_block_sequence
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if journal_blocks.len() != journal_block_sequence.len() {
        return Err(io::Error::other("debugfs returned duplicate journal blocks").into());
    }
    let free_block = debugfs_first_free_block(linux, &image_tool_path)?;
    if journal_blocks.contains(&free_block) {
        return Err(io::Error::other("debugfs returned a journal-owned free block").into());
    }
    let total_blocks = IMAGE_BYTES
        .checked_div(u64::from(case.block_size))
        .ok_or_else(|| io::Error::other("zero block size in journal interop case"))?;
    let home_blocks = select_replay_blocks(
        total_blocks,
        free_block,
        &journal_blocks,
        multi_descriptor_payload_count(case)?,
    )?;

    let first_payload = case_root.join("transaction-one.bin");
    copy_home_payloads(
        &image,
        &first_payload,
        case.block_size,
        &home_blocks,
        Some((free_block, 0xA1)),
    )?;
    let second_payload = case_root.join("transaction-two.bin");
    write_pattern_block(&second_payload, case.block_size, 0xB2)?;
    let torn_payload = case_root.join("uncommitted-tail.bin");
    write_pattern_block(&torn_payload, case.block_size, 0xC3)?;
    let commands = case_root.join("journal.commands");
    let block_list = comma_separated_blocks(&home_blocks)?;
    let first_payload_tool_path = linux.tool_path(&first_payload)?;
    let second_payload_tool_path = linux.tool_path(&second_payload)?;
    let torn_payload_tool_path = linux.tool_path(&torn_payload)?;
    let command_body = format!(
        "journal_open -c -v {checksum}\n\
         journal_write -b {blocks} {first}\n\
         journal_write -r {free_block}\n\
         journal_write -b {free_block} {second}\n\
         journal_write -c -b {free_block} {torn}\n\
         journal_close\n",
        checksum = case.checksum_version,
        blocks = block_list,
        first = first_payload_tool_path,
        second = second_payload_tool_path,
        torn = torn_payload_tool_path,
    );
    fs::write(&commands, command_body)?;
    let commands_tool_path = linux.tool_path(&commands)?;
    let mut debugfs = linux.command("debugfs");
    debugfs.args(["-w", "-f", &commands_tool_path, &image_tool_path]);
    run_checked(
        debugfs,
        &format!("debugfs journal construction for {}", case.name()),
    )?;
    normalize_internal_debugfs_descriptors(&image, &journal_block_sequence, case)?;

    verify_primary_recovery_marker(&image, true)?;
    let reference_image = case_root.join("e2fsck-reference.img");
    fs::copy(&image, &reference_image)?;
    let reference_path = linux.tool_path(&reference_image)?;
    let mut reference_replay = linux.command("e2fsck");
    reference_replay.args(["-E", "journal_only", "-y", &reference_path]);
    run_checked(
        reference_replay,
        &format!("reference journal replay for {}", case.name()),
    )?;
    verify_pattern_block(&reference_image, case.block_size, free_block, 0xB2)?;
    verify_primary_recovery_marker(&image, true)?;

    drive_core_mount_and_clean_close(&image)?;
    verify_pattern_block(&image, case.block_size, free_block, 0xB2)?;

    let core_label = b"CORE-JBD2";
    drive_core_commit_without_checkpoint(&image, core_label)?;
    let mut journal_only = linux.command("e2fsck");
    journal_only.args(["-E", "journal_only", "-y", &image_tool_path]);
    run_checked(
        journal_only,
        &format!("e2fsck journal-only replay for {}", case.name()),
    )?;
    verify_volume_label(&image, core_label)?;

    let mut e2fsck = linux.command("e2fsck");
    e2fsck.args(["-f", "-n", &image_tool_path]);
    run_checked(e2fsck, &format!("e2fsck clean check for {}", case.name()))?;
    Ok(())
}

/// Verifies the primary ext4 incompat feature bit that authorizes journal replay.
///
/// # Errors
///
/// Returns an error for file I/O or a marker value different from `expected`.
fn verify_primary_recovery_marker(image: &Path, expected: bool) -> TaskResult<()> {
    let marked = primary_recovery_marker(image)?;
    if marked == expected {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "primary needs_recovery marker is {marked}, expected {expected}"
        ))
        .into())
    }
}

/// Reads the primary ext4 incompat feature bit that authorizes journal replay.
///
/// # Errors
///
/// Returns an error for offset overflow or raw image I/O failure.
fn primary_recovery_marker(image: &Path) -> TaskResult<bool> {
    const SUPERBLOCK_OFFSET: u64 = 1024;
    const FEATURE_INCOMPAT_OFFSET: u64 = 0x60;
    const NEEDS_RECOVERY: u32 = 0x0004;

    let mut file = File::open(image)?;
    let offset = SUPERBLOCK_OFFSET
        .checked_add(FEATURE_INCOMPAT_OFFSET)
        .ok_or_else(|| io::Error::other("primary feature offset overflow"))?;
    file.seek(io::SeekFrom::Start(offset))?;
    let mut raw = [0_u8; size_of::<u32>()];
    file.read_exact(&mut raw)?;
    Ok(u32::from_le_bytes(raw) & NEEDS_RECOVERY != 0)
}

/// Returns the ordered block sequence printed by one read-only debugfs command.
///
/// # Errors
///
/// Returns an error when debugfs fails, emits non-UTF-8 output, or no numeric block is found.
fn debugfs_block_sequence(
    linux: LinuxEnvironment,
    image: &str,
    request: &str,
) -> TaskResult<Vec<u64>> {
    let mut command = linux.command("debugfs");
    command.args(["-R", request, image]);
    let output = run_checked_output(command, "debugfs journal block query")?;
    let stdout = String::from_utf8(output.stdout)?;
    let blocks = stdout
        .split_ascii_whitespace()
        .filter_map(|token| token.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if blocks.is_empty() {
        Err(io::Error::other(format!(
            "debugfs returned no journal blocks: {}",
            stdout.trim()
        ))
        .into())
    } else {
        Ok(blocks)
    }
}

/// Returns one payload count that crosses exactly one descriptor-capacity boundary.
///
/// # Errors
///
/// Returns an error when the selected JBD2 block cannot contain even one complete first tag.
fn multi_descriptor_payload_count(case: JournalInteropCase) -> TaskResult<usize> {
    let tag_bytes = if case.checksum_version == 3 {
        16_usize
    } else {
        8_usize
            .checked_add(if case.block_numbers_64bit { 4 } else { 0 })
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| io::Error::other("JBD2 v2 tag-size overflow"))?
    };
    let usable = usize::try_from(case.block_size)?
        .checked_sub(12)
        .and_then(|value| value.checked_sub(4))
        .ok_or_else(|| io::Error::other("JBD2 descriptor payload underflow"))?;
    let first_tag = tag_bytes
        .checked_add(16)
        .ok_or_else(|| io::Error::other("JBD2 first-tag size overflow"))?;
    let remaining = usable
        .checked_sub(first_tag)
        .ok_or_else(|| io::Error::other("JBD2 descriptor cannot hold a first tag"))?;
    let capacity_crossing = remaining
        .checked_div(tag_bytes)
        .and_then(|value| value.checked_add(2))
        .ok_or_else(|| io::Error::other("JBD2 descriptor capacity overflow"))?;
    // debugfs reserves descriptor blocks with `data_blocks * tag_bytes / (block_size - 20)`.
    // Cross that estimator's first quotient as well, otherwise its transaction boundary omits the
    // commit block even though the writer already emitted a second descriptor.
    let estimate_denominator = usize::try_from(case.block_size)?
        .checked_sub(20)
        .ok_or_else(|| io::Error::other("debugfs descriptor estimate underflow"))?;
    let estimator_crossing =
        estimate_denominator
            .checked_add(tag_bytes.checked_sub(1).ok_or_else(|| {
                io::Error::other("debugfs descriptor tag width is unexpectedly zero")
            })?)
            .and_then(|value| value.checked_div(tag_bytes))
            .ok_or_else(|| io::Error::other("debugfs descriptor estimate overflow"))?;
    Ok(capacity_crossing.max(estimator_crossing))
}

/// Canonicalizes descriptor boundaries emitted by e2fsprogs `debugfs journal_write`.
///
/// The production parser deliberately requires the explicit UUID mandated by the JBD2 writer
/// contract.  Current debugfs advances a typed tag pointer when copying that UUID, while Linux's
/// kernel writer advances a byte pointer.  This gate-only normalizer accepts either an already
/// correct UUID or the exact all-zero hole left by that debugfs bug, clears only UUID words left in
/// unused v3/32-bit tag fields, then refreshes the independently checked descriptor checksum.  The
/// same emitter also omits `LAST_TAG` when a descriptor becomes exactly full; the normalizer adds it
/// only after a complete tag stream has exhausted the block. Any other input remains corruption.
///
/// # Errors
///
/// Returns an error for an unexpected journal mapping/profile, invalid active transaction stream,
/// non-debugfs UUID damage, checksum failure, absent multi-descriptor/revoke/torn-tail coverage, or
/// host file I/O failure.
fn normalize_internal_debugfs_descriptors(
    image: &Path,
    journal_blocks: &[u64],
    case: JournalInteropCase,
) -> TaskResult<()> {
    let evidence = normalize_debugfs_descriptors(
        image,
        JournalImageLayout::Internal(journal_blocks),
        case,
        DebugfsCommitTimestamp::Preserve,
    )?;
    if evidence
        .first_committed_descriptors
        .is_none_or(|count| count < 2)
    {
        return Err(io::Error::other(format!(
            "debugfs did not emit a committed multi-descriptor transaction: {evidence:?}"
        ))
        .into());
    }
    if evidence.revoke_blocks == 0 {
        return Err(io::Error::other("debugfs did not emit a revoke record").into());
    }
    if evidence.pending_descriptors == 0 {
        return Err(
            io::Error::other("debugfs did not leave an uncommitted descriptor tail").into(),
        );
    }
    if evidence.normalized_descriptors == 0 {
        println!("debugfs emitted kernel-canonical descriptors without normalization");
    }
    Ok(())
}

/// Canonicalizes descriptors in one dedicated external-journal image.
///
/// # Errors
///
/// Returns an error for fractional device blocks, unsupported device length, invalid JBD2
/// placement/profile, an absent committed transaction, unrecognized debugfs bytes, or file I/O.
fn normalize_external_debugfs_descriptors(
    journal: &Path,
    fixture: &ExternalJournalFixture,
    fake_time: u64,
) -> TaskResult<()> {
    const EXT_SUPERBLOCK_END: u64 = 2048;

    let block_size = u64::from(fixture.block_size);
    let device_bytes = journal.metadata()?.len();
    if device_bytes
        .checked_rem(block_size)
        .ok_or_else(|| io::Error::other("external journal block size is zero"))?
        != 0
    {
        return Err(
            io::Error::other("external journal length is not divisible by its block size").into(),
        );
    }
    let capacity_blocks = u32::try_from(
        device_bytes
            .checked_div(block_size)
            .ok_or_else(|| io::Error::other("external journal block size is zero"))?,
    )?;
    let superblock_block = u32::try_from(EXT_SUPERBLOCK_END.div_ceil(block_size))?;
    let evidence = normalize_debugfs_descriptors(
        journal,
        JournalImageLayout::ExternalIdentity {
            capacity_blocks,
            superblock_block,
        },
        JournalInteropCase {
            block_size: fixture.block_size,
            checksum_version: fixture.checksum_version,
            block_numbers_64bit: fixture.block_numbers_64bit,
            revokes: false,
        },
        DebugfsCommitTimestamp::Canonical(fake_time),
    )?;
    if evidence.first_committed_descriptors.is_none() {
        return Err(io::Error::other(format!(
            "debugfs did not emit a committed external-journal transaction: {evidence:?}"
        ))
        .into());
    }
    Ok(())
}

/// Canonicalizes recognized debugfs descriptor defects through one explicit journal mapping.
///
/// # Errors
///
/// Returns an error for invalid geometry/profile/control checksums, unrecognized descriptor bytes,
/// coordinate overflow, or host image I/O failure.
fn normalize_debugfs_descriptors(
    image: &Path,
    layout: JournalImageLayout<'_>,
    case: JournalInteropCase,
    commit_timestamp: DebugfsCommitTimestamp,
) -> TaskResult<DebugfsJournalEvidence> {
    const JBD2_MAGIC: u32 = 0xC03B_3998;
    const JBD2_DESCRIPTOR: u32 = 1;
    const JBD2_COMMIT: u32 = 2;
    const JBD2_SUPERBLOCK_V2: u32 = 4;
    const JBD2_REVOKE: u32 = 5;
    const JBD2_INCOMPAT_REVOKE: u32 = 0x0001;
    const JBD2_INCOMPAT_64BIT: u32 = 0x0002;
    const JBD2_INCOMPAT_CSUM_V2: u32 = 0x0008;
    const JBD2_INCOMPAT_CSUM_V3: u32 = 0x0010;

    let mut file = OpenOptions::new().read(true).write(true).open(image)?;
    let superblock_physical = layout.superblock_physical()?;
    let superblock = read_image_block(&mut file, superblock_physical, case.block_size)?;
    if read_be_u32(&superblock, 0)? != JBD2_MAGIC
        || read_be_u32(&superblock, 4)? != JBD2_SUPERBLOCK_V2
        || read_be_u32(&superblock, 0x0C)? != case.block_size
    {
        return Err(io::Error::other("debugfs journal superblock header is invalid").into());
    }
    let maxlen = read_be_u32(&superblock, 0x10)?;
    let first = read_be_u32(&superblock, 0x14)?;
    let mut sequence = read_be_u32(&superblock, 0x18)?;
    let mut cursor = read_be_u32(&superblock, 0x1C)?;
    if cursor == 0 || first == 0 || first >= maxlen || maxlen > layout.capacity_blocks()? {
        return Err(io::Error::other("debugfs journal ring geometry is invalid").into());
    }
    let incompat = read_be_u32(&superblock, 0x28)?;
    let expected_checksum = if case.checksum_version == 2 {
        JBD2_INCOMPAT_CSUM_V2
    } else {
        JBD2_INCOMPAT_CSUM_V3
    };
    let expected_64bit = if case.block_numbers_64bit {
        JBD2_INCOMPAT_64BIT
    } else {
        0
    };
    let expected_revokes = if case.revokes {
        JBD2_INCOMPAT_REVOKE
    } else {
        0
    };
    if incompat & (JBD2_INCOMPAT_CSUM_V2 | JBD2_INCOMPAT_CSUM_V3) != expected_checksum
        || incompat & JBD2_INCOMPAT_64BIT != expected_64bit
        || incompat & JBD2_INCOMPAT_REVOKE != expected_revokes
    {
        return Err(io::Error::other(format!(
            "debugfs journal feature profile differs from the case: incompat={incompat:#010X}, expected checksum={expected_checksum:#010X}, 64bit={expected_64bit:#010X}, revoke={expected_revokes:#010X}"
        ))
        .into());
    }
    let uuid: [u8; 16] = superblock
        .get(0x30..0x40)
        .ok_or_else(|| io::Error::other("debugfs journal UUID is truncated"))?
        .try_into()?;
    let tag_bytes = if case.checksum_version == 3 {
        16_usize
    } else {
        8_usize
            .checked_add(if case.block_numbers_64bit { 4 } else { 0 })
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| io::Error::other("debugfs tag-size overflow"))?
    };
    let usable_ring = maxlen
        .checked_sub(first)
        .ok_or_else(|| io::Error::other("debugfs usable-ring underflow"))?;
    let mut consumed = 0_u32;
    let mut transaction_descriptors = 0_usize;
    let mut first_committed_descriptors = None;
    let mut revoke_blocks = 0_usize;
    let mut normalized_descriptors = 0_usize;

    while consumed < usable_ring {
        let physical = layout.physical_block(cursor)?;
        let mut block = read_image_block(&mut file, physical, case.block_size)?;
        if read_be_u32(&block, 0).ok() != Some(JBD2_MAGIC)
            || read_be_u32(&block, 8).ok() != Some(sequence)
        {
            break;
        }
        match read_be_u32(&block, 4)? {
            JBD2_DESCRIPTOR => {
                let (payloads, changed) = normalize_debugfs_descriptor(
                    &mut block,
                    uuid,
                    tag_bytes,
                    case.checksum_version == 3,
                    case.block_numbers_64bit,
                )?;
                if changed {
                    write_image_block(&mut file, physical, case.block_size, &block)?;
                    normalized_descriptors = normalized_descriptors
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("normalized descriptor count overflow"))?;
                }
                transaction_descriptors = transaction_descriptors
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("transaction descriptor count overflow"))?;
                let advance = u32::try_from(payloads)?
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("descriptor ring advance overflow"))?;
                cursor = advance_journal_cursor(cursor, advance, first, maxlen)?;
                consumed = consumed
                    .checked_add(advance)
                    .ok_or_else(|| io::Error::other("descriptor scan length overflow"))?;
            }
            JBD2_REVOKE => {
                revoke_blocks = revoke_blocks
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("revoke block count overflow"))?;
                cursor = advance_journal_cursor(cursor, 1, first, maxlen)?;
                consumed = consumed
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("revoke scan length overflow"))?;
            }
            JBD2_COMMIT => {
                if let DebugfsCommitTimestamp::Canonical(seconds) = commit_timestamp {
                    normalize_debugfs_commit_timestamp(&mut block, uuid, seconds)?;
                    write_image_block(&mut file, physical, case.block_size, &block)?;
                }
                first_committed_descriptors.get_or_insert(transaction_descriptors);
                transaction_descriptors = 0;
                sequence = sequence.wrapping_add(1);
                cursor = advance_journal_cursor(cursor, 1, first, maxlen)?;
                consumed = consumed
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("commit scan length overflow"))?;
            }
            _ => break,
        }
    }
    file.sync_all()?;
    Ok(DebugfsJournalEvidence {
        first_committed_descriptors,
        pending_descriptors: transaction_descriptors,
        revoke_blocks,
        normalized_descriptors,
    })
}

/// Replaces a valid checksummed debugfs commit timestamp with one deterministic instant.
///
/// # Errors
///
/// Returns an error when the commit fields are truncated, reserved v1 checksum metadata is nonzero,
/// or the independently generated checksum does not validate before normalization.
fn normalize_debugfs_commit_timestamp(
    block: &mut [u8],
    uuid: [u8; 16],
    seconds: u64,
) -> TaskResult<()> {
    const CHECKSUM_OFFSET: usize = 0x10;
    const COMMIT_SECONDS_OFFSET: usize = 0x30;
    const COMMIT_NANOSECONDS_OFFSET: usize = 0x38;

    if block
        .get(0x0C..CHECKSUM_OFFSET)
        .ok_or_else(|| io::Error::other("debugfs commit metadata is truncated"))?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(
            io::Error::other("debugfs commit carries reserved v1 checksum metadata").into(),
        );
    }
    let stored = read_be_u32(block, CHECKSUM_OFFSET)?;
    let calculated = jbd2_control_checksum(uuid, block, CHECKSUM_OFFSET)?;
    if stored != calculated {
        return Err(
            io::Error::other("debugfs commit checksum is invalid before normalization").into(),
        );
    }
    let seconds_end = COMMIT_SECONDS_OFFSET
        .checked_add(size_of::<u64>())
        .ok_or_else(|| io::Error::other("commit seconds offset overflow"))?;
    copy_exact_bytes(
        block
            .get_mut(COMMIT_SECONDS_OFFSET..seconds_end)
            .ok_or_else(|| io::Error::other("debugfs commit seconds are truncated"))?,
        &seconds.to_be_bytes(),
    )?;
    let nanoseconds_end = COMMIT_NANOSECONDS_OFFSET
        .checked_add(size_of::<u32>())
        .ok_or_else(|| io::Error::other("commit nanoseconds offset overflow"))?;
    block
        .get_mut(COMMIT_NANOSECONDS_OFFSET..nanoseconds_end)
        .ok_or_else(|| io::Error::other("debugfs commit nanoseconds are truncated"))?
        .fill(0);
    let checksum_end = CHECKSUM_OFFSET
        .checked_add(size_of::<u32>())
        .ok_or_else(|| io::Error::other("commit checksum offset overflow"))?;
    block
        .get_mut(CHECKSUM_OFFSET..checksum_end)
        .ok_or_else(|| io::Error::other("debugfs commit checksum is truncated"))?
        .fill(0);
    let checksum = jbd2_control_checksum(uuid, block, CHECKSUM_OFFSET)?;
    copy_exact_bytes(
        block
            .get_mut(CHECKSUM_OFFSET..checksum_end)
            .ok_or_else(|| io::Error::other("debugfs commit checksum disappeared"))?,
        &checksum.to_be_bytes(),
    )?;
    Ok(())
}

/// Normalizes one debugfs descriptor and returns its payload count and whether bytes changed.
///
/// # Errors
///
/// Returns an error when its original tail checksum, tag stream, flags, or explicit UUID bytes do
/// not match either the canonical JBD2 form or the exact zero hole left by debugfs.
fn normalize_debugfs_descriptor(
    block: &mut [u8],
    uuid: [u8; 16],
    tag_bytes: usize,
    checksum_v3: bool,
    block_numbers_64bit: bool,
) -> TaskResult<(usize, bool)> {
    const SAME_UUID: u32 = 0x0002;
    const LAST_TAG: u32 = 0x0008;
    const SUPPORTED_FLAGS: u32 = 0x000F;

    let tail = block
        .len()
        .checked_sub(4)
        .ok_or_else(|| io::Error::other("debugfs descriptor is smaller than its checksum tail"))?;
    if read_be_u32(block, tail)? != jbd2_control_checksum(uuid, block, tail)? {
        return Err(io::Error::other(
            "debugfs descriptor checksum is invalid before normalization",
        )
        .into());
    }
    let mut offset = 12_usize;
    let mut count = 0_usize;
    let mut changed = false;
    let mut last_flag_offset: Option<usize> = None;
    let mut last_flags = 0_u32;
    loop {
        let tag_end = offset
            .checked_add(tag_bytes)
            .ok_or_else(|| io::Error::other("debugfs tag offset overflow"))?;
        if tag_end > tail {
            let flag_offset = last_flag_offset.ok_or_else(|| {
                io::Error::other("debugfs descriptor cannot hold one complete tag")
            })?;
            if last_flags & LAST_TAG != 0 {
                break;
            }
            let canonical_flags = last_flags | LAST_TAG;
            if checksum_v3 {
                let end = flag_offset
                    .checked_add(size_of::<u32>())
                    .ok_or_else(|| io::Error::other("v3 terminal flag offset overflow"))?;
                copy_exact_bytes(
                    block
                        .get_mut(flag_offset..end)
                        .ok_or_else(|| io::Error::other("v3 terminal flags are truncated"))?,
                    &canonical_flags.to_be_bytes(),
                )?;
            } else {
                let canonical_flags = u16::try_from(canonical_flags)?;
                let end = flag_offset
                    .checked_add(size_of::<u16>())
                    .ok_or_else(|| io::Error::other("v2 terminal flag offset overflow"))?;
                copy_exact_bytes(
                    block
                        .get_mut(flag_offset..end)
                        .ok_or_else(|| io::Error::other("v2 terminal flags are truncated"))?,
                    &canonical_flags.to_be_bytes(),
                )?;
            }
            changed = true;
            break;
        }
        let flag_offset = if checksum_v3 {
            offset
                .checked_add(4)
                .ok_or_else(|| io::Error::other("v3 flag offset overflow"))?
        } else {
            offset
                .checked_add(6)
                .ok_or_else(|| io::Error::other("v2 flag offset overflow"))?
        };
        let mut flags = if checksum_v3 {
            read_be_u32(block, flag_offset)?
        } else {
            u32::from(read_be_u16(block, flag_offset)?)
        };
        if checksum_v3 && !block_numbers_64bit {
            let high_offset = offset
                .checked_add(8)
                .ok_or_else(|| io::Error::other("v3 high-block offset overflow"))?;
            let block_high = read_be_u32(block, high_offset)?;
            if block_high != 0 {
                let known_uuid_residue = read_be_u32(&uuid, 0)? == block_high
                    || read_be_u32(&uuid, 4)? == block_high
                    || read_be_u32(&uuid, 8)? == block_high
                    || read_be_u32(&uuid, 12)? == block_high;
                if !known_uuid_residue {
                    return Err(io::Error::other(
                        "debugfs v3/32-bit tag has an unknown high-block residue",
                    )
                    .into());
                }
                let high_end = high_offset
                    .checked_add(size_of::<u32>())
                    .ok_or_else(|| io::Error::other("v3 high-block end overflow"))?;
                block
                    .get_mut(high_offset..high_end)
                    .ok_or_else(|| io::Error::other("v3 high-block field is truncated"))?
                    .fill(0);
                changed = true;
            }
        }
        if checksum_v3 && flags & !SUPPORTED_FLAGS != 0 {
            let residual_uuid = u32::from(u16::from_be_bytes([uuid[4], uuid[5]]));
            let canonical_flags = flags & u32::from(u16::MAX);
            if flags >> 16 == residual_uuid && canonical_flags & !SUPPORTED_FLAGS == 0 {
                let end = flag_offset
                    .checked_add(size_of::<u32>())
                    .ok_or_else(|| io::Error::other("v3 debugfs flag offset overflow"))?;
                copy_exact_bytes(
                    block
                        .get_mut(flag_offset..end)
                        .ok_or_else(|| io::Error::other("v3 debugfs flags are truncated"))?,
                    &canonical_flags.to_be_bytes(),
                )?;
                flags = canonical_flags;
                changed = true;
            }
        }
        if flags & !SUPPORTED_FLAGS != 0 || count == 0 && flags & SAME_UUID != 0 {
            return Err(io::Error::other("debugfs descriptor tag flags are invalid").into());
        }
        last_flag_offset = Some(flag_offset);
        last_flags = flags;
        offset = tag_end;
        if flags & SAME_UUID == 0 {
            let uuid_end = offset
                .checked_add(uuid.len())
                .ok_or_else(|| io::Error::other("debugfs UUID offset overflow"))?;
            let destination = block
                .get_mut(offset..uuid_end)
                .ok_or_else(|| io::Error::other("debugfs descriptor UUID is truncated"))?;
            if destination != uuid {
                if destination.iter().any(|byte| *byte != 0) {
                    return Err(io::Error::other(
                        "debugfs descriptor UUID is neither canonical nor its known zero hole",
                    )
                    .into());
                }
                copy_exact_bytes(destination, &uuid)?;
                changed = true;
            }
            offset = uuid_end;
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| io::Error::other("debugfs tag count overflow"))?;
        if flags & LAST_TAG != 0 {
            break;
        }
    }
    if changed {
        block
            .get_mut(tail..)
            .ok_or_else(|| io::Error::other("debugfs descriptor tail disappeared"))?
            .fill(0);
        let checksum = jbd2_crc32c(jbd2_crc32c(u32::MAX, &uuid), block);
        copy_exact_bytes(
            block
                .get_mut(tail..)
                .ok_or_else(|| io::Error::other("debugfs descriptor tail is truncated"))?,
            &checksum.to_be_bytes(),
        )?;
    }
    Ok((count, changed))
}

/// Advances one logical cursor in a checked circular JBD2 ring.
///
/// # Errors
///
/// Returns an error when the cursor or ring is invalid.
fn advance_journal_cursor(mut cursor: u32, steps: u32, first: u32, maxlen: u32) -> TaskResult<u32> {
    if cursor < first || cursor >= maxlen || first >= maxlen {
        return Err(io::Error::other("JBD2 cursor is outside its ring").into());
    }
    for _step in 0..steps {
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| io::Error::other("JBD2 cursor overflow"))?;
        if cursor == maxlen {
            cursor = first;
        }
    }
    Ok(cursor)
}

/// Reads one filesystem block from a raw host image.
///
/// # Errors
///
/// Returns an error for offset arithmetic, allocation, seek, or read failure.
fn read_image_block(file: &mut File, block: u64, block_size: u32) -> TaskResult<Vec<u8>> {
    let offset = block
        .checked_mul(u64::from(block_size))
        .ok_or_else(|| io::Error::other("image block offset overflow"))?;
    file.seek(io::SeekFrom::Start(offset))?;
    let mut bytes = vec![0_u8; usize::try_from(block_size)?];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Writes one complete filesystem block to a raw host image.
///
/// # Errors
///
/// Returns an error for length/offset mismatch, seek, or write failure.
fn write_image_block(file: &mut File, block: u64, block_size: u32, bytes: &[u8]) -> TaskResult<()> {
    if bytes.len() != usize::try_from(block_size)? {
        return Err(io::Error::other("image block write length mismatch").into());
    }
    let offset = block
        .checked_mul(u64::from(block_size))
        .ok_or_else(|| io::Error::other("image block write offset overflow"))?;
    file.seek(io::SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    Ok(())
}

/// Copies bytes only after proving both ranges have identical lengths.
///
/// # Errors
///
/// Returns an error instead of panicking when the destination and source widths differ.
fn copy_exact_bytes(destination: &mut [u8], source: &[u8]) -> TaskResult<()> {
    if destination.len() != source.len() {
        return Err(io::Error::other("exact byte-copy length mismatch").into());
    }
    for (destination_byte, source_byte) in destination.iter_mut().zip(source) {
        *destination_byte = *source_byte;
    }
    Ok(())
}

/// Reads one checked big-endian 16-bit integer.
///
/// # Errors
///
/// Returns an error when the range is outside `bytes`.
fn read_be_u16(bytes: &[u8], offset: usize) -> TaskResult<u16> {
    let end = offset
        .checked_add(size_of::<u16>())
        .ok_or_else(|| io::Error::other("big-endian u16 offset overflow"))?;
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| io::Error::other("big-endian u16 is truncated"))?
            .try_into()?,
    ))
}

/// Reads one checked big-endian 32-bit integer.
///
/// # Errors
///
/// Returns an error when the range is outside `bytes`.
fn read_be_u32(bytes: &[u8], offset: usize) -> TaskResult<u32> {
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or_else(|| io::Error::other("big-endian u32 offset overflow"))?;
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| io::Error::other("big-endian u32 is truncated"))?
            .try_into()?,
    ))
}

/// Computes a JBD2 control-block checksum with one zeroed tail field.
///
/// # Errors
///
/// Returns an error when the checksum field is outside `block`.
fn jbd2_control_checksum(uuid: [u8; 16], block: &[u8], tail: usize) -> TaskResult<u32> {
    let suffix = tail
        .checked_add(4)
        .ok_or_else(|| io::Error::other("JBD2 checksum tail overflow"))?;
    let prefix = block
        .get(..tail)
        .ok_or_else(|| io::Error::other("JBD2 checksum prefix is truncated"))?;
    let suffix = block
        .get(suffix..)
        .ok_or_else(|| io::Error::other("JBD2 checksum suffix is truncated"))?;
    let seed = jbd2_crc32c(u32::MAX, &uuid);
    let seed = jbd2_crc32c(seed, prefix);
    let seed = jbd2_crc32c(seed, &[0_u8; 4]);
    Ok(jbd2_crc32c(seed, suffix))
}

/// Advances Linux's uncomplemented CRC32C state over one byte slice.
fn jbd2_crc32c(seed: u32, bytes: &[u8]) -> u32 {
    const POLYNOMIAL_REVERSED: u32 = 0x82F6_3B78;

    let mut crc = seed;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _bit in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (POLYNOMIAL_REVERSED & mask);
        }
    }
    crc
}

/// Finds one unallocated filesystem block through the independent debugfs allocator.
///
/// # Errors
///
/// Returns an error when debugfs fails or its stable `Free blocks found:` output cannot be parsed.
fn debugfs_first_free_block(linux: LinuxEnvironment, image: &str) -> TaskResult<u64> {
    let mut command = linux.command("debugfs");
    command.args(["-R", "find_free_block 1 10000", image]);
    let output = run_checked_output(command, "debugfs free-block query")?;
    let stdout = String::from_utf8(output.stdout)?;
    let marker = "Free blocks found:";
    let suffix = stdout
        .split_once(marker)
        .map(|(_prefix, suffix)| suffix)
        .ok_or_else(|| io::Error::other("debugfs free-block marker is absent"))?;
    suffix
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| io::Error::other("debugfs returned no free block"))?
        .parse::<u64>()
        .map_err(Into::into)
}

/// Selects unique in-range replay targets while excluding every internal-journal extent block.
///
/// # Errors
///
/// Returns an error when the requested count cannot be selected from the image geometry.
fn select_replay_blocks(
    total_blocks: u64,
    free_block: u64,
    journal_blocks: &BTreeSet<u64>,
    count: usize,
) -> TaskResult<Vec<u64>> {
    let mut selected = Vec::new();
    selected.try_reserve_exact(count)?;
    selected.push(free_block);
    let mut candidate = 100_u64;
    while selected.len() < count && candidate < total_blocks {
        if candidate != free_block && !journal_blocks.contains(&candidate) {
            selected.push(candidate);
        }
        candidate = candidate
            .checked_add(1)
            .ok_or_else(|| io::Error::other("replay block candidate overflow"))?;
    }
    if selected.len() == count {
        Ok(selected)
    } else {
        Err(io::Error::other("image has too few non-journal replay targets").into())
    }
}

/// Writes concatenated home-block images, replacing one selected block with a known pattern.
///
/// # Errors
///
/// Returns an error for offset arithmetic or source/destination file I/O failure.
fn copy_home_payloads(
    image: &Path,
    output: &Path,
    block_size: u32,
    blocks: &[u64],
    replacement: Option<(u64, u8)>,
) -> TaskResult<()> {
    let mut source = File::open(image)?;
    let mut destination = File::create(output)?;
    let block_bytes = usize::try_from(block_size)?;
    let mut buffer = vec![0_u8; block_bytes];
    for block in blocks {
        if replacement.is_some_and(|(replacement_block, _pattern)| replacement_block == *block) {
            let (_replacement_block, pattern) =
                replacement.ok_or_else(|| io::Error::other("replacement disappeared"))?;
            buffer.fill(pattern);
        } else {
            let offset = block
                .checked_mul(u64::from(block_size))
                .ok_or_else(|| io::Error::other("home payload offset overflow"))?;
            source.seek(io::SeekFrom::Start(offset))?;
            source.read_exact(&mut buffer)?;
        }
        destination.write_all(&buffer)?;
    }
    destination.sync_all()?;
    Ok(())
}

/// Writes one complete block filled with a deterministic byte pattern.
///
/// # Errors
///
/// Returns an error when the block size cannot be represented or the file cannot be persisted.
fn write_pattern_block(path: &Path, block_size: u32, pattern: u8) -> TaskResult<()> {
    let mut file = File::create(path)?;
    file.write_all(&vec![pattern; usize::try_from(block_size)?])?;
    file.sync_all()?;
    Ok(())
}

/// Serializes an ordered block sequence in compact debugfs comma/range syntax.
///
/// # Errors
///
/// Returns an error when string formatting fails or the list is empty.
fn comma_separated_blocks(blocks: &[u64]) -> TaskResult<String> {
    let Some(first) = blocks.first().copied() else {
        return Err(io::Error::other("journal block list is empty").into());
    };
    let mut serialized = String::new();
    let mut range_start = first;
    let mut range_end = first;
    for block in blocks.iter().copied().skip(1) {
        if range_end.checked_add(1) == Some(block) {
            range_end = block;
        } else {
            append_debugfs_block_range(&mut serialized, range_start, range_end)?;
            range_start = block;
            range_end = block;
        }
    }
    append_debugfs_block_range(&mut serialized, range_start, range_end)?;
    Ok(serialized)
}

/// Appends one inclusive debugfs block range to an existing comma list.
///
/// # Errors
///
/// Returns an error when formatting into the owned string fails.
fn append_debugfs_block_range(output: &mut String, start: u64, end: u64) -> TaskResult<()> {
    if !output.is_empty() {
        output.push(',');
    }
    if start == end {
        write!(output, "{start}")?;
    } else {
        write!(output, "{start}-{end}")?;
    }
    Ok(())
}

/// Drives recovery, commit/checkpoint, and clean close through every production write/flush
/// boundary, abandons the in-memory typestate, and proves that a fresh mount reaches a clean
/// old-or-new state.
///
/// The smallest tracked external-journal fixture keeps this exhaustive matrix bounded while the
/// ordinary interoperability loop independently covers every supported block-size/profile pair.
///
/// # Errors
///
/// Returns an error for image copying, production state-machine failure, a partial semantic
/// result, a remount that cannot clean the image, or independent e2fsck rejection.
fn verify_external_journal_fault_matrix(
    linux: LinuxEnvironment,
    case_root: &Path,
    dirty_filesystem: &Path,
    dirty_journal: &Path,
    fixture: &ExternalJournalFixture,
) -> TaskResult<()> {
    let matrix_root = case_root.join("fault-matrix");
    fs::create_dir(&matrix_root)?;
    let old_replay_block = {
        let mut image = File::open(dirty_filesystem)?;
        read_image_block(&mut image, fixture.replay_block, fixture.block_size)?
    };
    let new_replay_block = vec![0xD4; usize::try_from(fixture.block_size)?];

    let (probe_filesystem, probe_journal) = copy_fault_pair(
        &matrix_root,
        "recovery-probe",
        dirty_filesystem,
        dirty_journal,
    )?;
    let recovery_probe =
        run_external_mount_until_boundary(&probe_filesystem, &probe_journal, None)?;
    let recovery_effects = require_completed_effect_probe("recovery", recovery_probe)?;
    remove_fault_pair(&probe_filesystem, &probe_journal)?;

    for boundary in 1..=recovery_effects {
        let stem = format!("recovery-{boundary:03}");
        let (filesystem, journal) =
            copy_fault_pair(&matrix_root, &stem, dirty_filesystem, dirty_journal)?;
        let run = run_external_mount_until_boundary(&filesystem, &journal, Some(boundary))?;
        require_stopped_effect("recovery", boundary, run)?;
        let observed = {
            let mut image = File::open(&filesystem)?;
            read_image_block(&mut image, fixture.replay_block, fixture.block_size)?
        };
        require_old_or_new_bytes(
            "recovery home block",
            &observed,
            &old_replay_block,
            &new_replay_block,
        )?;
        drive_external_core_mount_and_clean_close(&filesystem, &journal)?;
        verify_pattern_block(&filesystem, fixture.block_size, fixture.replay_block, 0xD4)?;
        verify_primary_recovery_marker(&filesystem, false)?;
        verify_external_e2fsck_clean(linux, &filesystem, &journal, &stem)?;
        remove_fault_pair(&filesystem, &journal)?;
    }

    let (clean_filesystem, clean_journal) =
        copy_fault_pair(&matrix_root, "clean-base", dirty_filesystem, dirty_journal)?;
    drive_external_core_mount_and_clean_close(&clean_filesystem, &clean_journal)?;
    verify_primary_recovery_marker(&clean_filesystem, false)?;

    let (probe_filesystem, probe_journal) = copy_fault_pair(
        &matrix_root,
        "close-probe",
        &clean_filesystem,
        &clean_journal,
    )?;
    let close_probe =
        run_external_clean_close_until_boundary(&probe_filesystem, &probe_journal, None)?;
    let close_effects = require_completed_effect_probe("clean close", close_probe)?;
    remove_fault_pair(&probe_filesystem, &probe_journal)?;

    for boundary in 1..=close_effects {
        let stem = format!("close-{boundary:03}");
        let (filesystem, journal) =
            copy_fault_pair(&matrix_root, &stem, &clean_filesystem, &clean_journal)?;
        let run = run_external_clean_close_until_boundary(&filesystem, &journal, Some(boundary))?;
        require_stopped_effect("clean close", boundary, run)?;
        drive_external_core_mount_and_clean_close(&filesystem, &journal)?;
        verify_primary_recovery_marker(&filesystem, false)?;
        verify_external_e2fsck_clean(linux, &filesystem, &journal, &stem)?;
        remove_fault_pair(&filesystem, &journal)?;
    }

    const FAULT_LABEL: &[u8] = b"FAULT-JBD2";
    let old_label = read_raw_volume_label(&clean_filesystem)?;
    let new_label = padded_volume_label(FAULT_LABEL)?;
    let (probe_filesystem, probe_journal) = copy_fault_pair(
        &matrix_root,
        "mutation-probe",
        &clean_filesystem,
        &clean_journal,
    )?;
    let mutation_probe =
        run_external_mutation_until_boundary(&probe_filesystem, &probe_journal, FAULT_LABEL, None)?;
    let mutation_effects = require_completed_effect_probe("commit/checkpoint", mutation_probe)?;
    remove_fault_pair(&probe_filesystem, &probe_journal)?;

    for boundary in 1..=mutation_effects {
        let stem = format!("mutation-{boundary:03}");
        let (filesystem, journal) =
            copy_fault_pair(&matrix_root, &stem, &clean_filesystem, &clean_journal)?;
        let run = run_external_mutation_until_boundary(
            &filesystem,
            &journal,
            FAULT_LABEL,
            Some(boundary),
        )?;
        require_stopped_effect("commit/checkpoint", boundary, run)?;
        let interrupted_label = read_raw_volume_label(&filesystem)?;
        require_old_or_new_bytes(
            "interrupted volume label",
            &interrupted_label,
            &old_label,
            &new_label,
        )?;
        drive_external_core_mount_and_clean_close(&filesystem, &journal)?;
        let remounted_label = read_raw_volume_label(&filesystem)?;
        require_old_or_new_bytes(
            "remounted volume label",
            &remounted_label,
            &old_label,
            &new_label,
        )?;
        verify_primary_recovery_marker(&filesystem, false)?;
        verify_external_e2fsck_clean(linux, &filesystem, &journal, &stem)?;
        remove_fault_pair(&filesystem, &journal)?;
    }

    remove_fault_pair(&clean_filesystem, &clean_journal)?;
    fs::remove_dir(&matrix_root)?;
    println!(
        "JBD2 production fault matrix: PASS ({recovery_effects} recovery, \
         {mutation_effects} commit/checkpoint, {close_effects} clean-close boundaries)"
    );
    Ok(())
}

/// Copies one primary/external-journal pair under a unique matrix stem.
///
/// # Errors
///
/// Returns an error when either host copy fails. A failed second copy rolls back the first.
fn copy_fault_pair(
    matrix_root: &Path,
    stem: &str,
    filesystem_source: &Path,
    journal_source: &Path,
) -> TaskResult<(PathBuf, PathBuf)> {
    let filesystem = matrix_root.join(format!("{stem}.filesystem.img"));
    let journal = matrix_root.join(format!("{stem}.journal.img"));
    fs::copy(filesystem_source, &filesystem)?;
    match fs::copy(journal_source, &journal) {
        Ok(_bytes) => Ok((filesystem, journal)),
        Err(error) => {
            let rollback = fs::remove_file(&filesystem);
            match rollback {
                Ok(()) => Err(error.into()),
                Err(rollback_error) => Err(io::Error::other(format!(
                    "journal copy failed ({error}); filesystem rollback also failed ({rollback_error})"
                ))
                .into()),
            }
        }
    }
}

/// Removes one temporary primary/external-journal pair while retaining both failure diagnostics.
///
/// # Errors
///
/// Returns an error when either image cannot be removed.
fn remove_fault_pair(filesystem: &Path, journal: &Path) -> TaskResult<()> {
    let filesystem_result = fs::remove_file(filesystem).map_err(Into::into);
    let journal_result = fs::remove_file(journal).map_err(Into::into);
    combine_verification_and_cleanup(filesystem_result, journal_result)
}

/// Requires a non-empty full probe and returns its effect count.
///
/// # Errors
///
/// Returns an error when the workflow stopped unexpectedly or exposed no write/flush boundary.
fn require_completed_effect_probe(label: &str, run: EffectBoundaryRun) -> TaskResult<usize> {
    if !run.completed {
        return Err(io::Error::other(format!("{label} effect probe stopped unexpectedly")).into());
    }
    if run.completed_effects == 0 {
        return Err(io::Error::other(format!("{label} effect probe found no boundary")).into());
    }
    Ok(run.completed_effects)
}

/// Requires one exact simulated-crash boundary to have been reached.
///
/// # Errors
///
/// Returns an error when the workflow terminated or stopped after a different effect count.
fn require_stopped_effect(label: &str, expected: usize, run: EffectBoundaryRun) -> TaskResult<()> {
    if run.completed || run.completed_effects != expected {
        return Err(io::Error::other(format!(
            "{label} boundary {expected} produced completed={} effects={}",
            run.completed, run.completed_effects
        ))
        .into());
    }
    Ok(())
}

/// Requires one fixed-width representation to equal either complete semantic endpoint.
///
/// # Errors
///
/// Returns an error when an interrupted write exposes a third, partially updated value.
fn require_old_or_new_bytes(
    label: &str,
    observed: &[u8],
    old: &[u8],
    new: &[u8],
) -> TaskResult<()> {
    if observed == old || observed == new {
        Ok(())
    } else {
        Err(io::Error::other(format!("{label} is neither the old nor new state")).into())
    }
}

/// Reads the fixed-width ext4 primary volume-label field.
///
/// # Errors
///
/// Returns an error for offset arithmetic or raw image I/O failure.
fn read_raw_volume_label(image: &Path) -> TaskResult<[u8; 16]> {
    const SUPERBLOCK_OFFSET: u64 = 1024;
    const VOLUME_LABEL_OFFSET: u64 = 0x78;

    let mut file = File::open(image)?;
    let offset = SUPERBLOCK_OFFSET
        .checked_add(VOLUME_LABEL_OFFSET)
        .ok_or_else(|| io::Error::other("volume-label offset overflow"))?;
    file.seek(io::SeekFrom::Start(offset))?;
    let mut label = [0_u8; 16];
    file.read_exact(&mut label)?;
    Ok(label)
}

/// Pads one accepted ext4 volume label into its complete on-disk field.
///
/// # Errors
///
/// Returns an error when the caller supplies more than the ext4 field width.
fn padded_volume_label(label: &[u8]) -> TaskResult<[u8; 16]> {
    if label.len() > 16 {
        return Err(io::Error::other("fault-matrix volume label exceeds 16 bytes").into());
    }
    let mut padded = [0_u8; 16];
    for (destination, source) in padded.iter_mut().zip(label) {
        *destination = *source;
    }
    Ok(padded)
}

/// Uses e2fsck as an independent oracle for one external-journal crash outcome.
///
/// # Errors
///
/// Returns an error for path conversion, process launch, or non-clean e2fsck status.
fn verify_external_e2fsck_clean(
    linux: LinuxEnvironment,
    filesystem: &Path,
    journal: &Path,
    label: &str,
) -> TaskResult<()> {
    let filesystem_path = linux.tool_path(filesystem)?;
    let journal_path = linux.tool_path(journal)?;
    let mut e2fsck = linux.command("e2fsck");
    e2fsck.args(["-f", "-n", "-j", &journal_path, &filesystem_path]);
    run_checked(e2fsck, &format!("fault-matrix e2fsck for {label}"))
}

/// Opens and fully mounts one external-journal image pair through the public production protocol.
///
/// # Errors
///
/// Returns an error for device geometry, host I/O, probe mismatch, or core mount rejection.
fn mount_external_core(
    storage: &mut FileStorageAdapter,
) -> TaskResult<Box<ext4_core::CompletedMount>> {
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.filesystem.metadata()?.len());
    let external_length = ext4_core::DeviceLength::from_bytes(
        storage
            .external_journal
            .as_ref()
            .ok_or_else(|| io::Error::other("external adapter lost its journal"))?
            .metadata()?
            .len(),
    );
    let mut transition = Box::try_new(ext4_core::MountOperation::new(
        filesystem_length,
        ext4_core::FscryptKeySet::empty(),
    ))?
    .advance(ext4_core::OperationEvent::Admitted);
    loop {
        match transition {
            ext4_core::MountTransition::SubmitLower { request, suspended } => {
                let completion = complete_file_request(storage, request)?;
                transition =
                    suspended.advance(ext4_core::OperationEvent::StorageCompleted(completion));
            }
            ext4_core::MountTransition::DiscoverExternalJournal {
                requirement,
                suspended,
            } => {
                let validated = drive_external_probe(storage, requirement, external_length)?;
                transition = suspended.attach_external_journal(validated);
            }
            ext4_core::MountTransition::Complete(result) => {
                return result.map_err(|error| core_task_error(error).into());
            }
        }
    }
}

/// Runs external-journal mount/recovery until normal completion or one selected storage effect.
///
/// # Errors
///
/// Returns an error for invalid boundary selection, host I/O, probe failure, or core rejection.
fn run_external_mount_until_boundary(
    filesystem: &Path,
    journal: &Path,
    stop_after: Option<usize>,
) -> TaskResult<EffectBoundaryRun> {
    let mut storage = FileStorageAdapter::open_external(filesystem, journal)?;
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.filesystem.metadata()?.len());
    let external_length = ext4_core::DeviceLength::from_bytes(
        storage
            .external_journal
            .as_ref()
            .ok_or_else(|| io::Error::other("external adapter lost its journal"))?
            .metadata()?
            .len(),
    );
    let mut controller = EffectBoundaryController::new(stop_after)?;
    let mut transition = Box::try_new(ext4_core::MountOperation::new(
        filesystem_length,
        ext4_core::FscryptKeySet::empty(),
    ))?
    .advance(ext4_core::OperationEvent::Admitted);
    loop {
        match transition {
            ext4_core::MountTransition::SubmitLower { request, suspended } => {
                let Some(completion) = controller.complete(&mut storage, request)? else {
                    return Ok(controller.stopped());
                };
                transition =
                    suspended.advance(ext4_core::OperationEvent::StorageCompleted(completion));
            }
            ext4_core::MountTransition::DiscoverExternalJournal {
                requirement,
                suspended,
            } => {
                let validated = drive_external_probe(&mut storage, requirement, external_length)?;
                transition = suspended.attach_external_journal(validated);
            }
            ext4_core::MountTransition::Complete(result) => {
                result.map_err(core_task_error)?;
                return Ok(controller.completed());
            }
        }
    }
}

/// Mounts a clean external-journal pair and runs clean close until one selected effect boundary.
///
/// # Errors
///
/// Returns an error for mount/close protocol failure or host storage I/O.
fn run_external_clean_close_until_boundary(
    filesystem: &Path,
    journal: &Path,
    stop_after: Option<usize>,
) -> TaskResult<EffectBoundaryRun> {
    let mut storage = FileStorageAdapter::open_external(filesystem, journal)?;
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.filesystem.metadata()?.len());
    let completed = mount_external_core(&mut storage)?;
    let (profile, _epoch, _coordinator) = completed.into_parts();
    let mut controller = EffectBoundaryController::new(stop_after)?;
    let mut close = Box::try_new(ext4_core::CleanCloseOperation::new(
        filesystem_length,
        profile.journal_target(),
    ))?
    .advance(ext4_core::OperationEvent::Admitted);
    loop {
        match close {
            ext4_core::CleanCloseTransition::SubmitLower { request, suspended } => {
                let Some(completion) = controller.complete(&mut storage, request)? else {
                    return Ok(controller.stopped());
                };
                close = suspended.advance(ext4_core::OperationEvent::StorageCompleted(completion));
            }
            ext4_core::CleanCloseTransition::Complete(result) => {
                result.map_err(core_task_error)?;
                return Ok(controller.completed());
            }
        }
    }
}

/// Mounts a clean external-journal pair and runs one volume-label commit through checkpoint.
///
/// # Errors
///
/// Returns an error for mount/resolve/commit/checkpoint failure or host storage I/O.
fn run_external_mutation_until_boundary(
    filesystem: &Path,
    journal: &Path,
    label: &[u8],
    stop_after: Option<usize>,
) -> TaskResult<EffectBoundaryRun> {
    let mut storage = FileStorageAdapter::open_external(filesystem, journal)?;
    let completed = mount_external_core(&mut storage)?;
    let (prepared, mut coordinator, ticket) =
        prepare_volume_label_commit(&mut storage, completed, label)?;
    let mut controller = EffectBoundaryController::new(stop_after)?;

    let ordered = match complete_boundary_sequence(&mut storage, &mut controller, prepared.start())?
    {
        BoundarySequence::Stopped => return Ok(controller.stopped()),
        BoundarySequence::Finished(ordered) => ordered,
    };
    if !complete_boundary_request(&mut storage, &mut controller, ordered.flush_request())? {
        return Ok(controller.stopped());
    }
    let payloads =
        match complete_boundary_sequence(&mut storage, &mut controller, ordered.completed())? {
            BoundarySequence::Stopped => return Ok(controller.stopped()),
            BoundarySequence::Finished(payloads) => payloads,
        };
    if !complete_boundary_request(&mut storage, &mut controller, payloads.flush_request())? {
        return Ok(controller.stopped());
    }
    let (commit_request, commit_durability) = payloads.completed().submit();
    if !complete_boundary_request(&mut storage, &mut controller, commit_request)? {
        return Ok(controller.stopped());
    }
    if !complete_boundary_request(
        &mut storage,
        &mut controller,
        commit_durability.flush_request(),
    )? {
        return Ok(controller.stopped());
    }
    let published = commit_durability.completed().publish(
        &mut coordinator,
        ext4_core::VisibilityLease::granted(ticket),
    );
    let (epoch, checkpoint) = published.into_parts();
    let home = match complete_boundary_sequence(
        &mut storage,
        &mut controller,
        checkpoint.start(ext4_core::CheckpointLease::granted(epoch.sequence())),
    )? {
        BoundarySequence::Stopped => return Ok(controller.stopped()),
        BoundarySequence::Finished(home) => home,
    };
    if !complete_boundary_request(&mut storage, &mut controller, home.flush_request())? {
        return Ok(controller.stopped());
    }
    let (clean_request, clean_durability) = home.completed().submit();
    if !complete_boundary_request(&mut storage, &mut controller, clean_request)? {
        return Ok(controller.stopped());
    }
    if !complete_boundary_request(
        &mut storage,
        &mut controller,
        clean_durability.flush_request(),
    )? {
        return Ok(controller.stopped());
    }
    let _checkpointed_epoch = clean_durability.completed(&mut coordinator);
    Ok(controller.completed())
}

/// Consumes one production request sequence until completion or the selected crash boundary.
///
/// # Errors
///
/// Returns an error for host I/O or a mismatching lower completion identity.
fn complete_boundary_sequence<Next>(
    storage: &mut FileStorageAdapter,
    controller: &mut EffectBoundaryController,
    mut sequence: ext4_core::StorageRequestSequence<Next>,
) -> TaskResult<BoundarySequence<Next>> {
    loop {
        match sequence.advance() {
            ext4_core::StorageRequestSequenceStep::Submit { request, suspended } => {
                if !complete_boundary_request(storage, controller, request)? {
                    return Ok(BoundarySequence::Stopped);
                }
                sequence = suspended;
            }
            ext4_core::StorageRequestSequenceStep::Finished(next) => {
                return Ok(BoundarySequence::Finished(next));
            }
        }
    }
}

/// Executes one typestate-owned request and validates its completion unless a crash is selected.
///
/// # Errors
///
/// Returns an error for host I/O or a mismatching lower completion identity.
fn complete_boundary_request(
    storage: &mut FileStorageAdapter,
    controller: &mut EffectBoundaryController,
    request: ext4_core::StorageRequest,
) -> TaskResult<bool> {
    let identity = ext4_core::StorageRequestIdentity::from_request(&request);
    let Some(completion) = controller.complete(storage, request)? else {
        return Ok(false);
    };
    identity.complete(completion).map_err(core_task_error)?;
    Ok(true)
}

/// Executes the public production mount/recovery and clean-close protocols against one image file.
///
/// # Errors
///
/// Returns an error for host file I/O, unexpected external discovery, or any core terminal error.
fn drive_core_mount_and_clean_close(image: &Path) -> TaskResult<()> {
    let mut storage = FileStorageAdapter::open_internal(image)?;
    let length = ext4_core::DeviceLength::from_bytes(storage.filesystem.metadata()?.len());
    let mut transition = Box::try_new(ext4_core::MountOperation::new(
        length,
        ext4_core::FscryptKeySet::empty(),
    ))?
    .advance(ext4_core::OperationEvent::Admitted);
    let completed = loop {
        match transition {
            ext4_core::MountTransition::SubmitLower { request, suspended } => {
                let completion = complete_file_request(&mut storage, request)?;
                transition =
                    suspended.advance(ext4_core::OperationEvent::StorageCompleted(completion));
            }
            ext4_core::MountTransition::DiscoverExternalJournal { .. } => {
                return Err(io::Error::other(
                    "internal-journal interoperability image requested external discovery",
                )
                .into());
            }
            ext4_core::MountTransition::Complete(result) => {
                break result.map_err(core_task_error)?;
            }
        }
    };
    let (profile, _epoch, _coordinator) = completed.into_parts();
    let mut close = Box::try_new(ext4_core::CleanCloseOperation::new(
        length,
        profile.journal_target(),
    ))?
    .advance(ext4_core::OperationEvent::Admitted);
    loop {
        match close {
            ext4_core::CleanCloseTransition::SubmitLower { request, suspended } => {
                let completion = complete_file_request(&mut storage, request)?;
                close = suspended.advance(ext4_core::OperationEvent::StorageCompleted(completion));
            }
            ext4_core::CleanCloseTransition::Complete(result) => {
                result.map_err(core_task_error)?;
                return Ok(());
            }
        }
    }
}

/// Executes production external discovery, validation, recovery, and clean close against two
/// ordinary host files.
///
/// # Errors
///
/// Returns an error for file I/O, UUID/profile mismatch, unexpected probe outcome, or any core
/// mount/close protocol failure.
fn drive_external_core_mount_and_clean_close(
    filesystem: &Path,
    external_journal: &Path,
) -> TaskResult<()> {
    let mut storage = FileStorageAdapter::open_external(filesystem, external_journal)?;
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.filesystem.metadata()?.len());
    let completed = mount_external_core(&mut storage)?;
    let (profile, _epoch, _coordinator) = completed.into_parts();
    let mut close = Box::try_new(ext4_core::CleanCloseOperation::new(
        filesystem_length,
        profile.journal_target(),
    ))?
    .advance(ext4_core::OperationEvent::Admitted);
    loop {
        match close {
            ext4_core::CleanCloseTransition::SubmitLower { request, suspended } => {
                let completion = complete_file_request(&mut storage, request)?;
                close = suspended.advance(ext4_core::OperationEvent::StorageCompleted(completion));
            }
            ext4_core::CleanCloseTransition::Complete(result) => {
                result.map_err(core_task_error)?;
                return Ok(());
            }
        }
    }
}

/// Runs the public core validator for one exclusively selected external-journal file.
///
/// # Errors
///
/// Returns an error for file I/O, core corruption, or a UUID mismatch after exclusive selection.
fn drive_external_probe(
    storage: &mut FileStorageAdapter,
    requirement: ext4_core::ExternalJournalRequirement,
    external_length: ext4_core::DeviceLength,
) -> TaskResult<Box<ext4_core::ValidatedExternalJournal>> {
    let mut transition = Box::try_new(ext4_core::ExternalJournalProbeOperation::new(
        requirement,
        external_length,
    ))?
    .advance(ext4_core::OperationEvent::Admitted);
    loop {
        match transition {
            ext4_core::ExternalJournalProbeTransition::SubmitLower { request, suspended } => {
                let completion = complete_file_request(storage, request)?;
                transition =
                    suspended.advance(ext4_core::OperationEvent::StorageCompleted(completion));
            }
            ext4_core::ExternalJournalProbeTransition::Complete(Ok(
                ext4_core::ExternalJournalProbeOutcome::Match(validated),
            )) => return Ok(validated),
            ext4_core::ExternalJournalProbeTransition::Complete(Ok(
                ext4_core::ExternalJournalProbeOutcome::Mismatch,
            )) => {
                return Err(io::Error::other(
                    "exclusive external journal did not match the filesystem UUID",
                )
                .into());
            }
            ext4_core::ExternalJournalProbeTransition::Complete(Err(error)) => {
                return Err(core_task_error(error).into());
            }
        }
    }
}

/// Resolves and fully preallocates one volume-label commit from an owned completed mount.
///
/// This is the shared semantic boundary used by ordinary interoperability and the exhaustive
/// crash matrix; neither path substitutes a test-only commit constructor.
///
/// # Errors
///
/// Returns an error for mutation admission, resolve I/O, reservation conflict, invalid label, or
/// fallible preallocation before the first commit write.
fn prepare_volume_label_commit(
    storage: &mut FileStorageAdapter,
    completed: Box<ext4_core::CompletedMount>,
    label: &[u8],
) -> TaskResult<(
    ext4_core::CommitReadyMutation,
    ext4_core::MutationCoordinatorState,
    u64,
)> {
    let (profile, epoch, mut coordinator) = (*completed).into_parts();
    let ticket = coordinator.admit_mutation().map_err(core_task_error)?;
    let mut operation = ext4_core::MutationResolveOperation::new(&profile);
    let mut event = ext4_core::OperationEvent::Admitted;
    let resolved = loop {
        let mut ready = operation.accept(event).map_err(core_task_error)?;
        let result = {
            let mut crypto = RejectingCryptographicOperation;
            let mut pass = ready.begin_pass(
                &epoch,
                ext4_core::Ext4Timestamp::from_unix_seconds(1),
                &mut crypto,
            );
            pass.set_volume_label(ext4_core::Ext4VolumeLabel::new(label).map_err(core_task_error)?);
            pass.resolve(ticket, &coordinator)
        };
        match ready.finish(result) {
            ext4_core::MutationResolveTransition::SubmitLower { request, suspended } => {
                event = ext4_core::OperationEvent::StorageCompleted(complete_file_request(
                    storage, request,
                )?);
                operation = suspended;
            }
            ext4_core::MutationResolveTransition::Complete(result) => {
                break result.map_err(core_task_error)?;
            }
        }
    };
    let reserved = resolved
        .reserve(&coordinator, ext4_core::MutationLease::granted(ticket))
        .map_err(core_task_error)?;
    let prepared = reserved
        .prepare_commit(
            &coordinator,
            &epoch,
            ext4_core::CommitLease::granted(ticket),
        )
        .map_err(core_task_error)?;
    Ok((prepared, coordinator, ticket))
}

/// Mounts a clean image, commits a core-generated metadata transaction, and intentionally stops
/// before checkpoint so e2fsck becomes the independent replay implementation.
///
/// # Errors
///
/// Returns an error for mount/resolve/commit typestate failure or host image I/O failure.
fn drive_core_commit_without_checkpoint(image: &Path, label: &[u8]) -> TaskResult<()> {
    let mut storage = FileStorageAdapter::open_internal(image)?;
    let length = ext4_core::DeviceLength::from_bytes(storage.filesystem.metadata()?.len());
    let mut mount = Box::try_new(ext4_core::MountOperation::new(
        length,
        ext4_core::FscryptKeySet::empty(),
    ))?
    .advance(ext4_core::OperationEvent::Admitted);
    let completed = loop {
        match mount {
            ext4_core::MountTransition::SubmitLower { request, suspended } => {
                let completion = complete_file_request(&mut storage, request)?;
                mount = suspended.advance(ext4_core::OperationEvent::StorageCompleted(completion));
            }
            ext4_core::MountTransition::DiscoverExternalJournal { .. } => {
                return Err(io::Error::other(
                    "core-generated internal transaction requested external discovery",
                )
                .into());
            }
            ext4_core::MountTransition::Complete(result) => {
                break result.map_err(core_task_error)?;
            }
        }
    };
    let (prepared, _coordinator, _ticket) =
        prepare_volume_label_commit(&mut storage, completed, label)?;
    let ordered = complete_storage_sequence(&mut storage, prepared.start())?;
    complete_file_request_checked(&mut storage, ordered.flush_request())?;
    let payloads = complete_storage_sequence(&mut storage, ordered.completed())?;
    complete_file_request_checked(&mut storage, payloads.flush_request())?;
    let (commit_request, commit_durability) = payloads.completed().submit();
    complete_file_request_checked(&mut storage, commit_request)?;
    complete_file_request_checked(&mut storage, commit_durability.flush_request())?;
    let _durable_uncheckpointed = commit_durability.completed();
    storage.sync_all()?;
    Ok(())
}

/// Runs one preallocated production storage sequence and validates every exact completion.
///
/// # Errors
///
/// Returns an error for request I/O or completion identity mismatch.
fn complete_storage_sequence<Next>(
    storage: &mut FileStorageAdapter,
    mut sequence: ext4_core::StorageRequestSequence<Next>,
) -> TaskResult<Next> {
    loop {
        match sequence.advance() {
            ext4_core::StorageRequestSequenceStep::Submit { request, suspended } => {
                complete_file_request_checked(storage, request)?;
                sequence = suspended;
            }
            ext4_core::StorageRequestSequenceStep::Finished(next) => return Ok(next),
        }
    }
}

/// Executes and validates one exact storage request outside a core operation wrapper.
///
/// # Errors
///
/// Returns an error for host I/O or a mismatched completion identity.
fn complete_file_request_checked(
    storage: &mut FileStorageAdapter,
    request: ext4_core::StorageRequest,
) -> TaskResult<()> {
    let identity = ext4_core::StorageRequestIdentity::from_request(&request);
    let completion = complete_file_request(storage, request)?;
    identity.complete(completion).map_err(core_task_error)?;
    Ok(())
}

/// Cryptographic boundary used by the volume-label-only production mutation resolve pass.
#[derive(Debug)]
struct RejectingCryptographicOperation;

impl ext4_core::CryptographicOperation for RejectingCryptographicOperation {
    fn fill_random(&mut self, _output: &mut [u8]) -> ext4_core::Result<()> {
        Err(ext4_core::Error::CryptographicFailure)
    }

    fn hkdf_sha512(
        &mut self,
        _key: &[u8],
        _info: &[u8],
        _output: &mut [u8],
    ) -> ext4_core::Result<()> {
        Err(ext4_core::Error::CryptographicFailure)
    }

    fn encrypt_aes_256_xts(
        &mut self,
        _key: &[u8; 64],
        _data_unit: u64,
        _buffer: &mut [u8],
    ) -> ext4_core::Result<()> {
        Err(ext4_core::Error::CryptographicFailure)
    }

    fn decrypt_aes_256_xts(
        &mut self,
        _key: &[u8; 64],
        _data_unit: u64,
        _buffer: &mut [u8],
    ) -> ext4_core::Result<()> {
        Err(ext4_core::Error::CryptographicFailure)
    }

    fn encrypt_aes_256_cbc_cs3(
        &mut self,
        _key: &[u8; 32],
        _buffer: &mut [u8],
    ) -> ext4_core::Result<()> {
        Err(ext4_core::Error::CryptographicFailure)
    }

    fn decrypt_aes_256_cbc_cs3(
        &mut self,
        _key: &[u8; 32],
        _buffer: &mut [u8],
    ) -> ext4_core::Result<()> {
        Err(ext4_core::Error::CryptographicFailure)
    }

    fn sha256(&mut self, _input: &[u8]) -> ext4_core::Result<[u8; 32]> {
        Err(ext4_core::Error::CryptographicFailure)
    }

    fn sha512(&mut self, _input: &[u8]) -> ext4_core::Result<[u8; 64]> {
        Err(ext4_core::Error::CryptographicFailure)
    }
}

/// Completes one core-owned request against a host file while retaining its transfer buffer.
///
/// # Errors
///
/// Returns an error for external-device requests, offset arithmetic, or host file I/O failure.
fn complete_file_request(
    storage: &mut FileStorageAdapter,
    request: ext4_core::StorageRequest,
) -> TaskResult<ext4_core::StorageCompletion> {
    let transfer = match request {
        ext4_core::StorageRequest::Read {
            target,
            offset,
            mut buffer,
        } => {
            let file = storage.target_mut(target)?;
            file.seek(io::SeekFrom::Start(offset.get()))?;
            file.read_exact(&mut buffer)?;
            ext4_core::CompletedStorageTransfer::Read {
                target,
                offset,
                buffer,
            }
        }
        ext4_core::StorageRequest::Write {
            target,
            offset,
            buffer,
        } => {
            let file = storage.target_mut(target)?;
            file.seek(io::SeekFrom::Start(offset.get()))?;
            file.write_all(&buffer)?;
            ext4_core::CompletedStorageTransfer::Write {
                target,
                offset,
                buffer,
            }
        }
        ext4_core::StorageRequest::Flush { target } => {
            storage.target_mut(target)?.sync_all()?;
            ext4_core::CompletedStorageTransfer::Flush { target }
        }
    };
    let information = transfer.byte_count();
    Ok(ext4_core::StorageCompletion::success(transfer, information))
}

/// Converts one no-std core error into the host task error boundary.
fn core_task_error(error: ext4_core::Error) -> io::Error {
    io::Error::other(error.to_string())
}

/// Verifies that one replay target contains the latest committed pattern, not the torn tail.
///
/// # Errors
///
/// Returns an error for range/file I/O failure or a mismatching byte.
fn verify_pattern_block(image: &Path, block_size: u32, block: u64, expected: u8) -> TaskResult<()> {
    let mut file = File::open(image)?;
    let offset = block
        .checked_mul(u64::from(block_size))
        .ok_or_else(|| io::Error::other("replay verification offset overflow"))?;
    file.seek(io::SeekFrom::Start(offset))?;
    let mut bytes = vec![0_u8; usize::try_from(block_size)?];
    file.read_exact(&mut bytes)?;
    if bytes.iter().all(|byte| *byte == expected) {
        Ok(())
    } else {
        let first = bytes.first().copied().unwrap_or_default();
        Err(io::Error::other(format!(
            "journal replay did not publish pattern {expected:#04X}; first byte is {first:#04X}"
        ))
        .into())
    }
}

/// Verifies the primary-superblock label after e2fsck replays a core-generated transaction.
///
/// # Errors
///
/// Returns an error for file I/O, invalid label length, or mismatching on-disk bytes.
fn verify_volume_label(image: &Path, expected: &[u8]) -> TaskResult<()> {
    if expected.len() > ext4_core::Ext4VolumeLabel::MAX_BYTES {
        return Err(io::Error::other("expected volume label is too long").into());
    }
    let mut file = File::open(image)?;
    let offset = 1024_u64
        .checked_add(0x78)
        .ok_or_else(|| io::Error::other("volume label offset overflow"))?;
    file.seek(io::SeekFrom::Start(offset))?;
    let mut raw = [0_u8; ext4_core::Ext4VolumeLabel::MAX_BYTES];
    file.read_exact(&mut raw)?;
    let actual = raw
        .get(..expected.len())
        .ok_or_else(|| io::Error::other("volume label comparison range is invalid"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::other("e2fsck did not replay the core-generated metadata label").into())
    }
}

/// Creates one process-unique task directory under the repository target tree.
///
/// # Errors
///
/// Returns an error when the clock or directory creation fails.
fn create_task_directory(repository_root: &Path, task: &str) -> TaskResult<PathBuf> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let parent = repository_root.join("target").join(task);
    fs::create_dir_all(&parent)?;
    let directory = parent.join(format!("{}-{}", process::id(), elapsed.as_nanos()));
    fs::create_dir(&directory)?;
    Ok(directory)
}

/// Removes only the exact task-owned directory after validating its resolved parent boundary.
///
/// # Errors
///
/// Returns an error when the path is outside the named target subtree or cleanup fails.
fn remove_task_directory(repository_root: &Path, directory: &Path, task: &str) -> TaskResult<()> {
    let expected_parent = repository_root.join("target").join(task);
    let resolved_parent = directory
        .parent()
        .ok_or_else(|| io::Error::other("task directory has no parent"))?;
    if resolved_parent != expected_parent || directory == expected_parent {
        return Err(io::Error::other("refusing to remove an unowned task directory").into());
    }
    fs::remove_dir_all(directory)?;
    Ok(())
}

/// Returns the tracked external-journal fixture directory.
fn journal_fixture_directory(repository_root: &Path) -> PathBuf {
    repository_root
        .join("tests")
        .join("fixtures")
        .join("journal")
}

/// Parses the strict, versioned external-journal provenance manifest.
///
/// # Errors
///
/// Returns an error for file I/O, malformed fields, duplicate identities, unsafe relative paths,
/// unsupported profiles, invalid UUIDs or digests, or a fixture count other than three.
fn parse_journal_fixture_manifest(path: &Path) -> TaskResult<JournalFixtureManifest> {
    let text = fs::read_to_string(path)?;
    parse_journal_fixture_manifest_text(&text)
}

/// Parses manifest records after the file-system boundary has supplied UTF-8 text.
///
/// # Errors
///
/// Returns an error for malformed fields, duplicate identities, unsafe relative paths,
/// unsupported profiles, invalid UUIDs or digests, or a fixture count other than three.
fn parse_journal_fixture_manifest_text(text: &str) -> TaskResult<JournalFixtureManifest> {
    let mut e2fsprogs_version = None;
    let mut fake_time = None;
    let mut fixtures = Vec::new();
    let mut names = BTreeSet::new();
    let mut files = BTreeSet::new();
    for (line_index, raw_line) in text.lines().enumerate() {
        let line_number = line_index
            .checked_add(1)
            .ok_or_else(|| io::Error::other("manifest line number overflow"))?;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            ["e2fsprogs", version] if e2fsprogs_version.is_none() => {
                e2fsprogs_version = Some((*version).to_owned());
            }
            ["fake-time", seconds] if fake_time.is_none() => {
                fake_time = Some(seconds.parse::<u64>()?);
            }
            [
                "fixture",
                name,
                block_size,
                checksum_version,
                bitness,
                replay_block,
                filesystem_uuid,
                filesystem_file,
                filesystem_sha256,
                journal_uuid,
                journal_file,
                journal_sha256,
            ] => {
                let block_size = block_size.parse::<u32>()?;
                let checksum_version = checksum_version.parse::<u8>()?;
                let block_numbers_64bit = match *bitness {
                    "32" => false,
                    "64" => true,
                    _ => return Err(manifest_line_error(line_number, "bitness must be 32 or 64")),
                };
                let replay_block = replay_block.parse::<u64>()?;
                if replay_block == 0 {
                    return Err(manifest_line_error(
                        line_number,
                        "replay block must be nonzero",
                    ));
                }
                for file in [*filesystem_file, *journal_file] {
                    let path = Path::new(file);
                    if path.components().count() != 1 || path.file_name() != Some(OsStr::new(file))
                    {
                        return Err(manifest_line_error(
                            line_number,
                            "fixture paths must be single relative file names",
                        ));
                    }
                    if !files.insert(file.to_owned()) {
                        return Err(manifest_line_error(line_number, "duplicate fixture file"));
                    }
                }
                if !names.insert((*name).to_owned()) {
                    return Err(manifest_line_error(line_number, "duplicate fixture name"));
                }
                for uuid in [*filesystem_uuid, *journal_uuid] {
                    if !is_canonical_uuid(uuid) {
                        return Err(manifest_line_error(line_number, "invalid canonical UUID"));
                    }
                }
                for digest in [*filesystem_sha256, *journal_sha256] {
                    if !is_sha256_hex(digest) {
                        return Err(manifest_line_error(line_number, "invalid SHA-256 digest"));
                    }
                }
                fixtures.push(ExternalJournalFixture {
                    name: (*name).to_owned(),
                    block_size,
                    checksum_version,
                    block_numbers_64bit,
                    replay_block,
                    filesystem_uuid: (*filesystem_uuid).to_owned(),
                    journal_uuid: (*journal_uuid).to_owned(),
                    filesystem_file: (*filesystem_file).to_owned(),
                    filesystem_sha256: filesystem_sha256.to_ascii_uppercase(),
                    journal_file: (*journal_file).to_owned(),
                    journal_sha256: journal_sha256.to_ascii_uppercase(),
                });
            }
            _ => {
                return Err(manifest_line_error(
                    line_number,
                    "unrecognized manifest record",
                ));
            }
        }
    }
    let manifest = JournalFixtureManifest {
        e2fsprogs_version: e2fsprogs_version
            .ok_or_else(|| io::Error::other("manifest omits e2fsprogs version"))?,
        fake_time: fake_time.ok_or_else(|| io::Error::other("manifest omits fake time"))?,
        fixtures,
    };
    validate_fixture_profiles(&manifest)?;
    Ok(manifest)
}

/// Constructs one manifest diagnostic bound to its source line.
fn manifest_line_error(line: usize, message: &str) -> Box<dyn Error> {
    io::Error::other(format!("journal fixture manifest line {line}: {message}")).into()
}

/// Validates the exact three external-journal profiles promised by the repository gate.
///
/// # Errors
///
/// Returns an error when a profile is missing, duplicated, or carries unexpected geometry.
fn validate_fixture_profiles(manifest: &JournalFixtureManifest) -> TaskResult<()> {
    let expected = [
        ("external-1k-v2-32", 1024_u32, 2_u8, false),
        ("external-2k-v3-64", 2048_u32, 3_u8, true),
        ("external-4k-v3-64", 4096_u32, 3_u8, true),
    ];
    if manifest.fixtures.len() != expected.len() {
        return Err(io::Error::other("manifest must contain exactly three fixtures").into());
    }
    for (name, block_size, checksum_version, block_numbers_64bit) in expected {
        let matches = manifest
            .fixtures
            .iter()
            .filter(|fixture| {
                fixture.name == name
                    && fixture.block_size == block_size
                    && fixture.checksum_version == checksum_version
                    && fixture.block_numbers_64bit == block_numbers_64bit
            })
            .count();
        if matches != 1 {
            return Err(io::Error::other(format!(
                "manifest does not define the exact required profile {name}"
            ))
            .into());
        }
    }
    Ok(())
}

/// Whether one string is a canonical lowercase-or-uppercase UUID spelling.
fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// Whether one string carries exactly 32 SHA-256 bytes in hexadecimal.
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Regenerates external-journal fixtures under the pinned e2fsprogs/loop-device authority.
///
/// # Errors
///
/// Returns an error unless the host provides the manifest-pinned e2fsprogs release and root loop
/// authority, or when regenerated raw bytes/digests differ from the tracked fixtures.
fn verify_journal_fixture_provenance(repository_root: &Path) -> TaskResult<()> {
    let linux = LinuxEnvironment::require()?;
    let fixture_directory = journal_fixture_directory(repository_root);
    let manifest_path = fixture_directory.join("provenance.manifest");
    let manifest = parse_journal_fixture_manifest(&manifest_path)?;
    let actual_version = linux.e2fsprogs_version()?;
    if actual_version != manifest.e2fsprogs_version {
        return Err(io::Error::other(format!(
            "fixture provenance requires e2fsprogs {}, found {actual_version}",
            manifest.e2fsprogs_version
        ))
        .into());
    }
    linux.require_loop_device_authority()?;

    let temporary_root = create_task_directory(repository_root, "journal-fixture-provenance")?;
    let verification = (|| -> TaskResult<()> {
        for fixture in &manifest.fixtures {
            verify_reproduced_external_fixture(
                linux,
                &fixture_directory,
                &temporary_root,
                fixture,
                manifest.fake_time,
            )?;
        }
        Ok(())
    })();
    let cleanup = remove_task_directory(
        repository_root,
        &temporary_root,
        "journal-fixture-provenance",
    );
    combine_verification_and_cleanup(verification, cleanup)?;
    println!(
        "external JBD2 fixture provenance (e2fsprogs {}): PASS",
        manifest.e2fsprogs_version
    );
    Ok(())
}

/// Regenerates and byte-compares one external-journal fixture pair.
///
/// # Errors
///
/// Returns an error for tracked digest drift, image generation/finalization failure, regenerated
/// digest drift, or any byte difference.
fn verify_reproduced_external_fixture(
    linux: LinuxEnvironment,
    fixture_directory: &Path,
    temporary_root: &Path,
    fixture: &ExternalJournalFixture,
    fake_time: u64,
) -> TaskResult<()> {
    let tracked_filesystem = fixture_directory.join(&fixture.filesystem_file);
    let tracked_journal = fixture_directory.join(&fixture.journal_file);
    require_fixture_digest(
        &tracked_filesystem,
        &fixture.filesystem_sha256,
        &format!("{} tracked filesystem", fixture.name),
    )?;
    require_fixture_digest(
        &tracked_journal,
        &fixture.journal_sha256,
        &format!("{} tracked external journal", fixture.name),
    )?;

    let case_root = temporary_root.join(&fixture.name);
    fs::create_dir(&case_root)?;
    let generated_filesystem = case_root.join("filesystem.img");
    let generated_journal = case_root.join("external-journal.img");
    generate_external_journal_fixture(
        linux,
        &case_root,
        &generated_filesystem,
        &generated_journal,
        fixture,
        fake_time,
    )?;
    require_fixture_digest(
        &generated_filesystem,
        &fixture.filesystem_sha256,
        &format!("{} regenerated filesystem", fixture.name),
    )?;
    require_fixture_digest(
        &generated_journal,
        &fixture.journal_sha256,
        &format!("{} regenerated external journal", fixture.name),
    )?;
    require_identical_files(
        &tracked_filesystem,
        &generated_filesystem,
        &format!("{} filesystem", fixture.name),
    )?;
    require_identical_files(
        &tracked_journal,
        &generated_journal,
        &format!("{} external journal", fixture.name),
    )?;
    Ok(())
}

/// Produces one deterministic dirty external-journal pair using only the pinned external oracle.
///
/// # Errors
///
/// Returns an error for host file I/O, path conversion, loop attachment/finalization, e2fsprogs
/// failure, an unexpected free replay block, or command-file construction.
fn generate_external_journal_fixture(
    linux: LinuxEnvironment,
    case_root: &Path,
    filesystem: &Path,
    journal: &Path,
    fixture: &ExternalJournalFixture,
    fake_time: u64,
) -> TaskResult<()> {
    const FILESYSTEM_BYTES: u64 = 16 * 1024 * 1024;
    const JOURNAL_BYTES: u64 = 4 * 1024 * 1024;

    File::create(filesystem)?.set_len(FILESYSTEM_BYTES)?;
    File::create(journal)?.set_len(JOURNAL_BYTES)?;
    let filesystem_path = linux.tool_path(filesystem)?;
    let journal_path = linux.tool_path(journal)?;
    let loops = FixtureLoopDevices::attach(linux, &journal_path, &filesystem_path)?;
    let generation = (|| -> TaskResult<()> {
        let fake_time = fake_time.to_string();
        let block_size = fixture.block_size.to_string();
        let journal_extended = format!("hash_seed={}", fixture.journal_uuid);
        let mut journal_format =
            linux.command_with_environment("mke2fs", "E2FSPROGS_FAKE_TIME", &fake_time);
        journal_format.args([
            "-q",
            "-F",
            "-O",
            "journal_dev",
            "-b",
            &block_size,
            "-E",
            &journal_extended,
            "-U",
            &fixture.journal_uuid,
            &loops.journal,
        ]);
        run_checked(
            journal_format,
            &format!("external journal format for {}", fixture.name),
        )?;

        let features = if fixture.block_numbers_64bit {
            "metadata_csum,64bit,^metadata_csum_seed,^orphan_file"
        } else {
            "metadata_csum,^64bit,^metadata_csum_seed,^orphan_file"
        };
        let extended = format!(
            "lazy_itable_init=0,lazy_journal_init=0,hash_seed={}",
            fixture.filesystem_uuid
        );
        let journal_option = format!("device={}", loops.journal);
        let mut filesystem_format =
            linux.command_with_environment("mke2fs", "E2FSPROGS_FAKE_TIME", &fake_time);
        filesystem_format.args([
            "-q",
            "-F",
            "-t",
            "ext4",
            "-b",
            &block_size,
            "-O",
            features,
            "-E",
            &extended,
            "-U",
            &fixture.filesystem_uuid,
            "-J",
            &journal_option,
            &loops.filesystem,
        ]);
        run_checked(
            filesystem_format,
            &format!("external filesystem format for {}", fixture.name),
        )?;

        let free_block = debugfs_first_free_block(linux, &loops.filesystem)?;
        if free_block != fixture.replay_block {
            return Err(io::Error::other(format!(
                "{} replay block drift: manifest={} generated={free_block}",
                fixture.name, fixture.replay_block
            ))
            .into());
        }
        let payload = case_root.join("committed-payload.bin");
        write_pattern_block(&payload, fixture.block_size, 0xD4)?;
        let payload_path = linux.tool_path(&payload)?;
        let commands = case_root.join("journal.commands");
        let command_body = format!(
            "journal_open -c -v {checksum} -f {journal}\n\
             journal_write -b {block} {payload}\n\
             journal_close\n",
            checksum = fixture.checksum_version,
            journal = loops.journal,
            block = fixture.replay_block,
            payload = payload_path,
        );
        fs::write(&commands, command_body)?;
        let commands_path = linux.tool_path(&commands)?;
        let mut debugfs =
            linux.command_with_environment("debugfs", "E2FSPROGS_FAKE_TIME", &fake_time);
        debugfs.args(["-w", "-f", &commands_path, &loops.filesystem]);
        run_checked(
            debugfs,
            &format!("external journal transaction for {}", fixture.name),
        )?;
        let sync = linux.command("sync");
        run_checked(sync, "external fixture pre-detach sync")?;
        Ok(())
    })();
    let detach = loops.detach(linux);
    combine_verification_and_cleanup(generation, detach)?;
    normalize_external_debugfs_descriptors(journal, fixture, fake_time)
}

/// Attaches one raw ordinary file to the next free Linux loop device.
///
/// # Errors
///
/// Returns an error when losetup fails or emits an invalid loop-device path.
fn attach_loop_device(linux: LinuxEnvironment, image: &str) -> TaskResult<String> {
    let mut command = linux.command("losetup");
    command.args(["--find", "--show", image]);
    let output = run_checked_output(command, "loop-device attach")?;
    let path = String::from_utf8(output.stdout)?.trim().to_owned();
    if !is_loop_device_path(&path) {
        return Err(io::Error::other(format!(
            "losetup emitted an invalid loop-device path: {path}"
        ))
        .into());
    }
    Ok(path)
}

/// Explicitly releases one loop-device attachment.
///
/// # Errors
///
/// Returns an error when losetup rejects the exact validated device path.
fn detach_loop_device(linux: LinuxEnvironment, device: &str) -> TaskResult<()> {
    if !is_loop_device_path(device) {
        return Err(io::Error::other("refusing to detach an invalid loop-device path").into());
    }
    let mut command = linux.command("losetup");
    command.args(["--detach", device]);
    run_checked(command, &format!("loop-device detach for {device}"))
}

/// Whether one child result names exactly `/dev/loop` followed by decimal digits.
fn is_loop_device_path(path: &str) -> bool {
    path.strip_prefix("/dev/loop").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// Verifies one tracked or regenerated file against its manifest digest.
///
/// # Errors
///
/// Returns an error when the file is missing/unreadable or its SHA-256 differs.
fn require_fixture_digest(path: &Path, expected: &str, description: &str) -> TaskResult<()> {
    require_file(path, description)?;
    let actual = sha256_file(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{description} SHA-256 mismatch: expected {expected}, found {actual}"
        ))
        .into())
    }
}

/// Byte-compares two raw fixture files without retaining either image in memory.
///
/// # Errors
///
/// Returns an error for file I/O, differing lengths, or the first differing byte window.
fn require_identical_files(expected: &Path, actual: &Path, description: &str) -> TaskResult<()> {
    if expected.metadata()?.len() != actual.metadata()?.len() {
        return Err(io::Error::other(format!("{description} raw lengths differ")).into());
    }
    let mut expected_file = File::open(expected)?;
    let mut actual_file = File::open(actual)?;
    let mut expected_buffer = vec![0_u8; 64 * 1024];
    let mut actual_buffer = vec![0_u8; 64 * 1024];
    loop {
        let expected_read = expected_file.read(&mut expected_buffer)?;
        let actual_read = actual_file.read(&mut actual_buffer)?;
        if expected_read != actual_read {
            return Err(io::Error::other(format!("{description} raw read lengths differ")).into());
        }
        if expected_read == 0 {
            return Ok(());
        }
        let expected_bytes = expected_buffer
            .get(..expected_read)
            .ok_or_else(|| io::Error::other("expected fixture read range is invalid"))?;
        let actual_bytes = actual_buffer
            .get(..actual_read)
            .ok_or_else(|| io::Error::other("actual fixture read range is invalid"))?;
        if expected_bytes != actual_bytes {
            return Err(io::Error::other(format!("{description} raw bytes differ")).into());
        }
    }
}

/// Preserves both an operation failure and its mandatory finalization failure.
///
/// # Errors
///
/// Returns the operation error, finalization error, or a combined diagnostic when both fail.
fn combine_verification_and_cleanup(
    operation: TaskResult<()>,
    cleanup: TaskResult<()>,
) -> TaskResult<()> {
    match (operation, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(operation_error), Err(cleanup_error)) => Err(io::Error::other(format!(
            "operation failed ({operation_error}); mandatory finalization also failed ({cleanup_error})"
        ))
        .into()),
    }
}

/// Builds and verifies one exact signed production driver bundle.
///
/// # Errors
///
/// Returns an error on non-Windows hosts, failed build or analysis commands, missing or invalid
/// artifacts, source drift, or artifact hashing failure.
fn verify_production_driver(repository_root: &Path) -> TaskResult<()> {
    verify_portable(repository_root)?;
    verify_driver(repository_root)?;
    verify_journal_interop(repository_root)?;
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
    let signed_driver_hash = verify_final_signed_artifact(&artifacts.driver, "production driver")?;
    let signed_catalog_hash =
        verify_final_signed_artifact(&artifacts.catalog, "production catalog")?;
    let snapshot_directory =
        create_task_directory(repository_root, "production-artifact-snapshot")?;
    let verification = (|| -> TaskResult<SealedProductionArtifacts> {
        let sealed =
            seal_production_artifacts(&artifacts, &snapshot_directory, &signed_driver_hash)?;
        if sealed.catalog_hash != signed_catalog_hash {
            return Err(io::Error::other(
                "signed catalog changed after final Authenticode verification and before analyzer sealing",
            )
            .into());
        }
        run_production_reachability(repository_root, &sealed.artifacts)?;
        sealed.verify_unchanged()?;
        verify_sha256(
            &artifacts.driver,
            &signed_driver_hash,
            "final signed production driver",
        )?;
        verify_sha256(
            &artifacts.catalog,
            &signed_catalog_hash,
            "final signed production catalog",
        )?;
        verify_sha256(
            &artifacts.inf,
            &sealed.inf_hash,
            "final production installation metadata",
        )?;
        Ok(sealed)
    })();
    let sealed = match verification {
        Ok(sealed) => sealed,
        Err(verification_error) => {
            let cleanup = remove_task_directory(
                repository_root,
                &snapshot_directory,
                "production-artifact-snapshot",
            );
            return combine_verification_and_cleanup(Err(verification_error), cleanup);
        }
    };
    let publication = (|| -> TaskResult<PathBuf> {
        let source_after = source_snapshot(repository_root)?;
        if source_before != source_after {
            return Err(io::Error::other(
                "source inputs changed while the production artifact gate was running",
            )
            .into());
        }
        write_production_manifest(
            repository_root,
            &snapshot_directory,
            &identity,
            &source_before,
            &sealed,
        )?;
        publish_verified_bundle(repository_root, &snapshot_directory, &identity)
    })();
    let bundle_directory = match publication {
        Ok(bundle_directory) => bundle_directory,
        Err(publication_error) => {
            let cleanup = remove_task_directory(
                repository_root,
                &snapshot_directory,
                "production-artifact-snapshot",
            );
            return combine_verification_and_cleanup(Err(publication_error), cleanup);
        }
    };

    println!("production artifact bundle: PASS");
    println!("identity: {}", identity.as_str());
    println!("bundle: {}", bundle_directory.display());
    println!("LLVM IR: ext4win.ll ({})", sealed.ir_hash);
    println!("link map: ext4win.map ({})", sealed.map_hash,);
    println!("signed driver: ext4win.sys ({})", sealed.driver_hash,);
    println!("signed catalog: ext4win.cat ({})", sealed.catalog_hash);
    println!("installation metadata: ext4win.inf ({})", sealed.inf_hash);
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
    let catalog = package_root.join("ext4win.cat");
    let inf = package_root.join("ext4win.inf");
    require_file(&link_map, "cargo-wdk package link map")?;
    require_file(&driver, "cargo-wdk signed package driver")?;
    require_file(&catalog, "cargo-wdk signed package catalog")?;
    require_file(&inf, "cargo-wdk package installation metadata")?;

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
        catalog,
        inf,
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

/// Authenticode-verifies one final package artifact and proves it was stable during verification.
///
/// cargo-wdk separately validates the driver/catalog package under its WDK signing workflow.
/// This final readback uses Authenticode policy so a locally trusted test-signed bundle remains
/// verifiable; it does not claim a Microsoft production-root deployment chain.
///
/// # Errors
///
/// Returns an error when `signtool` rejects the artifact or its SHA-256 changes before or after
/// the verification command.
fn verify_final_signed_artifact(path: &Path, description: &str) -> TaskResult<String> {
    let before = sha256_file(path)?;
    let signtool = locate_signtool()?;
    let mut command = Command::new(signtool);
    command.args(["verify", "/pa", "/v"]).arg(path);
    run_checked(
        command,
        &format!("final {description} Authenticode signature verification"),
    )?;
    verify_sha256(
        path,
        &before,
        &format!("{description} during final Authenticode verification"),
    )?;
    Ok(before)
}

/// Locates the x64 Authenticode verifier from PATH or the newest installed numeric Windows Kit.
///
/// cargo-wdk establishes its own WDK tool environment internally, so the parent process is not
/// required to expose `signtool.exe` on PATH. Final artifact verification therefore owns an
/// explicit host-tool discovery boundary instead of relying on ambient child-process setup.
///
/// # Errors
///
/// Returns `NotFound` when neither PATH nor a validated Windows Kits installation contains the
/// executable, or returns directory-enumeration errors from an existing kit root.
fn locate_signtool() -> TaskResult<PathBuf> {
    if let Some(path) = env::var_os("PATH") {
        for directory in env::split_paths(&path) {
            let candidate = directory.join("signtool.exe");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    let program_files = env::var_os("ProgramFiles(x86)").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "ProgramFiles(x86) is unavailable while locating signtool.exe",
        )
    })?;
    let kit_root = PathBuf::from(program_files)
        .join("Windows Kits")
        .join("10")
        .join("bin");
    if !kit_root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Windows Kits tool root is absent: {}", kit_root.display()),
        )
        .into());
    }

    let mut selected: Option<(WindowsKitVersion, PathBuf)> = None;
    for entry in fs::read_dir(&kit_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(version) = WindowsKitVersion::parse(&name) else {
            continue;
        };
        let candidate = entry.path().join("x64").join("signtool.exe");
        if !candidate.is_file() {
            continue;
        }
        if selected
            .as_ref()
            .is_none_or(|(current, _path)| version > *current)
        {
            selected = Some((version, candidate));
        }
    }
    selected.map(|(_version, path)| path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no numeric x64 Windows Kit contains signtool.exe below {}",
                kit_root.display()
            ),
        )
        .into()
    })
}

/// Copies every analyzer input only after proving the source file remained one exact byte sequence.
///
/// # Errors
///
/// Returns an error for source mutation, I/O failure, a duplicate snapshot destination, or a
/// signed-driver digest that differs from the cryptographically verified final SYS.
fn seal_production_artifacts(
    source: &ProductionArtifacts,
    directory: &Path,
    signed_driver_hash: &str,
) -> TaskResult<SealedProductionArtifacts> {
    let ir = directory.join("ext4win.ll");
    let link_map = directory.join("ext4win.map");
    let driver = directory.join("ext4win.sys");
    let catalog = directory.join("ext4win.cat");
    let inf = directory.join("ext4win.inf");
    let ir_hash = copy_stable_artifact(&source.ir, &ir, "release LLVM IR")?;
    let map_hash = copy_stable_artifact(&source.link_map, &link_map, "release link map")?;
    let driver_hash = copy_stable_artifact(&source.driver, &driver, "signed driver")?;
    let catalog_hash = copy_stable_artifact(&source.catalog, &catalog, "signed catalog")?;
    let inf_hash = copy_stable_artifact(&source.inf, &inf, "driver installation metadata")?;
    if driver_hash != signed_driver_hash {
        return Err(io::Error::other(
            "signed driver changed after final Authenticode verification and before analyzer sealing",
        )
        .into());
    }
    Ok(SealedProductionArtifacts {
        artifacts: ProductionArtifacts {
            ir,
            link_map,
            driver,
            catalog,
            inf,
        },
        ir_hash,
        map_hash,
        driver_hash,
        catalog_hash,
        inf_hash,
    })
}

/// Writes the versioned evidence manifest into an unpublished verified bundle.
///
/// # Errors
///
/// Returns an error when tool identity cannot be captured or the manifest cannot be created and
/// durably written.
fn write_production_manifest(
    repository_root: &Path,
    directory: &Path,
    identity: &ArtifactIdentity,
    source_snapshot: &SourceSnapshot,
    sealed: &SealedProductionArtifacts,
) -> TaskResult<()> {
    let rustc_verbose = command_version(
        command_with_arguments("rustc", &["--version", "--verbose"]),
        "rustc version query",
    )?;
    let rustc = required_version_line(&rustc_verbose, "release:")?;
    let llvm = required_version_line(&rustc_verbose, "LLVM version:")?;
    let cargo = command_version(
        command_with_arguments("cargo", &["--version"]),
        "Cargo version query",
    )?;
    let mut cargo_wdk_command = command_with_arguments("cargo", &["wdk", "--version"]);
    cargo_wdk_command.current_dir(repository_root.join("crates").join("ext4-driver"));
    let cargo_wdk = command_version(cargo_wdk_command, "cargo-wdk version query")?;
    let wdk = production_wdk_version()?;
    let source_hash = source_snapshot.hex_digest()?;
    let rustflags = ["-C", "target-feature=+crt-static", "--emit=llvm-ir,link"]
        .join(ENCODED_RUSTFLAGS_SEPARATOR);

    let mut manifest = String::new();
    writeln!(&mut manifest, "manifest_version=1")?;
    writeln!(&mut manifest, "artifact_id={}", identity.as_str())?;
    writeln!(&mut manifest, "source_snapshot_sha256={source_hash}")?;
    writeln!(&mut manifest, "target=x86_64-pc-windows-msvc")?;
    writeln!(&mut manifest, "profile=release")?;
    writeln!(
        &mut manifest,
        "rustflags={}",
        normalized_manifest_value(&rustflags)
    )?;
    writeln!(&mut manifest, "rustc={}", normalized_manifest_value(rustc))?;
    writeln!(&mut manifest, "llvm={}", normalized_manifest_value(llvm))?;
    writeln!(&mut manifest, "cargo={}", normalized_manifest_value(&cargo))?;
    writeln!(
        &mut manifest,
        "cargo_wdk={}",
        normalized_manifest_value(&cargo_wdk)
    )?;
    writeln!(&mut manifest, "wdk={}", normalized_manifest_value(&wdk))?;
    write_manifest_artifact(&mut manifest, "ir", "ext4win.ll", &sealed.ir_hash)?;
    write_manifest_artifact(&mut manifest, "map", "ext4win.map", &sealed.map_hash)?;
    write_manifest_artifact(&mut manifest, "sys", "ext4win.sys", &sealed.driver_hash)?;
    write_manifest_artifact(&mut manifest, "cat", "ext4win.cat", &sealed.catalog_hash)?;
    write_manifest_artifact(&mut manifest, "inf", "ext4win.inf", &sealed.inf_hash)?;

    let manifest_path = directory.join("manifest-v1.txt");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(manifest_path)?;
    output.write_all(manifest.as_bytes())?;
    output.sync_all()?;
    Ok(())
}

/// Appends one artifact path and digest pair to the production manifest.
///
/// # Errors
///
/// Returns a formatting error when the in-memory manifest cannot accept the record.
fn write_manifest_artifact(
    manifest: &mut String,
    name: &str,
    path: &str,
    hash: &str,
) -> Result<(), core::fmt::Error> {
    writeln!(manifest, "artifact.{name}.path={path}")?;
    writeln!(manifest, "artifact.{name}.sha256={hash}")
}

/// Replaces line-breaking or field-separator bytes before recording tool output.
fn normalized_manifest_value(value: &str) -> String {
    value
        .trim()
        .replace('\r', "")
        .replace('\n', " | ")
        .replace(ENCODED_RUSTFLAGS_SEPARATOR, "<US>")
}

/// Extracts one required field from rustc's verbose version report.
///
/// # Errors
///
/// Returns an error when the report omits the named nonempty field.
fn required_version_line<'a>(report: &'a str, prefix: &str) -> TaskResult<&'a str> {
    report
        .lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::trim))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::other(format!(
                "tool version report omitted required field {prefix}"
            ))
            .into()
        })
}

/// Runs one version command and returns nonempty UTF-8 stdout.
///
/// # Errors
///
/// Returns an error when the command fails, emits non-UTF-8 output, or emits no version text.
fn command_version(command: Command, description: &str) -> TaskResult<String> {
    let output = run_checked_output(command, description)?;
    let value = String::from_utf8(output.stdout)?;
    if value.trim().is_empty() {
        Err(io::Error::other(format!("{description} returned empty stdout")).into())
    } else {
        Ok(value)
    }
}

/// Constructs one child command without inheriting a task-specific working directory.
fn command_with_arguments(program: &str, arguments: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(arguments);
    command
}

/// Resolves the numeric WDK/SDK version containing the exact final signature verifier.
///
/// # Errors
///
/// Returns an error when the selected tool path is not contained in a numeric Windows Kit.
fn production_wdk_version() -> TaskResult<String> {
    let signtool = locate_signtool()?;
    signtool
        .ancestors()
        .filter_map(Path::file_name)
        .filter_map(OsStr::to_str)
        .find(|name| WindowsKitVersion::parse(name).is_some())
        .map(str::to_owned)
        .ok_or_else(|| {
            io::Error::other(format!(
                "selected signtool is not below a numeric Windows Kit: {}",
                signtool.display()
            ))
            .into()
        })
}

/// Atomically publishes a fully verified staging directory under its artifact identity.
///
/// # Errors
///
/// Returns an error when the staging boundary is invalid, the identity already exists, or the
/// final directory cannot be created or renamed.
fn publish_verified_bundle(
    repository_root: &Path,
    staging_directory: &Path,
    identity: &ArtifactIdentity,
) -> TaskResult<PathBuf> {
    let expected_staging_parent = repository_root
        .join("target")
        .join("production-artifact-snapshot");
    if staging_directory.parent() != Some(expected_staging_parent.as_path()) {
        return Err(io::Error::other("refusing to publish an unowned staging directory").into());
    }
    let verified_parent = repository_root.join("target").join("verified-production");
    fs::create_dir_all(&verified_parent)?;
    let destination = verified_parent.join(identity.as_str());
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "verified artifact identity already exists: {}",
                destination.display()
            ),
        )
        .into());
    }
    fs::rename(staging_directory, &destination)?;
    Ok(destination)
}

/// Copies one source artifact into a new private file while rejecting any source-byte race.
///
/// # Errors
///
/// Returns an error when the source changes while read, the new snapshot cannot be created, or its
/// digest does not exactly equal the stable source digest.
fn copy_stable_artifact(
    source: &Path,
    destination: &Path,
    description: &str,
) -> TaskResult<String> {
    let before = sha256_file(source)?;
    let bytes = fs::read(source)?;
    let copied_hash = sha256_bytes(&bytes)?;
    verify_sha256(source, &before, description)?;
    if copied_hash != before {
        return Err(io::Error::other(format!(
            "{description} changed while its analyzer snapshot was being read"
        ))
        .into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    verify_sha256(destination, &before, "sealed production artifact")?;
    Ok(before)
}

/// Requires one file to retain an expected uppercase SHA-256 digest.
///
/// # Errors
///
/// Returns an error when the file cannot be hashed or its bytes differ from `expected`.
fn verify_sha256(path: &Path, expected: &str, description: &str) -> TaskResult<()> {
    let actual = sha256_file(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{description} changed: expected SHA-256 {expected}, found {actual}"
        ))
        .into())
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
    sha256_bytes(&fs::read(path)?)
}

/// Formats the SHA-256 digest of already-owned bytes without reopening a file.
///
/// # Errors
///
/// Returns an error only when hexadecimal formatting fails.
fn sha256_bytes(bytes: &[u8]) -> TaskResult<String> {
    let digest = Sha256::digest(bytes);
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

/// Executes one child process and returns captured output only for a successful status.
///
/// # Errors
///
/// Returns an error when the child cannot start or exits unsuccessfully, including captured
/// diagnostics in the latter case.
fn run_checked_output(mut command: Command, description: &str) -> TaskResult<Output> {
    let output = command.output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(io::Error::other(format!(
            "{description} failed with {}: stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim(),
        ))
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactIdentity, Sha256, Task, TaskResult, UNVERIFIED_ARTIFACT_ID, WindowsKitVersion,
        comma_separated_blocks, copy_exact_bytes, hash_source_record, jbd2_control_checksum,
        normalize_debugfs_commit_timestamp, normalize_debugfs_descriptor,
        normalized_manifest_value, padded_volume_label, parse_journal_fixture_manifest_text,
        read_be_u32, required_version_line,
    };
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

    /// Windows Kit ordering is numeric and rejects noncanonical or partial directory names.
    ///
    /// # Panics
    ///
    /// Panics if lexical version traps order incorrectly or malformed names are accepted.
    #[test]
    fn windows_kit_version_parsing_preserves_numeric_tool_order() {
        let older = WindowsKitVersion::parse("10.0.9999.0");
        let newer = WindowsKitVersion::parse("10.0.10000.0");
        assert!(older.is_some());
        assert!(newer.is_some());
        assert!(newer > older);
        assert_eq!(WindowsKitVersion::parse("10.0.28000"), None);
        assert_eq!(WindowsKitVersion::parse("10.0.28000.0.preview"), None);
        assert_eq!(WindowsKitVersion::parse("10.0.x.0"), None);
    }

    /// Only the five documented, semantically distinct workflows are accepted.
    ///
    /// # Panics
    ///
    /// Panics if the parser accepts an ambiguous name or rejects a documented name.
    #[test]
    fn task_parser_rejects_ambiguous_commands() {
        assert_eq!(
            Task::parse(OsStr::new("verify-portable")),
            Some(Task::Portable)
        );
        assert_eq!(Task::parse(OsStr::new("verify-driver")), Some(Task::Driver));
        assert_eq!(
            Task::parse(OsStr::new("verify-journal-interop")),
            Some(Task::JournalInterop)
        );
        assert_eq!(
            Task::parse(OsStr::new("verify-journal-fixture-provenance")),
            Some(Task::JournalFixtureProvenance)
        );
        assert_eq!(
            Task::parse(OsStr::new("verify-production-driver")),
            Some(Task::ProductionDriver)
        );
        assert_eq!(Task::parse(OsStr::new("verify")), None);
    }

    /// Production manifest fields preserve tool identity without admitting record injection.
    ///
    /// # Panics
    ///
    /// Panics if line boundaries survive normalization or required version fields are ambiguous.
    #[test]
    fn production_manifest_values_have_one_record_boundary() {
        assert_eq!(normalized_manifest_value("one\r\ntwo\n"), "one | two");
        let report = "release: 1.91.0-nightly\nLLVM version: 21.1.0\n";
        assert_eq!(
            required_version_line(report, "release:").ok(),
            Some("1.91.0-nightly")
        );
        assert_eq!(
            required_version_line(report, "LLVM version:").ok(),
            Some("21.1.0")
        );
        assert!(required_version_line(report, "host:").is_err());
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

    /// The provenance grammar accepts exactly the three promised profiles and rejects path escape.
    ///
    /// # Panics
    ///
    /// Panics if a valid manifest is rejected or an unsafe fixture path is accepted.
    #[test]
    fn journal_manifest_parser_owns_profile_and_path_validation() {
        let manifest = fixture_manifest("external-1k-v2-32.filesystem.img");
        let parsed = parse_journal_fixture_manifest_text(&manifest);
        assert!(
            parsed.is_ok(),
            "valid fixture manifest must parse: {parsed:?}"
        );
        let Some(parsed) = parsed.ok() else {
            return;
        };
        assert_eq!(parsed.e2fsprogs_version, "1.47.1");
        assert_eq!(parsed.fake_time, 1_700_000_000);
        assert_eq!(parsed.fixtures.len(), 3);

        let escaped = fixture_manifest("../external-1k-v2-32.filesystem.img");
        assert!(parse_journal_fixture_manifest_text(&escaped).is_err());
    }

    /// Ordered block lists retain discontinuities while compacting adjacent runs.
    ///
    /// # Panics
    ///
    /// Panics if serialization changes debugfs block-list semantics.
    #[test]
    fn debugfs_block_range_serialization_preserves_ordered_runs() {
        let serialized = comma_separated_blocks(&[4, 5, 6, 9, 11, 12]);
        assert!(serialized.is_ok(), "ordered block list must serialize");
        assert_eq!(serialized.ok().as_deref(), Some("4-6,9,11-12"));
        assert!(comma_separated_blocks(&[]).is_err());
    }

    /// Volume-label boundary conversion accepts every representable width and rejects overflow.
    ///
    /// # Panics
    ///
    /// Panics if a short label is rejected, padding is nonzero, or a 17-byte label is accepted.
    #[test]
    fn fault_matrix_volume_label_padding_has_exact_ext4_width() {
        assert_eq!(
            padded_volume_label(b"FAULT-JBD2").ok(),
            Some(*b"FAULT-JBD2\0\0\0\0\0\0")
        );
        assert_eq!(
            padded_volume_label(b"0123456789ABCDEF").ok(),
            Some(*b"0123456789ABCDEF")
        );
        assert!(padded_volume_label(b"0123456789ABCDEFG").is_err());
    }

    /// Known debugfs descriptor residue is canonicalized without relaxing production parsing.
    ///
    /// # Panics
    ///
    /// Panics if UUID placement, unused high-word cleanup, or checksum refresh regresses.
    #[test]
    fn debugfs_descriptor_normalizer_accepts_only_recognized_residue() {
        let result = (|| -> TaskResult<()> {
            const BLOCK_BYTES: usize = 1024;
            const TAG_OFFSET: usize = 12;
            const TAIL_OFFSET: usize = BLOCK_BYTES - 4;
            let uuid = [
                0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED,
                0xFE, 0x0F,
            ];
            let mut block = vec![0_u8; BLOCK_BYTES];
            write_test_bytes(&mut block, TAG_OFFSET, &41_u32.to_be_bytes())?;
            write_test_bytes(&mut block, TAG_OFFSET + 4, &8_u32.to_be_bytes())?;
            let residue = uuid
                .get(8..12)
                .ok_or_else(|| std::io::Error::other("UUID residue range is absent"))?;
            write_test_bytes(&mut block, TAG_OFFSET + 8, residue)?;
            write_test_bytes(&mut block, TAG_OFFSET + 12, &0x1122_3344_u32.to_be_bytes())?;
            let checksum = jbd2_control_checksum(uuid, &block, TAIL_OFFSET)?;
            write_test_bytes(&mut block, TAIL_OFFSET, &checksum.to_be_bytes())?;

            let (count, changed) = normalize_debugfs_descriptor(&mut block, uuid, 16, true, false)?;
            assert_eq!(count, 1);
            assert!(changed);
            assert_eq!(
                block.get(TAG_OFFSET + 8..TAG_OFFSET + 12),
                Some([0_u8; 4].as_slice())
            );
            assert_eq!(
                block.get(TAG_OFFSET + 16..TAG_OFFSET + 32),
                Some(uuid.as_slice())
            );
            assert_eq!(
                read_be_u32(&block, TAIL_OFFSET)?,
                jbd2_control_checksum(uuid, &block, TAIL_OFFSET)?
            );
            Ok(())
        })();
        assert!(
            result.is_ok(),
            "descriptor normalization failed: {result:?}"
        );
    }

    /// Fixture commit timestamps are canonicalized only after their source checksum validates.
    ///
    /// # Panics
    ///
    /// Panics if deterministic timestamp encoding or commit checksum refresh regresses.
    #[test]
    fn debugfs_commit_normalizer_rechecks_and_refreshes_checksum() {
        let result = (|| -> TaskResult<()> {
            const CHECKSUM_OFFSET: usize = 0x10;
            let uuid = [0xA5_u8; 16];
            let mut block = vec![0_u8; 1024];
            write_test_bytes(&mut block, 0x30, &99_u64.to_be_bytes())?;
            write_test_bytes(&mut block, 0x38, &123_u32.to_be_bytes())?;
            let checksum = jbd2_control_checksum(uuid, &block, CHECKSUM_OFFSET)?;
            write_test_bytes(&mut block, CHECKSUM_OFFSET, &checksum.to_be_bytes())?;

            normalize_debugfs_commit_timestamp(&mut block, uuid, 1_700_000_000)?;
            assert_eq!(
                block.get(0x30..0x38),
                Some(1_700_000_000_u64.to_be_bytes().as_slice())
            );
            assert_eq!(block.get(0x38..0x3C), Some([0_u8; 4].as_slice()));
            assert_eq!(
                read_be_u32(&block, CHECKSUM_OFFSET)?,
                jbd2_control_checksum(uuid, &block, CHECKSUM_OFFSET)?
            );

            *block
                .get_mut(0)
                .ok_or_else(|| std::io::Error::other("empty commit block"))? ^= 1;
            assert!(normalize_debugfs_commit_timestamp(&mut block, uuid, 2).is_err());
            Ok(())
        })();
        assert!(result.is_ok(), "commit normalization failed: {result:?}");
    }

    /// Returns the digest of one normalized source record.
    fn record_digest(path: &str, contents: Option<&[u8]>) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hash_source_record(&mut hasher, path, contents);
        hasher.finalize().into()
    }

    /// Returns one complete strict manifest while allowing its first filesystem path to vary.
    fn fixture_manifest(first_filesystem: &str) -> String {
        let digest = "0".repeat(64);
        format!(
            "e2fsprogs 1.47.1\n\
             fake-time 1700000000\n\
             fixture external-1k-v2-32 1024 2 32 10000 11111111-1111-4111-8111-111111111111 {first_filesystem} {digest} aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa external-1k-v2-32.journal.img {digest}\n\
             fixture external-2k-v3-64 2048 3 64 27 22222222-2222-4222-8222-222222222222 external-2k-v3-64.filesystem.img {digest} bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb external-2k-v3-64.journal.img {digest}\n\
             fixture external-4k-v3-64 4096 3 64 9 33333333-3333-4333-8333-333333333333 external-4k-v3-64.filesystem.img {digest} cccccccc-cccc-4ccc-8ccc-cccccccccccc external-4k-v3-64.journal.img {digest}\n"
        )
    }

    /// Writes one private test wire field with production-equivalent range and length checks.
    ///
    /// # Errors
    ///
    /// Returns an error for offset overflow, a truncated destination, or a length mismatch.
    fn write_test_bytes(block: &mut [u8], offset: usize, bytes: &[u8]) -> TaskResult<()> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("test wire offset overflow"))?;
        let destination = block
            .get_mut(offset..end)
            .ok_or_else(|| std::io::Error::other("test wire field is truncated"))?;
        copy_exact_bytes(destination, bytes)
    }
}
