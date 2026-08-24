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
    process::{self, Command, ExitCode, Output, Stdio},
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
    /// Exercises bounded HTree reads and local updates against fresh ext4 images.
    HtreeInterop,
    /// Reproduces tracked external-journal fixtures under the pinned Linux toolchain.
    JournalFixtureProvenance,
    /// Builds and verifies one signed, identity-bound Windows driver bundle.
    ProductionDriver,
    /// Performs read-only validation of a dedicated live-driver host.
    CheckLiveDriverHost,
    /// Builds a verified bundle and exercises it only against a new disposable VHDX.
    VerifyLiveVhdx,
    /// Reconciles and removes one interrupted disposable VHDX session.
    CleanupLiveVhdxSession,
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
        } else if argument == "verify-htree-interop" {
            Some(Self::HtreeInterop)
        } else if argument == "verify-journal-fixture-provenance" {
            Some(Self::JournalFixtureProvenance)
        } else if argument == "verify-production-driver" {
            Some(Self::ProductionDriver)
        } else if argument == "check-live-driver-host" {
            Some(Self::CheckLiveDriverHost)
        } else if argument == "verify-live-vhdx" {
            Some(Self::VerifyLiveVhdx)
        } else if argument == "cleanup-live-vhdx-session" {
            Some(Self::CleanupLiveVhdxSession)
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

/// Deterministic Linux executable search path used for direct WSL execution.
///
/// `wsl.exe --exec` does not execute through an interactive/login shell and
/// therefore must not rely on the distribution's shell initialization to add
/// administrative directories such as `/usr/sbin`.
///
/// e2fsprogs utilities including `mke2fs`, `debugfs`, and `e2fsck` are normally
/// installed below `/usr/sbin` on Ubuntu.
const WSL_TOOL_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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
                "ext4 interoperability requires Linux or an installed WSL distribution",
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
    ///
    /// WSL execution uses `/usr/bin/env` with one deterministic Linux PATH
    /// rather than relying on the non-login environment inherited by
    /// `wsl.exe --exec`.
    fn command(self, program: &str) -> Command {
        match self {
            Self::Native => Command::new(program),

            Self::Wsl => {
                let mut command = Command::new("wsl.exe");

                command
                    .args(["--exec", "/usr/bin/env"])
                    .arg(format!("PATH={WSL_TOOL_PATH}"))
                    .arg(program);

                command
            }
        }
    }

    /// Builds one Linux command with an environment variable visible in the Linux process.
    ///
    /// A Windows environment override on `wsl.exe` is not forwarded into the distribution unless
    /// `WSLENV` is configured. Routing through `/usr/bin/env` keeps fixture generation independent
    /// of the caller's global WSL configuration while avoiding shell interpretation.
    ///
    /// The deterministic PATH also ensures programs located in `/usr/sbin` can be executed when
    /// WSL is entered through `wsl.exe --exec`.
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
                    .args(["--exec", "/usr/bin/env"])
                    .arg(format!("PATH={WSL_TOOL_PATH}"))
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
                .ok_or_else(|| io::Error::other("ext4 gate path is not UTF-8").into()),

            Self::Wsl => {
                let mut command = Command::new("wsl.exe");

                //
                // Use an absolute path here as well so path conversion does
                // not depend on the environment supplied by wsl.exe.
                //
                command.args(["--exec", "/usr/bin/wslpath", "-a"]).arg(path);

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

/// Host-side storage behavior required by the production core state machines.
trait HostStorage {
    /// Returns the selected device length.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is unavailable or its metadata cannot be read.
    fn length(&self, target: ext4_core::StorageTarget) -> TaskResult<u64>;
    /// Reads one exact range from the selected volatile image.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is unavailable or the exact range cannot be read.
    fn read_exact(
        &mut self,
        target: ext4_core::StorageTarget,
        offset: u64,
        output: &mut [u8],
    ) -> TaskResult<()>;
    /// Applies one complete write to the selected volatile image.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is unavailable or the complete range cannot be written.
    fn write_all(
        &mut self,
        target: ext4_core::StorageTarget,
        offset: u64,
        input: &[u8],
    ) -> TaskResult<()>;
    /// Makes only the selected device's volatile image durable.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is unavailable or cannot reach host durability.
    fn flush(&mut self, target: ext4_core::StorageTarget) -> TaskResult<()>;
}

/// Direct host-file implementation used by ordinary interoperability execution.
#[derive(Debug)]
struct FileStorageAdapter {
    /// Primary filesystem image.
    filesystem: File,
    /// External journal image when the mounted profile requires one.
    external_journal: Option<File>,
}

/// One write completed against a volatile crash-model device since its last flush.
#[derive(Debug)]
struct PendingCrashWrite {
    /// Device-relative byte offset.
    offset: u64,
    /// Complete write payload retained for sector-prefix materialization.
    bytes: Vec<u8>,
}

/// Independent volatile/durable state for one crash-model device.
#[derive(Debug)]
struct CrashDeviceImage {
    /// Caller-visible image used by core reads and volatile writes.
    volatile: File,
    /// Last state made durable by a successful flush.
    durable: Vec<u8>,
    /// Ordered writes accepted after the last successful device-local flush.
    pending: Vec<PendingCrashWrite>,
}

/// Fault adapter keeping filesystem and external journal durability independent.
#[derive(Debug)]
struct CrashStorageAdapter {
    /// Primary filesystem device state.
    filesystem: CrashDeviceImage,
    /// Dedicated external journal device state when selected by the mounted profile.
    external_journal: Option<CrashDeviceImage>,
}

/// Shape of one completed write or flush in a production workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageEffect {
    /// One volatile write whose crash persistence is selectable at 512-byte boundaries.
    Write {
        /// Device receiving the write.
        target: ext4_core::StorageTarget,
        /// Complete write byte length.
        bytes: usize,
    },
    /// One successful flush affecting only its selected device.
    Flush {
        /// Device made durable.
        target: ext4_core::StorageTarget,
    },
}

/// Exact crash boundary selected from a previously probed storage-effect trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectCut {
    /// One-based effect index.
    effect: usize,
    /// Persisted byte prefix for a write, or `None` for a completed flush.
    write_prefix: Option<usize>,
}

/// Progress of one production workflow stopped only after a selected write or flush effect.
#[derive(Debug, Eq, PartialEq)]
struct EffectBoundaryRun {
    /// Number of write/flush requests completed by this execution.
    completed_effects: usize,
    /// Whether the workflow reached its semantic terminal state instead of simulating a crash.
    completed: bool,
    /// Exact ordered effect shapes observed before termination.
    effects: Vec<StorageEffect>,
}

/// Counts production durability effects and withholds the completion that crosses a selected
/// crash boundary.
#[derive(Debug)]
struct EffectBoundaryController {
    /// Selected write-prefix or completed-flush crash boundary.
    cut: Option<EffectCut>,
    /// Write/flush completions already applied to the host image.
    completed_effects: usize,
    /// Ordered effect trace used to enumerate every subsequent crash run.
    effects: Vec<StorageEffect>,
}

impl EffectBoundaryController {
    /// Creates one full execution or a crash execution stopped after an exact effect count.
    ///
    /// # Errors
    ///
    /// Returns an error when zero is supplied even though effect boundaries are one-based.
    fn new(cut: Option<EffectCut>) -> TaskResult<Self> {
        if cut.is_some_and(|cut| cut.effect == 0) {
            return Err(io::Error::other("effect boundary zero is invalid").into());
        }
        Ok(Self {
            cut,
            completed_effects: 0,
            effects: Vec::new(),
        })
    }

    /// Executes one request and returns no completion when its durable effect is the selected
    /// simulated-crash boundary.
    ///
    /// A write cut persists the selected 512-byte prefix plus earlier writes on that device. A
    /// flush cut persists only the selected device. The remount must therefore accept both the
    /// old and new semantic state without relying on volatile operation state.
    ///
    /// # Errors
    ///
    /// Returns an error for request I/O, effect-count overflow, or host durability failure.
    fn complete(
        &mut self,
        storage: &mut CrashStorageAdapter,
        request: ext4_core::StorageRequest,
    ) -> TaskResult<Option<ext4_core::StorageCompletion>> {
        let effect = match &request {
            ext4_core::StorageRequest::Read { .. } => None,
            ext4_core::StorageRequest::Write { target, buffer, .. } => Some(StorageEffect::Write {
                target: *target,
                bytes: buffer.len(),
            }),
            ext4_core::StorageRequest::Flush { target } => {
                Some(StorageEffect::Flush { target: *target })
            }
        };
        let completion = complete_file_request(storage, request)?;
        if let Some(effect) = effect {
            self.completed_effects = self
                .completed_effects
                .checked_add(1)
                .ok_or_else(|| io::Error::other("effect boundary count overflow"))?;
            self.effects.push(effect);
            if self
                .cut
                .is_some_and(|cut| cut.effect == self.completed_effects)
            {
                let cut = self
                    .cut
                    .ok_or_else(|| io::Error::other("selected effect cut disappeared"))?;
                match (effect, cut.write_prefix) {
                    (StorageEffect::Write { target, bytes }, Some(prefix)) => {
                        if prefix > bytes || prefix % 512 != 0 {
                            return Err(io::Error::other(
                                "write crash prefix is outside a 512-byte sector boundary",
                            )
                            .into());
                        }
                        storage.materialize_write_prefix(target, prefix)?;
                    }
                    (StorageEffect::Flush { .. }, None) => storage.materialize_durable()?,
                    (StorageEffect::Write { .. }, None)
                    | (StorageEffect::Flush { .. }, Some(_)) => {
                        return Err(io::Error::other(
                            "effect cut persistence does not match its request kind",
                        )
                        .into());
                    }
                }
                return Ok(None);
            }
        }
        Ok(Some(completion))
    }

    /// Reports a simulated crash after the selected completion.
    fn stopped(self) -> EffectBoundaryRun {
        EffectBoundaryRun {
            completed_effects: self.completed_effects,
            completed: false,
            effects: self.effects,
        }
    }

    /// Reports normal completion of the production workflow.
    fn completed(self) -> EffectBoundaryRun {
        EffectBoundaryRun {
            completed_effects: self.completed_effects,
            completed: true,
            effects: self.effects,
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

    /// Returns one routed immutable host file or rejects an unavailable external target.
    /// # Errors
    ///
    /// Returns an error when an internal-only adapter receives an external-journal request.
    fn target(&self, target: ext4_core::StorageTarget) -> TaskResult<&File> {
        match target {
            ext4_core::StorageTarget::Filesystem => Ok(&self.filesystem),
            ext4_core::StorageTarget::ExternalJournal => self
                .external_journal
                .as_ref()
                .ok_or_else(|| io::Error::other("unexpected external-journal request").into()),
        }
    }
}

impl HostStorage for FileStorageAdapter {
    fn length(&self, target: ext4_core::StorageTarget) -> TaskResult<u64> {
        Ok(self.target(target)?.metadata()?.len())
    }

    fn read_exact(
        &mut self,
        target: ext4_core::StorageTarget,
        offset: u64,
        output: &mut [u8],
    ) -> TaskResult<()> {
        let file = self.target_mut(target)?;
        file.seek(io::SeekFrom::Start(offset))?;
        file.read_exact(output)?;
        Ok(())
    }

    fn write_all(
        &mut self,
        target: ext4_core::StorageTarget,
        offset: u64,
        input: &[u8],
    ) -> TaskResult<()> {
        let file = self.target_mut(target)?;
        file.seek(io::SeekFrom::Start(offset))?;
        file.write_all(input)?;
        Ok(())
    }

    fn flush(&mut self, target: ext4_core::StorageTarget) -> TaskResult<()> {
        self.target_mut(target)?.sync_all()?;
        Ok(())
    }
}

impl CrashDeviceImage {
    /// Opens one volatile image and snapshots its initial durable bytes.
    /// # Errors
    ///
    /// Returns an error when the image cannot be read or opened read/write.
    fn open(path: &Path) -> TaskResult<Self> {
        Ok(Self {
            volatile: OpenOptions::new().read(true).write(true).open(path)?,
            durable: fs::read(path)?,
            pending: Vec::new(),
        })
    }

    /// Copies the volatile device state into its durable image after a successful flush.
    /// # Errors
    ///
    /// Returns an error when host synchronization or image reading fails.
    fn flush(&mut self) -> TaskResult<()> {
        self.volatile.sync_all()?;
        self.volatile.seek(io::SeekFrom::Start(0))?;
        self.durable.clear();
        self.volatile.read_to_end(&mut self.durable)?;
        self.pending.clear();
        Ok(())
    }

    /// Replaces the caller-visible image with durable bytes and an optional pending-write prefix.
    /// # Errors
    ///
    /// Returns an error for invalid ranges or host image I/O failure.
    fn materialize(&mut self, write_prefix: Option<usize>) -> TaskResult<()> {
        let durable_len = u64::try_from(self.durable.len())?;
        self.volatile.set_len(durable_len)?;
        self.volatile.seek(io::SeekFrom::Start(0))?;
        self.volatile.write_all(&self.durable)?;
        if let Some(prefix) = write_prefix {
            let Some((selected, prior)) = self.pending.split_last() else {
                return Err(io::Error::other("write cut has no pending device write").into());
            };
            for write in prior {
                write_host_range(&mut self.volatile, write.offset, &write.bytes)?;
            }
            let bytes = selected
                .bytes
                .get(..prefix)
                .ok_or_else(|| io::Error::other("write cut prefix exceeds its payload"))?;
            write_host_range(&mut self.volatile, selected.offset, bytes)?;
        }
        self.volatile.sync_all()?;
        Ok(())
    }
}

impl CrashStorageAdapter {
    /// Opens one internally journaled device image for a fault run.
    /// # Errors
    ///
    /// Returns an error when the filesystem image cannot be opened or snapshotted.
    fn open_internal(filesystem: &Path) -> TaskResult<Self> {
        Ok(Self {
            filesystem: CrashDeviceImage::open(filesystem)?,
            external_journal: None,
        })
    }

    /// Opens two independently durable device images for one external-journal fault run.
    /// # Errors
    ///
    /// Returns an error when either image cannot be opened or snapshotted.
    fn open_external(filesystem: &Path, external_journal: &Path) -> TaskResult<Self> {
        Ok(Self {
            filesystem: CrashDeviceImage::open(filesystem)?,
            external_journal: Some(CrashDeviceImage::open(external_journal)?),
        })
    }

    /// Returns the selected crash-model device.
    /// # Errors
    ///
    /// Returns an error when an internal-journal run receives an external-journal request.
    fn target(&self, target: ext4_core::StorageTarget) -> TaskResult<&CrashDeviceImage> {
        match target {
            ext4_core::StorageTarget::Filesystem => Ok(&self.filesystem),
            ext4_core::StorageTarget::ExternalJournal => self
                .external_journal
                .as_ref()
                .ok_or_else(|| io::Error::other("unexpected external-journal request").into()),
        }
    }

    /// Returns the uniquely borrowed selected crash-model device.
    /// # Errors
    ///
    /// Returns an error when an internal-journal run receives an external-journal request.
    fn target_mut(
        &mut self,
        target: ext4_core::StorageTarget,
    ) -> TaskResult<&mut CrashDeviceImage> {
        match target {
            ext4_core::StorageTarget::Filesystem => Ok(&mut self.filesystem),
            ext4_core::StorageTarget::ExternalJournal => self
                .external_journal
                .as_mut()
                .ok_or_else(|| io::Error::other("unexpected external-journal request").into()),
        }
    }

    /// Materializes only durable bytes for both independently flushed devices.
    /// # Errors
    ///
    /// Returns an error when either caller-visible image cannot be replaced and synchronized.
    fn materialize_durable(&mut self) -> TaskResult<()> {
        self.filesystem.materialize(None)?;
        if let Some(journal) = self.external_journal.as_mut() {
            journal.materialize(None)?;
        }
        Ok(())
    }

    /// Materializes a sector prefix on one device while losing all volatile writes on the other.
    /// # Errors
    ///
    /// Returns an error when the selected pending write or host image range is invalid.
    fn materialize_write_prefix(
        &mut self,
        target: ext4_core::StorageTarget,
        prefix: usize,
    ) -> TaskResult<()> {
        match target {
            ext4_core::StorageTarget::Filesystem => {
                self.filesystem.materialize(Some(prefix))?;
                if let Some(journal) = self.external_journal.as_mut() {
                    journal.materialize(None)?;
                }
            }
            ext4_core::StorageTarget::ExternalJournal => {
                self.filesystem.materialize(None)?;
                self.external_journal
                    .as_mut()
                    .ok_or_else(|| io::Error::other("unexpected external-journal write cut"))?
                    .materialize(Some(prefix))?;
            }
        }
        Ok(())
    }
}

impl HostStorage for CrashStorageAdapter {
    fn length(&self, target: ext4_core::StorageTarget) -> TaskResult<u64> {
        Ok(self.target(target)?.volatile.metadata()?.len())
    }

    fn read_exact(
        &mut self,
        target: ext4_core::StorageTarget,
        offset: u64,
        output: &mut [u8],
    ) -> TaskResult<()> {
        let file = &mut self.target_mut(target)?.volatile;
        file.seek(io::SeekFrom::Start(offset))?;
        file.read_exact(output)?;
        Ok(())
    }

    fn write_all(
        &mut self,
        target: ext4_core::StorageTarget,
        offset: u64,
        input: &[u8],
    ) -> TaskResult<()> {
        let device = self.target_mut(target)?;
        write_host_range(&mut device.volatile, offset, input)?;
        device.pending.push(PendingCrashWrite {
            offset,
            bytes: input.to_vec(),
        });
        Ok(())
    }

    fn flush(&mut self, target: ext4_core::StorageTarget) -> TaskResult<()> {
        self.target_mut(target)?.flush()
    }
}

/// Writes one exact host-file range without changing bytes outside the supplied slice.
/// # Errors
///
/// Returns an error when seeking or writing the selected range fails.
fn write_host_range(file: &mut File, offset: u64, bytes: &[u8]) -> TaskResult<()> {
    file.seek(io::SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    Ok(())
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
    let task_argument = arguments.next();
    if arguments.next().is_some() {
        return Err(usage_error().into());
    }

    let repository_root = repository_root()?;
    match task {
        Task::CleanupLiveVhdxSession => {
            let session_id = task_argument.as_deref().ok_or_else(usage_error)?;
            cleanup_live_vhdx_session(&repository_root, session_id)
        }
        Task::Portable
        | Task::Driver
        | Task::JournalInterop
        | Task::HtreeInterop
        | Task::JournalFixtureProvenance
        | Task::ProductionDriver
        | Task::CheckLiveDriverHost
        | Task::VerifyLiveVhdx => {
            if task_argument.is_some() {
                return Err(usage_error().into());
            }
            match task {
                Task::Portable => verify_portable(&repository_root),
                Task::Driver => verify_driver(&repository_root),
                Task::JournalInterop => verify_journal_interop(&repository_root),
                Task::HtreeInterop => verify_htree_interop(&repository_root),
                Task::JournalFixtureProvenance => {
                    verify_journal_fixture_provenance(&repository_root)
                }
                Task::ProductionDriver => verify_production_driver(&repository_root),
                Task::CheckLiveDriverHost => check_live_driver_host(&repository_root),
                Task::VerifyLiveVhdx => verify_live_vhdx(&repository_root),
                Task::CleanupLiveVhdxSession => {
                    Err(io::Error::other("cleanup task lost its required argument").into())
                }
            }
        }
    }
}

/// Returns the stable command-line contract.
fn usage_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: cargo xtask <verify-portable|verify-driver|verify-journal-interop|verify-htree-interop|verify-journal-fixture-provenance|verify-production-driver|check-live-driver-host|verify-live-vhdx|cleanup-live-vhdx-session SESSION_ID>",
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

/// Performs read-only validation of the dedicated live-driver host contract.
///
/// # Errors
///
/// Returns an error on non-Windows hosts or when elevation, Hyper-V PowerShell, WSL,
/// e2fsprogs, Driver Verifier configuration, or clean ext4win service/package state is absent.
fn check_live_driver_host(repository_root: &Path) -> TaskResult<()> {
    require_windows_live_host()?;
    run_live_vhdx_script(repository_root, "Preflight", None, None)
}

/// Builds one verified production bundle and exercises it only on a new fixed-size VHDX.
///
/// # Errors
///
/// Returns an error for host-contract, release-gate, session-recording, VHDX, WSL, DriverStore,
/// driver operation, dismount, unload, or cleanup failure.
fn verify_live_vhdx(repository_root: &Path) -> TaskResult<()> {
    check_live_driver_host(repository_root)?;
    let bundle = build_verified_production_bundle(repository_root)?;
    let session_id = ArtifactIdentity::create(repository_root)?;
    run_live_vhdx_script(
        repository_root,
        "Run",
        Some(bundle.as_path()),
        Some(session_id.as_str()),
    )?;
    println!("live VHDX driver assurance: PASS");
    println!("session: {}", session_id.as_str());
    Ok(())
}

/// Reconciles an interrupted session after validating its generated identity boundary.
///
/// # Errors
///
/// Returns an error for a malformed identifier, missing or mismatched session evidence, or any
/// unload, package removal, VHDX detach, or cleanup failure.
fn cleanup_live_vhdx_session(repository_root: &Path, session_id: &OsStr) -> TaskResult<()> {
    require_windows_live_host()?;
    let session_id = session_id
        .to_str()
        .filter(|value| {
            value.len() == UNVERIFIED_ARTIFACT_ID.len()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| {
            io::Error::other("session id must be exactly 32 lowercase hexadecimal digits")
        })?;
    run_live_vhdx_script(repository_root, "Cleanup", None, Some(session_id))
}

/// Rejects live workflows outside the Windows host boundary.
///
/// # Errors
///
/// Returns `Unsupported` on non-Windows hosts.
fn require_windows_live_host() -> TaskResult<()> {
    if cfg!(target_os = "windows") {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "live VHDX validation requires a dedicated elevated Windows host",
        )
        .into())
    }
}

/// Invokes the repository-owned live VHDX script with only generated bundle/session identities.
///
/// # Errors
///
/// Returns an error when the script is absent, PowerShell cannot start, or the requested workflow
/// fails closed.
fn run_live_vhdx_script(
    repository_root: &Path,
    mode: &str,
    bundle: Option<&Path>,
    session_id: Option<&str>,
) -> TaskResult<()> {
    let script = repository_root
        .join("tools")
        .join("xtask")
        .join("live-vhdx.ps1");
    require_file(&script, "live VHDX workflow script")?;
    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ]);
    command
        .arg(script)
        .arg("-Mode")
        .arg(mode)
        .arg("-RepositoryRoot")
        .arg(repository_root);
    if let Some(bundle) = bundle {
        command.arg("-Bundle").arg(bundle);
    }
    if let Some(session_id) = session_id {
        command.arg("-SessionId").arg(session_id);
    }
    run_checked(command, &format!("live VHDX {mode} workflow"))
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
        verify_internal_mutation_profiles(linux, &temporary_root)?;
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

/// Independently observed free-space counters from a debugfs superblock projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DebugfsFreeSpace {
    /// Free filesystem blocks, in filesystem block units.
    blocks: u64,
    /// Free inode records.
    inodes: u64,
}

/// Generates fresh 4 KiB and BIGALLOC images, mutates them through ext4-core, and validates each
/// final state with debugfs and e2fsck.
///
/// # Errors
///
/// Returns an error for image generation, production mutation failure, independent-oracle
/// mismatch, accounting drift, or e2fsck rejection.
fn verify_internal_mutation_profiles(
    linux: LinuxEnvironment,
    temporary_root: &Path,
) -> TaskResult<()> {
    let regular_root = temporary_root.join("mutation-4k");
    fs::create_dir(&regular_root)?;
    let regular_image = regular_root.join("filesystem.img");
    format_mutation_image(linux, &regular_image, None)?;
    verify_regular_mutation_profile(linux, &regular_root, &regular_image)?;

    let bigalloc_root = temporary_root.join("mutation-bigalloc-16k");
    fs::create_dir(&bigalloc_root)?;
    let bigalloc_image = bigalloc_root.join("filesystem.img");
    format_mutation_image(linux, &bigalloc_image, Some(16_384))?;
    verify_bigalloc_mutation_profile(linux, &bigalloc_root, &bigalloc_image)?;

    println!("ext4-core fresh-image mutation profiles: PASS");
    Ok(())
}

/// Exercises the HTree read and mutation contract against independently formatted images.
///
/// # Errors
///
/// Returns an error when Linux filesystem tools are unavailable, a profile fails, or temporary
/// artifact cleanup cannot complete.
fn verify_htree_interop(repository_root: &Path) -> TaskResult<()> {
    let linux = LinuxEnvironment::require()?;
    let temporary_root = create_task_directory(repository_root, "htree-interop")?;
    let verification = (|| -> TaskResult<()> {
        verify_large_directory_depth_two(linux, &temporary_root)?;
        for block_size in [1_024_u32, 4_096] {
            for metadata_checksum in [false, true] {
                for large_directory in [false, true] {
                    verify_htree_mutation_profile(
                        linux,
                        &temporary_root,
                        block_size,
                        metadata_checksum,
                        large_directory,
                    )?;
                }
            }
        }
        verify_htree_fault_matrix(linux, &temporary_root)?;
        Ok(())
    })();
    let cleanup = remove_task_directory(repository_root, &temporary_root, "htree-interop");
    combine_verification_and_cleanup(verification, cleanup)?;
    println!("ext4-core HTree interoperability profiles: PASS");
    Ok(())
}

/// Number of maximum-length names committed atomically by the HTree fault workflow.
const HTREE_FAULT_ENTRY_COUNT: usize = 5;
/// Maximum recovered images checked by one external-oracle process.
const HTREE_FAULT_ORACLE_BATCH: usize = 8;

/// One recovered HTree crash image awaiting independent black-box validation.
#[derive(Debug)]
struct HtreeFaultOracleCase {
    /// Stable cut label used in diagnostics.
    label: String,
    /// Recovered and cleanly closed filesystem image.
    image: PathBuf,
}

/// Exercises every sector/flush crash cut of a transaction that converts and splits a directory.
///
/// # Errors
///
/// Returns an error when probe/cut execution, crash recovery, namespace endpoint validation,
/// independent filesystem validation, or task-owned artifact handling fails.
fn verify_htree_fault_matrix(linux: LinuxEnvironment, temporary_root: &Path) -> TaskResult<()> {
    const BLOCK_SIZE: u32 = 1_024;

    let matrix_root = temporary_root.join("fault-matrix");
    fs::create_dir(&matrix_root)?;
    let baseline = matrix_root.join("baseline.img");
    format_htree_image(
        linux,
        &baseline,
        16 * 1024 * 1024,
        BLOCK_SIZE,
        true,
        false,
        1,
    )?;

    let probe = matrix_root.join("probe.img");
    fs::copy(&baseline, &probe)?;
    let probe_run = run_internal_htree_mutation_until_boundary(&probe, None)?;
    let effects = require_completed_effect_probe("HTree commit/checkpoint", probe_run)?;
    let cuts = enumerate_effect_cuts(&effects)?;
    fs::remove_file(&probe)?;

    let mut batch_start = 0_usize;
    while batch_start < cuts.len() {
        let batch_end = core::cmp::min(
            batch_start
                .checked_add(HTREE_FAULT_ORACLE_BATCH)
                .ok_or_else(|| io::Error::other("HTree fault-oracle batch boundary overflow"))?,
            cuts.len(),
        );
        let cut_batch = cuts
            .get(batch_start..batch_end)
            .ok_or_else(|| io::Error::other("invalid HTree fault-oracle batch range"))?;
        let mut cases = Vec::new();
        cases
            .try_reserve_exact(cut_batch.len())
            .map_err(|_| io::Error::other("HTree fault-oracle batch allocation failed"))?;
        for cut in cut_batch.iter().copied() {
            let label = format!("htree-{}", effect_cut_stem(cut));
            let image = matrix_root.join(format!("{label}.img"));
            fs::copy(&baseline, &image)?;
            let run = run_internal_htree_mutation_until_boundary(&image, Some(cut))?;
            require_stopped_effect("HTree commit/checkpoint", cut, run)?;
            drive_core_mount_and_clean_close(&image)?;
            cases.push(HtreeFaultOracleCase { label, image });
        }
        verify_htree_fault_oracle_batch(linux, &cases)?;
        for case in cases {
            fs::remove_file(case.image)?;
        }
        batch_start = batch_end;
    }

    println!(
        "HTree production fault matrix: PASS ({} sector/flush cuts across {} effects)",
        cuts.len(),
        effects.len()
    );
    Ok(())
}

/// Builds the fixed maximum-length name set used by every HTree fault run and endpoint check.
///
/// # Errors
///
/// Returns an error when name generation, ext4 validation, or bounded vector allocation fails.
fn htree_fault_names() -> TaskResult<Vec<ext4_core::Ext4Name>> {
    let mut names = Vec::new();
    names
        .try_reserve_exact(HTREE_FAULT_ENTRY_COUNT)
        .map_err(|_| io::Error::other("HTree fault-name allocation failed"))?;
    for index in 0..HTREE_FAULT_ENTRY_COUNT {
        let raw = depth_two_profile_name(index)?;
        names.push(ext4_core::Ext4Name::new(raw.as_bytes()).map_err(core_task_error)?);
    }
    Ok(names)
}

/// Requires one recovered fault image to expose the complete old or complete new namespace.
///
/// # Errors
///
/// Returns an error when black-box directory inspection fails, the transaction is partially
/// visible, or the complete new endpoint is not represented as a readable HTree.
fn verify_htree_fault_endpoint(listing: &str, tree_dump: &str, label: &str) -> TaskResult<()> {
    let names = htree_fault_names()?;
    let present = names
        .iter()
        .filter(|name| {
            let marker = format!("/{}/", String::from_utf8_lossy(name.bytes()));
            listing.contains(&marker)
        })
        .count();
    match present {
        0 => Ok(()),
        HTREE_FAULT_ENTRY_COUNT if tree_dump.contains("Root node dump") => Ok(()),
        HTREE_FAULT_ENTRY_COUNT => Err(io::Error::other(format!(
            "{label} exposes the new namespace without a readable HTree root"
        ))
        .into()),
        partial => Err(io::Error::other(format!(
            "{label} exposes a partial HTree transaction ({partial}/{HTREE_FAULT_ENTRY_COUNT})"
        ))
        .into()),
    }
}

/// Runs namespace inspection and read-only fsck for a bounded set of recovered images in one
/// external process, then validates each delimited result independently.
///
/// # Errors
///
/// Returns an error when path conversion, an oracle command, output decoding/delimiting, fsck, or
/// an endpoint invariant fails.
fn verify_htree_fault_oracle_batch(
    linux: LinuxEnvironment,
    cases: &[HtreeFaultOracleCase],
) -> TaskResult<()> {
    if cases.is_empty() || cases.len() > HTREE_FAULT_ORACLE_BATCH {
        return Err(io::Error::other("invalid HTree fault-oracle batch size").into());
    }
    let script = r#"set -eu
i=0
for image do
    printf '\n__EXT4WIN_HTREE_CASE_%s_LISTING__\n' "$i"
    debugfs -R 'ls -p /' "$image" 2>&1
    printf '\n__EXT4WIN_HTREE_CASE_%s_TREE__\n' "$i"
    debugfs -R 'htree_dump /' "$image" 2>&1
    printf '\n__EXT4WIN_HTREE_CASE_%s_FSCK__\n' "$i"
    e2fsck -f -n "$image" 2>&1
    printf '\n__EXT4WIN_HTREE_CASE_%s_END__\n' "$i"
    i=$((i + 1))
done
"#;
    let mut command = linux.command("sh");
    command.args(["-c", script, "ext4win-htree-oracle"]);
    for case in cases {
        command.arg(linux.tool_path(&case.image)?);
    }
    let output = run_checked_output(command, "batched HTree debugfs/e2fsck oracle")?;
    let output = String::from_utf8(output.stdout)?;
    for (index, case) in cases.iter().enumerate() {
        let listing_marker = format!("__EXT4WIN_HTREE_CASE_{index}_LISTING__");
        let tree_marker = format!("__EXT4WIN_HTREE_CASE_{index}_TREE__");
        let fsck_marker = format!("__EXT4WIN_HTREE_CASE_{index}_FSCK__");
        let end_marker = format!("__EXT4WIN_HTREE_CASE_{index}_END__");
        let listing =
            delimited_oracle_section(&output, &listing_marker, &tree_marker, &case.label)?;
        let tree_dump = delimited_oracle_section(&output, &tree_marker, &fsck_marker, &case.label)?;
        let _fsck = delimited_oracle_section(&output, &fsck_marker, &end_marker, &case.label)?;
        verify_htree_fault_endpoint(listing, tree_dump, &case.label)?;
    }
    Ok(())
}

/// Returns one uniquely delimited oracle section.
///
/// # Errors
///
/// Returns an error when either delimiter is missing or reversed.
fn delimited_oracle_section<'output>(
    output: &'output str,
    start: &str,
    end: &str,
    label: &str,
) -> TaskResult<&'output str> {
    let after_start = output
        .split_once(start)
        .map(|(_, suffix)| suffix)
        .ok_or_else(|| io::Error::other(format!("{label} oracle omitted {start}")))?;
    after_start
        .split_once(end)
        .map(|(section, _)| section)
        .ok_or_else(|| io::Error::other(format!("{label} oracle omitted {end}")).into())
}

/// Generates one indexed-directory profile, drives local HTree updates, and validates the result
/// through black-box filesystem tools.
///
/// # Errors
///
/// Returns an error when formatting, batched mutation, bounded enumeration, exact lookup, rename,
/// debugfs inspection, or e2fsck validation fails.
fn verify_htree_mutation_profile(
    linux: LinuxEnvironment,
    temporary_root: &Path,
    block_size: u32,
    metadata_checksum: bool,
    large_directory: bool,
) -> TaskResult<()> {
    const ENTRY_COUNT: usize = 48;
    const MUTATION_BATCH: usize = 24;

    let checksum_label = if metadata_checksum { "csum" } else { "nocsum" };
    let size_label = if large_directory { "large" } else { "standard" };
    let label = format!("htree-{block_size}-{checksum_label}-{size_label}");
    println!("HTree interoperability profile: {label}");
    let case_root = temporary_root.join(&label);
    fs::create_dir(&case_root)?;
    let image = case_root.join("filesystem.img");
    format_htree_image(
        linux,
        &image,
        32 * 1024 * 1024,
        block_size,
        metadata_checksum,
        large_directory,
        8,
    )?;

    for first in (0..ENTRY_COUNT).step_by(MUTATION_BATCH) {
        let end = core::cmp::min(
            first
                .checked_add(MUTATION_BATCH)
                .ok_or_else(|| io::Error::other("HTree mutation batch boundary overflow"))?,
            ENTRY_COUNT,
        );
        drive_internal_core_mutation(&image, |pass| {
            let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
            for index in first..end {
                let name = htree_profile_name(block_size, "entry", index)?;
                pass.create_file(root, &name, mutation_file_metadata()?)?;
            }
            Ok(())
        })?;
    }

    let source =
        htree_profile_name(block_size, "entry", ENTRY_COUNT - 1).map_err(core_task_error)?;
    let renamed =
        htree_profile_name(block_size, "renamed", ENTRY_COUNT - 1).map_err(core_task_error)?;
    drive_internal_core_mutation(&image, |pass| {
        let root =
            ext4_core::CommittedReadPass::load_directory(pass, ext4_core::DirectoryNodeId::ROOT)?;
        let mut cursor = ext4_core::DirectoryScanCursor::start();
        let mut count = 0_usize;
        let mut saw_source = false;
        loop {
            let batch = ext4_core::CommittedReadPass::scan_directory(
                pass,
                &root,
                &cursor,
                ext4_core::DirectoryScanLimit::MAX,
            )?;
            if batch.entries().len() > ext4_core::MAX_DIRECTORY_SCAN_ENTRIES {
                return Err(ext4_core::Error::InvalidDirectoryScanLimit);
            }
            let exhausted = batch.is_exhausted();
            cursor = *batch.continuation();
            for scanned in batch.into_entries() {
                count = count
                    .checked_add(1)
                    .ok_or(ext4_core::Error::ArithmeticOverflow)?;
                if scanned.entry().name() == &source {
                    saw_source = true;
                }
            }
            if exhausted {
                break;
            }
        }
        if count != ENTRY_COUNT + 3 || !saw_source {
            return Err(ext4_core::Error::InvalidDirectoryEntry);
        }
        if !matches!(
            ext4_core::CommittedReadPass::lookup_child(pass, &root, &source)?,
            ext4_core::ChildLookup::Found(_)
        ) {
            return Err(ext4_core::Error::DirectoryEntryNotFound);
        }
        let transaction_root = pass.directory(root.id())?;
        pass.rename_child(
            transaction_root,
            &source,
            transaction_root,
            &renamed,
            ext4_core::RenameTargetCollision::Reject,
        )
    })?;

    let dump = debugfs_request_output(linux, &image, "htree_dump /")?;
    if !dump.contains("Root node dump") {
        return Err(io::Error::other(format!(
            "{label} did not produce a debugfs-readable HTree root"
        ))
        .into());
    }
    let renamed_path = format!("/{}", String::from_utf8_lossy(renamed.bytes()));
    let source_path = format!("/{}", String::from_utf8_lossy(source.bytes()));
    if !debugfs_path_exists(linux, &image, &renamed_path)? {
        return Err(io::Error::other(format!(
            "{label} renamed HTree entry is absent from debugfs"
        ))
        .into());
    }
    debugfs_require_absent(linux, &image, &source_path)?;
    verify_internal_e2fsck_clean(linux, &image, &label)
}

/// Formats a temporary HTree interoperability image with explicit block/checksum/large-directory
/// features.
///
/// # Errors
///
/// Returns an error when image allocation, host path conversion, or mke2fs execution fails.
fn format_htree_image(
    linux: LinuxEnvironment,
    image: &Path,
    image_bytes: u64,
    block_size: u32,
    metadata_checksum: bool,
    large_directory: bool,
    journal_megabytes: u32,
) -> TaskResult<()> {
    File::create(image)?.set_len(image_bytes)?;
    let image_path = linux.tool_path(image)?;
    let checksum = if metadata_checksum {
        "metadata_csum,^uninit_bg"
    } else {
        "^metadata_csum,uninit_bg"
    };
    let large = if large_directory {
        "large_dir"
    } else {
        "^large_dir"
    };
    let features = format!("64bit,dir_index,{checksum},{large},^metadata_csum_seed,^orphan_file");
    let journal_size = format!("size={journal_megabytes}");
    let mut mke2fs = linux.command("mke2fs");
    mke2fs.args([
        "-q",
        "-F",
        "-t",
        "ext4",
        "-b",
        &block_size.to_string(),
        "-O",
        &features,
        "-E",
        "lazy_itable_init=0,lazy_journal_init=0",
        "-J",
        &journal_size,
        &image_path,
    ]);
    run_checked(mke2fs, "HTree mutation image format")
}

/// Builds and validates one real two-level LARGEDIR tree through external directory optimization.
///
/// The external tool sees only an ordinary directory stream. Its optimizer chooses the HTree
/// representation, while ext4-core subsequently proves that the resulting depth-two root is
/// readable through the production lookup and paging paths.
///
/// # Errors
///
/// Returns an error when image formatting, external population/optimization, raw depth
/// verification, production lookup/paging, or final filesystem validation fails.
fn verify_large_directory_depth_two(
    linux: LinuxEnvironment,
    temporary_root: &Path,
) -> TaskResult<()> {
    const ENTRY_COUNT: usize = 64_000;
    const BLOCK_SIZE: u32 = 1_024;
    const MINIMUM_DIRECTORY_BYTES: usize = 16 * 1024 * 1024;
    const DX_ROOT_INDIRECT_LEVELS_OFFSET: usize = 30;

    let label = "htree-1024-csum-large-depth2";
    println!("HTree interoperability profile: {label}");
    let case_root = temporary_root.join(label);
    fs::create_dir(&case_root)?;
    let image = case_root.join("filesystem.img");
    format_htree_image(linux, &image, 64 * 1024 * 1024, BLOCK_SIZE, true, true, 8)?;
    let image_path = linux.tool_path(&image)?;
    populate_depth_two_mounted_image(linux, &image_path, ENTRY_COUNT)?;

    let blocks = debugfs_block_sequence(linux, &image_path, "blocks /depth2")?;
    let directory_bytes = blocks
        .len()
        .checked_mul(usize::try_from(BLOCK_SIZE)?)
        .ok_or_else(|| io::Error::other("depth-two directory byte size overflow"))?;
    if directory_bytes <= MINIMUM_DIRECTORY_BYTES {
        return Err(io::Error::other(format!(
            "{label} directory is only {directory_bytes} bytes; expected more than 16 MiB"
        ))
        .into());
    }
    let first = blocks
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("depth-two directory has no root block"))?;
    let mut file = File::open(&image)?;
    let root = read_image_block(&mut file, first, BLOCK_SIZE)?;
    if root.get(DX_ROOT_INDIRECT_LEVELS_OFFSET).copied() != Some(2) {
        return Err(io::Error::other(format!(
            "{label} optimizer did not produce a depth-two HTree root"
        ))
        .into());
    }

    let directory_name = ext4_core::Ext4Name::new(b"depth2").map_err(core_task_error)?;
    let target_name = ext4_core::Ext4Name::new(
        depth_two_profile_name(
            ENTRY_COUNT
                .checked_sub(1)
                .ok_or_else(|| io::Error::other("depth-two entry count underflow"))?,
        )?
        .as_bytes(),
    )
    .map_err(core_task_error)?;
    let ((), exact_lower_reads) = drive_internal_core_read_observed(&image, |pass| {
        let root =
            ext4_core::CommittedReadPass::load_directory(pass, ext4_core::DirectoryNodeId::ROOT)?;
        let child = ext4_core::CommittedReadPass::lookup_child(pass, &root, &directory_name)?;
        let directory_id = match child {
            ext4_core::ChildLookup::Found(child) => match *child.node() {
                ext4_core::NodeId::Directory(directory) => directory,
                ext4_core::NodeId::File(_) | ext4_core::NodeId::Symlink(_) => {
                    return Err(ext4_core::Error::WrongInodeKind);
                }
            },
            ext4_core::ChildLookup::NotFound => {
                return Err(ext4_core::Error::DirectoryEntryNotFound);
            }
        };
        let directory = ext4_core::CommittedReadPass::load_directory(pass, directory_id)?;
        if !matches!(
            ext4_core::CommittedReadPass::lookup_child(pass, &directory, &target_name)?,
            ext4_core::ChildLookup::Found(_)
        ) {
            return Err(ext4_core::Error::DirectoryEntryNotFound);
        }
        Ok(())
    })?;
    if exact_lower_reads >= blocks.len() {
        return Err(io::Error::other(format!(
            "{label} exact lookup issued {exact_lower_reads} lower reads for {} directory blocks",
            blocks.len()
        ))
        .into());
    }

    drive_internal_core_read(&image, |pass| {
        let root =
            ext4_core::CommittedReadPass::load_directory(pass, ext4_core::DirectoryNodeId::ROOT)?;
        let child = ext4_core::CommittedReadPass::lookup_child(pass, &root, &directory_name)?;
        let directory_id = match child {
            ext4_core::ChildLookup::Found(child) => match *child.node() {
                ext4_core::NodeId::Directory(directory) => directory,
                ext4_core::NodeId::File(_) | ext4_core::NodeId::Symlink(_) => {
                    return Err(ext4_core::Error::WrongInodeKind);
                }
            },
            ext4_core::ChildLookup::NotFound => {
                return Err(ext4_core::Error::DirectoryEntryNotFound);
            }
        };
        let directory = ext4_core::CommittedReadPass::load_directory(pass, directory_id)?;
        let first = ext4_core::CommittedReadPass::scan_directory(
            pass,
            &directory,
            &ext4_core::DirectoryScanCursor::start(),
            ext4_core::DirectoryScanLimit::MAX,
        )?;
        if first.entries().len() != ext4_core::MAX_DIRECTORY_SCAN_ENTRIES || first.is_exhausted() {
            return Err(ext4_core::Error::InvalidDirectoryEntry);
        }
        let second = ext4_core::CommittedReadPass::scan_directory(
            pass,
            &directory,
            first.continuation(),
            ext4_core::DirectoryScanLimit::MAX,
        )?;
        if second.entries().len() != ext4_core::MAX_DIRECTORY_SCAN_ENTRIES || second.is_exhausted()
        {
            return Err(ext4_core::Error::InvalidDirectoryEntry);
        }
        Ok(())
    })?;
    println!(
        "depth-two >16 MiB lookup/paging: PASS ({exact_lower_reads} exact lower reads, {} directory blocks)",
        blocks.len()
    );
    verify_internal_e2fsck_clean(linux, &image, label)
}

/// Populates a mounted ext4 image through the kernel's public filesystem behavior.
///
/// # Errors
///
/// Returns an error when mount-directory creation, loop mounting, hard-link population, sync,
/// unmount, or mandatory mount-directory cleanup fails.
fn populate_depth_two_mounted_image(
    linux: LinuxEnvironment,
    image_path: &str,
    entry_count: usize,
) -> TaskResult<()> {
    const PREFIX: &str = "/tmp/ext4win-htree-mount.";

    let mut temporary = linux.command("mktemp");
    temporary.args(["-d", "/tmp/ext4win-htree-mount.XXXXXXXX"]);
    let output = run_checked_output(temporary, "depth-two mount directory creation")?;
    let mount_directory = String::from_utf8(output.stdout)?.trim().to_owned();
    if !mount_directory.starts_with(PREFIX)
        || mount_directory.len() <= PREFIX.len()
        || mount_directory.contains(char::is_whitespace)
    {
        return Err(io::Error::other("mktemp returned an unsafe depth-two mount path").into());
    }

    let mut mount = linux.command("mount");
    mount.args(["-o", "loop", image_path, &mount_directory]);
    if let Err(error) = run_checked(mount, "depth-two loop mount") {
        let cleanup = remove_depth_two_mount_directory(linux, &mount_directory);
        return combine_verification_and_cleanup(Err(error), cleanup);
    }

    let workload = (|| -> TaskResult<()> {
        let script = r#"import os, sys
root = sys.argv[1]
count = int(sys.argv[2])
depth = os.path.join(root, "depth2")
os.mkdir(depth)
target = os.path.join(root, "depth2-target")
open(target, "wb").close()
for index in range(count):
    name = f"depth-{index:05d}-"
    name += "x" * (255 - len(name))
    os.link(target, os.path.join(depth, name))
"#;
        let mut populate = linux.command("python3");
        populate
            .args(["-c", script, &mount_directory, &entry_count.to_string()])
            .stdout(Stdio::null());
        run_checked(populate, "depth-two mounted directory population")?;
        let mut sync = linux.command("sync");
        sync.args(["-f", &mount_directory]);
        run_checked(sync, "depth-two mounted image sync")
    })();
    let mut unmount = linux.command("umount");
    unmount.arg(&mount_directory);
    let unmounted =
        combine_verification_and_cleanup(workload, run_checked(unmount, "depth-two loop unmount"));
    let removed = remove_depth_two_mount_directory(linux, &mount_directory);
    combine_verification_and_cleanup(unmounted, removed)
}

/// Removes one empty, validated Linux-local mount directory.
///
/// # Errors
///
/// Returns an error when the path is outside the dedicated prefix or removal fails.
fn remove_depth_two_mount_directory(
    linux: LinuxEnvironment,
    mount_directory: &str,
) -> TaskResult<()> {
    const PREFIX: &str = "/tmp/ext4win-htree-mount.";

    if !mount_directory.starts_with(PREFIX)
        || mount_directory.len() <= PREFIX.len()
        || mount_directory.contains(char::is_whitespace)
    {
        return Err(io::Error::other("refusing unsafe depth-two mount cleanup path").into());
    }
    let mut remove = linux.command("rmdir");
    remove.args(["--", mount_directory]);
    run_checked(remove, "depth-two mount directory cleanup")
}

/// Builds one unique maximum-length directory component for the depth-two profile.
///
/// # Errors
///
/// Returns an error when the fixed prefix exceeds the ext4 name limit or padding allocation fails.
fn depth_two_profile_name(index: usize) -> TaskResult<String> {
    const NAME_BYTES: usize = 255;

    let mut name = format!("depth-{index:05}-");
    let padding = NAME_BYTES
        .checked_sub(name.len())
        .ok_or_else(|| io::Error::other("depth-two name prefix exceeds ext4 limit"))?;
    name.try_reserve_exact(padding)
        .map_err(|_| io::Error::other("depth-two name allocation failed"))?;
    name.extend(core::iter::repeat_n('x', padding));
    Ok(name)
}

/// Builds a deterministic long name that forces local leaf splits at the selected block size.
///
/// # Errors
///
/// Returns an error when the generated component length is invalid or allocation fails.
fn htree_profile_name(
    block_size: u32,
    prefix: &str,
    index: usize,
) -> ext4_core::Result<ext4_core::Ext4Name> {
    let total_bytes: usize = match block_size {
        1_024 => 103,
        4_096 => 115,
        _ => return Err(ext4_core::Error::UnsupportedBlockSize),
    };
    let mut name = format!("{prefix}-{index:04}-");
    let padding = total_bytes
        .checked_sub(name.len())
        .ok_or(ext4_core::Error::InvalidName)?;
    name.try_reserve_exact(padding)
        .map_err(|_| ext4_core::Error::OutOfMemory)?;
    name.extend(core::iter::repeat_n('x', padding));
    ext4_core::Ext4Name::new(name.as_bytes())
}

/// Creates one deterministic fresh ext4 image accepted by the production mount validator.
///
/// # Errors
///
/// Returns an error when image allocation, path conversion, or mke2fs execution fails.
fn format_mutation_image(
    linux: LinuxEnvironment,
    image: &Path,
    cluster_bytes: Option<u32>,
) -> TaskResult<()> {
    const IMAGE_BYTES: u64 = 256 * 1024 * 1024;

    File::create(image)?.set_len(IMAGE_BYTES)?;
    let image_path = linux.tool_path(image)?;
    let features = if cluster_bytes.is_some() {
        "metadata_csum,64bit,bigalloc,^metadata_csum_seed,^orphan_file"
    } else {
        "metadata_csum,64bit,^metadata_csum_seed,^orphan_file"
    };
    let mut mke2fs = linux.command("mke2fs");
    mke2fs.args([
        "-q",
        "-F",
        "-t",
        "ext4",
        "-b",
        "4096",
        "-O",
        features,
        "-E",
        "lazy_itable_init=0,lazy_journal_init=0",
        "-J",
        "size=8",
    ]);
    if let Some(cluster_bytes) = cluster_bytes {
        mke2fs.args(["-C", &cluster_bytes.to_string()]);
    }
    mke2fs.arg(&image_path);
    run_checked(mke2fs, "fresh mutation image format")
}

/// Exercises create, multi-block write, grow, shrink, rename, hard link, unlink, and xattr
/// set/update/delete on one fresh 4 KiB filesystem.
///
/// # Errors
///
/// Returns an error for typed mutation failure or any independent debugfs/e2fsck mismatch.
fn verify_regular_mutation_profile(
    linux: LinuxEnvironment,
    case_root: &Path,
    image: &Path,
) -> TaskResult<()> {
    const INITIAL_BYTES: usize = 20_480;
    const FINAL_BYTES: usize = 12_288;
    const FINAL_SIZE: u64 = 12_288;
    const GROWN_BYTES: u64 = 28_672;
    const TAIL_OFFSET: u64 = 24_576;

    let baseline = debugfs_free_space(linux, image)?;
    let source = ext4_core::Ext4Name::new(b"source.bin").map_err(core_task_error)?;
    let renamed = ext4_core::Ext4Name::new(b"renamed.bin").map_err(core_task_error)?;
    let linked = ext4_core::Ext4Name::new(b"linked.bin").map_err(core_task_error)?;
    let initial = vec![0x5A_u8; INITIAL_BYTES];
    drive_internal_core_mutation(image, |pass| {
        let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
        let file = pass.create_file(root, &source, mutation_file_metadata()?)?;
        pass.write_file_range(file, ext4_core::FileOffset::ZERO, &initial)
    })?;

    drive_internal_core_mutation(image, |pass| {
        let (_root, file_id) = mutation_root_file(pass, &source)?;
        let file = pass.file(file_id)?;
        pass.extend_file(file, ext4_core::FileSize::from_bytes(GROWN_BYTES))?;
        pass.write_file_range(
            file,
            ext4_core::FileOffset::from_bytes(TAIL_OFFSET),
            &[0xE5_u8; 4096],
        )?;
        let node = pass.node(ext4_core::NodeId::File(file_id))?;
        pass.set_xattr(
            node,
            mutation_xattr_name()?,
            ext4_core::XattrValue::new(b"set-value")?,
        )?;
        Ok(())
    })?;
    debugfs_require_xattr(
        linux,
        case_root,
        image,
        "/source.bin",
        b"set-value",
        "regular-set",
    )?;

    drive_internal_core_mutation(image, |pass| {
        let (root, file_id) = mutation_root_file(pass, &source)?;
        let file = pass.file(file_id)?;
        pass.truncate_file(file, ext4_core::FileSize::from_bytes(FINAL_SIZE))?;
        pass.rename_child(
            root,
            &source,
            root,
            &renamed,
            ext4_core::RenameTargetCollision::Reject,
        )?;
        let hard_link = pass.hard_link_source(ext4_core::HardLinkNodeId::File(file_id))?;
        pass.create_hard_link(
            hard_link,
            root,
            &linked,
            ext4_core::HardLinkDestination::Vacant,
        )?;
        let node = pass.node(ext4_core::NodeId::File(file_id))?;
        pass.set_xattr(
            node,
            mutation_xattr_name()?,
            ext4_core::XattrValue::new(b"updated-value")?,
        )
    })?;
    debugfs_require_xattr(
        linux,
        case_root,
        image,
        "/renamed.bin",
        b"updated-value",
        "regular-update",
    )?;

    drive_internal_core_mutation(image, |pass| {
        let (root, file_id) = mutation_root_file(pass, &linked)?;
        pass.unlink_file(root, &renamed)?;
        let node = pass.node(ext4_core::NodeId::File(file_id))?;
        let removed = pass.remove_xattr(node, &mutation_xattr_name()?)?;
        if removed.is_none() {
            return Err(ext4_core::Error::InvalidXattr);
        }
        Ok(())
    })?;

    let expected = initial
        .get(..FINAL_BYTES)
        .ok_or_else(|| io::Error::other("regular expected-content range is absent"))?;
    debugfs_require_file(
        linux,
        case_root,
        image,
        "/linked.bin",
        expected,
        1,
        "regular",
    )?;
    debugfs_require_absent(linux, image, "/source.bin")?;
    debugfs_require_absent(linux, image, "/renamed.bin")?;
    debugfs_require_xattr_absent(linux, image, "/linked.bin", b"user.ext4win.interop")?;
    require_free_space_delta(baseline, debugfs_free_space(linux, image)?, 3, 1, "regular")?;
    verify_internal_e2fsck_clean(linux, image, "regular mutation profile")
}

/// Exercises allocation, truncation, unlink, and deterministic cluster reuse on one fresh
/// 4 KiB-block/16 KiB-cluster BIGALLOC filesystem.
///
/// # Errors
///
/// Returns an error for typed mutation failure, non-reuse, accounting drift, or oracle rejection.
fn verify_bigalloc_mutation_profile(
    linux: LinuxEnvironment,
    case_root: &Path,
    image: &Path,
) -> TaskResult<()> {
    let baseline = debugfs_free_space(linux, image)?;
    let alpha = ext4_core::Ext4Name::new(b"alpha.bin").map_err(core_task_error)?;
    let beta = ext4_core::Ext4Name::new(b"beta.bin").map_err(core_task_error)?;
    let alpha_content = vec![0xA6_u8; 20_480];
    drive_internal_core_mutation(image, |pass| {
        let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
        let file = pass.create_file(root, &alpha, mutation_file_metadata()?)?;
        pass.write_file_range(file, ext4_core::FileOffset::ZERO, &alpha_content)
    })?;
    drive_internal_core_mutation(image, |pass| {
        let (_root, file_id) = mutation_root_file(pass, &alpha)?;
        let file = pass.file(file_id)?;
        pass.truncate_file(file, ext4_core::FileSize::from_bytes(4096))
    })?;
    let image_path = linux.tool_path(image)?;
    let alpha_blocks = debugfs_block_sequence(linux, &image_path, "blocks /alpha.bin")?;
    let alpha_cluster = first_bigalloc_cluster(&alpha_blocks)?;

    drive_internal_core_mutation(image, |pass| {
        let (root, _file_id) = mutation_root_file(pass, &alpha)?;
        pass.unlink_file(root, &alpha)
    })?;
    drive_internal_core_mutation(image, |pass| {
        let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
        let file = pass.create_file(root, &beta, mutation_file_metadata()?)?;
        pass.write_file_range(file, ext4_core::FileOffset::ZERO, &[0xB7_u8; 4096])
    })?;
    let beta_blocks = debugfs_block_sequence(linux, &image_path, "blocks /beta.bin")?;
    let beta_cluster = first_bigalloc_cluster(&beta_blocks)?;
    if beta_cluster != alpha_cluster {
        return Err(io::Error::other(format!(
            "BIGALLOC cluster was not reused: released={alpha_cluster} allocated={beta_cluster}"
        ))
        .into());
    }
    debugfs_require_file(
        linux,
        case_root,
        image,
        "/beta.bin",
        &[0xB7_u8; 4096],
        1,
        "bigalloc",
    )?;
    debugfs_require_absent(linux, image, "/alpha.bin")?;
    require_free_space_delta(
        baseline,
        debugfs_free_space(linux, image)?,
        4,
        1,
        "BIGALLOC",
    )?;
    verify_internal_e2fsck_clean(linux, image, "BIGALLOC mutation profile")
}

/// Returns deterministic POSIX metadata used by interoperability-created regular files.
///
/// # Errors
///
/// Returns an error only if the fixed permission representation becomes invalid.
fn mutation_file_metadata() -> ext4_core::Result<ext4_core::NewFileMetadata> {
    Ok(ext4_core::NewFileMetadata::new(
        ext4_core::Ext4Owner::new(
            ext4_core::Ext4Uid::from_u32(1000),
            ext4_core::Ext4Gid::from_u32(1000),
        ),
        ext4_core::Ext4Permissions::new(0o644)?,
    ))
}

/// Returns the fixed public xattr name exercised by mutation interoperability.
///
/// # Errors
///
/// Returns an error only if the fixed name representation becomes invalid.
fn mutation_xattr_name() -> ext4_core::Result<ext4_core::XattrName> {
    ext4_core::XattrName::new(ext4_core::XattrNamespace::User, b"ext4win.interop")
}

/// Resolves one named root child into its typed transaction directory and file identities.
///
/// # Errors
///
/// Returns an error when the root or child cannot be read, the name is absent, or it is not a
/// regular file.
fn mutation_root_file(
    pass: &mut ext4_core::MutationResolvePass<'_, '_, '_>,
    name: &ext4_core::Ext4Name,
) -> ext4_core::Result<(ext4_core::TransactionDirectory, ext4_core::FileNodeId)> {
    let root =
        ext4_core::CommittedReadPass::load_directory(pass, ext4_core::DirectoryNodeId::ROOT)?;
    let child = ext4_core::CommittedReadPass::lookup_child(pass, &root, name)?;
    let file_id = match child {
        ext4_core::ChildLookup::Found(child) => match *child.node() {
            ext4_core::NodeId::File(file) => file,
            ext4_core::NodeId::Directory(_) | ext4_core::NodeId::Symlink(_) => {
                return Err(ext4_core::Error::WrongInodeKind);
            }
        },
        ext4_core::ChildLookup::NotFound => return Err(ext4_core::Error::InvalidDirectoryEntry),
    };
    Ok((pass.directory(root.id())?, file_id))
}

/// Converts the first physical block into its 16 KiB BIGALLOC cluster identity.
///
/// # Errors
///
/// Returns an error when debugfs reports no allocated block.
fn first_bigalloc_cluster(blocks: &[u64]) -> TaskResult<u64> {
    blocks
        .first()
        .copied()
        .and_then(|block| block.checked_div(4))
        .ok_or_else(|| io::Error::other("BIGALLOC file has no physical cluster").into())
}

/// Captures one debugfs request's UTF-8 stdout and diagnostics.
///
/// # Errors
///
/// Returns an error for path conversion, process failure, or non-UTF-8 output.
fn debugfs_request_output(
    linux: LinuxEnvironment,
    image: &Path,
    request: &str,
) -> TaskResult<String> {
    let image_path = linux.tool_path(image)?;
    let mut command = linux.command("debugfs");
    command.args(["-R", request, &image_path]);
    let output = run_checked_output(command, &format!("debugfs request `{request}`"))?;
    let mut text = String::from_utf8(output.stdout)?;
    text.push_str(&String::from_utf8(output.stderr)?);
    Ok(text)
}

/// Reads free block and inode counters through the independent debugfs parser.
///
/// # Errors
///
/// Returns an error when debugfs fails or omits either numeric field.
fn debugfs_free_space(linux: LinuxEnvironment, image: &Path) -> TaskResult<DebugfsFreeSpace> {
    let output = debugfs_request_output(linux, image, "stats")?;
    Ok(DebugfsFreeSpace {
        blocks: debugfs_numeric_field(&output, "Free blocks:")?,
        inodes: debugfs_numeric_field(&output, "Free inodes:")?,
    })
}

/// Parses one exact numeric field from debugfs output.
///
/// # Errors
///
/// Returns an error when the field is absent, empty, or not an unsigned integer.
fn debugfs_numeric_field(output: &str, field: &str) -> TaskResult<u64> {
    let value = output
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(field))
        .ok_or_else(|| io::Error::other(format!("debugfs omitted `{field}`")))?;
    Ok(value.trim().parse()?)
}

/// Requires exact block/inode consumption relative to a fresh-image baseline.
///
/// # Errors
///
/// Returns an error for counter growth, arithmetic failure, or a mismatching allocation charge.
fn require_free_space_delta(
    baseline: DebugfsFreeSpace,
    observed: DebugfsFreeSpace,
    expected_blocks: u64,
    expected_inodes: u64,
    label: &str,
) -> TaskResult<()> {
    let consumed_blocks = baseline
        .blocks
        .checked_sub(observed.blocks)
        .ok_or_else(|| io::Error::other(format!("{label} free-block count grew unexpectedly")))?;
    let consumed_inodes = baseline
        .inodes
        .checked_sub(observed.inodes)
        .ok_or_else(|| io::Error::other(format!("{label} free-inode count grew unexpectedly")))?;
    if consumed_blocks != expected_blocks || consumed_inodes != expected_inodes {
        return Err(io::Error::other(format!(
            "{label} accounting mismatch: blocks={consumed_blocks}/{expected_blocks} \
             inodes={consumed_inodes}/{expected_inodes}"
        ))
        .into());
    }
    Ok(())
}

/// Requires one debugfs-visible regular file to have exact content, size, and link count.
///
/// # Errors
///
/// Returns an error when stat/dump fails or any observable differs.
fn debugfs_require_file(
    linux: LinuxEnvironment,
    case_root: &Path,
    image: &Path,
    path: &str,
    expected: &[u8],
    links: u16,
    label: &str,
) -> TaskResult<()> {
    let stat = debugfs_request_output(linux, image, &format!("stat {path}"))?;
    let size_field = format!("Size: {}", expected.len());
    let links_field = format!("Links: {links}");
    if !stat.contains("Inode:") || !stat.contains(&size_field) || !stat.contains(&links_field) {
        return Err(
            io::Error::other(format!("{label} stat mismatch for {path}: {}", stat.trim())).into(),
        );
    }
    let dump = case_root.join(format!("{label}-dump.bin"));
    let dump_path = linux.tool_path(&dump)?;
    let image_path = linux.tool_path(image)?;
    let mut command = linux.command("debugfs");
    command.args(["-R", &format!("dump -p {path} {dump_path}"), &image_path]);
    run_checked(command, &format!("debugfs dump for {label}"))?;
    let observed = fs::read(&dump)?;
    fs::remove_file(&dump)?;
    if observed != expected {
        return Err(io::Error::other(format!("{label} content mismatch for {path}")).into());
    }
    Ok(())
}

/// Requires debugfs not to resolve one path to an inode.
///
/// # Errors
///
/// Returns an error when debugfs fails or reports an existing inode.
fn debugfs_require_absent(linux: LinuxEnvironment, image: &Path, path: &str) -> TaskResult<()> {
    let stat = debugfs_request_output(linux, image, &format!("stat {path}"))?;
    if stat.contains("Inode:") {
        Err(io::Error::other(format!("debugfs unexpectedly resolved {path}")).into())
    } else {
        Ok(())
    }
}

/// Returns whether debugfs resolves one path to an inode.
///
/// # Errors
///
/// Returns an error when debugfs cannot inspect the image.
fn debugfs_path_exists(linux: LinuxEnvironment, image: &Path, path: &str) -> TaskResult<bool> {
    Ok(debugfs_request_output(linux, image, &format!("stat {path}"))?.contains("Inode:"))
}

/// Requires an external-journal recovery result to be one complete namespace/data/xattr endpoint.
///
/// # Errors
///
/// Returns an error when old/new namespace states are mixed or the selected endpoint's content,
/// link count, or xattr value differs.
fn debugfs_require_external_old_or_new(
    linux: LinuxEnvironment,
    case_root: &Path,
    image: &Path,
    old_content: &[u8],
    new_content: &[u8],
    label: &str,
) -> TaskResult<()> {
    let old_exists = debugfs_path_exists(linux, image, "/external-old.bin")?;
    let new_exists = debugfs_path_exists(linux, image, "/external-new.bin")?;
    match (old_exists, new_exists) {
        (true, false) => {
            let endpoint = format!("{label}-old");
            debugfs_require_file(
                linux,
                case_root,
                image,
                "/external-old.bin",
                old_content,
                1,
                &endpoint,
            )?;
            debugfs_require_xattr(
                linux,
                case_root,
                image,
                "/external-old.bin",
                b"external-old",
                &endpoint,
            )
        }
        (false, true) => {
            let endpoint = format!("{label}-new");
            debugfs_require_file(
                linux,
                case_root,
                image,
                "/external-new.bin",
                new_content,
                1,
                &endpoint,
            )?;
            debugfs_require_xattr(
                linux,
                case_root,
                image,
                "/external-new.bin",
                b"external-new",
                &endpoint,
            )
        }
        (false, false) | (true, true) => Err(io::Error::other(format!(
            "{label} external mutation has mixed namespace state: old={old_exists} new={new_exists}"
        ))
        .into()),
    }
}

/// Requires one exact xattr value through debugfs's independent xattr decoder.
///
/// # Errors
///
/// Returns an error when extraction fails or the value differs.
fn debugfs_require_xattr(
    linux: LinuxEnvironment,
    case_root: &Path,
    image: &Path,
    path: &str,
    expected: &[u8],
    label: &str,
) -> TaskResult<()> {
    let output = case_root.join(format!("{label}-xattr.bin"));
    let output_path = linux.tool_path(&output)?;
    let image_path = linux.tool_path(image)?;
    let request = format!("ea_get -f {output_path} {path} user.ext4win.interop");
    let mut command = linux.command("debugfs");
    command.args(["-R", &request, &image_path]);
    run_checked(command, &format!("debugfs xattr extraction for {label}"))?;
    let observed = fs::read(&output)?;
    fs::remove_file(&output)?;
    if observed != expected {
        return Err(io::Error::other(format!("{label} xattr mismatch for {path}")).into());
    }
    Ok(())
}

/// Requires one xattr name to be absent from debugfs's decoded list.
///
/// # Errors
///
/// Returns an error when debugfs fails or reports the removed name.
fn debugfs_require_xattr_absent(
    linux: LinuxEnvironment,
    image: &Path,
    path: &str,
    qualified_name: &[u8],
) -> TaskResult<()> {
    let output = debugfs_request_output(linux, image, &format!("ea_list {path}"))?;
    let qualified_name = String::from_utf8(qualified_name.to_vec())?;
    if output.contains(&qualified_name) {
        Err(io::Error::other(format!(
            "debugfs still reports removed xattr {qualified_name} on {path}"
        ))
        .into())
    } else {
        Ok(())
    }
}

/// Requires e2fsck to accept one internal-journal mutation image without modification.
///
/// # Errors
///
/// Returns an error for path conversion, process launch, or non-clean e2fsck status.
fn verify_internal_e2fsck_clean(
    linux: LinuxEnvironment,
    image: &Path,
    label: &str,
) -> TaskResult<()> {
    let image_path = linux.tool_path(image)?;
    let mut e2fsck = linux.command("e2fsck");
    e2fsck.args(["-f", "-n", &image_path]);
    run_checked(e2fsck, &format!("e2fsck for {label}"))
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
    if fixture.name == "external-4k-v3-64" {
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
/// The 4 KiB external-journal fixture is the mutation/crash profile; the ordinary interoperability
/// loop independently covers every supported block-size/checksum/address-width pair.
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
    let recovery_cuts = enumerate_effect_cuts(&recovery_effects)?;
    remove_fault_pair(&probe_filesystem, &probe_journal)?;

    for cut in recovery_cuts.iter().copied() {
        let stem = format!("recovery-{}", effect_cut_stem(cut));
        let (filesystem, journal) =
            copy_fault_pair(&matrix_root, &stem, dirty_filesystem, dirty_journal)?;
        let run = run_external_mount_until_boundary(&filesystem, &journal, Some(cut))?;
        require_stopped_effect("recovery", cut, run)?;
        let observed = {
            let mut image = File::open(&filesystem)?;
            read_image_block(&mut image, fixture.replay_block, fixture.block_size)?
        };
        require_old_new_or_sector_prefix_bytes(
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
    let close_cuts = enumerate_effect_cuts(&close_effects)?;
    remove_fault_pair(&probe_filesystem, &probe_journal)?;

    for cut in close_cuts.iter().copied() {
        let stem = format!("close-{}", effect_cut_stem(cut));
        let (filesystem, journal) =
            copy_fault_pair(&matrix_root, &stem, &clean_filesystem, &clean_journal)?;
        let run = run_external_clean_close_until_boundary(&filesystem, &journal, Some(cut))?;
        require_stopped_effect("clean close", cut, run)?;
        drive_external_core_mount_and_clean_close(&filesystem, &journal)?;
        verify_primary_recovery_marker(&filesystem, false)?;
        verify_external_e2fsck_clean(linux, &filesystem, &journal, &stem)?;
        remove_fault_pair(&filesystem, &journal)?;
    }

    let source_name = ext4_core::Ext4Name::new(b"external-old.bin").map_err(core_task_error)?;
    let target_name = ext4_core::Ext4Name::new(b"external-new.bin").map_err(core_task_error)?;
    let old_content = vec![0x31_u8; 1024];
    let appended = vec![0x42_u8; 2048];
    let mut new_content = old_content.clone();
    new_content.resize(4096, 0);
    new_content.extend_from_slice(&appended);
    drive_external_core_mutation(&clean_filesystem, &clean_journal, |pass| {
        let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
        let file = pass.create_file(root, &source_name, mutation_file_metadata()?)?;
        pass.write_file_range(file, ext4_core::FileOffset::ZERO, &old_content)
    })?;
    drive_external_core_mutation(&clean_filesystem, &clean_journal, |pass| {
        let (_root, file_id) = mutation_root_file(pass, &source_name)?;
        let node = pass.node(ext4_core::NodeId::File(file_id))?;
        pass.set_xattr(
            node,
            mutation_xattr_name()?,
            ext4_core::XattrValue::new(b"external-old")?,
        )
    })?;
    debugfs_require_file(
        linux,
        &matrix_root,
        &clean_filesystem,
        "/external-old.bin",
        &old_content,
        1,
        "external-baseline",
    )?;
    let (probe_filesystem, probe_journal) = copy_fault_pair(
        &matrix_root,
        "mutation-probe",
        &clean_filesystem,
        &clean_journal,
    )?;
    let mutation_probe = run_external_file_mutation_until_boundary(
        &probe_filesystem,
        &probe_journal,
        &source_name,
        &target_name,
        &appended,
        None,
    )?;
    let mutation_effects = require_completed_effect_probe("commit/checkpoint", mutation_probe)?;
    let mutation_cuts = enumerate_effect_cuts(&mutation_effects)?;
    remove_fault_pair(&probe_filesystem, &probe_journal)?;

    for cut in mutation_cuts.iter().copied() {
        let stem = format!("mutation-{}", effect_cut_stem(cut));
        let (filesystem, journal) =
            copy_fault_pair(&matrix_root, &stem, &clean_filesystem, &clean_journal)?;
        let run = run_external_file_mutation_until_boundary(
            &filesystem,
            &journal,
            &source_name,
            &target_name,
            &appended,
            Some(cut),
        )?;
        require_stopped_effect("commit/checkpoint", cut, run)?;
        drive_external_core_mount_and_clean_close(&filesystem, &journal)?;
        debugfs_require_external_old_or_new(
            linux,
            &matrix_root,
            &filesystem,
            &old_content,
            &new_content,
            &stem,
        )?;
        verify_primary_recovery_marker(&filesystem, false)?;
        verify_external_e2fsck_clean(linux, &filesystem, &journal, &stem)?;
        remove_fault_pair(&filesystem, &journal)?;
    }

    remove_fault_pair(&clean_filesystem, &clean_journal)?;
    fs::remove_dir(&matrix_root)?;
    let total_effects = recovery_effects
        .len()
        .checked_add(mutation_effects.len())
        .and_then(|count| count.checked_add(close_effects.len()))
        .ok_or_else(|| io::Error::other("fault-matrix effect count overflow"))?;
    println!(
        "JBD2 production fault matrix: PASS ({} recovery, {} commit/checkpoint, \
         {} clean-close sector/flush cuts across {} effects)",
        recovery_cuts.len(),
        mutation_cuts.len(),
        close_cuts.len(),
        total_effects,
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

/// Requires a non-empty full probe and returns its exact ordered effect trace.
///
/// # Errors
///
/// Returns an error when the workflow stopped unexpectedly or exposed no write/flush boundary.
fn require_completed_effect_probe(
    label: &str,
    run: EffectBoundaryRun,
) -> TaskResult<Vec<StorageEffect>> {
    if !run.completed {
        return Err(io::Error::other(format!("{label} effect probe stopped unexpectedly")).into());
    }
    if run.completed_effects == 0 {
        return Err(io::Error::other(format!("{label} effect probe found no boundary")).into());
    }
    if run.completed_effects != run.effects.len() {
        return Err(io::Error::other(format!(
            "{label} effect probe counted {} effects but recorded {}",
            run.completed_effects,
            run.effects.len()
        ))
        .into());
    }
    Ok(run.effects)
}

/// Enumerates every permitted crash persistence outcome for one exact production trace.
///
/// Each write contributes an unpersisted case, every 512-byte prefix, and the full write. Each
/// flush contributes one target-local durable cut.
///
/// # Errors
///
/// Returns an error when a production write is empty or is not composed of atomic sectors.
fn enumerate_effect_cuts(effects: &[StorageEffect]) -> TaskResult<Vec<EffectCut>> {
    let mut cuts = Vec::new();
    for (index, observed) in effects.iter().copied().enumerate() {
        let effect_number = index
            .checked_add(1)
            .ok_or_else(|| io::Error::other("effect index overflow"))?;
        match observed {
            StorageEffect::Write { bytes, .. } => {
                if bytes == 0 || bytes % 512 != 0 {
                    return Err(io::Error::other(format!(
                        "effect {effect_number} write length {bytes} is not a positive sector multiple"
                    ))
                    .into());
                }
                for prefix in (0..=bytes).step_by(512) {
                    cuts.push(EffectCut {
                        effect: effect_number,
                        write_prefix: Some(prefix),
                    });
                }
            }
            StorageEffect::Flush { .. } => cuts.push(EffectCut {
                effect: effect_number,
                write_prefix: None,
            }),
        }
    }
    Ok(cuts)
}

/// Produces a filesystem-safe identity for one sector-prefix or target-local-flush cut.
fn effect_cut_stem(cut: EffectCut) -> String {
    match cut.write_prefix {
        Some(prefix) => format!("{:03}-write-{prefix:08}", cut.effect),
        None => format!("{:03}-flush", cut.effect),
    }
}

/// Requires one exact simulated-crash boundary to have been reached.
///
/// # Errors
///
/// Returns an error when the workflow terminated or stopped after a different effect count.
fn require_stopped_effect(
    label: &str,
    expected: EffectCut,
    run: EffectBoundaryRun,
) -> TaskResult<()> {
    if run.completed
        || run.completed_effects != expected.effect
        || run.effects.len() != expected.effect
    {
        return Err(io::Error::other(format!(
            "{label} boundary {} produced completed={} effects={} trace={}",
            effect_cut_stem(expected),
            run.completed,
            run.completed_effects,
            run.effects.len()
        ))
        .into());
    }
    let observed = run
        .effects
        .last()
        .copied()
        .ok_or_else(|| io::Error::other("stopped effect trace is empty"))?;
    match (observed, expected.write_prefix) {
        (StorageEffect::Write { bytes, .. }, Some(prefix)) if prefix <= bytes => {}
        (StorageEffect::Flush { .. }, None) => {}
        _ => {
            return Err(io::Error::other(format!(
                "{label} boundary {} does not match its observed request",
                effect_cut_stem(expected)
            ))
            .into());
        }
    }
    Ok(())
}

/// Requires an interrupted recovery write to equal a sector-prefix transition from old to new.
///
/// The dirty journal remains authoritative until replayed home blocks and the journal-clean marker
/// are durable. A device may therefore expose complete old/new bytes or a prefix of newly persisted
/// sectors followed by the old suffix before the next mount replays the transaction again.
/// # Errors
///
/// Returns an error when the representations differ in length, are not sector-sized, or contain a
/// mixture that no single ordered 512-byte write prefix can produce.
fn require_old_new_or_sector_prefix_bytes(
    label: &str,
    observed: &[u8],
    old: &[u8],
    new: &[u8],
) -> TaskResult<()> {
    const SECTOR_BYTES: usize = 512;

    if observed.len() != old.len()
        || observed.len() != new.len()
        || !observed.len().is_multiple_of(SECTOR_BYTES)
    {
        return Err(io::Error::other(format!(
            "{label} does not share one sector-aligned representation"
        ))
        .into());
    }
    for prefix in (0..=observed.len()).step_by(SECTOR_BYTES) {
        if observed.get(..prefix) == new.get(..prefix)
            && observed.get(prefix..) == old.get(prefix..)
        {
            return Ok(());
        }
    }
    Err(io::Error::other(format!(
        "{label} is not an ordered sector-prefix transition"
    ))
    .into())
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

/// Opens and fully mounts one internal-journal image through the public production protocol.
///
/// # Errors
///
/// Returns an error for device geometry, host I/O, unexpected external discovery, or core mount
/// rejection.
fn mount_internal_core<S: HostStorage>(
    storage: &mut S,
) -> TaskResult<Box<ext4_core::CompletedMount>> {
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.length(ext4_core::StorageTarget::Filesystem)?);
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
            ext4_core::MountTransition::DiscoverExternalJournal { .. } => {
                return Err(io::Error::other(
                    "internal-journal interoperability image requested external discovery",
                )
                .into());
            }
            ext4_core::MountTransition::Complete(result) => {
                return result.map_err(|error| core_task_error(error).into());
            }
        }
    }
}

/// Opens and fully mounts one external-journal image pair through the public production protocol.
///
/// # Errors
///
/// Returns an error for device geometry, host I/O, probe mismatch, or core mount rejection.
fn mount_external_core<S: HostStorage>(
    storage: &mut S,
) -> TaskResult<Box<ext4_core::CompletedMount>> {
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.length(ext4_core::StorageTarget::Filesystem)?);
    let external_length = ext4_core::DeviceLength::from_bytes(
        storage.length(ext4_core::StorageTarget::ExternalJournal)?,
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

/// Runs a clean close for one mounted profile through the same storage boundary.
///
/// # Errors
///
/// Returns an error for lower storage I/O or a rejected clean-close transition.
fn complete_core_clean_close<S: HostStorage>(
    storage: &mut S,
    filesystem_length: ext4_core::DeviceLength,
    journal_target: ext4_core::StorageTarget,
) -> TaskResult<()> {
    let mut close = Box::try_new(ext4_core::CleanCloseOperation::new(
        filesystem_length,
        journal_target,
    ))?
    .advance(ext4_core::OperationEvent::Admitted);
    loop {
        match close {
            ext4_core::CleanCloseTransition::SubmitLower { request, suspended } => {
                let completion = complete_file_request(storage, request)?;
                close = suspended.advance(ext4_core::OperationEvent::StorageCompleted(completion));
            }
            ext4_core::CleanCloseTransition::Complete(result) => {
                result.map_err(core_task_error)?;
                return Ok(());
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
    cut: Option<EffectCut>,
) -> TaskResult<EffectBoundaryRun> {
    let mut storage = CrashStorageAdapter::open_external(filesystem, journal)?;
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.length(ext4_core::StorageTarget::Filesystem)?);
    let external_length = ext4_core::DeviceLength::from_bytes(
        storage.length(ext4_core::StorageTarget::ExternalJournal)?,
    );
    let mut controller = EffectBoundaryController::new(cut)?;
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
                storage.materialize_durable()?;
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
    cut: Option<EffectCut>,
) -> TaskResult<EffectBoundaryRun> {
    let mut storage = CrashStorageAdapter::open_external(filesystem, journal)?;
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.length(ext4_core::StorageTarget::Filesystem)?);
    let completed = mount_external_core(&mut storage)?;
    let (profile, _epoch, _coordinator) = completed.into_parts();
    let mut controller = EffectBoundaryController::new(cut)?;
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
                storage.materialize_durable()?;
                return Ok(controller.completed());
            }
        }
    }
}

/// Mounts a clean external-journal pair and runs one rename/write/xattr commit through checkpoint.
///
/// # Errors
///
/// Returns an error for mount/resolve/commit/checkpoint failure or host storage I/O.
fn run_external_file_mutation_until_boundary(
    filesystem: &Path,
    journal: &Path,
    source_name: &ext4_core::Ext4Name,
    target_name: &ext4_core::Ext4Name,
    appended: &[u8],
    cut: Option<EffectCut>,
) -> TaskResult<EffectBoundaryRun> {
    let mut storage = CrashStorageAdapter::open_external(filesystem, journal)?;
    let completed = mount_external_core(&mut storage)?;
    let (profile, epoch, mut coordinator) = (*completed).into_parts();
    let ticket = coordinator.admit_mutation().map_err(core_task_error)?;
    let (prepared, ()) = prepare_core_mutation(
        &mut storage,
        &profile,
        &epoch,
        &coordinator,
        ticket,
        |pass| {
            let (root, file_id) = mutation_root_file(pass, source_name)?;
            let file = pass.file(file_id)?;
            pass.write_file_range(file, ext4_core::FileOffset::from_bytes(4096), appended)?;
            pass.rename_child(
                root,
                source_name,
                root,
                target_name,
                ext4_core::RenameTargetCollision::Reject,
            )?;
            let node = pass.node(ext4_core::NodeId::File(file_id))?;
            pass.set_xattr(
                node,
                mutation_xattr_name()?,
                ext4_core::XattrValue::new(b"external-new")?,
            )
        },
    )?;
    run_prepared_mutation_until_boundary(&mut storage, &mut coordinator, ticket, prepared, cut)
}

/// Runs the fixed HTree conversion/split transaction until completion or one durability cut.
///
/// # Errors
///
/// Returns an error for name construction, internal mount/resolve/reservation, or commit/checkpoint
/// boundary execution failure.
fn run_internal_htree_mutation_until_boundary(
    filesystem: &Path,
    cut: Option<EffectCut>,
) -> TaskResult<EffectBoundaryRun> {
    let names = htree_fault_names()?;
    let mut storage = CrashStorageAdapter::open_internal(filesystem)?;
    let completed = mount_internal_core(&mut storage)?;
    let (profile, epoch, mut coordinator) = (*completed).into_parts();
    let ticket = coordinator.admit_mutation().map_err(core_task_error)?;
    let (prepared, ()) = prepare_core_mutation(
        &mut storage,
        &profile,
        &epoch,
        &coordinator,
        ticket,
        |pass| {
            let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
            for name in &names {
                pass.create_file(root, name, mutation_file_metadata()?)?;
            }
            Ok(())
        },
    )?;
    run_prepared_mutation_until_boundary(&mut storage, &mut coordinator, ticket, prepared, cut)
}

/// Drives one preallocated production mutation through every durability boundary or one exact cut.
///
/// # Errors
///
/// Returns an error for controller construction, host storage effects, completion identity,
/// publication, checkpoint, or final durable materialization failure.
fn run_prepared_mutation_until_boundary(
    storage: &mut CrashStorageAdapter,
    coordinator: &mut ext4_core::MutationCoordinatorState,
    ticket: u64,
    prepared: ext4_core::CommitReadyMutation,
    cut: Option<EffectCut>,
) -> TaskResult<EffectBoundaryRun> {
    let mut controller = EffectBoundaryController::new(cut)?;

    let ordered = match complete_boundary_sequence(storage, &mut controller, prepared.start())? {
        BoundarySequence::Stopped => return Ok(controller.stopped()),
        BoundarySequence::Finished(ordered) => ordered,
    };
    if !complete_boundary_request(storage, &mut controller, ordered.flush_request())? {
        return Ok(controller.stopped());
    }
    let payloads = match complete_boundary_sequence(storage, &mut controller, ordered.completed())?
    {
        BoundarySequence::Stopped => return Ok(controller.stopped()),
        BoundarySequence::Finished(payloads) => payloads,
    };
    if !complete_boundary_request(storage, &mut controller, payloads.flush_request())? {
        return Ok(controller.stopped());
    }
    let (commit_request, commit_durability) = payloads.completed().submit();
    if !complete_boundary_request(storage, &mut controller, commit_request)? {
        return Ok(controller.stopped());
    }
    if !complete_boundary_request(storage, &mut controller, commit_durability.flush_request())? {
        return Ok(controller.stopped());
    }
    let published = commit_durability
        .completed()
        .publish(coordinator, ext4_core::VisibilityLease::granted(ticket));
    let (epoch, checkpoint) = published.into_parts();
    let home = match complete_boundary_sequence(
        storage,
        &mut controller,
        checkpoint.start(ext4_core::CheckpointLease::granted(epoch.sequence())),
    )? {
        BoundarySequence::Stopped => return Ok(controller.stopped()),
        BoundarySequence::Finished(home) => home,
    };
    if !complete_boundary_request(storage, &mut controller, home.flush_request())? {
        return Ok(controller.stopped());
    }
    let (clean_request, clean_durability) = home.completed().submit();
    if !complete_boundary_request(storage, &mut controller, clean_request)? {
        return Ok(controller.stopped());
    }
    if !complete_boundary_request(storage, &mut controller, clean_durability.flush_request())? {
        return Ok(controller.stopped());
    }
    let _checkpointed_epoch = clean_durability.completed(coordinator);
    storage.materialize_durable()?;
    Ok(controller.completed())
}

/// Consumes one production request sequence until completion or the selected crash boundary.
///
/// # Errors
///
/// Returns an error for host I/O or a mismatching lower completion identity.
fn complete_boundary_sequence<Next>(
    storage: &mut CrashStorageAdapter,
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
    storage: &mut CrashStorageAdapter,
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
    let length =
        ext4_core::DeviceLength::from_bytes(storage.length(ext4_core::StorageTarget::Filesystem)?);
    let completed = mount_internal_core(&mut storage)?;
    let (profile, _epoch, _coordinator) = completed.into_parts();
    complete_core_clean_close(&mut storage, length, profile.journal_target())
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
        ext4_core::DeviceLength::from_bytes(storage.length(ext4_core::StorageTarget::Filesystem)?);
    let completed = mount_external_core(&mut storage)?;
    let (profile, _epoch, _coordinator) = completed.into_parts();
    complete_core_clean_close(&mut storage, filesystem_length, profile.journal_target())
}

/// Runs the public core validator for one exclusively selected external-journal file.
///
/// # Errors
///
/// Returns an error for file I/O, core corruption, or a UUID mismatch after exclusive selection.
fn drive_external_probe<S: HostStorage>(
    storage: &mut S,
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

/// Resolves and fully preallocates one production mutation against an explicit committed epoch.
///
/// The mutation closure is restarted after lower reads exactly as it is in the driver. Its owned
/// output becomes observable only when resolve reaches a terminal success.
///
/// # Errors
///
/// Returns an error for resolve I/O, mutation rejection, reservation conflict, or fallible
/// preallocation before the first commit write.
fn prepare_core_mutation<S, F, R>(
    storage: &mut S,
    profile: &ext4_core::MountedProfile,
    epoch: &ext4_core::CommittedEpoch,
    coordinator: &ext4_core::MutationCoordinatorState,
    ticket: u64,
    mut mutate: F,
) -> TaskResult<(ext4_core::CommitReadyMutation, R)>
where
    S: HostStorage,
    F: for<'storage, 'epoch, 'crypto> FnMut(
        &mut ext4_core::MutationResolvePass<'storage, 'epoch, 'crypto>,
    ) -> ext4_core::Result<R>,
{
    let mut operation = ext4_core::MutationResolveOperation::new(profile);
    let mut event = ext4_core::OperationEvent::Admitted;
    let (resolved, output) = loop {
        let mut ready = operation.accept(event).map_err(core_task_error)?;
        let mut pass_output = None;
        let result = {
            let mut crypto = RejectingCryptographicOperation;
            let mut pass = ready.begin_pass(
                epoch,
                ext4_core::Ext4Timestamp::from_unix_seconds(1),
                &mut crypto,
            );
            match mutate(&mut pass) {
                Ok(output) => {
                    pass_output = Some(output);
                    pass.resolve(ticket, coordinator)
                }
                Err(error) => Err(error),
            }
        };
        match ready.finish(result) {
            ext4_core::MutationResolveTransition::SubmitLower { request, suspended } => {
                event = ext4_core::OperationEvent::StorageCompleted(complete_file_request(
                    storage, request,
                )?);
                operation = suspended;
            }
            ext4_core::MutationResolveTransition::Complete(result) => {
                let resolved = result.map_err(core_task_error)?;
                let output = pass_output.ok_or_else(|| {
                    io::Error::other("successful mutation resolve lost its owned output")
                })?;
                break (resolved, output);
            }
        }
    };
    let reserved = resolved
        .reserve(coordinator, ext4_core::MutationLease::granted(ticket))
        .map_err(core_task_error)?;
    let prepared = reserved
        .prepare_commit(coordinator, epoch, ext4_core::CommitLease::granted(ticket))
        .map_err(core_task_error)?;
    Ok((prepared, output))
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
fn prepare_volume_label_commit<S: HostStorage>(
    storage: &mut S,
    completed: Box<ext4_core::CompletedMount>,
    label: &[u8],
) -> TaskResult<(
    ext4_core::CommitReadyMutation,
    ext4_core::MutationCoordinatorState,
    u64,
)> {
    let (profile, epoch, mut coordinator) = (*completed).into_parts();
    let ticket = coordinator.admit_mutation().map_err(core_task_error)?;
    let (prepared, ()) =
        prepare_core_mutation(storage, &profile, &epoch, &coordinator, ticket, |pass| {
            pass.set_volume_label(ext4_core::Ext4VolumeLabel::new(label)?);
            Ok(())
        })?;
    Ok((prepared, coordinator, ticket))
}

/// Completes a fully preallocated mutation through commit publication and clean checkpoint.
///
/// # Errors
///
/// Returns an error for any lower write/flush failure or completion identity mismatch.
fn complete_prepared_mutation<S: HostStorage>(
    storage: &mut S,
    coordinator: &mut ext4_core::MutationCoordinatorState,
    ticket: u64,
    prepared: ext4_core::CommitReadyMutation,
) -> TaskResult<ext4_core::CommittedEpoch> {
    let ordered = complete_storage_sequence(storage, prepared.start())?;
    complete_file_request_checked(storage, ordered.flush_request())?;
    let payloads = complete_storage_sequence(storage, ordered.completed())?;
    complete_file_request_checked(storage, payloads.flush_request())?;
    let (commit_request, commit_durability) = payloads.completed().submit();
    complete_file_request_checked(storage, commit_request)?;
    complete_file_request_checked(storage, commit_durability.flush_request())?;
    let published = commit_durability
        .completed()
        .publish(coordinator, ext4_core::VisibilityLease::granted(ticket));
    let (epoch, checkpoint) = published.into_parts();
    let home = complete_storage_sequence(
        storage,
        checkpoint.start(ext4_core::CheckpointLease::granted(epoch.sequence())),
    )?;
    complete_file_request_checked(storage, home.flush_request())?;
    let (clean_request, clean_durability) = home.completed().submit();
    complete_file_request_checked(storage, clean_request)?;
    complete_file_request_checked(storage, clean_durability.flush_request())?;
    Ok(clean_durability.completed(coordinator))
}

/// Executes one typed mutation against a mounted image and cleanly closes the volume.
///
/// # Errors
///
/// Returns an error for admission, resolve, commit, checkpoint, clean-close, or host I/O failure.
fn drive_core_mutation<S, F, R>(
    storage: &mut S,
    completed: Box<ext4_core::CompletedMount>,
    mutate: F,
) -> TaskResult<R>
where
    S: HostStorage,
    F: for<'storage, 'epoch, 'crypto> FnMut(
        &mut ext4_core::MutationResolvePass<'storage, 'epoch, 'crypto>,
    ) -> ext4_core::Result<R>,
{
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.length(ext4_core::StorageTarget::Filesystem)?);
    let (profile, epoch, mut coordinator) = (*completed).into_parts();
    let ticket = coordinator.admit_mutation().map_err(core_task_error)?;
    let (prepared, output) =
        prepare_core_mutation(storage, &profile, &epoch, &coordinator, ticket, mutate)?;
    let _checkpointed_epoch =
        complete_prepared_mutation(storage, &mut coordinator, ticket, prepared)?;
    complete_core_clean_close(storage, filesystem_length, profile.journal_target())?;
    Ok(output)
}

/// Mounts one internal-journal image, executes a typed mutation, and cleanly closes it.
///
/// # Errors
///
/// Returns an error for image I/O or any production mount/mutation/close transition.
fn drive_internal_core_mutation<F, R>(image: &Path, mutate: F) -> TaskResult<R>
where
    F: for<'storage, 'epoch, 'crypto> FnMut(
        &mut ext4_core::MutationResolvePass<'storage, 'epoch, 'crypto>,
    ) -> ext4_core::Result<R>,
{
    let mut storage = FileStorageAdapter::open_internal(image)?;
    let completed = mount_internal_core(&mut storage)?;
    drive_core_mutation(&mut storage, completed, mutate)
}

/// Mounts one internal-journal image, executes a restartable committed-epoch read, and cleanly
/// closes it without manufacturing an empty mutation.
///
/// # Errors
///
/// Returns an error for image I/O, mount/read suspension, the terminal read result, or clean close.
fn drive_internal_core_read<F, R>(image: &Path, read: F) -> TaskResult<R>
where
    F: for<'storage, 'epoch> FnMut(
        &mut ext4_core::EpochReadPass<'_, 'storage, 'epoch>,
    ) -> ext4_core::Result<R>,
{
    drive_internal_core_read_observed(image, read).map(|(output, _lower_reads)| output)
}

/// Mounts one internal-journal image, executes a restartable committed-epoch read, and reports
/// how many lower reads the production operation submitted after mounting.
///
/// # Errors
///
/// Returns an error for image I/O, mount/read suspension, unexpected non-read I/O, the terminal
/// read result, request-count overflow, or clean close.
fn drive_internal_core_read_observed<F, R>(image: &Path, mut read: F) -> TaskResult<(R, usize)>
where
    F: for<'storage, 'epoch> FnMut(
        &mut ext4_core::EpochReadPass<'_, 'storage, 'epoch>,
    ) -> ext4_core::Result<R>,
{
    let mut storage = FileStorageAdapter::open_internal(image)?;
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.length(ext4_core::StorageTarget::Filesystem)?);
    let completed = mount_internal_core(&mut storage)?;
    let (profile, epoch, _coordinator) = (*completed).into_parts();
    let mut operation = ext4_core::EpochReadOperation::new(&profile);
    let mut event = ext4_core::OperationEvent::Admitted;
    let mut lower_reads = 0_usize;
    let output = loop {
        let mut crypto = RejectingCryptographicOperation;
        match operation.run(event, &epoch, &mut crypto, |pass| read(pass)) {
            ext4_core::ReadTransition::SubmitLower { request, suspended } => {
                if !matches!(&request, ext4_core::StorageRequest::Read { .. }) {
                    return Err(io::Error::other(
                        "committed read operation submitted non-read storage I/O",
                    )
                    .into());
                }
                lower_reads = lower_reads
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("lower read count overflow"))?;
                event = ext4_core::OperationEvent::StorageCompleted(complete_file_request(
                    &mut storage,
                    request,
                )?);
                operation = suspended;
            }
            ext4_core::ReadTransition::Complete(result) => {
                break result.map_err(core_task_error)?;
            }
        }
    };
    complete_core_clean_close(&mut storage, filesystem_length, profile.journal_target())?;
    Ok((output, lower_reads))
}

/// Mounts one external-journal image pair, executes a typed mutation, and cleanly closes it.
///
/// # Errors
///
/// Returns an error for image I/O or any production mount/mutation/close transition.
fn drive_external_core_mutation<F, R>(
    filesystem: &Path,
    external_journal: &Path,
    mutate: F,
) -> TaskResult<R>
where
    F: for<'storage, 'epoch, 'crypto> FnMut(
        &mut ext4_core::MutationResolvePass<'storage, 'epoch, 'crypto>,
    ) -> ext4_core::Result<R>,
{
    let mut storage = FileStorageAdapter::open_external(filesystem, external_journal)?;
    let completed = mount_external_core(&mut storage)?;
    drive_core_mutation(&mut storage, completed, mutate)
}

/// Mounts a clean image, commits a core-generated metadata transaction, and intentionally stops
/// before checkpoint so e2fsck becomes the independent replay implementation.
///
/// # Errors
///
/// Returns an error for mount/resolve/commit typestate failure or host image I/O failure.
fn drive_core_commit_without_checkpoint(image: &Path, label: &[u8]) -> TaskResult<()> {
    let mut storage = FileStorageAdapter::open_internal(image)?;
    let completed = mount_internal_core(&mut storage)?;
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
    Ok(())
}

/// Runs one preallocated production storage sequence and validates every exact completion.
///
/// # Errors
///
/// Returns an error for request I/O or completion identity mismatch.
fn complete_storage_sequence<S: HostStorage, Next>(
    storage: &mut S,
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
    storage: &mut impl HostStorage,
    request: ext4_core::StorageRequest,
) -> TaskResult<()> {
    let identity = ext4_core::StorageRequestIdentity::from_request(&request);
    let completion = complete_file_request(storage, request)?;
    identity.complete(completion).map_err(core_task_error)?;
    Ok(())
}

/// Cryptographic boundary used by unencrypted interoperability mutation resolve passes.
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
fn complete_file_request<S: HostStorage>(
    storage: &mut S,
    request: ext4_core::StorageRequest,
) -> TaskResult<ext4_core::StorageCompletion> {
    let transfer = match request {
        ext4_core::StorageRequest::Read {
            target,
            offset,
            mut buffer,
        } => {
            storage.read_exact(target, offset.get(), &mut buffer)?;
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
            storage.write_all(target, offset.get(), &buffer)?;
            ext4_core::CompletedStorageTransfer::Write {
                target,
                offset,
                buffer,
            }
        }
        ext4_core::StorageRequest::Flush { target } => {
            storage.flush(target)?;
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
fn combine_verification_and_cleanup<T>(
    operation: TaskResult<T>,
    cleanup: TaskResult<()>,
) -> TaskResult<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
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
    let _bundle = build_verified_production_bundle(repository_root)?;
    Ok(())
}

/// Runs the release umbrella and returns the atomically published evidence bundle.
///
/// # Errors
///
/// Returns an error on any portable, driver, interoperability, WDK, signing, reachability,
/// identity, source-drift, or publication failure.
fn build_verified_production_bundle(repository_root: &Path) -> TaskResult<PathBuf> {
    verify_portable(repository_root)?;
    verify_driver(repository_root)?;
    verify_journal_interop(repository_root)?;
    verify_htree_interop(repository_root)?;
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
    Ok(bundle_directory)
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
        ArtifactIdentity, CrashStorageAdapter, EffectCut, HostStorage, Sha256, StorageEffect, Task,
        TaskResult, UNVERIFIED_ARTIFACT_ID, WindowsKitVersion, comma_separated_blocks,
        copy_exact_bytes, effect_cut_stem, enumerate_effect_cuts, hash_source_record,
        jbd2_control_checksum, normalize_debugfs_commit_timestamp, normalize_debugfs_descriptor,
        normalized_manifest_value, parse_journal_fixture_manifest_text, read_be_u32,
        required_version_line,
    };
    use sha2::Digest as _;
    use std::{ffi::OsStr, fs, path::Path};

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

    /// Only the eight documented, semantically distinct workflows are accepted.
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
            Task::parse(OsStr::new("verify-htree-interop")),
            Some(Task::HtreeInterop)
        );
        assert_eq!(
            Task::parse(OsStr::new("verify-journal-fixture-provenance")),
            Some(Task::JournalFixtureProvenance)
        );
        assert_eq!(
            Task::parse(OsStr::new("verify-production-driver")),
            Some(Task::ProductionDriver)
        );
        assert_eq!(
            Task::parse(OsStr::new("check-live-driver-host")),
            Some(Task::CheckLiveDriverHost)
        );
        assert_eq!(
            Task::parse(OsStr::new("verify-live-vhdx")),
            Some(Task::VerifyLiveVhdx)
        );
        assert_eq!(
            Task::parse(OsStr::new("cleanup-live-vhdx-session")),
            Some(Task::CleanupLiveVhdxSession)
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

    /// Write effects expand to every atomic-sector prefix while flushes remain target-local cuts.
    ///
    /// # Panics
    ///
    /// Panics if sector-prefix enumeration skips an endpoint or accepts a non-sector write.
    #[test]
    fn fault_matrix_enumerates_atomic_write_prefixes_and_flushes() {
        let effects = [
            StorageEffect::Write {
                target: ext4_core::StorageTarget::Filesystem,
                bytes: 1024,
            },
            StorageEffect::Flush {
                target: ext4_core::StorageTarget::ExternalJournal,
            },
        ];
        let cuts = enumerate_effect_cuts(&effects);
        assert!(cuts.is_ok(), "sector-aligned effects must enumerate");
        assert_eq!(
            cuts.ok(),
            Some(vec![
                EffectCut {
                    effect: 1,
                    write_prefix: Some(0),
                },
                EffectCut {
                    effect: 1,
                    write_prefix: Some(512),
                },
                EffectCut {
                    effect: 1,
                    write_prefix: Some(1024),
                },
                EffectCut {
                    effect: 2,
                    write_prefix: None,
                },
            ])
        );
        assert_eq!(
            effect_cut_stem(EffectCut {
                effect: 2,
                write_prefix: None,
            }),
            "002-flush"
        );
        assert!(
            enumerate_effect_cuts(&[StorageEffect::Write {
                target: ext4_core::StorageTarget::Filesystem,
                bytes: 513,
            }])
            .is_err()
        );
    }

    /// A journal flush cannot make filesystem writes durable, and a filesystem write cut retains
    /// earlier ordered writes while dropping the selected write's unpersisted suffix.
    ///
    /// # Panics
    ///
    /// Panics if independently durable device state or write-prefix materialization regresses.
    #[test]
    fn crash_storage_keeps_device_durability_independent() {
        let root = std::env::temp_dir();
        let filesystem = root.join(format!(
            "ext4win-crash-adapter-{}-filesystem.img",
            std::process::id()
        ));
        let journal = root.join(format!(
            "ext4win-crash-adapter-{}-journal.img",
            std::process::id()
        ));
        let result = (|| -> TaskResult<()> {
            fs::write(&filesystem, [0xA1_u8; 1024])?;
            fs::write(&journal, [0xB2_u8; 1024])?;
            let mut storage = CrashStorageAdapter::open_external(&filesystem, &journal)?;
            storage.write_all(ext4_core::StorageTarget::Filesystem, 0, &[0xC3_u8; 512])?;
            storage.write_all(
                ext4_core::StorageTarget::ExternalJournal,
                0,
                &[0xD4_u8; 512],
            )?;
            storage.flush(ext4_core::StorageTarget::ExternalJournal)?;
            storage.write_all(ext4_core::StorageTarget::Filesystem, 512, &[0xE5_u8; 512])?;
            storage.materialize_write_prefix(ext4_core::StorageTarget::Filesystem, 0)?;
            drop(storage);

            let filesystem_bytes = fs::read(&filesystem)?;
            let journal_bytes = fs::read(&journal)?;
            assert_eq!(filesystem_bytes.get(..512), Some([0xC3_u8; 512].as_slice()));
            assert_eq!(filesystem_bytes.get(512..), Some([0xA1_u8; 512].as_slice()));
            assert_eq!(journal_bytes.get(..512), Some([0xD4_u8; 512].as_slice()));
            assert_eq!(journal_bytes.get(512..), Some([0xB2_u8; 512].as_slice()));
            Ok(())
        })();
        let filesystem_cleanup = fs::remove_file(&filesystem);
        let journal_cleanup = fs::remove_file(&journal);
        assert!(
            result.is_ok(),
            "crash adapter verification failed: {result:?}"
        );
        assert!(
            filesystem_cleanup.is_ok(),
            "filesystem fixture cleanup failed: {filesystem_cleanup:?}"
        );
        assert!(
            journal_cleanup.is_ok(),
            "journal fixture cleanup failed: {journal_cleanup:?}"
        );
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
