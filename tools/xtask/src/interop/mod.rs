use crate::{
    TaskResult,
    process::{run_checked, run_checked_output},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Seek as _, Write as _},
    path::Path,
    process::Command,
};

/// Owns independent JBD2, HTree, crash-cut, and fixture-provenance scenarios.
mod scenarios;

pub(crate) use scenarios::{
    verify_htree_interop, verify_journal_fixture_provenance, verify_journal_interop,
};

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
    /// Discovers and verifies the manifest-pinned e2fsprogs toolset.
    ///
    /// # Errors
    ///
    /// Returns an error instead of skipping when Linux, WSL, or any required executable is absent,
    /// or when the installed e2fsprogs release differs from the repository authority.
    fn require(expected_e2fsprogs_version: &str) -> TaskResult<Self> {
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

        let actual_e2fsprogs_version = environment.e2fsprogs_version()?;
        require_e2fsprogs_version(&actual_e2fsprogs_version, expected_e2fsprogs_version)?;

        for tool in ["debugfs", "e2fsck"] {
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

/// Enforces the repository's exact e2fsprogs release authority.
///
/// # Errors
///
/// Returns an error when the discovered release differs from the manifest-pinned release.
fn require_e2fsprogs_version(actual: &str, expected: &str) -> TaskResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "ext4 interoperability requires manifest-pinned e2fsprogs {expected}, found {actual}"
        ))
        .into())
    }
}

#[cfg(test)]
mod environment_tests {
    use super::require_e2fsprogs_version;

    /// The environment contract accepts only the exact manifest release token.
    ///
    /// # Panics
    ///
    /// Panics if exact equality is rejected or release drift is accepted.
    #[test]
    fn e2fsprogs_release_must_match_manifest_exactly() {
        assert!(require_e2fsprogs_version("1.47.2", "1.47.2").is_ok());
        assert!(require_e2fsprogs_version("1.47.0", "1.47.2").is_err());
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

/// Runs an internal-journal mount until normal completion or one selected storage effect.
/// # Errors
/// Returns an error for invalid boundary selection, host I/O, external discovery, or core rejection.
fn run_internal_mount_until_boundary(
    filesystem: &Path,
    cut: Option<EffectCut>,
) -> TaskResult<EffectBoundaryRun> {
    let mut storage = CrashStorageAdapter::open_internal(filesystem)?;
    let filesystem_length =
        ext4_core::DeviceLength::from_bytes(storage.length(ext4_core::StorageTarget::Filesystem)?);
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
            ext4_core::MountTransition::DiscoverExternalJournal { .. } => {
                return Err(io::Error::other(
                    "internal-journal fault image requested external discovery",
                )
                .into());
            }
            ext4_core::MountTransition::Complete(result) => {
                result.map_err(core_task_error)?;
                storage.materialize_durable()?;
                return Ok(controller.completed());
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
