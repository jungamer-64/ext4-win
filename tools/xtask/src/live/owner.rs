//! Owns disposable storage identity, external operation intents and ordered finalization.
use super::VerifierPlan;
use crate::{
    TaskResult, driver_load, fixture,
    process::{combine_verification_and_cleanup, run_checked, run_checked_output},
    production::build_verified_production_bundle,
    session::{Operation, Phase, Session, SessionId},
    storage::{self, DisposablePartition, Partition},
    windows,
};
use alloc::collections::BTreeSet;
use core::time::Duration;
use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::Instant,
};

#[path = "benchmark.rs"]
mod benchmark;

/// Storage and workload selected before the disposable session acquires resources.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum LiveWorkload {
    /// Existing filesystem and driver assurance scenario.
    Assurance,
    /// Independent random-I/O dataset and repeated native measurements.
    RandomIo,
}

/// WSL attachment stage; interrupted intent is not assumed to have rolled back.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum WslAttachment {
    /// No session attachment or unobserved WSL shutdown responsibility remains.
    Detached,
    /// Attachment may have been accepted.
    Requested,
    /// An identity-matched Linux device was observed.
    Attached,
    /// Detachment may already have committed; WSL shutdown still requires observation.
    Detaching,
}
/// Delegated driver lifecycle stage, separate from volume state and Driver Verifier admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DriverStage {
    /// No nested driver installation has been requested.
    Absent,
    /// Installation may have been accepted; exact package admission remains incomplete.
    Installing,
    /// Exact package/service identity was admitted and the service was observed stopped.
    Installed,
    /// Initial SCM start may have been accepted.
    Starting,
    /// SCM Running and exact installed package identity were observed.
    Running,
    /// Nested cleanup completed.
    Cleaned,
}
/// Narrow independent storage and driver identities saved for interruption recovery.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveState {
    /// Workload selected before storage construction and retained across activation.
    workload: LiveWorkload,
    /// GPT and volume identity cannot exist independently of their owning disk.
    storage: StorageIdentity,
    /// Independent WSL attachment progress.
    wsl: WslAttachment,
    /// Nested driver lifecycle progress.
    driver: DriverStage,
    /// Boot in which the session may have applied volatile Verifier settings.
    #[serde(default, rename = "verifier_selection_boot")]
    verifier_effect: Option<VerifierEffect>,
    /// Disposable ext4 UUID retained before identity-table effects and checked after restart.
    identity: Option<[u8; 16]>,
}

/// These effects have different release authorities within their originating boot.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum VerifierEffect {
    /// DIF runtime rule classes acquired by the live session.
    RuntimeRules {
        /// Boot in which the rules may have been enabled.
        boot: String,
    },
    /// A persistent record of a named volatile selection released by reboot.
    NamedSelection(String),
}

/// Monotonic acquisition of storage identity, independent of current attachment state.
#[derive(Debug, Serialize, Deserialize)]
enum StorageIdentity {
    /// The generated VHDX may exist, but no stable disk observation has been committed.
    Unobserved,
    /// The disk was observed; partition construction may still be incomplete.
    Disk {
        /// Stable disk unique identifier.
        unique: String,
    },
    /// Exact partition identity was published before format or driver discovery.
    Partition {
        /// Stable owning disk unique identifier.
        unique: String,
        /// GPT identifier, type and byte extent.
        partition: Partition,
        /// Optional Mount Manager observation for the exact partition.
        volume: Option<String>,
    },
}
impl LiveState {
    /// Borrows acquired disk identity without claiming current attachment.
    fn disk(&self) -> Option<&str> {
        match &self.storage {
            StorageIdentity::Unobserved => None,
            StorageIdentity::Disk { unique } | StorageIdentity::Partition { unique, .. } => {
                Some(unique)
            }
        }
    }
    /// Borrows acquired GPT identity; the representation also retains its owning disk.
    fn partition(&self) -> Option<&Partition> {
        match &self.storage {
            StorageIdentity::Partition { partition, .. } => Some(partition),
            _ => None,
        }
    }
    /// Borrows a Mount Manager observation, without authorizing mounted-volume operations.
    fn volume(&self) -> Option<&str> {
        match &self.storage {
            StorageIdentity::Partition { volume, .. } => volume.as_deref(),
            _ => None,
        }
    }
    /// Records the Mount Manager observation only within an acquired partition's identity.
    /// # Errors
    /// Returns a missing-partition protocol error or a changed persistent volume identity.
    fn observe_volume(&mut self, observed: String) -> TaskResult<()> {
        match &mut self.storage {
            StorageIdentity::Partition { volume, .. } => {
                if volume
                    .as_ref()
                    .is_some_and(|previous| !previous.eq_ignore_ascii_case(&observed))
                {
                    return Err(io::Error::other(
                        "the same GPT partition acquired a different volume GUID",
                    )
                    .into());
                }
                *volume = Some(observed);
                Ok(())
            }
            _ => Err(
                io::Error::other("volume observation requires acquired partition identity").into(),
            ),
        }
    }
}

/// Executes a native WSL command with explicit root and deterministic tool search path.
/// # Errors
/// Returns requester or external command errors.
fn wsl_output(arguments: &[OsString]) -> TaskResult<Output> {
    let mut command = Command::new("wsl.exe");
    if arguments
        .first()
        .is_some_and(|argument| argument == "--exec")
    {
        command.args([
            "--user",
            "root",
            "--exec",
            "/usr/bin/env",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL=C",
        ]);
        command.args(arguments.iter().skip(1));
    } else {
        command.args(arguments);
    }
    run_checked_output(command, "WSL session operation")
}

/// Decodes a WSL management response whose output is text.
/// # Errors
/// Returns command or response encoding errors.
fn wsl(arguments: &[OsString]) -> TaskResult<String> {
    Ok(String::from_utf8(wsl_output(arguments)?.stdout)?)
}
/// Converts static WSL arguments without a shell interpretation boundary.
/// # Errors
/// Returns WSL operation failures.
fn wsl_words(arguments: &[&str]) -> TaskResult<String> {
    wsl(&arguments.iter().map(OsString::from).collect::<Vec<_>>())
}
/// Converts a Windows-host path into one absolute Linux path.
/// # Errors
/// Returns ambiguous or nonabsolute WSL conversion output.
fn linux_path(path: &Path) -> TaskResult<String> {
    let output = wsl(&[
        OsString::from("--exec"),
        OsString::from("wslpath"),
        OsString::from("-a"),
        path.as_os_str().to_owned(),
    ])?;
    let mut lines = output.lines();
    let path = lines
        .next()
        .filter(|path| path.starts_with('/'))
        .ok_or_else(|| io::Error::other("WSL path is not absolute"))?;
    if lines.next().is_some() {
        return Err(io::Error::other("ambiguous WSL path").into());
    }
    Ok(path.into())
}

/// Derives storage path from the session's validated directory rather than storing a second path authority.
fn vhdx(session: &Session<LiveState>) -> PathBuf {
    session.directory().join("disk.vhdx")
}
/// Builds the narrow partition scope from already recorded identities.
/// # Errors
/// Returns missing disk or partition identity.
fn scope(session: &Session<LiveState>) -> TaskResult<DisposablePartition> {
    Ok(DisposablePartition {
        vhdx: vhdx(session),
        disk: session
            .state()
            .disk()
            .map(str::to_owned)
            .ok_or_else(|| io::Error::other("session disk identity absent"))?,
        partition: session
            .state()
            .partition()
            .cloned()
            .ok_or_else(|| io::Error::other("session partition identity absent"))?,
    })
}
/// Matches one safely named Linux partition by both GPT identity and type.
/// # Errors
/// Returns missing or ambiguous partition matches or malformed GUIDs.
fn linux_partition(layout: &str, partition: &Partition) -> TaskResult<String> {
    let mut matches = Vec::new();
    for line in layout.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let [name, "part", id, kind] = fields.as_slice() else {
            continue;
        };
        if !name.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            continue;
        }
        let Ok(id) = windows_host::guid_bytes(id) else {
            continue;
        };
        let Ok(kind) = windows_host::guid_bytes(kind) else {
            continue;
        };
        if id == partition.id && kind == partition.kind {
            matches.push((*name).to_owned());
        }
    }
    let [name] = matches.as_slice() else {
        return Err(io::Error::other(
            "WSL did not expose exactly one identity-matched session partition",
        )
        .into());
    };
    Ok(name.clone())
}

/// Identifies each phase that requires separate Verifier evidence.
#[derive(Clone, Copy)]
enum VerifierObservation {
    /// Runtime flags before exercising the mounted filesystem.
    BeforeFilesystemIo,
    /// Runtime flags after remount and before the first unload.
    BeforeAttachedUnload,
    /// Runtime flags before exercising storage hot attachment.
    BeforeHotAttach,
    /// Runtime flags after exercising storage hot attachment.
    AfterHotAttach,
}

impl VerifierObservation {
    /// Stable report names retain the evidence independently for each load and I/O phase.
    const fn file_name(self) -> &'static str {
        match self {
            Self::BeforeFilesystemIo => "verifier-before-filesystem-io.txt",
            Self::BeforeAttachedUnload => "verifier-before-attached-unload.txt",
            Self::BeforeHotAttach => "verifier-before-hot-attach.txt",
            Self::AfterHotAttach => "verifier-after-hot-attach.txt",
        }
    }
}

/// Parses current-boot Driver Verifier activity and requires the requested observation.
/// # Errors
/// Returns unknown/localized, ambiguous, insufficient or unloaded reports.
fn verifier_activity(report: &str) -> TaskResult<()> {
    let mut flags = Vec::new();
    let mut modules = Vec::new();
    for line in report.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower
            .strip_prefix("verifier flags:")
            .or_else(|| lower.strip_prefix("verify flags level"))
        {
            let value = value
                .trim()
                .strip_prefix("0x")
                .ok_or_else(|| io::Error::other("invalid Verifier flags"))?;
            flags.push(u32::from_str_radix(value, 16)?);
        }
        if let Some(value) = lower.strip_prefix("module:") {
            let value = value.trim();
            if let Some(value) = value.strip_prefix("ext4win.sys ") {
                let value = value
                    .trim()
                    .strip_prefix("(load:")
                    .and_then(|value| value.strip_suffix(')'))
                    .ok_or_else(|| io::Error::other("invalid Verifier module counters"))?;
                let (loads, unloads) = value
                    .split_once("/ unload:")
                    .ok_or_else(|| io::Error::other("invalid Verifier module counters"))?;
                modules.push((loads.trim().parse::<u64>()?, unloads.trim().parse::<u64>()?));
            }
        }
    }
    let ([flags], [(loads, unloads)]) = (flags.as_slice(), modules.as_slice()) else {
        return Err(io::Error::other(
            "runtime Verifier report must identify flags and exactly one ext4win.sys module",
        )
        .into());
    };
    if loads <= unloads {
        return Err(io::Error::other("Verifier does not observe ext4win.sys loaded").into());
    }
    if flags & 0x0002_091b != 0x0002_091b {
        return Err(io::Error::other(format!(
            "required runtime Verifier checks are missing from flags {flags:#010x}"
        ))
        .into());
    }
    Ok(())
}

/// Queries live activity independently of the receipt of a configuration command.
/// # Errors
/// Returns a command or text encoding error.
fn query_verifier() -> TaskResult<String> {
    let mut command = Command::new("verifier.exe");
    command.arg("/query");
    let output = run_checked_output(command, "Driver Verifier runtime query")?;
    Ok(String::from_utf8(output.stdout)?)
}

/// Requires a current boot without another active Verifier selection.
/// # Errors
/// Returns an observation error or a report that does not establish inactivity.
fn require_idle_verifier() -> TaskResult<()> {
    let report = query_verifier()?;
    if report.trim() != "No drivers are currently verified." {
        return Err(io::Error::other(format!("Driver Verifier is not idle: {report}")).into());
    }
    Ok(())
}

/// Observes and retains the loaded driver's distinct current-boot reports.
/// # Errors
/// Returns query, evidence write or runtime-activity validation failures.
fn observe_verifier(
    session: &mut Session<LiveState>,
    observation: VerifierObservation,
) -> TaskResult<()> {
    let report = query_verifier()?;
    fs::write(session.directory().join(observation.file_name()), &report)?;
    verifier_activity(&report)?;
    session.publish(Phase::Observed(Operation::ObserveVerifier))
}

/// Identifies the boot in which a volatile selection exists.
/// # Errors
/// Returns management errors or an unrecognized boot timestamp.
fn verifier_boot() -> TaskResult<String> {
    let observed = windows::management(
        "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')",
        Duration::from_secs(30),
    )?;
    observed
        .as_str()
        .filter(|boot| !boot.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("Windows boot timestamp is unavailable").into())
}

/// Checks the native operation status, which may report failure after process exit zero.
/// # Errors
/// Returns a missing, ambiguous, malformed or unsuccessful DIF status.
fn require_dif_success(report: &str) -> TaskResult<()> {
    let mut statuses = report
        .lines()
        .filter_map(|line| line.trim().strip_prefix("\"StatusCode\":"));
    let status = statuses
        .next()
        .and_then(|value| value.trim().strip_prefix("0x"))
        .ok_or_else(|| io::Error::other("Driver Verifier DIF receipt lacks a status"))?;
    let status = u32::from_str_radix(status, 16)?;
    if statuses.next().is_some() {
        return Err(io::Error::other("Driver Verifier DIF receipt has ambiguous status").into());
    }
    if status != 0 {
        return Err(
            io::Error::other(format!("Driver Verifier DIF returned {status:#010x}")).into(),
        );
    }
    Ok(())
}

/// Prints the control diagnostics before evaluating the native result.
/// # Errors
/// Returns process, diagnostic output, encoding or native DIF status errors.
fn run_dif(command: Command, description: &str) -> TaskResult<()> {
    let output = run_checked_output(command, description)?;
    io::stdout().write_all(&output.stdout)?;
    io::stderr().write_all(&output.stderr)?;
    require_dif_success(&String::from_utf8(output.stdout)?)
}

/// Releases this session's current-boot DIF settings after image departure.
/// # Errors
/// Leaves the boot ownership in place when Verifier does not confirm cleanup.
fn release_runtime_verifier(session: &mut Session<LiveState>) -> TaskResult<()> {
    let Some(effect) = session.state().verifier_effect.as_ref() else {
        return Ok(());
    };
    if session.state().driver != DriverStage::Cleaned {
        return Err(
            io::Error::other("Verifier release requires observed driver image departure").into(),
        );
    }
    let current_boot = verifier_boot()?;
    match effect {
        VerifierEffect::RuntimeRules { boot } if boot == &current_boot => {
            session.publish(Phase::Intent(Operation::DeactivateVerifier))?;
            let mut command = Command::new("verifier.exe");
            command.arg("/stop");
            run_dif(command, "release session Driver Verifier runtime rules")?;
            require_idle_verifier()?;
        }
        VerifierEffect::NamedSelection(boot) if boot == &current_boot => {
            return Err(io::Error::other(
                "named volatile Verifier selection requires a reboot before session cleanup can complete",
            ).into());
        }
        _ => {}
    }
    session.state_mut().verifier_effect = None;
    session.publish(Phase::Observed(Operation::DeactivateVerifier))
}

/// Applies rules only when the session owns the runtime configuration.
/// The boot-configured guest supplies rule classes from the start of each load.
/// # Errors
/// Returns activation, runtime query or insufficient activity errors.
fn verify_loaded_image(
    session: &mut Session<LiveState>,
    verifier: VerifierPlan,
    observation: VerifierObservation,
) -> TaskResult<()> {
    if verifier == VerifierPlan::Runtime {
        if session.state().verifier_effect.is_none() {
            session.state_mut().verifier_effect = Some(VerifierEffect::RuntimeRules {
                boot: verifier_boot()?,
            });
        }
        session.publish(Phase::Intent(Operation::ActivateVerifier))?;
        let mut command = Command::new("verifier.exe");
        command.args([
            "/dif",
            "1",
            "2",
            "4",
            "5",
            "9",
            "12",
            "18",
            "/now",
            "/driver",
            "ext4win.sys",
        ]);
        run_dif(command, "live Driver Verifier activation")?;
        session.publish(Phase::Observed(Operation::ActivateVerifier))?;
    }
    observe_verifier(session, observation)
}

/// Checks live-host prerequisites without storage, package or driver mutation.
/// # Errors
/// Returns any hosted preflight, Hyper-V, WSL or e2fsprogs prerequisite failure.
pub(crate) fn check_live_driver_host(root: &Path) -> TaskResult<()> {
    driver_load::check_hosted_driver_host(root)?;
    windows::management(
        "@('New-VHD','Get-VHD','Mount-VHD','Dismount-VHD','Get-Disk','Set-Disk','Initialize-Disk','New-Partition','verifier.exe','mountvol.exe','fsutil.exe') | ForEach-Object { Get-Command $_ -ErrorAction Stop | Out-Null }; $true",
        Duration::from_secs(60),
    )?;
    wsl_words(&["--status"])?;
    wsl_words(&["--exec", "mke2fs", "-V"])?;
    println!("live VHDX host contract: PASS");
    Ok(())
}

/// Records intent and executes one Hyper-V attachment/detachment boundary.
/// # Errors
/// Returns phase publication or native management failures; intent remains recoverable.
fn attachment(session: &mut Session<LiveState>, attach: bool) -> TaskResult<()> {
    let operation = if attach {
        Operation::AttachWindows
    } else {
        Operation::DetachWindows
    };
    let command = if attach { "Mount-VHD" } else { "Dismount-VHD" };
    let path = windows::literal(vhdx(session).as_os_str())?;
    session.publish(Phase::Intent(operation))?;
    windows::management(
        &format!("{command} -Path {path} | Out-Null; $true"),
        Duration::from_secs(60),
    )?;
    session.publish(Phase::Observed(operation))
}
/// Creates a new fixed-size VHDX, records disk identity and independently captures its Linux data GPT extent.
/// # Errors
/// Returns construction, partition, identity or durable publication failures.
fn create_storage(session: &mut Session<LiveState>, workload: LiveWorkload) -> TaskResult<()> {
    let path = windows::literal(vhdx(session).as_os_str())?;
    session.publish(Phase::Intent(Operation::CreateVhdx))?;
    let bytes = match workload {
        LiveWorkload::Assurance => 268_435_456_u64,
        LiveWorkload::RandomIo => 2_147_483_648,
    };
    windows::management(
        &format!("New-VHD -Path {path} -Fixed -SizeBytes {bytes} | Out-Null; $true"),
        Duration::from_secs(300),
    )?;
    session.publish(Phase::Observed(Operation::CreateVhdx))?;
    attachment(session, true)?;
    let disk = storage::disk(&vhdx(session))?
        .ok_or_else(|| io::Error::other("new VHDX did not identify a disk"))?;
    session.state_mut().storage = StorageIdentity::Disk {
        unique: disk.unique.clone(),
    };
    session.publish(Phase::Observed(Operation::AttachWindows))?;
    session.publish(Phase::Intent(Operation::Partition))?;
    windows::management(
        &format!(
            "Set-Disk -Number {} -IsOffline $false; Set-Disk -Number {} -IsReadOnly $false; Initialize-Disk -Number {} -PartitionStyle GPT | Out-Null; New-Partition -DiskNumber {} -UseMaximumSize -GptType '{{0FC63DAF-8483-4772-8E79-3D69D8477DE4}}' | Out-Null; $true",
            disk.number, disk.number, disk.number, disk.number
        ),
        Duration::from_secs(120),
    )?;
    let partition = storage::constructed_partition(&disk)?;
    session.state_mut().storage = StorageIdentity::Partition {
        unique: disk.unique,
        partition,
        volume: None,
    };
    session.publish(Phase::Observed(Operation::Partition))?;
    storage::validate(&scope(session)?)?;
    attachment(session, false)
}

/// Acquires the WSL partition mapping only for the owned VHDX and its recorded GPT identity.
/// # Errors
/// Returns device-difference, GPT identity or attachment failures.
fn attach_wsl_partition(session: &mut Session<LiveState>) -> TaskResult<String> {
    if session.state().wsl != WslAttachment::Detached || storage::disk(&vhdx(session))?.is_some() {
        return Err(io::Error::other("WSL acquisition requires a detached session VHDX").into());
    }
    let before = wsl_words(&["--exec", "lsblk", "-dn", "-o", "NAME"])?;
    session.state_mut().wsl = WslAttachment::Requested;
    session.publish(Phase::Intent(Operation::AttachWsl))?;
    wsl(&[
        "--mount".into(),
        "--vhd".into(),
        vhdx(session).into_os_string(),
        "--bare".into(),
    ])?;
    let after = wsl_words(&["--exec", "lsblk", "-dn", "-o", "NAME"])?;
    let before: BTreeSet<_> = before.lines().collect();
    let added: Vec<_> = after
        .lines()
        .filter(|name| !before.contains(name))
        .collect();
    let [device] = added.as_slice() else {
        return Err(io::Error::other("WSL attach did not expose exactly one new device").into());
    };
    if device.is_empty() || !device.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(io::Error::other("WSL returned an unsafe block device name").into());
    }
    let device = format!("/dev/{device}");
    let layout = wsl_words(&[
        "--exec",
        "lsblk",
        "-nr",
        "-o",
        "NAME,TYPE,PARTUUID,PARTTYPE",
        &device,
    ])?;
    let partition = session
        .state()
        .partition()
        .ok_or_else(|| io::Error::other("partition not published before format"))?;
    let partition = format!("/dev/{}", linux_partition(&layout, partition)?);
    session.state_mut().wsl = WslAttachment::Attached;
    session.publish(Phase::Observed(Operation::AttachWsl))?;
    Ok(partition)
}

/// Formats and populates through Linux tools before any Windows-driver mount can occur.
/// # Errors
/// Returns device-difference, GPT identity, oracle, helper or WSL detachment failures.
fn format_storage(
    session: &mut Session<LiveState>,
    helper: &Path,
    workload: LiveWorkload,
) -> TaskResult<()> {
    let partition = attach_wsl_partition(session)?;
    session.publish(Phase::Intent(Operation::Format))?;
    wsl_words(&[
        "--exec",
        "mke2fs",
        "-t",
        "ext4",
        "-F",
        "-b",
        "4096",
        "-O",
        "metadata_csum,64bit",
        &partition,
    ])?;
    wsl_words(&[
        "--exec",
        "debugfs",
        "-w",
        "-R",
        "mkdir /live-ci",
        &partition,
    ])?;
    wsl_words(&[
        "--exec",
        "debugfs",
        "-w",
        "-R",
        "set_inode_field /live-ci mode 040755",
        &partition,
    ])?;
    for field in [
        "set_inode_field /live-ci uid 1000",
        "set_inode_field /live-ci gid 100",
    ] {
        wsl_words(&["--exec", "debugfs", "-w", "-R", field, &partition])?;
    }
    let stat = wsl_words(&["--exec", "debugfs", "-R", "stat /live-ci", &partition])?;
    if !stat
        .split_whitespace()
        .collect::<Vec<_>>()
        .array_windows::<2>()
        .any(|words| matches!(words, ["Mode:", "0755"]))
    {
        return Err(
            io::Error::other("test directory lacks explicit POSIX write permission").into(),
        );
    }
    let helper = linux_path(helper)?;
    wsl_words(&["--exec", &helper, "live-directory", &partition])?;
    if matches!(workload, LiveWorkload::RandomIo) {
        wsl_words(&["--exec", &helper, "live-random-files", &partition])?;
    }
    wsl_words(&["--exec", "e2fsck", "-fn", &partition])?;
    session.publish(Phase::Observed(Operation::Format))?;
    finish_wsl(session, wsl)?;
    Ok(())
}

/// Rejects pending journal recovery, which a read-only e2fsck can skip.
/// # Errors
/// Returns missing or ambiguous superblock observations, an unclean state or pending recovery.
fn require_clean_superblock(report: &str) -> TaskResult<()> {
    let mut states = report
        .lines()
        .filter_map(|line| line.strip_prefix("Filesystem state:"))
        .map(str::trim);
    let mut features = report
        .lines()
        .filter_map(|line| line.strip_prefix("Filesystem features:"));
    let features = match (features.next(), features.next()) {
        (Some(features), None) => features,
        _ => return Err(io::Error::other("ambiguous debugfs filesystem features").into()),
    };
    if states.next() != Some("clean")
        || states.next().is_some()
        || features
            .split_whitespace()
            .any(|feature| feature == "needs_recovery")
    {
        return Err(io::Error::other("Linux observed an unclean ext4 superblock").into());
    }
    Ok(())
}

/// Checks the values independently reported by debugfs for the Windows-created inode.
/// # Errors
/// Returns an incomplete, ambiguous or differing field observation.
fn require_persisted_probe_metadata(report: &str) -> TaskResult<()> {
    for (field, expected) in [
        ("Type:", "regular"),
        ("Mode:", "0644"),
        ("User:", "1000"),
        ("Group:", "100"),
        ("Links:", "1"),
    ] {
        let mut values = report
            .split_whitespace()
            .zip(report.split_whitespace().skip(1))
            .filter_map(|(label, value)| (label == field).then_some(value));
        if values.next() != Some(expected) || values.next().is_some() {
            return Err(io::Error::other(format!("persisted probe has unexpected {field}")).into());
        }
    }
    Ok(())
}

/// Validates the original post-I/O disk using read-only Linux tools after unload.
/// # Errors
/// Returns identity, clean-filesystem, Windows-created file or WSL finalization failures.
fn verify_persisted_storage(session: &mut Session<LiveState>, payload: &[u8]) -> TaskResult<()> {
    if session.state().driver != DriverStage::Cleaned {
        return Err(io::Error::other("Linux inspection requires completed driver cleanup").into());
    }
    let partition = attach_wsl_partition(session)?;
    session.publish(Phase::Intent(Operation::InspectFilesystem))?;
    let superblock = wsl_words(&["--exec", "debugfs", "-R", "stats -h", &partition])?;
    require_clean_superblock(&superblock)?;
    let report = wsl_words(&["--exec", "e2fsck", "-f", "-n", &partition])?;
    println!("Post-I/O e2fsck:\n{report}");
    let metadata = wsl_words(&[
        "--exec",
        "debugfs",
        "-R",
        "stat /live-ci/alpha.bin",
        &partition,
    ])?;
    println!("Post-I/O debugfs stat:\n{metadata}");
    require_persisted_probe_metadata(&metadata)?;
    let arguments = [
        "--exec",
        "debugfs",
        "-R",
        "cat /live-ci/alpha.bin",
        &partition,
    ];
    if wsl_output(&arguments.map(OsString::from))?.stdout != payload {
        return Err(
            io::Error::other("Linux readback differs from the Windows-written payload").into(),
        );
    }
    session.publish(Phase::Observed(Operation::InspectFilesystem))?;
    finish_wsl(session, wsl)?;
    println!("live VHDX post-I/O filesystem integrity: PASS");
    Ok(())
}

/// Reconciles the recorded GPT identity and observes WSL shutdown before releasing attachment
/// responsibility. Missing partition data cannot prove that an earlier attachment rolled back.
/// # Errors
/// Returns ambiguous identity, external operation or record-publication failure. Every failure
/// before the observed shutdown retains a non-detached durable state for the next owner.
fn finish_wsl(
    session: &mut Session<LiveState>,
    mut execute: impl FnMut(&[OsString]) -> TaskResult<String>,
) -> TaskResult<()> {
    if session.state().wsl == WslAttachment::Detached {
        return Ok(());
    }
    let layout = execute(
        &[
            "--exec",
            "lsblk",
            "-nr",
            "-o",
            "NAME,TYPE,PARTUUID,PARTTYPE",
        ]
        .map(OsString::from),
    )?;
    let partition = session
        .state()
        .partition()
        .ok_or_else(|| io::Error::other("WSL attachment has no recorded partition"))?;
    let id = partition.id;
    let matching = layout
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .nth(2)
                .and_then(|id| windows_host::guid_bytes(id).ok())
                == Some(id)
        })
        .count();
    if matching > 1 {
        return Err(
            io::Error::other("WSL recovery sees ambiguous session partition identity").into(),
        );
    }
    session.state_mut().wsl = WslAttachment::Detaching;
    if matching == 1 {
        session.publish(Phase::Intent(Operation::DetachWsl))?;
        execute(&["--unmount".into(), vhdx(session).into_os_string()])?;
        session.publish(Phase::Observed(Operation::DetachWsl))?;
    }
    session.publish(Phase::Intent(Operation::ShutdownWsl))?;
    execute(&["--shutdown".into()])?;
    session.state_mut().wsl = WslAttachment::Detached;
    session.publish(Phase::Observed(Operation::ShutdownWsl))
}

/// Waits for Mount Manager registration and creates only the owner-generated directory mount point.
/// # Errors
/// Returns changed identity, absent discovery, mount or publication failures.
fn mount_namespace(session: &mut Session<LiveState>) -> TaskResult<PathBuf> {
    let identity = storage::validate(&scope(session)?)?;
    let start = Instant::now();
    let volume = loop {
        if let Some(volume) = windows_host::find_volume(&identity)? {
            break volume;
        }
        if start.elapsed() >= Duration::from_secs(30) {
            return Err(io::Error::other(
                "Linux data GUID volume was not registered with Mount Manager",
            )
            .into());
        }
        thread::sleep(Duration::from_millis(200));
    };
    storage::validate(&scope(session)?)?;
    session.state_mut().observe_volume(volume.clone())?;
    session.publish(Phase::Intent(Operation::MountNamespace))?;
    let mount = session.directory().join("mount");
    fs::create_dir(&mount)?;
    let mut command = Command::new("mountvol.exe");
    command.arg(&mount).arg(volume);
    run_checked(command, "session volume namespace mount")?;
    session.publish(Phase::Observed(Operation::MountNamespace))?;
    Ok(mount)
}
/// Removes only the matching mount-point binding, followed by its empty generated directory.
/// # Errors
/// Returns changed volume targets, namespace withdrawal or empty-directory removal failures.
fn remove_namespace(session: &mut Session<LiveState>) -> TaskResult<()> {
    let mount = session.directory().join("mount");
    let metadata = match fs::symlink_metadata(&mount) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_attributes() & 0x400 != 0 {
        let mut trailing = mount.as_os_str().to_owned();
        trailing.push("\\");
        let volume = windows_host::volume_at_mount(Path::new(&trailing))?;
        if session.state().volume() != Some(&volume) {
            return Err(io::Error::other("session mount point targets a different volume").into());
        }
        session.publish(Phase::Intent(Operation::RemoveNamespace))?;
        let mut command = Command::new("mountvol.exe");
        command.arg(&mount).arg("/D");
        run_checked(command, "session namespace removal")?;
    }
    fs::remove_dir(&mount)?;
    session.publish(Phase::Observed(Operation::RemoveNamespace))
}

/// Executes file I/O and exact native cursor tests, recording durable content before clean dismount.
/// # Errors
/// Returns observable filesystem, native protocol, timing-evidence or finalization failures.
fn exercise_io(session: &mut Session<LiveState>, mount: &Path) -> TaskResult<Vec<u8>> {
    let root = mount.join("live-ci");
    let alpha = root.join("alpha.bin");
    let beta = root.join("beta.bin");
    let payload: Vec<_> = (0_usize..8192)
        .map(|index| u8::try_from(index % 251).map_err(io::Error::other))
        .collect::<io::Result<_>>()?;
    session.publish(Phase::Intent(Operation::FilesystemIo))?;
    println!("live filesystem I/O: create payload file");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&alpha)?;
    println!("live filesystem I/O: write payload");
    let operation = file.write_all(&payload).map_err(Into::into);
    println!("live filesystem I/O: close payload handle");
    combine_verification_and_cleanup(
        operation,
        windows_host::close_file(file).map_err(Into::into),
    )?;
    println!("live filesystem I/O: verify existing-file reset and creation attributes");
    let reset_path = root.join("reset.bin");
    windows_host::verify_existing_file_reset(&reset_path)?;
    println!("live filesystem I/O: verify allocation reservation and release");
    windows_host::verify_allocation_control(&reset_path)?;
    println!("live filesystem I/O: verify handle-local timestamp suppression");
    windows_host::verify_timestamp_suppression(&reset_path)?;
    println!("live filesystem I/O: verify native file positions");
    windows_host::verify_file_positions(&reset_path)?;
    println!("live filesystem I/O: verify hard-link deletion and coalescing rename");
    windows_host::verify_hard_link_lifecycle(
        &root,
        windows_host::NamespaceAccess::RestorePrivilege,
    )?;
    println!("live filesystem I/O: verify short-name opens, collisions, hard links and tunneling");
    windows_host::verify_short_name_lifecycle(
        &root,
        windows_host::NamespaceAccess::RestorePrivilege,
    )?;
    println!("live filesystem I/O: verify file metadata");
    windows_host::verify_metadata(&alpha, "\\live-ci\\alpha.bin", 8_192)?;
    println!("live filesystem I/O: query created-file security");
    let descriptor = windows_host::file_security(&alpha)?;
    let expected = ext4_core::Ext4Security::new(
        ext4_core::Ext4Owner::new(
            ext4_core::Ext4Uid::from_u32(1000),
            ext4_core::Ext4Gid::from_u32(100),
        ),
        ext4_core::Ext4Permissions::new(0o644)
            .map_err(|error| io::Error::other(format!("{error:?}")))?,
    );
    let actual = ext4_security::Descriptor::decode(
        &descriptor,
        &fixture_identity()?,
        ext4_security::Components::ALL,
        &ext4_core::Ext4Access::from_mode(expected),
    )
    .map_err(|error| io::Error::other(format!("{error:?}")))?;
    if actual != expected {
        return Err(io::Error::other(
            "created inode owner/group/mode differs from effective identity",
        )
        .into());
    }
    for attempt in 1..=2 {
        println!("live filesystem I/O: set unchanged created-file DACL ({attempt})");
        windows_host::set_file_dacl(&alpha, &descriptor)?;
        println!("live filesystem I/O: query security round trip ({attempt})");
        if windows_host::file_security(&alpha)? != descriptor {
            return Err(
                io::Error::other("native security descriptor round trip changed metadata").into(),
            );
        }
    }
    println!("live filesystem I/O: read back payload");
    if fs::read(&alpha)? != payload {
        return Err(io::Error::other("live readback differs from payload").into());
    }
    println!("live filesystem I/O: verify explicit namespace-delete refusal");
    match fs::rename(&alpha, &beta) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
        Err(error) => return Err(error.into()),
        Ok(()) => {
            return Err(io::Error::other("inode rwx unexpectedly granted namespace DELETE").into());
        }
    }
    exercise_identity_update(session, &alpha)?;
    println!("live filesystem I/O: open durability handle");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(0x8000_0000)
        .open(&alpha)?;
    println!("live filesystem I/O: flush payload");
    let operation = file.sync_all().map_err(Into::into);
    println!("live filesystem I/O: close durability handle");
    combine_verification_and_cleanup(
        operation,
        windows_host::close_file(file).map_err(Into::into),
    )?;
    let directory = root.join("large-directory");
    println!("live filesystem I/O: verify native directory cursor contracts");
    windows_host::verify_directory(&directory)?;
    println!("live filesystem I/O: enumerate 100000 directory entries");
    let start = Instant::now();
    let mut first = None;
    let mut seen = BTreeSet::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        if first.is_none() {
            first = Some(start.elapsed().as_secs_f64() * 1000.0);
        }
        if !seen.insert(entry.file_name()) {
            return Err(io::Error::other("large directory returned a duplicate name").into());
        }
        if seen.len().is_multiple_of(10000) {
            println!(
                "live filesystem I/O: enumerated {} directory entries",
                seen.len()
            );
        }
    }
    if seen.len() != 100000 {
        return Err(io::Error::other(
            "large directory enumeration count differs from independent fixture",
        )
        .into());
    }
    for index in 0..100000 {
        if !seen.contains(&OsString::from(format!("entry-{index:06}"))) {
            return Err(io::Error::other("large directory omitted an expected name").into());
        }
    }
    fs::write(
        session.directory().join("directory-enumeration.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"entries": seen.len(), "first_ms": first, "total_ms": start.elapsed().as_secs_f64() * 1000.0}),
        )?,
    )?;
    println!("live filesystem I/O: validate storage identity");
    storage::validate(&scope(session)?)?;
    session.publish(Phase::Observed(Operation::FilesystemIo))?;
    println!("live filesystem I/O: PASS");
    Ok(payload)
}

/// Replaces once after authoritative generation observation; acknowledgement failure is never retried.
/// # Errors
/// Returns uncertain query/effect, generation exhaustion or non-applied publication failure.
fn replace_identity(
    session: &mut Session<LiveState>,
    uuid: ext4_core::FilesystemUuid,
    map: ext4_security::IdentityMap,
) -> TaskResult<()> {
    let current = windows_host::query_identity(uuid)?;
    if current.outcome == ext4_security::PublicationOutcome::Unknown
        || current.saved_generation != current.active.generation
    {
        return Err(io::Error::other(
            "identity publication requires reconciliation before replacement",
        )
        .into());
    }
    let generation = current
        .active
        .generation
        .checked_add(1)
        .ok_or_else(|| io::Error::other("identity generation exhausted"))?;
    let replacement = ext4_security::Replacement::new(
        current.active.generation,
        ext4_security::MappingSnapshot {
            uuid,
            generation,
            map,
        },
    )
    .map_err(|error| io::Error::other(format!("{error:?}")))?;
    session.state_mut().identity = Some(uuid.bytes());
    session.publish(Phase::Intent(Operation::IdentityMapping))?;
    let result = windows_host::replace_identity(replacement)?;
    if result.outcome != ext4_security::PublicationOutcome::Applied
        || result.active.generation != generation
    {
        return Err(
            io::Error::other("identity replacement did not apply its durable successor").into(),
        );
    }
    session.publish(Phase::Observed(Operation::IdentityMapping))
}
/// Builds the explicit disposable fixture's user and primary-group bindings.
/// # Errors
/// Returns native effective-token or mapping validation failure.
fn fixture_identity() -> TaskResult<ext4_security::IdentityMap> {
    let effective = windows_host::effective_identity()?;
    Ok(ext4_security::IdentityMap::new(
        vec![ext4_security::UserMapping {
            sid: effective.user,
            uid: ext4_core::Ext4Uid::from_u32(1000),
        }],
        vec![ext4_security::GroupMapping {
            sid: effective.primary_group,
            gid: ext4_core::Ext4Gid::from_u32(100),
        }],
    )
    .map_err(|error| io::Error::other(format!("{error:?}")))?)
}
/// Configures the owned UUID after mounting, exercising live slot publication.
/// # Errors
/// Returns volume identification, configuration or native communication failure.
fn configure_identity(session: &mut Session<LiveState>) -> TaskResult<()> {
    let uuid = windows_host::volume_identity(
        session
            .state()
            .volume()
            .ok_or_else(|| io::Error::other("identity configuration lacks an owned volume"))?,
    )?;
    replace_identity(session, uuid, fixture_identity()?)
}
/// New opens observe mapping removal while an existing handle retains its acquired write authority.
/// # Errors
/// Returns unexpected admission, data effects, close or replacement failures.
fn exercise_identity_update(session: &mut Session<LiveState>, path: &Path) -> TaskResult<()> {
    let uuid = ext4_core::FilesystemUuid::from_bytes(
        session
            .state()
            .identity
            .ok_or_else(|| io::Error::other("identity update lacks UUID authority"))?,
    );
    let mut retained = OpenOptions::new().write(true).open(path)?;
    let operation = (|| {
        replace_identity(session, uuid, ext4_security::IdentityMap::empty())?;
        match OpenOptions::new().write(true).open(path) {
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
            Err(error) => return Err(error.into()),
            Ok(file) => {
                windows_host::close_file(file)?;
                return Err(io::Error::other(
                    "new open retained revoked identity write permission",
                )
                .into());
            }
        }
        retained.write_all(&[0])?;
        retained.sync_all()?;
        replace_identity(session, uuid, fixture_identity()?)
    })();
    combine_verification_and_cleanup(
        operation,
        windows_host::close_file(retained).map_err(Into::into),
    )
}

/// Reconciles native mounted state before issuing a clean dismount; failed acknowledgements are queried.
/// # Errors
/// Returns missing partition authority, changed mounted identity or native dismount failures.
fn dismount_filesystem(session: &mut Session<LiveState>) -> TaskResult<()> {
    if session.state().partition().is_none() {
        if !matches!(session.state().driver, DriverStage::Absent) {
            return Err(
                io::Error::other("driver or volume publication lacks partition identity").into(),
            );
        }
        return Ok(());
    }
    println!("live dismount: validate storage identity");
    let identity = storage::validate(&scope(session)?)?;
    println!("live dismount: find volume by partition identity");
    let observed = windows_host::find_volume(&identity)?;
    let matched = observed.is_some();
    println!("live dismount: volume identity matched={matched}");
    let Some(volume) = observed.or_else(|| session.state().volume().map(str::to_owned)) else {
        return Ok(());
    };
    println!("live dismount: query mounted state");
    let mounted = windows_host::mount_state(&volume)?;
    println!("live dismount: mounted state={mounted:?}");
    match mounted {
        windows_host::MountState::Mounted => {
            if !matched {
                return Err(io::Error::other(
                    "mounted recorded volume no longer matches session partition",
                )
                .into());
            }
            session.state_mut().observe_volume(volume.clone())?;
            session.publish(Phase::Intent(Operation::DismountFilesystem))?;
            let mut command = Command::new("fsutil.exe");
            command.args(["volume", "dismount", &volume]);
            run_checked(command, "session filesystem dismount")?;
            session.publish(Phase::Observed(Operation::DismountFilesystem))?;
        }
        windows_host::MountState::Dismounted | windows_host::MountState::Absent => {}
    }
    Ok(())
}
/// Confirms the exact detached session volume no longer resolves to a device.
/// # Errors
/// Returns device-query or timeout failures; retained Mount Manager names do not establish presence.
fn wait_removed(session: &Session<LiveState>) -> TaskResult<()> {
    let Some(volume) = session.state().volume() else {
        return Ok(());
    };
    let start = Instant::now();
    loop {
        if !windows_host::volume_device_present(volume)? {
            return Ok(());
        }
        if start.elapsed() >= Duration::from_secs(30) {
            return Err(
                io::Error::other("withdrawn session volume still resolves to a device").into(),
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Requested storage availability, independent of VHDX attachment and driver lifetime.
#[derive(Clone, Copy)]
enum DiskAvailability {
    /// Withdraw the disposable disk's volumes through the normal storage PnP path.
    Offline,
    /// Reenumerate the same disposable disk without changing its partition identity.
    Online,
}

/// Changes only the identity-matched session VHDX disk and observes the resulting disk state.
/// An interrupted request can leave either state; cleanup detaches that same owned VHDX.
/// # Errors
/// Returns changed identity, management failure or an unconfirmed state transition.
fn disk_availability(
    session: &mut Session<LiveState>,
    availability: DiskAvailability,
) -> TaskResult<()> {
    let scope = scope(session)?;
    let path = windows::literal(scope.vhdx.as_os_str())?;
    let unique = windows::literal(OsStr::new(&scope.disk))?;
    let (offline, operation) = match availability {
        DiskAvailability::Offline => {
            storage::validate(&scope)?;
            ("$true", Operation::OfflineDisk)
        }
        DiskAvailability::Online => ("$false", Operation::OnlineDisk),
    };
    session.publish(Phase::Intent(operation))?;
    let observed = windows::management(
        &format!(
            "$vhd=Get-VHD -Path {path}; if (-not $vhd.Attached) {{ throw 'session VHDX is detached' }}; $disk=Get-Disk -Number $vhd.DiskNumber; if ($disk.UniqueId -ne {unique}) {{ throw 'session disk identity changed' }}; $disk | Set-Disk -IsOffline {offline}; (Get-Disk -Number $vhd.DiskNumber).IsOffline -eq {offline}"
        ),
        Duration::from_secs(60),
    )?;
    if observed != serde_json::Value::Bool(true) {
        return Err(io::Error::other("disk availability transition was not observed").into());
    }
    session.publish(Phase::Observed(operation))
}

/// Requires repeated offline/online discovery to preserve all assigned paths and durable content.
/// Leaves the final online mount available for the attached-volume unload scenario.
/// # Errors
/// Returns lifecycle, changed volume GUID/path assignments or persisted-content failures.
fn exercise_offline_online(session: &mut Session<LiveState>, payload: &[u8]) -> TaskResult<()> {
    let volume = session
        .state()
        .volume()
        .ok_or_else(|| io::Error::other("offline scenario lacks a volume identity"))?
        .to_owned();
    let paths: BTreeSet<_> = windows_host::volume_mount_paths(&volume)?
        .into_iter()
        .collect();
    for _ in 0..2 {
        dismount_filesystem(session)?;
        disk_availability(session, DiskAvailability::Offline)?;
        disk_availability(session, DiskAvailability::Online)?;
        let mount = mount_namespace(session)?;
        if fs::read(mount.join("live-ci/alpha.bin"))? != payload {
            return Err(io::Error::other("online volume lost durable content").into());
        }
        remove_namespace(session)?;
        let observed: BTreeSet<_> = windows_host::volume_mount_paths(&volume)?
            .into_iter()
            .collect();
        if observed != paths {
            return Err(io::Error::other("disk offline/online changed volume mount paths").into());
        }
    }
    Ok(())
}

/// Command used to invoke the remount requester in a separate process.
pub(crate) const READ_REMOUNT_PAYLOAD: &str = "read-remount-payload";

/// Performs the fresh file open in a supervised process so a pending kernel request cannot
/// block the live session owner. Progress goes to stderr and stdout carries only payload bytes.
/// # Errors
/// Returns native open, read, output, or explicit close errors.
pub(crate) fn read_remount_payload(path: &Path) -> TaskResult<()> {
    eprintln!("live remount requester: opening file");
    let mut file = fs::File::open(path)?;
    eprintln!("live remount requester: fresh open completed");
    let readback = (|| -> TaskResult<()> {
        let mut output = io::stdout().lock();
        io::copy(&mut file, &mut output)?;
        output.flush()?;
        eprintln!("live remount requester: payload read completed");
        Ok(())
    })();
    eprintln!("live remount requester: closing fresh handle");
    let closed = windows_host::close_file(file).map_err(Into::into);
    if closed.is_ok() {
        eprintln!("live remount requester: fresh handle closed");
    }
    combine_verification_and_cleanup(readback, closed)
}

/// Executes native I/O, remount, unload with attached storage, and hot-attach after restart.
/// # Errors
/// Returns load, Verifier, discovery, filesystem, hot-attach or required detachment failures.
fn exercise_driver(
    root: &Path,
    session: &mut Session<LiveState>,
    verifier: VerifierPlan,
) -> TaskResult<Vec<u8>> {
    let scope = scope(session)?;
    storage::validate(&scope)?;
    let id = session.id().clone();
    let artifact = driver_load::start_session(root, &id, Some(&scope), || {
        if windows_host::driver_image_loaded("ext4win.sys")? {
            return Err(io::Error::other("live startup requires an unloaded driver image").into());
        }
        if verifier == VerifierPlan::Runtime {
            require_idle_verifier()?;
        }
        session.state_mut().driver = DriverStage::Starting;
        session.publish(Phase::Intent(Operation::StartDriver))
    })?;
    session.state_mut().driver = DriverStage::Running;
    session.publish(Phase::Observed(Operation::StartDriver))?;
    verify_loaded_image(session, verifier, VerifierObservation::BeforeFilesystemIo)?;
    let mount = mount_namespace(session)?;
    configure_identity(session)?;
    let payload = exercise_io(session, &mount)?;
    if matches!(session.state().workload, LiveWorkload::RandomIo) {
        session.publish(Phase::Intent(Operation::FilesystemIo))?;
        benchmark::run(
            &mount.join("live-ci/random-io"),
            &session.directory().join("random-io.json"),
            &artifact,
        )?;
        session.publish(Phase::Observed(Operation::FilesystemIo))?;
    }
    let retained = OpenOptions::new()
        .read(true)
        .open(mount.join("live-ci/alpha.bin"))?;
    let remount = (|| -> TaskResult<()> {
        dismount_filesystem(session)?;
        println!("live remount: read through a fresh open while the old handle remains");
        let mut requester = Command::new(env::current_exe()?);
        requester
            .arg(READ_REMOUNT_PAYLOAD)
            .arg(mount.join("live-ci/alpha.bin"))
            .stderr(Stdio::inherit());
        let readback = windows::bounded(requester, Duration::from_secs(60))
            .and_then(|outcome| windows::checked_outcome(outcome, "remount readback"));
        match &readback {
            Ok(_) => println!("live remount: fresh-open read completed"),
            Err(error) => println!("live remount: fresh-open read failed: {error}"),
        }
        if readback? != payload {
            return Err(io::Error::other(
                "fresh mount while an old FILE_OBJECT remains lost durable content",
            )
            .into());
        }
        Ok(())
    })();
    println!("live remount: close the retained old handle");
    let released = windows_host::close_file(retained).map_err(Into::into);
    println!("live remount: old-handle close result={released:?}");
    combine_verification_and_cleanup(remount, released)?;
    remove_namespace(session)?;
    exercise_offline_online(session, &payload)?;
    storage::validate(&scope)?;
    observe_verifier(session, VerifierObservation::BeforeAttachedUnload)?;
    println!("live unload: stop the driver with the session VHDX still attached");
    let driver = driver_load::quiesce_session(root, session.id())?;
    dismount_filesystem(session)?;
    session.publish(Phase::Intent(Operation::StopDriver))?;
    driver.restart(|| {
        session.publish(Phase::Observed(Operation::StopDriver))?;
        storage::validate(&scope)?;
        attachment(session, false)?;
        wait_removed(session)?;
        session.publish(Phase::Intent(Operation::StartDriver))
    })?;
    session.publish(Phase::Observed(Operation::StartDriver))?;
    verify_loaded_image(session, verifier, VerifierObservation::BeforeHotAttach)?;
    attachment(session, true)?;
    let mount = mount_namespace(session)?;
    if fs::read(mount.join("live-ci/alpha.bin"))? != payload {
        return Err(io::Error::other("hot-attached volume lost durable content").into());
    }
    let uuid = ext4_core::FilesystemUuid::from_bytes(
        session
            .state()
            .identity
            .ok_or_else(|| io::Error::other("reattachment lost ext4 identity"))?,
    );
    let restored = windows_host::query_identity(uuid)?;
    if restored.saved_generation != restored.active.generation
        || restored
            .active
            .map
            .creator(
                windows_host::effective_identity()?.user,
                windows_host::effective_identity()?.primary_group,
            )
            .is_err()
    {
        return Err(io::Error::other("reattachment lost durable identity mapping").into());
    }
    storage::validate(&scope)?;
    observe_verifier(session, VerifierObservation::AfterHotAttach)?;
    let mut driver = driver_load::quiesce_session(root, session.id())?;
    dismount_filesystem(session)?;
    remove_namespace(session)?;
    attachment(session, false)?;
    wait_removed(session)?;
    // Exercise recovery after endpoint retirement commits while SCM is still Running.
    driver.prepare_unload()?;
    Ok(payload)
}

/// Finalizes the exact nested driver session before any Linux inspection of written storage.
/// # Errors
/// Returns missing driver identity or mandatory package and service cleanup failures.
fn cleanup_bound_driver(root: &Path, session: &mut Session<LiveState>) -> TaskResult<()> {
    if session.state().driver == DriverStage::Cleaned {
        return Ok(());
    }
    let driver_directory = root
        .join("target/driver-load-sessions")
        .join(session.id().as_str());
    if driver_directory.is_dir() {
        session.publish(Phase::Intent(Operation::CleanupDriver))?;
        driver_load::cleanup_driver_load_session(root, OsStr::new(session.id().as_str()))?;
        session.state_mut().driver = DriverStage::Cleaned;
        session.publish(Phase::Observed(Operation::CleanupDriver))?;
    } else if matches!(
        session.state().driver,
        DriverStage::Starting | DriverStage::Running
    ) {
        return Err(io::Error::other("started driver's durable session identity is absent").into());
    }
    Ok(())
}

/// Withdraws storage before driver retirement and releases boot-scoped Verifier ownership.
/// # Errors
/// Returns identity changes, unresolved WSL/volume state or mandatory resource finalization failures.
fn cleanup(root: &Path, session: &mut Session<LiveState>) -> TaskResult<()> {
    if session.phase() == Phase::Complete {
        if vhdx(session).exists() || session.directory().join("mount").exists() {
            return Err(io::Error::other("completed session has new storage or namespace state; no cleanup authority is retained").into());
        }
        return Ok(());
    }
    finish_wsl(session, wsl)?;
    if let Some(disk) = storage::disk(&vhdx(session))? {
        if session
            .state()
            .disk()
            .is_some_and(|expected| !expected.eq_ignore_ascii_case(&disk.unique))
        {
            return Err(io::Error::other("cleanup disk identity differs from session").into());
        }
        if disk.offline && session.state().partition().is_some() {
            disk_availability(session, DiskAvailability::Online)?;
        }
        dismount_filesystem(session)?;
        remove_namespace(session)?;
        attachment(session, false)?;
        wait_removed(session)?;
    } else {
        remove_namespace(session)?;
    }
    cleanup_bound_driver(root, session)?;
    if vhdx(session).exists() {
        session.publish(Phase::Intent(Operation::RemoveVhdx))?;
        fs::remove_file(vhdx(session))?;
        session.publish(Phase::Observed(Operation::RemoveVhdx))?;
    }
    release_runtime_verifier(session)?;
    session.publish(Phase::Complete)
}

/// Reloads durable identity and revalidates resource relationships before interrupted cleanup.
/// # Errors
/// Returns invalid records, missing relationship evidence or any cleanup failure.
pub(crate) fn cleanup_live_vhdx_session(root: &Path, id: &OsStr) -> TaskResult<()> {
    windows_host::require_administrator()?;
    let id = SessionId::parse(id)?;
    let mut session: Session<LiveState> = Session::load(root, "live-vhdx-sessions", &id)?;
    if (session.state().wsl != WslAttachment::Detached
        || session.state().driver != DriverStage::Absent)
        && session.state().partition().is_none()
    {
        return Err(io::Error::other("invalid recorded live identity relationship").into());
    }
    cleanup(root, &mut session)
}

/// Measures an exact signed artifact on independently populated disposable storage.
/// # Errors
/// Returns build, workload, integrity or mandatory joined cleanup failures.
pub(crate) fn benchmark_multi_file(root: &Path) -> TaskResult<()> {
    let id = SessionId::create(root)?;
    prepare_session(root, LiveWorkload::RandomIo, id.clone())?;
    verify_live_vhdx(root, OsStr::new(id.as_str()), VerifierPlan::Runtime)
}

/// Creates disposable storage and an identity-bound stopped installation for later activation.
/// # Errors
/// Returns preflight, build, storage or installation failures, preserving cleanup failures.
fn prepare_session(root: &Path, workload: LiveWorkload, id: SessionId) -> TaskResult<()> {
    check_live_driver_host(root)?;
    let helper = fixture::executable(root)?;
    let bundle = build_verified_production_bundle(root)?;
    println!("live VHDX session: {}", id.as_str());
    let state = LiveState {
        workload,
        storage: StorageIdentity::Unobserved,
        wsl: WslAttachment::Detached,
        driver: DriverStage::Absent,
        verifier_effect: None,
        identity: None,
    };
    let mut session = Session::create(root, "live-vhdx-sessions", id, state)?;
    let operation = (|| {
        create_storage(&mut session, workload)?;
        format_storage(&mut session, &helper, workload)?;
        attachment(&mut session, true)?;
        let scope = scope(&session)?;
        storage::validate(&scope)?;
        session.state_mut().driver = DriverStage::Installing;
        session.publish(Phase::Intent(Operation::InstallPackage))?;
        driver_load::install_session(root, &bundle, session.id().clone(), Some(&scope))?;
        session.state_mut().driver = DriverStage::Installed;
        session.publish(Phase::Observed(Operation::InstallPackage))
    })();
    if operation.is_err() {
        let cleanup = cleanup_live_vhdx_session(root, OsStr::new(session.id().as_str()));
        return combine_verification_and_cleanup(operation, cleanup);
    }
    println!(
        "live VHDX preparation: PASS; activation pending for {}",
        session.id().as_str()
    );
    Ok(())
}

/// Prepares one caller-named session without issuing a driver-start request.
/// Successful preparation transfers finalization responsibility to verification or explicit cleanup.
/// # Errors
/// Returns malformed identity, build, storage, installation or mandatory cleanup failures.
pub(crate) fn prepare_live_vhdx(root: &Path, id: &OsStr) -> TaskResult<()> {
    prepare_session(root, LiveWorkload::Assurance, SessionId::parse(id)?)
}

/// Consumes a prepared session through live validation, cleanup and joined ETW completion.
/// # Errors
/// Returns incomplete/consumed preparation, stale identity/source, live or cleanup failures.
pub(crate) fn verify_live_vhdx(root: &Path, id: &OsStr, verifier: VerifierPlan) -> TaskResult<()> {
    windows_host::require_administrator()?;
    let id = SessionId::parse(id)?;
    let mut session: Session<LiveState> = Session::load(root, "live-vhdx-sessions", &id)?;
    if session.state().driver != DriverStage::Installed
        || session.phase() != Phase::Observed(Operation::InstallPackage)
    {
        return Err(io::Error::other(
            "live activation requires completed preparation; reconcile any interrupted activation",
        )
        .into());
    }
    let trace = match windows_host::TraceSession::start(
        &root.join("crates/ext4-driver/operational-trace-v1.txt"),
        &root.join("target/live-driver-trace"),
    ) {
        Ok(trace) => trace,
        Err(error) => {
            let cleanup = cleanup_live_vhdx_session(root, OsStr::new(session.id().as_str()));
            return combine_verification_and_cleanup(Err(error.into()), cleanup);
        }
    };
    let operation = exercise_driver(root, &mut session, verifier).and_then(|payload| {
        cleanup_bound_driver(root, &mut session)?;
        verify_persisted_storage(&mut session, &payload)
    });
    let resources = cleanup_live_vhdx_session(root, OsStr::new(session.id().as_str()));
    let operation = combine_verification_and_cleanup(operation, resources);
    let completion = trace.finish().map(|_| ()).map_err(Into::into);
    combine_verification_and_cleanup(operation, completion)?;
    println!("live VHDX driver assurance: PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Fails if a read-only filesystem inspection can accept pending recovery or an unclean state.
    #[test]
    fn persisted_superblock_must_be_clean_without_pending_recovery() {
        let report = "Filesystem features:  has_journal extents 64bit\nFilesystem state:  clean";
        assert!(require_clean_superblock(report).is_ok());
        assert!(
            require_clean_superblock(&report.replace("64bit", "64bit needs_recovery")).is_err()
        );
        assert!(require_clean_superblock(&report.replace("clean", "clean with errors")).is_err());
        assert!(require_clean_superblock("Filesystem state:  clean").is_err());
    }

    /// # Panics
    /// Fails if the post-write oracle accepts missing, ambiguous or different inode observations.
    #[test]
    fn persisted_probe_metadata_requires_independent_inode_fields() {
        let report = "Inode: 16 Type: regular Mode: 0644 Flags: 0x80000\nUser: 1000 Group: 100 Size: 8192\nLinks: 1 Blockcount: 16";
        assert!(require_persisted_probe_metadata(report).is_ok());
        assert!(require_persisted_probe_metadata(&report.replace("Links: 1", "Links: 2")).is_err());
        assert!(require_persisted_probe_metadata(&report.replace("Group: 100", "")).is_err());
        assert!(require_persisted_probe_metadata(&format!("{report}\nLinks: 1")).is_err());
    }

    /// # Errors
    /// Returns durable fixture setup, reload or mandatory cleanup failures.
    /// # Panics
    /// Fails if interruption loses finalization responsibility or a completed shutdown is repeated.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible session setup and recovery surround assertions at external acceptance boundaries"
    )]
    fn interrupted_wsl_finalization_retains_shutdown_responsibility() -> TaskResult<()> {
        let root = crate::process::repository_root()?;
        let fixture = crate::process::create_task_directory(&root, "wsl-finalization")?;
        let result = (|| -> TaskResult<()> {
            let partition = Partition {
                number: 2,
                id: windows_host::guid_bytes("2ca3ad84-858a-49ba-be4a-430713ddf498")?,
                kind: windows_host::guid_bytes("0fc63daf-8483-4772-8e79-3d69d8477de4")?,
                offset: 4096,
                length: 8192,
            };
            let visible = "sde disk\nsde2 part 2ca3ad84-858a-49ba-be4a-430713ddf498 0fc63daf-8483-4772-8e79-3d69d8477de4\n";
            for (layout, interrupted) in [
                ("", "--shutdown"),
                (visible, "--unmount"),
                (visible, "--shutdown"),
            ] {
                let id = SessionId::create(&fixture)?;
                let mut session = Session::create(
                    &fixture,
                    "sessions",
                    id.clone(),
                    LiveState {
                        workload: LiveWorkload::Assurance,
                        storage: StorageIdentity::Partition {
                            unique: "fixture-disk".into(),
                            partition: partition.clone(),
                            volume: None,
                        },
                        wsl: WslAttachment::Requested,
                        driver: DriverStage::Absent,
                        verifier_effect: None,
                        identity: None,
                    },
                )?;
                session.publish(Phase::Intent(Operation::AttachWsl))?;
                let mut effects = Vec::new();
                assert!(
                    finish_wsl(&mut session, |arguments| {
                        let command = arguments.first().and_then(|value| value.to_str());
                        if command == Some("--exec") {
                            return Ok(layout.into());
                        }
                        let durable: Session<LiveState> = Session::load(&fixture, "sessions", &id)?;
                        assert_eq!(durable.state().wsl, WslAttachment::Detaching);
                        effects.push(command.map(str::to_owned));
                        if command == Some(interrupted) {
                            return Err(io::Error::other("external acceptance is uncertain").into());
                        }
                        Ok(String::new())
                    })
                    .is_err()
                );
                assert_eq!(effects.last().and_then(Option::as_deref), Some(interrupted));
                let mut recovered: Session<LiveState> = Session::load(&fixture, "sessions", &id)?;
                assert_eq!(recovered.state().wsl, WslAttachment::Detaching);
                let mut shutdowns = 0;
                finish_wsl(&mut recovered, |arguments| {
                    match arguments.first().and_then(|value| value.to_str()) {
                        Some("--exec") => Ok(String::new()),
                        Some("--shutdown") => {
                            shutdowns += 1;
                            Ok(String::new())
                        }
                        _ => Err(io::Error::other("recovery repeated an unobserved detach").into()),
                    }
                })?;
                assert_eq!(shutdowns, 1);
                let mut completed: Session<LiveState> = Session::load(&fixture, "sessions", &id)?;
                assert_eq!(completed.state().wsl, WslAttachment::Detached);
                assert_eq!(completed.phase(), Phase::Observed(Operation::ShutdownWsl));
                finish_wsl(&mut completed, |_| {
                    Err(
                        io::Error::other("completed finalization repeated an external effect")
                            .into(),
                    )
                })?;
            }
            Ok(())
        })();
        let cleanup = crate::process::remove_task_directory(&root, &fixture, "wsl-finalization");
        combine_verification_and_cleanup(result, cleanup)
    }

    /// # Panics
    /// Fails if a DIF receipt without a unique successful native status is accepted.
    #[test]
    fn dif_requires_native_success() {
        let rejected = r#""StatusCode": 0xc0000c7e
"CurrentlyEnabled": Yes
"RuleClasses": 0x0012091b 0x00000000"#;
        let accepted = rejected.replace("0xc0000c7e", "0x00000000");
        assert!(require_dif_success(rejected).is_err());
        assert!(require_dif_success(&accepted).is_ok());
        assert!(require_dif_success(&format!("{accepted}\n{rejected}")).is_err());
        assert!(require_dif_success(r#""CurrentlyEnabled": Yes"#).is_err());
    }

    /// # Panics
    /// Fails if a recovered named selection could be mistaken for a session-owned DIF effect.
    #[test]
    fn persisted_verifier_effects_keep_their_release_authority() {
        assert!(matches!(
            serde_json::from_str::<VerifierEffect>(r#""first boot""#),
            Ok(VerifierEffect::NamedSelection(boot)) if boot == "first boot"
        ));
        assert!(matches!(
            serde_json::from_str::<VerifierEffect>(r#"{"boot":"first boot"}"#),
            Ok(VerifierEffect::RuntimeRules { boot }) if boot == "first boot"
        ));
    }

    /// Runtime counters and independent GPT identities decide admission, not loose substrings.
    /// # Errors
    /// Returns unexpected fixture parsing errors.
    /// # Panics
    /// Panics if unknown or insufficient evidence is admitted.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "contract assertions intentionally fail the test; external observation parsing preserves error context"
    )]
    fn runtime_and_partition_admission() -> TaskResult<()> {
        let report = "Verifier Flags: 0x001209bb\nMODULE: ext4win.sys (load: 1 / unload: 0)";
        verifier_activity(report)?;
        assert!(verifier_activity(&report.replace("0x001209bb", "0x00000000")).is_err());
        assert!(verifier_activity(&report.replace("load: 1", "load: 0")).is_err());
        assert!(verifier_activity(&format!("{report}\n{report}")).is_err());

        let partition = Partition {
            number: 2,
            id: windows_host::guid_bytes("2ca3ad84-858a-49ba-be4a-430713ddf498")?,
            kind: windows_host::guid_bytes("0fc63daf-8483-4772-8e79-3d69d8477de4")?,
            offset: 1,
            length: 1,
        };
        let mut state = LiveState {
            workload: LiveWorkload::Assurance,
            storage: StorageIdentity::Partition {
                unique: "fixture-disk".into(),
                partition: partition.clone(),
                volume: None,
            },
            wsl: WslAttachment::Detached,
            driver: DriverStage::Running,
            verifier_effect: None,
            identity: None,
        };
        let volume = r"\\?\Volume{2ca3ad84-858a-49ba-be4a-430713ddf498}\";
        state.observe_volume(volume.into())?;
        state.observe_volume(volume.to_uppercase())?;
        assert!(
            state
                .observe_volume(r"\\?\Volume{00000000-0000-0000-0000-000000000001}\".into())
                .is_err()
        );
        assert!(
            state
                .volume()
                .is_some_and(|current| current.eq_ignore_ascii_case(volume))
        );
        let layout = "sde disk\nsde2 part 2ca3ad84-858a-49ba-be4a-430713ddf498 0fc63daf-8483-4772-8e79-3d69d8477de4\n";
        assert_eq!(linux_partition(layout, &partition)?, "sde2");
        assert!(linux_partition(&format!("{layout}{layout}"), &partition).is_err());
        Ok(())
    }
}
