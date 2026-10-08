//! Owns disposable storage identity, external operation intents and ordered finalization.
use crate::{
    TaskResult, driver_load, fixture,
    process::{combine_verification_and_cleanup, run_checked, run_checked_output},
    production::{VerifiedProductionBundle, build_verified_production_bundle},
    session::{Operation, Phase, Session, SessionId},
    storage::{self, DisposablePartition, Partition},
    windows,
};
use alloc::collections::BTreeSet;
use core::time::Duration;
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Instant,
};

#[path = "benchmark.rs"]
mod benchmark;

/// Storage and workload selected before the disposable session acquires resources.
#[derive(Clone, Copy, Debug)]
enum LiveWorkload {
    /// Existing filesystem and driver assurance scenario.
    Assurance,
    /// Independent random-I/O dataset and repeated native measurements.
    RandomIo,
}

/// WSL attachment stage; interrupted intent is not assumed to have rolled back.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum WslAttachment {
    /// No session attachment remains.
    Detached,
    /// Attachment may have been accepted.
    Requested,
    /// An identity-matched Linux device was observed.
    Attached,
    /// Detachment may already have committed.
    Detaching,
}
/// Delegated driver lifecycle stage, separate from volume state and Driver Verifier admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DriverStage {
    /// Driver startup has not been requested.
    Unstarted,
    /// Nested session establishment/start outcome may be unknown.
    Requested,
    /// SCM Running and exact installed package identity were observed.
    Running,
    /// Nested cleanup completed.
    Cleaned,
}
/// Narrow independent storage and driver identities saved for interruption recovery.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveState {
    /// GPT and volume identity cannot exist independently of their owning disk.
    storage: StorageIdentity,
    /// Independent WSL attachment progress.
    wsl: WslAttachment,
    /// Nested driver lifecycle progress.
    driver: DriverStage,
    /// Disposable ext4 UUID retained before identity-table effects, for query-based cleanup.
    identity: Option<[u8; 16]>,
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
    /// Returns a missing-partition protocol error.
    fn observe_volume(&mut self, observed: String) -> TaskResult<()> {
        match &mut self.storage {
            StorageIdentity::Partition { volume, .. } => {
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
fn wsl(arguments: &[OsString]) -> TaskResult<String> {
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
        ]);
        command.args(arguments.iter().skip(1));
    } else {
        command.args(arguments);
    }
    let output = run_checked_output(command, "WSL session operation")?;
    Ok(String::from_utf8(output.stdout)?)
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

/// Parses current-boot Driver Verifier activity; next-boot settings are not runtime evidence.
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
    if flags & 0x0002_091b != 0x0002_091b || loads <= unloads {
        return Err(io::Error::other(
            "runtime Verifier checks are missing or ext4win.sys is not loaded",
        )
        .into());
    }
    Ok(())
}
/// Observes and retains exact loaded-driver Verifier evidence before filesystem work.
/// # Errors
/// Returns query, evidence write or runtime-activity validation failures.
fn observe_verifier(session: &mut Session<LiveState>) -> TaskResult<()> {
    let mut command = Command::new("verifier.exe");
    command.arg("/query");
    let output = run_checked_output(command, "loaded Driver Verifier runtime query")?;
    let report = String::from_utf8(output.stdout)?;
    fs::write(session.directory().join("verifier-runtime.txt"), &report)?;
    verifier_activity(&report)?;
    session.publish(Phase::Observed(Operation::ObserveVerifier))
}

/// Checks live-host prerequisites without storage, package or driver mutation.
/// # Errors
/// Returns any hosted preflight, Hyper-V, WSL or e2fsprogs prerequisite failure.
pub(crate) fn check_live_driver_host(root: &Path) -> TaskResult<()> {
    driver_load::check_hosted_driver_host(root)?;
    windows::management(
        "@('New-VHD','Get-VHD','Mount-VHD','Dismount-VHD','Get-Disk','Set-Disk','Initialize-Disk','New-Partition','verifier.exe','mountvol.exe','fsutil.exe') | ForEach-Object { Get-Command $_ -ErrorAction Stop | Out-Null }; $true",
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
    windows::management(&format!("{command} -Path {path} | Out-Null; $true"))?;
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
    windows::management(&format!(
        "New-VHD -Path {path} -Fixed -SizeBytes {bytes} | Out-Null; $true"
    ))?;
    session.publish(Phase::Observed(Operation::CreateVhdx))?;
    attachment(session, true)?;
    let disk = storage::disk(&vhdx(session))?
        .ok_or_else(|| io::Error::other("new VHDX did not identify a disk"))?;
    session.state_mut().storage = StorageIdentity::Disk {
        unique: disk.unique.clone(),
    };
    session.publish(Phase::Observed(Operation::AttachWindows))?;
    session.publish(Phase::Intent(Operation::Partition))?;
    windows::management(&format!(
        "Set-Disk -Number {} -IsOffline $false; Set-Disk -Number {} -IsReadOnly $false; Initialize-Disk -Number {} -PartitionStyle GPT | Out-Null; New-Partition -DiskNumber {} -UseMaximumSize -GptType '{{0FC63DAF-8483-4772-8E79-3D69D8477DE4}}' | Out-Null; $true",
        disk.number, disk.number, disk.number, disk.number
    ))?;
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

/// Formats and populates through Linux tools before any Windows-driver mount can occur.
/// # Errors
/// Returns device-difference, GPT identity, oracle, helper or WSL detachment failures.
fn format_storage(
    session: &mut Session<LiveState>,
    helper: &Path,
    workload: LiveWorkload,
) -> TaskResult<()> {
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
    detach_wsl(session)?;
    session.publish(Phase::Intent(Operation::ShutdownWsl))?;
    wsl_words(&["--shutdown"])?;
    session.publish(Phase::Observed(Operation::ShutdownWsl))?;
    Ok(())
}

/// Reconciles WSL attachment by querying the recorded GPT identity before any repeated detachment.
/// # Errors
/// Returns ambiguous device identity, unmount or record-publication failures.
fn detach_wsl(session: &mut Session<LiveState>) -> TaskResult<()> {
    if session.state().wsl == WslAttachment::Detached {
        return Ok(());
    }
    let layout = wsl_words(&[
        "--exec",
        "lsblk",
        "-nr",
        "-o",
        "NAME,TYPE,PARTUUID,PARTTYPE",
    ])?;
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
    if matching == 1 {
        session.state_mut().wsl = WslAttachment::Detaching;
        session.publish(Phase::Intent(Operation::DetachWsl))?;
        wsl(&["--unmount".into(), vhdx(session).into_os_string()])?;
    }
    session.state_mut().wsl = WslAttachment::Detached;
    session.publish(Phase::Observed(Operation::DetachWsl))
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
    let reset = OpenOptions::new()
        .create_new(true)
        .write(true)
        .attributes(0x02)
        .open(&reset_path)?;
    windows_host::close_file(reset)?;
    if fs::metadata(&reset_path)?.file_attributes() & 0x02 == 0 {
        return Err(io::Error::other("create attributes were not applied").into());
    }
    for create_if_missing in [false, true] {
        fs::write(&reset_path, b"existing payload")?;
        let reset = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(create_if_missing)
            .open(&reset_path)?;
        let verification = (|| {
            if reset.metadata()?.len() == 0 {
                Ok(())
            } else {
                Err(io::Error::other("overwrite did not reset EOF").into())
            }
        })();
        combine_verification_and_cleanup(
            verification,
            windows_host::close_file(reset).map_err(Into::into),
        )?;
    }
    println!("live filesystem I/O: verify handle-local timestamp suppression");
    windows_host::verify_timestamp_suppression(&reset_path)?;
    println!("live filesystem I/O: verify file metadata");
    windows_host::verify_metadata(&alpha, "\\live-ci\\alpha.bin", 8_192)?;
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
        expected,
    )
    .map_err(|error| io::Error::other(format!("{error:?}")))?;
    if actual != expected {
        return Err(io::Error::other(
            "created inode owner/group/mode differs from effective identity",
        )
        .into());
    }
    windows_host::set_file_dacl(&alpha, &descriptor)?;
    if windows_host::file_security(&alpha)? != descriptor {
        return Err(
            io::Error::other("native security descriptor round trip changed metadata").into(),
        );
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
        if !matches!(session.state().driver, DriverStage::Unstarted) {
            return Err(
                io::Error::other("driver or volume publication lacks partition identity").into(),
            );
        }
        return Ok(());
    }
    let identity = storage::validate(&scope(session)?)?;
    let observed = windows_host::find_volume(&identity)?;
    let matched = observed.is_some();
    let Some(volume) = observed.or_else(|| session.state().volume().map(str::to_owned)) else {
        return Ok(());
    };
    match windows_host::mount_state(&volume)? {
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
/// Confirms Mount Manager withdrew the exact retired session volume.
/// # Errors
/// Returns enumeration or timeout failures.
fn wait_removed(session: &Session<LiveState>) -> TaskResult<()> {
    let Some(volume) = session.state().volume() else {
        return Ok(());
    };
    let start = Instant::now();
    loop {
        if !windows_host::volume_names()?
            .iter()
            .any(|observed| observed == volume)
        {
            return Ok(());
        }
        if start.elapsed() >= Duration::from_secs(30) {
            return Err(
                io::Error::other("Mount Manager retained the removed session volume").into(),
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Executes startup discovery, native I/O and reattachment while the same driver remains loaded.
/// # Errors
/// Returns load, Verifier, discovery, filesystem, hot-attach or required detachment failures.
fn exercise_driver(
    root: &Path,
    bundle: &VerifiedProductionBundle,
    session: &mut Session<LiveState>,
    workload: LiveWorkload,
) -> TaskResult<()> {
    attachment(session, true)?;
    let scope = scope(session)?;
    storage::validate(&scope)?;
    session.state_mut().driver = DriverStage::Requested;
    session.publish(Phase::Intent(Operation::StartDriver))?;
    driver_load::start_session(root, bundle, session.id().clone(), Some(&scope))?;
    session.state_mut().driver = DriverStage::Running;
    session.publish(Phase::Observed(Operation::StartDriver))?;
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
    run_checked(command, "live Driver Verifier activation")?;
    observe_verifier(session)?;
    let mount = mount_namespace(session)?;
    configure_identity(session)?;
    let payload = exercise_io(session, &mount)?;
    if matches!(workload, LiveWorkload::RandomIo) {
        session.publish(Phase::Intent(Operation::FilesystemIo))?;
        benchmark::run(
            &mount.join("live-ci/random-io"),
            &session.directory().join("random-io.json"),
            bundle.artifact_id(),
        )?;
        session.publish(Phase::Observed(Operation::FilesystemIo))?;
    }
    dismount_filesystem(session)?;
    remove_namespace(session)?;
    attachment(session, false)?;
    wait_removed(session)?;
    session.publish(Phase::Intent(Operation::StopDriver))?;
    driver_load::restart_session(root, session.id())?;
    session.publish(Phase::Observed(Operation::StartDriver))?;
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
    observe_verifier(session)?;
    dismount_filesystem(session)?;
    remove_namespace(session)?;
    attachment(session, false)?;
    wait_removed(session)
}

/// Removes owned storage first, preserving the driver's unload endpoint until volume cleanup ends.
/// # Errors
/// Returns identity changes, unresolved WSL/volume state or mandatory resource finalization failures.
fn cleanup(root: &Path, session: &mut Session<LiveState>) -> TaskResult<()> {
    if session.phase() == Phase::Complete {
        if vhdx(session).exists() || session.directory().join("mount").exists() {
            return Err(io::Error::other("completed session has new storage or namespace state; no cleanup authority is retained").into());
        }
        return Ok(());
    }
    let wsl_may_be_attached = session.state().wsl != WslAttachment::Detached;
    detach_wsl(session)?;
    if wsl_may_be_attached {
        // Dedicated-host authority includes oracle shutdown. This also reconciles attachment
        // accepted before lsblk published a partition, without treating missing GUID data as rollback.
        session.publish(Phase::Intent(Operation::ShutdownWsl))?;
        wsl_words(&["--shutdown"])?;
        session.publish(Phase::Observed(Operation::ShutdownWsl))?;
    }
    if let Some(disk) = storage::disk(&vhdx(session))? {
        if session
            .state()
            .disk()
            .is_some_and(|expected| !expected.eq_ignore_ascii_case(&disk.unique))
        {
            return Err(io::Error::other("cleanup disk identity differs from session").into());
        }
        dismount_filesystem(session)?;
        remove_namespace(session)?;
        attachment(session, false)?;
        wait_removed(session)?;
    } else {
        remove_namespace(session)?;
    }
    if vhdx(session).exists() {
        session.publish(Phase::Intent(Operation::RemoveVhdx))?;
        fs::remove_file(vhdx(session))?;
        session.publish(Phase::Observed(Operation::RemoveVhdx))?;
    }
    if let Some(uuid) = session.state().identity
        && windows_host::service_state("ext4win")? == Some(4)
    {
        let uuid = ext4_core::FilesystemUuid::from_bytes(uuid);
        let observed = windows_host::query_identity(uuid)?;
        if !observed.active.map.users().is_empty() || !observed.active.map.groups().is_empty() {
            replace_identity(session, uuid, ext4_security::IdentityMap::empty())?;
        }
        session.state_mut().identity = None;
        session.publish(Phase::Observed(Operation::IdentityMapping))?;
    }
    let driver_directory = root
        .join("target/driver-load-sessions")
        .join(session.id().as_str());
    if driver_directory.is_dir() {
        session.publish(Phase::Intent(Operation::CleanupDriver))?;
        driver_load::cleanup_driver_load_session(root, OsStr::new(session.id().as_str()))?;
        session.state_mut().driver = DriverStage::Cleaned;
        session.publish(Phase::Observed(Operation::CleanupDriver))?;
    } else if session.state().driver == DriverStage::Running {
        return Err(io::Error::other("started driver's durable session identity is absent").into());
    }
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
        || session.state().driver != DriverStage::Unstarted)
        && session.state().partition().is_none()
    {
        return Err(io::Error::other("invalid recorded live identity relationship").into());
    }
    cleanup(root, &mut session)
}

/// Builds one signed bundle and requires live validation, storage/driver cleanup and ETW completion.
/// # Errors
/// Returns any build, live operation, identity, trace or mandatory cleanup failure.
pub(crate) fn verify_live_vhdx(root: &Path) -> TaskResult<()> {
    run_live_session(root, LiveWorkload::Assurance)
}

/// Measures an exact signed artifact on independently populated disposable storage.
/// # Errors
/// Returns build, workload, integrity or mandatory joined cleanup failures.
pub(crate) fn benchmark_multi_file(root: &Path) -> TaskResult<()> {
    run_live_session(root, LiveWorkload::RandomIo)
}

/// Owns the complete joined storage, driver and trace session for one workload.
/// # Errors
/// Returns preflight, build, live operations or mandatory cleanup failures.
fn run_live_session(root: &Path, workload: LiveWorkload) -> TaskResult<()> {
    check_live_driver_host(root)?;
    let helper = fixture::executable(root)?;
    let bundle = build_verified_production_bundle(root)?;
    let id = SessionId::create(root)?;
    println!("live VHDX session: {}", id.as_str());
    let state = LiveState {
        storage: StorageIdentity::Unobserved,
        wsl: WslAttachment::Detached,
        driver: DriverStage::Unstarted,
        identity: None,
    };
    let mut session = Session::create(root, "live-vhdx-sessions", id, state)?;
    let trace = windows_host::TraceSession::start(
        &root.join("crates/ext4-driver/operational-trace-v1.txt"),
        &root.join("target/live-driver-trace"),
    )?;
    let operation = (|| {
        create_storage(&mut session, workload)?;
        format_storage(&mut session, &helper, workload)?;
        exercise_driver(root, &bundle, &mut session, workload)
    })();
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
        assert!(verifier_activity(&report.replace("load: 1", "load: 0")).is_err());
        assert!(verifier_activity(&report.replace("0x001209bb", "0x00000001")).is_err());
        assert!(verifier_activity(&format!("{report}\n{report}")).is_err());
        let partition = Partition {
            number: 2,
            id: windows_host::guid_bytes("2ca3ad84-858a-49ba-be4a-430713ddf498")?,
            kind: windows_host::guid_bytes("0fc63daf-8483-4772-8e79-3d69d8477de4")?,
            offset: 1,
            length: 1,
        };
        let layout = "sde disk\nsde2 part 2ca3ad84-858a-49ba-be4a-430713ddf498 0fc63daf-8483-4772-8e79-3d69d8477de4\n";
        assert_eq!(linux_partition(layout, &partition)?, "sde2");
        assert!(linux_partition(&format!("{layout}{layout}"), &partition).is_err());
        Ok(())
    }
}
