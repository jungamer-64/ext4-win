//! One typed owner for production package identity, install intent, SCM and cleanup authority.
use crate::{
    TaskResult,
    process::{combine_verification_and_cleanup, run_checked, run_checked_output, sha256_file},
    production::{VerifiedProductionBundle, build_verified_production_bundle},
    session::{BundleIdentity, Operation, Phase, Session, SessionId},
    windows::{self, CommandOutcome},
};
use alloc::collections::BTreeMap;
use core::time::Duration;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Instant,
};

/// Package admission evidence retained after independent DriverStore selection.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledPackage {
    /// Structured PnPUtil-selected OEM INF.
    oem: String,
    /// SetupAPI-owned DriverStore image path.
    image: PathBuf,
}
/// Package lifecycle facts that remain meaningful after interruption.
#[derive(Debug, Serialize, Deserialize)]
enum PackageState {
    /// No installation effect has been requested.
    Absent,
    /// Installation may be accepted but its OEM identity has not been recorded.
    Installing,
    /// Independent package, path and hash evidence was observed.
    Installed(InstalledPackage),
    /// Removal may have committed while remaining service cleanup is pending.
    Removing(InstalledPackage),
    /// The exact package is absent; service path evidence remains for reconciliation.
    Removed(InstalledPackage),
}
/// Durable driver-session state; the loaded image is never inferred from bundle integrity alone.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriverState {
    /// Identity projected directly from the production gate.
    bundle: BundleIdentity,
    /// Authenticode signer identity verified before installation.
    signer: String,
    /// Narrow package acquisition/removal progress.
    package: PackageState,
    /// Independently acquired service identity; package installation can finish before this exists.
    service: ServiceIdentity,
    /// Lifecycle contract identity retained for recovery.
    control: ControlContract,
}
/// Service configuration acquisition is independent of DriverStore package admission.
#[derive(Debug, Serialize, Deserialize)]
enum ServiceIdentity {
    /// No service configuration has yet been admitted; this does not establish service absence.
    Unobserved,
    /// An exact policy/path observation was bound to the admitted package before service control.
    Bound {
        /// Raw configured ImagePath whose spelling must remain unchanged.
        raw: String,
    },
}
/// Checked-in lifecycle ABI boundary, distinct from authorization to issue a control request.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ControlContract {
    /// Win32 secured control path.
    path: String,
    /// Payload-free prepare-unload request code.
    ioctl: u32,
}
/// Inventory record normalized from the external PnPUtil XML representation.
#[derive(Debug, Deserialize)]
struct Package {
    /// Published package INF.
    oem: String,
    /// Original INF identity.
    original: String,
    /// Package provider identity.
    provider: String,
    /// Files reported by structured inventory.
    files: Vec<String>,
}

/// Parses the checked-in lifecycle contract once at its native boundary.
/// # Errors
/// Returns malformed records or unsupported lifecycle control fields.
fn control(root: &Path) -> TaskResult<ControlContract> {
    let mut values = BTreeMap::new();
    for line in
        fs::read_to_string(root.join("crates/ext4-driver/lifecycle-control-v1.txt"))?.lines()
    {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| io::Error::other("malformed lifecycle contract"))?;
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(io::Error::other("duplicate lifecycle contract record").into());
        }
    }
    let get = |key: &str| {
        values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| io::Error::other(format!("lifecycle contract missing {key}")))
    };
    let path = get("win32_device_path")?;
    let tail = path
        .strip_prefix("\\\\.\\")
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .ok_or_else(|| io::Error::other("malformed lifecycle device path"))?;
    let _validated_tail = tail;
    let ioctl = get("prepare_unload_ioctl")?
        .strip_prefix("0x")
        .filter(|value| value.len() == 8)
        .ok_or_else(|| io::Error::other("malformed lifecycle IOCTL"))?;
    if get("contract_version")? != "1" {
        return Err(io::Error::other("unsupported lifecycle contract").into());
    }
    Ok(ControlContract {
        path: path.into(),
        ioctl: u32::from_str_radix(ioctl, 16)?,
    })
}

/// Inventories all packages externally, then selects repository identity in Rust.
/// # Errors
/// Returns PnPUtil, XML-normalization or typed record errors.
fn packages(directory: &Path) -> TaskResult<Vec<Package>> {
    fs::create_dir_all(directory)?;
    let instant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let inventory = directory.join(format!("inventory-{instant}.xml"));
    let mut command = Command::new("pnputil.exe");
    command
        .args(["/enum-drivers", "/files", "/format", "xml", "/output-file"])
        .arg(&inventory);
    run_checked(command, "structured DriverStore inventory")?;
    let literal = windows::literal(inventory.as_os_str())?;
    let records = windows::management(&format!(
        "[xml]$xml=[IO.File]::ReadAllText({literal}); @($xml.PnpUtil.Driver | ForEach-Object {{ [pscustomobject]@{{ oem=[string]$_.DriverName; original=[string]$_.OriginalName; provider=[string]$_.ProviderName; files=@($_.Files.File | ForEach-Object {{ [string]$_.Name }}) }} }})"
    ))?;
    let mut records: Vec<Package> = windows::observations(records)?;
    records.retain(|package| {
        package.original.eq_ignore_ascii_case("ext4win.inf")
            && package.provider.eq_ignore_ascii_case("ext4-win")
    });
    for package in &records {
        if package
            .files
            .iter()
            .filter(|file| file.eq_ignore_ascii_case("ext4win.sys"))
            .count()
            != 1
        {
            return Err(io::Error::other(
                "structured DriverStore inventory does not identify exactly one SYS",
            )
            .into());
        }
        windows_host::driver_store_image(&package.oem)?;
    }
    Ok(records)
}

/// Obtains signer identity and certificate-store matches as external observations.
/// # Errors
/// Returns Authenticode extraction or management-boundary failures.
fn signer(bundle: &BundleIdentity, require_trust: bool) -> TaskResult<String> {
    let path = windows::literal(bundle.directory.join("ext4win.sys").as_os_str())?;
    let observation = windows::management(&format!(
        "$certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile({path})); try {{ [pscustomobject]@{{ thumbprint=$certificate.Thumbprint; root=@(Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object Thumbprint -EQ $certificate.Thumbprint).Count; publishers=@(Get-ChildItem Cert:\\LocalMachine\\TrustedPublisher | Where-Object Thumbprint -EQ $certificate.Thumbprint).Count }} }} finally {{ $certificate.Dispose() }}"
    ))?;
    let thumbprint = observation
        .get("thumbprint")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other("production signer identity absent"))?;
    if require_trust
        && (observation.get("root").and_then(serde_json::Value::as_u64) != Some(1)
            || observation
                .get("publishers")
                .and_then(serde_json::Value::as_u64)
                != Some(1))
    {
        return Err(io::Error::other(
            "production signer is not uniquely present in LocalMachine Root and TrustedPublisher",
        )
        .into());
    }
    Ok(thumbprint.into())
}

/// Read-only hosted-load preflight rejects unrelated Linux data GUID storage and existing package state.
/// # Errors
/// Returns administrator, signing, lifecycle, inventory or discovery-scope failures.
pub(crate) fn check_hosted_driver_host(root: &Path) -> TaskResult<()> {
    host_contract(root)?;
    crate::storage::assert_scope(None)?;
    println!("hosted driver-load host contract: PASS");
    Ok(())
}
/// Establishes hosted prerequisites without mutating services or storage.
/// # Errors
/// Returns any missing prerequisite or non-clean host state.
fn host_contract(root: &Path) -> TaskResult<()> {
    windows_host::require_administrator()?;
    let mut command = Command::new("bcdedit.exe");
    command.args(["/enum", "{current}"]);
    let output = run_checked_output(command, "BCD current-loader query")?;
    let report = String::from_utf8(output.stdout)?;
    let enabled = report.lines().filter(|line| {
        let words: Vec<_> = line.split_whitespace().collect();
        matches!(words.as_slice(), [name, value] if name.eq_ignore_ascii_case("testsigning") && (value.eq_ignore_ascii_case("yes") || value.eq_ignore_ascii_case("on")))
    }).count();
    if enabled != 1 {
        return Err(
            io::Error::other("current boot loader does not report TESTSIGNING enabled").into(),
        );
    }
    control(root)?;
    if windows_host::service_state("ext4win")?.is_some()
        || windows_host::service_registered("ext4win")?
    {
        return Err(io::Error::other("an ext4win service already exists").into());
    }
    if !packages(&root.join("target/driver-load-preflight"))?.is_empty() {
        return Err(io::Error::other("an ext4win DriverStore package already exists").into());
    }
    Ok(())
}

/// Exports the selected package and checks the actual SYS bytes independently of its path.
/// # Errors
/// Returns export, ambiguity or exact-hash failures.
fn export(package: &Package, directory: &Path, expected: &str) -> TaskResult<()> {
    let instant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let root = directory.join(format!("driverstore-export-{instant}"));
    fs::create_dir(&root)?;
    let mut command = Command::new("pnputil.exe");
    command.args(["/export-driver", &package.oem]).arg(&root);
    run_checked(command, "DriverStore package export")?;
    let mut candidates = Vec::new();
    let mut pending = vec![root];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if entry.file_name().eq_ignore_ascii_case("ext4win.sys") {
                candidates.push(entry.path());
            }
        }
    }
    let [image] = candidates.as_slice() else {
        return Err(io::Error::other("exported package must contain exactly one SYS").into());
    };
    let actual = sha256_file(image)?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(
            io::Error::other("exported DriverStore SYS hash differs from production").into(),
        );
    }
    println!("exported DriverStore SYS SHA-256: {actual}");
    Ok(())
}

/// Verifies the exact service policy, raw path, DriverStore mapping and current SYS bytes.
/// # Errors
/// Returns changed service, path, package or byte identity.
fn service_identity(
    package: &InstalledPackage,
    raw: &str,
    expected: &str,
    require_file: bool,
) -> TaskResult<()> {
    let configuration = windows_host::service_configuration("ext4win")?;
    let path = windows_host::driver_path(&configuration.image)?;
    if configuration.kind != 2
        || configuration.start != 3
        || configuration.image != raw
        || !path
            .as_os_str()
            .eq_ignore_ascii_case(package.image.as_os_str())
    {
        return Err(io::Error::other(
            "service policy or ImagePath differs from the package-bound identity",
        )
        .into());
    }
    let root = PathBuf::from(
        std::env::var_os("SystemRoot").ok_or_else(|| io::Error::other("SystemRoot absent"))?,
    )
    .join("System32/DriverStore/FileRepository");
    if !path
        .parent()
        .and_then(Path::parent)
        .is_some_and(|parent| parent.as_os_str().eq_ignore_ascii_case(root.as_os_str()))
        || !path
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("ext4win.sys"))
        || !path.parent().and_then(Path::file_name).is_some_and(|name| {
            name.to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("ext4win.inf_")
        })
    {
        return Err(
            io::Error::other("service ImagePath escaped the selected DriverStore image").into(),
        );
    }
    if path.is_file() {
        if !sha256_file(&path)?.eq_ignore_ascii_case(expected) {
            return Err(
                io::Error::other("service ImagePath SYS hash differs from production").into(),
            );
        }
    } else if require_file {
        return Err(io::Error::other("service DriverStore SYS is absent").into());
    }
    println!("service registry: Type=2 Start=3");
    println!("service ImagePath: {}", path.display());
    Ok(())
}

/// Waits for the independently queried SCM state, bounded by owner policy.
/// # Errors
/// Returns query or deadline failure; pending initialization/stop is retained for recovery.
fn wait_state(expected: u32, timeout: Duration) -> TaskResult<()> {
    let start = Instant::now();
    loop {
        if windows_host::service_state("ext4win")? == Some(expected) {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SCM terminal state was not observed; outcome uncertain",
            )
            .into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}
/// Requests a bounded SCM operation, publishing its intent before any accepted effect.
/// # Errors
/// Returns a returned SCM error or explicit uncertain-acceptance timeout.
fn scm(session: &mut Session<DriverState>, operation: Operation, command: &str) -> TaskResult<()> {
    session.publish(Phase::Intent(operation))?;
    let mut request = Command::new("sc.exe");
    request.args([command, "ext4win"]);
    let outcome = windows::bounded(request, Duration::from_secs(30))?;
    if matches!(outcome, CommandOutcome::Uncertain { .. }) {
        session.publish(Phase::Deferred(operation))?;
    }
    windows::checked_outcome(outcome, &format!("SCM {command}"))?;
    Ok(())
}

/// Starts the exact production-gate bundle and returns its durable session identity.
/// # Errors
/// Returns preflight, production identity, installation, start or verification failures.
/// A partially established session remains recoverable by its printed identity.
pub(crate) fn start_session(
    root: &Path,
    bundle: &VerifiedProductionBundle,
    id: SessionId,
    scope: Option<&crate::storage::DisposablePartition>,
) -> TaskResult<()> {
    host_contract(root)?;
    crate::storage::assert_scope(scope)?;
    let identity = BundleIdentity::from_verified(bundle);
    identity.revalidate(root)?;
    let signer = signer(&identity, true)?;
    println!("certificate LocalMachine\\Root thumbprint: {signer}");
    println!("certificate LocalMachine\\TrustedPublisher thumbprint: {signer}");
    let state = DriverState {
        bundle: identity,
        signer,
        package: PackageState::Absent,
        service: ServiceIdentity::Unobserved,
        control: control(root)?,
    };
    let mut session = Session::create(root, "driver-load-sessions", id, state)?;
    session.state_mut().package = PackageState::Installing;
    session.publish(Phase::Intent(Operation::InstallPackage))?;
    let mut command = Command::new("pnputil.exe");
    command
        .args(["/add-driver"])
        .arg(session.state().bundle.directory.join("ext4win.inf"))
        .arg("/install");
    run_checked(command, "ext4win package installation")?;
    bind_installed(&mut session)?;
    session.publish(Phase::Observed(Operation::InstallPackage))?;
    bind_service(&mut session, true)?;
    scm(&mut session, Operation::StartDriver, "start")?;
    wait_state(4, Duration::from_secs(15))?;
    let PackageState::Installed(package) = &session.state().package else {
        return Err(io::Error::other("driver start lost package authority").into());
    };
    let ServiceIdentity::Bound { raw } = &session.state().service else {
        return Err(io::Error::other("driver start lacks bound service identity").into());
    };
    service_identity(package, raw, &session.state().bundle.sys, true)?;
    println!("service state: Running");
    session.publish(Phase::Observed(Operation::StartDriver))?;
    Ok(())
}

/// Acquires package identity only while a durable install intent authorizes reconciliation.
/// # Errors
/// Returns absent/ambiguous packages, byte mismatches or wrong service paths.
fn bind_installed(session: &mut Session<DriverState>) -> TaskResult<()> {
    if !matches!(session.state().package, PackageState::Installing) {
        return Err(io::Error::other("package binding lacks installation intent").into());
    }
    let inventory = packages(session.directory())?;
    let [package] = inventory.as_slice() else {
        return Err(io::Error::other("installation did not select exactly one package").into());
    };
    export(package, session.directory(), &session.state().bundle.sys)?;
    let image = windows_host::driver_store_image(&package.oem)?;
    let installed = InstalledPackage {
        oem: package.oem.clone(),
        image,
    };
    if !sha256_file(&installed.image)?.eq_ignore_ascii_case(&session.state().bundle.sys) {
        return Err(io::Error::other("SetupAPI-selected package SYS hash mismatch").into());
    }
    session.state_mut().package = PackageState::Installed(installed);
    session.publish(Phase::Observed(Operation::BindPackage))?;
    Ok(())
}

/// Acquires service policy independently, only against an already verified package mapping.
/// # Errors
/// Returns missing package authority, service configuration or exact identity mismatches.
fn bind_service(session: &mut Session<DriverState>, require_file: bool) -> TaskResult<()> {
    let package = match &session.state().package {
        PackageState::Installed(package)
        | PackageState::Removing(package)
        | PackageState::Removed(package) => package,
        _ => {
            return Err(
                io::Error::other("service acquisition lacks admitted package identity").into(),
            );
        }
    };
    let raw = match &session.state().service {
        ServiceIdentity::Bound { raw } => raw.clone(),
        ServiceIdentity::Unobserved => windows_host::service_configuration("ext4win")?.image,
    };
    service_identity(package, &raw, &session.state().bundle.sys, require_file)?;
    session.state_mut().service = ServiceIdentity::Bound { raw };
    session.publish(Phase::Observed(Operation::BindService))
}

/// Loads and revalidates a driver's full durable cleanup identity.
/// # Errors
/// Returns malformed records or any changed artifact/signer/lifecycle contract.
fn recovered(root: &Path, id: &SessionId) -> TaskResult<Session<DriverState>> {
    windows_host::require_administrator()?;
    let session: Session<DriverState> = Session::load(root, "driver-load-sessions", id)?;
    session.state().bundle.revalidate(root)?;
    if signer(&session.state().bundle, false)? != session.state().signer
        || control(root)? != session.state().control
    {
        return Err(io::Error::other("driver session signer or control contract changed").into());
    }
    Ok(session)
}

/// Performs the control request in a bounded requester process after revalidating session identity.
/// # Errors
/// Returns native control/release failures or identity mismatch.
pub(crate) fn prepare_driver_unload(root: &Path, id: &OsStr) -> TaskResult<()> {
    let session = recovered(root, &SessionId::parse(id)?)?;
    let package = match &session.state().package {
        PackageState::Installed(package)
        | PackageState::Removing(package)
        | PackageState::Removed(package) => package,
        _ => return Err(io::Error::other("control retirement lacks package identity").into()),
    };
    service_identity(
        package,
        match &session.state().service {
            ServiceIdentity::Bound { raw } => raw,
            ServiceIdentity::Unobserved => {
                return Err(
                    io::Error::other("control retirement lacks acquired service identity").into(),
                );
            }
        },
        &session.state().bundle.sys,
        !matches!(session.state().package, PackageState::Removed(_)),
    )?;
    let outcome = windows_host::prepare_unload(
        Path::new(&session.state().control.path),
        session.state().control.ioctl,
    )?;
    println!("{outcome:?}");
    Ok(())
}

/// Reconciles an interrupted session; pending initialization retains its service and image.
/// # Errors
/// Returns any identity mismatch, pending/uncertain lifecycle operation or required cleanup failure.
pub(crate) fn cleanup_driver_load_session(root: &Path, id: &OsStr) -> TaskResult<()> {
    let mut session = recovered(root, &SessionId::parse(id)?)?;
    if session.phase() == Phase::Complete {
        if !packages(session.directory())?.is_empty()
            || windows_host::service_state("ext4win")?.is_some()
            || windows_host::service_registered("ext4win")?
        {
            return Err(io::Error::other("completed driver session has new service/package state; no cleanup authority is retained").into());
        }
        return Ok(());
    }
    let inventory = packages(session.directory())?;
    if inventory.len() > 1 {
        return Err(io::Error::other("ambiguous remaining ext4win packages").into());
    }
    if matches!(session.state().package, PackageState::Installing) && !inventory.is_empty() {
        bind_installed(&mut session)?;
    }
    if inventory.is_empty() {
        // Removal can commit before its acknowledgement or record publication. Preserve the
        // acquired mapping for residual-service reconciliation, without requiring deleted bytes.
        let prior = core::mem::replace(&mut session.state_mut().package, PackageState::Absent);
        session.state_mut().package = match prior {
            PackageState::Installed(package) | PackageState::Removing(package) => {
                PackageState::Removed(package)
            }
            other => other,
        };
        session.publish(Phase::Observed(Operation::RemovePackage))?;
    }
    if let Some(observed) = inventory.first() {
        let package = match &session.state().package {
            PackageState::Installed(package) | PackageState::Removing(package) => package,
            _ => {
                return Err(
                    io::Error::other("remaining package has no active session authority").into(),
                );
            }
        };
        if observed.oem != package.oem
            || windows_host::driver_store_image(&observed.oem)? != package.image
        {
            return Err(io::Error::other("remaining OEM package identity changed").into());
        }
        export(observed, session.directory(), &session.state().bundle.sys)?;
    }
    let service_state = windows_host::service_state("ext4win")?;
    if service_state.is_some() || windows_host::service_registered("ext4win")? {
        bind_service(&mut session, !inventory.is_empty())?;
    }
    if let Some(state) = service_state {
        if state == 2 {
            session.publish(Phase::Deferred(Operation::StartDriver))?;
            return Err(io::Error::other(
                "driver remains StartPending; retaining its service and package for reconciliation",
            )
            .into());
        }
        if state != 1 {
            if state != 3 {
                session.publish(Phase::Intent(Operation::PrepareUnload))?;
                let mut request = Command::new(std::env::current_exe()?);
                request
                    .arg("prepare-driver-unload")
                    .arg(session.id().as_str());
                let outcome = windows::bounded(request, Duration::from_secs(30))?;
                if matches!(outcome, CommandOutcome::Uncertain { .. }) {
                    session.publish(Phase::Deferred(Operation::PrepareUnload))?;
                }
                let output = windows::checked_outcome(outcome, "driver prepare-unload")?;
                let output = String::from_utf8(output)?;
                if !matches!(output.lines().last(), Some("Retired" | "EndpointAbsent")) {
                    return Err(
                        io::Error::other("invalid control retirement acknowledgement").into(),
                    );
                }
                session.publish(Phase::Observed(Operation::PrepareUnload))?;
                scm(&mut session, Operation::StopDriver, "stop")?;
            }
            wait_state(1, Duration::from_secs(60))?;
            session.publish(Phase::Observed(Operation::StopDriver))?;
        }
    }
    if let Some(package) = inventory.first() {
        let prior = core::mem::replace(&mut session.state_mut().package, PackageState::Absent);
        let installed = match prior {
            PackageState::Installed(package) | PackageState::Removing(package) => package,
            _ => return Err(io::Error::other("package removal lost its acquired identity").into()),
        };
        session.state_mut().package = PackageState::Removing(installed);
        session.publish(Phase::Intent(Operation::RemovePackage))?;
        let mut command = Command::new("pnputil.exe");
        command.args(["/delete-driver", &package.oem, "/uninstall", "/force"]);
        run_checked(command, "session DriverStore package removal")?;
        let prior = core::mem::replace(&mut session.state_mut().package, PackageState::Absent);
        let PackageState::Removing(installed) = prior else {
            return Err(io::Error::other("package removal state changed").into());
        };
        session.state_mut().package = PackageState::Removed(installed);
        session.publish(Phase::Observed(Operation::RemovePackage))?;
    }
    if windows_host::service_state("ext4win")?.is_some()
        || windows_host::service_registered("ext4win")?
    {
        // Package removal may alter service visibility independently. Deletion still requires
        // the exact configuration acquired from this session's verified package mapping.
        bind_service(&mut session, false)?;
        scm(&mut session, Operation::DeleteService, "delete")?;
        let start = Instant::now();
        while windows_host::service_state("ext4win")?.is_some() {
            if start.elapsed() >= Duration::from_secs(5) {
                return Err(io::Error::other("service remains after deletion").into());
            }
            thread::sleep(Duration::from_millis(100));
        }
        session.publish(Phase::Observed(Operation::DeleteService))?;
    }
    if !packages(session.directory())?.is_empty()
        || windows_host::service_state("ext4win")?.is_some()
        || windows_host::service_registered("ext4win")?
    {
        return Err(io::Error::other("service/package remains after cleanup").into());
    }
    println!("cleanup service/package absence: PASS");
    session.publish(Phase::Complete)?;
    Ok(())
}

/// Builds one bundle, loads exactly it and requires complete lifecycle finalization.
/// # Errors
/// Returns host/build/load failures while preserving mandatory cleanup failures.
pub(crate) fn verify_hosted_driver_load(root: &Path) -> TaskResult<()> {
    check_hosted_driver_host(root)?;
    let bundle = build_verified_production_bundle(root)?;
    let mut shutdown = Command::new("wsl.exe");
    shutdown.arg("--shutdown");
    run_checked(shutdown, "production WSL oracle shutdown")?;
    let id = SessionId::create(root)?;
    println!("driver-load session: {}", id.as_str());
    let operation = start_session(root, &bundle, id.clone(), None);
    let cleanup = if root
        .join("target/driver-load-sessions")
        .join(id.as_str())
        .is_dir()
    {
        cleanup_driver_load_session(root, OsStr::new(id.as_str()))
    } else {
        Ok(())
    };
    combine_verification_and_cleanup(operation, cleanup)?;
    println!("hosted kernel-load smoke assurance: PASS");
    Ok(())
}
