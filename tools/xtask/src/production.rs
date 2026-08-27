use crate::{
    TaskResult,
    development::{verify_driver, verify_portable},
    interop::{verify_htree_interop, verify_journal_interop},
    process::{
        cargo_command, combine_verification_and_cleanup, create_task_directory,
        remove_task_directory, require_file, run_checked, run_checked_output, sha256_bytes,
        sha256_file,
    },
};
use alloc::collections::BTreeSet;
use core::fmt::Write as _;
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::{self as host_process, Command},
    time::{SystemTime, UNIX_EPOCH},
};

/// Fixed marker prefix embedded in all identity-bound production artifacts.
const ARTIFACT_ID_MARKER: &str = "EXT4WIN_ARTIFACT_ID=";

/// Sentinel reserved for ordinary builds that did not pass the production workflow.
pub(crate) const UNVERIFIED_ARTIFACT_ID: &str = "00000000000000000000000000000000";

/// Cargo encoded-rustflags field separator.
const ENCODED_RUSTFLAGS_SEPARATOR: &str = "\u{1f}";

/// Non-sentinel identity shared by one production build's IR, link map, and image.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ArtifactIdentity(String);

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
    pub(crate) fn create(repository_root: &Path) -> TaskResult<Self> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let mut hasher = Sha256::new();
        hasher.update(elapsed.as_nanos().to_le_bytes());
        hasher.update(host_process::id().to_le_bytes());
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
    pub(crate) fn as_str(&self) -> &str {
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

/// Atomically published production bundle whose manifest and artifacts passed the release gate.
#[derive(Debug)]
pub(crate) struct VerifiedProductionBundle {
    /// Exact atomically published bundle directory.
    directory: PathBuf,
    /// Build-generated identity embedded in the signed driver and directory name.
    artifact_id: String,
    /// Hash of the exact signed SYS admitted by the production gate.
    driver_hash: String,
    /// Hash of the exact signed catalog admitted by the production gate.
    catalog_hash: String,
    /// Hash of the exact installation metadata admitted by the production gate.
    inf_hash: String,
}

impl VerifiedProductionBundle {
    /// Returns the exact published directory passed to downstream artifact consumers.
    pub(crate) fn as_path(&self) -> &Path {
        &self.directory
    }

    /// Returns the exact embedded artifact identity established during production verification.
    pub(crate) fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Returns the admitted signed-driver digest without reparsing the published manifest.
    pub(crate) fn driver_hash(&self) -> &str {
        &self.driver_hash
    }

    /// Returns the admitted signed-catalog digest without reparsing the published manifest.
    pub(crate) fn catalog_hash(&self) -> &str {
        &self.catalog_hash
    }

    /// Returns the admitted installation-metadata digest without reparsing the published manifest.
    pub(crate) fn inf_hash(&self) -> &str {
        &self.inf_hash
    }
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

/// Builds and verifies one exact signed production driver bundle.
///
/// # Errors
///
/// Returns an error on non-Windows hosts, failed build or analysis commands, missing or invalid
/// artifacts, source drift, or artifact hashing failure.
pub(crate) fn verify_production_driver(repository_root: &Path) -> TaskResult<()> {
    let _bundle = build_verified_production_bundle(repository_root)?;
    Ok(())
}

/// Runs the release umbrella and returns the atomically published evidence bundle.
///
/// # Errors
///
/// Returns an error on any portable, driver, interoperability, WDK, signing, reachability,
/// identity, source-drift, or publication failure.
pub(crate) fn build_verified_production_bundle(
    repository_root: &Path,
) -> TaskResult<VerifiedProductionBundle> {
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
    Ok(VerifiedProductionBundle {
        directory: bundle_directory,
        artifact_id: identity.as_str().to_owned(),
        driver_hash: sealed.driver_hash,
        catalog_hash: sealed.catalog_hash,
        inf_hash: sealed.inf_hash,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The process boundary keeps the path, artifact ID, and all three hashes paired.
    ///
    /// # Panics
    ///
    /// Panics if serialization drops, swaps, or splits an identity field.
    #[test]
    fn verified_bundle_process_arguments_preserve_identity() {
        let bundle = VerifiedProductionBundle {
            directory: PathBuf::from("bundle with spaces/0123456789abcdef0123456789abcdef"),
            artifact_id: "0123456789abcdef0123456789abcdef".to_owned(),
            driver_hash: "A".repeat(64),
            catalog_hash: "B".repeat(64),
            inf_hash: "C".repeat(64),
        };
        let mut command = Command::new("powershell.exe");
        crate::driver_load::append_verified_bundle_arguments(&mut command, &bundle);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("-Bundle"),
                bundle.directory.as_os_str(),
                OsStr::new("-BundleArtifactId"),
                OsStr::new(&bundle.artifact_id),
                OsStr::new("-BundleSysHash"),
                OsStr::new(&bundle.driver_hash),
                OsStr::new("-BundleCatalogHash"),
                OsStr::new(&bundle.catalog_hash),
                OsStr::new("-BundleInfHash"),
                OsStr::new(&bundle.inf_hash),
            ]
        );
    }

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
    /// Returns the digest of one normalized source record.
    fn record_digest(path: &str, contents: Option<&[u8]>) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hash_source_record(&mut hasher, path, contents);
        hasher.finalize().into()
    }
}
