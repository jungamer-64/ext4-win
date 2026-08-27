#[cfg(windows)]
use crate::process::require_file;
use crate::{
    TaskResult,
    process::{cargo_command, run_checked, run_checked_output},
};
use alloc::collections::BTreeSet;
#[cfg(windows)]
use std::{env, process::Command};
use std::{fs, io, path::Path};

/// Runs formatting, checking, tests, and Clippy without selecting the WDK crate.
///
/// # Errors
///
/// Returns an error when a portable Cargo gate cannot start or exits unsuccessfully.
pub(crate) fn verify_portable(repository_root: &Path) -> TaskResult<()> {
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
pub(crate) fn verify_driver(repository_root: &Path) -> TaskResult<()> {
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

/// Replays every declared fuzz target against its tracked corpus exactly once.
///
/// The target list comes from `cargo fuzz list`; adding a target therefore cannot silently omit
/// it from the deterministic pull-request gate. The separately pinned cargo-fuzz version remains
/// a build-tool input rather than a duplicated workflow constant.
///
/// # Errors
///
/// Returns an error when the version pin is malformed, the installed cargo-fuzz version differs,
/// target discovery fails, a target name is unsafe as one corpus path component, a corpus is
/// missing or empty, or a replay exits unsuccessfully.
pub(crate) fn verify_fuzz_replay(repository_root: &Path) -> TaskResult<()> {
    let required_version = required_cargo_fuzz_version(repository_root)?;
    let version_command = cargo_command(repository_root, &["fuzz", "--version"]);
    let version_output = run_checked_output(version_command, "cargo-fuzz version query")?;
    let installed_version = String::from_utf8(version_output.stdout)?;
    require_cargo_fuzz_version(&installed_version, &required_version)?;

    let list_command = cargo_command(repository_root, &["fuzz", "list"]);
    let list_output = run_checked_output(list_command, "fuzz target discovery")?;
    let targets = parse_fuzz_targets(&String::from_utf8(list_output.stdout)?)?;
    #[cfg(windows)]
    let windows_runtime = WindowsFuzzRuntime::discover(repository_root)?;
    for target in targets {
        let corpus = repository_root.join("fuzz").join("corpus").join(&target);
        require_nonempty_corpus(&corpus, &target)?;

        let mut command = cargo_command(repository_root, &["fuzz", "run"]);
        command.arg(&target).arg(&corpus).args(["--", "-runs=1"]);
        #[cfg(windows)]
        windows_runtime.apply(&mut command);
        run_checked(command, &format!("{target} tracked-corpus replay"))?;
    }
    println!("tracked fuzz corpus replay: PASS");
    Ok(())
}

/// Host paths needed by the MSVC linker and loader for sanitizer-enabled fuzz binaries.
#[cfg(windows)]
struct WindowsFuzzRuntime {
    /// Complete MSVC linker search path containing compiler-rt.
    library_path: std::ffi::OsString,
    /// Complete executable search path containing the sanitizer runtime DLL.
    executable_path: std::ffi::OsString,
}

#[cfg(windows)]
impl WindowsFuzzRuntime {
    /// Resolves compiler-rt from the active Clang installation instead of encoding its versioned
    /// installation path in repository configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when Clang cannot report a usable resource directory, the required
    /// compiler-rt artifacts are absent, or a child search path cannot be constructed.
    fn discover(repository_root: &Path) -> TaskResult<Self> {
        let mut command = Command::new("clang");
        command
            .current_dir(repository_root)
            .arg("--print-resource-dir");
        let output = run_checked_output(command, "Clang resource-directory query")?;
        let report = String::from_utf8(output.stdout)?;
        let resource_directory = report.trim();
        if resource_directory.is_empty() {
            return Err(io::Error::other("Clang returned an empty resource directory").into());
        }

        let runtime_directory = Path::new(resource_directory).join("lib").join("windows");
        require_file(
            &runtime_directory.join("clang_rt.asan_dynamic_runtime_thunk-x86_64.lib"),
            "MSVC AddressSanitizer linker runtime",
        )?;
        require_file(
            &runtime_directory.join("clang_rt.asan_dynamic-x86_64.dll"),
            "MSVC AddressSanitizer loader runtime",
        )?;

        Ok(Self {
            library_path: prepend_environment_path("LIB", &runtime_directory)?,
            executable_path: prepend_environment_path("PATH", &runtime_directory)?,
        })
    }

    /// Applies the discovered runtime only to the fuzz child process and its descendants.
    fn apply(&self, command: &mut Command) {
        command
            .env("LIB", &self.library_path)
            .env("PATH", &self.executable_path);
    }
}

/// Prepends one exact directory to a child process search path without mutating global state.
///
/// # Errors
///
/// Returns an error when the existing path contains a value that cannot be joined safely.
#[cfg(windows)]
fn prepend_environment_path(variable: &str, directory: &Path) -> TaskResult<std::ffi::OsString> {
    let mut paths = vec![directory.to_path_buf()];
    if let Some(existing) = env::var_os(variable) {
        paths.extend(env::split_paths(&existing));
    }
    Ok(env::join_paths(paths)?)
}

/// Reads and validates the repository-owned cargo-fuzz version pin.
///
/// # Errors
///
/// Returns an error when the pin cannot be read or is not one ASCII semantic-version token.
fn required_cargo_fuzz_version(repository_root: &Path) -> TaskResult<String> {
    let path = repository_root.join("fuzz").join("cargo-fuzz.version");
    let contents = fs::read_to_string(path)?;
    let version = contents.trim();
    if version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err(
            io::Error::other("cargo-fuzz version pin is not one ASCII version token").into(),
        );
    }
    Ok(version.to_owned())
}

/// Requires the installed cargo-fuzz report to match the repository pin exactly.
///
/// # Errors
///
/// Returns an error for a different version or any noncanonical version output.
fn require_cargo_fuzz_version(report: &str, required: &str) -> TaskResult<()> {
    let expected = format!("cargo-fuzz {required}");
    if report.trim() == expected {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "cargo-fuzz version mismatch: required={required} installed={}",
            report.trim()
        ))
        .into())
    }
}

/// Parses the canonical cargo-fuzz target list into unique path-safe target names.
///
/// # Errors
///
/// Returns an error when no target exists, a name is duplicated, or a name cannot be used as one
/// corpus-directory component.
fn parse_fuzz_targets(report: &str) -> TaskResult<Vec<String>> {
    let mut targets = BTreeSet::new();
    for line in report.lines() {
        let target = line.trim();
        if target.is_empty() {
            continue;
        }
        if !target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(io::Error::other(format!(
                "fuzz target is not one safe path component: {target}"
            ))
            .into());
        }
        if !targets.insert(target.to_owned()) {
            return Err(io::Error::other(format!("duplicate fuzz target: {target}")).into());
        }
    }
    if targets.is_empty() {
        return Err(io::Error::other("cargo fuzz list returned no targets").into());
    }
    Ok(targets.into_iter().collect())
}

/// Requires one target's tracked corpus to exist and contain at least one regular file.
///
/// # Errors
///
/// Returns an error when the directory cannot be read or contains no regular corpus input.
fn require_nonempty_corpus(corpus: &Path, target: &str) -> TaskResult<()> {
    for entry in fs::read_dir(corpus)? {
        if entry?.file_type()?.is_file() {
            return Ok(());
        }
    }
    Err(io::Error::other(format!("tracked fuzz corpus is empty: {target}")).into())
}

#[cfg(test)]
mod tests {
    use super::{parse_fuzz_targets, require_cargo_fuzz_version};

    /// Version reports match only the exact pinned cargo-fuzz executable identity.
    ///
    /// # Panics
    ///
    /// Panics if whitespace normalization changes the identity or another version is accepted.
    #[test]
    fn cargo_fuzz_version_requires_exact_identity() {
        assert!(require_cargo_fuzz_version("cargo-fuzz 0.13.2\n", "0.13.2").is_ok());
        assert!(require_cargo_fuzz_version("cargo-fuzz 0.13.3", "0.13.2").is_err());
        assert!(require_cargo_fuzz_version("cargo fuzz 0.13.2", "0.13.2").is_err());
    }

    /// Target discovery is deterministic and rejects names that could escape a corpus directory.
    ///
    /// # Panics
    ///
    /// Panics if sorting, duplicate rejection, or path-component validation regresses.
    #[test]
    fn fuzz_targets_are_unique_safe_path_components() {
        assert_eq!(
            parse_fuzz_targets("mount_image\njournal_recovery\n").ok(),
            Some(vec![
                "journal_recovery".to_owned(),
                "mount_image".to_owned()
            ])
        );
        assert!(parse_fuzz_targets("mount_image\nmount_image\n").is_err());
        assert!(parse_fuzz_targets("../mount_image\n").is_err());
        assert!(parse_fuzz_targets("\n").is_err());
    }
}
