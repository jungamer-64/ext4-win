use crate::TaskResult;
use core::fmt::Write as _;
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::{self as host_process, Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

/// Resolves the workspace root from the xtask package location.
///
/// # Errors
///
/// Returns an error when the compiled package location is not nested two levels below a root.
pub(crate) fn repository_root() -> Result<PathBuf, io::Error> {
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_directory
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("xtask is not nested below the workspace root"))
}

/// Creates one process-unique task directory under the repository target tree.
///
/// # Errors
///
/// Returns an error when the clock or directory creation fails.
pub(crate) fn create_task_directory(repository_root: &Path, task: &str) -> TaskResult<PathBuf> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let parent = repository_root.join("target").join(task);
    fs::create_dir_all(&parent)?;
    let directory = parent.join(format!("{}-{}", host_process::id(), elapsed.as_nanos()));
    fs::create_dir(&directory)?;
    Ok(directory)
}

/// Removes only the exact task-owned directory after validating its resolved parent boundary.
///
/// # Errors
///
/// Returns an error when the path is outside the named target subtree or cleanup fails.
pub(crate) fn remove_task_directory(
    repository_root: &Path,
    directory: &Path,
    task: &str,
) -> TaskResult<()> {
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

/// Preserves both an operation failure and its mandatory finalization failure.
///
/// # Errors
///
/// Returns the operation error, finalization error, or a combined diagnostic when both fail.
pub(crate) fn combine_verification_and_cleanup<T>(
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

/// Rejects a missing or non-file repository input or produced artifact.
///
/// # Errors
///
/// Returns `NotFound` when `path` is not a regular file.
pub(crate) fn require_file(path: &Path, description: &str) -> Result<(), io::Error> {
    if path.is_file() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{description} was not produced: {}", path.display()),
        ))
    }
}

/// Computes an uppercase SHA-256 digest for one artifact file.
///
/// # Errors
///
/// Returns an error when the file cannot be read or digest formatting fails.
pub(crate) fn sha256_file(path: &Path) -> TaskResult<String> {
    sha256_bytes(&fs::read(path)?)
}

/// Formats the SHA-256 digest of already-owned bytes without reopening a file.
///
/// # Errors
///
/// Returns an error only when hexadecimal formatting fails.
pub(crate) fn sha256_bytes(bytes: &[u8]) -> TaskResult<String> {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02X}")?;
    }
    Ok(output)
}

/// Creates one cargo child command rooted at an explicit package or workspace directory.
pub(crate) fn cargo_command(working_directory: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new("cargo");
    command.current_dir(working_directory).args(arguments);
    command
}

/// Executes one child process and reports a nonzero status as a workflow error.
///
/// # Errors
///
/// Returns an error when the child cannot start or exits unsuccessfully.
pub(crate) fn run_checked(mut command: Command, description: &str) -> TaskResult<()> {
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
pub(crate) fn run_checked_output(mut command: Command, description: &str) -> TaskResult<Output> {
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
