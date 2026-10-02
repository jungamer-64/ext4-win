//! Windows management capability boundary. Rust callers own identity, sequencing and recovery.
use crate::TaskResult;
use core::time::Duration;
use serde_json::Value;
use std::{
    ffi::OsStr,
    io::{self, Read},
    os::windows::io::AsRawHandle,
    process::{Child, Command, Output, Stdio},
    thread,
    time::Instant,
};

/// Quotes exactly one PowerShell literal; argument data cannot become executable syntax.
/// # Errors
/// Returns non-Unicode input rather than changing the selected resource identity.
pub(crate) fn literal(value: &OsStr) -> io::Result<String> {
    let value = value.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "management paths must be valid Unicode",
        )
    })?;
    let value = if let Some(tail) = value.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{tail}")
    } else {
        value.strip_prefix("\\\\?\\").unwrap_or(value).to_owned()
    };
    Ok(format!("'{}'", value.replace('\'', "''")))
}
/// Normalizes PowerShell's scalar/array/empty projection before establishing typed observations.
/// # Errors
/// Returns malformed external fields.
pub(crate) fn observations<T: serde::de::DeserializeOwned>(value: Value) -> TaskResult<Vec<T>> {
    let value = match value {
        Value::Null => Value::Array(Vec::new()),
        Value::Array(_) => value,
        scalar => Value::Array(vec![scalar]),
    };
    Ok(serde_json::from_value(value)?)
}
/// Runs one management API expression and normalizes its external representation to JSON.
/// # Errors
/// Returns process, nonzero status, output encoding, or JSON errors.
pub(crate) fn management(expression: &str) -> TaskResult<Value> {
    let mut command = Command::new("powershell.exe");
    command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $value = & {{ {expression} }}; ConvertTo-Json -InputObject $value -Depth 12 -Compress"));
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Windows management API failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
/// Executes a bounded command with captured output, preserving accepted-operation uncertainty.
#[derive(Debug)]
pub(crate) enum CommandOutcome {
    /// Requester completed and reported its exact exit status and diagnostics.
    Exited(Output),
    /// Requester was stopped and joined; the external operation may already have been accepted.
    Uncertain {
        /// Captured stdout/stderr before requester termination.
        stdout: Vec<u8>,
        /// Captured stderr.
        stderr: Vec<u8>,
    },
}
/// Requester supervision retained through successful completion or termination observation.
#[derive(Debug)]
struct Requester(Option<Child>);
impl Drop for Requester {
    /// Stops and observes an abandoned requester; accepted SCM/device effects still need reconciliation.
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if let Err(error) = child.kill() {
                eprintln!("requester fallback termination: {error}");
            }
            if let Err(error) = child.wait() {
                eprintln!("requester fallback completion: {error}");
            }
        }
    }
}
/// Runs and observes the user-mode requester separately from the external effect it requests.
/// # Errors
/// Returns spawn, pipe, observation, termination or capture failures.
pub(crate) fn bounded(mut command: Command, timeout: Duration) -> TaskResult<CommandOutcome> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let mut owner = Requester(Some(command.spawn()?));
    let child = owner
        .0
        .as_mut()
        .ok_or_else(|| io::Error::other("requester missing"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("requester stdout absent"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("requester stderr absent"))?;
    let capture = (|| -> TaskResult<CommandOutcome> {
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let start = Instant::now();
        let (status, uncertain) = loop {
            drain(&mut stdout, &mut stdout_bytes)?;
            drain(&mut stderr, &mut stderr_bytes)?;
            if let Some(status) = child.try_wait()? {
                break (status, false);
            }
            if start.elapsed() >= timeout {
                match child.kill() {
                    Ok(()) => break (child.wait()?, true),
                    Err(error) => {
                        if let Some(status) = child.try_wait()? {
                            break (status, false);
                        }
                        return Err(error.into());
                    }
                }
            }
            thread::sleep(Duration::from_millis(20));
        };
        drain(&mut stdout, &mut stdout_bytes)?;
        drain(&mut stderr, &mut stderr_bytes)?;
        if uncertain {
            Ok(CommandOutcome::Uncertain {
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            })
        } else {
            Ok(CommandOutcome::Exited(Output {
                status,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            }))
        }
    })();
    if capture.is_ok() {
        owner.0.take();
    }
    capture
}

/// Captures only bytes already available, with an explicit eight-MiB per-stream diagnostic limit.
/// # Errors
/// Returns pipe errors or a policy-limit failure; the requester owner then terminates and waits.
fn drain(pipe: &mut (impl AsRawHandle + Read), bytes: &mut Vec<u8>) -> io::Result<()> {
    let available =
        usize::try_from(windows_host::pipe_bytes_available(pipe)?).map_err(io::Error::other)?;
    let length = bytes
        .len()
        .checked_add(available)
        .ok_or_else(|| io::Error::other("diagnostic length overflow"))?;
    if length > 8 * 1024 * 1024 {
        return Err(io::Error::other(
            "requester diagnostic capture exceeds eight MiB; external outcome uncertain",
        ));
    }
    let start = bytes.len();
    bytes.resize(length, 0);
    pipe.read_exact(
        bytes
            .get_mut(start..)
            .ok_or_else(|| io::Error::other("capture range invalid"))?,
    )
}
/// Checks a requester result while keeping timeout distinguishable from returned errors.
/// # Errors
/// Returns an explicit TimedOut classification for uncertain acceptance, or exit-code diagnostics.
pub(crate) fn checked_outcome(outcome: CommandOutcome, description: &str) -> TaskResult<Vec<u8>> {
    match outcome {
        CommandOutcome::Exited(output) if output.status.success() => Ok(output.stdout),
        CommandOutcome::Exited(output) => Err(io::Error::other(format!(
            "{description} failed: {}; {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into()),
        CommandOutcome::Uncertain { stdout, stderr } => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{description}: external acceptance/outcome uncertain; {}; {}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            ),
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Native requester capture preserves both exit errors and uncertain timeout acceptance.
    /// # Errors
    /// Returns unexpected native process or pipe failures.
    /// # Panics
    /// Panics if a requester result loses its completion classification or diagnostics.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions intentionally fail process-supervision contracts after fallible execution"
    )]
    fn requester_completion_contract() -> TaskResult<()> {
        let mut command = Command::new("cmd.exe");
        command.args(["/d", "/c", "echo stdout & echo stderr 1>&2 & exit /b 7"]);
        let outcome = bounded(command, Duration::from_secs(10))?;
        assert!(
            matches!(&outcome, CommandOutcome::Exited(output) if output.status.code() == Some(7) && !output.stdout.is_empty() && !output.stderr.is_empty())
        );
        assert!(checked_outcome(outcome, "expected error").is_err());
        let mut command = Command::new("powershell.exe");
        command.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::WriteLine('accepted'); Start-Sleep -Seconds 30",
        ]);
        let outcome = bounded(command, Duration::from_secs(2))?;
        assert!(matches!(&outcome, CommandOutcome::Uncertain { .. }));
        let failure = checked_outcome(outcome, "timed requester")
            .err()
            .ok_or_else(|| io::Error::other("timeout unexpectedly completed"))?;
        assert_eq!(
            failure.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(
            literal(OsStr::new("C:\\name's space"))?,
            "'C:\\name''s space'"
        );
        Ok(())
    }
}
