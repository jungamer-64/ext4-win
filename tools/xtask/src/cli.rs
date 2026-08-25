use crate::{
    TaskResult,
    development::{verify_driver, verify_fuzz_replay, verify_portable},
    interop::{verify_htree_interop, verify_journal_fixture_provenance, verify_journal_interop},
    live::{check_live_driver_host, cleanup_live_vhdx_session, verify_live_vhdx},
    process::repository_root,
    production::verify_production_driver,
};
use std::{env, ffi::OsStr, io, process::ExitCode};

/// One supported host workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Task {
    /// Runs the complete host-independent development gate.
    Portable,
    /// Checks, tests, lints, and documents the Windows driver crate.
    Driver,
    /// Replays every tracked corpus through its declared fuzz target once.
    FuzzReplay,
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
        } else if argument == "verify-fuzz-replay" {
            Some(Self::FuzzReplay)
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

/// Parses and runs one complete workflow from the process command line.
pub(crate) fn run() -> ExitCode {
    match execute() {
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
fn execute() -> TaskResult<()> {
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
        | Task::FuzzReplay
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
                Task::FuzzReplay => verify_fuzz_replay(&repository_root),
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
        "usage: cargo xtask <verify-portable|verify-driver|verify-fuzz-replay|verify-journal-interop|verify-htree-interop|verify-journal-fixture-provenance|verify-production-driver|check-live-driver-host|verify-live-vhdx|cleanup-live-vhdx-session SESSION_ID>",
    )
}

#[cfg(test)]
mod tests {
    use super::{Task, *};

    /// Every documented workflow has one exact name and ambiguous names remain rejected.
    ///
    /// # Panics
    ///
    /// Panics if a documented workflow is missing or an unspecified umbrella name is accepted.
    #[test]
    fn task_parser_accepts_only_documented_commands() {
        assert_eq!(
            Task::parse(OsStr::new("verify-portable")),
            Some(Task::Portable)
        );
        assert_eq!(Task::parse(OsStr::new("verify-driver")), Some(Task::Driver));
        assert_eq!(
            Task::parse(OsStr::new("verify-fuzz-replay")),
            Some(Task::FuzzReplay)
        );
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
}
