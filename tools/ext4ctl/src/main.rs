//! Administrator CLI for UUID-scoped identity and future-mount policy configuration.
use std::process::ExitCode;

/// Resolves parsed updates against one observed policy before acquiring persistence authority.
/// # Errors
/// Rejects recovery options on RW and memory budgets outside the memory recovery mode.
fn replace_policy_fields(
    observed: ext4_core::MountAccess,
    access: Option<ext4_control::AccessMode>,
    recovery: Option<ext4_core::ReadOnlyRecovery>,
    memory: Option<ext4_core::RecoveryMemoryLimit>,
) -> Result<ext4_core::MountAccess, String> {
    use ext4_core::{MountAccess, ReadOnlyRecovery};
    let selected = match access {
        Some(ext4_control::AccessMode::ReadWrite) => MountAccess::ReadWrite,
        Some(ext4_control::AccessMode::ReadOnly) => MountAccess::ReadOnly {
            recovery: ReadOnlyRecovery::Replay,
        },
        None => observed,
    };
    match selected {
        MountAccess::ReadWrite if recovery.is_some() || memory.is_some() => {
            Err("recovery options require read-only access".to_owned())
        }
        MountAccess::ReadWrite => Ok(selected),
        MountAccess::ReadOnly { recovery: current } => {
            let recovery = recovery.unwrap_or(current);
            let recovery = match (recovery, memory) {
                (ReadOnlyRecovery::Memory { limit }, bytes) => ReadOnlyRecovery::Memory {
                    limit: bytes.unwrap_or(limit),
                },
                (_, Some(_)) => return Err("--recovery-memory requires memory recovery".to_owned()),
                (mode, None) => mode,
            };
            Ok(MountAccess::ReadOnly { recovery })
        }
    }
}

/// User-visible grammar; replacements contain the entire desired table.
const USAGE: &str = "ext4ctl volumes\next4ctl features <volume-path>\next4ctl trim <volume-path|ext4-uuid>\next4ctl whoami\next4ctl identity show <volume-path|ext4-uuid>\next4ctl identity replace <volume-path|ext4-uuid> [--user <account|SID> <UID>]... [--group <account|SID> <GID>]...\next4ctl identity clear <volume-path|ext4-uuid>\next4ctl policy show <volume-path|ext4-uuid>\next4ctl policy set <volume-path|ext4-uuid> [--access read-write|read-only] [--recovery replay|noload|memory] [--recovery-memory <bytes>]\next4ctl casefold show <directory>\next4ctl casefold set <directory> on|off";
/// Fully parsed action before any replacement can be submitted.
#[derive(Debug, Eq, PartialEq)]
enum Command {
    /// Mounted ext4 volumes and UUIDs.
    Volumes,
    /// Discard free ranges through the currently mounted volume's allocation coordinator.
    Trim(String),
    /// Observe the mounted format declarations without enabling or changing any feature.
    Features(String),
    /// Observe one opened directory's committed comparison state.
    CasefoldShow(String),
    /// Journal an empty directory's comparison transition.
    CasefoldSet {
        /// Directory path selected by the native handle.
        path: String,
        /// Complete requested comparison state.
        state: ext4_core::DirectoryCasefold,
    },
    /// Effective token user and primary group.
    Whoami,
    /// Saved/applied generations and complete active table.
    Show(String),
    /// Observe the durable selection for subsequent mounts.
    PolicyShow(String),
    /// Preserve unspecified policy fields and compare the observed generation before saving.
    PolicySet {
        /// Exact UUID or mounted volume path.
        target: String,
        /// Explicit media-mode replacement.
        access: Option<ext4_control::AccessMode>,
        /// Explicit recovery mode; a memory budget alone does not select it.
        recovery: Option<ext4_core::ReadOnlyRecovery>,
        /// Explicit logical recovery-memory budget.
        recovery_memory: Option<ext4_core::RecoveryMemoryLimit>,
    },
    /// Full replacement, including empty tables for clear.
    Replace {
        /// Explicit UUID or Windows volume path.
        target: String,
        /// Unresolved user account and numeric ID pairs.
        users: Vec<(String, u32)>,
        /// Unresolved group account and numeric ID pairs.
        groups: Vec<(String, u32)>,
    },
}
/// Parses all arguments before acquiring mutation authority.
/// # Errors
/// Rejects unknown actions, missing operands and invalid numeric identities.
fn parse(mut args: impl Iterator<Item = String>) -> Result<Command, String> {
    let action = args.next().ok_or_else(|| USAGE.to_owned())?;
    let command = match action.as_str() {
        "volumes" => Command::Volumes,
        "whoami" => Command::Whoami,
        "trim" => Command::Trim(args.next().ok_or_else(|| USAGE.to_owned())?),
        "features" => Command::Features(args.next().ok_or_else(|| USAGE.to_owned())?),
        "casefold" => {
            let action = args.next().ok_or_else(|| USAGE.to_owned())?;
            let path = args.next().ok_or_else(|| USAGE.to_owned())?;
            match action.as_str() {
                "show" => Command::CasefoldShow(path),
                "set" => {
                    let state = match args.next().as_deref() {
                        Some("on") => ext4_core::DirectoryCasefold::Enabled,
                        Some("off") => ext4_core::DirectoryCasefold::Disabled,
                        _ => return Err(USAGE.to_owned()),
                    };
                    Command::CasefoldSet { path, state }
                }
                _ => return Err(USAGE.to_owned()),
            }
        }
        "policy" => {
            let action = args.next().ok_or_else(|| USAGE.to_owned())?;
            let target = args.next().ok_or_else(|| USAGE.to_owned())?;
            match action.as_str() {
                "show" => Command::PolicyShow(target),
                "set" => {
                    let mut access = None;
                    let mut recovery = None;
                    let mut recovery_memory = None;
                    while let Some(option) = args.next() {
                        let value = args
                            .next()
                            .ok_or_else(|| format!("{option} requires a value"))?;
                        match option.as_str() {
                            "--access" if access.is_none() => {
                                access = Some(match value.as_str() {
                                    "read-write" => ext4_control::AccessMode::ReadWrite,
                                    "read-only" => ext4_control::AccessMode::ReadOnly,
                                    _ => return Err(format!("invalid access mode: {value}")),
                                })
                            }
                            "--recovery" if recovery.is_none() => {
                                recovery = Some(match value.as_str() {
                                    "replay" => ext4_core::ReadOnlyRecovery::Replay,
                                    "noload" => ext4_core::ReadOnlyRecovery::NoLoad,
                                    "memory" => ext4_core::ReadOnlyRecovery::Memory {
                                        limit: ext4_core::RecoveryMemoryLimit::DEFAULT,
                                    },
                                    _ => return Err(format!("invalid recovery mode: {value}")),
                                });
                            }
                            "--recovery-memory" if recovery_memory.is_none() => {
                                let bytes = value
                                    .parse::<usize>()
                                    .map_err(|error| format!("invalid recovery budget: {error}"))?;
                                recovery_memory = Some(
                                    ext4_core::RecoveryMemoryLimit::new(bytes)
                                        .map_err(|error| error.to_string())?,
                                );
                            }
                            _ => {
                                return Err(format!("unknown or repeated policy option: {option}"));
                            }
                        }
                    }
                    if access.is_none() && recovery.is_none() && recovery_memory.is_none() {
                        return Err("policy set requires at least one option".to_owned());
                    }
                    Command::PolicySet {
                        target,
                        access,
                        recovery,
                        recovery_memory,
                    }
                }
                _ => return Err(USAGE.to_owned()),
            }
        }
        "identity" => {
            let action = args.next().ok_or_else(|| USAGE.to_owned())?;
            let target = args.next().ok_or_else(|| USAGE.to_owned())?;
            match action.as_str() {
                "show" => Command::Show(target),
                "clear" => Command::Replace {
                    target,
                    users: Vec::new(),
                    groups: Vec::new(),
                },
                "replace" => {
                    let mut users = Vec::new();
                    let mut groups = Vec::new();
                    while let Some(option) = args.next() {
                        let entries = match option.as_str() {
                            "--user" => &mut users,
                            "--group" => &mut groups,
                            _ => return Err(format!("unknown mapping option: {option}")),
                        };
                        let account = args.next().ok_or_else(|| {
                            format!("{option} requires an account or SID and numeric ID")
                        })?;
                        let id = args
                            .next()
                            .ok_or_else(|| format!("{option} requires a numeric ID"))?
                            .parse::<u32>()
                            .map_err(|error| format!("invalid numeric ID: {error}"))?;
                        entries.push((account, id));
                    }
                    Command::Replace {
                        target,
                        users,
                        groups,
                    }
                }
                _ => return Err(USAGE.to_owned()),
            }
        }
        _ => return Err(USAGE.to_owned()),
    };
    if let Some(extra) = args.next() {
        return Err(format!("unexpected argument: {extra}"));
    }
    Ok(command)
}
/// Displays ext4 UUID bytes without native GUID byte-order conversion.
#[cfg(windows)]
fn uuid_text(uuid: ext4_core::FilesystemUuid) -> String {
    ext4_security::uuid_text(uuid)
        .into_iter()
        .map(char::from)
        .collect()
}
/// Retains authoritative comparison state even if native release fails after acknowledgement.
/// # Errors
/// Reports the native outcome without retrying a possibly committed transition.
#[cfg(windows)]
fn casefold_reply(
    result: Result<ext4_core::DirectoryCasefold, windows_host::DirectoryCasefoldError>,
) -> Result<ext4_core::DirectoryCasefold, String> {
    match result {
        Ok(state) => Ok(state),
        Err(error @ windows_host::DirectoryCasefoldError::Release { state, .. }) => {
            println!("casefold {}", casefold_text(state));
            Err(error.to_string())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Presents physical progress before deciding the command's exit status.
#[cfg(windows)]
fn show_trim(report: ext4_control::TrimReport) {
    println!(
        "UUID {}\noutcome {:?}\nstatus {:#010x}\nacknowledged bytes {}\nuncertain bytes {}",
        uuid_text(report.uuid),
        report.outcome,
        report.status,
        report.acknowledged_bytes,
        report.uncertain_bytes
    );
}

/// Shows complete masks separately from named declarations and immutable admitted media access.
#[cfg(windows)]
fn show_features(state: ext4_control::FeaturesState) {
    use ext4_core::FilesystemFeature as Feature;
    println!(
        "UUID {}\nadmitted access {:?}\ncompatible {:#010x}\nincompatible {:#010x}\nread-only-compatible {:#010x}",
        uuid_text(state.uuid),
        state.admitted_access,
        state.declared.compatible.bits(),
        state.declared.incompatible.bits(),
        state.declared.read_only_compatible.bits()
    );
    for (name, feature) in [
        ("casefold", Feature::Casefold),
        ("inline_data", Feature::InlineData),
        ("ea_inode", Feature::AttributeValueInodes),
        ("mmp", Feature::MultipleMountProtection),
        ("fast_commit", Feature::FastCommit),
        ("encrypt", Feature::Encryption),
        ("bigalloc", Feature::BigAllocation),
        ("metadata_csum", Feature::MetadataChecksums),
        ("dir_index", Feature::DirectoryIndex),
        ("verity", Feature::Verity),
    ] {
        println!(
            "{name} {}",
            if state.declared.contains(feature) {
                "declared"
            } else {
                "absent"
            }
        );
    }
}

/// Retains an authoritative report even if host cleanup fails after the driver replied.
/// # Errors
/// Stopped, unknown or cleanup-failed operations fail the CLI without automatic resubmission.
#[cfg(windows)]
fn trim_reply(
    result: Result<ext4_control::TrimReport, windows_host::TrimError>,
) -> Result<(), String> {
    match result {
        Ok(report) => {
            show_trim(report);
            if report.outcome == ext4_control::TrimOutcome::Complete {
                Ok(())
            } else {
                Err(format!("TRIM stopped: {:?}", report.outcome))
            }
        }
        Err(error) => {
            if let windows_host::TrimSubmission::Acknowledged(report) = error.submission {
                show_trim(report);
            }
            Err(error.to_string())
        }
    }
}
/// User-facing spelling shared by observed and acknowledged comparison states.
#[cfg(windows)]
const fn casefold_text(state: ext4_core::DirectoryCasefold) -> &'static str {
    match state {
        ext4_core::DirectoryCasefold::Disabled => "off",
        ext4_core::DirectoryCasefold::Enabled => "on",
    }
}

/// Resolves explicit UUIDs or mounted volumes, without guessing numeric identities.
/// # Errors
/// Returns native-volume resolution diagnostics.
#[cfg(windows)]
fn target_uuid(target: &str) -> Result<ext4_core::FilesystemUuid, String> {
    match ext4_security::parse_uuid(target) {
        Ok(uuid) => Ok(uuid),
        Err(_) => windows_host::volume_identity(target)
            .map_err(|error| format!("cannot resolve ext4 UUID from {target}: {error}")),
    }
}
/// Prints current commit facts and explicit mappings.
#[cfg(windows)]
fn show(state: &ext4_security::MappingState) {
    println!(
        "UUID {}\nsaved generation {}\napplied generation {}\noutcome {:?}\nstatus {:#010x}",
        uuid_text(state.active.uuid),
        state.saved_generation,
        state.active.generation,
        state.outcome,
        state.status
    );
    for entry in state.active.map.users() {
        println!("user {} {}", entry.sid, entry.uid.as_u32());
    }
    for entry in state.active.map.groups() {
        println!("group {} {}", entry.sid, entry.gid.as_u32());
    }
}
/// Reports durable selection without implying that an existing session was changed.
#[cfg(windows)]
fn show_policy(state: &ext4_control::PolicyState) {
    use ext4_core::{MountAccess, ReadOnlyRecovery};
    let (access, recovery) = match state.selected.policy {
        MountAccess::ReadWrite => ("read-write", "none"),
        MountAccess::ReadOnly {
            recovery: ReadOnlyRecovery::Replay,
        } => ("read-only", "replay"),
        MountAccess::ReadOnly {
            recovery: ReadOnlyRecovery::NoLoad,
        } => ("read-only", "noload"),
        MountAccess::ReadOnly {
            recovery: ReadOnlyRecovery::Memory { .. },
        } => ("read-only", "memory"),
    };
    println!(
        "UUID {}\nsaved generation {}\noutcome {:?}\nstatus {:#010x}\naccess {}\nrecovery {}\napplies to subsequent mounts",
        uuid_text(state.selected.uuid),
        state.selected.generation,
        state.outcome,
        state.status,
        access,
        recovery
    );
    if let MountAccess::ReadOnly {
        recovery: ReadOnlyRecovery::Memory { limit },
    } = state.selected.policy
    {
        println!("recovery memory {} bytes", limit.bytes());
    }
}
/// Retains an authoritative policy reply even when native handle release failed.
/// # Errors
/// Preserves preparation, query, uncertainty and release diagnostics.
#[cfg(windows)]
fn policy_reply(
    result: Result<
        ext4_control::PolicyState,
        windows_host::ControlError<ext4_control::PolicyState>,
    >,
) -> Result<ext4_control::PolicyState, String> {
    match result {
        Ok(state) => Ok(state),
        Err(windows_host::ControlError::Release { state, source }) => {
            show_policy(&state);
            Err(format!(
                "policy reply received; control handle release failed: {source}"
            ))
        }
        Err(error) => Err(error.to_string()),
    }
}
/// Executes a fully parsed command; complete validation precedes replacement submission.
/// # Errors
/// Preserves native diagnostics and refuses unresolved saved/applied state.
#[cfg(windows)]
fn execute(command: Command) -> Result<(), String> {
    match command {
        Command::Trim(volume) => trim_reply(windows_host::trim_volume(&volume))?,
        Command::Features(volume) => match windows_host::query_volume_features(&volume) {
            Ok(state) => show_features(state),
            Err(error) => {
                if let windows_host::FeaturesQueryError::Release { state, .. } = &error {
                    show_features(*state);
                }
                return Err(error.to_string());
            }
        },
        Command::Volumes => {
            for (name, uuid) in
                windows_host::identity_volumes().map_err(|error| error.to_string())?
            {
                println!("{} {name}", uuid_text(uuid));
            }
        }
        Command::CasefoldShow(path) => {
            let state = casefold_reply(windows_host::query_directory_casefold(
                std::path::Path::new(&path),
            ))?;
            println!("casefold {}", casefold_text(state));
        }
        Command::CasefoldSet { path, state } => {
            let state = casefold_reply(windows_host::set_directory_casefold(
                std::path::Path::new(&path),
                state,
            ))?;
            println!("casefold {}", casefold_text(state));
        }
        Command::Whoami => {
            let identity = windows_host::effective_identity().map_err(|error| error.to_string())?;
            println!(
                "user {}\nprimary group {}",
                identity.user, identity.primary_group
            );
        }
        Command::Show(target) => show(
            &windows_host::query_identity(target_uuid(&target)?)
                .map_err(|error| error.to_string())?,
        ),
        Command::PolicyShow(target) => show_policy(&policy_reply(windows_host::query_policy(
            target_uuid(&target)?,
        ))?),
        Command::PolicySet {
            target,
            access,
            recovery,
            recovery_memory,
        } => {
            let uuid = target_uuid(&target)?;
            let observed = policy_reply(windows_host::query_policy(uuid))?;
            if observed.outcome == ext4_control::PolicyOutcome::Unknown {
                show_policy(&observed);
                return Err(
                    "policy persistence requires reconciliation before replacement".to_owned(),
                );
            }
            let policy =
                replace_policy_fields(observed.selected.policy, access, recovery, recovery_memory)?;
            let replacement =
                ext4_control::PolicyReplacement::new(observed.selected.generation, uuid, policy)
                    .map_err(|error| format!("invalid policy replacement: {error:?}"))?;
            let state = policy_reply(windows_host::replace_policy(replacement))?;
            show_policy(&state);
            if state.outcome != ext4_control::PolicyOutcome::Saved {
                return Err(format!("policy was not saved: {:?}", state.outcome));
            }
        }
        Command::Replace {
            target,
            users,
            groups,
        } => {
            let uuid = target_uuid(&target)?;
            let users = users
                .into_iter()
                .map(|(account, uid)| {
                    windows_host::resolve_identity(&account).map(|sid| ext4_security::UserMapping {
                        sid,
                        uid: ext4_core::Ext4Uid::from_u32(uid),
                    })
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            let groups = groups
                .into_iter()
                .map(|(account, gid)| {
                    windows_host::resolve_identity(&account).map(|sid| {
                        ext4_security::GroupMapping {
                            sid,
                            gid: ext4_core::Ext4Gid::from_u32(gid),
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            let map = ext4_security::IdentityMap::new(users, groups)
                .map_err(|error| format!("invalid identity table: {error:?}"))?;
            let observed = windows_host::query_identity(uuid).map_err(|error| error.to_string())?;
            if observed.outcome == ext4_security::PublicationOutcome::Unknown
                || observed.saved_generation != observed.active.generation
            {
                show(&observed);
                return Err(
                    "saved/applied state requires reconciliation before replacement".to_owned(),
                );
            }
            let expected = observed.active.generation;
            let generation = expected
                .checked_add(1)
                .ok_or_else(|| "identity generation exhausted".to_owned())?;
            let replacement = ext4_security::Replacement::new(
                expected,
                ext4_security::MappingSnapshot {
                    uuid,
                    generation,
                    map,
                },
            )
            .map_err(|error| format!("invalid replacement: {error:?}"))?;
            let state =
                windows_host::replace_identity(replacement).map_err(|error| error.to_string())?;
            show(&state);
            if state.outcome != ext4_security::PublicationOutcome::Applied {
                return Err(format!("replacement was not applied: {:?}", state.outcome));
            }
        }
    }
    Ok(())
}
/// Non-Windows builds parse arguments but cannot submit a native request.
/// # Errors
/// Always returns the required platform condition.
#[cfg(not(windows))]
fn execute(_command: Command) -> Result<(), String> {
    Err("ext4ctl requires Windows and a running ext4 driver".to_owned())
}
/// Process boundary retains parser/native diagnostics and exits unsuccessfully on failure.
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|value| value == "--help" || value == "-h")
    {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match parse(args.into_iter()).and_then(execute) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(test)]
mod tests {
    /// # Panics
    /// Fails if access-only RO retains private recovery or budget-only input enables it.
    #[test]
    fn recovery_options_select_one_complete_policy() {
        use ext4_core::{MountAccess, ReadOnlyRecovery, RecoveryMemoryLimit};
        let memory = MountAccess::ReadOnly {
            recovery: ReadOnlyRecovery::Memory {
                limit: RecoveryMemoryLimit::DEFAULT,
            },
        };
        assert_eq!(
            replace_policy_fields(memory, Some(ext4_control::AccessMode::ReadOnly), None, None),
            Ok(MountAccess::ReadOnly {
                recovery: ReadOnlyRecovery::Replay
            })
        );
        assert!(
            replace_policy_fields(
                MountAccess::ReadWrite,
                None,
                Some(ReadOnlyRecovery::NoLoad),
                None
            )
            .is_err()
        );
        assert!(
            replace_policy_fields(
                MountAccess::ReadOnly {
                    recovery: ReadOnlyRecovery::Replay
                },
                None,
                None,
                Some(RecoveryMemoryLimit::DEFAULT)
            )
            .is_err()
        );
        for mode in ["replay", "noload", "memory"] {
            assert!(
                parse(
                    [
                        "policy",
                        "set",
                        "X:",
                        "--access",
                        "read-only",
                        "--recovery",
                        mode
                    ]
                    .into_iter()
                    .map(str::to_owned)
                )
                .is_ok()
            );
        }
    }
    use super::*;
    /// # Panics
    /// Fails if an observation command accepts a feature toggle or omits the mounted target.
    #[test]
    fn features_is_an_explicit_mounted_observation() {
        assert_eq!(
            parse(["features", "X:"].into_iter().map(str::to_owned)),
            Ok(Command::Features("X:".to_owned()))
        );
        for args in [
            vec!["features"],
            vec!["features", "X:", "--enable", "fast_commit"],
        ] {
            assert!(parse(args.into_iter().map(str::to_owned)).is_err());
        }
    }
    /// # Panics
    /// Fails if a missing volume or extra operand can reach discard submission.
    #[test]
    fn trim_requires_one_explicit_volume() {
        assert_eq!(
            parse(["trim", "X:"].into_iter().map(str::to_owned)),
            Ok(Command::Trim("X:".to_owned()))
        );
        for args in [vec!["trim"], vec!["trim", "X:", "--retry"]] {
            assert!(parse(args.into_iter().map(str::to_owned)).is_err());
        }
    }
    /// # Panics
    /// Panics if partial policy updates lose omission semantics or invalid budgets reach submission.
    #[test]
    fn policy_options_are_complete_before_submission() {
        assert_eq!(
            parse(
                ["policy", "set", "X:", "--access", "read-only"]
                    .into_iter()
                    .map(str::to_owned)
            ),
            Ok(Command::PolicySet {
                target: "X:".to_owned(),
                access: Some(ext4_control::AccessMode::ReadOnly),
                recovery: None,
                recovery_memory: None,
            })
        );
        for args in [
            vec!["policy", "set", "X:"],
            vec!["policy", "set", "X:", "--recovery-memory", "0"],
            vec![
                "policy",
                "set",
                "X:",
                "--recovery-memory",
                "18446744073709551616",
            ],
            vec![
                "policy",
                "set",
                "X:",
                "--access",
                "read-only",
                "--access",
                "read-write",
            ],
            vec!["policy", "show", "X:", "--access", "read-write"],
        ] {
            assert!(parse(args.into_iter().map(str::to_owned)).is_err());
        }
    }
    /// # Panics
    /// Fails if comparison controls accept incomplete or ambiguous transition operands.
    #[test]
    fn directory_comparison_grammar() {
        assert_eq!(
            parse(
                ["casefold", "set", "X:/empty", "on"]
                    .into_iter()
                    .map(str::to_owned)
            ),
            Ok(Command::CasefoldSet {
                path: "X:/empty".to_owned(),
                state: ext4_core::DirectoryCasefold::Enabled
            })
        );
        assert_eq!(
            parse(
                ["casefold", "show", "X:/empty"]
                    .into_iter()
                    .map(str::to_owned)
            ),
            Ok(Command::CasefoldShow("X:/empty".to_owned()))
        );
        for args in [
            vec!["casefold", "set", "X:/empty"],
            vec!["casefold", "set", "X:/empty", "yes"],
            vec!["casefold", "show", "X:/empty", "on"],
        ] {
            assert!(parse(args.into_iter().map(str::to_owned)).is_err());
        }
    }

    /// Full replacements retain each explicit pair and reject missing/overflowing operands.
    /// # Panics
    /// Panics if parsing loses mappings or accepts incomplete replacements.
    #[test]
    fn complete_replacement_grammar() {
        let args = [
            "identity",
            "replace",
            "X:",
            "--user",
            "S-1-5-21-1",
            "1000",
            "--user",
            "DOMAIN\\user",
            "1001",
            "--group",
            "S-1-5-32-545",
            "100",
        ];
        assert_eq!(
            parse(args.into_iter().map(str::to_owned)),
            Ok(Command::Replace {
                target: "X:".to_owned(),
                users: vec![
                    ("S-1-5-21-1".to_owned(), 1000),
                    ("DOMAIN\\user".to_owned(), 1001)
                ],
                groups: vec![("S-1-5-32-545".to_owned(), 100)]
            })
        );
        assert!(
            parse(
                ["identity", "replace", "X:", "--user", "name"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_err()
        );
        assert!(
            parse(
                ["identity", "replace", "X:", "--user", "name", "4294967296"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_err()
        );
    }
}
