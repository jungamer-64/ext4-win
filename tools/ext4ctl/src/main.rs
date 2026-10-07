//! Administrator CLI for explicit UUID-scoped Windows/ext4 identity correspondence.
use std::process::ExitCode;

/// User-visible grammar; replacements contain the entire desired table.
const USAGE: &str = "ext4ctl volumes\next4ctl whoami\next4ctl identity show <volume-path|ext4-uuid>\next4ctl identity replace <volume-path|ext4-uuid> [--user <account|SID> <UID>]... [--group <account|SID> <GID>]...\next4ctl identity clear <volume-path|ext4-uuid>";
/// Fully parsed action before any replacement can be submitted.
#[derive(Debug, Eq, PartialEq)]
enum Command {
    /// Mounted ext4 volumes and UUIDs.
    Volumes,
    /// Effective token user and primary group.
    Whoami,
    /// Saved/applied generations and complete active table.
    Show(String),
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
/// Executes a fully parsed command; complete validation precedes replacement submission.
/// # Errors
/// Preserves native diagnostics and refuses unresolved saved/applied state.
#[cfg(windows)]
fn execute(command: Command) -> Result<(), String> {
    match command {
        Command::Volumes => {
            for (name, uuid) in
                windows_host::identity_volumes().map_err(|error| error.to_string())?
            {
                println!("{} {name}", uuid_text(uuid));
            }
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
    use super::*;
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
