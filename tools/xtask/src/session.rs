//! Typed durable session records. Each intent is published before its external effect.
//!
//! A returned command failure never proves rollback. Recovery reloads the last committed
//! record and revalidates current external identity before consuming cleanup authority.
use crate::{TaskResult, process::sha256_file};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// Observation-only identity of a recoverable session; possession alone grants no cleanup authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct SessionId(String);
impl SessionId {
    /// Creates a process- and instant-bound lowercase identity.
    /// # Errors
    /// Returns a system clock error.
    pub(crate) fn create(root: &Path) -> TaskResult<Self> {
        let instant = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut hash = Sha256::new();
        hash.update(b"ext4win-host-session");
        hash.update(instant.to_le_bytes());
        hash.update(std::process::id().to_le_bytes());
        hash.update(root.as_os_str().to_string_lossy().as_bytes());
        Ok(Self(
            hash.finalize()
                .iter()
                .take(16)
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ))
    }
    /// Validates the exact CLI/recovery identity spelling.
    /// # Errors
    /// Returns invalid or non-Unicode identities.
    pub(crate) fn parse(value: &OsStr) -> TaskResult<Self> {
        let value = value
            .to_str()
            .filter(|value| {
                value.len() == 32
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| {
                io::Error::other("session id must be 32 lowercase hexadecimal digits")
            })?;
        Ok(Self(value.into()))
    }
    /// Returns the recorded identity without broadening operation authority.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// External effect whose outcome may need reconciliation after interruption.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Operation {
    /// DriverStore installation.
    InstallPackage,
    /// Package identity established independently through export and SetupAPI.
    BindPackage,
    /// Exact service policy/path independently bound to an admitted package.
    BindService,
    /// SCM start.
    StartDriver,
    /// Secured control-device retirement.
    PrepareUnload,
    /// SCM stop and terminal completion observation.
    StopDriver,
    /// DriverStore removal.
    RemovePackage,
    /// SCM service deletion.
    DeleteService,
    /// Disposable VHDX creation.
    CreateVhdx,
    /// Windows VHDX attachment.
    AttachWindows,
    /// GPT initialization/partition construction.
    Partition,
    /// Windows VHDX detachment.
    DetachWindows,
    /// WSL attachment.
    AttachWsl,
    /// ext4 oracle formatting and independent fixture construction.
    Format,
    /// WSL detachment.
    DetachWsl,
    /// WSL oracle shutdown.
    ShutdownWsl,
    /// Mount Manager namespace publication.
    MountNamespace,
    /// Mount Manager namespace withdrawal.
    RemoveNamespace,
    /// Observable file-system workload.
    FilesystemIo,
    /// Driver Verifier activation.
    ActivateVerifier,
    /// Driver Verifier runtime observation.
    ObserveVerifier,
    /// Clean filesystem dismount.
    DismountFilesystem,
    /// Disposable VHDX removal.
    RemoveVhdx,
    /// Live driver's nested session cleanup.
    CleanupDriver,
}
/// Persisted operation stage, distinguishing prepared intent, observed completion and uncertain progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Phase {
    /// Identity published before any external mutation.
    Created,
    /// Durable intent exists, while acceptance/outcome may still be unknown.
    Intent(Operation),
    /// The owner observed the operation's defined completion boundary.
    Observed(Operation),
    /// External progress requires later reconciliation; no rollback is claimed.
    Deferred(Operation),
    /// Final absence/completion was observed for all owned resources.
    Complete,
}
/// One immutable publication of a typed owner state.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    /// Format boundary owned by this record parser.
    schema: u8,
    /// Exact session identity.
    id: SessionId,
    /// Ordered publication sequence, independent of timestamps.
    sequence: u64,
    /// Last operation's acceptance/observation state.
    phase: Phase,
    /// Resource identities owned by the relevant subsystem.
    state: T,
}
/// Owner of a single generated session directory and its typed publication protocol.
#[derive(Debug)]
pub(crate) struct Session<T> {
    /// Validated generated directory; callers cannot substitute arbitrary cleanup roots.
    directory: PathBuf,
    /// Current semantic state, published only at an explicit transition boundary.
    record: Record<T>,
}
impl<T: Serialize + DeserializeOwned> Session<T> {
    /// Publishes initial identity before beginning external work.
    /// # Errors
    /// Returns path, serialization, file, or durable publication failures.
    pub(crate) fn create(root: &Path, domain: &str, id: SessionId, state: T) -> TaskResult<Self> {
        let parent = root.join("target").join(domain);
        fs::create_dir_all(&parent)?;
        let directory = parent.join(id.as_str());
        fs::create_dir(&directory)?;
        let mut owner = Self {
            directory: directory.canonicalize()?,
            record: Record {
                schema: 1,
                id,
                sequence: 0,
                phase: Phase::Created,
                state,
            },
        };
        owner.publish(Phase::Created)?;
        Ok(owner)
    }
    /// Reads the latest immutable committed record, ignoring uncommitted staged files.
    /// # Errors
    /// Returns unsafe paths, missing records, malformed data or mismatched identity.
    pub(crate) fn load(root: &Path, domain: &str, id: &SessionId) -> TaskResult<Self> {
        let parent = root.join("target").join(domain).canonicalize()?;
        let directory = parent.join(id.as_str()).canonicalize()?;
        if directory.parent() != Some(parent.as_path())
            || directory.file_name() != Some(OsStr::new(id.as_str()))
        {
            return Err(io::Error::other("session path escaped its generated parent").into());
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name();
            if entry.file_type()?.is_file()
                && name
                    .to_str()
                    .is_some_and(|name| name.starts_with("record-") && name.ends_with(".json"))
            {
                records.push(entry.path());
            }
        }
        let path = records
            .iter()
            .max()
            .ok_or_else(|| io::Error::other("session has no committed Rust record"))?;
        let record: Record<T> = serde_json::from_slice(&fs::read(path)?)?;
        SessionId::parse(OsStr::new(record.id.as_str()))?;
        if record.schema != 1
            || &record.id != id
            || path.file_name() != Some(OsStr::new(&format!("record-{:020}.json", record.sequence)))
        {
            return Err(io::Error::other("session record identity or sequence mismatch").into());
        }
        Ok(Self { directory, record })
    }
    /// Borrows the bounded resource state; it does not skip external freshness validation.
    pub(crate) fn state(&self) -> &T {
        &self.record.state
    }
    /// Mutates only this owner's unpublished state before an explicit publication.
    pub(crate) fn state_mut(&mut self) -> &mut T {
        &mut self.record.state
    }
    /// Returns the last published semantic stage.
    pub(crate) fn phase(&self) -> Phase {
        self.record.phase
    }
    /// Returns the owner's exact identity.
    pub(crate) fn id(&self) -> &SessionId {
        &self.record.id
    }
    /// Returns the validated session directory for session-local evidence.
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }
    /// Publishes one transition after completing serialization and flushing staged bytes.
    /// # Errors
    /// Returns serialization, write, flush or publication errors. An error after native
    /// publication may leave a committed record; recovery reloads rather than assuming absence.
    pub(crate) fn publish(&mut self, phase: Phase) -> TaskResult<()> {
        let sequence = self
            .record
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("session phase sequence exhausted"))?;
        let candidate = Record {
            schema: self.record.schema,
            id: self.record.id.clone(),
            sequence,
            phase,
            state: &self.record.state,
        };
        let bytes = serde_json::to_vec_pretty(&candidate)?;
        let path = self.directory.join(format!("record-{sequence:020}.json"));
        // A failed publication can leave staged bytes. A fresh attempt reserves a new staging
        // identity so same-process recovery never reuses an earlier attempt's partial file.
        let staging_id = SessionId::create(&self.directory)?;
        let staged = self.directory.join(format!(
            "pending-{sequence:020}-{}.tmp",
            staging_id.as_str()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staged)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        #[cfg(windows)]
        windows_host::close_file(file)?;
        #[cfg(not(windows))]
        drop(file);
        #[cfg(windows)]
        windows_host::publish_phase(&staged, &path)?;
        #[cfg(not(windows))]
        {
            fs::rename(&staged, &path)?;
            fs::File::open(&self.directory)?.sync_all()?;
        }
        self.record.sequence = sequence;
        self.record.phase = phase;
        println!("session={} phase={phase:?}", self.id().as_str());
        Ok(())
    }
}

/// Persisted package identity used only after recovery revalidates bytes and signer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleIdentity {
    /// Published bundle directory.
    pub(crate) directory: PathBuf,
    /// Production artifact identity, independent of host session identity.
    pub(crate) artifact: String,
    /// Admitted SYS SHA-256.
    pub(crate) sys: String,
    /// Admitted CAT SHA-256.
    pub(crate) cat: String,
    /// Admitted INF SHA-256.
    pub(crate) inf: String,
}
impl BundleIdentity {
    /// Copies the authoritative production gate result without reparsing a second manifest.
    pub(crate) fn from_verified(bundle: &crate::production::VerifiedProductionBundle) -> Self {
        Self {
            directory: bundle.as_path().to_path_buf(),
            artifact: bundle.artifact_id().into(),
            sys: bundle.driver_hash().into(),
            cat: bundle.catalog_hash().into(),
            inf: bundle.inf_hash().into(),
        }
    }
    /// Revalidates immutable recorded identity before issuing any lifecycle effect.
    /// # Errors
    /// Returns path escape, invalid identity or changed package bytes.
    pub(crate) fn revalidate(&self, root: &Path) -> TaskResult<()> {
        let parent = root.join("target/verified-production").canonicalize()?;
        let directory = self.directory.canonicalize()?;
        SessionId::parse(OsStr::new(&self.artifact))?;
        if directory.parent() != Some(parent.as_path())
            || directory.file_name() != Some(OsStr::new(&self.artifact))
        {
            return Err(io::Error::other("bundle escaped its production identity boundary").into());
        }
        for (name, expected) in [
            ("ext4win.sys", &self.sys),
            ("ext4win.cat", &self.cat),
            ("ext4win.inf", &self.inf),
        ] {
            if expected.len() != 64
                || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !sha256_file(&directory.join(name))?.eq_ignore_ascii_case(expected)
            {
                return Err(
                    io::Error::other(format!("recorded bundle {name} hash mismatch")).into(),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Recovery observes only committed immutable records and checks publication identity.
    /// # Errors
    /// Returns fixture creation, publication, reload or generated-directory cleanup failures.
    /// # Panics
    /// Panics if recovery selects staged records or accepts mismatched committed identity.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions intentionally fail durable-publication contracts after fallible preparation"
    )]
    fn recovery_publication_contract() -> TaskResult<()> {
        let root = crate::process::repository_root()?;
        let fixture = crate::process::create_task_directory(&root, "session-contract")?;
        let operation = (|| -> TaskResult<()> {
            let id = SessionId::create(&fixture)?;
            let mut owner = Session::create(&fixture, "sessions", id.clone(), 7_u32)?;
            owner.publish(Phase::Intent(Operation::AttachWindows))?;
            *owner.state_mut() = 8;
            owner.publish(Phase::Observed(Operation::AttachWindows))?;
            fs::write(
                owner.directory().join("pending-999.tmp"),
                "torn staged write",
            )?;
            let mut recovered: Session<u32> = Session::load(&fixture, "sessions", &id)?;
            assert_eq!(recovered.state(), &8);
            assert_eq!(recovered.phase(), Phase::Observed(Operation::AttachWindows));
            let blocked = recovered
                .directory()
                .join(format!("record-{:020}.json", recovered.record.sequence + 1));
            fs::create_dir(&blocked)?;
            assert!(
                recovered
                    .publish(Phase::Intent(Operation::DetachWindows))
                    .is_err()
            );
            fs::remove_dir(&blocked)?;
            recovered = Session::load(&fixture, "sessions", &id)?;
            assert_eq!(recovered.phase(), Phase::Observed(Operation::AttachWindows));
            recovered.publish(Phase::Intent(Operation::DetachWindows))?;
            let resumed: Session<u32> = Session::load(&fixture, "sessions", &id)?;
            assert_eq!(resumed.phase(), Phase::Intent(Operation::DetachWindows));
            let latest = recovered
                .directory()
                .join(format!("record-{:020}.json", recovered.record.sequence));
            let altered =
                fs::read_to_string(&latest)?.replace(id.as_str(), "0".repeat(32).as_str());
            fs::write(latest, altered)?;
            assert!(Session::<u32>::load(&fixture, "sessions", &id).is_err());
            Ok(())
        })();
        let cleanup = crate::process::remove_task_directory(&root, &fixture, "session-contract");
        crate::process::combine_verification_and_cleanup(operation, cleanup)
    }
}
