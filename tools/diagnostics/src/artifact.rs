//! Immutable, digest-checked historical artifact snapshots; integrity is distinct from trust.
use crate::invalid;
use alloc::collections::BTreeMap;
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Component, Path},
};

/// Owned bytes and recorded identity of exactly the inputs read for one analysis.
#[derive(Debug)]
pub(crate) struct Snapshot {
    /// Recorded build identity; this does not authorize loading a driver.
    pub(crate) identity: String,
    /// Source digest recorded at build time, without a current-checkout claim.
    pub(crate) source: String,
    /// Digests of the immutable bytes analyzed.
    pub(crate) digests: BTreeMap<String, String>,
    /// The analysis-owned copies; subsequent file replacement cannot alter this snapshot.
    contents: BTreeMap<String, Vec<u8>>,
}

impl Snapshot {
    /// Reads selected artifacts once and checks their manifest identity and path confinement.
    /// # Errors
    /// Returns malformed manifests, path escape, I/O, or digest mismatch errors.
    pub(crate) fn read(root: &Path, kinds: &[&str]) -> io::Result<Self> {
        let root = root.canonicalize()?;
        let mut records = BTreeMap::new();
        for line in fs::read_to_string(root.join("manifest-v1.txt"))?.lines() {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| invalid("malformed manifest record"))?;
            if records.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(invalid("duplicate manifest record"));
            }
        }
        let record = |name: &str| {
            records
                .get(name)
                .map(String::as_str)
                .ok_or_else(|| invalid(format!("missing manifest record {name}")))
        };
        if record("manifest_version")? != "1" {
            return Err(invalid("unsupported production manifest version"));
        }
        let identity = record("artifact_id")?;
        if identity.len() != 32
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || identity.bytes().all(|byte| byte == b'0')
        {
            return Err(invalid("invalid artifact identity"));
        }
        let source = record("source_snapshot_sha256")?;
        if source.len() != 64 || !source.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid("invalid source snapshot digest"));
        }
        let mut contents = BTreeMap::new();
        let mut digests = BTreeMap::new();
        for kind in kinds {
            let name = record(&format!("artifact.{kind}.path"))?;
            if name.is_empty()
                || name.contains(['\\', ':'])
                || Path::new(name)
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_)))
            {
                return Err(invalid("invalid bundle-relative artifact path"));
            }
            let path = root.join(name).canonicalize()?;
            if !path.starts_with(&root) {
                return Err(invalid("artifact path escapes bundle"));
            }
            let bytes = fs::read(path)?;
            let hash = digest(&bytes);
            if !hash.eq_ignore_ascii_case(record(&format!("artifact.{kind}.sha256"))?) {
                return Err(invalid(format!("{kind} identity mismatch")));
            }
            contents.insert((*kind).to_owned(), bytes);
            digests.insert((*kind).to_owned(), hash);
        }
        Ok(Self {
            identity: identity.into(),
            source: source.to_ascii_lowercase(),
            contents,
            digests,
        })
    }

    /// Borrows a selected immutable input.
    /// # Errors
    /// Returns an error when this snapshot was not asked to read the input.
    pub(crate) fn bytes(&self, kind: &str) -> io::Result<&[u8]> {
        self.contents
            .get(kind)
            .map(Vec::as_slice)
            .ok_or_else(|| invalid("artifact not in analysis snapshot"))
    }
}

/// Formats a byte sequence without allocation at each byte.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
/// Computes the digest of the actual bytes inspected.
pub(crate) fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Reads a fixed-size little-endian field from a checked byte boundary.
/// # Errors
/// Returns an error for overflowing offsets or truncated bytes.
pub(crate) fn field<const N: usize>(bytes: &[u8], offset: usize) -> io::Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| invalid("byte offset overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid("truncated data"))?
        .try_into()
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Immutable analysis bytes remain stable after replacement; damaged or ambiguous identities fail.
    /// # Errors
    /// Returns fixture I/O or unexpected snapshot failures.
    /// # Panics
    /// Panics if a snapshot observes replacement or malformed manifests are accepted.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions intentionally fail the immutable-snapshot contract test"
    )]
    fn immutable_artifact_boundary() -> io::Result<()> {
        let instant = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ext4win-snapshot-{}-{instant}", std::process::id()));
        fs::create_dir(&root)?;
        let operation = (|| {
            fs::write(root.join("driver.ir"), b"initial")?;
            let manifest = format!(
                "manifest_version=1\nartifact_id={}\nsource_snapshot_sha256={}\nartifact.ir.path=driver.ir\nartifact.ir.sha256={}\n",
                "1".repeat(32),
                "2".repeat(64),
                digest(b"initial")
            );
            fs::write(root.join("manifest-v1.txt"), &manifest)?;
            let snapshot = Snapshot::read(&root, &["ir"])?;
            fs::write(root.join("driver.ir"), b"replacement")?;
            assert_eq!(snapshot.bytes("ir")?, b"initial");
            assert!(Snapshot::read(&root, &["ir"]).is_err());
            fs::write(
                root.join("manifest-v1.txt"),
                format!("{manifest}artifact_id={}\n", "3".repeat(32)),
            )?;
            assert!(Snapshot::read(&root, &["ir"]).is_err());
            fs::write(
                root.join("manifest-v1.txt"),
                manifest.replace("path=driver.ir", "path=../driver.ir"),
            )?;
            assert!(Snapshot::read(&root, &["ir"]).is_err());
            Ok(())
        })();
        let cleanup = fs::remove_file(root.join("driver.ir"))
            .and_then(|()| fs::remove_file(root.join("manifest-v1.txt")))
            .and_then(|()| fs::remove_dir(&root));
        match (operation, cleanup) {
            (Err(error), Err(cleanup)) => Err(invalid(format!("{error}; cleanup: {cleanup}"))),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}
