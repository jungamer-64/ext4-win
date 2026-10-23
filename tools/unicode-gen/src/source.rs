//! Pinned UCD acquisition. Only authenticated UTF-8 enters the generator or shared cache.
//!
//! Cache entries live outside the source tree and are checked on every read.
//! Missing entries are fetched with curl over HTTPS. Publication links a complete file;
//! concurrent readers cannot observe partial writes. Cache loss requires a new download,
//! so neither cache durability nor cleanup after process termination is required.

use crate::{GenerationResult, UNICODE_VERSION};
use alloc::{collections::BTreeMap, vec::Vec};
use core::fmt::Write as _;
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    io::Write as _,
    path::{Path, PathBuf},
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
};

/// Exact upstream bytes required by the generator and its independent conformance corpus.
const INPUTS: &[(&str, &str)] = &[
    (
        "UnicodeData.txt",
        "93ab1acd8fd9d450463b50ae77eab151a7cda48f98b25b56baed8070f80fc936",
    ),
    (
        "CaseFolding.txt",
        "9c772627c6ee77eea6a17b42927b8ee28ca05dc65d6a511062104baaf3d12294",
    ),
    (
        "DerivedCoreProperties.txt",
        "a6eb7a8671fb532fbd88c37fd7b20b5b2e7dbfc8b121f74c14abe2947db0da68",
    ),
    (
        "DerivedAge.txt",
        "2fc081011d8fabaf7cf4937732dd5a6d6a57e492c43f3adfeded513387ee0ec3",
    ),
    (
        "NormalizationTest.txt",
        "8cabbd6293c88ca05f0b601ade0fd16978ac670a077c0e0f419986ddd33c6941",
    ),
    (
        "ReadMe.txt",
        "cb3613bcfc0ad962bf17cca18af090aac11c350fef294916e97bcb100839baff",
    ),
];

/// Verbatim data notice accompanying every generated table and distribution.
const LICENSE_NAME: &str = "LICENSE-UNICODE";
/// Digest of the complete upstream Unicode V3 notice, including its copyright.
const LICENSE_SHA256: &str = "e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96";
/// Official upstream location; changed bytes require an explicit digest update.
const LICENSE_URL: &str = "https://www.unicode.org/license.txt";

/// Returns the fixed source set after authenticating every cached or downloaded input.
/// # Errors
/// Returns cache, download, hash mismatch or UTF-8 failures without accepting changed data.
pub(super) fn load(cache: &Path) -> GenerationResult<BTreeMap<&'static str, String>> {
    let mut sources = BTreeMap::new();
    for (name, expected) in INPUTS {
        let url = format!("https://www.unicode.org/Public/{UNICODE_VERSION}/ucd/{name}");
        sources.insert(*name, read_input(cache, name, expected, || download(&url))?);
    }
    Ok(sources)
}

/// Lists exactly the files whose authenticated bytes determine generation.
pub(super) fn paths(cache: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    INPUTS
        .iter()
        .map(move |(name, _)| cache.join(name))
        .chain(core::iter::once(cache.join(LICENSE_NAME)))
}

/// Authenticates the complete Unicode data notice for generated artifacts and distributions.
/// # Errors
/// Returns cache, download, digest or UTF-8 failure without accepting changed notice text.
pub fn license(cache: &Path) -> GenerationResult<String> {
    read_input(cache, LICENSE_NAME, LICENSE_SHA256, || {
        download(LICENSE_URL)
    })
}

/// Reuses authenticated cache bytes or publishes an authenticated download on a cache miss.
/// # Errors
/// Returns read, fetch, authentication or publication failures. Corrupt entries are rejected;
/// removing the named cache file explicitly permits a fresh download on the next invocation.
fn read_input(
    cache: &Path,
    name: &str,
    expected: &str,
    fetch: impl FnOnce() -> GenerationResult<Vec<u8>>,
) -> GenerationResult<String> {
    let path = cache.join(name);
    match fs::read(&path) {
        Ok(bytes) => authenticate(&path, expected, bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let source = authenticate(&path, expected, fetch()?)?;
            publish(cache, &path, &source)?;
            Ok(source)
        }
        Err(error) => Err(error.into()),
    }
}

/// Establishes the pinned source identity before decoding or publication.
/// # Errors
/// Returns a digest mismatch or invalid UTF-8, identifying the affected cache path.
fn authenticate(path: &Path, expected: &str, bytes: Vec<u8>) -> GenerationResult<String> {
    let mut actual = String::new();
    for byte in Sha256::digest(&bytes) {
        write!(&mut actual, "{byte:02x}")?;
    }
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Unicode source hash mismatch at {}: expected {expected}, found {actual}",
                path.display()
            ),
        )
        .into());
    }
    Ok(String::from_utf8(bytes)?)
}

/// Delegates HTTPS transport and certificate verification to the host curl executable.
/// # Errors
/// Returns missing curl, HTTP, TLS or bounded-transfer failures; no failed output is cached.
fn download(url: &str) -> GenerationResult<Vec<u8>> {
    eprintln!("fetching Unicode source: {url}");
    let output = Command::new("curl")
        .args([
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "15",
            "--max-time",
            "60",
            "--max-filesize",
            "8388608",
            "--url",
            url,
        ])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Unicode source download failed for {url} ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
        .into());
    }
    Ok(output.stdout)
}

/// Publishes a complete cache entry without replacing an existing entry from another writer.
/// # Errors
/// Returns staging, publication, conflicting-entry or cleanup failure. Interrupted staging files
/// have no authority and are never read as cache entries.
fn publish(cache: &Path, path: &Path, source: &str) -> GenerationResult<()> {
    fs::create_dir_all(cache)?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let staged = cache.join(format!(".{}-{nonce}.tmp", process::id()));
    let mut file = fs::File::create_new(&staged)?;
    let publication = (|| -> GenerationResult<()> {
        file.write_all(source.as_bytes())?;
        drop(file);
        match fs::hard_link(&staged, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if fs::read(path)? != source.as_bytes() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("conflicting Unicode cache entry: {}", path.display()),
                    )
                    .into());
                }
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    })();
    finish_cache_operation(publication, fs::remove_file(staged))
}

/// Preserves acquisition or publication diagnostics alongside staging cleanup failure.
/// # Errors
/// Returns either failure, combining diagnostics if both operations fail.
fn finish_cache_operation<T>(
    operation: GenerationResult<T>,
    cleanup: io::Result<()>,
) -> GenerationResult<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(operation), Err(cleanup)) => Err(io::Error::other(format!(
            "cache operation failed ({operation}); cleanup also failed ({cleanup})"
        ))
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// SHA-256 known answer for the small transport fixture.
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    /// Creates a unique, test-owned directory outside the source tree.
    /// # Errors
    /// Returns clock or directory creation failure.
    fn cache_directory() -> GenerationResult<PathBuf> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!("ext4-ucd-test-{}-{nonce}", process::id()));
        fs::create_dir(&path)?;
        Ok(path)
    }

    /// Cache reuse authenticates bytes and does not invoke transport; corruption fails closed.
    /// # Errors
    /// Returns fixture I/O, authentication or cleanup failures.
    /// # Panics
    /// Panics if cache reuse downloads or modified bytes are accepted.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions observe authenticated cache reuse and corruption rejection; fixture I/O remains fallible"
    )]
    fn cache_authenticates_downloads_and_reuse() -> GenerationResult<()> {
        let cache = cache_directory()?;
        let result = (|| -> GenerationResult<()> {
            assert_eq!(
                read_input(&cache, "input.txt", ABC_SHA256, || Ok(b"abc".to_vec()))?,
                "abc"
            );
            assert_eq!(
                read_input(&cache, "input.txt", ABC_SHA256, || {
                    Err(io::Error::other("cache hit must not download").into())
                })?,
                "abc"
            );
            fs::write(cache.join("input.txt"), b"corrupt")?;
            let mut fetched = false;
            assert!(
                read_input(&cache, "input.txt", ABC_SHA256, || {
                    fetched = true;
                    Ok(b"abc".to_vec())
                })
                .is_err()
            );
            assert!(!fetched);
            Ok(())
        })();
        finish_cache_operation(result, fs::remove_dir_all(cache))
    }

    /// Neither transport failures nor unauthenticated data become reusable cache entries.
    /// # Errors
    /// Returns fixture I/O, valid-source publication or cleanup failures.
    /// # Panics
    /// Panics if a failed acquisition is published or a competing writer replaces cached bytes.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions observe acquisition and publication failure semantics; fixture I/O remains fallible"
    )]
    fn failed_downloads_leave_no_cache_entry() -> GenerationResult<()> {
        let cache = cache_directory()?;
        let result = (|| -> GenerationResult<()> {
            assert!(
                read_input(&cache, "input.txt", ABC_SHA256, || {
                    Err(io::Error::other("transport failure").into())
                })
                .is_err()
            );
            assert!(!cache.join("input.txt").exists());
            assert!(
                read_input(&cache, "input.txt", ABC_SHA256, || Ok(b"changed".to_vec())).is_err()
            );
            assert!(!cache.join("input.txt").exists());
            assert_eq!(
                read_input(&cache, "input.txt", ABC_SHA256, || Ok(b"abc".to_vec()))?,
                "abc"
            );
            publish(&cache, &cache.join("input.txt"), "abc")?;
            assert!(publish(&cache, &cache.join("input.txt"), "conflict").is_err());
            assert_eq!(fs::read(cache.join("input.txt"))?, b"abc");
            assert_eq!(fs::read_dir(&cache)?.count(), 1);
            Ok(())
        })();
        finish_cache_operation(result, fs::remove_dir_all(cache))
    }
}
