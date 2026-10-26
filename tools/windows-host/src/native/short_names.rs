//! Live observations of per-link DOS aliases through the Windows I/O boundary.

use super::{FileHandle, NamespaceAccess, completed, directory_query, field, file_information_query,
    identity, remove_namespace_link, single_name};
use std::{io, path::Path};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES};

/// Exercises alias opens, collision selection, wildcard matching, hard links and name tunneling.
/// The caller supplies a writable unencrypted directory on the mounted filesystem under test.
/// # Errors
/// Returns native I/O, alias identity, creation-time or explicit cleanup failures.
pub fn verify_short_name_lifecycle(directory: &Path, access: NamespaceAccess) -> io::Result<()> {
    match access {
        NamespaceAccess::Descriptor => lifecycle(directory),
        NamespaceAccess::RestorePrivilege => identity::with_restore_privilege(|| lifecycle(directory)),
    }
}

/// Observes the actual alternate-name class, including its counted UTF-16 framing.
/// # Errors
/// Returns native query, framing, encoding or handle release failure.
fn alternate_name(path: &Path) -> io::Result<String> {
    let file = FileHandle::open(path, FILE_READ_ATTRIBUTES, 0)?;
    let observed = (|| {
        let record = file_information_query(&file, 21, 64, 0)?;
        let length = usize::try_from(u32::from_le_bytes(field(&record, 0)?)).map_err(io::Error::other)?;
        let end = 4_usize.checked_add(length).ok_or_else(|| io::Error::other("alternate name length overflow"))?;
        let payload = record.get(4..end).ok_or_else(|| io::Error::other("alternate name payload missing"))?;
        let (pairs, remainder) = payload.as_chunks::<2>();
        if !remainder.is_empty() || pairs.is_empty() || pairs.len() > 12 || record.len() != end {
            return Err(io::Error::other("invalid alternate name framing"));
        }
        let units: Vec<_> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
        String::from_utf16(&units).map_err(io::Error::other)
    })();
    completed(observed, file.close())
}

/// Captures Windows creation time independently from the alias record.
/// # Errors
/// Returns native query, framing or handle release failure.
fn creation_time(path: &Path) -> io::Result<i64> {
    let file = FileHandle::open(path, FILE_READ_ATTRIBUTES, 0)?;
    let observed = file_information_query(&file, 4, 40, 0)
        .and_then(|record| field(&record, 0).map(i64::from_le_bytes));
    completed(observed, file.close())
}

/// Uses several exact links to distinguish inode payload identity from alias ownership.
/// # Errors
/// Returns contract disagreement, native I/O or cleanup failure.
fn lifecycle(directory: &Path) -> io::Result<()> {
    let first_name = "short name first.document";
    let paths = [directory.join(first_name), directory.join("short name second.document"),
        directory.join("short name hardlink.document"), directory.join("renamed short name.document")];
    let [first, second, hardlink, renamed] = &paths;
    let result = (|| {
        std::fs::write(first, b"original inode")?;
        std::fs::write(second, b"different inode")?;
        let first_alias = alternate_name(first)?;
        let second_alias = alternate_name(second)?;
        if first_alias.eq_ignore_ascii_case(&second_alias)
            || std::fs::read(directory.join(&first_alias))? != b"original inode"
            || std::fs::read(directory.join(&second_alias))? != b"different inode"
        { return Err(io::Error::other("short alias collision or open identity differs")); }
        let file = FileHandle::open(directory, 0x0010_0001, FILE_FLAG_BACKUP_SEMANTICS)?;
        let query = directory_query(&file, Some(&first_alias), 512, true, false, 0)
            .and_then(|record| single_name(&record, first_name));
        completed(query, file.close())?;
        std::fs::hard_link(first, hardlink)?;
        let hard_alias = alternate_name(hardlink)?;
        if first_alias.eq_ignore_ascii_case(&hard_alias)
            || std::fs::read(directory.join(&hard_alias))? != b"original inode"
        { return Err(io::Error::other("hard-link aliases do not preserve link identity")); }
        std::fs::rename(first, renamed)?;
        let renamed_alias = alternate_name(renamed)?;
        if std::fs::read(directory.join(&renamed_alias))? != b"original inode"
            || directory.join(&first_alias).try_exists()?
        { return Err(io::Error::other("rename retained an obsolete alias")); }
        let created = creation_time(renamed)?;
        remove_namespace_link(renamed)?;
        std::fs::write(renamed, b"recreated inode")?;
        if alternate_name(renamed)? != renamed_alias || creation_time(renamed)? != created
            || std::fs::read(directory.join(&renamed_alias))? != b"recreated inode"
            || std::fs::read(directory.join(&hard_alias))? != b"original inode"
        { return Err(io::Error::other("delete/recreate tunnel or surviving hard-link identity differs")); }
        Ok(())
    })();
    let mut cleanup = Ok(());
    for path in paths {
        if let Err(error) = remove_namespace_link(&path) && error.kind() != io::ErrorKind::NotFound && cleanup.is_ok() {
            cleanup = Err(error);
        }
    }
    completed(result, cleanup)
}
