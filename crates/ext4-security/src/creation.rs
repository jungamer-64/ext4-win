//! Creator identity and POSIX setgid inheritance at the inode construction boundary.
use crate::Error;
use ext4_core::{Ext4Owner, Ext4Permissions, Ext4Security};

/// Namespace kind whose initial permission and setgid inheritance differ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildKind {
    /// Regular file with initial mode 0644.
    File,
    /// Directory with initial mode 0755 and inherited parent setgid.
    Directory,
}

/// Constructs metadata only from explicitly mapped effective identity and parent security.
/// # Errors
/// Returns an error if the computed mode is outside the core permission vocabulary.
pub fn child_security(
    creator: Ext4Owner,
    parent: Ext4Security,
    kind: ChildKind,
) -> Result<Ext4Security, Error> {
    let setgid = parent.permissions().as_u16() & 0o2000;
    let gid = if setgid != 0 {
        parent.owner().gid()
    } else {
        creator.gid()
    };
    let mode = match kind {
        ChildKind::File => 0o644,
        ChildKind::Directory => 0o755 | setgid,
    };
    Ok(Ext4Security::new(
        Ext4Owner::new(creator.uid(), gid),
        Ext4Permissions::new(mode).map_err(|_| Error::InvalidEncoding)?,
    ))
}
