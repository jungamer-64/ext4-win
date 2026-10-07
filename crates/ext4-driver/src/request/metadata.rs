//! Creation metadata policy for Windows-created ext4 inodes.
//!
//! New inodes copy the containing directory's uid/gid at creation. Permission modes are selected
//! independently by child kind; later parent ownership changes do not affect existing children.

use ext4_core::{Ext4Owner, Ext4Permissions, NewDirectoryMetadata, NewFileMetadata, Result};

/// Default metadata for Windows-created regular files.
/// # Errors
///
/// Returns an error when the default `0644` mode cannot be represented as ext4 permissions.
pub(crate) fn default_file_metadata(parent_owner: Ext4Owner) -> Result<NewFileMetadata> {
    Ok(NewFileMetadata::new(
        parent_owner,
        Ext4Permissions::new(0o644)?,
    ))
}

/// Default metadata for Windows-created directories.
/// # Errors
///
/// Returns an error when the default `0755` mode cannot be represented as ext4 permissions.
pub(crate) fn default_directory_metadata(parent_owner: Ext4Owner) -> Result<NewDirectoryMetadata> {
    Ok(NewDirectoryMetadata::new(
        parent_owner,
        Ext4Permissions::new(0o755)?,
    ))
}
