//! Driver defaults for Windows-created ext4 inodes.

use ext4_core::{
    Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Uid, NewDirectoryMetadata, NewFileMetadata,
    Result,
};

/// Default POSIX owner for Windows-created inodes before security mapping lands.
fn default_owner() -> Ext4Owner {
    Ext4Owner::new(Ext4Uid::from_u32(0), Ext4Gid::from_u32(0))
}

/// Default metadata for Windows-created regular files.
/// # Errors
///
/// Returns an error when the default `0644` mode cannot be represented as ext4 permissions.
pub(crate) fn default_file_metadata() -> Result<NewFileMetadata> {
    Ok(NewFileMetadata::new(
        default_owner(),
        Ext4Permissions::new(0o644)?,
    ))
}

/// Default metadata for Windows-created directories.
/// # Errors
///
/// Returns an error when the default `0755` mode cannot be represented as ext4 permissions.
pub(crate) fn default_directory_metadata() -> Result<NewDirectoryMetadata> {
    Ok(NewDirectoryMetadata::new(
        default_owner(),
        Ext4Permissions::new(0o755)?,
    ))
}
