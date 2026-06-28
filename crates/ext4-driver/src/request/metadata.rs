//! Driver defaults for Windows-created ext4 inodes.

use ext4_core::{
    Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Uid, NewDirectoryMetadata, NewFileMetadata,
    NewSymlinkMetadata, Result,
};

/// Default POSIX owner for Windows-created inodes before security mapping lands.
fn default_owner() -> Ext4Owner {
    Ext4Owner::new(Ext4Uid::from_u32(0), Ext4Gid::from_u32(0))
}

/// Default metadata for Windows-created regular files.
pub(crate) fn default_file_metadata() -> Result<NewFileMetadata> {
    Ok(NewFileMetadata::new(
        default_owner(),
        Ext4Permissions::new(0o644)?,
    ))
}

/// Default metadata for Windows-created directories.
pub(crate) fn default_directory_metadata() -> Result<NewDirectoryMetadata> {
    Ok(NewDirectoryMetadata::new(
        default_owner(),
        Ext4Permissions::new(0o755)?,
    ))
}

/// Default metadata for Windows-created symbolic links.
pub(crate) fn default_symlink_metadata() -> Result<NewSymlinkMetadata> {
    Ok(NewSymlinkMetadata::new(
        default_owner(),
        Ext4Permissions::new(0o777)?,
    ))
}
