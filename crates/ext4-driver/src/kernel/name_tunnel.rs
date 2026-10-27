//! A mounted volume owns FsRtl's expiring name cache through native allocation and teardown.

#[cfg(not(test))]
use crate::kernel::status::DriverError;
use crate::kernel::status::DriverResult;
use crate::namespace::WindowsName;
use crate::short_name::ShortName;
#[cfg(not(test))]
use core::{ffi::c_void, ptr::NonNull};
use ext4_core::Ext4Timestamp;

/// FsRtl owns synchronization and cache expiry; the VCB owns its complete native lifetime.
#[derive(Debug)]
pub(crate) struct NameTunnel {
    /// Stable nonpaged allocation, destroyed only after mounted operations drain.
    #[cfg(not(test))]
    native: NonNull<c_void>,
}

/// Advisory metadata restored only if a new link's committed collision policy admits it.
#[derive(Debug)]
pub(crate) struct TunneledName {
    /// Optional persisted short component associated with the removed link.
    pub(crate) alias: Option<ShortName>,
    /// Creation time carried by the native cache.
    pub(crate) created: Ext4Timestamp,
}

/// Allocation-complete payload retained until the removing transaction becomes durable.
#[derive(Debug)]
pub(crate) enum TunnelRemoval {
    /// A directory allocation has lost its namespace and cannot retain cached children.
    Directory(u64),
    /// One exact non-directory link was removed or renamed.
    Name {
        /// Parent allocation incarnation combined with its inode number.
        directory: u64,
        /// Removed plaintext name, admitted only for an unencrypted parent.
        name: WindowsName,
        /// Alias exposed by this exact link before removal.
        alias: Option<ShortName>,
        /// Windows timestamp passed through FsRtl's opaque data slot.
        created: i64,
    },
}

impl TunnelRemoval {
    /// Captures the allocation key whose cached child names are retired with a directory.
    /// # Errors
    /// Returns the current directory's inode read or validation failure.
    pub(crate) fn directory(
        read: &mut impl ext4_core::CommittedReadPass,
        directory: ext4_core::DirectoryNodeId,
    ) -> DriverResult<Self> {
        Ok(Self::Directory(directory_key(read.load_node_metadata(
            ext4_core::NodeId::Directory(directory),
        )?)))
    }
    /// Captures advisory data while the old link still belongs to a coherent committed view.
    /// # Errors
    /// Returns inode/alias metadata, Windows encoding or allocation failure.
    pub(crate) fn prepare(
        read: &mut impl ext4_core::CommittedReadPass,
        parent: ext4_core::DirectoryNodeId,
        name: &ext4_core::Ext4Name,
        node: ext4_core::NodeId,
    ) -> DriverResult<Option<Self>> {
        if matches!(node, ext4_core::NodeId::Directory(_)) {
            return Ok(None);
        }
        let parent_metadata = read.load_node_metadata(ext4_core::NodeId::Directory(parent))?;
        if parent_metadata.is_encrypted() {
            return Ok(None);
        }
        let times = read.load_node_metadata(node)?.times();
        Ok(Some(Self::Name {
            directory: directory_key(parent_metadata),
            name: WindowsName::from_ext4(name)?,
            alias: crate::short_name::visible_alias(read, parent, name, node)?,
            created: super::time::windows_timestamp(times.created().unwrap_or(times.changed())),
        }))
    }
}

/// Parent identity includes its allocation generation so inode reuse cannot restore old names.
pub(crate) fn directory_key(metadata: ext4_core::NodeMetadataSnapshot) -> u64 {
    (u64::from(metadata.generation().as_u32()) << 32) | u64::from(metadata.node().file_index())
}

impl NameTunnel {
    /// Allocates and initializes the native cache before the volume is published.
    /// # Errors
    /// Returns native nonpaged allocation failure.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "native allocation returns sole FsRtl cache ownership"
        )
    )]
    pub(crate) fn try_new() -> DriverResult<Self> {
        #[cfg(not(test))]
        {
            // SAFETY: Native creation needs no caller storage and returns exclusive ownership.
            let native = NonNull::new(unsafe { ext4win_tunnel_create() })
                .ok_or(DriverError::InsufficientResources)?;
            Ok(Self { native })
        }
        #[cfg(test)]
        {
            Ok(Self {})
        }
    }

    /// Restores an advisory cache hit without granting any namespace or mutation authority.
    /// # Errors
    /// Returns native lookup failure or a cached payload outside the Windows/ext4 codec domain.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "bounded counted strings and stack outputs remain live throughout the native call"
        )
    )]
    pub(crate) fn find(
        &self,
        directory: u64,
        name: &WindowsName,
    ) -> DriverResult<Option<TunneledName>> {
        #[cfg(not(test))]
        {
            let name_length = u16::try_from(core::mem::size_of_val(name.utf16()))
                .map_err(|_| DriverError::InvalidName)?;
            let mut short = [0_u16; 12];
            let mut short_length = 0_u16;
            let mut created = 0_i64;
            let mut found = 0_u8;
            // SAFETY: The cache outlives this call, input strings are bounded and all outputs are exact writable stack values.
            let status = unsafe {
                ext4win_tunnel_find(
                    self.native.as_ptr(),
                    directory,
                    name.utf16().as_ptr(),
                    name_length,
                    short.as_mut_ptr(),
                    &mut short_length,
                    &mut created,
                    &mut found,
                )
            };
            if status < 0 {
                return Err(DriverError::CacheManagerFailure(status));
            }
            if found == 0 {
                return Ok(None);
            }
            if !short_length.is_multiple_of(2) {
                return Err(DriverError::InvalidWindowsMetadata);
            }
            let alias = if short_length == 0 {
                None
            } else {
                Some(ShortName::from_utf16(
                    short
                        .get(..usize::from(short_length / 2))
                        .ok_or(DriverError::InvalidWindowsMetadata)?,
                )?)
            };
            Ok(Some(TunneledName {
                alias,
                created: super::time::ext4_timestamp(created)?,
            }))
        }
        #[cfg(test)]
        {
            let _inputs = (directory, name);
            Ok(None)
        }
    }

    /// Publishes only after the removing transaction is durable. Cache allocation loss is benign.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "FsRtl copies bounded immutable payloads before the call returns"
        )
    )]
    pub(crate) fn removed(&self, removal: TunnelRemoval) {
        let TunnelRemoval::Name {
            directory,
            name,
            alias,
            created,
        } = removal
        else {
            let TunnelRemoval::Directory(directory) = removal else {
                return;
            };
            #[cfg(not(test))]
            // SAFETY: VCB ownership retains the native cache; the durable removed directory key is copied by value.
            unsafe {
                ext4win_tunnel_delete_directory(self.native.as_ptr(), directory);
            }
            #[cfg(test)]
            {
                let _directory = directory;
            }
            return;
        };
        #[cfg(not(test))]
        {
            let Ok(length) = u16::try_from(core::mem::size_of_val(name.utf16())) else {
                return;
            };
            let mut short = [0_u16; 12];
            let short_length = alias.map_or(0, |alias| alias.copy_utf16(&mut short));
            // SAFETY: VCB lifetime retains the cache, and native add copies all input before returning.
            unsafe {
                ext4win_tunnel_add(
                    self.native.as_ptr(),
                    directory,
                    name.utf16().as_ptr(),
                    length,
                    short.as_ptr(),
                    short_length,
                    created,
                );
            }
        }
        #[cfg(test)]
        {
            let _removed = (directory, name, alias, created);
        }
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "FsRtl serializes its own cache; the VCB drains requests before destruction"
)]
// SAFETY: Native FsRtl routines synchronize all accesses to their pinned cache allocation.
unsafe impl Send for NameTunnel {}
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "FsRtl serializes its own cache; shared methods never expose native storage"
)]
// SAFETY: Native cache synchronization permits shared calls while the VCB retains ownership.
unsafe impl Sync for NameTunnel {}

impl Drop for NameTunnel {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "sole VCB owner releases native cache after mounted operations drain"
        )
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        // SAFETY: This is the unique cache owner and all borrowing mounted operations have drained.
        unsafe {
            ext4win_tunnel_destroy(self.native.as_ptr());
        }
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "private native boundary owns FsRtl layout and exception handling"
)]
unsafe extern "C" {
    fn ext4win_tunnel_create() -> *mut c_void;
    fn ext4win_tunnel_destroy(cache: *mut c_void);
    fn ext4win_tunnel_delete_directory(cache: *mut c_void, directory: u64);
    fn ext4win_tunnel_add(
        cache: *mut c_void,
        directory: u64,
        name: *const u16,
        name_length: u16,
        short: *const u16,
        short_length: u16,
        created: i64,
    );
    fn ext4win_tunnel_find(
        cache: *mut c_void,
        directory: u64,
        name: *const u16,
        name_length: u16,
        short: *mut u16,
        short_length: *mut u16,
        created: *mut i64,
        found: *mut u8,
    ) -> i32;
}
