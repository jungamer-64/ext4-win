//! Directory-change registration, encoding, publication, and cleanup.

use super::*;

/// One validated directory-notification registration owned by a FILE_OBJECT.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DirectoryNotificationRegistration {
    /// Stable CCB-owned `UNICODE_STRING` retained by FsRtl until cleanup.
    full_directory_name: NonNull<UNICODE_STRING>,
    /// Stable unique CCB address that identifies the owning FILE_OBJECT to FsRtl.
    context: NonNull<c_void>,
    /// Recursive observation is owned by this individual registration.
    subtree: bool,
    /// Supported Windows completion-filter bits.
    completion_filter: wdk_sys::ULONG,
}

impl DirectoryNotificationRegistration {
    /// Builds one registration after the request boundary has rejected unsupported semantics.
    pub(crate) const fn new(
        full_directory_name: NonNull<UNICODE_STRING>,
        context: NonNull<c_void>,
        completion_filter: wdk_sys::ULONG,
        subtree: bool,
    ) -> Self {
        Self {
            full_directory_name,
            context,
            completion_filter,
            subtree,
        }
    }
}

/// Namespace name-change action exposed through directory notifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryChangeAction {
    /// A child was created.
    Added,
    /// A child was removed.
    Removed,
    /// An existing name now resolves to different file metadata.
    Modified,
    /// A child is being reported under its former name.
    RenamedOldName,
    /// A child is being reported under its replacement name.
    RenamedNewName,
}

impl DirectoryChangeAction {
    /// Returns the WDK FILE_ACTION payload for this namespace mutation.
    pub(super) const fn as_ulong(self) -> wdk_sys::ULONG {
        match self {
            Self::Added => wdk_sys::FILE_ACTION_ADDED,
            Self::Removed => wdk_sys::FILE_ACTION_REMOVED,
            Self::Modified => wdk_sys::FILE_ACTION_MODIFIED,
            Self::RenamedOldName => wdk_sys::FILE_ACTION_RENAMED_OLD_NAME,
            Self::RenamedNewName => wdk_sys::FILE_ACTION_RENAMED_NEW_NAME,
        }
    }
}

/// Committed namespace mutation prepared before its ext4 transaction is published.
#[derive(Debug)]
pub(crate) struct DirectoryChange {
    /// Removing-link data admitted before staging and cached only after durable publication.
    pub(super) tunnel: Option<Box<crate::kernel::name_tunnel::TunnelRemoval>>,
    /// Full synthetic target name used only by the FsRtl notifier package.
    pub(super) targets: DriverVec<DirectoryNotificationTarget>,
    /// FILE_NOTIFY_CHANGE_FILE_NAME or FILE_NOTIFY_CHANGE_DIR_NAME.
    pub(super) completion_filter: wdk_sys::ULONG,
    /// FILE_ACTION_* payload written to matching watcher buffers.
    pub(super) action: DirectoryChangeAction,
}

impl DirectoryChange {
    /// Captures cache data before mutation; publication remains tied to this durable event.
    /// # Errors
    /// Returns namespace metadata, encoding or allocation failures before staging writes.
    pub(crate) fn with_tunnel(
        mut self,
        read: &mut impl ext4_core::CommittedReadPass,
        parent: DirectoryNodeId,
        name: &Ext4Name,
        node: NodeId,
    ) -> DriverResult<Self> {
        let removal = if let NodeId::Directory(directory) = node {
            if self.action == DirectoryChangeAction::Removed {
                Some(crate::kernel::name_tunnel::TunnelRemoval::directory(
                    read, directory,
                )?)
            } else {
                None
            }
        } else {
            crate::kernel::name_tunnel::TunnelRemoval::prepare(read, parent, name, node)?
        };
        self.tunnel = match removal {
            Some(removal) => Some(memory::boxed_try_with(|| Ok(removal))?),
            None => None,
        };
        Ok(self)
    }
    /// Builds a namespace change event for one parent/name/node tuple.
    /// # Errors
    ///
    /// Returns an encoding, length, or allocation error while preparing the notification payload.
    pub(crate) fn new(
        read: &mut impl ext4_core::CommittedReadPass,
        parent: DirectoryNodeId,
        name: &Ext4Name,
        node: NodeId,
        action: DirectoryChangeAction,
    ) -> DriverResult<Self> {
        let completion_filter = if matches!(node, NodeId::Directory(_)) {
            wdk_sys::FILE_NOTIFY_CHANGE_DIR_NAME
        } else {
            wdk_sys::FILE_NOTIFY_CHANGE_FILE_NAME
        };
        Ok(Self {
            targets: DirectoryNotificationTarget::ancestors(read, parent, name)?,
            tunnel: None,
            completion_filter,
            action,
        })
    }

    /// Prepares an actual metadata transition for one reachable link.
    /// # Errors
    /// Returns ancestry, encoding or allocation failure before any media write.
    pub(crate) fn modified(
        read: &mut impl ext4_core::CommittedReadPass,
        parent: DirectoryNodeId,
        name: &Ext4Name,
        filter: u32,
    ) -> DriverResult<Self> {
        Ok(Self {
            targets: DirectoryNotificationTarget::ancestors(read, parent, name)?,
            tunnel: None,
            completion_filter: filter,
            action: DirectoryChangeAction::Modified,
        })
    }

    /// Builds the metadata-change event required when one exact file link is replaced in place.
    /// # Errors
    ///
    /// Returns an encoding, length, or allocation error while preparing the notification payload.
    pub(crate) fn hard_link_replaced(
        read: &mut impl ext4_core::CommittedReadPass,
        parent: DirectoryNodeId,
        name: &Ext4Name,
    ) -> DriverResult<Self> {
        const FILTER: wdk_sys::ULONG = wdk_sys::FILE_NOTIFY_CHANGE_ATTRIBUTES
            | wdk_sys::FILE_NOTIFY_CHANGE_SIZE
            | wdk_sys::FILE_NOTIFY_CHANGE_LAST_WRITE
            | wdk_sys::FILE_NOTIFY_CHANGE_LAST_ACCESS
            | wdk_sys::FILE_NOTIFY_CHANGE_CREATION
            | wdk_sys::FILE_NOTIFY_CHANGE_SECURITY
            | wdk_sys::FILE_NOTIFY_CHANGE_EA;
        Ok(Self {
            targets: DirectoryNotificationTarget::ancestors(read, parent, name)?,
            tunnel: None,
            completion_filter: FILTER,
            action: DirectoryChangeAction::Modified,
        })
    }
}

/// Opaque FsRtl notification list owned by one mounted VCB.
pub(crate) struct DirectoryChangeNotifier {
    /// Native list and synchronization object, initialized only after the VCB has a stable Box
    /// allocation. FsRtl synchronizes access to the opaque list internally.
    #[cfg(not(test))]
    native: UnsafeCell<NativeDirectoryChangeNotifier>,
    /// Whether `native` has been initialized and can be passed to FsRtl.
    #[cfg(not(test))]
    initialized: bool,
}

/// Native FsRtl notification storage whose list links must point at its final address.
#[cfg(not(test))]
struct NativeDirectoryChangeNotifier {
    /// Opaque volume-wide synchronization state allocated by FsRtl.
    sync: PNOTIFY_SYNC,
    /// Head of the FsRtl-owned notification list.
    list_head: LIST_ENTRY,
}

impl DirectoryChangeNotifier {
    /// Creates uninitialized notifier storage before the VCB reaches a stable heap address.
    pub(super) const fn uninitialized() -> Self {
        #[cfg(not(test))]
        {
            Self {
                native: UnsafeCell::new(NativeDirectoryChangeNotifier {
                    sync: core::ptr::null_mut(),
                    list_head: LIST_ENTRY {
                        Flink: core::ptr::null_mut(),
                        Blink: core::ptr::null_mut(),
                    },
                }),
                initialized: false,
            }
        }
        #[cfg(test)]
        {
            Self {}
        }
    }

    /// Initializes FsRtl notification state at the VCB's final address.
    /// # Errors
    ///
    /// Returns an error when FsRtl cannot allocate the volume synchronization object or this
    /// lifecycle transition is attempted twice.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    pub(super) fn initialize(&mut self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            if self.initialized {
                return Err(DriverError::InternalInvariantViolation);
            }
            let native = self.native.get();
            let list_head = unsafe {
                // SAFETY: `self` is the VCB's final Box allocation, so this
                // embedded LIST_ENTRY has a stable address for its lifetime.
                core::ptr::addr_of_mut!((*native).list_head)
            };
            unsafe {
                // SAFETY: The head points to its own empty-list links before
                // FsRtl receives the list for the first time.
                (*list_head).Flink = list_head;
            }
            unsafe {
                // SAFETY: The same initialized list head owns both links.
                (*list_head).Blink = list_head;
            }
            let sync = unsafe {
                // SAFETY: `sync` is writable VCB-owned storage that has not
                // yet been initialized by FsRtl.
                core::ptr::addr_of_mut!((*native).sync)
            };
            let status = unsafe {
                // SAFETY: Mount initialization runs at PASSIVE_LEVEL with exclusive
                // ownership of the unpublished VCB's writable synchronization storage.
                // The native boundary catches FsRtl's allocation exception.
                ffi::ext4win_notify_initialize_sync(sync)
            };
            if status != STATUS_SUCCESS {
                return Err(DriverError::InsufficientResources);
            }
            self.initialized = true;
            Ok(())
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Verifies that this mounted-volume notifier can accept one IRP transfer.
    /// # Errors
    ///
    /// Returns an error when the mounted VCB notifier was not initialized.
    pub(crate) fn ensure_registration_ready(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        if !self.initialized {
            return Err(DriverError::InternalInvariantViolation);
        }
        Ok(())
    }

    /// Gives one queued directory-change IRP to FsRtl for pending completion.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    pub(crate) fn register(
        &self,
        target: DispatchTarget,
        registration: DirectoryNotificationRegistration,
    ) -> wdk_sys::NTSTATUS {
        #[cfg(not(test))]
        {
            let native = self.native.get();
            let sync = unsafe {
                // SAFETY: `initialized` guarantees FsRtl populated this
                // mounted VCB's synchronization pointer.
                (*native).sync
            };
            let list_head = unsafe {
                // SAFETY: The native storage stays pinned inside the mounted
                // VCB and FsRtl synchronizes access to the list links.
                core::ptr::addr_of_mut!((*native).list_head)
            };
            unsafe {
                // SAFETY: The IRP was removed from the driver queue and its
                // unique completion owner is intentionally transferring it to
                // FsRtl. The registration context is a live CCB pointer.
                ffi::ext4win_notify_register(
                    sync,
                    list_head,
                    registration.context.as_ptr(),
                    registration.full_directory_name.as_ptr().cast(),
                    registration.completion_filter,
                    u8::from(registration.subtree),
                    target.into_raw_irp(),
                );
            }
            STATUS_PENDING
        }
        #[cfg(test)]
        {
            let DirectoryNotificationRegistration {
                full_directory_name,
                context,
                completion_filter,
                subtree,
            } = registration;
            core::hint::black_box((
                target,
                full_directory_name,
                context,
                completion_filter,
                subtree,
            ));
            STATUS_SUCCESS
        }
    }

    /// Reports one committed namespace name change to matching watcher IRPs.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    pub(super) fn report(&self, change: DirectoryChange) {
        #[cfg(not(test))]
        {
            if !self.initialized {
                return;
            }
            for target in change.targets.iter() {
                let mut full_target_name = target.unicode_string();
                let native = self.native.get();
                let sync = unsafe {
                    // SAFETY: `initialized` guarantees FsRtl populated this
                    // mounted VCB's synchronization pointer.
                    (*native).sync
                };
                let list_head = unsafe {
                    // SAFETY: The native storage stays pinned inside the mounted
                    // VCB and FsRtl synchronizes access to the list links.
                    core::ptr::addr_of_mut!((*native).list_head)
                };
                unsafe {
                    // SAFETY: This runs after the namespace transaction commits
                    // at PASSIVE_LEVEL. FsRtl consumes the event synchronously.
                    ffi::ext4win_notify_report(
                        sync,
                        list_head,
                        core::ptr::from_mut(&mut full_target_name).cast(),
                        target.name_offset_bytes,
                        change.completion_filter,
                        change.action.as_ulong(),
                    );
                }
            }
        }
        #[cfg(test)]
        {
            for target in change.targets.iter() {
                core::hint::black_box((
                    target.unicode_string(),
                    target.name_offset_bytes,
                    change.completion_filter,
                    change.action.as_ulong(),
                ));
            }
        }
    }

    /// Cancels and releases notification state owned by one cleaned-up FILE_OBJECT.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    pub(crate) fn cleanup(&self, context: NonNull<c_void>) {
        #[cfg(not(test))]
        {
            if !self.initialized {
                return;
            }
            let native = self.native.get();
            let sync = unsafe {
                // SAFETY: `initialized` guarantees FsRtl populated this
                // mounted VCB's synchronization pointer.
                (*native).sync
            };
            let list_head = unsafe {
                // SAFETY: The native storage stays pinned inside the mounted
                // VCB and FsRtl synchronizes access to the list links.
                core::ptr::addr_of_mut!((*native).list_head)
            };
            unsafe {
                // SAFETY: The CCB pointer uniquely identifies the FILE_OBJECT
                // being cleaned up and stays alive until its later close IRP.
                ffi::ext4win_notify_cleanup(sync, list_head, context.as_ptr());
            }
        }
        #[cfg(test)]
        {
            let _context = context;
        }
    }
    /// Completes all pending directory watches when storage is removed. The notifier remains
    /// initialized so later per-handle cleanup is idempotent and final teardown can join it.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the pinned VCB retains FsRtl synchronization while the sole actor withdraws its watches"
        )
    )]
    #[cfg(not(test))]
    pub(super) fn cleanup_all(&self) {
        #[cfg(not(test))]
        {
            if !self.initialized {
                return;
            }
            let native = self.native.get();
            let sync = unsafe {
                // SAFETY: Initialization populated the VCB-owned synchronization object.
                (*native).sync
            };
            let list_head = unsafe {
                // SAFETY: The pinned VCB owns this list; FsRtl synchronizes native links.
                core::ptr::addr_of_mut!((*native).list_head)
            };
            unsafe {
                // SAFETY: No actor-owned registration can race this volume-wide withdrawal.
                ffi::ext4win_notify_cleanup_all(sync, list_head);
            }
        }
    }
}

impl Drop for DirectoryChangeNotifier {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        {
            if !self.initialized {
                return;
            }
            self.cleanup_all();
            let native = self.native.get();
            let sync_slot = unsafe {
                // SAFETY: The initialized sync pointer is stored in this
                // unique mutable VCB teardown path.
                core::ptr::addr_of_mut!((*native).sync)
            };
            unsafe {
                // SAFETY: The list has been cleaned up and this is the unique
                // FsRtl uninitialization for the mounted VCB.
                ffi::FsRtlNotifyUninitializeSync(sync_slot);
            }
            self.initialized = false;
        }
    }
}

impl fmt::Debug for DirectoryChangeNotifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectoryChangeNotifier(..)")
    }
}

/// Stable synthetic directory name used only for FsRtl's lexical watcher matching.
#[derive(Debug)]
pub(super) struct DirectoryNotificationDirectoryName {
    /// UTF-16 `\\` followed by four private inode-identity code units.
    units: [u16; DIRECTORY_NOTIFICATION_DIRECTORY_UNITS],
    /// FsRtl retains this descriptor pointer until the CCB cleanup transition.
    string: UNICODE_STRING,
    /// Prevents moving the self-referential descriptor after `Buffer` is initialized.
    _pin: PhantomPinned,
}

impl DirectoryNotificationDirectoryName {
    /// Allocates one stable synthetic name for a directory CCB.
    /// # Errors
    ///
    /// Returns an error when the stable descriptor allocation fails.
    pub(super) fn try_new(directory: DirectoryNodeId) -> DriverResult<Pin<Box<Self>>> {
        let units = Self::encode(directory);
        let byte_length = u16::try_from(core::mem::size_of_val(&units))
            .map_err(|_| DriverError::InvalidBufferSize)?;
        let mut name = memory::boxed_try_with(|| {
            Ok(Self {
                units,
                string: UNICODE_STRING {
                    Length: byte_length,
                    MaximumLength: byte_length,
                    Buffer: core::ptr::null_mut(),
                },
                _pin: PhantomPinned,
            })
        })?;
        name.string.Buffer = name.units.as_mut_ptr();
        Ok(Box::into_pin(name))
    }

    /// Encodes one directory identity without allocating storage.
    fn encode(directory: DirectoryNodeId) -> [u16; DIRECTORY_NOTIFICATION_DIRECTORY_UNITS] {
        let mut units = [0_u16; DIRECTORY_NOTIFICATION_DIRECTORY_UNITS];
        let mut slots = units.iter_mut();
        if let Some(first) = slots.next() {
            *first = DIRECTORY_NOTIFICATION_SEPARATOR;
        }
        for (slot, byte) in slots.zip(NodeId::Directory(directory).file_index().to_be_bytes()) {
            *slot = DIRECTORY_NOTIFICATION_INODE_MARKER | u16::from(byte);
        }
        units
    }

    /// Returns the stable descriptor address retained by FsRtl.
    pub(super) fn descriptor(&self) -> NonNull<UNICODE_STRING> {
        NonNull::from(&self.string)
    }
}

impl PartialEq for DirectoryNotificationDirectoryName {
    fn eq(&self, other: &Self) -> bool {
        self.units == other.units
    }
}

impl Eq for DirectoryNotificationDirectoryName {}

/// Full synthetic target path reported to the FsRtl notification package.
#[derive(Debug)]
pub(super) struct DirectoryNotificationTarget {
    /// Complete UTF-16 target, allocated before commit and retained through synchronous reporting.
    pub(super) units: DriverVec<u16>,
    /// UTF-16 byte count of the populated target path.
    pub(super) byte_length: u16,
    /// Byte offset of the final child component inside `units`.
    pub(super) name_offset_bytes: u16,
}

impl DirectoryNotificationTarget {
    /// Prepares one anchored path for each ancestor before mutation publication.
    /// Synthetic roots identify watched directories by inode, so moving a directory never
    /// invalidates an outstanding watch. Each suffix is the actual relative Windows path.
    /// # Errors
    /// Returns cyclic/malformed ancestry, encoding, length or allocation failures.
    fn ancestors(
        read: &mut impl ext4_core::CommittedReadPass,
        mut parent: DirectoryNodeId,
        name: &Ext4Name,
    ) -> DriverResult<DriverVec<Self>> {
        let mut components = DriverVec::new();
        components
            .try_push_owned(WindowsName::from_ext4(name)?)
            .map_err(|error| error.into_parts().0)?;
        let mut visited = DriverVec::new();
        let mut targets = DriverVec::new();
        loop {
            if visited.as_slice().contains(&parent) {
                return Err(ext4_core::Error::InvalidDirectoryEntry.into());
            }
            visited.try_push(parent)?;
            targets
                .try_push_owned(Self::from_components(parent, components.as_slice())?)
                .map_err(|error| error.into_parts().0)?;
            if parent == DirectoryNodeId::ROOT {
                break;
            }
            let link = crate::namespace::directory_parent(read, parent)?;
            components
                .try_push_owned(link.name)
                .map_err(|error| error.into_parts().0)?;
            parent = link.directory;
        }
        Ok(targets)
    }

    /// Encodes an inode anchor followed by leaf-to-root input components in path order.
    /// # Errors
    /// Rejects empty paths, counted-string overflow or allocation failure.
    fn from_components(anchor: DirectoryNodeId, components: &[WindowsName]) -> DriverResult<Self> {
        if components.is_empty() {
            return Err(DriverError::InvalidParameter);
        }
        let mut units = DriverVec::new();
        units.try_extend_from_copy_slice(&DirectoryNotificationDirectoryName::encode(anchor))?;
        let mut name_offset_bytes = 0;
        for component in components.iter().rev() {
            units.try_push(DIRECTORY_NOTIFICATION_SEPARATOR)?;
            name_offset_bytes = u16::try_from(core::mem::size_of_val(units.as_slice()))
                .map_err(|_| DriverError::InvalidBufferSize)?;
            units.try_extend_from_copy_slice(component.utf16())?;
        }
        let byte_length = u16::try_from(core::mem::size_of_val(units.as_slice()))
            .map_err(|_| DriverError::InvalidBufferSize)?;
        Ok(Self {
            units,
            byte_length,
            name_offset_bytes,
        })
    }

    /// Views this complete target as the layout accepted by FsRtl's PSTRING ABI.
    pub(super) fn unicode_string(&self) -> UNICODE_STRING {
        UNICODE_STRING {
            Length: self.byte_length,
            MaximumLength: self.byte_length,
            Buffer: self.units.as_slice().as_ptr().cast_mut(),
        }
    }
}

/// UTF-16 backslash separator used in FsRtl synthetic paths.
const DIRECTORY_NOTIFICATION_SEPARATOR: u16 = 0x005C;
/// High-byte marker separating encoded inode bytes from Windows path separators.
const DIRECTORY_NOTIFICATION_INODE_MARKER: u16 = 0x0100;
/// `\\` plus four lossless inode-identity units.
pub(super) const DIRECTORY_NOTIFICATION_DIRECTORY_UNITS: usize = 5;

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Fails when the native suffix or final-component byte offset differs from the Windows path.
    #[test]
    fn ancestor_notification_contains_relative_path_in_component_order() {
        let result = (|| -> DriverResult<()> {
            let components = [
                WindowsName::from_utf16(&[99, 104, 105, 108, 100])?,
                WindowsName::from_utf16(&[115, 117, 98])?,
            ];
            let target =
                DirectoryNotificationTarget::from_components(DirectoryNodeId::ROOT, &components)?;
            assert_eq!(
                target.units.as_slice().get(5..),
                Some([92_u16, 115, 117, 98, 92, 99, 104, 105, 108, 100].as_slice())
            );
            assert_eq!(target.name_offset_bytes, 20);
            assert_eq!(target.unicode_string().Length, 30);
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }

    /// # Panics
    /// Fails if Unicode names lose UTF-16 units or the direct-parent notification boundary.
    #[test]
    fn notification_preserves_unicode_and_maximum_component() {
        let result = (|| -> DriverResult<()> {
            for name in ["é😀".as_bytes(), [b'a'; 255].as_slice()] {
                let component = WindowsName::from_ext4(&Ext4Name::new(name)?)?;
                let expected = DriverVec::try_copied_from_slice(component.utf16())?;
                let target = DirectoryNotificationTarget::from_components(
                    DirectoryNodeId::ROOT,
                    &[component],
                )?;
                assert_eq!(target.name_offset_bytes, 12);
                assert_eq!(target.units.as_slice().get(6..), Some(expected.as_slice()));
            }
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }
}
