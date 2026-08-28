//! Directory-change registration, encoding, publication, and cleanup.

use super::*;

/// One validated directory-notification registration owned by a FILE_OBJECT.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DirectoryNotificationRegistration {
    /// Stable CCB-owned `UNICODE_STRING` retained by FsRtl until cleanup.
    full_directory_name: NonNull<UNICODE_STRING>,
    /// Stable unique CCB address that identifies the owning FILE_OBJECT to FsRtl.
    context: NonNull<c_void>,
    /// Supported Windows completion-filter bits.
    completion_filter: wdk_sys::ULONG,
}

impl DirectoryNotificationRegistration {
    /// Builds one registration after the request boundary has rejected unsupported semantics.
    pub(crate) const fn new(
        full_directory_name: NonNull<UNICODE_STRING>,
        context: NonNull<c_void>,
        completion_filter: wdk_sys::ULONG,
    ) -> Self {
        Self {
            full_directory_name,
            context,
            completion_filter,
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
#[derive(Clone, Copy, Debug)]
pub(crate) struct DirectoryChange {
    /// Full synthetic target name used only by the FsRtl notifier package.
    pub(super) target: DirectoryNotificationTarget,
    /// FILE_NOTIFY_CHANGE_FILE_NAME or FILE_NOTIFY_CHANGE_DIR_NAME.
    pub(super) completion_filter: wdk_sys::ULONG,
    /// FILE_ACTION_* payload written to matching watcher buffers.
    pub(super) action: DirectoryChangeAction,
}

impl DirectoryChange {
    /// Builds a namespace change event for one parent/name/node tuple.
    /// # Errors
    ///
    /// Returns an error when the ext4 child name cannot be represented in the Windows notification
    /// namespace.
    pub(crate) fn new(
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
            target: DirectoryNotificationTarget::new(parent, name)?,
            completion_filter,
            action,
        })
    }

    /// Builds the metadata-change event required when one exact file link is replaced in place.
    /// # Errors
    ///
    /// Returns an error when the ext4 child name cannot be represented in the Windows notification
    /// namespace.
    pub(crate) fn hard_link_replaced(
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
            target: DirectoryNotificationTarget::new(parent, name)?,
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
            unsafe {
                // SAFETY: FsRtl initializes the one opaque synchronization
                // pointer stored in this mounted VCB.
                ffi::FsRtlNotifyInitializeSync(sync);
            }
            if unsafe {
                // SAFETY: FsRtl initialized the out pointer above; this only
                // reads the pointer value before publication.
                (*native).sync.is_null()
            } {
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
                ffi::FsRtlNotifyFullChangeDirectory(
                    sync,
                    list_head,
                    registration.context.as_ptr(),
                    registration.full_directory_name.as_ptr().cast(),
                    0,
                    0,
                    registration.completion_filter,
                    target.into_raw_irp(),
                    None,
                    core::ptr::null_mut(),
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
            } = registration;
            core::hint::black_box((target, full_directory_name, context, completion_filter));
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
            let mut full_target_name = change.target.unicode_string();
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
                ffi::FsRtlNotifyFullReportChange(
                    sync,
                    list_head,
                    core::ptr::from_mut(&mut full_target_name).cast(),
                    change.target.name_offset_bytes,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    change.completion_filter,
                    change.action.as_ulong(),
                    core::ptr::null_mut(),
                );
            }
        }
        #[cfg(test)]
        {
            let _change = change;
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
                ffi::FsRtlNotifyCleanup(sync, list_head, context.as_ptr());
            }
        }
        #[cfg(test)]
        {
            let _context = context;
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
            let native = self.native.get();
            let sync = unsafe {
                // SAFETY: `initialized` guarantees FsRtl populated this
                // mounted VCB's synchronization pointer.
                (*native).sync
            };
            let list_head = unsafe {
                // SAFETY: This final VCB teardown still owns the stable list
                // head and no new request can be accepted during destruction.
                core::ptr::addr_of_mut!((*native).list_head)
            };
            unsafe {
                // SAFETY: FsRtl completes and frees every remaining opaque
                // notification record before its synchronization object dies.
                ffi::FsRtlNotifyCleanupAll(sync, list_head);
            }
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
#[derive(Clone, Copy, Debug)]
pub(super) struct DirectoryNotificationTarget {
    /// UTF-16 `\\<opaque parent id>\\<child name>` target path.
    pub(super) units: [u16; DIRECTORY_NOTIFICATION_TARGET_UNITS],
    /// UTF-16 byte count of the populated target path.
    pub(super) byte_length: u16,
    /// Byte offset of the final child component inside `units`.
    pub(super) name_offset_bytes: u16,
}

impl DirectoryNotificationTarget {
    /// Builds one complete target path from a directory entry identity.
    /// # Errors
    ///
    /// Returns an error when the ext4 child name cannot be represented by Windows.
    fn new(parent: DirectoryNodeId, name: &Ext4Name) -> DriverResult<Self> {
        let directory_units = DirectoryNotificationDirectoryName::encode(parent);
        let name = WindowsName::from_ext4(name)?;
        let prefix_length = DIRECTORY_NOTIFICATION_DIRECTORY_UNITS
            .checked_add(1)
            .ok_or(DriverError::InvalidBufferSize)?;
        let length = prefix_length
            .checked_add(name.utf16().len())
            .ok_or(DriverError::InvalidBufferSize)?;
        if length > DIRECTORY_NOTIFICATION_TARGET_UNITS {
            return Err(DriverError::InvalidBufferSize);
        }
        let mut units = [0_u16; DIRECTORY_NOTIFICATION_TARGET_UNITS];
        let directory_destination = units
            .get_mut(..DIRECTORY_NOTIFICATION_DIRECTORY_UNITS)
            .ok_or(DriverError::InvalidBufferSize)?;
        let directory_source = directory_units
            .get(..DIRECTORY_NOTIFICATION_DIRECTORY_UNITS)
            .ok_or(DriverError::InvalidBufferSize)?;
        memory::copy_exact(directory_destination, directory_source)?;
        let separator = units
            .get_mut(DIRECTORY_NOTIFICATION_DIRECTORY_UNITS)
            .ok_or(DriverError::InvalidBufferSize)?;
        *separator = DIRECTORY_NOTIFICATION_SEPARATOR;
        let child_destination = units
            .get_mut(prefix_length..length)
            .ok_or(DriverError::InvalidBufferSize)?;
        memory::copy_exact(child_destination, name.utf16())?;
        let byte_length = u16::try_from(
            length
                .checked_mul(core::mem::size_of::<u16>())
                .ok_or(DriverError::InvalidBufferSize)?,
        )
        .map_err(|_| DriverError::InvalidBufferSize)?;
        let name_offset_bytes = u16::try_from(
            prefix_length
                .checked_mul(core::mem::size_of::<u16>())
                .ok_or(DriverError::InvalidBufferSize)?,
        )
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
            Buffer: self.units.as_ptr().cast_mut(),
        }
    }
}

/// UTF-16 backslash separator used in FsRtl synthetic paths.
const DIRECTORY_NOTIFICATION_SEPARATOR: u16 = 0x005C;
/// High-byte marker separating encoded inode bytes from Windows path separators.
const DIRECTORY_NOTIFICATION_INODE_MARKER: u16 = 0x0100;
/// `\\` plus four lossless inode-identity units.
pub(super) const DIRECTORY_NOTIFICATION_DIRECTORY_UNITS: usize = 5;
/// Synthetic parent path, one separator, and the largest ext4 name in UTF-16 units.
const DIRECTORY_NOTIFICATION_TARGET_UNITS: usize = 261;
