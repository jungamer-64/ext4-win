//! Directory-change registration, encoding, publication, and cleanup.

use super::*;

/// One validated directory-notification registration owned by a FILE_OBJECT.
#[derive(Debug)]
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
    /// Anchored names and crossed-directory access projections prepared together.
    path: DirectoryNotificationPath,
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
        mapping: &ext4_security::IdentityMap,
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
            path: DirectoryNotificationPath::prepare(read, mapping, parent, name)?,
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
        mapping: &ext4_security::IdentityMap,
        parent: DirectoryNodeId,
        name: &Ext4Name,
        filter: u32,
    ) -> DriverResult<Self> {
        Ok(Self {
            path: DirectoryNotificationPath::prepare(read, mapping, parent, name)?,
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
        mapping: &ext4_security::IdentityMap,
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
            path: DirectoryNotificationPath::prepare(read, mapping, parent, name)?,
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
        subject: crate::kernel::requestor_subject::NotificationSubject,
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
                    subject.into_fsrtl(),
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
                subject,
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
            change.path.for_each(|target, traversal| {
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
                        core::ptr::from_ref(&traversal).cast(),
                    );
                }
            });
        }
        #[cfg(test)]
        {
            change.path.for_each(|target, traversal| {
                core::hint::black_box((
                    target.unicode_string(),
                    target.name_offset_bytes,
                    change.completion_filter,
                    change.action.as_ulong(),
                    traversal,
                ));
            });
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

/// Each enclosing watch anchor adds the directory crossed below it. Descriptors and names
/// are built under one committed read pass and identity snapshot before durable publication.
#[derive(Debug)]
struct DirectoryNotificationPath {
    /// Immediate parent followed by outward traversal; each prefix ends at one watch anchor.
    steps: DriverVec<DirectoryNotificationStep>,
}

/// Direct-child visibility and traversal into another directory have different authority.
#[derive(Debug)]
enum DirectoryNotificationStep {
    /// No traversal beyond the directory whose open handle owns the watch.
    Direct(DirectoryNotificationTarget),
    /// Reaching the change from this enclosing anchor crosses another directory.
    Crossed {
        /// Synthetic name for this exact watched-directory identity.
        target: DirectoryNotificationTarget,
        /// Complete aligned projection of the crossed directory's access policy.
        descriptor: ext4_security::Descriptor,
    },
}

impl DirectoryNotificationStep {
    /// Borrows the anchored name without granting traversal authority.
    fn target(&self) -> &DirectoryNotificationTarget {
        match self {
            Self::Direct(target) | Self::Crossed { target, .. } => target,
        }
    }
}

impl DirectoryNotificationPath {
    /// Prepares one anchored path for each ancestor before mutation publication.
    /// Synthetic roots identify watched directories by inode, so moving a directory never
    /// invalidates an outstanding watch. Each suffix is the actual relative Windows path.
    /// # Errors
    /// Returns cyclic/malformed ancestry, encoding, length or allocation failures.
    fn prepare(
        read: &mut impl ext4_core::CommittedReadPass,
        mapping: &ext4_security::IdentityMap,
        mut parent: DirectoryNodeId,
        name: &Ext4Name,
    ) -> DriverResult<Self> {
        let mut components = DriverVec::new();
        components
            .try_push_owned(WindowsName::from_ext4(name)?)
            .map_err(|error| error.into_parts().0)?;
        let mut visited = DriverVec::new();
        let mut steps = DriverVec::new();
        steps
            .try_push_owned(DirectoryNotificationStep::Direct(
                DirectoryNotificationTarget::from_components(parent, components.as_slice())?,
            ))
            .map_err(|error| error.into_parts().0)?;
        while parent != DirectoryNodeId::ROOT {
            if visited.as_slice().contains(&parent) {
                return Err(ext4_core::Error::InvalidDirectoryEntry.into());
            }
            visited.try_push(parent)?;
            let access = read.load_access(NodeId::Directory(parent))?;
            let descriptor =
                ext4_security::Descriptor::for_request(&access, mapping, wdk_sys::FILE_TRAVERSE)?;
            let link = crate::namespace::directory_parent(read, parent)?;
            components
                .try_push_owned(link.name)
                .map_err(|error| error.into_parts().0)?;
            parent = link.directory;
            steps
                .try_push_owned(DirectoryNotificationStep::Crossed {
                    target: DirectoryNotificationTarget::from_components(
                        parent,
                        components.as_slice(),
                    )?,
                    descriptor,
                })
                .map_err(|error| error.into_parts().0)?;
        }
        Ok(Self { steps })
    }

    /// Lends only complete path prefixes for synchronous native reporting.
    fn for_each(
        &self,
        mut report: impl FnMut(&DirectoryNotificationTarget, NotificationTraversal<'_>),
    ) {
        let mut prefix = self.steps.as_slice();
        while let Some((last, preceding)) = prefix.split_last() {
            report(last.target(), NotificationTraversal { steps: prefix });
            prefix = preceding;
        }
    }
}

/// Immutable descriptors for the exact synthetic watch anchor currently being reported.
#[derive(Debug)]
struct NotificationTraversal<'a> {
    /// Crossed directories, excluding the directory whose handle owns the watch.
    steps: &'a [DirectoryNotificationStep],
}

impl NotificationTraversal<'_> {
    /// Every crossed directory must grant traversal to the same captured subject.
    fn permits(&self, mut check: impl FnMut(&ext4_security::Descriptor) -> bool) -> bool {
        self.steps.iter().all(|step| match step {
            DirectoryNotificationStep::Direct(_) => true,
            DirectoryNotificationStep::Crossed { descriptor, .. } => check(descriptor),
        })
    }
}

/// Evaluates prepared access projections while C holds the original token lock.
/// # Safety
/// C lends the live report-local traversal and an already-locked FsRtl-owned subject.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "FsRtl invokes this callback synchronously while both borrowed inputs remain live"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_notification_traverse(
    target: *const NotificationTraversal<'_>,
    subject: *mut wdk_sys::SECURITY_SUBJECT_CONTEXT,
) -> u8 {
    let traversal = unsafe {
        // SAFETY: C passes the borrowed report-local traversal unchanged.
        &*target
    };
    u8::from(traversal.permits(|descriptor| unsafe {
        // SAFETY: RTL built this aligned immutable image; C retains and locks subject.
        ffi::ext4win_notification_check_traverse(
            subject,
            descriptor.bytes().as_ptr().cast_mut().cast(),
        ) != 0
    }))
}

impl DirectoryNotificationTarget {
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

    /// Produces distinct valid native policy images for independent traversal decisions.
    /// # Errors
    /// Returns fixture permission or native descriptor construction failure.
    fn traversal_descriptor(mode: u16) -> DriverResult<ext4_security::Descriptor> {
        let access = ext4_core::Ext4Access::from_mode(ext4_core::Ext4Security::new(
            ext4_core::Ext4Owner::new(
                ext4_core::Ext4Uid::from_u32(1000),
                ext4_core::Ext4Gid::from_u32(100),
            ),
            ext4_core::Ext4Permissions::new(mode)?,
        ));
        Ok(ext4_security::Descriptor::for_request(
            &access,
            &ext4_security::IdentityMap::empty(),
            wdk_sys::FILE_TRAVERSE,
        )?)
    }

    /// # Errors
    /// Returns fixture name, permission, native descriptor or vector allocation failure.
    /// # Panics
    /// Fails if an enclosing watch skips a crossed directory or checks beyond its own anchor.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture construction propagates errors while assertions verify path visibility"
    )]
    fn recursive_notification_checks_only_the_intervening_directory_prefix() -> DriverResult<()> {
        let name = WindowsName::from_utf16(&[102])?;
        let mut steps = DriverVec::new();
        steps
            .try_push_owned(DirectoryNotificationStep::Direct(
                DirectoryNotificationTarget::from_components(DirectoryNodeId::ROOT, &[name])?,
            ))
            .map_err(|error| error.into_parts().0)?;
        for mode in [0o700, 0o711] {
            steps
                .try_push_owned(DirectoryNotificationStep::Crossed {
                    target: DirectoryNotificationTarget::from_components(
                        DirectoryNodeId::ROOT,
                        &[WindowsName::from_utf16(&[102])?],
                    )?,
                    descriptor: traversal_descriptor(mode)?,
                })
                .map_err(|error| error.into_parts().0)?;
        }
        let path = DirectoryNotificationPath { steps };
        for denied in 1..=2 {
            let DirectoryNotificationStep::Crossed {
                descriptor: blocked,
                ..
            } = path
                .steps
                .as_slice()
                .get(denied)
                .ok_or(DriverError::InternalInvariantViolation)?
            else {
                return Err(DriverError::InternalInvariantViolation);
            };
            let mut decisions = alloc::vec::Vec::new();
            path.for_each(|_, traversal| {
                let allowed = traversal.permits(|descriptor| !core::ptr::eq(descriptor, blocked));
                decisions.push((traversal.steps.len(), allowed));
            });
            assert!(decisions.contains(&(1, true)));
            assert!(decisions.contains(&(2, denied != 1)));
            assert!(decisions.contains(&(3, false)));
        }
        path.for_each(|_, traversal| assert!(traversal.permits(|_| true)));
        Ok(())
    }

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
