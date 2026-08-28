//! Shared stream registry, share-access accounting, and child-creation admission.

use super::*;

/// VCB-owned FCB table and share accounting protected by one concrete executive resource.
pub(super) struct FileControlBlockLedger {
    /// Mutable ledger state reachable only while `lock` is held.
    pub(super) table: UnsafeCell<DriverVec<Box<FileControlBlock>>>,
    /// Stable-address executive resource for every table/share/reference transition.
    lock: FileControlBlockLedgerLock,
}

/// One explicit FCB retention authority used while durable metadata is published outside the
/// ledger resource.
struct StreamPublicationLease {
    /// Ledger that granted and must release this lease.
    owner: NonNull<FileControlBlockLedger>,
    /// Exact FCB retained by the ledger-owned deferred lease count.
    fcb: NonNull<FileControlBlock>,
}

#[expect(
    unsafe_code,
    reason = "the explicit lease retains the exact FCB pointer while publishing outside the ledger"
)]
impl StreamPublicationLease {
    /// Publishes one complete stream-size tuple through the native Cc/MM boundary.
    /// # Errors
    ///
    /// Returns the exact Cache Manager publication failure.
    fn publish(&self, sizes: StreamSizes) -> DriverResult<()> {
        let fcb = unsafe {
            // SAFETY: This lease keeps the FCB table entry alive until its own Drop completes.
            self.fcb.as_ref()
        };
        fcb.stream_context.set_sizes(sizes)
    }
}

#[expect(
    unsafe_code,
    reason = "the lease releases the exact ledger/Fcb identity retained at acquisition"
)]
impl Drop for StreamPublicationLease {
    fn drop(&mut self) {
        let owner = unsafe {
            // SAFETY: An FCB cannot outlive its VCB-owned ledger; this lease retains an FCB entry.
            self.owner.as_ref()
        };
        owner.release_stream_publication_lease(self.fcb);
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Every production and test access to `table` is serialized by `lock`; no reference to
// the table or an FCB's ledger-owned mutable fields escapes the guard scope.
unsafe impl Sync for FileControlBlockLedger {}

impl fmt::Debug for FileControlBlockLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileControlBlockLedger(..)")
    }
}

impl Drop for FileControlBlockLedger {
    fn drop(&mut self) {
        if !self.table.get_mut().is_empty() {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        }
    }
}

/// Stable-address WDK executive resource dedicated to the FCB ledger.
struct FileControlBlockLedgerLock {
    /// Native resource initialized only after this allocation reaches its final pinned address.
    #[cfg(not(test))]
    native: Pin<Box<MaybeUninit<wdk_sys::ERESOURCE>>>,
    /// Host mutex with the same exclusive RAII ownership model as the native resource.
    #[cfg(test)]
    native: Mutex<()>,
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Production access uses only the executive-resource routines against pinned initialized
// storage. The host backend is a `Mutex`. Both provide exclusive guard ownership.
unsafe impl Sync for FileControlBlockLedgerLock {}

impl fmt::Debug for FileControlBlockLedgerLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileControlBlockLedgerLock(..)")
    }
}

/// Exclusive requester-thread ownership of the FCB ledger resource.
struct FileControlBlockLedgerGuard<'a> {
    /// Native resource released on the same thread when this guard drops.
    #[cfg(not(test))]
    lock: &'a FileControlBlockLedgerLock,
    /// Host guard used only where WDK executive-resource routines are unavailable.
    #[cfg(test)]
    _native: MutexGuard<'a, ()>,
    /// Executive resources cannot be released by a different thread than their acquirer.
    _not_send: PhantomData<*mut ()>,
}

impl FileControlBlockLedgerLock {
    /// Allocates and initializes an executive resource at its permanent address.
    /// # Errors
    ///
    /// Returns an error when stable resource storage cannot be allocated or initialized.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn try_new() -> DriverResult<Self> {
        #[cfg(not(test))]
        {
            let native =
                memory::boxed_try_with(|| Ok(MaybeUninit::<wdk_sys::ERESOURCE>::uninit()))?;
            let native = Box::into_pin(native);
            let status = unsafe {
                // SAFETY: `native` is pinned at its final nonpaged address. The storage is not
                // exposed or dropped as an initialized ERESOURCE unless initialization succeeds.
                ffi::ExInitializeResourceLite(native.as_ref().get_ref().as_ptr().cast_mut())
            };
            if status < STATUS_SUCCESS {
                return Err(DriverError::InsufficientResources);
            }
            Ok(Self { native })
        }
        #[cfg(test)]
        {
            Ok(Self {
                native: Mutex::new(()),
            })
        }
    }

    /// Acquires exclusive ledger ownership until the returned guard drops.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn acquire(&self) -> FileControlBlockLedgerGuard<'_> {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The resource was initialized at this pinned address. This combined routine
            // retains PASSIVE_LEVEL while disabling normal kernel APC delivery, and guard Drop
            // releases it on the acquiring thread.
            ffi::ExEnterCriticalRegionAndAcquireResourceExclusive(self.native_ptr());
        }
        #[cfg(test)]
        let native = match self.native.lock() {
            Ok(native) => native,
            Err(poisoned) => poisoned.into_inner(),
        };
        FileControlBlockLedgerGuard {
            #[cfg(not(test))]
            lock: self,
            #[cfg(test)]
            _native: native,
            _not_send: PhantomData,
        }
    }

    /// Returns the initialized native resource pointer.
    #[cfg(not(test))]
    fn native_ptr(&self) -> *mut wdk_sys::ERESOURCE {
        self.native.as_ref().get_ref().as_ptr().cast_mut()
    }
}

impl Drop for FileControlBlockLedgerGuard<'_> {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This !Send guard is dropping on the thread that exclusively acquired the
            // matching resource and entered its critical region.
            ffi::ExReleaseResourceAndLeaveCriticalRegion(self.lock.native_ptr());
        }
    }
}

#[cfg(not(test))]
impl Drop for FileControlBlockLedgerLock {
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn drop(&mut self) {
        let status = unsafe {
            // SAFETY: Construction publishes this wrapper only after successful initialization,
            // and ledger teardown guarantees no guard or table entry remains.
            ffi::ExDeleteResourceLite(self.native_ptr())
        };
        if status < STATUS_SUCCESS {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        }
    }
}

/// Share validation required before publishing one handle claim.
#[derive(Clone, Copy, Debug)]
pub(super) enum FileControlBlockShareCheck {
    /// Existing-node operations must first respect the access shared by prior handles.
    ExistingNode {
        /// Virtual access required by the existing-node disposition.
        operation_access: ExistingOperationAccess,
        /// Oplock behavior that must be admitted atomically with the new share claim.
        oplock_policy: OplockCreatePolicy,
    },
    /// A transaction-local new node has no pre-existing operation access to validate.
    NewNode,
}

/// One normalized existing-stream claim admitted atomically by the FCB ledger.
#[derive(Clone, Copy, Debug)]
struct ExistingFileControlBlockOpen {
    /// Mounted-volume identity that owns the stream.
    volume: NonNull<VolumeControlBlock>,
    /// Durable size snapshot used if construction creates the FCB.
    stream: NodeStreamSizes,
    /// FILE_OBJECT whose share claim is being published.
    file_object: KernelFileObject,
    /// Access already granted by the create security boundary.
    desired_access: GrantedAccess,
    /// Existing-node operation access that participates in share validation.
    operation_access: ExistingOperationAccess,
    /// Requested Windows sharing.
    share_access: ShareAccess,
    /// Requested create-time oplock behavior.
    oplock_policy: OplockCreatePolicy,
}

impl FileControlBlockLedger {
    /// Creates an empty synchronized FCB ledger and its native resource.
    /// # Errors
    ///
    /// Returns an error when the stable executive resource cannot be allocated or initialized.
    pub(super) fn try_new() -> DriverResult<Self> {
        Ok(Self {
            table: UnsafeCell::new(DriverVec::new()),
            lock: FileControlBlockLedgerLock::try_new()?,
        })
    }

    /// Opens an existing-node FCB and atomically records its share claim.
    /// # Errors
    ///
    /// Returns an error when FCB allocation/reference growth or Windows share validation fails.
    fn open_existing(
        &self,
        request: ExistingFileControlBlockOpen,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        self.open(
            request.volume,
            request.stream,
            request.file_object,
            request.desired_access,
            request.share_access,
            FileControlBlockShareCheck::ExistingNode {
                operation_access: request.operation_access,
                oplock_policy: request.oplock_policy,
            },
        )
    }

    /// Opens a staged-new-node FCB and atomically records its share claim.
    /// # Errors
    ///
    /// Returns an error when FCB allocation/reference growth or Windows share validation fails.
    fn open_new(
        &self,
        volume: NonNull<VolumeControlBlock>,
        stream: NodeStreamSizes,
        file_object: KernelFileObject,
        desired_access: GrantedAccess,
        share_access: ShareAccess,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        self.open(
            volume,
            stream,
            file_object,
            desired_access,
            share_access,
            FileControlBlockShareCheck::NewNode,
        )
    }

    /// Opens or creates one ledger entry and records the FILE_OBJECT share claim atomically.
    /// # Errors
    ///
    /// Returns an error when allocation, reference growth, or share validation fails.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn open(
        &self,
        volume: NonNull<VolumeControlBlock>,
        stream: NodeStreamSizes,
        file_object: KernelFileObject,
        desired_access: GrantedAccess,
        share_access: ShareAccess,
        share_check: FileControlBlockShareCheck,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        let node = stream.node();
        if let Some(result) =
            self.try_open_present(node, file_object, desired_access, share_access, share_check)
        {
            return result;
        }

        let candidate = self.file_control_block(volume, stream)?;
        let mut discarded = None;
        let mut removed = None;
        let result = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource uniquely owns table mutation for this scope.
                &mut *self.table.get()
            };
            if let Some(fcb) = find_file_control_block_in_table(table, node) {
                discarded = Some(candidate);
                record_reused_file_control_block_open(
                    table,
                    fcb,
                    file_object,
                    desired_access,
                    share_access,
                    share_check,
                )
                .map(|()| fcb)
            } else {
                let fcb = NonNull::from(candidate.as_ref());
                match table.try_push_owned(candidate) {
                    Ok(()) => match record_file_control_block_share(
                        table,
                        fcb,
                        file_object,
                        desired_access,
                        share_access,
                        share_check,
                    ) {
                        Ok(()) => Ok(fcb),
                        Err(error) => {
                            removed = release_file_object_lease_in_table(table, fcb, false);
                            Err(error)
                        }
                    },
                    Err(error) => {
                        let (error, candidate) = error.into_parts();
                        discarded = Some(candidate);
                        Err(error)
                    }
                }
            }
        };
        drop(removed);
        drop(discarded);
        result
    }

    /// Creates an uninserted FCB candidate owned by this ledger.
    /// # Errors
    ///
    /// Returns an allocation or native-header initialization/binding error.
    pub(super) fn file_control_block(
        &self,
        volume: NonNull<VolumeControlBlock>,
        stream: NodeStreamSizes,
    ) -> DriverResult<Box<FileControlBlock>> {
        let candidate = memory::boxed_try_with(|| {
            FileControlBlock::try_new(volume, NonNull::from(self), stream)
        })?;
        candidate.bind_stream_owner()?;
        Ok(candidate)
    }

    /// Attempts to reuse an existing entry without allocating a candidate FCB.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn try_open_present(
        &self,
        node: NodeId,
        file_object: KernelFileObject,
        desired_access: GrantedAccess,
        share_access: ShareAccess,
        share_check: FileControlBlockShareCheck,
    ) -> Option<DriverResult<NonNull<FileControlBlock>>> {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table lookup and open-state mutation.
            &*self.table.get()
        };
        let fcb = find_file_control_block_in_table(table, node)?;
        Some(
            record_reused_file_control_block_open(
                table,
                fcb,
                file_object,
                desired_access,
                share_access,
                share_check,
            )
            .map(|()| fcb),
        )
    }

    /// Releases a share claim and selects final-active-handle deletion while retaining the FCB.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn release_share_access(
        &self,
        fcb: NonNull<FileControlBlock>,
        file_object: KernelFileObject,
    ) -> FileCleanupDisposition {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes lookup and open-state mutation.
            &*self.table.get()
        };
        let mut state = ledger_file_control_block_open_state(table, fcb);
        let state = unsafe {
            // SAFETY: The ledger resource remains exclusively held and the helper validated this
            // state pointer against the owning table.
            state.as_mut()
        };
        state.remove_share_access(file_object);
        state.cleanup_disposition()
    }

    /// Publishes a stable delete-pending target for one live FCB.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn set_delete_pending(
        &self,
        fcb: NonNull<FileControlBlock>,
        pending: PendingFileDeletion,
    ) {
        let previous = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource serializes lookup and open-state mutation.
                &*self.table.get()
            };
            let mut state = ledger_file_control_block_open_state(table, fcb);
            unsafe {
                // SAFETY: The FCB was validated against the table while the resource is held.
                state.as_mut()
            }
            .set_delete_pending(pending)
        };
        drop(previous);
    }

    /// Cancels delete-pending for one live FCB.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn clear_delete_pending(&self, fcb: NonNull<FileControlBlock>) {
        let previous = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource serializes lookup and open-state mutation.
                &*self.table.get()
            };
            let mut state = ledger_file_control_block_open_state(table, fcb);
            unsafe {
                // SAFETY: The FCB was validated against the table while the resource is held.
                state.as_mut()
            }
            .clear_delete_pending()
        };
        drop(previous);
    }

    /// Returns whether one live FCB is delete-pending.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn delete_pending(&self, fcb: NonNull<FileControlBlock>) -> bool {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table and open-state observation.
            &*self.table.get()
        };
        let state = ledger_file_control_block_open_state(table, fcb);
        unsafe {
            // SAFETY: The FCB was validated against the table while the resource is held.
            state.as_ref()
        }
        .delete_pending()
    }

    /// Publishes committed removal of the exact pending target.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn complete_delete(
        &self,
        fcb: NonNull<FileControlBlock>,
        target: NonNull<FileDeleteTarget>,
    ) {
        let completed = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource serializes lookup and open-state mutation.
                &*self.table.get()
            };
            let mut state = ledger_file_control_block_open_state(table, fcb);
            unsafe {
                // SAFETY: The FCB was validated against the table while the resource is held.
                state.as_mut()
            }
            .complete_delete(target)
        };
        drop(completed);
    }

    /// Atomically releases a share claim and the same FILE_OBJECT's final FCB reference.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn release_share_access_and_reference(
        &self,
        fcb: NonNull<FileControlBlock>,
        file_object: KernelFileObject,
    ) {
        let native_resident = unsafe {
            // SAFETY: The closing FILE_OBJECT retains its FCB until this release completes.
            fcb.as_ref()
        }
        .has_native_stream_residency()
        .unwrap_or_else(|_| {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
        });
        let removed = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource uniquely owns table and open-state mutation.
                &mut *self.table.get()
            };
            let mut state = ledger_file_control_block_open_state(table, fcb);
            unsafe {
                // SAFETY: The ledger resource remains exclusively held and the helper validated
                // this state pointer against the owning table.
                state.as_mut()
            }
            .remove_share_access(file_object);
            release_file_object_lease_in_table(table, fcb, native_resident)
        };
        drop(removed);
    }

    /// Releases one FILE_OBJECT's final FCB reference at close.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn close(&self, fcb: NonNull<FileControlBlock>) {
        let native_resident = unsafe {
            // SAFETY: The closing FILE_OBJECT retains its FCB until this release completes.
            fcb.as_ref()
        }
        .has_native_stream_residency()
        .unwrap_or_else(|_| {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
        });
        let removed = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource uniquely owns table and open-state mutation.
                &mut *self.table.get()
            };
            release_file_object_lease_in_table(table, fcb, native_resident)
        };
        drop(removed);
    }

    /// Looks up current streams at durable publication and retains each through a short explicit
    /// lease while the ledger resource is released for the native Cc/MM call.
    /// # Errors
    ///
    /// Returns the exact stream-lease or Cc/MM publication failure.
    pub(super) fn publish_stream_sizes(
        &self,
        updates: PreparedStreamSizePublications,
    ) -> DriverResult<()> {
        for update in updates.nodes.iter() {
            if let Some(lease) = self.acquire_stream_publication_lease(update.node())? {
                lease.publish(update.sizes)?;
            }
        }
        Ok(())
    }

    /// Acquires an explicit stream lease before releasing the ledger resource for a Cc/MM call.
    /// # Errors
    ///
    /// Returns insufficient resources when the finite deferred-lease count is exhausted.
    #[expect(
        unsafe_code,
        reason = "the ledger resource serializes the table and deferred-lease transition"
    )]
    fn acquire_stream_publication_lease(
        &self,
        node: NodeId,
    ) -> DriverResult<Option<StreamPublicationLease>> {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table lookup and lifetime mutation.
            &*self.table.get()
        };
        let Some(fcb) = find_file_control_block_in_table(table, node) else {
            return Ok(None);
        };
        let mut state = ledger_file_control_block_open_state(table, fcb);
        unsafe {
            // SAFETY: The resource remains held and the FCB was found in this owning table.
            state.as_mut()
        }
        .acquire_deferred_lease()?;
        Ok(Some(StreamPublicationLease {
            owner: NonNull::from(self),
            fcb,
        }))
    }

    /// Releases one publication lease and destroys the FCB only after native residency drains.
    #[expect(
        unsafe_code,
        reason = "the live lease retains its FCB while the ledger serializes terminal release"
    )]
    fn release_stream_publication_lease(&self, fcb: NonNull<FileControlBlock>) {
        let native_resident = unsafe {
            // SAFETY: The outstanding publication lease retains this FCB for the observation.
            fcb.as_ref()
        }
        .has_native_stream_residency()
        .unwrap_or_else(|_| {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
        });
        let removed = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource uniquely owns table and lifetime mutation.
                &mut *self.table.get()
            };
            let Some(index) = table
                .iter()
                .position(|candidate| NonNull::from(candidate.as_ref()) == fcb)
            else {
                KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
            };
            let mut state = ledger_file_control_block_open_state(table, fcb);
            let reclaimable = unsafe {
                // SAFETY: The ledger resource and exact lease grant this lifetime transition.
                state.as_mut()
            }
            .release_deferred_lease(native_resident);
            if reclaimable {
                table.swap_remove(index)
            } else {
                None
            }
        };
        drop(removed);
    }

    /// Returns the current user-handle count for one table-owned FCB.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the ledger resource serializes the exact FCB open-count observation"
    )]
    pub(super) fn stream_open_count(&self, fcb: NonNull<FileControlBlock>) -> u32 {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table membership and open state.
            &*self.table.get()
        };
        let state = ledger_file_control_block_open_state(table, fcb);
        unsafe {
            // SAFETY: The FCB is table-owned for this retained FILE_OBJECT and the guard is held.
            state.as_ref().share_access.OpenCount
        }
    }

    /// Returns whether every namespace FILE_OBJECT has released its FCB reference.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn is_empty(&self) -> bool {
        let _guard = self.lock.acquire();
        unsafe {
            // SAFETY: The executive resource serializes table observation.
            (*self.table.get()).is_empty()
        }
    }

    /// Returns whether a currently open inode identity rejects new namespace traversal.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn node_delete_pending(&self, node: NodeId) -> bool {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table and open-state observation.
            &*self.table.get()
        };
        let Some(fcb) = find_file_control_block_in_table(table, node) else {
            return false;
        };
        let fcb = unsafe {
            // SAFETY: The table owns this FCB and the resource remains held for the observation.
            fcb.as_ref()
        };
        let state = unsafe {
            // SAFETY: The ledger resource serializes this FCB open-state observation.
            &*fcb.open_state.get()
        };
        state.delete_pending()
    }

    /// Requires a currently open inode to permit ordinary namespace replacement.
    /// # Errors
    ///
    /// Returns delete-pending or sharing-violation when the open state rejects replacement.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn ensure_node_replaceable(&self, node: NodeId) -> DriverResult<()> {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table and open-state observation.
            &*self.table.get()
        };
        let Some(fcb) = find_file_control_block_in_table(table, node) else {
            return Ok(());
        };
        let fcb = unsafe {
            // SAFETY: The table owns this FCB and the resource remains held for the observation.
            fcb.as_ref()
        };
        let state = unsafe {
            // SAFETY: The ledger resource serializes this FCB open-state observation.
            &*fcb.open_state.get()
        };
        state.ensure_namespace_replaceable()
    }
}

#[derive(Debug)]
/// Missing-child node kind selected before an ext4 namespace create transaction starts.
pub(crate) enum ChildCreationTarget {
    /// Create a regular file with prebuilt metadata.
    File(NewFileMetadata),
    /// Create a directory with prebuilt metadata.
    Directory(NewDirectoryMetadata),
}

impl VolumeControlBlock {
    /// Builds a mounted VCB from a completed mount operation and validated lower devices.
    /// # Errors
    ///
    /// Returns an error when driver-local mounted state cannot be allocated.
    pub(crate) fn from_completed_mount(
        mount: CompletedMount,
        storage: MountedStorage,
    ) -> DriverResult<Self> {
        Ok(Self {
            directory_change_notifier: DirectoryChangeNotifier::uninitialized(),
            file_control_blocks: FileControlBlockLedger::try_new()?,
            volume_control: VolumeControlPlane::mounted(),
            runtime: VolumeRuntime::try_new(mount, storage)?,
            stream_context: StreamContext::try_new(StreamOwnerKind::Volume, StreamSizes::EMPTY)?,
        })
    }

    /// Binds the volume stream header after the VCB reaches its final heap address.
    /// # Errors
    ///
    /// Returns an invariant error if mount publication attempts to bind this VCB more than once.
    pub(crate) fn bind_stream_owner(&self) -> DriverResult<()> {
        self.stream_context
            .bind_owner(NonNull::from(self).cast::<c_void>())
    }

    /// Returns the advanced-header address published through direct volume FILE_OBJECTs.
    pub(crate) fn stream_header(&self) -> NonNull<c_void> {
        self.stream_context.header()
    }

    /// Returns the direct-volume stream's shared section-object set.
    /// # Errors
    ///
    /// Returns an invariant error if the volume's native header is malformed.
    pub(crate) fn stream_section_objects(
        &self,
    ) -> DriverResult<NonNull<wdk_sys::SECTION_OBJECT_POINTERS>> {
        self.stream_context.section_objects()
    }

    /// Initializes the volume-wide FsRtl notification state after this VCB reaches stable storage.
    /// # Errors
    ///
    /// Returns an error when FsRtl cannot allocate the notifier synchronization state.
    pub(crate) fn initialize_directory_change_notifier(&mut self) -> DriverResult<()> {
        self.directory_change_notifier.initialize()
    }

    /// Returns the volume-wide directory notification state.
    pub(crate) const fn directory_change_notifier(&self) -> &DirectoryChangeNotifier {
        &self.directory_change_notifier
    }

    /// Reports one committed namespace name change to pending directory watchers.
    pub(crate) fn report_directory_change(&self, change: DirectoryChange) {
        self.directory_change_notifier.report(change);
    }

    /// Opens or reuses an existing node's FCB and records its share claim atomically.
    /// # Errors
    ///
    /// Returns an error when FCB allocation/reference growth or Windows share validation fails.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn open_existing_file_control_block(
        volume: NonNull<Self>,
        stream: NodeStreamSizes,
        file_object: KernelFileObject,
        desired_access: GrantedAccess,
        existing_operation_access: ExistingOperationAccess,
        share_access: ShareAccess,
        oplock_policy: OplockCreatePolicy,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        let volume_ptr = volume.as_ptr();
        let file_control_blocks = unsafe {
            // SAFETY: `volume_ptr` identifies the live, stable mounted VCB. `addr_of!` projects
            // the ledger address without creating a reference to the transaction-owned volume.
            core::ptr::addr_of!((*volume_ptr).file_control_blocks)
        };
        let file_control_blocks = unsafe {
            // SAFETY: The mounted VCB pointer is stable for request processing. Raw field
            // projection borrows only the independently synchronized ledger and never creates a
            // shared reference spanning the transaction-owned `volume` field.
            &*file_control_blocks
        };
        file_control_blocks.open_existing(ExistingFileControlBlockOpen {
            volume,
            stream,
            file_object,
            desired_access,
            operation_access: existing_operation_access,
            share_access,
            oplock_policy,
        })
    }

    /// Returns whether logical dismount already consumed shutdown registration.
    pub(super) fn is_logically_dismounted(&self) -> bool {
        matches!(
            self.volume_control.state,
            MountedVolumeState::Dismounted { .. } | MountedVolumeState::Retiring
        )
    }
}
/// Driver publication values prepared for a child staged in an ephemeral mutation pass.
#[derive(Debug)]
pub(crate) struct PendingChildCreation {
    /// Stable synchronized FCB ledger owned by the mounted VCB.
    pub(super) file_control_blocks: NonNull<FileControlBlockLedger>,
    /// VCB that owns any FCB opened for the staged node.
    pub(super) volume: MountedVolumeRef,
    /// Node identity allocated by the staged transaction.
    pub(super) node: NodeId,
}

impl PendingChildCreation {
    /// Returns the node identity allocated by the staged create transaction.
    pub(crate) const fn node(&self) -> NodeId {
        self.node
    }

    /// Opens the staged node's FCB and records its share claim atomically.
    /// # Errors
    ///
    /// Returns an error when FCB allocation/reference growth or Windows share validation fails.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn open_file_control_block(
        &self,
        file_object: KernelFileObject,
        desired_access: GrantedAccess,
        share_access: ShareAccess,
        stream_sizes: NodeStreamSizes,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        if stream_sizes.node() != self.node {
            return Err(DriverError::InternalInvariantViolation);
        }
        unsafe {
            // SAFETY: The mounted VCB outlives all admitted operations and FILE_OBJECT contexts.
            self.file_control_blocks.as_ref()
        }
        .open_new(
            self.volume.as_non_null(),
            stream_sizes,
            file_object,
            desired_access,
            share_access,
        )
    }

    /// Sets or replaces one xattr on the staged child in this create transaction.
    /// # Errors
    ///
    /// Returns an error when the staged node rejects xattr mutation.
    pub(crate) fn set_xattr(
        &mut self,
        transaction: &mut MutationResolvePass<'_, '_, '_>,
        name: XattrName,
        value: XattrValue,
    ) -> DriverResult<()> {
        let node = transaction.node(self.node)?;
        transaction.set_xattr(node, name, value)?;
        Ok(())
    }

    /// Removes one xattr from the staged child in this create transaction.
    /// # Errors
    ///
    /// Returns an error when the staged node rejects xattr mutation.
    pub(crate) fn remove_xattr(
        &mut self,
        transaction: &mut MutationResolvePass<'_, '_, '_>,
        name: &XattrName,
    ) -> DriverResult<()> {
        let node = transaction.node(self.node)?;
        transaction.remove_xattr(node, name)?;
        Ok(())
    }
}

/// Records a share claim and then publishes one additional FILE_OBJECT reference.
/// # Errors
///
/// Returns an error without changing either count when reference growth or share validation fails.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn record_reused_file_control_block_open(
    table: &DriverVec<Box<FileControlBlock>>,
    fcb: NonNull<FileControlBlock>,
    file_object: KernelFileObject,
    desired_access: GrantedAccess,
    share_access: ShareAccess,
    share_check: FileControlBlockShareCheck,
) -> DriverResult<()> {
    let mut state = ledger_file_control_block_open_state(table, fcb);
    let state = unsafe {
        // SAFETY: The caller holds the ledger resource exclusively and the helper validated this
        // state pointer against the owning table.
        state.as_mut()
    };
    let references = state.next_file_object_reference()?;
    state.record_share_access(file_object, desired_access, share_access, share_check)?;
    state.lifetime = references;
    Ok(())
}

/// Records the first share claim on a newly inserted FCB.
/// # Errors
///
/// Returns an error when Windows rejects the requested share claim.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn record_file_control_block_share(
    table: &DriverVec<Box<FileControlBlock>>,
    fcb: NonNull<FileControlBlock>,
    file_object: KernelFileObject,
    desired_access: GrantedAccess,
    share_access: ShareAccess,
    share_check: FileControlBlockShareCheck,
) -> DriverResult<()> {
    let mut state = ledger_file_control_block_open_state(table, fcb);
    unsafe {
        // SAFETY: The caller holds the ledger resource exclusively and the helper validated this
        // state pointer against the owning table.
        state.as_mut()
    }
    .record_share_access(file_object, desired_access, share_access, share_check)
}

/// Consumes one handle lease and removes the FCB only after the stream becomes reclaimable.
#[expect(
    unsafe_code,
    reason = "the ledger resource uniquely owns stream-lifetime mutation and table removal"
)]
fn release_file_object_lease_in_table(
    table: &mut DriverVec<Box<FileControlBlock>>,
    fcb: NonNull<FileControlBlock>,
    native_resident: bool,
) -> Option<Box<FileControlBlock>> {
    let Some(index) = table
        .iter()
        .position(|candidate| NonNull::from(candidate.as_ref()) == fcb)
    else {
        KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
    };
    let mut state = ledger_file_control_block_open_state(table, fcb);
    let reclaimable = unsafe {
        // SAFETY: The caller holds the ledger resource and table ownership was validated above.
        state.as_mut()
    }
    .release_file_object_reference(native_resident);
    if !reclaimable {
        return None;
    }
    match table.swap_remove(index) {
        Some(removed) => Some(removed),
        None => KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck(),
    }
}

/// Finds a VCB-owned FCB by node identity.
fn find_file_control_block_in_table(
    table: &DriverVec<Box<FileControlBlock>>,
    node: NodeId,
) -> Option<NonNull<FileControlBlock>> {
    table
        .iter()
        .find(|fcb| fcb.node() == node)
        .map(|fcb| NonNull::from(fcb.as_ref()))
}

/// Returns one ledger-owned FCB's open-state address after validating table ownership.
fn ledger_file_control_block_open_state(
    table: &DriverVec<Box<FileControlBlock>>,
    fcb: NonNull<FileControlBlock>,
) -> NonNull<FileControlBlockOpenState> {
    let fcb = table
        .iter()
        .find(|candidate| NonNull::from(candidate.as_ref()) == fcb)
        .map(Box::as_ref)
        .unwrap_or_else(|| {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
        });
    NonNull::new(fcb.open_state.get()).unwrap_or_else(|| {
        KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
    })
}
