//! Shared stream registry, share-access accounting, and child-creation admission.

use super::*;

/// VCB-owned FCB table and share accounting protected by one concrete executive resource.
pub(super) struct FileControlBlockLedger {
    /// Mutable ledger state reachable only while `lock` is held.
    pub(super) table: UnsafeCell<DriverVec<Box<FileControlBlock>>>,
    /// Stable-address executive resource for every table/share/reference transition.
    lock: FileControlBlockLedgerLock,
}

/// Ledger-owned retention shared by the narrow stream authorities that may outlive its resource.
#[derive(Debug)]
struct DeferredStreamLease {
    /// Ledger that granted and must release this lease.
    owner: NonNull<FileControlBlockLedger>,
    /// Exact FCB retained by the ledger-owned deferred lease count.
    fcb: NonNull<FileControlBlock>,
}

/// Node-kind constraint established before a deferred stream lease can inspect native sections.
#[derive(Clone, Copy, Debug)]
enum DeferredStreamTarget {
    /// Paging I/O is valid only for a regular-file stream.
    RegularFile,
    /// Cache-map lifetime applies to any namespace-node FILE_OBJECT.
    Node,
}

/// One explicit FCB retention authority used while durable metadata is published outside the
/// ledger resource.
#[derive(Debug)]
struct StreamPublicationLease {
    /// Sole retention authority for the stream publication call.
    retained: DeferredStreamLease,
}

/// One regular-file stream retained independently from a user-handle CCB for paging I/O.
#[derive(Debug)]
pub(crate) struct PagingStreamLease {
    /// Sole retention authority for this paging operation.
    _retained: DeferredStreamLease,
    /// FILE_OBJECT whose FsContext and shared section identity granted this lease.
    file_object: KernelFileObject,
    /// Typed inode identity fixed while the ledger resource was held.
    file: FileNodeId,
}

/// One shared stream cache retained while a PASSIVE_LEVEL worker calls Cc/MM outside the actor.
#[derive(Debug)]
pub(crate) struct StreamCacheLease {
    /// Sole retention authority for shared cache flush/purge work.
    retained: DeferredStreamLease,
}

/// One FILE_OBJECT cache identity retained while a PASSIVE_LEVEL worker calls Cc/MM.
#[derive(Debug)]
pub(crate) struct FileObjectCacheLease {
    /// Attenuated shared-stream authority used by every cache operation.
    stream: StreamCacheLease,
    /// FILE_OBJECT whose private cache map participates in the operation.
    file_object: KernelFileObject,
}

/// Preallocated volume-lock cache drain whose leases cover every current namespace stream.
#[derive(Debug)]
pub(crate) struct PreparedStreamCacheDrain {
    /// Exact ledger whose streams were captured by this plan.
    owner: NonNull<FileControlBlockLedger>,
    /// Remaining shared streams; each lease is consumed by exactly one cache work item.
    remaining: DriverVec<StreamCacheLease>,
    /// Number of native drain calls that returned success to the actor.
    completed: usize,
    /// Immutable number of streams captured before the lock transition was published.
    total: usize,
}

impl PreparedStreamCacheDrain {
    /// Selects one shared stream for coherency flush/purge.
    pub(crate) fn next(&mut self) -> Option<VolumeLockStreamDrainLease> {
        self.remaining
            .pop()
            .map(|stream| VolumeLockStreamDrainLease { stream })
    }

    /// Consumes one successful native drain result.
    /// # Errors
    ///
    /// Returns an invariant error if the result belongs to another ledger or exceeds the captured
    /// stream count.
    pub(crate) fn record_completion(
        &mut self,
        completed: CompletedVolumeLockStreamDrain,
    ) -> DriverResult<()> {
        if completed.owner() != self.owner || self.completed >= self.total {
            return Err(DriverError::InternalInvariantViolation);
        }
        self.completed = self
            .completed
            .checked_add(1)
            .ok_or(DriverError::InternalInvariantViolation)?;
        drop(completed);
        Ok(())
    }

    /// Converts an exhausted plan into authority for the final ledger readiness check.
    /// # Errors
    ///
    /// Returns an invariant error unless every captured stream completed its native drain.
    pub(crate) fn into_completed(self) -> DriverResult<CompletedStreamCacheDrain> {
        if !self.remaining.is_empty() || self.completed != self.total {
            return Err(DriverError::InternalInvariantViolation);
        }
        Ok(CompletedStreamCacheDrain { owner: self.owner })
    }
}

/// One stream selected from a volume-lock drain plan but not yet accepted by Cc/MM.
#[derive(Debug)]
pub(crate) struct VolumeLockStreamDrainLease {
    /// Shared-stream retention spanning the native call.
    stream: StreamCacheLease,
}

impl VolumeLockStreamDrainLease {
    /// Executes the native cache and section drain, returning success authority to the actor.
    /// # Errors
    ///
    /// Returns the exact cache failure or mapped-section conflict status.
    pub(crate) fn execute(self) -> DriverResult<CompletedVolumeLockStreamDrain> {
        self.stream.drain_for_volume_lock()?;
        Ok(CompletedVolumeLockStreamDrain {
            stream: self.stream,
        })
    }
}

/// Successful native drain for one stream, still retained until the actor records it.
#[derive(Debug)]
pub(crate) struct CompletedVolumeLockStreamDrain {
    /// Lease proving which captured ledger accepted the drain.
    stream: StreamCacheLease,
}

impl CompletedVolumeLockStreamDrain {
    /// Returns the ledger identity carried by the retained stream.
    fn owner(&self) -> NonNull<FileControlBlockLedger> {
        self.stream.retained.owner
    }
}

/// Authority proving every stream captured for one volume lock completed its native drain.
#[derive(Debug)]
pub(crate) struct CompletedStreamCacheDrain {
    /// Exact ledger for which completion was established.
    owner: NonNull<FileControlBlockLedger>,
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
            self.retained.fcb.as_ref()
        };
        fcb.stream_context.set_sizes(sizes)
    }
}

#[expect(
    unsafe_code,
    reason = "the lease releases the exact ledger/Fcb identity retained at acquisition"
)]
impl Drop for DeferredStreamLease {
    fn drop(&mut self) {
        let owner = unsafe {
            // SAFETY: An FCB cannot outlive its VCB-owned ledger; this lease retains an FCB entry.
            self.owner.as_ref()
        };
        owner.release_deferred_stream_lease(self.fcb);
    }
}

impl PagingStreamLease {
    /// Returns the regular-file inode retained for this paging request.
    pub(crate) const fn file(&self) -> FileNodeId {
        self.file
    }

    /// Requires the live paging IRP to retain the same FILE_OBJECT that granted this lease.
    /// # Errors
    ///
    /// Returns an invariant error if operation ownership and the current IRP diverge.
    pub(crate) fn validate_file_object(
        &self,
        file_object: ActiveFileObject<'_>,
    ) -> DriverResult<()> {
        if file_object.address() == self.file_object {
            Ok(())
        } else {
            Err(DriverError::InternalInvariantViolation)
        }
    }
}

#[expect(
    unsafe_code,
    reason = "the deferred ledger lease retains the exact FCB pointer for every worker call"
)]
impl StreamCacheLease {
    /// Returns the retained stream after the ledger has released its lifetime resource.
    fn stream(&self) -> &FileControlBlock {
        unsafe {
            // SAFETY: `retained` keeps this exact table entry alive through the worker call.
            self.retained.fcb.as_ref()
        }
    }

    /// Flushes every dirty page in the shared stream cache.
    /// # Errors
    ///
    /// Returns the exact Cache Manager flush status.
    pub(crate) fn flush(&self) -> DriverResult<()> {
        self.stream().stream_context.flush_cache()
    }

    /// Flushes and purges the shared cache before direct or size-changing I/O.
    /// # Errors
    ///
    /// Returns the exact Cache Manager coherency status.
    pub(crate) fn purge(&self) -> DriverResult<()> {
        self.stream().stream_context.coherency_flush_and_purge()
    }

    /// Flushes cached data and releases every unreferenced data or image section before lock.
    /// # Errors
    ///
    /// Returns the exact cache failure or mapped-section conflict status.
    pub(crate) fn drain_for_volume_lock(&self) -> DriverResult<()> {
        self.stream().stream_context.drain_cache_for_volume_lock()
    }
}

impl FileObjectCacheLease {
    /// Attenuates this FILE_OBJECT authority to the shared stream cache only.
    pub(crate) fn into_stream(self) -> StreamCacheLease {
        self.stream
    }

    /// Reads cached bytes into the pre-captured system mapping.
    /// # Errors
    ///
    /// Returns the exact Cache Manager or representation failure.
    pub(crate) fn read(
        &self,
        offset: i64,
        length: usize,
        output: Option<NonNull<u8>>,
    ) -> DriverResult<usize> {
        self.stream.stream().stream_context.cached_read(
            self.file_object.as_non_null(),
            offset,
            length,
            output,
        )
    }

    /// Accepts a within-EOF write from the pre-captured system mapping.
    /// # Errors
    ///
    /// Returns the exact Cache Manager or representation failure.
    pub(crate) fn write(
        &self,
        offset: i64,
        input: Option<NonNull<u8>>,
        length: usize,
    ) -> DriverResult<()> {
        self.stream.stream().stream_context.cached_write(
            self.file_object.as_non_null(),
            offset,
            input,
            length,
        )
    }

    /// Releases this FILE_OBJECT's private cache map.
    /// # Errors
    ///
    /// Returns the exact Cache Manager exception status.
    pub(crate) fn uninitialize(&self) -> DriverResult<()> {
        self.stream
            .stream()
            .stream_context
            .uninitialize_cache_map(self.file_object.as_non_null())
    }
}

#[expect(
    unsafe_code,
    reason = "the ledger and top-level paging IRP retain every raw identity until operation drop"
)]
// SAFETY: The ledger-owned deferred count retains the FCB and VCB. The FILE_OBJECT is used only
// for identity comparison while the top-level paging IRP remains owned by the same operation.
unsafe impl Send for PagingStreamLease {}

#[expect(
    unsafe_code,
    reason = "the work envelope and deferred lease retain every raw cache identity until completion"
)]
// SAFETY: The worker owns this lease exclusively. Its operation-owned IRP retains FILE_OBJECT and
// buffer mappings, while the ledger count retains the FCB and VCB until the envelope is reclaimed.
unsafe impl Send for StreamCacheLease {}

#[expect(
    unsafe_code,
    reason = "the work envelope and IRP retain the exact FILE_OBJECT cache identity"
)]
// SAFETY: The containing operation-owned IRP retains FILE_OBJECT while the nested stream lease
// retains the FCB and VCB through worker completion.
unsafe impl Send for FileObjectCacheLease {}

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

    /// Preallocates and retains every stream whose cache must drain before volume lock.
    /// # Errors
    ///
    /// Returns access denied while any namespace handle remains active, or the exact allocation
    /// or finite deferred-lease failure before any Cache Manager work is submitted.
    #[expect(
        unsafe_code,
        reason = "two ledger passes separate allocation from validated lease acquisition"
    )]
    pub(super) fn prepare_volume_lock_cache_drain(&self) -> DriverResult<PreparedStreamCacheDrain> {
        let stream_count = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource serializes table and share-state observation.
                &*self.table.get()
            };
            for fcb in table.iter() {
                let state = unsafe {
                    // SAFETY: The table owns each FCB and the resource remains held.
                    &*fcb.open_state.get()
                };
                if state.has_active_handle() {
                    return Err(DriverError::AccessDenied);
                }
            }
            table.len()
        };

        let mut remaining = DriverVec::try_with_capacity(stream_count)?;
        let mut failed_lease = None;
        let acquisition = {
            let _guard = self.lock.acquire();
            let table = unsafe {
                // SAFETY: The executive resource serializes table and lifetime mutation.
                &*self.table.get()
            };
            if table.len() != stream_count {
                Err(DriverError::InternalInvariantViolation)
            } else {
                let mut result = Ok(());
                for fcb in table.iter() {
                    let state = unsafe {
                        // SAFETY: This table owns the FCB while the resource is held.
                        &mut *fcb.open_state.get()
                    };
                    if state.has_active_handle() {
                        result = Err(DriverError::AccessDenied);
                        break;
                    }
                    if let Err(error) = state.acquire_deferred_lease() {
                        result = Err(error);
                        break;
                    }
                    let lease = StreamCacheLease {
                        retained: DeferredStreamLease {
                            owner: NonNull::from(self),
                            fcb: NonNull::from(fcb.as_ref()),
                        },
                    };
                    if let Err(error) = remaining.push_reserved_owned(lease) {
                        let (error, lease) = error.into_parts();
                        failed_lease = Some(lease);
                        result = Err(error);
                        break;
                    }
                }
                result
            }
        };
        drop(failed_lease);
        acquisition?;
        Ok(PreparedStreamCacheDrain {
            owner: NonNull::from(self),
            remaining,
            completed: 0,
            total: stream_count,
        })
    }

    /// Requires every active handle, native section, and deferred cache/paging operation to have
    /// drained after all prepared purge work completes.
    /// # Errors
    ///
    /// Returns access denied while a competing handle or deferred operation remains, and the
    /// native mapped-file status while a cache map or section still retains a stream.
    #[expect(
        unsafe_code,
        reason = "the ledger resource serializes final volume-lock readiness observation"
    )]
    pub(super) fn finish_volume_lock_cache_drain(
        &self,
        completed: CompletedStreamCacheDrain,
    ) -> DriverResult<()> {
        if completed.owner != NonNull::from(self) {
            return Err(DriverError::InternalInvariantViolation);
        }
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table and lifetime observation.
            &*self.table.get()
        };
        for fcb in table.iter() {
            let state = unsafe {
                // SAFETY: The table owns each FCB and the resource remains held.
                &*fcb.open_state.get()
            };
            if state.has_active_handle() {
                return Err(DriverError::AccessDenied);
            }
            if state.native_residency_recheck_pending() {
                return Err(DriverError::CacheManagerFailure(
                    wdk_sys::STATUS_USER_MAPPED_FILE,
                ));
            }
            if !state.volume_lock_ready() {
                return Err(DriverError::AccessDenied);
            }
        }
        Ok(())
    }

    /// Advances every waiting native resident to one due delayed-close observation.
    ///
    /// This mutates only ledger-owned progress. The later Cc/MM observation is deliberately made
    /// after releasing the executive resource.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the ledger resource serializes table traversal and lifetime mutation"
    )]
    pub(super) fn mark_native_residency_rechecks_due(&self) -> bool {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table traversal and open-state mutation.
            &*self.table.get()
        };
        let mut changed = false;
        for fcb in table.iter() {
            let state = unsafe {
                // SAFETY: The table owns every FCB and the resource remains held for this pass.
                &mut *fcb.open_state.get()
            };
            changed |= state.mark_native_residency_recheck_due();
        }
        changed
    }

    /// Executes one bounded pass over due native residents outside the ledger resource.
    ///
    /// Each selected FCB first receives an explicit deferred lease. Dropping that lease performs
    /// the fresh Cc/MM observation and either reclaims the drained stream or returns it to the
    /// shared timer's waiting set.
    #[cfg(not(test))]
    pub(super) fn recheck_due_native_residency(&self) {
        while let Some(lease) = self.try_acquire_native_residency_recheck() {
            drop(lease);
        }
    }

    /// Returns whether the driver-owned delayed-close set is nonempty.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the ledger resource serializes table traversal and lifetime observation"
    )]
    pub(super) fn native_residency_recheck_pending(&self) -> bool {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table and lifetime observation.
            &*self.table.get()
        };
        table.iter().any(|fcb| {
            let state = unsafe {
                // SAFETY: The table owns this FCB and the resource remains held for observation.
                &*fcb.open_state.get()
            };
            state.native_residency_recheck_pending()
        })
    }

    /// Retains one due FCB before its native section pointers are inspected without the resource.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the ledger resource serializes table traversal and lease acquisition"
    )]
    fn try_acquire_native_residency_recheck(&self) -> Option<DeferredStreamLease> {
        let _guard = self.lock.acquire();
        let table = unsafe {
            // SAFETY: The executive resource serializes table traversal and lifetime mutation.
            &*self.table.get()
        };
        for candidate in table.iter() {
            let fcb = NonNull::from(candidate.as_ref());
            let state = unsafe {
                // SAFETY: The table owns this FCB and the resource remains held for mutation.
                &mut *candidate.open_state.get()
            };
            if state.try_acquire_native_residency_recheck() {
                return Some(DeferredStreamLease {
                    owner: NonNull::from(self),
                    fcb,
                });
            }
        }
        None
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
            retained: DeferredStreamLease {
                owner: NonNull::from(self),
                fcb,
            },
        }))
    }

    /// Acquires one regular-file paging lease from the shared stream identity on a FILE_OBJECT.
    ///
    /// FsContext2 is intentionally outside this protocol: CLEANUP may already have retired every
    /// user-handle authority while Cache Manager or Memory Manager still owns paging work.
    /// # Errors
    ///
    /// Returns an object, ownership, stream-kind, or deferred-lease failure without publishing a
    /// partial lease.
    pub(super) fn acquire_paging_stream_lease(
        &self,
        file_object: ActiveFileObject<'_>,
        volume: NonNull<VolumeControlBlock>,
    ) -> DriverResult<PagingStreamLease> {
        let (retained, node) = self.acquire_deferred_stream_lease(
            file_object,
            volume,
            DeferredStreamTarget::RegularFile,
        )?;
        let NodeId::File(file) = node else {
            return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
        };
        Ok(PagingStreamLease {
            _retained: retained,
            file_object: file_object.address(),
            file,
        })
    }

    /// Acquires one stream lease for a PASSIVE_LEVEL cache worker without retaining ledger locks.
    /// # Errors
    ///
    /// Returns an object, ownership, section-identity, or deferred-lease failure.
    pub(super) fn acquire_file_object_cache_lease(
        &self,
        file_object: ActiveFileObject<'_>,
        volume: NonNull<VolumeControlBlock>,
    ) -> DriverResult<FileObjectCacheLease> {
        let (retained, _node) =
            self.acquire_deferred_stream_lease(file_object, volume, DeferredStreamTarget::Node)?;
        Ok(FileObjectCacheLease {
            stream: StreamCacheLease { retained },
            file_object: file_object.address(),
        })
    }

    /// Validates one shared FILE_OBJECT stream identity and grants its deferred lifetime lease.
    /// # Errors
    ///
    /// Returns an object, ownership, section-identity, or finite lease-budget failure.
    #[expect(
        unsafe_code,
        reason = "the active FILE_OBJECT and ledger resource retain every decoded native identity"
    )]
    fn acquire_deferred_stream_lease(
        &self,
        file_object: ActiveFileObject<'_>,
        volume: NonNull<VolumeControlBlock>,
        target: DeferredStreamTarget,
    ) -> DriverResult<(DeferredStreamLease, NodeId)> {
        let _guard = self.lock.acquire();
        let object = file_object.as_ref();
        if object.Flags & wdk_sys::FO_VOLUME_OPEN != 0 {
            return Err(DriverError::ObjectTypeMismatch);
        }
        let header =
            NonNull::new(object.FsContext.cast::<c_void>()).ok_or(DriverError::InvalidParameter)?;
        let fcb = unsafe {
            // SAFETY: The active IRP retains its FILE_OBJECT and stream header while the owning
            // ledger resource prevents concurrent FCB table removal.
            StreamContext::decode_owner(header, StreamOwnerKind::Node)?
        }
        .cast::<FileControlBlock>();
        let table = unsafe {
            // SAFETY: The executive resource serializes table lookup and lifetime mutation.
            &*self.table.get()
        };
        if !table
            .iter()
            .any(|candidate| NonNull::from(candidate.as_ref()) == fcb)
        {
            return Err(DriverError::InvalidParameter);
        }
        let stream = unsafe {
            // SAFETY: Exact pointer membership was established while the ledger resource is held.
            fcb.as_ref()
        };
        if stream.owner() != NonNull::from(self) || stream.volume() != volume {
            return Err(DriverError::InvalidDeviceRequest);
        }
        let node = stream.node();
        if matches!(target, DeferredStreamTarget::RegularFile) && !matches!(node, NodeId::File(_)) {
            return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
        }
        let sections = unsafe {
            // SAFETY: The same active FILE_OBJECT and retained FCB own this embedded section store.
            StreamContext::decode_section_objects(header)?
        };
        if object.SectionObjectPointer != sections.as_ptr()
            || sections != stream.stream_section_objects()?
        {
            KernelWideInconsistency::file_object_context_corruption().bugcheck();
        }
        let mut state = ledger_file_control_block_open_state(table, fcb);
        unsafe {
            // SAFETY: The resource remains held and exact table membership was validated above.
            state.as_mut()
        }
        .acquire_deferred_lease()?;
        Ok((
            DeferredStreamLease {
                owner: NonNull::from(self),
                fcb,
            },
            node,
        ))
    }

    /// Releases one deferred stream lease and destroys the FCB only after native residency drains.
    #[expect(
        unsafe_code,
        reason = "the live lease retains its FCB while the ledger serializes terminal release"
    )]
    fn release_deferred_stream_lease(&self, fcb: NonNull<FileControlBlock>) {
        let native_resident = unsafe {
            // SAFETY: The outstanding deferred stream lease retains this FCB for the observation.
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
