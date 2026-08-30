//! Native stream state, cache publication, byte-range locks, and deletion state.

use super::*;

/// Ledger-owned file control block for one mounted inode stream.
pub(crate) struct FileControlBlock {
    /// Mounted volume that owns this file.
    volume: NonNull<VolumeControlBlock>,
    /// Ledger that owns this FCB allocation and every open-state transition.
    owner: NonNull<FileControlBlockLedger>,
    /// Ext4 node opened by this FCB.
    pub(super) node: NodeId,
    /// Windows advanced-header stream identity shared by every FILE_OBJECT for this inode.
    ///
    /// This field precedes the lock package so native callbacks are withdrawn before their bound
    /// FILE_LOCK storage is uninitialized during terminal FCB destruction.
    pub(super) stream_context: StreamContext,
    /// FsRtl-owned byte-range lock state for this opened inode identity.
    byte_range_locks: FileByteRangeLocks,
    /// Ledger-owned mutable state; accessed only under `owner`'s exclusive resource.
    pub(super) open_state: UnsafeCell<FileControlBlockOpenState>,
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: `volume`, `owner`, and `node` are immutable after construction. FsRtl synchronizes its
// opaque byte-range lock package, while `open_state` is accessed only under the owner ledger's
// exclusive executive resource.
unsafe impl Sync for FileControlBlock {}

impl fmt::Debug for FileControlBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileControlBlock")
            .field("volume", &self.volume)
            .field("owner", &self.owner)
            .field("node", &self.node)
            .field("byte_range_locks", &self.byte_range_locks)
            .field("open_state", &"FileControlBlockOpenState(..)")
            .finish()
    }
}

impl FileControlBlock {
    /// Creates an FCB boundary value for a mounted node with one open reference.
    /// # Errors
    ///
    /// Returns an error if the native header or its synchronization resources cannot be allocated.
    pub(super) fn try_new_staged(
        volume: NonNull<VolumeControlBlock>,
        owner: NonNull<FileControlBlockLedger>,
        stream: StagedNodeStreamMetadata,
        trace: OperationalTrace,
    ) -> DriverResult<Self> {
        let node = stream.node();
        let sizes = stream.sizes();
        Ok(Self {
            volume,
            owner,
            node,
            stream_context: StreamContext::try_new_staged_node(sizes, trace)?,
            byte_range_locks: FileByteRangeLocks::new(),
            open_state: UnsafeCell::new(FileControlBlockOpenState::new()),
        })
    }

    /// Creates an FCB with one epoch-tagged committed metadata projection.
    /// # Errors
    ///
    /// Returns an error if the native header or its synchronization resources cannot be allocated.
    pub(super) fn try_new_committed(
        volume: NonNull<VolumeControlBlock>,
        owner: NonNull<FileControlBlockLedger>,
        stream: CommittedNodeStreamMetadata,
        trace: OperationalTrace,
    ) -> DriverResult<Self> {
        Ok(Self {
            volume,
            owner,
            node: stream.node(),
            stream_context: StreamContext::try_new_committed_node(
                stream.sizes(),
                stream.snapshot(),
                stream.epoch(),
                trace,
            )?,
            byte_range_locks: FileByteRangeLocks::new(),
            open_state: UnsafeCell::new(FileControlBlockOpenState::new()),
        })
    }

    /// Binds the native header after the ledger candidate reaches its final heap address.
    /// # Errors
    ///
    /// Returns an invariant error on repeated binding or malformed native ownership.
    pub(super) fn bind_stream_owner(&self) -> DriverResult<()> {
        self.stream_context
            .bind_owner(NonNull::from(self).cast::<c_void>())?;
        self.stream_context
            .bind_byte_range_locks(self.byte_range_locks.native_pointer())
    }

    /// Returns the advanced-header pointer installed in every FILE_OBJECT for this inode.
    pub(crate) fn stream_header(&self) -> NonNull<c_void> {
        self.stream_context.header()
    }

    /// Returns the inode stream's shared cache and mapped-section authority.
    /// # Errors
    ///
    /// Returns an invariant error if the inode's native header is malformed.
    pub(crate) fn stream_section_objects(
        &self,
    ) -> DriverResult<NonNull<wdk_sys::SECTION_OBJECT_POINTERS>> {
        self.stream_context.section_objects()
    }

    /// Reads the sole Windows-visible size authority from the advanced header.
    /// # Errors
    ///
    /// Returns an invariant error if the native header cannot provide a coherent snapshot.
    pub(crate) fn stream_sizes(&self) -> DriverResult<StreamSizes> {
        self.stream_context.sizes()
    }

    /// Reports whether a cache map or mapped section still retains this stream.
    /// # Errors
    ///
    /// Returns an invariant error if native stream metadata is malformed.
    pub(super) fn has_native_stream_residency(&self) -> DriverResult<bool> {
        self.stream_context.has_native_residency()
    }

    /// Returns the mounted VCB pointer that owns this open node.
    pub(crate) const fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.volume
    }

    /// Returns the ledger that owns this FCB without borrowing the enclosing VCB.
    pub(super) const fn owner(&self) -> NonNull<FileControlBlockLedger> {
        self.owner
    }

    /// Returns the ext4 node identity opened by this FCB.
    pub(crate) const fn node(&self) -> NodeId {
        self.node
    }

    /// Transfers one validated lock-control IRP to the FsRtl lock package.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the consuming dispatch target transfers its one live IRP to FsRtl"
        )
    )]
    pub(crate) fn process_byte_range_lock(&self, target: DispatchTarget) -> wdk_sys::NTSTATUS {
        #[cfg(not(test))]
        {
            let raw_irp = target.into_raw_irp();
            let Some(irp) = NonNull::new(raw_irp) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
            };
            unsafe {
                // SAFETY: `target` was consumed and no driver completion owner remains.
                self.stream_context.process_file_lock(irp)
            }
        }
        #[cfg(test)]
        {
            let _target = target;
            wdk_sys::STATUS_SUCCESS
        }
    }

    /// Transfers one validated oplock FSCTL to the stream-owned FsRtl oplock package.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the consuming dispatch target transfers its one live IRP to FsRtl"
        )
    )]
    pub(crate) fn process_oplock_fsctrl(&self, target: DispatchTarget) -> wdk_sys::NTSTATUS {
        #[cfg(not(test))]
        {
            let open_count = unsafe {
                // SAFETY: This FILE_OBJECT retains the FCB and therefore its ledger owner.
                self.owner.as_ref()
            }
            .stream_open_count(NonNull::from(self));
            let raw_irp = target.into_raw_irp();
            let Some(irp) = NonNull::new(raw_irp) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
            };
            unsafe {
                // SAFETY: `target` was consumed and no driver completion owner remains.
                self.stream_context
                    .process_oplock_fsctrl(irp, open_count, 0)
            }
        }
        #[cfg(test)]
        {
            let _target = target;
            wdk_sys::STATUS_SUCCESS
        }
    }

    /// Returns whether the requestor may read one fully resolved file byte range.
    /// # Errors
    ///
    /// Returns an error when the resolved range cannot be represented by FsRtl.
    pub(crate) fn permits_byte_range_read(
        &self,
        requestor: RequestorProcess,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        self.byte_range_locks
            .permits_read(requestor, file_object, start, length, key)
    }

    /// Returns whether the requestor may write one fully resolved file byte range.
    /// # Errors
    ///
    /// Returns an error when the resolved range cannot be represented by FsRtl.
    pub(crate) fn permits_byte_range_write(
        &self,
        requestor: RequestorProcess,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        self.byte_range_locks
            .permits_write(requestor, file_object, start, length, key)
    }

    /// Releases all byte-range locks held by this FILE_OBJECT's requestor during cleanup.
    pub(crate) fn release_handle_byte_range_locks(
        &self,
        requestor: RequestorProcess,
        file_object: KernelFileObject,
    ) {
        if self
            .stream_context
            .unlock_all(file_object.as_non_null(), requestor.as_non_null())
            .is_err()
        {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        }
    }
}

/// Complete identity-bound Windows stream projection derived from one coherent core snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NodeStreamMetadata {
    /// Inode metadata that owns every projected Windows field.
    snapshot: NodeMetadataSnapshot,
    /// Native section and allocation sizes derived from `snapshot`.
    sizes: StreamSizes,
}

impl NodeStreamMetadata {
    /// Converts one coherent core observation without granting publication authority.
    /// # Errors
    ///
    /// Returns an error when the observed sizes exceed Windows' signed size domain.
    pub(crate) fn try_from_snapshot(
        snapshot: NodeMetadataSnapshot,
        cluster_size: ClusterSize,
    ) -> DriverResult<Self> {
        Ok(Self {
            snapshot,
            sizes: StreamSizes::try_from_ext4(
                snapshot.size(),
                snapshot.allocation_size(),
                cluster_size,
            )?,
        })
    }

    /// Identity bound to this coherent projection.
    pub(crate) const fn node(self) -> NodeId {
        self.snapshot.node()
    }

    /// Complete coherent core metadata represented by this projection.
    pub(crate) const fn snapshot(self) -> NodeMetadataSnapshot {
        self.snapshot
    }

    /// Complete native size tuple for this stream state.
    pub(crate) const fn sizes(self) -> StreamSizes {
        self.sizes
    }
}

/// One complete node metadata observation bound to its exact committed epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommittedNodeStreamMetadata {
    /// Complete coherent inode and Windows projection.
    metadata: NodeStreamMetadata,
    /// Committed epoch from which `metadata` was observed.
    epoch: ext4_core::EpochSequence,
}

impl CommittedNodeStreamMetadata {
    /// Binds one complete observation to the immutable epoch that supplied it.
    pub(crate) const fn new(metadata: NodeStreamMetadata, epoch: ext4_core::EpochSequence) -> Self {
        Self { metadata, epoch }
    }

    /// Identity bound to this committed observation.
    pub(crate) const fn node(self) -> NodeId {
        self.metadata.node()
    }

    /// Complete coherent core metadata represented by this observation.
    pub(crate) const fn snapshot(self) -> NodeMetadataSnapshot {
        self.metadata.snapshot()
    }

    /// Complete native size tuple for this observation.
    pub(crate) const fn sizes(self) -> StreamSizes {
        self.metadata.sizes()
    }

    /// Immutable committed epoch that owns this observation.
    pub(crate) const fn epoch(self) -> ext4_core::EpochSequence {
        self.epoch
    }
}

/// Transaction-local stream identity whose query metadata remains hidden until commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StagedNodeStreamMetadata {
    /// Inode identity allocated by the transaction.
    pub(super) node: NodeId,
    /// Native sizes used for cache and mapped-section admission before commit.
    pub(super) sizes: StreamSizes,
}

impl StagedNodeStreamMetadata {
    /// Converts transaction-local metadata while keeping it unqueryable until commit.
    /// # Errors
    ///
    /// Returns an error when the observed sizes exceed Windows' signed size domain.
    pub(crate) fn try_from_staged_snapshot(
        snapshot: NodeMetadataSnapshot,
        cluster_size: ClusterSize,
    ) -> DriverResult<Self> {
        Ok(Self {
            node: snapshot.node(),
            sizes: StreamSizes::try_from_ext4(
                snapshot.size(),
                snapshot.allocation_size(),
                cluster_size,
            )?,
        })
    }

    /// Identity bound to this coherent projection.
    pub(crate) const fn node(self) -> NodeId {
        self.node
    }

    /// Complete native size tuple for this stream state.
    pub(crate) const fn sizes(self) -> StreamSizes {
        self.sizes
    }
}

/// Prevalidated metadata retained with the exact mutation's commit continuation.
///
/// Preparation does not snapshot FCB addresses: publication resolves inode identities under the
/// ledger guard after epoch visibility. Future opens initialize from that current epoch.
#[derive(Debug)]
pub(crate) struct PreparedStreamMetadataPublications {
    /// One final metadata projection per live inode changed by the reserved mutation.
    pub(super) nodes: DriverVec<NodeStreamMetadata>,
}

impl PreparedStreamMetadataPublications {
    /// Prepares all conversions and storage before the first lower write.
    /// # Errors
    ///
    /// Returns an error on allocation failure or a size outside the Windows domain.
    pub(crate) fn try_new(
        snapshots: &[NodeMetadataSnapshot],
        cluster_size: ClusterSize,
    ) -> DriverResult<Self> {
        let mut nodes = DriverVec::try_with_capacity(snapshots.len())?;
        for snapshot in snapshots {
            nodes.try_push(NodeStreamMetadata::try_from_snapshot(
                *snapshot,
                cluster_size,
            )?)?;
        }
        Ok(Self { nodes })
    }
}

/// Result of durable ext4 visibility publication plus the independently fallible Windows stream
/// projection.
pub(crate) struct DurablePublicationOutcome {
    /// Checkpoint work remains mandatory because the ext4 commit is already visible.
    pub(super) checkpoint: PendingCheckpoint,
    /// Exact Cc/MM projection result; failure cannot roll back the durable mutation.
    pub(super) stream_projection: DriverResult<()>,
}

impl DurablePublicationOutcome {
    /// Separates mandatory checkpoint ownership from the post-commit projection result.
    pub(crate) fn into_parts(self) -> (PendingCheckpoint, DriverResult<()>) {
        (self.checkpoint, self.stream_projection)
    }
}

/// Mutable FCB lifecycle state owned exclusively by `FileControlBlockLedger`.
pub(super) struct FileControlBlockOpenState {
    /// I/O manager share-access accounting for this inode identity.
    pub(super) share_access: SHARE_ACCESS,
    /// Explicit stream lifetime across handle and cache/mapping residency domains.
    pub(super) lifetime: StreamLifetimeState,
    /// One namespace deletion truth shared by every handle for this inode.
    pub(super) deletion: FileDeletionState,
}

impl FileControlBlockOpenState {
    /// Creates empty share accounting for the first FILE_OBJECT reference.
    pub(super) const fn new() -> Self {
        Self {
            share_access: SHARE_ACCESS {
                OpenCount: 0,
                Readers: 0,
                Writers: 0,
                Deleters: 0,
                SharedRead: 0,
                SharedWrite: 0,
                SharedDelete: 0,
            },
            lifetime: StreamLifetimeState::OpenHandles {
                handles: NonZeroU32::MIN,
                deferred_leases: 0,
            },
            deletion: FileDeletionState::Live,
        }
    }

    /// Checks any operation-implied access and records the FILE_OBJECT share claim.
    /// # Errors
    ///
    /// Returns an error when existing handles do not share the effective operation access or when
    /// the requested handle claim cannot be recorded.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn record_share_access(
        &mut self,
        file_object: KernelFileObject,
        desired_access: GrantedAccess,
        share_access: ShareAccess,
        share_check: FileControlBlockShareCheck,
    ) -> DriverResult<()> {
        self.deletion.ensure_openable()?;
        if let FileControlBlockShareCheck::ExistingNode {
            operation_access: existing_operation_access,
            oplock_policy,
        } = share_check
        {
            if matches!(oplock_policy, OplockCreatePolicy::ReserveFilter)
                && self.share_access.OpenCount != 0
            {
                return Err(DriverError::OplockNotGranted);
            }
            let operation_status = unsafe {
                // SAFETY: The ledger exclusively owns this SHARE_ACCESS record. Update is false,
                // so operation-implied access is checked without recording it as returned-handle
                // authority.
                ffi::IoCheckShareAccess(
                    existing_operation_access.as_raw(),
                    share_access.as_ulong(),
                    file_object.as_ptr(),
                    core::ptr::addr_of_mut!(self.share_access),
                    0,
                )
            };
            if operation_status < STATUS_SUCCESS {
                return Err(DriverError::ShareAccessConflict);
            }
        }
        let status = unsafe {
            // SAFETY: The ledger exclusively owns this SHARE_ACCESS record. This call records only
            // the access explicitly requested for the returned FILE_OBJECT.
            ffi::IoCheckShareAccess(
                desired_access.as_raw(),
                share_access.as_ulong(),
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.share_access),
                1,
            )
        };
        if status < STATUS_SUCCESS {
            return Err(DriverError::ShareAccessConflict);
        }
        Ok(())
    }

    /// Removes one FILE_OBJECT's recorded share-access claim.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn remove_share_access(&mut self, file_object: KernelFileObject) {
        unsafe {
            // SAFETY: Successful create recorded this FILE_OBJECT against this ledger-owned
            // SHARE_ACCESS, and the lifecycle transition selects one unique removal point.
            ffi::IoRemoveShareAccess(
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.share_access),
            );
        }
    }

    /// Selects deferred deletion after one share claim has been removed.
    pub(super) fn cleanup_disposition(&self) -> FileCleanupDisposition {
        self.deletion
            .cleanup_target(self.share_access.OpenCount)
            .map_or(
                FileCleanupDisposition::Retained,
                FileCleanupDisposition::Delete,
            )
    }

    /// Requires ordinary replacement to respect deletion state and open-inode lifetime.
    /// # Errors
    ///
    /// Returns delete-pending or sharing-violation when the current open state rejects replacement.
    pub(super) fn ensure_namespace_replaceable(&self) -> DriverResult<()> {
        self.deletion.ensure_openable()?;
        if self.share_access.OpenCount == 0 {
            Ok(())
        } else {
            Err(DriverError::ShareAccessConflict)
        }
    }

    /// Returns whether one active handle still owns share-access authority for this stream.
    pub(super) const fn has_active_handle(&self) -> bool {
        self.share_access.OpenCount != 0
    }

    /// Returns whether lock-time cache draining has removed every non-handle resident.
    pub(super) const fn volume_lock_ready(&self) -> bool {
        matches!(
            self.lifetime,
            StreamLifetimeState::OpenHandles {
                deferred_leases: 0,
                ..
            }
        )
    }

    /// Publishes a shared delete-pending target and returns displaced storage.
    ///
    /// A create-time delete-on-close target is mandatory and therefore cannot be replaced by a
    /// later, cancellable disposition request from another already-open handle.
    pub(super) fn set_delete_pending(
        &mut self,
        pending: PendingFileDeletion,
    ) -> Option<PendingFileDeletion> {
        if matches!(
            &self.deletion,
            FileDeletionState::Pending(existing)
                if existing.cause() == FileDeletionCause::DeleteOnClose
        ) {
            return Some(pending);
        }
        match core::mem::replace(&mut self.deletion, FileDeletionState::Pending(pending)) {
            FileDeletionState::Live => None,
            FileDeletionState::Pending(previous) => Some(previous),
            FileDeletionState::Deleted => {
                KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
            }
        }
    }

    /// Cancels a disposition-originated delete-pending before final active cleanup.
    ///
    /// Create-time delete-on-close is mandatory and is intentionally unaffected.
    pub(super) fn clear_delete_pending(&mut self) -> Option<PendingFileDeletion> {
        if matches!(
            &self.deletion,
            FileDeletionState::Pending(existing)
                if existing.cause() == FileDeletionCause::DeleteOnClose
        ) {
            return None;
        }
        match core::mem::replace(&mut self.deletion, FileDeletionState::Live) {
            FileDeletionState::Live => None,
            FileDeletionState::Pending(previous) => Some(previous),
            FileDeletionState::Deleted => {
                KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
            }
        }
    }

    /// Returns whether the inode has crossed into delete-pending.
    pub(super) const fn delete_pending(&self) -> bool {
        self.deletion.is_pending()
    }

    /// Publishes successful removal of the exact target selected by cleanup.
    pub(super) fn complete_delete(
        &mut self,
        target: NonNull<FileDeleteTarget>,
    ) -> PendingFileDeletion {
        match core::mem::replace(&mut self.deletion, FileDeletionState::Deleted) {
            FileDeletionState::Pending(pending) if pending.target() == target => pending,
            FileDeletionState::Live
            | FileDeletionState::Pending(_)
            | FileDeletionState::Deleted => {
                KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
            }
        }
    }

    /// Aborts the exact final-cleanup deletion before any lower write can have taken effect.
    ///
    /// This is distinct from a disposition cancellation: it is legal for create-time
    /// delete-on-close as well, but only after the last active handle has entered cleanup and the
    /// deletion attempt itself failed before an uncertain external effect.
    pub(super) fn abort_cleanup_delete(
        &mut self,
        target: NonNull<FileDeleteTarget>,
    ) -> Option<PendingFileDeletion> {
        if self.share_access.OpenCount != 0 {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck();
        }
        match core::mem::replace(&mut self.deletion, FileDeletionState::Live) {
            FileDeletionState::Pending(pending) if pending.target() == target => Some(pending),
            FileDeletionState::Deleted => {
                self.deletion = FileDeletionState::Deleted;
                None
            }
            FileDeletionState::Live | FileDeletionState::Pending(_) => {
                KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
            }
        }
    }

    /// Computes one additional FILE_OBJECT reference without mutating state.
    /// # Errors
    ///
    /// Returns an error when the FCB open-reference counter cannot be incremented.
    pub(super) fn next_file_object_reference(&self) -> DriverResult<StreamLifetimeState> {
        self.lifetime.with_additional_handle()
    }

    /// Consumes one FILE_OBJECT lease while preserving a native or deferred stream resident.
    pub(super) fn release_file_object_reference(&mut self, native_resident: bool) -> bool {
        self.lifetime = self.lifetime.without_handle(native_resident);
        matches!(self.lifetime, StreamLifetimeState::Reclaimable)
    }

    /// Acquires one explicit lease for work that must outlive the ledger guard.
    /// # Errors
    ///
    /// Returns insufficient resources when the finite lease count is exhausted.
    pub(super) fn acquire_deferred_lease(&mut self) -> DriverResult<()> {
        self.lifetime = self.lifetime.with_additional_deferred_lease()?;
        Ok(())
    }

    /// Releases one explicit lease using a fresh observation of native cache/section residency.
    pub(super) fn release_deferred_lease(&mut self, native_resident: bool) -> bool {
        self.lifetime = self.lifetime.without_deferred_lease(native_resident);
        matches!(self.lifetime, StreamLifetimeState::Reclaimable)
    }

    /// Makes a previously observed native resident eligible for one actor-owned recheck pass.
    #[cfg(not(test))]
    pub(super) fn mark_native_residency_recheck_due(&mut self) -> bool {
        let (lifetime, changed) = self.lifetime.with_due_native_residency_recheck();
        self.lifetime = lifetime;
        changed
    }

    /// Acquires one explicit lease for a due native-residency observation.
    ///
    /// Counter exhaustion leaves the due obligation intact so a later actor pass can retry after
    /// another deferred operation releases its lease.
    #[cfg(not(test))]
    pub(super) fn try_acquire_native_residency_recheck(&mut self) -> bool {
        let (lifetime, acquired) = self.lifetime.with_native_residency_recheck_lease();
        self.lifetime = lifetime;
        acquired
    }

    /// Returns whether the stream requires delayed native-residency maintenance.
    pub(super) const fn native_residency_recheck_pending(&self) -> bool {
        self.lifetime.native_residency_recheck_pending()
    }
}

/// Actor-owned progress of one native cache/section residency observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeResidencyRecheck {
    /// The last observation found a native resident; wait before polling Cc/MM again.
    Waiting,
    /// The shared delayed-close timer fired and one fresh observation is due.
    Due,
}

/// Lifetime of one inode stream independent of any particular handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StreamLifetimeState {
    /// At least one FILE_OBJECT owns the stream; native residents may coexist.
    OpenHandles {
        /// Exact number of FILE_OBJECT close obligations.
        handles: NonZeroU32,
        /// Oplock continuations, paging operations, or workers retaining the stream.
        deferred_leases: u32,
    },
    /// No FILE_OBJECT or native section remains, but explicit work retains the stream.
    DeferredOnly {
        /// Nonzero worker/oplock/paging lease count.
        deferred_leases: NonZeroU32,
    },
    /// No FILE_OBJECT remains, but a native cache map or section still retains the stream.
    NativeResident {
        /// Explicit worker/oplock/paging leases that coexist with native residency.
        deferred_leases: u32,
        /// Delayed-close polling progress owned by the volume reactor actor.
        recheck: NativeResidencyRecheck,
    },
    /// No handle or resident lease remains and the ledger may destroy the stream.
    Reclaimable,
}

impl StreamLifetimeState {
    /// Computes the state after admitting one additional FILE_OBJECT.
    /// # Errors
    ///
    /// Returns too-many-open-references without consuming the existing state on counter overflow.
    pub(super) fn with_additional_handle(self) -> DriverResult<Self> {
        match self {
            Self::OpenHandles {
                handles,
                deferred_leases,
            } => Ok(Self::OpenHandles {
                handles: handles
                    .get()
                    .checked_add(1)
                    .and_then(NonZeroU32::new)
                    .ok_or(DriverError::TooManyOpenReferences)?,
                deferred_leases,
            }),
            Self::DeferredOnly { deferred_leases } => Ok(Self::OpenHandles {
                handles: NonZeroU32::MIN,
                deferred_leases: deferred_leases.get(),
            }),
            Self::NativeResident {
                deferred_leases, ..
            } => Ok(Self::OpenHandles {
                handles: NonZeroU32::MIN,
                deferred_leases,
            }),
            Self::Reclaimable => {
                KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
            }
        }
    }

    /// Computes the state after one FILE_OBJECT close from a fresh native residency observation.
    pub(super) fn without_handle(self, native_resident: bool) -> Self {
        match self {
            Self::OpenHandles {
                handles,
                deferred_leases,
            } if handles.get() > 1 => Self::OpenHandles {
                handles: NonZeroU32::new(handles.get() - 1).unwrap_or_else(|| {
                    KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
                }),
                deferred_leases,
            },
            Self::OpenHandles {
                handles,
                deferred_leases,
            } if handles == NonZeroU32::MIN => {
                if native_resident {
                    Self::NativeResident {
                        deferred_leases,
                        recheck: NativeResidencyRecheck::Waiting,
                    }
                } else if let Some(deferred_leases) = NonZeroU32::new(deferred_leases) {
                    Self::DeferredOnly { deferred_leases }
                } else {
                    Self::Reclaimable
                }
            }
            Self::OpenHandles { .. }
            | Self::DeferredOnly { .. }
            | Self::NativeResident { .. }
            | Self::Reclaimable => {
                KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
            }
        }
    }

    /// Adds one non-handle lease without changing handle or native residency authority.
    /// # Errors
    ///
    /// Returns insufficient resources when the finite lease count is exhausted.
    pub(super) fn with_additional_deferred_lease(self) -> DriverResult<Self> {
        match self {
            Self::OpenHandles {
                handles,
                deferred_leases,
            } => Ok(Self::OpenHandles {
                handles,
                deferred_leases: deferred_leases
                    .checked_add(1)
                    .ok_or(DriverError::InsufficientResources)?,
            }),
            Self::DeferredOnly { deferred_leases } => Ok(Self::DeferredOnly {
                deferred_leases: deferred_leases
                    .get()
                    .checked_add(1)
                    .and_then(NonZeroU32::new)
                    .ok_or(DriverError::InsufficientResources)?,
            }),
            Self::NativeResident {
                deferred_leases,
                recheck,
            } => Ok(Self::NativeResident {
                deferred_leases: deferred_leases
                    .checked_add(1)
                    .ok_or(DriverError::InsufficientResources)?,
                recheck,
            }),
            Self::Reclaimable => {
                KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
            }
        }
    }

    /// Removes one non-handle lease and selects reclamation only after native residency drains.
    pub(super) fn without_deferred_lease(self, native_resident: bool) -> Self {
        match self {
            Self::OpenHandles {
                handles,
                deferred_leases,
            } if deferred_leases != 0 => Self::OpenHandles {
                handles,
                deferred_leases: deferred_leases.checked_sub(1).unwrap_or_else(|| {
                    KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
                }),
            },
            Self::DeferredOnly { deferred_leases } => {
                let remaining = deferred_leases.get() - 1;
                if native_resident {
                    Self::NativeResident {
                        deferred_leases: remaining,
                        recheck: NativeResidencyRecheck::Waiting,
                    }
                } else if let Some(deferred_leases) = NonZeroU32::new(remaining) {
                    Self::DeferredOnly { deferred_leases }
                } else {
                    Self::Reclaimable
                }
            }
            Self::NativeResident {
                deferred_leases,
                recheck: _,
            } if deferred_leases != 0 => {
                let remaining = deferred_leases.checked_sub(1).unwrap_or_else(|| {
                    KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
                });
                if native_resident {
                    Self::NativeResident {
                        deferred_leases: remaining,
                        recheck: NativeResidencyRecheck::Waiting,
                    }
                } else if let Some(deferred_leases) = NonZeroU32::new(remaining) {
                    Self::DeferredOnly { deferred_leases }
                } else {
                    Self::Reclaimable
                }
            }
            Self::OpenHandles { .. } | Self::NativeResident { .. } | Self::Reclaimable => {
                KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
            }
        }
    }

    /// Makes one waiting native resident eligible for a new Cc/MM observation.
    pub(super) const fn with_due_native_residency_recheck(self) -> (Self, bool) {
        match self {
            Self::NativeResident {
                deferred_leases,
                recheck: NativeResidencyRecheck::Waiting,
            } => (
                Self::NativeResident {
                    deferred_leases,
                    recheck: NativeResidencyRecheck::Due,
                },
                true,
            ),
            Self::OpenHandles { .. }
            | Self::DeferredOnly { .. }
            | Self::NativeResident { .. }
            | Self::Reclaimable => (self, false),
        }
    }

    /// Adds the lease that pins one FCB while its due Cc/MM observation runs outside the ledger.
    pub(super) const fn with_native_residency_recheck_lease(self) -> (Self, bool) {
        match self {
            Self::NativeResident {
                deferred_leases,
                recheck: NativeResidencyRecheck::Due,
            } => match deferred_leases.checked_add(1) {
                Some(deferred_leases) => (
                    Self::NativeResident {
                        deferred_leases,
                        recheck: NativeResidencyRecheck::Waiting,
                    },
                    true,
                ),
                None => (self, false),
            },
            Self::OpenHandles { .. }
            | Self::DeferredOnly { .. }
            | Self::NativeResident { .. }
            | Self::Reclaimable => (self, false),
        }
    }

    /// Returns whether native cache/section residency still owns delayed-close maintenance.
    pub(super) const fn native_residency_recheck_pending(self) -> bool {
        matches!(self, Self::NativeResident { .. })
    }
}

/// Opaque FsRtl byte-range lock state owned by one FCB.
///
/// FsRtl synchronizes concurrent access to this state internally. `UnsafeCell` only permits the
/// native routines to mutate their opaque storage through the FCB's shared reference; it does not
/// expose Rust-side mutable access.
struct FileByteRangeLocks {
    /// Native lock package storage, initialized exactly once for this FCB.
    #[cfg(not(test))]
    native: UnsafeCell<wdk_sys::FILE_LOCK>,
}

/// Signed native range passed to FsRtl after file-position resolution.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "native FsRtl byte-range checks are compiled out in unit tests"
    )
)]
pub(super) struct NativeFileByteRange {
    /// Non-negative starting byte.
    start: LARGE_INTEGER,
    /// Non-negative range length.
    length: LARGE_INTEGER,
}

impl NativeFileByteRange {
    /// Converts a core file range to the signed Windows lock domain.
    /// # Errors
    ///
    /// Returns an error when either endpoint exceeds the signed Windows file-offset range.
    pub(super) fn new(start: FileOffset, length: usize) -> DriverResult<Self> {
        let end = start.checked_add_len(length)?;
        let _end = i64::try_from(end.bytes()).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self {
            start: LARGE_INTEGER {
                QuadPart: i64::try_from(start.bytes())
                    .map_err(|_| DriverError::InvalidParameter)?,
            },
            length: LARGE_INTEGER {
                QuadPart: i64::try_from(length).map_err(|_| DriverError::InvalidParameter)?,
            },
        })
    }
}

impl FileByteRangeLocks {
    /// Initializes FsRtl state for a newly allocated FCB.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn new() -> Self {
        #[cfg(not(test))]
        {
            let locks = Self {
                native: UnsafeCell::new(wdk_sys::FILE_LOCK::default()),
            };
            unsafe {
                // SAFETY: `native` points to uninitialized FILE_LOCK storage
                // owned exclusively by this newly created FCB.
                ffi::FsRtlInitializeFileLock(locks.native.get(), None, None);
            }
            locks
        }
        #[cfg(test)]
        {
            Self {}
        }
    }

    /// Returns the stable FCB-owned FILE_LOCK address bound into the native stream header.
    fn native_pointer(&self) -> NonNull<wdk_sys::FILE_LOCK> {
        #[cfg(not(test))]
        {
            // `UnsafeCell::get` is non-null and the enclosing FCB is already in stable storage.
            NonNull::new(self.native.get()).unwrap_or_else(|| {
                KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
            })
        }
        #[cfg(test)]
        {
            NonNull::dangling()
        }
    }

    /// Checks one resolved read range against this FCB's byte-range locks.
    /// # Errors
    ///
    /// Returns an error when the resolved range cannot be represented by FsRtl.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn permits_read(
        &self,
        requestor: RequestorProcess,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        let range = NativeFileByteRange::new(start, length)?;
        #[cfg(not(test))]
        {
            let mut range = range;
            Ok(unsafe {
                // SAFETY: FsRtl receives initialized lock state, checked signed
                // range values, the live FILE_OBJECT, and the IRP requestor.
                ffi::FsRtlFastCheckLockForRead(
                    self.native.get(),
                    core::ptr::addr_of_mut!(range.start),
                    core::ptr::addr_of_mut!(range.length),
                    key.as_ulong(),
                    file_object.as_ptr(),
                    requestor.as_ptr(),
                ) != 0
            })
        }
        #[cfg(test)]
        {
            let _requestor = requestor;
            let _file_object = file_object;
            let _key = key;
            let _range = range;
            Ok(true)
        }
    }

    /// Checks one resolved write range against this FCB's byte-range locks.
    /// # Errors
    ///
    /// Returns an error when the resolved range cannot be represented by FsRtl.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn permits_write(
        &self,
        requestor: RequestorProcess,
        file_object: KernelFileObject,
        start: FileOffset,
        length: usize,
        key: ByteRangeLockKey,
    ) -> DriverResult<bool> {
        let range = NativeFileByteRange::new(start, length)?;
        #[cfg(not(test))]
        {
            let mut range = range;
            Ok(unsafe {
                // SAFETY: FsRtl receives initialized lock state, checked signed
                // range values, the live FILE_OBJECT, and the IRP requestor.
                ffi::FsRtlFastCheckLockForWrite(
                    self.native.get(),
                    core::ptr::addr_of_mut!(range.start),
                    core::ptr::addr_of_mut!(range.length),
                    key.as_ulong(),
                    file_object.as_ptr().cast::<c_void>(),
                    requestor.as_ptr(),
                ) != 0
            })
        }
        #[cfg(test)]
        {
            let _requestor = requestor;
            let _file_object = file_object;
            let _key = key;
            let _range = range;
            Ok(true)
        }
    }
}

impl Drop for FileByteRangeLocks {
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
            // SAFETY: This FCB initialized `native` once and cannot be
            // dropped until its final FILE_OBJECT reference is released.
            ffi::FsRtlUninitializeFileLock(self.native.get());
        }
    }
}

impl fmt::Debug for FileByteRangeLocks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileByteRangeLocks(..)")
    }
}
