//! Owned PASSIVE_LEVEL native work and reactor completion ownership.

use core::ptr::NonNull;

#[cfg(not(test))]
use alloc::boxed::Box;
#[cfg(not(test))]
use core::ffi::c_void;
#[cfg(not(test))]
use core::fmt;
#[cfg(not(test))]
use wdk_sys::LIST_ENTRY;

use crate::kernel::status::{DriverError, DriverResult};
use crate::state::{
    CompletedVolumeLockStreamDrain, FileObjectCacheLease, PreparedStreamDeletion,
    PreparedStreamSizeChange, PreparedStreamWriteOpen, StreamCacheLease, StreamDeletionLease,
    StreamSizeChangeLease, StreamWriteOpenLease, VolumeLockStreamDrainLease,
};

#[cfg(not(test))]
use crate::kernel::{fatal::KernelWideInconsistency, ffi};
#[cfg(not(test))]
use crate::memory;
#[cfg(not(test))]
use crate::state::KernelDevice;

#[cfg(not(test))]
use super::lower::CompletionRundownLease;
#[cfg(not(test))]
use super::reactor::{CompletionOperation, CompletionReactor};
#[cfg(not(test))]
use super::scheduler::SlotId;

/// One captured native call whose resource lease owns every identity through worker completion.
#[derive(Debug)]
pub(crate) enum PassiveWork {
    /// Retained UUID update or reconciliation, owned through worker completion.
    Identity(alloc::boxed::Box<crate::identity::IdentityWork>),
    /// Read sector geometry without blocking the actor or retaining its mounted-state borrow.
    SectorSize {
        /// Borrowed native admission; the suspended mounted operation and worker rundown
        /// retain its VCB until completion.
        storage: crate::kernel::stream::VolumeStorageAccess,
        /// Referenced VPB real device released when this work finishes or fails before queueing.
        query: crate::kernel::storage::SectorSizeQuery,
        /// Mount-owned logical unit that the native result must agree with.
        logical: crate::state::TransferSectorSize,
    },
    /// Acquire Cache Manager pages for the suspended request.
    Mdl {
        /// Retains the exact stream through the native call.
        file_object: FileObjectCacheLease,
        /// IRP retained by the suspended operation until worker return.
        irp: NonNull<wdk_sys::IRP>,
        /// Read access or preparation for a within-EOF write.
        action: super::MdlTransfer,
    },
    /// Read cached bytes into a system-addressable top-level IRP mapping.
    Read {
        /// Stream retained independently from the handle CCB.
        file_object: FileObjectCacheLease,
        /// Signed Windows byte offset validated before worker submission.
        offset: i64,
        /// Maximum transfer byte count.
        length: usize,
        /// Writable system mapping retained by the suspended IRP.
        output: Option<NonNull<u8>>,
    },
    /// Accept one within-EOF write into Cache Manager.
    Write {
        /// Stream retained independently from the handle CCB.
        file_object: FileObjectCacheLease,
        /// Signed Windows byte offset validated before worker submission.
        offset: i64,
        /// Readable system mapping retained by the suspended IRP.
        input: Option<NonNull<u8>>,
        /// Exact accepted byte count on success.
        length: usize,
    },
    /// Flush every dirty cached page for one stream.
    Flush {
        /// Stream retained through flush completion.
        stream: StreamCacheLease,
    },
    /// Terminal cache writeback after ordinary admission closes.
    CloseWriteback {
        /// Stream retained until the native writeback call returns.
        stream: StreamCacheLease,
    },
    /// Flush and purge one stream before direct or size-changing I/O.
    Purge {
        /// Stream retained through the coherency boundary.
        stream: StreamCacheLease,
    },
    /// Flush cached data and release every unreferenced section before volume lock.
    DrainForVolumeLock {
        /// Stream retained through the complete cache and Memory Manager boundary.
        stream: VolumeLockStreamDrainLease,
    },
    /// Establish one cache/section gate for a resolved stream-size mutation.
    PrepareSizeChange {
        /// Exact retained stream and new-size semantics.
        stream: StreamSizeChangeLease,
    },
    /// Establish one image/data-section gate for a cleanup namespace deletion.
    PrepareDeletion {
        /// Exact cleaned-up stream retained independently from its handle.
        stream: StreamDeletionLease,
    },
    /// Establish one image-section gate for an existing regular-file write-open.
    PrepareWriteOpen {
        /// Exact resident stream retained independently from the pending create handle.
        stream: StreamWriteOpenLease,
    },
    /// Notify FsRtl of non-cancellable handle cleanup without asynchronous continuation allocation.
    CleanupOplock {
        /// Exact retained stream and create-time deletion semantics.
        check: super::CleanupOplock,
        /// Live cleanup IRP retained by the suspended finalization owner.
        irp: NonNull<wdk_sys::IRP>,
    },
    /// Release one FILE_OBJECT's private cache map.
    Uninitialize {
        /// Stream and FILE_OBJECT identity retained through uninitialization.
        file_object: FileObjectCacheLease,
    },
}

/// Exact result returned by one passive native work item.
#[derive(Debug)]
pub(crate) enum PassiveWorkCompletion {
    /// Fully prepared response after persistence and publication finish.
    Identity(alloc::vec::Vec<u8>),
    /// Native sector observation, including its exact failure status.
    SectorSize(DriverResult<crate::kernel::storage::SectorSizeInformation>),
    /// MDL chain acquisition and observed byte count.
    Mdl(DriverResult<usize>),
    /// Cached read status and observed transfer byte count.
    Read(DriverResult<usize>),
    /// Cached write acceptance status.
    Write(DriverResult<()>),
    /// Dirty-page flush status.
    Flush(DriverResult<()>),
    /// Terminal writeback status, including pinned/mapped-page conflicts.
    CloseWriteback(DriverResult<()>),
    /// Coherency flush/purge status.
    Purge(DriverResult<()>),
    /// Volume-lock cache and section drain status.
    DrainForVolumeLock(DriverResult<CompletedVolumeLockStreamDrain>),
    /// Native size-change gate acquisition status and release authority.
    PrepareSizeChange(DriverResult<PreparedStreamSizeChange>),
    /// Native deletion gate acquisition status and release authority.
    PrepareDeletion(DriverResult<PreparedStreamDeletion>),
    /// Native write-open gate acquisition status and release authority.
    PrepareWriteOpen(DriverResult<PreparedStreamWriteOpen>),
    /// Synchronous handle-oplock release status; driver completion ownership remains retained.
    CleanupOplock(DriverResult<()>),
    /// Private cache-map uninitialization status.
    Uninitialize(DriverResult<()>),
}

impl PassiveWork {
    /// Captures cleanup-only FsRtl work while the suspended IRP remains the sole completion owner.
    pub(crate) fn cleanup_oplock(
        check: super::CleanupOplock,
        active: &super::ActiveIrp<'_>,
    ) -> Self {
        Self::CleanupOplock {
            check,
            irp: active.irp,
        }
    }
    /// Captures MDL work under the exclusive top-level completion owner.
    pub(crate) fn mdl(
        file_object: FileObjectCacheLease,
        active: &super::ActiveIrp<'_>,
        action: super::MdlTransfer,
    ) -> Self {
        Self::Mdl {
            file_object,
            irp: active.irp,
            action,
        }
    }
    /// Builds one stream flush.
    pub(crate) const fn flush(stream: StreamCacheLease) -> Self {
        Self::Flush { stream }
    }

    /// Builds one stream coherency flush/purge.
    pub(crate) const fn purge(stream: StreamCacheLease) -> Self {
        Self::Purge { stream }
    }

    /// Builds one volume-lock cache and section drain.
    pub(crate) const fn drain_for_volume_lock(stream: VolumeLockStreamDrainLease) -> Self {
        Self::DrainForVolumeLock { stream }
    }

    /// Builds one resolved stream-size cache/section precommit gate.
    pub(crate) const fn prepare_size_change(stream: StreamSizeChangeLease) -> Self {
        Self::PrepareSizeChange { stream }
    }

    /// Builds one cleanup stream-deletion section gate.
    pub(crate) const fn prepare_deletion(stream: StreamDeletionLease) -> Self {
        Self::PrepareDeletion { stream }
    }

    /// Builds one existing write-open image-section gate.
    pub(crate) const fn prepare_write_open(stream: StreamWriteOpenLease) -> Self {
        Self::PrepareWriteOpen { stream }
    }

    /// Builds one FILE_OBJECT cache-map uninitialization.
    pub(crate) const fn uninitialize(file_object: FileObjectCacheLease) -> Self {
        Self::Uninitialize { file_object }
    }

    /// Executes the sole native call selected before the actor suspended.
    pub(super) fn execute(self) -> PassiveWorkCompletion {
        match self {
            Self::Identity(work) => PassiveWorkCompletion::Identity((*work).execute()),
            Self::SectorSize {
                query,
                logical,
                storage,
            } => {
                let result = storage.authorize().and_then(|()| query.execute(logical));
                PassiveWorkCompletion::SectorSize(
                    result.and_then(|information| storage.authorize().map(|()| information)),
                )
            }
            Self::Mdl {
                file_object,
                irp,
                action,
            } => PassiveWorkCompletion::Mdl(file_object.mdl(irp, action)),
            Self::Read {
                file_object,
                offset,
                length,
                output,
            } => PassiveWorkCompletion::Read(file_object.read(offset, length, output)),
            Self::Write {
                file_object,
                offset,
                input,
                length,
            } => PassiveWorkCompletion::Write(file_object.write(offset, input, length)),
            Self::Flush { stream } => PassiveWorkCompletion::Flush(stream.flush()),
            Self::CloseWriteback { stream } => {
                PassiveWorkCompletion::CloseWriteback(stream.close_writeback())
            }
            Self::Purge { stream } => PassiveWorkCompletion::Purge(stream.purge()),
            Self::DrainForVolumeLock { stream } => {
                PassiveWorkCompletion::DrainForVolumeLock(stream.execute())
            }
            Self::PrepareSizeChange { stream } => {
                PassiveWorkCompletion::PrepareSizeChange(stream.execute())
            }
            Self::PrepareDeletion { stream } => {
                PassiveWorkCompletion::PrepareDeletion(stream.execute())
            }
            Self::PrepareWriteOpen { stream } => {
                PassiveWorkCompletion::PrepareWriteOpen(stream.execute())
            }
            Self::CleanupOplock { check, irp } => {
                PassiveWorkCompletion::CleanupOplock(check.execute(irp))
            }
            Self::Uninitialize { file_object } => {
                PassiveWorkCompletion::Uninitialize(file_object.uninitialize())
            }
        }
    }

    /// Preserves the selected operation kind when worker preparation fails before queueing.
    pub(super) fn failed(self, error: DriverError) -> PassiveWorkCompletion {
        match self {
            Self::Identity(work) => PassiveWorkCompletion::Identity((*work).failed(error)),
            Self::SectorSize { .. } => PassiveWorkCompletion::SectorSize(Err(error)),
            Self::Mdl { .. } => PassiveWorkCompletion::Mdl(Err(error)),
            Self::Read { .. } => PassiveWorkCompletion::Read(Err(error)),
            Self::Write { .. } => PassiveWorkCompletion::Write(Err(error)),
            Self::Flush { .. } => PassiveWorkCompletion::Flush(Err(error)),
            Self::CloseWriteback { .. } => PassiveWorkCompletion::CloseWriteback(Err(error)),
            Self::Purge { .. } => PassiveWorkCompletion::Purge(Err(error)),
            Self::DrainForVolumeLock { .. } => {
                PassiveWorkCompletion::DrainForVolumeLock(Err(error))
            }
            Self::PrepareSizeChange { .. } => PassiveWorkCompletion::PrepareSizeChange(Err(error)),
            Self::PrepareDeletion { .. } => PassiveWorkCompletion::PrepareDeletion(Err(error)),
            Self::PrepareWriteOpen { .. } => PassiveWorkCompletion::PrepareWriteOpen(Err(error)),
            Self::CleanupOplock { .. } => PassiveWorkCompletion::CleanupOplock(Err(error)),
            Self::Uninitialize { .. } => PassiveWorkCompletion::Uninitialize(Err(error)),
        }
    }
}

#[expect(
    unsafe_code,
    reason = "suspended IRPs, stream leases and referenced devices retain every captured mapping and identity through native work"
)]
// SAFETY: IRP mappings belong to the unique suspended operation, stream leases retain Cc/MM
// identities, and sector queries own a device reference. One work envelope consumes the call
// before the operation can resume or release any input resource.
unsafe impl Send for PassiveWork {}

/// Preparation failure that returns the unique suspended operation to the reactor.
#[cfg(not(test))]
pub(super) struct PassiveWorkPreparationError {
    /// Exact allocation or rundown failure.
    error: DriverError,
    /// Operation that never crossed the worker effect boundary.
    suspended: Box<dyn CompletionOperation>,
    /// Prepared native call that never crossed the worker effect boundary.
    work: PassiveWork,
}

#[cfg(not(test))]
impl PassiveWorkPreparationError {
    /// Recovers the failure and unique operation authority.
    pub(super) fn into_parts(self) -> (DriverError, PassiveWork, Box<dyn CompletionOperation>) {
        (self.error, self.work, self.suspended)
    }
}

/// Stable native worker storage. Dormant reserves exist before device admission is published.
#[cfg(not(test))]
#[repr(C)]
pub(super) struct PassiveWorkEnvelope {
    /// First-field node, linked only after native work is complete.
    node: core::cell::UnsafeCell<LIST_ENTRY>,
    /// Native queue storage owned until this envelope is finally destroyed.
    work_item: NonNull<wdk_sys::_IO_WORKITEM>,
    /// I/O Manager callback device, retained through the worker lifetime.
    device: KernelDevice,
    /// Reuse policy and completion-destination lifetime are a single ownership fact.
    lifetime: PassiveLifetime,
    /// The payload cannot be both a pending native call and a published completion.
    state: PassiveState,
}

/// Finalization keeps its lease while dormant; ordinary work releases it on reclamation.
#[cfg(not(test))]
enum PassiveLifetime {
    /// Actor retirement precedes release of this prepared finalization reserve.
    Reserve(CompletionRundownLease),
    /// One dynamically prepared request owns this lease until completion reclamation.
    Request(CompletionRundownLease),
}

/// Context kept until the actor reclaims the exact completed native call.
#[cfg(not(test))]
struct PassiveJob {
    /// Destination retained by the envelope's lifetime lease.
    reactor: NonNull<CompletionReactor>,
    /// Exact active slot generation that owns the suspended operation.
    identity: SlotId,
    /// Unique operation whose resources cannot release before the native call returns.
    suspended: Box<dyn CompletionOperation>,
}

/// Ownership phases of a prepared native call; only the owning worker can publish completion.
#[cfg(not(test))]
enum PassiveState {
    /// Prepared storage holds no request, stream or active-slot identity.
    Dormant,
    /// The queue owns the next native call and its completion destination.
    Prepared(PassiveJob, PassiveWork),
    /// The native call ended; the actor owns the result through inbox publication.
    Completed(PassiveJob, PassiveWorkCompletion),
}

#[cfg(not(test))]
impl fmt::Debug for PassiveWorkEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassiveWorkEnvelope")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this boundary owns native worker allocation, queueing and intrusive lifetime transfer"
)]
impl PassiveWorkEnvelope {
    /// Allocates storage before publication while the supplied lease pins its destination.
    /// # Errors
    /// Returns allocation failure before any callback or native effect has been submitted.
    fn allocate(device: KernelDevice, lifetime: PassiveLifetime) -> DriverResult<Box<Self>> {
        let work_item = NonNull::new(unsafe {
            // SAFETY: Initialization or active request ownership retains the device.
            ffi::IoAllocateWorkItem(device.as_ptr())
        })
        .ok_or(DriverError::InsufficientResources)?;
        match memory::boxed_try_map(lifetime, |lifetime| Self {
            node: core::cell::UnsafeCell::new(LIST_ENTRY::default()),
            work_item,
            device,
            lifetime,
            state: PassiveState::Dormant,
        }) {
            Ok(envelope) => Ok(envelope),
            Err(failure) => {
                unsafe {
                    // SAFETY: This native item was never queued and allocation rollback owns it.
                    ffi::IoFreeWorkItem(work_item.as_ptr());
                }
                Err(failure.into_parts().0)
            }
        }
    }

    /// Prepares cache-map release storage before any open handle can depend on finalization.
    /// # Errors
    /// Returns allocation failure while reactor initialization still owns rollback.
    pub(super) fn prepare_reserve(
        device: KernelDevice,
        lease: CompletionRundownLease,
    ) -> DriverResult<Box<Self>> {
        Self::allocate(device, PassiveLifetime::Reserve(lease))
    }

    /// Binds existing storage without allocation; its retained lifetime already pins the reactor.
    pub(super) fn bind(
        mut self: Box<Self>,
        reactor: NonNull<CompletionReactor>,
        identity: SlotId,
        work: PassiveWork,
        suspended: Box<dyn CompletionOperation>,
    ) -> Box<Self> {
        if !matches!(self.state, PassiveState::Dormant) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        self.state = PassiveState::Prepared(
            PassiveJob {
                reactor,
                identity,
                suspended,
            },
            work,
        );
        self
    }

    /// Prepares ordinary native work while preserving ownership on pre-effect failure.
    /// # Errors
    /// Returns allocation failure together with the unconsumed work and operation.
    pub(super) fn try_new(
        device: KernelDevice,
        reactor: NonNull<CompletionReactor>,
        identity: SlotId,
        work: PassiveWork,
        suspended: Box<dyn CompletionOperation>,
        rundown: CompletionRundownLease,
    ) -> Result<Box<Self>, PassiveWorkPreparationError> {
        match Self::allocate(device, PassiveLifetime::Request(rundown)) {
            Ok(envelope) => Ok(envelope.bind(reactor, identity, work, suspended)),
            Err(error) => Err(PassiveWorkPreparationError {
                error,
                suspended,
                work,
            }),
        }
    }

    /// Consumes ordinary work before submission; finalization reserves are non-cancellable.
    #[expect(
        clippy::boxed_local,
        reason = "the consuming Box owns native callback storage and its one deallocation obligation"
    )]
    pub(super) fn cancel_before_queue(
        mut envelope: Box<Self>,
    ) -> (PassiveWork, Box<dyn CompletionOperation>) {
        if !matches!(envelope.lifetime, PassiveLifetime::Request(_)) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        let PassiveState::Prepared(job, work) =
            core::mem::replace(&mut envelope.state, PassiveState::Dormant)
        else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        (work, job.suspended)
    }

    /// Native queue publication is infallible once storage and lifetime ownership exist.
    pub(super) fn queue(envelope: Box<Self>) {
        let raw = Box::into_raw(envelope);
        let work_item = unsafe {
            // SAFETY: The callback exclusively owns this stable envelope after queue publication.
            (*raw).work_item
        };
        unsafe {
            // SAFETY: Storage and lifetime lease retain the context through callback/inbox transfer.
            ffi::IoQueueWorkItem(
                work_item.as_ptr(),
                Some(passive_work_item),
                wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue,
                raw.cast::<c_void>(),
            );
        }
    }
    /// Node ownership transfers only after the native call has consumed its resource lease.
    pub(super) fn node_ptr(&self) -> *mut LIST_ENTRY {
        self.node.get()
    }
    /// Recovers stable storage after exclusive inbox removal.
    /// # Safety
    /// The node must have been removed exactly once from this reactor's native-work inbox.
    pub(super) unsafe fn from_node(node: NonNull<LIST_ENTRY>) -> NonNull<Self> {
        node.cast()
    }
    /// Completed payload carries the exact active-slot generation through worker transfer.
    pub(super) fn identity(&self) -> SlotId {
        let PassiveState::Completed(job, _) = &self.state else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        job.identity
    }
    /// Returns native completion ownership and restores finalization storage to its dormant reserve.
    pub(super) fn reclaim(
        mut envelope: Box<Self>,
    ) -> (
        Box<dyn CompletionOperation>,
        PassiveWorkCompletion,
        Option<Box<Self>>,
    ) {
        let PassiveState::Completed(job, completion) =
            core::mem::replace(&mut envelope.state, PassiveState::Dormant)
        else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        let reserve = if matches!(envelope.lifetime, PassiveLifetime::Reserve(_)) {
            Some(envelope)
        } else {
            None
        };
        (job.suspended, completion, reserve)
    }
}

#[cfg(not(test))]
impl Drop for PassiveWorkEnvelope {
    #[expect(
        unsafe_code,
        reason = "unique dormant/completed envelope ownership proves this native item is not queued"
    )]
    fn drop(&mut self) {
        unsafe {
            // SAFETY: Pre-publication rollback or exclusive inbox reclamation owns the dequeued item.
            ffi::IoFreeWorkItem(self.work_item.as_ptr());
        }
        // Reading the lease variants states the lifetime contract; they release only after native storage.
        match &self.lifetime {
            PassiveLifetime::Reserve(lease) | PassiveLifetime::Request(lease) => {
                let _retained = lease;
            }
        }
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "one owner transfers stable worker storage between actor, native queue and inbox"
)]
// SAFETY: The queue and actor never own this envelope simultaneously; its lease pins the destination.
unsafe impl Send for PassiveWorkEnvelope {}

/// Executes the single prepared native call and publishes its result without later context access.
/// # Safety
/// The I/O Manager must return the unique context queued by PassiveWorkEnvelope::queue.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native callback entry transfers unique ownership of the queued stable envelope"
)]
unsafe extern "C" fn passive_work_item(device: wdk_sys::PDEVICE_OBJECT, context: wdk_sys::PVOID) {
    let mut address = NonNull::new(context.cast::<PassiveWorkEnvelope>()).unwrap_or_else(|| {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
    });
    let envelope = unsafe {
        // SAFETY: This dequeued callback exclusively owns storage until inbox publication.
        address.as_mut()
    };
    if device != envelope.device.as_ptr() {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    }
    let PassiveState::Prepared(job, work) =
        core::mem::replace(&mut envelope.state, PassiveState::Dormant)
    else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let reactor = job.reactor;
    envelope.state = PassiveState::Completed(job, work.execute());
    unsafe {
        // SAFETY: The completed envelope retains this destination until publication takes its
        // own lease, then transfers the unique unlinked node without borrowing its payload.
        CompletionReactor::enqueue_passive_completion(reactor, address);
    }
    // The actor may reclaim or reuse storage immediately; no envelope access is permitted here.
}
