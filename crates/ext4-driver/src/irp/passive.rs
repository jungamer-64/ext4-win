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
        /// Unique completion authority moves to the worker until native chain access ends.
        owned: super::OwnedIrp,
        /// Read access or preparation for a within-EOF write.
        transfer: super::MdlTransferRequest,
    },
    /// Read cached bytes into a system-addressable top-level IRP mapping.
    Read {
        /// Stream retained independently from the handle CCB.
        file_object: FileObjectCacheLease,
        /// Sole completion owner retains the captured output through worker execution.
        owned: super::OwnedIrp,
        /// Signed Windows byte offset validated before worker submission.
        offset: i64,
        /// Maximum transfer byte count.
        length: usize,
    },
    /// Accept one within-EOF write into Cache Manager.
    Write {
        /// Stream retained independently from the handle CCB.
        file_object: FileObjectCacheLease,
        /// Sole completion owner retains the captured input through worker execution.
        owned: super::OwnedIrp,
        /// Signed Windows byte offset validated before worker submission.
        offset: i64,
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
    /// Flush/purge and freeze one regular file before constructing a verity tree.
    PrepareVerity {
        /// Exact stream allocation retained independently from its requesting handle.
        stream: crate::state::StreamVerityLease,
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
        /// Sole completion owner retains FILE_OBJECT through native teardown.
        owned: super::OwnedIrp,
    },
}

/// Exact result returned by one passive native work item.
#[derive(Debug)]
pub(crate) enum PassiveWorkCompletion {
    /// No native effect occurred; the executor retains this request for bounded admission retry.
    Retry(PassiveWork),
    /// Fully prepared response after persistence and publication finish.
    Identity(alloc::vec::Vec<u8>),
    /// Native sector observation, including its exact failure status.
    SectorSize(DriverResult<crate::kernel::storage::SectorSizeInformation>),
    /// MDL chain acquisition and observed byte count.
    Mdl {
        /// Unique completion authority returned after the native effect or pre-effect cancellation.
        owned: super::OwnedIrp,
        /// Exact chain-acquisition outcome.
        result: DriverResult<usize>,
    },
    /// Cached read status and observed transfer byte count.
    Read {
        /// Completion authority returned only after native buffer access ends.
        owned: super::OwnedIrp,
        /// Exact transfer outcome, including preparation failure before native access.
        result: DriverResult<usize>,
    },
    /// Cached write acceptance status.
    Write {
        /// Completion authority returned only after native buffer access ends.
        owned: super::OwnedIrp,
        /// Acceptance outcome; failure does not publish a successful byte count.
        result: DriverResult<()>,
    },
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
    /// Frozen data and cache invalidation result, retained through protection publication.
    PrepareVerity(DriverResult<crate::state::PreparedStreamVerity>),
    /// Synchronous handle-oplock release status; driver completion ownership remains retained.
    CleanupOplock(DriverResult<()>),
    /// Private cache-map uninitialization status.
    Uninitialize {
        /// Completion authority returned after native FILE_OBJECT access ends.
        owned: super::OwnedIrp,
        /// Exact teardown outcome, including failure before worker submission.
        result: DriverResult<()>,
    },
}

impl PassiveWork {
    /// Checks mounted storage only for work that can access the volume's data device.
    /// Registry work owns independent authority; terminal cleanup must remain possible after removal.
    /// # Errors
    /// Returns the supplied storage authorization failure before volume work can be queued.
    pub(crate) fn authorize_storage(
        &self,
        authorize: impl FnOnce() -> DriverResult<()>,
    ) -> DriverResult<()> {
        match self {
            Self::Identity(_) | Self::Uninitialize { .. } | Self::CleanupOplock { .. } => Ok(()),
            Self::SectorSize { .. }
            | Self::Mdl { .. }
            | Self::Read { .. }
            | Self::Write { .. }
            | Self::Flush { .. }
            | Self::CloseWriteback { .. }
            | Self::Purge { .. }
            | Self::DrainForVolumeLock { .. }
            | Self::PrepareSizeChange { .. }
            | Self::PrepareDeletion { .. }
            | Self::PrepareWriteOpen { .. }
            | Self::PrepareVerity { .. } => authorize(),
        }
    }

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
        owned: super::OwnedIrp,
        transfer: super::MdlTransferRequest,
    ) -> Self {
        Self::Mdl {
            file_object,
            owned,
            transfer,
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
    pub(crate) const fn uninitialize(
        file_object: FileObjectCacheLease,
        owned: super::OwnedIrp,
    ) -> Self {
        Self::Uninitialize { file_object, owned }
    }

    /// Executes the sole native call selected before the actor suspended.
    pub(super) fn execute(self, retrying: bool) -> PassiveWorkCompletion {
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
                mut owned,
                transfer,
            } => {
                let result = file_object.mdl(owned.request(), transfer, retrying);
                if result == Err(DriverError::CacheManagerFailure(wdk_sys::STATUS_CANT_WAIT)) {
                    return PassiveWorkCompletion::Retry(Self::Mdl {
                        file_object,
                        owned,
                        transfer,
                    });
                }
                PassiveWorkCompletion::Mdl { owned, result }
            }
            Self::Read {
                file_object,
                mut owned,
                offset,
                length,
            } => {
                let result = file_object.read(owned.request(), offset, length);
                PassiveWorkCompletion::Read { owned, result }
            }
            Self::Write {
                file_object,
                mut owned,
                offset,
                length,
            } => {
                let result = file_object.write(owned.request(), offset, length, retrying);
                if result == Err(DriverError::CacheManagerFailure(wdk_sys::STATUS_CANT_WAIT)) {
                    return PassiveWorkCompletion::Retry(Self::Write {
                        file_object,
                        owned,
                        offset,
                        length,
                    });
                }
                PassiveWorkCompletion::Write { owned, result }
            }
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
            Self::PrepareVerity { stream } => {
                PassiveWorkCompletion::PrepareVerity(stream.execute())
            }
            Self::CleanupOplock { check, irp } => {
                PassiveWorkCompletion::CleanupOplock(check.execute(irp))
            }
            Self::Uninitialize {
                file_object,
                mut owned,
            } => {
                let result = owned.request().with_active(|active| {
                    file_object.uninitialize(active.current_stack()?.file_object()?)
                });
                PassiveWorkCompletion::Uninitialize { owned, result }
            }
        }
    }

    /// Preserves the selected operation kind when worker preparation fails before queueing.
    pub(super) fn failed(self, error: DriverError) -> PassiveWorkCompletion {
        match self {
            Self::Identity(work) => PassiveWorkCompletion::Identity((*work).failed(error)),
            Self::SectorSize { .. } => PassiveWorkCompletion::SectorSize(Err(error)),
            Self::Mdl { owned, .. } => PassiveWorkCompletion::Mdl {
                owned,
                result: Err(error),
            },
            Self::Read { owned, .. } => PassiveWorkCompletion::Read {
                owned,
                result: Err(error),
            },
            Self::Write { owned, .. } => PassiveWorkCompletion::Write {
                owned,
                result: Err(error),
            },
            Self::Flush { .. } => PassiveWorkCompletion::Flush(Err(error)),
            Self::CloseWriteback { .. } => PassiveWorkCompletion::CloseWriteback(Err(error)),
            Self::Purge { .. } => PassiveWorkCompletion::Purge(Err(error)),
            Self::DrainForVolumeLock { .. } => {
                PassiveWorkCompletion::DrainForVolumeLock(Err(error))
            }
            Self::PrepareSizeChange { .. } => PassiveWorkCompletion::PrepareSizeChange(Err(error)),
            Self::PrepareDeletion { .. } => PassiveWorkCompletion::PrepareDeletion(Err(error)),
            Self::PrepareWriteOpen { .. } => PassiveWorkCompletion::PrepareWriteOpen(Err(error)),
            Self::PrepareVerity { .. } => PassiveWorkCompletion::PrepareVerity(Err(error)),
            Self::CleanupOplock { .. } => PassiveWorkCompletion::CleanupOplock(Err(error)),
            Self::Uninitialize { owned, .. } => PassiveWorkCompletion::Uninitialize {
                owned,
                result: Err(error),
            },
        }
    }

    /// Returns worker-owned IRP authority on cancellation before native submission.
    /// Other work leaves IRP ownership in its suspended operation and resumes that cancel path.
    #[cfg(not(test))]
    pub(super) fn cancel_before_execution(self) -> super::reactor::CompletionEvent {
        match self {
            work @ (Self::Read { .. }
            | Self::Write { .. }
            | Self::Mdl { .. }
            | Self::Uninitialize { .. }) => super::reactor::CompletionEvent::PassiveCompleted(
                work.failed(DriverError::from(ext4_core::Error::OperationCancelled)),
            ),
            _ => super::reactor::CompletionEvent::Core(ext4_core::OperationEvent::CancelRequested),
        }
    }
}

#[expect(
    unsafe_code,
    reason = "suspended IRPs, stream leases and referenced devices retain every captured mapping and identity through native work"
)]
// SAFETY: Cached transfers and cache teardown own their IRP; other IRP work is retained by the
// suspended operation in the same envelope. Stream leases retain Cc/MM identities, and sector queries own
// a device reference. Native access ends before either completion owner can resume or release.
unsafe impl Send for PassiveWork {}

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
    /// Finite count of unsuccessful native admissions, separated from native effects.
    retries: super::scheduler::NativeAdmissionBudget,
}

/// Native completion either returns resources or retains the exact admission for another attempt.
#[cfg(not(test))]
pub(super) enum PassiveReclaim {
    /// Native work ended; finalization can recover its dormant storage.
    Completed {
        /// Original operation consuming the native result.
        operation: Box<dyn CompletionOperation>,
        /// Authoritative result, including transferred IRP ownership.
        completion: PassiveWorkCompletion,
        /// Terminal execution storage, absent for ordinary work.
        reserve: Option<Box<PassiveWorkEnvelope>>,
    },
    /// No native effect occurred and callback storage remains prepared.
    Deferred(Box<PassiveWorkEnvelope>),
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
            retries: super::scheduler::NativeAdmissionBudget::new(),
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

    /// Reserves ordinary worker storage before transferring request or operation ownership.
    /// # Errors
    /// Returns allocation failure without accepting a request or submitting native work.
    pub(super) fn prepare_request(
        device: KernelDevice,
        rundown: CompletionRundownLease,
    ) -> DriverResult<Box<Self>> {
        Self::allocate(device, PassiveLifetime::Request(rundown))
    }

    /// Consumes ordinary work before submission; finalization reserves are non-cancellable.
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
    /// Projects the first-field inbox node while preserving access to the complete allocation.
    pub(super) fn node_ptr(envelope: NonNull<Self>) -> *mut LIST_ENTRY {
        envelope.as_ptr().cast()
    }
    /// Recovers stable storage after exclusive inbox removal.
    /// # Safety
    /// The node must have been removed exactly once from this reactor's native-work inbox and
    /// retain complete-allocation provenance established by [`Self::node_ptr`].
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
    pub(super) fn reclaim(mut envelope: Box<Self>) -> PassiveReclaim {
        let PassiveState::Completed(job, completion) =
            core::mem::replace(&mut envelope.state, PassiveState::Dormant)
        else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        let completion = if let PassiveWorkCompletion::Retry(work) = completion {
            if envelope.retries.defer() {
                envelope.state = PassiveState::Prepared(job, work);
                return PassiveReclaim::Deferred(envelope);
            }
            work.failed(DriverError::CacheManagerFailure(wdk_sys::STATUS_IO_TIMEOUT))
        } else {
            completion
        };
        let reserve = if matches!(envelope.lifetime, PassiveLifetime::Reserve(_)) {
            Some(envelope)
        } else {
            None
        };
        PassiveReclaim::Completed {
            operation: job.suspended,
            completion,
            reserve,
        }
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
    envelope.state = PassiveState::Completed(job, work.execute(envelope.retries.retrying()));
    unsafe {
        // SAFETY: The completed envelope retains this destination until publication takes its
        // own lease, then transfers the unique unlinked node without borrowing its payload.
        CompletionReactor::enqueue_passive_completion(reactor, address);
    }
    // The actor may reclaim or reuse storage immediately; no envelope access is permitted here.
}
