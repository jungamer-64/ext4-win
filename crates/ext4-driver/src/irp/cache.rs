//! PASSIVE_LEVEL Cache Manager work and reactor completion ownership.

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
    CompletedVolumeLockStreamDrain, FileObjectCacheLease, PreparedStreamSizeChange,
    StreamCacheLease, StreamSizeChangeLease, VolumeLockStreamDrainLease,
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

/// One fully captured Cache Manager call whose stream lease owns every native identity.
#[derive(Debug)]
pub(crate) enum CacheWork {
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
    /// Release one FILE_OBJECT's private cache map.
    Uninitialize {
        /// Stream and FILE_OBJECT identity retained through uninitialization.
        file_object: FileObjectCacheLease,
    },
}

/// Exact result returned by one Cache Manager work item.
#[derive(Debug)]
pub(crate) enum CacheWorkCompletion {
    /// Cached read status and observed transfer byte count.
    Read(DriverResult<usize>),
    /// Cached write acceptance status.
    Write(DriverResult<()>),
    /// Dirty-page flush status.
    Flush(DriverResult<()>),
    /// Coherency flush/purge status.
    Purge(DriverResult<()>),
    /// Volume-lock cache and section drain status.
    DrainForVolumeLock(DriverResult<CompletedVolumeLockStreamDrain>),
    /// Native size-change gate acquisition status and release authority.
    PrepareSizeChange(DriverResult<PreparedStreamSizeChange>),
    /// Private cache-map uninitialization status.
    Uninitialize(DriverResult<()>),
}

impl CacheWork {
    /// Builds one cached read after range, mapping, and stream lease capture.
    pub(crate) const fn read(
        file_object: FileObjectCacheLease,
        offset: i64,
        length: usize,
        output: Option<NonNull<u8>>,
    ) -> Self {
        Self::Read {
            file_object,
            offset,
            length,
            output,
        }
    }

    /// Builds one within-EOF cached write after range, mapping, and stream lease capture.
    pub(crate) const fn write(
        file_object: FileObjectCacheLease,
        offset: i64,
        input: Option<NonNull<u8>>,
        length: usize,
    ) -> Self {
        Self::Write {
            file_object,
            offset,
            input,
            length,
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

    /// Builds one FILE_OBJECT cache-map uninitialization.
    pub(crate) const fn uninitialize(file_object: FileObjectCacheLease) -> Self {
        Self::Uninitialize { file_object }
    }

    /// Executes the sole native Cc/MM call selected before the actor suspended.
    pub(super) fn execute(self) -> CacheWorkCompletion {
        match self {
            Self::Read {
                file_object,
                offset,
                length,
                output,
            } => CacheWorkCompletion::Read(file_object.read(offset, length, output)),
            Self::Write {
                file_object,
                offset,
                input,
                length,
            } => CacheWorkCompletion::Write(file_object.write(offset, input, length)),
            Self::Flush { stream } => CacheWorkCompletion::Flush(stream.flush()),
            Self::Purge { stream } => CacheWorkCompletion::Purge(stream.purge()),
            Self::DrainForVolumeLock { stream } => {
                CacheWorkCompletion::DrainForVolumeLock(stream.execute())
            }
            Self::PrepareSizeChange { stream } => {
                CacheWorkCompletion::PrepareSizeChange(stream.execute())
            }
            Self::Uninitialize { file_object } => {
                CacheWorkCompletion::Uninitialize(file_object.uninitialize())
            }
        }
    }

    /// Preserves the selected operation kind when worker preparation fails before queueing.
    pub(super) fn failed(self, error: DriverError) -> CacheWorkCompletion {
        match self {
            Self::Read { .. } => CacheWorkCompletion::Read(Err(error)),
            Self::Write { .. } => CacheWorkCompletion::Write(Err(error)),
            Self::Flush { .. } => CacheWorkCompletion::Flush(Err(error)),
            Self::Purge { .. } => CacheWorkCompletion::Purge(Err(error)),
            Self::DrainForVolumeLock { .. } => CacheWorkCompletion::DrainForVolumeLock(Err(error)),
            Self::PrepareSizeChange { .. } => CacheWorkCompletion::PrepareSizeChange(Err(error)),
            Self::Uninitialize { .. } => CacheWorkCompletion::Uninitialize(Err(error)),
        }
    }
}

#[expect(
    unsafe_code,
    reason = "the suspended IRP and cache stream lease retain every pre-captured mapping and identity"
)]
// SAFETY: Each pointer belongs to the unique suspended top-level IRP. `CacheWork` moves into one
// work envelope and is consumed before that operation can resume or release its mappings.
unsafe impl Send for CacheWork {}

/// Preparation failure that returns the unique suspended operation to the reactor.
#[cfg(not(test))]
pub(super) struct CacheWorkPreparationError {
    /// Exact allocation or rundown failure.
    error: DriverError,
    /// Operation that never crossed the worker effect boundary.
    suspended: Box<dyn CompletionOperation>,
    /// Prepared cache call that never crossed the worker effect boundary.
    work: CacheWork,
}

#[cfg(not(test))]
impl CacheWorkPreparationError {
    /// Recovers the failure and unique operation authority.
    pub(super) fn into_parts(self) -> (DriverError, CacheWork, Box<dyn CompletionOperation>) {
        (self.error, self.work, self.suspended)
    }
}

/// Stable work-item allocation published into the reactor cache-completion inbox.
#[cfg(not(test))]
#[repr(C)]
pub(super) struct CacheWorkEnvelope {
    /// First-field intrusive node used only after worker execution completes.
    node: LIST_ENTRY,
    /// I/O work item that pins the mounted device through callback entry.
    work_item: Option<NonNull<wdk_sys::_IO_WORKITEM>>,
    /// Mounted device supplied by the I/O Manager to the callback.
    device: KernelDevice,
    /// Reactor retained by `rundown` until inbox reclamation.
    reactor: NonNull<CompletionReactor>,
    /// Exact bounded slot generation that submitted this work.
    identity: SlotId,
    /// Completion destination lifetime authority.
    rundown: CompletionRundownLease,
    /// Unique top-level operation suspended outside actor ownership.
    suspended: Option<Box<dyn CompletionOperation>>,
    /// Cache call consumed exactly once by the work-item callback.
    work: Option<CacheWork>,
    /// Result published only after `work` has been consumed.
    completion: Option<CacheWorkCompletion>,
}

#[cfg(not(test))]
impl fmt::Debug for CacheWorkEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CacheWorkEnvelope")
            .field("identity", &self.identity)
            .field("work", &self.work)
            .field("completion", &self.completion)
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the work-item envelope is the audited owner of WDK allocation, queue, and intrusive-list boundaries"
)]
impl CacheWorkEnvelope {
    /// Allocates the WDK work item and stable envelope before any Cc/MM effect can occur.
    /// # Errors
    ///
    /// Returns the exact allocation failure together with both unconsumed ownership values.
    pub(super) fn try_new(
        device: KernelDevice,
        reactor: NonNull<CompletionReactor>,
        identity: SlotId,
        work: CacheWork,
        suspended: Box<dyn CompletionOperation>,
        rundown: CompletionRundownLease,
    ) -> Result<Box<Self>, CacheWorkPreparationError> {
        let work_item = NonNull::new(unsafe {
            // SAFETY: The live mounted device remains retained by the active top-level operation.
            ffi::IoAllocateWorkItem(device.as_ptr())
        });
        let Some(work_item) = work_item else {
            return Err(CacheWorkPreparationError {
                error: DriverError::InsufficientResources,
                suspended,
                work,
            });
        };
        match memory::boxed_try_map((work, suspended, rundown), |(work, suspended, rundown)| {
            Self {
                node: LIST_ENTRY::default(),
                work_item: Some(work_item),
                device,
                reactor,
                identity,
                rundown,
                suspended: Some(suspended),
                work: Some(work),
                completion: None,
            }
        }) {
            Ok(envelope) => Ok(envelope),
            Err(failure) => {
                let (error, (work, suspended, _rundown)) = failure.into_parts();
                unsafe {
                    // SAFETY: Allocation succeeded but this item was never queued.
                    ffi::IoFreeWorkItem(work_item.as_ptr());
                }
                Err(CacheWorkPreparationError {
                    error,
                    suspended,
                    work,
                })
            }
        }
    }

    /// Reclaims a fully allocated envelope before its non-cancellable effect boundary.
    #[expect(
        clippy::boxed_local,
        reason = "the Box owns the stable address paired with the allocated WDK work item"
    )]
    pub(super) fn cancel_before_queue(
        mut envelope: Box<Self>,
    ) -> (CacheWork, Box<dyn CompletionOperation>) {
        let work_item = envelope.work_item.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        unsafe {
            // SAFETY: This prepared work item was allocated but never queued.
            ffi::IoFreeWorkItem(work_item.as_ptr());
        }
        let work = envelope.work.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        let suspended = envelope.suspended.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        (work, suspended)
    }

    /// Queues one uniquely owned envelope to the system delayed work queue.
    pub(super) fn queue(envelope: Box<Self>) {
        let raw = Box::into_raw(envelope);
        let envelope = unsafe {
            // SAFETY: `raw` remains uniquely owned by the queued callback until inbox publication.
            &*raw
        };
        let work_item = envelope.work_item.unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        unsafe {
            // SAFETY: The envelope and work item remain live until the callback consumes both.
            ffi::IoQueueWorkItem(
                work_item.as_ptr(),
                Some(cache_work_item),
                wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue,
                raw.cast::<c_void>(),
            );
        }
    }

    /// Returns the embedded inbox node address.
    pub(super) fn node_ptr(&self) -> *mut LIST_ENTRY {
        core::ptr::addr_of!(self.node).cast_mut()
    }

    /// Recovers an envelope from its first-field intrusive node.
    /// # Safety
    ///
    /// `node` must have been removed exactly once from the cache-completion inbox.
    pub(super) unsafe fn from_node(node: NonNull<LIST_ENTRY>) -> NonNull<Self> {
        node.cast()
    }

    /// Exact scheduler identity retained across worker execution.
    pub(super) const fn identity(&self) -> SlotId {
        self.identity
    }

    /// Reclaims one completed envelope into operation and event ownership.
    #[expect(
        clippy::boxed_local,
        reason = "the Box is reconstructed from the intrusive first-field node and consumed here"
    )]
    pub(super) fn reclaim(
        mut envelope: Box<Self>,
    ) -> (Box<dyn CompletionOperation>, CacheWorkCompletion) {
        if envelope.work_item.is_some() || envelope.work.is_some() {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        let suspended = envelope.suspended.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        let completion = envelope.completion.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        (suspended, completion)
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the work queue transfers one raw stable envelope between the actor and callback"
)]
// SAFETY: Ownership is exclusive: actor -> work queue -> reactor inbox. Shared callback access is
// limited to the immutable reactor destination retained by the rundown lease.
unsafe impl Send for CacheWorkEnvelope {}

/// PASSIVE_LEVEL callback that executes one Cc/MM call and publishes its typed result.
/// # Safety
///
/// `device` and `context` must be the pair queued by [`CacheWorkEnvelope::queue`].
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the I/O Manager returns the unique raw cache work envelope supplied at queue time"
)]
unsafe extern "C" fn cache_work_item(device: wdk_sys::PDEVICE_OBJECT, context: wdk_sys::PVOID) {
    let envelope = NonNull::new(context.cast::<CacheWorkEnvelope>()).unwrap_or_else(|| {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
    });
    let envelope = unsafe {
        // SAFETY: Work-item ownership is unique until this callback publishes the envelope.
        envelope.as_ptr().as_mut()
    }
    .unwrap_or_else(|| KernelWideInconsistency::completion_reactor_state_corruption().bugcheck());
    if device != envelope.device.as_ptr() || envelope.completion.is_some() {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    }
    let work = envelope.work.take().unwrap_or_else(|| {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
    });
    envelope.completion = Some(work.execute());
    let work_item = envelope.work_item.take().unwrap_or_else(|| {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
    });
    unsafe {
        // SAFETY: The callback has consumed this dequeued work item and no later code uses it.
        ffi::IoFreeWorkItem(work_item.as_ptr());
    }
    let reactor = unsafe {
        // SAFETY: The envelope's rundown lease retains this stable completion destination.
        envelope.reactor.as_ref()
    };
    unsafe {
        // SAFETY: Callback transfers its unique, completed, unlinked envelope to the reactor.
        reactor.enqueue_cache_completion(NonNull::from(envelope));
    }
}
