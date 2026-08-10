//! Concrete top-level request operations advanced only by scheduler events.

use alloc::boxed::Box;
use core::ptr::NonNull;

use ext4_core::{EpochReadOperation, Error, OperationEvent, ReadTransition};

use crate::irp::reactor::{CompletionOperation, OperationTransition};
use crate::irp::{IrpCompletion, OwnedIrp};
use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::storage::{MountedStorageDevices, StorageFailureClass};
use crate::memory;
use crate::state::{EpochLease, MountedVolumeDevice, VolumeControlBlock};

/// Admission failure that preserves the unique top-level completion authority.
#[derive(Debug)]
pub(crate) struct AdmitOperationError {
    /// Normal driver error completed to the requestor.
    error: DriverError,
    /// IRP that never entered an active scheduler slot.
    owned: OwnedIrp,
}

impl AdmitOperationError {
    /// Builds an ownership-preserving admission failure.
    pub(crate) const fn new(error: DriverError, owned: OwnedIrp) -> Self {
        Self { error, owned }
    }

    /// Separates the error from terminal IRP ownership.
    pub(crate) fn into_parts(self) -> (DriverError, OwnedIrp) {
        (self.error, self.owned)
    }
}

/// Read-only request executed against one immutable epoch lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadRequestKind {
    /// Regular file data read.
    Read,
    /// File information query.
    QueryInformation,
    /// Directory enumeration query.
    QueryDirectory,
    /// Extended-attribute query.
    QueryEa,
    /// Security descriptor query.
    QuerySecurity,
}

/// Explicit ownership phase of one top-level read operation.
#[derive(Debug)]
enum ReadOperationState {
    /// IRP and transcript are available for one concrete event.
    Running {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Operation-owned storage transcript.
        read: EpochReadOperation,
    },
    /// Terminal completion consumed the IRP; only the box remains to be dropped.
    Terminal,
}

/// One restartable read operation over a fixed committed epoch.
#[derive(Debug)]
struct ReadRequestOperation {
    /// Mounted VCB retained by the admitted device/FILE_OBJECT lifetime.
    volume: NonNull<VolumeControlBlock>,
    /// Immutable epoch pinned independently from later checkpoint publication.
    epoch: EpochLease,
    /// Concrete mounted lower devices.
    devices: MountedStorageDevices,
    /// Request semantics selected from captured queue metadata.
    kind: ReadRequestKind,
    /// Explicit operation phase.
    state: ReadOperationState,
}

impl ReadRequestOperation {
    /// Allocates and initializes one read operation while preserving IRP ownership on failure.
    fn try_new(
        owned: OwnedIrp,
        kind: ReadRequestKind,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        let volume = match MountedVolumeDevice::vcb(owned.device()) {
            Some(volume) => volume,
            None => {
                return Err(AdmitOperationError::new(
                    DriverError::InvalidDeviceRequest,
                    owned,
                ));
            }
        };
        let (epoch, devices, read) = {
            let mut access = unsafe {
                // SAFETY: Admission executes on the sole reactor thread and the mounted VCB is
                // stable until its reactor has drained every admitted operation.
                VolumeControlBlock::operation_access(volume)
            };
            let read = EpochReadOperation::new(access.runtime().profile());
            let devices = access.runtime().storage();
            let epoch = match access.runtime_mut().acquire_epoch() {
                Ok(epoch) => epoch,
                Err(error) => return Err(AdmitOperationError::new(error, owned)),
            };
            (epoch, devices, read)
        };
        match memory::boxed_try_map((owned, epoch), |(owned, epoch)| Self {
            volume,
            epoch,
            devices,
            kind,
            state: ReadOperationState::Running { owned, read },
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, (owned, _epoch)) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Executes the driver read surface for one ephemeral committed pass.
    fn execute_pass(
        kind: ReadRequestKind,
        owned: &mut OwnedIrp,
        read: &mut ext4_core::EpochReadPass<'_, '_, '_>,
    ) -> DriverResult<IrpCompletion> {
        match kind {
            ReadRequestKind::Read => crate::request::file_info::read(owned.request(), read),
            ReadRequestKind::QueryInformation => {
                crate::request::file_info::query(owned.request(), read)
            }
            ReadRequestKind::QueryDirectory => {
                crate::request::file_info::query_directory(owned.request(), read)
            }
            ReadRequestKind::QueryEa => crate::request::ea::query(owned.request(), read),
            ReadRequestKind::QuerySecurity => {
                crate::request::security::query(owned.request(), read)
            }
        }
    }

    /// Completes and consumes one terminal top-level IRP.
    fn complete(owned: OwnedIrp, result: DriverResult<IrpCompletion>) -> OperationTransition {
        let _status = owned.complete_result(result);
        OperationTransition::Complete
    }
}

impl CompletionOperation for ReadRequestOperation {
    fn advance(mut self: Box<Self>, event: OperationEvent) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, ReadOperationState::Terminal);
        let ReadOperationState::Running { mut owned, read } = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        let kind = self.kind;
        let transition = read.run(event, self.epoch.epoch(), |pass| {
            match Self::execute_pass(kind, &mut owned, pass) {
                Err(DriverError::Core(Error::OperationSuspended)) => Err(Error::OperationSuspended),
                result => Ok(result),
            }
        });
        match transition {
            ReadTransition::SubmitLower { request, suspended } => {
                self.state = ReadOperationState::Running {
                    owned,
                    read: suspended,
                };
                OperationTransition::SubmitLower {
                    devices: self.devices,
                    request,
                    suspended: self,
                }
            }
            ReadTransition::Complete(Ok(result)) => Self::complete(owned, result),
            ReadTransition::Complete(Err(error)) => {
                Self::complete(owned, Err(DriverError::from(error)))
            }
        }
    }

    fn record_storage_failure(&mut self, failure: StorageFailureClass) {
        if failure == StorageFailureClass::DurabilityUnknown {
            let mut access = unsafe {
                // SAFETY: Failure classification executes on the sole reactor thread while this
                // operation retains the mounted VCB lifetime.
                VolumeControlBlock::operation_access(self.volume)
            };
            access.runtime_mut().record_durability_unknown();
        }
    }
}

// SAFETY: The VCB and epoch remain stable until reactor drain, and the unique IRP moves only
// between this box and completion envelopes.
unsafe impl Send for ReadRequestOperation {}

/// Synchronous request kinds that require no lower-storage state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImmediateRequestKind {
    /// Volume information query from already committed runtime state.
    QueryVolumeInformation,
    /// Terminal FILE_OBJECT close.
    Close,
}

/// Explicit state of one immediate top-level operation.
#[derive(Debug)]
enum ImmediateOperationState {
    /// IRP is available for its sole admitted event.
    Ready(OwnedIrp),
    /// IRP completion was consumed.
    Terminal,
}

/// One request that completes in a single reactor transition.
#[derive(Debug)]
struct ImmediateRequestOperation {
    /// Concrete request semantics.
    kind: ImmediateRequestKind,
    /// Explicit ownership phase.
    state: ImmediateOperationState,
}

impl ImmediateRequestOperation {
    /// Allocates an immediate operation without losing IRP completion authority on OOM.
    fn try_new(
        owned: OwnedIrp,
        kind: ImmediateRequestKind,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        match memory::boxed_try_map(owned, |owned| Self {
            kind,
            state: ImmediateOperationState::Ready(owned),
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, owned) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }
}

impl CompletionOperation for ImmediateRequestOperation {
    fn advance(mut self: Box<Self>, event: OperationEvent) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, ImmediateOperationState::Terminal);
        let ImmediateOperationState::Ready(mut owned) = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        let result = match event {
            OperationEvent::Admitted => match self.kind {
                ImmediateRequestKind::QueryVolumeInformation => {
                    crate::request::volume_info::query(owned.request())
                }
                ImmediateRequestKind::Close => owned
                    .request()
                    .with_active(crate::request::file_info::close),
            },
            OperationEvent::CancelRequested => Err(DriverError::from(Error::OperationCancelled)),
            OperationEvent::StorageCompleted(_)
            | OperationEvent::RetryElapsed(_)
            | OperationEvent::IntentGranted(_)
            | OperationEvent::CommitGranted(_)
            | OperationEvent::VisibilityGranted(_)
            | OperationEvent::CheckpointGranted(_)
            | OperationEvent::BarrierReleased(_) => Err(DriverError::InternalInvariantViolation),
        };
        let _status = owned.complete_result(result);
        OperationTransition::Complete
    }

    fn record_storage_failure(&mut self, _failure: StorageFailureClass) {
        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
            .bugcheck();
    }
}

// SAFETY: Unique IRP authority is moved only by the reactor thread.
unsafe impl Send for ImmediateRequestOperation {}

/// Allocates one concrete read operation.
pub(crate) fn read(
    owned: OwnedIrp,
    kind: ReadRequestKind,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    ReadRequestOperation::try_new(owned, kind)
}

/// Allocates one concrete single-transition operation.
pub(crate) fn immediate(
    owned: OwnedIrp,
    kind: ImmediateRequestKind,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    ImmediateRequestOperation::try_new(owned, kind)
}
