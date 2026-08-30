//! Concrete top-level request operations advanced only by scheduler events.

use alloc::boxed::Box;
use ext4_core::{
    CleanCloseOperation, CleanCloseTransition, CleanJournalDurability, CommitDurability,
    CommitReadyMutation, CompletedStorageTransfer, DurableMutation, EpochReadOperation, Error,
    ExternalJournalProbeOperation, ExternalJournalProbeOutcome, ExternalJournalProbeTransition,
    ExternalJournalRequirement, FscryptKeySet, HomeBlockDurability, JournalPayloadDurability,
    MountOperation, MountTransition, MutationResolveOperation, MutationResolveTransition,
    OperationEvent, OrderedDataDurability, ReadTransition, ReservedMutation, ResolvedMutation,
    StorageRequest, StorageRequestIdentity, StorageRequestSequence, StorageRequestSequenceStep,
};
use wdk_sys::STATUS_SUCCESS;

use crate::irp::reactor::{
    CLEANUP_HANDLE_BARRIER, CLOSE_HANDLE_BARRIER, CompletionEvent, CompletionOperation,
    ControlDeviceOperation, InfalliblePublication, IntentRequest, MountedVolumeOperation,
    OperationTransition, PublicationAuthority, ReactorTarget, WaitCondition,
};
use crate::irp::{
    AtomicOplockReservation, CreateCompletion, IrpCompletion, OplockCheck, OplockContinuation,
    OwnedIrp,
};
use crate::kernel::cng::CngOperation;
use crate::kernel::external_journal::{ExclusiveExternalJournal, ExternalJournalCandidates};
use crate::kernel::ffi;
use crate::kernel::operational_trace::{OperationalOutcome, OperationalPath, OperationalTrace};
use crate::kernel::status::{DriverError, DriverResult, STATUS_FILE_LOCK_CONFLICT, STATUS_RETRY};
use crate::kernel::storage::{
    ExternalJournalLease, LowerStorageDevice, MountedStorage, MountedStorageRoute,
    StorageFailureClass,
};
use crate::memory;
use crate::request::file_system_control::MountAdmission;
use crate::state::{
    EpochLease, EpochPublicationSlot, EpochPublicationSlots, MountedVolumeAccess,
    MountedVolumeDevice, MountedVolumeDeviceExtension, MutationActivityLease, PendingCheckpoint,
    PreparedVolumeStateTransition, RawVolumeOperationKind, RawVolumeTarget, VolumeControlBlock,
};

/// Faults the mounted mutation authority only for real Cc/MM failures, not ordinary conflicts or
/// the internal stale-plan restart signal.
fn record_cache_coherency_failure(error: DriverError, access: &mut MountedVolumeAccess<'_>) {
    if let DriverError::CacheManagerFailure(status) = error
        && status != wdk_sys::STATUS_USER_MAPPED_FILE
        && status != STATUS_FILE_LOCK_CONFLICT
        && status != STATUS_RETRY
    {
        access.record_cache_writeback_failure(status);
    }
}

/// Implements the shell adapter that alone projects a mounted-volume access capability.
macro_rules! impl_mounted_operation_adapter {
    ($operation:ty) => {
        impl CompletionOperation for $operation {
            fn advance(
                self: Box<Self>,
                event: CompletionEvent,
                target: &mut ReactorTarget,
            ) -> OperationTransition {
                target.with_mounted_access(|access| self.advance_mounted(event, access))
            }

            fn record_storage_failure(
                &mut self,
                failure: StorageFailureClass,
                target: &mut ReactorTarget,
            ) {
                target.with_mounted_access(|access| {
                    self.record_mounted_storage_failure(failure, access);
                });
            }
        }
    };
}

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

/// Explicit ownership phase of one mount request.
#[derive(Debug)]
enum MountRequestState {
    /// The mount IRP retains its VPB while a private length query is constructed.
    QueryLength {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Stable kernel identities captured from the mount stack.
        admission: MountAdmission,
    },
    /// Core mount resolution or recovery I/O owns the next concrete event.
    Mounting {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Stable kernel identities captured from the mount stack.
        admission: MountAdmission,
        /// Concrete lower storage geometry used by core requests.
        devices: MountedStorage,
        /// Suspended consuming core mount operation.
        mount: Box<MountOperation>,
    },
    /// One shared candidate awaits its device-length completion.
    DiscoveringCandidateLength {
        /// Discovery ownership shared by every candidate phase.
        context: ExternalMountContext,
    },
    /// Core validation of one shared candidate owns the next lower completion.
    DiscoveringCandidateProbe {
        /// Discovery ownership shared by every candidate phase.
        context: ExternalMountContext,
        /// Candidate geometry used only for this shared probe.
        candidate: LowerStorageDevice,
        /// Suspended core candidate validator.
        probe: Box<ExternalJournalProbeOperation>,
    },
    /// The unique matching interface has been reopened exclusively and awaits its length.
    QueryExclusiveJournalLength {
        /// Top-level mount IRP.
        owned: OwnedIrp,
        /// Stable mount admission identities.
        admission: MountAdmission,
        /// Primary storage owner, not yet carrying the external lease.
        devices: MountedStorage,
        /// Core mount suspended in `AwaitingExternal`.
        mount: Box<MountOperation>,
        /// Exact filesystem-derived validation requirement.
        requirement: ExternalJournalRequirement,
        /// Exclusive handle and referenced file object.
        external: ExclusiveExternalJournal,
    },
    /// The exclusive device is being revalidated before its token may enter the mount.
    ProbingExclusiveJournal {
        /// Complete ownership suspended across exclusive core validation.
        context: ExclusiveExternalProbeContext,
        /// Suspended core validator over the exclusive device.
        probe: Box<ExternalJournalProbeOperation>,
    },
    /// Terminal completion consumed the mount IRP.
    Terminal,
}

/// Shared ownership carried while all distinct volume candidates are probed.
#[derive(Debug)]
struct ExternalMountContext {
    /// Unique top-level mount completion authority.
    owned: OwnedIrp,
    /// Stable filesystem device and VPB identities.
    admission: MountAdmission,
    /// Primary storage lifetime owner.
    devices: MountedStorage,
    /// Core mount suspended at external-journal discovery.
    mount: Box<MountOperation>,
    /// Exact filesystem-derived UUID/profile/user requirement.
    requirement: ExternalJournalRequirement,
    /// Deduplicated shared-open candidate set.
    candidates: ExternalJournalCandidates,
    /// Candidate whose length or core probe is currently active.
    candidate_index: usize,
}

/// Ownership retained while the unique share-zero journal is revalidated by core.
#[derive(Debug)]
struct ExclusiveExternalProbeContext {
    /// Unique top-level mount completion authority.
    owned: OwnedIrp,
    /// Stable filesystem device and VPB identities.
    admission: MountAdmission,
    /// Primary storage lifetime owner, not yet carrying the external lease.
    devices: MountedStorage,
    /// Core mount suspended at external-journal discovery.
    mount: Box<MountOperation>,
    /// Lower route with an already validated device length.
    external: LowerStorageDevice,
    /// Unique share-zero handle and referenced FILE_OBJECT.
    lease: ExternalJournalLease,
}

/// Mount admission driven entirely by private-IRP completion events.
#[derive(Debug)]
struct MountRequestOperation {
    /// Current consuming ownership phase.
    state: MountRequestState,
    /// Driver-lifetime event capability propagated into the mounted VCB and its streams.
    trace: OperationalTrace,
}

impl MountRequestOperation {
    /// Allocates one mount state machine without dropping the IRP on allocation failure.
    /// # Errors
    ///
    /// Returns the still-owned IRP when operation storage cannot be allocated.
    fn try_new(
        owned: OwnedIrp,
        admission: MountAdmission,
        trace: OperationalTrace,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        match memory::boxed_try_map((owned, admission, trace), |(owned, admission, trace)| {
            Self {
                state: MountRequestState::QueryLength { owned, admission },
                trace,
            }
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, (owned, _admission, _trace)) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Completes and consumes the top-level mount IRP.
    fn complete(owned: OwnedIrp, result: DriverResult<IrpCompletion>) -> OperationTransition {
        let _status = owned.complete_result(result);
        OperationTransition::Complete
    }

    /// Converts a core mount transition into its matching reactor action.
    fn drive_mount(
        mut self: Box<Self>,
        owned: OwnedIrp,
        admission: MountAdmission,
        devices: MountedStorage,
        transition: MountTransition,
    ) -> OperationTransition {
        match transition {
            MountTransition::SubmitLower { request, suspended } => {
                let route = devices.route();
                self.state = MountRequestState::Mounting {
                    owned,
                    admission,
                    devices,
                    mount: suspended,
                };
                OperationTransition::SubmitLower {
                    devices: route,
                    request,
                    suspended: self,
                }
            }
            MountTransition::DiscoverExternalJournal {
                requirement,
                suspended,
            } => {
                let candidates =
                    match ExternalJournalCandidates::enumerate(admission.target_device()) {
                        Ok(candidates) => candidates,
                        Err(error) => return Self::complete(owned, Err(error)),
                    };
                let context = ExternalMountContext {
                    owned,
                    admission,
                    devices,
                    mount: suspended,
                    requirement,
                    candidates,
                    candidate_index: 0,
                };
                self.query_next_external_candidate(context)
            }
            MountTransition::Complete(Ok(completed)) => Self::complete(
                owned,
                Self::publish_mount(admission, devices, completed, self.trace),
            ),
            MountTransition::Complete(Err(Error::InvalidMagic | Error::InvalidSuperblock)) => {
                Self::complete(owned, Err(DriverError::UnrecognizedVolume))
            }
            MountTransition::Complete(Err(error)) => {
                Self::complete(owned, Err(DriverError::from(error)))
            }
        }
    }

    /// Starts the next shared probe, or converts the unique shared match into an exclusive reopen.
    fn query_next_external_candidate(
        mut self: Box<Self>,
        context: ExternalMountContext,
    ) -> OperationTransition {
        if context.candidate_index < context.candidates.len() {
            let Some(target) = context.candidates.device(context.candidate_index) else {
                return Self::complete(context.owned, Err(DriverError::InternalInvariantViolation));
            };
            let completion_owner = context.admission.file_system_device();
            self.state = MountRequestState::DiscoveringCandidateLength { context };
            OperationTransition::QueryDeviceLength {
                completion_owner,
                target,
                suspended: self,
            }
        } else {
            let ExternalMountContext {
                owned,
                admission,
                devices,
                mount,
                requirement,
                candidates,
                candidate_index: _,
            } = context;
            let selected = match candidates.into_selected() {
                Ok(selected) => selected,
                Err(error) => return Self::complete(owned, Err(error)),
            };
            let external = match ExclusiveExternalJournal::open(selected) {
                Ok(external) => external,
                Err(error) => return Self::complete(owned, Err(error)),
            };
            let completion_owner = admission.file_system_device();
            let target = external.device();
            self.state = MountRequestState::QueryExclusiveJournalLength {
                owned,
                admission,
                devices,
                mount,
                requirement,
                external,
            };
            OperationTransition::QueryDeviceLength {
                completion_owner,
                target,
                suspended: self,
            }
        }
    }

    /// Converts one shared core-probe transition into a lower request or the next candidate.
    fn drive_shared_external_probe(
        mut self: Box<Self>,
        mut context: ExternalMountContext,
        candidate: LowerStorageDevice,
        transition: ExternalJournalProbeTransition,
    ) -> OperationTransition {
        match transition {
            ExternalJournalProbeTransition::SubmitLower { request, suspended } => {
                let route = context.devices.route().with_external(candidate);
                self.state = MountRequestState::DiscoveringCandidateProbe {
                    context,
                    candidate,
                    probe: suspended,
                };
                OperationTransition::SubmitLower {
                    devices: route,
                    request,
                    suspended: self,
                }
            }
            ExternalJournalProbeTransition::Complete(Ok(outcome)) => {
                let record_result = match outcome {
                    ExternalJournalProbeOutcome::Match(_) => {
                        context.candidates.record_match(context.candidate_index)
                    }
                    ExternalJournalProbeOutcome::Mismatch => Ok(()),
                };
                if let Err(error) = record_result {
                    return Self::complete(context.owned, Err(error));
                }
                context.candidate_index = match context.candidate_index.checked_add(1) {
                    Some(next) => next,
                    None => {
                        return Self::complete(
                            context.owned,
                            Err(DriverError::InternalInvariantViolation),
                        );
                    }
                };
                self.query_next_external_candidate(context)
            }
            ExternalJournalProbeTransition::Complete(Err(error)) => {
                Self::complete(context.owned, Err(DriverError::from(error)))
            }
        }
    }

    /// Converts the exclusive revalidation transition into mount attachment or a lower request.
    fn drive_exclusive_external_probe(
        mut self: Box<Self>,
        context: ExclusiveExternalProbeContext,
        transition: ExternalJournalProbeTransition,
    ) -> OperationTransition {
        match transition {
            ExternalJournalProbeTransition::SubmitLower { request, suspended } => {
                let route = context.devices.route().with_external(context.external);
                self.state = MountRequestState::ProbingExclusiveJournal {
                    context,
                    probe: suspended,
                };
                OperationTransition::SubmitLower {
                    devices: route,
                    request,
                    suspended: self,
                }
            }
            ExternalJournalProbeTransition::Complete(Ok(ExternalJournalProbeOutcome::Match(
                validated,
            ))) => {
                let devices = context
                    .devices
                    .with_external(context.external, context.lease);
                let transition = context.mount.attach_external_journal(validated);
                self.drive_mount(context.owned, context.admission, devices, transition)
            }
            ExternalJournalProbeTransition::Complete(Ok(ExternalJournalProbeOutcome::Mismatch)) => {
                Self::complete(
                    context.owned,
                    Err(DriverError::ExternalJournalExclusiveOpenFailed),
                )
            }
            ExternalJournalProbeTransition::Complete(Err(error)) => {
                Self::complete(context.owned, Err(DriverError::from(error)))
            }
        }
    }

    /// Publishes a fully mounted VCB and device after every core recovery action is complete.
    /// # Errors
    ///
    /// Returns an error when VCB/provider allocation, notifier or device initialization, or WDK
    /// publication fails.
    #[expect(
        unsafe_code,
        reason = "mount publication owns the audited IoCreateDevice and unpublished-device rollback boundary"
    )]
    fn publish_mount(
        admission: MountAdmission,
        devices: MountedStorage,
        completed: Box<ext4_core::CompletedMount>,
        trace: OperationalTrace,
    ) -> DriverResult<IrpCompletion> {
        let _output_buffer_length = admission.output_buffer_length().as_usize();
        let Some(driver_object) = admission.file_system_device().driver_object() else {
            return Err(DriverError::InvalidParameter);
        };
        let mut vcb = memory::boxed_try_with(move || {
            VolumeControlBlock::from_completed_mount(*completed, devices, trace)
        })?;
        vcb.bind_stream_owner()?;
        vcb.initialize_directory_change_notifier()?;

        let extension_size =
            wdk_sys::ULONG::try_from(core::mem::size_of::<MountedVolumeDeviceExtension>())
                .map_err(|_| DriverError::InvalidParameter)?;
        let mut device = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: The control device's driver object creates one unpublished mounted device;
            // `device` is writable out storage until this call returns.
            ffi::IoCreateDevice(
                driver_object,
                extension_size,
                core::ptr::null_mut(),
                ffi::FILE_DEVICE_DISK_FILE_SYSTEM,
                0,
                0,
                core::ptr::addr_of_mut!(device),
            )
        };
        if status < STATUS_SUCCESS {
            return Err(DriverError::InsufficientResources);
        }

        let Some(device) = (unsafe {
            // SAFETY: Successful IoCreateDevice returned this unpublished live mounted device.
            crate::state::KernelDevice::from_raw(device)
        }) else {
            return Err(DriverError::InternalInvariantViolation);
        };
        match MountedVolumeDevice::initialize(
            device,
            vcb,
            admission.vpb().as_non_null(),
            admission.target_device(),
        ) {
            Ok(()) => Ok(IrpCompletion::EMPTY),
            Err(error) => {
                unsafe {
                    // SAFETY: Initialization rejected the unpublished device and retained no VCB
                    // ownership in its extension.
                    ffi::IoDeleteDevice(device.as_ptr());
                }
                Err(error)
            }
        }
    }
}

impl ControlDeviceOperation for MountRequestOperation {
    fn advance_control(mut self: Box<Self>, event: OperationEvent) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, MountRequestState::Terminal);
        match state {
            MountRequestState::QueryLength { owned, admission } => match event {
                OperationEvent::Admitted => {
                    self.state = MountRequestState::QueryLength { owned, admission };
                    OperationTransition::QueryDeviceLength {
                        completion_owner: admission.file_system_device(),
                        target: admission.target_device(),
                        suspended: self,
                    }
                }
                OperationEvent::DeviceLengthCompleted(Ok(length)) => {
                    let filesystem =
                        match LowerStorageDevice::from_device(admission.target_device(), length) {
                            Ok(filesystem) => filesystem,
                            Err(error) => return Self::complete(owned, Err(error)),
                        };
                    let devices =
                        MountedStorage::primary(admission.file_system_device(), filesystem);
                    let mount = match memory::boxed_try_with(move || {
                        Ok(MountOperation::new(length, FscryptKeySet::empty()))
                    }) {
                        Ok(mount) => mount,
                        Err(error) => return Self::complete(owned, Err(error)),
                    };
                    let transition = mount.advance(OperationEvent::Admitted);
                    self.drive_mount(owned, admission, devices, transition)
                }
                OperationEvent::DeviceLengthCompleted(Err(error)) => {
                    Self::complete(owned, Err(DriverError::from(error)))
                }
                OperationEvent::CancelRequested => {
                    Self::complete(owned, Err(DriverError::from(Error::OperationCancelled)))
                }
                OperationEvent::StorageCompleted(_)
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::CheckpointGranted(_)
                | OperationEvent::BarrierReleased(_) => {
                    Self::complete(owned, Err(DriverError::InternalInvariantViolation))
                }
            },
            MountRequestState::Mounting {
                owned,
                admission,
                devices,
                mount,
            } => {
                let transition = mount.advance(event);
                self.drive_mount(owned, admission, devices, transition)
            }
            MountRequestState::DiscoveringCandidateLength { context } => match event {
                OperationEvent::DeviceLengthCompleted(Ok(length)) => {
                    let Some(device) = context.candidates.device(context.candidate_index) else {
                        return Self::complete(
                            context.owned,
                            Err(DriverError::InternalInvariantViolation),
                        );
                    };
                    let candidate = match LowerStorageDevice::from_device(device, length) {
                        Ok(candidate) => candidate,
                        Err(error) => return Self::complete(context.owned, Err(error)),
                    };
                    let probe = match memory::boxed_try_with(|| {
                        Ok(ExternalJournalProbeOperation::new(
                            context.requirement,
                            length,
                        ))
                    }) {
                        Ok(probe) => probe,
                        Err(error) => return Self::complete(context.owned, Err(error)),
                    };
                    let transition = probe.advance(OperationEvent::Admitted);
                    self.drive_shared_external_probe(context, candidate, transition)
                }
                OperationEvent::DeviceLengthCompleted(Err(error)) => {
                    Self::complete(context.owned, Err(DriverError::from(error)))
                }
                OperationEvent::CancelRequested => Self::complete(
                    context.owned,
                    Err(DriverError::from(Error::OperationCancelled)),
                ),
                _ => Self::complete(context.owned, Err(DriverError::InternalInvariantViolation)),
            },
            MountRequestState::DiscoveringCandidateProbe {
                context,
                candidate,
                probe,
            } => {
                let transition = probe.advance(event);
                self.drive_shared_external_probe(context, candidate, transition)
            }
            MountRequestState::QueryExclusiveJournalLength {
                owned,
                admission,
                devices,
                mount,
                requirement,
                external,
            } => match event {
                OperationEvent::DeviceLengthCompleted(Ok(length)) => {
                    let (external_device, lease) = external.into_parts();
                    let external = match LowerStorageDevice::from_device(external_device, length) {
                        Ok(external) => external,
                        Err(error) => return Self::complete(owned, Err(error)),
                    };
                    let probe = match memory::boxed_try_with(|| {
                        Ok(ExternalJournalProbeOperation::new(requirement, length))
                    }) {
                        Ok(probe) => probe,
                        Err(error) => return Self::complete(owned, Err(error)),
                    };
                    let transition = probe.advance(OperationEvent::Admitted);
                    self.drive_exclusive_external_probe(
                        ExclusiveExternalProbeContext {
                            owned,
                            admission,
                            devices,
                            mount,
                            external,
                            lease,
                        },
                        transition,
                    )
                }
                OperationEvent::DeviceLengthCompleted(Err(error)) => {
                    Self::complete(owned, Err(DriverError::from(error)))
                }
                OperationEvent::CancelRequested => {
                    Self::complete(owned, Err(DriverError::from(Error::OperationCancelled)))
                }
                _ => Self::complete(owned, Err(DriverError::InternalInvariantViolation)),
            },
            MountRequestState::ProbingExclusiveJournal { context, probe } => {
                let transition = probe.advance(event);
                self.drive_exclusive_external_probe(context, transition)
            }
            MountRequestState::Terminal => OperationTransition::Complete,
        }
    }

    fn record_control_storage_failure(&mut self, _failure: StorageFailureClass) {}
}

impl CompletionOperation for MountRequestOperation {
    fn advance(
        self: Box<Self>,
        event: CompletionEvent,
        target: &mut ReactorTarget,
    ) -> OperationTransition {
        target.require_control_device();
        self.advance_control(event.into_core())
    }

    fn record_storage_failure(&mut self, failure: StorageFailureClass, target: &mut ReactorTarget) {
        target.require_control_device();
        self.record_control_storage_failure(failure);
    }
}

#[expect(
    unsafe_code,
    reason = "the mount operation moves only through the reactor while its IRP pins kernel identities"
)]
// SAFETY: Stable kernel identities are pinned by the top-level mount IRP; the core operation and
// IRP move only by value between the reactor and nonpaged completion envelopes.
unsafe impl Send for MountRequestOperation {}

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
    /// Reparse-point FSCTL query.
    GetReparsePoint,
}

/// Read request after data-stream authority has been fixed at actor admission.
#[derive(Debug)]
enum PreparedReadRequest {
    /// Regular-file data read with handle or paging stream authority.
    Data(crate::request::file_info::RegularFileDataAuthority),
    /// Non-data read class whose existing handle/device authority remains sufficient.
    Other(ReadRequestKind),
}

impl PreparedReadRequest {
    /// Captures a paging stream lease before the operation may suspend or outlive CCB cleanup.
    /// # Errors
    ///
    /// Returns a stream-identity or lease failure for paging data reads.
    fn prepare(
        kind: ReadRequestKind,
        owned: &mut OwnedIrp,
        access: &MountedVolumeAccess<'_>,
    ) -> DriverResult<Self> {
        if kind == ReadRequestKind::Read {
            crate::request::file_info::prepare_regular_file_data_authority(owned.request(), access)
                .map(Self::Data)
        } else {
            Ok(Self::Other(kind))
        }
    }

    /// Reports whether the operation owns cleanup-independent paging stream authority.
    const fn is_paging(&self) -> bool {
        matches!(self, Self::Data(authority) if authority.is_paging())
    }
}

/// Explicit ownership phase of one top-level read operation.
#[derive(Debug)]
enum ReadOperationState {
    /// A non-paging data read is ready to transfer its IRP to the stream oplock package.
    CheckingOplock {
        /// Unique top-level completion authority before FsRtl delegation.
        owned: OwnedIrp,
        /// Operation-owned storage transcript that has not observed an epoch.
        read: EpochReadOperation,
        /// Stream lease and normalized check flags.
        check: OplockCheck,
    },
    /// FsRtl owns the data-read IRP during an oplock break wait.
    OplockDelegated {
        /// Operation-owned storage transcript retained without IRP completion authority.
        read: EpochReadOperation,
    },
    /// The reactor restored the data-read IRP after FsRtl completion.
    OplockReady {
        /// Unique top-level completion authority returned by FsRtl.
        owned: OwnedIrp,
        /// Operation-owned storage transcript that has not observed an epoch.
        read: EpochReadOperation,
        /// Exact immediate or callback-published oplock status.
        status: wdk_sys::NTSTATUS,
    },
    /// IRP and transcript are available for one concrete event.
    Running {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Operation-owned storage transcript.
        read: EpochReadOperation,
    },
    /// Cached read is executing outside the actor and retains its publication range.
    Cached {
        /// Unique top-level completion authority retaining the output mapping.
        owned: OwnedIrp,
        /// Validated start for synchronous position publication.
        start: ext4_core::FileOffset,
        /// Maximum Cache Manager transfer selected before submission.
        requested: usize,
    },
    /// Direct read waits for Cache Manager coherency before entering the ext4 read path.
    Purging {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Immutable read transcript retained without being advanced.
        read: EpochReadOperation,
    },
    /// Terminal completion consumed the IRP; only the box remains to be dropped.
    Terminal,
}

/// One restartable read operation over a fixed committed epoch.
#[derive(Debug)]
struct ReadRequestOperation {
    /// Immutable epoch pinned independently from later checkpoint publication.
    epoch: EpochLease,
    /// Concrete mounted lower devices.
    devices: MountedStorageRoute,
    /// Request semantics plus any paging stream lease captured at admission.
    request: PreparedReadRequest,
    /// Mutable CNG objects and work buffers owned across every read suspension.
    crypto: CngOperation,
    /// Explicit operation phase.
    state: ReadOperationState,
}

impl ReadRequestOperation {
    /// Captures the stream check required by a non-paging data read.
    /// # Errors
    ///
    /// Returns a FILE_OBJECT identity or finite stream-lease failure before the oplock package is
    /// invoked. Paging reads already own a cleanup-independent stream lease and do not break
    /// handle oplocks.
    fn prepare_oplock_check(
        request: &PreparedReadRequest,
        owned: &mut OwnedIrp,
        access: &MountedVolumeAccess<'_>,
    ) -> DriverResult<Option<OplockCheck>> {
        match request {
            PreparedReadRequest::Data(authority) if !authority.is_paging() => {
                owned.request().with_active(|active| {
                    let file_object = active.current_stack()?.file_object()?;
                    access
                        .acquire_oplock_stream_lease(file_object)
                        .map(OplockCheck::ordinary)
                        .map(Some)
                })
            }
            PreparedReadRequest::Data(_) | PreparedReadRequest::Other(_) => Ok(None),
        }
    }

    /// Allocates and initializes one read operation while preserving IRP ownership on failure.
    /// # Errors
    ///
    /// Returns the still-owned IRP when mounted-state lookup, crypto/epoch acquisition, or
    /// operation allocation fails.
    fn try_new(
        mut owned: OwnedIrp,
        kind: ReadRequestKind,
        access: &mut MountedVolumeAccess<'_>,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        let request = match PreparedReadRequest::prepare(kind, &mut owned, access) {
            Ok(request) => request,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        let oplock = match Self::prepare_oplock_check(&request, &mut owned, access) {
            Ok(oplock) => oplock,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        let paging = request.is_paging();
        let trace = access.operational_trace();
        let crypto = match access.new_crypto_operation() {
            Ok(crypto) => crypto,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        let read = EpochReadOperation::new(access.mounted_profile());
        let devices = access.storage_route();
        let epoch = match access.acquire_epoch() {
            Ok(epoch) => epoch,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        match memory::boxed_try_map(
            (owned, epoch, crypto, request, oplock),
            |(owned, epoch, crypto, request, oplock)| {
                let state = match oplock {
                    Some(check) => ReadOperationState::CheckingOplock { owned, read, check },
                    None => ReadOperationState::Running { owned, read },
                };
                Self {
                    epoch,
                    devices,
                    request,
                    crypto,
                    state,
                }
            },
        ) {
            Ok(operation) => {
                if paging {
                    trace.record(
                        OperationalPath::PagingRead,
                        STATUS_SUCCESS,
                        OperationalOutcome::Selected,
                    );
                }
                Ok(operation)
            }
            Err(error) => {
                let (error, (owned, _epoch, _crypto, _request, _oplock)) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Executes the driver read surface for one ephemeral committed pass.
    /// # Errors
    ///
    /// Returns an error from request decoding, ext4 reads, output serialization, or control-plane
    /// validation for the selected request kind.
    fn execute_pass(
        request: &PreparedReadRequest,
        owned: &mut OwnedIrp,
        access: &MountedVolumeAccess<'_>,
        read: &mut ext4_core::EpochReadPass<'_, '_, '_>,
    ) -> DriverResult<IrpCompletion> {
        match request {
            PreparedReadRequest::Data(authority) => {
                crate::request::file_info::read(owned.request(), read, authority)
            }
            PreparedReadRequest::Other(ReadRequestKind::QueryInformation) => {
                crate::request::file_info::query(owned.request(), read)
            }
            PreparedReadRequest::Other(ReadRequestKind::QueryDirectory) => {
                crate::request::file_info::query_directory(owned.request(), read)
            }
            PreparedReadRequest::Other(ReadRequestKind::QueryEa) => {
                crate::request::ea::query(owned.request(), read)
            }
            PreparedReadRequest::Other(ReadRequestKind::QuerySecurity) => {
                crate::request::security::query(owned.request(), read)
            }
            PreparedReadRequest::Other(ReadRequestKind::GetReparsePoint) => {
                let mut request = owned.request();
                crate::request::file_system_control::authorize_path_handle(&mut request, access)?;
                crate::request::reparse::get_reparse_point(request, read)
            }
            PreparedReadRequest::Other(ReadRequestKind::Read) => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }

    /// Completes and consumes one terminal top-level IRP.
    fn complete(owned: OwnedIrp, result: DriverResult<IrpCompletion>) -> OperationTransition {
        let _status = owned.complete_result(result);
        OperationTransition::Complete
    }

    /// Reacquires the current durable epoch after a native size gate invalidated a cache plan.
    fn restart_cache_plan(
        mut self: Box<Self>,
        owned: OwnedIrp,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let epoch = match access.acquire_epoch() {
            Ok(epoch) => epoch,
            Err(error) => return Self::complete(owned, Err(error)),
        };
        self.epoch = epoch;
        self.state = ReadOperationState::Running {
            owned,
            read: EpochReadOperation::new(access.mounted_profile()),
        };
        self.advance_mounted(CompletionEvent::Core(OperationEvent::Admitted), access)
    }
}

impl OplockContinuation for ReadRequestOperation {
    fn resume_after_oplock(
        mut self: Box<Self>,
        owned: OwnedIrp,
        status: wdk_sys::NTSTATUS,
    ) -> Box<dyn CompletionOperation> {
        let state = core::mem::replace(&mut self.state, ReadOperationState::Terminal);
        let ReadOperationState::OplockDelegated { read } = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        self.state = ReadOperationState::OplockReady {
            owned,
            read,
            status,
        };
        self
    }
}

impl MountedVolumeOperation for ReadRequestOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, ReadOperationState::Terminal);
        let state = match state {
            ReadOperationState::CheckingOplock { owned, read, check } => {
                return match event.into_core() {
                    OperationEvent::Admitted => {
                        self.state = ReadOperationState::OplockDelegated { read };
                        OperationTransition::CheckOplock {
                            check,
                            owned,
                            suspended: self,
                        }
                    }
                    OperationEvent::CancelRequested => {
                        Self::complete(owned, Err(DriverError::from(Error::OperationCancelled)))
                    }
                    OperationEvent::StorageCompleted(_)
                    | OperationEvent::DeviceLengthCompleted(_)
                    | OperationEvent::RetryElapsed(_)
                    | OperationEvent::IntentGranted(_)
                    | OperationEvent::CommitGranted(_)
                    | OperationEvent::VisibilityGranted(_)
                    | OperationEvent::CheckpointGranted(_)
                    | OperationEvent::BarrierReleased(_) => {
                        Self::complete(owned, Err(DriverError::InternalInvariantViolation))
                    }
                };
            }
            ReadOperationState::OplockReady {
                owned,
                read,
                status,
            } => {
                return match event.into_core() {
                    OperationEvent::Admitted if status >= STATUS_SUCCESS => {
                        let epoch = match access.acquire_epoch() {
                            Ok(epoch) => epoch,
                            Err(error) => return Self::complete(owned, Err(error)),
                        };
                        self.epoch = epoch;
                        self.state = ReadOperationState::Running { owned, read };
                        self.advance_mounted(
                            CompletionEvent::Core(OperationEvent::Admitted),
                            access,
                        )
                    }
                    OperationEvent::Admitted => {
                        Self::complete(owned, Err(DriverError::OplockFailure(status)))
                    }
                    OperationEvent::CancelRequested => {
                        Self::complete(owned, Err(DriverError::from(Error::OperationCancelled)))
                    }
                    OperationEvent::StorageCompleted(_)
                    | OperationEvent::DeviceLengthCompleted(_)
                    | OperationEvent::RetryElapsed(_)
                    | OperationEvent::IntentGranted(_)
                    | OperationEvent::CommitGranted(_)
                    | OperationEvent::VisibilityGranted(_)
                    | OperationEvent::CheckpointGranted(_)
                    | OperationEvent::BarrierReleased(_) => {
                        Self::complete(owned, Err(DriverError::InternalInvariantViolation))
                    }
                };
            }
            ReadOperationState::OplockDelegated { .. } => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
            state => state,
        };
        let (mut owned, read, event, cache_prepared) = match (state, event) {
            (
                ReadOperationState::Cached {
                    mut owned,
                    start,
                    requested,
                },
                CompletionEvent::CacheCompleted(crate::irp::CacheWorkCompletion::Read(result)),
            ) => {
                if result == Err(DriverError::CacheManagerFailure(STATUS_RETRY)) {
                    return self.restart_cache_plan(owned, access);
                } else {
                    let result = crate::request::file_info::finish_cached_read(
                        owned.request(),
                        start,
                        requested,
                        result,
                    );
                    return Self::complete(owned, result);
                }
            }
            (
                ReadOperationState::Purging { owned, read },
                CompletionEvent::CacheCompleted(crate::irp::CacheWorkCompletion::Purge(result)),
            ) => match result {
                Ok(()) => (owned, read, OperationEvent::Admitted, true),
                Err(DriverError::CacheManagerFailure(STATUS_RETRY)) => {
                    return self.restart_cache_plan(owned, access);
                }
                Err(error) => {
                    record_cache_coherency_failure(error, access);
                    return Self::complete(owned, Err(error));
                }
            },
            (ReadOperationState::Running { owned, read }, event) => {
                (owned, read, event.into_core(), false)
            }
            _ => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        };
        if !cache_prepared
            && matches!(event, OperationEvent::Admitted)
            && matches!(self.request, PreparedReadRequest::Data(_))
        {
            let PreparedReadRequest::Data(authority) = &self.request else {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            };
            let plan = match crate::request::file_info::prepare_read_cache_plan(
                owned.request(),
                authority,
                access,
            ) {
                Ok(plan) => plan,
                Err(error) => return Self::complete(owned, Err(error)),
            };
            match plan {
                crate::request::file_info::ReadCachePlan::Cached {
                    work,
                    start,
                    requested,
                } => {
                    self.state = ReadOperationState::Cached {
                        owned,
                        start,
                        requested,
                    };
                    return OperationTransition::SubmitCacheWork {
                        work,
                        suspended: self,
                    };
                }
                crate::request::file_info::ReadCachePlan::PurgeBeforeDirect(work) => {
                    self.state = ReadOperationState::Purging { owned, read };
                    return OperationTransition::SubmitCacheWork {
                        work,
                        suspended: self,
                    };
                }
                crate::request::file_info::ReadCachePlan::Direct => {}
            }
        }
        let request = &self.request;
        let transition =
            read.run(
                event,
                self.epoch.epoch(),
                &mut self.crypto,
                |pass| match Self::execute_pass(request, &mut owned, access, pass) {
                    Err(DriverError::Core(Error::OperationSuspended)) => {
                        Err(Error::OperationSuspended)
                    }
                    result => Ok(result),
                },
            );
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
            ReadTransition::Complete(Ok(result)) => {
                if self.request.is_paging() {
                    access
                        .operational_trace()
                        .record_result(OperationalPath::PagingRead, &result);
                }
                Self::complete(owned, result)
            }
            ReadTransition::Complete(Err(error)) => {
                let result = Err(DriverError::from(error));
                if self.request.is_paging() {
                    access
                        .operational_trace()
                        .record_result::<IrpCompletion>(OperationalPath::PagingRead, &result);
                }
                Self::complete(owned, result)
            }
        }
    }

    fn record_mounted_storage_failure(
        &mut self,
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    ) {
        if matches!(
            failure,
            StorageFailureClass::DurabilityUnknown { .. } | StorageFailureClass::ReadUnreliable
        ) {
            match failure {
                StorageFailureClass::ReadUnreliable => {
                    access.record_read_unreliable();
                }
                StorageFailureClass::DurabilityUnknown { .. } => {
                    access.record_durability_unknown();
                }
                StorageFailureClass::Terminal => {}
            }
        }
    }
}

#[expect(
    unsafe_code,
    reason = "the read operation moves only through the reactor while its VCB and epoch stay retained"
)]
// SAFETY: The VCB and epoch remain stable until reactor drain, and the unique IRP moves only
// between this box and completion envelopes.
unsafe impl Send for ReadRequestOperation {}

/// Explicit ownership phase of one direct-volume data request.
#[derive(Debug)]
enum RawVolumeOperationState {
    /// IRP target and request parameters have not yet been admitted.
    Ready(OwnedIrp),
    /// One whole-sector read or write is owned by the lower completion envelope.
    Transferring {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Direct-volume handle whose policy authorized the request.
        target: RawVolumeTarget,
        /// Position and completion payload prepared before lower I/O.
        publication: crate::request::file_info::RawVolumeTransferPublication,
        /// Exact lower completion identity.
        expected: StorageRequestIdentity,
        /// Whether the completed write requires a following device flush.
        write_through: bool,
    },
    /// A completed raw write waits for its required lower-device flush.
    Flushing {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Direct-volume handle whose write retry authority may be consumed.
        target: RawVolumeTarget,
        /// Position and completion payload retained until the flush succeeds.
        publication: crate::request::file_info::RawVolumeTransferPublication,
        /// Bytes already written before this durability barrier.
        completed: usize,
        /// Exact lower flush completion identity.
        expected: StorageRequestIdentity,
    },
    /// Terminal completion consumed the IRP.
    Terminal,
}

/// Lower-storage operation for direct-volume reads and dismounted raw writes.
#[derive(Debug)]
struct RawVolumeOperation {
    /// Data operation selected from the captured major function.
    kind: RawVolumeOperationKind,
    /// Mounted lower device route retained independently from the ext4 epoch.
    devices: MountedStorageRoute,
    /// Write-only operational event capability inherited from the mounted volume.
    trace: OperationalTrace,
    /// Machine-readable failure selected before the synthetic failed completion arrives.
    lower_failure: Option<StorageFailureClass>,
    /// Current consuming ownership phase.
    state: RawVolumeOperationState,
}

impl RawVolumeOperation {
    /// Allocates one raw-volume operation while preserving IRP completion ownership on OOM.
    /// # Errors
    ///
    /// Returns the still-owned IRP when operation allocation fails.
    fn try_new(
        owned: OwnedIrp,
        kind: RawVolumeOperationKind,
        access: &MountedVolumeAccess<'_>,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        let devices = access.storage_route();
        let trace = access.operational_trace();
        let path = match kind {
            RawVolumeOperationKind::Read => OperationalPath::RawRead,
            RawVolumeOperationKind::Write => OperationalPath::RawWrite,
        };
        match memory::boxed_try_map((owned, kind), |(owned, kind)| Self {
            kind,
            devices,
            trace,
            lower_failure: None,
            state: RawVolumeOperationState::Ready(owned),
        }) {
            Ok(operation) => {
                trace.record(path, STATUS_SUCCESS, OperationalOutcome::Selected);
                Ok(operation)
            }
            Err(error) => {
                let (error, (owned, _kind)) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Completes and consumes one terminal raw-volume IRP.
    fn complete(
        &self,
        owned: OwnedIrp,
        result: DriverResult<IrpCompletion>,
    ) -> OperationTransition {
        self.trace.record_result(
            match self.kind {
                RawVolumeOperationKind::Read => OperationalPath::RawRead,
                RawVolumeOperationKind::Write => OperationalPath::RawWrite,
            },
            &result,
        );
        let _status = owned.complete_result(result);
        OperationTransition::Complete
    }

    /// Completes an IRP whose committed-progress wrapper does not expose its terminal status.
    fn complete_with_status(
        &self,
        owned: OwnedIrp,
        result: DriverResult<IrpCompletion>,
        status: wdk_sys::NTSTATUS,
    ) -> OperationTransition {
        self.trace.record_status(
            match self.kind {
                RawVolumeOperationKind::Read => OperationalPath::RawRead,
                RawVolumeOperationKind::Write => OperationalPath::RawWrite,
            },
            status,
        );
        let _completion_status = owned.complete_result(result);
        OperationTransition::Complete
    }

    /// Completes a failed transfer while preserving lower-reported partial write progress.
    fn complete_transfer_failure(&mut self, owned: OwnedIrp, error: Error) -> OperationTransition {
        match self.lower_failure.take() {
            Some(StorageFailureClass::DurabilityUnknown { completed }) => {
                match IrpCompletion::from_usize(completed) {
                    Ok(completion) => self.complete_with_status(
                        owned,
                        Ok(completion.committed_failure(DriverError::RawOutcomeUncertain)),
                        DriverError::RawOutcomeUncertain.ntstatus(),
                    ),
                    Err(error) => self.complete(owned, Err(error)),
                }
            }
            Some(StorageFailureClass::Terminal | StorageFailureClass::ReadUnreliable) | None => {
                self.complete(owned, Err(DriverError::from(error)))
            }
        }
    }
}

impl MountedVolumeOperation for RawVolumeOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let event = event.into_core();
        let state = core::mem::replace(&mut self.state, RawVolumeOperationState::Terminal);
        match state {
            RawVolumeOperationState::Ready(mut owned) => match event {
                OperationEvent::Admitted => {
                    let prepared = match crate::request::file_info::prepare_raw_volume_transfer(
                        owned.request(),
                        self.kind,
                        access,
                    ) {
                        Ok(prepared) => prepared,
                        Err(error) => return self.complete(owned, Err(error)),
                    };
                    let Some(prepared) = prepared else {
                        return self.complete(owned, Ok(IrpCompletion::EMPTY));
                    };
                    let (target, request, publication, write_through) = prepared.into_parts();
                    let expected = StorageRequestIdentity::from_request(&request);
                    self.state = RawVolumeOperationState::Transferring {
                        owned,
                        target,
                        publication,
                        expected,
                        write_through,
                    };
                    OperationTransition::SubmitLower {
                        devices: self.devices,
                        request,
                        suspended: self,
                    }
                }
                OperationEvent::CancelRequested => {
                    self.complete(owned, Err(DriverError::from(Error::OperationCancelled)))
                }
                OperationEvent::StorageCompleted(_)
                | OperationEvent::DeviceLengthCompleted(_)
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::CheckpointGranted(_)
                | OperationEvent::BarrierReleased(_) => {
                    self.complete(owned, Err(DriverError::InternalInvariantViolation))
                }
            },
            RawVolumeOperationState::Transferring {
                mut owned,
                target,
                publication,
                expected,
                write_through,
            } => {
                if matches!(event, OperationEvent::CancelRequested) {
                    return self.complete(owned, Err(DriverError::from(Error::OperationCancelled)));
                }
                let OperationEvent::StorageCompleted(completion) = event else {
                    return self.complete(owned, Err(DriverError::InternalInvariantViolation));
                };
                let transfer = match expected.complete_transfer(completion) {
                    Ok(transfer) => transfer,
                    Err(error) => {
                        return self.complete_transfer_failure(owned, error);
                    }
                };
                match (self.kind, transfer) {
                    (
                        RawVolumeOperationKind::Read,
                        CompletedStorageTransfer::Read { buffer, .. },
                    ) => {
                        let completion = crate::request::file_info::finish_raw_volume_read(
                            owned.request(),
                            publication,
                            &buffer,
                        );
                        self.complete(owned, completion)
                    }
                    (
                        RawVolumeOperationKind::Write,
                        CompletedStorageTransfer::Write { buffer, .. },
                    ) if write_through => {
                        let completed = buffer.len();
                        let request = StorageRequest::Flush {
                            target: ext4_core::StorageTarget::Filesystem,
                        };
                        let expected = StorageRequestIdentity::from_request(&request);
                        self.trace.record(
                            OperationalPath::RawFlush,
                            STATUS_SUCCESS,
                            OperationalOutcome::Selected,
                        );
                        self.state = RawVolumeOperationState::Flushing {
                            owned,
                            target,
                            publication,
                            completed,
                            expected,
                        };
                        OperationTransition::SubmitLower {
                            devices: self.devices,
                            request,
                            suspended: self,
                        }
                    }
                    (RawVolumeOperationKind::Write, CompletedStorageTransfer::Write { .. }) => {
                        self.complete(owned, Ok(publication.publish()))
                    }
                    (RawVolumeOperationKind::Read, CompletedStorageTransfer::Write { .. })
                    | (RawVolumeOperationKind::Write, CompletedStorageTransfer::Read { .. })
                    | (_, CompletedStorageTransfer::Flush { .. }) => {
                        self.complete(owned, Err(DriverError::InternalInvariantViolation))
                    }
                }
            }
            RawVolumeOperationState::Flushing {
                owned,
                target,
                publication,
                completed,
                expected,
            } => {
                let OperationEvent::StorageCompleted(completion) = event else {
                    target.mark_write_uncertain(completed);
                    self.trace.record_status(
                        OperationalPath::RawFlush,
                        DriverError::RawOutcomeUncertain.ntstatus(),
                    );
                    return self.complete_with_status(
                        owned,
                        Ok(publication.committed_failure(DriverError::RawOutcomeUncertain)),
                        DriverError::RawOutcomeUncertain.ntstatus(),
                    );
                };
                match expected.complete(completion) {
                    Ok(()) => {
                        self.trace
                            .record_status(OperationalPath::RawFlush, STATUS_SUCCESS);
                        self.complete(owned, Ok(publication.publish()))
                    }
                    Err(_error) => {
                        target.mark_write_uncertain(completed);
                        self.trace.record_status(
                            OperationalPath::RawFlush,
                            DriverError::RawOutcomeUncertain.ntstatus(),
                        );
                        self.complete_with_status(
                            owned,
                            Ok(publication.committed_failure(DriverError::RawOutcomeUncertain)),
                            DriverError::RawOutcomeUncertain.ntstatus(),
                        )
                    }
                }
            }
            RawVolumeOperationState::Terminal => OperationTransition::Complete,
        }
    }

    fn record_mounted_storage_failure(
        &mut self,
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    ) {
        self.lower_failure = Some(failure);
        match failure {
            StorageFailureClass::ReadUnreliable => access.record_read_unreliable(),
            StorageFailureClass::DurabilityUnknown { completed } => match &self.state {
                RawVolumeOperationState::Transferring { target, .. } => {
                    target.mark_write_uncertain(completed);
                }
                RawVolumeOperationState::Flushing {
                    target, completed, ..
                } => {
                    target.mark_write_uncertain(*completed);
                }
                RawVolumeOperationState::Ready(_) | RawVolumeOperationState::Terminal => {
                    access.record_durability_unknown();
                }
            },
            StorageFailureClass::Terminal => {}
        }
    }
}

#[expect(
    unsafe_code,
    reason = "the raw operation moves through the reactor while its FILE_OBJECT CCB remains live"
)]
// SAFETY: The top-level IRP retains the direct-volume FILE_OBJECT and its CCB until completion;
// operation state moves only through the sole reactor and stable lower completion envelopes.
unsafe impl Send for RawVolumeOperation {}

/// Synchronous request kinds that require no lower-storage state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImmediateRequestKind {
    /// Volume information query from already committed runtime state.
    QueryVolumeInformation,
    /// Terminal FILE_OBJECT close.
    Close,
    /// Fscrypt key-status query from the committed epoch snapshot.
    GetEncryptionKeyStatus,
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
    /// CLOSE alone consumes one terminal barrier before touching FILE_OBJECT contexts.
    close_barrier_released: bool,
}

impl ImmediateRequestOperation {
    /// Allocates an immediate operation without losing IRP completion authority on OOM.
    /// # Errors
    ///
    /// Returns the still-owned IRP when operation storage cannot be allocated.
    fn try_new(
        owned: OwnedIrp,
        kind: ImmediateRequestKind,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        match memory::boxed_try_map(owned, |owned| Self {
            kind,
            state: ImmediateOperationState::Ready(owned),
            close_barrier_released: false,
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, owned) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }
}

impl MountedVolumeOperation for ImmediateRequestOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let event = event.into_core();
        let state = core::mem::replace(&mut self.state, ImmediateOperationState::Terminal);
        let ImmediateOperationState::Ready(mut owned) = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        let event = if self.kind == ImmediateRequestKind::Close && !self.close_barrier_released {
            match event {
                OperationEvent::Admitted => {
                    self.state = ImmediateOperationState::Ready(owned);
                    return OperationTransition::Wait {
                        condition: WaitCondition::Barrier {
                            identity: CLOSE_HANDLE_BARRIER,
                        },
                        suspended: self,
                    };
                }
                OperationEvent::BarrierReleased(permit) => {
                    if permit.into_identity() != CLOSE_HANDLE_BARRIER {
                        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                            .bugcheck();
                    }
                    self.close_barrier_released = true;
                    OperationEvent::Admitted
                }
                _ => {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                        .bugcheck()
                }
            }
        } else {
            event
        };
        let result = match event {
            OperationEvent::Admitted => match self.kind {
                ImmediateRequestKind::QueryVolumeInformation => {
                    crate::request::volume_info::query(owned.request(), access)
                }
                ImmediateRequestKind::Close => owned
                    .request()
                    .with_active(|active| crate::request::file_info::close(active, access)),
                ImmediateRequestKind::GetEncryptionKeyStatus => (|| {
                    let mut request = owned.request();
                    crate::request::file_system_control::authorize_path_handle(
                        &mut request,
                        access,
                    )?;
                    let stack = request
                        .with_active(|active| active.current_stack()?.file_system_control())?;
                    crate::request::fsctl::get_encryption_key_status(&mut request, stack, access)
                })(),
            },
            OperationEvent::CancelRequested => Err(DriverError::from(Error::OperationCancelled)),
            OperationEvent::StorageCompleted(_)
            | OperationEvent::DeviceLengthCompleted(_)
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

    fn record_mounted_storage_failure(
        &mut self,
        _failure: StorageFailureClass,
        _access: &mut MountedVolumeAccess<'_>,
    ) {
        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
            .bugcheck();
    }
}

#[expect(
    unsafe_code,
    reason = "the immediate operation's unique IRP authority moves only on the reactor thread"
)]
// SAFETY: Unique IRP authority is moved only by the reactor thread.
unsafe impl Send for ImmediateRequestOperation {}

/// Explicit ownership phase of a directory-change delegation.
#[derive(Debug)]
enum NotificationOperationState {
    /// The IRP remains ext4win-owned until its admitted event transfers it to FsRtl.
    Ready(OwnedIrp),
    /// FsRtl or terminal completion owns the IRP.
    Terminal,
}

/// One directory notification whose terminal ownership is delegated exactly once.
#[derive(Debug)]
struct NotificationOperation {
    /// Current IRP authority phase.
    state: NotificationOperationState,
}

impl NotificationOperation {
    /// Allocates the delegation state without dropping the unique IRP on OOM.
    /// # Errors
    ///
    /// Returns the still-owned IRP when operation storage cannot be allocated.
    fn try_new(owned: OwnedIrp) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        match memory::boxed_try_map(owned, |owned| Self {
            state: NotificationOperationState::Ready(owned),
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, owned) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }
}

impl MountedVolumeOperation for NotificationOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        _access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let event = event.into_core();
        let state = core::mem::replace(&mut self.state, NotificationOperationState::Terminal);
        let NotificationOperationState::Ready(owned) = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        match event {
            OperationEvent::Admitted => {
                let _status = crate::request::file_info::notify_change_directory(owned);
            }
            OperationEvent::CancelRequested => {
                let _status =
                    owned.complete_result(Err(DriverError::from(Error::OperationCancelled)));
            }
            OperationEvent::StorageCompleted(_)
            | OperationEvent::DeviceLengthCompleted(_)
            | OperationEvent::RetryElapsed(_)
            | OperationEvent::IntentGranted(_)
            | OperationEvent::CommitGranted(_)
            | OperationEvent::VisibilityGranted(_)
            | OperationEvent::CheckpointGranted(_)
            | OperationEvent::BarrierReleased(_) => {
                let _status = owned.complete_result(Err(DriverError::InternalInvariantViolation));
            }
        }
        OperationTransition::Complete
    }

    fn record_mounted_storage_failure(
        &mut self,
        _failure: StorageFailureClass,
        _access: &mut MountedVolumeAccess<'_>,
    ) {
        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
            .bugcheck();
    }
}

#[expect(
    unsafe_code,
    reason = "the notification IRP moves only from the reactor into the FsRtl ownership boundary"
)]
// SAFETY: Unique IRP authority moves only on the sole reactor thread until it is consumed by the
// FsRtl notification package.
unsafe impl Send for NotificationOperation {}

/// Explicit ownership phase of one byte-range lock request.
#[derive(Debug)]
enum ByteRangeLockOperationState {
    /// The driver owns the IRP and its prevalidated stream oplock check.
    CheckingOplock {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Stream lifetime and normalized FsRtl check flags.
        check: OplockCheck,
    },
    /// FsRtl owns the IRP until its oplock completion callback returns it.
    OplockDelegated,
    /// The reactor recovered the exact IRP and oplock result.
    OplockReady {
        /// Unique top-level completion authority returned by FsRtl.
        owned: OwnedIrp,
        /// Immediate or callback-published oplock status.
        status: wdk_sys::NTSTATUS,
    },
    /// FsRtl file-lock ownership or terminal completion consumed the IRP.
    Terminal,
}

/// One handle-serialized lock-control request delegated to FsRtl exactly once.
#[derive(Debug)]
struct ByteRangeLockOperation {
    /// Current completion-ownership phase.
    state: ByteRangeLockOperationState,
}

impl ByteRangeLockOperation {
    /// Allocates a lock operation only after validating its regular-file stream and lease.
    /// # Errors
    ///
    /// Returns the still-owned IRP when the target is malformed, stream retention fails, or
    /// operation storage cannot be allocated.
    fn try_new(
        mut owned: OwnedIrp,
        access: &MountedVolumeAccess<'_>,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        let check = match owned.request().with_active(|active| {
            let _file_control_block = crate::request::file_info::lock_control(active)?;
            let file_object = active.current_stack()?.file_object()?;
            access
                .acquire_oplock_stream_lease(file_object)
                .map(OplockCheck::ordinary)
        }) {
            Ok(check) => check,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        match memory::boxed_try_map((owned, check), |(owned, check)| Self {
            state: ByteRangeLockOperationState::CheckingOplock { owned, check },
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, (owned, _check)) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Completes and consumes one lock-control IRP inside driver ownership.
    fn complete(owned: OwnedIrp, result: DriverResult<IrpCompletion>) -> OperationTransition {
        let _status = owned.complete_result(result);
        OperationTransition::Complete
    }

    /// Revalidates the live FILE_OBJECT identity and transfers terminal ownership to FsRtl.
    fn delegate(mut owned: OwnedIrp) -> OperationTransition {
        let file_control_block = match owned
            .request()
            .with_active(crate::request::file_info::lock_control)
        {
            Ok(file_control_block) => file_control_block,
            Err(error) => return Self::complete(owned, Err(error)),
        };
        let _status = owned.delegate_byte_range_lock(file_control_block);
        OperationTransition::Complete
    }
}

impl OplockContinuation for ByteRangeLockOperation {
    fn resume_after_oplock(
        mut self: Box<Self>,
        owned: OwnedIrp,
        status: wdk_sys::NTSTATUS,
    ) -> Box<dyn CompletionOperation> {
        let state = core::mem::replace(&mut self.state, ByteRangeLockOperationState::Terminal);
        let ByteRangeLockOperationState::OplockDelegated = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        self.state = ByteRangeLockOperationState::OplockReady { owned, status };
        self
    }
}

impl MountedVolumeOperation for ByteRangeLockOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        _access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let event = event.into_core();
        let state = core::mem::replace(&mut self.state, ByteRangeLockOperationState::Terminal);
        match (state, event) {
            (
                ByteRangeLockOperationState::CheckingOplock { owned, check },
                OperationEvent::Admitted,
            ) => {
                self.state = ByteRangeLockOperationState::OplockDelegated;
                OperationTransition::CheckOplock {
                    check,
                    owned,
                    suspended: self,
                }
            }
            (
                ByteRangeLockOperationState::OplockReady { owned, status },
                OperationEvent::Admitted,
            ) if status >= STATUS_SUCCESS => Self::delegate(owned),
            (
                ByteRangeLockOperationState::OplockReady { owned, status },
                OperationEvent::Admitted,
            ) => Self::complete(owned, Err(DriverError::OplockFailure(status))),
            (
                ByteRangeLockOperationState::CheckingOplock { owned, .. }
                | ByteRangeLockOperationState::OplockReady { owned, .. },
                OperationEvent::CancelRequested,
            ) => Self::complete(owned, Err(DriverError::from(Error::OperationCancelled))),
            (
                ByteRangeLockOperationState::CheckingOplock { owned, .. }
                | ByteRangeLockOperationState::OplockReady { owned, .. },
                OperationEvent::StorageCompleted(_)
                | OperationEvent::DeviceLengthCompleted(_)
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::CheckpointGranted(_)
                | OperationEvent::BarrierReleased(_),
            ) => Self::complete(owned, Err(DriverError::InternalInvariantViolation)),
            (ByteRangeLockOperationState::OplockDelegated, _)
            | (ByteRangeLockOperationState::Terminal, _) => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }

    fn record_mounted_storage_failure(
        &mut self,
        _failure: StorageFailureClass,
        _access: &mut MountedVolumeAccess<'_>,
    ) {
        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
            .bugcheck();
    }
}

#[expect(
    unsafe_code,
    reason = "the deferred stream lease and IRP move only through the reactor oplock envelope"
)]
// SAFETY: The stream lease retains its ledger-owned FCB through any FsRtl wait, the mounted VCB is
// stable until reactor drain, and the operation is reclaimed before the sole reactor advances it.
unsafe impl Send for ByteRangeLockOperation {}

/// Volume lifecycle semantics selected from one payload-free standard FSCTL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeControlRequestKind {
    /// Flushes a clean journal before publishing an exclusive volume lock.
    Lock,
    /// Releases a lock already owned by this direct-volume handle.
    Unlock,
    /// Flushes a clean journal before terminal logical dismount publication.
    Dismount,
    /// Observes whether the volume remains logically mounted.
    IsMounted,
    /// Expands only this handle's raw extent bound to the complete lower partition.
    AllowExtendedDasdIo,
}

/// Explicit ownership phase of one direct-volume lifecycle request.
#[derive(Debug)]
enum VolumeControlOperationState {
    /// IRP target and lifecycle transition have not yet been decoded.
    Ready(OwnedIrp),
    /// Every shared stream cache is being coherently flushed and purged before volume lock.
    CacheDraining {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Stable direct-volume identities.
        target: crate::request::file_system_control::DirectVolumeTarget,
        /// Reversible lock publication retained through the full durability sequence.
        transition: PreparedVolumeStateTransition,
        /// Concrete lower devices already selected from the mounted runtime.
        devices: MountedStorageRoute,
        /// Remaining preallocated shared-stream cache leases.
        drain: crate::state::PreparedStreamCacheDrain,
    },
    /// A prevalidated state transition waits until checkpointing leaves a clean journal.
    Waiting {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Stable direct-volume identities.
        target: crate::request::file_system_control::DirectVolumeTarget,
        /// State publication prepared before suspension.
        transition: PreparedVolumeStateTransition,
        /// Concrete lower devices already selected from the mounted runtime.
        devices: MountedStorageRoute,
    },
    /// The clean-journal barrier released and one lower device flush is in flight.
    Flushing {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Stable direct-volume identities.
        target: crate::request::file_system_control::DirectVolumeTarget,
        /// State publication prepared before suspension.
        transition: PreparedVolumeStateTransition,
        /// Exact lower completion identity.
        expected: StorageRequestIdentity,
    },
    /// One-way dismount close is preparing or executing its durability sequence.
    CleanClosing {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Stable direct-volume identities.
        target: crate::request::file_system_control::DirectVolumeTarget,
        /// Terminal publication retained until durable marker clearance.
        transition: PreparedVolumeStateTransition,
        /// Suspended core clean-close operation.
        close: Box<CleanCloseOperation>,
    },
    /// Terminal completion consumed the IRP.
    Terminal,
}

/// Barrier-driven direct-volume lifecycle operation.
#[derive(Debug)]
struct VolumeControlOperation {
    /// Requested lifecycle semantics.
    kind: VolumeControlRequestKind,
    /// Current consuming ownership phase.
    state: VolumeControlOperationState,
}

impl VolumeControlOperation {
    /// Allocates one lifecycle operation while preserving IRP completion ownership on OOM.
    /// # Errors
    ///
    /// Returns the still-owned IRP when operation storage cannot be allocated.
    fn try_new(
        owned: OwnedIrp,
        kind: VolumeControlRequestKind,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        match memory::boxed_try_map((owned, kind), |(owned, kind)| Self {
            kind,
            state: VolumeControlOperationState::Ready(owned),
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, (owned, _kind)) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Completes and consumes the lifecycle IRP.
    fn complete(owned: OwnedIrp, result: DriverResult<IrpCompletion>) -> OperationTransition {
        let _status = owned.complete_result(result);
        OperationTransition::Complete
    }

    /// Publishes the prevalidated lock or dismount transition after successful lower flush.
    fn publish(
        kind: VolumeControlRequestKind,
        owned: OwnedIrp,
        target: crate::request::file_system_control::DirectVolumeTarget,
        transition: PreparedVolumeStateTransition,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        access.publish_volume_state_transition(transition);
        match kind {
            VolumeControlRequestKind::Lock => {
                MountedVolumeDevice::publish_volume_lock(target.device(), true);
            }
            VolumeControlRequestKind::Dismount => {
                MountedVolumeDevice::publish_direct_writes_allowed(target.device());
                MountedVolumeDevice::unregister_shutdown_notification(target.device());
                MountedVolumeDevice::complete_dismount(target.device());
            }
            VolumeControlRequestKind::Unlock
            | VolumeControlRequestKind::IsMounted
            | VolumeControlRequestKind::AllowExtendedDasdIo => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption(
                )
                .bugcheck();
            }
        }
        Self::complete(owned, Ok(IrpCompletion::EMPTY))
    }

    /// Ends a failed attempt, reopening admission only for a reversible volume lock.
    fn fail_transition(
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        error: DriverError,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        access.fail_volume_state_transition(transition);
        Self::complete(owned, Err(error))
    }

    /// Submits the next shared-stream drain or advances a completed plan to journal durability.
    fn continue_lock_cache_drain(
        mut self: Box<Self>,
        owned: OwnedIrp,
        target: crate::request::file_system_control::DirectVolumeTarget,
        transition: PreparedVolumeStateTransition,
        devices: MountedStorageRoute,
        mut drain: crate::state::PreparedStreamCacheDrain,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Some(stream) = drain.next() {
            self.state = VolumeControlOperationState::CacheDraining {
                owned,
                target,
                transition,
                devices,
                drain,
            };
            return OperationTransition::SubmitCacheWork {
                work: crate::irp::CacheWork::drain_for_volume_lock(stream),
                suspended: self,
            };
        }
        let completed = match drain.into_completed() {
            Ok(completed) => completed,
            Err(error) => return Self::fail_lock_cache_drain(owned, transition, error, access),
        };
        if let Err(error) = access.finish_volume_lock_cache_drain(completed) {
            return Self::fail_lock_cache_drain(owned, transition, error, access);
        }
        self.state = VolumeControlOperationState::Waiting {
            owned,
            target,
            transition,
            devices,
        };
        OperationTransition::Wait {
            condition: WaitCondition::JournalClean,
            suspended: self,
        }
    }

    /// Distinguishes an ordinary mapped-section lock conflict from terminal cache writeback
    /// failure before aborting the reversible volume-lock attempt.
    fn fail_lock_cache_drain(
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        error: DriverError,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        record_cache_coherency_failure(error, access);
        Self::fail_transition(owned, transition, error, access)
    }

    /// Allocates the core clean-close operation from immutable mounted geometry.
    /// # Errors
    ///
    /// Returns a driver allocation error if the close state machine cannot be reserved before the
    /// closing durability sequence begins.
    fn prepare_clean_close(
        access: &MountedVolumeAccess<'_>,
    ) -> DriverResult<Box<CleanCloseOperation>> {
        let profile = access.mounted_profile();
        let filesystem_length = profile.filesystem_length();
        let journal_target = profile.journal_target();
        memory::boxed_try_with(|| Ok(CleanCloseOperation::new(filesystem_length, journal_target)))
    }

    /// Drives one uninterruptible dismount durability transition.
    fn drive_clean_close(
        mut self: Box<Self>,
        owned: OwnedIrp,
        target: crate::request::file_system_control::DirectVolumeTarget,
        transition: PreparedVolumeStateTransition,
        result: CleanCloseTransition,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        match result {
            CleanCloseTransition::SubmitLower { request, suspended } => {
                let devices = access.storage_route();
                self.state = VolumeControlOperationState::CleanClosing {
                    owned,
                    target,
                    transition,
                    close: suspended,
                };
                OperationTransition::SubmitClosingLower {
                    devices,
                    request,
                    suspended: self,
                }
            }
            CleanCloseTransition::Complete(Ok(_durability)) => {
                Self::publish(self.kind, owned, target, transition, access)
            }
            CleanCloseTransition::Complete(Err(error)) => {
                Self::fail_transition(owned, transition, DriverError::from(error), access)
            }
        }
    }
}

impl MountedVolumeOperation for VolumeControlOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let event = match event {
            CompletionEvent::Core(event) => event,
            CompletionEvent::CacheCompleted(completion) => {
                let state =
                    core::mem::replace(&mut self.state, VolumeControlOperationState::Terminal);
                let (
                    VolumeControlOperationState::CacheDraining {
                        owned,
                        target,
                        transition,
                        devices,
                        drain,
                    },
                    crate::irp::CacheWorkCompletion::DrainForVolumeLock(result),
                ) = (state, completion)
                else {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                        .bugcheck()
                };
                return match result {
                    Ok(completed) => {
                        let mut drain = drain;
                        if let Err(error) = drain.record_completion(completed) {
                            return Self::fail_lock_cache_drain(owned, transition, error, access);
                        }
                        self.continue_lock_cache_drain(
                            owned, target, transition, devices, drain, access,
                        )
                    }
                    Err(error) => Self::fail_lock_cache_drain(owned, transition, error, access),
                };
            }
            CompletionEvent::VolumeFailed(error) => {
                let state =
                    core::mem::replace(&mut self.state, VolumeControlOperationState::Terminal);
                let VolumeControlOperationState::Waiting {
                    owned, transition, ..
                } = state
                else {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                return Self::fail_transition(owned, transition, error, access);
            }
        };
        let state = core::mem::replace(&mut self.state, VolumeControlOperationState::Terminal);
        match state {
            VolumeControlOperationState::Ready(mut owned) => match event {
                OperationEvent::Admitted => {
                    let target = match crate::request::file_system_control::direct_volume_target(
                        &mut owned.request(),
                    ) {
                        Ok(target) => target,
                        Err(error) => return Self::complete(owned, Err(error)),
                    };
                    if !access.owns_volume(target.volume()) {
                        return Self::complete(owned, Err(DriverError::InvalidDeviceRequest));
                    }
                    match self.kind {
                        VolumeControlRequestKind::Unlock => {
                            let result = access.unlock_volume(target.owner());
                            if result.is_ok() {
                                MountedVolumeDevice::publish_volume_lock(target.device(), false);
                            }
                            Self::complete(owned, result.map(|()| IrpCompletion::EMPTY))
                        }
                        VolumeControlRequestKind::IsMounted => {
                            let result = access.ensure_mounted();
                            Self::complete(owned, result.map(|()| IrpCompletion::EMPTY))
                        }
                        VolumeControlRequestKind::AllowExtendedDasdIo => {
                            let result =
                                crate::request::file_system_control::allow_extended_dasd_io(
                                    &mut owned.request(),
                                    access,
                                );
                            Self::complete(owned, result.map(|()| IrpCompletion::EMPTY))
                        }
                        VolumeControlRequestKind::Lock => {
                            let prepared = match access.prepare_lock_volume(target.owner()) {
                                Ok(prepared) => prepared,
                                Err(error) => return Self::complete(owned, Err(error)),
                            };
                            let (transition, drain) = prepared.into_parts();
                            let devices = access.storage_route();
                            self.continue_lock_cache_drain(
                                owned, target, transition, devices, drain, access,
                            )
                        }
                        VolumeControlRequestKind::Dismount => {
                            let transition = match access.prepare_dismount_volume(target.owner()) {
                                Ok(transition) => transition,
                                Err(error) => return Self::complete(owned, Err(error)),
                            };
                            let devices = access.storage_route();
                            self.state = VolumeControlOperationState::Waiting {
                                owned,
                                target,
                                transition,
                                devices,
                            };
                            OperationTransition::WaitForClosingDrain {
                                condition: WaitCondition::JournalClean,
                                suspended: self,
                            }
                        }
                    }
                }
                OperationEvent::CancelRequested => {
                    Self::complete(owned, Err(DriverError::from(Error::OperationCancelled)))
                }
                OperationEvent::StorageCompleted(_)
                | OperationEvent::DeviceLengthCompleted(_)
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::CheckpointGranted(_)
                | OperationEvent::BarrierReleased(_) => {
                    Self::complete(owned, Err(DriverError::InternalInvariantViolation))
                }
            },
            VolumeControlOperationState::Waiting {
                owned,
                target,
                transition,
                devices,
            } => match event {
                OperationEvent::BarrierReleased(permit) => {
                    if permit.into_identity() != 1 {
                        return Self::fail_transition(
                            owned,
                            transition,
                            DriverError::InternalInvariantViolation,
                            access,
                        );
                    }
                    if transition.is_clean_close() {
                        let close = match Self::prepare_clean_close(access) {
                            Ok(close) => close,
                            Err(error) => {
                                return Self::fail_transition(owned, transition, error, access);
                            }
                        };
                        let result = close.advance(OperationEvent::Admitted);
                        self.drive_clean_close(owned, target, transition, result, access)
                    } else {
                        let request = StorageRequest::Flush {
                            target: ext4_core::StorageTarget::Filesystem,
                        };
                        let expected = StorageRequestIdentity::from_request(&request);
                        self.state = VolumeControlOperationState::Flushing {
                            owned,
                            target,
                            transition,
                            expected,
                        };
                        OperationTransition::SubmitLower {
                            devices,
                            request,
                            suspended: self,
                        }
                    }
                }
                OperationEvent::CancelRequested => Self::fail_transition(
                    owned,
                    transition,
                    DriverError::from(Error::OperationCancelled),
                    access,
                ),
                OperationEvent::Admitted
                | OperationEvent::StorageCompleted(_)
                | OperationEvent::DeviceLengthCompleted(_)
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::CheckpointGranted(_) => Self::fail_transition(
                    owned,
                    transition,
                    DriverError::InternalInvariantViolation,
                    access,
                ),
            },
            VolumeControlOperationState::Flushing {
                owned,
                target,
                transition,
                expected,
            } => {
                if matches!(event, OperationEvent::CancelRequested) {
                    return Self::fail_transition(
                        owned,
                        transition,
                        DriverError::from(Error::OperationCancelled),
                        access,
                    );
                }
                let OperationEvent::StorageCompleted(completion) = event else {
                    return Self::fail_transition(
                        owned,
                        transition,
                        DriverError::InternalInvariantViolation,
                        access,
                    );
                };
                match expected.complete(completion) {
                    Ok(()) => Self::publish(self.kind, owned, target, transition, access),
                    Err(error) => {
                        Self::fail_transition(owned, transition, DriverError::from(error), access)
                    }
                }
            }
            VolumeControlOperationState::CleanClosing {
                owned,
                target,
                transition,
                close,
            } => {
                let result = close.advance(event);
                self.drive_clean_close(owned, target, transition, result, access)
            }
            VolumeControlOperationState::CacheDraining {
                owned, transition, ..
            } => match event {
                OperationEvent::CancelRequested => Self::fail_transition(
                    owned,
                    transition,
                    DriverError::from(Error::OperationCancelled),
                    access,
                ),
                OperationEvent::Admitted
                | OperationEvent::StorageCompleted(_)
                | OperationEvent::DeviceLengthCompleted(_)
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::CheckpointGranted(_)
                | OperationEvent::BarrierReleased(_) => Self::fail_transition(
                    owned,
                    transition,
                    DriverError::InternalInvariantViolation,
                    access,
                ),
            },
            VolumeControlOperationState::Terminal => OperationTransition::Complete,
        }
    }

    fn record_mounted_storage_failure(
        &mut self,
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    ) {
        if !failure.is_durability_unknown() {
            return;
        }
        let _target = match &self.state {
            VolumeControlOperationState::Flushing { target, .. }
            | VolumeControlOperationState::CleanClosing { target, .. } => *target,
            VolumeControlOperationState::Ready(_)
            | VolumeControlOperationState::CacheDraining { .. }
            | VolumeControlOperationState::Waiting { .. }
            | VolumeControlOperationState::Terminal => return,
        };
        access.record_durability_unknown();
    }
}

#[expect(
    unsafe_code,
    reason = "the volume-control operation moves through the reactor while mounted identities stay pinned"
)]
// SAFETY: Stable VCB/FILE_OBJECT identities remain pinned by the IRP and mounted device; state
// moves only by value between the sole reactor thread and stable lower envelopes.
unsafe impl Send for VolumeControlOperation {}

/// Durability barrier semantics selected by the top-level major function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlushRequestKind {
    /// Ordinary file/volume flush: commit durability plus filesystem device flush.
    FlushBuffers,
    /// Shutdown: clean checkpointed journal plus filesystem device flush.
    Shutdown,
}

/// Explicit ownership phase of one flush request.
#[derive(Debug)]
enum FlushOperationState {
    /// IRP target has not yet been validated on the reactor thread.
    Ready(OwnedIrp),
    /// FsRtl owns the file-specific flush IRP during an oplock break wait.
    OplockDelegated {
        /// Validated durability scope retained without IRP completion authority.
        scope: crate::state::VolumeFlushScope,
    },
    /// The reactor restored the file-specific flush IRP after FsRtl completion.
    OplockReady {
        /// Unique top-level completion authority returned by FsRtl.
        owned: OwnedIrp,
        /// Exact immediate or callback-published oplock status.
        status: wdk_sys::NTSTATUS,
        /// Validated durability scope retained across the oplock wait.
        scope: crate::state::VolumeFlushScope,
    },
    /// One file stream is flushing dirty Cache Manager pages outside the actor.
    CacheFlushing {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Validated durability scope resumed after successful cache writeback.
        scope: crate::state::VolumeFlushScope,
    },
    /// IRP waits behind the selected volume durability barrier.
    Waiting {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Shutdown terminal publication, absent for ordinary flush buffers.
        transition: Option<PreparedVolumeStateTransition>,
    },
    /// One filesystem flush is owned by a lower completion envelope.
    InFlight {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Identity of the exact lower flush.
        expected: StorageRequestIdentity,
        /// Mounted journal or terminal raw device whose flush is being observed.
        scope: crate::state::VolumeFlushScope,
    },
    /// One-way shutdown close is preparing or executing its durability sequence.
    CleanClosing {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Shutdown terminal publication retained until durable marker clearance.
        transition: PreparedVolumeStateTransition,
        /// Suspended core clean-close operation.
        close: Box<CleanCloseOperation>,
    },
    /// Terminal completion consumed the IRP.
    Terminal,
}

/// Validated flush target plus the stream check required before file-specific cache writeback.
struct PreparedFlushTarget {
    /// Journal or raw-device durability scope selected by the opened target.
    scope: crate::state::VolumeFlushScope,
    /// Node-stream oplock check; absent for shutdown, raw-volume, and device-level flushes.
    oplock: Option<OplockCheck>,
}

/// One non-retrying-at-the-domain-level device flush operation.
#[derive(Debug)]
struct FlushRequestOperation {
    /// Mounted lower devices.
    devices: MountedStorageRoute,
    /// Barrier semantics.
    kind: FlushRequestKind,
    /// Current consuming state.
    state: FlushOperationState,
}

impl FlushRequestOperation {
    /// Allocates one flush operation while preserving the top-level IRP on OOM.
    /// # Errors
    ///
    /// Returns the still-owned IRP when mounted-state lookup or operation allocation fails.
    fn try_new(
        owned: OwnedIrp,
        kind: FlushRequestKind,
        access: &MountedVolumeAccess<'_>,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        let devices = access.storage_route();
        match memory::boxed_try_map(owned, |owned| Self {
            devices,
            kind,
            state: FlushOperationState::Ready(owned),
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, owned) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Validates the FILE_OBJECT or device-level flush target and captures any stream oplock.
    /// # Errors
    ///
    /// Returns an error when identity, lifecycle, raw access, or volume health rejects the flush.
    fn prepare_target(
        &self,
        owned: &mut OwnedIrp,
        access: &MountedVolumeAccess<'_>,
    ) -> DriverResult<PreparedFlushTarget> {
        owned.request().with_active(|active| {
            if self.kind == FlushRequestKind::Shutdown {
                access.authorize_durability()?;
                return Ok(PreparedFlushTarget {
                    scope: crate::state::VolumeFlushScope::Filesystem,
                    oplock: None,
                });
            }
            let stack = active.current_stack()?;
            match stack.file_object() {
                Ok(file_object) => match crate::state::OpenedFileObject::decode(file_object)? {
                    crate::state::OpenedFileObject::Node(opened) => {
                        if !access.owns_volume(opened.volume()) {
                            return Err(DriverError::InvalidDeviceRequest);
                        }
                        access.authorize_handle(opened.file_object())?;
                        access.authorize_durability()?;
                        let oplock = access
                            .acquire_oplock_stream_lease(file_object)
                            .map(OplockCheck::ordinary)?;
                        Ok(PreparedFlushTarget {
                            scope: crate::state::VolumeFlushScope::Filesystem,
                            oplock: Some(oplock),
                        })
                    }
                    crate::state::OpenedFileObject::Volume(opened) => access
                        .volume_flush_scope(opened.raw_target())
                        .map(|scope| PreparedFlushTarget {
                            scope,
                            oplock: None,
                        }),
                },
                Err(DriverError::InvalidParameter) => {
                    access.authorize_durability()?;
                    Ok(PreparedFlushTarget {
                        scope: crate::state::VolumeFlushScope::Filesystem,
                        oplock: None,
                    })
                }
                Err(error) => Err(error),
            }
        })
    }

    /// Captures a node stream lease for file-specific `FlushBuffers` requests.
    /// # Errors
    ///
    /// Returns a FILE_OBJECT, stream-identity, or lease failure before worker submission.
    fn prepare_cache_flush(
        &self,
        owned: &mut OwnedIrp,
        access: &MountedVolumeAccess<'_>,
    ) -> DriverResult<Option<crate::irp::CacheWork>> {
        if self.kind == FlushRequestKind::Shutdown {
            return Ok(None);
        }
        owned.request().with_active(|active| {
            let file_object = match active.current_stack()?.file_object() {
                Ok(file_object) => file_object,
                Err(DriverError::InvalidParameter) => return Ok(None),
                Err(error) => return Err(error),
            };
            match crate::state::OpenedFileObject::decode(file_object)? {
                crate::state::OpenedFileObject::Node(_) => access
                    .acquire_file_object_cache_lease(file_object)
                    .map(crate::state::FileObjectCacheLease::into_stream)
                    .map(crate::irp::CacheWork::flush)
                    .map(Some),
                crate::state::OpenedFileObject::Volume(_) => Ok(None),
            }
        })
    }

    /// Completes and consumes the top-level flush IRP.
    fn complete(owned: OwnedIrp, result: DriverResult<IrpCompletion>) -> OperationTransition {
        let _status = owned.complete_result(result);
        OperationTransition::Complete
    }

    /// Starts file-cache writeback after the file-specific oplock check has completed.
    fn begin_cache_flush(
        mut self: Box<Self>,
        mut owned: OwnedIrp,
        scope: crate::state::VolumeFlushScope,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let work = match self.prepare_cache_flush(&mut owned, access) {
            Ok(work) => work,
            Err(error) => return Self::complete(owned, Err(error)),
        };
        if let Some(work) = work {
            self.state = FlushOperationState::CacheFlushing { owned, scope };
            OperationTransition::SubmitCacheWork {
                work,
                suspended: self,
            }
        } else {
            self.continue_after_cache_flush(owned, scope, access)
        }
    }

    /// Continues the journal and lower-device durability sequence after cache writeback.
    fn continue_after_cache_flush(
        mut self: Box<Self>,
        owned: OwnedIrp,
        scope: crate::state::VolumeFlushScope,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let crate::state::VolumeFlushScope::RawDevice(_) = scope {
            let request = StorageRequest::Flush {
                target: ext4_core::StorageTarget::Filesystem,
            };
            let expected = StorageRequestIdentity::from_request(&request);
            self.state = FlushOperationState::InFlight {
                owned,
                expected,
                scope,
            };
            return OperationTransition::SubmitLower {
                devices: self.devices,
                request,
                suspended: self,
            };
        }
        match self.kind {
            FlushRequestKind::FlushBuffers => {
                self.state = FlushOperationState::Waiting {
                    owned,
                    transition: None,
                };
                OperationTransition::Wait {
                    condition: WaitCondition::VolumeDurability,
                    suspended: self,
                }
            }
            FlushRequestKind::Shutdown => {
                let transition = match access.prepare_shutdown() {
                    Ok(transition) => transition,
                    Err(error) => return Self::complete(owned, Err(error)),
                };
                self.state = FlushOperationState::Waiting {
                    owned,
                    transition: Some(transition),
                };
                OperationTransition::WaitForClosingDrain {
                    condition: WaitCondition::JournalClean,
                    suspended: self,
                }
            }
        }
    }

    /// Drives one uninterruptible shutdown durability transition.
    fn drive_clean_close(
        mut self: Box<Self>,
        owned: OwnedIrp,
        transition: PreparedVolumeStateTransition,
        result: CleanCloseTransition,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        match result {
            CleanCloseTransition::SubmitLower { request, suspended } => {
                self.state = FlushOperationState::CleanClosing {
                    owned,
                    transition,
                    close: suspended,
                };
                OperationTransition::SubmitClosingLower {
                    devices: self.devices,
                    request,
                    suspended: self,
                }
            }
            CleanCloseTransition::Complete(Ok(_durability)) => {
                access.publish_volume_state_transition(transition);
                Self::complete(owned, Ok(IrpCompletion::EMPTY))
            }
            CleanCloseTransition::Complete(Err(error)) => {
                Self::complete(owned, Err(DriverError::from(error)))
            }
        }
    }
}

impl OplockContinuation for FlushRequestOperation {
    fn resume_after_oplock(
        mut self: Box<Self>,
        owned: OwnedIrp,
        status: wdk_sys::NTSTATUS,
    ) -> Box<dyn CompletionOperation> {
        let state = core::mem::replace(&mut self.state, FlushOperationState::Terminal);
        let FlushOperationState::OplockDelegated { scope } = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        self.state = FlushOperationState::OplockReady {
            owned,
            status,
            scope,
        };
        self
    }
}

impl MountedVolumeOperation for FlushRequestOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let event = match event {
            CompletionEvent::Core(event) => event,
            CompletionEvent::CacheCompleted(completion) => {
                let state = core::mem::replace(&mut self.state, FlushOperationState::Terminal);
                let (
                    FlushOperationState::CacheFlushing { owned, scope },
                    crate::irp::CacheWorkCompletion::Flush(result),
                ) = (state, completion)
                else {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                        .bugcheck()
                };
                return match result {
                    Ok(()) => self.continue_after_cache_flush(owned, scope, access),
                    Err(error) => {
                        record_cache_coherency_failure(error, access);
                        Self::complete(owned, Err(error))
                    }
                };
            }
            CompletionEvent::VolumeFailed(error) => {
                let state = core::mem::replace(&mut self.state, FlushOperationState::Terminal);
                let FlushOperationState::Waiting { owned, transition } = state else {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if let Some(transition) = transition {
                    access.fail_volume_state_transition(transition);
                }
                return Self::complete(owned, Err(error));
            }
        };
        let state = core::mem::replace(&mut self.state, FlushOperationState::Terminal);
        match state {
            FlushOperationState::Ready(mut owned) => match event {
                OperationEvent::Admitted => {
                    let target = match self.prepare_target(&mut owned, access) {
                        Ok(target) => target,
                        Err(error) => return Self::complete(owned, Err(error)),
                    };
                    if let Some(check) = target.oplock {
                        self.state = FlushOperationState::OplockDelegated {
                            scope: target.scope,
                        };
                        OperationTransition::CheckOplock {
                            check,
                            owned,
                            suspended: self,
                        }
                    } else {
                        self.begin_cache_flush(owned, target.scope, access)
                    }
                }
                OperationEvent::CancelRequested => {
                    Self::complete(owned, Err(DriverError::from(Error::OperationCancelled)))
                }
                OperationEvent::StorageCompleted(_)
                | OperationEvent::DeviceLengthCompleted(_)
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::CheckpointGranted(_)
                | OperationEvent::BarrierReleased(_) => {
                    Self::complete(owned, Err(DriverError::InternalInvariantViolation))
                }
            },
            FlushOperationState::OplockReady {
                owned,
                status,
                scope,
            } => match event {
                OperationEvent::Admitted if status >= STATUS_SUCCESS => {
                    self.begin_cache_flush(owned, scope, access)
                }
                OperationEvent::Admitted => {
                    Self::complete(owned, Err(DriverError::OplockFailure(status)))
                }
                OperationEvent::CancelRequested => {
                    Self::complete(owned, Err(DriverError::from(Error::OperationCancelled)))
                }
                OperationEvent::StorageCompleted(_)
                | OperationEvent::DeviceLengthCompleted(_)
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::CheckpointGranted(_)
                | OperationEvent::BarrierReleased(_) => {
                    Self::complete(owned, Err(DriverError::InternalInvariantViolation))
                }
            },
            FlushOperationState::OplockDelegated { .. } => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
            FlushOperationState::CacheFlushing { .. } => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
            FlushOperationState::Waiting { owned, transition } => match event {
                OperationEvent::BarrierReleased(permit) => {
                    let expected_identity = match self.kind {
                        FlushRequestKind::FlushBuffers => 0,
                        FlushRequestKind::Shutdown => 1,
                    };
                    if permit.into_identity() != expected_identity {
                        return Self::complete(owned, Err(DriverError::InternalInvariantViolation));
                    }
                    match (self.kind, transition) {
                        (FlushRequestKind::FlushBuffers, None) => {
                            let request = StorageRequest::Flush {
                                target: ext4_core::StorageTarget::Filesystem,
                            };
                            let expected = StorageRequestIdentity::from_request(&request);
                            self.state = FlushOperationState::InFlight {
                                owned,
                                expected,
                                scope: crate::state::VolumeFlushScope::Filesystem,
                            };
                            OperationTransition::SubmitLower {
                                devices: self.devices,
                                request,
                                suspended: self,
                            }
                        }
                        (FlushRequestKind::Shutdown, Some(transition)) => {
                            let close = match VolumeControlOperation::prepare_clean_close(access) {
                                Ok(close) => close,
                                Err(error) => return Self::complete(owned, Err(error)),
                            };
                            let result = close.advance(OperationEvent::Admitted);
                            self.drive_clean_close(owned, transition, result, access)
                        }
                        (FlushRequestKind::FlushBuffers, Some(_))
                        | (FlushRequestKind::Shutdown, None) => {
                            Self::complete(owned, Err(DriverError::InternalInvariantViolation))
                        }
                    }
                }
                OperationEvent::CancelRequested => {
                    Self::complete(owned, Err(DriverError::from(Error::OperationCancelled)))
                }
                OperationEvent::Admitted
                | OperationEvent::StorageCompleted(_)
                | OperationEvent::DeviceLengthCompleted(_)
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::CheckpointGranted(_) => {
                    Self::complete(owned, Err(DriverError::InternalInvariantViolation))
                }
            },
            FlushOperationState::InFlight {
                owned,
                expected,
                scope,
            } => {
                if matches!(event, OperationEvent::CancelRequested) {
                    return Self::complete(
                        owned,
                        Err(DriverError::from(Error::OperationCancelled)),
                    );
                }
                let OperationEvent::StorageCompleted(completion) = event else {
                    return Self::complete(owned, Err(DriverError::InternalInvariantViolation));
                };
                match expected.complete(completion) {
                    Ok(()) => Self::complete(owned, Ok(IrpCompletion::EMPTY)),
                    Err(error) => {
                        let error = match scope {
                            crate::state::VolumeFlushScope::Filesystem => DriverError::from(error),
                            crate::state::VolumeFlushScope::RawDevice(target) => {
                                target.mark_write_uncertain(0);
                                DriverError::RawOutcomeUncertain
                            }
                        };
                        Self::complete(owned, Err(error))
                    }
                }
            }
            FlushOperationState::CleanClosing {
                owned,
                transition,
                close,
            } => {
                let result = close.advance(event);
                self.drive_clean_close(owned, transition, result, access)
            }
            FlushOperationState::Terminal => OperationTransition::Complete,
        }
    }

    fn record_mounted_storage_failure(
        &mut self,
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    ) {
        if !failure.is_durability_unknown() {
            return;
        }
        access.record_durability_unknown();
    }
}

#[expect(
    unsafe_code,
    reason = "the flush operation moves through the reactor while its VCB and top-level IRP remain live"
)]
// SAFETY: The mounted VCB and top-level IRP remain live through reactor drain; the operation moves
// only by value between the reactor and stable completion envelopes.
unsafe impl Send for FlushRequestOperation {}

/// Mutation request semantics selected entirely from captured queue metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MutationRequestKind {
    /// Create/open, including missing-child creation.
    Create,
    /// Regular-file data write.
    Write,
    /// File-information mutation.
    SetInformation,
    /// Extended-attribute mutation.
    SetEa,
    /// Security-descriptor mutation.
    SetSecurity,
    /// Volume-label mutation.
    SetVolumeInformation,
    /// Store a Windows reparse point.
    SetReparsePoint,
    /// Delete a Windows reparse point.
    DeleteReparsePoint,
    /// Enable fs-verity metadata.
    EnableVerity,
    /// Add one mount-scoped fscrypt key snapshot.
    AddEncryptionKey,
    /// Remove one mount-scoped fscrypt key snapshot.
    RemoveEncryptionKey,
    /// Cleanup-time namespace deletion after the terminal handle barrier.
    Cleanup,
}

/// Mutation request after any paging stream lifetime authority has been captured.
#[derive(Debug)]
enum PreparedMutationRequest {
    /// Regular-file data write with handle or paging stream authority.
    DataWrite(crate::request::file_info::RegularFileDataAuthority),
    /// Non-data mutation class whose existing lifecycle authority remains sufficient.
    Other(MutationRequestKind),
}

impl PreparedMutationRequest {
    /// Captures a paging stream lease before journal admission may suspend the operation.
    /// # Errors
    ///
    /// Returns a stream-identity or lease failure for paging data writes.
    fn prepare(
        kind: MutationRequestKind,
        owned: &mut OwnedIrp,
        access: &MountedVolumeAccess<'_>,
    ) -> DriverResult<Self> {
        if kind == MutationRequestKind::Write {
            crate::request::file_info::prepare_regular_file_data_authority(owned.request(), access)
                .map(Self::DataWrite)
        } else {
            Ok(Self::Other(kind))
        }
    }

    /// Returns the captured request class without exposing the stream lease.
    const fn kind(&self) -> MutationRequestKind {
        match self {
            Self::DataWrite(_) => MutationRequestKind::Write,
            Self::Other(kind) => *kind,
        }
    }

    /// Reports whether this write owns cleanup-independent paging stream authority.
    const fn is_paging(&self) -> bool {
        matches!(self, Self::DataWrite(authority) if authority.is_paging())
    }
}

/// Terminal payload appropriate for the top-level IRP's major function.
#[derive(Debug)]
enum TopLevelCompletion {
    /// Ordinary status/information completion.
    Normal(IrpCompletion),
    /// Create completion with create action or reparse ownership.
    Create(CreateCompletion),
}

/// Driver-visible values produced by one successful mutation resolve pass.
#[derive(Debug)]
enum PendingDriverPublication {
    /// Create must acquire its FCB/share claim before the first write.
    Create(Box<crate::request::create::PendingCreatePublication>),
    /// Write position was fully validated and prepared by resolve.
    Write(crate::request::file_info::PreparedWritePublication),
    /// Set-information driver state was fully allocated by resolve.
    SetFile(crate::request::file_info::SetFilePublication),
    /// Cleanup deletion notification and target were fully prepared by resolve.
    Cleanup(Box<crate::request::file_info::PreparedCleanupPublication>),
    /// Prevalidated VPB label publication.
    VolumeLabel(crate::request::volume_info::PreparedVolumeLabelPublication),
    /// Mutation has no additional driver state to publish.
    Normal(IrpCompletion),
}

/// Post-commit driver publication whose durable path cannot allocate or fail.
#[derive(Debug)]
struct PreparedDriverPublication {
    /// Every changed live inode's sizes, derived from the reserved core mutation.
    stream_sizes: crate::state::PreparedStreamSizePublications,
    /// Handle, cursor, notification, or volume state published after the sizes.
    effect: PreparedDriverEffect,
}

/// Operation-specific state prepared before any irreversible lower write.
#[derive(Debug)]
enum PreparedDriverEffect {
    /// Fully claimed create handle state.
    Create(Box<crate::request::create::PreparedCreatePublication>),
    /// Checked write cursor and completion.
    Write(crate::request::file_info::PreparedWritePublication),
    /// Set-information publication.
    SetFile(crate::request::file_info::SetFilePublication),
    /// Cleanup deletion publication.
    Cleanup(Box<crate::request::file_info::PreparedCleanupPublication>),
    /// Volume-label publication.
    VolumeLabel(crate::request::volume_info::PreparedVolumeLabelPublication),
    /// No driver-side mutation publication.
    Normal(IrpCompletion),
}

impl PendingDriverPublication {
    /// Completes every fallible driver-side acquisition before commit I/O can start.
    /// # Errors
    ///
    /// Returns an error when sizes cannot be represented or create cannot acquire its FCB/share
    /// state. No partially prepared value has publication authority on failure.
    fn prepare(
        self,
        stream_sizes: crate::state::PreparedStreamSizePublications,
    ) -> DriverResult<PreparedDriverPublication> {
        let effect = match self {
            Self::Create(publication) => {
                let publication = (*publication).prepare()?;
                PreparedDriverEffect::Create(memory::boxed_try_with(move || Ok(publication))?)
            }
            Self::Write(publication) => PreparedDriverEffect::Write(publication),
            Self::SetFile(publication) => PreparedDriverEffect::SetFile(publication),
            Self::Cleanup(publication) => PreparedDriverEffect::Cleanup(publication),
            Self::VolumeLabel(publication) => PreparedDriverEffect::VolumeLabel(publication),
            Self::Normal(completion) => PreparedDriverEffect::Normal(completion),
        };
        Ok(PreparedDriverPublication {
            stream_sizes,
            effect,
        })
    }
}

impl PreparedDriverEffect {
    /// Applies only moves and prevalidated pointer/state updates after commit durability.
    fn publish(self, operations: &mut crate::state::MountedVolumeAccess<'_>) -> TopLevelCompletion {
        match self {
            Self::Create(publication) => {
                TopLevelCompletion::Create((*publication).publish(operations))
            }
            Self::Write(publication) => TopLevelCompletion::Normal(publication.publish()),
            Self::SetFile(publication) => {
                publication.publish(operations);
                TopLevelCompletion::Normal(IrpCompletion::EMPTY)
            }
            Self::Cleanup(publication) => {
                TopLevelCompletion::Normal((*publication).publish(operations))
            }
            Self::VolumeLabel(publication) => {
                publication.publish();
                TopLevelCompletion::Normal(IrpCompletion::EMPTY)
            }
            Self::Normal(completion) => TopLevelCompletion::Normal(completion),
        }
    }
}

/// State retained throughout one durable commit while the top-level IRP remains owned.
#[derive(Debug)]
struct CommitContext {
    /// Unique top-level completion authority.
    owned: OwnedIrp,
    /// Infallible driver-visible publication.
    publication: PreparedDriverPublication,
    /// Pre-reserved durable epoch slot.
    durable_slot: EpochPublicationSlot,
    /// Pre-reserved checkpoint epoch slot.
    checkpoint_slot: EpochPublicationSlot,
    /// Native cache/section gate retained until durable stream-size publication completes.
    size_changes: Option<crate::state::PreparedStreamSizeChanges>,
    /// Native image/data-section gate retained until durable cleanup deletion publishes.
    deletion: Option<crate::state::PreparedStreamDeletion>,
}

/// One restart-local resolve pass with every native gate already retained for revalidation.
#[derive(Debug)]
struct ResolutionAttempt {
    /// Immutable metadata epoch against which the resolve transcript is valid.
    epoch: EpochLease,
    /// Restartable core resolver for this epoch.
    resolve: MutationResolveOperation,
    /// Native size gates retained across a stale-pass restart.
    size_changes: Option<crate::state::PreparedStreamSizeChanges>,
    /// Stronger cleanup deletion gate retained across a stale-pass restart.
    deletion: Option<crate::state::PreparedStreamDeletion>,
}

/// Exact write/flush phase awaiting one matching lower completion.
#[derive(Debug)]
enum CommitIoPhase {
    /// One ordered data write is in flight; `remaining` owns the rest.
    OrderedWrite {
        /// Identity of the exact in-flight lower write.
        expected: StorageRequestIdentity,
        /// Remaining ordered writes and their durability continuation.
        remaining: StorageRequestSequence<OrderedDataDurability>,
    },
    /// Filesystem flush after every ordered data write.
    OrderedFlush {
        /// Identity of the in-flight filesystem flush.
        expected: StorageRequestIdentity,
        /// Continuation revealed after ordered-data durability.
        next: OrderedDataDurability,
    },
    /// One journal descriptor/payload write is in flight.
    JournalWrite {
        /// Identity of the exact in-flight journal write.
        expected: StorageRequestIdentity,
        /// Remaining journal writes and their durability continuation.
        remaining: StorageRequestSequence<JournalPayloadDurability>,
    },
    /// Journal payload durability flush preceding the commit record.
    JournalFlush {
        /// Identity of the in-flight journal-device flush.
        expected: StorageRequestIdentity,
        /// Commit-record continuation revealed after the flush.
        next: JournalPayloadDurability,
    },
    /// Single commit record write.
    CommitWrite {
        /// Identity of the in-flight commit-record write.
        expected: StorageRequestIdentity,
        /// Commit durability continuation retained through the write.
        next: CommitDurability,
    },
    /// Flush that establishes commit durability.
    CommitFlush {
        /// Identity of the in-flight commit durability flush.
        expected: StorageRequestIdentity,
        /// Durable mutation revealed only by successful completion.
        next: CommitDurability,
    },
}

/// Exact checkpoint write/flush phase after the top-level mutation is already visible.
#[derive(Debug)]
enum CheckpointIoPhase {
    /// One home-block write is in flight.
    HomeWrite {
        /// Identity of the exact in-flight home-block write.
        expected: StorageRequestIdentity,
        /// Remaining home writes and clean-journal continuation.
        remaining: StorageRequestSequence<HomeBlockDurability>,
    },
    /// Filesystem durability flush after home-block writes.
    HomeFlush {
        /// Identity of the in-flight home-block durability flush.
        expected: StorageRequestIdentity,
        /// Clean-journal continuation revealed after the flush.
        next: HomeBlockDurability,
    },
    /// Clean journal-superblock write.
    CleanWrite {
        /// Identity of the in-flight clean journal write.
        expected: StorageRequestIdentity,
        /// Clean journal durability continuation retained through the write.
        next: CleanJournalDurability,
    },
    /// Flush that makes the clean journal state durable.
    CleanFlush {
        /// Identity of the in-flight clean journal flush.
        expected: StorageRequestIdentity,
        /// Overlay-free epoch publication revealed by successful completion.
        next: CleanJournalDurability,
    },
}

/// Resolver continuation selected after an FsRtl oplock conflict boundary returns the IRP.
#[derive(Debug)]
enum OplockResume {
    /// An ordinary handle mutation continues the exact resolver that preceded its break check.
    ContinueResolution {
        /// Immutable epoch retained through a possible oplock wait.
        epoch: EpochLease,
        /// Resolver that has not yet observed an event.
        resolve: MutationResolveOperation,
    },
    /// An existing-node create restarts resolution and revalidates its provisional claim.
    RestartExistingCreate,
    /// Final cleanup restarts against a fresh epoch after the parent-directory break completes.
    RestartCleanupDeletion {
        /// Exact parent authorized by the completed removal check.
        parent: ext4_core::DirectoryNodeId,
    },
}

/// Parent-directory oplock authority retained across cleanup deletion re-resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupParentOplockState {
    /// No final cleanup deletion parent has been checked.
    Unresolved,
    /// The exact pending-delete parent completed its required removal break or had no resident FCB.
    Authorized(ext4_core::DirectoryNodeId),
}

impl CleanupParentOplockState {
    /// Reports whether this authority covers the exact pending-delete parent.
    fn authorizes(self, parent: ext4_core::DirectoryNodeId) -> bool {
        matches!(self, Self::Authorized(authorized) if authorized == parent)
    }
}

/// Explicit ownership phase of one journaled mutation operation.
#[derive(Debug)]
enum MutationOperationState {
    /// A handle mutation is ready to transfer its IRP to the stream oplock package.
    CheckingOplock {
        /// Unique top-level completion authority before FsRtl delegation.
        owned: OwnedIrp,
        /// Stream lease and normalized check flags.
        check: OplockCheck,
        /// Exact continuation selected after FsRtl returns the IRP.
        resume: OplockResume,
    },
    /// FsRtl owns the raw top-level IRP and the external envelope owns this operation.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "host tests cannot execute the WDK callback that consumes this continuation"
        )
    )]
    OplockDelegated {
        /// Exact continuation retained until IRP ownership returns.
        resume: OplockResume,
    },
    /// The reactor restored driver IRP/cancel authority after FsRtl completion.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "host tests cannot execute the WDK callback that constructs this resumed state"
        )
    )]
    OplockReady {
        /// Unique top-level completion authority returned by FsRtl.
        owned: OwnedIrp,
        /// Exact immediate or callback-published oplock status.
        status: wdk_sys::NTSTATUS,
        /// Exact continuation entered only after successful oplock admission.
        resume: OplockResume,
    },
    /// A within-EOF cached write is executing outside the actor.
    CacheWriting {
        /// Unique top-level completion authority retaining the input mapping.
        owned: OwnedIrp,
        /// Cursor and successful byte count fixed before Cache Manager acceptance.
        publication: crate::request::file_info::PreparedWritePublication,
    },
    /// A journaled write waits for shared-cache flush and purge.
    CachePurging {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Immutable epoch pinned for the first resolve attempt.
        epoch: EpochLease,
        /// Restartable core resolve state entered only after coherency succeeds.
        resolve: MutationResolveOperation,
    },
    /// Cleanup waits for its FILE_OBJECT private cache map to detach.
    CacheUninitializing {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Immutable epoch pinned for any cleanup deletion resolve.
        epoch: EpochLease,
        /// Restartable cleanup resolve entered after cache-map detachment returns.
        resolve: MutationResolveOperation,
    },
    /// A resolved size mutation establishes its native cache/section gate outside the actor.
    PreparingSizeChange {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Preallocated gates derived under an intent that has already been released.
        plan: crate::state::StreamSizeChangePlan,
        /// Stronger cleanup-deletion gate retained while other streams prepare size changes.
        deletion: Option<crate::state::PreparedStreamDeletion>,
    },
    /// A disposition or cleanup deletion flushes image/data sections outside the actor.
    PreparingDeletion {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Size gates already retained for other streams.
        size_changes: Option<crate::state::PreparedStreamSizeChanges>,
    },
    /// An existing regular-file create flushes its executable image outside the actor.
    PreparingWriteOpen {
        /// Unique top-level create completion authority.
        owned: OwnedIrp,
    },
    /// Read-only resolution against one immutable epoch.
    Resolving {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Immutable epoch pinned for this resolve attempt.
        epoch: EpochLease,
        /// Restartable core resolve state.
        resolve: MutationResolveOperation,
        /// Native gates already coherent and retained across the latest resolve attempt.
        size_changes: Option<crate::state::PreparedStreamSizeChanges>,
        /// Exact cleanup stream already drained and sealed for deletion.
        deletion: Option<crate::state::PreparedStreamDeletion>,
    },
    /// Resolved resources await atomic intent acquisition.
    AwaitingIntent {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Resource-version-bearing resolved mutation.
        resolved: ResolvedMutation,
        /// Driver publication values prepared by resolve.
        publication: PendingDriverPublication,
        /// Native gates retained while the resolved projection is revalidated under intent.
        size_changes: Option<crate::state::PreparedStreamSizeChanges>,
        /// Exact cleanup stream retained while its deletion is revalidated under intent.
        deletion: Option<crate::state::PreparedStreamDeletion>,
    },
    /// Revalidated reservation and all publication allocations await commit serialization.
    AwaitingCommit {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Intent-protected core mutation.
        reserved: ReservedMutation,
        /// Fully fallible-prepared driver publication.
        publication: PreparedDriverPublication,
        /// Both epoch storage reservations allocated before the first write.
        slots: EpochPublicationSlots,
        /// Native gate retained when this commit changes stream size.
        size_changes: Option<crate::state::PreparedStreamSizeChanges>,
        /// Native gate retained when this commit removes the cleaned-up regular file.
        deletion: Option<crate::state::PreparedStreamDeletion>,
    },
    /// Commit writes and durability flushes are in progress.
    CommitIo {
        /// Top-level and publication ownership retained through durability.
        context: CommitContext,
        /// Exact in-flight commit I/O phase.
        phase: CommitIoPhase,
    },
    /// Durable mutation waits only for the short visibility gate.
    AwaitingVisibility {
        /// Top-level and publication ownership retained until visibility.
        context: CommitContext,
        /// Core state proven durable but not yet reader-visible.
        durable: DurableMutation,
    },
    /// Durable values plus the consumed visibility grant await infallible publication.
    PublishingDurable {
        /// Top-level and publication ownership consumed by the publish transition.
        context: CommitContext,
        /// Core durable mutation moved into the committed epoch.
        durable: DurableMutation,
        /// One-use short visibility capability.
        visibility: ext4_core::VisibilityLease,
    },
    /// Detached checkpoint waits independently of reader visibility.
    AwaitingCheckpoint(PendingCheckpoint),
    /// Checkpoint lower I/O is in progress.
    CheckpointIo {
        /// Exact in-flight checkpoint I/O phase.
        phase: CheckpointIoPhase,
        /// Pre-reserved overlay-free epoch storage.
        publication: EpochPublicationSlot,
        /// Visible overlay epoch being checkpointed.
        epoch: ext4_core::EpochSequence,
    },
    /// Clean journal and overlay-free epoch await infallible publication.
    PublishingCheckpoint {
        /// Core clean-journal durability state.
        durability: CleanJournalDurability,
        /// Pre-reserved overlay-free epoch storage.
        publication: EpochPublicationSlot,
        /// Visible overlay epoch whose checkpoint is complete.
        epoch: ext4_core::EpochSequence,
    },
    /// Every authority has been consumed.
    Terminal,
}

/// One journaled request whose operation allocation is reused through checkpoint completion.
#[derive(Debug)]
struct MutationRequestOperation {
    /// Validated mounted lower devices.
    devices: MountedStorageRoute,
    /// Write-only operational event capability retained with paging writeback continuations.
    trace: OperationalTrace,
    /// Stable FIFO ticket retained across stale-plan re-resolution.
    ticket: u64,
    /// Close-drain activity retained until every terminal/checkpoint path drops this operation.
    _activity: MutationActivityLease,
    /// Timestamp fixed for the logical mutation across every replay pass.
    now: ext4_core::Ext4Timestamp,
    /// Captured request semantics plus any paging stream lease.
    request: PreparedMutationRequest,
    /// Mutable CNG objects and work buffers retained through resolve and commit.
    crypto: CngOperation,
    /// Cleanup deletion plan retained across resolve suspension.
    cleanup_deletion: Option<crate::request::file_info::PendingCleanupDeletion>,
    /// Parent-directory removal check completed for the current cleanup deletion target.
    cleanup_parent_oplock: CleanupParentOplockState,
    /// Fully allocated disposition state retained while its native preflight runs.
    disposition_deletion: Option<crate::request::file_info::PendingDispositionDeletion>,
    /// Fully allocated existing-node create retained while its native write-open check runs.
    pending_existing_create: Option<crate::request::create::PendingExistingCreateOpen>,
    /// Exact successful native write-open gate retained through FILE_OBJECT attachment.
    write_open: Option<crate::state::PreparedStreamWriteOpen>,
    /// Whether a successful pre-commit write has made abort/replay relevant.
    write_effect_observed: bool,
    /// CLEANUP alone must consume its per-handle terminal barrier before releasing handle state.
    cleanup_barrier_released: bool,
    /// Pre-cleanup failure returned only after cleanup-owned releases have completed.
    cleanup_deferred_error: Option<DriverError>,
    /// Current consuming state.
    state: MutationOperationState,
}

/// Restart-local driver state consulted by exactly one concrete request surface.
struct DriverResolveState<'a> {
    /// Cleanup deletion plan retained across lower-read suspension.
    cleanup_deletion: &'a mut Option<crate::request::file_info::PendingCleanupDeletion>,
    /// Parent-directory removal authority already established for cleanup deletion.
    cleanup_parent_oplock: CleanupParentOplockState,
    /// Disposition deletion plan retained across its native preflight.
    disposition_deletion: &'a mut Option<crate::request::file_info::PendingDispositionDeletion>,
    /// Exact successful deletion gate retained for revalidation.
    prepared_deletion: Option<&'a crate::state::PreparedStreamDeletion>,
    /// Existing-node create retained across its native write-open preflight.
    pending_existing_create: &'a mut Option<crate::request::create::PendingExistingCreateOpen>,
    /// Exact successful write-open gate retained for FILE_OBJECT attachment.
    write_open: Option<&'a crate::state::PreparedStreamWriteOpen>,
}

/// Result of one driver request surface invoked inside an ephemeral core resolve pass.
enum DriverResolveDisposition {
    /// Request completed without staging a filesystem mutation.
    Complete(TopLevelCompletion),
    /// A regular-file disposition must establish a native deletion gate outside the actor.
    PrepareDispositionDeletion {
        /// Stable FCB retained by the pending SET_INFORMATION IRP.
        fcb: core::ptr::NonNull<crate::state::FileControlBlock>,
        /// Exact regular-file inode bound to that FCB.
        node: ext4_core::NodeId,
    },
    /// Final cleanup must break the parent-directory oplock before staging link removal.
    CheckCleanupParentOplock {
        /// Exact directory containing the stable pending-delete target.
        parent: ext4_core::DirectoryNodeId,
    },
    /// A resident regular-file create must flush its executable image outside the actor.
    PrepareWriteOpen {
        /// Stable FCB retained by the provisional existing-node share claim.
        fcb: core::ptr::NonNull<crate::state::FileControlBlock>,
        /// Exact regular-file inode bound to that FCB.
        node: ext4_core::NodeId,
    },
    /// An existing-node create must visit its stream oplock package before attachment.
    CheckOplock {
        /// Exact FCB retained by the provisional create claim.
        fcb: core::ptr::NonNull<crate::state::FileControlBlock>,
        /// Normalized create oplock behavior.
        policy: crate::irp::OplockCreatePolicy,
    },
    /// An existing-node create must synchronously establish its encoded atomic oplock.
    ReserveOplock {
        /// Exact FCB retained by the provisional create claim.
        fcb: core::ptr::NonNull<crate::state::FileControlBlock>,
        /// User-handle count captured with the same provisional claim.
        open_count: core::num::NonZeroU32,
    },
    /// Core mutation and corresponding post-commit driver values were staged.
    Mutation(PendingDriverPublication),
}

impl MutationRequestOperation {
    /// Retains the current node stream when this request class can break an oplock.
    ///
    /// Position-only updates and paging writeback do not change stream or namespace state, so
    /// they bypass this break protocol. CREATE has a separate admission protocol; CLEANUP derives
    /// its FsRtl flags from the exact opened handle before releasing any handle-owned state.
    /// # Errors
    ///
    /// Returns request decoding, FILE_OBJECT identity, or finite stream-lease failures before any
    /// oplock break is initiated.
    fn prepare_oplock_check(
        request: &PreparedMutationRequest,
        owned: &mut OwnedIrp,
        access: &MountedVolumeAccess<'_>,
    ) -> DriverResult<Option<OplockCheck>> {
        let requires_check = match request {
            PreparedMutationRequest::DataWrite(authority) => {
                !authority.is_paging()
                    && !owned
                        .request()
                        .prepared_write()?
                        .stack()
                        .length()
                        .is_empty()
            }
            PreparedMutationRequest::Other(MutationRequestKind::SetInformation) => {
                owned.request().with_active(|active| {
                    let class = active.current_stack()?.set_file()?.information_class();
                    Ok::<_, DriverError>(class != crate::irp::SetFileInformationClass::Position)
                })?
            }
            PreparedMutationRequest::Other(
                MutationRequestKind::SetEa
                | MutationRequestKind::SetSecurity
                | MutationRequestKind::SetReparsePoint
                | MutationRequestKind::DeleteReparsePoint
                | MutationRequestKind::EnableVerity,
            ) => true,
            PreparedMutationRequest::Other(
                MutationRequestKind::Create
                | MutationRequestKind::SetVolumeInformation
                | MutationRequestKind::AddEncryptionKey
                | MutationRequestKind::RemoveEncryptionKey,
            ) => false,
            PreparedMutationRequest::Other(MutationRequestKind::Cleanup) => {
                return owned.request().with_active(|active| {
                    let file_object = active.current_stack()?.file_object()?;
                    match crate::state::OpenedFileObject::decode(file_object)? {
                        crate::state::OpenedFileObject::Node(opened) => {
                            let deletion = opened.create_deletion();
                            access
                                .acquire_oplock_stream_lease(file_object)
                                .map(|stream| OplockCheck::cleanup(stream, deletion))
                                .map(Some)
                        }
                        crate::state::OpenedFileObject::Volume(_) => Ok(None),
                    }
                });
            }
            PreparedMutationRequest::Other(MutationRequestKind::Write) => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        };
        if !requires_check {
            return Ok(None);
        }
        owned.request().with_active(|active| {
            let file_object = active.current_stack()?.file_object()?;
            access
                .acquire_oplock_stream_lease(file_object)
                .map(OplockCheck::ordinary)
                .map(Some)
        })
    }

    /// Allocates one mutation operation after acquiring its stable ticket and epoch lease.
    /// # Errors
    ///
    /// Returns the still-owned IRP when mounted state, time, crypto, ticket, epoch, or operation
    /// allocation cannot be acquired.
    fn try_new(
        mut owned: OwnedIrp,
        kind: MutationRequestKind,
        access: &mut MountedVolumeAccess<'_>,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        let request = match PreparedMutationRequest::prepare(kind, &mut owned, access) {
            Ok(request) => request,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        let oplock = match Self::prepare_oplock_check(&request, &mut owned, access) {
            Ok(oplock) => oplock,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        let trace = access.operational_trace();
        let paging = request.is_paging();
        let now = match crate::kernel::time::current_ext4_timestamp() {
            Ok(now) => now,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        let crypto = match access.new_crypto_operation() {
            Ok(crypto) => crypto,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        let (ticket, activity) = match access.admit_mutation() {
            Ok(admission) => admission,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        let epoch = match access.acquire_epoch() {
            Ok(epoch) => epoch,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        let devices = access.storage_route();
        let resolve = MutationResolveOperation::new(access.mounted_profile());
        match memory::boxed_try_map(
            (owned, epoch, crypto, activity, request),
            |(owned, epoch, crypto, activity, request)| {
                let state = match oplock {
                    Some(check) => MutationOperationState::CheckingOplock {
                        owned,
                        check,
                        resume: OplockResume::ContinueResolution { epoch, resolve },
                    },
                    None => MutationOperationState::Resolving {
                        owned,
                        epoch,
                        resolve,
                        size_changes: None,
                        deletion: None,
                    },
                };
                Self {
                    devices,
                    trace,
                    ticket,
                    _activity: activity,
                    now,
                    request,
                    crypto,
                    cleanup_deletion: None,
                    cleanup_parent_oplock: CleanupParentOplockState::Unresolved,
                    disposition_deletion: None,
                    pending_existing_create: None,
                    write_open: None,
                    write_effect_observed: false,
                    cleanup_barrier_released: false,
                    cleanup_deferred_error: None,
                    state,
                }
            },
        ) {
            Ok(operation) => {
                if paging {
                    trace.record(
                        OperationalPath::PagingWrite,
                        STATUS_SUCCESS,
                        OperationalOutcome::Selected,
                    );
                }
                Ok(operation)
            }
            Err(error) => {
                let (error, (owned, _epoch, _crypto, _activity, _request)) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Completes one top-level success with its major-function-specific ownership protocol.
    fn complete_success(
        &self,
        owned: OwnedIrp,
        completion: TopLevelCompletion,
    ) -> OperationTransition {
        if let Some(error) = self.cleanup_deferred_error {
            if self.request.is_paging() {
                self.trace.record(
                    OperationalPath::PagingWrite,
                    error.ntstatus(),
                    OperationalOutcome::Failed,
                );
            }
            match completion {
                TopLevelCompletion::Normal(_) => {
                    let _status = owned.complete_result(Err(error));
                }
                TopLevelCompletion::Create(_) => {
                    let _status = owned.complete_create_result(Err(error));
                }
            }
            return OperationTransition::Complete;
        }
        if self.request.is_paging() {
            self.trace.record(
                OperationalPath::PagingWrite,
                STATUS_SUCCESS,
                OperationalOutcome::Completed,
            );
        }
        match completion {
            TopLevelCompletion::Normal(completion) => {
                let _status = owned.complete(completion);
            }
            TopLevelCompletion::Create(completion) => {
                let _status = owned.complete_create_result(Ok(completion));
            }
        }
        OperationTransition::Complete
    }

    /// Completes one top-level failure while respecting create auxiliary-buffer ownership.
    fn complete_error(
        mut self: Box<Self>,
        owned: OwnedIrp,
        mut error: DriverError,
    ) -> OperationTransition {
        if self.request.is_paging() {
            self.trace.record(
                OperationalPath::PagingWrite,
                error.ntstatus(),
                OperationalOutcome::Failed,
            );
        }
        if let Some(pending) = self.pending_existing_create.take()
            && let Err(backout_error) = pending.abort(&owned)
        {
            error = backout_error;
        }
        drop(self.write_open.take());
        if let Some(deletion) = self.cleanup_deletion.as_mut() {
            deletion.abort_before_failure_completion();
        }
        if self.request.kind() == MutationRequestKind::Create {
            let _status = owned.complete_create_result(Err(error));
        } else {
            let _status = owned.complete_result(Err(error));
        }
        OperationTransition::Complete
    }

    /// Runs the concrete driver mutation surface inside one restart-local core pass.
    /// # Errors
    ///
    /// Returns an error from request decoding, mutation staging, pre-commit publication
    /// preparation, or cleanup lifecycle validation.
    fn execute_resolve(
        request: &PreparedMutationRequest,
        state: DriverResolveState<'_>,
        owned: &mut OwnedIrp,
        operations: &mut crate::state::MountedVolumeAccess<'_>,
        mutation: &mut crate::request::DriverMutationPass<'_, '_, '_>,
    ) -> DriverResult<DriverResolveDisposition> {
        match request {
            PreparedMutationRequest::Other(MutationRequestKind::Create) => {
                match crate::request::create::execute(
                    owned.request(),
                    operations,
                    mutation,
                    state.pending_existing_create,
                    state.write_open,
                )? {
                    crate::request::create::CreateResolution::Complete(completion) => Ok(
                        DriverResolveDisposition::Complete(TopLevelCompletion::Create(completion)),
                    ),
                    crate::request::create::CreateResolution::PrepareWriteOpen { fcb, node } => {
                        Ok(DriverResolveDisposition::PrepareWriteOpen { fcb, node })
                    }
                    crate::request::create::CreateResolution::CheckOplock { fcb, policy } => {
                        Ok(DriverResolveDisposition::CheckOplock { fcb, policy })
                    }
                    crate::request::create::CreateResolution::ReserveOplock { fcb, open_count } => {
                        Ok(DriverResolveDisposition::ReserveOplock { fcb, open_count })
                    }
                    crate::request::create::CreateResolution::Mutation(publication) => {
                        Ok(DriverResolveDisposition::Mutation(
                            PendingDriverPublication::Create(publication),
                        ))
                    }
                }
            }
            PreparedMutationRequest::DataWrite(authority) => {
                match crate::request::file_info::write(owned.request(), mutation, authority)? {
                    crate::request::file_info::WriteResolution::Complete(completion) => Ok(
                        DriverResolveDisposition::Complete(TopLevelCompletion::Normal(completion)),
                    ),
                    crate::request::file_info::WriteResolution::Mutation(publication) => {
                        Ok(DriverResolveDisposition::Mutation(
                            PendingDriverPublication::Write(publication),
                        ))
                    }
                }
            }
            PreparedMutationRequest::Other(MutationRequestKind::SetInformation) => {
                match crate::request::file_info::set(
                    owned.request(),
                    operations,
                    mutation,
                    state.disposition_deletion,
                    state.prepared_deletion,
                )? {
                    crate::request::file_info::SetFileResolution::Complete(completion) => Ok(
                        DriverResolveDisposition::Complete(TopLevelCompletion::Normal(completion)),
                    ),
                    crate::request::file_info::SetFileResolution::PrepareDeletion { fcb, node } => {
                        Ok(DriverResolveDisposition::PrepareDispositionDeletion { fcb, node })
                    }
                    crate::request::file_info::SetFileResolution::Mutation(publication) => {
                        Ok(DriverResolveDisposition::Mutation(
                            PendingDriverPublication::SetFile(publication),
                        ))
                    }
                }
            }
            PreparedMutationRequest::Other(MutationRequestKind::SetEa) => {
                let completion = crate::request::ea::set(owned.request(), mutation)?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Normal(completion),
                ))
            }
            PreparedMutationRequest::Other(MutationRequestKind::SetSecurity) => {
                let completion = crate::request::security::set(owned.request(), mutation)?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Normal(completion),
                ))
            }
            PreparedMutationRequest::Other(MutationRequestKind::SetVolumeInformation) => {
                match crate::request::volume_info::set(owned.request(), operations, mutation)? {
                    crate::request::volume_info::SetVolumeResolution::Complete(completion) => Ok(
                        DriverResolveDisposition::Complete(TopLevelCompletion::Normal(completion)),
                    ),
                    crate::request::volume_info::SetVolumeResolution::Mutation(publication) => {
                        Ok(DriverResolveDisposition::Mutation(
                            PendingDriverPublication::VolumeLabel(publication),
                        ))
                    }
                }
            }
            PreparedMutationRequest::Other(MutationRequestKind::SetReparsePoint) => {
                let mut request = owned.request();
                crate::request::file_system_control::authorize_path_handle(
                    &mut request,
                    operations,
                )?;
                let completion = crate::request::reparse::set_reparse_point(request, mutation)?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Normal(completion),
                ))
            }
            PreparedMutationRequest::Other(MutationRequestKind::DeleteReparsePoint) => {
                let mut request = owned.request();
                crate::request::file_system_control::authorize_path_handle(
                    &mut request,
                    operations,
                )?;
                let completion = crate::request::reparse::delete_reparse_point(request, mutation)?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Normal(completion),
                ))
            }
            PreparedMutationRequest::Other(MutationRequestKind::EnableVerity) => {
                let mut request = owned.request();
                crate::request::file_system_control::authorize_path_handle(
                    &mut request,
                    operations,
                )?;
                let completion = crate::request::fsctl::enable_verity(request, mutation)?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Normal(completion),
                ))
            }
            PreparedMutationRequest::Other(MutationRequestKind::AddEncryptionKey) => {
                let mut request = owned.request();
                crate::request::file_system_control::authorize_path_handle(
                    &mut request,
                    operations,
                )?;
                let stack =
                    request.with_active(|active| active.current_stack()?.file_system_control())?;
                let completion =
                    crate::request::fsctl::add_encryption_key(&mut request, stack, mutation)?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Normal(completion),
                ))
            }
            PreparedMutationRequest::Other(MutationRequestKind::RemoveEncryptionKey) => {
                let mut request = owned.request();
                crate::request::file_system_control::authorize_path_handle(
                    &mut request,
                    operations,
                )?;
                let stack =
                    request.with_active(|active| active.current_stack()?.file_system_control())?;
                let completion =
                    crate::request::fsctl::remove_encryption_key(&mut request, stack, mutation)?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Normal(completion),
                ))
            }
            PreparedMutationRequest::Other(MutationRequestKind::Cleanup) => {
                if state.cleanup_deletion.is_none() {
                    match crate::request::file_info::cleanup(owned.request(), operations)? {
                        crate::request::file_info::CleanupResolution::Complete(completion) => {
                            return Ok(DriverResolveDisposition::Complete(
                                TopLevelCompletion::Normal(completion),
                            ));
                        }
                        crate::request::file_info::CleanupResolution::Delete(deletion) => {
                            *state.cleanup_deletion = Some(deletion);
                        }
                    }
                }
                let Some(deletion) = state.cleanup_deletion.as_ref() else {
                    return Err(DriverError::InternalInvariantViolation);
                };
                let parent = deletion.parent();
                if !state.cleanup_parent_oplock.authorizes(parent) {
                    return Ok(DriverResolveDisposition::CheckCleanupParentOplock { parent });
                }
                let publication =
                    crate::request::file_info::stage_cleanup_deletion(deletion, mutation)?;
                let publication = memory::boxed_try_with(move || Ok(publication))?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Cleanup(publication),
                ))
            }
            PreparedMutationRequest::Other(MutationRequestKind::Write) => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }

    /// Reacquires the latest immutable epoch while retaining the original FIFO ticket.
    fn restart_resolution(
        self: Box<Self>,
        owned: OwnedIrp,
        size_changes: Option<crate::state::PreparedStreamSizeChanges>,
        deletion: Option<crate::state::PreparedStreamDeletion>,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let epoch = match access.acquire_epoch() {
            Ok(epoch) => epoch,
            Err(error) => return self.complete_error(owned, error),
        };
        let resolve = MutationResolveOperation::new(access.mounted_profile());
        self.advance_resolution(
            owned,
            ResolutionAttempt {
                epoch,
                resolve,
                size_changes,
                deletion,
            },
            OperationEvent::Admitted,
            access,
        )
    }

    /// Integrates one resolution event and emits only its matching next action.
    fn advance_resolution(
        mut self: Box<Self>,
        mut owned: OwnedIrp,
        attempt: ResolutionAttempt,
        event: OperationEvent,
        operations: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let ResolutionAttempt {
            epoch,
            resolve,
            size_changes,
            deletion,
        } = attempt;
        let mut ready = match resolve.accept(event) {
            Ok(ready) => ready,
            Err(error) => return self.complete_error(owned, DriverError::from(error)),
        };
        // The version set sealed below must describe the same inode/allocation snapshot as this
        // pass. A completed lower read from an older epoch cannot be relabeled with new versions.
        if !operations.is_current_epoch(&epoch) {
            drop(ready);
            return self.restart_resolution(owned, size_changes, deletion, operations);
        }
        let mut publication = None;
        let resolved = {
            let request = &self.request;
            let mut pass = ready.begin_pass(epoch.epoch(), self.now, &mut self.crypto);
            match Self::execute_resolve(
                request,
                DriverResolveState {
                    cleanup_deletion: &mut self.cleanup_deletion,
                    cleanup_parent_oplock: self.cleanup_parent_oplock,
                    disposition_deletion: &mut self.disposition_deletion,
                    prepared_deletion: deletion.as_ref(),
                    pending_existing_create: &mut self.pending_existing_create,
                    write_open: self.write_open.as_ref(),
                },
                &mut owned,
                operations,
                &mut pass,
            ) {
                Ok(DriverResolveDisposition::Complete(completion)) => {
                    if self.request.kind() == MutationRequestKind::Create {
                        if self.pending_existing_create.is_some() {
                            return self
                                .complete_error(owned, DriverError::InternalInvariantViolation);
                        }
                        drop(self.write_open.take());
                    }
                    return self.complete_success(owned, completion);
                }
                Ok(DriverResolveDisposition::CheckCleanupParentOplock { parent }) => {
                    drop(pass);
                    if self.request.kind() != MutationRequestKind::Cleanup
                        || self.cleanup_deletion.is_none()
                        || size_changes.is_some()
                        || deletion.is_some()
                    {
                        return self.complete_error(owned, DriverError::InternalInvariantViolation);
                    }
                    let stream = match operations.acquire_parent_oplock_stream_lease(parent) {
                        Ok(stream) => stream,
                        Err(error) => return self.complete_error(owned, error),
                    };
                    let Some(stream) = stream else {
                        self.cleanup_parent_oplock = CleanupParentOplockState::Authorized(parent);
                        return self.restart_resolution(owned, None, None, operations);
                    };
                    self.state = MutationOperationState::OplockDelegated {
                        resume: OplockResume::RestartCleanupDeletion { parent },
                    };
                    return OperationTransition::CheckOplock {
                        check: OplockCheck::parent_removal(stream),
                        owned,
                        suspended: self,
                    };
                }
                Ok(DriverResolveDisposition::PrepareDispositionDeletion { fcb, node }) => {
                    drop(pass);
                    let stream = match operations.prepare_stream_deletion(fcb, node) {
                        Ok(Some(stream)) => stream,
                        Ok(None) => {
                            return self
                                .complete_error(owned, DriverError::InternalInvariantViolation);
                        }
                        Err(error) => return self.complete_error(owned, error),
                    };
                    self.state = MutationOperationState::PreparingDeletion {
                        owned,
                        size_changes,
                    };
                    return OperationTransition::SubmitCacheWork {
                        work: crate::irp::CacheWork::prepare_deletion(stream),
                        suspended: self,
                    };
                }
                Ok(DriverResolveDisposition::PrepareWriteOpen { fcb, node }) => {
                    drop(pass);
                    if size_changes.is_some()
                        || deletion.is_some()
                        || self.pending_existing_create.is_none()
                        || self.write_open.is_some()
                    {
                        return self.complete_error(owned, DriverError::InternalInvariantViolation);
                    }
                    let stream = match operations.prepare_stream_write_open(fcb, node) {
                        Ok(stream) => stream,
                        Err(error) => return self.complete_error(owned, error),
                    };
                    self.state = MutationOperationState::PreparingWriteOpen { owned };
                    return OperationTransition::SubmitCacheWork {
                        work: crate::irp::CacheWork::prepare_write_open(stream),
                        suspended: self,
                    };
                }
                Ok(DriverResolveDisposition::CheckOplock { fcb, policy }) => {
                    drop(pass);
                    if size_changes.is_some()
                        || deletion.is_some()
                        || self.pending_existing_create.is_none()
                        || self.write_open.is_some()
                    {
                        return self.complete_error(owned, DriverError::InternalInvariantViolation);
                    }
                    let stream = match operations.acquire_claimed_oplock_stream_lease(fcb) {
                        Ok(stream) => stream,
                        Err(error) => return self.complete_error(owned, error),
                    };
                    let check = match OplockCheck::create(stream, policy) {
                        Ok(check) => check,
                        Err(error) => return self.complete_error(owned, error),
                    };
                    self.state = MutationOperationState::OplockDelegated {
                        resume: OplockResume::RestartExistingCreate,
                    };
                    return OperationTransition::CheckOplock {
                        check,
                        owned,
                        suspended: self,
                    };
                }
                Ok(DriverResolveDisposition::ReserveOplock { fcb, open_count }) => {
                    drop(pass);
                    if size_changes.is_some()
                        || deletion.is_some()
                        || self.pending_existing_create.is_none()
                        || self.write_open.is_some()
                    {
                        return self.complete_error(owned, DriverError::InternalInvariantViolation);
                    }
                    let stream = match operations.acquire_claimed_oplock_stream_lease(fcb) {
                        Ok(stream) => stream,
                        Err(error) => return self.complete_error(owned, error),
                    };
                    let reservation =
                        match AtomicOplockReservation::acquire(stream, open_count, &owned) {
                            Ok(reservation) => reservation,
                            Err(error) => return self.complete_error(owned, error),
                        };
                    self.pending_existing_create
                        .as_mut()
                        .unwrap_or_else(|| {
                            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                                .bugcheck()
                        })
                        .accept_oplock_reservation(reservation);
                    return self.restart_resolution(owned, None, None, operations);
                }
                Ok(DriverResolveDisposition::Mutation(prepared)) => {
                    if self.pending_existing_create.is_some() || self.write_open.is_some() {
                        return self.complete_error(owned, DriverError::InternalInvariantViolation);
                    }
                    publication = Some(prepared);
                    operations.resolve_mutation(pass, self.ticket)
                }
                Err(DriverError::Core(Error::OperationSuspended)) => Err(Error::OperationSuspended),
                Err(DriverError::CacheManagerFailure(STATUS_RETRY))
                    if self.request.kind() == MutationRequestKind::Create
                        && self.pending_existing_create.is_some() =>
                {
                    drop(pass);
                    let pending = self.pending_existing_create.take().unwrap_or_else(|| {
                        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                            .bugcheck()
                    });
                    if let Err(error) = pending.abort(&owned) {
                        return self.complete_error(owned, error);
                    }
                    drop(self.write_open.take());
                    return self.restart_resolution(owned, None, None, operations);
                }
                Err(error) => return self.complete_error(owned, error),
            }
        };
        match ready.finish(resolved) {
            MutationResolveTransition::SubmitLower { request, suspended } => {
                self.state = MutationOperationState::Resolving {
                    owned,
                    epoch,
                    resolve: suspended,
                    size_changes,
                    deletion,
                };
                OperationTransition::SubmitLower {
                    devices: self.devices,
                    request,
                    suspended: self,
                }
            }
            MutationResolveTransition::Complete(Ok(resolved)) => {
                let Some(publication) = publication else {
                    return self.complete_error(owned, DriverError::InternalInvariantViolation);
                };
                let resources = resolved.observed_resources().resources();
                let mut requested = match memory::DriverVec::try_with_capacity(resources.len()) {
                    Ok(requested) => requested,
                    Err(error) => return self.complete_error(owned, error),
                };
                for resource in resources {
                    if let Err(error) = requested.try_push(resource) {
                        return self.complete_error(owned, error);
                    }
                }
                self.state = MutationOperationState::AwaitingIntent {
                    owned,
                    resolved,
                    publication,
                    size_changes,
                    deletion,
                };
                OperationTransition::RequestIntent {
                    request: IntentRequest::new(self.ticket, requested),
                    suspended: self,
                }
            }
            MutationResolveTransition::Complete(Err(error)) => {
                self.complete_error(owned, DriverError::from(error))
            }
        }
    }

    /// Submits one commit-phase request after storing its exact expected completion identity.
    fn submit_commit_request(
        mut self: Box<Self>,
        context: CommitContext,
        phase: CommitIoPhase,
        request: StorageRequest,
    ) -> OperationTransition {
        self.state = MutationOperationState::CommitIo { context, phase };
        OperationTransition::SubmitLower {
            devices: self.devices,
            request,
            suspended: self,
        }
    }

    /// Emits the next ordered-data request or its required filesystem flush.
    fn drive_ordered(
        self: Box<Self>,
        context: CommitContext,
        sequence: StorageRequestSequence<OrderedDataDurability>,
    ) -> OperationTransition {
        match sequence.advance() {
            StorageRequestSequenceStep::Submit { request, suspended } => {
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_commit_request(
                    context,
                    CommitIoPhase::OrderedWrite {
                        expected,
                        remaining: suspended,
                    },
                    request,
                )
            }
            StorageRequestSequenceStep::Finished(next) => {
                let request = next.flush_request();
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_commit_request(
                    context,
                    CommitIoPhase::OrderedFlush { expected, next },
                    request,
                )
            }
        }
    }

    /// Emits the next journal payload write or its pre-commit durability flush.
    fn drive_journal(
        self: Box<Self>,
        context: CommitContext,
        sequence: StorageRequestSequence<JournalPayloadDurability>,
    ) -> OperationTransition {
        match sequence.advance() {
            StorageRequestSequenceStep::Submit { request, suspended } => {
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_commit_request(
                    context,
                    CommitIoPhase::JournalWrite {
                        expected,
                        remaining: suspended,
                    },
                    request,
                )
            }
            StorageRequestSequenceStep::Finished(next) => {
                let request = next.flush_request();
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_commit_request(
                    context,
                    CommitIoPhase::JournalFlush { expected, next },
                    request,
                )
            }
        }
    }

    /// Submits the single commit record after journal payload durability.
    fn submit_commit_record(
        self: Box<Self>,
        context: CommitContext,
        payload: JournalPayloadDurability,
    ) -> OperationTransition {
        let (request, next) = payload.completed().submit();
        let expected = StorageRequestIdentity::from_request(&request);
        self.submit_commit_request(
            context,
            CommitIoPhase::CommitWrite { expected, next },
            request,
        )
    }

    /// Submits the flush that makes the commit record durable.
    fn submit_commit_flush(
        self: Box<Self>,
        context: CommitContext,
        next: CommitDurability,
    ) -> OperationTransition {
        let request = next.flush_request();
        let expected = StorageRequestIdentity::from_request(&request);
        self.submit_commit_request(
            context,
            CommitIoPhase::CommitFlush { expected, next },
            request,
        )
    }

    /// Converts a commit-path lower failure into a recovery-required terminal result.
    fn fail_commit_path(
        self: Box<Self>,
        context: CommitContext,
        error: Error,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if self.write_effect_observed {
            access.record_durability_unknown();
        }
        self.complete_error(context.owned, DriverError::from(error))
    }

    /// Records one successfully completed pre-visibility write.
    fn observed_write(mut self: Box<Self>) -> Box<Self> {
        self.write_effect_observed = true;
        if let Some(deletion) = self.cleanup_deletion.as_mut() {
            deletion.preserve_pending_after_uncertain_effect();
        }
        self
    }

    /// Integrates one matching commit-phase completion and advances only that phase.
    fn advance_commit_io(
        self: Box<Self>,
        context: CommitContext,
        phase: CommitIoPhase,
        event: OperationEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let OperationEvent::StorageCompleted(completion) = event else {
            return self.fail_commit_path(context, Error::DeviceIo, access);
        };
        match phase {
            CommitIoPhase::OrderedWrite {
                expected,
                remaining,
            } => match expected.complete(completion) {
                Ok(()) => self.observed_write().drive_ordered(context, remaining),
                Err(error) => self.fail_commit_path(context, error, access),
            },
            CommitIoPhase::OrderedFlush { expected, next } => match expected.complete(completion) {
                Ok(()) => self.drive_journal(context, next.completed()),
                Err(error) => self.fail_commit_path(context, error, access),
            },
            CommitIoPhase::JournalWrite {
                expected,
                remaining,
            } => match expected.complete(completion) {
                Ok(()) => self.observed_write().drive_journal(context, remaining),
                Err(error) => self.fail_commit_path(context, error, access),
            },
            CommitIoPhase::JournalFlush { expected, next } => match expected.complete(completion) {
                Ok(()) => self.submit_commit_record(context, next),
                Err(error) => self.fail_commit_path(context, error, access),
            },
            CommitIoPhase::CommitWrite { expected, next } => match expected.complete(completion) {
                Ok(()) => self.observed_write().submit_commit_flush(context, next),
                Err(error) => self.fail_commit_path(context, error, access),
            },
            CommitIoPhase::CommitFlush { expected, next } => match expected.complete(completion) {
                Ok(()) => {
                    let durable = next.completed();
                    let ticket = self.ticket;
                    let mut this = self;
                    this.state = MutationOperationState::AwaitingVisibility { context, durable };
                    OperationTransition::Wait {
                        condition: WaitCondition::Visibility { ticket },
                        suspended: this,
                    }
                }
                Err(error) => self.fail_commit_path(context, error, access),
            },
        }
    }

    /// Submits one checkpoint request after storing its expected identity.
    fn submit_checkpoint_request(
        mut self: Box<Self>,
        phase: CheckpointIoPhase,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
        request: StorageRequest,
    ) -> OperationTransition {
        self.state = MutationOperationState::CheckpointIo {
            phase,
            publication,
            epoch,
        };
        OperationTransition::SubmitLower {
            devices: self.devices,
            request,
            suspended: self,
        }
    }

    /// Emits the next home-block write or its filesystem durability flush.
    fn drive_checkpoint_home(
        self: Box<Self>,
        sequence: StorageRequestSequence<HomeBlockDurability>,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
    ) -> OperationTransition {
        match sequence.advance() {
            StorageRequestSequenceStep::Submit { request, suspended } => {
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_checkpoint_request(
                    CheckpointIoPhase::HomeWrite {
                        expected,
                        remaining: suspended,
                    },
                    publication,
                    epoch,
                    request,
                )
            }
            StorageRequestSequenceStep::Finished(next) => {
                let request = next.flush_request();
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_checkpoint_request(
                    CheckpointIoPhase::HomeFlush { expected, next },
                    publication,
                    epoch,
                    request,
                )
            }
        }
    }

    /// Submits the clean journal-superblock write after home-block durability.
    fn submit_clean_record(
        self: Box<Self>,
        next: HomeBlockDurability,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
    ) -> OperationTransition {
        let (request, next) = next.completed().submit();
        let expected = StorageRequestIdentity::from_request(&request);
        self.submit_checkpoint_request(
            CheckpointIoPhase::CleanWrite { expected, next },
            publication,
            epoch,
            request,
        )
    }

    /// Submits the flush that establishes a clean journal state.
    fn submit_clean_flush(
        self: Box<Self>,
        next: CleanJournalDurability,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
    ) -> OperationTransition {
        let request = next.flush_request();
        let expected = StorageRequestIdentity::from_request(&request);
        self.submit_checkpoint_request(
            CheckpointIoPhase::CleanFlush { expected, next },
            publication,
            epoch,
            request,
        )
    }

    /// Ends a failed detached checkpoint while retaining the already published overlay.
    fn fail_checkpoint(
        &self,
        publication: EpochPublicationSlot,
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        drop(publication);
        match failure {
            StorageFailureClass::Terminal => access.record_durable_abort(),
            StorageFailureClass::ReadUnreliable => {
                access.record_read_unreliable();
            }
            StorageFailureClass::DurabilityUnknown { .. } => {
                access.record_durability_unknown();
            }
        }
        OperationTransition::Complete
    }

    /// Integrates one matching detached-checkpoint completion.
    fn advance_checkpoint_io(
        self: Box<Self>,
        phase: CheckpointIoPhase,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
        event: OperationEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let OperationEvent::StorageCompleted(completion) = event else {
            return self.fail_checkpoint(
                publication,
                StorageFailureClass::DurabilityUnknown { completed: 0 },
                access,
            );
        };
        match phase {
            CheckpointIoPhase::HomeWrite {
                expected,
                remaining,
            } => match expected.complete(completion) {
                Ok(()) => self.drive_checkpoint_home(remaining, publication, epoch),
                Err(_) => self.fail_checkpoint(publication, StorageFailureClass::Terminal, access),
            },
            CheckpointIoPhase::HomeFlush { expected, next } => {
                match expected.complete(completion) {
                    Ok(()) => self.submit_clean_record(next, publication, epoch),
                    Err(_) => {
                        self.fail_checkpoint(publication, StorageFailureClass::Terminal, access)
                    }
                }
            }
            CheckpointIoPhase::CleanWrite { expected, next } => {
                match expected.complete(completion) {
                    Ok(()) => self.submit_clean_flush(next, publication, epoch),
                    Err(_) => self.fail_checkpoint(
                        publication,
                        StorageFailureClass::DurabilityUnknown { completed: 0 },
                        access,
                    ),
                }
            }
            CheckpointIoPhase::CleanFlush { expected, next } => {
                match expected.complete(completion) {
                    Ok(()) => {
                        let mut this = self;
                        this.state = MutationOperationState::PublishingCheckpoint {
                            durability: next,
                            publication,
                            epoch,
                        };
                        OperationTransition::Publish { publication: this }
                    }
                    Err(_) => self.fail_checkpoint(
                        publication,
                        StorageFailureClass::DurabilityUnknown { completed: 0 },
                        access,
                    ),
                }
            }
        }
    }
}

impl OplockContinuation for MutationRequestOperation {
    fn resume_after_oplock(
        mut self: Box<Self>,
        owned: OwnedIrp,
        status: wdk_sys::NTSTATUS,
    ) -> Box<dyn CompletionOperation> {
        let state = core::mem::replace(&mut self.state, MutationOperationState::Terminal);
        let MutationOperationState::OplockDelegated { resume } = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        self.state = MutationOperationState::OplockReady {
            owned,
            status,
            resume,
        };
        self
    }
}

impl MountedVolumeOperation for MutationRequestOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let event = match event {
            CompletionEvent::Core(event) => event,
            CompletionEvent::CacheCompleted(completion) => {
                let state = core::mem::replace(&mut self.state, MutationOperationState::Terminal);
                match (state, completion) {
                    (
                        MutationOperationState::CacheWriting { owned, publication },
                        crate::irp::CacheWorkCompletion::Write(result),
                    ) => {
                        if result == Err(DriverError::CacheManagerFailure(STATUS_RETRY)) {
                            return self.restart_resolution(owned, None, None, access);
                        }
                        return match crate::request::file_info::finish_cached_write(
                            publication,
                            result,
                        ) {
                            Ok(completion) => self.complete_success(
                                owned,
                                TopLevelCompletion::Normal(completion),
                            ),
                            Err(error) => {
                                record_cache_coherency_failure(error, access);
                                self.complete_error(owned, error)
                            }
                        };
                    }
                    (
                        MutationOperationState::CachePurging {
                            owned,
                            epoch,
                            resolve,
                        },
                        crate::irp::CacheWorkCompletion::Purge(result),
                    ) => {
                        return match result {
                            Ok(()) => self.advance_resolution(
                                owned,
                                ResolutionAttempt {
                                    epoch,
                                    resolve,
                                    size_changes: None,
                                    deletion: None,
                                },
                                OperationEvent::Admitted,
                                access,
                            ),
                            Err(DriverError::CacheManagerFailure(STATUS_RETRY)) => {
                                self.restart_resolution(owned, None, None, access)
                            }
                            Err(error) => {
                                record_cache_coherency_failure(error, access);
                                self.complete_error(owned, error)
                            }
                        };
                    }
                    (
                        MutationOperationState::CacheUninitializing {
                            owned,
                            epoch,
                            resolve,
                        },
                        crate::irp::CacheWorkCompletion::Uninitialize(result),
                    ) => {
                        if let Err(error) = result
                            && self.cleanup_deferred_error.is_none()
                        {
                            self.cleanup_deferred_error = Some(error);
                        }
                        return self.advance_resolution(
                            owned,
                            ResolutionAttempt {
                                epoch,
                                resolve,
                                size_changes: None,
                                deletion: None,
                            },
                            OperationEvent::Admitted,
                            access,
                        );
                    }
                    (
                        MutationOperationState::PreparingSizeChange {
                            owned,
                            mut plan,
                            deletion,
                        },
                        crate::irp::CacheWorkCompletion::PrepareSizeChange(result),
                    ) => {
                        return match result {
                            Ok(size_change) => {
                                if let Err(error) = plan.record_completion(size_change) {
                                    return self.complete_error(owned, error);
                                }
                                if let Some(stream) = plan.next() {
                                    self.state = MutationOperationState::PreparingSizeChange {
                                        owned,
                                        plan,
                                        deletion,
                                    };
                                    OperationTransition::SubmitCacheWork {
                                        work: crate::irp::CacheWork::prepare_size_change(stream),
                                        suspended: self,
                                    }
                                } else {
                                    let size_changes = match plan.into_prepared() {
                                        Ok(size_changes) => size_changes,
                                        Err(error) => return self.complete_error(owned, error),
                                    };
                                    self.restart_resolution(
                                        owned,
                                        size_changes,
                                        deletion,
                                        access,
                                    )
                                }
                            }
                            Err(error) => {
                                record_cache_coherency_failure(error, access);
                                self.complete_error(owned, error)
                            }
                        };
                    }
                    (
                        MutationOperationState::PreparingDeletion {
                            owned,
                            size_changes,
                        },
                        crate::irp::CacheWorkCompletion::PrepareDeletion(result),
                    ) => {
                        return match result {
                            Ok(deletion) => {
                                self.restart_resolution(owned, size_changes, Some(deletion), access)
                            }
                            Err(error) => {
                                record_cache_coherency_failure(error, access);
                                self.complete_error(owned, error)
                            }
                        };
                    }
                    (
                        MutationOperationState::PreparingWriteOpen { owned },
                        crate::irp::CacheWorkCompletion::PrepareWriteOpen(result),
                    ) => {
                        return match result {
                            Ok(write_open) => {
                                if self.write_open.replace(write_open).is_some() {
                                    return self.complete_error(
                                        owned,
                                        DriverError::InternalInvariantViolation,
                                    );
                                }
                                self.restart_resolution(owned, None, None, access)
                            }
                            Err(error) => {
                                record_cache_coherency_failure(error, access);
                                self.complete_error(owned, error)
                            }
                        };
                    }
                    _ => {
                        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                            .bugcheck()
                    }
                }
            }
            CompletionEvent::VolumeFailed(error) => {
                let state = core::mem::replace(&mut self.state, MutationOperationState::Terminal);
                let MutationOperationState::AwaitingCommit { owned, .. } = state else {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                return self.complete_error(owned, error);
            }
        };
        let event = if self.request.kind() == MutationRequestKind::Cleanup
            && !self.cleanup_barrier_released
        {
            match event {
                OperationEvent::Admitted => {
                    return OperationTransition::Wait {
                        condition: WaitCondition::Barrier {
                            identity: CLEANUP_HANDLE_BARRIER,
                        },
                        suspended: self,
                    };
                }
                OperationEvent::BarrierReleased(permit) => {
                    if permit.into_identity() != CLEANUP_HANDLE_BARRIER {
                        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                            .bugcheck();
                    }
                    self.cleanup_barrier_released = true;
                    OperationEvent::Admitted
                }
                _ => {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                        .bugcheck()
                }
            }
        } else {
            event
        };
        let state = core::mem::replace(&mut self.state, MutationOperationState::Terminal);
        match state {
            MutationOperationState::CheckingOplock {
                owned,
                check,
                resume,
            } => match event {
                OperationEvent::Admitted => {
                    self.state = MutationOperationState::OplockDelegated { resume };
                    OperationTransition::CheckOplock {
                        check,
                        owned,
                        suspended: self,
                    }
                }
                OperationEvent::CancelRequested => {
                    self.complete_error(owned, DriverError::from(Error::OperationCancelled))
                }
                _ => self.complete_error(owned, DriverError::InvalidDeviceRequest),
            },
            MutationOperationState::OplockReady {
                owned,
                status,
                resume,
            } => {
                let oplock_error = match event {
                    OperationEvent::CancelRequested => {
                        Some(DriverError::from(Error::OperationCancelled))
                    }
                    OperationEvent::Admitted if status >= STATUS_SUCCESS => None,
                    OperationEvent::Admitted => Some(DriverError::OplockFailure(status)),
                    _ => return self.complete_error(owned, DriverError::InvalidDeviceRequest),
                };
                match resume {
                    OplockResume::ContinueResolution { epoch, resolve } => {
                        if let Some(error) = oplock_error {
                            if self.request.kind() != MutationRequestKind::Cleanup {
                                return self.complete_error(owned, error);
                            }
                            if self.cleanup_deferred_error.is_none() {
                                self.cleanup_deferred_error = Some(error);
                            }
                        }
                        self.advance_resolution(
                            owned,
                            ResolutionAttempt {
                                epoch,
                                resolve,
                                size_changes: None,
                                deletion: None,
                            },
                            OperationEvent::Admitted,
                            access,
                        )
                    }
                    OplockResume::RestartExistingCreate => {
                        if let Some(error) = oplock_error {
                            return self.complete_error(owned, error);
                        }
                        let result = self
                            .pending_existing_create
                            .as_mut()
                            .ok_or(DriverError::InternalInvariantViolation)
                            .and_then(|pending| pending.accept_oplock_status(status));
                        match result {
                            Ok(()) => self.restart_resolution(owned, None, None, access),
                            Err(error) => self.complete_error(owned, error),
                        }
                    }
                    OplockResume::RestartCleanupDeletion { parent } => {
                        if let Some(error) = oplock_error {
                            return self.complete_error(owned, error);
                        }
                        if self.request.kind() != MutationRequestKind::Cleanup
                            || self.cleanup_deletion.is_none()
                        {
                            return self
                                .complete_error(owned, DriverError::InternalInvariantViolation);
                        }
                        self.cleanup_parent_oplock = CleanupParentOplockState::Authorized(parent);
                        self.restart_resolution(owned, None, None, access)
                    }
                }
            }
            MutationOperationState::OplockDelegated { .. } => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
            MutationOperationState::Resolving {
                mut owned,
                epoch,
                resolve,
                size_changes,
                deletion,
            } => {
                if matches!(event, OperationEvent::Admitted)
                    && size_changes.is_none()
                    && deletion.is_none()
                {
                    if self.request.kind() == MutationRequestKind::Cleanup {
                        let work = match crate::request::file_info::prepare_cleanup_cache_work(
                            owned.request(),
                            access,
                        ) {
                            Ok(work) => work,
                            Err(error) => return self.complete_error(owned, error),
                        };
                        if let Some(work) = work {
                            self.state = MutationOperationState::CacheUninitializing {
                                owned,
                                epoch,
                                resolve,
                            };
                            return OperationTransition::SubmitCacheWork {
                                work,
                                suspended: self,
                            };
                        }
                    }
                    if let PreparedMutationRequest::DataWrite(authority) = &self.request {
                        let plan = match crate::request::file_info::prepare_write_cache_plan(
                            owned.request(),
                            authority,
                            access,
                        ) {
                            Ok(plan) => plan,
                            Err(error) => return self.complete_error(owned, error),
                        };
                        match plan {
                            crate::request::file_info::WriteCachePlan::Cached {
                                work,
                                publication,
                            } => {
                                self.state =
                                    MutationOperationState::CacheWriting { owned, publication };
                                return OperationTransition::SubmitCacheWork {
                                    work,
                                    suspended: self,
                                };
                            }
                            crate::request::file_info::WriteCachePlan::PurgeBeforeDirect(work) => {
                                self.state = MutationOperationState::CachePurging {
                                    owned,
                                    epoch,
                                    resolve,
                                };
                                return OperationTransition::SubmitCacheWork {
                                    work,
                                    suspended: self,
                                };
                            }
                            crate::request::file_info::WriteCachePlan::Direct => {}
                        }
                    }
                }
                self.advance_resolution(
                    owned,
                    ResolutionAttempt {
                        epoch,
                        resolve,
                        size_changes,
                        deletion,
                    },
                    event,
                    access,
                )
            }
            MutationOperationState::CacheWriting { .. }
            | MutationOperationState::CachePurging { .. }
            | MutationOperationState::CacheUninitializing { .. } => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
            MutationOperationState::PreparingSizeChange { owned, .. }
            | MutationOperationState::PreparingDeletion { owned, .. }
            | MutationOperationState::PreparingWriteOpen { owned } => match event {
                OperationEvent::CancelRequested => {
                    self.complete_error(owned, DriverError::from(Error::OperationCancelled))
                }
                _ => self.complete_error(owned, DriverError::InvalidDeviceRequest),
            },
            MutationOperationState::AwaitingIntent {
                owned,
                resolved,
                publication,
                size_changes,
                deletion,
            } => {
                let intent = match event {
                    OperationEvent::IntentGranted(intent) => intent,
                    OperationEvent::CancelRequested => {
                        return self
                            .complete_error(owned, DriverError::from(Error::OperationCancelled));
                    }
                    _ => return self.complete_error(owned, DriverError::InvalidDeviceRequest),
                };
                let reserved = access.reserve_mutation(resolved, intent);
                let reserved = match reserved {
                    Ok(reserved) => reserved,
                    Err(Error::ClusterReferenceConflict) => {
                        drop(publication);
                        return self.restart_resolution(owned, size_changes, deletion, access);
                    }
                    Err(error) => {
                        drop(publication);
                        return self.complete_error(owned, DriverError::from(error));
                    }
                };
                let stream_sizes = match crate::state::PreparedStreamSizePublications::try_new(
                    reserved.node_storage_updates(),
                    access.volume_geometry().cluster_size(),
                ) {
                    Ok(stream_sizes) => stream_sizes,
                    Err(error) => return self.complete_error(owned, error),
                };
                if let (Some(prepared), Some(cleanup)) =
                    (deletion.as_ref(), self.cleanup_deletion.as_ref())
                    && prepared.node() != cleanup.node()
                {
                    return self.complete_error(owned, DriverError::InternalInvariantViolation);
                }
                if deletion.is_none()
                    && let Some(cleanup) = self.cleanup_deletion.as_ref()
                {
                    let stream = match access
                        .prepare_stream_deletion(cleanup.file_control_block(), cleanup.node())
                    {
                        Ok(stream) => stream,
                        Err(error) => return self.complete_error(owned, error),
                    };
                    if let Some(stream) = stream {
                        drop(stream_sizes);
                        drop(publication);
                        drop(reserved);
                        self.state = MutationOperationState::PreparingDeletion {
                            owned,
                            size_changes,
                        };
                        return OperationTransition::SubmitCacheWorkAfterIntentRelease {
                            work: crate::irp::CacheWork::prepare_deletion(stream),
                            suspended: self,
                        };
                    }
                }
                let deletion_node = deletion.as_ref().map(|prepared| prepared.node());
                let size_changes = match size_changes {
                    Some(prepared) => {
                        let matches = match access.prepared_stream_size_changes_match(
                            &stream_sizes,
                            &prepared,
                            deletion_node,
                        ) {
                            Ok(matches) => matches,
                            Err(error) => return self.complete_error(owned, error),
                        };
                        if matches {
                            Some(prepared)
                        } else {
                            drop(prepared);
                            None
                        }
                    }
                    None => None,
                };
                if size_changes.is_none() {
                    let mut plan =
                        match access.prepare_stream_size_changes(&stream_sizes, deletion_node) {
                            Ok(plan) => plan,
                            Err(error) => return self.complete_error(owned, error),
                        };
                    if let Some(stream) = plan.next() {
                        drop(stream_sizes);
                        drop(publication);
                        drop(reserved);
                        self.state = MutationOperationState::PreparingSizeChange {
                            owned,
                            plan,
                            deletion,
                        };
                        return OperationTransition::SubmitCacheWorkAfterIntentRelease {
                            work: crate::irp::CacheWork::prepare_size_change(stream),
                            suspended: self,
                        };
                    }
                    let empty = match plan.into_prepared() {
                        Ok(empty) => empty,
                        Err(error) => return self.complete_error(owned, error),
                    };
                    if empty.is_some() {
                        return self.complete_error(owned, DriverError::InternalInvariantViolation);
                    }
                }
                let publication = match publication.prepare(stream_sizes) {
                    Ok(publication) => publication,
                    Err(error) => return self.complete_error(owned, error),
                };
                let slots = {
                    let reservations = access.reserve_epoch_publication();
                    match reservations {
                        Ok(slots) => slots,
                        Err(error) => return self.complete_error(owned, error),
                    }
                };
                self.state = MutationOperationState::AwaitingCommit {
                    owned,
                    reserved,
                    publication,
                    slots,
                    size_changes,
                    deletion,
                };
                OperationTransition::RequestCommit {
                    ticket: self.ticket,
                    suspended: self,
                }
            }
            MutationOperationState::AwaitingCommit {
                owned,
                reserved,
                publication,
                slots,
                size_changes,
                deletion,
            } => {
                let commit = match event {
                    OperationEvent::CommitGranted(commit) => commit,
                    OperationEvent::CancelRequested => {
                        return self
                            .complete_error(owned, DriverError::from(Error::OperationCancelled));
                    }
                    _ => return self.complete_error(owned, DriverError::InvalidDeviceRequest),
                };
                let ready: Result<CommitReadyMutation, Error> =
                    access.prepare_mutation_commit(reserved, commit);
                let ready = match ready {
                    Ok(ready) => ready,
                    Err(error) => return self.complete_error(owned, DriverError::from(error)),
                };
                let (durable_slot, checkpoint_slot) = slots.into_parts();
                let context = CommitContext {
                    owned,
                    publication,
                    durable_slot,
                    checkpoint_slot,
                    size_changes,
                    deletion,
                };
                self.drive_ordered(context, ready.start())
            }
            MutationOperationState::CommitIo { context, phase } => {
                self.advance_commit_io(context, phase, event, access)
            }
            MutationOperationState::AwaitingVisibility { context, durable } => {
                let OperationEvent::VisibilityGranted(visibility) = event else {
                    return self.fail_commit_path(context, Error::DeviceIo, access);
                };
                self.state = MutationOperationState::PublishingDurable {
                    context,
                    durable,
                    visibility,
                };
                OperationTransition::Publish { publication: self }
            }
            MutationOperationState::PublishingDurable { context, .. } => {
                self.fail_commit_path(context, Error::DeviceIo, access)
            }
            MutationOperationState::AwaitingCheckpoint(pending) => match event {
                OperationEvent::Admitted => OperationTransition::Wait {
                    condition: WaitCondition::Checkpoint {
                        epoch: pending.epoch(),
                    },
                    suspended: {
                        self.state = MutationOperationState::AwaitingCheckpoint(pending);
                        self
                    },
                },
                OperationEvent::CheckpointGranted(checkpoint) => {
                    let (operation, publication, epoch) = pending.into_parts();
                    self.drive_checkpoint_home(operation.start(checkpoint), publication, epoch)
                }
                OperationEvent::StorageCompleted(_)
                | OperationEvent::DeviceLengthCompleted(_)
                | OperationEvent::CancelRequested
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::BarrierReleased(_) => {
                    let (_, publication, _) = pending.into_parts();
                    self.fail_checkpoint(
                        publication,
                        StorageFailureClass::DurabilityUnknown { completed: 0 },
                        access,
                    )
                }
            },
            MutationOperationState::CheckpointIo {
                phase,
                publication,
                epoch,
            } => self.advance_checkpoint_io(phase, publication, epoch, event, access),
            MutationOperationState::PublishingCheckpoint { publication, .. } => self
                .fail_checkpoint(
                    publication,
                    StorageFailureClass::DurabilityUnknown { completed: 0 },
                    access,
                ),
            MutationOperationState::Terminal => OperationTransition::Complete,
        }
    }

    fn record_mounted_storage_failure(
        &mut self,
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    ) {
        if matches!(
            (&self.state, failure),
            (
                MutationOperationState::CommitIo { .. },
                StorageFailureClass::DurabilityUnknown { .. }
            )
        ) && let Some(deletion) = self.cleanup_deletion.as_mut()
        {
            deletion.preserve_pending_after_uncertain_effect();
        }
        match (&self.state, failure) {
            (_, StorageFailureClass::ReadUnreliable) => {
                access.record_read_unreliable();
            }
            (
                MutationOperationState::CommitIo { .. },
                StorageFailureClass::DurabilityUnknown { .. },
            ) => {
                access.record_durability_unknown();
            }
            (MutationOperationState::CheckpointIo { .. }, StorageFailureClass::Terminal) => {
                access.record_durable_abort();
            }
            (
                MutationOperationState::CheckpointIo { .. },
                StorageFailureClass::DurabilityUnknown { .. },
            ) => {
                access.record_durability_unknown();
            }
            (
                MutationOperationState::Resolving { .. },
                StorageFailureClass::Terminal | StorageFailureClass::DurabilityUnknown { .. },
            )
            | (
                MutationOperationState::AwaitingIntent { .. }
                | MutationOperationState::CheckingOplock { .. }
                | MutationOperationState::OplockDelegated { .. }
                | MutationOperationState::OplockReady { .. }
                | MutationOperationState::AwaitingCommit { .. }
                | MutationOperationState::PreparingSizeChange { .. }
                | MutationOperationState::PreparingDeletion { .. }
                | MutationOperationState::PreparingWriteOpen { .. }
                | MutationOperationState::CacheWriting { .. }
                | MutationOperationState::CachePurging { .. }
                | MutationOperationState::CacheUninitializing { .. }
                | MutationOperationState::AwaitingVisibility { .. }
                | MutationOperationState::PublishingDurable { .. }
                | MutationOperationState::AwaitingCheckpoint(_)
                | MutationOperationState::PublishingCheckpoint { .. }
                | MutationOperationState::Terminal,
                _,
            )
            | (MutationOperationState::CommitIo { .. }, StorageFailureClass::Terminal) => {}
        }
    }
}

impl InfalliblePublication for MutationRequestOperation {
    fn authority(&self) -> PublicationAuthority {
        match &self.state {
            MutationOperationState::PublishingDurable { .. } => PublicationAuthority::Durable {
                ticket: self.ticket,
            },
            MutationOperationState::PublishingCheckpoint { epoch, .. } => {
                PublicationAuthority::Checkpoint { epoch: *epoch }
            }
            MutationOperationState::CacheWriting { .. }
            | MutationOperationState::CheckingOplock { .. }
            | MutationOperationState::OplockDelegated { .. }
            | MutationOperationState::OplockReady { .. }
            | MutationOperationState::CachePurging { .. }
            | MutationOperationState::CacheUninitializing { .. }
            | MutationOperationState::PreparingSizeChange { .. }
            | MutationOperationState::PreparingDeletion { .. }
            | MutationOperationState::PreparingWriteOpen { .. }
            | MutationOperationState::Resolving { .. }
            | MutationOperationState::AwaitingIntent { .. }
            | MutationOperationState::AwaitingCommit { .. }
            | MutationOperationState::CommitIo { .. }
            | MutationOperationState::AwaitingVisibility { .. }
            | MutationOperationState::AwaitingCheckpoint(_)
            | MutationOperationState::CheckpointIo { .. }
            | MutationOperationState::Terminal => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }

    fn publish(
        mut self: Box<Self>,
        access: &mut MountedVolumeAccess<'_>,
    ) -> Box<dyn CompletionOperation> {
        let state = core::mem::replace(&mut self.state, MutationOperationState::Terminal);
        match state {
            MutationOperationState::PublishingDurable {
                context,
                durable,
                visibility,
            } => {
                let CommitContext {
                    owned,
                    publication,
                    durable_slot,
                    checkpoint_slot,
                    size_changes,
                    deletion,
                } = context;
                let PreparedDriverPublication {
                    stream_sizes,
                    effect,
                } = publication;
                let publication = access.publish_durable(
                    durable,
                    visibility,
                    durable_slot,
                    checkpoint_slot,
                    stream_sizes,
                );
                let (pending, stream_projection) = publication.into_parts();
                let completion = effect.publish(access);
                if let Err(error) = &stream_projection {
                    access.record_publication_failure(error.ntstatus());
                }
                drop(size_changes);
                drop(deletion);
                match stream_projection {
                    Ok(()) => {
                        let _complete = self.complete_success(owned, completion);
                    }
                    Err(error) => match completion {
                        TopLevelCompletion::Normal(completion) => {
                            let _status = owned.complete(completion.committed_failure(error));
                        }
                        TopLevelCompletion::Create(_completion) => {
                            let _status = owned.complete_create_result(Err(error));
                        }
                    },
                }
                self.state = MutationOperationState::AwaitingCheckpoint(pending);
            }
            MutationOperationState::PublishingCheckpoint {
                durability,
                publication,
                epoch,
            } => {
                access.publish_checkpoint(durability, publication, epoch);
                self.state = MutationOperationState::Terminal;
            }
            MutationOperationState::CacheWriting { .. }
            | MutationOperationState::CheckingOplock { .. }
            | MutationOperationState::OplockDelegated { .. }
            | MutationOperationState::OplockReady { .. }
            | MutationOperationState::CachePurging { .. }
            | MutationOperationState::CacheUninitializing { .. }
            | MutationOperationState::PreparingSizeChange { .. }
            | MutationOperationState::PreparingDeletion { .. }
            | MutationOperationState::PreparingWriteOpen { .. }
            | MutationOperationState::Resolving { .. }
            | MutationOperationState::AwaitingIntent { .. }
            | MutationOperationState::AwaitingCommit { .. }
            | MutationOperationState::CommitIo { .. }
            | MutationOperationState::AwaitingVisibility { .. }
            | MutationOperationState::AwaitingCheckpoint(_)
            | MutationOperationState::CheckpointIo { .. }
            | MutationOperationState::Terminal => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
        self
    }
}

#[expect(
    unsafe_code,
    reason = "the mutation operation moves through the sole reactor while all raw identities remain retained"
)]
// SAFETY: Every raw identity names VCB/FCB/FILE_OBJECT storage retained through reactor drain;
// mutable access is confined to the sole reactor thread and completion envelopes move only owned
// state.
unsafe impl Send for MutationRequestOperation {}

impl_mounted_operation_adapter!(ReadRequestOperation);
impl_mounted_operation_adapter!(RawVolumeOperation);
impl_mounted_operation_adapter!(ImmediateRequestOperation);
impl_mounted_operation_adapter!(NotificationOperation);
impl_mounted_operation_adapter!(ByteRangeLockOperation);
impl_mounted_operation_adapter!(VolumeControlOperation);
impl_mounted_operation_adapter!(FlushRequestOperation);
impl_mounted_operation_adapter!(MutationRequestOperation);

/// Allocates one completion-driven mount operation.
/// # Errors
///
/// Returns the still-owned IRP when mount operation allocation fails.
pub(crate) fn mount(
    owned: OwnedIrp,
    admission: MountAdmission,
    trace: OperationalTrace,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    MountRequestOperation::try_new(owned, admission, trace)
}

/// Allocates one directory-change notification delegation.
/// # Errors
///
/// Returns the still-owned IRP when notification operation allocation fails.
pub(crate) fn notification(
    owned: OwnedIrp,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    NotificationOperation::try_new(owned)
}

/// Allocates one handle-serialized byte-range lock delegation.
/// # Errors
///
/// Returns the still-owned IRP when target validation, stream retention, or allocation fails.
pub(crate) fn byte_range_lock(
    owned: OwnedIrp,
    access: &MountedVolumeAccess<'_>,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    ByteRangeLockOperation::try_new(owned, access)
}

/// Allocates one barrier-driven direct-volume lifecycle operation.
/// # Errors
///
/// Returns the still-owned IRP when lifecycle operation allocation fails.
pub(crate) fn volume_control(
    owned: OwnedIrp,
    kind: VolumeControlRequestKind,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    VolumeControlOperation::try_new(owned, kind)
}

/// Allocates one concrete read operation.
/// # Errors
///
/// Returns the still-owned IRP when read admission or operation allocation fails.
pub(crate) fn read(
    owned: OwnedIrp,
    kind: ReadRequestKind,
    access: &mut MountedVolumeAccess<'_>,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    ReadRequestOperation::try_new(owned, kind, access)
}

/// Allocates one direct-volume lower I/O operation without acquiring an ext4 epoch.
/// # Errors
///
/// Returns the still-owned IRP when operation allocation fails.
#[inline(never)]
pub(crate) fn raw_volume(
    owned: OwnedIrp,
    kind: RawVolumeOperationKind,
    access: &MountedVolumeAccess<'_>,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    RawVolumeOperation::try_new(owned, kind, access)
}

/// Allocates one concrete single-transition operation.
/// # Errors
///
/// Returns the still-owned IRP when immediate operation allocation fails.
pub(crate) fn immediate(
    owned: OwnedIrp,
    kind: ImmediateRequestKind,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    ImmediateRequestOperation::try_new(owned, kind)
}

/// Allocates one concrete journaled mutation operation.
/// # Errors
///
/// Returns the still-owned IRP when mutation admission or operation allocation fails.
pub(crate) fn mutation(
    owned: OwnedIrp,
    kind: MutationRequestKind,
    access: &mut MountedVolumeAccess<'_>,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    MutationRequestOperation::try_new(owned, kind, access)
}

/// Allocates one concrete durability-barrier and lower-flush operation.
/// # Errors
///
/// Returns the still-owned IRP when flush admission or operation allocation fails.
pub(crate) fn flush(
    owned: OwnedIrp,
    kind: FlushRequestKind,
    access: &MountedVolumeAccess<'_>,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    FlushRequestOperation::try_new(owned, kind, access)
}

#[cfg(test)]
mod tests {
    use crate::irp::OwnedIrp;
    use crate::kernel::status::DriverError;

    use super::AdmitOperationError;

    fn split_admission_error(error: AdmitOperationError) -> (DriverError, OwnedIrp) {
        error.into_parts()
    }

    /// Keeps the ownership-preserving admission error consumer in the unit-test production graph.
    ///
    /// # Panics
    ///
    /// This test has no runtime failure path. Compilation fails if admission errors stop returning
    /// the sole top-level IRP completion authority.
    #[test]
    fn admission_error_boundary_remains_linked() {
        let _split: fn(AdmitOperationError) -> (DriverError, OwnedIrp) = split_admission_error;
    }
}
