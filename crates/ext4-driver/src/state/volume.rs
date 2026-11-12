//! Mounted-volume lifecycle, handle admission, and durable mutation coordination.

use super::*;
use crate::kernel::operational_trace::{OperationalOutcome, OperationalPath};

#[derive(Debug)]
/// Shared mounted-volume stream owner at a pinned heap address.
/// Native owner pointers borrow this allocation through shared references. Epoch and lifecycle
/// mutation belongs to the separate reactor-owned fields of [`MountedVolumeBinding`].
pub(crate) struct VolumeControlBlock {
    /// FsRtl's advisory per-volume filename tunneling owner.
    pub(super) name_tunnel: crate::kernel::name_tunnel::NameTunnel,
    /// Write-only operational event capability inherited from the driver registration owner.
    pub(super) trace: OperationalTrace,
    /// Volume-wide opaque FsRtl notification state. This field drops before filesystem state so
    /// pending notify IRPs cannot outlive the mounted namespace they observe.
    pub(super) directory_change_notifier: DirectoryChangeNotifier,
    /// Synchronized VCB-owned FCB identities and Windows share ledger. This field drops before
    /// the mounted volume because every FCB retains that volume as its data-plane owner.
    pub(super) file_control_blocks: FileControlBlockLedger,
    /// Header-based stream identity used by every direct volume FILE_OBJECT.
    pub(super) stream_context: StreamContext,
    /// Prevents the native direct-volume owner address from being invalidated by a safe move.
    pub(super) _pin: PhantomPinned,
}

/// Actor-owned mounted-volume lifecycle and direct-open ledger.
#[derive(Debug)]
pub(super) struct VolumeControlPlane {
    /// Current mount/lock state.
    pub(super) state: MountedVolumeState,
    /// Share claims for direct user volume opens.
    handles: FileObjectShares,
    /// Direct-volume FILE_OBJECT allocations retained until Close.
    volume_file_objects: u32,
}

impl VolumeControlPlane {
    /// PnP can prepare a reversible removal only while no direct FILE_OBJECT remains.
    /// # Errors
    /// Returns device busy for locks, terminal transitions, or an outstanding direct open.
    fn authorize_query_removal(&self) -> DriverResult<()> {
        if self.state != MountedVolumeState::Mounted || self.volume_file_objects != 0 {
            return Err(DriverError::DeviceBusy);
        }
        Ok(())
    }
    /// Creates the control plane for a newly mounted volume.
    pub(super) const fn mounted() -> Self {
        Self {
            state: MountedVolumeState::Mounted,
            handles: FileObjectShares::new(),
            volume_file_objects: 0,
        }
    }
}

/// Native routing projection after filesystem session termination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionEndRouting {
    /// A retained handle owns raw access until unlock or cleanup.
    DirectAccess,
    /// Failed finalization retains an existing lock without granting media writes.
    Retain,
    /// No old direct owner remains; a fresh mount may recover media.
    Remount,
}

/// Exclusive direct access retained after the filesystem session ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DismountedAccess {
    /// No old handle may access media; a fresh mount may recover it.
    Released,
    /// The dismounting handle retains direct access until cleanup.
    Unlocked(KernelFileObject),
    /// Explicit unlock or cleanup releases both direct access and remount exclusion.
    Locked(KernelFileObject),
}

impl DismountedAccess {
    /// Requires the exact retained direct-volume FILE_OBJECT.
    /// # Errors
    /// Returns access denied after release or for another handle.
    fn authorize(self, owner: KernelFileObject) -> DriverResult<()> {
        match self {
            Self::Unlocked(current) | Self::Locked(current) if current == owner => Ok(()),
            _ => Err(DriverError::AccessDenied),
        }
    }
}

/// Mounted-volume state serialized by the device actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MountedVolumeState {
    /// Namespace and direct-volume opens are admitted.
    Mounted,
    /// Namespace admission is closed while a reversible lock attempt drains.
    Locking {
        /// FILE_OBJECT owning the lock attempt.
        owner: KernelFileObject,
    },
    /// The exact lock owner may inspect the live filesystem or begin direct writes.
    Locked {
        /// FILE_OBJECT owning the clean volume lock.
        owner: KernelFileObject,
    },
    /// The first raw write ended the ext4 session; unlock requires a fresh mount.
    RawLocked {
        /// FILE_OBJECT retaining exclusive direct access.
        owner: KernelFileObject,
    },
    /// Ordinary admission is excluded while reversible cache writeback drains.
    PreparingClose {
        /// Exact operation selecting the session's terminal state.
        target: VolumeCloseTarget,
        /// Independent explicit lock retained through preparation.
        lock_owner: Option<KernelFileObject>,
    },
    /// Paging is sealed and the completion owner must finish termination.
    Closing {
        /// Exact target whose prepared authority was consumed by sealing.
        target: VolumeCloseTarget,
        /// Independent explicit lock retained through finalization.
        lock_owner: Option<KernelFileObject>,
    },
    /// Filesystem admission is terminal; direct access has its own lifetime.
    Dismounted {
        /// Direct access and remount exclusion retained by the dismounting handle.
        access: DismountedAccess,
    },
    /// System shutdown observed a fully durable clean marker.
    ShutdownComplete {
        /// Prior lock retained only for late cleanup accounting.
        lock_owner: Option<KernelFileObject>,
    },
    /// Logical termination completed without claiming clean media durability.
    CloseFailed {
        /// Explicit lock remains excluded until its owner releases it.
        lock_owner: Option<KernelFileObject>,
        /// Exact failure returned by the termination owner.
        error: DriverError,
    },
    /// Removal or media replacement revoked data authority; only handle release remains legal.
    StorageRevoked(crate::kernel::stream::StorageRevocation),
    /// The unique retirement worker owns physical teardown.
    Retiring,
}

/// An admitted requester selects one terminal state without duplicating its identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeCloseTarget {
    /// The original IRP retains the dismounting direct-volume FILE_OBJECT.
    Dismount(KernelFileObject),
    /// The first raw write consumes a locked ext4 session before lower submission.
    RawWrite(KernelFileObject),
    /// System shutdown carries no user handle authority.
    Shutdown,
}

/// Retained issuer identity; each physical submission revalidates its permission.
#[derive(Clone, Copy, Debug)]
pub(crate) enum StorageSubmissionSource {
    /// The live ext4 session, including its ownership deadline, owns this transfer.
    Filesystem,
    /// The original IRP retains direct access; raw failures cannot authorize ext4 replay.
    RawVolume {
        /// Exact direct-volume handle retained through physical completion.
        target: RawVolumeTarget,
        /// Flush consumes the same permission as a raw write.
        kind: RawVolumeOperationKind,
    },
}

impl MountedVolumeState {
    /// Closes namespace admission before a reversible lock attempt suspends.
    /// # Errors
    /// Returns removal, competing exclusion, or terminal dismount.
    pub(super) fn begin_lock(self, owner: KernelFileObject) -> DriverResult<Self> {
        match self {
            Self::Mounted => Ok(Self::Locking { owner }),
            Self::StorageRevoked(revocation) => Err(revocation.error()),
            Self::Locking { .. } | Self::Locked { .. } => Err(DriverError::AccessDenied),
            _ => Err(DriverError::VolumeDismounted),
        }
    }

    /// Only the matching durability barrier may publish the lock.
    pub(super) fn finish_lock(self, owner: KernelFileObject) -> Option<Self> {
        match self {
            Self::Locking { owner: current } if current == owner => Some(Self::Locked { owner }),
            _ => None,
        }
    }

    /// An uncommitted lock attempt may restore ordinary admission.
    pub(super) fn abort_lock(self, owner: KernelFileObject) -> Option<Self> {
        match self {
            Self::Locking { owner: current } if current == owner => Some(Self::Mounted),
            _ => None,
        }
    }

    /// Releases a lock without reconstructing an ended filesystem session.
    /// # Errors
    /// Returns removal or not-locked for a non-owner.
    pub(super) fn unlock(self, owner: KernelFileObject) -> DriverResult<Self> {
        match self {
            Self::StorageRevoked(revocation) => Err(revocation.error()),
            Self::Locked { owner: current } if current == owner => Ok(Self::Mounted),
            Self::RawLocked { owner: current } if current == owner => Ok(Self::Dismounted {
                access: DismountedAccess::Released,
            }),
            Self::Dismounted {
                access: DismountedAccess::Locked(current),
            } if current == owner => Ok(Self::Dismounted {
                access: DismountedAccess::Released,
            }),
            Self::PreparingClose {
                target,
                lock_owner: Some(current),
            } if current == owner => Ok(Self::PreparingClose {
                target,
                lock_owner: None,
            }),
            Self::Closing {
                target,
                lock_owner: Some(current),
            } if current == owner => Ok(Self::Closing {
                target,
                lock_owner: None,
            }),
            Self::CloseFailed {
                error,
                lock_owner: Some(current),
            } if current == owner => Ok(Self::CloseFailed {
                error,
                lock_owner: None,
            }),
            Self::ShutdownComplete {
                lock_owner: Some(current),
            } if current == owner => Ok(Self::ShutdownComplete { lock_owner: None }),
            _ => Err(DriverError::NotLocked),
        }
    }

    /// Selects reversible preparation independently of media health.
    /// # Errors
    /// Returns removal, competing lock exclusion or terminal dismount.
    pub(super) fn prepare_close(self, target: VolumeCloseTarget) -> DriverResult<Self> {
        let lock_owner = match (self, target) {
            (Self::StorageRevoked(revocation), _) => return Err(revocation.error()),
            (Self::Mounted, VolumeCloseTarget::Dismount(_) | VolumeCloseTarget::Shutdown) => None,
            (
                Self::Locked { owner },
                VolumeCloseTarget::Dismount(current) | VolumeCloseTarget::RawWrite(current),
            ) if current == owner => Some(owner),
            (Self::Locked { owner }, VolumeCloseTarget::Shutdown) => Some(owner),
            (Self::Mounted | Self::Locking { .. } | Self::Locked { .. }, _) => {
                return Err(DriverError::AccessDenied);
            }
            _ => return Err(DriverError::VolumeDismounted),
        };
        Ok(Self::PreparingClose { target, lock_owner })
    }

    /// Consumes preparation before paging admission is sealed.
    pub(super) fn seal_close(self, expected: VolumeCloseTarget) -> Option<Self> {
        match self {
            Self::PreparingClose { target, lock_owner } if target == expected => {
                Some(Self::Closing { target, lock_owner })
            }
            _ => None,
        }
    }

    /// Only unsealed preparation can restore the retained live session.
    pub(super) fn abort_close(self, expected: VolumeCloseTarget) -> Option<Self> {
        match self {
            Self::PreparingClose { target, lock_owner } if target == expected => {
                Some(match lock_owner {
                    Some(owner) => Self::Locked { owner },
                    None => Self::Mounted,
                })
            }
            _ => None,
        }
    }

    /// Publishes direct access only after the session's clean-close obligations ended.
    pub(super) fn finish_close(self, expected: VolumeCloseTarget) -> Option<Self> {
        let Self::Closing { target, lock_owner } = self else {
            return None;
        };
        if target != expected {
            return None;
        }
        Some(match target {
            VolumeCloseTarget::Dismount(owner) => Self::Dismounted {
                access: match lock_owner {
                    Some(current) if current == owner => DismountedAccess::Locked(owner),
                    None => DismountedAccess::Unlocked(owner),
                    Some(_) => return None,
                },
            },
            VolumeCloseTarget::RawWrite(owner) if lock_owner == Some(owner) => {
                Self::RawLocked { owner }
            }
            VolumeCloseTarget::RawWrite(_) => return None,
            VolumeCloseTarget::Shutdown => Self::ShutdownComplete { lock_owner },
        })
    }

    /// Failure never restores session authority or claims clean durability.
    pub(super) fn fail_close(
        self,
        expected: VolumeCloseTarget,
        error: DriverError,
    ) -> Option<Self> {
        match self {
            Self::Closing { target, lock_owner } if target == expected => {
                Some(Self::CloseFailed { lock_owner, error })
            }
            _ => None,
        }
    }

    /// Explicit dismount can invalidate a session already ended by a raw write.
    pub(super) fn dismount_raw(self, owner: KernelFileObject) -> Option<Self> {
        match self {
            Self::RawLocked { owner: current } if current == owner => Some(Self::Dismounted {
                access: DismountedAccess::Locked(owner),
            }),
            _ => None,
        }
    }

    /// Cleanup releases direct access independently of whether an explicit lock existed.
    pub(super) fn cleanup(self, owner: KernelFileObject) -> (Self, VolumeHandleCleanup) {
        match self {
            Self::Locking { owner: current } if current == owner => {
                (Self::Mounted, VolumeHandleCleanup::Released)
            }
            Self::Dismounted {
                access: DismountedAccess::Unlocked(current),
            } if current == owner => (
                Self::Dismounted {
                    access: DismountedAccess::Released,
                },
                VolumeHandleCleanup::DirectAccessReleased,
            ),
            Self::Locked { owner: current } | Self::RawLocked { owner: current }
                if current == owner =>
            {
                (
                    self.unlock(owner).unwrap_or_else(|_| {
                        KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
                    }),
                    VolumeHandleCleanup::Unlocked,
                )
            }
            Self::Dismounted {
                access: DismountedAccess::Locked(current),
            }
            | Self::PreparingClose {
                lock_owner: Some(current),
                ..
            }
            | Self::Closing {
                lock_owner: Some(current),
                ..
            }
            | Self::CloseFailed {
                lock_owner: Some(current),
                ..
            }
            | Self::ShutdownComplete {
                lock_owner: Some(current),
            } if current == owner => (
                self.unlock(owner).unwrap_or_else(|_| {
                    KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
                }),
                VolumeHandleCleanup::Unlocked,
            ),
            Self::Retiring => KernelWideInconsistency::mounted_volume_state_corruption().bugcheck(),
            _ => (self, VolumeHandleCleanup::Released),
        }
    }

    /// Selects physical retirement only after every retained FILE_OBJECT and stream ends.
    pub(super) fn retire_if_unreferenced(
        self,
        namespace_empty: bool,
        volume_file_objects: u32,
    ) -> (Self, VolumeRetirement) {
        if self.permits_retirement() && namespace_empty && volume_file_objects == 0 {
            (Self::Retiring, VolumeRetirement::Start)
        } else {
            (self, VolumeRetirement::Retained)
        }
    }

    /// A failed close can retire without establishing healthy media authority.
    fn permits_retirement(self) -> bool {
        matches!(
            self,
            Self::StorageRevoked(_)
                | Self::Dismounted {
                    access: DismountedAccess::Released
                }
                | Self::CloseFailed {
                    lock_owner: None,
                    ..
                }
        )
    }

    /// Reports whether the filesystem remains logically mounted.
    /// # Errors
    /// Returns removal or terminal dismount.
    pub(super) fn ensure_mounted(self) -> DriverResult<()> {
        match self {
            Self::StorageRevoked(revocation) => Err(revocation.error()),
            Self::Mounted
            | Self::Locking { .. }
            | Self::Locked { .. }
            | Self::PreparingClose { .. }
            | Self::Closing { .. } => Ok(()),
            _ => Err(DriverError::VolumeDismounted),
        }
    }

    /// Applies namespace admission independently of media-write permission.
    /// # Errors
    /// Returns exclusion, removal or terminal dismount.
    pub(super) fn authorize_create(self) -> DriverResult<()> {
        match self {
            Self::Mounted => Ok(()),
            Self::StorageRevoked(revocation) => Err(revocation.error()),
            Self::Locking { .. }
            | Self::Locked { .. }
            | Self::PreparingClose { .. }
            | Self::Closing { .. } => Err(DriverError::AccessDenied),
            _ => Err(DriverError::VolumeDismounted),
        }
    }

    /// Applies ordinary handle admission without granting direct media access.
    /// # Errors
    /// Returns exclusion, removal or terminal dismount.
    pub(super) fn authorize_handle(self, owner: KernelFileObject) -> DriverResult<()> {
        match self {
            Self::Mounted => Ok(()),
            Self::Locked { owner: current } if current == owner => Ok(()),
            Self::StorageRevoked(revocation) => Err(revocation.error()),
            Self::Locking { .. }
            | Self::Locked { .. }
            | Self::PreparingClose { .. }
            | Self::Closing { .. } => Err(DriverError::AccessDenied),
            _ => Err(DriverError::VolumeDismounted),
        }
    }

    /// Requires a completed lock whose ext4 session is still live.
    /// # Errors
    /// Returns not-locked for another owner or an ended session.
    pub(super) fn authorize_key_removal(self, owner: KernelFileObject) -> DriverResult<()> {
        match self {
            Self::Locked { owner: current } if current == owner => Ok(()),
            _ => Err(DriverError::NotLocked),
        }
    }

    /// Preparation may reserve a locked write before its session termination runs.
    /// # Errors
    /// Returns the same lifecycle exclusion as physical submission for all other requests.
    fn prepare_raw(
        self,
        owner: KernelFileObject,
        kind: RawVolumeOperationKind,
    ) -> DriverResult<()> {
        if matches!(self, Self::Locked { owner: current } if current == owner) {
            return Ok(());
        }
        self.authorize_raw(owner, kind)
    }

    /// Media writes require an ended session, independently of the handle's data rights.
    /// # Errors
    /// Returns removal, lost direct ownership, or terminal retirement.
    pub(super) fn authorize_raw(
        self,
        owner: KernelFileObject,
        kind: RawVolumeOperationKind,
    ) -> DriverResult<()> {
        match self {
            Self::StorageRevoked(revocation) => Err(revocation.error()),
            Self::Locked { owner: current }
                if current == owner && kind == RawVolumeOperationKind::Read =>
            {
                Ok(())
            }
            Self::RawLocked { owner: current } if current == owner => Ok(()),
            Self::Dismounted { access } => access.authorize(owner),
            Self::Retiring => Err(DriverError::VolumeDismounted),
            _ => Err(DriverError::AccessDenied),
        }
    }

    /// An ended session cannot participate in ext4 submission or raw flush interpretation.
    const fn raw_session(self) -> bool {
        matches!(self, Self::RawLocked { .. } | Self::Dismounted { .. })
    }

    /// Extent selection changes no data authority.
    /// # Errors
    /// Returns exclusion, removal or terminal dismount.
    pub(super) fn authorize_raw_extent_change(self, owner: KernelFileObject) -> DriverResult<()> {
        match self {
            Self::Mounted => Ok(()),
            Self::Locked { owner: current } | Self::RawLocked { owner: current }
                if current == owner =>
            {
                Ok(())
            }
            Self::Dismounted { access } => access.authorize(owner),
            Self::StorageRevoked(revocation) => Err(revocation.error()),
            Self::Locking { .. }
            | Self::Locked { .. }
            | Self::PreparingClose { .. }
            | Self::Closing { .. } => Err(DriverError::AccessDenied),
            _ => Err(DriverError::VolumeDismounted),
        }
    }
}

/// Stable identity of one mounted VCB without granting a reference to its control-plane fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MountedVolumeRef {
    /// Heap-stable mounted VCB.
    volume: NonNull<VolumeControlBlock>,
}

impl MountedVolumeRef {
    /// Wraps a heap-stable mounted VCB identity.
    const fn new(volume: NonNull<VolumeControlBlock>) -> Self {
        Self { volume }
    }

    /// Returns the raw typed identity for existing FCB ownership boundaries.
    pub(super) const fn as_non_null(self) -> NonNull<VolumeControlBlock> {
        self.volume
    }

    /// Attenuates the stable mounted identity to its write-only trace capability.
    #[expect(
        unsafe_code,
        reason = "the FCB construction lease retains the heap-stable VCB while copying one scalar capability"
    )]
    pub(super) fn trace(self) -> OperationalTrace {
        unsafe {
            // SAFETY: The ledger creates FCBs only while this mounted VCB is actor-owned and live.
            self.volume.as_ref().trace
        }
    }
}

/// Non-cloneable mounted-volume authority owned only by the WDK reactor shell.
#[derive(Debug)]
pub(crate) struct MountedVolumeBinding {
    /// Shared heap-stable stream, notification and FCB ownership; destroyed before runtime storage.
    volume: Pin<Box<VolumeControlBlock>>,
    /// Exclusive state allocation, independent of the native shared-owner pointer graph.
    pub(super) actor: Box<MountedVolumeActorState>,
}

/// Mutable volume authority carried only by the owning reactor, never by native stream pointers.
#[derive(Debug)]
pub(super) struct MountedVolumeActorState {
    /// Actor-owned volume lifecycle and direct-open share accounting.
    pub(super) volume_control: VolumeControlPlane,
    /// Actor-owned epochs, mutation coordination and retained lower storage.
    pub(super) runtime: VolumeRuntime,
}

impl MountedVolumeBinding {
    /// Builds the shared stream owner and the reactor's independent mutable state after recovery.
    /// # Errors
    /// Returns allocation, provider, notification or native stream initialization failure before publication.
    pub(crate) fn from_completed_mount(
        mount: CompletedMount,
        storage: MountedStorage,
        trace: OperationalTrace,
        catalog: &mut crate::identity::IdentityDirectory,
    ) -> DriverResult<Self> {
        let runtime = VolumeRuntime::try_new(mount, storage, catalog)?;
        let actor = memory::boxed_try_with(|| {
            Ok(MountedVolumeActorState {
                volume_control: VolumeControlPlane::mounted(),
                runtime,
            })
        })?;
        let mut volume = memory::boxed_try_with(|| {
            Ok(VolumeControlBlock {
                name_tunnel: crate::kernel::name_tunnel::NameTunnel::try_new()?,
                trace,
                directory_change_notifier: DirectoryChangeNotifier::uninitialized(),
                file_control_blocks: FileControlBlockLedger::try_new()?,
                stream_context: StreamContext::try_new_volume(
                    StreamSizes::EMPTY,
                    trace,
                    actor.runtime.observe_reliability()?,
                )?,
                _pin: PhantomPinned,
            })
        })?;
        volume.initialize_directory_change_notifier()?;
        let volume = Box::into_pin(volume);
        volume
            .as_ref()
            .bind_stream_owner(actor.runtime.storage().filesystem_control_device())?;
        Ok(Self { volume, actor })
    }

    /// Borrows the shared stream owner without granting actor-state mutation.
    pub(super) fn volume(&self) -> &VolumeControlBlock {
        self.volume.as_ref().get_ref()
    }

    /// Runs one non-suspending reactor transition with lifetime-bound mounted access.
    pub(crate) fn with_access<R>(
        &mut self,
        transition: impl FnOnce(&mut MountedVolumeAccess<'_>) -> R,
    ) -> R {
        self.actor.runtime.observe_media_ownership();
        transition(&mut MountedVolumeAccess {
            volume: self.volume.as_ref().get_ref(),
            volume_control: &mut self.actor.volume_control,
            runtime: &mut self.actor.runtime,
        })
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The binding moves once into the device reactor. Only that reactor's sole actor thread
// calls `with_access`, and teardown releases shared resources before runtime storage after all
// actor operations and callbacks drain.
unsafe impl Send for MountedVolumeBinding {}

/// Lifetime-bound mounted VCB access available only inside one reactor callback.
pub(crate) struct MountedVolumeAccess<'volume> {
    /// Shared stream identity and independently synchronized native resources.
    volume: &'volume VolumeControlBlock,
    /// Exclusive lifecycle authority for this actor transition.
    volume_control: &'volume mut VolumeControlPlane,
    /// Exclusive epoch and mutation authority for this actor transition.
    runtime: &'volume mut VolumeRuntime,
}

impl MountedVolumeAccess<'_> {
    /// Acquires unique paging initialization authority without borrowing the VCB across I/O.
    /// # Errors
    /// Returns stale stream identity, competing setup, native residency or lease exhaustion.
    pub(crate) fn acquire_paging_file_setup(
        &self,
        fcb: NonNull<FileControlBlock>,
        file: KernelFileObject,
        extension: bool,
    ) -> DriverResult<PagingFileSetupLease> {
        self.volume
            .file_control_blocks
            .acquire_paging_file_setup(fcb, file, extension)
    }
    /// Borrows advisory tunneling without granting ext4 namespace mutation authority.
    pub(crate) fn name_tunnel(&self) -> &crate::kernel::name_tunnel::NameTunnel {
        &self.volume.name_tunnel
    }
    /// Pins the UUID identity table only for metadata/security operation admission.
    /// # Errors
    /// Returns finite reference-budget exhaustion.
    pub(crate) fn identity_snapshot(&self) -> DriverResult<crate::identity::IdentitySnapshot> {
        self.runtime.identity.get().capture()
    }
    /// Lends the cache to one synchronous pass while retaining independent driver authorities.
    /// The sole reactor actor cannot admit another pass while this closure runs. The owner is
    /// restored before any returned scheduler transition is acted upon; no cache borrow can
    /// enter a lower envelope. Temporary absence is an ordinary disabled cache representation.
    pub(crate) fn with_metadata_cache<T>(
        &mut self,
        operation: impl FnOnce(&mut ext4_core::MetadataCache, &mut Self) -> T,
    ) -> T {
        let mut cache = core::mem::take(&mut self.runtime.metadata_cache);
        let result = operation(&mut cache, self);
        self.runtime.metadata_cache = cache;
        result
    }
    /// Closes new-create admission before waiting for already admitted mutations to drain.
    /// # Errors
    /// Returns device busy for a direct open or competing lifecycle, terminal media failure,
    /// or another query-remove reservation. No durable marker is changed by this operation.
    #[expect(
        unsafe_code,
        reason = "the sole mounted actor retains its pinned volume through the preparation"
    )]
    pub(crate) fn prepare_query_removal(
        &self,
    ) -> DriverResult<crate::kernel::stream::QueryRemovalPreparation> {
        self.authorize_durability()?;
        self.volume_control.authorize_query_removal()?;
        unsafe {
            // SAFETY: The suspended operation and reactor rundown retain this VCB and native gate.
            self.volume.stream_context.prepare_query_removal()
        }
    }

    /// Revalidates direct opens and lifecycle after previously admitted work has finished.
    /// # Errors
    /// Returns device removed or terminal durability failure, or device busy if prior work
    /// published an open while query removal was draining.
    pub(crate) fn authorize_query_removal(&self) -> DriverResult<()> {
        self.authorize_durability()?;
        self.volume_control.authorize_query_removal()
    }

    /// Retains every cache stream after pre-query mutations have drained.
    /// # Errors
    /// Returns device busy for namespace handles, or the exact allocation/lease failure.
    pub(crate) fn prepare_query_removal_cache_drain(
        &self,
    ) -> DriverResult<PreparedStreamCacheDrain> {
        self.authorize_query_removal()?;
        self.volume
            .file_control_blocks
            .prepare_volume_lock_cache_drain()
            .map_err(|error| {
                if error == DriverError::AccessDenied {
                    DriverError::DeviceBusy
                } else {
                    error
                }
            })
    }
    /// Captures volume-scoped native authority for the current actor's retained VCB.
    #[expect(
        unsafe_code,
        reason = "the actor and its device rundown retain the pinned VCB and native header"
    )]
    pub(crate) fn storage_access(&self) -> crate::kernel::stream::VolumeStorageAccess {
        unsafe {
            // SAFETY: The mounted actor owns the pinned VCB until terminal reactor join.
            self.volume.stream_context.storage_access()
        }
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck())
    }

    /// Rejects native storage that has received a terminal PnP notification.
    /// # Errors
    ///
    /// Returns device removed regardless of cached data or the current immutable epoch.
    pub(crate) fn authorize_storage(&self) -> DriverResult<()> {
        self.storage_access().authorize()
    }

    /// Revalidates the issuing authority while holding the lower submission exclusion.
    /// A completed dismount retains raw lock authority independently of the ended ext4 session.
    /// # Errors
    /// Returns removal, expired filesystem ownership, a lost raw lock or insufficient access.
    pub(crate) fn authorize_storage_submission(
        &mut self,
        authority: StorageSubmissionSource,
    ) -> DriverResult<crate::kernel::stream::StorageSubmissionLease> {
        self.authorize_submission_authority(authority)?;
        let permit = self.storage_access().acquire_submission()?;
        self.authorize_submission_authority(authority)?;
        Ok(permit)
    }

    /// Observes only the authority named by the retained operation; raw identity grants no ext4 I/O.
    /// # Errors
    /// Returns revocation, lock loss, write protection or per-handle access failure.
    fn authorize_submission_authority(
        &mut self,
        authority: StorageSubmissionSource,
    ) -> DriverResult<()> {
        match authority {
            StorageSubmissionSource::Filesystem => self.runtime.require_media_ownership(),
            StorageSubmissionSource::RawVolume { target, kind } => {
                self.authorize_raw_volume_io(target, kind)?;
                if !self.volume_control.state.raw_session() {
                    self.runtime.require_media_ownership()?;
                }
                Ok(())
            }
        }
    }

    /// Revalidates a retained cached transfer's independent reliability after media verification.
    /// # Errors
    /// Rejects removal or revoked read/write health without restoring any authority.
    #[cfg(not(test))]
    pub(crate) fn authorize_cache_resumption(&self, write: bool) -> DriverResult<()> {
        self.authorize_storage()?;
        if write {
            self.runtime.authorize_durability()
        } else {
            self.runtime.authorize_media_read()
        }
    }

    /// Revalidates the original operation's current reliability after same-media verification.
    /// # Errors
    /// Removal, revoked ownership or a failed runtime prevents reissuing even a zero-progress I/O.
    #[cfg(not(test))]
    pub(crate) fn authorize_storage_resumption(
        &self,
        request: &ext4_core::StorageRequest,
    ) -> DriverResult<()> {
        self.authorize_storage()?;
        match request {
            ext4_core::StorageRequest::Read { .. } => self.runtime.authorize_media_read(),
            ext4_core::StorageRequest::Write { .. } | ext4_core::StorageRequest::Flush { .. } => {
                self.runtime.authorize_durability()
            }
        }
    }

    /// Reconciles a published storage revocation on the sole actor. Surprise removal retains
    /// the device even without handles until final REMOVE arrives; media replacement does not.
    /// Existing sections and lower completions retain their owners; no flush or clean-marker
    /// write is attempted here.
    #[cfg(not(test))]
    pub(crate) fn observe_storage_revocation(&mut self) -> Option<VolumeRetirement> {
        let revocation = self.storage_access().revocation()?;
        if self.volume_control.state == MountedVolumeState::Retiring {
            return None;
        }
        if !matches!(
            self.volume_control.state,
            MountedVolumeState::StorageRevoked(_)
        ) {
            self.runtime.record_durability_unknown();
            self.runtime.record_read_unreliable();
            self.volume.directory_change_notifier.cleanup_all();
        }
        // Final removal may supersede replacement; the latest cause selects caller failures.
        self.volume_control.state = MountedVolumeState::StorageRevoked(revocation);
        Some(self.begin_retirement())
    }

    /// Ends this instance after verification observed another medium in the same device.
    ///
    /// Storage is revoked before the VPB moves new opens to an unmounted successor, so a fresh
    /// mount can never race this instance's lower submissions. Physical ownership is revoked
    /// without writing a clean marker or MMP release to the replacement medium. The actor's next
    /// revocation observation completes the session termination and selects retirement.
    pub(crate) fn publish_media_replacement(&mut self, device: crate::state::KernelDevice) {
        #[expect(
            unsafe_code,
            reason = "the mounted actor retains the pinned VCB and native header through publication"
        )]
        let published = unsafe {
            // SAFETY: The sole actor owns this pinned VCB until terminal reactor join.
            self.volume.stream_context.publish_media_replacement()
        }
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        if published {
            self.runtime.record_media_changed();
        }
        crate::state::MountedVolumeDevice::withdraw_replaced_media(device);
    }

    /// Returns the write-only operational event capability for this mounted volume.
    pub(crate) const fn operational_trace(&self) -> OperationalTrace {
        self.volume.trace
    }
}

/// VPB-visible effect produced when a direct-volume handle is cleaned up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeHandleCleanup {
    /// Cleanup released direct access acquired without an explicit volume lock.
    DirectAccessReleased,
    /// Only the direct-volume share claim was released.
    Released,
    /// The cleaned-up FILE_OBJECT also owned the volume lock.
    Unlocked,
}

/// Physical-retirement decision produced by one actor-owned Close transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeRetirement {
    /// At least one FILE_OBJECT remains or the volume has not logically dismounted.
    Retained,
    /// The last FILE_OBJECT closed after dismount and teardown must be queued exactly once.
    Start,
}

/// Direct-volume Close effects published after typed context release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VolumeCloseOutcome {
    /// Whether a cancelled open also released the visible VPB lock.
    cleanup: VolumeHandleCleanup,
    /// Whether this Close owns the one physical-retirement transition.
    retirement: VolumeRetirement,
}

/// Lifecycle transition retained while a durability barrier drains earlier work.
#[derive(Debug)]
pub(crate) struct PreparedVolumeStateTransition {
    /// Exact mounted owner whose state may be published or failed.
    volume: MountedVolumeRef,
    /// Publication variant that owns the expected pre-state and authorized post-state.
    kind: PreparedVolumeStateTransitionKind,
}

/// Unique reversible exclusion; sealing consumes it into terminal close authority.
#[derive(Debug)]
pub(crate) struct PreparedVolumeClose {
    /// Exact mounted owner retaining the reversible exclusion.
    volume: MountedVolumeRef,
    /// Exact close target selected while the filesystem still owns its mounted session.
    target: VolumeCloseTarget,
}

/// Reversible volume-lock transition paired with every stream cache lease it must drain.
#[derive(Debug)]
pub(crate) struct PreparedVolumeLock {
    /// State publication retained until journal and lower-device durability complete.
    transition: PreparedVolumeStateTransition,
    /// Preallocated shared-stream cache drain.
    cache_drain: PreparedStreamCacheDrain,
}

impl PreparedVolumeLock {
    /// Separates the state publication from the sequential cache-work plan.
    pub(crate) fn into_parts(self) -> (PreparedVolumeStateTransition, PreparedStreamCacheDrain) {
        (self.transition, self.cache_drain)
    }
}

#[derive(Debug)]
/// Lifecycle publication authorized only after its matching durability barrier.
enum PreparedVolumeStateTransitionKind {
    /// Ordinary volume-lock publication after one filesystem flush.
    Lock {
        /// FILE_OBJECT whose lock attempt has already closed namespace admission.
        owner: KernelFileObject,
    },
    /// Logical session termination; successful raw access additionally requires clean finalization.
    SessionEnd {
        /// Terminal selected when the current `Closing` state was entered.
        target: VolumeCloseTarget,
    },
}

impl VolumeCloseOutcome {
    /// Returns the VPB-visible cleanup effect.
    pub(crate) const fn cleanup(self) -> VolumeHandleCleanup {
        self.cleanup
    }

    /// Returns the physical-retirement decision.
    pub(crate) const fn retirement(self) -> VolumeRetirement {
        self.retirement
    }
}

impl MountedVolumeAccess<'_> {
    /// Returns the stable raw identity stored in FCB and open-handle lifetime records.
    pub(crate) fn file_object_owner(&self) -> NonNull<VolumeControlBlock> {
        NonNull::from(self.volume)
    }

    /// Checks that a lifetime record belongs to this device-local mounted binding.
    pub(crate) fn owns_volume(&self, candidate: NonNull<VolumeControlBlock>) -> bool {
        NonNull::from(self.volume) == candidate
    }

    /// Records one direct-volume FILE_OBJECT share claim.
    /// # Errors
    ///
    /// Returns an error when an existing volume handle denies the requested sharing.
    pub(crate) fn open_volume_handle(
        &mut self,
        file_object: KernelFileObject,
        desired_access: GrantedAccess,
        share_access: ShareAccess,
    ) -> DriverResult<()> {
        let control = &mut self.volume_control;
        control.state.authorize_create()?;
        let next_count = control
            .volume_file_objects
            .checked_add(1)
            .ok_or(DriverError::InsufficientResources)?;
        control
            .handles
            .open(file_object, desired_access, share_access)?;
        control.volume_file_objects = next_count;
        Ok(())
    }

    /// Removes one direct-volume FILE_OBJECT share claim.
    pub(crate) fn cleanup_volume_handle(
        &mut self,
        file_object: KernelFileObject,
    ) -> VolumeHandleCleanup {
        let control = &mut self.volume_control;
        control.handles.cleanup(file_object);
        let (state, effect) = control.state.cleanup(file_object);
        control.state = state;
        effect
    }

    /// Releases one direct-volume FILE_OBJECT and selects terminal physical retirement.
    pub(crate) fn close_volume_file_object(
        &mut self,
        file_object: KernelFileObject,
        release_plan: CloseReleasePlan,
    ) -> VolumeCloseOutcome {
        let cleanup = {
            let control = &mut self.volume_control;
            let cleanup = match release_plan {
                CloseReleasePlan::CleanedHandle => VolumeHandleCleanup::Released,
                CloseReleasePlan::CancelledOpen => {
                    control.handles.cleanup(file_object);
                    let (state, cleanup) = control.state.cleanup(file_object);
                    control.state = state;
                    cleanup
                }
            };
            control.volume_file_objects = control
                .volume_file_objects
                .checked_sub(1)
                .unwrap_or_else(|| {
                    KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
                });
            cleanup
        };
        VolumeCloseOutcome {
            cleanup,
            retirement: self.begin_retirement(),
        }
    }

    /// Rechecks physical retirement after one namespace FILE_OBJECT has closed.
    pub(crate) fn close_node_file_object(&mut self) -> VolumeRetirement {
        self.begin_retirement()
    }

    /// A terminal operation may finish after the last Close, so actor progress must also select
    /// retirement. Ordinary mounted operation does not acquire the stream ledger for this check.
    #[cfg(not(test))]
    pub(crate) fn recheck_terminal_retirement(&mut self) -> VolumeRetirement {
        if self.volume_control.state.permits_retirement() {
            self.begin_retirement()
        } else {
            VolumeRetirement::Retained
        }
    }

    /// Returns whether one or more handle-free streams still have native cache/section residents.
    #[cfg(not(test))]
    pub(crate) fn delayed_close_pending(&self) -> bool {
        self.volume
            .file_control_blocks
            .native_residency_recheck_pending()
    }

    /// Consumes one shared delayed-close timer event and rechecks every resident stream once.
    ///
    /// Native Cc/MM inspection occurs outside the ledger resource. If this pass drains the final
    /// namespace stream after logical dismount, it also owns the unique physical-retirement
    /// transition.
    #[cfg(not(test))]
    pub(crate) fn expire_delayed_close_timer(&mut self) -> VolumeRetirement {
        self.volume
            .file_control_blocks
            .mark_native_residency_rechecks_due();
        self.volume
            .file_control_blocks
            .recheck_due_native_residency();
        self.begin_retirement()
    }

    /// Atomically moves the actor-owned volume into its one physical-retirement transition.
    fn begin_retirement(&mut self) -> VolumeRetirement {
        if self.authorize_storage().is_err()
            && !self.storage_access().revocation_permits_retirement()
        {
            return VolumeRetirement::Retained;
        }
        let namespace_empty = self.volume.file_control_blocks.is_empty();
        let control = &mut self.volume_control;
        if control.state.permits_retirement() {
            // Terminal observations distinguish retained FILE_OBJECTs from cache/worker streams.
            // They carry no identity or count and grant no retirement authority.
            for (path, drained) in [
                (
                    OperationalPath::VolumeHandlesDrain,
                    control.volume_file_objects == 0,
                ),
                (OperationalPath::VolumeStreamsDrain, namespace_empty),
            ] {
                self.volume.trace.record_status(
                    path,
                    if drained {
                        STATUS_SUCCESS
                    } else {
                        wdk_sys::STATUS_PENDING
                    },
                );
            }
        }
        let (state, retirement) = control
            .state
            .retire_if_unreferenced(namespace_empty, control.volume_file_objects);
        control.state = state;
        if retirement == VolumeRetirement::Start {
            self.volume.trace.record(
                OperationalPath::VolumeRetirement,
                STATUS_SUCCESS,
                OperationalOutcome::Selected,
            );
        }
        retirement
    }

    /// Validates a volume lock and prepares its post-durability publication.
    /// # Errors
    ///
    /// Returns access denied while any other handle is active, volume dismounted after terminal
    /// dismount.
    pub(crate) fn prepare_lock_volume(
        &mut self,
        owner: KernelFileObject,
    ) -> DriverResult<PreparedVolumeLock> {
        self.authorize_durability()?;
        let next_state = self.volume_control.state.begin_lock(owner)?;
        if self.volume_control.handles.active_handle_count() != 1 {
            return Err(DriverError::AccessDenied);
        }
        let cache_drain = self
            .volume
            .file_control_blocks
            .prepare_volume_lock_cache_drain()?;
        self.volume_control.state = next_state;
        Ok(PreparedVolumeLock {
            transition: PreparedVolumeStateTransition {
                volume: MountedVolumeRef::new(NonNull::from(self.volume)),
                kind: PreparedVolumeStateTransitionKind::Lock { owner },
            },
            cache_drain,
        })
    }

    /// Requires the prepared cache drain to have removed every non-handle stream resident.
    /// # Errors
    ///
    /// Returns access denied for an outstanding operation or the native mapped-file conflict.
    pub(crate) fn finish_volume_lock_cache_drain(
        &self,
        completed: crate::state::CompletedStreamCacheDrain,
    ) -> DriverResult<()> {
        self.volume
            .file_control_blocks
            .finish_volume_lock_cache_drain(completed)
    }

    /// Releases a volume lock owned by the supplied direct-volume FILE_OBJECT.
    /// # Errors
    ///
    /// Returns not-locked when this FILE_OBJECT is not the current lock owner.
    pub(crate) fn unlock_volume(&mut self, owner: KernelFileObject) -> DriverResult<()> {
        if self.storage_access().key_removal_active() {
            return Err(DriverError::DeviceBusy);
        }
        let control = &mut self.volume_control;
        control.state = control.state.unlock(owner)?;
        Ok(())
    }

    /// Excludes ordinary operations while leaving paging and session ownership intact.
    /// # Errors
    /// Returns storage, lifecycle or paging-file exclusion before changing admission.
    pub(crate) fn prepare_volume_close(
        &mut self,
        target: VolumeCloseTarget,
    ) -> DriverResult<PreparedVolumeClose> {
        self.authorize_storage()?;
        if !matches!(target, VolumeCloseTarget::Shutdown) {
            self.volume.file_control_blocks.authorize_dismount()?;
        }
        let state = self.volume_control.state.prepare_close(target)?;
        self.storage_access().begin_close_writeback()?;
        self.volume_control.state = state;
        Ok(PreparedVolumeClose {
            volume: MountedVolumeRef::new(NonNull::from(self.volume)),
            target,
        })
    }

    /// Rechecks paging-file setup published by work that was admitted before preparation.
    /// # Errors
    /// Returns paging-file exclusion, snapshot allocation or retained-stream capacity failure.
    pub(crate) fn prepare_close_writeback(
        &self,
        preparation: &PreparedVolumeClose,
    ) -> DriverResult<DriverVec<StreamCacheLease>> {
        self.require_close_preparation(preparation);
        if !matches!(preparation.target, VolumeCloseTarget::Shutdown) {
            self.volume.file_control_blocks.authorize_dismount()?;
        }
        self.prepare_cache_writeback()
    }

    /// Healthy preparation can reopen; an unhealthy session returns sealed termination authority.
    /// Physical removal owns its independent teardown and returns no session continuation.
    pub(crate) fn abort_or_seal_close(
        &mut self,
        preparation: PreparedVolumeClose,
    ) -> Option<PreparedVolumeStateTransition> {
        self.require_close_preparation(&preparation);
        if self.authorize_storage().is_err() {
            return None;
        }
        if self.runtime.authorize_durability().is_err() {
            return Some(self.seal_volume_close(preparation).unwrap_or_else(|_| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            }));
        }
        self.storage_access().abort_close_writeback();
        self.volume_control.state = self
            .volume_control
            .state
            .abort_close(preparation.target)
            .unwrap_or_else(|| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
        None
    }

    /// Consumes reversible preparation before sealing paging and issuing any clean-marker effect.
    /// # Errors
    /// Returns removal if native revocation won while cache writeback was outside the actor.
    pub(crate) fn seal_volume_close(
        &mut self,
        preparation: PreparedVolumeClose,
    ) -> DriverResult<PreparedVolumeStateTransition> {
        self.require_close_preparation(&preparation);
        self.authorize_storage()?;
        self.volume_control.state = self
            .volume_control
            .state
            .seal_close(preparation.target)
            .unwrap_or_else(|| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
        self.storage_access().seal_close_writeback();
        Ok(PreparedVolumeStateTransition {
            volume: preparation.volume,
            kind: PreparedVolumeStateTransitionKind::SessionEnd {
                target: preparation.target,
            },
        })
    }

    /// A continuation may resolve only the exclusion acquired from this mounted owner.
    fn require_close_preparation(&self, preparation: &PreparedVolumeClose) {
        if !self.owns_volume(preparation.volume.as_non_null()) {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
        }
    }

    /// Captures every resident inode stream after admission has excluded new cache owners.
    /// # Errors
    /// Returns snapshot allocation or retained-stream capacity failure.
    pub(crate) fn prepare_cache_writeback(&self) -> DriverResult<DriverVec<StreamCacheLease>> {
        self.volume.file_control_blocks.prepare_cache_writeback()
    }

    /// Publishes one previously validated lifecycle transition after its barrier succeeds.
    /// # Errors
    ///
    /// Device removal revokes earlier prepared lock/close publication authority.
    pub(crate) fn publish_volume_state_transition(
        &mut self,
        transition: PreparedVolumeStateTransition,
    ) -> DriverResult<()> {
        if !self.owns_volume(transition.volume.as_non_null()) {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
        }
        self.authorize_storage()?;
        let control = &mut self.volume_control;
        match transition.kind {
            PreparedVolumeStateTransitionKind::Lock { owner } => {
                control.state = control.state.finish_lock(owner).unwrap_or_else(|| {
                    KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
                });
            }
            PreparedVolumeStateTransitionKind::SessionEnd { target } => {
                control.state = control.state.finish_close(target).unwrap_or_else(|| {
                    KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
                });
                self.volume.directory_change_notifier.cleanup_all();
            }
        }
        Ok(())
    }

    /// Consumes a failed lifecycle publication while preserving one-way clean-close semantics.
    pub(crate) fn fail_volume_state_transition(
        &mut self,
        transition: PreparedVolumeStateTransition,
        error: DriverError,
    ) {
        if !self.owns_volume(transition.volume.as_non_null()) {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
        }
        if self.authorize_storage().is_err() {
            return;
        }
        let storage = self.storage_access();
        let control = &mut self.volume_control;
        control.state = match transition.kind {
            PreparedVolumeStateTransitionKind::Lock { owner } => control.state.abort_lock(owner),
            PreparedVolumeStateTransitionKind::SessionEnd { target } => {
                storage.seal_close_writeback();
                self.volume.directory_change_notifier.cleanup_all();
                control.state.fail_close(target, error)
            }
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    }

    /// Reports whether the volume remains logically mounted.
    /// # Errors
    ///
    /// Returns volume dismounted after a successful forced dismount.
    pub(crate) fn ensure_mounted(&self) -> DriverResult<()> {
        self.authorize_storage()?;
        self.volume_control.state.ensure_mounted()
    }

    /// Authorizes creation of a new FILE_OBJECT against the current volume state.
    /// # Errors
    ///
    /// Returns access denied while locked or volume dismounted after terminal dismount.
    pub(crate) fn authorize_create(&self) -> DriverResult<()> {
        self.storage_access().authorize_create()?;
        self.volume_control.state.authorize_create()
    }

    /// Authorizes one ordinary handle operation against the current volume state.
    /// # Errors
    ///
    /// Returns access denied when another handle owns the lock, or volume dismounted after
    /// terminal logical dismount.
    pub(crate) fn authorize_handle(&self, file_object: KernelFileObject) -> DriverResult<()> {
        self.authorize_storage()?;
        self.volume_control.state.authorize_handle(file_object)
    }

    /// Requires the completed cache/mapping drain owned by this exact volume FILE_OBJECT.
    /// # Errors
    /// Returns not-locked unless this handle owns the clean lock; close or removal revokes it.
    pub(crate) fn authorize_key_removal(&self, owner: KernelFileObject) -> DriverResult<()> {
        self.authorize_storage()?;
        self.runtime.authorize_durability()?;
        self.volume_control.state.authorize_key_removal(owner)
    }

    /// Retains create exclusion through a key mutation, even if its lock owner is cleaned up.
    /// # Errors
    /// Returns lock-owner, reliability, media or competing-removal failure before exclusion.
    pub(crate) fn begin_key_removal(
        &self,
        owner: KernelFileObject,
    ) -> DriverResult<crate::kernel::stream::KeyRemovalLease> {
        self.authorize_key_removal(owner)?;
        self.storage_access().begin_key_removal()
    }

    /// Retains one regular-file stream for paging I/O without consulting handle-local CCB state.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT stream identity is malformed, belongs to another
    /// mounted volume, is not a regular file, or the finite deferred-lease count is exhausted.
    pub(crate) fn acquire_paging_stream_lease(
        &self,
        file_object: ActiveFileObject<'_>,
    ) -> DriverResult<PagingStreamLease> {
        self.storage_access().authorize_paging()?;
        self.volume
            .file_control_blocks
            .acquire_paging_stream_lease(file_object, NonNull::from(self.volume))
    }

    /// Retains one node stream while FsRtl owns a pending oplock-break IRP.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT stream identity is malformed, belongs to another
    /// mounted volume, or the finite deferred-lease count is exhausted.
    pub(crate) fn acquire_oplock_stream_lease(
        &self,
        file_object: ActiveFileObject<'_>,
    ) -> DriverResult<OplockStreamLease> {
        self.volume
            .file_control_blocks
            .acquire_oplock_stream_lease(file_object, NonNull::from(self.volume))
    }

    /// Acquires the mutation grant barrier and FsRtl check lease for one node FILE_OBJECT.
    /// # Errors
    ///
    /// Returns an identity, retention, or finite-counter failure before the break check begins.
    pub(crate) fn acquire_oplock_mutation(
        &self,
        file_object: ActiveFileObject<'_>,
    ) -> DriverResult<(OplockMutationLease, OplockStreamLease)> {
        self.volume
            .file_control_blocks
            .acquire_oplock_mutation(file_object, NonNull::from(self.volume))
    }

    /// Reserves one node and retains its resident stream for an FsRtl check.
    /// # Errors
    ///
    /// Returns a finite reservation or deferred-lease failure before any FsRtl call. The optional
    /// check lease is absent only when no FCB is currently resident; the node reservation
    /// remains active in either case.
    pub(crate) fn acquire_node_oplock_mutation(
        &self,
        node: NodeId,
    ) -> DriverResult<(OplockMutationLease, Option<OplockStreamLease>)> {
        self.volume
            .file_control_blocks
            .acquire_node_oplock_mutation(node)
    }

    /// Probes existing opens before choosing the create oplock protocol; no share claim is made.
    /// # Errors
    /// Returns the current sharing conflict for protocol selection.
    pub(crate) fn check_existing_create_sharing(
        &self,
        node: NodeId,
        file: KernelFileObject,
        access: crate::irp::ExistingOperationAccess,
        sharing: crate::irp::ShareAccess,
    ) -> DriverResult<()> {
        self.volume
            .file_control_blocks
            .check_existing_create_sharing(node, file, access, sharing)
    }

    /// Retains the exact stream already owned by a provisional create claim.
    /// # Errors
    ///
    /// Returns an ownership invariant or finite deferred-lease failure before FsRtl delegation.
    pub(crate) fn acquire_claimed_oplock_stream_lease(
        &self,
        fcb: NonNull<FileControlBlock>,
    ) -> DriverResult<OplockStreamLease> {
        self.volume
            .file_control_blocks
            .acquire_claimed_oplock_stream_lease(fcb)
    }

    /// Reports whether the exact stream currently permits a new oplock grant.
    pub(crate) fn oplock_grant_available(&self, fcb: NonNull<FileControlBlock>) -> bool {
        self.volume.file_control_blocks.oplock_grant_available(fcb)
    }

    /// Retains one node stream while a PASSIVE_LEVEL worker executes Cache Manager work.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT stream identity is malformed, belongs to another
    /// mounted volume, or the finite deferred-lease count is exhausted.
    pub(crate) fn acquire_file_object_cache_lease(
        &self,
        file_object: ActiveFileObject<'_>,
    ) -> DriverResult<FileObjectCacheLease> {
        self.volume
            .file_control_blocks
            .acquire_file_object_cache_lease(file_object, NonNull::from(self.volume))
    }

    /// Preallocates final size gates, combining image exclusion with any existing-file reset.
    /// Resets require admission even when their cache dimensions are unchanged. `requester` names
    /// the regular file whose main resource the synchronous paging end-of-file requester owns;
    /// its growth is covered by that ownership and needs no passive preparation.
    /// # Errors
    ///
    /// Returns the exact allocation, stream-retention, or native size-snapshot failure before the
    /// first Cache Manager or Memory Manager call is submitted.
    pub(crate) fn prepare_stream_size_changes(
        &self,
        updates: &PreparedStreamMetadataPublications,
        deletion: Option<NodeId>,
        reset: Option<NodeId>,
        requester: Option<NodeId>,
    ) -> DriverResult<StreamSizeChangePlan> {
        self.volume
            .file_control_blocks
            .prepare_stream_size_changes(updates, deletion, reset, requester)
    }

    /// Verifies that retained native gates still match the latest resolved size projection.
    /// # Errors
    ///
    /// Returns a native size snapshot failure or a cross-volume gate invariant error.
    pub(crate) fn prepared_stream_size_changes_match(
        &self,
        updates: &PreparedStreamMetadataPublications,
        prepared: &PreparedStreamSizeChanges,
        deletion: Option<NodeId>,
        reset: Option<NodeId>,
    ) -> DriverResult<bool> {
        self.volume
            .file_control_blocks
            .prepared_stream_size_changes_match(updates, prepared, deletion, reset)
    }

    /// Retains one exact cleanup FCB for native stream-deletion preparation.
    /// # Errors
    ///
    /// Returns an ownership or deferred-lease failure before any Cc/MM call is submitted.
    pub(crate) fn prepare_stream_deletion(
        &self,
        fcb: NonNull<FileControlBlock>,
        node: NodeId,
    ) -> DriverResult<Option<StreamDeletionLease>> {
        self.volume
            .file_control_blocks
            .prepare_stream_deletion(fcb, node)
    }

    /// Retains a resident regular-file stream for an existing write-open image check.
    /// # Errors
    ///
    /// Returns a finite deferred-lease failure before any MM call.
    pub(crate) fn prepare_stream_write_open(
        &self,
        fcb: NonNull<FileControlBlock>,
        node: NodeId,
    ) -> DriverResult<StreamWriteOpenLease> {
        self.volume
            .file_control_blocks
            .prepare_stream_write_open(fcb, node)
    }

    /// Retains the exact file for the native verity preparation boundary.
    /// # Errors
    /// Returns retention or malformed stream identity before freezing data for hashing.
    pub(crate) fn prepare_stream_verity(
        &self,
        fcb: NonNull<FileControlBlock>,
        file: ext4_core::FileNodeId,
    ) -> DriverResult<StreamVerityLease> {
        self.volume
            .file_control_blocks
            .prepare_stream_verity(fcb, file)
    }

    /// Grants exclusive physical-map mutation over the exact retained stream.
    /// # Errors
    /// Returns protected/stale stream or reference admission failure.
    pub(crate) fn prepare_stream_relocation(
        &self,
        fcb: NonNull<FileControlBlock>,
        file: ext4_core::FileNodeId,
    ) -> DriverResult<StreamRelocationLease> {
        self.volume
            .file_control_blocks
            .prepare_stream_relocation(fcb, file)
    }

    /// Installs FILE_OBJECT-owned protection while no relocation is active.
    /// # Errors
    /// Returns movement conflict or allocation failure before acquiring protection.
    pub(crate) fn protect_file_clusters(
        &self,
        fcb: NonNull<FileControlBlock>,
        file: KernelFileObject,
    ) -> DriverResult<()> {
        self.volume
            .file_control_blocks
            .protect_file_clusters(fcb, file)
    }

    /// Produces one bounded raw transfer authority from lifecycle, access, and extent state.
    /// # Errors
    ///
    /// Returns access denied unless the exact retained direct owner has the matching data right;
    /// media writes require the filesystem session to have ended.
    pub(crate) fn authorize_raw_volume_io(
        &self,
        target: RawVolumeTarget,
        kind: RawVolumeOperationKind,
    ) -> DriverResult<RawVolumeIoPermit> {
        self.authorize_storage()?;
        if !self.owns_volume(target.volume()) {
            return Err(DriverError::InvalidDeviceRequest);
        }
        self.volume_control
            .state
            .authorize_raw(target.owner(), kind)?;
        self.raw_volume_bounds(target, kind)
    }

    /// Validates a raw request before any session-close or media effect.
    /// # Errors
    /// Returns lifecycle, retained data access, media policy or geometry failure.
    pub(crate) fn prepare_raw_volume_io(
        &self,
        target: RawVolumeTarget,
        kind: RawVolumeOperationKind,
    ) -> DriverResult<RawVolumeIoPermit> {
        self.authorize_storage()?;
        if !self.owns_volume(target.volume()) {
            return Err(DriverError::InvalidDeviceRequest);
        }
        self.volume_control
            .state
            .prepare_raw(target.owner(), kind)?;
        self.raw_volume_bounds(target, kind)
    }

    /// Selects the required session handoff without granting lower-write permission.
    pub(crate) fn raw_write_requires_close(&self, owner: KernelFileObject) -> bool {
        matches!(self.volume_control.state, MountedVolumeState::Locked { owner: current } if current == owner)
    }

    /// A raw-locked session already completed every filesystem and ownership obligation.
    pub(crate) fn raw_locked_by(&self, owner: KernelFileObject) -> bool {
        matches!(self.volume_control.state, MountedVolumeState::RawLocked { owner: current } if current == owner)
    }

    /// Completes explicit dismount without reusing the journal cursor consumed by a raw write.
    pub(crate) fn dismount_raw_session(&mut self, owner: KernelFileObject) {
        self.volume_control.state = self
            .volume_control
            .state
            .dismount_raw(owner)
            .unwrap_or_else(|| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
    }

    /// Reuses immutable geometry and retained handle rights without conflating session authority.
    /// # Errors
    /// Returns data-right, write-policy, uncertain-write or coordinate conversion failure.
    fn raw_volume_bounds(
        &self,
        target: RawVolumeTarget,
        kind: RawVolumeOperationKind,
    ) -> DriverResult<RawVolumeIoPermit> {
        let (access, extent) = target.authority();
        access.require(kind)?;
        if kind == RawVolumeOperationKind::Write {
            self.runtime.authorize_media_write()?;
            target.ensure_write_retryable()?;
        }
        let route = self.storage_route();
        let bound = match extent {
            RawExtentPolicy::FilesystemExtent => self.mounted_profile().filesystem_length(),
            RawExtentPolicy::PartitionExtent => route.filesystem_device_length(),
        };
        Ok(RawVolumeIoPermit {
            bound,
            sector_size: usize::try_from(route.filesystem_sector_size().as_u32())
                .map_err(|_| DriverError::InvalidParameter)?,
        })
    }

    /// Authorizes changing only this direct-volume handle's selected raw bound.
    /// # Errors
    ///
    /// Returns an ownership or lifecycle error when the handle cannot control its raw extent.
    pub(crate) fn authorize_raw_extent_change(&self, owner: KernelFileObject) -> DriverResult<()> {
        self.volume_control.state.authorize_raw_extent_change(owner)
    }

    /// Selects a direct-volume flush without reusing a logically dismounted ext4 epoch.
    /// # Errors
    ///
    /// Returns an ownership, access, lifecycle, or consumed raw-write authority error.
    pub(crate) fn volume_flush_scope(
        &self,
        target: RawVolumeTarget,
    ) -> DriverResult<VolumeFlushScope> {
        if !self.owns_volume(target.volume()) {
            return Err(DriverError::InvalidDeviceRequest);
        }
        let state = self.volume_control.state;
        if state.raw_session() {
            state.authorize_raw(target.owner(), RawVolumeOperationKind::Read)?;
            target
                .authority()
                .0
                .require(RawVolumeOperationKind::Write)?;
            target.ensure_write_retryable()?;
            Ok(VolumeFlushScope::RawDevice(target))
        } else {
            state.authorize_handle(target.owner())?;
            self.authorize_durability()?;
            Ok(VolumeFlushScope::Filesystem)
        }
    }

    /// Requires the mounted journal's authoritative health before promising a durable flush.
    /// # Errors
    ///
    /// Returns the same terminal failure status as future mutation attempts.
    pub(crate) fn authorize_durability(&self) -> DriverResult<()> {
        self.authorize_storage()?;
        self.runtime.authorize_durability()
    }

    /// Checks the unique directory link before namespace traversal.
    /// # Errors
    /// Returns delete-pending for a directory whose removal has been accepted.
    pub(crate) fn ensure_directory_openable(&self, directory: DirectoryNodeId) -> DriverResult<()> {
        self.volume
            .file_control_blocks
            .ensure_location_openable(NodeId::Directory(directory), None)
    }
    /// Checks an exact selected link without restricting the inode's other hard links.
    /// # Errors
    /// Returns delete-pending only for the selected namespace identity.
    pub(crate) fn ensure_location_openable(
        &self,
        node: NodeId,
        location: &OpenedLocation,
    ) -> DriverResult<()> {
        self.volume
            .file_control_blocks
            .ensure_location_openable(node, Some(location))
    }
    /// Whether another active inode handle prevents reclaiming its final link.
    pub(crate) fn has_active_inode_handles(&self, fcb: NonNull<FileControlBlock>) -> bool {
        self.volume.file_control_blocks.stream_open_count(fcb) != 0
    }
    /// Claims another inactive namespace link while this cleanup retains the inode stream.
    pub(crate) fn claim_file_delete(
        &self,
        fcb: NonNull<FileControlBlock>,
    ) -> FileCleanupDisposition {
        self.volume.file_control_blocks.claim_file_delete(fcb)
    }
    /// Defers one claimed deletion until the remaining inode handles have cleaned up.
    pub(crate) fn defer_file_delete(
        &self,
        fcb: NonNull<FileControlBlock>,
        target: NonNull<FileDeleteTarget>,
    ) {
        self.volume
            .file_control_blocks
            .defer_cleanup_delete(fcb, target);
    }

    /// Requires an existing replacement target to have no active handles.
    /// # Errors
    ///
    /// Returns delete-pending for a terminal target or sharing-violation while any active handle
    /// could still reference an inode that replacement would unlink.
    pub(crate) fn ensure_node_replaceable(&self, node: NodeId) -> DriverResult<()> {
        let ledger = &self.volume.file_control_blocks;
        ledger.ensure_node_replaceable(node)
    }

    /// Prepares an opened destination link's spelling change during hard-link replacement.
    /// # Errors
    /// Returns reference exhaustion before any namespace write.
    pub(crate) fn prepare_link_rename(
        &self,
        node: NodeId,
        source: &OpenedLocation,
        destination: OpenedLocation,
    ) -> DriverResult<Option<PreparedLinkRename>> {
        self.volume
            .file_control_blocks
            .prepare_link_rename(node, source, destination)
    }

    /// Publishes successful removal of the exact claimed link deletion target.
    pub(crate) fn complete_file_delete(
        &mut self,
        fcb: NonNull<FileControlBlock>,
        target: NonNull<FileDeleteTarget>,
    ) {
        self.volume.file_control_blocks.complete_delete(fcb, target);
    }

    /// Publishes a validated delete-pending target into one live FCB.
    pub(crate) fn set_file_delete_pending(
        &mut self,
        fcb: NonNull<FileControlBlock>,
        pending: PendingFileDeletion,
    ) {
        self.volume
            .file_control_blocks
            .set_delete_pending(fcb, pending);
    }

    /// Reports one committed namespace mutation through the mounted VCB notifier.
    pub(crate) fn report_directory_change(&self, change: DirectoryChange) {
        self.volume.report_directory_change(change);
    }

    /// Immutable mounted profile required to construct core operation state machines.
    pub(crate) fn mounted_profile(&self) -> &MountedProfile {
        self.runtime.profile()
    }

    /// Pins the final drained journal cursor under the host's terminal durability barrier.
    pub(crate) fn start_clean_close(
        &self,
        close: alloc::boxed::Box<ext4_core::CleanCloseOperation>,
        now: ext4_core::Ext4Timestamp,
    ) -> ext4_core::CleanCloseTransition {
        close.start(self.runtime.coordinator(), now)
    }

    /// Validated lower-device route for one core storage request.
    pub(crate) fn storage_route(&self) -> MountedStorageRoute {
        self.runtime.storage()
    }

    /// Allocates operation-local cryptographic state from the mounted providers.
    /// # Errors
    ///
    /// Returns an error when CNG operation state cannot be allocated or initialized.
    pub(crate) fn new_crypto_operation(&self) -> DriverResult<CngOperation> {
        self.runtime.crypto().try_new_operation()
    }

    /// Acquires one immutable committed epoch lease.
    /// # Errors
    ///
    /// Returns an error when reads are no longer reliable or the bounded lease registry is full.
    pub(crate) fn acquire_epoch(&mut self) -> DriverResult<EpochLease> {
        self.authorize_storage()?;
        self.runtime.acquire_epoch()
    }

    /// Admits current metadata and committed dependency versions for one synchronous read pass.
    /// # Errors
    /// Returns storage removal or a mismatched coordinator publication before read interpretation.
    pub(crate) fn committed_read<'state>(
        &'state self,
        cache: &'state mut ext4_core::MetadataCache,
    ) -> DriverResult<ext4_core::CommittedReadContext<'state>> {
        self.authorize_storage()?;
        self.runtime.committed_read(cache)
    }

    /// Admits a staging snapshot while retaining independent native per-handle preparation.
    /// # Errors
    /// Returns storage removal, media revocation or a stale/foreign snapshot before staging.
    pub(crate) fn mutation_context<'cache>(
        &self,
        cache: ext4_core::MetadataCacheAccess<'cache>,
    ) -> DriverResult<ext4_core::MutationResolveContext<'cache>> {
        self.authorize_storage()?;
        self.runtime.mutation_context(cache)
    }

    /// Observes current checkpointed discard admission without granting it.
    /// # Errors
    /// Returns storage removal, revoked ownership or write-policy failure.
    pub(crate) fn trim_ready(&self) -> DriverResult<bool> {
        self.authorize_storage()?;
        self.runtime.trim_ready()
    }
    /// Admits only a current free-space selection; no global allocation or journal authority escapes.
    /// # Errors
    /// Returns media removal, revocation, stale metadata or pre-effect allocation failure.
    pub(crate) fn reserve_trim(
        &mut self,
        selection: ext4_core::TrimSelection,
    ) -> DriverResult<ext4_core::TrimAdmission> {
        self.authorize_storage()?;
        self.runtime.reserve_trim(selection)
    }
    /// Returns a unique ended lower request even after independent media authority was revoked.
    /// # Errors
    /// A foreign completion retains both owners and changes no allocation exclusion.
    pub(crate) fn complete_trim(
        &mut self,
        pending: ext4_core::PendingTrim,
        completion: ext4_core::TrimCompletion,
    ) -> Result<ext4_core::TrimBatchResult, ext4_core::TrimCompletionMismatch> {
        self.runtime.complete_trim(pending, completion)
    }

    /// Allocates one mutation ticket and active-mutation lifetime lease.
    /// # Errors
    ///
    /// Returns an error when mutation is no longer authorized or bounded accounting overflows.
    pub(crate) fn admit_mutation(&mut self) -> DriverResult<(u64, MutationActivityLease)> {
        self.authorize_storage()?;
        self.storage_access().authorize_paging()?;
        self.runtime.admit_mutation()
    }

    /// Admits mount-local key publication while retaining volume-close drain ownership.
    /// # Errors
    /// Returns storage lifecycle or operation-accounting failure without granting media writes.
    pub(crate) fn admit_key_change(&mut self) -> DriverResult<(u64, MutationActivityLease)> {
        self.authorize_storage()?;
        self.storage_access().authorize_paging()?;
        self.runtime.admit_key_change()
    }

    /// Resolves one ephemeral core pass against the current mutation coordinator snapshot.
    /// # Errors
    ///
    /// Returns a core mutation error when the pass cannot resolve against the current snapshot.
    pub(crate) fn resolve_mutation(
        &self,
        pass: MutationResolvePass<'_, '_, '_>,
        ticket: u64,
    ) -> Result<ResolvedMutation, ext4_core::Error> {
        pass.resolve(ticket, self.runtime.coordinator())
    }

    /// Resolves a validated key insertion against the current mounted key snapshot.
    /// # Errors
    /// Returns storage removal, key conflict, or allocation failure.
    pub(crate) fn resolve_key_addition(
        &self,
        ticket: u64,
        key: ext4_core::FscryptMasterKey,
    ) -> DriverResult<ext4_core::ResolvedKeyChange> {
        self.authorize_storage()?;
        self.runtime.resolve_key_addition(ticket, key)
    }

    /// Resolves a key removal while its native namespace exclusion remains held.
    /// # Errors
    /// Returns storage removal or snapshot allocation failure.
    pub(crate) fn resolve_key_removal(
        &self,
        ticket: u64,
        identifier: FscryptKeyIdentifier,
    ) -> DriverResult<ext4_core::ResolvedKeyChange> {
        self.authorize_storage()?;
        self.runtime.resolve_key_removal(ticket, identifier)
    }

    /// Preallocates a version-revalidated key publication under exclusive scheduler grants.
    /// # Errors
    /// Returns stale grants or allocation failure before any key becomes visible.
    pub(crate) fn prepare_key_change(
        &mut self,
        change: ext4_core::ReservedKeyChange,
        commit: CommitLease,
    ) -> DriverResult<ext4_core::PreparedKeyChange> {
        self.runtime.prepare_key_change(change, commit)
    }

    /// Consumes unpublished key preparation on cancellation or terminal driver failure.
    pub(crate) fn abort_key_change(&mut self, change: ext4_core::PreparedKeyChange) {
        self.runtime.abort_key_change(change);
    }

    /// Revalidates the key snapshot after the scheduler acquired its exclusive intent.
    /// # Errors
    /// Returns a changed key version before commit admission.
    pub(crate) fn reserve_key_change(
        &self,
        change: ext4_core::ResolvedKeyChange,
        intent: MutationLease,
    ) -> DriverResult<ext4_core::ReservedKeyChange> {
        Ok(change.reserve(intent, self.runtime.coordinator())?)
    }

    /// Reserves one immutable slot for a key-only publication.
    /// # Errors
    /// Returns admission or allocation failure before publication.
    pub(crate) fn reserve_key_publication(&self) -> DriverResult<EpochPublicationSlot> {
        self.runtime.reserve_key_publication()
    }

    /// Consumes the matching visibility grant into one mount-local key epoch.
    /// # Errors
    /// Returns ownership loss without changing the visible keys.
    pub(crate) fn publish_keys(
        &mut self,
        change: ext4_core::PreparedKeyChange,
        visibility: VisibilityLease,
        slot: EpochPublicationSlot,
    ) -> DriverResult<()> {
        self.runtime.publish_keys(change, visibility, slot)
    }

    /// Revalidates one resolved mutation under its granted resource intent.
    /// # Errors
    ///
    /// Returns a core mutation error when revalidation no longer matches the granted intent.
    pub(crate) fn reserve_mutation(
        &self,
        resolved: ResolvedMutation,
        intent: MutationLease,
    ) -> Result<ReservedMutation, ext4_core::Error> {
        resolved.reserve(intent, self.runtime.coordinator())
    }

    /// Prepares a commit from the coordinator and current immutable epoch authorities.
    /// # Errors
    ///
    /// Returns a core mutation error when commit preparation cannot consume the supplied grant.
    pub(crate) fn prepare_mutation_commit(
        &mut self,
        reserved: ReservedMutation,
        commit: CommitLease,
    ) -> Result<CommitReadyMutation, ext4_core::Error> {
        self.runtime.prepare_mutation_commit(reserved, commit)
    }

    /// Reserves both immutable epoch publication slots before the first lower write.
    /// # Errors
    ///
    /// Returns an error when mutation is no longer authorized or stable storage cannot be
    /// allocated.
    pub(crate) fn reserve_epoch_publication(&mut self) -> DriverResult<EpochPublicationSlots> {
        self.runtime.reserve_epoch_publication()
    }

    /// Issues the session-bound intent after the reactor scheduler acquired the resource set.
    #[cfg(not(test))]
    pub(crate) fn grant_intent(&mut self, ticket: u64) -> MutationLease {
        self.runtime.grant_intent(ticket)
    }

    /// Grants the serialized commit lane when its runtime preconditions are satisfied.
    ///
    /// # Errors
    ///
    /// Returns the volume failure without confusing terminal rejection with a pending grant.
    #[cfg(not(test))]
    pub(crate) fn acquire_commit(&mut self, ticket: u64) -> DriverResult<Option<CommitLease>> {
        self.authorize_storage()?;
        self.runtime.acquire_commit(ticket)
    }

    /// Returns an unused pre-write commit grant to the runtime.
    #[cfg(not(test))]
    pub(crate) fn abandon_commit(&mut self, ticket: u64) {
        self.runtime.abandon_commit(ticket);
    }

    /// Grants the short durable-visibility publication lane.
    /// # Errors
    /// Returns removed storage or revoked ownership separately from contention.
    #[cfg(not(test))]
    pub(crate) fn try_grant_visibility(
        &mut self,
        ticket: u64,
    ) -> DriverResult<Option<VisibilityLease>> {
        self.authorize_storage()?;
        self.runtime.try_grant_visibility(ticket)
    }

    /// Grants the detached checkpoint lane for one visible epoch.
    /// # Errors
    /// Returns removed storage or revoked ownership separately from checkpoint contention.
    #[cfg(not(test))]
    pub(crate) fn try_grant_checkpoint(
        &mut self,
        epoch: ext4_core::EpochSequence,
    ) -> DriverResult<Option<ext4_core::CheckpointLease>> {
        self.authorize_storage()?;
        self.runtime.try_grant_checkpoint(epoch)
    }

    /// Revalidates the session before a previously granted checkpoint can start lower writes.
    /// # Errors
    /// Consumes the grant and retains checkpoint state on ownership revocation or stale admission.
    #[expect(
        clippy::result_large_err,
        reason = "rejection retains checkpoint ownership without allocating after commit"
    )]
    pub(crate) fn start_checkpoint(
        &self,
        operation: ext4_core::CheckpointOperation,
        checkpoint: ext4_core::CheckpointLease,
    ) -> Result<
        ext4_core::StorageRequestSequence<ext4_core::HomeBlockDurability>,
        (ext4_core::Error, ext4_core::CheckpointOperation),
    > {
        operation.start(checkpoint, self.runtime.coordinator())
    }

    /// Observes the next due MMP action or its completion watchdog deadline.
    #[cfg(not(test))]
    pub(crate) fn mmp_wakeup(&self) -> Option<ext4_core::MmpDeadline> {
        self.runtime.mmp_wakeup()
    }
    /// Transfers only a due renewal or a filesystem-close-authorized record release.
    /// # Errors
    /// Revokes the session if no continuous acknowledgement remains.
    #[cfg(not(test))]
    pub(crate) fn start_mmp_action(&mut self) -> DriverResult<Option<ext4_core::MmpOperation>> {
        self.runtime.start_mmp_action()
    }
    /// Accepts an exact child postcondition before publishing a successor deadline.
    /// # Errors
    /// Returns lost ownership for stale, foreign or revoked completions.
    pub(crate) fn complete_mmp_action(
        &mut self,
        completion: ext4_core::MmpCompletion,
    ) -> DriverResult<()> {
        self.runtime.complete_mmp_action(completion)
    }
    /// Transfers completed filesystem durability to the independent ownership-release protocol.
    /// # Errors
    /// Returns a retired ownership chain or a duplicate close request.
    pub(crate) fn request_mmp_close(
        &mut self,
        durability: ext4_core::CleanCloseDurability,
    ) -> DriverResult<()> {
        self.runtime.request_mmp_close(durability)
    }
    /// Waits for ownership release without restoring journal or mutation authority.
    /// # Errors
    /// Returns the first terminal ownership failure instead of an indefinite close wait.
    #[cfg(not(test))]
    pub(crate) fn mmp_close_ready(&self) -> DriverResult<bool> {
        self.authorize_storage()?;
        self.runtime.mmp_close_ready()
    }
    /// Transfers journal sharing after combined filesystem and ownership durability.
    /// # Errors
    /// Rejects a premature or repeated acknowledgment.
    pub(crate) fn finish_mmp_close(
        &mut self,
    ) -> DriverResult<Option<crate::kernel::storage::ExternalJournalExclusion>> {
        self.runtime.finish_mmp_close()
    }
    /// Keeps exclusion after a failed close without reauthorizing filesystem I/O.
    pub(crate) fn retain_external_journal_exclusion(
        &mut self,
        exclusion: crate::kernel::storage::ExternalJournalExclusion,
    ) {
        self.runtime.retain_external_journal_exclusion(exclusion);
    }
    /// Irreversibly retires the session while retaining all outstanding completion owners.
    pub(crate) fn fail_mmp(&mut self, reason: ext4_core::Error) {
        self.runtime.fail_mmp(reason);
    }

    /// Observes physical session work without requiring clean journal state or live ownership.
    pub(crate) fn session_work_drained(&self) -> bool {
        self.runtime.session_work_drained()
    }

    /// Revokes an unclean session without writing recovery or MMP clean markers.
    pub(crate) fn abandon_session(&mut self) {
        self.runtime.abandon_session();
    }

    /// Transfers journal sharing only after an abandoned session's physical work drained.
    pub(crate) fn finish_abandoned_session(
        &mut self,
    ) -> Option<crate::kernel::storage::ExternalJournalExclusion> {
        self.runtime.finish_abandoned_session()
    }

    /// Native remount routing stays excluded while an explicit lock survives a failed close.
    pub(crate) fn failed_close_retains_lock(&self) -> bool {
        matches!(
            self.volume_control.state,
            MountedVolumeState::CloseFailed {
                lock_owner: Some(_),
                ..
            }
        )
    }

    /// Reports whether no mutation or checkpoint owns journal space.
    #[cfg(not(test))]
    pub(crate) fn publication_is_idle(&self) -> bool {
        self.runtime.publication_is_idle()
    }

    /// Publishes the durable epoch and its prevalidated stream metadata in one reactor turn.
    ///
    /// The core durability/visibility capabilities are required here, so a caller cannot install
    /// prepared stream metadata through the mounted-volume boundary before the commit is durable.
    /// `size_changes` are the gates that covered every size change being published.
    /// # Errors
    /// Returns ownership loss and the unpublished native projection for mandatory cleanup.
    #[inline(never)]
    pub(crate) fn publish_durable(
        &mut self,
        mutation: DurableMutation,
        visibility: VisibilityLease,
        durable_slot: EpochPublicationSlot,
        checkpoint_slot: EpochPublicationSlot,
        stream_metadata: PreparedStreamMetadataPublications,
        size_changes: Option<&PreparedStreamSizeChanges>,
    ) -> Result<DurablePublicationOutcome, (DriverError, PreparedStreamMetadataPublications)> {
        let checkpoint =
            match self
                .runtime
                .publish_durable(mutation, visibility, durable_slot, checkpoint_slot)
            {
                Ok(checkpoint) => checkpoint,
                Err(error) => return Err((error, stream_metadata)),
            };
        let epoch = checkpoint.epoch();
        let stream_projection = self.volume.file_control_blocks.publish_stream_metadata(
            stream_metadata,
            epoch,
            size_changes,
        );
        Ok(DurablePublicationOutcome {
            checkpoint,
            stream_projection,
        })
    }

    /// Publishes an overlay-free checkpoint and releases journal space.
    /// # Errors
    /// Returns revoked ownership without retiring the visible overlay or restoring journal authority.
    pub(crate) fn publish_checkpoint(
        &mut self,
        durability: CheckpointPublication,
        publication: EpochPublicationSlot,
    ) -> DriverResult<()> {
        self.runtime.publish_checkpoint(durability, publication)
    }

    /// Records a confirmed durable abort as a read-only transition.
    pub(crate) fn record_durable_abort(&mut self) {
        self.runtime.record_durable_abort();
    }

    /// Records an unknown write or flush outcome requiring replay.
    pub(crate) fn record_durability_unknown(&mut self) {
        self.runtime.record_durability_unknown();
    }

    /// Records that committed reads can no longer be trusted.
    pub(crate) fn record_read_unreliable(&mut self) {
        self.runtime.record_read_unreliable();
    }

    /// Records an exact post-commit Cc/MM publication failure and its aggregate stream progress.
    pub(crate) fn record_publication_failure(
        &mut self,
        status: wdk_sys::NTSTATUS,
        published_streams: usize,
        unexamined_updates: usize,
    ) {
        self.runtime
            .record_publication_failure(status, published_streams, unexamined_updates);
    }

    /// Records an exact Cache Manager dirty-page writeback failure.
    pub(crate) fn record_cache_writeback_failure(&mut self, status: wdk_sys::NTSTATUS) {
        self.runtime.record_cache_writeback_failure(status);
    }

    /// Current committed volume identity.
    pub(crate) fn volume_identity(&self) -> VolumeIdentity {
        self.runtime.identity()
    }

    /// Current committed allocation geometry.
    pub(crate) fn volume_geometry(&self) -> VolumeGeometry {
        self.runtime.current_epoch().geometry()
    }

    /// Persistent check requirement from the exact currently published superblock authority.
    pub(crate) fn volume_requires_check(&self) -> bool {
        self.runtime.current_epoch().requires_check()
    }

    /// Returns the committed epoch that owns non-suspending metadata observations.
    pub(crate) fn current_epoch_sequence(&self) -> ext4_core::EpochSequence {
        self.runtime.current_epoch().sequence()
    }

    /// Checks whether resolve still observes the epoch paired with the current coordinator.
    ///
    /// Unlike pure snapshot reads, mutations must not pair old inode/allocation observations with
    /// newer resource versions. Creates can also attach a FILE_OBJECT without mutation intents.
    /// Both therefore restart after an epoch change before the next non-suspending resolve pass.
    pub(crate) fn is_current_epoch(&self, epoch: &EpochLease) -> bool {
        epoch.epoch().sequence() == self.runtime.current_epoch().sequence()
    }

    /// Current committed fscrypt key presence.
    pub(crate) fn fscrypt_key_presence(
        &self,
        identifier: FscryptKeyIdentifier,
    ) -> FscryptKeyPresence {
        self.runtime.fscrypt_key_presence(identifier)
    }

    /// Stages a missing child in the current ephemeral mutation resolve pass.
    /// # Errors
    ///
    /// Returns an error when the parent cannot be loaded or child creation cannot be staged.
    pub(crate) fn begin_child_creation(
        &self,
        transaction: &mut MutationResolvePass<'_, '_, '_>,
        parent: DirectoryNodeId,
        name: &Ext4Name,
        target: ChildCreationTarget,
    ) -> DriverResult<PendingChildCreation> {
        let owner = MountedVolumeRef::new(NonNull::from(self.volume));
        let file_control_blocks = &self.volume.file_control_blocks;
        let parent = transaction.directory(parent)?;
        let node = match target {
            ChildCreationTarget::File(metadata) => {
                NodeId::File(transaction.create_file(parent, name, metadata)?.id())
            }
            ChildCreationTarget::Directory(metadata) => {
                NodeId::Directory(transaction.create_directory(parent, name, metadata)?.id())
            }
        };
        Ok(PendingChildCreation {
            file_control_blocks: NonNull::from(file_control_blocks),
            volume: owner,
            node,
        })
    }
}

#[cfg(test)]
mod query_removal_tests {
    use super::{DriverError, MountedVolumeState, VolumeControlPlane};

    /// # Panics
    /// Panics if a retained direct FILE_OBJECT or terminal lifecycle can enter reversible removal.
    #[test]
    fn query_removal_requires_an_unlocked_volume_without_direct_file_objects() {
        let mut control = VolumeControlPlane::mounted();
        assert_eq!(control.authorize_query_removal(), Ok(()));
        control.volume_file_objects = 1;
        assert_eq!(
            control.authorize_query_removal(),
            Err(DriverError::DeviceBusy)
        );
        control.volume_file_objects = 0;
        control.state = MountedVolumeState::ShutdownComplete { lock_owner: None };
        assert_eq!(
            control.authorize_query_removal(),
            Err(DriverError::DeviceBusy)
        );
    }
}
