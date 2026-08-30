//! Mounted-volume lifecycle, handle admission, and durable mutation coordination.

use super::*;

#[derive(Debug)]
/// Volume control block stored in a mounted volume device extension.
pub(crate) struct VolumeControlBlock {
    /// Write-only operational event capability inherited from the driver registration owner.
    pub(super) trace: OperationalTrace,
    /// Volume-wide opaque FsRtl notification state. This field drops before filesystem state so
    /// pending notify IRPs cannot outlive the mounted namespace they observe.
    pub(super) directory_change_notifier: DirectoryChangeNotifier,
    /// Synchronized VCB-owned FCB identities and Windows share ledger. This field drops before
    /// the mounted volume because every FCB retains that volume as its data-plane owner.
    pub(super) file_control_blocks: FileControlBlockLedger,
    /// Actor-owned volume lifecycle and direct-open share accounting.
    pub(super) volume_control: VolumeControlPlane,
    /// Mounted profile, committed epochs, and mutation coordination.
    pub(super) runtime: VolumeRuntime,
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
    handles: VolumeHandleLedger,
    /// Direct-volume FILE_OBJECT allocations retained until Close.
    volume_file_objects: u32,
}

impl VolumeControlPlane {
    /// Creates the control plane for a newly mounted volume.
    pub(super) const fn mounted() -> Self {
        Self {
            state: MountedVolumeState::Mounted,
            handles: VolumeHandleLedger::new(),
            volume_file_objects: 0,
        }
    }
}

/// Mounted-volume state serialized by the device actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MountedVolumeState {
    /// Namespace and direct-volume opens are admitted.
    Mounted,
    /// Namespace admission is closed while one lock request drains durable work.
    Locking {
        /// Direct-volume FILE_OBJECT that owns this reversible lock attempt.
        owner: KernelFileObject,
    },
    /// Only the FILE_OBJECT that locked the volume may issue ordinary operations.
    Locked {
        /// Direct-volume FILE_OBJECT that owns the lock.
        owner: KernelFileObject,
    },
    /// New mutations are rejected while prior work drains and the recovery marker is cleared.
    Closing {
        /// Terminal state selected by the request that began the one-way close.
        terminal: CleanCloseTerminal,
        /// Prior volume-lock owner, if any, retained for cleanup semantics.
        lock_owner: Option<KernelFileObject>,
    },
    /// Filesystem operations are rejected after a forced logical dismount.
    Dismounted {
        /// Prior lock owner allowed to release the lock after dismount.
        lock_owner: Option<KernelFileObject>,
    },
    /// System shutdown observed a fully durable clean marker.
    ShutdownComplete {
        /// Prior volume-lock owner retained only for late cleanup accounting.
        lock_owner: Option<KernelFileObject>,
    },
    /// Last FILE_OBJECT closed and the preallocated retirement work item owns teardown.
    Retiring,
}

/// Terminal publication selected before the volume enters one-way `Closing`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CleanCloseTerminal {
    /// Publish logical dismount and begin ordinary mounted-device retirement rules.
    Dismount,
    /// Publish shutdown completion without claiming physical device retirement.
    Shutdown,
}

impl MountedVolumeState {
    /// Closes namespace admission before the lock's durability barrier can suspend.
    /// # Errors
    ///
    /// Returns access denied when already locked or volume dismounted after terminal dismount.
    pub(super) fn begin_lock(self, owner: KernelFileObject) -> DriverResult<Self> {
        match self {
            Self::Mounted => Ok(Self::Locking { owner }),
            Self::Locking { .. } | Self::Locked { .. } => Err(DriverError::AccessDenied),
            Self::Closing { .. }
            | Self::Dismounted { .. }
            | Self::ShutdownComplete { .. }
            | Self::Retiring => Err(DriverError::VolumeDismounted),
        }
    }

    /// Publishes a clean lock only for the FILE_OBJECT that began its barrier.
    pub(super) fn finish_lock(self, owner: KernelFileObject) -> Option<Self> {
        match self {
            Self::Locking { owner: current } if current == owner => Some(Self::Locked { owner }),
            _ => None,
        }
    }

    /// Reopens namespace admission after an uncommitted lock attempt fails or is cancelled.
    pub(super) fn abort_lock(self, owner: KernelFileObject) -> Option<Self> {
        match self {
            Self::Locking { owner: current } if current == owner => Some(Self::Mounted),
            _ => None,
        }
    }

    /// Selects the state reached when one FILE_OBJECT releases its volume lock.
    /// # Errors
    ///
    /// Returns not locked when `owner` does not own the current lock.
    pub(super) fn unlock(self, owner: KernelFileObject) -> DriverResult<Self> {
        match self {
            Self::Locked {
                owner: current_owner,
            } if current_owner == owner => Ok(Self::Mounted),
            Self::Dismounted {
                lock_owner: Some(current_owner),
            } if current_owner == owner => Ok(Self::Dismounted { lock_owner: None }),
            Self::Closing {
                terminal,
                lock_owner: Some(current_owner),
            } if current_owner == owner => Ok(Self::Closing {
                terminal,
                lock_owner: None,
            }),
            Self::ShutdownComplete {
                lock_owner: Some(current_owner),
            } if current_owner == owner => Ok(Self::ShutdownComplete { lock_owner: None }),
            Self::Mounted
            | Self::Locking { .. }
            | Self::Locked { .. }
            | Self::Closing { .. }
            | Self::Dismounted { .. }
            | Self::ShutdownComplete { .. }
            | Self::Retiring => Err(DriverError::NotLocked),
        }
    }

    /// Selects the one-way closing state reached by a forced dismount request.
    /// # Errors
    ///
    /// Returns access denied for another lock owner or volume dismounted after terminal dismount.
    pub(super) fn begin_dismount(self, owner: KernelFileObject) -> DriverResult<Self> {
        match self {
            Self::Mounted => Ok(Self::Closing {
                terminal: CleanCloseTerminal::Dismount,
                lock_owner: None,
            }),
            Self::Locked {
                owner: current_owner,
            } if current_owner == owner => Ok(Self::Closing {
                terminal: CleanCloseTerminal::Dismount,
                lock_owner: Some(owner),
            }),
            Self::Locking { .. } | Self::Locked { .. } => Err(DriverError::AccessDenied),
            Self::Closing { .. }
            | Self::Dismounted { .. }
            | Self::ShutdownComplete { .. }
            | Self::Retiring => Err(DriverError::VolumeDismounted),
        }
    }

    /// Selects the one-way closing state reached by system shutdown.
    /// # Errors
    ///
    /// Returns volume dismounted once any terminal close has already begun.
    fn begin_shutdown(self) -> DriverResult<Self> {
        match self {
            Self::Mounted => Ok(Self::Closing {
                terminal: CleanCloseTerminal::Shutdown,
                lock_owner: None,
            }),
            Self::Locked { owner } => Ok(Self::Closing {
                terminal: CleanCloseTerminal::Shutdown,
                lock_owner: Some(owner),
            }),
            Self::Locking { .. } => Err(DriverError::AccessDenied),
            Self::Closing { .. }
            | Self::Dismounted { .. }
            | Self::ShutdownComplete { .. }
            | Self::Retiring => Err(DriverError::VolumeDismounted),
        }
    }

    /// Publishes the selected terminal state only after clean-close durability succeeds.
    pub(super) fn finish_close(self, expected: CleanCloseTerminal) -> Option<Self> {
        let Self::Closing {
            terminal,
            lock_owner,
        } = self
        else {
            return None;
        };
        if terminal != expected {
            return None;
        }
        Some(match terminal {
            CleanCloseTerminal::Dismount => Self::Dismounted { lock_owner },
            CleanCloseTerminal::Shutdown => Self::ShutdownComplete { lock_owner },
        })
    }

    /// Applies implicit lock release when the owning FILE_OBJECT is cleaned up.
    pub(super) fn cleanup(self, owner: KernelFileObject) -> (Self, VolumeHandleCleanup) {
        match self {
            Self::Locking { owner: current } if current == owner => {
                (Self::Mounted, VolumeHandleCleanup::Released)
            }
            Self::Locked {
                owner: current_owner,
            } if current_owner == owner => (Self::Mounted, VolumeHandleCleanup::Unlocked),
            Self::Dismounted {
                lock_owner: Some(current_owner),
            } if current_owner == owner => (
                Self::Dismounted { lock_owner: None },
                VolumeHandleCleanup::Unlocked,
            ),
            Self::Closing {
                terminal,
                lock_owner: Some(current_owner),
            } if current_owner == owner => (
                Self::Closing {
                    terminal,
                    lock_owner: None,
                },
                VolumeHandleCleanup::Unlocked,
            ),
            Self::ShutdownComplete {
                lock_owner: Some(current_owner),
            } if current_owner == owner => (
                Self::ShutdownComplete { lock_owner: None },
                VolumeHandleCleanup::Unlocked,
            ),
            Self::Mounted
            | Self::Locking { .. }
            | Self::Locked { .. }
            | Self::Closing { .. }
            | Self::Dismounted { .. }
            | Self::ShutdownComplete { .. } => (self, VolumeHandleCleanup::Released),
            Self::Retiring => KernelWideInconsistency::mounted_volume_state_corruption().bugcheck(),
        }
    }

    /// Selects the one physical-retirement transition after all FILE_OBJECTs close.
    pub(super) fn retire_if_unreferenced(
        self,
        namespace_empty: bool,
        volume_file_objects: u32,
    ) -> (Self, VolumeRetirement) {
        match self {
            Self::Dismounted { lock_owner: None }
                if namespace_empty && volume_file_objects == 0 =>
            {
                (Self::Retiring, VolumeRetirement::Start)
            }
            Self::Retiring => KernelWideInconsistency::mounted_volume_state_corruption().bugcheck(),
            Self::Mounted
            | Self::Locking { .. }
            | Self::Locked { .. }
            | Self::Closing { .. }
            | Self::Dismounted { .. }
            | Self::ShutdownComplete { .. } => (self, VolumeRetirement::Retained),
        }
    }

    /// Reports whether this volume remains logically mounted.
    /// # Errors
    ///
    /// Returns volume dismounted after the terminal transition.
    pub(super) fn ensure_mounted(self) -> DriverResult<()> {
        match self {
            Self::Mounted | Self::Locking { .. } | Self::Locked { .. } | Self::Closing { .. } => {
                Ok(())
            }
            Self::Dismounted { .. } | Self::ShutdownComplete { .. } | Self::Retiring => {
                Err(DriverError::VolumeDismounted)
            }
        }
    }

    /// Applies create/open admission policy.
    /// # Errors
    ///
    /// Returns access denied while locked or volume dismounted after terminal dismount.
    pub(super) fn authorize_create(self) -> DriverResult<()> {
        match self {
            Self::Mounted => Ok(()),
            Self::Locking { .. } | Self::Locked { .. } => Err(DriverError::AccessDenied),
            Self::Closing { .. } => Err(DriverError::AccessDenied),
            Self::Dismounted { .. } | Self::ShutdownComplete { .. } | Self::Retiring => {
                Err(DriverError::VolumeDismounted)
            }
        }
    }

    /// Applies ordinary handle-operation policy.
    /// # Errors
    ///
    /// Returns access denied for a competing lock owner or volume dismounted after dismount.
    pub(super) fn authorize_handle(self, file_object: KernelFileObject) -> DriverResult<()> {
        match self {
            Self::Mounted => Ok(()),
            Self::Locked { owner } if owner == file_object => Ok(()),
            Self::Locking { .. } | Self::Locked { .. } => Err(DriverError::AccessDenied),
            Self::Closing { .. } => Err(DriverError::AccessDenied),
            Self::Dismounted { .. } | Self::ShutdownComplete { .. } | Self::Retiring => {
                Err(DriverError::VolumeDismounted)
            }
        }
    }

    /// Requires the lock/dismount lifecycle authority for one raw data operation.
    /// # Errors
    ///
    /// Returns access denied unless this FILE_OBJECT owns the clean lock, and requires terminal
    /// logical dismount for writes.
    pub(super) fn authorize_raw(
        self,
        owner: KernelFileObject,
        kind: RawVolumeOperationKind,
    ) -> DriverResult<()> {
        match (self, kind) {
            (Self::Locked { owner: current }, RawVolumeOperationKind::Read) if current == owner => {
                Ok(())
            }
            (
                Self::Dismounted {
                    lock_owner: Some(current),
                },
                RawVolumeOperationKind::Read | RawVolumeOperationKind::Write,
            ) if current == owner => Ok(()),
            (
                Self::Mounted
                | Self::Locking { .. }
                | Self::Locked { .. }
                | Self::Closing { .. }
                | Self::Dismounted { .. }
                | Self::ShutdownComplete { .. },
                _,
            ) => Err(DriverError::AccessDenied),
            (Self::Retiring, _) => Err(DriverError::VolumeDismounted),
        }
    }

    /// Admits a handle-local raw extent change without granting data authority.
    /// # Errors
    ///
    /// Returns access denied for a competing owner, or volume dismounted once the raw owner is
    /// no longer retained. The lock owner may expand its bound after logical dismount.
    pub(super) fn authorize_raw_extent_change(self, owner: KernelFileObject) -> DriverResult<()> {
        match self {
            Self::Mounted => Ok(()),
            Self::Locked { owner: current }
            | Self::Dismounted {
                lock_owner: Some(current),
            } if current == owner => Ok(()),
            Self::Locking { .. } | Self::Locked { .. } | Self::Closing { .. } => {
                Err(DriverError::AccessDenied)
            }
            Self::Dismounted { .. } | Self::ShutdownComplete { .. } | Self::Retiring => {
                Err(DriverError::VolumeDismounted)
            }
        }
    }
}

/// Direct-volume FILE_OBJECT share claims owned by the mounted-device actor.
struct VolumeHandleLedger {
    /// I/O Manager share-access accounting for the mounted volume identity.
    share_access: SHARE_ACCESS,
}

impl VolumeHandleLedger {
    /// Creates empty direct-volume share accounting.
    const fn new() -> Self {
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
        }
    }

    /// Records one direct-volume FILE_OBJECT share claim.
    /// # Errors
    ///
    /// Returns an error when an existing direct-volume handle conflicts with the requested access.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn open(
        &mut self,
        file_object: KernelFileObject,
        desired_access: GrantedAccess,
        share_access: ShareAccess,
    ) -> DriverResult<()> {
        let status = unsafe {
            // SAFETY: The mounted-device actor exclusively owns this SHARE_ACCESS record and this
            // successful check records the returned FILE_OBJECT's exact claim.
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

    /// Removes one direct-volume FILE_OBJECT share claim at cleanup or canceled-open close.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn cleanup(&mut self, file_object: KernelFileObject) {
        unsafe {
            // SAFETY: A successful volume open recorded this FILE_OBJECT exactly once, and the
            // handle lifecycle selects one terminal share-removal transition.
            ffi::IoRemoveShareAccess(
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.share_access),
            );
        }
    }

    /// Returns the number of direct-volume handles whose share claims remain active.
    const fn active_handle_count(&self) -> u32 {
        self.share_access.OpenCount
    }
}

impl fmt::Debug for VolumeHandleLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VolumeHandleLedger(..)")
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
    /// Heap-stable VCB whose unique actor access is projected by [`Self::with_access`].
    volume: Pin<Box<VolumeControlBlock>>,
}

impl MountedVolumeBinding {
    /// Takes sole reactor ownership of a completed mounted VCB.
    pub(crate) const fn new(volume: Pin<Box<VolumeControlBlock>>) -> Self {
        Self { volume }
    }

    /// Runs one non-suspending reactor transition with lifetime-bound mounted access.
    #[expect(
        unsafe_code,
        reason = "the sole reactor borrow mutates VCB fields without relocating the pinned VCB"
    )]
    pub(crate) fn with_access<R>(
        &mut self,
        transition: impl FnOnce(&mut MountedVolumeAccess<'_>) -> R,
    ) -> R {
        let volume = unsafe {
            // SAFETY: The actor has unique access and this borrow does not move the VCB or any
            // address-sensitive field before it ends.
            self.volume.as_mut().get_unchecked_mut()
        };
        transition(&mut MountedVolumeAccess { volume })
    }

    /// Returns the VCB to terminal mounted-device teardown after reactor drain.
    pub(crate) fn into_volume(self) -> Pin<Box<VolumeControlBlock>> {
        self.volume
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The binding moves once into the device reactor. Only that reactor's sole actor thread
// calls `with_access`, and teardown recovers the Box only after the actor and completions drain.
unsafe impl Send for MountedVolumeBinding {}

/// Lifetime-bound mounted VCB access available only inside one reactor callback.
pub(crate) struct MountedVolumeAccess<'volume> {
    /// Unique VCB borrow that cannot cross a scheduler transition or lower submission.
    volume: &'volume mut VolumeControlBlock,
}

impl MountedVolumeAccess<'_> {
    /// Returns the write-only operational event capability for this mounted volume.
    pub(crate) const fn operational_trace(&self) -> OperationalTrace {
        self.volume.trace
    }
}

/// VPB-visible effect produced when a direct-volume handle is cleaned up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeHandleCleanup {
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
    /// Publication variant that owns the expected pre-state and authorized post-state.
    kind: PreparedVolumeStateTransitionKind,
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
    /// Terminal publication authorized only by a completed clean-close protocol.
    CleanClose {
        /// Terminal selected when the current `Closing` state was entered.
        terminal: CleanCloseTerminal,
    },
}

impl PreparedVolumeStateTransition {
    /// Whether this transition crossed the one-way closing boundary before suspension.
    pub(crate) const fn is_clean_close(&self) -> bool {
        matches!(
            self.kind,
            PreparedVolumeStateTransitionKind::CleanClose { .. }
        )
    }
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
    pub(crate) fn file_object_owner(&mut self) -> NonNull<VolumeControlBlock> {
        NonNull::from(&mut *self.volume)
    }

    /// Checks that a lifetime record belongs to this device-local mounted binding.
    pub(crate) fn owns_volume(&self, candidate: NonNull<VolumeControlBlock>) -> bool {
        NonNull::from(&*self.volume) == candidate
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
        let control = &mut self.volume.volume_control;
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
        let control = &mut self.volume.volume_control;
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
            let control = &mut self.volume.volume_control;
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
        let namespace_empty = self.volume.file_control_blocks.is_empty();
        let control = &mut self.volume.volume_control;
        let (state, retirement) = control
            .state
            .retire_if_unreferenced(namespace_empty, control.volume_file_objects);
        control.state = state;
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
        let next_state = self.volume.volume_control.state.begin_lock(owner)?;
        if self.volume.volume_control.handles.active_handle_count() != 1 {
            return Err(DriverError::AccessDenied);
        }
        let cache_drain = self
            .volume
            .file_control_blocks
            .prepare_volume_lock_cache_drain()?;
        self.volume.volume_control.state = next_state;
        Ok(PreparedVolumeLock {
            transition: PreparedVolumeStateTransition {
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
        let control = &mut self.volume.volume_control;
        control.state = control.state.unlock(owner)?;
        Ok(())
    }

    /// Prepares terminal logical dismount publication behind a clean-journal barrier.
    /// # Errors
    ///
    /// Returns access denied when another FILE_OBJECT owns the volume lock, volume dismounted for
    /// a repeated request.
    pub(crate) fn prepare_dismount_volume(
        &mut self,
        owner: KernelFileObject,
    ) -> DriverResult<PreparedVolumeStateTransition> {
        let control = &mut self.volume.volume_control;
        control.state = control.state.begin_dismount(owner)?;
        Ok(PreparedVolumeStateTransition {
            kind: PreparedVolumeStateTransitionKind::CleanClose {
                terminal: CleanCloseTerminal::Dismount,
            },
        })
    }

    /// Enters one-way shutdown closing before any drain or durability suspension.
    /// # Errors
    ///
    /// Returns volume dismounted when another terminal close already began.
    pub(crate) fn prepare_shutdown(&mut self) -> DriverResult<PreparedVolumeStateTransition> {
        let control = &mut self.volume.volume_control;
        control.state = control.state.begin_shutdown()?;
        Ok(PreparedVolumeStateTransition {
            kind: PreparedVolumeStateTransitionKind::CleanClose {
                terminal: CleanCloseTerminal::Shutdown,
            },
        })
    }

    /// Publishes one previously validated lifecycle transition after its barrier succeeds.
    pub(crate) fn publish_volume_state_transition(
        &mut self,
        transition: PreparedVolumeStateTransition,
    ) {
        let control = &mut self.volume.volume_control;
        match transition.kind {
            PreparedVolumeStateTransitionKind::Lock { owner } => {
                control.state = control.state.finish_lock(owner).unwrap_or_else(|| {
                    KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
                });
            }
            PreparedVolumeStateTransitionKind::CleanClose { terminal } => {
                control.state = control.state.finish_close(terminal).unwrap_or_else(|| {
                    KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
                });
            }
        }
    }

    /// Consumes a failed lifecycle publication while preserving one-way clean-close semantics.
    pub(crate) fn fail_volume_state_transition(
        &mut self,
        transition: PreparedVolumeStateTransition,
    ) {
        if let PreparedVolumeStateTransitionKind::Lock { owner } = transition.kind {
            let control = &mut self.volume.volume_control;
            control.state = control.state.abort_lock(owner).unwrap_or_else(|| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
        }
    }

    /// Reports whether the volume remains logically mounted.
    /// # Errors
    ///
    /// Returns volume dismounted after a successful forced dismount.
    pub(crate) fn ensure_mounted(&self) -> DriverResult<()> {
        self.volume.volume_control.state.ensure_mounted()
    }

    /// Authorizes creation of a new FILE_OBJECT against the current volume state.
    /// # Errors
    ///
    /// Returns access denied while locked or volume dismounted after terminal dismount.
    pub(crate) fn authorize_create(&self) -> DriverResult<()> {
        self.volume.volume_control.state.authorize_create()
    }

    /// Authorizes one ordinary handle operation against the current volume state.
    /// # Errors
    ///
    /// Returns access denied when another handle owns the lock, or volume dismounted after
    /// terminal logical dismount.
    pub(crate) fn authorize_handle(&self, file_object: KernelFileObject) -> DriverResult<()> {
        self.volume
            .volume_control
            .state
            .authorize_handle(file_object)
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
        self.volume
            .file_control_blocks
            .acquire_paging_stream_lease(file_object, NonNull::from(&*self.volume))
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
            .acquire_oplock_stream_lease(file_object, NonNull::from(&*self.volume))
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
            .acquire_oplock_mutation(file_object, NonNull::from(&*self.volume))
    }

    /// Reserves one parent-directory node and retains its resident stream for an FsRtl check.
    /// # Errors
    ///
    /// Returns a finite reservation or deferred-lease failure before any FsRtl call. The optional
    /// check lease is absent only when no parent FCB is currently resident; the node reservation
    /// remains active in either case.
    pub(crate) fn acquire_parent_oplock_mutation(
        &self,
        parent: ext4_core::DirectoryNodeId,
    ) -> DriverResult<(OplockMutationLease, Option<OplockStreamLease>)> {
        self.volume
            .file_control_blocks
            .acquire_parent_oplock_mutation(parent)
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

    /// Acquires the mutation grant barrier and check lease for a provisional create claim.
    /// # Errors
    ///
    /// Returns an ownership or finite-counter failure before the break check begins.
    pub(crate) fn acquire_claimed_oplock_mutation(
        &self,
        fcb: NonNull<FileControlBlock>,
    ) -> DriverResult<(OplockMutationLease, OplockStreamLease)> {
        self.volume
            .file_control_blocks
            .acquire_claimed_oplock_mutation(fcb)
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
            .acquire_file_object_cache_lease(file_object, NonNull::from(&*self.volume))
    }

    /// Preallocates native gates for every live regular-file cache-map size changed by one mutation.
    /// # Errors
    ///
    /// Returns the exact allocation, stream-retention, or native size-snapshot failure before the
    /// first Cache Manager or Memory Manager call is submitted.
    pub(crate) fn prepare_stream_size_changes(
        &self,
        updates: &PreparedStreamMetadataPublications,
        deletion: Option<NodeId>,
    ) -> DriverResult<StreamSizeChangePlan> {
        self.volume
            .file_control_blocks
            .prepare_stream_size_changes(updates, deletion)
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
    ) -> DriverResult<bool> {
        self.volume
            .file_control_blocks
            .prepared_stream_size_changes_match(updates, prepared, deletion)
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

    /// Produces one bounded raw transfer authority from lifecycle, access, and extent state.
    /// # Errors
    ///
    /// Returns access denied unless the handle owns the clean lock and retained the matching data
    /// right; writes additionally require completed logical dismount.
    pub(crate) fn authorize_raw_volume_io(
        &self,
        target: RawVolumeTarget,
        kind: RawVolumeOperationKind,
    ) -> DriverResult<RawVolumeIoPermit> {
        if !self.owns_volume(target.volume()) {
            return Err(DriverError::InvalidDeviceRequest);
        }
        self.volume
            .volume_control
            .state
            .authorize_raw(target.owner(), kind)?;
        let (access, extent) = target.authority();
        access.require(kind)?;
        if kind == RawVolumeOperationKind::Write {
            target.ensure_write_retryable()?;
        }
        let route = self.storage_route();
        let bound = match extent {
            RawExtentPolicy::FilesystemExtent => self.mounted_profile().filesystem_length(),
            RawExtentPolicy::PartitionExtent => route.filesystem_device_length(),
        };
        Ok(RawVolumeIoPermit {
            bound,
            sector_size: route.filesystem_sector_size(),
        })
    }

    /// Authorizes changing only this direct-volume handle's selected raw bound.
    /// # Errors
    ///
    /// Returns an ownership or lifecycle error when the handle cannot control its raw extent.
    pub(crate) fn authorize_raw_extent_change(&self, owner: KernelFileObject) -> DriverResult<()> {
        self.volume
            .volume_control
            .state
            .authorize_raw_extent_change(owner)
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
        let state = self.volume.volume_control.state;
        if matches!(state, MountedVolumeState::Dismounted { .. }) {
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
        self.volume.runtime.authorize_durability()
    }

    /// Rejects namespace traversal through an inode that is delete-pending.
    /// # Errors
    ///
    /// Returns delete-pending while an open FCB owns a deferred deletion for `node`.
    pub(crate) fn ensure_node_openable(&self, node: NodeId) -> DriverResult<()> {
        let ledger = &self.volume.file_control_blocks;
        if ledger.node_delete_pending(node) {
            Err(DriverError::DeletePending)
        } else {
            Ok(())
        }
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

    /// Publishes successful removal of the exact FCB-owned delete target.
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
        self.volume.runtime.profile()
    }

    /// Validated lower-device route for one core storage request.
    pub(crate) fn storage_route(&self) -> MountedStorageRoute {
        self.volume.runtime.storage()
    }

    /// Allocates operation-local cryptographic state from the mounted providers.
    /// # Errors
    ///
    /// Returns an error when CNG operation state cannot be allocated or initialized.
    pub(crate) fn new_crypto_operation(&self) -> DriverResult<CngOperation> {
        self.volume.runtime.crypto().try_new_operation()
    }

    /// Acquires one immutable committed epoch lease.
    /// # Errors
    ///
    /// Returns an error when reads are no longer reliable or the bounded lease registry is full.
    pub(crate) fn acquire_epoch(&mut self) -> DriverResult<EpochLease> {
        self.volume.runtime.acquire_epoch()
    }

    /// Allocates one mutation ticket and active-mutation lifetime lease.
    /// # Errors
    ///
    /// Returns an error when mutation is no longer authorized or bounded accounting overflows.
    pub(crate) fn admit_mutation(&mut self) -> DriverResult<(u64, MutationActivityLease)> {
        self.volume.runtime.admit_mutation()
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
        pass.resolve(ticket, self.volume.runtime.coordinator())
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
        resolved.reserve(self.volume.runtime.coordinator(), intent)
    }

    /// Prepares a commit from the coordinator and current immutable epoch authorities.
    /// # Errors
    ///
    /// Returns a core mutation error when commit preparation cannot consume the supplied grant.
    pub(crate) fn prepare_mutation_commit(
        &self,
        reserved: ReservedMutation,
        commit: CommitLease,
    ) -> Result<CommitReadyMutation, ext4_core::Error> {
        reserved.prepare_commit(
            self.volume.runtime.coordinator(),
            self.volume.runtime.current_epoch(),
            commit,
        )
    }

    /// Reserves both immutable epoch publication slots before the first lower write.
    /// # Errors
    ///
    /// Returns an error when mutation is no longer authorized or stable storage cannot be
    /// allocated.
    pub(crate) fn reserve_epoch_publication(&mut self) -> DriverResult<EpochPublicationSlots> {
        self.volume.runtime.reserve_epoch_publication()
    }

    /// Grants the serialized commit lane when its runtime preconditions are satisfied.
    ///
    /// # Errors
    ///
    /// Returns the volume failure without confusing terminal rejection with a pending grant.
    #[cfg(not(test))]
    pub(crate) fn acquire_commit(&mut self, ticket: u64) -> DriverResult<Option<CommitLease>> {
        self.volume.runtime.acquire_commit(ticket)
    }

    /// Returns an unused pre-write commit grant to the runtime.
    #[cfg(not(test))]
    pub(crate) fn abandon_commit(&mut self, ticket: u64) {
        self.volume.runtime.abandon_commit(ticket);
    }

    /// Grants the short durable-visibility publication lane.
    #[cfg(not(test))]
    pub(crate) fn try_grant_visibility(&mut self, ticket: u64) -> Option<VisibilityLease> {
        self.volume.runtime.try_grant_visibility(ticket)
    }

    /// Grants the detached checkpoint lane for one visible epoch.
    #[cfg(not(test))]
    pub(crate) fn try_grant_checkpoint(
        &mut self,
        epoch: ext4_core::EpochSequence,
    ) -> Option<ext4_core::CheckpointLease> {
        self.volume.runtime.try_grant_checkpoint(epoch)
    }

    /// Reports whether no mutation or checkpoint owns journal space.
    #[cfg(not(test))]
    pub(crate) fn journal_is_clean(&self) -> bool {
        self.volume.runtime.journal_is_clean()
    }

    /// Publishes the durable epoch and its prevalidated stream metadata in one reactor turn.
    ///
    /// The core durability/visibility capabilities are required here, so a caller cannot install
    /// prepared stream metadata through the mounted-volume boundary before the commit is durable.
    #[inline(never)]
    pub(crate) fn publish_durable(
        &mut self,
        mutation: DurableMutation,
        visibility: VisibilityLease,
        durable_slot: EpochPublicationSlot,
        checkpoint_slot: EpochPublicationSlot,
        stream_metadata: PreparedStreamMetadataPublications,
    ) -> DurablePublicationOutcome {
        let checkpoint = self.volume.runtime.publish_durable(
            mutation,
            visibility,
            durable_slot,
            checkpoint_slot,
        );
        let epoch = checkpoint.epoch();
        let stream_projection = self
            .volume
            .file_control_blocks
            .publish_stream_metadata(stream_metadata, epoch);
        DurablePublicationOutcome {
            checkpoint,
            stream_projection,
        }
    }

    /// Publishes an overlay-free checkpoint and releases journal space.
    pub(crate) fn publish_checkpoint(
        &mut self,
        durability: CleanJournalDurability,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
    ) {
        self.volume
            .runtime
            .publish_checkpoint(durability, publication, epoch);
    }

    /// Records a confirmed durable abort as a read-only transition.
    pub(crate) fn record_durable_abort(&mut self) {
        self.volume.runtime.record_durable_abort();
    }

    /// Records an unknown write or flush outcome requiring replay.
    pub(crate) fn record_durability_unknown(&mut self) {
        self.volume.runtime.record_durability_unknown();
    }

    /// Records that committed reads can no longer be trusted.
    pub(crate) fn record_read_unreliable(&mut self) {
        self.volume.runtime.record_read_unreliable();
    }

    /// Records an exact post-commit Cc/MM publication failure and its aggregate stream progress.
    pub(crate) fn record_publication_failure(
        &mut self,
        status: wdk_sys::NTSTATUS,
        published_streams: usize,
        unexamined_updates: usize,
    ) {
        self.volume.runtime.record_publication_failure(
            status,
            published_streams,
            unexamined_updates,
        );
    }

    /// Records an exact Cache Manager dirty-page writeback failure.
    pub(crate) fn record_cache_writeback_failure(&mut self, status: wdk_sys::NTSTATUS) {
        self.volume.runtime.record_cache_writeback_failure(status);
    }

    /// Current committed volume identity.
    pub(crate) fn volume_identity(&self) -> VolumeIdentity {
        self.volume.runtime.identity()
    }

    /// Current committed allocation geometry.
    pub(crate) fn volume_geometry(&self) -> VolumeGeometry {
        self.volume.runtime.current_epoch().geometry()
    }

    /// Returns the committed epoch that owns non-suspending metadata observations.
    pub(crate) fn current_epoch_sequence(&self) -> ext4_core::EpochSequence {
        self.volume.runtime.current_epoch().sequence()
    }

    /// Checks whether resolve still observes the epoch paired with the current coordinator.
    ///
    /// Unlike pure snapshot reads, mutations must not pair old inode/allocation observations with
    /// newer resource versions. Creates can also attach a FILE_OBJECT without mutation intents.
    /// Both therefore restart after an epoch change before the next non-suspending resolve pass.
    pub(crate) fn is_current_epoch(&self, epoch: &EpochLease) -> bool {
        epoch.epoch().sequence() == self.volume.runtime.current_epoch().sequence()
    }

    /// Current committed fscrypt key presence.
    pub(crate) fn fscrypt_key_presence(
        &self,
        identifier: FscryptKeyIdentifier,
    ) -> FscryptKeyPresence {
        self.volume.runtime.fscrypt_key_presence(identifier)
    }

    /// Stages a missing child in the current ephemeral mutation resolve pass.
    /// # Errors
    ///
    /// Returns an error when the parent cannot be loaded or child creation cannot be staged.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn begin_child_creation(
        &self,
        transaction: &mut MutationResolvePass<'_, '_, '_>,
        parent: DirectoryNodeId,
        name: &Ext4Name,
        target: ChildCreationTarget,
    ) -> DriverResult<PendingChildCreation> {
        let owner = MountedVolumeRef::new(NonNull::from(&*self.volume));
        let file_control_blocks = unsafe {
            // SAFETY: `owner` stays live for the lease lifetime, so projecting the disjoint ledger
            // field produces a stable raw address.
            core::ptr::addr_of!((*owner.as_non_null().as_ptr()).file_control_blocks)
        };
        let file_control_blocks = unsafe {
            // SAFETY: The projected ledger is independently synchronized and VCB-owned.
            &*file_control_blocks
        };
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
