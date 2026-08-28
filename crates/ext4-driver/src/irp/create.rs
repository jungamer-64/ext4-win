//! Create-request access, sharing, disposition, and option contracts.

use super::*;

/// Decoded create/open parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateParameters {
    /// Desired access mask requested by the opener.
    desired_access: DesiredAccess,
    /// Share-access bits requested by the opener.
    share_access: ShareAccess,
    /// Requested create disposition.
    disposition: CreateDisposition,
    /// File-vs-directory create/open requirement.
    target_requirement: CreateTargetRequirement,
    /// Write completion durability requested by create options.
    write_commitment: WriteCommitment,
    /// Data transfer buffering requested by create options.
    transfer_buffering: CreateTransferBuffering,
    /// Oplock break or reservation behavior requested by create options.
    oplock_policy: OplockCreatePolicy,
    /// Per-handle synchronous I/O mode requested by create options.
    synchronization_mode: CreateSynchronizationMode,
    /// Reparse-point opening mode requested by create options.
    reparse_point_mode: CreateReparsePointMode,
    /// Interpretation of `FILE_OBJECT::FileName`.
    name_interpretation: CreateNameInterpretation,
    /// Namespace deletion requested for the returned handle.
    deletion: CreateDeletion,
    /// Extended-attribute input length supplied with create.
    ea_length: IrpBufferLength,
    /// I/O-stack access-check policy selected for this create.
    access_check: CreateAccessCheck,
    /// Windows-visible path-name comparison policy.
    name_match: WindowsNameMatch,
    /// Whether the caller requests the named object or its containing directory.
    target_selection: CreateTargetSelection,
    /// Create flags whose semantics this filesystem does not implement.
    unsupported_flags: UnsupportedCreateFlags,
}

impl CreateParameters {
    /// Decodes raw WDK create parameters at the IRP boundary.
    /// # Errors
    ///
    /// Returns an error when share access, create disposition, or create options contain unsupported
    /// values.
    pub(super) fn decode(
        desired_access: wdk_sys::ACCESS_MASK,
        options: wdk_sys::ULONG,
        share_access: wdk_sys::USHORT,
        ea_length: IrpBufferLength,
        stack_flags: wdk_sys::UCHAR,
    ) -> Result<Self, DriverError> {
        let desired_access = DesiredAccess::from_raw(desired_access);
        let share_access = ShareAccess::from_raw(share_access)?;
        let disposition = CreateDisposition::from_options(options)?;
        let create_options = CreateOptions::decode(options, desired_access)?;
        let target_requirement = create_options.target_requirement();
        disposition.validate_target_requirement(target_requirement)?;
        Ok(Self {
            desired_access,
            share_access,
            disposition,
            target_requirement,
            write_commitment: create_options.write_commitment(),
            transfer_buffering: create_options.transfer_buffering(),
            oplock_policy: OplockCreatePolicy::decode(options, desired_access, share_access)?,
            synchronization_mode: create_options.synchronization_mode(),
            reparse_point_mode: create_options.reparse_point_mode(),
            name_interpretation: create_options.name_interpretation(),
            deletion: create_options.deletion(),
            ea_length,
            access_check: CreateAccessCheck::from_stack_flags(stack_flags),
            name_match: if stack_flag(stack_flags, wdk_sys::SL_CASE_SENSITIVE) {
                WindowsNameMatch::Exact
            } else {
                WindowsNameMatch::CaseInsensitive
            },
            target_selection: CreateTargetSelection::from_stack_flags(stack_flags),
            unsupported_flags: UnsupportedCreateFlags::from_stack_flags(stack_flags),
        })
    }

    /// Returns the desired access mask.
    pub(crate) const fn desired_access(self) -> DesiredAccess {
        self.desired_access
    }

    /// Returns virtual access whose sharing must permit this existing-object operation.
    pub(crate) const fn existing_operation_required_access(self) -> wdk_sys::ACCESS_MASK {
        match self.disposition {
            CreateDisposition::Overwrite | CreateDisposition::OverwriteIf => {
                wdk_sys::FILE_WRITE_DATA | wdk_sys::FILE_WRITE_EA | wdk_sys::FILE_WRITE_ATTRIBUTES
            }
            CreateDisposition::Supersede => {
                wdk_sys::DELETE | wdk_sys::FILE_WRITE_EA | wdk_sys::FILE_WRITE_ATTRIBUTES
            }
            CreateDisposition::Open | CreateDisposition::Create | CreateDisposition::OpenIf => 0,
        }
    }

    /// Returns the share access.
    pub(crate) const fn share_access(self) -> ShareAccess {
        self.share_access
    }

    /// Returns the create disposition.
    pub(crate) const fn disposition(self) -> CreateDisposition {
        self.disposition
    }

    /// Returns the target kind requirement.
    pub(crate) const fn target_requirement(self) -> CreateTargetRequirement {
        self.target_requirement
    }

    /// Returns write completion durability requested by create options.
    pub(crate) const fn write_commitment(self) -> WriteCommitment {
        self.write_commitment
    }

    /// Returns data transfer buffering requested at create/open.
    pub(crate) const fn transfer_buffering(self) -> CreateTransferBuffering {
        self.transfer_buffering
    }

    /// Returns create-time oplock break or reservation behavior.
    pub(crate) const fn oplock_policy(self) -> OplockCreatePolicy {
        self.oplock_policy
    }

    /// Returns synchronous I/O mode requested at create/open.
    pub(crate) const fn synchronization_mode(self) -> CreateSynchronizationMode {
        self.synchronization_mode
    }

    /// Returns reparse-point opening mode requested at create/open.
    pub(crate) const fn reparse_point_mode(self) -> CreateReparsePointMode {
        self.reparse_point_mode
    }

    /// Returns how the create FILE_OBJECT name must be interpreted.
    pub(crate) const fn name_interpretation(self) -> CreateNameInterpretation {
        self.name_interpretation
    }

    /// Returns namespace deletion requested for the returned handle.
    pub(crate) const fn deletion(self) -> CreateDeletion {
        self.deletion
    }

    /// Returns the input EA length.
    pub(crate) const fn ea_length(self) -> IrpBufferLength {
        self.ea_length
    }

    /// Returns whether kernel requestors may bypass target security evaluation.
    pub(crate) const fn access_check(self) -> CreateAccessCheck {
        self.access_check
    }

    /// Returns Windows-visible path-name comparison policy.
    pub(crate) const fn name_match(self) -> WindowsNameMatch {
        self.name_match
    }

    /// Returns the namespace object selected by this create.
    pub(crate) const fn target_selection(self) -> CreateTargetSelection {
        self.target_selection
    }

    /// Rejects valid create flags whose required filesystem protocol is not implemented.
    /// # Errors
    ///
    /// Returns not-supported instead of silently treating a special create as an ordinary open.
    pub(crate) const fn validate_supported_flags(self) -> DriverResult<()> {
        self.unsupported_flags.validate()
    }
}

/// Access-check policy carried by `IO_STACK_LOCATION::Flags`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateAccessCheck {
    /// Kernel-mode requestors may use their trusted access bypass.
    HonorRequestorMode,
    /// Evaluate access as user mode even for a kernel-mode requestor.
    ForceUserMode,
}

impl CreateAccessCheck {
    /// Decodes `SL_FORCE_ACCESS_CHECK`.
    fn from_stack_flags(flags: wdk_sys::UCHAR) -> Self {
        if stack_flag(flags, wdk_sys::SL_FORCE_ACCESS_CHECK) {
            Self::ForceUserMode
        } else {
            Self::HonorRequestorMode
        }
    }
}

/// Namespace object selected by a create request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateTargetSelection {
    /// Open or create the named object.
    NamedObject,
    /// Open the containing directory for the named final component.
    ParentDirectory,
}

impl CreateTargetSelection {
    /// Decodes `SL_OPEN_TARGET_DIRECTORY`.
    fn from_stack_flags(flags: wdk_sys::UCHAR) -> Self {
        if stack_flag(flags, wdk_sys::SL_OPEN_TARGET_DIRECTORY) {
            Self::ParentDirectory
        } else {
            Self::NamedObject
        }
    }
}

/// Special create modes that require protocols this filesystem does not expose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnsupportedCreateFlags {
    /// The Memory Manager requested paging-file semantics.
    paging_file: bool,
    /// Name resolution requested the stop-on-symlink contract.
    stop_on_symlink: bool,
    /// Replacement requested read-only-attribute bypass semantics.
    ignore_readonly_attribute: bool,
}

impl UnsupportedCreateFlags {
    /// Captures every currently unsupported create stack flag.
    fn from_stack_flags(flags: wdk_sys::UCHAR) -> Self {
        Self {
            paging_file: stack_flag(flags, wdk_sys::SL_OPEN_PAGING_FILE),
            stop_on_symlink: stack_flag(flags, wdk_sys::SL_STOP_ON_SYMLINK),
            ignore_readonly_attribute: stack_flag(flags, wdk_sys::SL_IGNORE_READONLY_ATTRIBUTE),
        }
    }

    /// Requires an ordinary create request.
    /// # Errors
    ///
    /// Returns not-supported when the caller requires a special create protocol not implemented
    /// by this filesystem.
    const fn validate(self) -> DriverResult<()> {
        if self.paging_file || self.stop_on_symlink || self.ignore_readonly_attribute {
            Err(DriverError::NotSupported)
        } else {
            Ok(())
        }
    }
}

/// Desired access requested by a create/open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DesiredAccess {
    /// Raw WDK access mask, retained for I/O Manager share-access accounting.
    raw: wdk_sys::ACCESS_MASK,
}

/// Access rights retained by a handle only after create authorization succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GrantedAccess {
    /// Concrete, generic-mapped WDK access mask.
    raw: wdk_sys::ACCESS_MASK,
}

/// Owner-bound view of the Security Reference Monitor state for one active create.
#[derive(Debug)]
pub(crate) struct CreateAccessState<'owner> {
    /// I/O Manager-owned state retained by the active create IRP.
    pub(super) access_state: NonNull<wdk_sys::ACCESS_STATE>,
    /// Effective processor mode after `SL_FORCE_ACCESS_CHECK` is applied.
    pub(super) access_mode: wdk_sys::KPROCESSOR_MODE,
    /// Forced checks must not reuse rights cached during a trusted kernel-mode open.
    pub(super) access_check: CreateAccessCheck,
    /// Prevents the state view from escaping its active completion-owner borrow.
    pub(super) owner: core::marker::PhantomData<&'owner mut wdk_sys::ACCESS_STATE>,
}

/// Virtual access used to preflight an existing-object create operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExistingOperationAccess {
    /// Raw WDK access mask checked without recording it as returned handle authority.
    raw: wdk_sys::ACCESS_MASK,
}

/// Write authority retained for one opened regular-file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegularFileWriteAccess {
    /// The handle was not opened for regular-file data writes.
    Denied,
    /// The handle may write only at the current end of file.
    AppendOnly,
    /// The handle may select an absolute, current, or end-of-file starting point.
    Positional,
}

/// Delete authority retained by one opened namespace handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteAccess {
    /// The handle was not opened with `DELETE` access.
    Denied,
    /// The handle may change the node's deletion disposition.
    Granted,
}

/// `FILE_WRITE_ATTRIBUTES` authority retained for one opened handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileAttributesWriteAccess {
    /// The handle cannot change file attributes or override read-only deletion protection.
    Denied,
    /// The handle was opened with `FILE_WRITE_ATTRIBUTES`.
    Granted,
}

impl DeleteAccess {
    /// Requires delete authority for a namespace mutation.
    /// # Errors
    ///
    /// Returns access denied when the opened handle lacks `DELETE`.
    pub(crate) const fn require(self) -> DriverResult<()> {
        match self {
            Self::Denied => Err(DriverError::AccessDenied),
            Self::Granted => Ok(()),
        }
    }
}

impl DesiredAccess {
    /// Wraps the raw WDK access mask.
    pub(super) const fn from_raw(raw: wdk_sys::ACCESS_MASK) -> Self {
        Self { raw }
    }

    /// Returns the requested WDK access mask for create authorization.
    pub(crate) const fn as_raw(self) -> wdk_sys::ACCESS_MASK {
        self.raw
    }

    /// Returns whether the request includes every selected access bit.
    pub(crate) const fn requests(self, mask: wdk_sys::ACCESS_MASK) -> bool {
        self.raw & mask == mask
    }
}

impl GrantedAccess {
    /// Constructs concrete rights after the access-check boundary authorizes them.
    pub(super) const fn from_authorized(raw: wdk_sys::ACCESS_MASK) -> Self {
        Self { raw }
    }

    /// Returns the WDK mask used for share-access accounting.
    pub(crate) const fn as_raw(self) -> wdk_sys::ACCESS_MASK {
        self.raw
    }

    /// Adds rights needed only while preflighting an existing-object operation.
    pub(crate) const fn including_for_operation(
        self,
        required: wdk_sys::ACCESS_MASK,
    ) -> ExistingOperationAccess {
        ExistingOperationAccess {
            raw: self.raw | required,
        }
    }

    /// Projects authorized Windows rights into regular-file write authority.
    pub(crate) const fn regular_file_write_access(self) -> RegularFileWriteAccess {
        if self.contains(wdk_sys::FILE_WRITE_DATA) {
            RegularFileWriteAccess::Positional
        } else if self.contains(wdk_sys::FILE_APPEND_DATA) {
            RegularFileWriteAccess::AppendOnly
        } else {
            RegularFileWriteAccess::Denied
        }
    }

    /// Projects authorized `DELETE` into retained per-handle authority.
    pub(crate) const fn delete_access(self) -> DeleteAccess {
        if self.contains(wdk_sys::DELETE) {
            DeleteAccess::Granted
        } else {
            DeleteAccess::Denied
        }
    }

    /// Projects authorized `FILE_WRITE_ATTRIBUTES` into retained authority.
    pub(crate) const fn file_attributes_write_access(self) -> FileAttributesWriteAccess {
        if self.contains(wdk_sys::FILE_WRITE_ATTRIBUTES) {
            FileAttributesWriteAccess::Granted
        } else {
            FileAttributesWriteAccess::Denied
        }
    }

    /// Returns whether all selected access bits are present.
    const fn contains(self, mask: wdk_sys::ACCESS_MASK) -> bool {
        self.raw & mask == mask
    }
}

impl CreateAccessState<'_> {
    /// Returns whether path traversal must be checked directory by directory.
    #[expect(
        unsafe_code,
        reason = "the active create owner uniquely retains ACCESS_STATE observation for this bounded call"
    )]
    pub(crate) fn requires_traverse_checks(&self) -> bool {
        let state = unsafe {
            // SAFETY: The active create IRP retains the non-null ACCESS_STATE for this view.
            self.access_state.as_ref()
        };
        state.Flags & wdk_sys::TOKEN_HAS_TRAVERSE_PRIVILEGE == 0
    }

    /// Authorizes and records the rights that become persistent handle authority.
    /// # Errors
    ///
    /// Returns the exact Security Reference Monitor or privilege-recording failure.
    #[expect(
        unsafe_code,
        reason = "the access-state mutation and Security Reference Monitor call are confined to the active create owner"
    )]
    pub(crate) fn authorize_requested(
        &mut self,
        descriptor: SecurityDescriptorRef<'_>,
        requested: DesiredAccess,
    ) -> DriverResult<GrantedAccess> {
        let kernel_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::KernelMode)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        if self.access_mode == kernel_mode {
            let granted = unrestricted_file_access(requested.as_raw());
            let state = unsafe {
                // SAFETY: The active create is the sole ACCESS_STATE executor; no native call
                // overlaps this field update.
                self.access_state.as_mut()
            };
            state.PreviouslyGrantedAccess |= granted;
            state.RemainingDesiredAccess = 0;
            return Ok(GrantedAccess::from_authorized(
                state.PreviouslyGrantedAccess,
            ));
        }

        let (desired, previously_granted) = unsafe {
            // SAFETY: Snapshot fields before the native check; no reference is retained across
            // the call that may update the ACCESS_STATE privilege set.
            let state = self.access_state.as_ref();
            match self.access_check {
                CreateAccessCheck::HonorRequestorMode => (
                    map_file_generic_access(state.RemainingDesiredAccess),
                    map_file_generic_access(state.PreviouslyGrantedAccess),
                ),
                CreateAccessCheck::ForceUserMode => (
                    map_file_generic_access(requested.as_raw() | state.RemainingDesiredAccess),
                    0,
                ),
            }
        };
        let granted = if desired == 0 {
            previously_granted
        } else {
            self.check(descriptor, desired, previously_granted)?
        };
        let state = unsafe {
            // SAFETY: The native check has completed and released all state borrows.
            self.access_state.as_mut()
        };
        state.PreviouslyGrantedAccess = previously_granted | granted;
        state.RemainingDesiredAccess = desired & !(granted | wdk_sys::MAXIMUM_ALLOWED);
        Ok(GrantedAccess::from_authorized(
            state.PreviouslyGrantedAccess,
        ))
    }

    /// Checks operation-only rights without turning them into returned handle authority.
    /// # Errors
    ///
    /// Returns the exact Security Reference Monitor or privilege-recording failure.
    pub(crate) fn authorize_operation(
        &mut self,
        descriptor: SecurityDescriptorRef<'_>,
        required: wdk_sys::ACCESS_MASK,
    ) -> DriverResult<()> {
        if required == 0 {
            return Ok(());
        }
        let kernel_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::KernelMode)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        if self.access_mode == kernel_mode {
            return Ok(());
        }
        self.check(descriptor, required, 0).map(|_| ())
    }

    /// Authorizes creation in the containing directory, including privilege-only rights, before
    /// recording the initial handle's rights. Parent creation permission cannot grant SACL access.
    /// # Errors
    ///
    /// Returns the parent access-check or explicit privilege-check failure without granting a
    /// handle. No ACCESS_STATE rights are published until both checks succeed.
    #[expect(
        unsafe_code,
        reason = "the active create owner exclusively records newly-created handle authority"
    )]
    pub(crate) fn authorize_child_creation(
        &mut self,
        parent: SecurityDescriptorRef<'_>,
        required: wdk_sys::ACCESS_MASK,
        requested: DesiredAccess,
    ) -> DriverResult<GrantedAccess> {
        self.authorize_operation(parent, required)?;
        self.authorize_operation(parent, requested.as_raw() & wdk_sys::ACCESS_SYSTEM_SECURITY)?;
        let granted = unrestricted_file_access(requested.as_raw());
        let state = unsafe {
            // SAFETY: This owner-bound mutable view is the sole create executor touching ACCESS_STATE.
            self.access_state.as_mut()
        };
        state.PreviouslyGrantedAccess = granted;
        state.RemainingDesiredAccess = 0;
        Ok(GrantedAccess::from_authorized(
            state.PreviouslyGrantedAccess,
        ))
    }

    /// Performs one descriptor check while retaining all privilege cleanup responsibility.
    /// # Errors
    ///
    /// Returns the native access denial or privilege-recording failure. Returned privilege
    /// storage is released on every outcome before control returns to the create executor.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this is the audited Security Reference Monitor FFI boundary for a live create ACCESS_STATE"
    )]
    fn check(
        &mut self,
        descriptor: SecurityDescriptorRef<'_>,
        desired: wdk_sys::ACCESS_MASK,
        previously_granted: wdk_sys::ACCESS_MASK,
    ) -> DriverResult<wdk_sys::ACCESS_MASK> {
        let mapping = unsafe {
            // SAFETY: The I/O Manager owns the immutable file-object generic mapping for the
            // running kernel; this actor calls the security monitor at PASSIVE_LEVEL.
            ffi::IoGetFileObjectGenericMapping()
        };
        unsafe {
            // SAFETY: This owner exclusively retains ACCESS_STATE and the WDK mapping remains
            // valid through both this preparation and the access check below.
            ffi::SeSetAccessStateGenericMapping(self.access_state.as_ptr(), mapping);
        }
        let state = unsafe {
            // SAFETY: The active create owner retains exclusive mutation authority for ACCESS_STATE.
            self.access_state.as_mut()
        };
        let mut privileges: wdk_sys::PPRIVILEGE_SET = core::ptr::null_mut();
        let mut granted = 0;
        let mut access_status = wdk_sys::STATUS_ACCESS_DENIED;
        unsafe {
            // SAFETY: The subject context is embedded in the live ACCESS_STATE and remains locked
            // only across this non-panicking SeAccessCheck call.
            ffi::SeLockSubjectContext(core::ptr::addr_of_mut!(state.SubjectSecurityContext));
        }
        let allowed = unsafe {
            // SAFETY: Every pointer names live storage for the duration of the call; the complete
            // self-relative descriptor is owned by the create resolve pass.
            ffi::SeAccessCheck(
                descriptor.as_ptr(),
                core::ptr::addr_of_mut!(state.SubjectSecurityContext),
                1,
                desired,
                previously_granted,
                core::ptr::addr_of_mut!(privileges),
                mapping,
                self.access_mode,
                core::ptr::addr_of_mut!(granted),
                core::ptr::addr_of_mut!(access_status),
            )
        };
        unsafe {
            // SAFETY: This exactly balances the immediately preceding subject-context lock.
            ffi::SeUnlockSubjectContext(core::ptr::addr_of_mut!(state.SubjectSecurityContext));
        }

        let append_status = if allowed != 0 && !privileges.is_null() {
            Some(unsafe {
                // SAFETY: SeAccessCheck returned this privilege set and the active ACCESS_STATE is
                // the required destination for audit/close semantics.
                ffi::SeAppendPrivileges(self.access_state.as_ptr(), privileges)
            })
        } else {
            None
        };
        if !privileges.is_null() {
            unsafe {
                // SAFETY: SeAccessCheck transferred this allocation to the caller exactly once.
                ffi::SeFreePrivileges(privileges);
            }
        }
        if let Some(status) = append_status
            && status < 0
        {
            return Err(DriverError::PrivilegeRecordingFailed(status));
        }
        if allowed == 0 {
            return Err(DriverError::SecurityCheckFailed(if access_status < 0 {
                access_status
            } else {
                wdk_sys::STATUS_ACCESS_DENIED
            }));
        }
        Ok(granted)
    }

    /// Kernel token checks cannot run in the user-mode unit-test process.
    /// # Errors
    ///
    /// Always returns not-supported; a unit-test process cannot grant kernel token authority.
    #[cfg(test)]
    fn check(
        &mut self,
        _descriptor: SecurityDescriptorRef<'_>,
        _desired: wdk_sys::ACCESS_MASK,
        _previously_granted: wdk_sys::ACCESS_MASK,
    ) -> DriverResult<wdk_sys::ACCESS_MASK> {
        Err(DriverError::NotSupported)
    }
}

/// Maps generic file rights while leaving MAXIMUM_ALLOWED for the descriptor-based access check.
pub(super) const fn map_file_generic_access(raw: wdk_sys::ACCESS_MASK) -> wdk_sys::ACCESS_MASK {
    let mut mapped = raw;
    if mapped & wdk_sys::GENERIC_READ != 0 {
        mapped = (mapped & !wdk_sys::GENERIC_READ) | wdk_sys::FILE_GENERIC_READ;
    }
    if mapped & wdk_sys::GENERIC_WRITE != 0 {
        mapped = (mapped & !wdk_sys::GENERIC_WRITE) | wdk_sys::FILE_GENERIC_WRITE;
    }
    if mapped & wdk_sys::GENERIC_EXECUTE != 0 {
        mapped = (mapped & !wdk_sys::GENERIC_EXECUTE) | wdk_sys::FILE_GENERIC_EXECUTE;
    }
    if mapped & wdk_sys::GENERIC_ALL != 0 {
        mapped = (mapped & !wdk_sys::GENERIC_ALL) | wdk_sys::FILE_ALL_ACCESS;
    }
    mapped
}

/// Expands the full file access request only for trusted kernel opens or newly created objects
/// whose parent and privilege-only access have already been checked.
const fn unrestricted_file_access(raw: wdk_sys::ACCESS_MASK) -> wdk_sys::ACCESS_MASK {
    let mapped = map_file_generic_access(raw);
    if mapped & wdk_sys::MAXIMUM_ALLOWED != 0 {
        (mapped & !wdk_sys::MAXIMUM_ALLOWED) | wdk_sys::FILE_ALL_ACCESS
    } else {
        mapped
    }
}

impl ExistingOperationAccess {
    /// Returns the WDK access mask for `IoCheckShareAccess`.
    pub(crate) const fn as_raw(self) -> wdk_sys::ACCESS_MASK {
        self.raw
    }
}

/// Share access requested by a create/open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShareAccess {
    /// Raw WDK share mask widened for I/O Manager share-access accounting.
    raw: wdk_sys::ULONG,
}

impl ShareAccess {
    /// Decodes the raw WDK share mask.
    /// # Errors
    ///
    /// Returns an error when `raw` contains bits outside the Windows file-share mask.
    pub(super) fn from_raw(raw: wdk_sys::USHORT) -> Result<Self, DriverError> {
        if raw & !FILE_SHARE_ACCESS_MASK != 0 {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self {
            raw: wdk_sys::ULONG::from(raw),
        })
    }

    /// Returns the WDK share mask for `IoCheckShareAccess`.
    pub(crate) const fn as_ulong(self) -> wdk_sys::ULONG {
        self.raw
    }
}

/// Requested create disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateDisposition {
    /// Open only if the path exists.
    Open,
    /// Create only if the path is absent.
    Create,
    /// Open existing or create absent.
    OpenIf,
    /// Truncate an existing regular file.
    Overwrite,
    /// Truncate an existing regular file or create an absent object.
    OverwriteIf,
    /// Replace an existing regular file's data or create an absent object.
    Supersede,
}

impl CreateDisposition {
    /// Decodes the disposition stored in Create.Options.
    /// # Errors
    ///
    /// Returns an error when the disposition bits do not name a supported Windows create
    /// disposition.
    fn from_options(options: wdk_sys::ULONG) -> Result<Self, DriverError> {
        match options >> CREATE_DISPOSITION_SHIFT {
            FILE_OPEN_DISPOSITION => Ok(Self::Open),
            FILE_CREATE_DISPOSITION => Ok(Self::Create),
            FILE_OPEN_IF_DISPOSITION => Ok(Self::OpenIf),
            FILE_SUPERSEDE_DISPOSITION => Ok(Self::Supersede),
            FILE_OVERWRITE_DISPOSITION => Ok(Self::Overwrite),
            FILE_OVERWRITE_IF_DISPOSITION => Ok(Self::OverwriteIf),
            _ => Err(DriverError::InvalidParameter),
        }
    }

    /// Validates create-disposition and target-kind combinations before path lookup.
    /// # Errors
    ///
    /// Returns an error when a destructive file disposition is combined with
    /// `FILE_DIRECTORY_FILE`.
    fn validate_target_requirement(self, requirement: CreateTargetRequirement) -> DriverResult<()> {
        if matches!(requirement, CreateTargetRequirement::Directory)
            && matches!(self, Self::Overwrite | Self::OverwriteIf | Self::Supersede)
        {
            return Err(DriverError::InvalidParameter);
        }
        Ok(())
    }
}

/// File-vs-directory target requirement requested by create options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateTargetRequirement {
    /// Caller accepts a file, symlink, or directory.
    Any,
    /// Caller requires a directory target.
    Directory,
    /// Caller requires a non-directory target.
    NonDirectory,
}

/// Requested file data transfer buffering for a newly opened handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateTransferBuffering {
    /// No direct-transfer constraints were requested.
    IntermediateAllowed,
    /// Caller requested `FILE_NO_INTERMEDIATE_BUFFERING`.
    NoIntermediate,
}

/// Create-time behavior when the named stream has, or will reserve, an oplock relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OplockCreatePolicy {
    /// Use the ordinary oplock break-and-wait protocol.
    Ordinary,
    /// Complete with the Windows alternate success status instead of waiting for a break.
    CompleteIfOplocked,
    /// Refuse the create rather than breaking an existing oplock.
    RequireUnbrokenOplock,
    /// Reserve the atomic filter-oplock acquisition protocol for this exact metadata-only open.
    ReserveFilter,
}

impl OplockCreatePolicy {
    /// Normalizes the mutually exclusive create flags and validates filter-reservation access.
    /// # Errors
    ///
    /// Returns invalid-parameter for ambiguous flags or a reserve-filter request whose exact
    /// desired/share contract cannot be honored.
    pub(super) fn decode(
        options: wdk_sys::ULONG,
        desired_access: DesiredAccess,
        share_access: ShareAccess,
    ) -> DriverResult<Self> {
        let complete = create_option_selected(options, wdk_sys::FILE_COMPLETE_IF_OPLOCKED);
        let require = create_option_selected(options, wdk_sys::FILE_OPEN_REQUIRING_OPLOCK);
        let reserve = create_option_selected(options, wdk_sys::FILE_RESERVE_OPFILTER);
        if [complete, require, reserve]
            .into_iter()
            .filter(|selected| *selected)
            .nth(1)
            .is_some()
        {
            return Err(DriverError::InvalidParameter);
        }
        if reserve {
            if desired_access.as_raw() != wdk_sys::FILE_READ_ATTRIBUTES
                || share_access.as_ulong() != wdk_sys::ULONG::from(FILE_SHARE_ACCESS_MASK)
            {
                return Err(DriverError::InvalidParameter);
            }
            Ok(Self::ReserveFilter)
        } else if require {
            Ok(Self::RequireUnbrokenOplock)
        } else if complete {
            Ok(Self::CompleteIfOplocked)
        } else {
            Ok(Self::Ordinary)
        }
    }
}

/// Requested per-handle synchronous I/O mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateSynchronizationMode {
    /// No synchronous file-position context was requested.
    Asynchronous,
    /// Synchronous I/O with alertable waits.
    SynchronousAlert,
    /// Synchronous I/O with non-alertable waits.
    SynchronousNonAlert,
}

impl CreateSynchronizationMode {
    /// Decodes synchronous I/O create options.
    /// # Errors
    ///
    /// Returns an error when both synchronous modes are set or `SYNCHRONIZE` access is absent.
    fn from_options(options: wdk_sys::ULONG, desired_access: DesiredAccess) -> DriverResult<Self> {
        let alert = create_option_selected(options, wdk_sys::FILE_SYNCHRONOUS_IO_ALERT);
        let nonalert = create_option_selected(options, wdk_sys::FILE_SYNCHRONOUS_IO_NONALERT);
        match (alert, nonalert) {
            (true, true) => Err(DriverError::InvalidParameter),
            (true, false) => Self::synchronized(desired_access, Self::SynchronousAlert),
            (false, true) => Self::synchronized(desired_access, Self::SynchronousNonAlert),
            (false, false) => Ok(Self::Asynchronous),
        }
    }

    /// Returns a synchronous mode after validating the access mask.
    /// # Errors
    ///
    /// Returns an error when the caller omitted `SYNCHRONIZE`.
    fn synchronized(desired_access: DesiredAccess, mode: Self) -> DriverResult<Self> {
        if !desired_access.requests(wdk_sys::SYNCHRONIZE) {
            return Err(DriverError::InvalidParameter);
        }
        Ok(mode)
    }
}

/// Requested reparse-point handling for an existing final path component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateReparsePointMode {
    /// Use normal reparse processing for final reparse points.
    ResolveFinalTarget,
    /// Open the final reparse point itself.
    OpenFinalReparsePoint,
}

impl CreateReparsePointMode {
    /// Decodes reparse-point create options.
    const fn from_options(options: wdk_sys::ULONG) -> Self {
        if create_option_selected(options, wdk_sys::FILE_OPEN_REPARSE_POINT) {
            Self::OpenFinalReparsePoint
        } else {
            Self::ResolveFinalTarget
        }
    }
}

/// Requested interpretation for `FILE_OBJECT::FileName`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateNameInterpretation {
    /// Interpret the FILE_OBJECT name as a Windows path.
    Path,
    /// Interpret the FILE_OBJECT name as a binary file reference.
    FileReference,
}

/// Namespace deletion requested as part of create/open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateDeletion {
    /// The returned handle does not implicitly publish delete-pending.
    Retain,
    /// Successful create/open must publish delete-pending for this exact link.
    DeleteOnClose,
}

impl CreateDeletion {
    /// Decodes `FILE_DELETE_ON_CLOSE` and its required handle authority.
    /// # Errors
    ///
    /// Returns access denied when delete-on-close is requested without `DELETE`.
    fn from_options(options: wdk_sys::ULONG, desired_access: DesiredAccess) -> DriverResult<Self> {
        if create_option_selected(options, wdk_sys::FILE_DELETE_ON_CLOSE) {
            if !desired_access.requests(wdk_sys::DELETE) {
                return Err(DriverError::AccessDenied);
            }
            Ok(Self::DeleteOnClose)
        } else {
            Ok(Self::Retain)
        }
    }
}

impl CreateNameInterpretation {
    /// Decodes create-name interpretation options.
    const fn from_options(options: wdk_sys::ULONG) -> Self {
        if create_option_selected(options, wdk_sys::FILE_OPEN_BY_FILE_ID) {
            Self::FileReference
        } else {
            Self::Path
        }
    }
}

impl CreateTargetRequirement {
    /// Decodes file-vs-directory create options.
    /// # Errors
    ///
    /// Returns an error when both directory-only and non-directory-only options are set.
    fn from_options(options: wdk_sys::ULONG) -> Result<Self, DriverError> {
        let directory = create_option_selected(options, wdk_sys::FILE_DIRECTORY_FILE);
        let non_directory = create_option_selected(options, wdk_sys::FILE_NON_DIRECTORY_FILE);
        match (directory, non_directory) {
            (true, true) => Err(DriverError::InvalidParameter),
            (true, false) => Ok(Self::Directory),
            (false, true) => Ok(Self::NonDirectory),
            (false, false) => Ok(Self::Any),
        }
    }
}

/// Create options that survive raw Windows boundary decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreateOptions {
    /// File-vs-directory requirement.
    target_requirement: CreateTargetRequirement,
    /// Requested write completion durability.
    write_commitment: WriteCommitment,
    /// Requested data transfer buffering.
    transfer_buffering: CreateTransferBuffering,
    /// Requested synchronous I/O mode.
    synchronization_mode: CreateSynchronizationMode,
    /// Requested reparse-point handling.
    reparse_point_mode: CreateReparsePointMode,
    /// Requested name interpretation.
    name_interpretation: CreateNameInterpretation,
    /// Requested namespace deletion lifecycle.
    deletion: CreateDeletion,
}

impl CreateOptions {
    /// Decodes and normalizes raw `Create.Options`.
    /// # Errors
    ///
    /// Returns an error when create options include bits outside the accepted ext4win boundary.
    fn decode(options: wdk_sys::ULONG, desired_access: DesiredAccess) -> DriverResult<Self> {
        let raw_options = options & CREATE_OPTIONS_MASK;
        if raw_options & !ACCEPTED_CREATE_OPTIONS != 0 {
            return Err(DriverError::NotSupported);
        }
        let transfer_buffering =
            if create_option_selected(options, wdk_sys::FILE_NO_INTERMEDIATE_BUFFERING) {
                CreateTransferBuffering::NoIntermediate
            } else {
                CreateTransferBuffering::IntermediateAllowed
            };
        let synchronization_mode =
            CreateSynchronizationMode::from_options(options, desired_access)?;
        let reparse_point_mode = CreateReparsePointMode::from_options(options);
        let name_interpretation = CreateNameInterpretation::from_options(options);
        let deletion = CreateDeletion::from_options(options, desired_access)?;
        let write_commitment = if create_option_selected(options, wdk_sys::FILE_WRITE_THROUGH)
            || matches!(transfer_buffering, CreateTransferBuffering::NoIntermediate)
        {
            WriteCommitment::FlushThrough
        } else {
            WriteCommitment::CommitOnly
        };
        Ok(Self {
            target_requirement: CreateTargetRequirement::from_options(options)?,
            write_commitment,
            transfer_buffering,
            synchronization_mode,
            reparse_point_mode,
            name_interpretation,
            deletion,
        })
    }

    /// Returns the decoded file-vs-directory requirement.
    const fn target_requirement(self) -> CreateTargetRequirement {
        self.target_requirement
    }

    /// Returns decoded write completion durability.
    const fn write_commitment(self) -> WriteCommitment {
        self.write_commitment
    }

    /// Returns decoded data transfer buffering.
    const fn transfer_buffering(self) -> CreateTransferBuffering {
        self.transfer_buffering
    }

    /// Returns decoded synchronous I/O mode.
    const fn synchronization_mode(self) -> CreateSynchronizationMode {
        self.synchronization_mode
    }

    /// Returns decoded reparse-point handling.
    const fn reparse_point_mode(self) -> CreateReparsePointMode {
        self.reparse_point_mode
    }

    /// Returns decoded name interpretation.
    const fn name_interpretation(self) -> CreateNameInterpretation {
        self.name_interpretation
    }

    /// Returns requested namespace deletion lifecycle.
    const fn deletion(self) -> CreateDeletion {
        self.deletion
    }
}

/// Returns true when a create option bit is present.
const fn create_option_selected(options: wdk_sys::ULONG, option: wdk_sys::ULONG) -> bool {
    options & option != 0
}

/// `FILE_SUPERSEDE` create disposition.
pub(super) const FILE_SUPERSEDE_DISPOSITION: wdk_sys::ULONG = 0;
/// `FILE_OPEN` create disposition.
pub(super) const FILE_OPEN_DISPOSITION: wdk_sys::ULONG = 1;
/// `FILE_CREATE` create disposition.
const FILE_CREATE_DISPOSITION: wdk_sys::ULONG = 2;
/// `FILE_OPEN_IF` create disposition.
pub(super) const FILE_OPEN_IF_DISPOSITION: wdk_sys::ULONG = 3;
/// `FILE_OVERWRITE` create disposition.
pub(super) const FILE_OVERWRITE_DISPOSITION: wdk_sys::ULONG = 4;
/// `FILE_OVERWRITE_IF` create disposition.
pub(super) const FILE_OVERWRITE_IF_DISPOSITION: wdk_sys::ULONG = 5;
/// Shift for the create disposition stored in `Options`.
pub(super) const CREATE_DISPOSITION_SHIFT: u32 = 24;
/// Mask for option bits below the create disposition.
const CREATE_OPTIONS_MASK: wdk_sys::ULONG = 0x00FF_FFFF;
/// Create options with an ext4win-internal domain meaning.
const DOMAIN_CREATE_OPTIONS: wdk_sys::ULONG = wdk_sys::FILE_DIRECTORY_FILE
    | wdk_sys::FILE_NON_DIRECTORY_FILE
    | wdk_sys::FILE_DELETE_ON_CLOSE
    | wdk_sys::FILE_WRITE_THROUGH
    | wdk_sys::FILE_NO_INTERMEDIATE_BUFFERING
    | wdk_sys::FILE_SYNCHRONOUS_IO_ALERT
    | wdk_sys::FILE_SYNCHRONOUS_IO_NONALERT
    | wdk_sys::FILE_OPEN_REPARSE_POINT
    | wdk_sys::FILE_OPEN_BY_FILE_ID
    | wdk_sys::FILE_COMPLETE_IF_OPLOCKED
    | wdk_sys::FILE_OPEN_REQUIRING_OPLOCK
    | wdk_sys::FILE_RESERVE_OPFILTER;
/// Create options consumed as Windows boundary hints.
const IGNORED_CREATE_HINT_OPTIONS: wdk_sys::ULONG = wdk_sys::FILE_SEQUENTIAL_ONLY
    | wdk_sys::FILE_NO_EA_KNOWLEDGE
    | wdk_sys::FILE_RANDOM_ACCESS
    | wdk_sys::FILE_OPEN_FOR_BACKUP_INTENT
    | wdk_sys::FILE_NO_COMPRESSION
    | wdk_sys::FILE_DISALLOW_EXCLUSIVE
    | wdk_sys::FILE_OPEN_NO_RECALL
    | wdk_sys::FILE_OPEN_FOR_FREE_SPACE_QUERY;
/// Create options accepted by this FSD boundary.
const ACCEPTED_CREATE_OPTIONS: wdk_sys::ULONG = DOMAIN_CREATE_OPTIONS | IGNORED_CREATE_HINT_OPTIONS;
/// WDK share-access bits accepted by create/open.
pub(super) const FILE_SHARE_ACCESS_MASK: wdk_sys::USHORT = 0x0007;
