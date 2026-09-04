//! Active, received, pending, and owned IRP lifecycle states.

use super::*;

/// Lifetime-bound view of an IRP held by one completion owner.
#[derive(Debug)]
pub(crate) struct ActiveIrp<'owner> {
    /// Device object receiving the request.
    pub(super) device: KernelDevice,
    /// Live IRP retained by the exclusively borrowed completion owner.
    pub(super) irp: NonNull<wdk_sys::IRP>,
    /// Prevents this view or any derived stack/buffer view from outliving the owner borrow.
    pub(super) owner: core::marker::PhantomData<&'owner mut DispatchTarget>,
}

impl ActiveIrp<'_> {
    /// Returns the typed device object boundary.
    pub(crate) const fn device(&self) -> KernelDevice {
        self.device
    }

    /// Returns whether this request is normal handle I/O or paging I/O.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn data_io_kind(&self) -> DataIoKind {
        let flags = unsafe {
            // SAFETY: The completion owner remains borrowed for this view's entire lifetime.
            self.irp.as_ref().Flags
        };
        if flags & wdk_sys::IRP_PAGING_IO == 0 {
            DataIoKind::Handle
        } else {
            DataIoKind::Paging
        }
    }

    /// Borrows the live create access state under this completion owner.
    /// # Errors
    ///
    /// Returns an error when the requestor mode, create security context, or access state is
    /// malformed.
    #[expect(
        unsafe_code,
        reason = "the active IRP owner retains the requestor mode and create security context for this bounded borrow"
    )]
    pub(crate) fn create_access_state(
        &mut self,
        policy: CreateAccessCheck,
    ) -> DriverResult<CreateAccessState<'_>> {
        let requestor_mode = unsafe {
            // SAFETY: This active view keeps the IRP live for the returned owner-bound state view.
            self.irp.as_ref().RequestorMode
        };
        self.current_stack()?
            .create_access_state(requestor_mode, policy)
    }

    /// Returns the kernel process identity used by FsRtl byte-range lock ownership.
    /// # Errors
    ///
    /// Returns an invariant error when the I/O Manager does not expose a requestor process for
    /// this live IRP.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    pub(crate) fn requestor_process(&self) -> DriverResult<RequestorProcess> {
        #[cfg(not(test))]
        let process = unsafe {
            // SAFETY: This active view keeps the IRP live for the duration of the native query.
            ffi::IoGetRequestorProcess(self.irp.as_ptr()).cast::<c_void>()
        };
        #[cfg(test)]
        let process = NonNull::<c_void>::dangling().as_ptr();
        NonNull::new(process)
            .map(RequestorProcess)
            .ok_or(DriverError::InternalInvariantViolation)
    }

    /// Returns METHOD_BUFFERED input bytes tied to this active owner borrow.
    /// # Errors
    ///
    /// Returns an error when the associated system buffer is null.
    pub(crate) fn buffered_input(
        &self,
        length: IrpBufferLength,
    ) -> Result<BufferedInput<'_>, DriverError> {
        BufferedInput::from_active(self.associated_system_buffer()?, length.as_usize())
    }

    /// Returns METHOD_BUFFERED output bytes tied to this active owner borrow.
    ///
    /// The complete output range is initialized to zero before it can become a Rust byte slice.
    /// # Errors
    ///
    /// Returns an error when the associated system buffer is null.
    pub(crate) fn buffered_output(
        &mut self,
        length: IrpBufferLength,
    ) -> Result<BufferedOutput<'_>, DriverError> {
        BufferedOutput::from_active(self.associated_system_buffer()?, length.as_usize())
    }

    /// Returns an opaque requestor-input range tied to this active owner borrow.
    ///
    /// The range can only be copied into driver-owned storage; it never becomes a Rust slice.
    /// # Errors
    ///
    /// Returns an error when neither a system buffer nor a mapped MDL covers `length`.
    pub(crate) fn requestor_input(
        &self,
        length: IrpBufferLength,
    ) -> Result<RequestorInput<'_>, DriverError> {
        RequestorInput::from_active(self.requestor_buffer(length)?)
    }

    /// Returns an opaque requestor-output range tied to this active owner borrow.
    ///
    /// The range can only receive bytes from driver-owned storage; it never becomes a Rust slice.
    /// # Errors
    ///
    /// Returns an error when neither a system buffer nor a mapped MDL covers `length`.
    pub(crate) fn requestor_output(
        &mut self,
        length: IrpBufferLength,
    ) -> Result<RequestorOutput<'_>, DriverError> {
        RequestorOutput::from_active(self.requestor_buffer(length)?)
    }

    /// Borrows disjoint output and FILE_OBJECT views for one output-and-cursor publication.
    /// # Errors
    ///
    /// Returns an error before publication if either the output mapping or FILE_OBJECT is invalid.
    pub(crate) fn requestor_output_with_file_object(
        &mut self,
        length: IrpBufferLength,
    ) -> DriverResult<(RequestorOutput<'_>, ActiveFileObject<'_>)> {
        let file_object = self.current_stack()?.file_object()?;
        let output = RequestorOutput::from_active(self.requestor_buffer(length)?)?;
        Ok((output, file_object))
    }

    /// Returns read-like IRP data bytes tied to this active owner borrow.
    /// # Errors
    ///
    /// Returns an error when neither a system buffer nor a mapped MDL can provide the input.
    /// Returns a write input address without creating a Rust reference before queue publication.
    /// # Errors
    ///
    /// Returns an error when neither a system buffer nor a mapped MDL covers `length`.
    pub(crate) fn data_input_address(
        &self,
        length: IrpBufferLength,
    ) -> Result<NonNull<u8>, DriverError> {
        self.data_buffer_address(length)
    }

    /// Returns write-like IRP data bytes tied to this active owner borrow.
    /// # Errors
    ///
    /// Returns an error when neither a system buffer nor a mapped MDL can provide the output.
    /// Returns a read output address without creating a Rust reference before queue publication.
    /// # Errors
    ///
    /// Returns an error when neither a system buffer nor a mapped MDL covers `length`.
    pub(crate) fn data_output_address(
        &self,
        length: IrpBufferLength,
    ) -> Result<NonNull<u8>, DriverError> {
        self.data_buffer_address(length)
    }

    /// Returns the current stack location tied to this active owner borrow.
    /// # Errors
    ///
    /// Returns an error when the current stack pointer is null.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn current_stack(&self) -> Result<CurrentIrpStackLocation<'_>, DriverError> {
        let irp = unsafe {
            // SAFETY: The completion owner remains borrowed for this view's entire lifetime.
            self.irp.as_ref()
        };
        let tail_overlay = unsafe {
            // SAFETY: CurrentStackLocation is stored through the active IRP tail overlay.
            irp.Tail.Overlay
        };
        let current_stack = unsafe {
            // SAFETY: The list overlay contains the active current stack pointer.
            tail_overlay
                .__bindgen_anon_2
                .__bindgen_anon_1
                .CurrentStackLocation
        };
        CurrentIrpStackLocation::from_active(current_stack)
    }

    /// Returns the buffered I/O system-buffer address.
    /// # Errors
    ///
    /// Returns an error when the active IRP has no system buffer.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn associated_system_buffer(&self) -> Result<NonNull<u8>, DriverError> {
        let irp = unsafe {
            // SAFETY: The completion owner remains borrowed for this view's entire lifetime.
            self.irp.as_ref()
        };
        let system_buffer = unsafe {
            // SAFETY: SystemBuffer is the active AssociatedIrp arm for buffered requests.
            irp.AssociatedIrp.SystemBuffer
        };
        NonNull::new(system_buffer)
            .map(NonNull::cast)
            .ok_or(DriverError::InvalidParameter)
    }

    /// Returns a system-mapped read/write data-buffer address.
    /// # Errors
    ///
    /// Returns an error when neither a system buffer nor a valid mapped MDL covers `length`.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn data_buffer_address(&self, length: IrpBufferLength) -> Result<NonNull<u8>, DriverError> {
        if let Ok(system_buffer) = self.associated_system_buffer() {
            return Ok(system_buffer);
        }

        let irp = unsafe {
            // SAFETY: The completion owner remains borrowed for this view's entire lifetime.
            self.irp.as_ref()
        };
        let Some(mdl) = NonNull::new(irp.MdlAddress) else {
            return Err(DriverError::InvalidParameter);
        };
        mdl_data_buffer_address(mdl, length)
    }

    /// Captures an opaque requestor buffer without creating a Rust reference to its bytes.
    /// # Errors
    ///
    /// Returns an error when a nonempty IRP buffer has no valid system-buffer or MDL mapping.
    fn requestor_buffer(&self, length: IrpBufferLength) -> DriverResult<RequestorBuffer> {
        let byte_count = length.as_usize();
        let address = if byte_count == 0 {
            None
        } else {
            Some(self.data_buffer_address(length)?)
        };
        Ok(RequestorBuffer {
            address,
            length: byte_count,
        })
    }
}

/// Opaque requestor-backed range that never participates in Rust's reference aliasing model.
#[derive(Clone, Copy, Debug)]
struct RequestorBuffer {
    /// First byte when the range is non-empty.
    address: Option<NonNull<u8>>,
    /// Exact mapped byte count.
    length: usize,
}

/// Requestor input that may only be snapshotted into driver-owned storage.
#[derive(Debug)]
pub(crate) struct RequestorInput<'owner> {
    /// Opaque requestor-backed range.
    buffer: RequestorBuffer,
    /// Prevents use after the active completion owner is released.
    owner: core::marker::PhantomData<&'owner ()>,
}

impl RequestorInput<'_> {
    /// Binds an opaque range to the active completion-owner lifetime.
    /// # Errors
    ///
    /// Returns an error when the opaque mapping does not satisfy the active input contract.
    fn from_active(buffer: RequestorBuffer) -> DriverResult<Self> {
        Ok(Self {
            buffer,
            owner: core::marker::PhantomData,
        })
    }

    /// Snapshots the complete input into equally sized driver-owned storage.
    /// # Errors
    ///
    /// Returns an error when the destination length differs or the mapped range is invalid.
    #[expect(
        unsafe_code,
        reason = "the lifetime-bound IRP view discharges the raw mapped-range copy contract"
    )]
    pub(crate) fn copy_to(&self, destination: &mut [u8]) -> DriverResult<()> {
        unsafe {
            // SAFETY: `owner` retains the mapped input, and safe callers cannot construct
            // `destination` as an alias of the opaque requestor range.
            copy_requestor_input_window(self.buffer.address, self.buffer.length, 0, destination)
        }
    }
}

/// Requestor output that may only receive bytes from driver-owned storage.
#[derive(Debug)]
pub(crate) struct RequestorOutput<'owner> {
    /// Opaque requestor-backed range.
    buffer: RequestorBuffer,
    /// Prevents use after the active completion owner is released.
    owner: core::marker::PhantomData<&'owner mut ()>,
}

impl RequestorOutput<'_> {
    /// Binds an opaque range to the active completion-owner lifetime.
    /// # Errors
    ///
    /// Returns an error when the opaque mapping does not satisfy the active output contract.
    fn from_active(buffer: RequestorBuffer) -> DriverResult<Self> {
        Ok(Self {
            buffer,
            owner: core::marker::PhantomData,
        })
    }

    /// Copies driver-owned bytes to `offset` in the requestor output.
    /// # Errors
    ///
    /// Returns an error when the selected range exceeds the mapped output.
    #[expect(
        unsafe_code,
        reason = "the lifetime-bound IRP view discharges the raw mapped-range copy contract"
    )]
    pub(crate) fn copy_from(&mut self, offset: usize, source: &[u8]) -> DriverResult<()> {
        unsafe {
            // SAFETY: `owner` uniquely retains the mapped output, and safe callers cannot
            // construct `source` as an alias of the opaque requestor range.
            copy_requestor_output_window(self.buffer.address, self.buffer.length, offset, source)
        }
    }
}

/// Copies one checked requestor-input window into driver-owned storage.
/// # Safety
///
/// A nonempty `address` must remain readable for `total_length` bytes during the call, with valid
/// provenance for one allocation. That range must not overlap `destination`.
/// # Errors
///
/// Returns an error when the selected range is invalid or exceeds Rust's pointer-offset domain.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
pub(super) unsafe fn copy_requestor_input_window(
    address: Option<NonNull<u8>>,
    total_length: usize,
    offset: usize,
    destination: &mut [u8],
) -> DriverResult<()> {
    let end = offset
        .checked_add(destination.len())
        .ok_or(DriverError::InternalInvariantViolation)?;
    if end > total_length {
        return Err(DriverError::InternalInvariantViolation);
    }
    if destination.is_empty() {
        return Ok(());
    }
    let address = address.ok_or(DriverError::InternalInvariantViolation)?;
    isize::try_from(total_length).map_err(|_| DriverError::InternalInvariantViolation)?;
    let source = address.as_ptr().wrapping_add(offset);
    unsafe {
        // SAFETY: The active or pending IRP owns `address` for `total_length`; checked arithmetic
        // selects an in-range source window, and the caller guarantees non-overlap with the
        // initialized driver-owned destination.
        core::ptr::copy_nonoverlapping(source, destination.as_mut_ptr(), destination.len());
    }
    Ok(())
}

/// Copies driver-owned bytes into one checked requestor-output window.
/// # Safety
///
/// A nonempty `address` must remain writable for `total_length` bytes during the call, with valid
/// provenance for one allocation. That range must not overlap `source`.
/// # Errors
///
/// Returns an error when the selected range is invalid or exceeds Rust's pointer-offset domain.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
pub(super) unsafe fn copy_requestor_output_window(
    address: Option<NonNull<u8>>,
    total_length: usize,
    offset: usize,
    source: &[u8],
) -> DriverResult<()> {
    let end = offset
        .checked_add(source.len())
        .ok_or(DriverError::InternalInvariantViolation)?;
    if end > total_length {
        return Err(DriverError::InternalInvariantViolation);
    }
    if source.is_empty() {
        return Ok(());
    }
    let address = address.ok_or(DriverError::InternalInvariantViolation)?;
    isize::try_from(total_length).map_err(|_| DriverError::InternalInvariantViolation)?;
    let destination = address.as_ptr().wrapping_add(offset);
    unsafe {
        // SAFETY: The active or pending IRP owns `address` for `total_length`; checked arithmetic
        // selects an in-range destination window, and the caller guarantees non-overlap with the
        // initialized driver-owned source.
        core::ptr::copy_nonoverlapping(source.as_ptr(), destination, source.len());
    }
    Ok(())
}

/// Opaque kernel process identity used solely for native byte-range lock ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestorProcess(NonNull<c_void>);

impl RequestorProcess {
    /// Returns the stable non-null process identity without granting process access.
    pub(crate) const fn as_non_null(self) -> NonNull<c_void> {
        self.0
    }

    /// Returns the opaque process pointer for FsRtl.
    #[cfg(not(test))]
    pub(crate) const fn as_ptr(self) -> *mut c_void {
        self.0.as_ptr()
    }
}

/// FILE_OBJECT view whose lifetime is bounded by an active IRP owner borrow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ActiveFileObject<'owner> {
    /// Stable non-null FILE_OBJECT address.
    pub(super) address: KernelFileObject,
    /// Prevents dereference after the active IRP owner borrow ends.
    pub(super) owner: core::marker::PhantomData<&'owner wdk_sys::FILE_OBJECT>,
}

impl ActiveFileObject<'_> {
    /// Returns the stable address for identity comparison and native calls.
    pub(crate) const fn address(self) -> KernelFileObject {
        self.address
    }

    /// Returns the WDK FILE_OBJECT for the lifetime of this active view.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn as_ref(&self) -> &wdk_sys::FILE_OBJECT {
        unsafe {
            // SAFETY: Construction is private to a lifetime-bound current-stack view whose IRP
            // owner keeps the FILE_OBJECT alive.
            &*self.address.as_ptr()
        }
    }

    /// Returns the raw pointer for native APIs whose call cannot outlive this view.
    pub(crate) const fn as_ptr(self) -> *mut wdk_sys::FILE_OBJECT {
        self.address.as_ptr()
    }

    /// Returns the related FILE_OBJECT retained by this active create request, when present.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn related_file_object(self) -> Option<Self> {
        unsafe {
            // SAFETY: The active create IRP retains its related FILE_OBJECT for this owner borrow.
            KernelFileObject::from_raw(self.as_ref().RelatedFileObject)
        }
        .map(|address| Self {
            address,
            owner: core::marker::PhantomData,
        })
    }
}

/// IRP received by a dispatch callback before its completion policy is selected.
#[derive(Debug)]
#[must_use]
pub(crate) struct ReceivedIrp {
    /// Target decoded from the raw dispatch ABI.
    target: DispatchTarget,
}

impl ReceivedIrp {
    /// Decodes raw WDK dispatch pointers into a received IRP.
    /// # Safety
    ///
    /// The pointers must identify the live device and IRP supplied for the active WDK dispatch
    /// callback.
    /// # Errors
    ///
    /// Returns an error when either the device object or IRP pointer is null.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn decode(device: PDEVICE_OBJECT, irp: PIRP) -> DriverResult<Self> {
        // SAFETY: The caller retains the raw callback pair for this received completion owner.
        let target = unsafe { DispatchTarget::decode(device, irp)? };
        Ok(Self { target })
    }

    /// Executes one non-suspending operation against a lifetime-bound active IRP view.
    pub(crate) fn with_active<R>(
        &mut self,
        operation: impl for<'view> FnOnce(&'view mut ActiveIrp<'view>) -> R,
    ) -> R {
        let mut active = self.target.active();
        operation(&mut active)
    }

    /// Returns the target device that received this IRP.
    pub(crate) const fn device(&self) -> KernelDevice {
        self.target.device
    }

    /// Completes this received IRP immediately.
    pub(crate) fn complete(self, completion: IrpCompletion) -> NTSTATUS {
        self.target.irp.complete(completion)
    }

    /// Completes this received IRP from a fallible request result.
    pub(crate) fn complete_result(self, result: DriverResult<IrpCompletion>) -> NTSTATUS {
        self.complete(match result {
            Ok(completion) => completion,
            Err(error) => IrpCompletion::from_error(error),
        })
    }

    /// Completes a raw IRP when dispatch-target decoding failed.
    /// # Safety
    ///
    /// A non-null `irp` must be the live IRP supplied to the active dispatch callback.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn complete_decode_error(irp: PIRP, error: DriverError) -> NTSTATUS {
        let completion = IrpCompletion::from_error(error);
        if let Some(irp) = unsafe {
            // SAFETY: The caller retains the callback's live IRP through this terminal completion.
            KernelIrp::from_raw(irp)
        } {
            return irp.complete(completion);
        }
        completion.status()
    }
}

/// Prepared IRP ready to transfer into the cancel-safe queue.
#[derive(Debug)]
#[must_use]
pub(super) struct PendingIrp {
    /// Dispatch target whose completion authority transfers with queue insertion.
    pub(super) target: DispatchTarget,
    /// Requestor-context capture transferred through `DriverContext[0]` before insertion.
    pub(super) context: QueueContextOwnership,
}

impl PendingIrp {
    /// Joins the received completion authority with its fully captured queue context.
    pub(super) fn from_received(received: ReceivedIrp, context: QueueContextOwnership) -> Self {
        Self {
            target: received.target,
            context,
        }
    }

    /// Publishes the context into `DriverContext[0]` and transfers queue ownership.
    pub(super) fn publish(self) -> PIRP {
        self.target.irp.publish_queue_context(self.context);
        self.target.irp.as_ptr()
    }

    /// Returns the status dispatch must return after this IRP has been pended.
    pub(super) const fn dispatch_status(&self) -> NTSTATUS {
        STATUS_PENDING
    }
}

/// Unique IRP completion authority held by the queue, device actor, or immediate path.
#[derive(Debug)]
#[must_use]
pub(crate) struct OwnedIrp {
    /// Target whose IRP can be completed exactly once by this owner.
    target: DispatchTarget,
    /// Request capture removed exactly once from `DriverContext[0]` with queue ownership.
    context: QueueContextOwnership,
    /// Active cancel-routine ownership after exclusive CSQ removal.
    #[cfg(not(test))]
    active_cancellation: Option<cancel::ActiveCancellation>,
}

/// Top-level IRP context retained while an external FsRtl package owns completion routing.
///
/// This value deliberately has no completion API. It can only be reclaimed after the external
/// completion callback returns the exact IRP to the reactor.
#[cfg(not(test))]
#[derive(Debug)]
pub(super) struct DelegatedIrp {
    /// Dispatch target whose raw IRP was transferred to FsRtl.
    target: DispatchTarget,
    /// Request capture retained independently from the IRP's temporary external owner.
    context: QueueContextOwnership,
}

#[cfg(not(test))]
impl DelegatedIrp {
    /// Returns the exact live IRP identity transferred to FsRtl.
    pub(super) const fn irp(&self) -> NonNull<wdk_sys::IRP> {
        self.target.irp.irp
    }

    /// Restores unique driver completion authority after the FsRtl callback returns the IRP.
    pub(super) fn reclaim(self) -> OwnedIrp {
        OwnedIrp {
            target: self.target,
            context: self.context,
            active_cancellation: None,
        }
    }
}

/// Actor-local request classification after queue metadata ownership is recovered.
pub(crate) enum ActorRequest<'a> {
    /// Request whose complete classification and requestor state were captured at dispatch.
    Captured(&'a PreparedRequest),
    /// FILE_OBJECT cleanup barrier.
    Cleanup,
    /// Terminal FILE_OBJECT close.
    Close,
}

/// Exclusive borrow of one pending IRP while its executor task decodes or awaits request state.
#[derive(Debug)]
pub(crate) struct PendingIrpLease<'a> {
    /// Completion owner retained mutably so the IRP cannot complete while derived pointers live.
    owner: &'a mut OwnedIrp,
}

impl<'a> PendingIrpLease<'a> {
    /// Executes one non-suspending operation against a lifetime-bound active IRP view.
    pub(crate) fn with_active<R>(
        &mut self,
        operation: impl for<'view> FnOnce(&'view mut ActiveIrp<'view>) -> R,
    ) -> R {
        let mut active = self.owner.target.active();
        operation(&mut active)
    }

    /// Borrows the read payload captured before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this pending request is not a read.
    pub(crate) fn prepared_read(&self) -> DriverResult<&PreparedRead> {
        self.owner.context.read()
    }

    /// Mutably borrows the read payload captured before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this pending request is not a read.
    pub(crate) fn prepared_read_mut(&mut self) -> DriverResult<&mut PreparedRead> {
        self.owner.context.read_mut()
    }

    /// Borrows the write contract captured before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this pending request is not a write.
    pub(crate) fn prepared_write(&self) -> DriverResult<&PreparedWrite> {
        self.owner.context.write()
    }

    /// Borrows the opaque query-security output target for the lifetime of this pending request.
    /// # Errors
    ///
    /// Returns an invariant error when the queued request was not prepared as query-security.
    pub(crate) fn query_security_parts(
        self,
    ) -> DriverResult<(SecuritySelection, &'a mut CapturedQuerySecurityOutput)> {
        self.owner.context.query_security_parts()
    }

    /// Borrows the owned set-security descriptor for the lifetime of this pending request.
    /// # Errors
    ///
    /// Returns an invariant error when the queued request was not prepared as set-security.
    pub(crate) fn set_security_parts(self) -> DriverResult<(SecuritySelection, &'a [u8])> {
        self.owner.context.set_security_parts()
    }

    /// Borrows the complete QueryDirectory payload sealed before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this is not a query-directory request.
    pub(crate) fn prepared_query_directory(&self) -> DriverResult<&PreparedQueryDirectory> {
        self.owner.context.query_directory()
    }

    /// Borrows the complete QueryEa payload sealed before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this is not a query-EA request.
    pub(crate) fn prepared_query_ea(&self) -> DriverResult<&PreparedQueryEa> {
        self.owner.context.query_ea()
    }
}

impl OwnedIrp {
    /// Takes queue context and terminal completion authority from one exclusively removed IRP.
    /// # Safety
    ///
    /// `irp` must be a live IRP exclusively removed from this device's CSQ with its queue context
    /// still published.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) unsafe fn from_queued_raw(device: KernelDevice, irp: PIRP) -> Self {
        let Some(irp) = (unsafe {
            // SAFETY: The caller owns the exclusively removed live IRP.
            KernelIrp::from_raw(irp)
        }) else {
            crate::kernel::fatal::KernelWideInconsistency::async_executor_state_corruption()
                .bugcheck();
        };
        let context = irp.take_queue_context();
        Self {
            target: DispatchTarget { device, irp },
            context,
            #[cfg(not(test))]
            active_cancellation: None,
        }
    }

    /// Builds queued ownership directly for completion-focused unit tests.
    /// # Safety
    ///
    /// `irp` must name a live test fixture retained until the returned owner is consumed.
    #[cfg(test)]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) unsafe fn from_test_raw(device: KernelDevice, irp: PIRP) -> Option<Self> {
        let irp = unsafe {
            // SAFETY: The test caller supplies a live fixture for the returned owner lifetime.
            KernelIrp::from_raw(irp)?
        };
        Some(Self {
            target: DispatchTarget { device, irp },
            context: QueueContextOwnership::Captured(QueueContext::for_test_create().ok()?),
        })
    }

    /// Borrows this pending IRP as an active request without releasing completion authority.
    pub(crate) const fn request(&mut self) -> PendingIrpLease<'_> {
        PendingIrpLease { owner: self }
    }

    /// Installs the active cancellation token after this IRP leaves the CSQ.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn install_active_cancellation(&mut self, envelope: NonNull<ActiveCancelEnvelope>) {
        if self.active_cancellation.is_some() {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        }
        self.active_cancellation = Some(unsafe {
            // SAFETY: Exclusive CSQ removal grants this owner the sole right to install a cancel
            // routine, and the selected envelope is stable until this token is dropped.
            cancel::ActiveCancellation::install(self.target.irp.as_ptr(), envelope)
        });
    }

    /// Returns the exact IRP identity for a prepared external-ownership publication.
    ///
    /// This does not transfer completion or cancellation authority. The caller must publish the
    /// identity only together with a protocol that retains this owner until delegation begins.
    #[cfg(not(test))]
    pub(super) const fn external_irp_identity(&self) -> NonNull<wdk_sys::IRP> {
        self.target.irp.irp
    }

    /// Removes driver cancel authority and transfers the raw IRP to an external FsRtl package.
    ///
    /// The cancel spin lock in `ActiveCancellation::drop` linearizes this handoff after any
    /// already-selected callback has finished. The returned value retains request capture but has
    /// no terminal completion authority until its matching external callback reclaims it.
    #[cfg(not(test))]
    pub(super) fn delegate_to_fsrtl(self) -> DelegatedIrp {
        let Self {
            target,
            context,
            active_cancellation,
        } = self;
        drop(active_cancellation);
        DelegatedIrp { target, context }
    }

    /// Returns the exhaustive actor-local request classification.
    pub(crate) fn actor_request(&self) -> ActorRequest<'_> {
        match &self.context {
            QueueContextOwnership::Captured(context) => ActorRequest::Captured(context.prepared()),
            QueueContextOwnership::Cleanup => ActorRequest::Cleanup,
            QueueContextOwnership::Close => ActorRequest::Close,
        }
    }

    /// Completes the IRP through the I/O Manager.
    pub(crate) fn complete(self, completion: IrpCompletion) -> NTSTATUS {
        let Self {
            target,
            context,
            #[cfg(not(test))]
            active_cancellation,
        } = self;
        #[cfg(not(test))]
        drop(active_cancellation);
        drop(context);
        target.irp.complete(completion)
    }

    /// Completes the IRP from a fallible request result.
    pub(crate) fn complete_result(self, result: DriverResult<IrpCompletion>) -> NTSTATUS {
        self.complete(match result {
            Ok(completion) => completion,
            Err(error) => IrpCompletion::from_error(error),
        })
    }

    /// Completes a create IRP from its ownership-bearing, mutually exclusive result.
    ///
    /// A successful reparse transfers the auxiliary buffer to the I/O Manager immediately before
    /// completing with `STATUS_REPARSE`. Failed results never transfer an allocation.
    pub(crate) fn complete_create_result(self, result: DriverResult<CreateCompletion>) -> NTSTATUS {
        let Self {
            target,
            context,
            #[cfg(not(test))]
            active_cancellation,
        } = self;
        #[cfg(not(test))]
        drop(active_cancellation);
        drop(context);
        match result {
            Ok(CreateCompletion::Handle(action)) => target.irp.complete_create_action(action),
            Ok(CreateCompletion::OplockBreakInProgress(action)) => {
                target.irp.complete_create_oplock_break(action)
            }
            Ok(CreateCompletion::ReparseSymlink(buffer)) => {
                target.irp.complete_create_symlink_reparse(buffer)
            }
            Err(error) => target.irp.complete(IrpCompletion::from_error(error)),
        }
    }

    /// Transfers this queued directory-change IRP's terminal completion authority to FsRtl.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn delegate_directory_notification(
        self,
        notifier: NonNull<DirectoryChangeNotifier>,
        registration: DirectoryNotificationRegistration,
    ) -> NTSTATUS {
        let Self {
            target,
            context,
            #[cfg(not(test))]
            active_cancellation,
        } = self;
        #[cfg(not(test))]
        drop(active_cancellation);
        drop(context);
        let notifier = unsafe {
            // SAFETY: Registration decoded the notifier from the mounted VCB kept live by this
            // consumed pending IRP.
            notifier.as_ref()
        };
        if let Err(error) = notifier.ensure_registration_ready() {
            return target.irp.complete(IrpCompletion::from_error(error));
        }
        notifier.register(target, registration)
    }

    /// Transfers this queued lock-control IRP's terminal completion authority to FsRtl.
    ///
    /// The caller has already serialized this request with the handle lane and completed its
    /// stream oplock check. FsRtl then owns completion, conflict waiting, and cancellation for the
    /// byte-range request.
    #[expect(
        unsafe_code,
        reason = "the decoded FCB remains live through the consumed queued IRP and handle lane"
    )]
    pub(crate) fn delegate_byte_range_lock(
        self,
        file_control_block: NonNull<FileControlBlock>,
    ) -> NTSTATUS {
        let Self {
            target,
            context,
            #[cfg(not(test))]
            active_cancellation,
        } = self;
        #[cfg(not(test))]
        drop(active_cancellation);
        drop(context);
        let file_control_block = unsafe {
            // SAFETY: Reactor admission decoded this FCB from the same live FILE_OBJECT. The
            // consumed IRP and its ordinary handle lane retain that object through delegation.
            file_control_block.as_ref()
        };
        file_control_block.process_byte_range_lock(target)
    }

    /// Transfers this queued namespace-stream oplock FSCTL's terminal completion to FsRtl.
    ///
    /// The caller has serialized the request through the live handle lane and revalidated the
    /// FILE_OBJECT-to-FCB binding immediately before this consuming transition.
    #[expect(
        unsafe_code,
        reason = "the decoded FCB remains live through the consumed queued IRP and handle lane"
    )]
    pub(crate) fn delegate_oplock_control(
        self,
        file_control_block: NonNull<FileControlBlock>,
    ) -> NTSTATUS {
        let Self {
            target,
            context,
            #[cfg(not(test))]
            active_cancellation,
        } = self;
        #[cfg(not(test))]
        drop(active_cancellation);
        drop(context);
        let file_control_block = unsafe {
            // SAFETY: Reactor admission decoded this FCB from the same live FILE_OBJECT. The
            // consumed IRP and its ordinary handle lane retain that object through delegation.
            file_control_block.as_ref()
        };
        file_control_block.process_oplock_fsctrl(target)
    }

    /// Completes the IRP as canceled.
    pub(super) fn complete_cancelled(self) -> NTSTATUS {
        self.complete(IrpCompletion::cancelled())
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: After CSQ removal, this unique completion authority moves only between the sole reactor
// thread and an ext4win-owned lower completion envelope. No requestor-context access occurs while
// the lower stack owns that envelope.
unsafe impl Send for OwnedIrp {}

/// Non-null IRP pointer kept private to the typed dispatch boundary.
#[derive(Clone, Copy, Debug)]
pub(super) struct KernelIrp {
    /// Non-null WDK IRP pointer.
    pub(super) irp: NonNull<wdk_sys::IRP>,
}

impl KernelIrp {
    /// Converts a raw WDK IRP pointer into the private non-null boundary type.
    /// # Safety
    ///
    /// A non-null pointer must identify a live I/O Manager-owned IRP retained by the current
    /// completion owner.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) unsafe fn from_raw(irp: PIRP) -> Option<Self> {
        NonNull::new(irp).map(|irp| Self { irp })
    }

    /// Returns the raw IRP pointer.
    pub(super) fn as_ptr(self) -> PIRP {
        self.irp.as_ptr()
    }

    /// Publishes one queue context into the sole driver-owned IRP context slot.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn publish_queue_context(self, context: QueueContextOwnership) {
        let mut irp = self.irp;
        let irp = unsafe {
            // SAFETY: Queue preparation retains unique dispatch ownership before CSQ insertion.
            irp.as_mut()
        };
        let overlay = unsafe {
            // SAFETY: Queue metadata and list linkage both use the IRP tail overlay.
            &mut irp.Tail.Overlay
        };
        let driver_storage = unsafe {
            // SAFETY: The first nested union arm is reserved for driver-owned context slots;
            // list linkage lives in the independent `overlay.__bindgen_anon_2` field.
            &mut overlay.__bindgen_anon_1.__bindgen_anon_1
        };
        let driver_context = &mut driver_storage.DriverContext;
        if !driver_context[0].is_null() {
            crate::kernel::fatal::KernelWideInconsistency::async_executor_state_corruption()
                .bugcheck();
        }
        driver_context[0] = match context {
            QueueContextOwnership::Captured(context) => {
                into_device_actor_mailbox(context).cast::<c_void>()
            }
            QueueContextOwnership::Cleanup => queue_context_marker(CLEANUP_QUEUE_CONTEXT_MARKER),
            QueueContextOwnership::Close => queue_context_marker(CLOSE_QUEUE_CONTEXT_MARKER),
        };
    }

    /// Takes the context after CSQ removal or cancellation transferred exclusive IRP ownership.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn take_queue_context(self) -> QueueContextOwnership {
        let mut irp = self.irp;
        let irp = unsafe {
            // SAFETY: The caller has exclusive IRP ownership after atomic CSQ removal.
            irp.as_mut()
        };
        let overlay = unsafe {
            // SAFETY: Exclusive CSQ removal permits mutable access to the IRP tail overlay.
            &mut irp.Tail.Overlay
        };
        let driver_storage = unsafe {
            // SAFETY: Queue publication selected the first nested union arm for driver context.
            &mut overlay.__bindgen_anon_1.__bindgen_anon_1
        };
        let driver_context = &mut driver_storage.DriverContext;
        let Some(context) = NonNull::new(driver_context[0]) else {
            crate::kernel::fatal::KernelWideInconsistency::async_executor_state_corruption()
                .bugcheck();
        };
        driver_context[0] = core::ptr::null_mut();
        if core::ptr::eq(
            context.as_ptr().cast_const(),
            queue_context_marker(CLEANUP_QUEUE_CONTEXT_MARKER).cast_const(),
        ) {
            return QueueContextOwnership::Cleanup;
        }
        if core::ptr::eq(
            context.as_ptr().cast_const(),
            queue_context_marker(CLOSE_QUEUE_CONTEXT_MARKER).cast_const(),
        ) {
            return QueueContextOwnership::Close;
        }
        let context = context.cast::<QueueContext>();
        unsafe {
            // SAFETY: The slot received this pointer from exactly one `Box::into_raw`, exclusive
            // CSQ removal grants the sole take right, and the slot was cleared before rebuilding.
            QueueContextOwnership::Captured(Box::from_raw(context.as_ptr()))
        }
    }

    /// Tests the published queue context without allowing its reference to escape the CSQ lock.
    ///
    /// # Safety
    /// The caller must hold the owning cancel-safe queue lock so removal cannot take or free the
    /// context until this method returns.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) unsafe fn published_queue_context_matches(
        self,
        cancellation: *mut c_void,
        ordinary_cleanup_only: bool,
    ) -> bool {
        let irp = unsafe {
            // SAFETY: The caller's CSQ lock contract keeps the queued IRP and context live.
            self.irp.as_ref()
        };
        let overlay = unsafe {
            // SAFETY: Queue publication selected the IRP tail overlay.
            &irp.Tail.Overlay
        };
        let driver_storage = unsafe {
            // SAFETY: Queue publication selected the first nested union arm for driver context.
            &overlay.__bindgen_anon_1.__bindgen_anon_1
        };
        let Some(context) = NonNull::new(driver_storage.DriverContext[0]) else {
            crate::kernel::fatal::KernelWideInconsistency::async_executor_state_corruption()
                .bugcheck();
        };
        if core::ptr::eq(
            context.as_ptr().cast_const(),
            queue_context_marker(CLEANUP_QUEUE_CONTEXT_MARKER).cast_const(),
        ) || core::ptr::eq(
            context.as_ptr().cast_const(),
            queue_context_marker(CLOSE_QUEUE_CONTEXT_MARKER).cast_const(),
        ) {
            return cancellation.is_null() && !ordinary_cleanup_only;
        }
        let context = context.cast::<QueueContext>();
        let context = unsafe {
            // SAFETY: The CSQ lock keeps this published Box allocation live for the call.
            context.as_ref()
        };
        context.matches_cancellation_context(cancellation)
            && (!ordinary_cleanup_only || context.cleanup_cancel_eligible())
    }

    /// Returns the raw IRP pointer for writes to the WDK completion fields.
    #[cfg(not(test))]
    fn as_mut_ptr(self) -> *mut wdk_sys::IRP {
        self.irp.as_ptr()
    }

    /// Writes status and byte count to the IRP status block.
    pub(super) fn write_status_block(self, completion: IrpCompletion) {
        self.write_status_and_information(
            completion.status(),
            completion.information().as_ulong_ptr(),
        );
    }

    /// Writes the raw WDK completion pair after a typed completion path selected its semantics.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn write_status_and_information(self, status: NTSTATUS, information: wdk_sys::ULONG_PTR) {
        let mut irp = self.irp;
        let irp = unsafe {
            // SAFETY: `KernelIrp` is constructed only from a non-null raw IRP
            // pointer, and the unique completion path owns terminal-field writes.
            irp.as_mut()
        };
        irp.IoStatus.__bindgen_anon_1.Status = status;
        irp.IoStatus.Information = information;
    }

    /// Installs a Rust-owned create reparse allocation into the IRP tail overlay.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn install_create_symlink_reparse_buffer(self, buffer: CreateSymlinkReparseBuffer) {
        let mut irp = self.irp;
        let irp = unsafe {
            // SAFETY: `KernelIrp` retains the non-null active IRP, and unique
            // completion authority permits mutation of its terminal fields.
            irp.as_mut()
        };
        irp.Tail.Overlay.AuxiliaryBuffer = buffer.into_raw();
    }

    /// Invokes the I/O Manager after the unique owner wrote all terminal IRP fields.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn finish_completion(self, status: NTSTATUS) -> NTSTATUS {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The IRP pointer belongs to the unique completion owner
            // and the calling completion path wrote every terminal field first.
            ffi::IoCompleteRequest(self.as_mut_ptr(), IO_NO_INCREMENT_PRIORITY);
        }
        status
    }

    /// Transfers a create reparse buffer to the I/O Manager and completes exactly once.
    fn complete_create_symlink_reparse(self, buffer: CreateSymlinkReparseBuffer) -> NTSTATUS {
        // A name-surrogate buffer is identified by its reparse tag. `IO_REPARSE` is reserved for
        // the separate contract where the filesystem has already replaced FILE_OBJECT::FileName.
        let information = wdk_sys::ULONG_PTR::from(wdk_sys::IO_REPARSE_TAG_SYMLINK);
        self.install_create_symlink_reparse_buffer(buffer);
        self.write_status_and_information(wdk_sys::STATUS_REPARSE, information);
        self.finish_completion(wdk_sys::STATUS_REPARSE)
    }

    /// Completes a successful create with its exact `FILE_*` action result.
    fn complete_create_action(self, action: CreateAction) -> NTSTATUS {
        self.write_status_and_information(
            wdk_sys::STATUS_SUCCESS,
            wdk_sys::ULONG_PTR::from(action.as_ulong()),
        );
        self.finish_completion(wdk_sys::STATUS_SUCCESS)
    }

    /// Completes a successful create while preserving its nonblocking oplock-break status.
    fn complete_create_oplock_break(self, action: CreateAction) -> NTSTATUS {
        self.write_status_and_information(
            wdk_sys::STATUS_OPLOCK_BREAK_IN_PROGRESS,
            wdk_sys::ULONG_PTR::from(action.as_ulong()),
        );
        self.finish_completion(wdk_sys::STATUS_OPLOCK_BREAK_IN_PROGRESS)
    }

    /// Completes the IRP through the I/O Manager.
    fn complete(self, completion: IrpCompletion) -> NTSTATUS {
        self.write_status_block(completion);
        self.finish_completion(completion.status())
    }
}

/// Transfers one typed payload from an arbitrary dispatch CPU into the device actor mailbox.
fn into_device_actor_mailbox<T: Send>(payload: Box<T>) -> *mut T {
    Box::into_raw(payload)
}
