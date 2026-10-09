//! Active, received, pending, and owned IRP lifecycle states.

use super::*;

/// Cache policy requested by this IRP independently of its FILE_OBJECT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataCachePolicy {
    /// The handle's intermediate-buffering policy may select Cc.
    Handle,
    /// This operation must bypass intermediate buffering.
    NonCached,
}

impl DataCachePolicy {
    /// Decodes the request-local Windows cache flag.
    pub(crate) const fn from_flags(flags: u32) -> Self {
        if flags & wdk_sys::IRP_NOCACHE != 0 {
            Self::NonCached
        } else {
            Self::Handle
        }
    }
}

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
    /// Copies the requestor mode retained unchanged through dispatch and capture.
    #[expect(
        unsafe_code,
        reason = "the active owner retains this initialized dispatch field"
    )]
    pub(super) fn requestor_mode(&self) -> wdk_sys::KPROCESSOR_MODE {
        unsafe {
            // SAFETY: The active owner retains this dispatch-stable scalar without borrowing IRP
            // fields that the I/O Manager can mutate during cancellation.
            (*self.irp.as_ptr()).RequestorMode
        }
    }
    /// Returns the typed device object boundary.
    pub(crate) const fn device(&self) -> KernelDevice {
        self.device
    }

    /// Copies the initial allocation request from the create-only IRP overlay.
    #[expect(
        unsafe_code,
        reason = "the active create owner retains the immutable allocation overlay"
    )]
    pub(crate) fn create_allocation_size(&self) -> i64 {
        let overlay = unsafe {
            // SAFETY: The create IRP owner retains this dispatch-stable overlay; no reference spans cancellation fields.
            (*self.irp.as_ptr()).Overlay
        };
        let size = unsafe {
            // SAFETY: This accessor is selected only for IRP_MJ_CREATE, whose allocation union arm is active.
            overlay.AllocationSize
        };
        unsafe {
            // SAFETY: QuadPart is the signed LARGE_INTEGER representation of this copied allocation request.
            size.QuadPart
        }
    }

    /// Captures the request-local cache policy before queue admission.
    #[expect(
        unsafe_code,
        reason = "the active IRP owner retains its immutable dispatch flags"
    )]
    pub(super) fn data_cache_policy(&self) -> DataCachePolicy {
        let flags = unsafe {
            // SAFETY: The active owner retains initialized dispatch flags; cancellation fields are not borrowed.
            (*self.irp.as_ptr()).Flags
        };
        DataCachePolicy::from_flags(flags)
    }

    /// Returns whether this request is normal handle I/O or paging I/O.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn data_io_kind(&self) -> DataIoKind {
        let flags = unsafe {
            // SAFETY: The active owner retains this initialized, dispatch-stable field. No
            // reference is created to cancellation fields that the I/O Manager can mutate.
            (*self.irp.as_ptr()).Flags
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
    pub(crate) fn create_access_state(
        &mut self,
        policy: CreateAccessCheck,
    ) -> DriverResult<CreateAccessState<'_>> {
        let requestor_mode = self.requestor_mode();
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

    /// Borrows an initialized system-buffer input prefix under this completion owner.
    /// # Errors
    /// Rejects a request without a buffered input contract, an excess prefix, or a null nonempty
    /// system buffer. An empty prefix requires no buffer allocation.
    #[expect(
        unsafe_code,
        reason = "the IRP owner borrow retains the checked initialized input for the returned slice"
    )]
    pub(crate) fn buffered_input(&self, length: IrpBufferLength) -> DriverResult<&[u8]> {
        self.current_stack()?
            .buffered_lengths()?
            .initialized_input
            .prefix(length.as_usize())?;
        if length.is_empty() {
            return Ok(&[]);
        }
        let address = self.associated_system_buffer()?;
        Ok(unsafe {
            // SAFETY: The operation-specific stack extent bounds this initialized input prefix.
            // SystemBuffer is an I/O Manager allocation, not a requestor mapping. Borrowing self
            // retains the IRP and excludes mutable output access or completion until the slice ends.
            core::slice::from_raw_parts(address.as_ptr(), length.as_usize())
        })
    }

    /// Initializes and exclusively borrows a writable system-buffer output prefix.
    /// # Errors
    /// Rejects a request without a buffered output contract, an excess prefix, or a null nonempty
    /// system buffer before initialization. An empty prefix requires no buffer allocation.
    #[expect(
        unsafe_code,
        reason = "the exclusive IRP owner borrow retains the checked initialized output slice"
    )]
    pub(crate) fn buffered_output(&mut self, length: IrpBufferLength) -> DriverResult<&mut [u8]> {
        self.current_stack()?
            .buffered_lengths()?
            .writable_output
            .prefix(length.as_usize())?;
        if length.is_empty() {
            return Ok(&mut []);
        }
        let address = self.associated_system_buffer()?;
        unsafe {
            // SAFETY: The checked prefix fits the I/O Manager's writable allocation. The mutable
            // owner borrow excludes every input/output slice; initialize before forming a reference.
            address.as_ptr().write_bytes(0, length.as_usize());
        }
        Ok(unsafe {
            // SAFETY: All bytes in the checked range are initialized above. This exclusive owner
            // borrow retains the allocation and excludes other slices and IRP completion.
            core::slice::from_raw_parts_mut(address.as_ptr(), length.as_usize())
        })
    }

    /// Publishes only filesystem-owned FILE_ALL_INFORMATION fields from initialized driver
    /// storage. Access, mode, and alignment belong to the upstream query owner and are neither
    /// read nor overwritten. No Rust reference is formed to the raw output buffer.
    /// # Errors
    /// Returns invalid-info-class for another query, info-length-mismatch for short capacity,
    /// invalid-buffer-size for an invalid initialized prefix, or a null-buffer error before writes.
    #[expect(
        unsafe_code,
        reason = "selective publication must preserve upstream-owned fields without borrowing uninitialized output bytes"
    )]
    pub(crate) fn publish_all_file_information(&mut self, source: &[u8]) -> DriverResult<()> {
        let stack = self.current_stack()?.query_file()?;
        if stack.information_class() != QueryFileInformationClass::All {
            return Err(DriverError::InvalidInfoClass);
        }
        if stack.length().as_usize() < core::mem::size_of::<wdk_sys::FILE_ALL_INFORMATION>() {
            return Err(DriverError::InfoLengthMismatch);
        }
        if source.len() > stack.length().as_usize() {
            return Err(DriverError::InvalidBufferSize);
        }
        let access = core::mem::offset_of!(wdk_sys::FILE_ALL_INFORMATION, AccessInformation);
        let position = core::mem::offset_of!(wdk_sys::FILE_ALL_INFORMATION, PositionInformation);
        let mode = core::mem::offset_of!(wdk_sys::FILE_ALL_INFORMATION, ModeInformation);
        let name = core::mem::offset_of!(wdk_sys::FILE_ALL_INFORMATION, NameInformation);
        let ranges = [
            (
                0,
                source.get(..access).ok_or(DriverError::InvalidBufferSize)?,
            ),
            (
                position,
                source
                    .get(position..mode)
                    .ok_or(DriverError::InvalidBufferSize)?,
            ),
            (
                name,
                source
                    .get(name..)
                    .filter(|bytes| bytes.len() >= 4)
                    .ok_or(DriverError::InvalidBufferSize)?,
            ),
        ];
        let address = self.associated_system_buffer()?.as_ptr();
        for (offset, bytes) in ranges {
            let destination = unsafe {
                // SAFETY: Every field offset is within the validated system-buffer capacity.
                address.add(offset)
            };
            unsafe {
                // SAFETY: All source ranges are initialized driver-owned bytes disjoint from the
                // active query's writable system buffer. Capacity and every range were validated
                // before publication. Only filesystem-owned fields are copied.
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len());
            }
        }
        Ok(())
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
    pub(crate) fn current_stack(&self) -> Result<CurrentIrpStackLocation<'_>, DriverError> {
        let stack = NonNull::new(KernelIrp { irp: self.irp }.current_stack_address())
            .ok_or(DriverError::InvalidParameter)?;
        Ok(CurrentIrpStackLocation {
            stack,
            owner: core::marker::PhantomData,
        })
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
        let associated = unsafe {
            // SAFETY: The active owner retains this dispatch-stable associated-IRP storage. The
            // narrow borrow excludes the independently mutable cancellation and driver slots.
            &(*self.irp.as_ptr()).AssociatedIrp
        };
        let system_buffer = unsafe {
            // SAFETY: The active owner retains this buffered request's initialized SystemBuffer
            // pointer. Cancellation does not modify this associated-IRP arm.
            associated.SystemBuffer
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

        let mdl = unsafe {
            // SAFETY: The completion owner remains borrowed for this view's entire lifetime.
            (*self.irp.as_ptr()).MdlAddress
        };
        let Some(mdl) = NonNull::new(mdl) else {
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
        let related = unsafe {
            // SAFETY: The active create retains this initialized related-object pointer field.
            (*self.as_ptr()).RelatedFileObject
        };
        unsafe {
            // SAFETY: The active create IRP retains its related FILE_OBJECT for this owner borrow.
            KernelFileObject::from_raw(related)
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
    /// Transfers a consuming MDL notification to its stream's preallocated passive worker.
    /// Cancellation cannot skip chain release. Allocation was completed before page acquisition.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "native queue publication consumes this unqueued IRP and retains its FILE_OBJECT until completion"
        )
    )]
    pub(crate) fn delegate_mdl_completion(mut self, _completion: MdlCompletion) -> NTSTATUS {
        let file_object = match self.with_active(|active| {
            active
                .current_stack()?
                .file_object()
                .map(ActiveFileObject::as_ptr)
        }) {
            Ok(file_object) => file_object,
            Err(error) => return self.complete_result(Err(error)),
        };
        #[cfg(not(test))]
        {
            let queue = unsafe {
                // SAFETY: The active FILE_OBJECT retains its native stream and pinned Rust inbox.
                ext4win_stream_mdl_queue(file_object)
            };
            let Some(queue) =
                NonNull::new(queue.cast::<super::mdl_completion::MdlCompletionQueue>())
            else {
                return self.complete_result(Err(DriverError::InternalInvariantViolation));
            };
            let file_object = NonNull::new(file_object).unwrap_or_else(|| {
                crate::kernel::fatal::KernelWideInconsistency::file_object_lifecycle_corruption()
                    .bugcheck()
            });
            let status = match unsafe {
                // SAFETY: Dispatch retains this FILE_OBJECT and its exact inbox until publication
                // acquires independent ownership, then consumes the unqueued IRP only on success.
                super::mdl_completion::MdlCompletionQueue::enqueue(
                    queue,
                    self.target.irp,
                    file_object,
                    _completion,
                )
            } {
                Ok(()) => STATUS_PENDING,
                Err(error) => error.ntstatus(),
            };
            if status == STATUS_PENDING {
                return status;
            }
            self.complete_result(Err(DriverError::CacheManagerFailure(status)))
        }
        #[cfg(test)]
        {
            let _file_object = file_object;
            self.complete_result(Err(DriverError::NotSupported))
        }
    }
    /// Transfers this original control request, including its transfer method, to lower storage.
    /// Completion and cancellation belong to the lower stack after this consuming boundary.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the consumed dispatch IRP and its volume FILE_OBJECT retain the lower target through delegation"
        )
    )]
    pub(crate) fn forward_device_control(self, _lower: KernelDevice) -> NTSTATUS {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Dispatch validated a direct-volume handle. The I/O Manager retains that
            // FILE_OBJECT and its mount through completion; no driver queue context was installed.
            ext4win_forward_original_irp(_lower.as_ptr(), self.target.into_raw_irp())
        }
        #[cfg(test)]
        self.complete_result(Err(DriverError::NotSupported))
    }
    /// Delegates the original unqueued PnP IRP. Lower drivers own completion and cancellation;
    /// no top-level Rust completion owner or actor slot remains after IoCallDriver.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the live mounted dispatch lease retains the lower route throughout original-IRP delegation"
        )
    )]
    pub(crate) fn forward_pnp(self, _lower: KernelDevice, minor: PnpMinor) -> NTSTATUS {
        if minor.initializes_success() {
            self.target.irp.write_status_block(IrpCompletion::EMPTY);
        }
        #[cfg(not(test))]
        unsafe {
            // SAFETY: No CSQ capture or cancel routine is installed. The caller retains the
            // lower route through this consuming call; the I/O Manager then owns the IRP.
            ext4win_forward_original_irp(_lower.as_ptr(), self.target.into_raw_irp())
        }
        #[cfg(test)]
        self.complete_result(Err(DriverError::NotSupported))
    }

    /// Waits for lower cancellation on the PnP system thread before reopening create admission.
    /// No allocation or actor work is needed; dispatch rundown retains the native gate throughout.
    #[expect(
        unsafe_code,
        reason = "PnP CANCEL_REMOVE arrives at PASSIVE_LEVEL and dispatch rundown retains both devices"
    )]
    pub(crate) fn cancel_remove(
        self,
        _lower: KernelDevice,
        _publisher: &crate::kernel::stream::StorageRemovalPublisher,
    ) -> NTSTATUS {
        let status = unsafe {
            // SAFETY: This is the original unqueued CANCEL_REMOVE; the system thread and
            // mounted dispatch lease retain its stack and lower device through the wait.
            _publisher.cancel_remove(_lower, self.target.irp.irp)
        };
        self.target.irp.complete(if status >= STATUS_SUCCESS {
            IrpCompletion::EMPTY
        } else {
            IrpCompletion::from_native_failure(status)
        })
    }
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

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this native boundary consumes the original unqueued control IRP"
)]
unsafe extern "system" {
    fn ext4win_stream_mdl_queue(file: *mut wdk_sys::FILE_OBJECT) -> *mut c_void;
    fn ext4win_forward_original_irp(
        device: wdk_sys::PDEVICE_OBJECT,
        irp: wdk_sys::PIRP,
    ) -> NTSTATUS;
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
    /// Completion routing owns a worker only after actor admission.
    #[cfg(not(test))]
    notification: super::notification::IrpNotification,
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
    /// Completion routing owns a worker only after actor admission.
    #[cfg(not(test))]
    notification: super::notification::IrpNotification,
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
            notification: self.notification,
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

/// Writable captured prefix retained by the IRP's completion-owner borrow.
/// Construction seals the read direction and capacity; no Rust reference borrows requestor bytes.
#[derive(Debug)]
pub(crate) struct CacheReadTransfer<'owner> {
    /// Exact FILE_OBJECT retained by the borrowing IRP.
    file_object: KernelFileObject,
    /// Exclusive capture borrow prevents completion and competing driver output access.
    prepared: &'owner mut PreparedRead,
    /// Prefix bounded by the capture's original extent.
    length: IrpBufferLength,
}

impl CacheReadTransfer<'_> {
    /// Returns the FILE_OBJECT identity for native stream matching.
    pub(crate) const fn file_object(&self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object.as_non_null()
    }

    /// Returns the checked prefix length.
    pub(crate) const fn length(&self) -> usize {
        self.length.as_usize()
    }

    /// Exposes the opaque writable mapping only while this transfer retains its IRP.
    pub(crate) fn address(&self) -> Option<NonNull<u8>> {
        self.prepared.output_address()
    }
}

/// Readable captured prefix retained by the IRP's completion-owner borrow.
/// Construction seals the write direction and capacity; no Rust reference borrows requestor bytes.
#[derive(Debug)]
pub(crate) struct CacheWriteTransfer<'owner> {
    /// Exact FILE_OBJECT retained by the borrowing IRP.
    file_object: KernelFileObject,
    /// Capture borrow prevents completion while native code reads the opaque input.
    prepared: &'owner PreparedWrite,
    /// Prefix bounded by the capture's original extent.
    length: IrpBufferLength,
}

impl CacheWriteTransfer<'_> {
    /// Returns the FILE_OBJECT identity for native stream matching.
    pub(crate) const fn file_object(&self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object.as_non_null()
    }

    /// Returns the checked prefix length.
    pub(crate) const fn length(&self) -> usize {
        self.length.as_usize()
    }

    /// Exposes the opaque readable mapping only while this transfer retains its IRP.
    pub(crate) fn address(&self) -> Option<NonNull<u8>> {
        self.prepared.input_address()
    }
}

impl<'a> PendingIrpLease<'a> {
    /// Borrows a captured read prefix for one synchronous native cache call.
    /// # Errors
    /// Rejects another request kind, an excess prefix or an absent FILE_OBJECT before native access.
    pub(crate) fn cache_read_transfer(
        mut self,
        length: usize,
    ) -> DriverResult<CacheReadTransfer<'a>> {
        let length = self.prepared_read()?.stack().length().prefix(length)?;
        let file_object = self.with_active(|active| {
            active
                .current_stack()?
                .file_object()
                .map(ActiveFileObject::address)
        })?;
        let prepared = self.owner.context.read_mut()?;
        Ok(CacheReadTransfer {
            file_object,
            prepared,
            length,
        })
    }

    /// Borrows a captured write prefix for one synchronous native cache call.
    /// # Errors
    /// Rejects another request kind, an excess prefix or an absent FILE_OBJECT before native access.
    pub(crate) fn cache_write_transfer(
        mut self,
        length: usize,
    ) -> DriverResult<CacheWriteTransfer<'a>> {
        let length = self.prepared_write()?.stack().length().prefix(length)?;
        let file_object = self.with_active(|active| {
            active
                .current_stack()?
                .file_object()
                .map(ActiveFileObject::address)
        })?;
        let prepared = self.owner.context.write()?;
        Ok(CacheWriteTransfer {
            file_object,
            prepared,
            length,
        })
    }

    /// Executes one non-suspending operation against a lifetime-bound active IRP view.
    pub(crate) fn with_active<R>(
        &mut self,
        operation: impl for<'view> FnOnce(&'view mut ActiveIrp<'view>) -> R,
    ) -> R {
        let mut active = self.owner.target.active();
        operation(&mut active)
    }

    /// Transfers the captured administrative command to its sole operation owner.
    /// # Errors
    /// Rejects a request with another captured kind or a consumed command.
    pub(crate) fn take_identity(&mut self) -> DriverResult<crate::identity::IdentityCommand> {
        self.owner.context.take_identity()
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
    ) -> DriverResult<(SecuritySelection, &'a mut CapturedRequestorOutput)> {
        self.owner.context.query_security_parts()
    }

    /// Borrows the copied VCN and locked output for a retrieval query.
    /// # Errors
    /// Returns an invariant error when this pending request is not a retrieval query.
    pub(crate) fn retrieval_parts(self) -> DriverResult<(u64, &'a mut CapturedRequestorOutput)> {
        self.owner.context.retrieval_parts()
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
    /// Removal consumes the pending reservation of the immutable captured progress class.
    pub(super) fn execution_class(&self) -> super::scheduler::ExecutionClass {
        self.context.execution_class()
    }

    /// Releases queue and cancellation ownership before the actor hands query removal to lower
    /// drivers. The reserved notification retains the mounted volume until submission returns.
    pub(crate) fn prepare_query_remove_forward(
        self,
        lower: KernelDevice,
        storage: crate::kernel::stream::VolumeStorageAccess,
    ) -> PreparedPnpForward {
        let Self {
            target,
            context,
            #[cfg(not(test))]
            notification,
            #[cfg(not(test))]
            active_cancellation,
        } = self;
        #[cfg(not(test))]
        drop(active_cancellation);
        drop(context);
        target.irp.write_status_block(IrpCompletion::EMPTY);
        PreparedPnpForward {
            submission: PnpSubmission {
                irp: target.irp,
                lower,
                storage,
            },
            #[cfg(not(test))]
            notification,
        }
    }
    /// Takes queue context and terminal completion authority from one exclusively removed IRP.
    /// # Safety
    ///
    /// `irp` must be a live IRP exclusively removed from this device's CSQ with its queue context
    /// still published.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) unsafe fn from_queued_raw(
        device: KernelDevice,
        irp: PIRP,
        #[cfg(not(test))] notification: super::notification::IrpNotification,
    ) -> Self {
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
            notification,
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
            #[cfg(not(test))]
            notification,
            active_cancellation,
        } = self;
        drop(active_cancellation);
        DelegatedIrp {
            target,
            context,
            notification,
        }
    }

    /// Returns the exhaustive actor-local request classification.
    pub(crate) fn actor_request(&self) -> ActorRequest<'_> {
        match &self.context {
            QueueContextOwnership::Captured(context) => ActorRequest::Captured(context.prepared()),
            QueueContextOwnership::Cleanup => ActorRequest::Cleanup,
            QueueContextOwnership::Close => ActorRequest::Close,
        }
    }

    /// Releases request capture and cancellation, retaining only terminal notification authority.
    pub(crate) fn prepare_completion(self, completion: IrpCompletion) -> PreparedIrpCompletion {
        let Self {
            target,
            context,
            #[cfg(not(test))]
            notification,
            #[cfg(not(test))]
            active_cancellation,
        } = self;
        #[cfg(not(test))]
        drop(active_cancellation);
        drop(context);
        target.irp.write_status_block(completion);
        PreparedIrpCompletion {
            #[cfg(not(test))]
            notification,
            irp: target.irp,
            status: completion.status(),
        }
    }

    /// Prepares terminal status without calling upper drivers.
    pub(crate) fn prepare_result(
        self,
        result: DriverResult<IrpCompletion>,
    ) -> PreparedIrpCompletion {
        self.prepare_completion(match result {
            Ok(completion) => completion,
            Err(error) => IrpCompletion::from_error(error),
        })
    }

    /// Prepares a create result, consuming its mutually exclusive completion ownership.
    ///
    /// A successful reparse installs its auxiliary buffer into the retained IRP. Notification
    /// transfers that buffer to the I/O Manager. Failed results never install an allocation.
    pub(crate) fn prepare_create_result(
        self,
        result: DriverResult<CreateCompletion>,
    ) -> PreparedIrpCompletion {
        let Self {
            target,
            context,
            #[cfg(not(test))]
            notification,
            #[cfg(not(test))]
            active_cancellation,
        } = self;
        #[cfg(not(test))]
        drop(active_cancellation);
        drop(context);
        let (status, information) = match result {
            Ok(CreateCompletion::Handle(action)) => (
                wdk_sys::STATUS_SUCCESS,
                wdk_sys::ULONG_PTR::from(action.as_ulong()),
            ),
            Ok(CreateCompletion::OplockBreakInProgress(action)) => (
                wdk_sys::STATUS_OPLOCK_BREAK_IN_PROGRESS,
                wdk_sys::ULONG_PTR::from(action.as_ulong()),
            ),
            Ok(CreateCompletion::ReparseSymlink(buffer)) => {
                target.irp.install_create_symlink_reparse_buffer(buffer);
                (
                    wdk_sys::STATUS_REPARSE,
                    wdk_sys::ULONG_PTR::from(wdk_sys::IO_REPARSE_TAG_SYMLINK),
                )
            }
            Err(error) => (error.ntstatus(), 0),
        };
        target.irp.write_status_and_information(status, information);
        PreparedIrpCompletion {
            #[cfg(not(test))]
            notification,
            irp: target.irp,
            status,
        }
    }

    /// Transfers this queued directory-change IRP's terminal completion authority to FsRtl.
    /// # Errors
    ///
    /// Returns the retained terminal notification if registration preparation fails.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn delegate_directory_notification(
        self,
        notifier: NonNull<DirectoryChangeNotifier>,
        registration: DirectoryNotificationRegistration,
    ) -> Result<NTSTATUS, PreparedIrpCompletion> {
        let Self {
            target,
            context,
            #[cfg(not(test))]
            notification,
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
            let completion = IrpCompletion::from_error(error);
            target.irp.write_status_block(completion);
            return Err(PreparedIrpCompletion {
                #[cfg(not(test))]
                notification,
                irp: target.irp,
                status: completion.status(),
            });
        }
        #[cfg(not(test))]
        drop(notification);
        Ok(notifier.register(target, registration))
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
            notification,
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
        #[cfg(not(test))]
        let completion = notification.for_file_lock();
        file_control_block.process_byte_range_lock(
            target,
            #[cfg(not(test))]
            completion,
        )
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
            notification,
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
        #[cfg(not(test))]
        drop(notification);
        file_control_block.process_oplock_fsctrl(target)
    }

    /// Prepares cancellation after detaching driver-owned request resources.
    pub(super) fn prepare_cancelled(self) -> PreparedIrpCompletion {
        self.prepare_completion(IrpCompletion::cancelled())
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: After CSQ removal, this unique completion authority moves between the reactor and
// driver-owned completion or cache-worker envelopes. Capture converts requestor-context inputs
// before queueing; cache workers borrow only captured system mappings while retaining this owner.
unsafe impl Send for OwnedIrp {}

/// Unique terminal IRP notification after all request-owned resources have been released.
///
/// The reactor must relinquish scheduling and actor authority before consuming this value.
/// Preparation cannot allocate or fail after a durable publication has committed.
#[derive(Debug)]
#[must_use]
pub(crate) struct PreparedIrpCompletion {
    /// Pre-admitted worker slot retained through upper completion callbacks.
    #[cfg(not(test))]
    notification: super::notification::IrpNotification,
    /// Live IRP whose status and auxiliary buffer have already been published.
    irp: KernelIrp,
    /// Saved status; notification may free the IRP before returning.
    status: NTSTATUS,
}

/// Original query-remove IRP whose terminal authority moves to lower storage on submission.
#[derive(Debug)]
#[must_use]
pub(crate) struct PreparedPnpForward {
    /// Captured original IRP and retained route transferred together to the native worker.
    submission: PnpSubmission,
    /// Sole terminal worker reservation, acquired before CSQ admission.
    #[cfg(not(test))]
    notification: super::notification::IrpNotification,
}

/// Original PnP submission retained by the preallocated notification worker.
#[derive(Debug)]
pub(super) struct PnpSubmission {
    /// Original IRP retained until the native consuming call.
    irp: KernelIrp,
    /// Mounted partition route retained by notification rundown.
    lower: KernelDevice,
    /// Observation only; terminal removal can veto a still-unsubmitted query.
    storage: crate::kernel::stream::VolumeStorageAccess,
}

impl PreparedPnpForward {
    /// Queues the already reserved worker after actor scheduling authority has been released.
    pub(super) fn queue(self) {
        #[cfg(not(test))]
        self.notification.queue_query_remove(self.submission);
        #[cfg(test)]
        self.submission.submit();
    }
}

impl PnpSubmission {
    /// Consumes original-IRP authority exactly once, outside all actor borrows.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "notification rundown retains the mounted route and original IRP through lower delegation"
        )
    )]
    pub(super) fn submit(self) {
        if let Err(error) = self.storage.authorize() {
            let _status = self.irp.complete(IrpCompletion::from_error(error));
            return;
        }
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Queue and driver cancellation capture were removed before publication.
            // Lower drivers consume the original IRP; no driver completion callback remains.
            let _status = ext4win_forward_original_irp(self.lower.as_ptr(), self.irp.as_ptr());
        }
        #[cfg(test)]
        {
            let _lower = self.lower;
            let _status = self.irp.complete(IrpCompletion::EMPTY);
        }
    }
}

impl PreparedIrpCompletion {
    /// Transfers terminal notification to the preallocated PASSIVE_LEVEL worker.
    ///
    /// The reactor has already released actor borrows and the top-level handle lane. Upper
    /// completion callbacks may now query the filesystem without preventing actor progress.
    /// Queueing cannot allocate or fail after durable publication. The returned status is the
    /// prepared request result; notification and callback rundown can finish asynchronously.
    pub(super) fn notify(self) -> NTSTATUS {
        #[cfg(not(test))]
        self.notification.queue(self.irp, self.status);
        #[cfg(test)]
        let _status = self.irp.finish_completion(self.status);
        self.status
    }
}

/// Non-null IRP pointer kept private to the typed dispatch boundary.
#[derive(Clone, Copy, Debug)]
pub(super) struct KernelIrp {
    /// Non-null WDK IRP pointer.
    pub(super) irp: NonNull<wdk_sys::IRP>,
}

impl KernelIrp {
    /// Computes only the driver-context array address using the WDK-generated field layout.
    #[expect(
        unsafe_code,
        reason = "the owning IRP contract retains this in-bounds native field"
    )]
    pub(super) fn driver_context_slots(self) -> NonNull<[*mut c_void; 4]> {
        unsafe {
            // SAFETY: The retained IRP allocation covers its entire generated layout. This offset
            // selects only DriverContext, preserving provenance without borrowing any union arm.
            self.irp.byte_add(core::mem::offset_of!(
                wdk_sys::IRP,
                Tail.Overlay.__bindgen_anon_1.__bindgen_anon_1.DriverContext
            ))
        }
        .cast()
    }

    /// Reads only the initialized current-stack pointer from a retained request.
    #[expect(
        unsafe_code,
        reason = "the owning IRP contract retains its initialized stack-pointer field"
    )]
    fn current_stack_address(self) -> PIO_STACK_LOCATION {
        let slot = unsafe {
            // SAFETY: The generated offset is inside this retained IRP allocation; no unrelated
            // tail fields are read or borrowed while projecting the pointer slot.
            self.irp.byte_add(core::mem::offset_of!(
                wdk_sys::IRP,
                Tail.Overlay
                    .__bindgen_anon_2
                    .__bindgen_anon_1
                    .CurrentStackLocation
            ))
        }
        .cast::<PIO_STACK_LOCATION>();
        unsafe {
            // SAFETY: Dispatch initialized this stable pointer before transferring IRP ownership.
            slot.as_ptr().read()
        }
    }
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

    /// Marks pending before publication to either the CSQ or the non-cancellable terminal FIFO.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(super) fn mark_pending(self) {
        let pending_bit = match u8::try_from(wdk_sys::SL_PENDING_RETURNED) {
            Ok(bit) => bit,
            Err(_) => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        };
        let current_stack = self.current_stack_address();
        let Some(stack) = NonNull::new(current_stack) else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        unsafe {
            // SAFETY: Queue publication uniquely owns the pending bit in the live stack location.
            (*stack.as_ptr()).Control |= pending_bit;
        }
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
        let mut slots = self.driver_context_slots();
        let driver_context = unsafe {
            // SAFETY: Before CSQ insertion, queue preparation uniquely owns these driver slots.
            // This borrow excludes unrelated IRP fields and independent tail list linkage.
            slots.as_mut()
        };
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
        let mut slots = self.driver_context_slots();
        let driver_context = unsafe {
            // SAFETY: Atomic CSQ removal transferred these driver slots to the completion owner;
            // active cancellation has not yet been installed. Other IRP fields remain unborrowed.
            slots.as_mut()
        };
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
        execution: Option<super::scheduler::ExecutionClass>,
    ) -> bool {
        let slots = self.driver_context_slots().cast::<*mut c_void>();
        let context = unsafe {
            // SAFETY: The caller's CSQ lock retains this published context slot and allocation.
            slots.as_ptr().read()
        };
        let Some(context) = NonNull::new(context) else {
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
            return cancellation.is_null()
                && !ordinary_cleanup_only
                && execution
                    .is_none_or(|class| class == super::scheduler::ExecutionClass::Finalization);
        }
        let context = context.cast::<QueueContext>();
        let context = unsafe {
            // SAFETY: The CSQ lock keeps this published Box allocation live for the call.
            context.as_ref()
        };
        context.matches_cancellation_context(cancellation)
            && (!ordinary_cleanup_only || context.cleanup_cancel_eligible())
            && execution.is_none_or(|class| class == context.execution_class())
    }

    /// Returns the raw IRP pointer for writes to the WDK completion fields.
    #[cfg(not(test))]
    fn as_mut_ptr(self) -> *mut wdk_sys::IRP {
        self.irp.as_ptr()
    }

    /// Reads the status already published by the sole prepared-completion owner.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the actor backlog retains this status-prepared IRP until notification transfers ownership"
    )]
    pub(super) fn prepared_status(self) -> NTSTATUS {
        let status_block = unsafe {
            // SAFETY: Prepared completion retains sole ownership of this initialized status block.
            &(*self.irp.as_ptr()).IoStatus
        };
        unsafe {
            // SAFETY: Prepared completion retains this IRP and initialized its terminal status arm.
            status_block.__bindgen_anon_1.Status
        }
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
        let status_block = unsafe {
            // SAFETY: The unique completion path owns this live IRP's terminal status block.
            // The narrow borrow leaves Cancel and every independently mutated field unborrowed.
            &mut (*self.irp.as_ptr()).IoStatus
        };
        status_block.__bindgen_anon_1.Status = status;
        status_block.Information = information;
    }

    /// Installs a Rust-owned create reparse allocation into the IRP tail overlay.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn install_create_symlink_reparse_buffer(self, buffer: CreateSymlinkReparseBuffer) {
        let slot = unsafe {
            // SAFETY: The generated auxiliary-buffer slot offset is inside this retained IRP;
            // projecting it does not borrow the tail union or its independent driver slots.
            self.irp.byte_add(core::mem::offset_of!(
                wdk_sys::IRP,
                Tail.Overlay.AuxiliaryBuffer
            ))
        }
        .cast::<*mut wdk_sys::CHAR>();
        unsafe {
            // SAFETY: Unique create completion owns this auxiliary-buffer slot in the live IRP.
            slot.as_ptr().write(buffer.into_raw());
        }
    }

    /// Invokes the I/O Manager after the unique owner wrote all terminal IRP fields.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    pub(super) fn finish_completion(self, status: NTSTATUS) -> NTSTATUS {
        #[cfg(not(test))]
        {
            // Preserve the filesystem recursion context across synchronous upper callbacks.
            let previous = unsafe {
                // SAFETY: This only observes the current thread's opaque filesystem context.
                ffi::IoGetTopLevelIrp()
            };
            if previous.is_null() {
                unsafe {
                    // SAFETY: This filesystem owns the live IRP through native completion. The
                    // thread-local marker is restored below before returning to any caller.
                    ffi::IoSetTopLevelIrp(self.as_mut_ptr());
                }
            }
            unsafe {
                // SAFETY: The unique completion owner wrote all terminal fields and released its
                // mappings and cancellation state before invoking the I/O Manager.
                ffi::IoCompleteRequest(self.as_mut_ptr(), IO_NO_INCREMENT_PRIORITY);
            }
            // The IRP may now be freed. Restore only the saved thread value; never inspect it.
            unsafe {
                // SAFETY: `previous` is the unchanged opaque value belonging to this same thread.
                ffi::IoSetTopLevelIrp(previous);
            }
        }
        status
    }

    /// Completes the IRP through the I/O Manager.
    pub(super) fn complete(self, completion: IrpCompletion) -> NTSTATUS {
        self.write_status_block(completion);
        self.finish_completion(completion.status())
    }
}

/// Transfers one typed payload from an arbitrary dispatch CPU into the device actor mailbox.
fn into_device_actor_mailbox<T: Send>(payload: Box<T>) -> *mut T {
    Box::into_raw(payload)
}
